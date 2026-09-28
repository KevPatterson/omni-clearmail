"""Metricas agregadas para el dashboard (Vista Empresa, Departamento, Usuario)."""
import json
import sqlite3
from datetime import datetime, timedelta, timezone

from app import config
from app.mail import engines, findings, quarantine, scoring


def _conn():
    conn = sqlite3.connect(config.DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def metrics_overview() -> dict:
    """Metricas agregadas de la organizacion (Capa 5 - Vista Empresa)."""
    conn = _conn()
    total = conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
    by_status = quarantine.count_by_status()
    blocked = by_status.get("blocked", 0)
    quarantined = by_status.get("quarantine", 0)
    released = by_status.get("released", 0)
    delivered = by_status.get("delivered", 0)

    tasa_bloqueo = round((blocked + quarantined) / total * 100, 1) if total else 0.0

    # tiempo medio de respuesta (simulado: desde llegada hasta veredicto)
    row = conn.execute("SELECT quarantined_at FROM messages ORDER BY id DESC LIMIT 1").fetchone()

    # URIs por usuario (simulado con recipients en cuarentena/bloqueo)
    risky = conn.execute(
        "SELECT recipients, composite_score FROM messages WHERE status IN ('quarantine','blocked')"
    ).fetchall()
    user_uri = {}
    for recips_json, score in risky:
        try:
            recips = json.loads(recips_json)
        except Exception:
            recips = ["desconocido"]
        for r in recips:
            user_uri[r] = max(user_uri.get(r, 0), round(score, 1))

    dept_heat = {}
    for _r, _s in risky:
        pass
    # departamento inferido del dominio en recipients
    depts = {}
    for recips_json, score in risky:
        try:
            recips = json.loads(recips_json)
        except Exception:
            continue
        for r in recips:
            domain = r.rsplit("@", 1)[-1] if "@" in r else "sin-dominio"
            dept = domain.split(".")[0].upper()
            depts.setdefault(dept, []).append(score)

    top_risky_users = sorted(user_uri.items(), key=lambda kv: -kv[1])[:10]
    conn.close()

    hallazgos = findings.findings_summary()

    return {
        "totales": {
            "mensajes": total, "bloqueados": blocked, "cuarentena": quarantined,
            "liberados": released, "entregados": delivered,
        },
        "tasa_bloqueo": tasa_bloqueo,
        "indice_riesgo_org": round(sum(user_uri.values()) / len(user_uri), 1) if user_uri else 0.0,
        "top_usuarios_riesgo": [{"usuario": u, "uri": v} for u, v in top_risky_users],
        "mapa_calor_departamento": [
            {"departamento": d, "media_score": round(sum(v) / len(v), 1), "mensajes": len(v)}
            for d, v in sorted(depts.items(), key=lambda kv: -(sum(kv[1]) / len(kv[1])))
        ],
        "hallazgos": {
            "total": hallazgos.get("total", 0),
            "criticos": hallazgos.get("criticos", 0),
            "altos": hallazgos.get("altos", 0),
            "nuevos": hallazgos.get("nuevos", 0),
        },
        "ultimo_analisis": row[0] if row else None,
        "fecha": datetime.now(timezone.utc).isoformat(),
    }


def department_view(dept: str) -> dict:
    """Vista Departamento: scoring, usuarios de riesgo, salud del flujo."""
    conn = _conn()
    rows = conn.execute(
        "SELECT subject, sender, recipients, composite_score, status, quarantined_at FROM messages "
        "WHERE status IN ('quarantine','blocked')"
    ).fetchall()
    conn.close()
    dept_rows = []
    for subject, sender, recips_json, score, status, ts in rows:
        try:
            recips = json.loads(recips_json)
        except Exception:
            recips = []
        if any(r.rsplit("@", 1)[-1].split(".")[0].upper() == dept.upper() for r in recips if "@" in r):
            dept_rows.append({"subject": subject, "sender": sender, "score": score, "status": status, "ts": ts})
    uri_dept = round(sum(r["score"] for r in dept_rows) / len(dept_rows), 1) if dept_rows else 0.0
    return {
        "departamento": dept,
        "mensajes_riesgo": len(dept_rows),
        "uri_dept": uri_dept,
        "usuarios_riesgo": list({r["sender"] for r in dept_rows}),
        "detalle": dept_rows[:50],
    }


def user_risk_uri(username: str) -> dict:
    """Indice de riesgo de un usuario concreto."""
    conn = _conn()
    rows = conn.execute(
        "SELECT recipients, composite_score, subject, status, quarantined_at FROM messages "
        "WHERE status IN ('quarantine','blocked')"
    ).fetchall()
    conn.close()
    scored = []
    for recips_json, score, subject, status, ts in rows:
        try:
            recips = json.loads(recips_json)
        except Exception:
            recips = []
        if username in recips:
            scored.append({"subject": subject, "score": score, "status": status, "ts": ts})
    return {
        "usuario": username,
        "uri": round(sum(s["score"] for s in scored) / len(scored), 1) if scored else 0.0,
        "mensajes_riesgo": len(scored),
        "detalle": scored[:30],
    }


def engine_coverage() -> dict:
    """Cobertura de motores locales y deteccion offline vs gateway."""
    stats = scoring.engine_accuracy_stats()
    active = [s for s in stats if s["n_analisis"] > 0]
    cobertura = round(len(active) / len(engines.ENGINE_WEIGHTS) * 100, 1) if engines.ENGINE_WEIGHTS else 0.0
    deteccion_offline = round(
        sum(s["n_detect"] for s in active) / sum(s["n_analisis"] for s in active) * 100, 1
    ) if any(s["n_analisis"] for s in active) else 0.0
    from app.mail import ksmg as ksmg_mod
    kst = ksmg_mod.status()
    return {
        "cobertura_motores_locales": cobertura,
        "motores_activos": [s["motor"] for s in active],
        "deteccion_offline_vs_gateway": deteccion_offline,
        "motores": stats,
        "fuente_ksmg": {
            "modo": kst.get("modo"),
            "real": kst.get("modo") in ("EML_WATCH", "IMAP", "SMTP"),
            "conectado": kst.get("conectado"),
        },
    }


def license_metrics() -> dict:
    """Metricas de licenciamiento para el dashboard (OMNI-Lic)."""
    from app.core import licensing
    state = licensing.license_state()
    return {
        "estado": state.get("estado"),
        "dias_restantes": state.get("dias_restantes"),
        "expira": state.get("expira"),
        "tipo": state.get("tipo"),
        "sistema": state.get("sistema"),
    }