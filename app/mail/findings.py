"""Dashboard de hallazgos de Omni-CleanerMail.

Extrae "hallazgos" de cada mensaje analizado: veredictos de bloqueo/cuarentena
y cada razon aportada por los motores (KSMG, ClamAV, YARA, Sandbox, ML local,
adjuntos). Cada hallazgo tiene tipo, severidad, titulo, detalle, motor origen,
estado y fecha. Incluye resumen agregado y exportacion CSV/JSON.
"""
import csv
import io
import json
import sqlite3
from datetime import datetime, timezone

from app import config

SEVERIDADES = ("CRITICA", "ALTA", "MEDIA", "BAJA", "INFO")
ESTADOS = ("NUEVO", "EN_REVISION", "REVISADO")

_TIPOS_POR_MOTOR = {
    "KSMG": "AUTENTICACION_CORREO",
    "ClamAV": "FIRMA_MALICIOSA",
    "YARA": "REGLA_YARA",
    "Sandbox": "SANDBOX",
    "ML-Local": "PHISHING_ML",
    "Adjuntos": "ADJUNTO_PELIGROSO",
}


def _conn():
    conn = sqlite3.connect(config.DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_findings():
    conn = _conn()
    conn.execute(
        """CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            msg_id TEXT NOT NULL,
            tipo TEXT NOT NULL,
            severidad TEXT NOT NULL,
            titulo TEXT NOT NULL,
            detalle TEXT,
            source TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'NUEVO',
            score REAL NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        )"""
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_sev ON findings (severidad)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_tipo ON findings (tipo)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_status ON findings (status)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_created ON findings (created_at)")
    conn.commit()
    conn.close()


def _severity_for(engine: str, score: float) -> str:
    s = score
    if s >= config.BLOCK_THRESHOLD:
        return "CRITICA"
    if s >= config.QUARANTINE_THRESHOLD:
        return "ALTA"
    if s >= 20:
        return "MEDIA"
    return "BAJA"


def extract_findings(msg: dict, engine_results: dict, fused: dict) -> list:
    """Deriva hallazgos de los veredictos y razones de los motores."""
    out = []
    msg_id = msg.get("msg_id", "")

    vote = fused.get("vote")
    if vote == "block":
        out.append({
            "msg_id": msg_id, "tipo": "MENSAJE_BLOQUEADO",
            "severidad": "CRITICA",
            "titulo": "Mensaje bloqueado por postura de amenazas",
            "detalle": f"Score compuesto {fused.get('composite_score')} >= umbral de bloqueo "
                      f"({config.BLOCK_THRESHOLD}). Remitente: {msg.get('sender')}.",
            "source": "FUSION", "score": fused.get("composite_score", 0),
        })
    elif vote == "quarantine":
        out.append({
            "msg_id": msg_id, "tipo": "MENSAJE_CUARENTENA",
            "severidad": "ALTA",
            "titulo": "Mensaje retenido en cuarentena",
            "detalle": f"Score compuesto {fused.get('composite_score')}. Consulte el panel de cuarentena.",
            "source": "FUSION", "score": fused.get("composite_score", 0),
        })

    seen = set()
    for name, result in (engine_results or {}).items():
        if not isinstance(result, dict):
            continue
        score = result.get("score", 0)
        if score >= config.QUARANTINE_THRESHOLD:
            sev = _severity_for(name, score)
            for reason in result.get("reasons", []) or []:
                key = (name, reason)
                if key in seen:
                    continue
                seen.add(key)
                out.append({
                    "msg_id": msg_id,
                    "tipo": _TIPOS_POR_MOTOR.get(name, "MOTOR_" + name.upper()),
                    "severidad": sev,
                    "titulo": reason,
                    "detalle": f"Motor {name} asigno score {score}/100 al mensaje.",
                    "source": name, "score": score,
                })
    return out


def record_findings(msg: dict, engine_results: dict, fused: dict) -> int:
    findings = extract_findings(msg, engine_results, fused)
    if not findings:
        return 0
    now = datetime.now(timezone.utc).isoformat()
    rows = [
        (f["msg_id"], f["tipo"], f["severidad"], f["titulo"],
         f["detalle"], f["source"], f["score"], now)
        for f in findings
    ]
    conn = _conn()
    conn.executemany(
        """INSERT INTO findings
           (msg_id, tipo, severidad, titulo, detalle, source, status, score, created_at)
           VALUES (?,?,?,?,?,?,'NUEVO',?,?)""",
        rows,
    )
    conn.commit()
    conn.close()
    return len(rows)


def list_findings(severidad=None, tipo=None, status=None, source=None,
                  msg_id=None, search=None, limit=500) -> list:
    conn = _conn()
    q = "SELECT * FROM findings WHERE 1=1"
    params = []
    if severidad:
        q += " AND severidad = ?"
        params.append(severidad.upper())
    if tipo:
        q += " AND tipo = ?"
        params.append(tipo.upper())
    if status:
        q += " AND status = ?"
        params.append(status.upper())
    if source:
        q += " AND source = ?"
        params.append(source.upper())
    if msg_id:
        q += " AND msg_id = ?"
        params.append(msg_id)
    if search:
        q += " AND (titulo LIKE ? OR detalle LIKE ? OR msg_id LIKE ?)"
        p = f"%{search}%"
        params += [p, p, p]
    q += " ORDER BY created_at DESC, id DESC LIMIT ?"
    params.append(min(limit, 3000))
    rows = conn.execute(q, params).fetchall()
    cols = [d[0] for d in conn.execute("SELECT * FROM findings LIMIT 1").description]
    conn.close()
    return [dict(zip(cols, r)) for r in rows]


def findings_summary() -> dict:
    conn = _conn()
    total = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    by_sev = {s: 0 for s in SEVERIDADES}
    by_status = {}
    by_tipo = {}
    for s, c in conn.execute("SELECT severidad, COUNT(*) FROM findings GROUP BY severidad"):
        by_sev[s] = c
    for st, c in conn.execute("SELECT status, COUNT(*) FROM findings GROUP BY status"):
        by_status[st] = c
    for t, c in conn.execute("SELECT tipo, COUNT(*) FROM findings GROUP BY tipo ORDER BY 2 DESC LIMIT 12"):
        by_tipo[t] = c
    top_motores = conn.execute(
        "SELECT source, COUNT(*) FROM findings GROUP BY source ORDER BY 2 DESC LIMIT 8"
    ).fetchall()
    ultimo = conn.execute("SELECT MAX(created_at) FROM findings").fetchone()[0]
    conn.close()

    criticos = by_sev.get("CRITICA", 0)
    altos = by_sev.get("ALTA", 0)
    nuevos = by_status.get("NUEVO", 0)
    if total:
        indice = round((criticos * 3 + altos * 2 + by_status.get("EN_REVISION", 0)) * 10 / total, 1)
    else:
        indice = 0.0

    return {
        "total": total,
        "por_severidad": by_sev,
        "criticos": criticos,
        "altos": altos,
        "nuevos": nuevos,
        "por_estado": by_status,
        "por_tipo": by_tipo,
        "top_motores": [{"motor": m, "hallazgos": c} for m, c in top_motores],
        "indice_riesgo": indice,
        "ultimo_hallazgo": ultimo,
        "fecha": datetime.now(timezone.utc).isoformat(),
    }


def update_status(finding_id: int, status: str) -> dict:
    status = status.upper()
    if status not in ESTADOS:
        return {"ok": False, "error": f"estado invalido: {status}"}
    conn = _conn()
    row = conn.execute("SELECT id FROM findings WHERE id=?", (finding_id,)).fetchone()
    if not row:
        conn.close()
        return {"ok": False, "error": "hallazgo no existe"}
    conn.execute("UPDATE findings SET status=? WHERE id=?", (status, finding_id))
    conn.commit()
    conn.close()
    return {"ok": True, "id": finding_id, "status": status}


def build_csv(severidad=None, tipo=None, status=None, source=None, msg_id=None,
              search=None) -> str:
    rows = list_findings(severidad=severidad, tipo=tipo, status=status, source=source,
                         msg_id=msg_id, search=search, limit=3000)
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "id", "msg_id", "tipo", "severidad", "titulo", "detalle",
        "motor_origen", "estado", "score", "fecha_hora",
    ])
    for r in rows:
        writer.writerow([
            r["id"], r["msg_id"], r["tipo"], r["severidad"], r["titulo"],
            (r["detalle"] or "").replace("\n", " "), r["source"], r["status"],
            r["score"], r["created_at"],
        ])
    return buf.getvalue()


def build_json(severidad=None, tipo=None, status=None, source=None, msg_id=None,
               search=None) -> str:
    return json.dumps({
        "reporte": "hallazgos-seguridad",
        "generado": datetime.now(timezone.utc).isoformat(),
        "hallazgos": list_findings(severidad=severidad, tipo=tipo, status=status,
                                   source=source, msg_id=msg_id, search=search,
                                   limit=3000),
    }, ensure_ascii=False, indent=2)