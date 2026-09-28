"""Reportes personalizados por buzon/usuario de Omni-CleanerMail.

Genera, para cada buzon (o para toda la organizacion con buzon='*'), un informe
periodico con:
- cantidad de correos ENTRANTES/SALIENTES y sus remitentes/destinatarios
- cantidad de buzones activos de la organizacion en el periodo
- cantidad y detalle de hallazgos de seguridad del buzon
- mensajes en cuarentena/bloqueados y score medio

Los informes se envian por email (SMTP) de forma on-demand y programada
(DIARIO/SEMANAL) mediante un worker en segundo plano.
"""
import csv
import io
import json
import smtplib
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate

from app import config

FRECUENCIAS = ("DIARIO", "SEMANAL")
BUZON_TODOS = "*"

_poller_thread = None
_poller_stop = threading.Event()


def _conn():
    conn = sqlite3.connect(config.DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_reports():
    conn = _conn()
    conn.execute(
        """CREATE TABLE IF NOT EXISTS smtp_config (
            clave TEXT PRIMARY KEY,
            valor TEXT
        )"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS report_config (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            buzon TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL,
            frecuencia TEXT NOT NULL DEFAULT 'DIARIO',
            hora TEXT NOT NULL DEFAULT '08:00',
            activo INTEGER NOT NULL DEFAULT 1,
            last_sent TEXT,
            created_at TEXT NOT NULL
        )"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS report_sent (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            buzon TEXT NOT NULL,
            email TEXT NOT NULL,
            dias INTEGER NOT NULL DEFAULT 7,
            resumen TEXT,
            enviado_ok INTEGER NOT NULL DEFAULT 0,
            detalle TEXT,
            sent_at TEXT NOT NULL
        )"""
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_report_sent_buzon ON report_sent (buzon)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_report_sent_at ON report_sent (sent_at)")
    conn.commit()
    conn.close()


# -------------------------------------------------------------------- configuracion SMTP salida
_SMTP_DEFAULT_KEYS = ("host", "port", "from", "user", "password")


def smtp_config() -> dict:
    """Configuracion SMTP efectiva: tabla (override) + variables de entorno (default)."""
    if not _smtp_loaded:
        _load_smtp()
    cfg = {
        "host": _smtp.get("host") or config.SMTP_HOST,
        "port": _smtp.get("port") or config.SMTP_PORT,
        "from": _smtp.get("from") or config.SMTP_FROM,
        "user": _smtp.get("user") if _smtp.get("user") is not None else config.SMTP_USER,
        "password": _smtp.get("password") if _smtp.get("password") is not None else config.SMTP_PASSWORD,
    }
    cfg["port"] = int(cfg["port"] or 587)
    return cfg


def save_smtp(payload: dict) -> dict:
    """Guarda overrides SMTP. Un valor vacio elimina el override (vuelve al entorno)."""
    vals = {}
    clears = []
    for k in ("host", "port", "from", "user"):
        if k in payload and payload.get(k) is not None:
            v = str(payload[k]).strip()
            if v == "":
                clears.append(k)
            else:
                vals[k] = v
    if "password" in payload and payload.get("password"):
        vals["password"] = str(payload["password"])
    global _smtp, _smtp_loaded
    for k in clears:
        _smtp.pop(k, None)
    _smtp.update(vals)
    _smtp_loaded = True
    conn = _conn()
    for k in clears:
        conn.execute("DELETE FROM smtp_config WHERE clave=?", (k,))
    for k, v in vals.items():
        conn.execute(
            "INSERT INTO smtp_config (clave, valor) VALUES (?,?) "
            "ON CONFLICT(clave) DO UPDATE SET valor=excluded.valor",
            (k, v))
    conn.commit()
    conn.close()
    return {"ok": True, "host": smtp_config()["host"], "port": smtp_config()["port"],
            "from": smtp_config()["from"], "user": smtp_config()["user"]}


def smtp_status() -> dict:
    cfg = smtp_config()
    return {"configurado": bool(cfg["host"]),
            "host": cfg["host"], "port": cfg["port"], "from": cfg["from"],
            "user": cfg["user"], "password_set": bool(cfg["password"])}


def _load_smtp():
    global _smtp, _smtp_loaded
    _smtp = {}
    try:
        conn = _conn()
        rows = conn.execute("SELECT clave, valor FROM smtp_config").fetchall()
        conn.close()
        _smtp = {k: v for k, v in rows}
    except Exception:
        _smtp = {}
    _smtp_loaded = True


_smtp = None
_smtp_loaded = False


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------- buzones conocidos
def buzones_disponibles() -> list:
    """Direcciones internas unicas conocidas en el ledger (los buzones de la org)."""
    conn = _conn()
    rows = conn.execute(
        """SELECT DISTINCT address FROM address_records
           WHERE is_internal = 1 ORDER BY address"""
    ).fetchall()
    conn.close()
    return [r[0] for r in rows]


def buzon_existe(buzon: str) -> bool:
    return buzon == BUZON_TODOS or buzon in buzones_disponibles()


# ---------------------------------------------------------------- configuracion
def load_config() -> list:
    conn = _conn()
    rows = conn.execute(
        "SELECT * FROM report_config ORDER BY buzon"
    ).fetchall()
    cols = [d[0] for d in conn.execute("SELECT * FROM report_config LIMIT 1").description]
    conn.close()
    out = []
    for r in rows:
        d = dict(zip(cols, r))
        due, nxt = _due(d)
        out.append({
            "buzon": d["buzon"],
            "email": d["email"],
            "frecuencia": d["frecuencia"],
            "hora": d["hora"],
            "activo": int(d["activo"] or 0),
            "last_sent": d["last_sent"],
            "proxima_ejecucion": nxt,
            "pendiente_envio": bool(due),
            "created_at": d["created_at"],
        })
    return out


def save_config(buzon: str, email: str, frecuencia: str, hora: str,
                activo: bool) -> dict:
    buzon = (buzon or "").strip().lower() or BUZON_TODOS
    email = (email or "").strip()
    frecuencia = (frecuencia or "DIARIO").upper()
    if frecuencia not in FRECUENCIAS:
        frecuencia = "DIARIO"
    if not _hora_valida(hora):
        hora = "08:00"
    if not email or "@" not in email:
        raise ValueError("email destino no valido para el reporte")
    conn = _conn()
    conn.execute(
        """INSERT INTO report_config (buzon, email, frecuencia, hora, activo, created_at)
           VALUES (?,?,?,?,?,?)
           ON CONFLICT(buzon) DO UPDATE SET
             email=excluded.email, frecuencia=excluded.frecuencia,
             hora=excluded.hora, activo=excluded.activo""",
        (buzon, email, frecuencia, hora, 1 if activo else 0, _now_iso()),
    )
    conn.commit()
    conn.close()
    return {"ok": True, "buzon": buzon, "email": email}


def delete_config(buzon: str) -> dict:
    buzon = (buzon or "").strip().lower()
    conn = _conn()
    conn.execute("DELETE FROM report_config WHERE buzon=?", (buzon,))
    conn.commit()
    conn.close()
    return {"ok": True, "buzon": buzon}


def _hora_valida(hora: str) -> bool:
    try:
        hh, mm = hora.split(":")
        int(hh), int(mm)
        if not (0 <= int(hh) <= 23 and 0 <= int(mm) <= 59):
            return False
    except (ValueError, AttributeError, TypeError):
        return False
    return True


def _due(row: dict) -> tuple:
    """Devuelve (pendiente, proxima_ejecucion_iso) para una fila de config."""
    if not row.get("activo") or not (row.get("frecuencia") or "").upper() in FRECUENCIAS:
        return False, None
    if not _hora_valida(row.get("hora")):
        return False, None
    freq = row["frecuencia"].upper()
    hh, mm = map(int, row["hora"].split(":"))
    now = datetime.now(timezone.utc)
    # ultima ocurrencia de la hora programada en UTC
    base = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
    if freq == "SEMANAL":
        days_since_mon = (base.weekday() - 0) % 7
        base = (base - timedelta(days=days_since_mon)).replace(hour=hh, minute=mm, second=0, microsecond=0)
        while base > now:
            base -= timedelta(days=7)
        prox = base + timedelta(days=7)
    else:
        if base > now:
            base -= timedelta(days=1)
        prox = base + timedelta(days=1)
    pend = now >= base and (not row.get("last_sent") or row["last_sent"] < base.isoformat())
    return bool(pend), prox.isoformat()


# -------------------------------------------------------------------- construccion del reporte
def build_report(buzon: str = BUZON_TODOS, days: int = None) -> dict:
    """Reporte de actividad para un buzon (o '*' para toda la org) en los ultimos `days` dias."""
    if days is None:
        days = config.REPORT_DEFAULT_DAYS
    days = max(1, min(int(days), config.REPORT_MAX_DAYS))
    buzon = (buzon or "").strip().lower() or BUZON_TODOS

    hasta = datetime.now(timezone.utc)
    desde = hasta - timedelta(days=days)
    d_iso, h_iso = desde.isoformat(), hasta.isoformat()

    conn = _conn()
    if buzon == BUZON_TODOS:
        entry = [r[0] for r in conn.execute(
            "SELECT DISTINCT msg_id FROM address_records "
            "WHERE direction='ENTRADA' AND recorded_at>=? AND recorded_at<=?",
            (d_iso, h_iso)).fetchall()]
        exit_ids = [r[0] for r in conn.execute(
            "SELECT DISTINCT msg_id FROM address_records "
            "WHERE direction='SALIDA' AND recorded_at>=? AND recorded_at<=?",
            (d_iso, h_iso)).fetchall()]
    else:
        entry = [r[0] for r in conn.execute(
            "SELECT DISTINCT msg_id FROM address_records "
            "WHERE address=? AND role='DESTINATARIO' AND direction='ENTRADA' "
            "AND recorded_at>=? AND recorded_at<=?",
            (buzon, d_iso, h_iso)).fetchall()]
        exit_ids = [r[0] for r in conn.execute(
            "SELECT DISTINCT msg_id FROM address_records "
            "WHERE address=? AND role='REMITENTE' AND direction='SALIDA' "
            "AND recorded_at>=? AND recorded_at<=?",
            (buzon, d_iso, h_iso)).fetchall()]

    def _in(ids):
        return "('" + "','".join(ids) + "')" if ids else "()"

    entrada = {"mensajes": len(entry), "remitentes_unicos": 0,
               "veredictos": {}, "score_promedio": None}
    salida = {"mensajes": len(exit_ids), "destinatarios_unicos": 0,
              "veredictos": {}, "score_promedio": None}

    if entry:
        inq = _in(entry)
        entrada["remitentes_unicos"] = conn.execute(
            f"SELECT COUNT(DISTINCT address) FROM address_records "
            f"WHERE role='REMITENTE' AND direction='ENTRADA' AND msg_id IN {inq}"
        ).fetchone()[0]
        for v, c in conn.execute(
            f"SELECT verdict, COUNT(DISTINCT msg_id) FROM address_records "
            f"WHERE msg_id IN {inq} GROUP BY verdict").fetchall():
            entrada["veredictos"][v] = c
        sc = conn.execute(
            f"SELECT AVG(score) FROM (SELECT DISTINCT msg_id, score "
            f"FROM address_records WHERE msg_id IN {inq})").fetchone()[0]
        entrada["score_promedio"] = round(sc, 1) if sc is not None else None

    if exit_ids:
        inq = _in(exit_ids)
        salida["destinatarios_unicos"] = conn.execute(
            f"SELECT COUNT(DISTINCT address) FROM address_records "
            f"WHERE role='DESTINATARIO' AND direction='SALIDA' AND msg_id IN {inq}"
        ).fetchone()[0]
        for v, c in conn.execute(
            f"SELECT verdict, COUNT(DISTINCT msg_id) FROM address_records "
            f"WHERE msg_id IN {inq} GROUP BY verdict").fetchall():
            salida["veredictos"][v] = c

    buzones_activos = conn.execute(
        "SELECT COUNT(DISTINCT address) FROM address_records "
        "WHERE is_internal=1 AND recorded_at>=? AND recorded_at<=?",
        (d_iso, h_iso)).fetchone()[0]
    buzones_externos = conn.execute(
        "SELECT COUNT(DISTINCT address) FROM address_records "
        "WHERE is_internal=0 AND recorded_at>=? AND recorded_at<=?",
        (d_iso, h_iso)).fetchone()[0]

    # hallazgos: los del periodo, restringidos al buzon si aplica
    if buzon == BUZON_TODOS:
        frows = conn.execute(
            """SELECT tipo, severidad, titulo, detalle, source, score, created_at, msg_id
               FROM findings WHERE created_at>=? AND created_at<=?
               ORDER BY created_at DESC LIMIT 200""",
            (d_iso, h_iso)).fetchall()
    else:
        fn = entry + exit_ids
        if fn:
            inq = _in(fn)
            frows = conn.execute(
                f"""SELECT tipo, severidad, titulo, detalle, source, score, created_at, msg_id
                    FROM findings WHERE msg_id IN {inq} AND created_at>=? AND created_at<=?
                    ORDER BY created_at DESC LIMIT 200""",
                (d_iso, h_iso)).fetchall()
        else:
            frows = []

    hallazgos = {
        "total": len(frows),
        "por_severidad": {},
        "por_tipo": {},
        "detalle_top": [
            {
                "msg_id": r[7], "tipo": r[0], "severidad": r[1],
                "titulo": r[2], "detalle": (r[3] or "")[:300],
                "source": r[4], "score": round(r[5], 1),
                "created_at": r[6],
            }
            for r in frows[:15]
        ],
    }
    for r in frows:
        hallazgos["por_severidad"][r[1]] = hallazgos["por_severidad"].get(r[1], 0) + 1
        hallazgos["por_tipo"][r[0]] = hallazgos["por_tipo"].get(r[0], 0) + 1

    # cuarentena/bloqueados del periodo
    if buzon == BUZON_TODOS:
        cuarentena = conn.execute(
            "SELECT COUNT(*) FROM messages "
            "WHERE status IN ('quarantine','block') AND quarantined_at>=? AND quarantined_at<=?",
            (d_iso, h_iso)).fetchone()[0]
    else:
        fn = entry + exit_ids
        if fn:
            cuarentena = conn.execute(
                f"SELECT COUNT(*) FROM messages "
                f"WHERE status IN ('quarantine','block') AND msg_id IN {_in(fn)}"
            ).fetchone()[0]
        else:
            cuarentena = 0

    conn.close()

    return {
        "buzon": buzon,
        "fecha": hasta.isoformat(),
        "periodo": {"desde": d_iso, "hasta": h_iso, "dias": days},
        "totales": {
            "entrada": entrada,
            "salida": salida,
            "buzones_activos": buzones_activos,
            "buzones_externos_contactados": buzones_externos,
            "cuarentena_bloqueados": cuarentena,
        },
        "hallazgos": hallazgos,
    }


def _hallazgos_csv(report: dict) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["msg_id", "tipo", "severidad", "titulo", "detalle",
                     "motor", "score", "fecha_hora"])
    for f in report["hallazgos"]["detalle_top"]:
        writer.writerow([
            f["msg_id"], f["tipo"], f["severidad"], f["titulo"],
            f["detalle"], f["source"], f["score"], f["created_at"],
        ])
    out = "\ufeff" + buf.getvalue()
    return out


# -------------------------------------------------------------------- render email
def _build_html(report: dict) -> str:
    t = report["totales"]
    ent, sal = t["entrada"], t["salida"]
    ve = "".join(f"<li>{k}: {v}</li>" for k, v in ent["veredictos"].items()) or "<li>sin datos</li>"
    vs = "".join(f"<li>{k}: {v}</li>" for k, v in sal["veredictos"].items()) or "<li>sin datos</li>"
    hs = report["hallazgos"]["por_severidad"]
    row_sev = "".join(
        f"<tr><td>{sev}</td><td>{c}</td></tr>" for sev, c in hs.items()
    ) or "<tr><td colspan=2>sin hallazgos</td></tr>"
    detalle = "".join(
        f"<tr><td>{f['severidad']}</td><td>{f['tipo']}</td><td>{f['titulo']}"
        f"<br><small>{f['detalle']}</small></td></tr>"
        for f in report["hallazgos"]["detalle_top"]
    ) or "<tr><td colspan=3>sin hallazgos en el periodo</td></tr>"
    buzon_label = "TODA LA ORGANIZACION" if report["buzon"] == BUZON_TODOS else report["buzon"]
    de = report["periodo"]["desde"][:16].replace("T", " ")
    ha = report["periodo"]["hasta"][:16].replace("T", " ")
    return f"""<div style="font-family:Arial,sans-serif;color:#222;max-width:720px;margin:auto">
<h2 style="color:#0a6ea8">Omni-ClearMail · Informe de correo</h2>
<p><b>Buzon:</b> {buzon_label} &nbsp;·&nbsp; <b>Periodo:</b> {de} → {ha}</p>
<h3 style="color:#0a6ea8">Totales del periodo</h3>
<table cellpadding="6" style="border-collapse:collapse;width:100%">
<tr style="background:#eef4f9"><th style="text-align:left">Métrica</th><th style="text-align:right">Valor</th></tr>
<tr><td>Correos ENTRANTES</td><td style="text-align:right">{ent['mensajes']}</td></tr>
<tr><td>Remitentes externos únicos</td><td style="text-align:right">{ent['remitentes_unicos']}</td></tr>
<tr><td>Correos SALIENTES</td><td style="text-align:right">{sal['mensajes']}</td></tr>
<tr><td>Destinatarios externos únicos</td><td style="text-align:right">{sal['destinatarios_unicos']}</td></tr>
<tr><td>Buzones activos (org)</td><td style="text-align:right">{t['buzones_activos']}</td></tr>
<tr><td>Buzones externos contactados</td><td style="text-align:right">{t['buzones_externos_contactados']}</td></tr>
<tr><td>En cuarentena/bloqueados</td><td style="text-align:right">{t['cuarentena_bloqueados']}</td></tr>
</table>
<h3 style="color:#0a6ea8">Veredictos de entrada</h3><ul>{ve}</ul>
<h3 style="color:#0a6ea8">Veredictos de salida</h3><ul>{vs}</ul>
<h3 style="color:#0a6ea8">Hallazgos: {report['hallazgos']['total']}</h3>
<table cellpadding="6" style="border-collapse:collapse;width:100%">
<tr style="background:#eef4f9"><th style="text-align:left">Severidad</th><th style="text-align:right">Cantidad</th></tr>
{row_sev}
</table>
<h3 style="color:#0a6ea8">Detalle (top hallazgos)</h3>
<table cellpadding="6" style="border-collapse:collapse;width:100%">
<tr style="background:#eef4f9"><th style="text-align:left">Severidad</th><th style="text-align:left">Tipo</th><th style="text-align:left">Detalle</th></tr>
{detalle}
</table>
<p style="color:#888;font-size:11px">Generado por Omni-CleanerMail · adjunto CSV con el detalle de hallazgos</p>
</div>"""


def _build_text(report: dict) -> str:
    t = report["totales"]
    buzon_label = "TODA LA ORGANIZACION" if report["buzon"] == BUZON_TODOS else report["buzon"]
    lins = [
        f"Informe Omni-ClearMail",
        f"Buzon: {buzon_label}",
        f"Periodo: {report['periodo']['desde'][:16]} -> {report['periodo']['hasta'][:16]}",
        "",
        "Totales del periodo",
        f"  Entrantes: {t['entrada']['mensajes']}",
        f"  Remitentes unicos: {t['entrada']['remitentes_unicos']}",
        f"  Salientes: {t['salida']['mensajes']}",
        f"  Destinatarios unicos: {t['salida']['destinatarios_unicos']}",
        f"  Buzones activos: {t['buzones_activos']}",
        f"  Buzones externos contactados: {t['buzones_externos_contactados']}",
        f"  Cuarentena/bloqueados: {t['cuarentena_bloqueados']}",
        "",
        f"Hallazgos: {report['hallazgos']['total']}",
        *[f"  {sev}: {c}" for sev, c in report['hallazgos']['por_severidad'].items()],
        "",
        "Detalle top hallazgos:",
        *[f"  [{f['severidad']}] {f['tipo']} - {f['titulo']}" for f in report['hallazgos']['detalle_top'][:10]],
        "",
        "Adjunto CSV con el detalle de hallazgos.",
    ]
    return "\n".join(lins)


# -------------------------------------------------------------------- envio
def _smtp_ok() -> bool:
    return bool(smtp_config()["host"])


def test_smtp() -> dict:
    """Valida conexion SMTP (y login si hay credenciales) con un HELO de prueba."""
    cfg = smtp_config()
    if not cfg["host"]:
        return {"ok": False, "detalle": "SMTP no configurado (LOOK_SMTP_HOST o panel)"}
    try:
        with smtplib.SMTP(cfg["host"], cfg["port"], timeout=15) as s:
            if cfg["port"] == 587:
                s.starttls()
            if cfg["user"]:
                s.login(cfg["user"], cfg["password"])
            s.ehlo()
        return {"ok": True, "detalle": f"SMTP {cfg['host']}:{cfg['port']} responde"}
    except Exception as e:
        return {"ok": False, "detalle": str(e)[:200]}


def send_report_email(buzon: str, email: str, days: int = None) -> dict:
    """Construye y envia el reporte del buzon al email indicado."""
    if not email or "@" not in email:
        _log_envio(buzon, email, days or config.REPORT_DEFAULT_DAYS, False,
                   "email destino no valido")
        return {"ok": False, "detalle": "email destino no valido"}
    if not _smtp_ok():
        _log_envio(buzon, email, days or config.REPORT_DEFAULT_DAYS, False,
                   "SMTP no configurado (LOOK_SMTP_HOST)")
        return {"ok": False, "detalle": "SMTP no configurado (LOOK_SMTP_HOST)"}
    try:
        report = build_report(buzon, days)
    except Exception as e:
        return {"ok": False, "detalle": f"error generando reporte: {e}"}
    try:
        cfg = smtp_config()
        msg = MIMEMultipart("mixed")
        msg["From"] = cfg["from"]
        msg["To"] = email
        label = "TODA LA ORGANIZACION" if buzon == BUZON_TODOS else buzon
        msg["Subject"] = f"Informe Omni-ClearMail · {label} · {report['periodo']['dias']}d"
        msg["Date"] = formatdate(localtime=True)
        msg.attach(MIMEText(_build_html(report), "html", "utf-8"))
        msg.attach(MIMEText(_build_text(report), "plain", "utf-8"))
        csv_part = MIMEText(_hallazgos_csv(report), "csv", "utf-8")
        csv_part.add_header("Content-Disposition", "attachment",
                            filename=f"hallazgos_{label.replace('@','_').replace('*','org')}_{report['periodo']['desde'][:10]}.csv")
        msg.attach(csv_part)

        with smtplib.SMTP(cfg["host"], cfg["port"], timeout=15) as s:
            if cfg["port"] == 587:
                s.starttls()
            if cfg["user"]:
                s.login(cfg["user"], cfg["password"])
            s.sendmail(cfg["from"], [email], msg.as_string())
        _log_envio(buzon, email, report.get("periodo", {}).get("dias", 7), True,
                   "enviado", report)
        return {"ok": True, "detalle": "informe enviado"}
    except Exception as e:
        _log_envio(buzon, email, report.get("periodo", {}).get("dias", 7), False,
                   str(e)[:300], report)
        return {"ok": False, "detalle": str(e)[:300]}


def _log_envio(buzon, email, dias, ok, detalle, report=None):
    resumen = None
    if report:
        resumen = {**report["totales"], "hallazgos": report["hallazgos"]["total"],
                   "periodo_desde": report["periodo"]["desde"]}
    conn = _conn()
    conn.execute(
        "INSERT INTO report_sent (buzon, email, dias, resumen, enviado_ok, detalle, sent_at) "
        "VALUES (?,?,?,?,?,?,?)",
        (buzon or "", email or "", dias, json.dumps(resumen, default=str) if resumen else None,
         1 if ok else 0, detalle, _now_iso()),
    )
    conn.commit()
    conn.close()


def list_envios(limit: int = 50) -> list:
    conn = _conn()
    rows = conn.execute(
        "SELECT * FROM report_sent ORDER BY sent_at DESC LIMIT ?",
        (min(limit, 500),)).fetchall()
    cols = [d[0] for d in conn.execute("SELECT * FROM report_sent LIMIT 1").description]
    conn.close()
    out = []
    for r in rows:
        d = dict(zip(cols, r))
        d["resumen"] = json.loads(d["resumen"]) if d["resumen"] else None
        out.append(d)
    return out


# -------------------------------------------------------------------- worker programado
def run_programados() -> dict:
    """Ejecuta ahora los reportes programados activos (salta la ventana de horario)."""
    configs = [c for c in load_config() if c["activo"]]
    resultados = []
    for c in configs:
        res = send_report_email(c["buzon"], c["email"])
        if res["ok"]:
            _marcar_enviado(c["buzon"])
        resultados.append({"buzon": c["buzon"], "email": c["email"], **res})
    return {"ejecutados": len(resultados), "ok": sum(1 for r in resultados if r["ok"]),
            "resultados": resultados}


def _marcar_enviado(buzon: str):
    conn = _conn()
    conn.execute("UPDATE report_config SET last_sent=? WHERE buzon=?",
                 (_now_iso(), buzon))
    conn.commit()
    conn.close()


def _worker_loop():
    while not _poller_stop.is_set():
        try:
            for c in load_config():
                due, _ = _due(c)
                if due:
                    res = send_report_email(c["buzon"], c["email"])
                    if res["ok"]:
                        _marcar_enviado(c["buzon"])
        except Exception:
            pass
        _poller_stop.wait(config.REPORT_POLL_SECONDS)


def start_poller() -> dict:
    global _poller_thread
    if _poller_thread and _poller_thread.is_alive():
        return {"poller_activo": True}
    _poller_stop.clear()
    _poller_thread = threading.Thread(target=_worker_loop, daemon=True, name="report-poller")
    _poller_thread.start()
    return {"poller_activo": True}


def stop_poller() -> dict:
    _poller_stop.set()
    return {"poller_activo": False}


def status() -> dict:
    configs = load_config()
    activos = [c for c in configs if c["activo"]]
    smtp = smtp_status()
    return {
        "configurados": len(configs),
        "activos": len(activos),
        "configs": configs,
        "poller_activo": bool(_poller_thread and _poller_thread.is_alive()),
        "smtp": smtp,
        "smtp_configurado": smtp["configurado"],
        "smtp_host": smtp["host"],
        "frecuencias": FRECUENCIAS,
        "buzones_conocidos": buzones_disponibles(),
    }