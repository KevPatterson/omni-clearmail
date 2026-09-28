"""Registro de direcciones de correo de entrada y salida (address ledger).

Capa 5 — Reporte y dashboard. Registra TODAS las direcciones que aparecen
en cada mensaje procesado (remitente y destinatarios) junto con el flujo
(ENTRADA/SALIDA), si pertenece a la organizacion (interna), el veredicto y
el score. Provee resumenes agregados y exportacion en CSV/JSON para generar
el reporte de direcciones exigido por el encargo.
"""
import csv
import io
import json
import sqlite3
from datetime import datetime, timezone

from app import config

ROLE_REMITENTE = "REMITENTE"
ROLE_DESTINATARIO = "DESTINATARIO"
DIR_ENTRADA = "ENTRADA"
DIR_SALIDA = "SALIDA"


def _conn():
    conn = sqlite3.connect(config.DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_addressbook():
    conn = _conn()
    conn.execute(
        """CREATE TABLE IF NOT EXISTS address_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            msg_id TEXT NOT NULL,
            address TEXT NOT NULL,
            role TEXT NOT NULL,
            direction TEXT NOT NULL,
            is_internal INTEGER NOT NULL DEFAULT 0,
            domain TEXT NOT NULL,
            subject TEXT,
            verdict TEXT NOT NULL,
            score REAL NOT NULL DEFAULT 0,
            recorded_at TEXT NOT NULL
        )"""
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_addr_recorded ON address_records (recorded_at)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_addr_direction ON address_records (direction)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_addr_email ON address_records (address)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_addr_domain ON address_records (domain)"
    )
    conn.commit()
    conn.close()


def _domain_of(address: str) -> str:
    if not address or "@" not in address:
        return "sin-dominio"
    return address.rsplit("@", 1)[-1].lower()


def is_internal_org(address: str) -> bool:
    domain = _domain_of(address)
    return domain in config.INTERNAL_DOMAINS or domain == "corp.demo"


def record_message_addresses(msg: dict, fused: dict, direction: str = DIR_ENTRADA):
    """Registra remitente y destinatarios de un mensaje en el ledger.

    `direction` indica el flujo del mensaje respecto a la organizacion:
    ENTRADA (correo recibido) o SALIDA (correo enviado por la org).
    """
    direction = direction.upper()
    if direction not in (DIR_ENTRADA, DIR_SALIDA):
        direction = DIR_ENTRADA

    now = datetime.now(timezone.utc).isoformat()
    subject = msg.get("subject", "")
    verdict = fused.get("vote", "deliver")
    score = fused.get("composite_score", 0)

    rows = []
    sender = (msg.get("sender") or "").strip()
    if sender:
        rows.append((
            msg.get("msg_id", ""), sender, ROLE_REMITENTE, direction,
            int(is_internal_org(sender)), _domain_of(sender), subject,
            verdict, score, now,
        ))
    recipients = msg.get("recipients") or []
    for r in dict.fromkeys(recipients):
        r = r.strip()
        if not r:
            continue
        rows.append((
            msg.get("msg_id", ""), r, ROLE_DESTINATARIO, direction,
            int(is_internal_org(r)), _domain_of(r), subject,
            verdict, score, now,
        ))

    if not rows:
        return 0

    conn = _conn()
    conn.executemany(
        """INSERT INTO address_records
           (msg_id, address, role, direction, is_internal, domain, subject,
            verdict, score, recorded_at)
           VALUES (?,?,?,?,?,?,?,?,?,?)""",
        rows,
    )
    conn.commit()
    conn.close()
    return len(rows)


def list_addresses(direction=None, role=None, domain=None, verdict=None,
                   search=None, internal=None, msg_id=None, limit=1000) -> list:
    conn = _conn()
    q = "SELECT * FROM address_records WHERE 1=1"
    params = []
    if direction:
        q += " AND direction = ?"
        params.append(direction.upper())
    if role:
        q += " AND role = ?"
        params.append(role.upper())
    if domain:
        q += " AND domain LIKE ?"
        params.append(f"%{domain.lower()}%")
    if verdict:
        q += " AND verdict = ?"
        params.append(verdict)
    if internal is not None:
        q += " AND is_internal = ?"
        params.append(1 if internal else 0)
    if msg_id:
        q += " AND msg_id = ?"
        params.append(msg_id)
    if search:
        q += " AND address LIKE ?"
        params.append(f"%{search.lower()}%")
    q += " ORDER BY recorded_at DESC LIMIT ?"
    params.append(min(limit, 5000))
    rows = conn.execute(q, params).fetchall()
    cols = [d[0] for d in conn.execute("SELECT * FROM address_records LIMIT 1").description]
    conn.close()
    return [dict(zip(cols, r)) for r in rows]


def address_summary() -> dict:
    """Agregados para el dashboard del informe de direcciones."""
    conn = _conn()
    total = conn.execute("SELECT COUNT(*) FROM address_records").fetchone()[0]

    def _count(q, p=()):
        return conn.execute(q, p).fetchone()[0]

    entrantes = _count("SELECT COUNT(DISTINCT address) FROM address_records WHERE direction=?", (DIR_ENTRADA,))
    salientes = _count("SELECT COUNT(DISTINCT address) FROM address_records WHERE direction=?", (DIR_SALIDA,))
    internas = _count("SELECT COUNT(DISTINCT address) FROM address_records WHERE is_internal=1")
    externas = _count("SELECT COUNT(DISTINCT address) FROM address_records WHERE is_internal=0")

    top_dominios = conn.execute(
        """SELECT domain, COUNT(*) c FROM address_records
           WHERE domain != 'sin-dominio' GROUP BY domain ORDER BY c DESC LIMIT 8"""
    ).fetchall()

    top_direcciones = conn.execute(
        """SELECT address, direction, COUNT(*) c, MAX(score) s
           FROM address_records GROUP BY address, direction
           ORDER BY c DESC LIMIT 10"""
    ).fetchall()

    por_veredicto = conn.execute(
        "SELECT verdict, COUNT(*) FROM address_records GROUP BY verdict"
    ).fetchall()

    ultimo = conn.execute(
        "SELECT MAX(recorded_at) FROM address_records"
    ).fetchone()[0]
    conn.close()

    return {
        "total_registros": total,
        "direcciones_entrantes": entrantes,
        "direcciones_salientes": salientes,
        "direcciones_internas": internas,
        "direcciones_externas": externas,
        "dominios": {d: c for d, c in top_dominios},
        "top_direcciones": [
            {"address": a, "direction": d, "veces": c, "max_score": round(s, 1)}
            for a, d, c, s in top_direcciones
        ],
        "por_veredicto": {v: c for v, c in por_veredicto},
        "ultimo_registro": ultimo,
        "fecha": datetime.now(timezone.utc).isoformat(),
    }


def build_csv(direction=None, role=None, domain=None, verdict=None,
              search=None, internal=None, msg_id=None) -> str:
    """Genera el CSV exportable del informe de direcciones."""
    rows = list_addresses(direction=direction, role=role, domain=domain,
                          verdict=verdict, search=search, internal=internal,
                          msg_id=msg_id, limit=5000)
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "id", "msg_id", "direccion", "rol", "flujo", "interna",
        "dominio", "asunto", "veredicto", "score", "fecha_hora",
    ])
    for r in rows:
        writer.writerow([
            r["id"], r["msg_id"], r["address"], r["role"], r["direction"],
            "SI" if r["is_internal"] else "NO", r["domain"], r["subject"] or "",
            r["verdict"], r["score"], r["recorded_at"],
        ])
    return buf.getvalue()


def build_json(direction=None, role=None, domain=None, verdict=None,
               search=None, internal=None, msg_id=None) -> str:
    return json.dumps({
        "reporte": "direcciones-correo",
        "generado": datetime.now(timezone.utc).isoformat(),
        "registros": list_addresses(direction=direction, role=role, domain=domain,
                                    verdict=verdict, search=search, internal=internal,
                                    msg_id=msg_id, limit=5000),
    }, ensure_ascii=False, indent=2)