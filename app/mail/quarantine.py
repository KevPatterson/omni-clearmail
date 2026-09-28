"""Cuarentena y purificacion (Capa 4).

Almacena mensajes retenidos, registra acciones en la cadena de auditoria
y provee autoservicio de liberacion para usuarios.
"""
import json
import sqlite3
from datetime import datetime, timezone

from app import config
from app.core import hashchain
from app.mail import addressbook, findings, scoring

STATUS = ("quarantine", "delivered", "blocked", "released", "expunged")


def _conn():
    conn = sqlite3.connect(config.DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_quarantine():
    conn = _conn()
    conn.execute(
        """CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            msg_id TEXT UNIQUE NOT NULL,
            subject TEXT NOT NULL,
            sender TEXT NOT NULL,
            recipients TEXT NOT NULL,
            body TEXT,
            links TEXT,
            attachments TEXT,
            engine_results TEXT,
            composite_score REAL NOT NULL,
            vote TEXT NOT NULL,
            status TEXT NOT NULL,
            quarantined_at TEXT NOT NULL,
            released_at TEXT,
            released_by TEXT,
            user_risk REAL DEFAULT 0
        )"""
    )
    conn.commit()
    conn.close()


def save_message(msg: dict, engine_results: dict, fused: dict, status: str = None,
                 direction: str = "ENTRADA"):
    if status is None:
        status = fused["vote"] if fused["vote"] in ("quarantine", "block") else "delivered"
        if fused["vote"] == "deliver":
            status = "delivered"
    conn = _conn()
    conn.execute(
        """INSERT OR REPLACE INTO messages
           (msg_id, subject, sender, recipients, body, links, attachments, engine_results,
            composite_score, vote, status, quarantined_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            msg["msg_id"], msg.get("subject", ""), msg.get("sender", ""),
            json.dumps(msg.get("recipients", [])), msg.get("body", ""),
            json.dumps(msg.get("links", [])), json.dumps(msg.get("attachments", [])),
            json.dumps({k: v for k, v in engine_results.items()}, default=str),
            fused["composite_score"], fused["vote"], status,
            datetime.now(timezone.utc).isoformat(),
        ),
    )
    conn.commit()
    conn.close()
    scoring.record_verdict(msg["msg_id"], engine_results, fused)
    addressbook.record_message_addresses(msg, fused, direction=direction)
    findings.record_findings(msg, engine_results, fused)
    return status


def get_message(msg_id: str):
    conn = _conn()
    row = conn.execute("SELECT * FROM messages WHERE msg_id=?", (msg_id,)).fetchone()
    cols = [d[0] for d in conn.description] if row else []
    conn.close()
    if not row:
        return None
    return dict(zip(cols, row))


def list_messages(status=None, limit=200, search=None, msg_id=None):
    conn = _conn()
    q = "SELECT * FROM messages WHERE 1=1"
    params = []
    if status:
        q += " AND status = ?"
        params.append(status)
    if msg_id:
        q += " AND msg_id = ?"
        params.append(msg_id)
    if search:
        q += " AND (subject LIKE ? OR sender LIKE ? OR recipients LIKE ?)"
        params += [f"%{search}%"] * 3
    q += " ORDER BY quarantined_at DESC LIMIT ?"
    params.append(limit)
    rows = conn.execute(q, params).fetchall()
    cols = [d[0] for d in conn.execute("SELECT * FROM messages LIMIT 1").description]
    conn.close()
    return [dict(zip(cols, r)) for r in rows]


def count_by_status():
    conn = _conn()
    rows = conn.execute("SELECT status, COUNT(*) FROM messages GROUP BY status").fetchall()
    conn.close()
    return {s: c for s, c in rows}


def quarantine_summary() -> dict:
    """Agregados para el dashboard de cuarentena."""
    conn = _conn()
    total = conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0]

    def _one(q, p=()):
        return conn.execute(q, p).fetchone()[0]

    bloqueados = _one("SELECT COUNT(*) FROM messages WHERE status='blocked'")
    en_cuarentena = _one("SELECT COUNT(*) FROM messages WHERE status='quarantine'")
    liberados = _one("SELECT COUNT(*) FROM messages WHERE status='released'")
    entregados = _one("SELECT COUNT(*) FROM messages WHERE status='delivered'")
    purgados = _one("SELECT COUNT(*) FROM messages WHERE status='expunged'")
    pendientes_usuario = _one(
        "SELECT COUNT(*) FROM messages WHERE status='quarantine' AND user_risk=0"
    )
    last24 = datetime.now(timezone.utc).replace(
        hour=0, minute=0, second=0, microsecond=0
    ).isoformat()
    ultimas24h = _one("SELECT COUNT(*) FROM messages WHERE quarantined_at >= ?", (last24,))
    score_medio = _one("SELECT AVG(composite_score) FROM messages") or 0
    score_max = _one("SELECT MAX(composite_score) FROM messages") or 0
    riesgo_alto = _one("SELECT COUNT(*) FROM messages WHERE composite_score >= 80")
    conn.close()
    return {
        "total": total,
        "por_estado": {
            "quarantine": en_cuarentena,
            "blocked": bloqueados,
            "released": liberados,
            "delivered": entregados,
            "expunged": purgados,
        },
        "bloqueados": bloqueados,
        "en_cuarentena": en_cuarentena,
        "liberados": liberados,
        "entregados": entregados,
        "purgados": purgados,
        "pendientes_usuario": pendientes_usuario,
        "ultimas24h": ultimas24h,
        "score_medio": round(score_medio, 1),
        "score_max": round(score_max, 1),
        "riesgo_alto": riesgo_alto,
        "fecha": datetime.now(timezone.utc).isoformat(),
    }


def action_release(msg_id: str, actor: str, reason: str = "") -> dict:
    """Libera un mensaje de la cuarentena (autoservicio o admin). Registra hash-chain."""
    msg = get_message(msg_id)
    if not msg:
        return {"ok": False, "error": "mensaje no existe"}
    if msg["status"] not in ("quarantine", "blocked"):
        return {"ok": False, "error": f"estado {msg['status']} no liberable"}
    conn = _conn()
    conn.execute(
        "UPDATE messages SET status='released', released_at=?, released_by=? WHERE msg_id=?",
        (datetime.now(timezone.utc).isoformat(), actor, msg_id),
    )
    conn.commit()
    conn.close()
    hashchain.append(
        "release_message", actor,
        {"msg_id": msg_id, "subject": msg["subject"], "motivo": reason},
    )
    return {"ok": True}


def action_expunge(msg_id: str, actor: str, reason: str = "") -> dict:
    """Elimina definitivamente de cuarentena. Registra hash-chain."""
    msg = get_message(msg_id)
    if not msg:
        return {"ok": False, "error": "mensaje no existe"}
    conn = _conn()
    conn.execute("UPDATE messages SET status='expunged' WHERE msg_id=?", (msg_id,))
    conn.commit()
    conn.close()
    hashchain.append(
        "expunge_message", actor,
        {"msg_id": msg_id, "subject": msg["subject"], "motivo": reason},
    )
    return {"ok": True}


def request_release(msg_id: str, actor: str):
    """Solicitud de liberacion de un usuario final."""
    hashchain.append("request_release", actor, {"msg_id": msg_id})
    return {"ok": True, "msg": "solicitud registrada, pendiente de aprobacion"}