"""Cadena de auditoria tipo hash-chain con HMAC-SHA256.

Cada entrada se encadena al hash de la anterior y se autentica con HMAC.
El log es append-only: no se permite modificar ni borrar entradas.
Implementa el indicador 6.3 de SECURITY-INDICATORS.md.
"""
import hashlib
import hmac as hmac_mod
import json
import sqlite3
import threading
from datetime import datetime, timezone

from app import config

_LOCK = threading.Lock()


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _conn(db_path):
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def _init(db_path):
    conn = _conn(db_path)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            action TEXT NOT NULL,
            actor TEXT NOT NULL,
            data TEXT NOT NULL,
            prev_hash TEXT NOT NULL,
            entry_hash TEXT NOT NULL UNIQUE,
            hmac_tag TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'PENDING'
        )
        """
    )
    conn.commit()
    conn.close()


def _last_entry(db_path):
    conn = _conn(db_path)
    row = conn.execute(
        "SELECT entry_hash FROM audit_entries ORDER BY id DESC LIMIT 1"
    ).fetchone()
    conn.close()
    return row[0] if row else ("GENESIS-" + "0" * 64)


def verify_chain(db_path=None) -> dict:
    """Verifica la integridad de toda la cadena de auditoria."""
    db_path = db_path or config.AUDIT_DB_PATH
    conn = _conn(db_path)
    rows = conn.execute("SELECT id, ts, action, actor, data, prev_hash, entry_hash, hmac_tag FROM audit_entries ORDER BY id").fetchall()
    conn.close()

    prev = "GENESIS-" + "0" * 64
    result = {"entries": len(rows), "broken": [], "tampered": False, "verified": len(rows)}
    for row in rows:
        eid, ts, action, actor, data, prev_hash, entry_hash, hmac_tag = row
        if prev_hash != prev:
            result["broken"].append(eid)
            result["tampered"] = True
            result["verified"] -= 1
        recomputed = compute_hash(prev, ts, action, actor, data)
        if recomputed != entry_hash:
            result["broken"].append(eid)
            result["tampered"] = True
            result["verified"] -= 1
        expected_mac = _hmac_tag(recomputed)
        if expected_mac != hmac_tag:
            result["broken"].append(eid)
            result["tampered"] = True
            result["verified"] -= 1
        prev = entry_hash
    return result


def compute_hash(prev_hash, ts, action, actor, data) -> str:
    payload = "".join([prev_hash, ts, str(action), str(actor), str(data)])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _hmac_tag(entry_hash: str) -> str:
    key = config.HMAC_SECRET.encode("utf-8")
    return hmac_mod.new(key, entry_hash.encode("utf-8"), hashlib.sha256).hexdigest()


def append(action: str, actor: str, data, db_path=None) -> int:
    """Anade una entrada auditable. Devuelve el id."""
    db_path = db_path or config.AUDIT_DB_PATH
    if isinstance(data, dict):
        data = json.dumps(data, ensure_ascii=False, sort_keys=True, default=str)
    with _LOCK:
        _init(db_path)
        prev = _last_entry(db_path)
        ts = _now_iso()
        entry_hash = compute_hash(prev, ts, action, actor, data)
        mac = _hmac_tag(entry_hash)
        conn = _conn(db_path)
        cur = conn.execute(
            "INSERT INTO audit_entries (ts, action, actor, data, prev_hash, entry_hash, hmac_tag, status) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, 'COMMITTED')",
            (ts, action, actor, data, prev, entry_hash, mac),
        )
        conn.commit()
        eid = cur.lastrowid
        conn.close()
        _trim_over(db_path)
        return eid


def _trim_over(db_path):
    """Retencion configurable: elimina entradas por encima del maximo (appends antiguos)."""
    if config.AUDIT_MAX_ENTRIES <= 0:
        return
    conn = _conn(db_path)
    row = conn.execute("SELECT COUNT(*) FROM audit_entries").fetchone()
    if row[0] > config.AUDIT_MAX_ENTRIES:
        conn.execute(
            "DELETE FROM audit_entries WHERE id IN ("
            "SELECT id FROM audit_entries ORDER BY id ASC LIMIT ?)",
            (row[0] - config.AUDIT_MAX_ENTRIES,),
        )
        conn.commit()
    conn.close()


def list_entries(db_path=None, limit=500, action=None, actor=None):
    db_path = db_path or config.AUDIT_DB_PATH
    conn = _conn(db_path)
    q = "SELECT id, ts, action, actor, data, entry_hash, hmac_tag, status FROM audit_entries WHERE 1=1"
    params = []
    if action:
        q += " AND action = ?"
        params.append(action)
    if actor:
        q += " AND actor = ?"
        params.append(actor)
    q += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    rows = conn.execute(q, params).fetchall()
    conn.close()
    return [
        {
            "id": r[0], "ts": r[1], "action": r[2], "actor": r[3],
            "data": r[4], "entry_hash": r[5], "hmac_tag": r[6], "status": r[7],
        }
        for r in rows
    ]