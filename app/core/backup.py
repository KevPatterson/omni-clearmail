"""Backup cifrado AES-256-GCM automatizado (core/backup.py analoga).

Cifra la base de datos SQLite con AES-256-GCM usando una clave derivada
de HMAC_SECRET. Retencion configurable via LOOK_BACKUP_RETENTION_DAYS.
"""
import hashlib
import os
import sqlite3
from datetime import datetime, timezone

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app import config


def _key() -> bytes:
    return hashlib.sha256(config.HMAC_SECRET.encode()).digest()


def _backup_dir():
    d = config.DATA_DIR / "backups"
    d.mkdir(parents=True, exist_ok=True)
    return d


def create_backup() -> dict:
    """Copia la BD y la cifra AES-256-GCM."""
    src = config.DB_PATH
    if not os.path.exists(src):
        return {"ok": False, "error": "BD no existe"}
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dst = _backup_dir() / f"omnimail_backup_{ts}.bin"
    raw = open(src, "rb").read()
    aes = AESGCM(_key())
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, raw, None)
    dst.write_bytes(nonce + ct)
    sha = hashlib.sha256(raw).hexdigest()
    _prune_old()
    return {"ok": True, "fichero": str(dst), "sha256_origen": sha, "bytes": len(ct)}


def restore_backup(path) -> dict:
    """Restaura y verifica integrity (GCM-tag)."""
    data = open(path, "rb").read()
    nonce, ct = data[:12], data[12:]
    aes = AESGCM(_key())
    try:
        raw = aes.decrypt(nonce, ct, None)
    except Exception:
        return {"ok": False, "error": "tag GCM invalido o clave incorrecta"}
    open(config.DB_PATH, "wb").write(raw)
    return {"ok": True, "restaurado_a": config.DB_PATH}


def _prune_old():
    if config.BACKUP_RETENTION_DAYS <= 0:
        return
    cutoff = datetime.now(timezone.utc).timestamp() - config.BACKUP_RETENTION_DAYS * 86400
    for f in _backup_dir().glob("*.bin"):
        if f.stat().st_mtime < cutoff or f.stat().st_mtime < cutoff:
            try:
                f.unlink()
            except OSError:
                pass


def status() -> dict:
    files = sorted(_backup_dir().glob("*.bin"))
    return {
        "backups": [{"nombre": f.name, "bytes": f.stat().st_size} for f in files],
        "retencion_dias": config.BACKUP_RETENTION_DAYS,
        "dir": str(_backup_dir()),
    }


def restore_test() -> dict:
    files = sorted(_backup_dir().glob("*.bin"))
    if not files:
        return {"ok": False, "error": "sin backups"}
    return restore_backup(str(files[-1]))