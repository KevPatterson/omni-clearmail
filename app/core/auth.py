"""Autenticacion y autorizacion: tokens, API keys, RBAC, rate limiting.

Implementa la seccion 1 de SECURITY-INDICATORS.md:
- Access tokens con expiracion corta (30 min max)
- Refresh tokens de un solo uso persistidos
- Comparacion en tiempo constante (hmac.compare_digest)
- API keys con hash SHA-256, prefix identificable, RBAC
- Rate limiting y bloqueo tras N intentos fallidos
"""
import hashlib
import hmac as hmac_mod
import json
import os
import secrets
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timezone

from app import config

_LOCK = threading.Lock()
_RATE = {}  # key -> {window_start, count}
_BLOCKED = {}  # key -> until_ts
LOGIN_ATTEMPTS = {}  # username -> [timestamps]

ROLES = ("SUPER_ADMIN", "ADMIN", "OPERATOR", "AUDITOR", "USER")
ROLE_PRIORITY = {r: i for i, r in enumerate(ROLES)}


def _now():
    return datetime.now(timezone.utc)


def _ts():
    return int(time.time())


def _conn():
    conn = sqlite3.connect(config.DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    conn = _conn()
    conn.execute(
        """CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'USER',
            created_at TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1
        )"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_hash TEXT UNIQUE NOT NULL,
            key_prefix TEXT NOT NULL,
            label TEXT NOT NULL,
            role TEXT NOT NULL,
            ttl_days INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT,
            revoked INTEGER NOT NULL DEFAULT 0,
            buzon TEXT
        )"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS refresh_tokens (
            token_hash TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            used INTEGER NOT NULL DEFAULT 0
        )"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS revoked_tokens (
            token_hash TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            revoked_at TEXT NOT NULL
        )"""
    )
    _migrate(conn)
    conn.commit()
    conn.close()
    _seed_users()


def _migrate(conn):
    """Migraciones ligeras de esquema para BDs existentes."""
    cols = [r[1] for r in conn.execute("PRAGMA table_info(api_keys)").fetchall()]
    if cols and "buzon" not in cols:
        conn.execute("ALTER TABLE api_keys ADD COLUMN buzon TEXT")


def _seed_users():
    if _user_by_name("admin"):
        return
    users = {
        "admin": ("SUPER_ADMIN", "admin123"),
        "operador": ("OPERATOR", "operador123"),
        "auditor": ("AUDITOR", "auditor123"),
        "usuario1": ("USER", "usuario123"),
    }
    for name, (role, pw) in users.items():
        _create_user(name, pw, role)


def pbkdf2(password: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 120_000).hex()


def _hash_password(password: str):
    salt = hashlib.sha256(secrets.token_hex(16).encode()).hexdigest()[:32]
    return f"{salt}${pbkdf2(password, salt.encode())}"


def _verify_password(password: str, stored: str) -> bool:
    salt, digest = stored.split("$")
    computed = pbkdf2(password, salt.encode())
    return hmac_mod.compare_digest(computed, digest)


def _user_by_name(username: str):
    conn = _conn()
    row = conn.execute(
        "SELECT id, username, password_hash, role, active FROM users WHERE username=?", (username,)
    ).fetchone()
    conn.close()
    if not row:
        return None
    return {"id": row[0], "username": row[1], "password_hash": row[2], "role": row[3], "active": row[4]}


def _create_user(username, password, role):
    conn = _conn()
    conn.execute(
        "INSERT INTO users (username, password_hash, role, created_at, active) VALUES (?,?,?,?,1)",
        (username, _hash_password(password), role, _now().isoformat()),
    )
    conn.commit()
    conn.close()


def rate_limit(key: str, limit_per_min: int, for_auth: bool = False) -> bool:
    """Devuelve True si la peticion supera el limite (debe rechazarse)."""
    now = _ts()
    if _BLOCKED.get(key, 0) > now:
        return True
    with _LOCK:
        entry = _RATE.get(key)
        if entry is None or entry[0] < now - 60:
            _RATE[key] = [now, 1]
            return False
        entry[1] += 1
        return entry[1] > limit_per_min


def check_blocked(username: str) -> bool:
    if username not in LOGIN_ATTEMPTS:
        return False
    LOGIN_ATTEMPTS[username] = [t for t in LOGIN_ATTEMPTS[username] if t > _ts() - 900]
    return len(LOGIN_ATTEMPTS[username]) >= config.MAX_LOGIN_ATTEMPTS


def record_failed_login(username: str):
    if username not in LOGIN_ATTEMPTS:
        LOGIN_ATTEMPTS[username] = []
    LOGIN_ATTEMPTS[username].append(_ts())


def clear_login_attempts(username: str):
    LOGIN_ATTEMPTS.pop(username, None)


class AuthError(Exception):
    def __init__(self, message, status=401):
        super().__init__(message)
        self.status = status


def login(username: str, password: str) -> dict:
    user = _user_by_name(username)
    if user is None or not user["active"]:
        record_failed_login(username)
        raise AuthError("Credenciales invalidas", 401)
    if check_blocked(username):
        raise AuthError("Demasiados intentos fallidos. Bloqueado temporalmente.", 429)
    if not _verify_password(password, user["password_hash"]):
        record_failed_login(username)
        raise AuthError("Credenciales invalidas", 401)
    clear_login_attempts(username)

    access = _issue_token(user["username"], user["role"], config.ACCESS_TOKEN_MINUTES * 60)
    refresh = _issue_refresh(user["username"])
    return {"access_token": access, "refresh_token": refresh, "expires_in": config.ACCESS_TOKEN_MINUTES * 60, "role": user["role"]}


def _issue_token(username: str, role: str, ttl_seconds: int) -> str:
    now = _ts()
    payload = {
        "sub": username,
        "role": role,
        "iat": now,
        "exp": now + ttl_seconds,
        "jti": uuid.uuid4().hex,
    }
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    sig = hmac_mod.new(config.HMAC_SECRET.encode(), body, hashlib.sha256).hexdigest()
    return f"omni-cm.{base64url(body)}.{base64url(sig)}"


def base64url(data) -> str:
    if isinstance(data, str):
        data = data.encode()
    from base64 import urlsafe_b64encode
    return urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64decode(s: str) -> bytes:
    from base64 import urlsafe_b64decode
    pad = "=" * (-len(s) % 4)
    return urlsafe_b64decode(s + pad)


def verify_token(token: str) -> dict:
    """Valida access token. Devuelve claims o lanza AuthError."""
    try:
        _, body, sig = token.split(".")
    except ValueError:
        raise AuthError("Token malformado", 401)
    expected = base64url(hmac_mod.new(config.HMAC_SECRET.encode(), _b64decode(body), hashlib.sha256).hexdigest())
    if not hmac_mod.compare_digest(sig, expected):
        raise AuthError("Firma de token invalida", 401)
    claims = json.loads(_b64decode(body))
    if claims["exp"] < _ts():
        raise AuthError("Token expirado", 401)
    if _is_revoked(claims):
        raise AuthError("Token revocado (logout server-side)", 401)
    return claims


def _is_revoked(claims: dict) -> bool:
    conn = _conn()
    row = conn.execute(
        "SELECT 1 FROM revoked_tokens WHERE token_hash=?",
        (hmac_mod.new(config.HMAC_SECRET.encode(), terms_payload(claims), hashlib.sha256).hexdigest(),),
    ).fetchone()
    conn.close()
    return row is not None


def terms_payload(claims: dict) -> bytes:
    return json.dumps(claims, sort_keys=True, separators=(",", ":")).encode()


def logout(claims: dict):
    conn = _conn()
    conn.execute(
        "INSERT OR REPLACE INTO revoked_tokens (token_hash, username, revoked_at) VALUES (?,?,?)",
        (hmac_mod.new(config.HMAC_SECRET.encode(), terms_payload(claims), hashlib.sha256).hexdigest(),
         claims["sub"], _now().isoformat()),
    )
    conn.commit()
    conn.close()


def _issue_refresh(username: str) -> str:
    from datetime import timedelta
    token = secrets.token_urlsafe(48)
    digest = hashlib.sha256(token.encode()).hexdigest()
    conn = _conn()
    conn.execute(
        "INSERT INTO refresh_tokens (token_hash, username, created_at, expires_at, used) VALUES (?,?,?,?,0)",
        (digest, username, _now().isoformat(), (_now() + timedelta(days=config.REFRESH_TOKEN_TTL_DAYS)).isoformat(),),
    )
    conn.commit()
    conn.close()
    return token


def refresh_access(refresh_token: str) -> dict:
    digest = hashlib.sha256(refresh_token.encode()).hexdigest()
    conn = _conn()
    row = conn.execute(
        "SELECT username, expires_at, used FROM refresh_tokens WHERE token_hash=?", (digest,)
    ).fetchone()
    if not row:
        conn.close()
        raise AuthError("Refresh token invalido", 401)
    username, expires_at, used = row
    if used:
        conn.close()
        raise AuthError("Refresh token ya utilizado (single-use)", 401)
    if datetime.fromisoformat(expires_at).replace(tzinfo=timezone.utc) < _now():
        conn.close()
        raise AuthError("Refresh token expirado", 401)
    conn.execute("UPDATE refresh_tokens SET used=1 WHERE token_hash=?", (digest,))
    conn.commit()
    conn.close()
    user = _user_by_name(username)
    if not user or not user["active"]:
        raise AuthError("Usuario inactivo", 401)
    access = _issue_token(username, user["role"], config.ACCESS_TOKEN_MINUTES * 60)
    return {"access_token": access, "refresh_token": _issue_refresh(username), "role": user["role"]}


def generate_api_key(label: str, role: str, ttl_days: int = None, buzon: str = None,
                     admin_claims=None) -> dict:
    """Genera API key con hash SHA-256 y prefijo identificable.

    `buzon` (opcional) restringe la clave a un buzon: se usa para auto-reportes M2M
    via `/api/reporte-buzon/mio`.
    """
    key = "omni-cm_" + secrets.token_urlsafe(32)
    key_hash = hashlib.sha256(key.encode()).hexdigest()
    ttl_days = ttl_days or config.API_KEY_TTL_DAYS
    expires = None
    if ttl_days:
        from datetime import timedelta
        expires = (_now() + timedelta(days=ttl_days)).isoformat()
    conn = _conn()
    conn.execute(
        "INSERT INTO api_keys (key_hash, key_prefix, label, role, ttl_days, created_at, expires_at, revoked, buzon) "
        "VALUES (?,?,?,?,?,?,?,0,?)",
        (key_hash, "omni-cm_", label, role, ttl_days, _now().isoformat(), expires, buzon or None),
    )
    conn.commit()
    conn.close()
    return {"api_key": key, "label": label, "role": role, "expires_at": expires,
            "buzon": buzon or None}


def list_api_keys():
    conn = _conn()
    rows = conn.execute(
        "SELECT id, key_prefix, label, role, ttl_days, created_at, expires_at, revoked, buzon "
        "FROM api_keys ORDER BY id"
    ).fetchall()
    conn.close()
    return [
        {"id": r[0], "prefix": r[1], "label": r[2], "role": r[3], "ttl_days": r[4],
         "created_at": r[5], "expires_at": r[6], "revoked": r[7], "buzon": r[8]}
        for r in rows
    ]


def revoke_api_key(key_id: int):
    conn = _conn()
    conn.execute("UPDATE api_keys SET revoked=1 WHERE id=?", (key_id,))
    conn.commit()
    conn.close()


def authenticate_api_key(api_key: str) -> dict:
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    conn = _conn()
    row = conn.execute(
        "SELECT label, role, expires_at, revoked, buzon FROM api_keys WHERE key_hash=?",
        (key_hash,)
    ).fetchone()
    conn.close()
    if not row:
        raise AuthError("API key invalida", 401)
    label, role, expires_at, revoked, buzon = row
    if revoked:
        raise AuthError("API key revocada", 403)
    if expires_at and datetime.fromisoformat(expires_at).replace(tzinfo=timezone.utc) < _now():
        raise AuthError("API key expirada", 403)
    return {"label": label, "role": role, "auth_type": "api_key", "buzon": buzon}


def require_role(claims: dict, *allowed_roles: str):
    role = claims.get("role")
    if role is None:
        raise AuthError("Sin rol", 403)
    if role == "SUPER_ADMIN":
        return
    if role not in allowed_roles:
        raise AuthError("Permisos insuficientes: requiere " + ", ".join(allowed_roles), 403)