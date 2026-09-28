"""License Integration Layer (LIL) — integracion OMNI-Lic.

Implementa PROMPT_INTEGRACION_LICENCIA.md:
- Generacion de solicitud SOLICITUD-OMNI-LIC-1.0 con binding real del host
- Carga y validacion offline de license.json (7 grupos de verificacion)
- Canonizacion JSON firma Ed25519 (sort_keys, compacto, exclude id/firma_hex)
- Hardware binding, heartbeat, notificaciones 30/15/7/3/2/1 y bloqueo por expiracion
"""
import hashlib
import json
import hmac as hmac_mod
import os
import secrets
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from app import config
from app.core import hardware, semiprime

_LOCK = threading.Lock()
_license_cache = {}

NOTIFY_THRESHOLDS = [30, 15, 7, 3, 2, 1]


def _now():
    return datetime.now(timezone.utc)


def _conn():
    conn = sqlite3.connect(config.DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def identity_sistema() -> str:
    return hardware.identity_sistema("Omni-CleanerMail")


def canonical_json(data: dict) -> str:
    """Canonizacion identica al emisor: sort_keys, separadores compactos, sin escape."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


# ---------------------------------------------------------------- public key
# Clave pública del emisor OMNI-Lic (canónica, exportada por OMNI-Lic).
# Las licencias SOLO las emite OMNI-Lic: este software nunca autofirma.
EMISOR_PUB_PEM_DEFAULT = """-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAwsDC2oySI73Ol7Ju6jlatToCAVDRZ8cz9lbXNIQ9pVY=
-----END PUBLIC KEY-----"""


def load_public_key() -> Ed25519PublicKey:
    """Clave pública del emisor OMNI-Lic.

    Se embebe la clave canónica del emisor central. Si existe `emisor_pub.pem`
    en disco, se exige que coincida con la canónica (garantía de concordancia);
    en caso contrario se usa la embebida.
    """
    pem = EMISOR_PUB_PEM_DEFAULT.encode()
    path = config.LICENSE_PUBLIC_KEY_PATH
    if path.exists():
        on_disk = path.read_bytes()
        if on_disk.strip() != pem.strip():
            raise ValueError(
                "emisor_pub.pem no coincide con la clave pública canónica del emisor "
                "OMNI-Lic. Las licencias SOLO se obtienen de OMNI-Lic "
                "(licencias@omni.group). Use la clave exportada por OMNI-Lic."
            )
    return serialization.load_pem_public_key(pem)


def _sig_payload(license_data: dict) -> dict:
    """Payload canonico a firmar: excluye 'id' y 'firma_hex'."""
    return {k: v for k, v in license_data.items() if k not in ("id", "firma_hex")}


def _verify_signature(license_data: dict) -> bool:
    pub = load_public_key()
    payload = canonical_json(_sig_payload(license_data)).encode("utf-8")
    try:
        pub.verify(bytes.fromhex(license_data["firma_hex"]), payload)
        return True
    except (InvalidSignature, ValueError, KeyError):
        return False


# ---------------------------------------------------------------- generacion solicitud
def generate_solicitud(cliente_nombre: str = "", cliente_email: str = "", tipo: str = "hosting") -> dict:
    """Genera solicitud_omni_lic.json con binding real del host."""
    fp = hardware.hardware_fingerprint()
    ip_local = fp["ip_local"][0] if fp["ip_local"] else "127.0.0.1"
    solicitud = {
        "formato": "SOLICITUD-OMNI-LIC-1.0",
        "version": "1.0",
        "tipo_solicitud": "licencia_omni_lic",
        "id_solicitud": uuid.uuid4().hex,
        "sistema": identity_sistema(),
        "tipo": tipo,
        "cliente": {"nombre": cliente_nombre, "email": cliente_email},
        "cliente_id": "",
        "emisor": {"url": "https://omni-lic.omni.group", "email": "licencias@omni.group"},
        "binding": {
            "ip": fp["ip"],
            "ip_local": ip_local,
            "hostname": fp["hostname"],
            "macs": fp["macs"],
            "components": {c: ip_local for c in config.LICENSE_COMPONENTS},
        },
        "solicitado_en": _now().isoformat(),
    }
    return solicitud


# ---------------------------------------------------------------- validacion
def validate_license(license_data: dict) -> list:
    """Devuelve lista de motivos de rechazo. Vacía = licencia valida."""
    reasons = []

    # 1. Forma
    required = ["cliente_id", "sistema", "tipo", "emitido", "expira", "binding",
                "semiprimo_n", "prueba_p", "prueba_q", "sello_n", "firma_hex"]
    missing = [f for f in required if not license_data.get(f)]
    if missing:
        reasons.append(f"Forma: campos obligatorios ausentes o vacios: {missing}")
    if license_data.get("sistema") != identity_sistema():
        reasons.append(f"Forma: sistema({license_data.get('sistema')}) != identidad_sistema()({identity_sistema()})")
    if license_data.get("tipo") not in ("trial", "hosting", "enterprise"):
        reasons.append("Forma: tipo no valido (debe ser trial/hosting/enterprise)")

    # 2. Cuasi-primo
    try:
        n = int(str(license_data.get("semiprimo_n")))
        if not semiprime.is_valid_semiprime(n):
            reasons.append("Cuasi-primo: semiprimo_n no es un semiprimo valido")
    except (TypeError, ValueError):
        reasons.append("Cuasi-primo: semiprimo_n no es un entero")

    # 3. Compromisos (formato sha512 hex de 128 chars)
    for campo in ("prueba_p", "prueba_q"):
        if not semiprime.sello_hex_valido(str(license_data.get(campo, ""))):
            reasons.append(f"Compromisos: {campo} no es hex sha512 de 128 chars")

    # 4. Sello
    try:
        n = int(str(license_data.get("semiprimo_n")))
        expected_seal = hashlib.sha512(str(n).encode()).hexdigest()
        if license_data.get("sello_n") != expected_seal:
            reasons.append("Sello: sello_n != sha512(str(semiprimo_n))")
    except (TypeError, ValueError):
        reasons.append("Sello: no verificable sin semiprimo_n")

    # 5. Firma Ed25519
    if not _verify_signature(license_data):
        reasons.append("Firma: firma Ed25519 invalida sobre payload canonico")

    # 6. Binding
    binding = license_data.get("binding") or {}
    fp = hardware.hardware_fingerprint()
    if binding.get("hostname") and binding["hostname"] != fp["hostname"]:
        reasons.append(f"Binding: hostname({binding['hostname']}) != hostname actual({fp['hostname']})")
    macs = binding.get("macs") or []
    if macs and not (set(m.lower() for m in macs) & set(m.lower() for m in fp["macs"])):
        reasons.append("Binding: ninguna MAC de la licencia coincide con el host")
    comps = binding.get("components") or {}
    local_ips = set(fp["ip_local"]) | {"127.0.0.1", "0.0.0.0", "localhost"}
    for comp, ip in comps.items():
        if ip not in local_ips:
            reasons.append(f"Binding: componente {comp} IP {ip} no es IP local")

    # 7. Vigencia
    try:
        expira = datetime.fromisoformat(license_data["expira"])
        if expira.tzinfo is None:
            expira = expira.replace(tzinfo=timezone.utc)
        if expira <= _now():
            reasons.append("Vigencia: licencia expirada")
    except (KeyError, ValueError):
        reasons.append("Vigencia: expira no valido")

    return reasons


def install_license(license_data: dict) -> dict:
    """Valida y persiste la licencia. Lanza ValueError con motivos si no es valida."""
    reasons = validate_license(license_data)
    if reasons:
        raise ValueError("Licencia invalida: " + " | ".join(reasons))
    config.LICENSE_FILE_PATH.write_text(
        json.dumps(license_data, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    with _LOCK:
        _license_cache.update(license_data)
    _audit("license_install", "licencia cargada y validada", license_data["cliente_id"])
    return {"ok": True, "noticed": reasons}


def load_current_license() -> dict | None:
    """Carga la licencia desde disco o cache."""
    if _license_cache:
        if _license_cache.get("expira"):
            try:
                expira = datetime.fromisoformat(_license_cache["expira"])
                if expira.tzinfo is None:
                    expira = expira.replace(tzinfo=timezone.utc)
                if expira > _now():
                    return _license_cache
            except (KeyError, ValueError):
                pass
    if not config.LICENSE_FILE_PATH.exists():
        return None
    try:
        data = json.loads(config.LICENSE_FILE_PATH.read_text(encoding="utf-8"))
        with _LOCK:
            _license_cache.update(data)
        return data
    except (json.JSONDecodeError, OSError):
        return None


def license_state() -> dict:
    """Estado de la licencia: vigente, gracia, expirada, ausente."""
    lic = load_current_license() or _license_cache or None
    if not lic:
        return {"estado": "SIN_LICENCIA", "dias_restantes": None, "expira": None}
    try:
        expira = datetime.fromisoformat(lic["expira"])
        if expira.tzinfo is None:
            expira = expira.replace(tzinfo=timezone.utc)
        dias = (expira - _now()).total_seconds() / 86400
    except (KeyError, ValueError):
        return {"estado": "INDEFINIDA", "dias_restantes": None, "expira": None}
    if dias <= 0:
        estado = "EXPIRADA"
    elif dias <= 7:
        estado = "GRACIA"
    else:
        estado = "VIGENTE"
    return {
        "estado": estado,
        "dias_restantes": round(max(dias, 0), 1),
        "expira": lic.get("expira"),
        "tipo": lic.get("tipo"),
        "cliente_id": lic.get("cliente_id"),
        "sistema": lic.get("sistema"),
        "notices": ["licencia en periodo de gracia"] if estado == "GRACIA" else [],
    }


def heartbeat() -> dict:
    """Re-verificacion periodica (6h en produccion). 3 fallos consecutivos -> shutdown."""
    with _LOCK:
        lic = load_current_license()
        if lic is None:
            return {"ok": False, "estado": "SIN_LICENCIA"}
        reasons = validate_license(lic)
        ok = not reasons
        state = license_state()
        if state["estado"] == "EXPIRADA":
            ok = False
            reasons.append("licencia expirada")
        if ok:
            _set_failures(0)
        else:
            fails = _bump_failures()
            _audit("license_heartbeat", "fallo", {"n": fails, "motivos": reasons[:3]})
            if fails >= 3:
                _audit("license_violation", "self-destruct por 3 fallos consecutivos", {"failures": fails})
                return {"ok": False, "shutdown": True, "motivos": reasons}
        return {"ok": ok, "consecutive_failures": _get_failures(), "estado": state["estado"], "motivos": reasons[:5]}


_sqlite_failures = None


def _failures_path():
    return config.DATA_DIR / "heartbeat_failures"


def _get_failures() -> int:
    try:
        return int(_failures_path().read_text().strip() or "0")
    except (OSError, ValueError):
        return 0


def _set_failures(n: int):
    _failures_path().write_text(str(n))


def _bump_failures() -> int:
    n = _get_failures() + 1
    _set_failures(n)
    return n


# ---------------------------------------------------------------- notificaciones
def check_expiry_notices(send_smtp=False) -> list:
    """Comprueba umbrales 30/15/7/3/2/1 y marca los enviados (no reenviar)."""
    state = license_state()
    sent = []
    if state["estado"] not in ("VIGENTE", "GRACIA"):
        return sent
    dias = state["dias_restantes"]
    conn = _conn()
    conn.execute(
        """CREATE TABLE IF NOT EXISTS license_notices (
            threshold INTEGER PRIMARY KEY,
            sent_at TEXT NOT NULL
        )"""
    )
    conn.commit()
    for t in NOTIFY_THRESHOLDS:
        if dias <= t:
            row = conn.execute("SELECT 1 FROM license_notices WHERE threshold=?", (t,)).fetchone()
            if not row:
                ts = _now().isoformat()
                conn.execute("INSERT OR REPLACE INTO license_notices (threshold, sent_at) VALUES (?,?)", (t, ts))
                notice = {"threshold": t, "dias": dias, "sent_at": ts}
                if send_smtp:
                    _send_email_notice(notice)
                sent.append(notice)
                _audit("license_expiring", f"aviso umbral {t} dias", notice)
    conn.commit()
    conn.close()
    return sent


def _send_email_notice(notice: dict):  # pragma: no cover - requiere SMTP real
    if not config.SMTP_HOST or not config.NOTIFY_EMAIL:
        return
    try:
        import smtplib
        from email.mime.text import MIMEText
        msg = MIMEText(
            f"Su licencia {identity_sistema()} expira en {notice['threshold']} dia(s).",
            "plain", "utf-8")
        msg["Subject"] = f"Su licencia {identity_sistema()} expira en {notice['threshold']} dia(s)"
        msg["From"] = config.SMTP_FROM
        msg["To"] = config.NOTIFY_EMAIL
        with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=10) as s:
            s.sendmail(config.SMTP_FROM, [config.NOTIFY_EMAIL], msg.as_string())
    except Exception:
        pass


def _audit(action, data, actor="SISTEMA"):
    from app.core import hashchain
    if isinstance(data, dict):
        try:
            json.dumps(data)
        except TypeError:
            data = str(data)
        else:
            data = json.dumps(data, ensure_ascii=False, sort_keys=True)
    hashchain.append(action, actor, data)


# ---------------------------------------------------------------- runtime guard
def service_blocked() -> bool:
    """Si la licencia ha expirado, ninguna funcionalidad debe ejecutarse."""
    lic = load_current_license()
    if lic is None:
        return True  # sin licencia no arranca
    state = license_state()
    if state["estado"] == "EXPIRADA":
        return True
    return False


def boot_check() -> dict:
    """Hook de arranque: sin licencia valida el software no arranca.

    En modo demo (OMNI_DEMO_MODE=1) se permite operar sin licencia para
    evaluacion; al instalar una licencia OMNI-Lic se valida con normalidad.
    """
    lic = load_current_license()
    if lic is None:
        if config.DEMO_MODE:
            return {
                "allowed": True,
                "estado": "DEMO",
                "message": "Modo demostracion sin licencia. Para salir de demo, "
                           "genere solicitud y cargue una licencia emitida por OMNI-Lic.",
            }
        return {
            "allowed": False,
            "message": "Sin licencia. Obtengala en OMNI-Lic (licencias@omni.group) o generando solicitud en el panel.",
            "screen": "NO_LICENSE",
        }
    reasons = validate_license(lic)
    state = license_state()
    if reasons or state["estado"] == "EXPIRADA":
        return {
            "allowed": False,
            "message": "Licencia caducada o invalida. Contacte licencias@omni.group para renovar.",
            "screen": "LICENSE_EXPIRED",
            "expira": state.get("expira"),
            "motivos": reasons,
        }
    return {"allowed": True, "estado": state["estado"], "dias_restantes": state["dias_restantes"]}