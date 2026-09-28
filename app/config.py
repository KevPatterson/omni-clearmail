"""Configuracion central de Omni-CleanerMail.

Todas las variables se leen de entorno con fallback a valores seguros por defecto.
Sigue la convencion LOOK_* / OMNI_* de SECURITY-INDICATORS.md.
"""
import os
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parent.parent / ".env")
except Exception:
    pass  # python-dotenv opcional; las variables se leen del entorno del sistema

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.getenv("OMNI_DATA_DIR", BASE_DIR / "app" / "data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------- base de datos
DB_PATH = str(DATA_DIR / "omnimaillook.db")
AUDIT_DB_PATH = DATA_DIR / "audit_chain.db"

# ------------------------------------------------------------- autenticacion
API_KEY_TTL_DAYS = int(os.getenv("LOOK_API_KEY_TTL_DAYS", "365"))
ACCESS_TOKEN_MINUTES = int(os.getenv("LOOK_ACCESS_TOKEN_MINUTES", "30"))
REFRESH_TOKEN_TTL_DAYS = int(os.getenv("LOOK_REFRESH_TOKEN_TTL_DAYS", "7"))
RATE_LIMIT_AUTH_PER_MIN = int(os.getenv("LOOK_RATE_LIMIT_AUTH", "10"))
RATE_LIMIT_API_PER_MIN = int(os.getenv("LOOK_RATE_LIMIT_API", "120"))
MAX_LOGIN_ATTEMPTS = int(os.getenv("LOOK_MAX_LOGIN_ATTEMPTS", "5"))
HMAC_SECRET = os.getenv("LOOK_HMAC_SECRET", "OMNI_CLEANERMAIL_DEV_SECRET_CHANGE_ME")

# ---------------------------------------------------------------- licencias
LICENSE_PUBLIC_KEY_PATH = DATA_DIR / "emisor_pub.pem"
LICENSE_FILE_PATH = DATA_DIR / "license.json"
SYSTEM_IDENTITY = "omni-cleanermail"          # identidad_sistema() del software
LICENSE_COMPONENTS = ["backend"]

# ------------------------------------------------------------------ web / hsts
HSTS = os.getenv("LOOK_HSTS", "1") == "1"

# ------------------------------------------------------------------- auditoria
AUDIT_MAX_ENTRIES = int(os.getenv("LOOK_AUDIT_MAX_ENTRIES", "100000"))
AUDIT_RETENTION_DAYS = int(os.getenv("LOOK_AUDIT_RETENTION_DAYS", "365"))

# ---------------------------------------------------------------------- backup
BACKUP_RETENTION_DAYS = int(os.getenv("LOOK_BACKUP_RETENTION_DAYS", "30"))

# ---------------------------------------------------------------------- umbrales
QUARANTINE_THRESHOLD = float(os.getenv("OMNI_QUARANTINE_THRESHOLD", "40"))
BLOCK_THRESHOLD = float(os.getenv("OMNI_BLOCK_THRESHOLD", "70"))
ALERT_CPU_PCT = int(os.getenv("LOOK_ALERT_CPU_THRESHOLD", "80"))
ALERT_MEM_PCT = int(os.getenv("LOOK_ALERT_MEM_THRESHOLD", "80"))

# ------------------------------------------------------------------- notificaciones
SMTP_HOST = os.getenv("LOOK_SMTP_HOST", "")
SMTP_PORT = int(os.getenv("LOOK_SMTP_PORT", "587"))
SMTP_FROM = os.getenv("LOOK_SMTP_FROM", "licencias@omni.group")
SMTP_USER = os.getenv("LOOK_SMTP_USER", "")
SMTP_PASSWORD = os.getenv("LOOK_SMTP_PASSWORD", "")
NOTIFY_EMAIL = os.getenv("LOOK_NOTIFY_EMAIL", "")

# Advertencia si SMTP no está configurado para modo producción
if not SMTP_HOST and os.getenv("OMNI_DEMO_MODE", "1") != "1":
    import warnings
    warnings.warn(
        "LOOK_SMTP_HOST no configurado: los reportes por email no funcionarán "
        "hasta configurar variables LOOK_SMTP_HOST/PORT/USER/PASSWORD",
        UserWarning,
    )

# ------------------------------------------------------------------ webhook
WEBHOOK_URL = os.getenv("LOOK_WEBHOOK_URL", "")

# ----------------------------------------------------------------- reportes por buzon
# Reportes personalizados de actividad (entrantes/salientes, hallazgos) enviados
# por email periodicamente para cada buzon/usuario de la organizacion.
REPORT_POLL_SECONDS = int(os.getenv("OMNI_REPORT_POLL_SECONDS", "60"))
REPORT_DEFAULT_DAYS = int(os.getenv("OMNI_REPORT_DEFAULT_DAYS", "7"))
REPORT_MAX_DAYS = int(os.getenv("OMNI_REPORT_MAX_DAYS", "90"))

# ---------------------------------------------------------------------- KSMG
# Integracion con Kaspersky Secure Mail Gateway (real o simulada).
# Modos: SIMULADO | EML_WATCH | IMAP | SMTP
# Por defecto SIMULADO; cambiar a EML_WATCH/IMAP/SMTP según infraestructura disponible.
KSMG_MODO = os.getenv("OMNI_KSMG_MODO", "SIMULADO").upper()

# Advertencia si KSMG está en modo simulado para producción
if KSMG_MODO == "SIMULADO" and os.getenv("OMNI_DEMO_MODE", "1") != "1":
    import warnings
    warnings.warn(
        "KSMG_MODO es SIMULADO: sin gateway KSMG real conectado. "
        "Para producción, configure OMNI_KSMG_MODO=EML_WATCH, IMAP o SMTP "
        "según la infraestructura disponible.",
        UserWarning,
    )
KSMG_HOST = os.getenv("OMNI_KSMG_HOST", "")            # host IMAP de KSMG
KSMG_PORT = int(os.getenv("OMNI_KSMG_PORT", "143"))    # puerto IMAP (993 con SSL)
KSMG_USER = os.getenv("OMNI_KSMG_USER", "")
KSMG_PASSWORD = os.getenv("OMNI_KSMG_PASSWORD", "")
KSMG_USE_SSL = os.getenv("OMNI_KSMG_USE_SSL", "0") == "1"
KSMG_IMAP_FOLDER = os.getenv("OMNI_KSMG_IMAP_FOLDER", "INBOX")
KSMG_WATCH_DIR = os.getenv("OMNI_KSMG_WATCH_DIR", "")   # carpeta de vigilancia .eml
KSMG_POLL_SECONDS = int(os.getenv("OMNI_KSMG_POLL_SECONDS", "30"))
KSMG_AUTO_START = os.getenv("OMNI_KSMG_AUTO_START", "0") == "1"
KSMG_SMTP_BIND = os.getenv("OMNI_KSMG_SMTP_BIND", "127.0.0.1")
KSMG_SMTP_PORT = int(os.getenv("OMNI_KSMG_SMTP_PORT", "2525"))

# ----------------------------------------------------------------- direcciones
# Dominios internos de la organizacion: se usan para marcar una direccion
# como interna (pertenece a la org) en el registro de entrada/salida.
INTERNAL_DOMAINS = [
    d.strip().lower() for d in
    os.getenv("OMNI_INTERNAL_DOMAINS", "corp.demo").split(",") if d.strip()
]

# -------------------------------------------------------------------- demo
DEMO_MODE = os.getenv("OMNI_DEMO_MODE", "1") == "1"

# Modo producción: cuando OMNI_DEMO_MODE no es "1", 
# se aplican restricciones adicionales y advertencias
if not DEMO_MODE:
    import warnings
    warnings.warn(
        "Modo PRODUCCIÓN activado: ciertas funcionalidades de demo están deshabilitadas. "
        "Asegúrese de tener configurado: LOOK_HMAC_SECRET, LOOK_SMTP_HOST, y modo KSMG adecuado.",
        UserWarning,
    )