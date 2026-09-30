#!/usr/bin/env python3
import os
path = r"C:\Me\School\Guillermo\Omni-ClearMail\app\config.py"
with open(path, "r", encoding="utf-8") as f:
    content = f.read()

# Exact old string matching line 54-60 from config.py
old_smtp = """# ------------------------------------------------------------------- notificaciones
SMTP_HOST = os.getenv("LOOK_SMTP_HOST", "")
SMTP_PORT = int(os.getenv("LOOK_SMTP_PORT", "587"))
SMTP_FROM = os.getenv("LOOK_SMTP_FROM", "licencias@omni.group")
SMTP_USER = os.getenv("LOOK_SMTP_USER", "")
SMTP_PASSWORD = os.getenv("LOOK_SMTP_PASSWORD", "")
NOTIFY_EMAIL = os.getenv("LOOK_NOTIFY_EMAIL", "")"""

new_smtp = """# ------------------------------------------------------------------- notificaciones
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
    )"""

if old_smtp in content:
    content = content.replace(old_smtp, new_smtp)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    print("ARCHIVO ACTUALIZADO: advertencia SMTP agregada a config.py")
else:
    print("No se encontró el patrón viejo")
    # Debug showing exact line 54
    lines = content.split("\n")
    for i in range(53, 60):
        print(f"Line {i+1}: [{lines[i]}]")