#!/usr/bin/env python3
import os
path = r"C:\Me\School\Guillermo\Omni-ClearMail\app\config.py"
with open(path, "r", encoding="utf-8") as f:
    content = f.read()

# Add KSMG mode warning after the KSMG_MODO line
# Find the line with KSMG_MODO and add warning after it
old_ksmg = """KSMG_MODO = os.getenv("OMNI_KSMG_MODO", "SIMULADO").upper()"""

new_ksmg = """KSMG_MODO = os.getenv("OMNI_KSMG_MODO", "SIMULADO").upper()

# Advertencia si KSMG está en modo simulado para producción
if KSMG_MODO == "SIMULADO" and os.getenv("OMNI_DEMO_MODE", "1") != "1":
    import warnings
    warnings.warn(
        "KSMG_MODO es SIMULADO: sin gateway KSMG real conectado. "
        "Para producción, configure OMNI_KSMG_MODO=EML_WATCH, IMAP o SMTP "
        "según la infraestructura disponible.",
        UserWarning,
    )"""

if old_ksmg in content:
    content = content.replace(old_ksmg, new_ksmg)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    print("ARCHIVO ACTUALIZADO: advertencia KSMG agregada a config.py")
else:
    print("No se encontró el patrón KSMG - mostrando contexto")
    lines = content.split("\n")
    for i in range(75, 80):
        if i < len(lines):
            print(f"Line {i+1}: [{lines[i]}]")