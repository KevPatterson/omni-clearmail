#!/usr/bin/env python3
import os
path = r"C:\Me\School\Guillermo\Omni-ClearMail\app\config.py"
with open(path, "r", encoding="utf-8") as f:
    content = f.read()

# Add production mode warning after DEMO_MODE line
old_demo = 'DEMO_MODE = os.getenv("OMNI_DEMO_MODE", "1") == "1"'

new_demo = '''DEMO_MODE = os.getenv("OMNI_DEMO_MODE", "1") == "1"

# Modo producción: cuando OMNI_DEMO_MODE no es "1", 
# se aplican restricciones adicionales y advertencias
if not DEMO_MODE:
    import warnings
    warnings.warn(
        "Modo PRODUCCIÓN activado: ciertas funcionalidades de demo están deshabilitadas. "
        "Asegúrese de tener configurado: LOOK_HMAC_SECRET, LOOK_SMTP_HOST, y modo KSMG adecuado.",
        UserWarning,
    )'''

if old_demo in content:
    content = content.replace(old_demo, new_demo)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    print("ARCHIVO ACTUALIZADO: separación DEMO/PRODUCCIÓN agregada a config.py")
else:
    print("No se encontró el patrón DEMO_MODE")
    # Show context
    idx = content.find('DEMO_MODE')
    if idx >= 0:
        print(f"Contexto encontrado en índice {idx}:")
        print(content[idx:idx+80])