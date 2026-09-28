"""Servicio headless de Omni-CleanerMail para produccion (Windows Task Scheduler / NSSM).

Igual que run.py pero SIN semilla demo y con salida minima para ejecutarse con pythonw.
Config:
    LOOK_BIND  (def. 127.0.0.1)
    LOOK_PORT  (def. 8000)
Uso:
    pythonw scripts\\servicio.py
"""
import os
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))


def main():
    host = os.getenv("LOOK_BIND", "127.0.0.1")
    port = int(os.getenv("LOOK_PORT", "8000"))

    from app.core import auth
    from app.mail import engines, quarantine

    auth.init_db()
    engines.init_engines()
    engines.seed_default_signatures()
    quarantine.init_quarantine()
    ensure_license()

    import uvicorn
    uvicorn.run("app.main:app", host=host, port=port, reload=False, log_level="warning")


def ensure_license():
    import json
    from app import config
    from app.core import licensing

    lic_path = config.LICENSE_FILE_PATH
    if lic_path.exists():
        try:
            data = json.loads(lic_path.read_text(encoding="utf-8"))
            if data.get("firma_hex") and licensing.validate_license(data):
                return
        except Exception:
            pass
    solicitud = licensing.generate_solicitud("Cliente", "licencias@omni.group", "enterprise")
    sop = config.DATA_DIR / "solicitud_omni_lic.json"
    sop.write_text(json.dumps(solicitud, ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()