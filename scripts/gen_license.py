"""Script de ayuda: genera la SOLICITUD OMNI-Lic.

Omni-CleanerMail NUNCA emite licencias. Las licencias SOLO las emite el
emisor central OMNI-Lic (licencias@omni.group).

Uso:
    python scripts/gen_license.py --tipo enterprise --cliente "ACME"
    -> genera app/data/solicitud_omni_lic.json
"""
import argparse
import json
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tipo", default="enterprise", choices=["trial", "hosting", "enterprise"])
    ap.add_argument("--cliente", default="Cliente Demo")
    args = ap.parse_args()

    from app import config
    from app.core import licensing

    solicitud = licensing.generate_solicitud(args.cliente, "licencias@omni.group", args.tipo)
    ruta = config.DATA_DIR / "solicitud_omni_lic.json"
    ruta.write_text(json.dumps(solicitud, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[ok] Solicitud OMNI-Lic generada -> {ruta}")
    print("[ok] Enviala a licencias@omni.group y coloca el license.json emitido en "
          "app/data/license.json")

    # reinicializa el guard de arranque (el server lo consulta en cada peticion)
    from app.api import routes
    routes._boot = None
    print("[ok] Guard de arranque refrescado")


if __name__ == "__main__":
    main()