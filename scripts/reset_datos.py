"""Reseteo controlado de los datos demo de Omni-CleanerMail.

Modos:
  --datos   (def): borra mensajes, hallazgos, ledger de direcciones, historial
                   de reportes y eventos KSMG. CONSERVA usuarios, configuracion
                   (reportes/KSMG/API keys), auditoria y licencia.
  --all     : mueve la base (datos + auditoria) a una copia con timestamp para
              arrancar de cero. TRUNCA la auditoria.

Uso:
  python scripts/reset_datos.py [--datos | --all]
"""
import shutil
import sys
import time
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))


def reset_datos():
    from app import config
    import sqlite3

    db = sqlite3.connect(config.DB_PATH)
    tables = ["report_sent", "ksmg_events", "findings", "address_records", "messages"]
    for t in tables:
        try:
            db.execute(f"DELETE FROM {t}")
        except sqlite3.Error:
            pass
    db.commit()
    db.close()
    print("[reset] Datos de mensajeria eliminados:", ", ".join(t for t in tables if True))


def reset_all():
    from app import config

    stamp = time.strftime("%Y%m%d_%H%M%S")
    for path in (Path(config.DB_PATH), config.AUDIT_DB_PATH):
        if path.exists():
            bkp = path.with_name(f"{path.name}.bkp_{stamp}")
            shutil.move(str(path), str(bkp))
            print(f"[reset] Base movida -> {bkp}")
    for wal in (Path(config.DB_PATH).with_suffix(".db-wal"), Path(config.DB_PATH).with_suffix(".db-shm")):
        if wal.exists():
            wal.unlink()


def main():
    arg = sys.argv[1] if len(sys.argv) > 1 else "--datos"
    if arg == "--datos":
        reset_datos()
        print("[reset] OK (modo datos).")
    elif arg == "--all":
        reset_all()
        print("[reset] OK (modo total). Al re-arrancar se regenera la BD desde cero.")
    else:
        print("uso: python scripts/reset_datos.py [--datos|--all]")
        sys.exit(2)


if __name__ == "__main__":
    main()