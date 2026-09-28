"""Launcher de Omni-CleanerMail en modo demo.

Pasos:
1. Inicializa las tablas (auth, motores, cuarentena).
2. Si no existe licencia valida, genera la SOLICITUD OMNI-Lic
   (el software NUNCA emite licencias: solo OMNI-Lic lo hace).
3. Lanza uvicorn en 127.0.0.1:8000.

Uso:
    python scripts/run.py [--port 8000] [--no-seed]
"""
import argparse
import json
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))


def ensure_license():
    from app import config
    from app.core import auth, licensing

    lic_path = config.LICENSE_FILE_PATH

    if lic_path.exists():
        try:
            data = json.loads(lic_path.read_text(encoding="utf-8"))
            if data.get("firma_hex") and not licensing.validate_license(data):
                print("[run] Licencia existente valida -> OK")
                return
        except Exception:
            pass

    print("[run] Sin licencia valida. Las licencias SOLO las emite OMNI-Lic.")
    solicitud = licensing.generate_solicitud("Cliente Demo", "demo@omni.local", "enterprise")
    solicitud_path = config.DATA_DIR / "solicitud_omni_lic.json"
    solicitud_path.write_text(json.dumps(solicitud, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[run] Solicitud OMNI-Lic generada -> {solicitud_path}")
    print("[run] Enviala a licencias@omni.group y coloca el license.json emitido en "
          "app/data/license.json")


def seed_demo_messages():
    from app.mail import addressbook, engines, findings, quarantine, scoring

    addressbook.init_addressbook()
    findings.init_findings()

    demos = [
        {
            "subject": "URGENTE: su cuenta sera bloqueada en 48 horas",
            "sender": "seguridad@fraud-bank-es.xyz",
            "recipients": ["admin@corp.demo", "operador@corp.demo"],
            "body": "Haga clic aqui para confirmar sus datos y evitar el cierre: "
                    "http://bit.ly/verifica-cuenta %20confirmacion password=secret",
            "links": ["http://bit.ly/verifica-cuenta"],
            "attachments": [{"filename": "factura_urgente.pdf", "size": 120000, "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}],
            "auth": {"spf": "fail", "dmarc": "fail", "dkim": "none"},
        },
        {
            "subject": "Nueva factura pendiente de pago",
            "sender": "facturacion@corp.provider",
            "recipients": ["usuario1@corp.demo"],
            "body": "Adjuntamos el recibo y documento de la factura. Por favor revise adjunto .docm",
            "attachments": [{"filename": "recibo_octubre.docm", "size": 260000, "sha256": ""}],
            "auth": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        },
        {
            "subject": "Reunion de equipo - acta mensual",
            "sender": "secretaria@corp.demo",
            "recipients": ["operador@corp.demo", "auditor@corp.demo"],
            "body": "Hola, atentamente adjuntamos el acta. Gracias y saludos.",
            "attachments": [],
            "auth": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        },
        {
            "subject": "GANADOR: premio promocion urgente - reclame ahora",
            "sender": "noreply@spam-hub.info",
            "recipients": ["usuario1@corp.demo", "usuario1@corp.demo"],
            "body": "Felicidades, ha ganado. Haga clic para reclamar: https://t.me/premio-promo",
            "links": ["https://t.me/premio-promo"],
            "attachments": [],
            "auth": {"spf": "fail", "dkim": "fail", "dmarc": "fail"},
        },
        {
            "subject": "Actualice sus credenciales del banco inmediatamente",
            "sender": "aviso@verifica-seg.rok",
            "recipients": ["admin@corp.demo"],
            "body": "Verifique su cuenta y confirme sus datos; de lo contrario sera bloqueada. "
                    "password:hunter2 clique aqui",
            "attachments": [],
            "auth": {"spf": "none", "dkim": "none", "dmarc": "none"},
        },
        {
            "subject": "Planificacion trimestral",
            "sender": "rrhh@corp.demo",
            "recipients": ["admin@corp.demo", "operador@corp.demo", "usuario1@corp.demo"],
            "body": "Hola a todos, adjunto la planificacion trimestral para revisar. Gracias.",
            "attachments": [{"filename": "plan_trim.xlsx", "size": 45000, "sha256": ""}],
            "auth": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        },
        {
            "subject": "Confirmacion de pedido 88231 - cliente",
            "sender": "ventas@corp.demo",
            "recipients": ["cliente@clientes-ext.com"],
            "body": "Estimado cliente, confirmamos su pedido 88231. Gracias por su confianza.",
            "attachments": [],
            "auth": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
            "direction": "SALIDA",
        },
        {
            "subject": "Informe mensual para el socio",
            "sender": "direccion@corp.demo",
            "recipients": ["socio@partners-galaxy.net"],
            "body": "Hola, adjuntamos el informe mensual de actividad. Saludos cordiales.",
            "attachments": [],
            "auth": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
            "direction": "SALIDA",
        },
    ]
    injected = 0
    for idx, msg in enumerate(demos):
        msg["msg_id"] = f"demo-{idx+1:04d}"
        results = engines.run_all_engines(msg)
        fused = scoring.fused_score(results)
        direction = msg.get("direction", "ENTRADA")
        quarantine.save_message(msg, results, fused, direction=direction)
        injected += 1
    print(f"[run] {injected} mensajes demo ingeridos")


def main():
    import os
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=int(os.getenv("LOOK_PORT", "8000")))
    ap.add_argument("--host", default=os.getenv("LOOK_BIND", "127.0.0.1"))
    ap.add_argument("--no-seed", action="store_true", help="no inyectar mensajes demo")
    args = ap.parse_args()

    from app.core import auth
    from app.mail import engines, quarantine
    auth.init_db()
    engines.init_engines()
    engines.seed_default_signatures()
    quarantine.init_quarantine()
    seed_demo_messages() if not args.no_seed else None
    ensure_license()

    import uvicorn
    print(f"[run] Omni-CleanerMail en http://{args.host}:{args.port}  (docs: /docs)")
    uvicorn.run("app.main:app", host=args.host, port=args.port, reload=False)


if __name__ == "__main__":
    main()