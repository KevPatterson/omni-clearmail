"""Smoke test end-to-end con TestClient (sin servidor externo)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from starlette.testclient import TestClient

from app.main import app

OK = []


def check(name, cond, extra=""):
    if cond:
        OK.append(name)
        print(f"[ok] {name}")
    else:
        print(f"[FAIL] {name} {extra}")


def main():
    with TestClient(app) as client:
        # health sin auth
        r = client.get("/api/health")
        check("health 200", r.status_code == 200, str(r.status_code))

        # login
        r = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})
        check("login 200", r.status_code == 200, str(r.status_code))
        token = r.json()["access_token"]
        h = {"Authorization": f"Bearer {token}"}

        # login erroneo -> 401
        r = client.post("/api/auth/login", json={"username": "admin", "password": "mal"})
        check("login fail 401", r.status_code == 401, str(r.status_code))

        # license state
        r = client.get("/api/licences/state", headers=h)
        check("licence state", r.status_code == 200, f"{(r.text[:200])}")
        state = r.json()
        # demo: sin licencia instalada; con licencia real: VIGENTE
        check("license demo/vigente", state.get("estado") in ("SIN_LICENCIA", "VIGENTE"), str(state))

        # dashboard overview
        r = client.get("/api/dashboard/overview", headers=h)
        check("overview", r.status_code == 200)
        d = r.json()
        print("   totales:", d.get("totales"))

        # quarantine list
        r = client.get("/api/quarantine", headers=h)
        check("quarantine", r.status_code == 200)
        msgs = r.json().get("mensajes", [])
        print("   quit_messages:", len(msgs))

        # engines
        r = client.get("/api/dashboard/engines", headers=h)
        check("engines", r.status_code == 200)
        print("   motores:", [m["motor"] for m in r.json().get("motores", [])])

        # department
        r = client.get("/api/dashboard/department/CORP", headers=h)
        check("department", r.status_code == 200)

        # ingest via API (json) - phishing realista
        r = client.post("/api/mail/ingest-json", json={
            "subject": "[URGENTE] Confirme su cuenta bancaria - Ref: SEC-2024-4782",
            "sender": "alertas-seguridad@banco-santander.tk",
            "recipients": ["usuario1@corp.demo"],
            "body": "Estimado cliente, hemos detectado actividad sospechosa en su cuenta ****2847. "
                    "Por seguridad, su cuenta ha sido temporalmente suspendida. "
                    "Debe verificar su identidad en las proximas 24 horas accediendo a: "
                    "https://192.168.1.50/verificacion. "
                    "Introduzca su contrasena y clave de seguridad. "
                    "Si no verifica, su cuenta sera bloqueada permanentemente.",
            "attachments": [],
            "auth": {"spf": "fail", "dmarc": "fail", "dkim": "fail"},
        })
        check("ingest 200", r.status_code == 200, str(r.status_code))
        verdict = r.json().get("verdict")
        print("   verdict:", verdict.get("vote"), verdict.get("composite_score"))

        # ingest outbound (SALIDA) - email legitimo corporativo
        r = client.post("/api/mail/ingest-json", json={
            "subject": "RE: Propuesta comercial Q1-2024 - Cliente Acme Corp",
            "sender": "comercial@corp.demo",
            "recipients": ["compras@cliente-acme.com"],
            "body": "Estimado cliente, adjuntamos la propuesta comercial solicitada para Q1-2024. "
                    "Incluye: Servicios de mantenimiento (12 meses), Soporte tecnico 24/7, "
                    "Licencias software corporativo. Total: 45,000 EUR + IVA. "
                    "Quedamos a su disposicion para cualquier aclaracion. "
                    "Saludos cordiales, Departamento Comercial.",
            "attachments": [],
            "auth": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
            "direction": "SALIDA",
        })
        check("ingest salida 200", r.status_code == 200, str(r.status_code))

        # hallazgos
        r = client.get("/api/findings/summary", headers=h)
        check("findings summary", r.status_code == 200)
        fs = r.json()
        print("   hallazgos:", fs.get("total"), "· criticos:", fs.get("criticos"))
        check("hallazgos generados", fs.get("total", 0) > 0, "sin hallazgos tras ingesta")
        r = client.get("/api/findings?severidad=CRITICA", headers=h)
        check("findings listado", r.status_code == 200 and isinstance(r.json().get("hallazgos"), list))

        # direcciones de entrada y salida
        r = client.get("/api/addresses/summary", headers=h)
        check("addresses summary", r.status_code == 200)
        ad = r.json()
        print("   direcciones: entrantes", ad.get("direcciones_entrantes"), "salientes", ad.get("direcciones_salientes"))
        check("direcciones entrantes registradas", ad.get("direcciones_entrantes", 0) >= 1)
        check("direcciones salientes registradas", ad.get("direcciones_salientes", 0) >= 1)
        r = client.get("/api/addresses?direction=SALIDA", headers=h)
        check("addresses filtro salida", r.status_code == 200 and r.json().get("registros"))

        # reportes exportables
        r = client.get("/api/report/addresses.csv", headers=h)
        check("report addresses csv", r.status_code == 200 and "direccion" in r.text)
        r = client.get("/api/report/addresses.json", headers=h)
        check("report addresses json", r.status_code == 200 and "registros" in r.json())
        r = client.get("/api/report/findings.csv", headers=h)
        check("report findings csv", r.status_code == 200 and "severidad" in r.text)
        r = client.get("/api/report/findings.json", headers=h)
        check("report findings json", r.status_code == 200 and "hallazgos" in r.json())

        # audit
        r = client.get("/api/audit/actions?limit=50")
        check("audit actions", r.status_code == 200 and isinstance(r.json(), list))
        r = client.get("/api/audit/summary")
        check("audit summary", r.status_code == 200)
        print("   audit integrity:", r.json())

        # API key
        r = client.post("/api/secure/keys", headers=h, json={"label": "demo", "role": "OPERATOR"})
        check("create key", r.status_code == 200)
        api_key = r.json().get("api_key", "")

        # access con API key en ingesta - email realista
        r = client.post("/api/mail/ingest", headers={"X-API-Key": api_key},
                        content=b"From: notificaciones@sistema-interno.corp.demo\r\n"
                                b"To: equipo-ti@corp.demo\r\n"
                                b"Subject: Backup automatico completado - Server PROD-DB-01\r\n"
                                b"Date: Mon, 22 Jan 2024 03:00:15 +0100\r\n"
                                b"Content-Type: text/plain\r\n"
                                b"\r\n"
                                b"Backup automatico completado exitosamente.\r\n"
                                b"Servidor: PROD-DB-01\r\n"
                                b"Base de datos: PostgreSQL 15.2\r\n"
                                b"Tamano: 2.4 GB\r\n"
                                b"Duracion: 18 minutos\r\n"
                                b"Estado: OK\r\n")
        check("ingest con api key", r.status_code == 200, str(r.status_code))

        # backup health
        r = client.get("/api/backup/health")
        check("backup health", r.status_code == 200, str(r.status_code))

        # raiz / (frontend)
        r = client.get("/")
        check("frontend 200", r.status_code == 200)

    print(f"\n==> {len(OK)} checks OK")


if __name__ == "__main__":
    main()