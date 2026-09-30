"""Test del modo KSMG simulado mejorado con emails realistas."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.mail import engines, parser

# Casos de prueba con emails realistas
casos = [
    {
        "nombre": "Phishing bancario BBVA realista",
        "raw": b"""From: BBVA Alertas <alertas.seguridad@bbva-clientes.tk>
To: carlos.martinez@empresa.com
Subject: Aviso importante: Confirme su identidad - Ref: SEC-2024-089473
Date: Mon, 15 Jan 2024 09:23:45 +0100
Message-ID: <20240115092345.12345@bbva-clientes.tk>
Content-Type: text/plain

Estimado cliente,

Hemos detectado un acceso desde un dispositivo no reconocido a su cuenta ****3847.

Por motivos de seguridad, su cuenta ha sido temporalmente suspendida.

Para reactivar su cuenta, debe verificar su identidad en las proximas 24 horas:

https://192.168.1.50/bbva/verificacion

Si no verifica su identidad, su cuenta sera bloqueada permanentemente 
y no podra acceder a sus fondos.

BBVA | Departamento de Seguridad
Este es un mensaje automatico, por favor no responda a este correo.
""",
        "score_esperado_min": 70,
        "categorias_esperadas": ["phish"]
    },
    {
        "nombre": "Malware disfrazado de factura DHL",
        "raw": b"""From: DHL Express <notificaciones@dhl-envios.com>
To: recepcion@empresa.com
Subject: Notificacion de entrega - Guia: 1234567890
Date: Tue, 16 Jan 2024 14:35:22 +0100
Message-ID: <20240116143522.98765@dhl-envios.com>
Content-Type: multipart/mixed; boundary="----=_Part_12345"

------=_Part_12345
Content-Type: text/plain; charset="UTF-8"

Estimado cliente,

Su paquete con numero de guia 1234567890 ha llegado a nuestras instalaciones
pero no ha podido ser entregado por falta de documentacion aduanera.

Para completar la entrega, descargue y abra el documento adjunto que contiene:
- Declaracion aduanera
- Factura proforma
- Instrucciones de pago

IMPORTANTE: Debe abrir el archivo adjunto antes de las 18:00 hrs para evitar
cargos adicionales de almacenamiento (15 EUR/dia).

Atentamente,
DHL Express - Departamento de Aduanas
Tel: +34 900 123 456

------=_Part_12345
Content-Type: application/zip; name="DHL_Documentos_Aduana.zip"
Content-Disposition: attachment; filename="DHL_Documentos_Aduana.zip"

[binary content]
------=_Part_12345--
""",
        "score_esperado_min": 60,
        "categorias_esperadas": ["phish"]
    },
    {
        "nombre": "Spam de curso online",
        "raw": b"""From: Academia Digital Pro <info@cursos-online-premium.info>
To: contacto@empresa.com
Subject: !!! Aprovecha 85% descuento - Cursos certificados !!!
Date: Wed, 17 Jan 2024 10:15:33 +0100
Message-ID: <20240117101533.54321@cursos-online-premium.info>
Content-Type: text/plain

OFERTA EXCLUSIVA POR TIEMPO LIMITADO!!!

Cursos online certificados con 85% de descuento!!!

- Python para Data Science - Antes 299 EUR ahora solo 44.85 EUR
- Marketing Digital Avanzado - Antes 399 EUR ahora solo 59.85 EUR
- Gestion de Proyectos PMP - Antes 599 EUR ahora solo 89.85 EUR

Esta oferta expira en 48 horas!!!

Miles de profesionales ya han mejorado su carrera con nosotros.

REGISTRATE AHORA: http://bit.ly/cursos2024

GANA DINERO FACIL: Conviertete en afiliado y make money 
con nuestro programa - Earn $200 por cada venta!!!

Para cancelar la suscripcion haz clic aqui. 
Academia Digital Pro - Madrid, Espana.
""",
        "score_esperado_min": 40,
        "categorias_esperadas": ["spam"]
    },
    {
        "nombre": "Email legitimo interno de trabajo",
        "raw": b"""From: Ana Garcia <ana.garcia@miempresa.com>
To: equipo-desarrollo@miempresa.com
Cc: jefe.proyecto@miempresa.com
Subject: RE: Revision sprint 2024-01 y planning siguiente iteracion
Date: Thu, 18 Jan 2024 16:20:15 +0100
Message-ID: <CAF8E3C2D.4567890@miempresa.com>
In-Reply-To: <CAF8E3C2A.1234567@miempresa.com>
References: <CAF8E3C2A.1234567@miempresa.com>
Authentication-Results: mx.google.com;
       spf=pass smtp.mailfrom=miempresa.com;
       dkim=pass header.i=@miempresa.com;
       dmarc=pass header.from=miempresa.com
Content-Type: text/plain; charset="UTF-8"

Hola equipo,

Gracias por la reunion de hoy. Aqui va el resumen de lo acordado:

SPRINT COMPLETADO (Sprint 2024-01):
- Modulo de autenticacion OAuth2 (JIRA-234)
- API REST endpoints v2 (JIRA-245)
- Tests unitarios coverage 85% (JIRA-256)
- Documentacion API - Pendiente para proximo sprint

PROXIMO SPRINT (2024-02):
- Integracion con sistema de pagos (JIRA-267) - Pedro
- Migracion base de datos PostgreSQL 15 (JIRA-268) - Laura  
- Dashboard analytics (JIRA-269) - Carlos
- Documentacion tecnica pendiente (JIRA-256) - Ana

RECORDATORIOS:
- Daily standup: 9:30 AM por Teams
- Demo con cliente: viernes 26/01 a las 15:00
- Code review: todos los PR antes de merge

Si hay dudas o necesitais soporte, avisad por el canal #desarrollo en Slack.

Saludos,
Ana Garcia
Tech Lead - Equipo Desarrollo
ana.garcia@miempresa.com | Ext: 3421
""",
        "score_esperado_min": 0,
        "score_esperado_max": 30,
        "categorias_esperadas": []
    },
    {
        "nombre": "Phishing sofisticado de Microsoft 365",
        "raw": b"""From: Microsoft 365 Admin <no-reply@microsoft-security.ml>
To: it.admin@empresa.com
Subject: [ACTION REQUIRED] Unusual sign-in activity detected
Date: Fri, 19 Jan 2024 03:47:12 +0000
Message-ID: <CAOkM9V3yH8xK@microsoft-security.ml>
Content-Type: text/plain

Microsoft 365 Security Alert

Security Alert: We detected unusual sign-in activity on your account.

Hello Administrator,

We detected a sign-in attempt from an unrecognized device:

Location: Moscow, Russia
IP Address: 185.220.101.45
Time: Jan 19, 2024 03:45 UTC

If this was not you, your account may be compromised.

Please verify this activity immediately:
https://192.168.2.100:8443/microsoft365/verify?token=abc123

You must verify within 12 hours or your account will be temporarily suspended.

Microsoft Corporation | One Microsoft Way | Redmond, WA 98052
This is an automated message. Please do not reply to this email.
""",
        "score_esperado_min": 70,
        "categorias_esperadas": ["phish"]
    },
    {
        "nombre": "Factura Excel con macros de proveedor habitual",
        "raw": b"""From: Contabilidad Proveedor SA <facturacion@proveedor-habitual.com>
To: cuentas.pagar@empresa.com
Subject: Factura F-2024-00156 - Servicios mes enero
Date: Mon, 22 Jan 2024 11:30:45 +0100
Message-ID: <20240122113045.ABCD@proveedor-habitual.com>
Content-Type: multipart/mixed; boundary="----=_Part_98765"

------=_Part_98765
Content-Type: text/plain; charset="UTF-8"

Buenos dias,

Adjunto factura F-2024-00156 correspondiente a los servicios prestados
durante el mes de enero 2024.

Detalle:
- Mantenimiento servidores: 2,500.00 EUR
- Soporte tecnico (80 horas): 4,800.00 EUR  
- Licencias software: 1,200.00 EUR
--------------------------------------
TOTAL: 8,500.00 EUR (IVA incluido)

Forma de pago: Transferencia bancaria
IBAN: ES12 3456 7890 1234 5678 9012
Vencimiento: 05/02/2024

NOTA: Para visualizar correctamente los graficos de facturacion,
por favor habilite las macros al abrir el documento Excel.

Quedamos a su disposicion para cualquier aclaracion.

Saludos cordiales,
Departamento de Facturacion
Proveedor Habitual SA
CIF: B-12345678
Tel: +34 91 234 56 78

------=_Part_98765
Content-Type: application/vnd.ms-excel.sheet.macroEnabled.12; 
              name="Factura_F-2024-00156_Enero.xlsm"
Content-Disposition: attachment; 
                     filename="Factura_F-2024-00156_Enero.xlsm"

[binary content]
------=_Part_98765--
""",
        "score_esperado_min": 30,
        "categorias_esperadas": ["malware"]
    }
]

print("\n" + "="*70)
print("TEST DEL MOTOR KSMG SIMULADO MEJORADO")
print("="*70 + "\n")

total_tests = len(casos)
tests_ok = 0
tests_fail = 0

for i, caso in enumerate(casos, 1):
    print(f"\n[TEST {i}/{total_tests}] {caso['nombre']}")
    print("-" * 70)
    
    try:
        # Parsear mensaje
        msg = parser.parse_message(caso["raw"])
        
        # Ejecutar motor KSMG
        resultado = engines.engine_ksmg(msg)
        
        score = resultado.get("score", 0)
        reasons = resultado.get("reasons", [])
        evidence = resultado.get("evidence", {})
        categorias = evidence.get("categorias", [])
        reglas = evidence.get("reglas", [])
        
        print(f"  Score: {score}/100")
        print(f"  Veredicto: {resultado.get('verdict', 'N/A')}")
        print(f"  Categorias: {categorias}")
        print(f"  Reglas aplicadas: {len(reglas)}")
        print(f"  Accion: {evidence.get('accion', 'N/A')}")
        print(f"\n  Razones (primeras 5):")
        for reason in reasons[:5]:
            print(f"    - {reason}")
        
        # Validaciones
        validaciones_ok = True
        
        # Validar score minimo
        score_min = caso.get("score_esperado_min", 0)
        score_max = caso.get("score_esperado_max", 100)
        if not (score_min <= score <= score_max):
            print(f"\n  FALLO: Score {score} fuera del rango esperado [{score_min}, {score_max}]")
            validaciones_ok = False
        
        # Validar categorias
        for cat_esperada in caso["categorias_esperadas"]:
            if cat_esperada not in categorias:
                print(f"\n  FALLO: Categoria esperada '{cat_esperada}' no detectada")
                validaciones_ok = False
        
        # Validar que se aplicaron reglas
        if len(reglas) == 0 and score > 20:
            print(f"\n  ADVERTENCIA: Score {score} pero sin reglas aplicadas")
        
        # Validar que marca como simulado
        evidence_str = str(evidence).lower()
        if "simulado" not in evidence_str and "heuristico" not in evidence_str:
            encontrado_en_reasons = any("simulado" in str(r).lower() for r in reasons)
            if not encontrado_en_reasons:
                print(f"\n  ADVERTENCIA: No se indica claramente que es modo simulado")
        
        if validaciones_ok:
            print(f"\n  TEST PASADO")
            tests_ok += 1
        else:
            print(f"\n  TEST FALLIDO")
            tests_fail += 1
            
    except Exception as e:
        print(f"\n  ERROR: {e}")
        import traceback
        traceback.print_exc()
        tests_fail += 1

print("\n" + "="*70)
print(f"RESUMEN: {tests_ok}/{total_tests} tests pasados, {tests_fail}/{total_tests} fallidos")
print("="*70 + "\n")

if tests_fail == 0:
    print("TODOS LOS TESTS PASARON")
    sys.exit(0)
else:
    print(f"{tests_fail} TESTS FALLARON")
    sys.exit(1)
