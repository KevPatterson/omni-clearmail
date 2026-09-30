"""Test del modo KSMG simulado mejorado."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.mail import engines, parser

# Casos de prueba
casos = [
    {
        "nombre": "Phishing bancario con urgencia",
        "raw": b"""From: Santander <notificaciones@santander-seguro.tk>
To: usuario@empresa.com
Subject: URGENTE: Su cuenta sera bloqueada en 24 horas
Content-Type: text/plain

Estimado cliente,

Su cuenta ha sido suspendida por actividad sospechosa.
Debe verificar su identidad inmediatamente o sera bloqueada permanentemente.

Haga clic aqui para confirmar sus datos:
http://santander-verify.tk/login

Introduzca su contrasena y clave de seguridad.

Atencion: tiene 24 horas para completar este proceso.

Santander - Servicio de Seguridad
""",
        "score_esperado_min": 70,
        "categorias_esperadas": ["phish"]
    },
    {
        "nombre": "Malware con adjunto ejecutable",
        "raw": b"""From: DHL <tracking@dhl-delivery.xyz>
To: usuario@empresa.com
Subject: Paquete retenido - Factura adjunta
Content-Type: multipart/mixed; boundary="boundary123"

--boundary123
Content-Type: text/plain

Su paquete esta retenido en aduana.
Descargue la factura adjunta y ejecute para procesar el pago.

--boundary123
Content-Type: application/octet-stream; name="factura_DHL_2024.pdf.exe"
Content-Disposition: attachment; filename="factura_DHL_2024.pdf.exe"

[binary content]
--boundary123--
""",
        "score_esperado_min": 70,
        "categorias_esperadas": ["malware"]
    },
    {
        "nombre": "Spam de farmacia",
        "raw": b"""From: Best Pharmacy <sales@cheap-meds.info>
To: usuario@empresa.com
Subject: !!! VIAGRA 80% DESCUENTO !!!

Farmacia online con los mejores precios.
Viagra, Cialis, Levitra - 80% discount!!!

Compre ahora y gane dinero con nuestro programa de afiliados.
Make money selling our products!

www.cheap-meds.info
""",
        "score_esperado_min": 40,
        "categorias_esperadas": ["spam"]
    },
    {
        "nombre": "Email legitimo limpio",
        "raw": b"""From: Juan Perez <juan.perez@empresa-real.com>
To: maria@otraempresa.com
Subject: Reunion del proyecto
Authentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass
Content-Type: text/plain

Hola Maria,

Te escribo para confirmar la reunion del proyecto para el proximo lunes a las 10:00.

Agenda:
1. Revision de avances
2. Planificacion sprint
3. Dudas y comentarios

Saludos,
Juan
""",
        "score_esperado_min": 0,
        "score_esperado_max": 30,
        "categorias_esperadas": []
    },
    {
        "nombre": "Spoofing de PayPal con URL sospechosa",
        "raw": b"""From: PayPal Security <admin@secure-payment-verify.ml>
To: usuario@empresa.com
Subject: Confirme su cuenta PayPal
Content-Type: text/plain

Estimado usuario de PayPal,

Detectamos actividad inusual en su cuenta.
Por favor confirme su identidad accediendo a:

https://192.168.1.100:8443/paypal/verify

Si no confirma en las proximas 48 horas, su cuenta sera suspendida.

Equipo de Seguridad PayPal
""",
        "score_esperado_min": 70,
        "categorias_esperadas": ["phish"]
    },
    {
        "nombre": "Documento Office con macros",
        "raw": b"""From: Contabilidad <facturas@proveedor.com>
To: usuario@empresa.com
Subject: Factura mensual adjunta
Content-Type: multipart/mixed; boundary="boundary456"

--boundary456
Content-Type: text/plain

Adjunto encontrara la factura del mes.
Por favor habilite las macros para visualizar correctamente.

--boundary456
Content-Type: application/vnd.ms-excel.sheet.macroEnabled.12; name="factura_marzo.xlsm"
Content-Disposition: attachment; filename="factura_marzo.xlsm"

[binary content]
--boundary456--
""",
        "score_esperado_min": 40,
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
            print(f"\n  ❌ FALLO: Score {score} fuera del rango esperado [{score_min}, {score_max}]")
            validaciones_ok = False
        
        # Validar categorias
        for cat_esperada in caso["categorias_esperadas"]:
            if cat_esperada not in categorias:
                print(f"\n  ❌ FALLO: Categoria esperada '{cat_esperada}' no detectada")
                validaciones_ok = False
        
        # Validar que se aplicaron reglas
        if len(reglas) == 0 and score > 20:
            print(f"\n  ⚠️  ADVERTENCIA: Score {score} pero sin reglas aplicadas")
        
        # Validar que marca como simulado
        evidence_str = str(evidence).lower()
        if "simulado" not in evidence_str and "heuristico" not in evidence_str:
            encontrado_en_reasons = any("simulado" in str(r).lower() for r in reasons)
            if not encontrado_en_reasons:
                print(f"\n  ⚠️  ADVERTENCIA: No se indica claramente que es modo simulado")
        
        if validaciones_ok:
            print(f"\n  ✅ TEST PASADO")
            tests_ok += 1
        else:
            print(f"\n  ❌ TEST FALLIDO")
            tests_fail += 1
            
    except Exception as e:
        print(f"\n  ❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        tests_fail += 1

print("\n" + "="*70)
print(f"RESUMEN: {tests_ok}/{total_tests} tests pasados, {tests_fail}/{total_tests} fallidos")
print("="*70 + "\n")

if tests_fail == 0:
    print("✅ TODOS LOS TESTS PASARON")
    sys.exit(0)
else:
    print(f"❌ {tests_fail} TESTS FALLARON")
    sys.exit(1)
