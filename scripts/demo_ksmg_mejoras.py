"""Demostración visual de las mejoras del motor KSMG simulado."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.mail import engines, parser

print("\n" + "="*80)
print("DEMOSTRACION: MOTOR KSMG SIMULADO MEJORADO")
print("="*80)

# Mensaje de phishing sofisticado
phishing_eml = b"""From: PayPal Security Team <security@paypal-verify.ml>
To: usuario@empresa.com
Subject: URGENTE: Confirme su cuenta en 24 horas
Content-Type: text/plain

Estimado usuario de PayPal,

Hemos detectado actividad sospechosa en su cuenta desde una ubicacion no reconocida.

Por razones de seguridad, su cuenta ha sido temporalmente suspendida.

Para reactivar su cuenta, debe verificar su identidad INMEDIATAMENTE:
https://192.168.1.100:8443/paypal-verify/login.php?user=admin@paypal.com

Introduzca su contrasena y clave de seguridad para confirmar.

ATENCION: Si no confirma en las proximas 24 horas, su cuenta sera 
permanentemente bloqueada y perdera acceso a sus fondos.

Equipo de Seguridad PayPal
"""

print("\n" + "-"*80)
print("CASO DE PRUEBA: Email de Phishing Sofisticado")
print("-"*80)

msg = parser.parse_message(phishing_eml)
print(f"\nRemitente: {msg['sender']}")
print(f"Asunto: {msg['subject']}")
print(f"Enlaces: {len(msg['links'])}")
print(f"Adjuntos: {len(msg['attachments'])}")

resultado = engines.engine_ksmg(msg)

print(f"\n{'='*80}")
print("RESULTADO DEL ANALISIS")
print("="*80)

print(f"\n🎯 VEREDICTO: {resultado['verdict'].upper()}")
print(f"📊 SCORE: {resultado['score']}/100")
print(f"⚡ ACCION: {resultado['evidence']['accion'].upper()}")

print(f"\n📋 CATEGORIAS DETECTADAS:")
for cat in resultado['evidence']['categorias']:
    print(f"   - {cat}")

print(f"\n🔍 REGLAS APLICADAS ({len(resultado['evidence']['reglas'])}):")
for regla in resultado['evidence']['reglas'][:10]:
    print(f"   - {regla}")
if len(resultado['evidence']['reglas']) > 10:
    print(f"   ... y {len(resultado['evidence']['reglas']) - 10} mas")

print(f"\n💡 RAZONES PRINCIPALES:")
for i, reason in enumerate(resultado['reasons'][:8], 1):
    print(f"   {i}. {reason}")
if len(resultado['reasons']) > 8:
    print(f"   ... y {len(resultado['reasons']) - 8} razones adicionales")

print(f"\n📈 CONFIABILIDAD: {resultado['evidence']['reliability']}%")
print(f"🔧 FUENTE: {resultado['evidence']['fuente']}")

# Estadisticas
print(f"\n{'='*80}")
print("ESTADISTICAS DE DETECCION")
print("="*80)

stats = {
    "phishing": 0,
    "malware": 0,
    "spam": 0,
    "auth": 0,
    "url": 0,
    "sender": 0
}

for regla in resultado['evidence']['reglas']:
    if 'PHISH' in regla:
        stats['phishing'] += 1
    elif 'MALWARE' in regla or 'ATTACH' in regla:
        stats['malware'] += 1
    elif 'SPAM' in regla:
        stats['spam'] += 1
    elif 'AUTH' in regla:
        stats['auth'] += 1
    elif 'URL' in regla:
        stats['url'] += 1
    elif 'SENDER' in regla:
        stats['sender'] += 1

print(f"""
   Detecciones de Phishing:    {stats['phishing']} reglas
   Detecciones de Malware:     {stats['malware']} reglas
   Detecciones de Spam:        {stats['spam']} reglas
   Problemas de Autenticación: {stats['auth']} reglas
   Anomalías de URL:           {stats['url']} reglas
   Anomalías de Remitente:     {stats['sender']} reglas
""")

print("="*80)
print("\n✅ El motor KSMG simulado mejorado proporciona:")
print("   • Detección granular con 90+ patrones")
print("   • Clasificación por categorías (phish/malware/spam)")
print("   • Reglas específicas aplicadas")
print("   • Scoring sofisticado 0-100")
print("   • Decisión automática (block/quarantine/deliver)")
print("   • Evidencia detallada y trazable")
print("\n⚠️  NOTA: Para producción, usar conectores reales (EML_WATCH/IMAP/SMTP)")
print("="*80 + "\n")
