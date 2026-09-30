"""Demostración visual de las mejoras del motor KSMG simulado."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.mail import engines, parser

print("\n" + "="*80)
print("DEMOSTRACION: MOTOR KSMG SIMULADO MEJORADO")
print("="*80)

# Mensaje de phishing realista tipo corporativo
phishing_eml = b"""From: Microsoft 365 Security <security-alerts@microsoft-services.ml>
To: it.manager@empresa.com
Subject: [CRITICAL] Suspicious login attempt blocked - Action Required
Date: Mon, 22 Jan 2024 08:15:33 +0000
Message-ID: <20240122081533.SEC789@microsoft-services.ml>
Content-Type: text/plain

Microsoft 365 Security Center

SECURITY ALERT - Immediate Action Required

We have detected and blocked a suspicious sign-in attempt to your Microsoft 365 
administrator account from an unrecognized location.

Sign-in Details:
- Location: Lagos, Nigeria
- IP Address: 197.210.55.123
- Device: Unknown (Linux)
- Time: January 22, 2024 at 8:12 AM UTC

If this was not you, your account credentials may have been compromised.

REQUIRED ACTION:
Please verify this activity within the next 12 hours by clicking below:
https://192.168.5.200:8443/m365/security/verify?session=a8f7b2e4

Failure to verify will result in temporary account suspension to protect 
your organization's data and services.

If you recognize this activity, no action is needed.

Best regards,
Microsoft 365 Security Team
Microsoft Corporation

This is an automated security notification. Do not reply to this email.
"""

print("\n" + "-"*80)
print("CASO DE PRUEBA: Phishing corporativo tipo Microsoft 365")
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

print(f"\nVEREDICTO: {resultado['verdict'].upper()}")
print(f"SCORE: {resultado['score']}/100")
print(f"ACCION: {resultado['evidence']['accion'].upper()}")

print(f"\nCATEGORIAS DETECTADAS:")
for cat in resultado['evidence']['categorias']:
    print(f"   - {cat}")

print(f"\nREGLAS APLICADAS ({len(resultado['evidence']['reglas'])}):")
for regla in resultado['evidence']['reglas'][:10]:
    print(f"   - {regla}")
if len(resultado['evidence']['reglas']) > 10:
    print(f"   ... y {len(resultado['evidence']['reglas']) - 10} mas")

print(f"\nRAZONES PRINCIPALES:")
for i, reason in enumerate(resultado['reasons'][:8], 1):
    print(f"   {i}. {reason}")
if len(resultado['reasons']) > 8:
    print(f"   ... y {len(resultado['reasons']) - 8} razones adicionales")

print(f"\nCONFIABILIDAD: {resultado['evidence']['reliability']}%")
print(f"FUENTE: {resultado['evidence']['fuente']}")

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
print("\nEl motor KSMG simulado mejorado proporciona:")
print("   - Deteccion granular con 90+ patrones")
print("   - Clasificacion por categorias (phish/malware/spam)")
print("   - Reglas especificas aplicadas")
print("   - Scoring sofisticado 0-100")
print("   - Decision automatica (block/quarantine/deliver)")
print("   - Evidencia detallada y trazable")
print("\nNOTA: Para produccion, usar conectores reales (EML_WATCH/IMAP/SMTP)")
print("="*80 + "\n")
