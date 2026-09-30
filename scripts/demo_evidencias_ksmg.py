"""Demostración de evidencias tipo KSMG real con cabeceras X-Kaspersky."""
import sys
import json
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.mail import engines, parser

print("\n" + "="*80)
print("EVIDENCIAS TIPO KSMG REAL - FORMATO IDENTICO AL GATEWAY")
print("="*80)

# Caso de phishing realista con SPF fail
phishing_msg = b"""From: Banco Santander Seguridad <alertas@santander-online.tk>
To: cliente@empresa.com
Subject: [IMPORTANTE] Verifique actividad inusual en su cuenta - REF: SS-2024-12847
Date: Wed, 24 Jan 2024 11:23:15 +0100
Message-ID: <20240124112315.98765@santander-online.tk>
Authentication-Results: mx.server.com; spf=fail; dkim=fail; dmarc=fail
Content-Type: text/plain

Estimado cliente,

Le informamos que hemos detectado movimientos inusuales en su cuenta 
****4729 del Banco Santander.

DETALLES DE LA ACTIVIDAD:
- Fecha: 24/01/2024 11:18:32
- Tipo: Intento de transferencia internacional
- Cantidad: 4,850.00 EUR
- Destino: Cuenta en Rumania

Por su seguridad, hemos bloqueado temporalmente las operaciones en su cuenta.

ACCION REQUERIDA:
Debe confirmar su identidad en las proximas 24 horas para desbloquear su cuenta:
https://192.168.3.100/santander/verificacion/cliente

Para verificar su identidad necesitara:
- Su numero de documento (DNI/NIE)
- Su contrasena de banca online
- Clave de firma SMS

IMPORTANTE: Si no realiza la verificacion, su cuenta permanecera bloqueada
y no podra realizar ninguna operacion bancaria.

Si reconoce esta actividad, puede ignorar este mensaje.

Atentamente,
Departamento de Seguridad y Fraude
Banco Santander
Linea de atencion 24h: 915 123 456

Este es un mensaje automatico del sistema de seguridad.
"""

msg = parser.parse_message(phishing_msg)
resultado = engines.engine_ksmg(msg)
evidence = resultado.get("evidence", {})

print("\n" + "-"*80)
print("CASO: Phishing bancario con fallos de autenticacion SPF/DKIM/DMARC")
print("-"*80)

print(f"\nMENSAJE:")
print(f"   Remitente: {msg['sender']}")
print(f"   Asunto: {msg['subject']}")
print(f"   Autenticacion: SPF=fail, DKIM=fail, DMARC=fail")

print(f"\n{'='*80}")
print("EVIDENCIAS TIPO KSMG REAL")
print("="*80)

print(f"\nESTRUCTURA DE EVIDENCIA:")
print(f"   real: {evidence.get('real')} (False = simulado, True = gateway real)")
print(f"   fuente: {evidence.get('fuente')}")
print(f"   accion: {evidence.get('accion')}")
print(f"   score_gateway: {evidence.get('score_gateway')}")
print(f"   reliability: {evidence.get('reliability')}%")

print(f"\nCATEGORIAS (igual que KSMG real):")
for cat in evidence.get('categorias', []):
    print(f"   - {cat}")

print(f"\nREGLAS KSMG (prefijo KSMG_* igual que gateway real):")
for regla in evidence.get('reglas', [])[:8]:
    print(f"   - {regla}")
if len(evidence.get('reglas', [])) > 8:
    print(f"   ... y {len(evidence.get('reglas', [])) - 8} reglas mas")

print(f"\nCABECERAS X-Kaspersky-* (formato identico a KSMG real):")
cabeceras = evidence.get('cabeceras', {})
for header, value in cabeceras.items():
    print(f"   {header}: {value}")

print(f"\n{'='*80}")
print("COMPARACION: KSMG SIMULADO vs KSMG REAL")
print("="*80)

print("""
Caracteristica               KSMG Real              KSMG Simulado        
---------------------------------------------------------------------------
SPF fail detectado           Si                     Si                
DMARC fail detectado         Si                     Si                
DKIM fail detectado          Si                     Si                
Categorias (phish/malware)   Si                     Si                
Reglas con prefijo KSMG_     Si                     Si                
Accion (block/quarantine)    Si                     Si                
Score gateway 0-100          Si                     Si                
Reliability 0-100            Si                     Si                
Cabeceras X-Kaspersky-*      Si                     Si                
Campo "real"                 True                   False (simulado)  
Campo "fuente"               "cabeceras KSMG"       "KSMG simulado"   
Base de amenazas tiempo r.   Millones               ~90 patrones      
Machine Learning             Avanzado               Heuristicas       
---------------------------------------------------------------------------
""")

print("="*80)
print("ESTRUCTURA JSON DE EVIDENCIA (formato KSMG)")
print("="*80)
print(json.dumps(evidence, indent=2, ensure_ascii=False))

print(f"\n{'='*80}")
print("CONCLUSIÓN")
print("="*80)
print("""
El KSMG simulado genera evidencias en FORMATO IDENTICO al KSMG real:

   1. SPF fail, DMARC fail, DKIM fail -> Detectados y reportados
   2. Categorias -> phishing, malware, spam, clean (igual que KSMG)
   3. Reglas -> Prefijo KSMG_* (KSMG_AUTH_SPF_FAIL, KSMG_PHISH_*, etc)
   4. Accion gateway -> block, quarantine, deliver
   5. Score gateway -> 0-100 con reliability
   6. Cabeceras X-Kaspersky-* -> Formato identico al gateway real
   
DIFERENCIAS:
   - Campo "real": False (marca explicita de simulado)
   - Campo "fuente": Indica "KSMG simulado"
   - Deteccion basada en ~90 patrones vs millones en KSMG real
   - Sin machine learning ni inteligencia de amenazas en tiempo real

Para produccion: usar conectores reales (EML_WATCH/IMAP/SMTP)
""")
print("="*80 + "\n")
