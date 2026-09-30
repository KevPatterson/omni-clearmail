"""Demostración de evidencias tipo KSMG real con cabeceras X-Kaspersky."""
import sys
import json
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.mail import engines, parser

print("\n" + "="*80)
print("EVIDENCIAS TIPO KSMG REAL - FORMATO IDENTICO AL GATEWAY")
print("="*80)

# Caso de phishing con SPF fail
phishing_msg = b"""From: Banco Santander <admin@santander-security.tk>
To: cliente@empresa.com
Subject: URGENTE: Verifique su cuenta en 24 horas
Authentication-Results: mx.server.com; spf=fail; dkim=fail; dmarc=fail
Content-Type: text/plain

Estimado cliente,

Su cuenta ha sido suspendida por actividad sospechosa.
Confirme su identidad inmediatamente accediendo a:
https://192.168.1.100/santander/login

Introduzca su contrasena y clave de seguridad.
Tiene 24 horas para evitar el bloqueo permanente.

Santander Seguridad
"""

msg = parser.parse_message(phishing_msg)
resultado = engines.engine_ksmg(msg)
evidence = resultado.get("evidence", {})

print("\n" + "-"*80)
print("CASO: Phishing con SPF/DKIM/DMARC fail")
print("-"*80)

print(f"\n📧 MENSAJE:")
print(f"   Remitente: {msg['sender']}")
print(f"   Asunto: {msg['subject']}")
print(f"   Autenticación: SPF=fail, DKIM=fail, DMARC=fail")

print(f"\n{'='*80}")
print("EVIDENCIAS TIPO KSMG REAL")
print("="*80)

print(f"\n🔍 ESTRUCTURA DE EVIDENCIA:")
print(f"   real: {evidence.get('real')} (False = simulado, True = gateway real)")
print(f"   fuente: {evidence.get('fuente')}")
print(f"   accion: {evidence.get('accion')}")
print(f"   score_gateway: {evidence.get('score_gateway')}")
print(f"   reliability: {evidence.get('reliability')}%")

print(f"\n📋 CATEGORIAS (igual que KSMG real):")
for cat in evidence.get('categorias', []):
    print(f"   - {cat}")

print(f"\n🔧 REGLAS KSMG (prefijo KSMG_* igual que gateway real):")
for regla in evidence.get('reglas', [])[:8]:
    print(f"   - {regla}")
if len(evidence.get('reglas', [])) > 8:
    print(f"   ... y {len(evidence.get('reglas', [])) - 8} reglas más")

print(f"\n📨 CABECERAS X-Kaspersky-* (formato idéntico a KSMG real):")
cabeceras = evidence.get('cabeceras', {})
for header, value in cabeceras.items():
    print(f"   {header}: {value}")

print(f"\n{'='*80}")
print("COMPARACION: KSMG SIMULADO vs KSMG REAL")
print("="*80)

print("""
┌────────────────────────────┬──────────────────────┬──────────────────────┐
│ Característica             │ KSMG Real            │ KSMG Simulado        │
├────────────────────────────┼──────────────────────┼──────────────────────┤
│ SPF fail detectado         │ ✅ Sí                │ ✅ Sí                │
│ DMARC fail detectado       │ ✅ Sí                │ ✅ Sí                │
│ DKIM fail detectado        │ ✅ Sí                │ ✅ Sí                │
│ Categorías (phish/malware) │ ✅ Sí                │ ✅ Sí                │
│ Reglas con prefijo KSMG_   │ ✅ Sí                │ ✅ Sí                │
│ Acción (block/quarantine)  │ ✅ Sí                │ ✅ Sí                │
│ Score gateway 0-100        │ ✅ Sí                │ ✅ Sí                │
│ Reliability 0-100          │ ✅ Sí                │ ✅ Sí                │
│ Cabeceras X-Kaspersky-*    │ ✅ Sí                │ ✅ Sí                │
│ Campo "real"               │ ✅ True              │ ⚠️  False (simulado) │
│ Campo "fuente"             │ ✅ "cabeceras KSMG"  │ ⚠️  "KSMG simulado"  │
│ Base de amenazas tiempo r. │ ✅ Millones          │ ❌ ~90 patrones      │
│ Machine Learning           │ ✅ Avanzado          │ ❌ Heurísticas       │
└────────────────────────────┴──────────────────────┴──────────────────────┘
""")

print("="*80)
print("ESTRUCTURA JSON DE EVIDENCIA (formato KSMG)")
print("="*80)
print(json.dumps(evidence, indent=2, ensure_ascii=False))

print(f"\n{'='*80}")
print("CONCLUSIÓN")
print("="*80)
print("""
✅ El KSMG simulado genera evidencias en FORMATO IDENTICO al KSMG real:

   1. SPF fail, DMARC fail, DKIM fail → Detectados y reportados
   2. Categorías → phishing, malware, spam, clean (igual que KSMG)
   3. Reglas → Prefijo KSMG_* (KSMG_AUTH_SPF_FAIL, KSMG_PHISH_*, etc)
   4. Acción gateway → block, quarantine, deliver
   5. Score gateway → 0-100 con reliability
   6. Cabeceras X-Kaspersky-* → Formato idéntico al gateway real
   
⚠️  DIFERENCIAS:
   - Campo "real": False (marca explícita de simulado)
   - Campo "fuente": Indica "KSMG simulado"
   - Detección basada en ~90 patrones vs millones en KSMG real
   - Sin machine learning ni inteligencia de amenazas en tiempo real

📌 Para producción: usar conectores reales (EML_WATCH/IMAP/SMTP)
""")
print("="*80 + "\n")
