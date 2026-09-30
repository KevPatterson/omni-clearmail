"""Motores de analisis multi-motor de Omni-CleanerMail.

Cada motor devuelve un veredicto: score 0-100, verdicto y razones.
Los motores cubren: KSMG(real o simulado), ClamAV(firmas), YARA(reglas),
Sandbox(comportamiento), ML local(NLP) y Analisis de adjuntos.

En produccion estas son las interfaces hacia KSMG real, clamd, yara-python,
CAPE/Cuckoo y los modelos ONNX/TFLite. Cuando la capa KSMG (app/mail/ksmg.py)
entrega evidencia real del gateway (cabeceras, lado, export), el motor KSMG
usa esos datos; si no, usa la heuristica local marcada como simulada.
"""
import hashlib
import json
import math
import re
import sqlite3
from pathlib import Path

from app import config

BENIGN = "clean"
SUSPICIOUS = "suspicious"
MALICIOUS = "malicious"


def _conn():
    conn = sqlite3.connect(config.DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_engines():
    conn = _conn()
    conn.execute(
        """CREATE TABLE IF NOT EXISTS signatures (
            sha256 TEXT PRIMARY KEY,
            family TEXT NOT NULL,
            severity INTEGER NOT NULL DEFAULT 50
        )"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS domain_reputation (
            domain TEXT PRIMARY KEY,
            reputation INTEGER NOT NULL DEFAULT 50
        )"""
    )
    conn.commit()
    conn.close()


def seed_default_signatures():
    conn = _conn()
    demo = [
        ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "Troj.MSIL.VirLock", 85),
        ("01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b", "Worm.Python.Nul", 80),
    ]
    conn.executemany("INSERT OR IGNORE INTO signatures VALUES (?,?,?)", demo)
    conn.commit()
    conn.close()


# --------------------------------------------------------------------- KSMG
def _score_ksmg_evidence(ev: dict) -> tuple:
    """Score a partir de evidencia REAL del gateway (cabeceras/sidecar)."""
    score = int(ev.get("score_gateway") or 0)
    reasons = []
    accion = str(ev.get("accion") or "").lower()
    if accion:
        if any(w in accion for w in ("block", "drop", "delete", "reject")):
            score = max(score, 70)
            reasons.append(f"accion gateway real: {accion}")
        elif "quarantine" in accion:
            score = max(score, 55)
            reasons.append(f"accion gateway real: {accion}")
        elif any(w in accion for w in ("clean", "pass", "deliver")):
            score = max(score, 0)
            reasons.append(f"accion gateway real: {accion}")
        else:
            reasons.append(f"accion gateway real: {accion}")
    for cat in [str(c).lower() for c in (ev.get("categorias") or [])]:
        if "phish" in cat:
            score = max(score, 70)
            reasons.append(f"clasificacion KSMG real/phishing: {cat}")
        elif "malware" in cat or "virus" in cat:
            score = max(score, 75)
            reasons.append(f"clasificacion KSMG real/Malware: {cat}")
        elif "spam" in cat:
            score = max(score, 60)
            reasons.append("clasificacion KSMG real/spam")
        elif "clean" in cat:
            score = min(score, 15)
            reasons.append("clasificacion KSMG real/clean")
    reglas = ev.get("reglas") or []
    if reglas:
        score += min(15, 3 * len(reglas))
        reasons.append(f"reglas KSMG real: {', '.join(str(r) for r in reglas[:4])}")
    if "cabeceras" in ev:
        reasons.append(f"evidencia: {ev.get('fuente') or 'cabeceras KSMG'}")
    if not reasons:
        reasons.append("evidencia real del gateway sin clasificacion")
    return max(0, min(100, score)), reasons


def engine_ksmg(msg: dict) -> dict:
    """Pasarela Kaspersky SMG: evidencia real del gateway o simulacion."""
    ev = msg.get("ksmg")
    if isinstance(ev, dict) and ev.get("real"):
        verdict = _verdict("KSMG", *_score_ksmg_evidence(ev))
        verdict["evidence"] = ev
        return verdict
    
    # Modo simulado: obtener score, reasons y evidence
    score, reasons, evidence = _ksmg_simulado(msg)
    verdict = _verdict("KSMG", score, reasons)
    verdict["evidence"] = evidence
    return verdict


def _ksmg_evidence_from_headers(raw: bytes) -> dict:
    """Extrae evidencia KSMG simulada desde cabeceras reales del mensaje,
    imitando lo que KSMG real enviaría via cabeceras X-Kaspersky*/X-KSMG*."""
    try:
        msg = email.message_from_bytes(raw, policy=email.policy.default)
    except Exception:
        return {"real": False, "evidence": {}}
    headers = {}
    veredictos = []
    accion = ""
    reglas = []
    for key in msg.keys():
        lk = key.lower()
        values = msg.get_all(key) or [""]
        val = " ".join(str(v) for v in values).strip()
        if lk.startswith("x-kaspersky") or lk.startswith("x-ksmg"):
            headers[lk] = val[:400]
            low = val.lower()
            # Extraer acción
            if "action" in low:
                # Patrón: Action: ... o action=...
                a_match = re.search(r"action[=:]\s*(\S+)", low)
                if a_match:
                    accion = a_match.group(1).strip().lower()
            # Detectar categorías/veredictos
            for token in ("phish", "malware", "virus", "spam"):
                if token in low and token not in veredictos:
                    veredictos.append(token)
            if "clean" in low and "clean" not in veredictos:
                veredictos.append("clean")
            # Detectar reglas
            rule_marker = re.compile(r"rule[=:\s]+([a-z0-9_.-]+)", re.I)
            reglas.extend(rule_marker.findall(val))
        elif lk in ("authentication-results", "spf", "dkim-signature", "dmarc"):
            headers[lk] = val[:400]
    # Si no hay cabeceras X-Kaspersky, construimos evidencia simulada heurística
    if not headers:
        return {"real": False, "evidence": {}}
    return {
        "real": True,
        "evidence": {
            "accion": accion,
            "veredictos": veredictos[:6],
            "reglas": reglas[:10],
            "cabeceras": headers,
        }
    }


def _ksmg_simulado(msg: dict) -> tuple:
    """Heuristica local tipo KSMG cuando no hay gateway real conectado.
    
    Simula la evidencia que KSMG real proveería mediante:
    - Analisis avanzado de SPF/DKIM/DMARC
    - Deteccion de phishing/malware/spam con patrones extendidos
    - Analisis de URLs y reputacion de dominios
    - Deteccion de adjuntos maliciosos y tecnicas de ofuscacion
    - Analisis de cabeceras y anomalias de remitente
    - Scoring sofisticado basado en multiples senales
    """
    score = 0
    reasons = []
    evidence = {"real": False, "details": {}}
    categorias = []
    reglas_aplicadas = []

    # Extraer datos del mensaje
    sender = msg.get("sender", "")
    subject = msg.get("subject", "")
    body = msg.get("body", "")
    recipients = msg.get("recipients", [])
    links = msg.get("links", [])
    attachments = msg.get("attachments", [])
    auth = msg.get("auth") or {}
    
    # Preparar haystack para busquedas
    haystack = " ".join([subject, body, sender]).lower()
    
    # Extraer dominio del remitente
    domain = sender.rsplit("@", 1)[-1].lower() if "@" in sender else ""
    
    # ============================================================
    # 1. ANALISIS DE AUTENTICACION (SPF/DKIM/DMARC)
    # ============================================================
    spf = str(auth.get("spf", "")).lower()
    dmarc = str(auth.get("dmarc", "")).lower()
    dkim = str(auth.get("dkim", "")).lower()
    
    spf_fail = "fail" in spf
    spf_softfail = "softfail" in spf or "~all" in spf
    dmarc_fail = "fail" in dmarc
    dkim_fail = "fail" in dkim
    auth_none = not spf and not dmarc and not dkim
    
    if spf_fail:
        score += 25
        reasons.append("SPF fail: remitente no autorizado")
        reglas_aplicadas.append("AUTH_SPF_FAIL")
    elif spf_softfail:
        score += 12
        reasons.append("SPF softfail: remitente sospechoso")
        reglas_aplicadas.append("AUTH_SPF_SOFTFAIL")
    
    if dmarc_fail:
        score += 20
        reasons.append("DMARC fail: politica de dominio violada")
        reglas_aplicadas.append("AUTH_DMARC_FAIL")
    
    if dkim_fail:
        score += 15
        reasons.append("DKIM fail: firma digital invalida")
        reglas_aplicadas.append("AUTH_DKIM_FAIL")
    
    if auth_none:
        score += 8
        reasons.append("sin registros de autenticacion (SPF/DKIM/DMARC)")
        reglas_aplicadas.append("AUTH_NONE")
    
    # ============================================================
    # 2. BLACKLIST DE DOMINIOS MALICIOSOS (extendida)
    # ============================================================
    blacklist_dominios = [
        # Dominios de phishing conocidos
        "malware-domain.net", "phish-campaign.com", "spam-hub.info",
        "fraud-bank-es.xyz", "cuenta-blue.red", "verifica-seg.rok",
        "banco-falso.com", "login-seguro.xyz", "act-cuenta.com",
        "recuperar-password.net", "verify-cuenta.ml", "secure-login.tk",
        # TLDs sospechosos comunmente usados en phishing
        ".tk", ".ml", ".ga", ".cf", ".gq",
        # Patrones sospechosos
        "paypal-secure", "amazon-verify", "apple-id", "microsoft-account",
        "google-security", "facebook-support", "whatsapp-verify",
        "bancosantander", "bbvanet", "lacaixa", "ing-direct"
    ]
    
    for mal_domain in blacklist_dominios:
        if mal_domain in domain or mal_domain in " ".join(links):
            score += 45
            reasons.append(f"dominio en blacklist: {mal_domain}")
            reglas_aplicadas.append("DOMAIN_BLACKLIST")
            categorias.append("phish")
            break
    
    # ============================================================
    # 3. DETECCION DE PHISHING (patrones extendidos)
    # ============================================================
    phishing_patterns = [
        # Solicitudes de credenciales
        (r"(ingres[ae]|introduzca|proporcione|confirme).*(contrase[nñ]a|password|clave|pin|codigo)", 35, "solicita credenciales"),
        (r"(contrase[nñ]a|password|clave).*[:=]\s*\S+", 40, "credencial en texto"),
        (r"(usuario|user|email).*[:=].*password.*[:=]", 45, "formato login sospechoso"),
        
        # Urgencia y amenazas
        (r"(urgente|inmediato|ahora|ya|rapido).*(cuenta|sesion|acceso)", 25, "urgencia + cuenta"),
        (r"(bloqueada?|suspendida?|cancelada?|desactivada?).*(cuenta|tarjeta|acceso)", 30, "amenaza de bloqueo"),
        (r"(ultimo|final|ultima).*(aviso|oportunidad|advertencia)", 25, "presion temporal"),
        (r"(24|48|72)\s*(horas?|hrs?)", 20, "limite de tiempo"),
        (r"(caduca|expira|vence).*(hoy|ma[nñ]ana|pronto)", 22, "expiracion inminente"),
        
        # Acciones sospechosas
        (r"(verifi(que|car)|confirme|actualice|reactive).*(cuenta|datos|informacion)", 28, "solicita verificacion"),
        (r"(haga?\s*)?clic.*(aqui|aqu[ií]|link|enlace|boton)", 20, "solicita click"),
        (r"(descargue?|abra|ejecute).*(adjunto|archivo|documento|factura)", 25, "solicita abrir adjunto"),
        
        # Instituciones financieras
        (r"(banco|bbva|santander|caixa|ing).*(verifi|confirm|actualiz|suspend)", 32, "suplantacion bancaria"),
        (r"(paypal|amazon|ebay|apple|microsoft|google).*(account|cuenta|verify|confirm)", 30, "suplantacion tech"),
        (r"hacienda|agencia tributaria|sat|sunat|dian.*devolucion|reembolso", 28, "suplantacion fiscal"),
        
        # URLs ofuscadas o sospechosas
        (r"https?://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", 25, "URL con IP directa"),
        (r"https?://[^/]*@", 30, "URL con autenticacion embebida"),
        (r"bit\.ly|tinyurl|goo\.gl|ow\.ly|short\.link", 15, "acortador de URL"),
        
        # Tecnicas de ofuscacion
        (r"[a-z]{1}[\s\u200b\u200c\u200d]+[a-z]{1}", 18, "caracteres invisibles"),
        (r"p[a4@]y[p|]?[a4@]l|[a4@]m[a4@]z[o0]n|g[o0]{2}gle", 28, "leetspeak/homoglyphs"),
    ]
    
    phish_detections = 0
    for pattern, peso, descripcion in phishing_patterns:
        if re.search(pattern, haystack, re.IGNORECASE):
            score += peso
            reasons.append(f"patron phishing: {descripcion}")
            reglas_aplicadas.append(f"PHISH_{descripcion.upper().replace(' ', '_')[:20]}")
            phish_detections += 1
            if phish_detections == 1:
                categorias.append("phish")
    
    # ============================================================
    # 4. DETECCION DE MALWARE
    # ============================================================
    malware_patterns = [
        (r"(factura|invoice|receipt|orden|pedido|tracking).*\d+.*\.(zip|rar|7z|exe)", 40, "factura falsa con ejecutable"),
        (r"(documento|document|file).*protegido.*macro", 35, "documento con macros"),
        (r"macro.*(habilitad|enabled|activar|enable)", 38, "solicita habilitar macros"),
        (r"(click|clic|abra|open).*(enable|habilitar|activar).*content", 32, "solicita habilitar contenido"),
        (r"(descargu?e|download).*(urgente|importante|confidencial)", 28, "descarga urgente"),
        (r"ejecutar como administrador|run as administrator", 42, "solicita permisos elevados"),
    ]
    
    malware_detections = 0
    for pattern, peso, descripcion in malware_patterns:
        if re.search(pattern, haystack, re.IGNORECASE):
            score += peso
            reasons.append(f"patron malware: {descripcion}")
            reglas_aplicadas.append(f"MALWARE_{descripcion.upper().replace(' ', '_')[:20]}")
            malware_detections += 1
            if malware_detections == 1:
                categorias.append("malware")
    
    # Analisis de adjuntos maliciosos
    if attachments:
        for att in attachments:
            filename = att.get("filename", "").lower()
            size = att.get("size", 0)
            ctype = att.get("content_type", "").lower()
            
            # Extensiones peligrosas
            extensiones_peligrosas = [
                (".exe", 50, "ejecutable Windows"),
                (".scr", 48, "screensaver ejecutable"),
                (".bat", 45, "batch script"),
                (".cmd", 45, "command script"),
                (".com", 48, "ejecutable DOS"),
                (".pif", 47, "program information file"),
                (".vbs", 42, "VBScript"),
                (".js", 40, "JavaScript"),
                (".jar", 38, "Java executable"),
                (".hta", 45, "HTML application"),
                (".ps1", 40, "PowerShell script"),
                (".msi", 35, "Windows installer"),
            ]
            
            for ext, peso, desc in extensiones_peligrosas:
                if filename.endswith(ext):
                    score += peso
                    reasons.append(f"adjunto peligroso: {desc} ({filename})")
                    reglas_aplicadas.append(f"ATTACH_{ext[1:].upper()}")
                    if "malware" not in categorias:
                        categorias.append("malware")
            
            # Doble extension sospechosa
            if re.search(r"\.(pdf|doc|xls|txt|jpg|png)\.(exe|scr|bat|vbs|js)", filename):
                score += 45
                reasons.append(f"doble extension sospechosa: {filename}")
                reglas_aplicadas.append("ATTACH_DOUBLE_EXT")
                if "malware" not in categorias:
                    categorias.append("malware")
            
            # Documentos Office con macros
            if filename.endswith((".docm", ".xlsm", ".pptm", ".dotm", ".xltm")):
                score += 32
                reasons.append(f"documento Office con macros: {filename}")
                reglas_aplicadas.append("ATTACH_OFFICE_MACRO")
                if "malware" not in categorias:
                    categorias.append("malware")
            
            # Archivos comprimidos sospechosos
            if filename.endswith((".zip", ".rar", ".7z", ".tar", ".gz")):
                if any(palabra in haystack for palabra in ["factura", "invoice", "pedido", "orden", "dhl", "fedex"]):
                    score += 28
                    reasons.append(f"archivo comprimido en contexto sospechoso: {filename}")
                    reglas_aplicadas.append("ATTACH_ARCHIVE_SUSP")
            
            # Tamano anomalo
            if size < 1024 and filename.endswith((".pdf", ".doc", ".xls")):
                score += 18
                reasons.append(f"documento sospechosamente pequeno: {filename} ({size} bytes)")
                reglas_aplicadas.append("ATTACH_SIZE_ANOMALY")
    
    # ============================================================
    # 5. DETECCION DE SPAM
    # ============================================================
    spam_patterns = [
        (r"(viagra|cialis|levitra|pharmacy)", 30, "farmacia ilegal"),
        (r"(casino|poker|ruleta|apuesta|lottery|loteria)", 28, "juego/apuestas"),
        (r"(ganar dinero|make money|earn \$|trabajo desde casa)", 25, "esquema dinero facil"),
        (r"(ampliar|agrandar|alargar).*(pene|miembro)", 35, "spam adulto"),
        (r"(descuento|discount|oferta|deal).*(90%|80%|70%|gratis|free)", 22, "oferta excesiva"),
        (r"(replica|imitacion).*(rolex|gucci|prada|louis vuitton)", 25, "productos falsificados"),
        (r"(herencia|inheritance|millones de dolares|lottery winner)", 28, "estafa nigeriana"),
        (r"(conozca|meet).*(mujeres|women|chicas|girls|singles)", 26, "spam citas"),
        (r"(peso|weight).*(perder|lose|adelgaz)", 24, "dietas milagro"),
    ]
    
    spam_detections = 0
    for pattern, peso, descripcion in spam_patterns:
        if re.search(pattern, haystack, re.IGNORECASE):
            score += peso
            reasons.append(f"patron spam: {descripcion}")
            reglas_aplicadas.append(f"SPAM_{descripcion.upper().replace(' ', '_')[:20]}")
            spam_detections += 1
            if spam_detections == 1:
                categorias.append("spam")
    
    # Indicadores adicionales de spam
    if subject.count("!") >= 3:
        score += 12
        reasons.append(f"exceso de exclamaciones en asunto ({subject.count('!')})")
        reglas_aplicadas.append("SPAM_EXCLAMATION")
    
    if subject.isupper() and len(subject) > 10:
        score += 15
        reasons.append("asunto completamente en mayusculas")
        reglas_aplicadas.append("SPAM_ALL_CAPS")
    
    if re.search(r"[\$€£]\s*\d+", subject):
        score += 10
        reasons.append("cantidades monetarias en asunto")
        reglas_aplicadas.append("SPAM_MONEY_SUBJECT")
    
    # ============================================================
    # 6. ANALISIS DE URLs
    # ============================================================
    if links:
        for url in links[:10]:  # Analizar max 10 URLs
            url_lower = url.lower()
            
            # IP directa en lugar de dominio
            if re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url):
                score += 22
                reasons.append("URL con IP directa (sin dominio)")
                reglas_aplicadas.append("URL_IP_DIRECT")
            
            # Puerto no estandar
            if re.search(r":\d{2,5}/", url) and ":80/" not in url and ":443/" not in url:
                score += 18
                reasons.append("URL con puerto no estandar")
                reglas_aplicadas.append("URL_NONSTANDARD_PORT")
            
            # Usuario/password en URL
            if "@" in url.split("/")[2] if len(url.split("/")) > 2 else False:
                score += 28
                reasons.append("URL con credenciales embebidas")
                reglas_aplicadas.append("URL_EMBEDDED_CREDS")
            
            # Dominio sospechosamente largo
            try:
                domain_part = url.split("//")[1].split("/")[0]
                if len(domain_part) > 50:
                    score += 20
                    reasons.append("dominio sospechosamente largo")
                    reglas_aplicadas.append("URL_LONG_DOMAIN")
            except:
                pass
        
        # Exceso de URLs
        if len(links) > 15:
            score += min(25, len(links) - 15)
            reasons.append(f"exceso de URLs ({len(links)})")
            reglas_aplicadas.append("URL_EXCESSIVE")
    
    # ============================================================
    # 7. ANOMALIAS DEL REMITENTE
    # ============================================================
    
    # Display name vs dominio inconsistente
    if "<" in sender and ">" in sender:
        display_name = sender.split("<")[0].strip().lower()
        email_part = sender.split("<")[1].split(">")[0].lower()
        
        # Nombre dice "banco" pero email no es del banco
        instituciones = ["paypal", "amazon", "google", "microsoft", "apple", "facebook", 
                        "banco", "santander", "bbva", "caixa", "hacienda"]
        for inst in instituciones:
            if inst in display_name and inst not in email_part:
                score += 35
                reasons.append(f"spoofing: nombre muestra '{inst}' pero dominio no coincide")
                reglas_aplicadas.append("SENDER_SPOOFING")
                if "phish" not in categorias:
                    categorias.append("phish")
                break
    
    # Dominio con guiones o numeros excesivos
    if domain and (domain.count("-") >= 3 or len(re.findall(r"\d", domain)) >= 4):
        score += 15
        reasons.append("dominio con patron sospechoso")
        reglas_aplicadas.append("SENDER_DOMAIN_PATTERN")
    
    # Dominio recien registrado (heuristica: TLDs baratos)
    tlds_baratos = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".win", ".review"]
    if any(domain.endswith(tld) for tld in tlds_baratos):
        score += 20
        reasons.append("TLD de alto riesgo")
        reglas_aplicadas.append("SENDER_RISKY_TLD")
    
    # ============================================================
    # 8. DETERMINAR ACCION Y VEREDICTO FINAL
    # ============================================================
    
    # Normalizar score
    score = int(max(0, min(100, score)))
    
    # Renombrar reglas a formato KSMG real
    reglas_ksmg = []
    for regla in reglas_aplicadas:
        if regla.startswith("AUTH_"):
            reglas_ksmg.append(f"KSMG_{regla}")
        elif regla.startswith("PHISH_") or regla.startswith("MALWARE_") or regla.startswith("SPAM_") or regla.startswith("URL_") or regla.startswith("SENDER_") or regla.startswith("ATTACH_"):
            reglas_ksmg.append(f"KSMG_{regla}")
        elif regla == "DOMAIN_BLACKLIST":
            reglas_ksmg.append("KSMG_BLACKLIST_DOMAIN")
        else:
            reglas_ksmg.append(f"KSMG_{regla}")
    
    # Determinar accion del gateway
    if score >= 70 or "malware" in categorias:
        accion = "block"
        verdict = "malicious"
        reasons.insert(0, f"ACCION GATEWAY: BLOCK (score {score}/100)")
    elif score >= 40 or len(categorias) >= 2:
        accion = "quarantine"
        verdict = "suspicious"
        reasons.insert(0, f"ACCION GATEWAY: QUARANTINE (score {score}/100)")
    else:
        accion = "deliver"
        verdict = "clean" if score < 20 else "suspicious"
        reasons.insert(0, f"ACCION GATEWAY: DELIVER (score {score}/100)")
    
    # Construir cabeceras X-Kaspersky simuladas
    cabeceras_ksmg = {
        "x-kaspersky-anti-spam-action": accion.upper(),
        "x-kaspersky-anti-spam-score": str(score),
    }
    
    # Agregar categorias a cabeceras
    if categorias:
        cats_unicas = list(set(categorias))
        cabeceras_ksmg["x-kaspersky-threats"] = ", ".join(cats_unicas)
    
    # Agregar reglas aplicadas a cabeceras
    if reglas_ksmg:
        cabeceras_ksmg["x-kaspersky-rules"] = "; ".join(reglas_ksmg[:10])
    
    # Agregar auth results a cabeceras
    auth_results = []
    if auth.get("spf"):
        auth_results.append(f"spf={auth.get('spf')}")
    if auth.get("dkim"):
        auth_results.append(f"dkim={auth.get('dkim')}")
    if auth.get("dmarc"):
        auth_results.append(f"dmarc={auth.get('dmarc')}")
    if auth_results:
        cabeceras_ksmg["x-kaspersky-auth-results"] = "; ".join(auth_results)
    
    # Construir evidencia (formato identico a KSMG real)
    evidence["real"] = False  # Marca como simulado
    evidence["fuente"] = "KSMG simulado (motor heuristico avanzado)"
    evidence["accion"] = accion
    evidence["categorias"] = list(set(categorias))  # phishing, malware, spam, clean
    evidence["reglas"] = reglas_ksmg[:15]  # Max 15 reglas con prefijo KSMG_
    evidence["score_gateway"] = score
    evidence["reliability"] = min(95, 60 + min(35, len(reglas_ksmg) * 2))  # Confiabilidad basada en reglas
    evidence["cabeceras"] = cabeceras_ksmg  # Cabeceras X-Kaspersky simuladas
    
    # Asegurar que siempre se indique modo simulado
    if not any("simulado" in str(r).lower() for r in reasons):
        reasons.append("Motor KSMG simulado activo (sin gateway real conectado)")
    
    return score, reasons[:20], evidence  # Max 20 razones


# -------------------------------------------------------------------- ClamAV
def engine_clamav(msg: dict) -> dict:
    """Simula ClamAV: coincidencia de firmas sobre adjuntos (sha256)."""
    score = 0
    reasons = []
    conn = _conn()
    for att in msg.get("attachments", []):
        fam = conn.execute(
            "SELECT family, severity FROM signatures WHERE sha256=?", (att.get("sha256", ""),)
        ).fetchone()
        if fam:
            score += fam[1]
            reasons.append(f"firma ClamAV: {fam[0]}")
    conn.close()

    extensions_band = [".exe", ".scr", ".vbs", ".js", ".hta", ".jar", ".dll", ".ps1"]
    for att in msg.get("attachments", []):
        fn = (att.get("filename") or "").lower()
        if any(fn.endswith(e) for e in extensions_band):
            score += 12
            reasons.append(f"adjunto bandeado: {fn}")
    return _verdict("ClamAV", score, reasons)


# ---------------------------------------------------------------------- YARA
YARA_RULES = [
    {
        "name": "phishing_credencial",
        "pattern": r"(password|contrasena|contrasena|clave|credenciales?)\s*[:=]\s*\S+",
        "weight": 25,
    },
    {
        "name": "url_ofuscada",
        "pattern": r"(http[s]?://)?\S*%[0-9a-fA-F]{2}\S*",
        "weight": 15,
    },
    {
        "name": "adjunto_doble_ext",
        "pattern": r"\w+\.(?:txt|jpg|png|pdf)\.(?:exe|scr|js|bat|cmd|vbs|hta)",
        "weight": 40,
    },
    {
        "name": "palabra_clave_banco",
        "pattern": r"\b(banco|caixa|santander|bbva|bcp|banrisul|cliente|confirmacion|actualizar datos)\b",
        "weight": 20,
    },
    {
        "name": "link_shortener",
        "pattern": r"https?://(bit\.ly|tinyurl\.com|t\.me|goo\.gl|cutt\.ly|rb\.gy)/\S+",
        "weight": 15,
    },
    {
        "name": "manifiesta_adjunto_office",
        "pattern": r"(\.docm|\.xlsm|\.pptm|\.docx|\.xlsx)\s+(adjunt|documento|factura|invoice|recibo)",
        "weight": 18,
    },
]

_re_cache = {r["name"]: re.compile(r["pattern"], re.IGNORECASE) for r in YARA_RULES}


def engine_yara(msg: dict) -> dict:
    score = 0
    reasons = []
    haystack = " ".join([
        msg.get("subject", ""),
        msg.get("body", ""),
        " ".join(a.get("filename", "") for a in msg.get("attachments", [])),
        msg.get("sender", ""),
    ])
    for rule in YARA_RULES:
        if _re_cache[rule["name"]].search(haystack):
            score += rule["weight"]
            reasons.append(f"regla YARA: {rule['name']}")
    return _verdict("YARA", score, reasons)


# --------------------------------------------------------------------- Sandbox
def engine_sandbox(msg: dict) -> dict:
    """Simula CAPE/Cuckoo: detonacion de adjuntos en entorno aislado."""
    score = 0
    reasons = []
    displayable = [".docm", ".xlsm", ".docx", ".xls", ".doc", ".pdf", ".exe", ".scr", ".jar"]
    for att in msg.get("attachments", []):
        fn = (att.get("filename") or "").lower()
        if any(fn.endswith(e) for e in displayable):
            size = att.get("size", 0)
            reasons.append(f"detonado en sandbox: {fn}")
            score += 10
            if size > 200_000:
                score += 5
                reasons.append("tamano sospechoso")
    # si no hay nada para detonar, el sandbox no aporta
    if not reasons:
        return {"engine": "Sandbox", "score": 0, "verdict": BENIGN, "reasons": ["sin adjuntos detonables"], "skip": True}
    score += 15  # la detonacion en si misma denota mayor riesgo de analisis
    reasons.append("analisis en entorno aislado")
    return _verdict("Sandbox", score, reasons)


# ----------------------------------------------------------------- ML local
class LocalNLPModel:
    """Mini modelo NLP local (logistic + pesos de n-gramas) para phishing ES/PT.

    Sustituto funcional del modelo ONNX/TFLite. Los pesos se cargan de
    models/ml_phishing.json si existe; si no, se usan pesos heuristicos.
    """

    def __init__(self, model_path: Path = None):
        self.model_path = Path(
            model_path or (config.BASE_DIR / "app" / "data" / "ml_phishing_es_pt.json")
        )
        self.weights = self._load()

    def _load(self) -> dict:
        if self.model_path.exists():
            try:
                return json.loads(self.model_path.read_text(encoding="utf-8"))
            except Exception:
                pass
        return {
            "phishing": 2.1, "urgente": 1.6, "inmediato": 1.5, "cuenta": 1.7,
            "bloqueada": 1.9, "password": 1.6, "clave": 1.3, "actualice": 1.8,
            "verifique": 1.5, "confirme": 1.4, "datos": 0.9, "haga clic": 1.6,
            "banco": 1.5, "caixa": 1.4, "seguridad": 1.0, "importante": 0.9,
            "adjunto": 0.7, "factura": 0.8, "win": 1.7, "prize": 1.9, "promocion": 1.2,
            "sospechoso": 0.5, "reembolso": 1.6, "oficial": -0.6, "hola": -0.3,
            "atentamente": -0.5, "saludos": -0.4, "gracias": -0.4,
        }

    def score(self, msg: dict) -> float:
        text = (msg.get("subject", "") + " " + msg.get("body", "")).lower()
        s = 0.0
        for k, w in self.weights.items():
            if k in text:
                s += w
        # penaliza presencia de SPF/DKIM legitimo
        auth = msg.get("auth") or {}
        if auth.get("spf") and "pass" in auth["spf"].lower():
            s -= 0.8
        if auth.get("dkim") and "pass" in auth["dkim"].lower():
            s -= 0.6
        if "verificate" in text or "clique aqui" in text:
            s += 1.8
        if "account" in text or "cuenta" in text:
            s += 1.0
        return max(-5.0, min(10.0, s))


_local_model = LocalNLPModel()


def engine_ml(msg: dict) -> dict:
    """Motor ML local (sin APIs externas)."""
    s = _local_model.score(msg)
    score = int(max(0, min(100, s * 10)))
    reasons = []
    if s > 4:
        reasons.append("clasificado phishing por modelo local (es/pt)")
    elif s > 2:
        reasons.append("probable phishing: patrones de ingenieria social local")
    else:
        reasons.append("contenido normal segun modelo local")
    return _verdict("ML-Local", score, reasons)


# ------------------------------------------------------------- Adjuntos/estatico
def engine_static(msg: dict) -> dict:
    """Analisis estatico: macros OOXML, pdfs peligrosos, scripts."""
    score = 0
    reasons = []
    for att in msg.get("attachments", []):
        fn = (att.get("filename") or "").lower()
        if fn.endswith((".docm", ".xlsm", ".pptm")):
            score += 30
            reasons.append(f"macro-ooxml: {fn}")
        if fn.endswith(".pdf"):
            score += 25
            reasons.append("pdf pendiente analisis (posible /JavaScript)")
        if fn.endswith((".ps1", ".vbs", ".js", ".hta", ".bat", ".cmd", ".scr")):
            score += 35
            reasons.append(f"script embebido: {fn}")
    return _verdict("Adjuntos", score, reasons)


# ------------------------------------------------------------------- fusion
ENGINES = [
    ("KSMG", engine_ksmg),
    ("ClamAV", engine_clamav),
    ("YARA", engine_yara),
    ("Sandbox", engine_sandbox),
    ("ML-Local", engine_ml),
    ("Adjuntos", engine_static),
]

# pesos por defecto
ENGINE_WEIGHTS = {
    "KSMG": 0.25,
    "ClamAV": 0.20,
    "YARA": 0.15,
    "Sandbox": 0.10,
    "ML-Local": 0.15,
    "Adjuntos": 0.15,
}


def run_all_engines(msg: dict) -> dict:
    results = {}
    for name, fn in ENGINES:
        try:
            v = fn(msg)
        except Exception as e:  # pragma: no cover
            v = {"engine": name, "score": 0, "verdict": BENIGN, "reasons": [f"error motor: {e}"]}
        results[name] = v
    return results


def _verdict(engine: str, score: int, reasons: list) -> dict:
    score = int(max(0, min(100, score)))
    if score >= config.BLOCK_THRESHOLD:
        verdict = MALICIOUS
    elif score >= config.QUARANTINE_THRESHOLD:
        verdict = SUSPICIOUS
    else:
        verdict = BENIGN
    return {"engine": engine, "score": score, "verdict": verdict, "reasons": reasons}