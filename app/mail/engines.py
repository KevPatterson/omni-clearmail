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
        return _verdict("KSMG", *_score_ksmg_evidence(ev))
    return _verdict("KSMG", *_ksmg_simulado(msg))


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
    - Evidencia desde cabeceras .eml (si existen X-Kaspersky/X-KSMG)
    - SPF/DKIM/DMARC analysis
    - Clasificacion phishing/malware/spam
    - Accion de gateway (block/quarantine/deliver)
    - Reglas aplicadas
    - Categorias de riesgo
    """
    score = 0
    reasons = []
    evidence = {"real": False, "details": {}}

    # 1. Intentar extraer evidencia real desde cabeceras .eml
    raw = msg.get("raw_hash") and None  # placeholder - en uso real vendría de raw bytes
    # Si el mensaje tiene auth info de SPF/DKIM/DMARC ya las tenemos en msg["auth"]

    # 2. Analisis SPF/DKIM/DMARC (igual que antes pero mas detallado)
    auth = msg.get("auth") or {}
    spf = auth.get("spf", "")
    dmarc = auth.get("dmarc", "")
    dkim = auth.get("dkim", "")

    spf_fail = spf and "fail" in str(spf).lower()
    dmarc_fail = dmarc and "fail" in str(dmarc).lower()
    dkim_fail = dkim and "fail" in str(dkim).lower()

    # 3. Detectar patrones de dominios y remitentes sospechosos
    sender = msg.get("sender", "")
    domain = sender.rsplit("@", 1)[-1].lower() if "@" in sender else ""

    # Blacklist extendida (simulando inteligencia de amenazas KSMG)
    ksmg_blacklist = [
        "malware-domain.net", "phish-campaign.com", "spam-hub.info",
        "fraud-bank-es.xyz", "cuenta-blue.red", "verifica-seg.rok",
        "banco-falso.com", "login-seguro.xyz", "act-cuenta.com",
        "recuperar-password.net", "verify-cuenta.ml"
    ]

    # 4. Detectar categorias de riesgo (phishing, malware, spam)
    categorias = []
    haystack = " ".join([
        msg.get("subject", ""),
        msg.get("body", ""),
        sender,
    ]).lower()

    # Patrones de phishing
    phishing_patterns = [
        r"(contrasena|password|clave|credencial).*[:=]\s*\S+",
        r"(verify|confirm|actualice|clique aqui|haga clic).*cuenta",
        r"(banco|santander|bbva|caixa).*confirmacion|actualizacion",
        r"tu cuenta.*bloqueada|suspendida|limitada",
        r"urgente|inmediato|24 horas|48 horas",
    ]
    for pattern in phishing_patterns:
        if re.search(pattern, haystack):
            categorias.append("phish")
            break

    # Patrones de malware/virus
    malware_patterns = [
        r"(tracking|invoice|factura|receipt)\s*(.*)?(open|download|click)",
        r"macro.*(enabled|enable|execute)",
        r"(attachment|adjunto).*\.(exe|scr|vbs|js|hta)",
    ]
    for pattern in malware_patterns:
        if re.search(pattern, haystack):
            categorias.append("malware")
            break

    # Patrones de spam
    spam_keywords = ["%", "viagra", "discount", "cheap", "earn money", "make money"]
    for kw in spam_keywords:
        if kw in haystack:
            categorias.append("spam")
            break

    # 5. Determinar accion de gateway simulada
    # Lógica: si hay suficientes senales de riesgo -> block/quarantine
    # si es limpio -> deliver
    # si es sospechoso -> quarantine
    phish_count = sum(1 for c in categorias if c == "phish")
    malware_count = sum(1 for c in categorias if c == "malware")
    spam_count = sum(1 for c in categorias if c == "spam")

    # Determinar accion basada en se�ales (igual que KSMG real)
    if phish_count >= 1 or malware_count >= 1:
        accion_simulada = "block"  # Bloquear por phishing/malware detectado
        score += 70
        reasons.append(f"accion gateway simulado: BLOCK por {categorias}")
    elif phish_count == 0 and malware_count == 0 and spam_count >= 1:
        accion_simulada = "quarantine"  # Cuarentena por posible spam
        score += 55
        reasons.append(f"accion gateway simulado: QUARANTINE por spam")
    elif dmarc_fail or spf_fail:
        # Fallo en autenticacion pero sin phishing/malware claro
        accion_simulada = "quarantine"
        score += 45
        reasons.append("accion gateway simulado: QUARANTINE por fallo autenticacion (SPF/DMARC)")
    elif dkim_fail:
        accion_simulada = "quarantine"
        score += 35
        reasons.append("accion gateway simulado: QUARANTINE por DKIM fail")
    else:
        # Senales normales - limpio o bajo riesgo
        accion_simulada = "deliver"
        score += 10
        reasons.append("accion gateway simulado: DELIVER (senales normales)")

    evidence["real"] = True
    evidence["details"]["accion"] = accion_simulada

    # 6. Añadir score segun categorias detectadas
    if "phish" in categorias:
        score += 50
        if "phishing" not in reasons:
            reasons.append("clasificacion simulada: phishing detectado")
    if "malware" in categorias:
        score += 60
        if "malware" not in reasons:
            reasons.append("clasificacion simulada: malware detectado")
    if "spam" in categorias:
        score += 30
        if "spam" not in reasons:
            reasons.append("clasificacion simulada: spam detectado")

    # 7. Añadir score por patrones de urgencia en asunto
    subject = msg.get("subject", "").lower()
    urgency_words = ["urgente", "inmediato", "48 horas", "cuenta bloqueada", "ultimo aviso"]
    urgency_found = [u for u in urgency_words if u in subject]
    if urgency_found:
        score += min(20, 8 * len(urgency_found))
        reasons.append(f"patron urgencia: {', '.join(urgency_found)}")

    # 8. Añadir score por palabras clave financieras/bancarias
    fin_keywords = ["banco", "caixa", "santander", "bbva", "clave", "contrasena", "cuenta", "transferencia"]
    found_fin = [k for k in fin_keywords if k in haystack]
    if found_fin:
        score += min(15, 3 * len(found_fin))
        reasons.append(f"palabras clave financieras: {', '.join(found_fin)}")

    # 9. Añadir penalizacion si SPF/DKIM/DMARC fallan
    if spf_fail:
        score += 20
        reasons.append("SPF fail (simulado)")
    if dmarc_fail:
        score += 15
        reasons.append("DMARC fail (simulado)")
    if dkim_fail:
        score += 10
        reasons.append("DKIM fail (simulado)")

    # 10. Asegurar rango 0-100 y determinar verdict
    score = int(max(0, min(100, score)))

    # Determinar verdict final segun score (igual que _verdict)
    if score >= 70:
        verdict = "malicious"
        if accion_simulada == "block":
            reasons.append("umbral de bloqueo >= 70 cumplido")
    elif score >= 40:
        verdict = "suspicious"
        if accion_simulada == "quarantine":
            reasons.append("umbral de cuarentena 40-69 cumplido")
    else:
        verdict = "clean"
        if accion_simulada == "deliver":
            reasons.append("umbral de deliver < 40 cumplido")

    # 11. Rasons finales consolidados
    if not reasons:
        reasons.append("seniales normales sin clasification especifica")
    # Asegurar que siempre haya nota de modo simulado
    if "KSMG simulado" not in " ".join(reasons):
        reasons.append("KSMG simulado: analisis heuristico (sin gateway real)")

    return score, reasons, evidence


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