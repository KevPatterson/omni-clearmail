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


def _ksmg_simulado(msg: dict) -> tuple:
    """Heuristica local tipo KSMG cuando no hay gateway real conectado."""
    score = 0
    reasons = []
    sender = msg.get("sender", "")
    domain = sender.rsplit("@", 1)[-1].lower() if "@" in sender else ""

    blacklist = ["malware-domain.net", "phish-campaign.com", "spam-hub.info",
                 "fraud-bank-es.xyz", "cuenta-blue.red", "verifica-seg.rok"]
    if domain in blacklist:
        score += 60
        reasons.append(f"dominio negro (sim KSMG): {domain}")

    auth = msg.get("auth") or {}
    if auth.get("spf") and "fail" in auth["spf"].lower():
        score += 20
        reasons.append("SPF fail")
    if auth.get("dmarc") and "fail" in auth["dmarc"].lower():
        score += 15
        reasons.append("DMARC fail")
    if auth.get("dkim") and "fail" in auth["dkim"].lower():
        score += 10
        reasons.append("DKIM fail")

    subject = (msg.get("subject") or "").lower()
    urgency = ["urgente", "inmediato", "48 horas", "cuenta bloqueada", "ultimo aviso", "finalize ya"]
    for u in urgency:
        if u in subject:
            score += 8
            reasons.append(f"asunto urgencia '{u}'")
            break

    if score == 0:
        reasons.append("sin senales en modo simulado")
    reasons.append("KSMG simulado: conectar gateway real en Integracion KSMG")
    return score, reasons


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