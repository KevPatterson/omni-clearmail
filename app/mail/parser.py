"""Parsing de mensajes de correo (.eml / raw).

Extrae remitente, destinatarios, asunto, cuerpo, enlaces y adjuntos.
Ademas intenta leer cabeceras SPF/DKIM/DMARC si estan presentes.
"""
import email
import email.policy
import re
import hashlib

_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_MACRO_STRINGS = [
    "vbaProject", "auto_open", "auto_Close", "_VBA_PROJECT", "ThisDocument",
    "module1", "Private Sub", "ExecuteExcel4Macro", "Shell(", "WScript",
]
_PDF_DANGER = ["/JavaScript", "/OpenAction", "/Launch", "/EmbeddedFile", "/RichMedia"]


def parse_message(raw: bytes, msg_id: str = None) -> dict:
    msg = email.message_from_bytes(raw, policy=email.policy.default)

    sender = _safe_header(msg.get("From", ""))
    recipients = _split_addr(msg.get("To", "")) + _split_addr(msg.get("Cc", ""))
    subject = _safe_header(msg.get("Subject", ""))
    date = msg.get("Date", "")

    body_parts = []
    links = []
    attachments = []
    for part in msg.walk():
        ctype = part.get_content_type()
        disp = str(part.get("Content-Disposition", ""))
        if ctype == "multipart/alternative" or ctype == "multipart/related" or ctype == "multipart/mixed":
            continue
        if part.is_attachment() or (disp and "attachment" in disp.lower()):
            filename = part.get_filename() or "sin_nombre"
            payload = part.get_payload(decode=True) or b""
            attachments.append({
                "filename": filename,
                "content_type": ctype,
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest() if payload else "",
            })
        else:
            try:
                text = part.get_content()
            except Exception:
                text = part.get_payload(decode=True).decode("utf-8", errors="replace") if part.get_payload(decode=True) else ""
            if text:
                body_parts.append(text)
                links.extend(_URL_RE.findall(text))

    body = "\n".join(body_parts)

    auth = {
        "spf": _extract_auth(msg, "authentication-results", "spf"),
        "dkim": _extract_auth(msg, "authentication-results", "dkim"),
        "dmarc": _extract_auth(msg, "authentication-results", "dmarc"),
    }

    return {
        "msg_id": msg_id or hashlib.sha256(raw).hexdigest()[:16],
        "message_id_header": msg.get("Message-ID", ""),
        "sender": sender,
        "recipients": list(dict.fromkeys(recipients)),
        "subject": subject,
        "date": date,
        "body": body,
        "body_hash": hashlib.sha256(body.encode()).hexdigest(),
        "links": links,
        "attachments": attachments,
        "has_attachment": bool(attachments),
        "auth": auth,
        "size_bytes": len(raw),
        "raw_hash": hashlib.sha256(raw).hexdigest(),
    }


def _safe_header(v: str) -> str:
    return str(v).strip()


def _split_addr(v: str) -> list:
    if not v:
        return []
    return [a.strip() for a in re.split(r"[;,]", v) if a.strip()]


def _extract_auth(msg, header_name: str, method: str) -> str:
    value = msg.get(header_name, "")
    for token in value.split(";"):
        t = token.strip().lower()
        if t.startswith(method + "="):
            return t.split("=", 1)[1].strip()
        if method in t:
            return t
    return ""


def extract_macro_indicators(attachments: list) -> list:
    """Indicadores heuristicos: macros OOXML y pdfs peligrosos."""
    found = []
    for att in attachments:
        fn = (att.get("filename") or "").lower()
        if fn.endswith((".docm", ".xlsm", ".pptm", ".doc", ".xls")) and any(
            s.lower() in fn.replace(".docm", "").replace(".xlsm", "").replace(".pptm", "")
            for s in _MACRO_STRINGS
        ):
            found.append(f"macro-doc:{fn}")
        if fn.endswith(".pdf"):
            found.append("pdf-analysis:{fn}")
        if fn.endswith((".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".jar")):
            found.append(f"ejecutable:{fn}")
    return found