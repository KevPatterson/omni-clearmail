"""Capa de integracion con Kaspersky Secure Mail Gateway (KSMG) real.

Provee conectores reales que alimentan Omni-CleanerMail con los mensajes y
la evidencia que KSMG reenvia/exporta:

- EML_WATCH  : vigilancia de un directorio con ficheros .eml (+ sidecar .json).
- IMAP       : poll sobre el buzón/quarentena de KSMG (imaplib, stdlib).
- SMTP       : receptor SMTP local al que KSMG puede reenviar el trafico
               (RFC 5321 minimo, stdlib socketserver).

Cuando un conector entrega un mensaje, se extrae la evidencia real del
gateway (cabeceras X-Kaspersky*/X-KSMG, authentication-results, sidecar JSON)
que alimenta al motor KSMG con datos reales. Sin conector activo, el motor
KSMG opera en modo simulado para el MVP.
"""
import email
import email.policy
import imaplib
import json
import re
import socket
import socketserver
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

from app import config
from app.core import hashchain
from app.mail import engines, parser, quarantine, scoring

MODOS = ("SIMULADO", "EML_WATCH", "IMAP", "SMTP")

_CONN_LOCK = threading.Lock()
_POLL_ACTIVE = False
_POLL_STOP = threading.Event()
_POLL_THREAD = None
_SMTP_SERVER = None
_SMTP_BIND = None

_MAX_MSG_SIZE = 25 * 1024 * 1024


# ------------------------------------------------------------------ base datos
def _conn():
    conn = sqlite3.connect(config.DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_ksmg():
    conn = _conn()
    conn.execute(
        "CREATE TABLE IF NOT EXISTS ksmg_config "
        "(id INTEGER PRIMARY KEY CHECK (id=1), config_json TEXT NOT NULL)"
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS ksmg_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            connector TEXT NOT NULL,
            source TEXT,
            msg_id TEXT,
            outcome TEXT NOT NULL,
            detail TEXT
        )"""
    )
    conn.commit()
    if conn.execute("SELECT id FROM ksmg_config WHERE id=1").fetchone() is None:
        conn.execute(
            "INSERT INTO ksmg_config (id, config_json) VALUES (1, ?)",
            (json.dumps(_default_config(), ensure_ascii=False),),
        )
    conn.commit()
    conn.close()


def _default_config() -> dict:
    return {
        "modo": config.KSMG_MODO,
        "host": config.KSMG_HOST,
        "port": config.KSMG_PORT,
        "user": config.KSMG_USER,
        "password": config.KSMG_PASSWORD,
        "use_ssl": config.KSMG_USE_SSL,
        "imap_folder": config.KSMG_IMAP_FOLDER,
        "watch_dir": config.KSMG_WATCH_DIR,
        "poll_seconds": config.KSMG_POLL_SECONDS,
        "auto_arranque": config.KSMG_AUTO_START,
        "smtp_bind": config.KSMG_SMTP_BIND,
        "smtp_port": config.KSMG_SMTP_PORT,
        "max_por_poll": 200,
    }


_VALID_KEYS = set(_default_config().keys())


def load_config() -> dict:
    conn = _conn()
    row = conn.execute("SELECT config_json FROM ksmg_config WHERE id=1").fetchone()
    conn.close()
    cfg = _default_config()
    if row:
        try:
            cfg.update(json.loads(row[0]))
        except Exception:
            pass
    return cfg


def save_config(payload: dict) -> dict:
    cfg = _default_config()
    for k, v in (payload or {}).items():
        if k == "password":
            if v:
                cfg["password"] = str(v)
        elif k in _VALID_KEYS:
            cfg[k] = v
    if cfg["modo"] not in MODOS:
        cfg["modo"] = "SIMULADO"
    for k in ("port", "poll_seconds", "smtp_port", "max_por_poll"):
        try:
            cfg[k] = int(cfg.get(k) or 0)
        except (TypeError, ValueError):
            cfg[k] = 0
    for k in ("use_ssl", "auto_arranque"):
        cfg[k] = bool(cfg[k])
    cfg["poll_seconds"] = max(5, cfg["poll_seconds"])
    cfg["max_por_poll"] = max(1, cfg["max_por_poll"])
    conn = _conn()
    conn.execute(
        "UPDATE ksmg_config SET config_json=? WHERE id=1",
        (json.dumps(cfg, ensure_ascii=False),),
    )
    conn.commit()
    conn.close()

    if cfg["auto_arranque"] and not _POLL_ACTIVE and cfg["modo"] != "SIMULADO":
        start_poller()
    if cfg["modo"] == "SIMULADO":
        stop_poller()
        stop_smtp()
    return public_config(cfg)


def public_config(cfg: dict = None) -> dict:
    cfg = dict(cfg or load_config())
    cfg["password"] = ""
    return cfg


def record_event(connector: str, source: str, msg_id: str, outcome: str, detail: str):
    with _CONN_LOCK:
        conn = _conn()
        conn.execute(
            "INSERT INTO ksmg_events (ts, connector, source, msg_id, outcome, detail) "
            "VALUES (?,?,?,?,?,?)",
            (
                datetime.now(timezone.utc).isoformat(),
                connector, source, msg_id, outcome, str(detail)[:500],
            ),
        )
        conn.commit()
        conn.close()


def list_events(limit: int = 50) -> list:
    conn = _conn()
    rows = conn.execute(
        "SELECT id, ts, connector, source, msg_id, outcome, detail "
        "FROM ksmg_events ORDER BY id DESC LIMIT ?",
        (min(limit, 500),),
    ).fetchall()
    conn.close()
    return [
        {"id": r[0], "ts": r[1], "connector": r[2], "source": r[3],
         "msg_id": r[4], "outcome": r[5], "detail": r[6]}
        for r in rows
    ]


# ---------------------------------------------------------- evidencia real KSMG
def evidence_from_headers(raw: bytes) -> dict:
    """Extrae evidencia del gateway desde las cabeceras reales del mensaje."""
    try:
        msg = email.message_from_bytes(raw, policy=email.policy.default)
    except Exception:
        return {"real": False}
    headers = {}
    veredictos = []
    reglas = []
    action = ""
    for key in msg.keys():
        lk = key.lower()
        values = msg.get_all(key) or [""]
        val = " ".join(str(v) for v in values).strip()
        if lk.startswith(("x-kaspersky", "x-ksmg", "x-kl", "x-spam")):
            headers[lk] = val[:400]
            low = val.lower()
            if "action" in lk:
                action = val
            for token in ("phish", "malware", "virus", "spam"):
                if token in low and token not in veredictos:
                    veredictos.append(token)
            if "clean" in low and "clean" not in veredictos:
                veredictos.append("clean")
        elif lk in ("received-spf", "authentication-results", "dkim-signature"):
            headers[lk] = val[:400]
    rule_marker = re.compile(r"rule[=:\s]+([a-z0-9_.-]+)", re.I)
    for val in headers.values():
        reglas.extend(rule_marker.findall(val))
    if not headers:
        return {"real": False}
    return {
        "real": True,
        "fuente": "cabeceras KSMG reales",
        "accion": action,
        "categorias": veredictos[:6],
        "reglas": reglas[:10],
        "cabeceras": headers,
    }


def evidence_from_json(data: dict) -> dict:
    """Evidencia desde un sidecar JSON exportado por KSMG (junto al .eml)."""
    if not isinstance(data, dict):
        return {"real": False}
    return {
        "real": True,
        "fuente": "export KSMG (sidecar JSON)",
        "accion": data.get("action", ""),
        "categorias": data.get("verdicts") or data.get("categorias") or [],
        "reglas": data.get("rules") or [],
        "score_gateway": data.get("score"),
        "reliability": data.get("reliability", 0),
    }


def normalize_evidence(ev: dict) -> dict:
    ev = ev or {}
    return {
        "real": bool(ev.get("real")),
        "fuente": ev.get("fuente", ""),
        "accion": ev.get("accion", ""),
        "categorias": list(ev.get("categorias") or []),
        "reglas": list(ev.get("reglas") or []),
        "score_gateway": ev.get("score_gateway"),
        "reliability": ev.get("reliability", 0),
    }


# -------------------------------------------------------------- procesado
def process_raw_message(raw: bytes, connector: str, source: str = "",
                        evidence: dict = None) -> dict:
    """Parseo, analisis multi-motor y persistencia de un mensaje real."""
    msg = parser.parse_message(raw)
    if evidence and evidence.get("real"):
        msg["ksmg"] = normalize_evidence(evidence)
    else:
        hev = evidence_from_headers(raw)
        if hev.get("real"):
            msg["ksmg"] = hev
    results = engines.run_all_engines(msg)
    fused = scoring.fused_score(results)
    quarantine.save_message(msg, results, fused, direction="ENTRADA")
    hashchain.append(
        "mail_ingested", f"KSMG-{connector}",
        {"msg_id": msg["msg_id"], "vote": fused["vote"], "source": source or connector},
    )
    record_event(connector, source or connector, msg["msg_id"], "ok",
                 f"vote={fused['vote']} score={fused['composite_score']}")
    return msg


# ------------------------------------------------------------ conectores
def connector_eml_watch(cfg: dict) -> dict:
    d = Path(cfg.get("watch_dir") or "")
    if not d.exists() or not d.is_dir():
        raise FileNotFoundError(f"directorio de vigilancia inexistente: {d}")
    done = d / "procesados"
    fail = d / "errores"
    done.mkdir(exist_ok=True)
    fail.mkdir(exist_ok=True)
    pendientes = [p for p in sorted(d.glob("*.eml")) if p.is_file()]
    procesados = 0
    for f in pendientes:
        try:
            raw = f.read_bytes()
            ev = None
            side = f.with_suffix(f.suffix + ".json")
            if side.exists():
                try:
                    ev = evidence_from_json(json.loads(side.read_text(encoding="utf-8")))
                except Exception:
                    ev = None
            process_raw_message(raw, "EML_WATCH", source=f.name, evidence=ev)
            f.replace(done / f.name)
            procesados += 1
        except Exception as e:
            record_event("EML_WATCH", f.name, "", "error", str(e))
            try:
                f.replace(fail / f.name)
            except Exception:
                pass
    return {"procesados": procesados, "pendientes": len(pendientes)}


def _imap_connect(cfg: dict):
    port = int(cfg.get("port") or (993 if cfg.get("use_ssl") else 143))
    cls = imaplib.IMAP4_SSL if cfg.get("use_ssl") else imaplib.IMAP4
    m = cls(str(cfg.get("host") or ""), port, timeout=15)
    m.login(str(cfg.get("user") or ""), str(cfg.get("password") or ""))
    return m


def connector_imap(cfg: dict, dry_run: bool = False) -> dict:
    m = _imap_connect(cfg)
    try:
        m.select(str(cfg.get("imap_folder") or "INBOX"))
        typ, data = m.search(None, "UNSEEN")
        ids = data[0].split() if data and data[0] else []
        if dry_run:
            return {"procesados": 0, "pendientes": len(ids)}
        procesados = 0
        for num in ids[: int(cfg.get("max_por_poll") or 200)]:
            typ, msg_data = m.fetch(num, "(RFC822)")
            if typ != "OK" or not msg_data or not msg_data[0]:
                continue
            first = msg_data[0]
            raw = b""
            if isinstance(first, tuple) and len(first) > 1 and isinstance(first[1], bytes):
                raw = first[1]
            if not raw:
                continue
            try:
                process_raw_message(raw, "IMAP", source=f"uid:{num.decode()}")
                m.store(num, "+FLAGS", "\\Seen")
                procesados += 1
            except Exception as e:
                record_event("IMAP", f"uid:{num.decode()}", "", "error", str(e))
        return {"procesados": procesados, "pendientes": len(ids)}
    finally:
        try:
            m.logout()
        except Exception:
            pass


# ------------------------------------------------------------ receptor SMTP
class _SMTPHandler(socketserver.StreamRequestHandler):
    """Receptor SMTP minimo (RFC 5321) para que KSMG reenvie el trafico."""

    def setup(self):
        super().setup()
        self.connection.settimeout(120)
        self._reset()

    def _reset(self):
        self._from = ""
        self._rcpts = []

    def _smtp_send(self, line: str):
        self.wfile.write((line + "\r\n").encode("utf-8"))
        self.wfile.flush()

    def _read_data(self, size_limit: int) -> bytes:
        lines = []
        total = 0
        while True:
            line = self.rfile.readline()
            if not line:
                break
            if line in (b".\r\n", b".\n", b"."):
                break
            if line.startswith(b".."):
                line = line[1:]
            lines.append(line)
            total += len(line)
            if total > size_limit:
                return None
        return b"".join(lines)

    def handle(self):
        self._smtp_send("220 Omni-CleanerMail KSMG ESMTP receiver ready")
        while True:
            try:
                line = self.rfile.readline()
            except Exception:
                break
            if not line:
                break
            line = line.decode("utf-8", "replace").rstrip("\r\n")
            if not line.strip():
                continue
            cmd = line.split(" ", 1)[0].upper()
            arg = line[len(cmd):].strip() if len(line) > len(cmd) else ""
            if cmd in ("EHLO", "HELO"):
                self._smtp_send("250-Omni-CleanerMail KSMG receiver")
                self._smtp_send("250 SIZE 26214400")
            elif cmd == "MAIL":
                m = re.search(r"from:\s*<([^>]*)>", arg, re.I) or \
                    re.search(r"from:\s*(\S+)", arg, re.I)
                self._from = m.group(1) if m else ""
                self._smtp_send("250 OK")
            elif cmd == "RCPT":
                m = re.search(r"to:\s*<([^>]*)>", arg, re.I) or \
                    re.search(r"to:\s*(\S+)", arg, re.I)
                if m:
                    self._rcpts.append(m.group(1))
                self._smtp_send("250 OK")
            elif cmd == "DATA":
                self._smtp_send("354 End data with <CR><LF>.<CR><LF>")
                raw = self._read_data(_MAX_MSG_SIZE)
                if raw is None:
                    self._smtp_send("552 5.3.4 Message too big")
                else:
                    try:
                        msg = process_raw_message(raw, "SMTP", source=self._from or "smtp")
                        self._smtp_send(f"250 2.0.0 OK queued msg_id={msg['msg_id']}")
                    except Exception as e:
                        record_event("SMTP", self._from or "", "", "error", str(e))
                        self._smtp_send("451 4.3.0 local processing error")
                self._reset()
            elif cmd == "RSET":
                self._reset()
                self._smtp_send("250 OK")
            elif cmd == "NOOP":
                self._smtp_send("250 OK")
            elif cmd == "HELP":
                self._smtp_send("214 MAIL RCPT DATA RSET NOOP QUIT")
            elif cmd == "QUIT":
                self._smtp_send("221 2.0.0 Bye")
                break
            else:
                self._smtp_send("500 5.5.1 Command not recognized")


class _SMTPThreadingServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def ensure_smtp(cfg: dict) -> dict:
    if _SMTP_SERVER is not None:
        return {"bind": _SMTP_BIND[0], "port": _SMTP_BIND[1]}
    return start_smtp(cfg)


def start_smtp(cfg: dict) -> dict:
    global _SMTP_SERVER, _SMTP_BIND
    stop_smtp()
    host = str(cfg.get("smtp_bind") or "127.0.0.1")
    port = int(cfg.get("smtp_port") or 2525)
    _SMTP_SERVER = _SMTPThreadingServer((host, port), _SMTPHandler)
    _SMTP_BIND = _SMTP_SERVER.server_address
    threading.Thread(target=_SMTP_SERVER.serve_forever, daemon=True).start()
    return {"bind": _SMTP_BIND[0], "port": _SMTP_BIND[1]}


def stop_smtp():
    global _SMTP_SERVER, _SMTP_BIND
    if _SMTP_SERVER is not None:
        try:
            _SMTP_SERVER.shutdown()
            _SMTP_SERVER.server_close()
        except Exception:
            pass
    _SMTP_SERVER = None
    _SMTP_BIND = None


# ------------------------------------------------------------ poller
def start_poller() -> dict:
    global _POLL_ACTIVE, _POLL_THREAD, _POLL_STOP
    if _POLL_ACTIVE and _POLL_THREAD is not None and _POLL_THREAD.is_alive():
        return {"ok": True, "msg": "poller ya activo"}
    _POLL_ACTIVE = True
    _POLL_STOP = threading.Event()
    _POLL_THREAD = threading.Thread(target=_poller_loop, daemon=True)
    _POLL_THREAD.start()
    return {"ok": True, "msg": "poller iniciado"}


def stop_poller() -> dict:
    global _POLL_ACTIVE
    _POLL_STOP.set()
    _POLL_ACTIVE = False
    return {"ok": True, "msg": "poller detenido"}


def _poller_loop():
    while not _POLL_STOP.is_set():
        cfg = load_config()
        poll_once(cfg)
        intervalo = max(5, int(cfg.get("poll_seconds") or 30))
        _POLL_STOP.wait(intervalo)


def poll_once(cfg: dict = None) -> dict:
    cfg = cfg or load_config()
    modo = cfg.get("modo", "SIMULADO")
    try:
        if modo == "EML_WATCH":
            res = connector_eml_watch(cfg)
            detalle = f"{res['procesados']} procesados, {res['pendientes']} en cola"
        elif modo == "IMAP":
            res = connector_imap(cfg)
            detalle = f"{res['procesados']} procesados, {res['pendientes']} pendientes"
        elif modo == "SMTP":
            res = ensure_smtp(cfg)
            detalle = f"receptor SMTP activo en {res['bind']}:{res['port']}"
        else:
            stop_smtp()
            detalle = "modo simulado (sin conector real)"
            _set_health(False, detalle)
            return {"modo": modo, "conectado": False, "detalle": detalle}
        _set_health(True, detalle)
        return {"modo": modo, "conectado": True, "detalle": detalle}
    except Exception as e:
        detalle = f"error en {modo}: {e}"
        _set_health(False, detalle)
        record_event(modo, "", "", "error", detalle)
        return {"modo": modo, "conectado": False, "detalle": detalle}


def _set_health(conectado: bool, detalle: str):
    conn = _conn()
    conn.execute(
        "CREATE TABLE IF NOT EXISTS ksmg_stats "
        "(id INTEGER PRIMARY KEY CHECK (id=1), stats_json TEXT NOT NULL)"
    )
    stats = {"conectado": conectado, "detalle": detalle,
             "verificado": datetime.now(timezone.utc).isoformat()}
    conn.execute(
        "INSERT INTO ksmg_stats (id, stats_json) VALUES (1, ?) "
        "ON CONFLICT(id) DO UPDATE SET stats_json=excluded.stats_json",
        (json.dumps(stats, ensure_ascii=False),),
    )
    conn.commit()
    conn.close()


def _stats_load() -> dict:
    conn = _conn()
    try:
        row = conn.execute("SELECT stats_json FROM ksmg_stats WHERE id=1").fetchone()
    except sqlite3.OperationalError:
        row = None
    conn.close()
    if row:
        try:
            return json.loads(row[0])
        except Exception:
            pass
    return {"conectado": False, "detalle": "", "verificado": None}


def status() -> dict:
    cfg = load_config()
    stats = _stats_load()
    counts = {"ok": 0, "error": 0}
    conn = _conn()
    for outcome, n in conn.execute(
        "SELECT outcome, COUNT(*) FROM ksmg_events GROUP BY outcome"
    ).fetchall():
        counts[outcome] = n
    conn.close()
    watch = None
    if cfg.get("modo") == "EML_WATCH":
        d = Path(cfg.get("watch_dir") or "")
        if d.is_dir():
            watch = len([p for p in d.glob("*.eml") if p.is_file()])
    return {
        "config": public_config(cfg),
        "modo": cfg.get("modo"),
        "conectado": stats.get("conectado"),
        "detalle": stats.get("detalle", ""),
        "verificado": stats.get("verificado"),
        "poller_activo": _POLL_ACTIVE and _POLL_THREAD is not None and _POLL_THREAD.is_alive(),
        "smtp_activo": _SMTP_SERVER is not None,
        "procesados": counts.get("ok", 0),
        "errores": counts.get("error", 0),
        "en_cola": watch,
    }


def test_connection(cfg: dict = None) -> dict:
    cfg = cfg or load_config()
    modo = cfg.get("modo", "SIMULADO")
    try:
        if modo == "EML_WATCH":
            d = Path(cfg.get("watch_dir") or "")
            if not d.exists() or not d.is_dir():
                return {"ok": False, "detalle": f"directorio inexistente: {d}"}
            n = len([p for p in d.glob("*.eml") if p.is_file()])
            return {"ok": True, "detalle": f"{n} ficheros .eml pendientes en {d}"}
        if modo == "IMAP":
            res = connector_imap(cfg, dry_run=True)
            return {"ok": True, "detalle": f"IMAP OK · {res['pendientes']} mensajes sin leer"}
        if modo == "SMTP":
            if _SMTP_SERVER is not None:
                return {"ok": True, "detalle": "receptor SMTP activo en "
                        f"{_SMTP_BIND[0]}:{_SMTP_BIND[1]}"}
            try:
                s = socket.create_connection((cfg.get("smtp_bind") or "127.0.0.1",
                                              int(cfg.get("smtp_port") or 2525)), timeout=2)
                s.close()
            except OSError:
                return {"ok": True, "detalle":
                        "puerto libre; el receptor arranca al iniciar el poller"}
            return {"ok": False, "detalle": "puerto ocupado por otro proceso"}
        return {"ok": True, "detalle": "modo simulado: no hay conector que probar"}
    except Exception as e:
        return {"ok": False, "detalle": str(e)}