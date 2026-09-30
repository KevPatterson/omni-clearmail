"""Endpoints REST de la API de Omni-CleanerMail."""
import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, UploadFile
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.responses import JSONResponse, StreamingResponse, RedirectResponse

from app import config
from app.api import dashboard_data
from app.core import auth, hashchain, licensing
from app.mail import (addressbook, engines, findings, ksmg, parser, quarantine,
                      reports, scoring)

bearer = HTTPBearer(auto_error=False)

router = APIRouter(prefix="/api")

# Status de arranque: control manda por la licencia (LIL hook).
_boot = None


def _boot_state():
    global _boot
    if _boot is None:
        _boot = licensing.boot_check()
    return _boot


def _refresh_boot():
    """Re-evalua el estado de licencia tras una instalacion en caliente."""
    global _boot
    _boot = licensing.boot_check()


def _check_allowed():
    boot = _boot_state()
    if not boot.get("allowed"):
        raise HTTPException(status_code=426, detail=boot.get("message", "licencia requerida"))


def _claims(cred: HTTPAuthorizationCredentials):
    return auth.verify_token(cred.credentials)


def _require_roles(cred, *roles):
    claims = _claims(cred)
    try:
        auth.require_role(claims, *roles)
    except auth.AuthError as e:
        raise HTTPException(e.status, detail=e.args[0])
    return claims


def _audit(action, actor, data):
    if isinstance(data, dict):
        data = json.dumps(data, ensure_ascii=False, sort_keys=True)
    hashchain.append(action, actor, data)


# ------------------------------------------------------------------- sistema
@router.get("/health")
def health(request: Request, x_api_key: str = Header(None)):
    if x_api_key:
        try:
            auth.authenticate_api_key(x_api_key)
        except auth.AuthError:
            raise HTTPException(401, "clave invalida")
    else:
        if auth.rate_limit(request.client.host, config.RATE_LIMIT_API_PER_MIN):
            raise HTTPException(429, "rate limit")
    return {"status": "ok", "service": "Omni-CleanerMail", "version": "1.0.0"}


@router.get("/readyz")
def readyz():
    return {"ready": True, "boot": _boot_state()}


@router.get("/boot")
def boot():
    return _boot_state()


# ------------------------------------------------------------------ autentificacion
@router.post("/auth/login")
def login(request: Request, payload: dict):
    if auth.rate_limit(request.client.host, config.RATE_LIMIT_AUTH_PER_MIN, for_auth=True):
        raise HTTPException(429, detail="Demasiadas peticiones de login")
    username = payload.get("username")
    password = payload.get("password")
    try:
        result = auth.login(username, password)
    except auth.AuthError as e:
        _audit("login_failed", username or request.client.host, {"motivo": e.args[0]})
        raise HTTPException(e.status, detail=e.args[0])
    _audit("login_success", username or "?", {"ip": request.client.host})
    return result


@router.post("/auth/refresh")
def refresh(payload: dict):
    try:
        return auth.refresh_access(payload.get("refresh_token", ""))
    except auth.AuthError as e:
        raise HTTPException(e.status, detail=e.args[0])


@router.post("/auth/logout")
def logout(request: Request, cred: HTTPAuthorizationCredentials = Depends(bearer)):
    if not cred:
        raise HTTPException(401, "token requerido")
    claims = _claims(cred)
    auth.logout(claims)
    return {"ok": True}


@router.get("/auth/me")
def me(cred: HTTPAuthorizationCredentials = Depends(bearer)):
    if not cred:
        raise HTTPException(401, "token requerido")
    return _claims(cred)


# ------------------------------------------------------------------- API keys
@router.get("/secure/keys")
def list_keys(cred: HTTPAuthorizationCredentials = Depends(bearer)):
    claims = _require_roles(cred, "ADMIN", "SUPER_ADMIN")
    return auth.list_api_keys()


@router.post("/secure/keys")
def create_key(payload: dict, cred: HTTPAuthorizationCredentials = Depends(bearer)):
    claims = _require_roles(cred, "ADMIN", "SUPER_ADMIN")
    key = auth.generate_api_key(
        payload.get("label", f"key-{claims['sub']}"),
        payload.get("role", "OPERATOR"),
        payload.get("ttl_days"),
        payload.get("buzon"),
    )
    _audit("api_key_created", claims["sub"],
           {"label": payload.get("label", ""), "buzon": payload.get("buzon", "")})
    return key


@router.delete("/secure/keys/{key_id}")
def revoke_key(key_id: int, cred: HTTPAuthorizationCredentials = Depends(bearer)):
    claims = _require_roles(cred, "ADMIN", "SUPER_ADMIN")
    auth.revoke_api_key(key_id)
    _audit("api_key_revoked", claims["sub"], {"key_id": key_id})
    return {"ok": True}


# ------------------------------------------------------------------- ingesta
@router.post("/mail/ingest")
async def ingest(request: Request):
    """Ingesta de mensajes crudos (.eml). Simula la llegada al MTA."""
    body = await request.body()
    x_api_key = request.headers.get("X-API-Key")
    if x_api_key:
        try:
            auth.authenticate_api_key(x_api_key)
        except auth.AuthError:
            raise HTTPException(401, "clave invalida")
    else:
        _check_allowed()
    if auth.rate_limit(request.client.host, config.RATE_LIMIT_API_PER_MIN):
        raise HTTPException(429, "rate limit")

    msg = parser.parse_message(body)
    results = engines.run_all_engines(msg)
    fused = scoring.fused_score(results)
    status = quarantine.save_message(msg, results, fused)
    _audit("mail_ingested", "MTA", {"msg_id": msg["msg_id"], "vote": fused["vote"], "direction": "ENTRADA"})
    return {"msg_id": msg["msg_id"], "verdict": fused, "status": status}


@router.post("/mail/ingest-json")
def ingest_json(request: Request, payload: dict):
    """Ingesta estructurada para demo (sin .eml).

    `direction` (opcional) indica el flujo del correo respecto a la org:
    ENTRADA (recibido) o SALIDA (enviado por la org). Por defecto ENTRADA.
    """
    x_api_key = request.headers.get("X-API-Key")
    if x_api_key:
        try:
            auth.authenticate_api_key(x_api_key)
        except auth.AuthError:
            raise HTTPException(401, "clave invalida")
    else:
        _check_allowed()
    msg = {
        "msg_id": payload.get("msg_id") or datetime.now(timezone.utc).strftime("%H%M%S%f"),
        "sender": payload.get("sender", "remitente@demo.es"),
        "recipients": payload.get("recipients", []),
        "subject": payload.get("subject", ""),
        "body": payload.get("body", ""),
        "attachments": payload.get("attachments", []),
        "links": payload.get("links", []),
        "auth": payload.get("auth", {}),
    }
    direction = (payload.get("direction") or "ENTRADA").upper()
    results = engines.run_all_engines(msg)
    fused = scoring.fused_score(results)
    status = quarantine.save_message(msg, results, fused, direction=direction)
    _audit("mail_ingested", "MTA", {"msg_id": msg["msg_id"], "vote": fused["vote"], "direction": direction})
    return {"msg_id": msg["msg_id"], "verdict": fused, "status": status, "direction": direction}


# ------------------------------------------------------------------- KSMG
@router.get("/ksmg/status")
def ksmg_status(cred: HTTPAuthorizationCredentials = Depends(bearer)):
    _check_allowed()
    if not cred:
        raise HTTPException(401, "token requerido")
    _claims(cred)
    return ksmg.status()


@router.post("/ksmg/config")
def ksmg_save(payload: dict, cred: HTTPAuthorizationCredentials = Depends(bearer)):
    _check_allowed()
    claims = _require_roles(cred, "ADMIN", "SUPER_ADMIN")
    cfg = ksmg.save_config(payload)
    _audit("ksmg_config", claims["sub"],
           {"modo": cfg.get("modo"), "host": cfg.get("host"), "port": cfg.get("port")})
    return cfg


@router.post("/ksmg/test")
def ksmg_test(payload: dict = None, cred: HTTPAuthorizationCredentials = Depends(bearer)):
    _check_allowed()
    _require_roles(cred, "ADMIN", "SUPER_ADMIN")
    cfg = ksmg.load_config()
    if payload:
        cfg.update({k: v for k, v in payload.items() if k in ksmg._VALID_KEYS and k != "password"})
    return ksmg.test_connection(cfg)


@router.post("/ksmg/poll")
def ksmg_poll(cred: HTTPAuthorizationCredentials = Depends(bearer)):
    _check_allowed()
    _require_roles(cred, "ADMIN", "SUPER_ADMIN")
    return ksmg.poll_once()


@router.post("/ksmg/start")
def ksmg_start(cred: HTTPAuthorizationCredentials = Depends(bearer)):
    _check_allowed()
    _require_roles(cred, "ADMIN", "SUPER_ADMIN")
    return ksmg.start_poller()


@router.post("/ksmg/stop")
def ksmg_stop(cred: HTTPAuthorizationCredentials = Depends(bearer)):
    _check_allowed()
    _require_roles(cred, "ADMIN", "SUPER_ADMIN")
    return ksmg.stop_poller()


@router.get("/ksmg/events")
def ksmg_events(limit: int = 50, cred: HTTPAuthorizationCredentials = Depends(bearer)):
    _check_allowed()
    if not cred:
        raise HTTPException(401, "token requerido")
    _claims(cred)
    return {"eventos": ksmg.list_events(limit=limit)}


# ------------------------------------------------------------------- reportes por buzon
@router.get("/reporte-buzon/estado")
def reporte_buzon_estado(cred: HTTPAuthorizationCredentials = Depends(bearer)):
    _check_allowed()
    if not cred:
        raise HTTPException(401, "token requerido")
    _claims(cred)
    return reports.status()


@router.get("/reporte-buzon/ver")
def reporte_buzon_ver(buzon: str = "*", days: int = None,
                      cred: HTTPAuthorizationCredentials = Depends(bearer)):
    _check_allowed()
    if not cred:
        raise HTTPException(401, "token requerido")
    _claims(cred)
    try:
        return reports.build_report(buzon, days)
    except Exception as e:
        raise HTTPException(400, detail=f"no se pudo generar el reporte: {e}")


@router.get("/reporte-buzon/historial")
def reporte_buzon_historial(limit: int = 50,
                            cred: HTTPAuthorizationCredentials = Depends(bearer)):
    _check_allowed()
    if not cred:
        raise HTTPException(401, "token requerido")
    _claims(cred)
    return {"enviados": reports.list_envios(limit=limit)}


@router.post("/reporte-buzon/config")
def reporte_buzon_config(payload: dict,
                         cred: HTTPAuthorizationCredentials = Depends(bearer)):
    _check_allowed()
    claims = _require_roles(cred, "ADMIN", "SUPER_ADMIN")
    try:
        cfg = reports.save_config(
            payload.get("buzon", ""), payload.get("email", ""),
            payload.get("frecuencia", "DIARIO"), payload.get("hora", "08:00"),
            bool(payload.get("activo", True)))
    except ValueError as e:
        raise HTTPException(400, detail=str(e))
    _audit("reporte_config", claims["sub"], cfg)
    return cfg


@router.post("/reporte-buzon/eliminar")
def reporte_buzon_eliminar(payload: dict,
                           cred: HTTPAuthorizationCredentials = Depends(bearer)):
    _check_allowed()
    claims = _require_roles(cred, "ADMIN", "SUPER_ADMIN")
    res = reports.delete_config(payload.get("buzon", ""))
    _audit("reporte_config", claims["sub"], {"accion": "eliminar", **res})
    return res


@router.post("/reporte-buzon/enviar")
def reporte_buzon_enviar(payload: dict,
                         cred: HTTPAuthorizationCredentials = Depends(bearer)):
    _check_allowed()
    claims = _require_roles(cred, "ADMIN", "SUPER_ADMIN")
    buzon = payload.get("buzon", "*")
    days = payload.get("days") or payload.get("dias")
    email = payload.get("email")
    if not email:
        cfg = reports.load_config()
        row = next((c for c in cfg if c["buzon"] == buzon), None)
        email = row["email"] if row else None
    if not email:
        raise HTTPException(400, detail="email destino no configurado para este buzon")
    res = reports.send_report_email(buzon, email, days)
    _audit("reporte_enviado", claims["sub"],
           {"buzon": buzon, "email": email, "ok": res.get("ok"),
            "detalle": res.get("detalle")})
    return res


@router.post("/reporte-buzon/ejecutar")
def reporte_buzon_ejecutar(cred: HTTPAuthorizationCredentials = Depends(bearer)):
    _check_allowed()
    claims = _require_roles(cred, "ADMIN", "SUPER_ADMIN")
    res = reports.run_programados()
    _audit("reporte_ejecutado", claims["sub"],
           {"ejecutados": res["ejecutados"], "ok": res["ok"]})
    return res


@router.post("/reporte-buzon/smtp")
def reporte_buzon_smtp(payload: dict,
                       cred: HTTPAuthorizationCredentials = Depends(bearer)):
    """Guarda la configuracion SMTP salida (override de LOOK_SMTP_*)."""
    _check_allowed()
    claims = _require_roles(cred, "ADMIN", "SUPER_ADMIN")
    res = reports.save_smtp(payload)
    _audit("reporte_config", claims["sub"], {"accion": "smtp", "host": res["host"]})
    return res


@router.post("/reporte-buzon/smtp-test")
def reporte_buzon_smtp_test(payload: dict,
                            cred: HTTPAuthorizationCredentials = Depends(bearer)):
    """Envia un correo de prueba por el SMTP configurado."""
    _check_allowed()
    _require_roles(cred, "ADMIN", "SUPER_ADMIN")
    return reports.test_smtp()


@router.get("/reporte-buzon/mio")
def reporte_buzon_mio(request: Request, days: int = None,
                      cred: HTTPAuthorizationCredentials = Depends(bearer)):
    """Auto-reporte M2M: devuelve el informe del buzon vinculado a la API key.

    Requiere cabecera `X-API-Key` con una clave que tenga alcance de buzon.
    Los usuarios del panel solo pueden consultar buzon si su email coincide
    con un buzón interno de la organizacion.
    """
    _check_allowed()
    x_api_key = request.headers.get("X-API-Key")
    if x_api_key:
        try:
            claims = auth.authenticate_api_key(x_api_key)
        except auth.AuthError as e:
            raise HTTPException(e.status, detail=e.args[0])
        buzon = claims.get("buzon")
        if not buzon:
            raise HTTPException(403, "la API key no tiene alcance de buzon")
        try:
            return reports.build_report(buzon, days)
        except Exception as e:
            raise HTTPException(400, detail=f"no se pudo generar el reporte: {e}")
    if not cred:
        raise HTTPException(401, "token requerido o X-API-Key")
    claims = _claims(cred)
    buzon = claims.get("email") or ""
    if buzon and not reports.buzon_existe(buzon):
        buzon = ""
    if not buzon:
        raise HTTPException(403, "tu usuario no tiene un buzon interno asociado")
    try:
        return reports.build_report(buzon, days)
    except Exception as e:
        raise HTTPException(400, detail=f"no se pudo generar el reporte: {e}")


# ------------------------------------------------------------------- cuarentena
@router.get("/quarantine")
def get_quarantine(request: Request, status: str = None, search: str = None,
                   msg_id: str = None, cred: HTTPAuthorizationCredentials = Depends(bearer)):
    _check_allowed()
    if not cred:
        raise HTTPException(401, "token requerido")
    claims = _claims(cred)
    msgs = quarantine.list_messages(status=status, search=search, msg_id=msg_id, limit=300)
    return {"total": len(msgs), "mensajes": msgs}


@router.get("/quarantine/summary")
def quarantine_summary(cred: HTTPAuthorizationCredentials = Depends(bearer)):
    _check_allowed()
    if not cred:
        raise HTTPException(401, "token requerido")
    _claims(cred)
    return quarantine.quarantine_summary()


@router.post("/quarantine/{msg_id}/release")
def release(msg_id: str, payload: dict = None, cred: HTTPAuthorizationCredentials = Depends(bearer)):
    _check_allowed()
    claims = _require_roles(cred, "OPERATOR", "ADMIN", "SUPER_ADMIN")
    result = quarantine.action_release(msg_id, claims["sub"], (payload or {}).get("motivo", ""))
    if not result.get("ok"):
        raise HTTPException(400, result.get("error", "error"))
    return result


@router.post("/quarantine/{msg_id}/expunge")
def expunge(msg_id: str, payload: dict = None, cred: HTTPAuthorizationCredentials = Depends(bearer)):
    _check_allowed()
    claims = _require_roles(cred, "ADMIN", "SUPER_ADMIN")
    result = quarantine.action_expunge(msg_id, claims["sub"], (payload or {}).get("motivo", ""))
    if not result.get("ok"):
        raise HTTPException(400, result.get("error", "error"))
    return result


@router.post("/quarantine/{msg_id}/request-release")
def request_release(msg_id: str, cred: HTTPAuthorizationCredentials = Depends(bearer)):
    _check_allowed()
    claims = _claims(cred)
    result = quarantine.request_release(msg_id, claims["sub"])
    return result


# ------------------------------------------------------------------- dashboard
@router.get("/dashboard/overview")
def dashboard_overview(cred: HTTPAuthorizationCredentials = Depends(bearer)):
    _check_allowed()
    if not cred:
        raise HTTPException(401, "token requerido")
    _claims(cred)
    return dashboard_data.metrics_overview()


@router.get("/dashboard/department/{dept}")
def dashboard_department(dept: str, cred: HTTPAuthorizationCredentials = Depends(bearer)):
    _check_allowed()
    if not cred:
        raise HTTPException(401, "token requerido")
    _claims(cred)
    return dashboard_data.department_view(dept)


@router.get("/dashboard/user/{username}")
def dashboard_user(username: str, cred: HTTPAuthorizationCredentials = Depends(bearer)):
    _check_allowed()
    auth.require_role(_claims(cred), "USER", "OPERATOR", "ADMIN", "SUPER_ADMIN", "AUDITOR")
    return dashboard_data.user_risk_uri(username)


@router.get("/dashboard/engines")
def dashboard_engines(cred: HTTPAuthorizationCredentials = Depends(bearer)):
    _check_allowed()
    if not cred:
        raise HTTPException(401, "token requerido")
    _claims(cred)
    return dashboard_data.engine_coverage()


@router.get("/dashboard/license")
def dashboard_license(cred: HTTPAuthorizationCredentials = Depends(bearer)):
    _check_allowed()
    if not cred:
        raise HTTPException(401, "token requerido")
    _claims(cred)
    return dashboard_data.license_metrics()


# ------------------------------------------------------------------- hallazgos
@router.get("/findings")
def list_findings(severidad: str = None, tipo: str = None, status: str = None,
                  source: str = None, msg_id: str = None, search: str = None,
                  limit: int = 300, cred: HTTPAuthorizationCredentials = Depends(bearer)):
    _check_allowed()
    if not cred:
        raise HTTPException(401, "token requerido")
    _claims(cred)
    rows = findings.list_findings(severidad=severidad, tipo=tipo, status=status,
                                  source=source, msg_id=msg_id, search=search, limit=limit)
    return {"total": len(rows), "hallazgos": rows}


@router.get("/findings/summary")
def findings_summary(cred: HTTPAuthorizationCredentials = Depends(bearer)):
    _check_allowed()
    if not cred:
        raise HTTPException(401, "token requerido")
    _claims(cred)
    return findings.findings_summary()


@router.post("/findings/{finding_id}/status")
def findings_status(finding_id: int, payload: dict = None,
                    cred: HTTPAuthorizationCredentials = Depends(bearer)):
    _check_allowed()
    claims = _require_roles(cred, "OPERATOR", "ADMIN", "SUPER_ADMIN")
    result = findings.update_status(finding_id, (payload or {}).get("status", "REVISADO"))
    if not result.get("ok"):
        raise HTTPException(400, result.get("error", "error"))
    _audit("findings_status", claims["sub"], {"id": finding_id, "status": result["status"]})
    return result


# ------------------------------------------------------------------- direcciones
@router.get("/addresses")
def list_addresses(direction: str = None, role: str = None, domain: str = None,
                   verdict: str = None, search: str = None, internal: bool = None,
                   msg_id: str = None, limit: int = 500,
                   cred: HTTPAuthorizationCredentials = Depends(bearer)):
    _check_allowed()
    if not cred:
        raise HTTPException(401, "token requerido")
    _claims(cred)
    return {"registros": addressbook.list_addresses(
        direction=direction, role=role, domain=domain, verdict=verdict,
        search=search, internal=internal, msg_id=msg_id, limit=limit)}


@router.get("/addresses/summary")
def addresses_summary(cred: HTTPAuthorizationCredentials = Depends(bearer)):
    _check_allowed()
    if not cred:
        raise HTTPException(401, "token requerido")
    _claims(cred)
    return addressbook.address_summary()


# ------------------------------------------------------------------- reportes exportables
def _csv_response(content: str, filename: str):
    return StreamingResponse(
        iter([content]),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _json_file_response(content: str, filename: str):
    return StreamingResponse(
        iter([content]),
        media_type="application/json; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/report/addresses.csv")
def report_addresses_csv(direction: str = None, role: str = None, domain: str = None,
                         verdict: str = None, search: str = None, internal: bool = None,
                         msg_id: str = None, cred: HTTPAuthorizationCredentials = Depends(bearer)):
    _check_allowed()
    if not cred:
        raise HTTPException(401, "token requerido")
    _claims(cred)
    return _csv_response(
        addressbook.build_csv(direction=direction, role=role, domain=domain,
                              verdict=verdict, search=search, internal=internal,
                              msg_id=msg_id),
        "informe_direcciones_correo.csv")


@router.get("/report/addresses.json")
def report_addresses_json(direction: str = None, role: str = None, domain: str = None,
                          verdict: str = None, search: str = None, internal: bool = None,
                          msg_id: str = None, cred: HTTPAuthorizationCredentials = Depends(bearer)):
    _check_allowed()
    if not cred:
        raise HTTPException(401, "token requerido")
    _claims(cred)
    return _json_file_response(
        addressbook.build_json(direction=direction, role=role, domain=domain,
                               verdict=verdict, search=search, internal=internal,
                               msg_id=msg_id),
        "informe_direcciones_correo.json")


@router.get("/report/findings.csv")
def report_findings_csv(severidad: str = None, tipo: str = None, status: str = None,
                        source: str = None, msg_id: str = None, search: str = None,
                        cred: HTTPAuthorizationCredentials = Depends(bearer)):
    _check_allowed()
    if not cred:
        raise HTTPException(401, "token requerido")
    _claims(cred)
    return _csv_response(
        findings.build_csv(severidad=severidad, tipo=tipo, status=status, source=source,
                           msg_id=msg_id, search=search),
        "informe_hallazgos_seguridad.csv")


@router.get("/report/findings.json")
def report_findings_json(severidad: str = None, tipo: str = None, status: str = None,
                         source: str = None, msg_id: str = None, search: str = None,
                         cred: HTTPAuthorizationCredentials = Depends(bearer)):
    _check_allowed()
    if not cred:
        raise HTTPException(401, "token requerido")
    _claims(cred)
    return _json_file_response(
        findings.build_json(severidad=severidad, tipo=tipo, status=status, source=source,
                            msg_id=msg_id, search=search),
        "informe_hallazgos_seguridad.json")


# ------------------------------------------------------------------- auditoria
@router.get("/audit/actions")
def audit_actions(action: str = None, actor: str = None, limit: int = 500):
    return hashchain.list_entries(limit=min(limit, 2000), action=action, actor=actor)


@router.get("/audit/summary")
def audit_summary():
    result = hashchain.verify_chain()
    return {
        "entradas": result["entries"],
        "integridad_ok": not result["tampered"],
        "verificadas": result["verified"],
        "rotas": result["broken"],
    }


@router.get("/audit/verify")
def audit_verify():
    result = hashchain.verify_chain()
    return result


# ------------------------------------------------------------------- metricas (Prometheus)
@router.get("/metrics")
def metrics():
    data = dashboard_data.metrics_overview()
    lines = [
        "# HELP omni_messages_total Mensajes procesados",
        "# TYPE omni_messages_total counter",
        f"omni_messages_total {data['totales']['mensajes']}",
        f"omni_blocked_total {data['totales']['bloqueados']}",
        f"omni_quarantined_total {data['totales']['cuarentena']}",
        f"omni_block_rate {data['tasa_bloqueo']}",
        f"omni_org_risk_index {data['indice_riesgo_org']}",
    ]
    return Response(content="\n".join(lines), media_type="text/plain")


# ------------------------------------------------------------------- EULA licencia
@router.get("/licences/state")
def licence_state(cred: HTTPAuthorizationCredentials = Depends(bearer)):
    _check_allowed()
    if not cred:
        raise HTTPException(401, "token requerido")
    _claims(cred)
    return licensing.license_state()


@router.get("/licences/generate-request")
def generate_request(cliente_nombre: str = "", cliente_email: str = "", tipo: str = "hosting"):
    return licensing.generate_solicitud(cliente_nombre, cliente_email, tipo)


@router.post("/licences/install")
def install_licence(payload: dict):
    try:
        result = licensing.install_license(payload)
        if result.get("ok"):
            _refresh_boot()
        return result
    except ValueError as e:
        raise HTTPException(400, detail=str(e))


@router.post("/licences/install-upload")
async def install_upload(file: UploadFile, cred: HTTPAuthorizationCredentials = Depends(bearer)):
    _check_allowed()
    _require_roles(cred, "ADMIN", "SUPER_ADMIN")
    raw = await file.read()
    try:
        data = json.loads(raw.decode("utf-8"))
    except Exception:
        raise HTTPException(400, "fichero de licencia JSON invalido")
    try:
        result = licensing.install_license(data)
        if result.get("ok"):
            _refresh_boot()
        return result
    except ValueError as e:
        raise HTTPException(400, detail=str(e))


@router.post("/licences/heartbeat")
def do_heartbeat(cred: HTTPAuthorizationCredentials = Depends(bearer)):
    _check_allowed()
    _require_roles(cred, "ADMIN", "SUPER_ADMIN")
    return licensing.heartbeat()


@router.get("/licences/check-notices")
def check_notices(cred: HTTPAuthorizationCredentials = Depends(bearer)):
    _check_allowed()
    _require_roles(cred, "ADMIN", "SUPER_ADMIN")
    return {"avisos": licensing.check_expiry_notices()}


# ------------------------------------------------------------------- backup
@router.get("/backup/health")
def backup_health():
    from app.core import backup as bk
    return bk.status()