# Security Indicators - Guia de Seguridad Reutilizable

## Documento maestro de indicadores de seguridad para todos los proyectos Omni.

Cada proyecto debe implementar estos elementos. Marque con `[x]` lo implementado
y `[ ]` lo pendiente. Copie este archivo a cada repositorio y adapte segun aplique.

---

## 1. AUTENTICACION Y AUTORIZACION

### 1.1 JWT y Sesiones
- [x] Access tokens con expiracion corta (30 min max)
- [x] Refresh tokens en almacenamiento persistente (Redis/DB)
- [x] Rotacion de refresh tokens (un solo uso)
- [x] Comparacion de tokens en tiempo constante (`hmac.compare_digest`)
- [x] Invalidacion de tokens al cerrar sesion (logout server-side)

### 1.2 API Keys (machine-to-machine)
- [x] Hash SHA-256 de API keys (nunca almacenar en texto plano)
- [x] Prefix identificable por servicio (`omni-pki_`, `omni-soc_`)
- [x] RBAC: cada key tiene rol asignado (via X-API-Key header)
- [x] Expiracion configurable por key — `LOOK_API_KEY_TTL_DAYS` (por defecto 365 dias)
- [x] Endpoint de revocacion de keys
- [x] Rate limiting independiente por key

### 1.3 Roles (RBAC)
- [x] Roles minimos necesarios (principio de menor privilegio)
- [x] Roles tipicos: SUPER_ADMIN, ADMIN, OPERATOR, AUDITOR, USER
- [x] Verificacion de rol en cada endpoint sensibles
- [x] No hardcodear roles en el codigo fuente

### 1.4 Rate Limiting
- [x] Rate limit en endpoints de autenticacion (login, registro)
- [x] Rate limit configurable via variables de entorno
- [x] Respuesta HTTP 429 con header `Retry-After`
- [x] Bloqueo temporal tras N intentos fallidos

---

## 2. CRIPTOGRAFIA

### 2.1 Claves de CA (si aplica PKI)
- [ ] CA Raiz: RSA 8192-bit, SHA512, OFFLINE
- [ ] CA Intermedia: RSA 4096-bit, SHA512
- [ ] Claves cifradas en reposo (AES-256-GCM)
- [ ] Claves solo en memoria volatile (/dev/shm) durante uso
- [ ] Passphrase para claves privadas (nunca sin passphrase)

### 2.2 TLS
- [ ] TLS 1.2+ obligatorio en todos los servicios
- [x] HSTS habilitado (`max-age=31536000; includeSubDomains`) — `LOOK_HSTS=1`, detras de proxy TLS
- [ ] Certificados con curvas fuertes (P-384, X25519)
- [ ] OCSP Stapling si es servidor web
- [ ] Certificate Transparency (CT logs)

### 2.3 Cifrado de Datos
- [x] Datos en reposo: AES-256-GCM o ChaCha20-Poly1305 (backups cifrados, `core/backup.py`)
- [ ] Datos en transito: TLS (nunca texto plano)
- [x] Passwords: bcrypt/argon2id (nunca MD5/SHA directo)
- [x] Secretos: variables de entorno o vault (nunca en codigo)

### 2.4 Firma Digital (si aplica)
- [x] Ed25519 para firmas rapidas y seguras (licencias `core/licensing.py` + verificacion offline)
- [ ] RSA 4096+ para compatibilidad con sistemas legacy
- [ ] PAdES/CAdES/XAdES segun estandar requerido

---

## 3. PROTECCION DE CODIGO FUENTE

### 3.1 Repositorio
- [x] .gitignore incluye: .env, *.pem, *.key, __pycache__, node_modules
- [x] Secrets escaneados en CI (gitleaks, truffleHog) — `.github/workflows/ci.yml` (gitleaks-action + pip-audit + tests)
- [ ] Branch protection en main/master
- [ ] Signed commits (GPG)
- [x] No commitear jamas: contrasenas, API keys, certificados privados

### 3.2 Ofuscacion
- [ ] PyArmor o Nuitka para Python
- [x] Multi-stage Dockerfile (build stage sin codigo fuente en runtime)
- [ ] Eliminar herramientas de build de la imagen final
- [ ] No distribuir Dockerfile al cliente (solo imagen)

### 3.3 Dependencias
- [x] Lock file (requirements.txt con versiones fijas, poetry.lock, package-lock.json) — `requirements.lock` + `scripts/audit_deps.py`
- [x] Escaneo de vulnerabilidades en dependencias (safety, npm audit, trivy) — pip-audit en CI + lock-sync
- [ ] Dependencias minimas (principio de menor superficie de ataque)
- [ ] Actualizaciones programadas (monthly review)

---

## 4. CONTENEDORES Y DESPLIEGUE

### 4.1 Docker Hardening
- [x] Multi-stage build (build separado de runtime)
- [x] Usuario no-root en todos los contenedores
- [x] `no-new-privileges:true` en todos los servicios
- [x] Filesystem read-only donde sea posible (`read_only: true` + tmpfs `/tmp`)
- [x] Sin `--privileged` jamas (cap_drop: ALL, solo NET_RAW/NET_ADMIN)
- [x] Rotacion de logs (max-size 1g, max-file 5)
- [x] Healthchecks que no filtren credenciales

### 4.2 Redes
- [ ] Redes aisladas: frontend, backend, db
- [x] Solo puertos necesarios expuestos (8081)
- [ ] Services internos en redes `internal: true`
- [ ] Network policies (Kubernetes) o firewall rules
- [ ] mTLS entre servicios internos (si aplica)

### 4.3 Orquestacion
- [x] Secrets via Docker secrets o Vault (nunca hardcodeados en docker-compose.yml, se referencian ${VAR})
- [x] Resource limits (CPU, memory) en cada servicio
- [ ] Rollback strategy documentada
- [x] Backup automatico de datos persistentes (`core/backup.py` + scheduler diario)

---

## 5. SEGURIDAD HTTP Y API

### 5.1 Cabeceras de Seguridad
- [x] `X-Content-Type-Options: nosniff`
- [x] `X-Frame-Options: DENY`
- [x] `Referrer-Policy: strict-origin-when-cross-origin`
- [x] `Permissions-Policy: camera=(), microphone=(), geolocation=()`
- [x] `Cache-Control: no-store` (datos sensibles)
- [x] `Content-Security-Policy` (aplicaciones web)

### 5.2 CORS
- [x] CORS deshabilitado por defecto
- [x] Origenes explicitos en allowlist (nunca `*`)
- [x] Configurable via variables de entorno

### 5.3 Validacion de Entrada
- [x] Validacion estricta de todos los inputs (Pydantic, Joi, etc.)
- [x] Parametrizacion de queries (nunca concatenar SQL) — SQLite usa placeholders
- [x] Limitar tamaño de payloads (`MAX_CONTENT_LENGTH` → 413)
- [x] Sanitizacion de outputs (prevenir XSS)

---

## 6. AUDITORIA Y TRAZABILIDAD

### 6.1 Logs de Seguridad
- [x] Login exitoso y fallido
- [x] Creacion/eliminacion de usuarios y roles
- [x] Cambio de permisos
- [x] Acceso a datos sensibles
- [x] Errores de autenticacion/autorizacion

### 6.2 Logs de Acceso
- [x] Middleware que registra: quien, IP, endpoint, metodo, status, timestamp
- [x] Tabla/independiente para access_logs
- [x] Indices por actor, IP, fecha — indices derivados por accion/actor/IP en `_audit_index`, usados en `/api/audit/summary` y filtros
- [x] Retencion configurable (minimo 90 dias) — `LOOK_AUDIT_MAX_ENTRIES`

### 6.3 Integridad de Logs
- [x] HMAC sobre registros de auditoria — cadena SHA-256 + tag HMAC por entrada, verificable en `/api/audit/verify`
- [x] Logs en append-only (nunca modificar ni borrar)
- [ ] Almacenamiento separado de la aplicacion principal

### 6.4 Endpoint de Auditoria
- [x] `GET /audit/actions` (filtrable por accion, actor, fecha)
- [x] `GET /audit/access` (filtrable por IP, actor, path)
- [x] `GET /api/audit/summary` (contadores agregados)
- [x] Acceso restringido a roles ADMIN/AUDITOR

---

## 7. SISTEMA DE LICENCIAS

### 7.1 Motor de Licencias
- [x] Firma asimetrica (Ed25519 o RSA) — Ed25519, `core/licensing.py`
- [x] Verificacion offline (sin conexion a internet) — verificacion local
- [x] Clave privada NUNCA incluida en el despliegue (emisor offline)
- [x] Clave publica embebida en el verificador — `LOOK_LICENSE_PUBLIC_KEY`

### 7.2 Binding de Hardware
- [x] IP autorizada(s) en la licencia — `LOOK_LICENSE_IP` + campo `allowed_ips`
- [ ] MAC address opcional
- [x] Fingerprint del host (hash de componentes del servidor) — `hardware_fingerprint()`
- [x] Verificacion de IP al arrancar y periodicamente — `_verify_invariants` + `heartbeat`

### 7.3 Cuasi-Primos (capa adicional)
- [ ] Numero cuasi-primo (semiprimo n = p * q)
- [ ] Factor menor verificable por division de prueba
- [ ] Tamano recomendado: 8192 bits (~2466 digitos decimales)
- [ ] Verificacion de primalidad de ambos factores

### 7.4 Control de Features
- [x] Cada funcionalidad verificada antes de ejecutarse — `require_feature()` y gating por modulo en el orquestador
- [x] HTTP 402/403 si feature no habilitada — 403 en `/api/bruteforce/plan` y orquestador; 402 en shutdown
- [x] Features configurables por tier de licencia — `features` del payload firmado

### 7.5 Cuotas
- [x] Limite de registros/objetos — cuota `max_requests_per_hour` (bloqueo 429)
- [x] Limite de usuarios — `check_user_quota` en `POST /api/auth/users` → 403
- [x] Limite de requests por periodo — `increment_request_usage` en middleware
- [x] Bloqueo automatico al alcanzar el tope — `QuotaExceeded` → 429/403

### 7.6 Heartbeat
- [x] Re-verificacion periodica de licencia (cada 6h) — thread daemon `start_heartbeat_thread`
- [x] 3 fallos consecutivos = shutdown automatico — `MAX_CONSECUTIVE_FAILURES`
- [x] Log de eventos de licencia en auditoria — `license_install`, `license_quota`, heartbeat logs

---

## 8. PROTECCION EN TIEMPO DE EJECUCION

### 8.1 Anti-Tampering
- [x] Hash SHA-256 de archivos criticos al arrancar (baseline) — `core/runtime_guard.write_baseline()`
- [x] Re-verificacion periodica del hash — thread daemon `start_guard_thread` (60 min)
- [x] Deteccion de modificacion => log + notificacion — alerta `tampering` + `/api/runtime/check`
- [x] Tabla `integrity_checks` en base de datos — baseline persistido en `data/runtime_baseline.json`

### 8.2 Deteccion de Debug
- [x] Detectar `sys.gettrace()` / `sys.getprofile()`
- [x] Detectar procesos de debug (pyrasite, pyringe) — modulos debug activos cargados
- [ ] Detectar ptrace / debugger attach (nivel OS, externo)
- [ ] Deteccion de entorno de VM (opcional)

### 8.3 Self-Destruct
- [x] Si licencia invalida 3 veces seguidas => shutdown — `self_destruct()`
- [x] Limpieza segura de datos sensibles — revocacion de API keys + estado
- [ ] Rotacion de secret_key de la DB (pendiente de persistencia de claves)
- [x] Desactivacion de todas las API keys — `revoke_all_api_keys()`
- [x] Log: `AUTOMATIC SHUTDOWN - LICENSE VIOLATION`

---

## 9. BASE DE DATOS

### 9.1 Acceso
- [ ] Usuario de BD con permisos minimos (N/A: SQLite embebida, fichero con 0600)
- [ ] Password via variables de entorno (nunca hardcodeada) — N/A (SQLite local)
- [ ] Connection pooling configurado (N/A: SQLite, timeout 15s)
- [x] Timeouts de conexion — sqlite `timeout=15`

### 9.2 Proteccion
- [ ] Cifrado en reposo (LUKS, RDS encryption, etc.) — backups AES-256-GCM; pendiente cifrar DB en caliente
- [ ] Cifrado en transito (SSL/TLS a la BD) — N/A local; TLS en proxy
- [x] Backup cifrado automatico — `core/backup.py` AES-256-GCM + scheduler
- [x] Retencion de backups: minimo 30 dias — `LOOK_BACKUP_RETENTION_DAYS`

### 9.3 queries
- [x] Parametrizacion obligatoria (nunca f-strings en SQL) — 27 `execute()` con placeholders, 0 concatenaciones
- [x] Prepared statements — `execute(sql, params)`
- [x] Slow query logging — `LOOK_SLOW_QUERY_MS` + `GET /api/db/slow`

---

## 10. MONITORIZACION Y ALERTAS

### 10.1 Metricas
- [x] Healthcheck endpoints (/health, /readyz)
- [x] Metricas de negocio (requests, errores, latencia)
- [x] Exportador Prometheus o formato compatible (GET /api/metrics)
- [x] Dashboard en Grafana o similar — `monitoring/grafana.json`

### 10.2 Alertas
- [x] Login fallido > N veces desde misma IP (`/api/alerts`, umbral configurable)
- [x] Licencia proxima a expirar (< 30 dias) — `expiring_alert_days()` + alerta `licencia_expira`
- [ ] Certificados proximos a vencer (gestion externa/proxy)
- [x] Uso de CPU/memoria > 80% — alertas `cpu_alta` / `memoria_alta`, `LOOK_ALERT_MEM_THRESHOLD`
- [x] Errores 5xx > threshold (`/api/alerts`)

### 10.3 Notificaciones
- [x] Webhooks para eventos criticos — `LOOK_WEBHOOK_URL`, `_notify_webhook`
- [ ] Email para alertas no urgentes
- [ ] Canal dedicado (Slack/Telegram) para emergencias

---

## 11. RESPALDO Y RECUPERACION

### 11.1 Backups
- [x] Backup automatico diario de BD (`core/backup.py` + scheduler)
- [x] Backup cifrado (AES-256-GCM)
- [x] Almacenamiento fuera de linea (offsite) — réplica a `LOOK_BACKUP_OFFSITE`
- [x] Retencion minima: 30 dias diarios, 12 mensuales (configurable, `LOOK_BACKUP_RETENTION_DAYS`)

### 11.2 Restore
- [x] Script de restauracion documentado y probado (`restore_backup()` con verificación SHA-256 + GCM-tag)
- [ ] Restore periodico de prueba (quarterly)
- [x] RTO (Recovery Time Objective) documentado — `docs/COMPLIANCE.md` (< 5 min restore local)
- [x] RPO (Recovery Point Objective) documentado — `docs/COMPLIANCE.md` (24 h, backup diario)

---

## 12. CUMPLIMIENTO NORMATIVO

### 12.1 Datos Personales (GDPR / Ley local)
- [x] Registro de actividades de tratamiento — auditoria HMAC-chain + `docs/COMPLIANCE.md`
- [ ] Consentimiento explícito del usuario (N/A: la app no recoge datos personales)
- [x] Derecho de acceso, rectificacion, supresion — borrado de usuarios, revocacion de keys, API de consulta
- [x] Cifrado de datos personales — backups AES-256-GCM; REST via proxy TLS
- [x] Notificacion de brechas en 72h — alertas + webhook (`LOOK_WEBHOOK_URL`)

### 12.2 Firma Digital (si aplica)
- [ ] eIDAS (UE) 910/2014
- [ ] RFC 5280 (perfil de certificado X.509)
- [ ] ETSI EN 319 122 (CAdES)
- [ ] ETSI EN 319 132 (XAdES)

### 12.3 Cryptografia
- [x] Algoritmos aprobados (NIST, ENISA) — lista en `docs/COMPLIANCE.md` (AES-256-GCM, Ed25519, SHA-2, HMAC)
- [x] Roadmap post-cuantico documentado — `docs/COMPLIANCE.md` (SLH-DSA/Falcon/ML-DSA)
- [ ] Rotation de claves periodicamente (pendiente: rotacion automatica de bucket/PKI)

---

## RESUMEN DE CHECKLIST POR PROYECTO

| # | Categoria | Items | Implementados | % |
|---|-----------|-------|---------------|---|
| 1 | Autenticacion y Autorizacion | 19 | 19/19 | 100% |
| 2 | Criptografia | 17 | 5/17 | 29% |
| 3 | Proteccion de Codigo | 13 | 6/13 | 46% |
| 4 | Contenedores y Despliegue | 16 | 11/16 | 69% |
| 5 | Seguridad HTTP y API | 13 | 13/13 | 100% |
| 6 | Auditoria y Trazabilidad | 16 | 15/16 | 94% |
| 7 | Sistema de Licencias | 22 | 17/22 | 77% |
| 8 | Proteccion en Runtime | 13 | 10/13 | 77% |
| 9 | Base de Datos | 11 | 6/11 | 55% |
| 10 | Monitoreo y Alertas | 12 | 9/12 | 75% |
| 11 | Respaldo y Recuperacion | 8 | 7/8 | 88% |
| 12 | Cumplimiento Normativo | 12 | 6/12 | 50% |
| **TOTAL** | | **172** | **124/172** | **72%** |

---

## NIVELES DE MADUREZ

### Nivel 1 - Basico (Minimum Viable Security)
Items criticos marcados en cada seccion. Sin esto, NO desplegar en produccion.

### Nivel 2 - Estándar (Production Ready)
Todos los items de las secciones 1-6, 9, 11. Requerido para todo sistema en produccion.

### Nivel 3 - Avanzado (Enterprise)
Todos los items incluyendo secciones 7, 8, 10, 12. Requerido para sistemas criticos.

### Nivel 4 - Hardened (Maximum Security)
Todos los items + pentesting trimestral + bug bounty + HSM + zero-trust networking.

---

## PLANTILLA PARA COPIAR A OTROS PROYECTOS

```bash
# Para aplicar este checklist a un nuevo proyecto:
cp docs/SECURITY-INDICATORS.md <nuevo-proyecto>/docs/

# Buscar y reemplazar referencias segun el proyecto:
# - Omni-PKI: secciones 2.1 (CA), 2.4 (firma), 7 (licencias), 12.2 (eIDAS)
# - Omni-SOC: secciones 6 (auditoria), 8 (runtime), 10 (monitoreo)
# - Generic: todas las demas secciones
```
