# MANUAL DE USUARIO — Omni-CleanerMail

## Plataforma de Gobierno y Filtrado Inteligente de Correo Electrónico

---

## 1. Introducción

**Omni-CleanerMail** es una plataforma de gobierno de correo electrónico que filtra, analiza y audita todo el tráfico de mail de una organización. Proporciona:

- **Dashboard de hallazgos de seguridad** con severidad, tipo y motor de detección.
- **Registro de todas las direcciones de correo** de entrada y salida, con veredicto y score.
- **Cuarentena inteligente** con acciones de liberación, expurgación y autopeticiones.
- **Motores de análisis** (KSMG, ClamAV, YARA, Sandbox, ML-Local, Adjuntos).
- **Vista por departamentos** con métricas de riesgo.
- **Gestión de licencia OMNI-Lic** con estados y alertas.
- **Auditoría hash-chain** con verificación de integridad.
- **Gestión de API Keys** para integración con MTA y sistemas externos.
- **Reportes exportables** en CSV y JSON.

El sistema opera en **modo demo** por defecto (sin licencia). Para producción se requiere una licencia emitida por OMNI-Lic.

---

## 2. Requisitos

| Componente | Versión mínima |
|---|---|
| Python | 3.10+ |
| fastapi | >= 0.100 |
| uvicorn | >= 0.22 |
| cryptography | >= 41.0 |

Las dependencias se instalan automáticamente con `pip install -r requirements.txt`.

---

## 3. Inicio y Detención del Servidor

### Iniciar
Doble clic en **`INICIO.bat`**. El script:
1. Verifica que Python esté disponible.
2. Instala dependencias si faltan.
3. Detiene instancias previas del servidor.
4. Lanza el servidor en **http://127.0.0.1:8000**.
5. Abre automáticamente el navegador.

### Detener
Doble clic en **`DETENER.bat`**. El script busca y detiene todos los procesos de Omni-CleanerMail activos.

### Inicio manual
```bash
cd Omni-ClearMail
python scripts/run.py --port 8791
```

---

## 4. Inicio de Sesión

Al abrir la URL se muestra la pantalla de login.

| Campo | Descripción |
|---|---|
| **Usuario** | Nombre de usuario registrado |
| **Contraseña** | Contraseña del usuario |

### Credenciales Demo

| Rol | Usuario | Contraseña |
|---|---|---|
| Administrador | `admin` | `admin123` |
| Operador | `operador` | `operador123` |

Los usuarios demo se crean automáticamente en el primer arranque.

---

## 5. Estructura de la Interfaz

La interfaz se organiza en:

- **Barra lateral izquierda** — Navegación entre paneles.
- **Barra superior** — Estado de salud, licencia, botón de cerrar sesión.
- **Área principal** — Contenido del panel seleccionado.

### Paneles disponibles

| Panel | Icono | Descripción |
|---|---|---|
| Hallazgos | Triángulo de alerta | Dashboard de hallazgos de seguridad |
| Panel General | Tablero | Métricas globales del sistema |
| Direcciones + Informe | Libreta | Registro de direcciones de correo ENTRADA/SALIDA |
| Cuarentena | Escudo | Gestión de mensajes retenidos |
| Motores | Motor | Motores de análisis y sus estadísticas |
| KSMG | Relámpago | Conectores reales con Kaspersky Secure Mail Gateway |
| Reportes | Gráfico | Informes personalizados por buzón con envío por email |
| Departamentos | Edificio | Métricas por departamento |
| Licencia | Llave | Estado de la licencia OMNI-Lic |
| Auditoría | Libro | Registro hash-chain de acciones |
| API Keys | Llave inglesa | Gestión de claves de API |

---

## 6. Panel: Hallazgos de Seguridad

### Dashboard (KPIs superiores)
- **Total hallazgos** — Cantidad total de hallazgos registrados.
- **Críticos** — Hallazgos con severidad CRITICA (rojo).
- **Altos** — Hallazgos con severidad ALTA (naranja).
- **Nuevos** — Hallazgos con estado NUEVO que no han sido revisados.

### Filtros dinámicos
| Filtro | Opciones | Descripción |
|---|---|---|
| Severidad | CRITICA / ALTA / MEDIA / BAJA / INFO | Filtra por nivel de severidad |
| Tipo | Ver lista abajo | Filtra por tipo de hallazgo |
| Motor | Todos los motores activos | Filtra por motor de origen |
| Buscar | Texto libre | Busca en título, detalle e ID de mensaje |

### Tipos de hallazgo
- `AUTENTICACION_CORREO` — Fallo en autenticación del remitente (SPF/DKIM/DMARC).
- `REGLA_YARA` — Coincidencia con reglas YARA.
- `PHISHING_ML` — Detección de phishing por ML.
- `MENSAJE_CUARENTENA` — Mensaje enviado a cuarentena.
- `MENSAJE_BLOQUEADO` — Mensaje bloqueado por alto riesgo.
- `FIRMA_MALICIOSA` — Firma conocida maliciosa detectada.
- `ADJUNTO_PELIGROSO` — Adjunto potencialmente peligroso.
- `EMBARCADO` — Contenido embebido sospechoso.

### Tabla dinámica
Cada fila muestra:
- **ID Hallazgo** — Identificador del hallazgo.
- **Tipo** — Tipo de hallazgo.
- **Severidad** — CRITICA / ALTA / MEDIA / BAJA / INFO (con color).
- **Título** — Descripción breve del hallazgo.
- **Motor** — Motor que lo detectó.
- **Estado** — NUEVO / EN_REVISION / REVISADO.
- **Enlaces** — Botones para ver el **mensaje** en cuarentena.

### Enlace cruzado
- Hacer clic en **Mensaje** → navega a la cuarentena filtrada por ese msg_id.
- Cambiar el estado de un hallazgo → se actualiza en tiempo real.

---

## 7. Panel: Direcciones + Informe

### Dashboard (KPIs superiores)
- **Total registros** — Total de registros de direcciones.
- **Entrantes** — Direcciones únicas de entrada.
- **Salientes** — Direcciones únicas de salida.
- **Internas** — Direcciones de dominios internos.
- **Externas** — Direcciones de dominios externos.

### Filtros dinámicos
| Filtro | Opciones | Descripción |
|---|---|---|
| Flujo | ENTRADA / SALIDA | Filtra por dirección del tráfico |
| Rol | REMITENTE / DESTINATARIO | Filtra por rol de la dirección |
| Interno | SI / NO | Filtra si la dirección es interna |
| Dominio | Texto libre | Filtra por dominio de la dirección |
| Buscar | Texto libre | Busca en la dirección de correo |

### Tabla dinámica
Cada fila muestra:
- **ID** — Identificador del registro.
- **Mensaje** — ID del mensaje asociado (enlace a cuarentena).
- **Dirección** — Dirección de correo completa.
- **Rol** — REMITENTE / DESTINATARIO.
- **Flujo** — ENTRADA / SALIDA (con color).
- **Interna** — SI / NO.
- **Dominio** — Dominio de la dirección.
- **Veredicto** — deliver / quarantine / block.
- **Score** — Puntuación de riesgo.

### Enlace cruzado
- Hacer clic en **Mensaje** → navega a la cuarentena filtrada por ese msg_id.
- Los filtros se combinan (ej: Flujo=SALIDA + Interno=NO = correos salientes a clientes externos).

### Exportación
- **CSV** — Descarga un archivo CSV con los registros filtrados.
- **JSON** — Descarga un archivo JSON con los registros filtrados.
- Los filtros activos se aplican al archivo descargado.

---

## 8. Panel: Cuarentena

### Dashboard (KPIs superiores)
- **Total** — Mensajes totales en el sistema.
- **En cuarentena** — Mensajes retenidos esperando decisión.
- **Bloqueados** — Mensajes bloqueados por alto riesgo.
- **Liberados** — Mensajes liberados por administrador.
- **Entregados** — Mensajes entregados normalmente.
- **Purgados** — Mensajes eliminados definitivamente.
- **Riesgo alto** — Mensajes con score >= 80.
- **Últimas 24h** — Mensajes procesados en las últimas 24 horas.

### Filtros dinámicos
| Filtro | Opciones | Descripción |
|---|---|---|
| Estado | Todas / Cuarentena / Bloqueados / Liberados / Purgados | Filtra por estado |
| Buscar | Texto libre | Busca en asunto, remitente o destinatarios |
| Msg ID | Texto exacto | Filtra por ID de mensaje específico |

### Tabla dinámica
Cada fila muestra:
- **Msg ID** — Identificador único del mensaje.
- **Asunto** — Asunto del correo.
- **De** — Dirección del remitente (enlace a direcciones).
- **Para** — Destinatarios (cada uno enlazado a direcciones).
- **Score** — Puntuación compuesta de riesgo (con indicador visual).
- **Estado** — quarantine / blocked / delivered / released / expunged (con color).
- **Acciones** — Liberar / Expurgar (según permisos).

### Enlace cruzado
- Hacer clic en **remitente** → navega a direcciones filtrada por esa dirección.
- Hacer clic en **destinatario** → navega a direcciones filtrada por ese destinatario.
- Hacer clic en **Msg ID** → navega a hallazgos filtrados por ese msg_id.
- Los botones de acción registran la acción en la auditoría hash-chain.

---

## 9. Panel: Motores

### Dashboard (KPIs superiores)
- **Total motores** — Cantidad de motores activos.
- **Motor más activo** — Motor con más análisis realizados.

### Tabla dinámica
Cada fila muestra:
- **Motor** — Nombre del motor (KSMG, ClamAV, YARA, etc.).
- **Estado** — ACTIVO / INACTIVO.
- **Mensajes analizados** — Cantidad de mensajes procesados por este motor.
- **Tiempo promedio** — Tiempo medio de procesamiento en ms.

### Enlace cruzado
- Hacer clic en el nombre del motor → navega a hallazgos filtrados por ese motor de origen.
- Los motores inactivos se muestran en gris.

---

## 10. Panel: Integración KSMG

El panel **KSMG** conecta la plataforma con un gateway real **Kaspersky Secure Mail Gateway** (o cualquier antivirus perimetral que emita cabeceras `X-Kaspersky`/`X-KSMG`/`X-KL` o archivos de veredicto en JSON).

### Dashboard (KPIs superiores)
- **Estado del conector** — Conectado / En pausa.
- **Mensajes procesados** — Mensajes reales recibidos desde el gateway.
- **Errores** — Fallos de conexión o procesamiento.
- **Modo** — SIMULADO / EML_WATCH / IMAP / SMTP.

### Modos de conexión reales
| Modo | Descripción |
|---|---|
| **EML_WATCH** | Vigila una carpeta donde el gateway deposita los correos en formato `.eml`. Opcionalmente lee `<nombre>.eml.json` (sidecar) con `action`, `verdicts`, `rules` y `score` reales del gateway. |
| **IMAP** | Consulta cada N segundos un buzón IMAP del gateway (o una carpeta de cuarentena) y procesa los correos no vistos. |
| **SMTP** | Receptor mínimo de correo que escucha en un puerto local (por defecto `127.0.0.1:2525`); el gateway reenvía ahí los correos a analizar. |

### Evidencia real vs simulación
- Si el correo llega con cabeceras KSMG reales (`X-Kaspersky-Spam-Action`, `X-KSMG-Action`, `X-Kaspersky-Spam-Result`, etc.) o un sidecar JSON, el motor KSMG puntúa con **evidencia real del gateway** (veredicto, reglas, clasificación) y lo refleja en los hallazgos como `KSMG real`.
- Si no hay evidencia, el motor usa su puntuación simulada y muestra la nota *"KSMG simulado: conectar gateway real en Integración KSMG"*.
- El badge del motor en **Motores** indica `REAL` (conectado) o `SIMULADO`.

### Acciones
- **Probar conexión** — Valida host/puerto/usuario del conector configurado.
- **Pollen (Borrar y analizar)** — Ejecuta un ciclo de captura inmediato en modo EML_WATCH/IMAP o arranca el receptor SMTP.
- **Iniciar / Detener** — Activa o detiene el ciclo automático periódico.
- **Guardar configuración** — Persiste y activa el modo elegido (requiere rol ADMIN/SUPER_ADMIN).
- **Registro de eventos** — Últimos 50 eventos del conector con veredicto, score y mensaje procesado.

> La contraseña de IMAP nunca se devuelve a la interfaz; se guarda cifrada en la base de datos.

---

## 11. Panel: Departamentos

### Dashboard (KPIs superiores)
- **Total departamentos** — Departamentos registrados.
- **Con actividad** — Departamentos con al menos un mensaje.

### Tabla dinámica
Cada fila muestra:
- **Departamento** — Nombre del departamento.
- **Mensajes** — Cantidad total de mensajes.
- **Riesgo promedio** — Score promedio de los mensajes.
- **Bloqueados** — Mensajes bloqueados.

### Enlace cruzado
- Hacer clic en un departamento → muestra detalles y enlaza a cuarentena filtrada por dominio de ese departamento.
- Los departamentos se derivan de los dominios de las direcciones internas.

---

## 12. Panel: Licencia

### Dashboard (KPIs superiores)
- **Estado** — VIGENTE / VENCIDA / SIN_LICENCIA / DEMO.
- **Tipo** — Tipo de licencia (OMNI-Lic, Corporate, etc.).
- **Días restantes** — Días hasta la expiración.
- **Sistema** — Identificador del sistema licenciado.

### Tabla de estado
Muestra el detalle completo de la licencia actual:
- ID de la licencia.
- Fecha de activación.
- Fecha de expiración.
- Estado actual.

### Enlace cruzado
- Hacer clic en **Ver eventos** → navega a auditoría filtrada por acciones de licencia.

---

## 13. Panel: Auditoría

### Dashboard (KPIs superiores)
- **Total entradas** — Acciones registradas en la cadena hash.
- **Integridad OK** — Si la cadena de hash no ha sido alterada.
- **Entradas verificadas** — Cantidad verificadas contra la cadena.

### Filtros dinámicos
| Filtro | Opciones | Descripción |
|---|---|---|
| Acción | Todas / login / mail_ingested / release_message / expunge_message / api_key_created / api_key_revoked / license_install / license_expiring / findings_status | Filtra por tipo de acción |
| Actor | Texto libre | Filtra por usuario que realizó la acción |

### Tabla dinámica
Cada fila muestra:
- **ID** — Número de entrada en la cadena.
- **Acción** — Tipo de acción realizada.
- **Actor** — Usuario que ejecutó la acción.
- **Detalle** — JSON con los datos de la acción.
- **Hash** — Hash SHA-256 de la entrada.
- **Fecha** — Fecha y hora UTC.

### Enlace cruzado
- Los filtros de acción se combinan con el actor.
- La verificación de integridad se ejecuta al cargar el panel.

---

## 14. Panel: API Keys

### Dashboard (KPIs superiores)
- **Total keys** — Claves de API registradas.
- **Activas** — Claves activas.
- **Revocadas** — Claves revocadas.

### Filtros dinámicos
| Filtro | Opciones | Descripción |
|---|---|---|
| Estado | ACTIVA / REVOCADA | Filtra por estado de la clave |
| Rol | ADMIN / OPERATOR / VIEWER | Filtra por rol asignado |

### Tabla dinámica
Cada fila muestra:
- **ID** — Identificador de la clave.
- **Etiqueta** — Nombre descriptivo de la clave.
- **Rol** — Rol asignado (ADMIN / OPERATOR / VIEWER).
- **Estado** — ACTIVA / REVOCADA (con color).
- **Creada** — Fecha de creación.
- **Acciones** — Revocar (solo para ADMIN).

### Enlace cruzado
- Revocar una clave registra la acción en auditoría.
- Las claves se usan para autenticar peticiones de ingesta desde el MTA.

---

## 15. Panel: Reportes por Buzón

El panel **Reportes** genera informes personalizados de actividad **por buzón/usuario** (o para toda la organización) y los envía por email. Cada buzón programado puede ser un usuario final distinto.

### Qué incluye cada informe
- **Correos ENTRANTES** — cantidad de mensajes recibidos por el buzón y remitentes externos únicos.
- **Correos SALIENTES** — cantidad de mensajes enviados y destinatarios externos únicos.
- **Cantidad de buzones** — buzones activos de la organización en el periodo y buzones externos contactados.
- **Hallazgos** — cantidad total, resumen por severidad/tipo y detalle (top hallazgos). Se adjunta un CSV con ese detalle.
- **Estado de mensajes** — cuarentena/bloqueados del periodo y score medio de entrada.

### Vista previa y envío
- **Ver informe** — genera la vista previa (KPIs + top hallazgos) sin enviar.
- **Enviar ahora** — genera y envía por email el informe del buzón seleccionado al correo indicado.
- **Guardar config** — registra una programación: buzón, email destino, frecuencia DIARIO/SEMANAL, hora y estado activo.
- **Ejecutar programados** — fuerza ahora el envío de todas las programaciones activas.

### Programación automática
- Con **DIARIO** envía cada día a la hora configurada; con **SEMANAL** cada lunes a esa hora.
- El worker en segundo plano revisa las programaciones cada 60 segundos (`OMNI_REPORT_POLL_SECONDS`) y envía las que estén pendientes; guarda la marca `last_sent` para no duplicar.
- El buzón especial `*` (TODA LA ORGANIZACIÓN) genera el informe agregado de toda la empresa, incluida la cantidad total de buzones.

### Envío por email (SMTP)
El panel incluye la tarjeta **SMTP de salida** donde un ADMIN puede indicar host, puerto, remitente y credenciales, y pulsar **Probar SMTP** para validar la conexión. La configuración del panel prevalece sobre las variables de entorno; si no se configura nada, se usan:
- `LOOK_SMTP_HOST` y `LOOK_SMTP_PORT` (587 usa STARTTLS).
- `LOOK_SMTP_FROM` (remitente, por defecto `licencias@omni.group`).
- `LOOK_SMTP_USER` / `LOOK_SMTP_PASSWORD` si el relay exige autenticación.

El historial de envíos aparece en la tabla inferior (resultado, periodo y resumen). Roles: configurar y enviar exige **ADMIN/SUPER_ADMIN**; ver informes está abierto a usuarios autenticados.

### Auto-reporte M2M por API key
En **API Keys** puede crear una clave con **alcance de buzón** (campo *buzón*, opcional). Esa clave, enviada en la cabecera `X-API-Key`, devuelve únicamente el informe de ese buzón:

```
GET /api/reporte-buzon/mio?days=7
X-API-Key: omni-cm_...
```

Permite que cada usuario/servicio reciba su propio informe sin acceder al panel. Sin alcance de buzón, la clave no puede usar este endpoint (403).

---

## 16. Navegación Cruzada entre Paneles

Todos los paneles están enlazados entre sí. Desde cualquier tabla puedes navegar a datos relacionados:

| Desde | Elemento clickeable | Navega a | Filtro aplicado |
|---|---|---|---|
| Hallazgos | Mensaje | Cuarentena | `msg_id` del hallazgo |
| Hallazgos | Motor | Hallazgos | `source` del motor |
| Direcciones | Mensaje | Cuarentena | `msg_id` del registro |
| Direcciones | Flujo | Direcciones | `direction` ENTRADA/SALIDA |
| Direcciones | Dominio | Direcciones | `domain` |
| Cuarentena | Remitente | Direcciones | `search` del remitente |
| Cuarentena | Destinatario | Direcciones | `search` del destinatario |
| Cuarentena | Msg ID | Hallazgos | `msg_id` |
| Motores | Nombre | Hallazgos | `source` del motor |
| Departamentos | Nombre | Cuarentena | `search` del dominio |
| Licencia | Ver eventos | Auditoría | `action` de licencia |
| Auditoría | Actor | Auditoría | `actor` |

### Barra de vínculos
Cuando navegues desde un vínculo cruzado, aparecerá una barra superior indicando el filtro activo con un botón **X** para limpiarlo y volver a la vista completa.

---

## 17. Reportes Exportables

### Desde la interfaz
Cada panel con reportes tiene botones **CSV** y **JSON** que descargan un archivo con los filtros activos aplicados.

### Por API

| Endpoint | Formato | Descripción |
|---|---|---|
| `GET /api/report/addresses.csv` | CSV | Informe de direcciones de correo |
| `GET /api/report/addresses.json` | JSON | Informe de direcciones de correo |
| `GET /api/report/findings.csv` | CSV | Informe de hallazgos de seguridad |
| `GET /api/report/findings.json` | JSON | Informe de hallazgos de seguridad |

Los parámetros de filtro se pasan como query string (ej: `?direction=ENTRADA&domain=corp.demo`).

---

## 18. Modo Demo vs Producción

### Modo Demo (por defecto)
- No requiere licencia.
- Crea 8 mensajes de ejemplo al iniciar (3 cuarentena, 3 entregados, 2 salientes).
- Crea usuarios demo (`admin`, `operador`).
- Muestra banner "Modo demo" en la interfaz.

### Producción
- Requiere licencia OMNI-Lic válida.
- Para activar: ejecutar `python scripts/run.py --port 8791` con `OMNI_DEMO_MODE=0`.
- Sin licencia el servidor no arranca.
- La licencia se valida contra el sistema OMNI-Lic central.

### Cambiar modo
```bash
# Producción (requiere licencia)
set OMNI_DEMO_MODE=0
python scripts/run.py --port 8791

# Demo (sin licencia)
set OMNI_DEMO_MODE=1
python scripts/run.py --port 8791
```

---

## 19. Endpoints de API Principales

### Autenticación
| Método | Endpoint | Descripción |
|---|---|---|
| POST | `/api/auth/login` | Inicio de sesión, devuelve JWT |

### Datos
| Método | Endpoint | Descripción |
|---|---|---|
| GET | `/api/boot` | Estado de licencia y acceso |
| GET | `/api/dashboard/overview` | Métricas globales |
| GET | `/api/dashboard/department/{dept}` | Métricas por departamento |
| GET | `/api/quarantine` | Lista de mensajes |
| GET | `/api/quarantine/summary` | Resumen de cuarentena |
| GET | `/api/findings` | Lista de hallazgos |
| GET | `/api/findings/summary` | Resumen de hallazgos |
| GET | `/api/addresses` | Lista de direcciones |
| GET | `/api/addresses/summary` | Resumen de direcciones |
| GET | `/api/audit/actions` | Acciones de auditoría |
| GET | `/api/audit/summary` | Resumen de integridad |

### Ingesta
| Método | Endpoint | Descripción |
|---|---|---|
| POST | `/api/mail/ingest` | Ingesta de .eml crudo |
| POST | `/api/mail/ingest-json` | Ingesta estructurada (demo) |

### Acciones
| Método | Endpoint | Descripción |
|---|---|---|
| POST | `/api/quarantine/{msg_id}/release` | Liberar mensaje |
| POST | `/api/quarantine/{msg_id}/expunge` | Expurgar mensaje |
| POST | `/api/findings/{id}/status` | Cambiar estado de hallazgo |
| POST | `/api/secure/keys` | Crear API key (opcional `buzon` para M2M) |
| DELETE | `/api/secure/keys/{id}` | Revocar API key |
| GET | `/api/reporte-buzon/estado` | Estado de reportes + SMTP |
| GET | `/api/reporte-buzon/ver?buzon=&days=` | Previsualizar informe |
| GET | `/api/reporte-buzon/mio` | Auto-reporte M2M por `X-API-Key` |
| POST | `/api/reporte-buzon/config` | Guardar programación |
| POST | `/api/reporte-buzon/enviar` | Enviar informe ahora |
| POST | `/api/reporte-buzon/smtp` | Guardar SMTP de salida |
| POST | `/api/reporte-buzon/smtp-test` | Probar conexión SMTP |

---

## 20. Solución de Problemas

### El servidor no arranca
1. Verificar que Python 3.10+ está instalado: `python --version`
2. Verificar dependencias: `pip install -r requirements.txt`
3. Verificar que el puerto no esté ocupado: `netstat -aon | findstr :8000`
4. Verificar que la BD no esté corrupta: eliminar `app/data/omnimaillook.db` y reiniciar.

### No puedo iniciar sesión
1. Verificar usuario y contraseña.
2. En modo demo, los usuarios son `admin`/`admin123` y `operador`/`operador123`.
3. Si la BD fue eliminada, los usuarios se recrean al reiniciar.

### La interfaz no carga
1. Verificar que el servidor está corriendo: `curl http://127.0.0.1:8000/api/health`
2. Verificar que no hay bloqueadores de contenido activos.
3. Intentar en modo incógnito.

### Error 429 (Rate Limit)
El servidor limita peticiones. Esperar un momento y reintentar.

### Error 401 (No autorizado)
El token JWT ha expirado. Volver a iniciar sesión.

---

## 21. Archivos del Sistema

```
Omni-ClearMail/
├── INICIO.bat              # Iniciar servidor
├── DETENER.bat             # Detener servidor
├── MANUAL_USUARIO.md       # Este manual
├── requirements.txt        # Dependencias Python
├── app/
│   ├── api/
│   │   ├── routes.py       # Endpoints de la API
│   │   └── dashboard_data.py  # Datos para dashboards
│   ├── core/
│   │   ├── auth.py         # Autenticación y autorización
│   │   ├── hashchain.py    # Cadena de auditoría hash
│   │   └── licensing.py    # Gestión de licencia
│   ├── mail/
│   │   ├── quarantine.py   # Cuarentena y mensajes
│   │   ├── findings.py     # Hallazgos de seguridad
│   │   ├── addressbook.py  # Ledger de direcciones
│   │   ├── engines.py      # Motores de análisis
│   │   ├── ksmg.py         # Integración real KSMG (conectores)
│   │   ├── reports.py      # Reportes por buzón + SMTP + M2M
│   │   ├── scoring.py      # Sistema de puntuación
│   │   └── parser.py       # Parser de .eml
│   ├── ui/
│   │   └── static/
│   │       └── index.html  # Interfaz web completa
│   ├── data/
│   │   ├── omnimaillook.db # Base de datos principal
│   │   └── audit_chain.db  # Cadena de auditoría
│   ├── config.py           # Configuración del sistema
│   └── main.py             # Punto de entrada FastAPI
├── scripts/
│   ├── run.py              # Script de inicio con seed demo
│   ├── servicio.py         # Arranque headless (servicio/tarea programada)
│   ├── install_windows.bat # Instalador Windows (venv + tarea de arranque)
│   ├── reset_datos.py      # Reset de datos demo
│   ├── gen_license.py      # Utilidad OMNI-Lic
│   └── smoke_test.py       # Tests de verificación
├── .env.example            # Plantilla de configuración por entorno
└── omni_lic/               # Módulo de licencias OMNI-Lic
```

---

## 22. Instalación y Despliegue (Windows)

### Instalación asistida
Como administrador, ejecute:

```
scripts\install_windows.bat
```

El script crea el entorno virtual `venv`, instala `requirements.txt`, copia `.env.example` a `.env`, y registra la tarea programada **Omni-CleanerMail** (arranque con el sistema, usuario SYSTEM) usando `scripts/servicio.py`.

### Configuración
Edite `.env` (se lee automáticamente si `python-dotenv` está instalado) o defina variables de entorno del sistema:
- `LOOK_BIND` (def. `127.0.0.1`) y `LOOK_PORT` (def. `8000`). Use `0.0.0.0` solo si el gateway KSMG está en otra máquina.
- `LOOK_SMTP_*` para el correo saliente.
- `OMNI_INTERNAL_DOMAINS` con los dominios internos de la organización (buzones de la empresa).
- `LOOK_HMAC_SECRET` con una clave aleatoria larga en producción.

### Arranque manual (pruebas)
```
venv\Scripts\python.exe scripts\run.py --no-seed
```
Sin `--no-seed` se inyectan mensajes demo. Con `scripts/servicio.py` no se inyecta nada.

### Exclusiones de antivirus (importante)
Excluya de la protección en tiempo real (Kaspersky / Defender) las rutas:
- `app\data` (base de datos y licencia)
- `venv`
- `.env`
- la carpeta de vigilancia de KSMG (`EML_WATCH`) y los `.eml` de prueba

### Reset de datos
```
python scripts\reset_datos.py --datos   # borra mensajes/hallazgos/ledger, conserva config y auditoría
python scripts\reset_datos.py --all     # mueve las bases a copia con fecha (arranque limpio)
```

---

## 23. Contacto y Soporte

- **Repositorio**: https://github.com/anomalyco/opencode
- **Bug reports**: https://github.com/anomalyco/opencode/issues
- **Desarrollado por**: OMNI I+D+i

---

*Versión 1.0.0 — Septiembre 2026*
