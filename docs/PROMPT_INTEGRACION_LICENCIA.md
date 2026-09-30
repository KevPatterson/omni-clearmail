# PROMPT-MÉTODO: Integrar licencia OMNI-Lic en cualquier software

> Copia todo el texto desde "INSTRUCCIONES PARA LA IA" hasta el final y pégalo a
> una IA (Claude, ChatGPT, etc.) junto con el árbol/código de tu software.
> La IA debe devolver la integración completa solicitada.

---

## INSTRUCCIONES PARA LA IA

Actúa como un ingeniero senior experto en el ecosistema OMNI. Tu tarea es agregar
a `<NOMBRE_DEL_SOFTWARE>` (lenguaje `<LENGUAJE>`, framework `<FRAMEWORK>`) un
sistema de licenciamiento integrado con **OMNI-Lic**, el emisor central de
licencias del ecosistema Omni.

### Contexto del ecosistema

- **OMNI-Lic** es el ÚNICO emisor de licencias. Este software NUNCA emite
  licencias: solo genera solicitudes y valida licencias firmadas por Omni-Lic.
- La licencia es un documento JSON firmado con **Ed25519** por el emisor.
- El software cliente embebe la **clave pública PEM** del emisor.
- Identidad del software ante OMNI-Lic (`sistema`): en BLANCO por defecto, se
  rellena AUTOMÁTICAMENTE al generar la solicitud (ver "Identidad del software"
  más abajo). NO hardcodearla ni pedirla al operador.
- Componentes del software (regla OMNI: la licencia incluye la IP de CADA
  componente): `<COMPONENTES>` (ej. `backend, frontend`).

### Identidad del software (autogenerada)

- El campo `sistema` de la solicitud (y el que se compara al validar la
  licencia) se deriva SOLO del nombre del software/proyecto, sin teclearlo:
  normalizar `<NOMBRE_DEL_SOFTWARE>` a un slug compatible con OMNI-Lic:
  1. Los espacios y/o "_" se convierten en `-`.
  2. Se pasan a minúsculas y se eliminan acentos y caracteres no
     alfanuméricos (se conservan `a-z`, `0-9` y `-`).
  3. Ejemplos: "Osint-Omin" -> `osint-omin`, "Omni OSINT" -> `omni-osint`,
     "Honey Omni AI" -> `honey-omni-ai`.
- La función que calcula el `sistema` debe ser un único punto (ej. función
  `identidad_sistema()`) usada tanto al generar la solicitud como al validar
  la licencia, de modo que SIEMPRE coincidan.

### Qué debes implementar

1. **Generación automática del fichero de solicitud** (`solicitud_omni_lic.json`)
   con el binding real del host donde corre el software, listo para importarse
   en Omni-Lic (endpoint `POST /api/solicitudes/importar-archivo`).
   Esta generación debe estar disponible **mediante una interfaz gráfica/panel
   del propio software** (no solo CLI): el usuario pulsa un botón "Generar
   solicitud de licencia", el sistema obtiene el binding real, crea el fichero
   y lo descarga/guarda en un clic. La interfaz también debe permitir indicar
   tipo, nombre y email del cliente antes de generar.
2. **Carga del fichero de licencia** (`license.json`): el usuario introduce el
   fichero emitido por Omni-Lic; el sistema lo valida offline y, si es válido,
   el software queda activo. Esta carga también es por interfaz (selector de
   archivo en el panel), no solo por comandos.
3. **Control de acceso por licencia**: sin licencia válida el software no arranca
   ni permite usar sus funcionalidades. Mensaje claro al usuario indicando cómo
   obtenerla (contacto de OMNI-Lic).
4. **Verificación de vigencia en cadena**: al arrancar, periódicamente y antes de
   cada acción sensible se comprueba firma, integridad, binding y expiración.
5. **Notificaciones de vencimiento**: avisos **visuales** (en la UI del software)
   y **por correo** (SMTP) a los umbrales de **30 días (1 mes), 15, 7, 3, 2 y 1
   día** antes de expirar.
6. **Bloqueo al expirar**: si `expira` ya pasó, el software deja de funcionar
   (sin degradación a modo "limitado"); se exige una licencia renovada.

### Contrato de solicitud (SOLICITUD-OMNI-LIC-1.0)

El fichero de solicitud que genera el software debe dar de alta al cliente o
usar uno existente, e incluir el binding real del host:

```json
{
  "formato": "SOLICITUD-OMNI-LIC-1.0",
  "version": "1.0",
  "tipo_solicitud": "licencia_omni_lic",
  "id_solicitud": "<uuid>",
  "sistema": "",
  "tipo": "hosting",
  "cliente": {"nombre": "<NOMBRE>", "email": "<EMAIL>"},
  "cliente_id": "",
  "emisor": {"url": "https://omni-lic.omni.group", "email": "licencias@omni.group"},
  "binding": {
    "ip": "<IP_PUBLICA>",
    "ip_local": "<IP_LOCAL>",
    "hostname": "<HOSTNAME>",
    "macs": ["AA:BB:CC:DD:EE:FF"],
    "components": {"<COMPONENTE_1>": "<IP>", "<COMPONENTE_2>": "<IP>"}
  },
  "solicitado_en": "<fecha ISO-8601 UTC>"
}
```

- `sistema` sale vacío en el código y se rellena en tiempo de ejecución con
  `identidad_sistema()` (slug del nombre del software, ver arriba).

- `binding.components` debe tener la IP de cada componente declarado.
- El software debe obtener las MACs, hostname e IPs locales reales de la
  máquina (no valores fijos).
- Si ya existe `cliente_id` en Omni-Lic, se debe incluir y omitir el dict
  `cliente` (o dejarlo para dar de alta automáticamente).

### Formato de la licencia emitida (que devolverá Omni-Lic)

```json
{
  "id": "<uuid-hex>",
  "cliente_id": "<id>",
  "sistema": "",
  "tipo": "trial|hosting|enterprise",
  "emitido": "<ISO-8601>",
  "expira": "<ISO-8601>",
  "binding": {"ip": "", "ip_local": "", "hostname": "", "macs": [], "components": {}},
  "semiprimo_n": "<entero grande>",
  "prueba_p": "<sha512 hex>",
  "prueba_q": "<sha512 hex>",
  "sello_n": "<sha512 hex>",
  "firma_hex": "<firma Ed25519 hex>"
}
```

> Nota: `sistema` viene vacío en el documento porque lo rellena
> `identidad_sistema()`. La validación compara el `sistema` de la licencia con
> `identidad_sistema()`, nunca con un valor tecleado o fijo.

### Interfaz de licencia (requisito UI)

Crear una vista/página "Licencia" en la interfaz del software con:

- **Estado actual**: tipo, cliente, emitido, expira, días restantes, y si está
  vigente/vencida.
- **Botón "Generar solicitud"**: formulario (tipo, nombre y email del cliente)
  y al confirmar genera/descarga `solicitud_omni_lic.json` automáticamente,
  mostrando el binding detectado (hostname, MACs e IPs por componente) y dónde
  guardar el fichero.
- **Selector de archivo**: para cargar la licencia emitida por OMNI-Lic
  (`license.json` / `.lic` / `.license`), validarla y activarla.
- **Avisos de vencimiento**: banner con los días restantes y las etapas
  30/15/7/3/2/1 destacadas.

### Verificación offline que debes implementar (método `validar_licencia`)

Rechaza la licencia si ALGUNA de estas comprobaciones falla; devuelve la lista
de motivos:

1. **Forma**: todos los campos obligatorios presentes no vacíos: `cliente_id`,
   `sistema`, `tipo`, `emitido`, `expira`, `binding`, `semiprimo_n`,
   `prueba_p`, `prueba_q`, `sello_n`, `firma_hex`. El `sistema` de la licencia
   debe ser == `identidad_sistema()` y `tipo` ∈ {trial, hosting, enterprise}.
2. **Cuasi-primo**: `semiprimo_n` es un entero COMPUESTO producto de dos primos
   distintos (Miller-Rabin para n grandes; división de prueba para n pequeños).
3. **Compromisos**: `prueba_p` = sha512(factor p), `prueba_q` = sha512(factor q)
   — no verificables directamente sin los factores; se comprueba el formato hex
   sha512 (128 chars) y la coherencia de `sello_n`.
4. **Sello**: `sello_n` == sha512(str(semiprimo_n)).
5. **Firma Ed25519**: se verifica sobre el payload canónico: JSON con claves
   ordenadas recursivamente (`sort_keys`), separadores compactos `,`/`:`, sin
   escape de HTML (`ensure_ascii=False`, en Python), EXCLUYENDO los campos `id`
   y `firma_hex`. Debe coincidir byte a byte con el canonizado del emisor.
6. **Binding por host**: `binding.hostname` == hostname actual; si hay MACs,
   al menos una coincide con una MAC del host; la IP de cada componente en
   `binding.components` corresponde a una IP local del host (o es
   127.0.0.1/0.0.0.0/localhost en entornos dev).
7. **Vigencia**: `expira` > ahora (UTC). Éxito = los 7 grupos sin fallos.

Clave pública del emisor (PEM) a embeber: la que exporte OMNI-Lic en
`claves/emisor_pub.pem` (referencia de ejemplo en otros verificadores del
ecosistema).

### Almacenamiento

- Guardar la licencia validada en `<RUTA_DE_DATOS>/license.json` (sustituir
  `<RUTA_DE_DATOS>` por la ruta de datos del software) y cachear en memoria:
  estado, sin semiprimo repetido por carga (una verificación completa por
  arranque; luego comprobar solo expiración en tiempo de ejecución).
- Persistir el historial de notificaciones de vencimiento enviadas
  (marcador por umbral: 30/15/7/3/2/1) para no reenviar el mismo aviso.

### Notificaciones de vencimiento

- **Visual**: banner/alerta persistente en la UI indicando días restantes y
  fecha exacta de expiración; en las etapas 7/3/2/1 el aviso debe ser
  destacado (modal o bloqueante leve). Mostrar también el estado vigente en un
  panel de "Licencia".
- **Correo**: al pasar cada umbral (30, 15, 7, 3, 2, 1 día antes), enviar un
  email al cliente configurado (SMTP: `smtp_host`, `smtp_port`, usuario,
  password, desde) con asunto tipo "Su licencia <identidad_sistema()> expira
  en N día(s)". Enviar a la cuenta del operador/cliente almacenada en la
  configuración del software.

### Bloqueo por expiración

- En el arranque y ANTES de operaciones críticas, si
  `LICENCIA identificar expirada -> desactivar funcionalidades`: mostrar
  pantalla de licencia caducada con la fecha de expiración, contacto de
  licencias (`licencias@omni.group`) e instrucción de renovar en OMNI-Lic.
- Mientras esté caducada, ninguna funcionalidad del sistema debe ejecutarse.

### Referencias de implementación reales en el ecosistema (consúltalas si están
en el workspace del usuario)

- Generación de solicitud: `Look-Omni-AI/tools/solicitar_licencia.py`
- Verificador Python (validación completa): módulo `omni_look.py` /
  `omni_socia.py` de los proyectos del ecosistema.
- Verificador Go (idéntico, sin dependencias): `Honey-Omni-AI/.../internal/core/license/omni_lic.go`
- Emisor y contrato: `Omni-Lic/app/services/emisor.py`,
  `Omni-Lic/app/routers/solicitudes.py`, `Omni-Lic/app/schemas.py`.

### Criterios de aceptación (verifica al terminar)

1. `solicitud_omni_lic.json` generado desde la **interfaz** (botón del panel)
   con hostname, MACs e IP reales de cada componente → importable en OMNI-Lic
   (`POST /api/solicitudes/importar-archivo`).
2. Sin licencia: el software muestra cómo obtenerla y no arranca.
3. Con licencia ${licencia válida emitida por OMNI-Lic}: el software arranca y
   verifica firma + binding + vigencia.
4. Modificar cualquier campo de `license.json` (firma, fecha, IP, hostname) →
   licencia rechazada.
5. Faltando 30/15/7/3/2/1 días se emite aviso visual y correo (una única vez
   por umbral).
6. Pasada la fecha `expira` el software bloquea todas las funcionalidades.

### Entregables

- Código de integración (módulo verificador + módulo de solicitud + módulo de
  notificaciones + hook de arranque/bloqueo + UI de licencia con generación de
  solicitud, carga de licencia y avisos de vencimiento).
- Instrucciones de uso (cómo generar la solicitud, dónde colocar `license.json`,
  cómo configurar SMTP).
- Casos de prueba (unit tests) mínimos: licencia válida, firma corrupta,
  binding distinto, expirada, avisos por umbral.