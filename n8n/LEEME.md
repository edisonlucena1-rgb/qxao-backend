# Flujos n8n de Qxao: guía de puesta en marcha

Tres flujos, todos sin claves dentro (solo referencian credenciales por nombre):

| Archivo | Webhook | Qué hace |
|---|---|---|
| `1-qxao-crear-cliente.json` | POST `/webhook/qxao-crear-cliente` | Evolution (instancia) → Chatwoot (cuenta + usuario admin + conexión con Evolution) → NocoDB (base + 3 tablas) → responde las URLs e IDs al backend |
| `2-qxao-eliminar-cliente.json` | POST `/webhook/qxao-eliminar-cliente` | Borra instancia de Evolution, cuenta y usuario de Chatwoot y base de NocoDB. Si algo falla, responde `error` y el admin ve el botón "Eliminar igualmente" |
| `3-qxao-obtener-qr.json` | GET `/webhook/qxao-obtener-qr` | Un solo flujo para todos los clientes: devuelve el QR o `CONNECTED` |

## 1. Orden recomendado

1. **Rota los secretos** (sección 6). Hazlo antes de crear credenciales nuevas.
2. **Base de datos del backend** (sección 2). Sin esto, cada despliegue borra tus clientes.
3. **Variables de `qxaoweb`** (sección 3).
4. **Credenciales en n8n** (sección 4) e **importar los flujos** (sección 5).
5. **Prueba** con un cliente de prueba creado desde el admin (sección 7).

## 2. Base de datos persistente para `qxaoweb`

Hoy el log dice `Context impl SQLiteImpl`: la base está dentro del contenedor y se pierde al desplegar.

Lo más limpio: en el proyecto **qxaoweb** → `+ Servicio` → **Postgres** (por ejemplo `qxao-db`). Easypanel te da la "URL de conexión interna". Pégala como `DATABASE_URL` en las variables de `qxaoweb`. El backend ya soporta Postgres (`psycopg2` instalado, tablas y columnas se crean solas al arrancar).

No uses `postgres-ia` para esto: es de los agentes (n8n, memoria) y conviene separar los datos del panel.

## 3. Variables de entorno de `qxaoweb`

| Variable | Valor |
|---|---|
| `DATABASE_URL` | la URL interna del Postgres nuevo |
| `JWT_SECRET_KEY`, `CSRF_SECRET_KEY` | **nuevos** (rotar) |
| `MASTER_EMAIL` | tu correo de master |
| `MASTER_PASSWORD` | contraseña real y larga. Ojo: si el master ya existe en la base, no se cambia sola; con la base nueva se crea con esta |
| `COOKIE_SECURE` | `true` (ya usas HTTPS) |
| `N8N_BASE_URL` | `https://n8n.qxao.dpdns.org` |
| `N8N_WEBHOOK_SECRET` | una clave larga aleatoria (por ejemplo `openssl rand -hex 32`). **Debe ser idéntica** a la de la credencial "Qxao Webhook Secret" en n8n |
| `ALLOWED_ORIGINS` | déjala como está |

**Borra** `N8N_QR_WEBHOOK_URL` (apunta al flujo antiguo de JL Burger) y `N8N_CREATE_CLIENT_WEBHOOK_URL`: los valores por defecto del código ya apuntan a los webhooks nuevos.

## 4. Credenciales en n8n (créalas tú directamente en n8n, no las pegues en chats)

Las cuatro son de tipo **Header Auth**. Los nombres deben ser exactos:

| Nombre de la credencial | Name (header) | Value |
|---|---|---|
| `Qxao Webhook Secret` | `X-Qxao-Secret` | el mismo valor de `N8N_WEBHOOK_SECRET` |
| `Evolution API` | `apikey` | la `AUTHENTICATION_API_KEY` de Evolution |
| `Chatwoot Platform` | `api_access_token` | token de la Platform App (Super Admin → Platform Apps) |
| `NocoDB` | `xc-token` | token API de NocoDB (Account → Tokens API) |

Chatwoot 4.13 usa el header `api_access_token`. El formato `Authorization: Bearer` solo existe desde la 4.19.

## 5. Importar y activar

1. En n8n: carpeta "Qxao ADMINITRADOR" → `Import from file` con cada JSON.
2. Abre cada flujo y, en los nodos con candado rojo, elige la credencial correspondiente (la importación no puede asignarla sola).
3. Activa los tres (interruptor "Active"). Los URL de producción solo funcionan con el flujo activo.

Las URLs públicas de Evolution, Chatwoot, NocoDB y n8n están escritas en el nodo **Config** de cada flujo. Si algún dominio cambia, se edita ahí.

## 6. Secretos que debes rotar

En las capturas y logs que compartiste aparecen en claro: `JWT_SECRET_KEY`, `CSRF_SECRET_KEY`, contraseña de Postgres y Redis, token de la Platform App de Chatwoot, token de acceso del perfil de Chatwoot, token de NocoDB y la API key de Evolution. Además, el historial del repositorio contiene una API key de n8n y la de Evolution antiguas. Rota todo, y pon el repositorio **privado**.

## 7. Prueba de punta a punta

1. Entra a `/admin.html` → **Nuevo cliente** (usa un correo que no exista ya en Chatwoot).
2. La fila debe pasar a `activo` y mostrar Chatwoot y NocoDB. Si queda en `error`, el motivo aparece en el historial del cliente y en la ejecución de n8n (pestaña Executions).
3. Entra como ese cliente (Impersonar) → QR → escanea con WhatsApp.
4. Borra el cliente de prueba desde el botón **Eliminar**: debe limpiar los tres sistemas.

## 8. Lo que debes verificar (no pude comprobarlo contra tus servidores)

- **NocoDB**: el cuerpo de creación de base y tablas (`/api/v2/meta/bases/` y `.../tables`) viene de la API v2. Si tu versión (2026.05) responde error, abre el Swagger de tu NocoDB y ajusta los nodos "NocoDB base" y "NocoDB crear tabla". Las tablas que recibe cada cliente (leads, productos, pedidos) son una plantilla **genérica**: se edita en el nodo "Plantilla tablas NocoDB".
- **Evolution v2.0.0**: el nodo "Evolution conectar Chatwoot" usa `POST /chatwoot/set/{instancia}` con `autoCreate: true`. En el entorno de Evolution debe estar `CHATWOOT_ENABLED=true` (hoy tienes `false` y `true` duplicados) y `CHATWOOT_IMPORT_DATABASE_CONNECTION_URI` vacío si no importas historial.
- **Contraseña del usuario de Chatwoot**: n8n genera una al azar y no se muestra ni se guarda. El cliente entra con "Olvidé mi contraseña", lo que requiere SMTP configurado en Chatwoot. Dime si quieres otro mecanismo.
- **Reprovisionar** tras un fallo a medias: la instancia de Evolution se reutiliza, pero la cuenta de Chatwoot o la base de NocoDB ya creadas no se detectan, y pueden quedar duplicadas. Revísalo a mano si pasa.
- Chatwoot `ENABLE_ACCOUNT_SIGNUP` debe estar en `false`: ahora cualquiera puede registrarse en tu Chatwoot.
