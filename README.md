# defensive-security-agent

CLI local para evaluaciones defensivas puntuales sobre hostnames autorizados. Permite consultar el scope y hacer una evaluación pública de headers HTTP; **no utiliza un LLM ni certifica ISO/IEC 27001**. El [roadmap](ROADMAP.md) separa capacidades actuales y futuras.

## Instalación

Python 3.12+; entorno comprobado en Linux con Python 3.12.3. Desde la raíz del proyecto:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.lock
.venv/bin/python -m pip install -e . --no-deps --no-build-isolation
.venv/bin/python -m pip check
```

El lockfile fija dependencias directas, transitivas y backend de construcción. Instalarlo **antes** del proyecto editable; así no se resuelven dependencias adicionales durante el build. No es una garantía de reproducibilidad binaria entre plataformas. La instalación necesita acceso al índice de paquetes o una caché disponible; `scope` no necesita red. Los tests web usan un servidor TLS local y no contactan targets externos.

No se requieren credenciales. `.venv`, la configuración local y `evidence/` están excluidos de Git.

## Configuración y consulta local de scope

Los permisos reales se definen únicamente en `config.yaml` (local, excluido de Git y Docker). Al clonar el repositorio, este archivo no existe. Copiar el ejemplo **solo si no existe `config.yaml`**:

```bash
cp -n config.example.yaml config.yaml
```

Luego editar su scope para incluir únicamente targets con autorización explícita. El ejemplo tiene scope vacío y no concede permisos. Para consultar un target declarado allí:

```bash
.venv/bin/python -m app.main scope "<target-autorizado>"
```

Resultado:

```text
AUTORIZADO: <target-autorizado>
Motivo: coincidencia exacta con una entrada del scope. No se realizó ningún escaneo.
```

Reemplazar los placeholders por targets reales. El path por defecto es `config.yaml` relativo al directorio de ejecución; se puede seleccionar otro archivo con `--config <ruta>`. Si falta o es inválido, se rechaza la consulta: nunca se utilizan permisos de ejemplo automáticamente.

## Evaluación pública de headers

Un target por ejecución; solo hostnames explícitamente autorizados en `scope.domains`. El comando hace un `GET https://<hostname>:443/`, verifica TLS, no sigue redirects ni reintenta, y genera un directorio único con `report.json` y `report.md`:

```bash
.venv/bin/python -m app.main scan "<hostname-autorizado>" --config config.yaml --evidence-dir evidence
```

El proceso resuelve DNS y se conecta a una dirección pública resuelta. Fija esa IP en el socket, rechaza respuestas DNS con destinos no globales y conserva hostname/SNI para TLS. Las IPs no quedan autorizadas como targets independientes. Aunque solo usa GET, la app podría tener efectos secundarios; la autorización debe cubrir `GET /` explícitamente.

Se observan HSTS, CSP, Referrer-Policy, Permissions-Policy, X-Frame-Options y X-Content-Type-Options. Ausencias o valores ambiguos son observaciones informativas, no vulnerabilidades confirmadas. Solo respuestas 2xx son `complete`; redirects, errores HTTP, DNS, TLS, timeout o protocolo producen reporte `incomplete` y código `3`. Un 2xx también podría ser un challenge de Cloudflare: el cuerpo no se inspecciona y no se garantiza haber observado la aplicación de origen. No se persiste el cuerpo, cookies, `Location` ni headers fuera de allowlist.

El JSON (esquema 2) es la fuente del Markdown. El reporte incluye resumen ejecutivo y explica cada observación con impacto potencial, recomendación, precauciones y validaciones pendientes. `complete` significa que terminaron los checks, no que el sitio sea seguro. El contexto de auditoría referencia ISO/IEC 27001:2022 Anexo A.8.26 de forma orientativa y deja sin completar alcance del SGSI, responsable, requisito y decisión de tratamiento para revisión organizacional. No prueba eficacia integral ni certificación; los artefactos tampoco están firmados ni proporcionan cadena de custodia. Ver el [contrato MVP](docs/mvp.md).

## Docker

Docker Engine y plugin Compose; no requiere instalar Python o crear `.venv` en el host. Preparar `config.yaml` y `evidence/` antes de ejecutar Compose. No es un servicio web ni necesita `docker compose up`:

```bash
docker compose build
mkdir -p evidence
docker compose run --rm agent scope "<target-autorizado>"

# Evaluación pública; UID/GID permiten leer los reportes en el host
APP_UID="$(id -u)" APP_GID="$(id -g)" docker compose run --rm agent scan "<hostname-autorizado>" --evidence-dir /evidence

# Suite completa en el contenedor
docker compose run --rm --entrypoint python agent -m unittest discover -s tests -v

# Restricciones efectivas del contenedor (solo dentro de Compose)
docker compose run --rm --entrypoint python agent -m unittest tests.check_container -v
```

Crear o revisar `config.yaml` y `evidence/` antes de ejecutar Compose. La configuración se monta en `/app/config.yaml` en solo lectura y la evidencia en `/evidence`; ambos montajes fallan si falta el path. Cambiar estos archivos no requiere reconstruir la imagen. Con Docker, `--config` y `--evidence-dir` deben apuntar a rutas dentro del contenedor.

- Imagen Python 3.12 slim Bookworm fijada por digest y dependencias fijadas por lockfile.
- Usuario no root (`10001:10001` por defecto), filesystem de solo lectura y `/tmp` temporal; sin capabilities ni escalada de privilegios.
- Red bridge para evaluación pública; sin puertos publicados ni acceso al socket Docker. El código rechaza DNS no público y fija la IP conectada; Compose por sí solo no restringe el egress a direcciones públicas. El build también necesita descargar imagen y paquetes.
- `.dockerignore` permite solo código, tests, fixture sintético y archivos de empaquetado. La imagen no contiene el scope real ni `.venv` o secretos.
- Se incluyen los tests y certificados sintéticos en la misma imagen. Rebuild necesario al cambiar código o fixtures.

`APP_UID` y `APP_GID` permiten que los reportes del bind mount pertenezcan al usuario local, sin ejecutar como root. Estas restricciones están en Compose: `docker run` sin opciones equivalentes no las aplica todas.

| Código de salida | Significado | Salida |
|---|---|---|
| `0` | Target autorizado (`scope`) o evaluación completada (`scan`) | stdout |
| `1` | Target válido, fuera del scope | stderr |
| `2` | Entrada, configuración o uso del CLI inválido | stderr |
| `3` | Evaluación incompleta; reportes con error generados | stdout |

`--help` sale con `0`. `scope` es una consulta local sin red; `scan` realiza una evaluación pública.

## Contratos de autorización

- Dominios ASCII con al menos dos etiquetas, sin punto final; comparación exacta tras convertir mayúsculas a minúsculas. No hay conversión automática de Unicode/IDNA.
- Autorizar un dominio no autoriza subdominios. Un subdominio requiere su propia entrada explícita.
- IPs IPv4 e IPv6 individuales normalizadas con `ipaddress`. No se admite CIDR, IPv4 ambiguo, IPv6 entre corchetes ni zonas de interfaz.
- No se aceptan URLs, puertos, rutas, comodines, espacios ni comandos.
- `scope` no resuelve DNS. `scan` resuelve el hostname solo como transporte de la solicitud autorizada; rechaza respuestas no globales y conecta a una IP fijada. La IP no queda autorizada como target independiente.
- `scope` vacío es válido pero no autoriza nada. Un target malformado o fuera del scope nunca produce una autorización.
- Configuración UTF-8 de hasta 64 KiB, cargada con un loader seguro. Se rechazan claves desconocidas o duplicadas, tipos inválidos y entradas de scope duplicadas tras normalizar.
- `scope`, `policy` y `tools` son obligatorios; policy y tools requieren todos los campos del ejemplo. Los flags destructivos deben ser booleanos `false`. El límite de solicitudes debe ser un número finito mayor que cero.
- `authorize_action` valida primero el scope y luego la acción conocida y su habilitación. `scan` consulta esa policy antes de DNS. El máximo de solicitudes por segundo sigue siendo solo validación de configuración: no aplica rate limiting entre procesos CLI.

La autorización del dominio no verifica autorización legal ni cubre automáticamente hosting/CDN/origen compartidos. El MVP observa solo la respuesta pública detrás de Cloudflare; no descubre ni intenta alcanzar el origen. Contratos completos en [`docs/mvp.md`](docs/mvp.md).

## Verificación

```bash
# Suite completa
.venv/bin/python -m unittest discover -s tests -v

# Solo scope
.venv/bin/python -m unittest tests.test_scope -v

# Un contrato concreto
.venv/bin/python -m unittest tests.test_scope.ScopeTests.test_no_inherited_or_suffix_authorization -v

# Regresión de exclusiones: requiere Git, solo en el checkout del host
.venv/bin/python -m unittest tests.check_git -v
```

| Criterio de aceptación | Verificación |
|---|---|
| Dominios exactos, subdominios e IPs | `tests/test_scope.py` |
| Entradas inválidas, inyección y scope vacío | `tests/test_scope.py` |
| Configuración segura, inmutable y sin claves ambiguas | `tests/test_config.py` |
| Bloqueo de acciones desconocidas, deshabilitadas o fuera del scope | `tests/test_policy.py` |
| Mensajes, códigos de salida y ausencia de llamadas a red/procesos en los caminos probados | `tests/test_cli.py` |
| Finding: severidad, estado, CVSS finito entre 0 y 10, timestamp con zona y JSON | `tests/test_models.py` |
| DNS no global, TLS/SNI, request único, redirects, allowlist de headers, límites y reportes | `tests/test_web.py` |
| Targets sin duplicación en Python y restricciones de empaquetado | `tests/test_packaging.py` |

Los tests usan únicamente `tests/fixtures/config.yaml`, con targets reservados, y no leen el scope real. Las pruebas web abren un servidor TLS local con certificado sintético; DNS se sustituye y la conexión a la IP pública simulada se redirige a loopback. No se contactan targets externos. El fixture de scope debe incluirse en Git; `/config.yaml` excluye solamente la configuración privada de la raíz. No hay linter, typechecker ni cobertura configurados; los tests no certifican la seguridad de herramientas futuras.

## Límites de esta entrega

`app/scope.py` centraliza sintaxis y autorización; `app/config.py` reutiliza la validación. `app/policy.py` valida la acción antes de scan. `app/web.py` contiene el request y la generación de reportes.

Los findings automáticos actuales son observaciones informativas de headers ausentes, inválidos o ambiguos, con referencia orientativa a A.8.26. No implican vulnerabilidad confirmada ni certificación ISO.

Pendientes: TLS ampliado, comportamiento sobre rutas explícitas, comparación de ejecuciones, evaluación interna del origen, autenticación e IA. No se añadieron dependencias HTTP o de escaneo. Ver [ROADMAP.md](ROADMAP.md) y [AGENTS.md](AGENTS.md) antes de ampliar el alcance.
