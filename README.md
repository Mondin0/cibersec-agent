# defensive-security-agent

Base local de autorización para futuras evaluaciones defensivas sobre targets con permiso explícito. **Esta primera etapa no escanea ni utiliza un LLM.**

## Instalación

Python 3.12+; entorno comprobado en Linux con Python 3.12.3. Desde la raíz del proyecto:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.lock
.venv/bin/python -m pip install -e . --no-deps --no-build-isolation
.venv/bin/python -m pip check
```

El lockfile fija dependencias directas, transitivas y backend de construcción. Instalarlo **antes** del proyecto editable; así no se resuelven dependencias adicionales durante el build. No es una garantía de reproducibilidad binaria entre plataformas. La instalación necesita acceso al índice de paquetes o una caché disponible; la consulta de scope y los tests no necesitan red.

No se usa `.env` ni se requieren credenciales. `.venv` y la configuración local están excluidos en `.gitignore`.

## Consulta de autorización

Los permisos reales se definen únicamente en `config.yaml` (local, excluido de Git y Docker). Este entorno ya tiene una configuración local con el dominio confirmado por el usuario. Para consultar un target declarado allí:

```bash
.venv/bin/python -m app.main scope "<target-autorizado>"
```

Resultado:

```text
AUTORIZADO: <target-autorizado>
Motivo: coincidencia exacta con una entrada del scope. No se realizó ningún escaneo.
```

En una instalación nueva, copiar el ejemplo **solo si no existe `config.yaml`**, y editar su scope según la autorización real:

```bash
cp -n config.example.yaml config.yaml
.venv/bin/python -m app.main scope "<target-autorizado>"
```

Reemplazar los placeholders por targets reales. El ejemplo tiene scope vacío y no concede permisos. El path por defecto es `config.yaml` relativo al directorio de ejecución; se puede seleccionar otro archivo con `--config <ruta>`. Si falta o es inválido, se rechaza la consulta: nunca se utilizan permisos de ejemplo automáticamente.

## Docker

Docker Engine y plugin Compose; no es un servicio web ni necesita `docker compose up`:

```bash
docker compose build
docker compose run --rm agent scope "<target-autorizado>"

# Suite completa en el contenedor
docker compose run --rm --entrypoint python agent -m unittest discover -s tests -v

# Restricciones efectivas del contenedor (solo dentro de Compose)
docker compose run --rm --entrypoint python agent -m unittest tests.check_container -v
```

Crear o revisar `config.yaml` antes de ejecutar Compose. Se monta en `/app/config.yaml` en solo lectura; si no existe, el montaje falla sin crear directorios ni conceder permisos. Cambiar este archivo no requiere reconstruir la imagen. Con Docker, `--config` debe apuntar a una ruta dentro del contenedor.

- Imagen Python 3.12 slim Bookworm fijada por digest y dependencias fijadas por lockfile.
- Usuario `10001:10001`, filesystem de solo lectura y `/tmp` temporal; sin capabilities ni escalada de privilegios.
- Sin red (`network_mode: none`), puertos publicados o acceso al socket Docker. El build sí necesita descargar imagen y paquetes.
- `.dockerignore` permite solo código, tests, fixture sintético y archivos de empaquetado. La imagen no contiene el scope real ni `.venv` o secretos.
- Se incluyen los tests en la misma imagen para verificarlos sin montar código del host. Rebuild necesario al cambiar código o fixture.

La ausencia de red es intencional en esta etapa. No quitarla hasta acordar los contratos de las futuras herramientas de red. Estas restricciones están en Compose: `docker run` sin opciones equivalentes no las aplica todas.

| Código de salida | Significado | Salida |
|---|---|---|
| `0` | Target autorizado | stdout |
| `1` | Target válido, fuera del scope | stderr |
| `2` | Entrada, configuración o uso del CLI inválido | stderr |

`--help` sale con `0`. Solo existe el subcomando `scope`; `scan` no está implementado.

## Contratos de autorización

- Dominios ASCII con al menos dos etiquetas, sin punto final; comparación exacta tras convertir mayúsculas a minúsculas. No hay conversión automática de Unicode/IDNA.
- Autorizar un dominio no autoriza subdominios. Un subdominio requiere su propia entrada explícita.
- IPs IPv4 e IPv6 individuales normalizadas con `ipaddress`. No se admite CIDR, IPv4 ambiguo, IPv6 entre corchetes ni zonas de interfaz.
- No se aceptan URLs, puertos, rutas, comodines, espacios ni comandos.
- No se resuelve DNS: un dominio no autoriza sus IPs ni los otros servicios de un hosting compartido.
- `scope` vacío es válido pero no autoriza nada. Un target malformado o fuera del scope nunca produce una autorización.
- Configuración UTF-8 de hasta 64 KiB, cargada con un loader seguro. Se rechazan claves desconocidas o duplicadas, tipos inválidos y entradas de scope duplicadas tras normalizar.
- `scope`, `policy` y `tools` son obligatorios; policy y tools requieren todos los campos del ejemplo. Los flags destructivos deben ser booleanos `false`. El límite de solicitudes debe ser un número finito mayor que cero.
- `authorize_action` valida primero el scope y luego la acción conocida y su habilitación. **No ejecuta herramientas.** El límite de solicitudes solo se valida: todavía no existe rate limiting.

La propiedad declarada del dominio se usa como contexto, no como verificación automática de autorización legal. Antes de agregar conexiones reales deben delimitarse puertos, infraestructura autorizada, resolución DNS, redirects y límites efectivos.

## Verificación

```bash
# Suite completa
.venv/bin/python -m unittest discover -s tests -v

# Solo scope
.venv/bin/python -m unittest tests.test_scope -v

# Un contrato concreto
.venv/bin/python -m unittest tests.test_scope.ScopeTests.test_no_inherited_or_suffix_authorization -v
```

| Criterio de aceptación | Verificación |
|---|---|
| Dominios exactos, subdominios e IPs | `tests/test_scope.py` |
| Entradas inválidas, inyección y scope vacío | `tests/test_scope.py` |
| Configuración segura, inmutable y sin claves ambiguas | `tests/test_config.py` |
| Bloqueo de acciones desconocidas, deshabilitadas o fuera del scope | `tests/test_policy.py` |
| Mensajes, códigos de salida y ausencia de llamadas a red/procesos en los caminos probados | `tests/test_cli.py` |
| Finding: severidad, estado, CVSS finito entre 0 y 10, timestamp con zona y JSON | `tests/test_models.py` |
| Targets sin duplicación en Python y restricciones de empaquetado | `tests/test_packaging.py` |

Los tests usan únicamente `tests/fixtures/config.yaml`, con targets reservados, y no leen el scope real. `tests/support.py` obtiene expectativas del YAML sin pasar por la normalización bajo prueba. Los tests del CLI bloquean y comprueban llamadas a funciones de sockets, DNS, subprocess y shell; no contactan targets. No se configuró todavía un linter, typechecker ni medición de cobertura. Los tests no certifican la seguridad de herramientas futuras.

## Límites de esta entrega

`app/scope.py` centraliza sintaxis y autorización; `app/config.py` reutiliza la validación de sintaxis sin duplicarla. `app/policy.py` consulta esa autorización. El CLI no consulta habilitaciones de tools porque no ejecuta ninguna acción.

El modelo `Finding` tiene referencias y controles ISO/IEC 27001 opcionales, pero todavía no se generan findings automáticamente ni se asignan controles. No implica certificación ISO.

Pendientes, fuera de esta etapa: HTTP headers, TLS, Nmap, Nuclei, evidencia, reportes y LLM. No se instalaron `httpx`, SDKs ni herramientas de escaneo porque aún no se usan. Ver [AGENTS.md](AGENTS.md) antes de ampliar el alcance.
