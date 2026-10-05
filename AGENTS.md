# defensive-security-agent

Proyecto local de ciberseguridad defensiva para targets con autorización explícita. El directorio se llama `cibersec-agent`; el nombre acordado del proyecto es `defensive-security-agent`.

## Alcance inicial acordado

- Implementadas: configuración, modelo `Finding`, scope centralizado, policy, CLI `scope` y MVP `scan` de headers públicos con reportes. No ampliar el alcance sin aprobación.
- `scope` es consulta local y no usa red. `scan <hostname>` hace un GET HTTPS a `/`, con policy/scope previos, y genera JSON/Markdown; no usa LLM.
- Fuera de alcance: crawling, auth, explotación, evaluación del origen/DC, Nmap, Nuclei, IA y comparación de ejecuciones.
- Python 3.12+ (verificado con 3.12.3), Pydantic, PyYAML y `unittest`. Contratos en `README.md`, `ROADMAP.md` y `docs/mvp.md`.

## Comandos y límites existentes

- Instalación: `python3 -m venv .venv`, luego `.venv/bin/python -m pip install -r requirements.lock`, luego `.venv/bin/python -m pip install -e . --no-deps --no-build-isolation`. El lockfile incluye el backend; instalarlo primero.
- Suite: `.venv/bin/python -m unittest discover -s tests -v`; scope: `.venv/bin/python -m unittest tests.test_scope -v`; caso individual: `.venv/bin/python -m unittest tests.test_scope.ScopeTests.test_no_inherited_or_suffix_authorization -v`.
- Sin `--config`, el CLI busca `config.yaml` relativo al cwd; no cae automáticamente al ejemplo. Códigos: `0` consulta autorizada/evaluación completada, `1` fuera de scope o acción denegada, `2` entrada/config/uso/artefactos inválidos, `3` evaluación incompleta con reporte.
- Scope real solo en `config.yaml`, local y excluido de Git/imagen. `config.example.yaml` tiene scope vacío. No hardcodear dominios ni targets del fixture en Python; tests usan exclusivamente `tests/fixtures/config.yaml` mediante `tests/support.py`, sin depender de permisos reales.
- El fixture `tests/fixtures/config.yaml` debe incluirse en Git. Mantener la exclusión como `/config.yaml`, no `config.yaml`: la regla sin slash también oculta el fixture. Verificar los archivos publicables y probar una copia limpia antes de afirmar que un clon funciona.
- Regresión de exclusiones (host con Git): `.venv/bin/python -m unittest tests.check_git -v`; no ejecutar esta suite dentro de la imagen, que no contiene Git ni el checkout.
- Docker: `docker compose build`, luego `docker compose run --rm agent scope <target>` o `scan <hostname> --evidence-dir /evidence`; suite: `docker compose run --rm --entrypoint python agent -m unittest discover -s tests -v`. No es un daemon.
- Crear `evidence/` en el host además de `config.yaml`. Compose monta config read-only y evidence en `/evidence`; `APP_UID`/`APP_GID` permiten ownership local al escanear.
- Compose usa bridge por la evaluación pública. Conserva no-root, filesystem read-only, `/tmp` temporal, capabilities eliminadas, no-new-privileges, sin puertos ni socket Docker. Egress no está limitado por Docker; el scanner valida DNS y fija IP pública.
- Aislamiento efectivo: `docker compose run --rm --entrypoint python agent -m unittest tests.check_container -v`. Solo dentro de Compose; verifica UID efectivo, capabilities, filesystem e interfaz habilitada.
- Imagen base fijada por digest; `.dockerignore` usa allowlist. Al actualizar empaquetado, conservar los tests ejecutables dentro de la imagen y verificar que no se incluya configuración privada.
- Sintaxis y autorización están en `app/scope.py`; `app/config.py` reutiliza la sintaxis. `authorize_action` en `app/policy.py` devuelve el target normalizado, no ejecuta una tool.
- Configuración estricta e inmutable, YAML seguro UTF-8 hasta 64 KiB, sin claves desconocidas o duplicadas. No usar `model_construct` ni actualizaciones sin validación para aceptar configuración externa.
- `scope` admite hostnames ASCII de múltiples etiquetas e IPs individuales sin convertir IDNA; no hace DNS. `scan` admite hostname solamente y resuelve DNS absoluto para fijar una IP pública al socket.
- `scan`: un GET a HTTPS/443 `/`, hostname/SNI verificados, sin redirect ni retry, máximo 15 s incluyendo DNS y 64 KiB de status+headers. Persiste solo headers allowlisted, no body/cookies/Location.
- `max_requests_per_second` solo se valida: no hace rate limiting entre procesos. El timeout de DNS usa hilo daemon, porque el resolver libc no se puede cancelar.
- Tests CLI verifican que `scope` no hace red/procesos; tests web usan solo TLS local sintético con DNS/IP simulados. No hay linter, typechecker ni cobertura configurados.

## Contratos y forma de trabajo

- Antes de implementar cada bloque, explicitar contratos de producto y técnicos: entradas, resultados, errores, prohibiciones y criterios de aceptación. Resolver ambigüedades de seguridad antes de escribir código.
- Derivar los tests de esos contratos, antes o junto con la implementación; cubrir casos positivos, negativos y límites. No cambiar expectativas para ocultar incumplimientos; un cambio de contrato requiere acuerdo explícito del usuario.
- Trabajar en bloques pequeños, sin funcionalidades extra. Al cerrar la etapa, revisar cada criterio como cumplido, pendiente o bloqueado y detenerse; no avanzar automáticamente a herramientas.
- Verificar la versión de Python y usar `.venv` local. Declarar dependencias en `pyproject.toml` y registrar versiones exactas para reproducir el entorno. No crear `.env` mientras no exista una necesidad concreta de variables o secretos.
- Distinguir siempre código implementado, comprobaciones ejecutadas y comportamiento verificado. Informar comandos reales, resultados, fallos y limitaciones; tests omitidos o bloqueados no cuentan como aprobados.
- Mantener este archivo actualizado al cambiar comandos, restricciones o decisiones confirmadas. Separar capacidades previstas de existentes; no convertirlo en historial ni afirmar verificaciones que no se realizaron.

## Autorización y seguridad

- El agente propone una prueba; el código decide si está permitida. Nunca aceptar comandos ni argumentos libres generados por un LLM.
- Una única función central valida scope. `scan` debe consultar `authorize_action` antes de DNS o cualquier socket.
- Dominios con coincidencia exacta: autorizar un dominio no autoriza subdominios ni las IPs resueltas.
- No inferir autorización legal o propiedad por la presencia de un target en `config.yaml`; requiere autorización explícita y delimitación de infraestructura. Un dominio no implica CDN, hosting compartido u origen. Usar targets sintéticos en tests; nunca targets reales.
- Scope admite dominios/IPs individuales: no URLs, puertos, rutas, comodines ni CIDR. `scan` solo admite hostnames exactos declarados en `scope.domains`; IP conectada es transporte, no un target autorizado.
- Rechazar entradas inválidas o fuera del scope antes de ejecutar acciones. Distinguir errores de sintaxis, autorización y configuración.
- Fallar cerrado: configuración inválida, entrada dudosa o acción desconocida implica rechazo, nunca autorización por defecto.
- Policy con acciones conocidas y herramientas habilitadas; rechazar configuraciones que permitan brute force, DoS o pruebas destructivas.
- Nunca ejecutar shell arbitrario ni usar `shell=True`. No borrar ni modificar información del target.
- Una evaluación es exactamente un GET; no seguir redirects, reintentar, explorar rutas ni persistir el body. Autorizar explícitamente `GET /`: una app defectuosa podría modificar estado aun con GET. Un error produce `incomplete`, nunca un resultado limpio.

## Verificación y etapas posteriores

- Mantener tests existentes de dominios, subdominios, IPs, inyección, policy/config y códigos del CLI.
- Tests web: DNS no global, pinning IP, TLS/SNI y certificado inválido, un GET, sin redirect/retry, límites, headers allowlisted, outputs exclusivos, permisos y JSON/Markdown. Solo servidor de TLS sintético en loopback.
- Ejecutar los tests tras cada bloque de implementación; informar resultados y pendientes antes de avanzar de etapa.
- Agregar capacidades una por una, tras verificar la autorización y obtener aprobación para continuar.
- Cada ejecución genera ID y directorio exclusivo; no sobrescribir reportes anteriores. Retención, respaldo y acceso son responsabilidad del usuario.
- Referencias ISO son orientativas; no afirman conformidad/certificación ni demuestran eficacia integral del control.
