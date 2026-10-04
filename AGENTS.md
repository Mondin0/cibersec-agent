# defensive-security-agent

Proyecto local de ciberseguridad defensiva para targets con autorización explícita. El directorio se llama `cibersec-agent`; el nombre acordado del proyecto es `defensive-security-agent`.

## Alcance inicial acordado

- Primera etapa implementada: configuración, modelo Finding, scope centralizado, policy, CLI de consulta y tests. No ampliar el alcance sin aprobación del usuario.
- CLI existente: `.venv/bin/python -m app.main scope <target>`. Es una consulta local de configuración, no prueba de propiedad ni escaneo: no debe hacer conexiones HTTP, resolver DNS o ejecutar herramientas externas.
- No implementar todavía `scan`, HTTP headers, TLS, Nmap, Nuclei, LLM, almacenamiento de evidencia ni reportes.
- Python 3.12+ (verificado con 3.12.3), Pydantic, PyYAML y `unittest`. Comandos y contratos completos en `README.md`.

## Comandos y límites existentes

- Instalación: `python3 -m venv .venv`, luego `.venv/bin/python -m pip install -r requirements.lock`, luego `.venv/bin/python -m pip install -e . --no-deps --no-build-isolation`. El lockfile incluye el backend; instalarlo primero.
- Suite: `.venv/bin/python -m unittest discover -s tests -v`; scope: `.venv/bin/python -m unittest tests.test_scope -v`; caso individual: `.venv/bin/python -m unittest tests.test_scope.ScopeTests.test_no_inherited_or_suffix_authorization -v`.
- Sin `--config`, el CLI busca `config.yaml` relativo al cwd; no cae automáticamente al ejemplo. Códigos: `0` autorizado, `1` fuera del scope, `2` entrada/configuración/uso inválido. Errores a stderr.
- Scope real solo en `config.yaml`, local y excluido de Git/imagen. `config.example.yaml` tiene scope vacío. No hardcodear dominios ni targets del fixture en Python; tests usan exclusivamente `tests/fixtures/config.yaml` mediante `tests/support.py`, sin depender de permisos reales.
- El fixture `tests/fixtures/config.yaml` debe incluirse en Git. Mantener la exclusión como `/config.yaml`, no `config.yaml`: la regla sin slash también oculta el fixture. Verificar los archivos publicables y probar una copia limpia antes de afirmar que un clon funciona.
- Regresión de exclusiones (host con Git): `.venv/bin/python -m unittest tests.check_git -v`; no ejecutar esta suite dentro de la imagen, que no contiene Git ni el checkout.
- Docker: `docker compose build`, luego `docker compose run --rm agent scope <target>`; suite: `docker compose run --rm --entrypoint python agent -m unittest discover -s tests -v`. No es un daemon y no requiere `up`.
- Aislamiento efectivo: `docker compose run --rm --entrypoint python agent -m unittest tests.check_container -v`. Esta suite es solo para Compose, no para el host; verificar UID, capabilities, filesystem y ausencia de interfaces de red externas.
- Compose monta `config.yaml` read-only y falla si falta; imagen sin scope real, usuario no root, filesystem read-only, `/tmp` temporal, capabilities eliminadas y sin red. No habilitar networking ni privilegios para esta etapa.
- Imagen base fijada por digest; `.dockerignore` usa allowlist. Al actualizar empaquetado, conservar los tests ejecutables dentro de la imagen y verificar que no se incluya configuración privada.
- Sintaxis y autorización están en `app/scope.py`; `app/config.py` reutiliza la sintaxis. `authorize_action` en `app/policy.py` devuelve el target normalizado, no ejecuta una tool.
- Configuración estricta e inmutable, YAML seguro UTF-8 hasta 64 KiB, sin claves desconocidas o duplicadas. No usar `model_construct` ni actualizaciones sin validación para aceptar configuración externa.
- Solo hostnames ASCII de múltiples etiquetas sin punto final e IPs individuales; no hay conversión IDNA ni DNS. Los tests del CLI bloquean funciones de red y procesos.
- `max_requests_per_second` solo se valida; rate limiting, DNS seguro y redirects deben resolverse antes de incorporar conexiones reales. No hay linter, typechecker ni cobertura configurados.

## Contratos y forma de trabajo

- Antes de implementar cada bloque, explicitar contratos de producto y técnicos: entradas, resultados, errores, prohibiciones y criterios de aceptación. Resolver ambigüedades de seguridad antes de escribir código.
- Derivar los tests de esos contratos, antes o junto con la implementación; cubrir casos positivos, negativos y límites. No cambiar expectativas para ocultar incumplimientos; un cambio de contrato requiere acuerdo explícito del usuario.
- Trabajar en bloques pequeños, sin funcionalidades extra. Al cerrar la etapa, revisar cada criterio como cumplido, pendiente o bloqueado y detenerse; no avanzar automáticamente a herramientas.
- Verificar la versión de Python y usar `.venv` local. Declarar dependencias en `pyproject.toml` y registrar versiones exactas para reproducir el entorno. No crear `.env` mientras no exista una necesidad concreta de variables o secretos.
- Distinguir siempre código implementado, comprobaciones ejecutadas y comportamiento verificado. Informar comandos reales, resultados, fallos y limitaciones; tests omitidos o bloqueados no cuentan como aprobados.
- Mantener este archivo actualizado al cambiar comandos, restricciones o decisiones confirmadas. Separar capacidades previstas de existentes; no convertirlo en historial ni afirmar verificaciones que no se realizaron.

## Autorización y seguridad

- El agente propone una prueba; el código decide si está permitida. Nunca aceptar comandos ni argumentos libres generados por un LLM.
- Una única función central debe validar scope. Cada futura herramienta debe pasar por ella antes de cualquier conexión o ejecución.
- Dominios con coincidencia exacta: autorizar un dominio no autoriza subdominios ni las IPs resueltas.
- No inferir autorización legal o propiedad por la presencia de un target en `config.yaml`; requiere confirmación explícita y delimitación de infraestructura. La confirmación previa del usuario no cubre targets agregados posteriormente ni hosting compartido; usar solo targets sintéticos del fixture en tests.
- En la primera etapa, admitir únicamente hostnames e IPs individuales: no URLs, puertos, rutas, comodines ni CIDR. Normalizar mayúsculas en dominios y comparar IPs con `ipaddress`.
- Rechazar entradas inválidas o fuera del scope antes de ejecutar acciones. Distinguir errores de sintaxis, autorización y configuración.
- Fallar cerrado: configuración inválida, entrada dudosa o acción desconocida implica rechazo, nunca autorización por defecto.
- Policy con acciones conocidas y herramientas habilitadas; rechazar configuraciones que permitan brute force, DoS o pruebas destructivas.
- Nunca ejecutar shell arbitrario ni usar `shell=True`. Las futuras herramientas construirán internamente comandos fijos, con timeout y captura de stdout/stderr.
- No borrar ni modificar información del target. No hacer pruebas reales como parte de los tests de esta etapa.

## Verificación y etapas posteriores

- Tests iniciales: dominios exactos, subdominios explícitos y no autorizados, sufijos engañosos, IPs permitidas y rechazadas, inyección en targets, acciones bloqueadas y configuración insegura.
- Probar también mensajes y códigos de salida del CLI y que la consulta de scope no use red ni herramientas externas. La verificación de autorización no sustituye la verificación de seguridad de futuras herramientas.
- Ejecutar los tests tras cada bloque de implementación; informar resultados y pendientes antes de avanzar de etapa.
- Agregar herramientas una por una solamente después de verificar la autorización y obtener aprobación para continuar.
- La evidencia futura debe tener identificadores únicos por ejecución y nunca sobrescribir ejecuciones anteriores.
- Preparar `Finding` para referencias opcionales a controles ISO/IEC 27001; ningún reporte constituye certificación ISO.
