# Contrato MVP — evaluación pública de headers

## Objetivo y límites

Una evaluación CLI, de un hostname por ejecución, observa la respuesta HTTPS pública servida para `GET /`. Es una comprobación técnica puntual, no un escaneo exhaustivo. No demuestra seguridad general, efectividad integral de controles, cumplimiento ni certificación ISO/IEC 27001.

No incluye autenticación, crawling, descubrimiento de rutas, explotación, métodos diseñados para modificar estado, acceso al origen/DC ni análisis con IA. Un GET también podría tener efectos secundarios por un defecto de la aplicación; la autorización debe cubrir explícitamente `GET /`.

## Entrada y autorización

- Target: hostname ASCII que figure explícitamente en `scope.domains`.
- No se admiten IPs directas, URLs, puertos, rutas ni comodines.
- La acción `http_headers` debe estar habilitada en policy.
- Sintaxis, scope o policy rechazados deben ocurrir antes de DNS o sockets.
- La autorización del hostname no autoriza la IP como target independiente.

## Conexión

- Una sola solicitud `GET https://<hostname>:443/`, con hostname exacto en `Host` y SNI.
- Una resolución DNS absoluta (sin sufijos de búsqueda); fijar la IP elegida en el socket, sin una segunda resolución.
- Se rechaza la respuesta DNS si alguna IP devuelta no es globalmente enrutable. La IP pública elegida se usa solo para transportar la solicitud autorizada.
- Validar cadena de confianza y nombre del certificado TLS. Un error de TLS no se omite ni reintenta.
- No seguir redirects, ni siquiera hacia otro hostname autorizado; no reintentar.
- Límite de 15 segundos para la evaluación, incluyendo espera de DNS, conexión, handshake y lectura de headers.
- Límite de 64 KiB para status line y headers de respuesta.
- No interpretar ni persistir el cuerpo de la respuesta. La lectura para delimitar headers puede recibir bytes adicionales de forma transitoria; se descartan y no se guardan. Persistir solo headers de seguridad de una lista permitida; nunca `Set-Cookie`, `Location` ni headers arbitrarios.

La IP conectada se registra como dato de trazabilidad, no como autorización adicional. El resultado describe únicamente la perspectiva pública observada detrás del intermediario (por ejemplo, Cloudflare), no el origen.

Solo respuestas 2xx cuentan como evaluación completa; redirects y otros status producen `incomplete`. Una respuesta 2xx puede aun ser una página de challenge de CDN: como el body no se inspecciona, el reporte no garantiza que se haya observado la aplicación de origen.

## Comprobaciones

Registrar presencia de:

- `Strict-Transport-Security`
- `Content-Security-Policy`
- `Referrer-Policy`
- `Permissions-Policy`
- `X-Frame-Options`

Para `X-Content-Type-Options`, el valor válido es `nosniff`. Valores repetidos o inválidos se reportan como ambiguos/inválidos. Las ausencias se reportan como observaciones de hardening de severidad informativa, no como vulnerabilidades confirmadas. La presencia no certifica la calidad de la política. No se evalúa aquí la calidad interna de CSP ni equivalencias como `frame-ancestors`.

## Evidencia y reportes

- Directorio local por ejecución con ID único; nunca sobrescribir ejecuciones previas.
- Generar `report.json` como fuente y `report.md` derivado. La versión de esquema actual es 2.
- Registrar ID, UTC de inicio/fin, target, perspectiva pública, IP conectada cuando exista, versiones de herramienta/reglas, estado HTTP, headers seleccionados, checks, hallazgos, errores y limitaciones.
- Incluir resumen ejecutivo con alcance, estado interpretado, checks planeados/completados y cantidad de observaciones. `complete` significa que terminaron estos checks técnicos, no que el sitio sea seguro.
- Cada observación explica lo observado, evidencia enlazada al check, impacto potencial, recomendación, precauciones y validaciones pendientes. No se presenta como vulnerabilidad confirmada.
- Cada hallazgo enlaza a un check del JSON. Una falla de DNS, TLS, timeout o respuesta inválida produce un reporte `incomplete`, sin presentarlo como resultado limpio.
- No guardar cuerpo, cookies, credenciales ni `Location`.
- Los controles ISO son referencias de contexto. Una correspondencia técnica puntual con ISO/IEC 27001:2022 Anexo A.8.26 (requisitos de seguridad de aplicaciones) no prueba que el control organizacional esté definido, implementado eficazmente o conforme. La organización y su auditor deben validar pertinencia y evidencia.
- El contexto de auditoría deja vacíos alcance del SGSI, responsable, requisito asociado y decisión de tratamiento; no se infieren automáticamente. La organización debe completarlos y revisarlos antes de usar el reporte como evidencia.
- Los archivos se crean con permisos restrictivos y modo exclusivo. Retención, respaldo y control de acceso al directorio quedan a cargo del usuario.
- Los artefactos locales no están firmados y no demuestran autenticidad o cadena de custodia; ese requisito, si aplica, queda para una etapa posterior.

## Códigos CLI

| Código | Significado |
|---|---|
| 0 | Evaluación completada y reportes generados; puede haber observaciones informativas |
| 1 | Target fuera de scope o acción denegada; no se conecta |
| 2 | Uso, entrada, configuración o escritura del reporte inválidos |
| 3 | Evaluación incompleta; se generan reportes con el error, no un resultado limpio |

## Criterios de aceptación

- Target inválido, fuera de scope o acción deshabilitada: cero DNS/sockets.
- Tests sintéticos verifican DNS no global, pinning de IP, SNI/hostname, TLS inválido, ausencia de redirect/retry, timeout total y límite de headers.
- Conexión TLS de integración solo a un servidor local sintético, con resolución y certificado de prueba; nunca a targets de usuario.
- El cuerpo, cookies, `Location` y headers fuera de allowlist no aparecen en artefactos.
- Dos ejecuciones conservan artefactos distintos sin alterar reportes previos; JSON es válido y Markdown coincide con el resumen y los checks.
- Los campos organizacionales quedan vacíos y la referencia ISO exige revisión humana.
- Errores de red y respuestas de acceso restringido no se presentan como “sin hallazgos”.
- Las regresiones de scope/configuración permanecen aprobadas.
