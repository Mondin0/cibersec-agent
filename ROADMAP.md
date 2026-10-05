# Roadmap — defensive-security-agent

## Objetivo

CLI personal para evaluar webs autorizadas y producir reportes con evidencia técnica que pueda referenciarse en evaluaciones de controles de ISO/IEC 27001. La herramienta no certifica ni determina por sí sola el cumplimiento.

## Alcance acordado

- Ejecución manual desde terminal; scheduling y despliegue quedan fuera del producto.
- Un hostname por ejecución.
- Primero la perspectiva pública del servicio servido por Cloudflare.
- MVP: HTTPS, puerto 443, `GET /`, sin redirects, reintentos, crawling, credenciales ni explotación.
- Salidas JSON y Markdown por ejecución, sin sobrescribir resultados anteriores.

## Etapas

| Estado | Etapa | Entrega | Criterio de salida |
|---|---|---|---|
| ✅ Implementada | 0. Base | Configuración, scope, policy, CLI de consulta y `Finding` | Suite local aprobada; sin conexiones de evaluación |
| ✅ Implementada; prueba en target autorizado pendiente | 1. MVP público | Headers HTTP, evidencia, JSON y Markdown | Se cumple [el contrato MVP](docs/mvp.md), incluidos los límites y errores incompletos |
| Pendiente | 2. TLS ampliado | Observaciones adicionales del certificado y protocolo | Se distingue validación de transporte de hallazgos de configuración |
| Pendiente | 3. Comportamiento público acotado | Comprobaciones predefinidas sobre rutas expresamente delimitadas | Contrato y límites por prueba; no se modifican datos |
| Pendiente | 4. Seguimiento e ISO | Comparación, mapeos ampliados y, si la auditoría lo requiere, integridad/custodia de artefactos | Trazabilidad validada; los reportes no afirman cumplimiento ni certificación automática |
| Pendiente | 5. Origen/DC | Perfil interno separado | Scope independiente; no se descubre ni evade Cloudflare para alcanzar el origen |
| Pendiente | 6. Autenticación e IA | Evaluación autenticada; luego asistencia sobre evidencia | Credenciales protegidas; la IA no decide permisos ni genera comandos ejecutables |

No se avanza automáticamente entre etapas. Cada etapa necesita revisión y aprobación.
