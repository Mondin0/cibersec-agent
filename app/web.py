from datetime import datetime, timezone
import ipaddress
import json
import logging
from importlib.metadata import PackageNotFoundError, version
import os
from pathlib import Path
import queue
import re
import socket
import ssl
import threading
import time
from uuid import uuid4

from app.models import Finding

logger = logging.getLogger(__name__)
_TIMEOUT_SECONDS = 15.0
_MAX_HEADER_BYTES = 65536
_RULESET_VERSION = "http-headers-v2"
_CONTROL = "ISO/IEC 27001:2022 Annex A.8.26"
_CHECKS = (
    ("hsts", "Strict-Transport-Security", "Usar HSTS para limitar downgrade a HTTP."),
    ("csp", "Content-Security-Policy", "Definir una política CSP apropiada para la aplicación."),
    ("referrer_policy", "Referrer-Policy", "Definir qué información de referencia puede compartir el navegador."),
    ("permissions_policy", "Permissions-Policy", "Limitar las funciones del navegador que la aplicación no necesita."),
    ("x_frame_options", "X-Frame-Options", "Definir protección contra framing; esta comprobación no evalúa CSP frame-ancestors."),
    ("content_type_options", "X-Content-Type-Options", "Configurar el valor X-Content-Type-Options: nosniff."),
)
_FINDING_GUIDANCE = {
    "hsts": (
        "Si el sitio también atiende HTTP, un navegador podría no exigir HTTPS en la primera visita.",
        ["No activar `includeSubDomains` o `preload` sin comprobar todos los subdominios y los requisitos de despliegue."],
        ["Verificar redirección HTTP→HTTPS, cobertura de subdominios y si existe un requisito aplicable."],
    ),
    "csp": (
        "Se pierde una capa de defensa en profundidad frente a ciertas cargas de contenido; esto no demuestra que exista XSS.",
        ["Una política genérica puede bloquear recursos legítimos; definirla según la aplicación."],
        ["Inventariar scripts, estilos y orígenes de recursos; validar una política en modo de reporte antes de aplicarla, si corresponde."],
    ),
    "referrer_policy": (
        "La información de referencia que comparten navegadores puede depender de sus valores predeterminados u otras políticas de la página.",
        ["La ausencia de este header no prueba exposición de datos: navegadores modernos suelen aplicar un valor predeterminado más restrictivo."],
        ["Revisar si la aplicación define una política equivalente y si URLs pueden contener información sensible."],
    ),
    "permissions_policy": (
        "Las funciones del navegador no quedan restringidas por este header en la respuesta observada; el riesgo depende de las funciones usadas y del contexto de embedding.",
        ["No bloquear funciones sin confirmar que la aplicación y sus integraciones no las necesitan."],
        ["Identificar funciones del navegador usadas y decidir si deben limitarse para esta aplicación."],
    ),
    "x_frame_options": (
        "Si una página interactiva puede ser enmarcada por terceros, podría aumentar el riesgo de clickjacking; la aplicabilidad depende de su contenido.",
        ["Una web estática o no interactiva puede tener una exposición distinta. CSP `frame-ancestors` puede ser una alternativa, pero este MVP no la evalúa."],
        ["Determinar si la aplicación debe permitir framing y revisar la directiva CSP `frame-ancestors` por separado."],
    ),
    "content_type_options": (
        "Un valor ausente o distinto de `nosniff` podría permitir que algunos navegadores interpreten contenido con un tipo inferido.",
        ["Asegurar que los tipos MIME servidos sean correctos antes de habilitar `nosniff`."],
        ["Validar `Content-Type` para los recursos servidos y confirmar que el valor de este header sea exactamente `nosniff`."],
    ),
}
_STATUS_LINE = re.compile(rb"HTTP/1\.[01] ([1-5][0-9][0-9])(?:[ \t].*)?")
_HEADER_NAME = re.compile(rb"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")


class AssessmentError(Exception):
    def __init__(self, category: str, message: str):
        super().__init__(message)
        self.category = category
        self.message = message


def _tls_client_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.load_default_certs()
    return context


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise AssessmentError("timeout", "La evaluación superó el límite total de 15 segundos.")
    return remaining


def _resolve_public_address(hostname: str, deadline: float) -> tuple[int, tuple, str]:
    result: queue.Queue = queue.Queue(maxsize=1)

    def resolve() -> None:
        try:
            result.put((True, socket.getaddrinfo(
                hostname + ".", 443, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP
            )))
        except Exception as exc:
            result.put((False, exc))

    # ponytail: libc DNS is not cancellable; a daemon worker bounds this CLI job, while async DNS is needed for long-lived embedding.
    threading.Thread(target=resolve, daemon=True, name="scope-dns").start()
    try:
        success, records = result.get(timeout=_remaining(deadline))
    except queue.Empty as exc:
        raise AssessmentError("timeout", "Se agotó el tiempo disponible para resolver DNS.") from exc
    if not success:
        raise AssessmentError("dns_error", "No se pudo resolver el hostname.") from records
    if not records:
        raise AssessmentError("dns_error", "DNS no devolvió direcciones.")

    addresses = []
    for family, socktype, proto, _, sockaddr in records:
        if family not in (socket.AF_INET, socket.AF_INET6) or socktype != socket.SOCK_STREAM:
            continue
        try:
            address = ipaddress.ip_address(sockaddr[0])
        except ValueError as exc:
            raise AssessmentError("dns_error", "DNS devolvió una dirección inválida.") from exc
        if not address.is_global:
            raise AssessmentError("dns_blocked", "DNS devolvió una dirección no enrutable públicamente.")
        addresses.append((family, proto, sockaddr, str(address)))
    if not addresses:
        raise AssessmentError("dns_error", "DNS no devolvió una dirección TCP utilizable.")
    _remaining(deadline)
    family, proto, sockaddr, address = addresses[0]
    return family, (sockaddr, proto), address


def _read_response_headers(sock: ssl.SSLSocket, deadline: float) -> tuple[int, dict[str, list[str]], int]:
    data = bytearray()
    while True:
        sock.settimeout(_remaining(deadline))
        chunk = sock.recv(min(4096, _MAX_HEADER_BYTES - len(data) + 1))
        if not chunk:
            raise AssessmentError("invalid_response", "La conexión cerró antes de completar los headers HTTP.")
        data.extend(chunk)
        end = data.find(b"\r\n\r\n")
        if end >= 0:
            if end + 4 > _MAX_HEADER_BYTES:
                raise AssessmentError("headers_too_large", "Los headers superan el límite de 64 KiB.")
            break
        if len(data) > _MAX_HEADER_BYTES:
            raise AssessmentError("headers_too_large", "Los headers superan el límite de 64 KiB.")

    lines = bytes(data[:end]).split(b"\r\n")
    match = _STATUS_LINE.fullmatch(lines[0]) if lines else None
    if not match:
        raise AssessmentError("invalid_response", "El servidor devolvió una status line HTTP inválida.")
    status = int(match.group(1))
    if 100 <= status < 200:
        raise AssessmentError("provisional_response", "Se recibió una respuesta HTTP provisional; no se procesa otra respuesta.")
    headers: dict[str, list[str]] = {}
    for line in lines[1:]:
        name, separator, value = line.partition(b":")
        if not separator or not _HEADER_NAME.fullmatch(name):
            raise AssessmentError("invalid_response", "El servidor devolvió un header HTTP inválido.")
        value = value.strip(b" \t")
        if any(byte < 32 and byte != 9 or byte == 127 for byte in value):
            raise AssessmentError("invalid_response", "El servidor devolvió un valor de header inválido.")
        key = name.decode("ascii").lower()
        if key in {header.lower() for _, header, _ in _CHECKS}:
            headers.setdefault(key, []).append(value.decode("latin-1"))
    return status, headers, end + 4


def _request(hostname: str, deadline: float) -> dict:
    family, (sockaddr, proto), address = _resolve_public_address(hostname, deadline)
    raw = socket.socket(family, socket.SOCK_STREAM, proto)
    tls = None
    try:
        raw.settimeout(_remaining(deadline))
        raw.connect(sockaddr)
        raw.settimeout(_remaining(deadline))
        try:
            context = _tls_client_context()
            raw.settimeout(_remaining(deadline))
            tls = context.wrap_socket(raw, server_hostname=hostname)
        except ssl.SSLCertVerificationError as exc:
            raise AssessmentError("tls_validation", "No se pudo validar el certificado TLS del hostname.") from exc
        except ssl.SSLError as exc:
            raise AssessmentError("tls_error", "Falló el handshake TLS.") from exc
        tls.settimeout(_remaining(deadline))
        request = (
            f"GET / HTTP/1.1\r\nHost: {hostname}\r\n"
            "User-Agent: defensive-security-agent/0.1.0\r\n"
            "Accept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
        ).encode("ascii")
        tls.sendall(request)
        status, headers, header_bytes = _read_response_headers(tls, deadline)
        return {
            "connected_ip": address,
            "tls": {"verified": True, "version": tls.version(), "cipher": tls.cipher()[0]},
            "status_code": status,
            "headers": headers,
            "header_bytes": header_bytes,
        }
    except AssessmentError:
        raise
    except (socket.timeout, TimeoutError) as exc:
        raise AssessmentError("timeout", "La evaluación superó el límite de tiempo disponible.") from exc
    except OSError as exc:
        raise AssessmentError("connection_error", "No se pudo completar la conexión HTTPS.") from exc
    finally:
        if tls is not None:
            tls.close()
        else:
            raw.close()


def _make_checks(headers: dict[str, list[str]], hostname: str, checked_at: datetime) -> tuple[list[dict], list[dict]]:
    checks, findings = [], []
    for check_index, (check_id, header, recommendation) in enumerate(_CHECKS):
        values = headers.get(header.lower(), [])
        if not values:
            state = "missing"
        elif len(values) > 1:
            state = "ambiguous"
        elif check_id == "content_type_options" and values[0].casefold() != "nosniff":
            state = "invalid"
        else:
            state = "present"
        check = {"id": check_id, "header": header, "state": state, "values": values}
        checks.append(check)
        if state != "present":
            finding_id = str(uuid4())
            check["finding_id"] = finding_id
            impact, precautions, pending_validation = _FINDING_GUIDANCE[check_id]
            if state == "missing":
                description = f"La respuesta HTTPS pública no incluyó el header {header}."
            elif state == "ambiguous":
                description = f"La respuesta HTTPS pública incluyó más de un valor para {header}."
            else:
                description = f"La respuesta HTTPS pública incluyó para {header} un valor distinto de `nosniff`."
            findings.append(Finding(
                id=finding_id,
                title=f"{header}: {state}",
                severity="info",
                asset=hostname,
                description=description,
                evidence=f"report.json#/checks/{check_index}",
                impact=impact,
                remediation=recommendation,
                detected_by="http_headers",
                timestamp=checked_at,
                iso27001_controls=[_CONTROL],
            ).model_dump(mode="json") | {
                "precautions": precautions,
                "pending_validation": pending_validation,
            })
    return checks, findings


def _report_markdown(report: dict) -> str:
    summary = report["executive_summary"]
    states = ", ".join(
        f"{state}: {count}" for state, count in summary["checks_by_state"].items() if count
    ) or "sin resultados"
    lines = [
        "# Evaluación web pública",
        "",
        f"- ID: `{report['run_id']}`",
        f"- Estado: **{report['status']}**",
        f"- Target: `{report['target']}`",
        f"- Perspectiva: {report['perspective']}",
        f"- Inicio (UTC): `{report['started_at']}`",
        f"- Fin (UTC): `{report['finished_at']}`",
        f"- Herramienta/reglas: `{report['tool']['version']}` / `{report['tool']['ruleset']}`",
        "",
        "## Resumen ejecutivo",
        "",
        f"**{summary['interpretation']}**",
        "",
        f"- Alcance: {summary['scope']}",
        f"- Checks: {summary['checks_completed']} de {summary['checks_planned']} completados ({states})",
        f"- Observaciones informativas: {summary['observations_count']}",
        "",
        "## Solicitud",
        "",
        "`GET https://<hostname>:443/`; sin redirects ni reintentos. El cuerpo no se persiste.",
        "",
    ]
    if report.get("response"):
        response = report["response"]
        if report.get("error"):
            lines.extend(["## Evaluación incompleta", "", report["error"]["message"], ""])
        lines.extend([
            "## Respuesta",
            "",
            f"- HTTP: `{response['status_code']}`",
            f"- IP de conexión (solo transporte): `{response['connected_ip']}`",
            f"- TLS verificado: `{response['tls']['version']}`",
            "",
            "## Checks",
            "",
            "| Header | Estado | Valor observado (allowlist) |",
            "|---|---|---|",
        ])
        for check in report["checks"]:
            values = ", ".join(check["values"]) if check["values"] else "—"
            safe = (values.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                    .replace("|", "&#124;").replace("`", "&#96;").replace("*", "&#42;")
                    .replace("[", "&#91;").replace("]", "&#93;").replace("\n", " "))
            lines.append(f"| {check['header']} | {check['state']} | {safe} |")
        lines.append("")
    else:
        lines.extend(["## Evaluación incompleta", "", f"{report['error']['message']}", ""])
    lines.extend(["## Hallazgos", ""])
    if report["findings"]:
        for finding in report["findings"]:
            lines.extend([
                f"### {finding['title']}",
                "",
                f"- Severidad: `{finding['severity']}` (observación informativa; no confirma una vulnerabilidad)",
                f"- Qué se observó: {finding['description']}",
                f"- Evidencia: `{finding['evidence']}`",
                f"- Impacto potencial: {finding['impact']}",
                f"- Recomendación: {finding['remediation']}",
                "- Precauciones:",
                *[f"  - {item}" for item in finding["precautions"]],
                "- Validaciones pendientes:",
                *[f"  - {item}" for item in finding["pending_validation"]],
                "",
            ])
    else:
        lines.extend(["No se generaron observaciones de hardening. Esto no significa que el sitio sea seguro.", ""])
    lines.extend([
        "## Referencia ISO (orientativa)",
        "",
        f"{_CONTROL} — requisitos de seguridad de aplicaciones. Su pertinencia para un requisito definido y la eficacia del control requieren revisión humana; este reporte no evalúa el SGSI ni afirma conformidad.",
        "",
        "## Contexto organizacional para completar",
        "",
        "Estos datos no se infieren de la evaluación. Deben ser definidos y revisados por la organización antes de usar el reporte como evidencia de auditoría.",
        "",
    ])
    fields = {
        "isms_scope": "Alcance del SGSI",
        "responsible_owner": "Responsable",
        "associated_requirement": "Requisito asociado",
        "treatment_decision": "Decisión de tratamiento",
    }
    for key, label in fields.items():
        value = report["audit_context"]["organizational_context"][key] or "No completado"
        lines.append(f"- {label}: {value}")
    lines.extend([
        "",
        "La aplicabilidad, el requisito, la decisión de tratamiento y la eficacia deben validarse por las personas responsables y, cuando corresponda, por el auditor.",
        "",
        "## Límites",
        "",
        "Una solicitud y la respuesta pública observada; GET podría producir efectos secundarios en una aplicación defectuosa. No se siguieron redirects, no se evaluó el cuerpo ni el origen, y no se probaron rutas adicionales.",
        "Una respuesta 2xx también podría ser un challenge de CDN; el cuerpo no se evaluó. Los artefactos locales no están firmados ni prueban cadena de custodia.",
        "",
    ])
    return "\n".join(lines)


def _write_artifacts(report: dict, evidence_dir: str | Path) -> Path:
    run_dir = Path(evidence_dir) / report["run_id"]
    run_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    os.chmod(run_dir, 0o700)
    for name, content in (
        ("report.json", json.dumps(report, ensure_ascii=True, indent=2) + "\n"),
        ("report.md", _report_markdown(report)),
    ):
        path = run_dir / name
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.chmod(path, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
    return run_dir


def assess_public_headers(hostname: str, evidence_dir: str | Path) -> tuple[dict, Path]:
    run_id = str(uuid4())
    started = datetime.now(timezone.utc)
    try:
        response = _request(hostname, time.monotonic() + _TIMEOUT_SECONDS)
        checks, findings = _make_checks(response.pop("headers"), hostname, datetime.now(timezone.utc))
        status_code = response["status_code"]
        if 200 <= status_code < 300:
            status, error = "complete", None
        elif 300 <= status_code < 400:
            status, error = "incomplete", {
                "category": "redirect_not_followed",
                "message": f"HTTP {status_code}: no se siguió el redirect; el destino no fue evaluado.",
            }
        else:
            status, error = "incomplete", {
                "category": "http_status",
                "message": f"HTTP {status_code}: la respuesta no se considera una evaluación completa.",
            }
    except AssessmentError as exc:
        logger.info("Evaluación incompleta (%s): %s", exc.category, exc.message)
        response, checks, findings = None, [], []
        status, error = "incomplete", {"category": exc.category, "message": exc.message}
    try:
        app_version = version("defensive-security-agent")
    except PackageNotFoundError:
        app_version = "unknown"
    finished = datetime.now(timezone.utc)
    report = {
        "schema_version": 2,
        "run_id": run_id,
        "status": status,
        "started_at": started.isoformat(),
        "finished_at": finished.isoformat(),
        "target": hostname,
        "perspective": "public_edge",
        "request": {"method": "GET", "scheme": "https", "port": 443, "path": "/", "redirects_followed": False, "retries": 0},
        "tool": {"name": "defensive-security-agent", "version": app_version, "ruleset": _RULESET_VERSION},
        "response": response,
        "checks": checks,
        "findings": findings,
        "error": error,
        "executive_summary": {
            "interpretation": (
                "Evaluación técnica completada; esto no significa que el sitio sea seguro."
                if status == "complete"
                else "Evaluación incompleta; no permite concluir que el sitio esté libre de problemas."
            ),
            "scope": f"Una respuesta HTTPS pública de {hostname} a GET /; sin body, origen ni rutas adicionales.",
            "checks_planned": len(_CHECKS),
            "checks_completed": len(checks),
            "checks_by_state": {
                state: sum(check["state"] == state for check in checks)
                for state in ("present", "missing", "ambiguous", "invalid")
            },
            "observations_count": len(findings),
        },
        "iso_reference": {
            "control": _CONTROL,
            "rationale": "La respuesta pública aporta una observación técnica que podría relacionarse con requisitos de seguridad de aplicaciones; la organización debe confirmar la pertinencia, el requisito aplicable y la eficacia del control.",
        },
        "audit_context": {
            "human_review_required": True,
            "review_note": "La pertinencia de la referencia ISO, el requisito y la eficacia del control requieren revisión humana. Este reporte no evalúa el SGSI ni afirma cumplimiento.",
            "organizational_context": {
                "isms_scope": None,
                "responsible_owner": None,
                "associated_requirement": None,
                "treatment_decision": None,
            },
        },
        "limitations": [
            "Una respuesta pública por hostname detrás de la infraestructura que lo sirve.",
            "No se siguieron redirects ni se evaluó el cuerpo, el origen o rutas adicionales.",
            "Headers presentes no implican políticas adecuadas; los faltantes son observaciones informativas, no vulnerabilidades confirmadas.",
            "Los artefactos locales no están firmados ni demuestran autenticidad o cadena de custodia.",
        ],
    }
    return report, _write_artifacts(report, evidence_dir)
