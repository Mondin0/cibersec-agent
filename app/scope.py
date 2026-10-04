import ipaddress
import logging
import re
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from app.config import ScopeConfig

logger = logging.getLogger(__name__)
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


class InvalidTarget(ValueError):
    pass


class OutOfScope(PermissionError):
    pass


def normalize_target(target: str) -> tuple[str, Literal["domain", "ip"]]:
    """Validate syntax without DNS, URL parsing or network access."""
    if not isinstance(target, str) or not target or len(target) > 253:
        raise InvalidTarget("El target debe ser un hostname ASCII o una IP individual.")
    if not target.isascii() or any(char.isspace() for char in target) or "%" in target:
        raise InvalidTarget("No se admiten espacios, Unicode ni zonas de interfaz.")
    try:
        return str(ipaddress.ip_address(target)), "ip"
    except ValueError:
        pass

    domain = target.lower()
    labels = domain.split(".")
    if (
        len(labels) < 2
        or not all(_LABEL.fullmatch(label) for label in labels)
        or not any(char.isalpha() for char in labels[-1])
    ):
        raise InvalidTarget("Hostname o IP inválido; no se admiten URLs, comandos ni rangos.")
    return domain, "domain"


def validate_scope(target: str, scope: "ScopeConfig") -> str:
    normalized, kind = normalize_target(target)
    allowed = scope.domains if kind == "domain" else scope.ips
    if normalized not in allowed:
        logger.info("Target fuera del scope: %r", normalized)
        raise OutOfScope(f"{normalized!r} no está incluido explícitamente en el scope.")
    return normalized
