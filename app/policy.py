import logging

from app.config import Config
from app.scope import validate_scope

_ACTIONS = frozenset({"http_headers", "tls", "nmap", "nuclei"})
logger = logging.getLogger(__name__)


class ActionDenied(PermissionError):
    pass


def authorize_action(action: str, target: str, config: Config) -> str:
    """Authorize only; this function does not execute a tool."""
    normalized = validate_scope(target, config.scope)
    if not isinstance(action, str) or action not in _ACTIONS:
        raise ActionDenied("Acción desconocida; solo se admiten comprobaciones predefinidas.")
    if not getattr(config.tools, action):
        raise ActionDenied(f"La herramienta {action!r} está deshabilitada.")
    logger.info("Acción autorizada: %s, target: %s", action, normalized)
    return normalized
