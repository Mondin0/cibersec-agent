import argparse
import logging
from pathlib import Path
import sys

from app.config import ConfigError, load_config
from app.scope import InvalidTarget, OutOfScope, validate_scope


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Consulta local de scope; no realiza escaneos.")
    commands = parser.add_subparsers(dest="command", required=True)
    scope_parser = commands.add_parser("scope", help="Consultar autorización de un hostname o IP")
    scope_parser.add_argument("target")
    scope_parser.add_argument("--config", type=Path, default=Path("config.yaml"))
    args = parser.parse_args(argv)

    try:
        config = load_config(args.config)
    except ConfigError as exc:
        print(f"CONFIGURACIÓN INVÁLIDA: {exc}", file=sys.stderr)
        return 2

    try:
        target = validate_scope(args.target, config.scope)
    except InvalidTarget as exc:
        print(f"ENTRADA INVÁLIDA: {args.target!r}. {exc}", file=sys.stderr)
        return 2
    except OutOfScope as exc:
        print(f"BLOQUEADO: {exc}", file=sys.stderr)
        return 1

    print(f"AUTORIZADO: {target}")
    print("Motivo: coincidencia exacta con una entrada del scope. No se realizó ningún escaneo.")
    return 0


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    raise SystemExit(main())
