import argparse
import logging
from pathlib import Path
import sys

from app.config import ConfigError, load_config
from app.policy import ActionDenied, authorize_action
from app.scope import InvalidTarget, OutOfScope, normalize_target, validate_scope
from app.web import assess_public_headers


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Consulta local de scope y evaluación web pública puntual.")
    commands = parser.add_subparsers(dest="command", required=True)
    scope_parser = commands.add_parser("scope", help="Consultar autorización de un hostname o IP")
    scope_parser.add_argument("target")
    scope_parser.add_argument("--config", type=Path, default=Path("config.yaml"))
    scan_parser = commands.add_parser("scan", help="Evaluar headers de una web pública autorizada")
    scan_parser.add_argument("target", help="Hostname explícitamente incluido en scope.domains")
    scan_parser.add_argument("--config", type=Path, default=Path("config.yaml"))
    scan_parser.add_argument("--evidence-dir", type=Path, default=Path("evidence"))
    args = parser.parse_args(argv)

    try:
        config = load_config(args.config)
    except ConfigError as exc:
        print(f"CONFIGURACIÓN INVÁLIDA: {exc}", file=sys.stderr)
        return 2

    if args.command == "scope":
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

    try:
        _, kind = normalize_target(args.target)
        if kind != "domain":
            raise InvalidTarget("scan requiere un hostname; las IPs directas no están admitidas.")
        target = authorize_action("http_headers", args.target, config)
    except InvalidTarget as exc:
        print(f"ENTRADA INVÁLIDA: {args.target!r}. {exc}", file=sys.stderr)
        return 2
    except (OutOfScope, ActionDenied) as exc:
        print(f"BLOQUEADO: {exc}", file=sys.stderr)
        return 1

    try:
        report, run_dir = assess_public_headers(target, args.evidence_dir)
    except (OSError, ValueError) as exc:
        print(f"ERROR DE EVIDENCIA: no se pudieron escribir los reportes: {exc}", file=sys.stderr)
        return 2
    print(f"EVALUACIÓN: {report['status']}")
    print(f"ID: {report['run_id']}")
    print(f"REPORTES: {run_dir / 'report.json'} y {run_dir / 'report.md'}")
    return 0 if report["status"] == "complete" else 3


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    raise SystemExit(main())
