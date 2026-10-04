from pathlib import Path
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator, model_validator
import yaml
from yaml.nodes import MappingNode

from app.scope import normalize_target


class ConfigError(ValueError):
    pass


class _ConfigModel(BaseModel):
    model_config = ConfigDict(
        strict=True, extra="forbid", frozen=True, revalidate_instances="always"
    )


class ScopeConfig(_ConfigModel):
    domains: tuple[str, ...] = ()
    ips: tuple[str, ...] = ()

    @field_validator("domains", "ips", mode="before")
    @classmethod
    def yaml_lists_to_tuples(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @field_validator("domains", "ips")
    @classmethod
    def normalize_entries(cls, entries: tuple[str, ...], info: ValidationInfo) -> tuple[str, ...]:
        expected_kind = "domain" if info.field_name == "domains" else "ip"
        normalized = []
        for entry in entries:
            target, kind = normalize_target(entry)
            if kind != expected_kind:
                raise ValueError(f"{entry!r} no corresponde a {info.field_name}.")
            normalized.append(target)
        if len(set(normalized)) != len(normalized):
            raise ValueError("El scope contiene entradas duplicadas tras normalizar.")
        return tuple(normalized)


class PolicyConfig(_ConfigModel):
    max_requests_per_second: float = Field(gt=0, allow_inf_nan=False)
    destructive_tests: bool
    brute_force: bool
    dos: bool

    @model_validator(mode="after")
    def reject_unsafe_policy(self) -> Self:
        if self.destructive_tests or self.brute_force or self.dos:
            raise ValueError("No se permiten pruebas destructivas, brute force ni DoS.")
        return self


class ToolsConfig(_ConfigModel):
    http_headers: bool
    tls: bool
    nmap: bool
    nuclei: bool


class Config(_ConfigModel):
    scope: ScopeConfig
    policy: PolicyConfig
    tools: ToolsConfig


class _UniqueKeySafeLoader(yaml.SafeLoader):
    """Reject ambiguous overrides instead of silently using the last YAML key."""

    def construct_mapping(self, node: MappingNode, deep: bool = False) -> dict[str, Any]:
        self.flatten_mapping(node)
        keys = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str):
                raise yaml.YAMLError("Las claves de configuración deben ser strings.")
            if key in keys:
                raise yaml.YAMLError(f"Clave YAML duplicada: {key!r}.")
            keys.add(key)
        return super().construct_mapping(node, deep=deep)


def load_config(path: str | Path) -> Config:
    try:
        with Path(path).open("rb") as file:
            content = file.read(65537)
        if len(content) > 65536:
            raise ConfigError("La configuración supera el límite de 64 KiB.")
        data = yaml.load(content.decode("utf-8"), Loader=_UniqueKeySafeLoader)
        return Config.model_validate(data)
    except (OSError, UnicodeError, yaml.YAMLError, RecursionError, ValueError) as exc:
        raise ConfigError(f"Configuración inválida ({path}): {exc}") from exc
