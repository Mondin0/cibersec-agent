from pathlib import Path
from ipaddress import ip_address
from tempfile import TemporaryDirectory
import unittest

from pydantic import ValidationError

from app.config import Config, ConfigError, ScopeConfig, load_config
from tests.support import DOMAIN, FIXTURE_PATH, FIXTURE_TEXT, IPV4, IPV6, SUBDOMAIN


EXAMPLE = Path(__file__).resolve().parents[1] / "config.example.yaml"


class ConfigTests(unittest.TestCase):
    def load_text(self, text: str) -> Config:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "config.yaml"
            path.write_text(text, encoding="utf-8")
            return load_config(path)

    def test_fixture_and_immutable_scope(self) -> None:
        config = load_config(FIXTURE_PATH)
        self.assertEqual(config.scope.domains, (DOMAIN, SUBDOMAIN))
        self.assertEqual(config.policy.max_requests_per_second, 5)
        with self.assertRaises(ValidationError):
            config.scope.domains = (f"other.{DOMAIN}",)

    def test_example_grants_no_permissions(self) -> None:
        self.assertEqual(load_config(EXAMPLE).scope, ScopeConfig())

    def test_normalization(self) -> None:
        scope = ScopeConfig(domains=[DOMAIN.upper()], ips=[ip_address(IPV6).exploded.upper()])
        self.assertEqual(scope.domains, (DOMAIN,))
        self.assertEqual(scope.ips, (IPV6,))

    def test_invalid_scope_entries(self) -> None:
        for values in (
            {"domains": [f"*.{DOMAIN}"]}, {"domains": [IPV4]},
            {"ips": [DOMAIN]}, {"ips": [f"{IPV4}/24"]},
            {"domains": DOMAIN}, {"domains": [1]},
            {"domains": [DOMAIN, DOMAIN.upper()]},
            {"ips": [IPV6, ip_address(IPV6).exploded]},
        ):
            with self.subTest(values=values), self.assertRaises(ValidationError):
                ScopeConfig(**values)

    def test_unsafe_or_ambiguous_config(self) -> None:
        example = FIXTURE_TEXT
        cases = [
            example.replace(f"{flag}: false", f"{flag}: true")
            for flag in ("destructive_tests", "brute_force", "dos")
        ]
        cases += [
            example.replace("max_requests_per_second: 5", f"max_requests_per_second: {value}")
            for value in ("0", "-1", "true", '"5"', ".nan", ".inf")
        ]
        cases += [
            example.replace("tls: true", 'tls: "true"'),
            example.replace("dos: false", "dos: 0"),
            example.replace("tls: true", "tls: true\n  tls: false"),
            example.replace("dos: false", "dos: false\n  unknown: false"),
            example.replace("scope:", "scope:\n  unknown: []"),
            example.replace("dos: false\n", ""),
            example.replace("nmap: false\n", ""),
            example + "unexpected: true\n",
            "", "[]", "scope: [", "!!python/object/apply:os.system ['whoami']",
            "scope: {}", "scope: {}\nscope: {}",
            "1: value", "? [a, b]\n: value", "scope: &scope {domains: [*scope]}",
        ]
        for text in cases:
            with self.subTest(text=text), self.assertRaises(ConfigError):
                self.load_text(text)

    def test_missing_file(self) -> None:
        with TemporaryDirectory() as directory, self.assertRaises(ConfigError):
            load_config(Path(directory) / "missing.yaml")

    def test_file_size_and_encoding(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "config.yaml"
            for content in (b"#" + b"a" * 65536, b"\xff"):
                with self.subTest(content_length=len(content)):
                    path.write_bytes(content)
                    with self.assertRaises(ConfigError):
                        load_config(path)

    def test_empty_scope_is_valid_but_does_not_grant_permissions(self) -> None:
        data = load_config(FIXTURE_PATH).model_dump()
        data["scope"] = {}
        self.assertEqual(Config.model_validate(data).scope, ScopeConfig())
