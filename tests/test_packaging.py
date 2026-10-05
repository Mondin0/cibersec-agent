import ast
from pathlib import Path
import unittest

import yaml

from tests.support import DOMAIN, IPV4, IPV6, SUBDOMAIN

ROOT = Path(__file__).resolve().parents[1]


class PackagingTests(unittest.TestCase):
    def test_fixture_targets_are_not_hardcoded_in_python(self) -> None:
        for directory in (ROOT / "app", ROOT / "tests"):
            for path in directory.rglob("*.py"):
                source = path.read_text(encoding="utf-8")
                for target in (DOMAIN, SUBDOMAIN, IPV4, IPV6):
                    with self.subTest(path=path, target=target):
                        self.assertNotIn(target, source)

    def test_compose_preserves_read_only_boundary_and_enables_public_scans(self) -> None:
        agent = yaml.safe_load((ROOT / "docker-compose.yml").read_text())["services"]["agent"]
        self.assertEqual(agent["network_mode"], "bridge")
        self.assertEqual(agent["user"], "${APP_UID:-10001}:${APP_GID:-10001}")
        self.assertTrue(agent["read_only"])
        self.assertEqual(agent["cap_drop"], ["ALL"])
        self.assertIn("no-new-privileges:true", agent["security_opt"])
        self.assertNotIn("ports", agent)
        self.assertFalse(agent.get("privileged", False))
        config_mount, evidence_mount = agent["volumes"]
        self.assertEqual(config_mount["source"], "./config.yaml")
        self.assertEqual(config_mount["target"], "/app/config.yaml")
        self.assertTrue(config_mount["read_only"])
        self.assertFalse(config_mount["bind"]["create_host_path"])
        self.assertEqual(evidence_mount["source"], "./evidence")
        self.assertEqual(evidence_mount["target"], "/evidence")
        self.assertFalse(evidence_mount.get("read_only", False))
        self.assertFalse(evidence_mount["bind"]["create_host_path"])

    def test_dockerfile_nonroot_and_fixed_entrypoint(self) -> None:
        lines = (ROOT / "Dockerfile").read_text().splitlines()
        self.assertIn("USER 10001:10001", lines)
        entrypoint, = [line for line in lines if line.startswith("ENTRYPOINT ")]
        self.assertEqual(ast.literal_eval(entrypoint.removeprefix("ENTRYPOINT ")), ["python", "-m", "app.main"])
        self.assertTrue(lines[0].startswith("FROM python:3.12-slim-bookworm@sha256:"))

    def test_build_context_is_allowlisted(self) -> None:
        patterns = (ROOT / ".dockerignore").read_text().splitlines()
        patterns = [line for line in patterns if line and not line.startswith("#")]
        self.assertEqual(patterns[0], "*")
        self.assertEqual(
            {line for line in patterns if line.startswith("!")},
            {"!Dockerfile", "!docker-compose.yml", "!.dockerignore", "!pyproject.toml", "!requirements.lock", "!config.example.yaml",
             "!app/", "!app/**", "!tests/", "!tests/**"},
        )
