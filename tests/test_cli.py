from contextlib import ExitStack, redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from app.main import main
from tests.support import DOMAIN, FIXTURE_PATH, FIXTURE_TEXT, IPV4


class CliTests(unittest.TestCase):
    def invoke(self, args: list[str]) -> tuple[int, str, str]:
        stdout, stderr = StringIO(), StringIO()
        with ExitStack() as stack:
            for function in (
                "socket.socket", "socket.getaddrinfo", "socket.gethostbyname",
                "socket.gethostbyname_ex", "socket.create_connection",
                "subprocess.Popen", "subprocess.run", "os.system", "os.popen",
            ):
                mock = stack.enter_context(patch(function, side_effect=AssertionError(function)))
                stack.callback(mock.assert_not_called)
            stack.enter_context(redirect_stdout(stdout))
            stack.enter_context(redirect_stderr(stderr))
            try:
                code = main(args)
            except SystemExit as exc:
                code = exc.code
        return code, stdout.getvalue(), stderr.getvalue()

    def scope(self, target: str) -> tuple[int, str, str]:
        return self.invoke(["scope", target, "--config", str(FIXTURE_PATH)])

    def test_authorized_without_network_or_processes(self) -> None:
        code, stdout, stderr = self.scope(DOMAIN.upper())
        self.assertEqual(code, 0)
        self.assertIn(f"AUTORIZADO: {DOMAIN}", stdout)
        self.assertEqual(stderr, "")

    def test_blocked_without_network_or_processes(self) -> None:
        code, stdout, stderr = self.scope(f"www.{DOMAIN}")
        self.assertEqual(code, 1)
        self.assertIn("BLOQUEADO", stderr)
        self.assertEqual(stdout, "")

    def test_invalid_target(self) -> None:
        for target in (f"{DOMAIN}; whoami", f"{DOMAIN}\n"):
            with self.subTest(target=target):
                code, stdout, stderr = self.scope(target)
                self.assertEqual(code, 2)
                self.assertIn("ENTRADA INVÁLIDA", stderr)
                self.assertEqual(stdout, "")
                self.assertNotIn(f"{DOMAIN}\n", stderr)

    def test_missing_or_invalid_config(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "config.yaml"
            for content in (None, "scope: [", FIXTURE_TEXT.replace("dos: false", "dos: true")):
                if content is not None:
                    path.write_text(content, encoding="utf-8")
                code, stdout, stderr = self.invoke([
                    "scope", DOMAIN, "--config", str(path),
                ])
                self.assertEqual(code, 2)
                self.assertIn("CONFIGURACIÓN INVÁLIDA", stderr)
                self.assertEqual(stdout, "")

    def test_default_config_is_not_example(self) -> None:
        from app.config import ConfigError
        with patch("app.main.load_config", side_effect=ConfigError("missing")) as loader:
            self.assertEqual(self.invoke(["scope", DOMAIN])[0], 2)
            loader.assert_called_once_with(Path("config.yaml"))

    def test_usage_errors(self) -> None:
        for args in ([], ["scope"], ["scan"]):
            with self.subTest(args=args):
                code, stdout, stderr = self.invoke(args)
                self.assertEqual(code, 2)
                self.assertEqual(stdout, "")
                self.assertTrue(stderr)

    def test_scan_authorizes_before_assessment(self) -> None:
        report = {"status": "complete", "run_id": "run-test"}
        with patch("app.main.assess_public_headers", return_value=(report, Path("evidence/run-test"))) as assess:
            code, stdout, stderr = self.invoke([
                "scan", DOMAIN, "--config", str(FIXTURE_PATH), "--evidence-dir", "evidence",
            ])
        self.assertEqual(code, 0)
        self.assertIn("EVALUACIÓN: complete", stdout)
        self.assertEqual(stderr, "")
        assess.assert_called_once_with(DOMAIN, Path("evidence"))

    def test_scan_rejects_ip_without_assessment(self) -> None:
        with patch("app.main.assess_public_headers") as assess:
            code, stdout, stderr = self.invoke([
                "scan", IPV4, "--config", str(FIXTURE_PATH),
            ])
        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertIn("requiere un hostname", stderr)
        assess.assert_not_called()

    def test_scan_rejects_out_of_scope_before_assessment(self) -> None:
        with patch("app.main.assess_public_headers") as assess:
            code, stdout, stderr = self.invoke([
                "scan", f"outside.{DOMAIN}", "--config", str(FIXTURE_PATH),
            ])
        self.assertEqual(code, 1)
        self.assertEqual(stdout, "")
        self.assertIn("BLOQUEADO", stderr)
        assess.assert_not_called()

    def test_scan_rejects_disabled_tool_before_assessment(self) -> None:
        with TemporaryDirectory() as directory:
            config = Path(directory) / "config.yaml"
            config.write_text(FIXTURE_TEXT.replace("http_headers: true", "http_headers: false"), encoding="utf-8")
            with patch("app.main.assess_public_headers") as assess:
                code, stdout, stderr = self.invoke(["scan", DOMAIN, "--config", str(config)])
        self.assertEqual(code, 1)
        self.assertEqual(stdout, "")
        self.assertIn("deshabilitada", stderr)
        assess.assert_not_called()

    def test_incomplete_scan_uses_exit_code_three(self) -> None:
        with patch("app.main.assess_public_headers", return_value=(
            {"status": "incomplete", "run_id": "run-test"}, Path("evidence/run-test"),
        )):
            code, stdout, stderr = self.invoke([
                "scan", DOMAIN, "--config", str(FIXTURE_PATH),
            ])
        self.assertEqual(code, 3)
        self.assertIn("EVALUACIÓN: incomplete", stdout)
        self.assertEqual(stderr, "")

    def test_help(self) -> None:
        code, stdout, stderr = self.invoke(["--help"])
        self.assertEqual(code, 0)
        self.assertIn("scope", stdout)
        self.assertEqual(stderr, "")
