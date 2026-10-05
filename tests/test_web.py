from datetime import datetime
import json
import os
from pathlib import Path
import socket
import ssl
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from app.web import AssessmentError, _make_checks, _read_response_headers, _request, assess_public_headers
from app.web import _tls_client_context
from tests.support import DOMAIN, SUBDOMAIN


FIXTURES = Path(__file__).parent / "fixtures"
CERT = FIXTURES / "tls_test_cert.pem"
KEY = FIXTURES / "tls_test_key.pem"
PUBLIC_TEST_IP = "1.1.1.1"  # Mocked DNS answer; the test redirects connect() to its loopback server.


class WebAssessmentTests(unittest.TestCase):
    def test_non_public_dns_answer_blocks_socket_creation(self) -> None:
        records = [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (PUBLIC_TEST_IP, 443)),
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 443)),
        ]
        with patch("app.web.socket.getaddrinfo", return_value=records), \
             patch("app.web.socket.socket", side_effect=AssertionError("socket opened")):
            with self.assertRaisesRegex(AssessmentError, "no enrutable"):
                _request(DOMAIN, time.monotonic() + 2)

    def test_tls_context_ignores_ssl_keylog_environment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            keylog = Path(directory) / "keys.log"
            with patch.dict(os.environ, {"SSLKEYLOGFILE": str(keylog)}):
                context = _tls_client_context()
            self.assertTrue(context.check_hostname)
            self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
            self.assertIsNone(context.keylog_filename)
            self.assertFalse(keylog.exists())

    def test_tls_request_is_pinned_and_reports_only_allowlisted_headers(self) -> None:
        response = (
            b"HTTP/1.1 302 Found\r\n"
            b"Location: https://elsewhere.test/path?token=private\r\n"
            b"Set-Cookie: session=private\r\n"
            b"Strict-Transport-Security: max-age=31536000\r\n"
            b"Content-Security-Policy: default-src 'self'\r\n"
            b"X-Content-Type-Options: nosniff\r\n"
            b"X-Private: private-header\r\n\r\nprivate-body-marker"
        )
        result, requested, sni, failures = self._assess_via_test_server(response, trusted=True)
        self.assertEqual(failures, [])
        self.assertEqual(len(requested), 1)
        self.assertEqual(requested[0], (PUBLIC_TEST_IP, 443))
        self.assertEqual(sni, [DOMAIN])
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["error"]["category"], "redirect_not_followed")
        self.assertIn("no se siguió el redirect", result["markdown_text"])
        self.assertEqual(result["response"]["status_code"], 302)
        self.assertEqual(result["response"]["connected_ip"], PUBLIC_TEST_IP)
        self.assertEqual({check["header"].lower() for check in result["checks"] if check["values"]}, {
            "strict-transport-security", "content-security-policy", "x-content-type-options",
        })
        self.assertEqual(result["request"]["redirects_followed"], False)
        self.assertEqual(result["request"]["retries"], 0)
        self.assertEqual(len(result["requests"]), 1)
        sent = result["requests"][0]
        self.assertTrue(sent.startswith(f"GET / HTTP/1.1\r\nHost: {DOMAIN}\r\n"))
        self.assertNotIn("Cookie:", sent)
        artifact_text = result["artifact_text"]
        self.assertNotIn("private-body-marker", artifact_text)
        self.assertNotIn("session=private", artifact_text)
        self.assertNotIn("token=private", artifact_text)
        self.assertNotIn("private-header", artifact_text)
        self.assertEqual(result["file_mode"], 0o600)
        report = result["saved_report"]
        self.assertEqual(report["findings"][0]["evidence"], "report.json#/checks/2")

    def test_untrusted_certificate_creates_incomplete_report_without_retry(self) -> None:
        response = b"HTTP/1.1 200 OK\r\n\r\n"
        result, requested, sni, failures = self._assess_via_test_server(response, trusted=False)
        self.assertEqual(len(requested), 1)
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["error"]["category"], "tls_validation")
        self.assertIsNone(result["response"])
        self.assertEqual(result["checks"], [])

    def test_certificate_hostname_mismatch_is_rejected(self) -> None:
        result, requested, _, _ = self._assess_via_test_server(
            b"HTTP/1.1 200 OK\r\n\r\n", trusted=True, hostname=SUBDOMAIN,
        )
        self.assertEqual(len(requested), 1)
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["error"]["category"], "tls_validation")

    def test_access_denied_response_is_not_a_clean_assessment(self) -> None:
        result, _, _, _ = self._assess_via_test_server(b"HTTP/1.1 403 Forbidden\r\n\r\n", trusted=True)
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["error"]["category"], "http_status")
        self.assertIn("HTTP 403", result["error"]["message"])

    def test_response_timeout_is_incomplete(self) -> None:
        result, requested, _, _ = self._assess_via_test_server(
            b"HTTP/1.1 200 OK\r\n\r\n", trusted=True, delay=0.1, timeout=0.02,
        )
        self.assertEqual(len(requested), 1)
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["error"]["category"], "timeout")

    def test_dns_timeout_is_incomplete_and_bounded(self) -> None:
        def slow_resolution(*args, **kwargs):
            time.sleep(0.1)
            return []

        with tempfile.TemporaryDirectory() as directory, \
             patch("app.web._TIMEOUT_SECONDS", 0.01), \
             patch("app.web.socket.getaddrinfo", side_effect=slow_resolution):
            started = time.monotonic()
            report, run_dir = assess_public_headers(DOMAIN, directory)
            elapsed = time.monotonic() - started
            self.assertTrue((run_dir / "report.json").exists())
            self.assertTrue((run_dir / "report.md").exists())
            markdown = (run_dir / "report.md").read_text(encoding="utf-8")
        self.assertLess(elapsed, 0.08)
        self.assertEqual(report["status"], "incomplete")
        self.assertEqual(report["error"]["category"], "timeout")
        self.assertEqual(report["executive_summary"]["checks_planned"], 6)
        self.assertEqual(report["executive_summary"]["checks_completed"], 0)
        self.assertIn("Evaluación incompleta", markdown)

    def test_header_limit_is_enforced(self) -> None:
        class FakeSocket:
            def __init__(self, data: bytes):
                self.data = data

            def settimeout(self, value: float) -> None:
                pass

            def recv(self, size: int) -> bytes:
                chunk, self.data = self.data[:size], self.data[size:]
                return chunk

        data = b"HTTP/1.1 200 OK\r\nX: " + b"a" * 100 + b"\r\n\r\n"
        with patch("app.web._MAX_HEADER_BYTES", 64):
            with self.assertRaisesRegex(AssessmentError, "64 KiB"):
                _read_response_headers(FakeSocket(data), time.monotonic() + 1)

    def test_provisional_http_response_is_not_mistaken_for_final(self) -> None:
        class FakeSocket:
            def settimeout(self, value: float) -> None:
                pass

            def recv(self, size: int) -> bytes:
                return b"HTTP/1.1 103 Early Hints\r\n\r\n"

        with self.assertRaisesRegex(AssessmentError, "provisional"):
            _read_response_headers(FakeSocket(), time.monotonic() + 1)

    def test_duplicate_or_invalid_headers_are_observations(self) -> None:
        checks, findings = _make_checks(
            {"x-content-type-options": ["nosniff", "wrong"]}, DOMAIN, datetime.now().astimezone()
        )
        self.assertEqual(checks[-1]["state"], "ambiguous")
        self.assertEqual(len(findings), 6)
        self.assertTrue(all(finding["severity"] == "info" for finding in findings))
        self.assertTrue(all(finding["precautions"] and finding["pending_validation"] for finding in findings))

    def test_runs_are_unique_and_json_is_source_of_markdown(self) -> None:
        def empty_response(hostname, deadline):
            return {"connected_ip": PUBLIC_TEST_IP, "tls": {"verified": True, "version": "TLSv1.3", "cipher": "test"},
                    "status_code": 200, "headers": {}, "header_bytes": 20}

        with tempfile.TemporaryDirectory() as directory, patch("app.web._request", side_effect=empty_response):
            first, first_dir = assess_public_headers(DOMAIN, directory)
            first_artifacts = {
                name: (first_dir / name).read_bytes() for name in ("report.json", "report.md")
            }
            second, second_dir = assess_public_headers(DOMAIN, directory)
            self.assertNotEqual(first["run_id"], second["run_id"])
            self.assertNotEqual(first_dir, second_dir)
            self.assertEqual(
                first_artifacts,
                {name: (first_dir / name).read_bytes() for name in first_artifacts},
            )
            for report, run_dir in ((first, first_dir), (second, second_dir)):
                saved = json.loads((run_dir / "report.json").read_text(encoding="utf-8"))
                self.assertEqual(saved, report)
                self.assertEqual(saved["schema_version"], 2)
                summary = saved["executive_summary"]
                self.assertEqual(summary["checks_planned"], 6)
                self.assertEqual(summary["checks_completed"], 6)
                self.assertEqual(summary["observations_count"], len(saved["findings"]))
                self.assertEqual(sum(summary["checks_by_state"].values()), summary["checks_completed"])
                self.assertIn("no significa que el sitio sea seguro", summary["interpretation"])
                audit = saved["audit_context"]
                self.assertTrue(audit["human_review_required"])
                self.assertIn("afirma cumplimiento", audit["review_note"])
                self.assertEqual(set(audit["organizational_context"].values()), {None})
                markdown = (run_dir / "report.md").read_text(encoding="utf-8")
                for check in report["checks"]:
                    self.assertIn(check["header"], markdown)
                self.assertIn("Resumen ejecutivo", markdown)
                self.assertIn("revisión humana", markdown)
                self.assertIn("Contexto organizacional para completar", markdown)
                self.assertIn("Observaciones informativas: 6", markdown)
                self.assertIn("afirma conformidad", markdown)
                self.assertIn("Alcance del SGSI: No completado", markdown)
                self.assertIn("Responsable: No completado", markdown)
                self.assertIn("Requisito asociado: No completado", markdown)
                self.assertIn("Decisión de tratamiento: No completado", markdown)
                for finding in report["findings"]:
                    check_index = int(finding["evidence"].rsplit("/", 1)[1])
                    linked_check = report["checks"][check_index]
                    self.assertEqual(linked_check["finding_id"], finding["id"])
                    self.assertIn(finding["description"], markdown)
                    self.assertIn(finding["impact"], markdown)
                    self.assertIn(finding["remediation"], markdown)
                    for item in finding["precautions"] + finding["pending_validation"]:
                        self.assertIn(item, markdown)
                self.assertEqual(os.stat(run_dir).st_mode & 0o777, 0o700)

    def _assess_via_test_server(
        self, response: bytes, trusted: bool, delay: float = 0, timeout: float = 15,
        hostname: str = DOMAIN,
    ) -> tuple[dict, list, list, list]:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        requests, requested, observed_sni, failures = [], [], [], []
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(CERT, KEY)
        server_context.set_servername_callback(lambda sock, name, context: observed_sni.append(name))

        def serve() -> None:
            try:
                connection, _ = listener.accept()
                with server_context.wrap_socket(connection, server_side=True) as tls:
                    request = bytearray()
                    while b"\r\n\r\n" not in request:
                        request.extend(tls.recv(1024))
                    requests.append(bytes(request).decode("ascii"))
                    time.sleep(delay)
                    tls.sendall(response)
            except (OSError, ssl.SSLError) as exc:
                failures.append(exc)
            finally:
                listener.close()

        server = threading.Thread(target=serve, daemon=True)
        server.start()
        original_connect = socket.socket.connect

        def redirect_to_local(sock, address):
            requested.append(address)
            if address == (PUBLIC_TEST_IP, 443):
                return original_connect(sock, ("127.0.0.1", port))
            return original_connect(sock, address)

        records = [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (PUBLIC_TEST_IP, 443))]
        client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        client_context.check_hostname = True
        client_context.verify_mode = ssl.CERT_REQUIRED
        if trusted:
            client_context.load_verify_locations(cafile=str(CERT))
        else:
            client_context.load_default_certs()
        with tempfile.TemporaryDirectory() as directory, \
             patch("app.web.socket.getaddrinfo", return_value=records) as resolver, \
             patch("socket.socket.connect", new=redirect_to_local), \
             patch("app.web._tls_client_context", return_value=client_context), \
             patch("app.web._TIMEOUT_SECONDS", timeout):
            report, run_dir = assess_public_headers(hostname, directory)
            server.join(timeout=2)
            self.assertFalse(server.is_alive())
            artifact_text = (run_dir / "report.json").read_text(encoding="utf-8")
            markdown_text = (run_dir / "report.md").read_text(encoding="utf-8")
            saved_report = json.loads(artifact_text)
            file_mode = os.stat(run_dir / "report.json").st_mode & 0o777
        resolver.assert_called_once_with(hostname + ".", 443, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
        return {
            **report,
            "requests": requests,
            "artifact_text": artifact_text,
            "markdown_text": markdown_text,
            "saved_report": saved_report,
            "file_mode": file_mode,
        }, requested, observed_sni, failures


if __name__ == "__main__":
    unittest.main()
