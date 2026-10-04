import unittest

from pydantic import ValidationError

from app.models import Finding
from tests.support import DOMAIN


class FindingTests(unittest.TestCase):
    def data(self) -> dict[str, str]:
        return {
            "id": "finding-1", "title": "Example", "severity": "info",
            "asset": DOMAIN, "description": "Example finding",
            "evidence": "scan-id/http_headers.json", "impact": "To be reviewed",
            "remediation": "Review configuration",
        }

    def test_defaults_and_json_round_trip(self) -> None:
        finding = Finding(**self.data())
        self.assertEqual(finding.status, "open")
        self.assertIsNone(finding.cvss)
        self.assertEqual(finding.iso27001_controls, [])
        self.assertIsNotNone(finding.timestamp.tzinfo)
        self.assertEqual(Finding.model_validate_json(finding.model_dump_json()), finding)

    def test_severity_status_and_cvss_constraints(self) -> None:
        for extra in (
            {"severity": "urgent"}, {"status": "unknown"}, {"cvss": -0.1},
            {"cvss": 10.1}, {"cvss": float("nan")}, {"cvss": float("inf")},
            {"cvss": True}, {"id": ""}, {"timestamp": "2026-10-04T12:00:00"},
        ):
            with self.subTest(extra=extra), self.assertRaises(ValidationError):
                Finding(**(self.data() | extra))
        for cvss in (0.0, 10.0):
            self.assertEqual(Finding(**self.data(), cvss=cvss).cvss, cvss)

    def test_lists_are_independent_and_assignment_validated(self) -> None:
        first = Finding(**self.data())
        second = Finding(**self.data())
        first.iso27001_controls.append("ISO/IEC 27001:2022 A.8.8")
        self.assertEqual(second.iso27001_controls, [])
        with self.assertRaises(ValidationError):
            first.status = "invalid"
