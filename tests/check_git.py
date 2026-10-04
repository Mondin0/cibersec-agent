from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]


class GitBoundaryTests(unittest.TestCase):
    """Run explicitly on the host in a Git checkout, not inside the image."""

    def test_private_config_ignored_but_fixture_publishable(self) -> None:
        for path, expected_code in (("config.yaml", 0), ("tests/fixtures/config.yaml", 1)):
            with self.subTest(path=path):
                result = subprocess.run(
                    ["git", "check-ignore", "--no-index", "--quiet", path],
                    cwd=ROOT, capture_output=True, text=True, check=False, timeout=10,
                )
                self.assertEqual(result.returncode, expected_code, result.stderr)
