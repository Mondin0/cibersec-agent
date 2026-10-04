import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest


class ContainerBoundaryTests(unittest.TestCase):
    """Run explicitly inside Compose, not in the host's default test discovery."""

    def test_nonroot_without_capabilities_or_escalation(self) -> None:
        self.assertEqual(os.getuid(), 10001)
        self.assertEqual(os.getgid(), 10001)
        status = dict(
            line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines()
        )
        self.assertEqual(int(status["CapEff"].strip(), 16), 0)
        self.assertEqual(status["NoNewPrivs"].strip(), "1")

    def test_network_has_only_loopback(self) -> None:
        self.assertEqual({path.name for path in Path("/sys/class/net").iterdir()}, {"lo"})

    def test_filesystem_and_configuration_are_read_only(self) -> None:
        for path in ("/app", "/app/config.yaml"):
            with self.subTest(path=path):
                self.assertTrue(os.statvfs(path).f_flag & os.ST_RDONLY)

    def test_temporary_storage_is_writable(self) -> None:
        with TemporaryDirectory(dir="/tmp") as directory:
            path = Path(directory) / "check"
            path.write_text("ok")
            self.assertEqual(path.read_text(), "ok")
