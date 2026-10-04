import unittest
from unittest.mock import patch

from app.config import load_config
from app.policy import ActionDenied, authorize_action
from app.scope import InvalidTarget, OutOfScope
from tests.support import DOMAIN, FIXTURE_PATH


class PolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = load_config(FIXTURE_PATH)

    def test_enabled_action(self) -> None:
        for action in ("http_headers", "tls"):
            self.assertEqual(
                authorize_action(action, DOMAIN.upper(), self.config),
                DOMAIN,
            )

    def test_disabled_or_unknown_action(self) -> None:
        for action in ("nmap", "nuclei", "shell", "brute_force", "__dict__", "tls; whoami"):
            with self.subTest(action=action), self.assertRaises(ActionDenied):
                authorize_action(action, DOMAIN, self.config)

    def test_out_of_scope_blocks_every_known_action(self) -> None:
        for action in ("http_headers", "tls", "nmap", "nuclei"):
            with self.subTest(action=action), self.assertRaises(OutOfScope):
                authorize_action(action, f"other.{DOMAIN}", self.config)

    def test_invalid_target_is_blocked(self) -> None:
        with self.assertRaises(InvalidTarget):
            authorize_action("tls", f"{DOMAIN}; whoami", self.config)

    def test_policy_uses_central_scope_validation(self) -> None:
        with patch("app.policy.validate_scope", side_effect=OutOfScope("blocked")) as validator:
            with self.assertRaises(OutOfScope):
                authorize_action("tls", DOMAIN, self.config)
            validator.assert_called_once_with(DOMAIN, self.config.scope)
