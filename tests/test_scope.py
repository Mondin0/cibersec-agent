import unittest
from ipaddress import ip_address

from app.config import ScopeConfig
from app.scope import InvalidTarget, OutOfScope, validate_scope
from tests.support import DOMAIN, IPV4, IPV6, SUBDOMAIN


class ScopeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scope = ScopeConfig(
            domains=[DOMAIN, SUBDOMAIN],
            ips=[IPV4, IPV6],
        )

    def test_exact_domain_and_case(self) -> None:
        for target in (DOMAIN, DOMAIN.upper()):
            with self.subTest(target=target):
                self.assertEqual(validate_scope(target, self.scope), DOMAIN)

    def test_explicit_subdomain(self) -> None:
        self.assertEqual(
            validate_scope(SUBDOMAIN, self.scope),
            SUBDOMAIN,
        )

    def test_no_inherited_or_suffix_authorization(self) -> None:
        for target in (
            f"other.{DOMAIN}", f"www.{DOMAIN}", f"deep.{SUBDOMAIN}",
            f"{DOMAIN}.{DOMAIN}", f"not{DOMAIN}",
        ):
            with self.subTest(target=target), self.assertRaises(OutOfScope):
                validate_scope(target, self.scope)

    def test_authorized_ips_and_canonical_ipv6(self) -> None:
        self.assertEqual(validate_scope(IPV4, self.scope), IPV4)
        self.assertEqual(validate_scope(ip_address(IPV6).exploded.upper(), self.scope), IPV6)

    def test_ip_not_authorized_by_domain(self) -> None:
        for target in (str(ip_address(IPV4) + 1), str(ip_address(IPV6) + 1), f"::ffff:{IPV4}"):
            with self.subTest(target=target), self.assertRaises(OutOfScope):
                validate_scope(target, self.scope)

    def test_invalid_targets(self) -> None:
        for target in (
            "", f" {DOMAIN}", f"{DOMAIN} ",
            f"{DOMAIN}; whoami", "$(whoami)", "--script=all",
            f"{DOMAIN}\n", f"{DOMAIN}\x00",
            f"https://{DOMAIN}", f"{DOMAIN}:443",
            f"{DOMAIN}/path", f"user@{DOMAIN}",
            f"*.{DOMAIN}", f"{DOMAIN}.",
            "10.10.20.0/24", "010.10.20.15", "999.10.20.15", "2130706433",
            "0x7f000001", "127.1", "[::1]", "fe80::1%eth0",
            f"-bad.{DOMAIN}", f"bad_.{DOMAIN}", f"bad..{DOMAIN}",
            f"á{DOMAIN}", f"{'a' * 64}.{DOMAIN}", None, 123,
        ):
            with self.subTest(target=target), self.assertRaises(InvalidTarget):
                validate_scope(target, self.scope)

    def test_empty_scope_denies(self) -> None:
        with self.assertRaises(OutOfScope):
            validate_scope(DOMAIN, ScopeConfig())
