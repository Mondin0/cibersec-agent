from pathlib import Path

import yaml

# Expected targets come from raw YAML, not the normalization under test.
FIXTURE_PATH = Path(__file__).parent / "fixtures" / "config.yaml"
FIXTURE_TEXT = FIXTURE_PATH.read_text(encoding="utf-8")
_DATA = yaml.safe_load(FIXTURE_TEXT)
DOMAIN, SUBDOMAIN = _DATA["scope"]["domains"]
IPV4, IPV6 = _DATA["scope"]["ips"]
