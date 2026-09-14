"""The fixture set that ships with the package, so an installed tool runs without the
repository. One JSON file per fixture-backed tool, validated on load by ``FixtureSet``."""

from pathlib import Path

DEFAULT_FIXTURES_DIR = Path(__file__).parent / "tools"
"""The nine read-only tools' fixtures. ``propose_alert_disposition`` has none: it is local."""

ATTACK_EXCERPT = Path(__file__).parent / "attack" / "enterprise-attack.excerpt.json"
"""An excerpt of the real ATT&CK enterprise bundle: the offline fallback for the live
adapter, holding every technique the eight scenarios declare. Provenance in
``tests/recorded/README.md``."""

__all__ = ["ATTACK_EXCERPT", "DEFAULT_FIXTURES_DIR"]
