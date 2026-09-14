"""The fixture set that ships with the package, so an installed tool runs without the
repository. One JSON file per fixture-backed tool, validated on load by ``FixtureSet``."""

from pathlib import Path

DEFAULT_FIXTURES_DIR = Path(__file__).parent / "tools"
"""The nine read-only tools' fixtures. ``propose_alert_disposition`` has none: it is local."""

__all__ = ["DEFAULT_FIXTURES_DIR"]
