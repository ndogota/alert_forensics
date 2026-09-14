"""Live adapters. Two ship: VirusTotal and the ATT&CK bundle. Both take an injected
``httpx.Client`` so the test suite can drive them through recorded responses."""

from alert_forensics.tools.live.attack import ATTACK_BUNDLE_URL, AttackStixAdapter
from alert_forensics.tools.live.virustotal import VT_BASE_URL, VirusTotalAdapter

__all__ = ["ATTACK_BUNDLE_URL", "VT_BASE_URL", "AttackStixAdapter", "VirusTotalAdapter"]
