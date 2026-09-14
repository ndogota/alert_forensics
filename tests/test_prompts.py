"""The system prompt defines the four verdicts by the discriminator, and names no alert."""

import re

from alert_forensics.agent.prompts import SYSTEM_PROMPT
from alert_forensics.contracts import Verdict


def test_the_prompt_defines_every_verdict_by_the_claim_discriminator():
    for verdict in Verdict:
        assert re.search(rf"^- {verdict.value}:", SYSTEM_PROMPT, re.MULTILINE), verdict
    flat = " ".join(SYSTEM_PROMPT.split())
    assert "whether the detection's claim about what happened is true" in flat
    assert "not whether the activity happened" in flat
    assert "is not the thing the rule named" in flat
    assert "legitimate and authorised" in flat
    assert "missing context names what would" in flat.split("- inconclusive:")[1]


def test_the_prompt_carries_the_taxonomy_and_not_the_answer_to_any_scenario():
    scenario_words = (
        "SASE", "gateway", "proxy", "Paris", "Amsterdam", "travel",
        "spray", "MFA", "forwarding", "IBAN", "invoice",
        "PowerShell", "maintenance", "LSASS", "red team",
        "Kerberoast", "SPN", "scanner", "RMM", "mshta", "VirusTotal",
        "resigned", "photo", "cloud storage",
    )  # fmt: skip
    lowered = SYSTEM_PROMPT.lower()
    leaked = [w for w in scenario_words if w.lower() in lowered]
    assert leaked == [], leaked
