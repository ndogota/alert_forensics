"""The system prompt defines the four verdicts by the discriminator, and names no alert."""

import re

from alert_forensics.agent.prompts import SYSTEM_PROMPT
from alert_forensics.contracts import Verdict


def test_the_prompt_defines_every_verdict_by_the_claim_discriminator():
    for verdict in Verdict:
        assert re.search(rf"^- {verdict.value}:", SYSTEM_PROMPT, re.MULTILINE), verdict
    flat = " ".join(SYSTEM_PROMPT.split())
    assert "a signal, which is what its logic measured" in flat
    assert "an assertion, which is what it claims about the world" in flat
    assert "The verdict turns on the assertion, never on the signal" in flat
    assert "The signal may be perfectly real and still support no such conclusion" in flat
    assert "legitimate and authorised" in flat
    assert "missing_context names what would" in flat.split("- inconclusive:")[1]
    assert "What the SOC should do belongs in recommended_action" in flat


def test_the_prompt_judges_truth_and_never_prescribes_tuning():
    """A verdict states what is true; the action lives in recommended_action. A rule
    that fires on a departing employee pushing 6.2 GB to personal storage is doing its
    job even when the folder is photographs, and a definition that said "tune" could
    not say so."""
    assert re.search(r"\btun(e|ed|ing)\b", SYSTEM_PROMPT, re.IGNORECASE) is None
    assert re.search(r"\bexception\b", SYSTEM_PROMPT, re.IGNORECASE) is None


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
