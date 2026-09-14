"""One run scored against its ground truth, deterministically and legibly."""

import json
from pathlib import Path

import pytest

from alert_forensics.agent import AnalystDecision, run_triage
from alert_forensics.agent.scripted import (
    ScriptedCall,
    ScriptedChatModel,
    StructuredTurn,
    ToolCallsTurn,
)
from alert_forensics.artifact import RunArtifact
from alert_forensics.contracts import Alert, RunOutcome, Verdict
from alert_forensics.evaluation import GroundTruth, contains_tokens, score_run
from alert_forensics.tools import (
    ANALYST_ROLE,
    DispositionAdapter,
    FixtureSet,
    InMemoryRawStore,
    Principal,
    fixture_adapters,
)
from conftest import ALERT_PAYLOAD, FIXTURE_TOOLS_DIR, T0

TRUTH = GroundTruth.model_validate(
    json.loads(Path("examples/atypical_travel.truth.json").read_text())
)


def call(id_, name, **args):
    return ScriptedCall(id=id_, name=name, args=args)


INVESTIGATION = ToolCallsTurn(
    tool_calls=[
        call(
            "tc-signins",
            "search_events",
            query="SigninLogs | where UserPrincipalName == 'jdoe@contoso.com'",
        ),
        call("tc-ioc", "lookup_ioc", indicator="203.0.113.7"),
        call("tc-runbook", "search_runbook", query="Atypical travel"),
    ]
)
PROPOSAL = ToolCallsTurn(
    tool_calls=[
        call(
            "tc-propose",
            "propose_alert_disposition",
            verdict="false_positive",
            recommended_action="Close.",
            escalate=False,
            summary="Gateway.",
        )
    ]
)

PARIS = "jdoe signed in from 203.0.113.7 in Paris, FR at 09:12."
AMSTERDAM = "jdoe signed in from 203.0.113.7 in Amsterdam, NL at 09:51."
SASE = "203.0.113.7 is owned by EXAMPLE-SASE-NET, the group SASE egress."


def result_turn(facts, *, verdict="false_positive", escalate=False, missing=()):
    return StructuredTurn(
        payload={
            "verdict": verdict,
            "confidence": 0.9,
            "mitre_techniques": [],
            "observed_facts": [{"statement": s, "evidence": e} for s, e in facts],
            "assumptions": [],
            "missing_context": [
                {"what": w, "why_it_matters": y, "how_to_obtain": h} for w, y, h in missing
            ],
            "recommended_action": "Close.",
            "escalate": escalate,
        }
    )


@pytest.fixture(scope="module")
def fixture_set():
    return FixtureSet.load(FIXTURE_TOOLS_DIR)


def run(script, fixture_set, max_corrections=1):
    model = ScriptedChatModel(
        script=script, profile={"structured_output": True}, model_id="scripted:test"
    )
    return run_triage(
        alert=Alert.model_validate(ALERT_PAYLOAD),
        model=model,
        model_id="scripted:test",
        principal=Principal(name="analyst", role=ANALYST_ROLE),
        adapters=[*fixture_adapters(fixture_set), DispositionAdapter(clock=lambda: T0)],
        store=InMemoryRawStore(),
        raw_store="mem",
        decide=lambda proposal: AnalystDecision(accept=True),
        investigation_id="inv-score",
        max_corrections=max_corrections,
        clock=lambda: T0,
    )


# --- token matching -------------------------------------------------------------------


def test_tokens_match_case_insensitively_on_normalised_whitespace():
    text = "IP  203.0.113.7\n belongs to EXAMPLE-SASE-NET"
    assert contains_tokens(text, ["ip", "203.0.113.7", "example-sase-net"]) == []
    assert contains_tokens(text, ["Belongs  To"]) == []
    assert contains_tokens("nothing here", ["SASE"]) == ["SASE"]


def test_a_token_matches_whole_words_never_inside_a_larger_word():
    # The case the rule was decided on: the owner name is not the word SASE.
    assert contains_tokens("belongs to EXAMPLE-SASE-NET", ["SASE"]) == ["SASE"]
    assert contains_tokens("belongs to (EXAMPLE-SASE-NET).", ["EXAMPLE-SASE-NET"]) == []
    # Punctuation inside a word is part of it; at its ends it is not.
    assert contains_tokens("from 203.0.113.7.", ["203.0.113"]) == ["203.0.113"]
    assert contains_tokens("from 203.0.113.7.", ["203.0.113.7"]) == []
    assert contains_tokens("in Paris, FR", ["paris"]) == []
    assert contains_tokens("technique T1078.004 applies", ["T1078"]) == ["T1078"]
    # A plural, a possessive and a compound are different words, listed as alternatives.
    assert contains_tokens("the session logs", ["log"]) == ["log"]
    assert contains_tokens("the session logs", [["log", "logs"]]) == []
    assert contains_tokens("the gateway's address", ["gateway"]) == ["gateway"]
    assert contains_tokens("the multi-factor prompt", ["factor"]) == ["factor"]
    # A multi-word token is a contiguous run of words.
    assert contains_tokens("device compliance was not checked", ["device compliance"]) == []
    assert contains_tokens("device was not in compliance", ["device compliance"]) == [
        "device compliance"
    ]


def test_an_alternatives_group_is_satisfied_by_any_one_and_reported_whole():
    assert contains_tokens("the VPN log", [["SASE", "VPN"], "log"]) == []
    assert contains_tokens("the gateway", [["SASE", "VPN"], "log"]) == [["SASE", "VPN"], "log"]


# --- a completed run --------------------------------------------------------------------


def test_a_correct_completed_run_scores_full_marks(fixture_set):
    facts = [(PARIS, ["tc-signins"]), (AMSTERDAM, ["tc-signins"]), (SASE, ["tc-ioc"])]
    missing = [
        ("SASE session log for jdoe", "Ties the user to the gateway.", "SASE provider audit."),
        ("MFA outcome of both sign-ins", "Shows the session was challenged.", "SigninLogs."),
    ]
    artifact = run([INVESTIGATION, PROPOSAL, result_turn(facts, missing=missing)], fixture_set)
    assert artifact.outcome is RunOutcome.completed
    score = score_run(artifact, TRUTH)
    assert score.scenario == "atypical_travel"
    assert score.outcome is RunOutcome.completed
    assert score.verdict_expected is Verdict.false_positive
    assert score.verdict_observed is Verdict.false_positive
    assert score.verdict_correct is True
    assert score.findings_reached == 3 and score.findings_required == 3
    assert [f.reached for f in score.findings] == [True, True, True]
    assert [f.fact_index for f in score.findings] == [0, 1, 2]
    assert score.context_named == 2 and score.context_expected == 2
    assert [c.entry_index for c in score.context] == [0, 1]
    assert score.escalate_expected is False and score.escalate_predicted is False
    assert score.escalation_correct is True
    assert score.total_facts == 3 and score.ungrounded_facts == 0
    assert score.error_kind is None


def test_a_finding_is_reached_through_any_of_its_tools(fixture_set):
    runbook_fact = "The runbook says 203.0.113.0/24 is the SASE gateway range."
    facts = [(runbook_fact, ["tc-runbook"])]
    score = score_run(run([INVESTIGATION, PROPOSAL, result_turn(facts)], fixture_set), TRUTH)
    sase = next(f for f in score.findings if f.name == "the_egress_address_is_the_sase_gateway")
    assert sase.reached and sase.fact_index == 0 and sase.cited_tool == "search_runbook"


def test_the_right_words_on_the_wrong_tool_do_not_count(fixture_set):
    # The Paris statement is right, but it cites VirusTotal, which never saw a sign-in.
    facts = [(PARIS, ["tc-ioc"])]
    score = score_run(run([INVESTIGATION, PROPOSAL, result_turn(facts)], fixture_set), TRUTH)
    paris = next(f for f in score.findings if f.name == "paris_sign_in_from_the_egress_address")
    assert paris.reached is False
    assert paris.candidates == 0
    assert paris.missed_tokens == ["203.0.113.7", "Paris"]


def test_a_miss_names_the_tokens_the_closest_candidate_lacked(fixture_set):
    facts = [("jdoe signed in from 203.0.113.7 twice.", ["tc-signins"])]
    score = score_run(run([INVESTIGATION, PROPOSAL, result_turn(facts)], fixture_set), TRUTH)
    paris = next(f for f in score.findings if f.name == "paris_sign_in_from_the_egress_address")
    assert paris.reached is False
    assert paris.candidates == 1
    assert paris.missed_tokens == ["Paris"]
    assert score.findings_reached == 0


def test_a_wrong_verdict_and_a_wrong_escalation_score_zero_on_those_alone(fixture_set):
    facts = [(PARIS, ["tc-signins"]), (AMSTERDAM, ["tc-signins"]), (SASE, ["tc-ioc"])]
    turn = result_turn(facts, verdict="benign_true_positive", escalate=True)
    score = score_run(run([INVESTIGATION, PROPOSAL, turn], fixture_set), TRUTH)
    assert score.verdict_correct is False
    assert score.verdict_observed is Verdict.benign_true_positive
    assert score.escalate_predicted is True and score.escalation_correct is False
    assert score.findings_reached == 3


def test_missing_context_matches_across_the_three_fields_joined(fixture_set):
    missing = [("The user's session", "Would tie the sign-ins to one device.", "VPN audit log.")]
    turn = result_turn([(PARIS, ["tc-signins"])], missing=missing)
    score = score_run(run([INVESTIGATION, PROPOSAL, turn], fixture_set), TRUTH)
    gateway = next(c for c in score.context if c.name == "gateway_session_log")
    assert gateway.named and gateway.entry_index == 0
    mfa = next(c for c in score.context if c.name == "mfa_or_device_compliance_outcome")
    assert mfa.named is False and mfa.entry_index is None
    assert score.context_named == 1


# --- failed runs ------------------------------------------------------------------------


def test_a_failed_error_run_scores_zero_on_everything_and_keeps_its_kind(fixture_set):
    artifact = run([INVESTIGATION], fixture_set)
    assert artifact.outcome is RunOutcome.failed_error
    score = score_run(artifact, TRUTH)
    assert score.verdict_correct is False and score.verdict_observed is None
    assert score.findings_reached == 0 and score.findings_required == 3
    assert all(not f.reached for f in score.findings)
    assert score.context_named == 0 and score.context_expected == 2
    assert score.escalate_predicted is None and score.escalation_correct is False
    assert score.total_facts == 0 and score.ungrounded_facts == 0
    assert score.error_kind == "ScriptExhaustedError"


def test_a_failed_ungrounded_run_scores_zero_even_where_its_words_were_right(fixture_set):
    facts = [(PARIS, ["tc-signins"]), (AMSTERDAM, ["tc-nope"])]
    script = [INVESTIGATION, PROPOSAL, result_turn(facts), StructuredTurn(payload={"repairs": []})]
    artifact = run(script, fixture_set)
    assert artifact.outcome is RunOutcome.failed_ungrounded
    score = score_run(artifact, TRUTH)
    assert score.verdict_correct is False
    assert score.verdict_observed is Verdict.false_positive
    assert score.findings_reached == 0
    assert score.escalation_correct is False and score.escalate_predicted is None
    assert score.total_facts == 2 and score.ungrounded_facts == 1
    assert score.error_kind is None


def test_a_truth_for_another_scenario_is_refused(fixture_set):
    artifact = run([INVESTIGATION, PROPOSAL, result_turn([(PARIS, ["tc-signins"])])], fixture_set)
    other = TRUTH.model_copy(update={"alert_id": "another"})
    with pytest.raises(ValueError, match="another"):
        score_run(artifact, other)


# --- the committed recording ----------------------------------------------------------


def test_the_recorded_real_run_scores_as_the_spec_says():
    artifact = RunArtifact.model_validate_json(Path("runs/atypical_travel/run.json").read_text())
    score = score_run(artifact, TRUTH)
    assert score.outcome is RunOutcome.completed
    assert score.verdict_correct is True
    assert score.findings_reached == 2 and score.findings_required == 3
    gateway = next(f for f in score.findings if f.name == "the_egress_address_is_the_sase_gateway")
    assert gateway.reached is False and gateway.candidates == 1
    # The fact named the ASN owner and never said what the address is.
    assert gateway.missed_tokens == ["SASE", ["gateway", "gateways", "egress", "proxy"]]
    assert score.context_named == 0 and score.context_expected == 2
    assert score.escalation_correct is True
    assert score.ungrounded_facts == 0
