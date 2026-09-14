"""The console script: ``alert-forensics triage``, ``show`` and ``replay``."""

import argparse
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from pydantic import JsonValue, ValidationError

from alert_forensics.agent import AnalystDecision, ScriptedChatModel, demo_script, run_triage
from alert_forensics.artifact import RunArtifact
from alert_forensics.contracts import Alert, RunOutcome
from alert_forensics.fixtures import ATTACK_EXCERPT, DEFAULT_FIXTURES_DIR
from alert_forensics.tools import (
    ROLES,
    DirectoryRawStore,
    DispositionAdapter,
    FixtureSet,
    Principal,
    RawIntegrityError,
    fixture_adapters,
)
from alert_forensics.tools.live.attack import AttackStixAdapter
from alert_forensics.tools.runner import AnyAdapter

SCRIPTED_MODEL_ID = "scripted:demo"
EXIT_OK, EXIT_FAILED_RUN, EXIT_USAGE = 0, 1, 2


class CliError(Exception):
    """A usage or configuration problem, reported on stderr before anything runs."""


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "triage":
            return _triage(args)
        if args.command == "replay":
            return _replay(args)
        return _show(args)
    except CliError as exc:
        print(f"alert-forensics: {exc}", file=sys.stderr)
        return EXIT_USAGE


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="alert-forensics",
        description="Triage a SOC alert with grounded claims, or show a run artifact.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    triage = commands.add_parser("triage", help="investigate one Graph security.alert v2 export")
    triage.add_argument("alert", type=Path, help="path to the alert JSON")
    triage.add_argument("--model", help="provider:name through init_chat_model")
    triage.add_argument(
        "--scripted",
        action="store_true",
        help="run on the scripted client with a built-in script; no key, no network",
    )
    triage.add_argument("--role", choices=sorted(ROLES), default="analyst")
    triage.add_argument("-o", "--output", type=Path, default=Path("run.json"))
    triage.add_argument("--max-corrections", type=int, default=1)
    triage.add_argument("--fixtures", type=Path, default=DEFAULT_FIXTURES_DIR)
    triage.add_argument("--recursion-limit", type=int, default=50)
    decision = triage.add_mutually_exclusive_group()
    decision.add_argument("--accept", action="store_true", help="accept the proposal")
    decision.add_argument("--reject", metavar="REASON", help="reject the proposal with a reason")

    show = commands.add_parser("show", help="print a run artifact readably")
    show.add_argument("run", type=Path, help="path to the run artifact JSON")

    replay = commands.add_parser(
        "replay", help="verify a recorded run against its raw store and print it"
    )
    replay.add_argument("run", type=Path, help="path to the recorded run artifact JSON")
    return parser


# --- triage ------------------------------------------------------------------------


def _triage(args: argparse.Namespace) -> int:
    alert = _load_alert(args.alert)
    role = ROLES[args.role]
    decide = _decider(args)
    if args.scripted:
        model_id = SCRIPTED_MODEL_ID
        model: Any = ScriptedChatModel(
            script=demo_script(alert), profile={"structured_output": True}, model_id=model_id
        )
    else:
        if not args.model:
            raise CliError("pass --model provider:name, or --scripted to run without a model")
        model_id = args.model
        model = _init_model(model_id)
    adapters = default_adapters(args.fixtures, scripted=args.scripted)
    output: Path = args.output
    raw_dir = output.with_name(f"{output.stem}.raw")
    artifact = run_triage(
        alert=alert,
        model=model,
        model_id=model_id,
        principal=Principal(name=role.name, role=role),
        adapters=adapters,
        store=DirectoryRawStore(raw_dir),
        raw_store=raw_dir.name,
        decide=decide,
        max_corrections=args.max_corrections,
        recursion_limit=args.recursion_limit,
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(artifact.model_dump_json(indent=2), encoding="utf-8")
    verdict = artifact.result.verdict.value if artifact.result else "none"
    print(f"{artifact.outcome.value}  verdict: {verdict}  artifact: {output}  raw: {raw_dir}")
    if artifact.error is not None:
        print(f"error: {artifact.error.kind}: {artifact.error.message}")
    return EXIT_OK if artifact.outcome is RunOutcome.completed else EXIT_FAILED_RUN


def _load_alert(path: Path) -> Alert:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise CliError(f"cannot read {path}: {exc.strerror}") from exc
    except ValueError as exc:
        raise CliError(f"{path} is not JSON: {exc}") from exc
    try:
        return Alert.model_validate(payload)
    except ValidationError as exc:
        raise CliError(f"{path} is not a Graph security.alert v2 object: {exc}") from exc


def _init_model(model_id: str) -> Any:
    from langchain.chat_models import init_chat_model

    try:
        return init_chat_model(model_id)
    except ImportError as exc:
        raise CliError(
            f"the provider for {model_id!r} is not installed: {exc}. Install the extra, "
            "for example alert-forensics[anthropic]"
        ) from exc
    except ValueError as exc:
        raise CliError(f"cannot initialise {model_id!r}: {exc}") from exc


def default_adapters(fixtures_dir: Path, *, scripted: bool) -> list[AnyAdapter]:
    """The adapter set a CLI run uses.

    ``get_attack_technique`` is live in every mode, with the packaged excerpt as the
    offline fallback: it needs no key, so a fixture there would be a gap. ``lookup_ioc``
    is live only with a key and never under ``--scripted``. The proposal is local.
    """
    try:
        fixture_set = FixtureSet.load(fixtures_dir)
    except (OSError, ValueError) as exc:
        raise CliError(f"cannot load fixtures from {fixtures_dir}: {exc}") from exc
    adapters: dict[str, AnyAdapter] = {a.definition.name: a for a in fixture_adapters(fixture_set)}
    adapters["get_attack_technique"] = AttackStixAdapter(fallback_bundle_path=ATTACK_EXCERPT)
    api_key = os.environ.get("VIRUSTOTAL_API_KEY")
    if api_key and not scripted:
        from alert_forensics.tools.live.virustotal import VirusTotalAdapter

        adapters["lookup_ioc"] = VirusTotalAdapter(api_key)
    adapters["propose_alert_disposition"] = DispositionAdapter()
    return list(adapters.values())


def _decider(args: argparse.Namespace) -> Any:
    if args.accept:
        return lambda proposal: AnalystDecision(accept=True)
    if args.reject is not None:
        reason = str(args.reject)
        return lambda proposal: AnalystDecision(accept=False, reason=reason)
    if not sys.stdin.isatty():
        raise CliError(
            "the proposal needs an analyst's decision and there is no terminal: pass --accept "
            "or --reject REASON"
        )
    return _ask_on_terminal


def _ask_on_terminal(proposal: dict[str, JsonValue]) -> AnalystDecision:
    print("\nThe agent proposes a disposition. Nothing has been written.")
    for key in ("verdict", "recommended_action", "escalate", "summary"):
        if key in proposal:
            print(f"  {key}: {proposal[key]}")
    while True:
        answer = input("Accept this proposal? [a]ccept / [r]eject: ").strip().lower()
        if answer in {"a", "accept"}:
            return AnalystDecision(accept=True)
        if answer in {"r", "reject"}:
            reason = input("Reason (optional): ").strip() or None
            return AnalystDecision(accept=False, reason=reason)


# --- show and replay ---------------------------------------------------------------


def _load_artifact(path: Path) -> RunArtifact:
    try:
        return RunArtifact.model_validate_json(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise CliError(f"cannot read {path}: {exc.strerror}") from exc
    except ValidationError as exc:
        raise CliError(f"{path} is not a run artifact: {exc}") from exc


def _show(args: argparse.Namespace) -> int:
    print(render(_load_artifact(args.run)))
    return EXIT_OK


def _replay(args: argparse.Namespace) -> int:
    """A recording is replayed only after its raw store verifies against the recorded
    hashes: a tampered artifact is detected, not printed as if it were the run."""
    path: Path = args.run
    artifact = _load_artifact(path)
    raw_dir = path.parent / artifact.raw_store
    if not raw_dir.is_dir():
        raise CliError(f"the raw store {raw_dir} is missing; the recording cannot be verified")
    store = DirectoryRawStore(raw_dir)
    for record in artifact.trace.records:
        try:
            store.get(record.raw_response_ref, expected_sha256=record.raw_response_sha256)
        except KeyError as exc:
            raise CliError(f"raw response {record.raw_response_ref} is missing") from exc
        except RawIntegrityError as exc:
            raise CliError(str(exc)) from exc
    date = artifact.trace.started_at.astimezone().strftime("%Y-%m-%d %H:%M %Z")
    print(f"Recording of a run by {artifact.model} on {date}.")
    if artifact.model.startswith(SCRIPTED_MODEL_ID.split(":")[0] + ":"):
        print("This run used the scripted client: it is a plumbing check, not a model run.")
    print(f"{len(artifact.trace.records)} raw responses verified against the recorded hashes.")
    print()
    print(render(artifact))
    return EXIT_OK


def render(artifact: RunArtifact) -> str:
    lines: list[str] = []
    alert = artifact.trace.alert
    lines.append(
        f"Run {artifact.investigation_id}  outcome: {artifact.outcome.value}  "
        f"model: {artifact.model}  role: {artifact.role}  passes: {artifact.passes}"
    )
    lines.append(f"Alert: {alert.title} ({alert.id})  severity: {alert.severity.value}")
    records = artifact.trace.records
    by_outcome = {
        o: sum(1 for r in records if r.outcome is o) for o in {r.outcome for r in records}
    }
    counts = ", ".join(f"{n} {o.value}" for o, n in sorted(by_outcome.items(), key=lambda x: x[0]))
    lines.append(f"Tool calls: {len(records)}" + (f" ({counts})" if counts else ""))
    if artifact.error is not None:
        lines.append(f"Error: {artifact.error.kind}: {artifact.error.message}")
    report = artifact.report
    if report is None:
        return "\n".join(lines)
    result = report.result
    lines.append(
        f"Verdict: {result.verdict.value}  confidence: {result.confidence:.2f}  "
        f"escalate: {'yes' if result.escalate else 'no'}"
    )
    if result.mitre_techniques:
        lines.append("Techniques: " + ", ".join(result.mitre_techniques))
    lines.append(f"Observed facts ({report.grounded_count} grounded of {report.total_facts}):")
    for fact in report.facts:
        mark = "" if fact.grounded else "  [UNGROUNDED]"
        lines.append(f"  {fact.index + 1}. {fact.statement}{mark}")
        for evidence_id in fact.evidence_ids:
            record = artifact.trace.find(evidence_id)
            if record is None:
                lines.append(f"     evidence: {evidence_id} (no such call)")
            else:
                lines.append(
                    f"     evidence: {evidence_id} ({record.tool_name}, "
                    f"{record.source_system.value}, {record.outcome.value})"
                )
        for problem in fact.problems:
            lines.append(f"     problem: {problem.kind} on {problem.evidence_id}: {problem.detail}")
    lines.append("Assumptions:" if result.assumptions else "Assumptions: none")
    for assumption in result.assumptions:
        lines.append(f"  - {assumption.statement}")
        lines.append(f"    why unverified: {assumption.why_unverified}")
    lines.append("Missing context:" if result.missing_context else "Missing context: none")
    for missing in result.missing_context:
        lines.append(f"  - {missing.what}")
        lines.append(f"    why it matters: {missing.why_it_matters}")
        lines.append(f"    how to obtain: {missing.how_to_obtain}")
    lines.append(f"Recommended action: {result.recommended_action}")
    lines.append("Human decisions:" if artifact.decisions else "Human decisions: none")
    for decision in artifact.decisions:
        proposal = decision.proposal
        reason = f" ({decision.reason})" if decision.reason else ""
        lines.append(
            f"  - {decision.decision.value}{reason}: proposed {proposal.get('verdict')}, "
            f"{proposal.get('recommended_action')}"
        )
    if artifact.corrections:
        for n, correction in enumerate(artifact.corrections, start=1):
            lines.append(
                f"Correction {n}: {len(correction.instruction.offending)} offending citation(s), "
                f"{len(correction.repairs.repairs)} repair(s) returned"
            )
    return "\n".join(lines)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
