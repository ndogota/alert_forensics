"""Ground truth as a contract: one file per scenario, beside its alert.

``examples/<scenario>.alert.json`` and ``examples/<scenario>.truth.json`` share the stem,
and the stem is the scenario's name everywhere. The loader checks the pairing rather
than assuming it: a truth whose ``scenario`` or ``alert_id`` disagrees with the file it
sits beside refuses to load.
"""

import json
import re
from pathlib import Path
from typing import Annotated

from pydantic import AfterValidator, Field, ValidationError, field_validator, model_validator

from alert_forensics.contracts import Alert, Verdict
from alert_forensics.contracts._base import ContractModel, NonEmptyStr
from alert_forensics.grounding import NON_EVIDENCE_SYSTEMS
from alert_forensics.tools.definitions import DEFINITIONS

Token = NonEmptyStr | Annotated[list[NonEmptyStr], Field(min_length=1)]
"""A string the text must contain as whole words, or a list of alternatives of which one
must appear."""

_EDGE_PUNCTUATION = re.compile(r"^\W+|\W+$")


def words(text: str) -> list[str]:
    """The words of ``text`` as the matcher reads them: split on whitespace, the
    punctuation at each word's ends stripped, casefolded. Punctuation inside a word is
    part of it, so ``203.0.113.7`` and ``EXAMPLE-SASE-NET`` are one word each."""
    stripped = (_EDGE_PUNCTUATION.sub("", raw) for raw in text.casefold().split())
    return [word for word in stripped if word]


def _holds_a_word(tokens: list[Token]) -> list[Token]:
    for token in tokens:
        for alternative in [token] if isinstance(token, str) else token:
            if not words(alternative):
                raise ValueError(f"token {alternative!r} holds no word and could never match")
    return tokens


Tokens = Annotated[list[Token], Field(min_length=1), AfterValidator(_holds_a_word)]

ALERT_SUFFIX = ".alert.json"
TRUTH_SUFFIX = ".truth.json"

EVIDENCE_TOOLS: frozenset[str] = frozenset(
    name for name, d in DEFINITIONS.items() if d.source_system not in NON_EVIDENCE_SYSTEMS
)
"""Tools whose records can carry a finding: every tool that reads a system."""


class GroundTruthError(ValueError):
    """A scenario that cannot be loaded: a missing or mismatched truth file."""


class RequiredFinding(ContractModel):
    """A finding an investigation must reach, matched by tool and by tokens."""

    name: NonEmptyStr
    tools: Annotated[list[NonEmptyStr], Field(min_length=1)]
    """The fact must cite a successful call to one of these. One entry is the common
    case; several mean the same fact can be established from more than one system."""
    tokens: Tokens
    """Every token must appear in the fact's statement, as whole words, case-insensitively."""

    @field_validator("tools")
    @classmethod
    def _registered_evidence_tools(cls, tools: list[str]) -> list[str]:
        for tool in tools:
            if tool not in DEFINITIONS:
                raise ValueError(f"{tool!r} is not a tool")
            if tool not in EVIDENCE_TOOLS:
                raise ValueError(f"{tool!r} reads no system; its record is never evidence")
        if len(set(tools)) != len(tools):
            raise ValueError("a tool is listed twice")
        return tools


class ExpectedContext(ContractModel):
    """Missing context an investigation should name, matched on tokens alone."""

    name: NonEmptyStr
    tokens: Tokens


class GroundTruth(ContractModel):
    scenario: NonEmptyStr
    alert_id: NonEmptyStr
    verdict: Verdict
    escalate: bool
    required_findings: list[RequiredFinding] = Field(default_factory=list)
    missing_context: list[ExpectedContext] = Field(default_factory=list)

    @model_validator(mode="after")
    def _unique_names(self) -> "GroundTruth":
        for label, items in (
            ("finding", self.required_findings),
            ("missing-context", self.missing_context),
        ):
            names = [item.name for item in items]
            if len(set(names)) != len(names):
                raise ValueError(f"duplicate {label} name")
        return self


class Scenario(ContractModel):
    name: NonEmptyStr
    alert: Alert
    truth: GroundTruth


def scenario_name(path: Path) -> str:
    """The stem shared by an alert file and its truth file."""
    for suffix in (ALERT_SUFFIX, TRUTH_SUFFIX):
        if path.name.endswith(suffix):
            return path.name.removesuffix(suffix)
    raise GroundTruthError(f"{path} is neither *{ALERT_SUFFIX} nor *{TRUTH_SUFFIX}")


def load_scenario(alert_path: Path) -> Scenario:
    name = scenario_name(alert_path)
    truth_path = alert_path.with_name(f"{name}{TRUTH_SUFFIX}")
    alert = Alert.model_validate(_read_json(alert_path))
    if not truth_path.is_file():
        raise GroundTruthError(
            f"{alert_path} has no ground truth beside it: {truth_path} is missing"
        )
    try:
        truth = GroundTruth.model_validate(_read_json(truth_path))
    except ValidationError as exc:
        raise GroundTruthError(f"{truth_path} is not a GroundTruth: {exc}") from exc
    if truth.scenario != name:
        raise GroundTruthError(
            f"{truth_path} names scenario {truth.scenario!r} but its file stem is {name!r}"
        )
    if truth.alert_id != alert.id:
        raise GroundTruthError(
            f"{truth_path} is the truth for alert {truth.alert_id!r} but sits beside "
            f"alert {alert.id!r}"
        )
    return Scenario(name=name, alert=alert, truth=truth)


def load_scenarios(directory: Path, only: str | None = None) -> list[Scenario]:
    """Every alert-and-truth pair under ``directory``, by name; ``only`` narrows to one."""
    scenarios = [load_scenario(path) for path in sorted(directory.glob(f"*{ALERT_SUFFIX}"))]
    if not scenarios:
        raise GroundTruthError(f"no scenario under {directory}: no *{ALERT_SUFFIX} file")
    if only is None:
        return scenarios
    chosen = [s for s in scenarios if s.name == only]
    if not chosen:
        names = ", ".join(s.name for s in scenarios)
        raise GroundTruthError(f"no scenario named {only!r} under {directory}; there are: {names}")
    return chosen


def _read_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise GroundTruthError(f"cannot read {path}: {exc.strerror}") from exc
    except ValueError as exc:
        raise GroundTruthError(f"{path} is not JSON: {exc}") from exc
