"""No stub answers another scenario's question, checked over whatever scenarios exist.

Eight scenarios share nine fixture files and the first matching stub wins in file order.
The entity rule makes a collision unlikely and nothing prevented one. Every stub names
the scenario it serves; here two probes are put to every stub that is not the
scenario's own, and a stub that would answer is a collision.

The alert probe is built from every alert present: its title, its description, every
string its evidence carries and its techniques. It holds that no stub answers a
question made of another alert's entities. It cannot hold that no stub answers a
question a model would ask, because no alert carries a model's words: the collision
that created the rule came from the question "VPN SASE corporate egress proxy Amsterdam
Paris", and a stub keyed on those words passes the alert probe.

The recording probe is the nearest thing to that corpus: every request every committed
recording under ``runs/<scenario>/<recording>/`` actually made, put to every stub that
does not serve that recording's scenario, as it was sent, through the matcher the
adapter uses. It grows with every recording.
"""

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Literal

from pydantic import JsonValue, ValidationError

from alert_forensics.artifact import RunArtifact
from alert_forensics.contracts import Alert
from alert_forensics.contracts._base import ContractModel, NonEmptyStr, StrictNonNegativeInt
from alert_forensics.evaluation.truth import Scenario
from alert_forensics.tools.fixtures import MANIFEST, SHARED, FixtureSet, could_answer, matches

RUN_FILE = "run.json"


class Collision(ContractModel):
    tool: NonEmptyStr
    stub: StrictNonNegativeInt
    """Index of the stub in its file."""
    label: NonEmptyStr
    """The scenario the stub says it serves."""
    scenario: NonEmptyStr
    """The scenario whose question it would answer."""
    probe: Literal["alert", "recording"] = "alert"
    """Where the question came from: the alert's own text, or a request a committed
    recording of the scenario actually made."""


class RecordedRequest(ContractModel):
    """One request a committed recording made, with the scenario it was a run of."""

    scenario: NonEmptyStr
    recording: NonEmptyStr
    """The artifact the request was read from."""
    tool: NonEmptyStr
    arguments: dict[str, JsonValue]


def probe(alert: Alert) -> list[str]:
    """What a question about this alert may carry: the whole text first, so an operator
    matcher sees everything at once, then every part on its own, so an exact value is
    tried entity by entity."""
    parts: list[str] = [alert.title, alert.description or "", *alert.mitre_techniques]
    _strings(alert.to_wire().get("evidence", []), parts)
    parts = [p for p in dict.fromkeys(parts) if p]
    return [" ".join(parts), *parts]


def _strings(value: object, into: list[str]) -> None:
    if isinstance(value, str):
        into.append(value)
    elif isinstance(value, dict):
        for item in value.values():
            _strings(item, into)
    elif isinstance(value, list):
        for item in value:
            _strings(item, into)


def recorded_requests(runs_dir: Path, scenarios: Sequence[Scenario]) -> list[RecordedRequest]:
    """Every request of every recording under ``runs_dir/<scenario>/<recording>/run.json``,
    in trace order. The scenario directory names the scenario; a name no scenario
    present carries, or a recording of another scenario's alert, cannot be attributed
    and is refused rather than skipped, since a request that is put to nothing checks
    nothing."""
    by_name = {s.name: s for s in scenarios}
    requests: list[RecordedRequest] = []
    for path in sorted(runs_dir.glob(f"*/*/{RUN_FILE}")):
        name = path.parent.parent.name
        scenario = by_name.get(name)
        if scenario is None:
            raise ValueError(
                f"the recording under {path.parent} is of scenario {name!r}, which names "
                "no scenario present; its requests cannot be attributed"
            )
        try:
            artifact = RunArtifact.model_validate_json(path.read_text(encoding="utf-8"))
        except (OSError, ValidationError, ValueError) as exc:
            raise ValueError(f"the recording under {path.parent} cannot be read: {exc}") from exc
        if artifact.trace.alert.id != scenario.alert.id:
            raise ValueError(
                f"the recording under {path.parent} is a run of alert "
                f"{artifact.trace.alert.id!r}, and scenario {name!r} is alert "
                f"{scenario.alert.id!r}"
            )
        requests.extend(
            RecordedRequest(
                scenario=name,
                recording=str(path),
                tool=record.tool_name,
                arguments=dict(record.arguments),
            )
            for record in artifact.trace.records
        )
    return requests


def fixture_collisions(
    fixture_set: FixtureSet,
    scenarios: Sequence[Scenario],
    requests: Sequence[RecordedRequest] = (),
) -> list[Collision]:
    """Every stub that would answer a question about a scenario it does not serve: one
    built from another alert's text, or one a committed recording of another scenario
    actually asked. A shared stub is exempt: it is exact, and its reading does not
    depend on who asks."""
    found: list[Collision] = []
    probes = {s.name: probe(s.alert) for s in scenarios}
    for tool in sorted(fixture_set.tools):
        for index, stub in enumerate(fixture_set.tools[tool].stubs):
            if stub.scenario == SHARED:
                continue
            for name, candidates in probes.items():
                if name != stub.scenario and could_answer(stub.match, candidates):
                    found.append(
                        Collision(tool=tool, stub=index, label=stub.scenario, scenario=name)
                    )
            asked: set[str] = set()
            for request in requests:
                if request.tool != tool or request.scenario == stub.scenario:
                    continue
                if not matches(stub.match, request.arguments):
                    continue
                key = json.dumps(
                    [request.scenario, request.arguments], sort_keys=True, ensure_ascii=False
                )
                if key in asked:
                    continue
                asked.add(key)
                found.append(
                    Collision(
                        tool=tool,
                        stub=index,
                        label=stub.scenario,
                        scenario=request.scenario,
                        probe="recording",
                    )
                )
    return found


def stale_labels(fixture_set: FixtureSet, scenarios: Sequence[Scenario]) -> list[str]:
    """Manifest entries that name no scenario present, or name it by another alert's
    id. A stub's label is held to the manifest by the loader; the manifest is held to
    the scenarios here."""
    present = {s.name: s.alert.id for s in scenarios}
    stale = []
    for label, alert_id in sorted(fixture_set.scenarios.items()):
        if label not in present:
            stale.append(f"{MANIFEST} names scenario {label!r}, which is not present")
        elif present[label] != alert_id:
            stale.append(
                f"{MANIFEST} names scenario {label!r} as alert {alert_id!r}; the scenario "
                f"present is alert {present[label]!r}"
            )
    return stale
