"""No stub answers another scenario's question, checked over whatever scenarios exist.

Eight scenarios share nine fixture files and the first matching stub wins in file order.
The entity rule makes a collision unlikely and nothing prevented one. Every stub names
the scenario it serves; here a probe is built from every alert present, its title, its
description, every string its evidence carries and its techniques, and put to every stub
that is not the alert's own. A stub that would answer is a collision.
"""

from collections.abc import Sequence

from alert_forensics.contracts import Alert
from alert_forensics.contracts._base import ContractModel, NonEmptyStr, StrictNonNegativeInt
from alert_forensics.evaluation.truth import Scenario
from alert_forensics.tools.fixtures import SHARED, TEST, FixtureSet, could_answer


class Collision(ContractModel):
    tool: NonEmptyStr
    stub: StrictNonNegativeInt
    """Index of the stub in its file."""
    label: NonEmptyStr
    """The scenario the stub says it serves."""
    scenario: NonEmptyStr
    """The scenario whose question it would answer."""


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


def fixture_collisions(fixture_set: FixtureSet, scenarios: Sequence[Scenario]) -> list[Collision]:
    """Every stub that would answer a question about a scenario it does not serve. A
    shared stub is exempt: it is exact, and its reading does not depend on who asks."""
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
    return found


def stale_labels(fixture_set: FixtureSet, scenarios: Sequence[Scenario]) -> list[str]:
    """Stubs whose label names no scenario present and is neither shared nor test."""
    present = {s.name for s in scenarios} | {SHARED, TEST}
    return [
        f"{tool} stub {index} is labelled {stub.scenario!r}, which names no scenario present"
        for tool in sorted(fixture_set.tools)
        for index, stub in enumerate(fixture_set.tools[tool].stubs)
        if stub.scenario not in present
    ]
