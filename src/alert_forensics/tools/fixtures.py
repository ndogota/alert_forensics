"""Fixture adapters: frozen responses matched against the request.

One JSON file per tool, ``<tool>.json``::

    {"tool": "lookup_ioc",
     "stubs": [{"match": {"indicator": "203.0.113.7"}, "response": {...}},
               {"match": {"indicator": {"$regex": "^10\\\\."}},
                "error": {"kind": "upstream_error", "detail": "..."}}]}

Stubs are tried in file order and the first match wins. A match value is compared for
equality, or is an operator object: ``{"$contains": "text"}``, ``{"$regex": "..."}``,
``{"$any": true}``, or ``{"$all": [operator, ...]}``, every one of which must hold. A
request no stub answers is a ``no_fixture`` error, never a silent empty result. There
is no default: a default cannot tell a reading nobody has seen from a query nobody
anticipated, and a stub must constrain at least one argument for the same reason. A
real empty reading is a stub whose match names the request it answers.

A stub on a free-text request, a hunting query, an SPL search, a runbook question,
answers only questions about the entities its response holds: the match names the
account, device or subject the rows are about, and not only the table. That rule the
loader cannot hold, since it cannot read what a query is about; the shipped fixtures
are held to it by tests.
"""

import copy
import json
import re
from pathlib import Path
from typing import Any

from pydantic import Field, JsonValue, ValidationError, field_validator, model_validator

from alert_forensics.contracts._base import ContractModel, NonEmptyStr
from alert_forensics.tools.adapter import (
    FailureKind,
    ToolAdapter,
    ToolDefinition,
    ToolRequest,
    UpstreamError,
)
from alert_forensics.tools.definitions import DEFINITIONS


class FixtureError(ContractModel):
    kind: FailureKind
    detail: NonEmptyStr


class FixtureStub(ContractModel):
    match: dict[str, JsonValue]
    response: JsonValue = None
    error: FixtureError | None = None

    @field_validator("match")
    @classmethod
    def _constrains_an_argument(cls, match: dict[str, JsonValue]) -> dict[str, JsonValue]:
        """A stub that would answer every request is a default under another name."""
        if not any(not _is_any(spec) for spec in match.values()):
            raise ValueError("a stub must constrain at least one argument")
        return match

    @model_validator(mode="after")
    def _response_xor_error(self) -> "FixtureStub":
        has_response = "response" in self.model_fields_set
        has_error = self.error is not None
        if has_response == has_error:
            raise ValueError("a stub carries exactly one of response or error")
        return self


class ToolFixture(ContractModel):
    """A fixture file. A ``default`` key is a field nobody declared and refuses to load."""

    tool: NonEmptyStr
    stubs: list[FixtureStub] = Field(default_factory=list)


class FixtureSet:
    """Every tool fixture found in a directory, validated on load."""

    def __init__(self, tools: dict[str, ToolFixture]) -> None:
        self.tools = tools

    @classmethod
    def load(cls, directory: Path) -> "FixtureSet":
        tools: dict[str, ToolFixture] = {}
        for path in sorted(directory.glob("*.json")):
            try:
                fixture = ToolFixture.model_validate(json.loads(path.read_text(encoding="utf-8")))
            except (ValidationError, ValueError) as exc:
                raise ValueError(f"fixture file {path.name} is invalid: {exc}") from exc
            if fixture.tool not in DEFINITIONS:
                raise ValueError(f"fixture file {path.name} names unknown tool {fixture.tool!r}")
            if fixture.tool != path.stem:
                raise ValueError(
                    f"fixture file {path.name} declares tool {fixture.tool!r}; the file must "
                    "be named after its tool"
                )
            tools[fixture.tool] = fixture
        return cls(tools)

    def for_tool(self, name: str) -> ToolFixture:
        return self.tools[name]


def _is_any(spec: JsonValue) -> bool:
    """Whether a matcher would accept every value: ``$any``, or an ``$all`` of nothing
    but those. Such a matcher constrains nothing."""
    if not isinstance(spec, dict):
        return False
    if spec.get("$any"):
        return True
    every = spec.get("$all")
    return isinstance(every, list) and all(_is_any(part) for part in every)


def _matches_value(spec: JsonValue, actual: JsonValue) -> bool:
    if isinstance(spec, dict) and any(str(k).startswith("$") for k in spec):
        if spec.get("$any"):
            return True
        if "$all" in spec:
            every = spec["$all"]
            return isinstance(every, list) and all(_matches_value(part, actual) for part in every)
        if "$contains" in spec:
            needle = spec["$contains"]
            if isinstance(actual, str):
                return isinstance(needle, str) and needle in actual
            if isinstance(actual, list):
                return needle in actual
            return False
        if "$regex" in spec:
            pattern = spec["$regex"]
            return (
                isinstance(pattern, str)
                and isinstance(actual, str)
                and re.search(pattern, actual) is not None
            )
        raise ValueError(f"unknown fixture matcher {sorted(spec)}")
    return spec == actual


def matches(match: dict[str, JsonValue], arguments: dict[str, JsonValue]) -> bool:
    return all(
        key in arguments and _matches_value(spec, arguments[key]) for key, spec in match.items()
    )


class FixtureAdapter(ToolAdapter[Any, Any, Any]):
    kind = "fixture"

    def __init__(self, definition: ToolDefinition[Any, Any, Any], fixture: ToolFixture) -> None:
        if fixture.tool != definition.name:
            raise ValueError(f"fixture for {fixture.tool!r} given to tool {definition.name!r}")
        super().__init__(definition)
        self.fixture = fixture

    def fetch(self, request: ToolRequest) -> JsonValue:
        arguments: dict[str, JsonValue] = request.model_dump(mode="json")
        for stub in self.fixture.stubs:
            if not matches(stub.match, arguments):
                continue
            if stub.error is not None:
                raise UpstreamError(stub.error.kind, stub.error.detail)
            return copy.deepcopy(stub.response)
        raise UpstreamError(
            "no_fixture",
            f"no fixture stub for {self.definition.name} matches arguments "
            f"{json.dumps(arguments, ensure_ascii=False, sort_keys=True)}",
        )


def fixture_adapters(fixture_set: FixtureSet) -> list[FixtureAdapter]:
    """One adapter per tool the set covers, in the registry's order."""
    return [
        FixtureAdapter(DEFINITIONS[name], fixture_set.tools[name])
        for name in DEFINITIONS
        if name in fixture_set.tools
    ]
