"""The adapter interface every tool sits behind.

A ``ToolDefinition`` is the contract the agent sees: name, source system, required scope,
request shape, response shape, and the projection from a validated response to the view
the model receives. A ``ToolAdapter`` is one way of obtaining a raw response for that
definition: a fixture set, a live API, a scripted stand-in. The definition does not
change when the adapter does; that is what makes a fixture-backed tool portable.
"""

from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel, ConfigDict, JsonValue

from alert_forensics.contracts import SourceSystem
from alert_forensics.contracts._base import ContractModel

FailureKind = Literal[
    "invalid_arguments",
    "upstream_error",
    "malformed_response",
    "no_fixture",
    "not_found",
    "unknown_tool",
]


class UpstreamError(Exception):
    """An adapter could not obtain a response. Carries a kind the journal records."""

    def __init__(self, kind: FailureKind, detail: str) -> None:
        super().__init__(f"{kind}: {detail}")
        self.kind: FailureKind = kind
        self.detail = detail


class ToolFailure(ContractModel):
    """What the model receives when a call ends with outcome ``error``."""

    error: FailureKind
    tool: str
    detail: str


class ToolRequest(ContractModel):
    """Base for every request shape. Unknown arguments are a model mistake, so they fail."""


class ToolResponse(BaseModel):
    """Base for every raw response shape. Real APIs add fields; the shape tolerates them
    and the raw is stored verbatim, so nothing is lost by tolerating."""

    model_config = ConfigDict(frozen=True, extra="allow")


class ToolView(ContractModel):
    """Base for every view. A field the model sees that nobody declared is a redaction
    gap, so views forbid unknown fields."""


AdapterKind = Literal["fixture", "live", "recorded", "local"]
"""What served a tool in a run: frozen fixtures, a real service, a recorded excerpt of
the real service used because the fetch failed, or a local tool with no upstream."""


@dataclass(frozen=True)
class LiveContract:
    """What a live adapter for this tool talks to, documented whether or not one ships.

    ``local`` is neither: the tool has no upstream and is complete as shipped.
    """

    status: Literal["live", "fixture", "local"]
    system: str
    endpoint: str
    auth: str
    permission: str
    notes: str = ""


@dataclass(frozen=True)
class ToolDefinition[Req: ToolRequest, Resp: ToolResponse, View: ToolView]:
    name: str
    description: str
    source_system: SourceSystem
    required_scope: str
    request_model: type[Req]
    response_model: type[Resp]
    view_model: type[View]
    projector: Callable[[Resp, Req | None], View]
    live: LiveContract

    @property
    def live_capable(self) -> bool:
        return self.live.status == "live"

    def project(self, response: Resp, request: Req | None = None) -> View:
        """Project a validated response to the view the model sees.

        Most projections depend only on the response. The ones that need the request
        (the process tree pivots on the requested process id) raise ``ValueError`` when
        called without one; the runner always passes it.
        """
        return self.projector(response, request)


class ToolAdapter[Req: ToolRequest, Resp: ToolResponse, View: ToolView](ABC):
    """One way of obtaining a raw response for a definition."""

    kind: AdapterKind = "live"
    """Recorded on the run artifact so a reader knows what served each tool. A class
    default; an adapter that falls back at fetch time sets it on the instance."""

    def __init__(self, definition: ToolDefinition[Req, Resp, View]) -> None:
        self.definition = definition

    @abstractmethod
    def fetch(self, request: Req) -> JsonValue:
        """Return the raw upstream response as JSON, or raise ``UpstreamError``.

        The runner validates the result against the definition's response shape; the
        adapter returns what it got, verbatim, so the stored raw is the real thing.
        """
