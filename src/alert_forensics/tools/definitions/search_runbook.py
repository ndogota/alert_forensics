"""``search_runbook``: internal knowledge, the retrieval component."""

from pydantic import Field

from alert_forensics.contracts import SourceSystem
from alert_forensics.tools.adapter import (
    LiveContract,
    ToolDefinition,
    ToolRequest,
    ToolResponse,
    ToolView,
)

MAX_EXCERPT = 2000


class SearchRunbookRequest(ToolRequest):
    query: str = Field(min_length=1)
    top_k: int = Field(default=3, ge=1, le=10)


class RunbookHit(ToolResponse):
    id: str
    title: str
    score: float
    source: str | None = None
    excerpt: str


class RunbookResponse(ToolResponse):
    hits: list[RunbookHit] = Field(default_factory=list)


class RunbookHitView(ToolView):
    id: str
    title: str
    score: float
    source: str | None
    excerpt: str


class RunbookView(ToolView):
    count: int
    hits: list[RunbookHitView]


def _project(response: RunbookResponse, request: SearchRunbookRequest | None) -> RunbookView:
    hits = response.hits[: request.top_k] if request is not None else response.hits
    return RunbookView(
        count=len(hits),
        hits=[
            RunbookHitView(
                id=h.id,
                title=h.title,
                score=h.score,
                source=h.source,
                excerpt=h.excerpt[:MAX_EXCERPT],
            )
            for h in hits
        ],
    )


SEARCH_RUNBOOK = ToolDefinition(
    name="search_runbook",
    description=(
        "Search the SOC's internal runbooks and known-good inventories: playbooks, "
        "allowlisted egress ranges, maintenance windows, exercise rosters."
    ),
    source_system=SourceSystem.runbook,
    required_scope="runbook:read",
    request_model=SearchRunbookRequest,
    response_model=RunbookResponse,
    view_model=RunbookView,
    projector=_project,
    live=LiveContract(
        status="fixture",
        system="Internal knowledge base",
        endpoint="Any retriever returning {hits:[{id,title,score,source,excerpt}]}",
        auth="Deployment specific",
        permission="Read on the runbook corpus",
        notes="A keyword or vector index over the SOC's runbooks; the fixtures ship excerpts.",
    ),
)
