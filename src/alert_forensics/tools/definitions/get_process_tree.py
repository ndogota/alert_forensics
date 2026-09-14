"""``get_process_tree``: ``DeviceProcessEvents`` lineage around one process.

The response is the hunting envelope, because that is what a live adapter runs: a fixed
KQL over ``DeviceProcessEvents``. The projection rebuilds the lineage from the rows: the
row for the requested process carries its parent and grandparent in the
``InitiatingProcess*`` columns, and rows initiated by it are its children.
"""

from typing import Literal

from pydantic import Field, JsonValue

from alert_forensics.contracts import SourceSystem
from alert_forensics.tools.adapter import LiveContract, ToolDefinition, ToolRequest, ToolView
from alert_forensics.tools.definitions._common import (
    HuntingResponse,
    optional_int,
    optional_str,
)

Relation = Literal["grandparent", "parent", "self", "child"]
Row = dict[str, JsonValue]


class GetProcessTreeRequest(ToolRequest):
    device_name: str = Field(min_length=1)
    process_id: int = Field(ge=0)
    process_creation_time: str | None = Field(
        default=None, description="ISO 8601; disambiguates a reused process id."
    )


class ProcessNode(ToolView):
    relation: Relation
    file_name: str | None
    folder_path: str | None
    command_line: str | None
    process_id: int | None
    created_at: str | None
    account: str | None
    sha256: str | None


class ProcessTreeView(ToolView):
    device_name: str
    process_id: int
    found: bool
    lineage: list[ProcessNode]


def _node(row: Row, relation: Relation) -> ProcessNode:
    return ProcessNode(
        relation=relation,
        file_name=optional_str(row.get("FileName")),
        folder_path=optional_str(row.get("FolderPath")),
        command_line=optional_str(row.get("ProcessCommandLine")),
        process_id=optional_int(row.get("ProcessId")),
        created_at=optional_str(row.get("ProcessCreationTime")),
        account=optional_str(row.get("AccountName")),
        sha256=optional_str(row.get("SHA256")),
    )


def _initiating_node(row: Row, relation: Relation) -> ProcessNode | None:
    """The parent as the child's row describes it, when no row of its own exists."""
    if row.get("InitiatingProcessFileName") is None and row.get("InitiatingProcessId") is None:
        return None
    return ProcessNode(
        relation=relation,
        file_name=optional_str(row.get("InitiatingProcessFileName")),
        folder_path=optional_str(row.get("InitiatingProcessFolderPath")),
        command_line=optional_str(row.get("InitiatingProcessCommandLine")),
        process_id=optional_int(row.get("InitiatingProcessId")),
        created_at=optional_str(row.get("InitiatingProcessCreationTime")),
        account=optional_str(row.get("InitiatingProcessAccountName")),
        sha256=optional_str(row.get("InitiatingProcessSHA256")),
    )


def _grandparent_node(row: Row) -> ProcessNode | None:
    """The grandparent as the child's row describes it: file name and id only."""
    if (
        row.get("InitiatingProcessParentFileName") is None
        and row.get("InitiatingProcessParentId") is None
    ):
        return None
    return ProcessNode(
        relation="grandparent",
        file_name=optional_str(row.get("InitiatingProcessParentFileName")),
        folder_path=None,
        command_line=None,
        process_id=optional_int(row.get("InitiatingProcessParentId")),
        created_at=optional_str(row.get("InitiatingProcessParentCreationTime")),
        account=None,
        sha256=None,
    )


def _sort_key(row: Row) -> str:
    return str(row.get("ProcessCreationTime") or row.get("Timestamp") or "")


def _project(response: HuntingResponse, request: GetProcessTreeRequest | None) -> ProcessTreeView:
    if request is None:
        raise ValueError("the process tree projection pivots on the request's process id")
    rows = response.results
    pid = request.process_id
    mine = [r for r in rows if optional_int(r.get("ProcessId")) == pid]
    if request.process_creation_time:
        exact = [r for r in mine if r.get("ProcessCreationTime") == request.process_creation_time]
        mine = exact or mine
    if not mine:
        return ProcessTreeView(
            device_name=request.device_name, process_id=pid, found=False, lineage=[]
        )
    me = mine[0]
    by_pid: dict[int, Row] = {}
    for row in rows:
        row_pid = optional_int(row.get("ProcessId"))
        if row_pid is not None and row_pid not in by_pid:
            by_pid[row_pid] = row

    lineage: list[ProcessNode] = []
    parent_pid = optional_int(me.get("InitiatingProcessId"))
    parent_row = by_pid.get(parent_pid) if parent_pid is not None else None
    if parent_row is not None:
        grandparent = _initiating_node(parent_row, "grandparent")
        parent: ProcessNode | None = _node(parent_row, "parent")
    else:
        grandparent = _grandparent_node(me)
        parent = _initiating_node(me, "parent")
    if grandparent is not None:
        lineage.append(grandparent)
    if parent is not None:
        lineage.append(parent)
    lineage.append(_node(me, "self"))
    children = sorted(
        (r for r in rows if optional_int(r.get("InitiatingProcessId")) == pid), key=_sort_key
    )
    lineage.extend(_node(r, "child") for r in children)
    return ProcessTreeView(
        device_name=request.device_name, process_id=pid, found=True, lineage=lineage
    )


GET_PROCESS_TREE = ToolDefinition(
    name="get_process_tree",
    description=(
        "Rebuild the process lineage around one process on a device from DeviceProcessEvents: "
        "grandparent, parent, the process itself and its children, with command lines."
    ),
    source_system=SourceSystem.defender,
    required_scope="hunting:read",
    request_model=GetProcessTreeRequest,
    response_model=HuntingResponse,
    view_model=ProcessTreeView,
    projector=_project,
    live=LiveContract(
        status="fixture",
        system="Microsoft Graph security API",
        endpoint="POST https://graph.microsoft.com/v1.0/security/runHuntingQuery",
        auth="as search_events",
        permission="ThreatHunting.Read.All",
        notes=(
            "Fixed KQL: DeviceProcessEvents | where DeviceName =~ '<device>' and "
            "(ProcessId == <pid> or InitiatingProcessId == <pid>) | project the lineage "
            "columns. Passwords inside command lines are redacted by the generic layer."
        ),
    ),
)
