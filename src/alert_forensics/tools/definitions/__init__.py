"""The ten tool definitions, registered once each, in the order of the spec's table:
nine read-only, then the one gated write action."""

from typing import Any

from alert_forensics.tools.adapter import ToolDefinition
from alert_forensics.tools.definitions.get_asset import GET_ASSET
from alert_forensics.tools.definitions.get_attack_technique import GET_ATTACK_TECHNIQUE
from alert_forensics.tools.definitions.get_identity import GET_IDENTITY
from alert_forensics.tools.definitions.get_process_tree import GET_PROCESS_TREE
from alert_forensics.tools.definitions.get_related_alerts import GET_RELATED_ALERTS
from alert_forensics.tools.definitions.lookup_ioc import LOOKUP_IOC
from alert_forensics.tools.definitions.propose_alert_disposition import (
    PROPOSE_ALERT_DISPOSITION,
)
from alert_forensics.tools.definitions.search_events import SEARCH_EVENTS
from alert_forensics.tools.definitions.search_runbook import SEARCH_RUNBOOK
from alert_forensics.tools.definitions.search_siem import SEARCH_SIEM

_ALL: tuple[ToolDefinition[Any, Any, Any], ...] = (
    SEARCH_EVENTS,
    SEARCH_SIEM,
    GET_IDENTITY,
    GET_ASSET,
    LOOKUP_IOC,
    GET_RELATED_ALERTS,
    GET_PROCESS_TREE,
    SEARCH_RUNBOOK,
    GET_ATTACK_TECHNIQUE,
    PROPOSE_ALERT_DISPOSITION,
)

DEFINITIONS: dict[str, ToolDefinition[Any, Any, Any]] = {d.name: d for d in _ALL}
TOOL_NAMES: list[str] = list(DEFINITIONS)

if len(TOOL_NAMES) != len(_ALL):
    raise RuntimeError("a tool name is registered twice")

__all__ = [
    "DEFINITIONS",
    "GET_ASSET",
    "GET_ATTACK_TECHNIQUE",
    "GET_IDENTITY",
    "GET_PROCESS_TREE",
    "GET_RELATED_ALERTS",
    "LOOKUP_IOC",
    "PROPOSE_ALERT_DISPOSITION",
    "SEARCH_EVENTS",
    "SEARCH_RUNBOOK",
    "SEARCH_SIEM",
    "TOOL_NAMES",
]
