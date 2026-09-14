"""The local adapter behind ``propose_alert_disposition``: it acknowledges, nothing more."""

from collections.abc import Callable
from datetime import UTC, datetime

from pydantic import JsonValue

from alert_forensics.tools.adapter import ToolAdapter
from alert_forensics.tools.definitions.propose_alert_disposition import (
    PROPOSE_ALERT_DISPOSITION,
    ProposeDispositionRequest,
    ProposeDispositionResponse,
    ProposeDispositionView,
)


class DispositionAdapter(
    ToolAdapter[ProposeDispositionRequest, ProposeDispositionResponse, ProposeDispositionView]
):
    """Echoes the proposal with a timestamp. There is no upstream to reach."""

    kind = "local"

    def __init__(self, clock: Callable[[], datetime] | None = None) -> None:
        super().__init__(PROPOSE_ALERT_DISPOSITION)
        self.clock = clock or (lambda: datetime.now(UTC))

    def fetch(self, request: ProposeDispositionRequest) -> JsonValue:
        proposed_at = self.clock().astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        raw: JsonValue = {
            "status": "proposed",
            **request.model_dump(mode="json"),
            "proposed_at": proposed_at,
        }
        return raw
