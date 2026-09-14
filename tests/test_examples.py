"""Every example alert resolves offline through the default adapter set."""

import json
from pathlib import Path

import pytest

from alert_forensics.cli import default_adapters
from alert_forensics.contracts import Alert, ToolOutcome
from alert_forensics.fixtures import DEFAULT_FIXTURES_DIR
from alert_forensics.tools import ANALYST_ROLE, InMemoryRawStore, Principal, ToolRunner

EXAMPLES = sorted(Path("examples").glob("*.alert.json"))


def test_there_is_at_least_one_example():
    assert EXAMPLES


@pytest.mark.parametrize("path", EXAMPLES, ids=[p.name for p in EXAMPLES])
def test_every_declared_technique_resolves_offline(path):
    alert = Alert.model_validate(json.loads(path.read_text()))
    assert alert.mitre_techniques, f"{path.name} declares no technique; the example should"
    runner = ToolRunner(
        adapters=default_adapters(DEFAULT_FIXTURES_DIR, scripted=True),
        principal=Principal(name="analyst", role=ANALYST_ROLE),
        store=InMemoryRawStore(),
        investigation_id="inv-examples",
    )
    for n, technique in enumerate(alert.mitre_techniques):
        record = runner.invoke(
            tool_call_id=f"tc-{n}",
            step=0,
            tool_name="get_attack_technique",
            arguments={"technique_id": technique},
        )
        assert record.outcome is ToolOutcome.ok, (technique, record.redacted_response)
        assert record.redacted_response["technique_id"] == technique
    assert runner.adapters["get_attack_technique"].kind == "recorded"
