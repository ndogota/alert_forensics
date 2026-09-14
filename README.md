# alert_forensics

A SOC alert triage agent that cites the tool call behind every observed fact, states what
it could not establish, and is measured against ground truth. The design authority is
[docs/SPEC.md](docs/SPEC.md).

## Slices

- **Slice 1, done.** Domain contracts (`Alert` in the Microsoft Graph `security.alert` v2
  shape, `ToolCallRecord`, `InvestigationTrace`, `TriageResult`) and the pure grounding
  validator `validate_grounding`, which resolves every cited evidence id against the real
  trace and reports `ungrounded_claim_rate`. The trace is designed for lossless JSON
  round-trip and replay, not only audit. No agent, no tools, no model calls yet, so
  LangChain and LangGraph are not yet runtime dependencies; they join when first imported.

- **Slice 2, done.** The tool layer, stopping before the agent graph: the `ToolAdapter`
  interface with a declared scope and response shape per tool, the nine definitions, the
  scope check that returns a structured denial, the two-layer redaction (projection, then
  a generic pass for secrets and personal data), the raw response store the record's
  `raw_response_ref` and `raw_response_sha256` point into, the `ToolRunner` pipeline that
  journals every call as a `ToolCallRecord`, fixture adapters for all nine tools, and two
  live adapters. The console script arrives with the agent graph.

## Tools: which are live, which are fixture-backed

Two adapters talk to a real service. Seven return frozen fixtures and document the live
contract to port to. Nothing here talks to a production SIEM or EDR out of the box.

| Tool | Shape follows | Adapter |
|---|---|---|
| `search_events` | Graph `security/runHuntingQuery` | fixture-backed |
| `search_siem` | Splunk search v2 | fixture-backed |
| `get_identity` | Splunk ES Asset and Identity framework | fixture-backed |
| `get_asset` | Splunk ES Asset and Identity framework | fixture-backed |
| `lookup_ioc` | VirusTotal API v3 | **live**, needs `VIRUSTOTAL_API_KEY` (a free key works) |
| `get_related_alerts` | Graph `security/alerts_v2` | fixture-backed |
| `get_process_tree` | `DeviceProcessEvents` through the hunting API | fixture-backed |
| `search_runbook` | internal knowledge base | fixture-backed |
| `get_attack_technique` | ATT&CK enterprise STIX bundle | **live**, no key; the bundle is cached under `~/.cache/alert-forensics/attack/` |

Every definition carries its live contract (endpoint, auth, permission) in code, so a
tenant owner writes an adapter against the same shape rather than a new tool. The test
suite never opens a socket: the live adapters are tested against recorded responses
through an in-memory transport, see [tests/recorded/README.md](tests/recorded/README.md).

## Development

```
uv sync
uv run pytest
uv run ruff check . && uv run ruff format --check .
uv run mypy --strict src/
```
