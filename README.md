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

## Development

```
uv sync
uv run pytest
uv run ruff check . && uv run ruff format --check .
uv run mypy --strict src/
```
