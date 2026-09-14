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
  scope check that returns a structured denial, the two-layer redaction (an allowlisted
  projection as the guarantee, then a generic pass over free text as the backstop), the
  raw response store the record's `raw_response_ref` and `raw_response_sha256` point
  into, the `ToolRunner` pipeline that journals every call as a `ToolCallRecord`, fixture
  adapters for all nine tools, and two live adapters.

- **Slice 3, done.** The agent graph on LangGraph 1.2 and LangChain 1.4: `create_agent`
  with tools from the `ToolRunner`, `HumanInTheLoopMiddleware` interrupting on the one
  write action, `propose_alert_disposition`, which writes nothing and needs the
  `alerts:write` scope that `tier1` does not hold; the bounded correction loop, one
  attempt by default, whose second pass receives a repair instruction and returns
  citation repairs; `RunOutcome` on the run artifact beside the trace and the grounding
  report; the scripted client, a chat model stand-in that replays a script with no key
  and no network, on which every graph test runs; and the console script. The replay
  viewer and the eval harness are slice 4.

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
| `propose_alert_disposition` | the project's own shape | local, no upstream: records a proposal for the analyst and writes nothing |

Every definition carries its live contract (endpoint, auth, permission) in code, so a
tenant owner writes an adapter against the same shape rather than a new tool. The test
suite never opens a socket: the live adapters are tested against recorded responses
through an in-memory transport, see [tests/recorded/README.md](tests/recorded/README.md).

## Using it

```
uv sync
uv run alert-forensics triage examples/atypical_travel.alert.json --scripted -o run.json
uv run alert-forensics show run.json
```

The first command runs the whole graph on the scripted client: no key, no network. The
proposal interrupt is answered on the terminal, or ahead of time with `--accept` or
`--reject REASON`. It writes `run.json`, the run artifact, and `run.raw/`, the raw tool
responses the trace's refs resolve under. A scripted run's verdict is `inconclusive` by
construction: the script replays tool calls and reasons about nothing. What it shows is
the mechanism: every call journalled, every fact cited and resolved, the interrupt, the
artifact.

With a model:

```
uv sync --extra anthropic
ANTHROPIC_API_KEY=... uv run alert-forensics triage ALERT.json --model anthropic:claude-sonnet-5 --role analyst -o run.json
```

`--model provider:name` goes through `init_chat_model`; the provider package is an extra
(`anthropic`, `openai`, `google`, `ollama`). `get_attack_technique` is then live against
the public bundle, and `lookup_ioc` is live when `VIRUSTOTAL_API_KEY` is set. The
artifact's `adapters` field records which adapter served each tool. `--role tier1` runs
under the restricted role. `--max-corrections` bounds the correction loop, default one.

Nothing in this repository has been run against a real model yet: the build runs
entirely on the scripted client, as the spec's cost discipline requires. The first
measured cell comes with the evaluation slice.

## Development

```
uv sync
uv run pytest
uv run ruff check . && uv run ruff format --check .
uv run mypy --strict src/
```

The test suite never opens a socket and never needs a key.
