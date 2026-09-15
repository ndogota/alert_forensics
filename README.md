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
  and no network, on which every graph test runs; and the console script.

- **Slice 4, done.** The evaluation harness. `GroundTruth` is a contract, one file per
  scenario beside its alert (`examples/<scenario>.truth.json`), checked against the
  alert it sits beside; a required finding names the tool a fact must cite and the
  tokens its statement must contain, so the match is deterministic and a miss is named.
  Scorers: verdict accuracy on exact match, evidence recall over grounded facts only,
  missing-context recall, escalation precision and recall, and `ungrounded_claim_rate`
  reported as the check that the loop held. A failed run scores zero on every metric
  and stays in every denominator; the failure rate is reported beside accuracy, split
  by outcome and error kind. Every proportion carries its Wilson 95 percent interval.
  Cost is derived at report time from a price table in the evaluation package; latency
  is the wall clock the harness measured. `alert-forensics eval` keeps one artifact per
  run and derives the summary; `eval-report` recomputes it. Scenarios 1 to 4 have a
  ground truth and fixtures; the other four are the next slices, written against this
  contract. The replay viewer is also still to come.

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
| `get_attack_technique` | ATT&CK enterprise STIX bundle | **live**, no key; cached under `~/.cache/alert-forensics/attack/`, with a recorded excerpt as the offline fallback |
| `propose_alert_disposition` | the project's own shape | local, no upstream: records a proposal for the analyst and writes nothing |

Every definition carries its live contract (endpoint, auth, permission) in code, so a
tenant owner writes an adapter against the same shape rather than a new tool. The test
suite never opens a socket: the live adapters are tested against recorded responses
through an in-memory transport, see [tests/recorded/README.md](tests/recorded/README.md).

## Using it

Without a key, replay a recorded run:

```
uv sync
uv run alert-forensics replay runs/atypical_travel/run.json
```

`replay` reads a committed artifact, verifies every raw tool response beside it against
the recorded hashes, states the model and the date, and prints the result: verdict,
grounded facts with their citations, assumptions, missing context, human decisions.
What it prints is a recording of a real model run, not a live one: nothing is called,
nothing is generated. The recording under `runs/atypical_travel/` is scenario 1 on a
real model, produced with the command under "With a model" below. A recording of the
scripted client is refused by the test suite: a fake demo is worse than none.

A plumbing check, no key and no model:

```
uv run alert-forensics triage examples/atypical_travel.alert.json --scripted -o run.json
uv run alert-forensics show run.json
```

This runs the whole graph on the scripted client. The proposal interrupt is answered on
the terminal, or ahead of time with `--accept` or `--reject REASON`. It writes
`run.json`, the artifact, and `run.raw/`, the raw responses the trace's refs resolve
under. A scripted run's verdict is `inconclusive` by construction: the script replays
tool calls and reasons about nothing. It shows the mechanism, every call journalled and
every fact resolved, and it is not a demonstration of triage.

With a model:

```
uv sync --extra anthropic
ANTHROPIC_API_KEY=... uv run alert-forensics triage ALERT.json --model anthropic:claude-sonnet-5 --role analyst -o run.json
```

`--model provider:name` goes through `init_chat_model`; the provider package is an extra
(`anthropic`, `openai`, `google`, `ollama`). `get_attack_technique` is live against the
public ATT&CK bundle in every mode, `--scripted` included, since it needs no key; when
the bundle cannot be fetched, the recorded excerpt shipped in the package serves and the
artifact's `adapters` field says `recorded` instead of `live`. `lookup_ioc` is live when
`VIRUSTOTAL_API_KEY` is set. `--role tier1` runs under the restricted role.
`--max-corrections` bounds the correction loop, default one.

The build runs entirely on the scripted client, as the spec's cost discipline requires;
real model runs are the recordings under `runs/` and the cells under `results/`.

## Evaluation

```
uv run alert-forensics eval --scripted
uv run alert-forensics eval --model anthropic:claude-sonnet-5 --runs 3
uv run alert-forensics eval-report results/
```

`eval` runs every scenario under `examples/` N times (`--runs`, default 3; `--scenario`
narrows to one) and writes one directory per run under `results/<model>/<role>/<scenario>/<k>/`:
`run.json`, the same artifact `triage` writes, so `show` and `replay` read it; `run.raw/`;
`eval.json`, the measured wall clock; and `score.json`, the run scored against the
scenario's ground truth. A second invocation adds runs to a cell rather than overwriting
it. It then writes `results/summary.json` and prints the report: per cell, the completed
and failed proportions split by outcome and error kind, verdict accuracy, evidence
recall, missing-context recall, escalation precision and recall, the ungrounded claim
rate over completed runs, wall clock, tokens and cost, each proportion with its Wilson
95 percent interval. A run the provider refused, a rate limit or an overloaded model, is
the quota's number and not the model's: it is reported apart, with how many refusals
came before any model turn, and it is out of every accuracy and failure denominator,
which are over the served runs; a cell with no served run says so in capitals. Wall
clock, tokens per run and mean cost are over the served runs, the tokens the refused
runs spent are printed beside them, and the cost total is over every run. `eval-report
DIR` re-scores every run from its artifact and the current ground truth and rewrites the
summary, so a corrected truth file re-scores old runs without a model. `--scenario`
narrows what is run, never what is summarised: the report covers the whole directory.
`--scripted` runs the suite with no key and no network; its verdict is `inconclusive` by
construction, so its accuracy is the floor, not a result. The price table lives in
`src/alert_forensics/evaluation/prices.py`, each row with its source and the date it was
read; a model missing from it is reported as unpriced, never as free.

## Development

```
uv sync
uv run pytest
uv run ruff check . && uv run ruff format --check .
uv run mypy --strict src/
```

The test suite never opens a socket and never needs a key.
