# alert_forensics

Repository: [github.com/ndogota/alert_forensics](https://github.com/ndogota/alert_forensics).
Matrix page: [alert-forensics.vercel.app](https://alert-forensics.vercel.app/), whose
numbers come from [reports/model-matrix.json](reports/model-matrix.json) and the
recordings under [runs/](runs/README.md).

A SOC alert triage agent whose every claim cites the tool call behind it. Its output is
three separate lists, not a summary: observed facts, each carrying the ids of the tool
calls it rests on, validated against the real trace; assumptions, which carry no
citation and say why they are unverified; and missing context, what could not be
established, why it matters and how to obtain it. It is measured against ground truth
by deterministic scorers, and its failed runs are counted and published beside its
correct ones. The design authority is [docs/SPEC.md](docs/SPEC.md); every decision
below is settled there, with its reason.

## The trap, first

Scenario 7 is a remote-management tool blocked by the EDR: a signed binary, VirusTotal 0
of 72, and a ground truth of `true_positive`, because the block caught the second
execution and the first arrived from `mshta.exe` launched by the mail client six
minutes earlier.

Seven real runs of `google_genai:gemini-3.5-flash-lite` have been made on it across the
three campaigns: one, then three, then three, under three fixture revisions. All seven
closed with zero tool calls and zero observed facts and asserted `benign_true_positive`
against the `true_positive` truth, at confidence 0.8, 0.85, 1.0, 0.9, 0.9, 0.9 and 0.9
in the order they were made. All seven were refused by the silence rule, under which a
result with no observed facts is grounded only when its verdict is `inconclusive` and
its missing context says what could not be established. All seven are counted
`failed_ungrounded`, and none was laundered into `inconclusive`. The three of campaign
03 closed in 2.1 to 3.2 seconds. The fixture revision made no difference to a run that
asked for no fixture: no stub reached any of the seven.

Beside it, in campaign 03, `anthropic:claude-sonnet-5` made eight to ten tool calls in
each of its three runs on the same alert and the same fixtures, ten, ten and eight,
every call answered. It returned `true_positive` at confidence 0.93 every time,
carried three of the four required findings as grounded facts in every run, named both
missing-context entries in every run, and escalated every time. Same alert, opposite
verdicts, and the gap is the tool calls: one model read the alert and answered from
it, the other asked the tools what the alert did not say.

All seven have a committed source. The first four, the gate run and the three of
campaign 02, are recordings under [runs/rmm_block/](runs/README.md) and replay with no
API key; the three of campaign 03 are the `per_run` rows of that cell in
[reports/model-matrix.json](reports/model-matrix.json).

```
uv sync
uv run alert-forensics replay runs/rmm_block/campaign-0/run.json
uv run alert-forensics replay runs/rmm_block/campaign-02-4/run.json
```

## The method

- **Grounding is validated against the trace, not asked for in a prompt.** The only
  identity link in a LangChain trace is the tool call id, so every observed fact carries
  a list of them, and a validator resolves each against the calls the runner actually
  journalled. An id that does not resolve, or resolves to a denied or failed call, or to
  the disposition proposal, makes the result invalid. `ungrounded_claim_rate` is held at
  zero on every completed run by construction.
- **The correction loop is bounded.** One attempt, two model passes in total. The second
  pass receives the offending facts and the list of citable calls, never the responses,
  and returns citation repairs: re-cite from that list, or withdraw the fact to
  `assumptions`. It cannot touch the verdict or anything else. A run still ungrounded
  after it is `failed_ungrounded`, never `inconclusive`.
- **Three separate lists.** A claim that cannot be attached to a tool call is not a
  fact. It belongs in `assumptions`, or it does not exist.
- **Failure is a first-class number.** A failed run scores zero on every metric and stays
  in every denominator. The failure rate is reported beside accuracy, split by outcome
  and error kind.
- **A provider refusal is counted apart.** A run the provider refused, a rate limit or an
  overloaded model, measures the quota and not the model. It is out of every accuracy
  and failure denominator, reported as its own proportion, split into refusals before
  any model turn and after work.
- **Deterministic scorers, no model judge.** Verdict accuracy is exact match on four
  values. Evidence recall counts required findings carried by a grounded fact, matched
  by the tool the fact cites and then by whole-word tokens in its statement. Every
  proportion carries its Wilson 95 percent interval.

## The numbers

Campaign 03: four models under the `analyst` role, three served runs per cell on eight
scenarios, run on 2026-09-15 from 17:36 UTC on fixture digest
`1a25e478dbab26d5a511364faecd6d450abd7dd633d962fa0ad063181130dff4`. Every proportion
below is over the served runs of that model, 24 for each: verdicts over runs, evidence
recall over (finding, served run) pairs, missing-context recall over (entry, served
run) pairs. The pooled recalls treat each pair as one trial, so their intervals are
narrower than the truth. Each cell carries its Wilson 95 percent interval, and every
number here is in [reports/model-matrix.json](reports/model-matrix.json).

| Model | Verdict | Evidence | Missing context | Cost |
|---|---|---|---|---|
| `openai:gpt-5-nano` | 7 of 24 (0.15 to 0.49) | 5 of 96 (0.02 to 0.12) | 12 of 48 (0.15 to 0.39) | 0.16 USD |
| `anthropic:claude-haiku-4-5` | 13 of 24 (0.35 to 0.72) | 34 of 96 (0.27 to 0.45) | 18 of 48 (0.25 to 0.52) | 0.88 USD |
| `google_genai:gemini-3.5-flash-lite` | 19 of 24 (0.60 to 0.91) | 36 of 96 (0.28 to 0.47) | 1 of 48 (0.00 to 0.11) | 0.14 USD |
| `anthropic:claude-sonnet-5` | 23 of 24 (0.80 to 0.99) | 56 of 96 (0.48 to 0.68) | 26 of 48 (0.40 to 0.67) | 2.87 USD |

Cost is the total over all of a model's runs, refused runs included, at the price table
in the evaluation package. Gemini ran on the free tier, which billed nothing; its cost
is what the same tokens cost on a billed account. Gemini's 24 served runs came out of
46 made: 22 were refused by the free tier, every one a rate limit, 21 before any model
turn and 1 after work, a refusal proportion of 22 of 46 (0.34 to 0.62). The other three
models were never refused.

Of the served runs, `anthropic:claude-sonnet-5` completed 24 of 24;
`anthropic:claude-haiku-4-5` completed 22 of 24, with 1 `failed_ungrounded` and 1
`failed_error`; `google_genai:gemini-3.5-flash-lite` completed 21 of 24, with 3
`failed_ungrounded`, scenario 7's, above; `openai:gpt-5-nano` completed 21 of 24, with
1 `failed_ungrounded` and 2 `failed_error`, both timeouts. A failed run stays in every
denominator above at zero.

## What the matrix says

`google_genai:gemini-3.5-flash-lite` reaches 19 of 24 verdicts on 36 of 96 findings,
while `anthropic:claude-haiku-4-5` reaches 13 of 24 on 34 of 96. So verdict accuracy
does not track the evidence behind it, and the cheapest model in the matrix beats one
six times its price on the verdict alone. The verdict is the number a leaderboard
would print; the evidence recall is the number that says what the verdict rests on.
At its best the agent reaches 23 of 24 verdicts and carries 56 of 96 findings there,
and the second number is the one to read.

Missing context is where the models separate rather than agree.
`google_genai:gemini-3.5-flash-lite` names what it could not establish in 1 of 48
(entry, served run) pairs. That is a property of that model, not of the agent: on the
same alerts and the same fixtures, `anthropic:claude-sonnet-5` names 26 of 48 and
`anthropic:claude-haiku-4-5` names 18 of 48. The axis is scored on every run, and what
the campaign shows is that it separates models rather than describing all of them.

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

## Using it, and the recordings

Eighteen real model runs are committed under `runs/<scenario>/<recording>/`, across all
eight scenarios, each replayable with no API key:

```
uv run alert-forensics replay runs/atypical_travel/campaign-0/run.json
```

`replay` reads the committed artifact, verifies every raw tool response beside it
against the recorded hashes, states the model and the date, and prints the result:
verdict, grounded facts with their citations, assumptions, missing context, human
decisions. Nothing is called and nothing is generated. [runs/README.md](runs/README.md)
lists each recording with what it shows. Which runs are committed is a rule in the
spec, not a choice: a run the spec cites, or the scenario's first completed real run,
whatever it scored. A recording of the scripted client is refused by the test suite.

A plumbing check with no key and no model:

```
uv run alert-forensics triage examples/atypical_travel.alert.json --scripted -o run.json
uv run alert-forensics show run.json
```

This runs the whole graph on the scripted client, which replays tool calls and reasons
about nothing; its verdict is `inconclusive` by construction. It shows the mechanism,
every call journalled and every fact resolved, and is not a demonstration of triage.
The proposal interrupt is answered on the terminal, or ahead of time with `--accept` or
`--reject REASON`.

With a model:

```
uv sync --extra google
GEMINI_API_KEY=... uv run alert-forensics triage ALERT.json --model google_genai:gemini-3.5-flash-lite --role analyst -o run.json
```

`--model provider:name` goes through `init_chat_model`; the provider package is an extra
(`anthropic`, `openai`, `google`, `ollama`). `--role tier1` runs under the restricted
role, `--max-corrections` bounds the loop (default one), and `--timeout` and
`--max-retries` bound every model call and are recorded on the artifact. A run the
provider refused exits 3, apart from a run that failed on its own account, which exits 1.

The evaluation harness:

```
uv run alert-forensics eval --model google_genai:gemini-3.5-flash-lite --runs 3 --results campaigns/03
uv run alert-forensics eval-report campaigns/03
uv run alert-forensics matrix campaigns/03 -o reports/model-matrix.json
```

`eval` runs every scenario under `examples/` N times into one directory per run, scores
each against the scenario's ground truth, and prints the report: per cell, served and
refused, the failure rate by outcome and error kind, verdict accuracy, evidence recall,
missing-context recall, escalation precision and recall, tool outcomes, wall clock,
tokens and cost, every proportion with its interval. A results directory is one fixture
revision, recorded as a digest, and a rerun under other fixtures is refused before any
run. `eval-report` re-scores a directory from its artifacts without a model. `matrix`
re-scores it the same way and writes the one committed file the page and the table
above are read from; [reports/README.md](reports/README.md) says what it holds.

## Development

```
uv sync
uv run pytest
uv run ruff check . && uv run ruff format --check .
uv run mypy --strict src/
```

The test suite never opens a socket and never needs a key.

## Limits

- Eight scenarios, all synthetic, in one taxonomy of four verdicts. Real alert queues
  are messier, noisier and ambiguous.
- Four models measured, at three served runs per cell. The intervals above say what
  three runs are worth.
- Single tenant, single language, no fine-tuning. Two connectors are live, seven are
  fixture-backed, and the fixtures were written by the author who wrote the ground
  truth.
- Read-only by design, with one gated proposal that writes nothing. This triages; it
  does not remediate.
- The numbers above come from `campaigns/03`, a results directory on the author's disk
  that is not committed, as no results directory is. What is committed is the derived
  view, [reports/model-matrix.json](reports/model-matrix.json), regenerated from that
  directory with the project's own scorer and no model call, and the eighteen
  recordings. A reader of this repository verifies the method, the test suite, the
  matrix file's contract and the eighteen recordings, and not the campaign. Every
  number in this file is in one of those two places.
