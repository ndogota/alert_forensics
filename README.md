# alert_forensics

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
minutes earlier. Four real runs of `google_genai:gemini-3.5-flash-lite` have been made
on it, one in the first campaign and three in the second. All four closed with zero
tool calls and zero observed facts and asserted `benign_true_positive`, at confidence
0.8, 0.85, 0.9 and 1.0. All four were refused by the silence rule, under which a result
with no observed facts is grounded only when its verdict is `inconclusive` and its
missing context says what could not be established. All four are counted
`failed_ungrounded`, and none was laundered into `inconclusive`. The first is committed
and replays with no API key:

```
uv sync
uv run alert-forensics replay runs/rmm_block/campaign-0/run.json
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

Campaign 02: `google_genai:gemini-3.5-flash-lite` under the `analyst` role, three served
runs per scenario on eight scenarios, run on 2026-09-15 on fixture digest
`a1861664bc5a11db2c484b92c836c382de183157f8793b27ba8e8ad41788c84e`. The provider's free
tier refused half of the runs made. Every proportion below the refusal line is over the
served runs, and the pooled recalls treat each (finding, run) pair as one trial, so
their intervals are narrower than the truth.

| Measure | Population | Value | Wilson 95 percent |
|---|---|---|---|
| Runs made | all | 48 | |
| Served | all runs | 24 of 48 | |
| Refused by the free tier | all runs | 24 of 48, 22 before any model turn and 2 after | 0.36 to 0.64 |
| Verdict accuracy | served runs | 21 of 24 | 0.69 to 0.96 |
| Evidence recall | (finding, served run) pairs | 38 of 96 | 0.30 to 0.50 |
| Missing-context recall | (entry, served run) pairs | 1 of 48 | 0.00 to 0.11 |
| First passes ungrounded | served runs | 24 of 24 | |
| Runs the correction loop repaired to completed | served runs | 21 of 24 | |
| Observed facts per served run | served runs | 49 facts, mean 2.04; 8 of 24 runs held zero or one | |
| Cost, at the paid-tier price table | all 48 runs | 0.173425 USD | |

The three served runs that were not repaired are scenario 7's, above. The campaign ran
on the free tier, which billed nothing; the cost is what the same tokens cost on a
billed account, from the price table in the evaluation package.

## What the gap is made of

The verdict was right in 21 of 24 served runs. The findings behind those verdicts were
carried, as grounded facts, in 38 of 96 pairs. Of the 32 required findings across the
eight scenarios, 8 were reached in every served run, 8 in some, and 16 in none. The 16
make 48 misses, and every one is attributed to the model rather than to the token
matcher: in no miss did a grounded fact citing a listed tool fail on wording alone.

In three cells, scenarios 4, 5 and 6, every served run reached the right verdict on one
runbook call and no telemetry call. Those nine verdicts are the runbook's; the recall of
those cells says so.

Where the model put the 48 missed findings, read from the artifacts:

- 31 were never stated anywhere in the result.
- 3 were stated as a grounded fact citing the runbook where the finding lists the
  telemetry: scenario 4's parent process, in every served run.
- 6 were in the runbook reading the model received and were filed in `assumptions` or
  `recommended_action` instead of as an observed fact: scenario 4's change window and
  scenario 8's HR routing, three runs each.
- 3 were written as the correct specific claim in `assumptions`, with no tool called
  that could have established it: scenario 4's encoded command in run 4, and scenario
  5's LSASS read in runs 3 and 4. A model judge reading the text would have scored
  those 3 correct. The scorer did not, because nothing in the trace supports them.
- The remaining 5 hold the finding's tokens inside a recommendation or a conditional
  restatement of the runbook, and state no finding.

That is what the three-list schema is for.

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

Fifteen real model runs are committed under `runs/<scenario>/<recording>/`, across all
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
```

`eval` runs every scenario under `examples/` N times into one directory per run, scores
each against the scenario's ground truth, and prints the report: per cell, served and
refused, the failure rate by outcome and error kind, verdict accuracy, evidence recall,
missing-context recall, escalation precision and recall, tool outcomes, wall clock,
tokens and cost, every proportion with its interval. A results directory is one fixture
revision, recorded as a digest, and a rerun under other fixtures is refused before any
run. `eval-report` re-scores a directory from its artifacts without a model.

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
- One model measured, `google_genai:gemini-3.5-flash-lite`, at three served runs per
  cell. The intervals above say what three runs are worth.
- Single tenant, single language, no fine-tuning. Two connectors are live, seven are
  fixture-backed, and the fixtures were written by the author who wrote the ground
  truth.
- Read-only by design, with one gated proposal that writes nothing. This triages; it
  does not remediate.
- The numbers above come from `campaigns/02`, a results directory on the author's disk
  that is not committed, as no results directory is; they were recomputed from its 48
  run artifacts with the project's own scorer on 2026-09-15. A reader of this
  repository can verify the method, the test suite and the fifteen recordings, and not
  the campaign.
