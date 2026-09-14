# alert_forensics, specification

An agent that triages SOC alerts, cites the evidence behind every claim, states what it
could not establish, and is measured against ground truth. Python, LangChain 1.4,
LangGraph 1.2.

Sibling project to [pod_forensics](https://github.com/ndogota/pod_forensics), which
applies the same method to Kubernetes incident diagnosis.

## Why this project, in three numbers

Reported false-positive rates range from 45 to 83 percent depending on methodology.
Roughly 0.01 percent of daily alerts relate to a real attack. Human accuracy drops
about 40 percent over a twelve hour shift once the false-positive rate passes 80.

So the interesting question is not whether a language model can read an alert. It is
whether its verdict can be trusted, and where it breaks. That is what gets measured
here.

## Design requirements, and how each is met

Nothing here is answered with prose. Each requirement maps to a mechanism.

| Requirement | Implementation |
|---|---|
| distinguish observed facts from assumptions | three separate lists in the schema, not one summary |
| reference the supporting information | every fact carries a `tool_call_id`, validated against the real trace |
| make missing context explicit | entries carry what, why it matters, how to obtain it |
| output usable by existing workflows | machine-consumable JSON, not prose for a human |
| know where conventional code beats a model | deterministic pre-processing, listed and named below |
| keep the analyst in control | human-in-the-loop interrupt on every write action |
| measurable reliability | ground-truth eval set, failed runs counted, Wilson intervals |
| quality, latency and cost | all three measured per investigation from real usage metadata |
| access control, sensitive data, traceability | tool scopes, redaction before the model, full audit trail |

## The centerpiece: grounded claims

LangChain has no native mechanism linking a model claim to the tool call that produced
it. The only guaranteed identity link in a trace is
`AIMessage.tool_calls[i]["id"] == ToolMessage.tool_call_id`. So the grounding is built:

- Each tool keeps its raw upstream response out of the model's context. The
  `ToolMessage.artifact` carries the `ToolCallRecord` the runner journalled, whose
  `raw_response_ref` and `raw_response_sha256` point at the raw in the store. The
  artifact never reaches the model; the raw never enters the message history at all.
- The output schema requires `evidence: list[str]` of tool call ids on every observed
  fact.
- A validator resolves every id against the actual trace. An id that does not resolve,
  or that resolves to a denied or failed call, makes the output invalid and the
  correction loop asks the model again. So does an id that resolves to the disposition
  proposal (problem kind `cites_non_evidence`): the proposal is addressed to the
  analyst, it reads no system, and a fact resting on it rests on the model's own
  words.
- A fact may correlate several source systems: a sign-in from Defender and an identity
  from Splunk cited together is one fact, not a defect. The systems a fact rests on are
  resolved from the cited records in the trace and reported on the grounding report as
  `source_systems`. The model never asserts them.
- Silence does not score. A result with no observed facts is grounded only when the
  verdict is `inconclusive` and `missing_context` names what could not be established.
- The metric `ungrounded_claim_rate` is enforced to zero rather than hoped for.

A claim that cannot be attached to a tool call is not a fact. It belongs in
`assumptions`, or it does not exist.

## The correction loop

When the validator rejects a result, the model is asked to repair it. Three decisions
bound that loop. Each is a decision, not an option, and carries its reason.

**One correction attempt, two model passes in total.** The attempt count is
configurable (`max_corrections`, default 1). The defects the validator catches are
invented ids and citations of failed calls. A model that cannot repair those with the
problems spelled out in front of it will not repair them on a third pass, and an
unbounded loop makes the measured cost and latency per investigation meaningless: a
number that depends on how many times the harness was willing to retry is a property of
the harness, not of the model.

**The second pass receives a repair instruction, not the report.** For each offending
fact it gets the statement, the offending evidence id, the problem kind, and the list of
`tool_call_id`s actually present in the trace. It does not get the already-grounded
facts, the trace, or the raw responses. The loop repairs citations; it is not a second
chance to reason. If it were, the harness would measure the wrong pass: a verdict that
is right only after the model was told which citations were fictional is not the verdict
the first pass produced.

Three details make that sentence precise, decided here because the sentence alone
leaves them open:

- The second pass is a fresh model call, not a continuation of the investigation
  thread. Continuing the thread would hand the model every tool response again, which
  is the trace in all but name. The instruction is the only user content it sees.
- A bare id carries no meaning, so each present id is listed with the tool it called,
  the arguments the model itself wrote, and the outcome. Never the response: what the
  call returned is exactly what the model may not re-read.
- The second pass returns citation repairs, not a result. For each offending fact, by
  index, it either re-cites from the present ids or withdraws the fact, giving the
  reason it could not be verified. The harness applies the repairs: a re-cited fact
  keeps its statement with the new evidence, a withdrawn fact moves to `assumptions`,
  a repair naming a fact that was not offending is ignored, and an offending fact the
  repair does not mention stays as it was. Verdict, confidence, techniques, recommended
  action, escalation, missing context and the grounded facts are the first pass's and
  cannot be touched. The repaired result is validated again, by the same validator.

**A run that leaves the loop still ungrounded is a failed run, never inconclusive.**

```
RunOutcome
  completed          the loop ended with a grounded result
  failed_ungrounded  the loop ended and the result is still ungrounded
  failed_error       no result was produced: model error, unparseable output, budget
```

The evaluation reports the failure rate as a first-class number beside accuracy, split
by outcome, and a failed run scores zero on every accuracy metric. `inconclusive` is a
verdict an analyst is sometimes right to give: the evidence really was insufficient and
the missing context says why. Laundering a failure into it would destroy the meaning of
verdict accuracy, the same way collapsing `benign_true_positive` into `false_positive`
loses the tuning decisions.

## The run artifact

One investigation produces one artifact, and the outcome lives on it beside the trace
and the report, not in a log line.

```
RunArtifact
  investigation_id
  outcome            RunOutcome
  model              the provider:model string the run was started with
  role               the role the tools ran under
  adapters           {tool: fixture | live | recorded | local}, what actually served each tool
  trace              InvestigationTrace: alert, every tool call, usage per model turn
  report             GroundingReport of the final result, or null when no result was produced
  passes             model passes that produced a result: 1 plus the corrections made
  corrections        [{instruction sent, repairs received, report before them}], one per pass
  decisions          [{tool_call_id, proposal, decision: accepted | rejected, reason}]
  error              {kind, message} on failed_error; on failed_ungrounded when the
                     correction pass itself failed; never on completed
  raw_store          directory the trace's raw_response_refs resolve under
```

- The result is not a separate field: the report carries it, and a report that
  disagrees with its result refuses to validate. `report.result` is the result.
- Usage per model turn is read from `usage_metadata` on each `AIMessage`, the
  provider-agnostic field, and numbered by the message's position among the model turns.
  That is the same numbering a `ToolCallRecord.step` uses, so a record and the turn that
  emitted it agree.
- `passes` counts model passes that produced a result. The trace's `usage` counts every
  model turn, including the tool-calling turns; the two are different numbers on
  purpose.
- A correction pass that raises leaves the first pass's ungrounded result standing:
  the outcome is `failed_ungrounded`, with the error recorded beside the report. It is
  not `failed_error`, because a result was produced; it is not laundered either.
- A correction pass that returns no repairs, prose instead of the schema, counts as an
  empty repair: the result is validated again unchanged and fails as it stood.
- On `failed_error` the trace still holds every call that was journalled before the
  failure. The artifact is written whatever the outcome, so a failed run is inspectable.

## Where conventional code wins

Stated explicitly, because the judgement matters more than a blanket use of models.

- Entity extraction and IOC parsing: parsers, deterministic.
- MITRE ATT&CK technique resolution: lookup in the official STIX bundle by
  `external_references.external_id`, never asked of the model.
- Playbook thresholds: password spray is 100 or more accounts, 5 or more countries, 25
  or more source IPs. That is arithmetic, and arithmetic does not hallucinate.
- VirusTotal interpretation: `last_analysis_stats` is a dict of engine counters and
  `reputation` is a signed community vote, often zero on rarely seen objects. Both are
  read by code; the model receives the reading, not the raw temptation.
- Deduplication and correlation on entity keys.
- Source-system attribution of every observed fact: resolved from the cited tool calls
  in the trace, never declared by the model.

The model is used for what remains: hypothesis, pivot selection, weighing contradictory
signals, and writing the summary.

## Output schema

```
TriageResult
  verdict            true_positive | false_positive | benign_true_positive | inconclusive
  confidence         float
  mitre_techniques   [T####.###]  resolved deterministically, not invented
  observed_facts     [{statement, evidence: [tool_call_id]}]
  assumptions        [{statement, why_unverified}]
  missing_context    [{what, why_it_matters, how_to_obtain}]
  recommended_action str
  escalate           bool

GroundingReport      produced by the validator from a TriageResult and its trace
  result             the TriageResult it describes, carried so the report stands alone
  facts              [{index, statement, evidence_ids, resolved_ids,
                       source_systems: [defender | splunk | ...], problems, grounded}]
  ungrounded_claim_rate, is_grounded, no_facts
```

The source systems live on the report, not on the fact: they are derived from the trace.
A result never travels without its report, and that is structural: the report carries
the result and refuses to validate if its facts or summary disagree with it.

`benign_true_positive` is a first-class verdict because a SOC needs it: the detection
fired correctly and the intent was legitimate. Collapsing it into false positive is how
tuning decisions get lost.

## Tool surface

Nine read-only tools and one gated write action. Every tool sits behind a `ToolAdapter`
that declares its required scope and its response shape. Shapes follow the real APIs, so
a fixture-backed tool is ported to a tenant by writing a new adapter, not by changing
the shape the agent sees.

| Tool | Shape follows | Adapter |
|---|---|---|
| `search_events` | Graph `security/runHuntingQuery`, `schema[] {name,type}` plus `results[]` | fixture |
| `search_siem` | Splunk search v2, sid then results, SPL string in | fixture |
| `get_identity` | Splunk Asset and Identity framework, priority drives urgency | fixture |
| `get_asset` | same framework, device compliance and criticality | fixture |
| `lookup_ioc` | VirusTotal v3, JSON:API envelope, epoch dates, engine counters | **live**, free API key |
| `get_related_alerts` | Microsoft Graph `security/alerts_v2` | fixture |
| `get_process_tree` | `DeviceProcessEvents` lineage through the hunting API | fixture |
| `search_runbook` | internal knowledge, the retrieval component | fixture |
| `get_attack_technique` | ATT&CK STIX bundle, deterministic, not a model call | **live**, public bundle, no key |
| `propose_alert_disposition` | the project's own shape; there is no upstream | local, writes nothing |

### The one write action

"Human in the loop on every write action" is a promise until there is a write action to
gate. `propose_alert_disposition` is that action, and it is deliberately the smallest one
that can exist:

- It takes a verdict, a recommended action, whether to escalate, and a one-paragraph
  summary. It records the proposal in the journal like any other call and returns an
  acknowledgement that says nothing was written. It changes no alert, no case, no
  notification, anywhere. The sentence "the agent never closes an alert, it prepares
  the investigation and proposes" is what this tool does, and the run artifact shows
  it.
- It requires the scope `alerts:write`. The `analyst` role holds it; `tier1` does not.
  A tier1 run that proposes is journalled as `denied`, which is the same structured
  denial every other out-of-scope call gets.
- It always interrupts, whatever the arguments. The interrupt is the gate on the action
  and the scope is the permission to perform it, checked in that order: a human who
  accepts a tier1 proposal has not granted tier1 a scope, and the journal says
  `denied`.
- Its source system is `human`: it reaches no upstream, and its counterpart is the
  analyst who accepts or rejects. A record from `human` is not evidence, and the
  grounding validator says so.
- Its live status is `local`: neither fixture nor live, complete as shipped.

The agent is told to propose before it answers. A run in which the model never
proposes still completes; the artifact's `decisions` list is empty and the evaluation
can count that.

### The tool layer

A tool call travels through one pipeline, whatever the adapter behind it:

1. Scope check. The principal's scopes are compared with the tool's declared scope. A
   miss produces a `ScopeDenial`, journalled with outcome `denied`. The adapter is never
   called.
2. Argument validation against the tool's request model. A miss is journalled as
   outcome `error`, kind `invalid_arguments`, with the validation message, so the model
   can correct the call.
3. The adapter fetches the raw upstream response. Any upstream failure, including a
   fixture that has no answer for the request, is journalled as outcome `error` with a
   structured `ToolFailure`. Nothing raises into the agent.
4. The raw response is stored out of context and referenced from the record by
   `raw_response_ref` and `raw_response_sha256`. It is stored whether or not it
   validates against the response shape: a malformed response is still evidence.
5. The raw response is validated against the response shape, projected to the tool's
   view, then passed through the generic redaction. The projection is what the model
   sees, verbatim, as `redacted_response`.

Decisions the pipeline rests on:

- Scopes are the project's own strings (`hunting:read`, `siem:search`, `identity:read`,
  `asset:read`, `ioc:lookup`, `alerts:read`, `runbook:read`, `attack:read`, and the one
  write scope `alerts:write`), each mapped to the live permission in the adapter's
  documented contract. Two roles ship: `analyst` holds every scope; `tier1` holds every
  read scope but `siem:search`, since raw SPL is commonly gated above tier one, and not
  `alerts:write`, since tier one escalates rather than disposes. A role that is really
  restricted is what makes the denial path something the harness exercises rather than
  a theoretical branch.
- The model is offered exactly the tools that have an adapter registered for the run,
  in the registry's order. A tool with no adapter is not a tool the model can call
  usefully, and offering it would journal `unknown_tool` errors for calls the harness
  invited.
- Response shapes tolerate unknown fields, since real APIs add them. Views forbid them,
  since a field the model sees that nobody declared is a redaction gap.
- Tabular views are allowlisted per tool and capped at 50 rows; the model is told the
  total row count, a `truncated` flag, and the number of dropped columns. The tool
  description tells the model to project to standard columns, so a query that returns
  only dropped columns is a query it can rewrite.
- Redaction is two-layered, with the guarantees stated under "Access control, sensitive
  data, traceability": the projection is the guarantee, the generic pass is the backstop.
- A call to a tool that does not exist, or that has no adapter registered, is journalled
  as an `error` of kind `unknown_tool` with source system `none`. The journal never files
  a call under a system it did not reach.
- Fixture adapters match a request against stubs: an exact value, `$contains` or
  `$regex` per argument, with an optional default. A request no stub answers is an
  `error` of kind `no_fixture`, never a silent empty result, so a fixture gap shows in
  the trace instead of being read as absence of evidence.
- Live adapters take an injected HTTP client. The test suite drives them through a
  recorded response and a transport that never opens a socket. Nothing in the tests
  reaches a live API.
- VirusTotal "not found" is a successful call: an indicator unknown to VirusTotal is a
  reading, and the projection says so. An ATT&CK id that does not exist is an error of
  kind `not_found`: ids come from the alert or from the model, and an invented one must
  fail loudly.

Alerts follow the Microsoft Graph `security.alert` v2 shape, including the polymorphic
`evidence[]` discriminated by `@odata.type` and `mitreTechniques` as `T####.###`
strings, which is the natural join to ATT&CK.

## Access control, sensitive data, traceability

- Every tool declares a required scope. The agent runs under an analyst role. A call
  outside scope returns a structured denial the agent must handle, not an exception.
- Redaction runs before the model sees anything, in two layers whose guarantees differ,
  stated the way the grounding report states its own:

  **Guaranteed by structure.** A view is a closed schema: every field the model sees was
  declared by name. Record views (identity, asset, IOC reading, ATT&CK, related alerts,
  process lineage) name each field they carry. Tabular views (hunting, SIEM) keep only
  the columns on the tool's allowlist, plus aggregates over allowlisted columns, and
  report how many columns were dropped as a count, never by name, so the model knows the
  row is a projection and cannot ask for a dropped column. `AdditionalFields` and `_raw`
  are on no allowlist; that is where nested JSON with service account passwords and NTLM
  hashes lives. Display names, given and family names, phone numbers and coordinates are
  on no view: `Latitude` and `Longitude` are not on the hunting allowlist, so the
  structural claim holds without the backstop; `City` and `Country` are, because a
  sign-in's location is the substance of a travel alert. The user principal name and email are: they are the join keys of the
  investigation, and an investigation that cannot name the account cannot triage it.

  **Best effort by pattern.** A generic pass over every string of every view is the
  backstop for what an allowlisted column carries in free text, a command line above
  all: secrets by pattern (tokens, keys, private key blocks, password assignments and
  flags), secret-bearing and personal fields by name at any depth, and the same inside
  any string that is itself a JSON object or array. A secret that matches no pattern in a
  command line reaches the model. That is the residual risk, and it is stated rather
  than hidden.

  **The raw holds everything else**, out of context, by ref and hash. Redaction is a
  projection, not a destruction: an analyst with access to the artifact store sees what
  the model did not.
- Every tool call is journalled with id, timestamp, caller, arguments and a hash of the
  response. The audit trail reconstructs the investigation without replaying it.

## Human in the loop

`HumanInTheLoopMiddleware` with `interrupt_on` over `propose_alert_disposition`. The
nine read-only tools are auto-approved. The proposal pauses the graph with the proposed
verdict, action, escalation and summary in front of the analyst, and resumes with
`Command(resume=...)` on a checkpointer.

Two decisions are offered, accept and reject with an optional reason. Not edit: an
edited proposal would be the analyst's verdict in the model's mouth, and the harness
would then measure the analyst. On accept the tool runs and the proposal is journalled.
On reject the tool does not run, the model is told so with the reason, and it may
propose again or answer. Every decision is recorded on the run artifact with the
proposal it answered, so the artifact shows what was proposed and what the human did.

The agent never closes an alert. It prepares the investigation and proposes.

## Model independence

`init_chat_model("{provider}:{model}")` throughout, so Anthropic, OpenAI, Google, a
local model through Ollama, or any OpenAI-compatible server are interchangeable.
Capability detection goes through `model.profile` rather than trial and error, which
also decides `ProviderStrategy` versus `ToolStrategy` for structured output.

- The decision is made once per model from `profile["structured_output"]`: true means
  `ProviderStrategy`, anything else means `ToolStrategy`. LangChain's own automatic
  choice falls back to matching model names when a profile is missing; that fallback is
  not used here, because a strategy chosen from a name is a guess and a guess is what
  the profile exists to replace. A model with no profile gets `ToolStrategy`, which every
  tool-calling model supports.
- Provider packages are optional extras, not dependencies: `alert-forensics[anthropic]`,
  `[openai]`, `[google]`, `[ollama]`. A missing provider fails at start-up with the
  package to install named, before any tool runs.

The harness is not tied to a vendor.

## The agent graph

A LangGraph `StateGraph` with four nodes, built once per investigation around one
`ToolRunner`, so every tool the model calls is journalled by the slice 2 pipeline by
construction. The graph is compiled on a checkpointer so the interrupt can resume.

```
investigate  the create_agent subgraph: tools from the runner, the human-in-the-loop
             middleware, TriageResult as the response format
ground       validate_grounding(result, trace); route on the report
repair       the correction pass: fresh model call, repair instruction in, repairs out,
             applied to the result; back to ground
finish       set the outcome: completed, failed_ungrounded, or failed_error when the
             model produced no result
```

- The model sees the alert once, as the first user message, in its wire form after the
  generic redaction pass. Display names in the alert's evidence are erased there.
- Tools are exposed to the model with the request model's JSON schema and validated by
  the runner, not by LangChain. A call with wrong arguments must reach the journal as
  `invalid_arguments`; a validation error thrown before the runner would leave the call
  unjournalled.
- A `ToolCallRecord.step` is the index of the model turn that emitted the call, read
  from the messages the tool node sees. The tool's `ToolMessage` content is the
  record's `redacted_response`, verbatim, and its artifact is the record.
- One turn's tool calls run one at a time, in the order the model emitted them. LangGraph
  would run them on a thread pool, and then the journal order, the trace, and the raw
  store's file order would vary from run to run for the same script. A run is
  deterministic up to model sampling only if the harness adds no randomness of its own.
  Parallel calls still share a `step`; the trace says so.
- The checkpointer deserialises the project's own contract types and LangGraph's
  built-ins, listed by class, and refuses anything else. A checkpoint is data, and data
  does not get to name a class.
- The graph runs under a recursion limit. Exceeding it is `failed_error` of kind
  `budget`. Any exception out of the graph, a provider error, unparseable structured
  output, an exhausted script, is `failed_error` with the exception's kind and message,
  and the artifact is still written with the trace as it stood.

## The scripted client

The whole cost discipline rests on running without a model, and the graph is untestable
without a stand-in, so the scripted client is part of the graph slice, not the
evaluation slice.

- It is a `BaseChatModel`. It replays a script of turns, each either a set of tool
  calls with their ids, or a structured output payload. It implements `bind_tools` so
  `create_agent` binds it like any provider model, and it renders a structured turn the
  way the bound strategy expects: JSON content under `ProviderStrategy`, a call to the
  structured-output tool under `ToolStrategy`. Both strategies are therefore exercised
  by the same script.
- It declares a `profile`, so the strategy decision above is exercised on it rather
  than bypassed for it.
- It emits deterministic `usage_metadata` on every turn, so the usage path of the trace
  is exercised without a provider.
- A turn may be a callable that receives the messages so far and returns the turn. That
  is how the demo script cites the calls that succeeded rather than the calls it hoped
  would.
- A script that runs out is an error, and the run is `failed_error`. A script that
  cites an id it never emitted is how the correction loop is tested on both outcomes.
- No key, no network, nothing to configure.

## Scenarios

Eight, realistic, entirely synthetic. Context: investment bank, around 45 000
endpoints, Entra ID with hybrid AD, Defender for Endpoint, Splunk ES with risk-based
alerting.

1. Atypical travel, Paris to Amsterdam. It is the group SASE gateway. **False positive.**
2. Password spray on the tenant, one success, then a new MFA method and a mailbox rule.
   **True positive** with follow-on activity.
3. Mailbox forwarding rule to an external address, filtering on invoice, IBAN, swift,
   payment. Three users, same destination. **True positive**, payment fraud.
4. Encoded PowerShell on a production server. Configuration management agent, declared
   maintenance window. **Benign true positive**: document an exception on the triplet,
   do not disable the rule.
5. LSASS access blocked. Internal red team exercise, account on the exercise list.
   **Benign true positive**, and confirm the prevention worked.
6. Apparent Kerberoasting, 180 SPNs in 90 seconds. It is the credentialed vulnerability
   scanner. **Structural false positive**: requalify as tuning rather than close it for
   the fifty-second time this year.
7. **The trap.** An RMM tool blocked by the EDR, signed binary, VirusTotal 0 of 72. The
   tier-one reflex is to close it in ninety seconds. It is initial access: the relay is
   not the IT provider's, an `mshta.exe` from a mail client preceded it by six minutes,
   and the block only caught the second attempt. Red Canary documented sixteen abused
   RMM tools in 2025. **True positive.**
8. The reverse trap. 6.2 GB to personal cloud storage by an employee who has resigned.
   It is a personal photo folder, 94 percent image content type, no abnormal access to
   sensitive shares. **Benign true positive**, an HR matter, not a security incident.

Seven and eight are the point of the exercise: the obvious signal points the wrong way
in both directions.

## Using it

This is a tool, not only a demonstration. It installs as a console script and is usable
by someone who is not the author.

```
alert-forensics triage ALERT.json --model anthropic:claude-sonnet-5 --role analyst -o run.json
alert-forensics triage ALERT.json --scripted -o run.json
alert-forensics show run.json
alert-forensics replay run.json
alert-forensics eval
```

- `triage` reads a real Microsoft Graph `security.alert` v2 export, runs the
  investigation, and writes the run artifact: outcome, trace, grounding report, and the
  raw store directory beside it, named after the artifact. `--role` is `analyst` or
  `tier1`. `--max-corrections` overrides the default of one.
- `--scripted` runs the same graph on the scripted client with a built-in script
  derived from the alert's evidence. No key. The verdict of a scripted run is
  `inconclusive` by construction and its missing context says why: the script replays
  calls, it reasons about nothing. What it demonstrates is the mechanism: the journal,
  the grounding, the interrupt, the artifact. It is a plumbing check, not the front
  door; the front door for someone without a key is `replay`.
- The proposal interrupt is answered on the terminal, or ahead of time with `--accept`
  or `--reject REASON` when there is no terminal. A run with neither and no terminal
  stops with that message rather than deciding for the analyst.
- The nine fixtures ship inside the package, so an installed tool runs without the
  repository. `--fixtures DIR` points at another set.
- `get_attack_technique` is live against the public bundle in every mode, `--scripted`
  included: it is live-capable and needs no key, so a fixture there is a gap the
  example would fall into. When the bundle cannot be fetched the adapter falls back to
  the recorded excerpt that ships in the package, cut from the real bundle and holding
  every technique the eight scenarios declare, and the artifact's `adapters` field says
  `recorded` instead of `live`. A cached bundle counts as live: it is the real bundle.
  `lookup_ioc` is live when `VIRUSTOTAL_API_KEY` is set and fixture-backed otherwise.
- No example alert declares a technique the default adapter set cannot resolve
  offline. A test enforces it, so a scenario that lands with a technique missing from
  the excerpt fails the suite rather than the newcomer's first command.
- `show` prints an artifact readably: outcome, verdict and confidence, each grounded
  fact with its citations and the systems they resolved to, assumptions, missing
  context, the recommended action, the human decisions, and the ungrounded facts when
  the run failed.
- `replay RUN.json` reads a recorded artifact, verifies the raw store beside it against
  the recorded hashes, states the model and the date of the run, and prints it through
  `show`. Recorded runs live under `runs/<scenario>/`, and each is a recording of a
  real model run, never of the scripted client: a recording of the scripted client
  would be a fake demo, which is worse than none. A test refuses a committed recording
  whose model is the scripted client. The viewer over the same artifacts, and `eval`,
  are the next slice.
- The model is chosen with `--model provider:name` through `init_chat_model`, so any
  provider works, and so does a local model through Ollama.

Every tool sits behind a `ToolAdapter` interface that declares its required scope and
its response shape. Two adapters are genuinely live and need no SOC: `lookup_ioc`
against the VirusTotal v3 API with a free key, and `get_attack_technique` against the
public ATT&CK STIX bundle with no key at all. The other seven are fixture-backed and
their live contract is documented, so someone with a Defender or Splunk tenant ports
them rather than rewrites them.

The README states, per tool, which is live-capable and which is fixture-backed.
Claiming more than that is how this gets caught in an interview, and the honesty is
worth more than the claim.

## Demonstration

The harness produces numbers. The demonstration makes the mechanism visible.

A static replay viewer, served from committed run artifacts, with no backend and no API
key at runtime:

- Pick a scenario and watch the investigation step through: each tool call, its
  arguments, and the redacted response the model actually saw.
- The structured output rendered as three distinct blocks. Every observed fact carries
  its citation, and clicking it expands the exact tool response it rests on. The
  grounding is not claimed, it is inspectable.
- Missing context shown as a first-class block rather than as an absence.
- For scenario 7, a side-by-side view: the same alert, the same evidence, two model
  tiers, opposite verdicts.

That last view is the argument in one screen. The matrix page carries the rest.

## Evaluation

- Verdict accuracy, evidence recall, missing-context recall, escalation precision and
  recall.
- Failure rate, split by `RunOutcome`, reported beside accuracy as a first-class number.
  A failed run scores zero on every accuracy metric and is never counted as
  `inconclusive`.
- `ungrounded_claim_rate`, enforced to zero.
- Cost and latency per investigation, from `usage_metadata` aggregated by
  `UsageMetadataCallbackHandler`, the provider-agnostic path.
- N runs per cell, Wilson 95 percent intervals. Failed runs stay in the denominator, so
  a model cannot look good by staying silent or by failing quietly.
- Capture and replay: fixtures are frozen, so a run is deterministic up to model
  sampling and a regression is a real regression. Recorded runs under `runs/` are the
  captures; `replay` reads them and needs no key.
- A deterministic scripted client runs the whole suite with no API key.

## Cost discipline

The build runs entirely against the scripted client, so development costs nothing.
Before the comparison matrix, one cell is measured on real usage and the full cost
extrapolated. Prompt caching applies since fixtures and tool definitions are constant.
Where the budget does not carry the intended number of runs, the run is smaller and the
report says so, with the wider intervals visible.

All fixtures are synthetic, so no confidential data is involved at any point.

## Scope and limits

Stated up front, because a careful reader will find them.

- Read-only by design, with one gated proposal that writes nothing. This triages; it
  does not remediate.
- Two connectors are live, seven are fixture-backed. `lookup_ioc` talks to VirusTotal
  and `get_attack_technique` reads the public ATT&CK bundle. The other seven follow the
  real API shapes and document their live contract, so a tenant owner ports them rather
  than rewrites them, but nothing here talks to a production SIEM or EDR out of the box.
  The README says which is which, per tool.
- Eight scenarios and a finite taxonomy. Real alert queues are messier, noisier and
  ambiguous.
- Single tenant, single language, no fine-tuning.
