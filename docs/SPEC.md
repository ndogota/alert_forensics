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
`tool_call_id`s in the trace that a citation can succeed on. It does not get the
already-grounded facts, the trace, or the raw responses. The loop repairs citations; it is not a second
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
- **Present means citable.** The list holds only the calls whose outcome is `ok` and
  whose source system returns evidence. A denied call, a failed call, and the
  disposition proposal are left out. The list is the menu the second pass chooses from,
  and one correction attempt is the whole budget, so an id offered there that the
  validator will then refuse is the loop inviting the failure it exists to repair. The
  proposal is the worst of them: its record carries the model's own summary restating
  the verdict, which makes it the most tempting citation in the list and the one that is
  never evidence. This was found on the committed scenario 1 recording, whose
  instruction offered the proposal's id sixth; re-citing it would have ended the run
  `failed_ungrounded` with no pass left. The alternative, listing every call with the
  reason it cannot be cited, was rejected: the offending entries already say why each
  refused id was refused, and the second pass has nothing to do with a call it may not
  cite. The outcome stays on each entry and now reads `ok` throughout, because an
  artifact recorded before this rule shows lists that offered denied calls and the
  proposal, and the field is what lets a reader see that. A trace with no citable call
  gives an empty list; the only repair left is to withdraw, and the run fails as it
  should.
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
  model_limits       {timeout_s, max_retries} the model client was bounded with, or null
                     for the scripted client, which makes no network call
  output_binding     {strategy: provider | tool, profile_declared, structured_output}:
                     how structured output was bound, and the profile values that decided it
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
- `output_binding` records the resolved structured-output strategy and the profile
  values the decision read: whether the model declared a profile at all, and the value
  of `profile["structured_output"]` as read, null when absent. A recording that cannot
  say how its output was bound cannot be reproduced, and the model string alone does not
  say it: a profile changes with the provider package version.
- `model_limits` sits beside `model` because the two numbers change the latency the
  evaluation measures: a call that was allowed six retries with exponential backoff and
  a call that was allowed one are not the same measurement, even on the same model.
  The artifact records what was asked of the client, verbatim; what a provider does
  with it is the provider's, see model independence.
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

### The four verdicts

The first real model run reasoned correctly and labelled wrongly: it wrote that the
travel "does not indicate malicious impossible travel" and was a "known artifact of
corporate proxy routing", then returned `benign_true_positive` where the ground truth is
`false_positive`. The verdicts had no discriminating definition anywhere, so the label
was a coin toss between two values that both sounded right. Until the definition exists,
a comparison matrix measures the ambiguity of the prompt, not the capability of the
models.

A detection produces a signal, which is what its logic measured, and an assertion,
which is what it claims about the world. The signal is almost always true; a log line
really was written. The verdict turns on the assertion, never on the signal.

- `true_positive`: the assertion is true and the activity is malicious or
  unauthorised.
- `benign_true_positive`: the assertion is true and the intent was legitimate and
  authorised. The rule worked.
- `false_positive`: the assertion is false. The signal may be perfectly real and still
  support no such conclusion.
- `inconclusive`: the evidence does not decide, and `missing_context` names what
  would.

A verdict states what is true. What the SOC should do belongs in `recommended_action`,
which exists for it, and no definition above carries an action. Scenario 8 is the
reason: on the truth axis nothing separates six from eight, both are false positives
whose signal was real, and on the action axis everything does. Six tunes permanently,
by excluding the scanner's account from the ticket rule. Eight tunes nothing at all: a
rule that fires on a departing employee pushing 6.2 GB to personal storage is doing
exactly its job, a human looked and found photographs, and next time the 6.2 GB is
source code. A definition that said "tune" could not say that.

The two are separated because a claim read at the level of the signal is almost always
true, and a label that turns on it collapses false positives into benign true positives:
two geo-IP locations far apart in a short window is a true computation, and the
assertion drawn from it, that the person was in two places, is false. That is the error
the first real run made. The assertion is the state of the world the rule is named for,
at the granularity of the technique it detects, with intent left out: intent is the
other axis, and an assertion that included it would leave no room for a benign true
positive. The label must not depend on which sentence describes the alert.

The definition is an analyst's, and it lives in the system prompt as the definition of
the four values, in exactly these terms. Nothing scenario-specific goes beside it: the
taxonomy belongs in the prompt, the answer to any given alert does not. Every scenario's
ground-truth label is checked against this discriminator under "Scenarios", with the
signal and the assertion stated separately; a ground truth that contradicts its own
discriminator makes every accuracy number meaningless.

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
- **It comes after evidence, and it comes alone.** The first real model run proposed at
  step 0, in the same parallel batch as the first two evidence calls, before any result
  was back, and the analyst was asked to approve a verdict built on nothing. The
  definition declares two ordering rules, enforced in code and not in the prompt:
  `needs_evidence`, the tool is not offered to the model until at least one call with
  outcome `ok` exists in the trace; and `alone_in_turn`, it may never be emitted in the
  same turn as another tool call. Enforcement has two halves. A middleware filters the
  tool out of the bound tools while the trace holds no `ok` record, and when the model
  emits a call that breaks either rule it jumps the turn straight to the tool node, past
  the interrupt: a proposal that will be refused is not put in front of the analyst. The
  runner then produces an `OrderDenial`, the same shape as a scope denial with the rule
  in place of the scope, journalled with outcome `denied`; the model reads the rule and
  the sibling calls of the turn run normally. Scope is checked before order: who may
  propose at all comes before when.

The agent is told to propose before it answers. A run in which the model never
proposes still completes; the artifact's `decisions` list is empty and the evaluation
can count that.

### The tool layer

A tool call travels through one pipeline, whatever the adapter behind it:

1. Scope check. The principal's scopes are compared with the tool's declared scope. A
   miss produces a `ScopeDenial`, journalled with outcome `denied`. The adapter is never
   called.
2. Order check, for a definition that declares ordering rules. A call before any `ok`
   record, or beside another call in its turn, produces an `OrderDenial`, journalled
   with outcome `denied`. The adapter is never called. The runner learns the turn's
   sibling calls from the caller, since a call may run before its siblings are
   journalled.
3. Argument validation against the tool's request model. A miss is journalled as
   outcome `error`, kind `invalid_arguments`, with the validation message, so the model
   can correct the call.
4. The adapter fetches the raw upstream response. Any upstream failure, including a
   fixture that has no answer for the request, is journalled as outcome `error` with a
   structured `ToolFailure`. Nothing raises into the agent.
5. The raw response is stored out of context and referenced from the record by
   `raw_response_ref` and `raw_response_sha256`. It is stored whether or not it
   validates against the response shape: a malformed response is still evidence.
6. The raw response is validated against the response shape, projected to the tool's
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
- Fixture adapters match a request against stubs: an exact value, `$contains`,
  `$regex` or `$any` per argument, or `$all`, a list of those that must every one hold,
  so a stub can require both the shape of a request and the entity it names in one
  place a reviewer reads. A request no stub answers is an `error` of kind
  `no_fixture`, never a silent empty result, so a fixture gap shows in the trace
  instead of being read as absence of evidence. **There is no fixture default.** The
  format once allowed one, and five of the nine fixtures declared an empty one, which
  contradicted the sentence before it and won in code: a request the stubs did not
  anticipate was answered with an empty result that the model read as a reading. The
  committed scenario 1 recording shows it twice. The model queried the runbook with
  "VPN SASE corporate egress proxy Amsterdam Paris", the stub matched only the phrase
  "atypical travel", and the default answered no hits, on the one source that says what
  the egress address is. It asked for the identity of `jdoe@contoso.com`, the stub
  matched only `jdoe`, and the default answered that the identity was not found. Neither
  was a reading; both were gaps, and the trace filed both as `ok`. A default cannot tell
  a reading nobody has seen from a query nobody anticipated, and the second is exactly
  what the trace must show. A real empty reading, an indicator VirusTotal has never
  seen, a user with no related alerts, is a stub whose match names the request it
  answers, so it is a declared reading a reviewer sees in the file, the way
  `never-seen.example` already is. None of the five defaults was that: each answered
  every request its stubs missed, including a variant spelling of the alert's own
  entities, so all five are removed and a fixture file that declares a default refuses
  to load. For the same reason a stub must constrain at least one argument: an empty
  match, or one whose every value is `$any`, is a default under another name and is
  refused too. What the model sees on a gap is the same structured failure any error
  gets, kind `no_fixture` and the arguments it sent, so it can rewrite the request or
  say what it could not obtain; and the trace says the harness, not the world, ran out.
- **A stub on a free-text request answers only questions about the entities its
  response holds.** For a query tool, `search_events` and `search_siem`, the match
  requires the query to name the principal entity of the rows it returns, an account,
  a device, an indicator, an action type, and not only the table or the index: a table
  name is a shape, and a shape matches every user. For the runbook, the match requires
  the query to name the entry's subject, the alert type its title names or a proper
  entity the entry names, a product, a range, an address, and never a generic
  infrastructure word such as egress, gateway, proxy or VPN, which every scenario's
  questions use. The reason is the one thing this project sells. An empty result is
  visibly nothing; a wrong result is indistinguishable from evidence. A fact built on
  another user's sign-in rows cites a call whose outcome is `ok`, the validator grounds
  it, the run completes, and the harness scores a fact about the wrong person as a
  reached finding, with no mark anywhere in the trace. The widening that replaced the
  defaults did exactly this on both free-text tools: the sign-in stub keyed on the
  table name answered a query about `mmartin@contoso.com` with jdoe's rows, and the
  runbook stub keyed on infrastructure words answered a question about an RMM relay,
  and one about a Kerberoasting scanner, with the atypical-travel entry at score 0.91.
  The rule that a stub must constrain at least one argument does not catch it, since
  the table is an argument. The three entity tools already obey it by construction,
  because their request is the entity. What is structural and what is not, stated:
  no default and at least one constraint are held by the loader; this rule is not,
  because the loader cannot read what a query is about, so it is held on the shipped
  fixtures by tests that ask each free-text stub about another account and another
  subject and require `no_fixture`, and every scenario's stubs arrive with those tests.
  The cost is a narrower hit: a query that names the table and not the account, or
  the runbook asked about egress points without naming the travel alert or the SASE
  product, is a visible `no_fixture` error the model can rephrase, and that is the
  right side to err on.
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

A proposal that breaks the ordering rules of the write action never reaches the
analyst: the turn jumps past the interrupt to the tool node, and the runner's denial is
what the model reads. The analyst decides on proposals, not on the model's mistakes.

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
  tool-calling model supports. The resolution is recorded on the artifact as
  `output_binding`, so a reader sees the strategy and the values that chose it.
- Provider packages are optional extras, not dependencies: `alert-forensics[anthropic]`,
  `[openai]`, `[google]`, `[ollama]`. A missing provider fails at start-up with the
  package to install named, before any tool runs.

- **Every model call is bounded.** `timeout` and `max_retries` are passed through
  `init_chat_model` to the provider client, from `--timeout` (default 60 seconds) and
  `--max-retries` (default 1). Without them the Google client retries a 429 or a 503
  six times with exponential backoff and says nothing, and the first real run of this
  project sat silent for minutes before failing: a rate limit, a slow call and a freeze
  were indistinguishable. The two values are passed verbatim and recorded verbatim on
  the artifact. Providers do not agree on what `max_retries` counts: Anthropic and
  OpenAI count retries after the first attempt, Google counts attempts including the
  first, so `1` there means no retry at all, and Ollama accepts neither knob and runs
  unbounded. The harness does not translate between them; a translation table would
  be a guess per provider, and the artifact would then record a number the client
  never saw.
- **A provider refusal is named as such.** When the client raises after its retries
  are spent because the provider would not serve the call, a rate limit or quota
  (HTTP 429, `ModelRateLimitError`) or an overloaded model (HTTP 503 or 529), the
  run is `failed_error` with the error kind `rate_limit` or `overloaded`, not the
  exception's class name. The classification reads the LangChain error class first,
  then the status code the exception carries, then the message, in that order, so a
  provider whose client does not yet map onto LangChain's error classes is still
  named. Any other exception keeps its class name as the kind, as before.

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
  and the artifact is still written with the trace as it stood. A provider refusal is
  the one exception whose kind is not its class name: `rate_limit` or `overloaded`,
  see model independence.
- The runner accepts a callback that receives every `ToolCallRecord` as it is
  journalled. That is how the console script shows progress: the runner already holds
  every record, so progress is a view over the journal, not a second source of truth.

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
   sensitive shares. **False positive**: the upload is real, and no organisational data
   left, so exfiltration is not supported. The rule is not at fault and is not tuned;
   the finding is routed to HR as personal use of a corporate device. See the table
   below for why this is not benign.

Seven and eight are the point of the exercise: the obvious signal points the wrong way
in both directions.

Every label, checked against the discriminator under "The four verdicts". The signal
is what the rule's logic measured; the assertion is what it claims about the world, at
the granularity of the technique it detects, with intent left out. The signal is true in
every row. The verdict turns on the assertion, then on intent.

| # | Signal measured | Assertion made | Assertion true? | Intent | Label |
|---|---|---|---|---|---|
| 1 | Two sign-ins by one user whose source IPs geo-locate to Paris and Amsterdam, 40 minutes apart | The person, or their credentials, was used from two places they could not both have been | No: one egress, the SASE gateway; the geo-IP of a gateway is not where the person is | n/a | false_positive |
| 2 | Many failed sign-ins across many accounts from few sources, then one success | Credentials were guessed at scale and an account was taken over | Yes: the success is followed by a new MFA method and a mailbox rule | Unauthorised | true_positive |
| 3 | Inbox rules created that forward to one external address, filtering on payment terms | Mail is being diverted outside the organisation | Yes: three users, one destination, invoice and IBAN filters | Unauthorised, payment fraud | true_positive |
| 4 | `powershell.exe` launched with an encoded command on a production server | An obfuscated command was executed on the server | Yes: the command was encoded, whoever ran it | Authorised: configuration management agent, declared window | benign_true_positive |
| 5 | A process opened LSASS with read access and was blocked | A process attempted to read credentials from LSASS memory | Yes: the attempt was made, and prevented | Authorised: red team, account on the exercise list | benign_true_positive |
| 6 | One account requested service tickets for 180 SPNs in 90 seconds | Service tickets were harvested to crack service-account passwords offline | No: the credentialed scanner obtained tickets to authenticate to the services it scans; nothing was harvested for cracking | n/a | false_positive |
| 7 | The EDR blocked a signed remote-management binary with a clean reputation | A remote-management tool was executed on the endpoint | Yes: the block caught the second attempt; the first ran, to a relay that is not the IT provider's, six minutes after `mshta.exe` from the mail client | Unauthorised, initial access | true_positive |
| 8 | 6.2 GB uploaded to a personal cloud storage domain by a user on the leaver list | Organisational data was moved out to personal storage by a departing employee | No: the folder is personal photographs, 94 percent image content type, and no sensitive share was touched. The rule is not at fault and is not tuned; the finding goes to HR | n/a | false_positive |

**One label moves: scenario 8, from benign true positive to false positive.** Read at
the level of the signal, a departing employee did upload to personal storage, and that
is the sentence under which the label was benign. Read at the level of the assertion,
the rule is named for exfiltration, and exfiltration is organisational data leaving;
none did. The operational test is whether the technique the rule names actually
occurred: encoded PowerShell did, an LSASS read did, Kerberoasting did not,
exfiltration did not, travel did not. All eight fall out of that without depending on
phrasing. Six is the same shape as eight: a sanctioned actor produced the exact volume
the rule measures without performing the technique the rule is named for, and if eight
were benign because the upload really happened, six would be benign because the tickets
really were requested. The two part on the action axis, not the truth axis. Six tunes
permanently by excluding the scanner's account. Eight tunes nothing: the rule did its
job, the human looked, and the finding is routed to HR. Eight stays the reverse trap:
the obvious signal still points at an incident, and it is not a security incident.

Seven is the mirror of one: a signed binary and a clean reputation make the assertion
no less true, as a gateway's geo-IP makes the travel no more real. Four holds because
encoding is a property of the command, not of who ran it: the assertion is true and
the intent decides. Five holds the same way.

## Using it

This is a tool, not only a demonstration. It installs as a console script and is usable
by someone who is not the author.

```
alert-forensics triage ALERT.json --model anthropic:claude-sonnet-5 --role analyst -o run.json
alert-forensics triage ALERT.json --scripted -o run.json
alert-forensics show run.json
alert-forensics replay run.json
alert-forensics eval --scripted
alert-forensics eval --model anthropic:claude-sonnet-5 --runs 3
alert-forensics eval-report results/
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
  whose model is the scripted client. `eval` and `eval-report` are described under
  "Evaluation"; the viewer over the same artifacts is the next slice.
- The model is chosen with `--model provider:name` through `init_chat_model`, so any
  provider works, and so does a local model through Ollama.
- `--timeout SECONDS` (default 60) and `--max-retries N` (default 1) bound every model
  call, passed through to the provider client and recorded on the artifact as
  `model_limits`. They exist because the alternative was verified: a client left on its
  defaults retries a rate limit in silence for minutes.
- While the investigation runs, one line per journalled tool call goes to stderr: the
  step, the tool name, the outcome and the duration. stdout carries the result line
  alone, so `triage ... | jq` and redirection keep working. `--quiet` suppresses the
  progress. Nothing is printed between launch and the first tool call, and nothing
  between the last and the result line; that is why the model call itself is bounded.
- The Google client logs one warning per tool, twice, for a JSON schema key it does not
  support and ignores. The console script filters that one message at startup. It is
  the library's note to itself, not a fault in the run, and a tool that opens with
  twenty-two lines of it reads as broken.
- A run the provider refused to serve, a rate limit, a quota, or an overloaded model,
  after the retries were spent, ends with a message on stderr naming the provider, the
  model, and the fact that it is the provider's capacity and not a bug in the run, and
  the exit code is 3. The artifact is still written, with `error.kind` `rate_limit` or
  `overloaded`. Exit codes: 0 completed, 1 the run failed on its own account
  (`failed_ungrounded`, or `failed_error` of any other kind), 2 usage or configuration,
  3 the provider refused. A silent wait is the one behaviour a CLI must never have.

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

The harness produces the numbers the project exists for. Every decision below was taken
before the seven remaining scenarios were written, because the scorers decide what a
scenario file must contain: seven ground truths written against a schema nobody had
exercised would all be rewritten once the first score came out.

### Ground truth as a contract

One `GroundTruth` file per scenario, beside its alert: `examples/<scenario>.alert.json`
and `examples/<scenario>.truth.json` share the stem, and the stem is the scenario's name
everywhere else, under `runs/` and under the results directory.

```
GroundTruth
  scenario           the file stem; the loader refuses a file whose stem disagrees
  alert_id           the alert's id; the loader refuses a pair whose ids disagree
  verdict            Verdict, the label from the table under "Scenarios"
  escalate           whether the investigation is expected to escalate
  required_findings  [{name, tools: [tool_name], tokens}]
  missing_context    [{name, tokens}]

tokens               [token], each token a string or a list of alternative strings
```

- `alert_id` is on the truth so that the pairing is checked, not assumed: a truth file
  copied beside the wrong alert fails to load rather than scoring the wrong scenario.
- `tools` names tools from the tool surface, validated against the registry; the write
  action is refused there, since its record is never evidence and a finding resting on
  it could never be carried by a grounded fact. One entry is the common case. Several
  entries mean the same fact can be established from more than one system, as a
  sign-in can be read from the hunting API or from the SIEM; the finding is reached
  through any of them. Several entries are not a hedge: a tool is listed only when its
  reading carries the finding's words. Scenario 1's gateway finding was the first
  example here and is no longer one, because VirusTotal's reading of the egress
  address carries an owner name and a network range, and not, in any word of it, what
  the address is; see the scenario for the check against the fixture.
- Names are unique within a file and appear in the score, so a miss is reported by name.

**A required finding is matched against an emitted fact by tool and by tokens, never by
a model.** A finding cannot reference a `tool_call_id`, which is generated per run, so
the match is defined on what a run does preserve: which tool a fact cites, and what its
statement says. A finding is reached when at least one observed fact satisfies both:

1. The fact is grounded, and among the calls it cites there is one whose `tool_name` is
   in the finding's `tools`. Grounding is required first: only a grounded fact carries a
   finding, so a fact that says the right thing on a citation that does not resolve is
   not credited. The tool is read from the trace record the citation resolves to, never
   from the statement.
2. The fact's statement contains every token, as whole words. Statement and token are
   both read as a sequence of words: split on whitespace, each word stripped of the
   punctuation at its ends, compared case-insensitively. A token is present when its
   words occur contiguously among the statement's words. A token that is a list of
   alternatives is satisfied by any one of them, so `["SASE", "VPN", "gateway"]` reads
   "one of these"; the list is small on purpose and is written out in the file where a
   reviewer sees it.

**A token never matches inside a larger word.** The first version of this rule was a
substring test, and it credited the committed scenario 1 recording with the gateway
finding on the token `SASE` found inside `EXAMPLE-SASE-NET`, the ASN owner name
VirusTotal returned. The model had copied a name; it never said gateway, and the finding
that carries the whole verdict was reached on letters the model did not choose. Under a
substring rule a token can be fitted to whatever the fixture happens to name, and a
truth file written after a recording exists, as scenario 1's was, will be. Whole words
make a token a claim the statement made. The cost is stated rather than hidden: a
plural, a possessive and a hyphenated compound are different words, so `log` does not
match `logs` and `SASE` does not match `EXAMPLE-SASE-NET`; where the truth author wants
them, they are listed as alternatives, in the file, where a reviewer sees them.
Punctuation at the ends of a word is stripped, so `Paris,` and `(EXAMPLE-SASE-NET)` are
the words they wrap; punctuation inside a word is part of it, so `203.0.113.7` is one
word that `203.0.113` does not match, and `T1078.004` is not `T1078`. A token that
normalises to no word at all could never match, and the loader refuses it.

The match is deterministic and a human can see why it passed or failed: the score names
the finding, the tokens it missed, and the facts it examined. A model judge would put a
model back inside the measurement, which is the thing this project exists to avoid, and
its misses would not be inspectable. The cost is that tokens are a literal floor: a fact
that establishes the finding in words the tokens did not anticipate is a recall miss.
That miss is visible by name, and widening the tokens is a decision a person reviews in
a diff. A judge's miss is neither.

An expected missing-context entry is matched the same way, on tokens alone: an entry is
named when at least one `missing_context` item contains every token across its `what`,
`why_it_matters` and `how_to_obtain` joined by a space. There is no tool to anchor to,
since missing context is by definition what no call established.

### Scorers

Each run is scored on its own into a `RunScore`, from its artifact and the scenario's
ground truth, and the cell numbers are built from the run scores. A `RunScore` is fully
derived: it can be recomputed from the artifact and the truth file at any time, which is
what `eval-report` does, so a ground truth corrected after a cell was run re-scores the
cell without running the model again.

- **Verdict accuracy.** Exact match of the four values, no partial credit. A run scores 1
  or 0, and the cell number is the proportion of runs scoring 1.
- **Evidence recall.** Required findings reached over required findings, counting only
  findings carried by a grounded fact. The cell number pools the pairs: reached
  findings summed over runs, over required findings times runs.
- **Missing-context recall.** Expected entries named over expected entries, pooled the
  same way.
- **Escalation precision and recall.** A run is a predicted escalation when it completed
  and its result escalates; it is an expected escalation when its ground truth says so.
  Recall is correct predictions over expected escalations; precision is correct
  predictions over predicted escalations. A failed run predicts nothing, so it never
  enters the precision denominator, and it is a missed escalation wherever one was
  expected. A cell with no expected escalation has no recall, and one with no predicted
  escalation has no precision; both are reported as absent, never as zero or one.
- **`ungrounded_claim_rate`.** Zero on a completed run by construction: the artifact
  refuses to validate otherwise. It is reported anyway, pooled over the facts of the
  completed runs, as the check that the loop did its job, and the summary carries a flag
  that says whether it held.

The pooled proportions treat every (finding, run) pair as one trial. Pairs from one run
are not independent, so the interval on a pooled recall is narrower than the truth; it is
reported as such, and the run count beside it says how much weight to give it.

### Failure is a first-class number

A run whose outcome is `failed_ungrounded` or `failed_error` scores zero on every
metric: verdict wrong, no finding reached, no missing context named, no escalation
predicted. It stays in every denominator. The failure rate is reported beside accuracy,
split by outcome and, for `failed_error`, by error kind, and it is never folded into
accuracy and never dropped. A model that fails a third of its runs cannot show a clean
accuracy on the rest: its accuracy denominator is all of its runs.

### Statistics

N runs per cell, configurable with `--runs`, default 3: small, because the build runs on
the scripted client and a real cell costs money, and the intervals say what three runs
are worth. A cell is one model under one role on one scenario.

Every proportion is reported as a `Proportion`: numerator, denominator, point estimate,
and the Wilson 95 percent interval. The interval is computed in code, with the formula
in the docstring, and never approximated with a normal interval: at n of 3 the normal
interval is meaningless and the Wilson interval is not. A proportion with an empty
denominator has no estimate and no interval, and is reported as absent. The interval
appears everywhere the point estimate does, in the summary file and in the printed
report, so a number cannot be read without its width.

### Cost and latency

Both per investigation, and neither on the contracts.

- **Cost** is derived at report time from the trace's `ModelUsageRecord` entries and a
  price table that lives in the evaluation package, keyed by the `provider:model` string,
  with the rate per million tokens for input, output, cache reads and cache writes, and
  the source and date of each row. The artifact carries tokens, never money, so a price
  change never rewrites an artifact. A model absent from the table has no cost, and the
  report says "no price for", never zero. The scripted client is in the table at zero,
  explicitly.
- **Latency** is the wall clock the harness measured around the investigation, recorded
  in the harness's own per-run file. It is not on the artifact, because a `triage` run
  answers the proposal interrupt on a terminal and its wall clock would include the
  analyst's deliberation; the harness answers every proposal instantly, so its clock
  measures the investigation alone. The proposal is accepted in every run: the human
  decision is not what the harness measures, and rejecting it would change what the
  model does next.

### The CLI

```
alert-forensics eval --scripted [--runs N] [--results DIR] [--scenario NAME]
alert-forensics eval --model provider:name [--role ROLE] [--runs N] [--results DIR] ...
alert-forensics eval-report DIR
```

- `eval` runs every scenario under `examples/` (`--scenario` narrows it) N times each
  and writes one directory per run: `DIR/<model>/<role>/<scenario>/<k>/` holding
  `run.json`, the same artifact `triage` writes, readable by `show` and `replay`;
  `run.raw/`, its raw store; `eval.json`, what only the harness knew, the scenario, the
  cell, the index, and the measured wall clock; and `score.json`, the `RunScore`. The
  model string is made a directory name by replacing the characters a path cannot carry.
  Every run keeps its artifact, whatever its outcome, so a failed run is inspectable,
  and a second invocation into the same directory continues the numbering rather than
  overwriting: a cell accumulates, and nothing measured is lost to a rerun.
- After the runs it writes `DIR/summary.json`, one `CellSummary` per cell found under
  the directory, and prints the report. The summary is derived from the run directories
  and can be recomputed at any time; `eval-report DIR` recomputes it, re-scoring every
  run from its artifact and the current ground truth, rewrites `score.json` and
  `summary.json`, and prints the report. Cells from several sessions in one directory
  are summarised together, since the summary reads whatever is there.
- `--scripted` runs the whole suite with no key and no network, on the built-in script,
  which is how the test suite exercises it. Its verdict is `inconclusive` by
  construction, so its verdict accuracy is zero on every scenario whose label is not
  inconclusive; that is the floor the harness measures, not a defect in it.
- `--model` runs it for real; `--timeout`, `--max-retries`, `--max-corrections` and
  `--role` mean what they mean for `triage`. A provider refusal is a `failed_error` run
  with kind `rate_limit` or `overloaded`, counted like any failure; the harness goes on
  to the next run rather than stopping, and the summary shows the kind.

### Scenario 1, the first ground truth

Checked against the table under "Scenarios": the signal is two sign-ins geo-located to
two cities, the assertion is that the person was in two places, and the assertion is
false because both sign-ins egress from the group SASE gateway. Label `false_positive`,
no escalation.

- Required findings, three: the Paris sign-in from `203.0.113.7`, the Amsterdam sign-in
  from `203.0.113.7`, each cited from `search_events`; and that the address is the SASE
  gateway, cited from `search_runbook`. Two findings for the two sign-ins rather than
  one for "both", because a fact that names each sign-in with its address has
  established the shared egress in a form the tokens can see, while "both" has too many
  spellings to enumerate honestly.
- The gateway finding is carried by the runbook alone. Checked against the fixtures
  under whole-word matching: the runbook excerpt reads "The group SASE gateways egress
  from 203.0.113.0/24 (Amsterdam) and 198.51.100.0/24 (Paris)", which carries `SASE`,
  `gateways`, `egress` and the range as whole words. VirusTotal's reading of the address
  carries `EXAMPLE-SASE-NET` as the owner and `203.0.113.0/24` as the network, and no
  field of it holds the word `SASE` or any of `gateway`, `gateways`, `egress`, `proxy`.
  A fact citing `lookup_ioc` that says the address is a gateway says more than its
  source does; that inference belongs in `assumptions`, and a finding must not reward
  it as a fact. `lookup_ioc` was listed until this check and is dropped.
- Its tokens: the address or the runbook's range, `203.0.113.7` or `203.0.113.0/24`,
  since the runbook names the range and a model restating it for the alert's address
  names the address; the word `SASE`; and one of `gateway`, `gateways`, `egress`,
  `proxy`, the runbook's own words and the two a model most plausibly restates them
  with. Its first tokens were `203.0.113` and `SASE`, fitted to the recording: the
  prefix matched inside the address and `SASE` matched inside the owner name, and a
  fact that only copied the ASN owner was credited with saying the address is a
  gateway. That is the case the whole-word rule above was decided on.
- The scenario's stubs answer the requests a model plausibly makes about this
  scenario's entities, and nothing else, under the free-text rule decided under the
  tool layer. The sign-in stub requires both a sign-in table, any of `SigninLogs`,
  `AADSignInEventsBeta` and `IdentityLogonEvents` since the model chooses the table,
  and the account `jdoe`, since the rows are jdoe's; a sign-in query about another
  account is a `no_fixture` error, not jdoe's rows. The runbook stub requires the
  entry's subject: the alert type, `atypical travel` or `impossible travel`, the
  product `SASE`, or one of the two ranges the entry names; a question about another
  scenario's subject, an RMM relay or a Kerberoasting scanner, is a `no_fixture` error,
  not this entry. The cities and the words egress, gateway, proxy and VPN were matched
  for one commit and are not any more: they are where the gateway sits and what a
  gateway is, and every scenario's questions use them. The identity stub matches the
  account name and its UPN, since the alert carries both and the model may ask with
  either. Checked against the committed recording: its sign-in query names
  `jdoe@contoso.com`, its runbook query names `SASE`, its identity request names the
  UPN, and all three still hit; a test replays the three requests from the artifact
  itself so the check cannot drift from the recording.
- Expected missing context, two: the gateway or VPN session log that ties the user to
  the gateway at both times, which no tool provides; and the MFA or device compliance
  outcome, which the runbook checklist asks for and the sign-in view does not carry.
- The committed recording under `runs/atypical_travel/` scores verdict 1, evidence
  recall 2 of 3, missing context 0 of 2, escalation correct. The gateway finding is not
  reached, and the trace says why. The model queried the runbook with "VPN SASE
  corporate egress proxy Amsterdam Paris", the right terms for the entry that answers
  it, and the fixture's default answered no hits because the stub matched only the
  phrase "atypical travel". It asked for the identity of `jdoe@contoso.com` and was
  told the identity was not found, for the same reason. With the runbook silent, the
  only citable source left for the gateway was VirusTotal, and the model wrote what
  VirusTotal says: "IP address 203.0.113.7 belongs to the ASN 64496 (EXAMPLE-SASE-NET)
  network range", which names the owner and never says the address is a gateway. It
  did not invent the gateway on that citation, which is the right behaviour. Under the
  substring rule it scored 3 of 3, on `SASE` inside the owner name. So the recall
  number measures a fixture gap the default hid, not the model: on this recording 2 of
  3 is a floor on what the model does with the evidence it was actually handed, and the
  fixture is now corrected as above. The number stands until the scenario is re-recorded
  under the corrected fixtures, and the recording is kept as it is, since a recording is
  a real run and this one is the run that found the defect. The missing-context zero is
  the model's: it named nothing it could not establish, and it had been told the runbook
  was empty and the identity unknown without naming either as unobtained.

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
