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

- Each tool keeps its raw upstream response in `ToolMessage.artifact`, which never
  reaches the model.
- The output schema requires `evidence: list[str]` of tool call ids on every observed
  fact.
- A validator resolves every id against the actual trace. An id that does not resolve
  makes the output invalid and the correction loop asks the model again.
- The metric `ungrounded_claim_rate` is enforced to zero rather than hoped for.

A claim that cannot be attached to a tool call is not a fact. It belongs in
`assumptions`, or it does not exist.

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

The model is used for what remains: hypothesis, pivot selection, weighing contradictory
signals, and writing the summary.

## Output schema

```
TriageResult
  verdict            true_positive | false_positive | benign_true_positive | inconclusive
  confidence         float
  mitre_techniques   [T####.###]  resolved deterministically, not invented
  observed_facts     [{statement, evidence: [tool_call_id], source_system}]
  assumptions        [{statement, why_unverified}]
  missing_context    [{what, why_it_matters, how_to_obtain}]
  recommended_action str
  escalate           bool
```

`benign_true_positive` is a first-class verdict because a SOC needs it: the detection
fired correctly and the intent was legitimate. Collapsing it into false positive is how
tuning decisions get lost.

## Tool surface, read-only

Shapes mimic real APIs so the code would port to a live environment.

| Tool | Modelled on |
|---|---|
| `search_events` | Defender advanced hunting, `schema[] {name,type}` plus `results[]` |
| `search_siem` | Splunk search v2, sid then results, SPL string in |
| `get_identity` | Splunk Asset and Identity framework, priority drives urgency |
| `get_asset` | same framework, device compliance and criticality |
| `lookup_ioc` | VirusTotal v3, JSON:API envelope, epoch dates, engine counters |
| `get_related_alerts` | Microsoft Graph `security/alerts_v2` |
| `get_process_tree` | `DeviceProcessEvents` lineage |
| `search_runbook` | internal knowledge, the retrieval component |
| `get_attack_technique` | ATT&CK STIX bundle, deterministic, not a model call |

Alerts follow the Microsoft Graph `security.alert` v2 shape, including the polymorphic
`evidence[]` discriminated by `@odata.type` and `mitreTechniques` as `T####.###`
strings, which is the natural join to ATT&CK.

## Access control, sensitive data, traceability

- Every tool declares a required scope. The agent runs under an analyst role. A call
  outside scope returns a structured denial the agent must handle, not an exception.
- Redaction runs before the model sees anything. Secrets, tokens and personal data stay
  in `artifact`. The model receives a redacted projection.
- Every tool call is journalled with id, timestamp, caller, arguments and a hash of the
  response. The audit trail reconstructs the investigation without replaying it.

## Human in the loop

`HumanInTheLoopMiddleware` with `interrupt_on`. Read-only tools are auto-approved. Any
write action, closing an alert, enriching a case, notifying, pauses the graph and waits
for an analyst decision, resumed with `Command(resume=...)` on a checkpointer.

The agent never closes an alert. It prepares the investigation and proposes.

## Model independence

`init_chat_model("{provider}:{model}")` throughout, so Anthropic, OpenAI, Google, a
local model through Ollama, or any OpenAI-compatible server are interchangeable.
Capability detection goes through `model.profile` rather than trial and error, which
also decides `ProviderStrategy` versus `ToolStrategy` for structured output.

The harness is not tied to a vendor.

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
- `ungrounded_claim_rate`, enforced to zero.
- Cost and latency per investigation, from `usage_metadata` aggregated by
  `UsageMetadataCallbackHandler`, the provider-agnostic path.
- N runs per cell, Wilson 95 percent intervals, failed runs counted as zero so a model
  cannot look good by staying silent.
- Capture and replay: fixtures are frozen, so a run is deterministic up to model
  sampling and a regression is a real regression.
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

- Read-only by design. This triages; it does not remediate.
- Connectors are mimicked, not live. The shapes follow the real APIs and the port is
  documented, but nothing here talks to a production SIEM.
- Eight scenarios and a finite taxonomy. Real alert queues are messier, noisier and
  ambiguous.
- Single tenant, single language, no fine-tuning.
