# Recorded runs

One directory per recording, `runs/<scenario>/<recording>/`, each holding `run.json`,
the run artifact, and `run.raw/`, the raw tool responses its trace refers to by ref and
hash. `alert-forensics replay runs/<scenario>/<recording>/run.json` verifies the raw
store and prints the run.

Every recording here is a real model run. The artifact states the model (`model`) and
the date (`trace.started_at`). The test suite refuses a recording made with the scripted
client, one the provider refused, before any turn or after work, which the artifact
says as `refused`, and one with no model turn. A served run in which the model called
no tool is a recording: it refers to no raw response, so no `run.raw/` sits beside it,
and `replay` says so. Which runs are committed is a rule, stated in
`docs/SPEC.md` under "Using it": a run the spec cites, or the scenario's demonstration
run, the first completed real run on the scenario in the order the runs were made.
A recording is named for the directory it was copied from, and the name says which
campaign. `campaign-<k>` is the run directory `<k>` of the first campaign, 2026-09-15,
under `results/google_genai-gemini-3.5-flash-lite/analyst/<scenario>/`, artifact and
raw store copied unchanged; the results directory itself is not committed. For
scenarios 7 and 8 that run directory is the gate run of "One real run before a cell is
paid for", the only real run each had in that campaign. `campaign-<nn>-<k>` is run
directory `<k>` of the campaign `campaigns/<nn>/`, under the same model, role and
scenario path, copied the same way; `campaigns/` is not committed either, and the
campaign's `eval.json` and `score.json` stay behind, since a recording is the run and
its score is re-derived from the artifact. `probe-<name>` is run directory `0` of the
gate directory `gates/probe-<name>/` of 2026-09-15, under the same model, role and
scenario path, copied the same way; `gates/` is not committed either.

Fifteen are runs of `google_genai:gemini-3.5-flash-lite` under the `analyst` role. The
three named `probe-` are the gate runs of the priced tiers on scenario 1, under
`analyst`, made on 2026-09-15 between 17:04 and 17:20 UTC.

- `runs/atypical_travel/defaults-2026-09-14/`: the first recording, 2026-09-14, made
  before the `no_fixture` rule, the whole-word tokens and the label binding. Completed,
  verdict right, evidence recall 2 of 3. It is the run that found the fixture-default
  defect: the runbook and the identity answered its questions with empty defaults, and
  the trace filed both as `ok`. Kept as it is, since it is cited for that.
- `runs/atypical_travel/campaign-0/`: the demonstration run, 2026-09-15. Completed,
  verdict right, evidence recall 1 of 3: one fact for both sign-ins, naming neither
  city.
- `runs/atypical_travel/probe-gpt-5-nano/`: `openai:gpt-5-nano`, the first OpenAI gate
  run, 17:05 UTC, cited for the strict binding and for the asset question.
  `failed_error` of kind `StructuredOutputValidationError`: the output schema was bound
  without the strict flag, the model returned a `summary` key the schema forbids on its
  second turn, and no pass was left. Seven tool calls, six `ok`; asked `get_asset` for
  `203.0.113.7` and was refused, a gap closed since.
- `runs/atypical_travel/probe-gpt-5-nano-strict/`: `openai:gpt-5-nano`, the strict
  probe, 17:18 UTC, cited for the strict binding. Bound with `strict=True` by a script
  that replaced the strategy for that run, so the artifact records no flag; the API
  accepted the schema. Completed, verdict `inconclusive` against `false_positive`,
  evidence recall 0 of 3, missing context 2 of 2, escalated. Six tool calls, all `ok`,
  none to the hunting API or the runbook.
- `runs/atypical_travel/probe-sonnet-5/`: `anthropic:claude-sonnet-5`, the Anthropic
  gate run, 17:04 UTC, cited for the asset question. Completed, verdict right, evidence
  recall 3 of 3, missing context 1 of 2. Seven tool calls, six `ok`; asked `get_asset`
  for `203.0.113.7` in its second turn, after the runbook had named the range, and was
  refused, a gap closed since.
- `runs/cloud_upload/campaign-0/`: the demonstration run, and the gate run, 12:26 UTC.
  Completed, verdict `benign_true_positive` against `false_positive`, evidence recall
  0 of 5, missing context 0 of 2. Three tool calls: one hunting query for dlarsen's
  cloud-app events, answered; the ATT&CK lookup; the proposal. It never queried the
  SIEM, the identity or the runbook, so four of the five findings rested on readings it
  never asked for.
- `runs/encoded_powershell/campaign-3/`: the demonstration run. Completed, verdict
  right, evidence recall 2 of 4, two tool calls.
- `runs/forwarding_rule/campaign-3/`: the demonstration run. Completed, verdict right,
  evidence recall 1 of 5, missing context 1 of 2.
- `runs/kerberoasting/campaign-0/`: the demonstration run. Completed, verdict right,
  evidence recall 2 of 3.
- `runs/lsass_access/campaign-3/`: cited for the silence rule. `failed_ungrounded`:
  the first pass cited the runbook entry's id and the alert's own id, the repair
  withdrew every fact, and the result asserted `benign_true_positive` at confidence 1.0
  with no observed fact. Two runbook questions refused, `purpleops` and `PurpleOps`.
- `runs/lsass_access/campaign-4/`: the demonstration run, and cited for the runbook
  gap. Completed, verdict right, evidence recall 0 of 4: three runbook questions
  refused, `purpleops`, `PurpleOps` and `rt-cred`, and the hunting API and the SIEM
  never asked.
- `runs/lsass_access/campaign-5/`: cited for the silence rule. `failed_ungrounded`:
  the first pass cited the alert's own id three times, the repair withdrew every fact,
  and the result asserted `true_positive` at confidence 0.9 with no observed fact. Two
  runbook questions refused, `PurpleOps` and `purple`.
- `runs/password_spray/campaign-3/`: the demonstration run, and cited for the address
  pivot. Completed, verdict right, evidence recall 1 of 4. Asked the runbook for the
  bare address `192.0.2.44` and was refused.
- `runs/password_spray/campaign-5/`: cited for the address pivot. Completed, verdict
  right, evidence recall 1 of 4. Asked the hunting API twice what `192.0.2.44` had done
  and was refused both times.
- `runs/rmm_block/campaign-0/`: cited for the silence rule and for the gate, 12:25
  UTC. `failed_ungrounded` in 2.35 seconds with zero tool calls: the model read the
  alert, asked nothing, and asserted `benign_true_positive` at confidence 0.8 with no
  observed fact. There is no `run.raw/`: the trace refers to nothing. It is the trap
  the scenario is written for, closed in seconds rather than ninety.
- `runs/rmm_block/campaign-02-3/`: run 3 of the second campaign, 14:20 UTC, under
  fixture digest `a1861664…`, the fixtures of commit 34bc77c, which predate the current
  ones; cited by scenario 7's section, since no stub reached a run that asked nothing.
  `failed_ungrounded` with zero tool calls: `benign_true_positive` at confidence 0.85
  with no observed fact, one assumption and one missing-context entry. No `run.raw/`.
- `runs/rmm_block/campaign-02-4/`: run 4 of the second campaign, 14:21 UTC, same
  digest, cited the same way. `failed_ungrounded` with zero tool calls:
  `benign_true_positive` at confidence 1.0 with no observed fact, no assumption and no
  missing-context entry, the only one of the seven runs on this scenario that named
  nothing it did not know. No `run.raw/`.
- `runs/rmm_block/campaign-02-5/`: run 5 of the second campaign, 14:21 UTC, same
  digest, cited the same way. `failed_ungrounded` with zero tool calls:
  `benign_true_positive` at confidence 0.9 with no observed fact, one assumption and
  one missing-context entry. No `run.raw/`.

The gaps named above are closed since 2026-09-15 and each refused request is replayed
from the recording in `tests/test_fixtures.py`, so the check cannot drift from the run.
The recordings are unchanged: a recording is what happened.

A recording is produced with a command of this shape, or copied from a campaign's run
directory:

```
uv run alert-forensics triage examples/atypical_travel.alert.json \
    --model provider:name -o runs/atypical_travel/<recording>/run.json
```
