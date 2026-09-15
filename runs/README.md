# Recorded runs

One directory per recording, `runs/<scenario>/<recording>/`, each holding `run.json`,
the run artifact, and `run.raw/`, the raw tool responses its trace refers to by ref and
hash. `alert-forensics replay runs/<scenario>/<recording>/run.json` verifies the raw
store and prints the run.

Every recording here is a real model run. The artifact states the model (`model`) and
the date (`trace.started_at`). The test suite refuses a recording made with the scripted
client, and one that holds no tool call. Which runs are committed is a rule, stated in
`docs/SPEC.md` under "Using it": a run the spec cites, or the scenario's demonstration
run, the first completed run of the first real campaign on the scenario in index order.
A recording named `campaign-<k>` is the run directory `<k>` of the campaign of
2026-09-15 under `results/google_genai-gemini-3.5-flash-lite/analyst/<scenario>/`,
artifact and raw store copied unchanged; the results directory itself is not committed.

All ten are runs of `google_genai:gemini-3.5-flash-lite` under the `analyst` role.

- `runs/atypical_travel/defaults-2026-09-14/`: the first recording, 2026-09-14, made
  before the `no_fixture` rule, the whole-word tokens and the label binding. Completed,
  verdict right, evidence recall 2 of 3. It is the run that found the fixture-default
  defect: the runbook and the identity answered its questions with empty defaults, and
  the trace filed both as `ok`. Kept as it is, since it is cited for that.
- `runs/atypical_travel/campaign-0/`: the demonstration run, 2026-09-15. Completed,
  verdict right, evidence recall 1 of 3: one fact for both sign-ins, naming neither
  city.
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

The gaps named above are closed since 2026-09-15 and each refused request is replayed
from the recording in `tests/test_fixtures.py`, so the check cannot drift from the run.
The recordings are unchanged: a recording is what happened.

A recording is produced with a command of this shape, or copied from a campaign's run
directory:

```
uv run alert-forensics triage examples/atypical_travel.alert.json \
    --model provider:name -o runs/atypical_travel/<recording>/run.json
```
