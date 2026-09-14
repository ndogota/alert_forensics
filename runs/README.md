# Recorded runs

One directory per scenario, each holding `run.json`, the run artifact, and `run.raw/`,
the raw tool responses its trace refers to by ref and hash. `alert-forensics replay
runs/<scenario>/run.json` verifies the raw store and prints the run.

Every recording here is a real model run. The artifact states the model (`model`) and
the date (`trace.started_at`). The test suite refuses a recording made with the scripted
client.

One is committed: scenario 1, atypical travel, under `runs/atypical_travel/`, a real
run on `google_genai:gemini-3.5-flash-lite` whose artifact states the model and the
date. A recording is produced with a command of this shape:

```
uv run alert-forensics triage examples/atypical_travel.alert.json \
    --model provider:name -o runs/atypical_travel/run.json
```
