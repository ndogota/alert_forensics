# Recorded runs

One directory per scenario, each holding `run.json`, the run artifact, and `run.raw/`,
the raw tool responses its trace refers to by ref and hash. `alert-forensics replay
runs/<scenario>/run.json` verifies the raw store and prints the run.

Every recording here is a real model run. The artifact states the model (`model`) and
the date (`trace.started_at`). The test suite refuses a recording made with the scripted
client.

None committed yet. The first is scenario 1, atypical travel:

```
uv run alert-forensics triage examples/atypical_travel.alert.json \
    --model anthropic:claude-sonnet-5 -o runs/atypical_travel/run.json
```
