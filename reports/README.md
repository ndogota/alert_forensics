# reports

The committed, derived view of a campaign. A results directory, `campaigns/03` and its
kind, is not committed: it holds every run artifact and raw store of a campaign and is
the measurement. This directory holds one small JSON derived from it, so a reader of a
clone, and the page under `web/`, can see the campaign's numbers without the campaign.
The decision is in `docs/SPEC.md` under "A campaign is one fixture revision", the
bullet "`reports/` is the committed, derived view of a campaign".

`model-matrix.json` is that file, for `campaigns/03`, the four-model matrix of
2026-09-15 under fixture digest `1a25e478…`. It holds:

- `metadata`: the models, the served runs per cell, the scenario ids with each
  scenario's truth verdict, expected escalation and counts of required findings and
  expected missing context, the role, the fixture digest, when the campaign started,
  when the file was generated, and `judge_model: null` beside a sentence saying why.
  The scorers are deterministic and no model judges any run.
- `cells`: one per (model, scenario), a projection of the summary `eval-report`
  prints: runs, served, refused split before and after a model turn, completed and
  failed by outcome, verdict accuracy, evidence recall, missing-context recall,
  escalation precision and recall, the tool calls with the `no_fixture` count, cost
  and wall clock. Every proportion is numerator, denominator, estimate and the Wilson
  95 percent bounds, the same shape the summary uses. Each cell carries `per_run`,
  one row per run with its outcome, verdict, confidence, call count and score.
- `by_model`: one rollup per model over its served runs, the same measures pooled
  from its cells.

## Regenerating it

The file is derived and regenerable. It is rebuilt from the campaign directory and the
current ground truth, re-scoring every run exactly as `eval-report` does, with no model
call and no key:

```
uv run alert-forensics matrix campaigns/03 -o reports/model-matrix.json
```

A ground truth corrected after the campaign re-scores it without a rerun, and this
command is how the corrected numbers reach the file. The command refuses a directory
of two fixture revisions, of a scenario with no truth, or of two roles. Whoever does
not hold the campaign directory cannot regenerate the file; what they can verify is
the method, the test suite, which holds this file to the summary and its bounds to the
stats module, and the recordings under `runs/`.

The page under `web/` reads this file at build time and nothing else from the
campaign; `web/README.md` says how it is built.
