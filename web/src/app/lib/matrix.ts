// Page-side reading types for reports/model-matrix.json.
//
// They describe the file as the page reads it and mirror the Matrix contract in
// src/alert_forensics/evaluation/matrix.py, declared here independently: the
// page is pure presentation over the committed JSON and imports nothing from
// the Python project. Every number the page shows is read from these shapes or
// from a committed recording; nothing is typed in.

export interface Proportion {
  numerator: number;
  denominator: number;
  estimate: number | null;
  low: number | null;
  high: number | null;
}

export interface Spread {
  mean: number;
  min: number;
  max: number;
}

export interface Money {
  mean: number | null;
  total: number;
}

export interface Calls {
  total: number;
  ok: number;
  error: number;
  denied: number;
  no_fixture: number;
  runs_with_gaps: number;
}

export interface Measures {
  runs: number;
  served: number;
  refused: Proportion;
  refused_kinds: Record<string, number>;
  refused_before_any_turn: number;
  refused_after_a_turn: number;
  completed: Proportion;
  failed: Proportion;
  failed_ungrounded: Proportion;
  failed_error: Proportion;
  error_kinds: Record<string, number>;
  verdict_accuracy: Proportion;
  evidence_recall: Proportion;
  missing_context_recall: Proportion;
  escalation_precision: Proportion;
  escalation_recall: Proportion;
  calls: Calls;
  wall_clock_s: Spread | null;
  cost_usd: Money | null;
  cost_note: string | null;
}

export interface RunRow {
  index: number;
  outcome: string;
  refused: boolean;
  error_kind: string | null;
  verdict: string | null;
  confidence: number | null;
  escalate: boolean | null;
  tool_calls: number;
  ok_calls: number;
  no_fixture: number;
  findings_reached: number;
  findings_required: number;
  context_named: number;
  context_expected: number;
  wall_clock_s: number;
}

export interface MatrixCell extends Measures {
  model: string;
  scenario: string;
  per_run: RunRow[];
}

export interface ModelRollup extends Measures {
  model: string;
  cells: number;
}

export interface ScenarioTruth {
  name: string;
  title: string;
  verdict: string;
  escalate: boolean;
  required_findings: number;
  missing_context: number;
}

export interface MatrixArtifact {
  metadata: {
    models: string[];
    runs_per_cell: number | null;
    scenario_ids: string[];
    scenarios: ScenarioTruth[];
    role: string;
    fixture_digest: string | null;
    campaign_started_at: string | null;
    generated_at: string;
    judge_model: null;
    judge_note: string;
  };
  cells: MatrixCell[];
  by_model: ModelRollup[];
}

// --- display helpers ---------------------------------------------------------

// A rate rendered as a percentage integer, e.g. 0.8 -> "80".
export function pct(x: number): string {
  return (x * 100).toFixed(0);
}

// "anthropic:claude-haiku-4-5" -> "claude-haiku-4-5". The provider prefix is
// the run's identity and is shown beside the label, never dropped from the id.
export function modelLabel(model: string): string {
  const i = model.indexOf(":");
  return i < 0 ? model : model.slice(i + 1);
}

export function providerOf(model: string): string {
  const i = model.indexOf(":");
  return i < 0 ? "" : model.slice(0, i);
}

// Bands drive the sparing use of semantic color. Only the point marker and the
// numeral carry it; the interval range is always the neutral color, so a wide
// bracket stays legible whatever the band.
export type Band = "good" | "warn" | "crit";

export function band(x: number): Band {
  if (x >= 0.8) return "good";
  if (x >= 0.5) return "warn";
  return "crit";
}

// "3/12" for a proportion, the count the estimate was made from.
export function counts(p: Proportion): string {
  return `${p.numerator}/${p.denominator}`;
}

// A short digest prefix, the way the spec cites one.
export function shortDigest(digest: string | null): string {
  return digest ? `${digest.slice(0, 8)}…` : "not on record";
}

// A compact UTC stamp, "2026-09-15 17:36 UTC", deterministic so the static
// build renders identically everywhere.
export function stamp(iso: string | null | undefined): string {
  if (!iso) return "unknown";
  const m = iso.match(/^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2})/);
  return m ? `${m[1]} ${m[2]} UTC` : iso;
}

export function usd(x: number): string {
  return `$${x.toFixed(x < 0.1 ? 4 : 2)}`;
}

// Columns in order of mean cost per served run, cheapest first, so the reader
// crosses the matrix from the free tier to the priced one. A model with no
// rollup cost keeps the artifact's order after the priced ones.
export function columnOrder(matrix: MatrixArtifact): string[] {
  const cost = new Map(
    matrix.by_model.map((r) => [r.model, r.cost_usd?.mean ?? null] as const),
  );
  return [...matrix.metadata.models].sort((a, b) => {
    const ca = cost.get(a) ?? null;
    const cb = cost.get(b) ?? null;
    if (ca === null && cb === null) return 0;
    if (ca === null) return 1;
    if (cb === null) return -1;
    return ca - cb;
  });
}

export interface ScenarioRow {
  scenario: string;
  truth: ScenarioTruth | undefined;
  cellsByModel: Record<string, MatrixCell | undefined>;
}

// One row per scenario in the order given, each carrying its cells by model.
// A (model, scenario) pair the artifact does not hold resolves to undefined so
// the grid marks it absent rather than crashing.
export function buildRows(
  matrix: MatrixArtifact,
  models: string[],
  order: string[],
): ScenarioRow[] {
  const truthByName = new Map(matrix.metadata.scenarios.map((s) => [s.name, s]));
  const present = new Set(matrix.cells.map((c) => c.scenario));
  const ids = [
    ...order.filter((id) => present.has(id)),
    ...matrix.metadata.scenario_ids.filter((id) => present.has(id) && !order.includes(id)),
  ];
  return ids.map((scenario) => {
    const cellsByModel: Record<string, MatrixCell | undefined> = {};
    for (const m of models) {
      cellsByModel[m] = matrix.cells.find((c) => c.model === m && c.scenario === scenario);
    }
    return { scenario, truth: truthByName.get(scenario), cellsByModel };
  });
}
