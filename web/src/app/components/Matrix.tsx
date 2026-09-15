"use client";

import { useState } from "react";
import type {
  MatrixArtifact,
  MatrixCell,
  ModelRollup,
  Proportion,
  RunRow,
  ScenarioTruth,
} from "../lib/matrix";
import {
  band,
  buildRows,
  columnOrder,
  counts,
  modelLabel,
  pct,
  providerOf,
  usd,
} from "../lib/matrix";
import { SCENARIO_ORDER, glossOf } from "../lib/scenarios";

// A single Wilson-interval readout, the signature component ported from
// pod_forensics. The point estimate is the numeral and the colored tick; the
// interval is the neutral bracket behind it. Color is applied only to the
// point, never to the interval, so a wide bracket stays legible whatever the
// band. An empty denominator has no estimate and no interval, and says so.
export function IntervalBar({
  label,
  p,
  size = "primary",
  note,
}: {
  label: string;
  p: Proportion;
  size?: "primary" | "secondary";
  note?: string;
}) {
  if (p.estimate === null || p.low === null || p.high === null) {
    return (
      <div className={`metric metric-${size} metric-absent`}>
        <div className="metric-head">
          <span className="metric-label">{label}</span>
          <span className="metric-point metric-na">n/a</span>
        </div>
        <div className="metric-ci">
          {counts(p)}
          {note ? ` · ${note}` : ""}
        </div>
      </div>
    );
  }
  const b = band(p.estimate);
  const width = Math.max(0, p.high - p.low);
  const title = `${label}: ${counts(p)} = ${p.estimate.toFixed(2)}, Wilson 95% [${p.low.toFixed(
    2,
  )}, ${p.high.toFixed(2)}]`;
  return (
    <div className={`metric metric-${size}`} title={title}>
      <div className="metric-head">
        <span className="metric-label">{label}</span>
        <span className={`metric-point band-${b}`}>
          {pct(p.estimate)}
          <span className="metric-unit">%</span>
        </span>
      </div>
      <div className="track" aria-hidden="true">
        <div
          className="track-range"
          style={{ left: `${p.low * 100}%`, width: `${Math.max(width * 100, 0.6)}%` }}
        />
        <div className={`track-tick band-${b}`} style={{ left: `${p.estimate * 100}%` }} />
      </div>
      <div className="metric-ci">
        {counts(p)} · [{pct(p.low)}, {pct(p.high)}]
        {note ? ` · ${note}` : ""}
      </div>
    </div>
  );
}

function outcomeClass(row: RunRow): string {
  if (row.refused) return "oc-refused";
  if (row.outcome === "completed") return "oc-completed";
  return "oc-failed";
}

// One row per run of a cell, as the file carries it.
export function RunTable({ rows }: { rows: RunRow[] }) {
  return (
    <table className="runs-table">
      <thead>
        <tr>
          <th>run</th>
          <th>outcome</th>
          <th>verdict</th>
          <th>conf</th>
          <th>esc</th>
          <th>calls</th>
          <th>ok</th>
          <th>no_fixture</th>
          <th>findings</th>
          <th>context</th>
          <th>wall s</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((r) => (
          <tr key={r.index} className={outcomeClass(r)}>
            <td>{r.index}</td>
            <td>
              {r.refused ? `refused (${r.error_kind})` : r.outcome}
              {!r.refused && r.error_kind ? ` (${r.error_kind})` : ""}
            </td>
            <td>{r.verdict ?? "none"}</td>
            <td>{r.confidence === null ? "" : r.confidence.toFixed(2)}</td>
            <td>{r.escalate === null ? "" : r.escalate ? "yes" : "no"}</td>
            <td>{r.tool_calls}</td>
            <td>{r.ok_calls}</td>
            <td>{r.no_fixture}</td>
            <td>
              {r.findings_reached}/{r.findings_required}
            </td>
            <td>
              {r.context_named}/{r.context_expected}
            </td>
            <td>{r.wall_clock_s.toFixed(1)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function kinds(k: Record<string, number>): string {
  return Object.entries(k)
    .map(([name, n]) => `${name} ${n}`)
    .join(", ");
}

// The expanded breakdown for one cell: every measure with its interval drawn,
// the tool calls, cost and wall clock over the served runs, and the rows.
function CellDetail({ cell, truth }: { cell: MatrixCell; truth: ScenarioTruth | undefined }) {
  const gaps = cell.calls.no_fixture;
  const refused = cell.refused.numerator;
  return (
    <div className="cell-detail">
      <div className="cd-headline">
        <span className="cd-model">{modelLabel(cell.model)}</span>
        <span className="cd-x">×</span>
        <span className="cd-scenario">{cell.scenario}</span>
        {truth && (
          <span className="truth-chip">
            truth {truth.verdict}
            {truth.escalate ? ", escalate" : ""}
          </span>
        )}
        <span className="cd-n">
          {cell.served} served of {cell.runs} runs
          {refused
            ? `; ${refused} refused by the provider (${kinds(cell.refused_kinds)}), ${
                cell.refused_before_any_turn
              } before any model turn, out of every denominator below`
            : ""}
        </span>
      </div>

      {cell.served === 0 && (
        <p className="cd-quota">
          No served run: this cell measures the quota, not the model, and every proportion
          below reads n/a.
        </p>
      )}

      <div className="cd-metrics">
        <IntervalBar label="verdict accuracy" p={cell.verdict_accuracy} />
        <IntervalBar
          label="evidence recall"
          p={cell.evidence_recall}
          note={gaps ? `${gaps} no_fixture: a floor` : undefined}
        />
        <IntervalBar label="missing-context recall" p={cell.missing_context_recall} />
        <IntervalBar label="completed" p={cell.completed} />
        <IntervalBar
          label="failed_ungrounded"
          p={cell.failed_ungrounded}
        />
        <IntervalBar
          label="failed_error"
          p={cell.failed_error}
          note={Object.keys(cell.error_kinds).length ? kinds(cell.error_kinds) : undefined}
        />
        <IntervalBar
          label="escalation precision"
          p={cell.escalation_precision}
          note={cell.escalation_precision.denominator ? undefined : "no predicted escalation"}
        />
        <IntervalBar
          label="escalation recall"
          p={cell.escalation_recall}
          note={cell.escalation_recall.denominator ? undefined : "no expected escalation"}
        />
        <IntervalBar label="refused by the provider" p={cell.refused} note="over all runs" />
      </div>

      <dl className="cd-facts">
        <div>
          <dt>tool calls</dt>
          <dd>
            {cell.calls.total} total · {cell.calls.ok} ok · {cell.calls.error} error ·{" "}
            {cell.calls.denied} denied · no_fixture {cell.calls.no_fixture} in{" "}
            {cell.calls.runs_with_gaps} of {cell.runs} runs
          </dd>
        </div>
        <div>
          <dt>wall clock, served runs</dt>
          <dd>
            {cell.wall_clock_s
              ? `mean ${cell.wall_clock_s.mean.toFixed(1)} s · min ${cell.wall_clock_s.min.toFixed(
                  1,
                )} · max ${cell.wall_clock_s.max.toFixed(1)}`
              : "n/a, no served run"}
          </dd>
        </div>
        <div>
          <dt>cost</dt>
          <dd>
            {cell.cost_usd
              ? `${
                  cell.cost_usd.mean === null ? "mean n/a" : `mean ${usd(cell.cost_usd.mean)}`
                } per served run · total ${usd(cell.cost_usd.total)} over all ${cell.runs} runs`
              : (cell.cost_note ?? "n/a")}
          </dd>
        </div>
      </dl>

      <RunTable rows={cell.per_run} />

      <p className="cd-trace-note">
        The runs behind this cell are in the campaign directory, which is not committed.
        The transcripts below are the committed recordings under <code>runs/</code>, real
        model runs on the same scenarios, not the campaign&apos;s.
      </p>
    </div>
  );
}

// One (model, scenario) cell in the grid: verdict accuracy beside evidence
// recall as interval bars, so the gap between them is what the eye sees, with
// served, refused and no_fixture condensed below. The cell is a toggle that
// opens its breakdown.
function Cell({
  cell,
  expanded,
  onToggle,
}: {
  cell: MatrixCell | undefined;
  expanded: boolean;
  onToggle: () => void;
}) {
  if (!cell) {
    return <div className="cell cell-absent">not run</div>;
  }
  const refused = cell.refused.numerator;
  return (
    <button
      type="button"
      className={`cell${expanded ? " cell-open" : ""}`}
      onClick={onToggle}
      aria-expanded={expanded}
    >
      <div className="cell-top">
        <span className="cell-n">
          served {cell.served}/{cell.runs}
        </span>
        <span className="cell-chevron" aria-hidden="true">
          {expanded ? "−" : "+"}
        </span>
      </div>
      <IntervalBar label="verdict" p={cell.verdict_accuracy} />
      <IntervalBar label="evidence" p={cell.evidence_recall} />
      <div className="cell-secondary">
        <span>
          <span className="cs-k">ctx</span> {counts(cell.missing_context_recall)}
        </span>
        <span className="cs-dot">·</span>
        <span>
          <span className="cs-k">failed</span> {cell.failed.numerator}
        </span>
        {refused > 0 && (
          <>
            <span className="cs-dot">·</span>
            <span>
              <span className="cs-k">refused</span> {refused}
            </span>
          </>
        )}
        {cell.calls.no_fixture > 0 && (
          <>
            <span className="cs-dot">·</span>
            <span>
              <span className="cs-k">no_fixture</span> {cell.calls.no_fixture}
            </span>
          </>
        )}
      </div>
    </button>
  );
}

// The per-model rollup over its served runs: verdicts and findings as counts
// beside each other, the same measures the cells carry, pooled.
function Rollup({ r }: { r: ModelRollup }) {
  return (
    <div className="rollup">
      <div className="rollup-model">
        {modelLabel(r.model)}
        <span className="rollup-provider">{providerOf(r.model)}</span>
      </div>
      <div className="rollup-tiers">
        <span className="rollup-tier">
          <span className="rt-label">verdicts</span>
          <span className="rt-val">{counts(r.verdict_accuracy)}</span>
        </span>
        <span className="rollup-tier">
          <span className="rt-label">findings</span>
          <span className="rt-val">{counts(r.evidence_recall)}</span>
        </span>
        <span className="rollup-tier">
          <span className="rt-label">context</span>
          <span className="rt-val">{counts(r.missing_context_recall)}</span>
        </span>
        <span className="rollup-tier">
          <span className="rt-label">completed</span>
          <span className="rt-val">{counts(r.completed)}</span>
        </span>
      </div>
      <IntervalBar label="verdict accuracy" p={r.verdict_accuracy} size="secondary" />
      <IntervalBar
        label="evidence recall"
        p={r.evidence_recall}
        size="secondary"
        note={r.calls.no_fixture ? `${r.calls.no_fixture} no_fixture` : undefined}
      />
      <div className="rollup-note">
        {r.served} served of {r.runs} runs
        {r.refused.numerator ? `, ${r.refused.numerator} refused by the provider` : ""} ·{" "}
        {r.cost_usd
          ? `${usd(r.cost_usd.total)} total, ${
              r.cost_usd.mean === null ? "n/a" : usd(r.cost_usd.mean)
            } per served run`
          : (r.cost_note ?? "unpriced")}
        {r.wall_clock_s ? ` · ${r.wall_clock_s.mean.toFixed(0)} s mean` : ""}
      </div>
    </div>
  );
}

export function Matrix({ matrix }: { matrix: MatrixArtifact }) {
  const present = new Set(matrix.cells.map((c) => c.model));
  const models = columnOrder(matrix).filter((m) => present.has(m));
  const rows = buildRows(matrix, models, SCENARIO_ORDER);

  // A single open cell at a time, keyed by "scenario|model".
  const [open, setOpen] = useState<string | null>(null);
  const toggle = (key: string) => setOpen((cur) => (cur === key ? null : key));

  const gridStyle = {
    gridTemplateColumns: `var(--label-col) repeat(${models.length}, minmax(200px, 1fr))`,
  };

  return (
    <section className="matrix-section" aria-label="model by scenario matrix">
      <div className="eyebrow">the matrix</div>
      <h2 className="section-title">Every model against every scenario</h2>
      <p className="section-lede">
        Verdict accuracy is the share of served runs whose verdict equals the truth. Evidence
        recall is the share of (required finding, run) pairs a grounded observed fact
        carried, matched by the tool it cites and whole-word tokens. Both are over the served
        runs; a run the provider refused is out of every denominator, and a failed run
        scores zero and stays in. Each bar is the Wilson 95% interval over the cell&apos;s
        count. Columns run from the cheapest mean cost per served run to the dearest.
      </p>
      <div className="matrix-legend">
        <span className="legend-item">
          <span className="legend-tick" /> point estimate
        </span>
        <span className="legend-item">
          <span className="legend-range" /> Wilson 95% [low, high]
        </span>
        <span className="legend-item">
          <span className="legend-swatch band-good" /> ≥80
        </span>
        <span className="legend-item">
          <span className="legend-swatch band-warn" /> 50 to 79
        </span>
        <span className="legend-item">
          <span className="legend-swatch band-crit" /> &lt;50
        </span>
        <span className="legend-hint">click a cell for the full breakdown</span>
      </div>

      <div className="matrix-scroll">
        <div className="grid" style={gridStyle}>
          <div className="grid-corner">
            <span className="corner-y">scenario ↓</span>
            <span className="corner-x">model →</span>
          </div>
          {models.map((m) => (
            <div key={m} className="grid-model-head">
              <span className="gmh-label">{modelLabel(m)}</span>
              <span className="gmh-id">{m}</span>
            </div>
          ))}

          {rows.map((row) => {
            const openKey = open && open.startsWith(`${row.scenario}|`) ? open : null;
            const openModel = openKey ? openKey.split("|")[1] : null;
            const openCell = openModel ? row.cellsByModel[openModel] : undefined;
            const gloss = glossOf(row.scenario);
            return (
              <FragmentRow
                key={row.scenario}
                scenario={row.scenario}
                number={gloss?.number}
                gloss={gloss?.gloss}
                trap={gloss?.trap ?? false}
                truth={row.truth}
                models={models}
                cellsByModel={row.cellsByModel}
                openKey={openKey}
                openCell={openCell}
                toggle={toggle}
              />
            );
          })}
        </div>
      </div>

      <div className="rollups">
        <h3 className="rollups-title">per-model rollup, over served runs</h3>
        <div className="rollups-grid">
          {models.map((m) => {
            const r = matrix.by_model.find((x) => x.model === m);
            return r ? <Rollup key={m} r={r} /> : null;
          })}
        </div>
      </div>
    </section>
  );
}

function FragmentRow({
  scenario,
  number,
  gloss,
  trap,
  truth,
  models,
  cellsByModel,
  openKey,
  openCell,
  toggle,
}: {
  scenario: string;
  number: number | undefined;
  gloss: string | undefined;
  trap: boolean;
  truth: ScenarioTruth | undefined;
  models: string[];
  cellsByModel: Record<string, MatrixCell | undefined>;
  openKey: string | null;
  openCell: MatrixCell | undefined;
  toggle: (key: string) => void;
}) {
  return (
    <>
      <div className={`grid-label${trap ? " grid-label-trap" : ""}`}>
        <span className="gl-id">
          {number !== undefined && <span className="gl-num">{number}</span>}
          {scenario}
        </span>
        {truth && <span className="gl-title">{truth.title}</span>}
        {gloss && <span className="gl-desc">{gloss}</span>}
        {truth && (
          <span className="gl-truth">
            truth {truth.verdict}
            {truth.escalate ? ", escalate" : ""} · {truth.required_findings} findings ·{" "}
            {truth.missing_context} context
          </span>
        )}
      </div>
      {models.map((m) => {
        const key = `${scenario}|${m}`;
        return (
          <Cell
            key={key}
            cell={cellsByModel[m]}
            expanded={openKey === key}
            onToggle={() => toggle(key)}
          />
        );
      })}
      {openCell && (
        <div className="detail-row">
          <CellDetail cell={openCell} truth={truth} />
        </div>
      )}
    </>
  );
}
