"use client";

import type { MatrixArtifact, MatrixCell, ModelRollup, RunRow, ScenarioTruth } from "../lib/matrix";
import { columnOrder, counts, modelLabel, shortDigest, stamp, usd } from "../lib/matrix";
import type { Recording } from "../lib/recordings";
import { IntervalBar, Matrix, RunTable } from "./Matrix";
import { Runs } from "./Runs";

// The headline is scenario 7, the trap, under the two models the spec names
// for it: the same alert, the same fixtures, opposite verdicts. Both ids are
// the run strings the campaign was started with. If either cell is absent the
// section renders nothing rather than a different comparison.
const TRAP = "rmm_block";
const LEFT = "google_genai:gemini-3.5-flash-lite";
const RIGHT = "anthropic:claude-sonnet-5";

// The sentence below the matrix names these two rollups.
const SENTENCE_A = "google_genai:gemini-3.5-flash-lite";
const SENTENCE_B = "anthropic:claude-haiku-4-5";

function totalCost(matrix: MatrixArtifact): number | null {
  let total = 0;
  for (const r of matrix.by_model) {
    if (!r.cost_usd) return null;
    total += r.cost_usd.total;
  }
  return total;
}

function StatusBar({ matrix }: { matrix: MatrixArtifact | null }) {
  const cost = matrix ? totalCost(matrix) : null;
  return (
    <div className="statusbar" role="banner">
      <div className="statusbar-inner">
        <span className="sb-brand">alert_forensics</span>
        <span className="sb-sep">::</span>
        <span className="sb-seg">model × scenario eval</span>
        {matrix && (
          <>
            <span className="sb-spacer" />
            <span className="sb-seg">
              <span className="sb-k">models</span> {matrix.metadata.models.length}
            </span>
            <span className="sb-dot">·</span>
            <span className="sb-seg">
              <span className="sb-k">served</span>{" "}
              {matrix.metadata.runs_per_cell === null
                ? "varies"
                : `${matrix.metadata.runs_per_cell}/cell`}
            </span>
            <span className="sb-dot">·</span>
            <span className="sb-seg">
              <span className="sb-k">judge</span> none
            </span>
            {cost !== null && (
              <>
                <span className="sb-dot">·</span>
                <span className="sb-seg">
                  <span className="sb-k">campaign cost</span> {usd(cost)}
                </span>
              </>
            )}
            <span className="sb-dot">·</span>
            <span
              className="sb-seg sb-ro"
              title="Nine read-only tools and one gated proposal that writes nothing. The agent never closes an alert."
            >
              read-only
            </span>
          </>
        )}
      </div>
    </div>
  );
}

function Header({ matrix }: { matrix: MatrixArtifact }) {
  const meta = matrix.metadata;
  return (
    <header className="head">
      <div className="eyebrow">soc alert triage eval</div>
      <h1 className="head-title">Does the verdict rest on the evidence?</h1>
      <p className="head-lede">
        alert_forensics is a SOC alert triage agent whose every claim cites the tool call
        behind it, measured against ground truth: a verdict, the observed facts it rests on
        with their citations, and what it could not establish.
      </p>

      <dl className="head-meta">
        <div>
          <dt>models</dt>
          <dd>{columnOrder(matrix).map(modelLabel).join(", ")}</dd>
        </div>
        <div>
          <dt>served runs / cell</dt>
          <dd>{meta.runs_per_cell === null ? "varies by cell" : meta.runs_per_cell}</dd>
        </div>
        <div>
          <dt>judge</dt>
          <dd>none</dd>
        </div>
        <div>
          <dt>role</dt>
          <dd>{meta.role}</dd>
        </div>
        <div>
          <dt>campaign started</dt>
          <dd>{stamp(meta.campaign_started_at)}</dd>
        </div>
        <div>
          <dt>fixtures</dt>
          <dd title={meta.fixture_digest ?? undefined}>{shortDigest(meta.fixture_digest)}</dd>
        </div>
      </dl>

      <p className="head-method">
        <strong>No model judges this.</strong> {meta.judge_note} Every proportion carries a
        Wilson 95% interval over its count, and the bars draw that interval directly: a
        wide bracket means few runs, not a wide result. A run the provider refused is out
        of every denominator; a run that failed scores zero and stays in.
      </p>
    </header>
  );
}

function uniq<T>(xs: T[]): T[] {
  return [...new Set(xs)];
}

function range(xs: number[]): string {
  if (xs.length === 0) return "0";
  const lo = Math.min(...xs);
  const hi = Math.max(...xs);
  return lo === hi ? `${lo}` : `${lo} to ${hi}`;
}

function outcomeCounts(rows: RunRow[]): string {
  const c = new Map<string, number>();
  for (const r of rows) c.set(r.outcome, (c.get(r.outcome) ?? 0) + 1);
  return [...c.entries()].map(([k, n]) => `${n} ${k}`).join(", ");
}

// One side of the headline: the cell's rows and what they add up to, every
// number read from the rows and the cell, the reading derived from the rows.
function Side({ cell, truth }: { cell: MatrixCell; truth: ScenarioTruth | undefined }) {
  const served = cell.per_run.filter((r) => !r.refused);
  const refused = cell.per_run.filter((r) => r.refused);
  const calls = served.map((r) => r.tool_calls);
  const verdicts = uniq(served.map((r) => r.verdict ?? "none"));
  const confidences = uniq(
    served.map((r) => (r.confidence === null ? "n/a" : r.confidence.toFixed(2))),
  );
  const silent = served.length > 0 && served.every((r) => r.tool_calls === 0);
  const wrong = truth ? verdicts.filter((v) => v !== truth.verdict) : [];
  return (
    <div className="duel-side">
      <div className="duel-model">
        {modelLabel(cell.model)}
        <span className="duel-provider">{cell.model}</span>
      </div>
      <p className="duel-sentence">
        {served.length} served run{served.length === 1 ? "" : "s"}, {range(calls)} tool call
        {calls.length === 1 && calls[0] === 1 ? "" : "s"} each, verdict{" "}
        <span className={wrong.length ? "verdict-wrong" : "verdict-right"}>
          {verdicts.join(" / ")}
        </span>{" "}
        at {confidences.join(" / ")}
        {truth ? ` against a ${truth.verdict} truth` : ""}: {outcomeCounts(served)}.
        {refused.length
          ? ` ${refused.length} more run${refused.length === 1 ? "" : "s"} refused by the provider before any model turn, the quota's number, out of every denominator.`
          : ""}
      </p>
      <p className="duel-reading">
        {silent
          ? "Asserted from the alert alone, with no evidence sought. The silence rule refused each result: a result with no observed fact is grounded only when its verdict is inconclusive and its missing context says why. Each run is failed_ungrounded, not laundered into inconclusive, and it is not a correct verdict either."
          : "Each verdict rests on observed facts that cite the tool calls made; the findings reached and the missing context named are in the rows, as the deterministic scorers matched them."}
      </p>
      <div className="duel-metrics">
        <IntervalBar label="verdict accuracy" p={cell.verdict_accuracy} size="secondary" />
        <IntervalBar label="evidence recall" p={cell.evidence_recall} size="secondary" />
        <IntervalBar
          label="missing-context recall"
          p={cell.missing_context_recall}
          size="secondary"
        />
      </div>
      <RunTable rows={cell.per_run} />
    </div>
  );
}

function Headline({ matrix }: { matrix: MatrixArtifact }) {
  const left = matrix.cells.find((c) => c.model === LEFT && c.scenario === TRAP);
  const right = matrix.cells.find((c) => c.model === RIGHT && c.scenario === TRAP);
  const truth = matrix.metadata.scenarios.find((s) => s.name === TRAP);
  if (!left || !right) return null;
  return (
    <section className="finding" aria-label="headline">
      <div className="eyebrow">the headline · scenario 7</div>
      <h2 className="finding-title">The same alert, the same fixtures, opposite verdicts</h2>
      <p className="finding-lede">
        Scenario 7 is the trap: a signed remote-management binary with a clean reputation,
        blocked by the EDR. The tier-one reflex is to close it. It is initial access: the
        relay is not the IT provider&apos;s, and a script from the mail client preceded it.
        {truth ? ` Truth: ${truth.verdict}${truth.escalate ? ", escalate" : ""}.` : ""} Both
        models were handed the same alert and the same fixture stubs under the same digest,
        in the same campaign.
      </p>
      <div className="duel">
        <Side cell={left} truth={truth} />
        <Side cell={right} truth={truth} />
      </div>
      <p className="finding-honest">
        Three served runs per cell, so each interval is wide; the rows are the runs
        themselves. The verdict is read exactly, the findings by cited tool and whole-word
        tokens; no model judges either.
      </p>
    </section>
  );
}

function Verdicts({ matrix }: { matrix: MatrixArtifact }) {
  const a = matrix.by_model.find((r) => r.model === SENTENCE_A);
  const b = matrix.by_model.find((r) => r.model === SENTENCE_B);
  if (!a || !b) return null;
  const phrase = (r: ModelRollup) =>
    `${modelLabel(r.model)} reaches ${r.verdict_accuracy.numerator} of ${
      r.verdict_accuracy.denominator
    } verdicts on ${r.evidence_recall.numerator} of ${r.evidence_recall.denominator} findings`;
  return (
    <section className="sentence" aria-label="verdicts against evidence">
      <p className="sentence-text">
        {phrase(a)}, {phrase(b)}. Verdict accuracy does not track evidence.
      </p>
      <p className="sentence-note">
        Over each model&apos;s served runs, pooled from its cells: verdicts as{" "}
        {counts(a.verdict_accuracy)} and {counts(b.verdict_accuracy)}, findings as{" "}
        {counts(a.evidence_recall)} and {counts(b.evidence_recall)}. A right verdict on few
        findings is a verdict the evidence did not carry.
      </p>
    </section>
  );
}

function Limits({ matrix, recordings }: { matrix: MatrixArtifact | null; recordings: Recording[] }) {
  const cells = matrix ? matrix.cells.length : 0;
  return (
    <section className="limits" aria-label="limits">
      <div className="eyebrow">limits</div>
      <h2 className="section-title">What this does not show</h2>
      <ul className="limits-list">
        <li>
          Eight scenarios, all synthetic, in one tenant with a finite taxonomy of four
          verdicts. Real alert queues are messier, noisier and ambiguous.
        </li>
        <li>
          {matrix ? matrix.metadata.models.length : "Four"} models, one role, one fixture
          revision, one campaign.
        </li>
        <li>
          {matrix?.metadata.runs_per_cell ?? "Three"} served runs per cell over {cells} cells,
          so every interval is wide. The bars say how wide; a point estimate at this count
          is not a fact.
        </li>
        <li>
          Evidence recall is a floor: a finding is matched by the tool a fact cites and by
          whole-word tokens, so a fact that establishes it in other words is a miss, and a
          cell with no_fixture calls carries the count beside the number.
        </li>
        <li>
          The campaign directory is not committed. What a reader verifies is the method, the
          test suite, which holds this file to the summary and its bounds to the stats module,
          and the {recordings.length} recordings above, each replayable against its recorded
          hashes.
        </li>
        <li>
          Seven of the nine read tools are fixture-backed. Two are live-capable: the
          indicator lookup and the ATT&amp;CK technique lookup. Nothing here talks to a
          production SIEM or EDR.
        </li>
      </ul>
    </section>
  );
}

function Placeholder() {
  return (
    <div className="placeholder">
      <div className="ph-prompt">
        <span className="ph-user">analyst</span>
        <span className="ph-at">@</span>
        <span className="ph-host">alert_forensics</span>
        <span className="ph-path">~/reports</span>
        <span className="ph-cursor" aria-hidden="true" />
      </div>
      <p className="ph-line">
        <span className="ph-err">reports/model-matrix.json not found or empty</span>
      </p>
      <p className="ph-body">
        The page is a static read of that file. Generate it from a campaign directory with{" "}
        <code>uv run alert-forensics matrix campaigns/03 -o reports/model-matrix.json</code>,
        commit it, and rebuild.
      </p>
    </div>
  );
}

export function Console({
  matrix,
  recordings,
}: {
  matrix: MatrixArtifact | null;
  recordings: Recording[];
}) {
  return (
    <div className="console">
      <StatusBar matrix={matrix} />
      <main className="page">
        {matrix ? (
          <>
            <Header matrix={matrix} />
            <Headline matrix={matrix} />
            <Matrix matrix={matrix} />
            <Verdicts matrix={matrix} />
          </>
        ) : (
          <Placeholder />
        )}
        <Runs recordings={recordings} />
        <Limits matrix={matrix} recordings={recordings} />
        <footer className="foot">
          <p>
            Read-only by design: nine read tools and one gated proposal that writes nothing.
            Served statically from two committed sources, the matrix file and the recordings.
            No server, no key, no fetch at runtime. Sibling of pod_forensics, which applies
            the same method to Kubernetes incident diagnosis.
          </p>
        </footer>
      </main>
    </div>
  );
}
