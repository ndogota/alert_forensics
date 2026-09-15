"use client";

import { useState } from "react";
import type { Recording } from "../lib/recordings";
import { modelLabel, stamp } from "../lib/matrix";
import { SCENARIO_ORDER, glossOf } from "../lib/scenarios";

function outcomeClass(outcome: string): string {
  return outcome === "completed" ? "oc-completed" : "oc-failed";
}

// One recording as a terminal transcript: every tool call in order, with its
// arguments as the model sent them, its outcome and the failure kind when it
// did not end ok; then, on a run that produced a result, the three lists the
// schema separates, each observed fact with the tool its citation resolves
// to. A failed run shows its error. Nothing here is summarised: it is the
// artifact, projected.
function Transcript({
  rec,
  open,
  onToggle,
}: {
  rec: Recording;
  open: boolean;
  onToggle: () => void;
}) {
  const r = rec.result;
  const id = `run-${rec.scenario}-${rec.recording}`;
  return (
    <article id={id} className="run">
      <button
        type="button"
        className={`run-head${open ? " run-open" : ""}`}
        onClick={onToggle}
        aria-expanded={open}
      >
        <span className="run-chevron" aria-hidden="true">
          {open ? "▾" : "▸"}
        </span>
        <span className="run-id">
          {rec.scenario}/{rec.recording}
        </span>
        <span className="run-model">{modelLabel(rec.model)}</span>
        <span className={`run-outcome ${outcomeClass(rec.outcome)}`}>{rec.outcome}</span>
        {r && (
          <span className="run-summary">
            <span className="run-verdict">{r.verdict}</span> at {r.confidence.toFixed(2)}
          </span>
        )}
        <span className="run-steps">
          {rec.calls.length} calls · {stamp(rec.startedAt)}
        </span>
      </button>

      {open && (
        <div className="run-body">
          <div className="transcript">
            <div className="tr-line tr-prompt">
              <span className="tr-caret">$</span> alert-forensics triage {rec.scenario} --model{" "}
              {rec.model} --role {rec.role}
            </div>
            {rec.calls.length === 0 && (
              <div className="tr-line tr-none">
                <span className="tr-caret">·</span> the model made no tool call
              </div>
            )}
            {rec.calls.map((c) => (
              <div key={c.id} className={`tr-line tr-call tr-${c.outcome}`} title={c.args}>
                <span className="tr-caret">›</span>
                <span className="tr-step">{c.step}</span>
                <span className="tr-tool">{c.tool}</span>
                <span className="tr-args">({c.args})</span>
                <span className={`tr-outcome tr-outcome-${c.outcome}`}>
                  {c.outcome}
                  {c.failureKind ? ` ${c.failureKind}` : ""}
                </span>
                <span className="tr-cost">
                  {c.id} · {c.durationMs.toFixed(1)} ms
                </span>
              </div>
            ))}
            <div className={`tr-line tr-done ${outcomeClass(rec.outcome)}`}>
              <span className="tr-caret">{rec.outcome === "completed" ? "✓" : "✗"}</span>{" "}
              {rec.outcome} · {rec.passes} pass{rec.passes === 1 ? "" : "es"}
              {rec.corrections ? ` · ${rec.corrections} correction` : ""} · {rec.modelTurns}{" "}
              model turns · {rec.inputTokens} in / {rec.outputTokens} out tokens
            </div>
          </div>

          {rec.error && (
            <p className="run-error">
              <span className="dg-k">error</span> {rec.error.kind}: {rec.error.message}
            </p>
          )}

          {r && (
            <div className="diagnosis">
              <div className="dg-row">
                <span className="dg-k">verdict</span>
                <span className="dg-v">
                  {r.verdict} · confidence {r.confidence.toFixed(2)} · escalate{" "}
                  {r.escalate ? "yes" : "no"}
                  {r.techniques.length ? ` · ${r.techniques.join(", ")}` : ""}
                </span>
              </div>

              <div className="dg-block">
                <span className="dg-k">
                  observed facts ({r.facts.filter((f) => f.grounded).length} grounded of{" "}
                  {r.facts.length})
                </span>
                {r.facts.length === 0 ? (
                  <p className="dg-none">none</p>
                ) : (
                  <ol className="dg-facts">
                    {r.facts.map((f) => (
                      <li key={f.index} className={f.grounded ? "" : "fact-ungrounded"}>
                        <span className="fact-statement">{f.statement}</span>
                        <span className="fact-cites">
                          {f.citations.map((c) => (
                            <code key={c.id} className={c.tool ? "" : "cite-unknown"}>
                              {c.id}
                              {c.tool ? ` → ${c.tool}` : " → no such call"}
                              {c.outcome && c.outcome !== "ok" ? ` (${c.outcome})` : ""}
                            </code>
                          ))}
                          {!f.grounded && (
                            <span className="fact-problems">
                              ungrounded: {f.problems.join("; ")}
                            </span>
                          )}
                        </span>
                      </li>
                    ))}
                  </ol>
                )}
              </div>

              <div className="dg-block">
                <span className="dg-k">assumptions ({r.assumptions.length})</span>
                {r.assumptions.length === 0 ? (
                  <p className="dg-none">none</p>
                ) : (
                  <ul className="dg-list">
                    {r.assumptions.map((a, i) => (
                      <li key={i}>
                        {a.statement}
                        <span className="dg-sub">why unverified: {a.why}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </div>

              <div className="dg-block">
                <span className="dg-k">missing context ({r.missingContext.length})</span>
                {r.missingContext.length === 0 ? (
                  <p className="dg-none">none</p>
                ) : (
                  <ul className="dg-list">
                    {r.missingContext.map((m, i) => (
                      <li key={i}>
                        {m.what}
                        <span className="dg-sub">why it matters: {m.why}</span>
                        <span className="dg-sub">how to obtain: {m.how}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </div>

              <p className="dg-fix">
                <span className="dg-k">recommended action</span> {r.recommendedAction}
              </p>
            </div>
          )}

          <div className="run-cost">
            {rec.decisions.length === 0
              ? "no proposal reached the analyst"
              : rec.decisions
                  .map(
                    (d) =>
                      `proposal ${d.decision}${d.verdict ? ` (${d.verdict})` : ""}${
                        d.reason ? `: ${d.reason}` : ""
                      }`,
                  )
                  .join(" · ")}
            {" · "}
            <code>
              uv run alert-forensics replay runs/{rec.scenario}/{rec.recording}/run.json
            </code>
          </div>
        </div>
      )}
    </article>
  );
}

export function Runs({ recordings }: { recordings: Recording[] }) {
  const [open, setOpen] = useState<Set<string>>(new Set());
  if (recordings.length === 0) return null;

  const rank = (id: string) => {
    const i = SCENARIO_ORDER.indexOf(id);
    return i < 0 ? 99 : i;
  };
  const ordered = [...recordings].sort(
    (a, b) => rank(a.scenario) - rank(b.scenario) || a.recording.localeCompare(b.recording),
  );
  const scenarios = [...new Set(ordered.map((r) => r.scenario))];
  const gates = ordered.filter((r) => r.recording.startsWith("probe-")).length;

  const toggle = (id: string) =>
    setOpen((cur) => {
      const next = new Set(cur);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  return (
    <section className="runs-section" aria-label="reference transcripts">
      <div className="eyebrow">reference transcripts</div>
      <h2 className="section-title">Real runs, replayable</h2>
      <p className="section-lede">
        These are the committed recordings under <code>runs/</code>: {recordings.length}{" "}
        real model runs across {scenarios.length} scenarios, of which {gates} are gate runs of
        the priced tiers on scenario 1. They are not the campaign&apos;s runs and are not
        measurement; which runs are committed is a rule in the spec, a run the spec cites or
        the scenario&apos;s first completed real run, so they are not the best ones. Each shows
        the tool calls in the order the model made them and, on a run that produced a
        result, every observed fact with the tool its citation resolves to.{" "}
        <code>alert-forensics replay</code> verifies each raw response against the recorded
        hash before printing the same thing.
      </p>

      {scenarios.map((scenario) => {
        const gloss = glossOf(scenario);
        return (
          <div key={scenario} className="runs-group">
            <div className="runs-group-head">
              {gloss && <span className="gl-num">{gloss.number}</span>}
              <span className="runs-group-id">{scenario}</span>
              {gloss && <span className="runs-group-desc">{gloss.gloss}</span>}
            </div>
            <div className="runs-list">
              {ordered
                .filter((r) => r.scenario === scenario)
                .map((r) => {
                  const key = `${r.scenario}/${r.recording}`;
                  return (
                    <Transcript
                      key={key}
                      rec={r}
                      open={open.has(key)}
                      onToggle={() => toggle(key)}
                    />
                  );
                })}
            </div>
          </div>
        );
      })}
    </section>
  );
}
