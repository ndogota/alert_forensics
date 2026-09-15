// A committed recording, runs/<scenario>/<recording>/run.json, projected to what
// the transcript view shows: every tool call in order and, on a run that
// produced a result, each observed fact with the tool its citation resolves
// to. The projection is pure; reading the files is lib/load.ts's job at build
// time. Nothing here is typed in: every field is read from the artifact.

export interface RecordedCall {
  id: string;
  step: number;
  tool: string;
  system: string;
  args: string;
  outcome: string;
  failureKind: string | null;
  durationMs: number;
}

export interface Citation {
  id: string;
  tool: string | null;
  outcome: string | null;
}

export interface RecordedFact {
  index: number;
  statement: string;
  grounded: boolean;
  citations: Citation[];
  problems: string[];
}

export interface RecordedResult {
  verdict: string;
  confidence: number;
  escalate: boolean;
  techniques: string[];
  facts: RecordedFact[];
  assumptions: { statement: string; why: string }[];
  missingContext: { what: string; why: string; how: string }[];
  recommendedAction: string;
}

export interface Recording {
  scenario: string;
  recording: string;
  alertTitle: string;
  model: string;
  role: string;
  startedAt: string;
  outcome: string;
  passes: number;
  corrections: number;
  error: { kind: string; message: string } | null;
  calls: RecordedCall[];
  result: RecordedResult | null;
  decisions: { decision: string; verdict: string | null; reason: string | null }[];
  modelTurns: number;
  inputTokens: number;
  outputTokens: number;
}

type Json = Record<string, unknown>;

function obj(x: unknown): Json {
  return x && typeof x === "object" && !Array.isArray(x) ? (x as Json) : {};
}

function arr(x: unknown): unknown[] {
  return Array.isArray(x) ? x : [];
}

function str(x: unknown, fallback = ""): string {
  return typeof x === "string" ? x : fallback;
}

function num(x: unknown, fallback = 0): number {
  return typeof x === "number" && Number.isFinite(x) ? x : fallback;
}

function compactArgs(args: unknown): string {
  const entries = Object.entries(obj(args));
  return entries
    .map(([k, v]) => `${k}=${typeof v === "string" ? v : JSON.stringify(v)}`)
    .join(", ");
}

// The failure kind of a call that did not end ok, read from the structured
// failure the model received: its `error` field names the kind.
function failureKind(outcome: string, response: unknown): string | null {
  if (outcome === "ok") return null;
  const kind = obj(response).error;
  return typeof kind === "string" ? kind : null;
}

export function projectRecording(
  scenario: string,
  recording: string,
  artifact: unknown,
): Recording {
  const a = obj(artifact);
  const trace = obj(a.trace);
  const records = arr(trace.records).map(obj);
  const calls: RecordedCall[] = records.map((r) => {
    const outcome = str(r.outcome);
    return {
      id: str(r.tool_call_id),
      step: num(r.step),
      tool: str(r.tool_name),
      system: str(r.source_system),
      args: compactArgs(r.arguments),
      outcome,
      failureKind: failureKind(outcome, r.redacted_response),
      durationMs: num(r.duration_us) / 1000,
    };
  });
  const byId = new Map(calls.map((c) => [c.id, c]));

  const report = a.report == null ? null : obj(a.report);
  let result: RecordedResult | null = null;
  if (report) {
    const res = obj(report.result);
    result = {
      verdict: str(res.verdict),
      confidence: num(res.confidence),
      escalate: res.escalate === true,
      techniques: arr(res.mitre_techniques).map((t) => str(t)),
      facts: arr(report.facts)
        .map(obj)
        .map((f) => ({
          index: num(f.index),
          statement: str(f.statement),
          grounded: f.grounded === true,
          citations: arr(f.evidence_ids).map((id) => {
            const call = byId.get(str(id));
            return {
              id: str(id),
              tool: call ? call.tool : null,
              outcome: call ? call.outcome : null,
            };
          }),
          problems: arr(f.problems)
            .map(obj)
            .map((p) => `${str(p.kind)} on ${str(p.evidence_id)}`),
        })),
      assumptions: arr(res.assumptions)
        .map(obj)
        .map((s) => ({ statement: str(s.statement), why: str(s.why_unverified) })),
      missingContext: arr(res.missing_context)
        .map(obj)
        .map((m) => ({
          what: str(m.what),
          why: str(m.why_it_matters),
          how: str(m.how_to_obtain),
        })),
      recommendedAction: str(res.recommended_action),
    };
  }

  const usage = arr(trace.usage).map(obj);
  const error = a.error == null ? null : obj(a.error);
  return {
    scenario,
    recording,
    alertTitle: str(obj(trace.alert).title),
    model: str(a.model),
    role: str(a.role),
    startedAt: str(trace.started_at),
    outcome: str(a.outcome),
    passes: num(a.passes),
    corrections: arr(a.corrections).length,
    error: error ? { kind: str(error.kind), message: str(error.message) } : null,
    calls,
    result,
    decisions: arr(a.decisions)
      .map(obj)
      .map((d) => ({
        decision: str(d.decision),
        verdict: str(obj(d.proposal).verdict) || null,
        reason: d.reason == null ? null : str(d.reason),
      })),
    modelTurns: usage.length,
    inputTokens: usage.reduce((n, u) => n + num(u.input_tokens), 0),
    outputTokens: usage.reduce((n, u) => n + num(u.output_tokens), 0),
  };
}
