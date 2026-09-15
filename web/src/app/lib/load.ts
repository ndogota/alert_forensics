import { readdir, readFile } from "node:fs/promises";
import path from "node:path";

import type { MatrixArtifact } from "./matrix";
import { projectRecording, type Recording } from "./recordings";

// Both sources are read once, at build time, from the repository root above
// web/: the committed matrix file and the committed recordings. Every read is
// guarded, so a checkout without one of them still builds and the page says
// what is missing rather than failing. Nothing is read at runtime.
const ROOT = path.resolve(process.cwd(), "..");
const MATRIX = path.join(ROOT, "reports", "model-matrix.json");
const RUNS = path.join(ROOT, "runs");

export async function loadMatrix(): Promise<MatrixArtifact | null> {
  try {
    const raw = await readFile(MATRIX, "utf8");
    const m = JSON.parse(raw) as MatrixArtifact;
    return Array.isArray(m.cells) && m.cells.length > 0 ? m : null;
  } catch {
    return null;
  }
}

async function dirs(dir: string): Promise<string[]> {
  try {
    const entries = await readdir(dir, { withFileTypes: true });
    return entries
      .filter((e) => e.isDirectory())
      .map((e) => e.name)
      .sort();
  } catch {
    return [];
  }
}

// One Recording per runs/<scenario>/<recording>/run.json, scenario order and
// recording order both lexical, which is the order runs/README.md lists them.
export async function loadRecordings(): Promise<Recording[]> {
  const out: Recording[] = [];
  for (const scenario of await dirs(RUNS)) {
    for (const recording of await dirs(path.join(RUNS, scenario))) {
      const file = path.join(RUNS, scenario, recording, "run.json");
      try {
        const raw = await readFile(file, "utf8");
        out.push(projectRecording(scenario, recording, JSON.parse(raw)));
      } catch {
        // A directory without an artifact is not a recording.
      }
    }
  }
  return out;
}
