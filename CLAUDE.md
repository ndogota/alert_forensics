# CLAUDE.md

alert_forensics, a SOC alert triage agent whose every claim cites the tool call
behind it. Read `docs/SPEC.md` before anything else. It is the design authority
and every decision in this repository is settled there.

## Rules

1. **The spec first.** A decision goes into `docs/SPEC.md` before the code that
   implements it, with the reason it was taken. Where the spec is silent,
   decide, write it down, then build. Where the spec and the code disagree, say
   so and stop; do not quietly pick a side.

2. **Git writes are limited to commits of the session's own work.** When the
   gates are green, stage exactly the files the session changed and commit them,
   grouped as separate commits where that is warranted, each with a subject and a
   body and no trailers, and report the hashes. Never push, branch, tag, rebase,
   amend, or rewrite history in any way, and never stage or commit anything
   outside the work of the session.

   **A commit a session makes is never cited back as evidence about the tree it
   found.** The case, on 2026-09-15: a stray working-tree edit, `.venv/` replaced
   by `venv/` plus `results.bak`, was committed as b338eb3 at 15:07 with an empty
   body, the first since 344d055, on the parent 6e4ff06; eight minutes later the
   session fixed the edit in 12ce9e0 and reported that it "was already committed
   in b338eb3", presenting the write as a state it had found, and the audit
   attributes b338eb3 to that same session. The commit stands, since history is
   never rewritten; the rule it leaves is this one. The state of the tree at the
   start of a session is what `git status` and `git log` showed then, and the
   report quotes it as such. Everything a session commits is the session's own
   writing, reported with its hash as something it made, and a report that cites
   a hash as "already there" cites one that predates the session's first command.
   A session that cannot tell which is which says so rather than choosing the
   reading that clears it. Every commit carries a body: an empty one is how a
   write like b338eb3 goes unexplained.

3. **Tests fail first.** Every behaviour arrives with a test that fails before
   the change and passes after. Say which ones failed and why.

4. **Re-run the full suite before reporting a number.** A count taken partway
   through the work is stale and will be checked.

   ```
   uv run pytest
   uv run ruff check . && uv run ruff format --check .
   uv run mypy --strict src/
   ```

   Quote the final summary line verbatim: passes, failures, skips. A failure is
   a failure. Do not call one expected unless pytest marks it `xfail`.

5. **Report what you decided and what you could not test.** A named untested
   path is worth more than an implied green.

## House style

- No em-dashes, anywhere: code, comments, documentation, output.
- Guarantees are structural where they can be. A rule held by a type or a
  validator beats a rule asked for in a prompt. Where something is best effort,
  say so beside what is guaranteed, the way the grounding report and the
  redaction section already do.
- Nothing scenario-specific enters `src/alert_forensics/agent/prompts.py`. The
  taxonomy and the method belong there; the answer to any given alert does not.
- Recordings under `runs/` are real model runs only, never generated from the
  scripted client.
- Raw responses stay out of context, by ref and hash. Views are closed schemas
  and tabular views are allowlisted per tool.
- The test suite opens no socket and reads no key.
