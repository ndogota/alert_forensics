# web

The matrix page: a static read of two committed sources, `../reports/model-matrix.json`
and the recordings under `../runs/`. It runs no server, needs no key and fetches nothing
at runtime. Everything it shows is read once at build time and baked into the HTML. The
decision is in `../docs/SPEC.md` under "Demonstration".

The structure and the visual language are ported from pod_forensics's dashboard so the
two projects read as siblings. The metrics are not: this project has no model judge, and
the file the page reads says so in `metadata.judge_model: null`.

## Build

```
pnpm install
pnpm build          # next build, static export under out/
```

`next.config.mjs` sets `output: "export"`, so the build writes a fully static site to
`out/`. JetBrains Mono is self-hosted by `next/font`, which fetches it once at build
time. `pnpm dev` serves the page at `http://localhost:3000` while editing.

The page reads `../reports/model-matrix.json` and `../runs/*/*/run.json` relative to
this directory. A checkout without the matrix file still builds and renders a
placeholder that says how to generate it.

## Vercel

The root directory must be `web`. With that set, the framework preset is detected as
Next.js, the build command is `next build`, and the output is the static export. No
environment variable is needed at build or at runtime.

The build reads two directories above `web/`, `reports/` and `runs/`. Vercel's
"Include source files outside of the Root Directory in the Build Step" setting must stay
enabled, which is its default, or the page builds to the placeholder.

## Updating the page

The page changes when either committed source changes: regenerate the matrix file with
`uv run alert-forensics matrix campaigns/03 -o reports/model-matrix.json` from the
repository root, or commit a new recording under `runs/`, then push. Nothing on the page
is typed in; every number is in one of those two sources.
