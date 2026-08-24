# scanner/

Node-only scan engine. ESM throughout, Node ≥ 24. The CLI bundle (`dist/agentic-security.mjs`) is built from `bin/agentic-security.js` and committed; the `src/` tree is what tests run against.

## Build invariants

- After **any** change to `src/` or `bin/`, run `npm run build` before relying on the bundle. `bin/` is the test entry point and re-imports `src/` directly, so unit tests don't require a rebuild — but anything calling the bundle (the CI gate, hooks, the published `npx` command) will be stale until you rebuild.
- The build is `ncc build … --minify`. Output is a single ESM file plus a SHA-256 sidecar. The hashing step is part of `npm run build`; do not commit the bundle without it.
- `chmod +x` is part of the build. If a `permission denied` shows up on `node dist/agentic-security.mjs`, rerun the build — somebody copied the file and lost the bit.

## Test commands (scoped, premortem-derived)

`npm test` is the full CI gate — `scripts/run-unit-tests.mjs` runs the scoped scripts below in ONE `node --test` invocation over their combined file list (derived from the scripts themselves, not hand-duplicated) rather than eleven separate processes, plus `test/cpp-dataflow.test.js` and `test:python` as their own steps afterward. For day-to-day work, use the scoped variants below individually — they're faster for one area and avoid blowing the context window:

| Script | Covers | When to run |
|--------|--------|-------------|
| `npm run test:smoke` | The end-to-end vulnerable-js fixture (~13 s: it runs a real scan, so it is the cheapest MEANINGFUL check, not an instant one) | After any change anywhere |
| `npm run test:sast` | Detector modules in `src/sast/` | When editing a SAST rule |
| `npm run test:posture` | Posture modules in `src/posture/` | When editing a posture annotator |
| `npm run test:dataflow` | IR, taint engine, calibration, held-out evaluator | When editing `src/dataflow/`, `src/ir/`, or calibration |
| `npm run test:mcp` | MCP server tools + audit log | When editing `src/mcp/` |
| `npm run test:report` | Report emit (SARIF/JUnit/CI/PoC/verifier) | When editing `src/report/` |
| `npm run test:lifecycle` | Dead-code + dead-module guards | Before committing a remediation that adds new modules |
| `npm run smoke` | One-shot: run the CLI against the vulnerable-js fixture | Sanity-check the bundle |

Every test file under `test/*.test.js` should be assigned to one of these scoped scripts. If you add a new test file, also add it to the matching script in `package.json` — `npm run test:lifecycle` will warn if a new module ships without a wire-up, but it won't catch tests dropped from scope.

## Key conventions

- **Findings schema** — `{ id, severity, file, line, vuln, cwe, description, remediation, parser, family, … }`. `parser` + `family` are required; `posture/finding-defaults.js` backfills before confidence/calibration so detectors that forget to set them still calibrate correctly.
- **No runtime cloud calls** — OSV/KEV data is fetched lazily and disk-cached under `~/.claude/agentic-security/osv-cache/`. Anything new that needs the network must be opt-in and degrade gracefully when offline.
- **`scan.findings` is the SAST array.** Secrets live on `scan.secrets`, supply-chain on `scan.supplyChain`, business-logic on `scan.logicVulns`. The report `normalizeFindings` merges them; engine code should keep them separate.
- **Suppression pragmas** — `// agentic-security-ignore: <rule-id>` on the offending line suppresses that rule for that line. `_applyIgnorePragmas` runs twice in `engine.js`: once after the cross-file passes, once after the deep-mode IR append. If you add a stage that appends findings, it must run after your stage too, or pragmas will be inert for whatever it produces. A finding with no integer `line` cannot be suppressed at all — see the root `CLAUDE.md` bullet.
- **Determinism** — `--deterministic` and `AGENTIC_SECURITY_LLM_VALIDATE` should produce byte-identical SARIF run-to-run. Sort outputs before emit; never use `Date.now()` in a finding ID.

## Subdirectory pointers

- `src/sast/CLAUDE.md` — how to add a new SAST module (was previously in root)
- `src/posture/CLAUDE.md` — what each module category is for (90+ modules, indexed there)
- `src/dataflow/CLAUDE.md` — k=1 monovariant scope, `SummaryCache` keying, what the engine does NOT model
- `src/mcp/CLAUDE.md` — MCP tool inventory, OWASP MCP Top 10 mapping, reserved-write list

(Fixture conventions and smoke-vs-unit scoping are covered above under "Test commands" — a separate test-directory guide was referenced here but never existed; found by the doc-drift checker at scripts/check-doc-drift.mjs and removed rather than left dangling.)

## LSP for self-development

The bundled LSP at `bin/agentic-security-lsp.js` ships to **users** for inline findings in their editors. It is not currently part of the development loop for this repo — Claude Code and the scanner test suite already cover internal needs. If you want to dogfood it, run `node bin/agentic-security-lsp.js` and point your editor's LSP client at it, but this is not a documented or supported workflow for contributors yet.
