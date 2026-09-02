# M4 deliverable #9 — Watch-mode graph delta updates: scoping

## What the parent doc assumed vs. what real investigation found

The M4 top-level scoping doc's own row for this deliverable says: *"A
file-watcher that reruns the scan and emits the same `GraphDiff` #8
produces, just triggered by filesystem events instead of an explicit
'compare two snapshots' command."* That framing undersold how much of this
already exists — and glossed over one real, load-bearing risk.

### 1. A near-identical file-watcher primitive already exists, fully reusable

`scanner/src/posture/watch-mode.js` — built for an EARLIER, unrelated PRD
(continuous SAST re-scan) — already ships:

- `watchProject(scanRoot, onChange, opts)`: subscribes to `fs.promises.watch`
  (Node ≥ 20, no new dependency), debounces bursts at 350ms
  (`DEBOUNCE_MS`), ignores `.git`/`node_modules`/`.agentic-security`/etc.
  (`IGNORE_DIR_RE`), filters to scannable source extensions
  (`SCAN_EXT_RE`), caps a runaway burst at `MAX_BURST=50` (drops the batch
  rather than storming the caller), and returns `{stop}`. It calls
  `onChange(batch)` with the changed absolute paths — the caller decides
  what "rescan" means.
- Already wired into a real CLI command: `agentic-security scan --watch`
  (`bin/agentic-security.js` ~line 559) — confirmed live, not dead code:
  runs a seed scan, then on every debounced change batch re-runs
  `runScan`, computes a SAST-finding delta (`computeDelta`), and writes
  `.agentic-security/watch-status.{md,json}` plus a stderr status line.
  Documented as blocking until `Ctrl-C`, matching `jest --watch`'s shape
  — but MEASURED FALSE during this sub-project's own Task 2 (confirmed
  independently by the coordinator too): `scan --watch` prints its
  banner and exits in well under 1 second on a real fixture, because its
  own dispatch (`process.exit(await cmdScan(args))`) kills the process
  before `watchProject`'s internal `fs.watch` subscription — set up
  inside an un-awaited async IIFE — ever gets a chance to fire. This is a
  real, pre-existing defect in the shipped `scan --watch` feature, not
  something this sub-project caused; fixing it is out of this
  sub-project's own scope (see this doc's own scope section) but a
  future reader must not assume `scan --watch` genuinely watches.
  `dataflow watch`'s own dispatch avoids this exact trap — see
  `bin/agentic-security.js`'s `case 'dataflow':` `watch` branch for the
  fix and its own detailed comment. Opt-out via
  `AGENTIC_SECURITY_NO_WATCH=1` remains real and correctly wired either way.
- **`watchProject` itself needs ZERO changes for the graph-delta case** —
  it's already generic (`onChange(batch)`, no SAST-specific assumption
  baked into the subscription logic itself). Only `computeDelta`/
  `persistStatus`/`renderStatusLine` are SAST-finding-shaped and are NOT
  reused; the graph-delta watcher builds its own equivalents from Task 1
  (`graph-diff.js`) and Task 2 (`drift-policy.js`) of the just-shipped
  sub-project 8b.
- **No dedicated unit test file exists for `watch-mode.js`** (confirmed:
  no `test/**/watch-mode*.test.js`; its only real test coverage today is
  incidental, inside `test/chat-batch5.test.js`). Not this sub-project's
  job to fix that gap in a module it doesn't own — noted so nobody assumes
  a green existing suite proves more than it does.

### 2. The real, load-bearing risk: `GraphSnapshot`'s commit-keyed persistence must NOT be reused naively here

`graph-snapshot.js`'s `persistGraphSnapshot(graph, scanRoot, opts)` keys
every snapshot file by the **real git HEAD commit**
(`.agentic-security/lineage-snapshots/<commit>.json`) — by design, for
sub-project 8a/8b's own cross-COMMIT history use case.

Watch mode's entire reason to exist is reacting to **uncommitted edits**
(the existing `scan --watch`'s own header: *"as the developer edits"*).
During one watch session, the developer typically does NOT commit between
every debounced rescan — so every single rescan in that session resolves
to the **same** git HEAD. Calling `persistGraphSnapshot` on every rescan
would silently **overwrite** `.agentic-security/lineage-snapshots/<HEAD>.json`
in place, over and over, with transient, uncommitted, mid-edit graph state
— destroying whatever real, committed snapshot a LATER `dataflow diff`
call might have wanted to compare against for that exact commit. This is
exactly the class of state-corruption bug this repo's own verification
discipline exists to catch before it ships, not after.

**The fix, decided here rather than left to an implementer's judgment
call:** watch-mode's own "before" state is kept **purely in an in-process
JS closure variable**, never written to the commit-keyed history at all —
the exact same pattern the existing SAST `--watch` already uses for
`prevFindings` (a plain local variable, not a file). `graph-snapshot.js`
needs one small, additive refactor to make this possible cleanly:
`persistGraphSnapshot`'s current construct-and-write-in-one-function
shape gets a **pure builder extracted** — `buildGraphSnapshot(graph,
scanRoot, opts)` returns the same validated `GraphSnapshot` object
`persistGraphSnapshot` already returns today, with **no disk I/O at all**;
`persistGraphSnapshot` becomes a thin wrapper: build via the new function,
then write when `stateWritesEnabled()`, exactly its current external
behavior, byte-for-byte (a pure refactor, not a behavior change — the
existing `graph-snapshot.test.js` suite must stay green unmodified,
proving this). Watch-mode calls `buildGraphSnapshot` directly, on every
rescan including the seed, and never calls `persistGraphSnapshot` at all.

### 3. `agentic-security explore`'s server has no live-reload — confirmed, not assumed

Read `src/server/routes.js`/`http-server.js`/`bin/agentic-security.js`'s
`cmdExplore` directly: `loadSignedGraph(targetAbs)` is called **once**,
before the server starts, and the loaded graph is embedded into the
server's closure — there is no per-request reload, no file-watcher, no
websocket/SSE push mechanism anywhere in that module. So writing a fresh
`.agentic-security/lineage-graph.json` from a separate `dataflow watch`
process would **not** make an already-running `explore` browser tab
update live. Making `explore` itself hot-reload is real, separate,
Milestone-3-server-touching scope this sub-project does **not** take
on — disclosed here explicitly so nobody assumes "watch-mode" means "the
website updates live" the way the parent doc's loose "graph delta
updates" phrasing might suggest. This sub-project is CLI-only, matching
`dataflow diff`'s own already-shipped precedent (8b, no UI component).

**Decided here, to keep this sub-project's own scope tight: `dataflow
watch` does NOT refresh `.agentic-security/lineage-graph.json` on every
rescan.** That refresh (plus its Ed25519/HMAC signing) is currently
inlined inside `cmdScan`'s own persistence block (`bin/agentic-security.js`
~lines 963-1097), not a standalone reusable function — extracting it
cleanly would be a second refactor of the same shape as
`buildGraphSnapshot` below, for a benefit that's real but modest (given
§3's own finding that an already-running `explore` tab wouldn't see it
anyway; only a session started fresh mid-watch would). Not worth the
added coupling for a "Medium" sub-project. `dataflow watch`'s own output
is the delta report only; running a real `agentic-security scan
--format json` (with `AGENTIC_SECURITY_LINEAGE_DEEP=1`) after stopping a
watch session, the same way a developer already would today, is what
refreshes the single-current artifact — unchanged from today's behavior.
A future increment could extract that persistence helper and wire it in;
not attempted here.

### 4. No incremental lineage-build support exists — confirmed, disclosed as a real, un-closed performance gap

`AGENTIC_SECURITY_INCREMENTAL=1` (the flag the existing SAST `--watch`
already sets) speeds up the **taint engine** only
(`dataflow/incremental-cache.js`) — confirmed via grep: nothing under
`src/lineage/` reads or benefits from it. Every `dataflow watch` rescan is
therefore a full `AGENTIC_SECURITY_LINEAGE_DEEP=1` rebuild, same cost as a
one-shot `agentic-security scan --format json` with that flag set. This is
a real, disclosed limitation (not a blocker — `docs/lineage/PRIVACY_COMPARISON.md`'s
own perf harness already measured the one-shot lineage-build overhead as
"well under target" on the reference fixture), not attempted to be closed
here; a future increment could add incremental lineage support, but
nothing in this sub-project's own scope commits to it.

## Scope for this sub-project

**In scope:**

- `graph-snapshot.js`: extract `buildGraphSnapshot` (pure, no I/O) from
  `persistGraphSnapshot` (additive refactor, existing tests must stay
  green unmodified — the proof this didn't change behavior).
- A new `dataflow watch [path] [--drift-policy <path>] [--fail-on-drift]`
  CLI subcommand (`bin/agentic-security.js`), mirroring `dataflow diff`'s
  own conventions (fail-closed, clean exit-code contract) and the existing
  `scan --watch`'s own blocking/`Ctrl-C`/stderr-status-line UX:
  - Seeds an initial `AGENTIC_SECURITY_LINEAGE_DEEP=1` scan, builds an
    in-memory `GraphSnapshot` via `buildGraphSnapshot` (never
    `persistGraphSnapshot`), keeps it in a closure variable.
  - On every debounced `watchProject` change batch: reruns the deep scan,
    builds a fresh in-memory `GraphSnapshot`, computes
    `computeGraphDiff(prevSnapshot, currSnapshot)` (Task 1's own function,
    reused unmodified), optionally evaluates `--drift-policy` via
    `evaluateDriftPolicies` (Task 2's own function, reused unmodified),
    and prints a one-line status (added/removed/changed counts + any
    violations) to stderr. Does NOT touch
    `.agentic-security/lineage-graph.json` (see §3's own "decided here"
    note above) — a real, disclosed, deliberate scope boundary, not an
    oversight.
  - `--fail-on-drift` has no meaning for a long-running watch process
    (there is no single exit code to gate) — the flag instead makes a
    detected violation print louder (e.g. a distinct stderr marker), never
    changes when the process exits; disclosed explicitly in
    `commands/dataflow.md`, not silently reinterpreted.
  - `Ctrl-C` / an external stop is the only way the process ends;
    `AGENTIC_SECURITY_NO_WATCH=1` (the existing, already-established
    opt-out `watchProject` itself already honors) disables it the same way
    it disables the existing SAST watch.
- `commands/dataflow.md`: a new `watch` section, disclosing the no-live-UI
  and no-incremental-lineage limitations explicitly (matching this repo's
  own established honesty convention — see `graph.limitations`'s
  precedent elsewhere in this package).
- Tests: a real `graph-snapshot.test.js` extension proving
  `buildGraphSnapshot` + `persistGraphSnapshot`'s wrapper behavior is
  unchanged; a real CLI test (mirroring `test/cli/dataflow-diff.test.js`'s
  own real-git-fixture, real-subprocess pattern, but driving
  `watchProject`'s subscription directly rather than spawning a
  genuinely-long-lived blocking subprocess — see the plan's own Task 2 for
  the exact testing strategy, since `dataflow watch` blocks until
  `Ctrl-C`/abort and a test cannot spawn-and-wait-forever).

**Out of scope, disclosed, not attempted:**

- Live-reloading an already-running `explore` server (a Milestone-3-server
  change, not this deliverable's own row).
- Incremental (non-full-rebuild) lineage analysis (a real, separate,
  disclosed performance gap — `src/lineage/` has no incremental hook
  today).
- A frontend/website "watch" indicator or live graph view (matches
  `dataflow diff`'s own CLI-only precedent from sub-project 8b).
- Any change to the existing SAST `scan --watch` flag or `watch-mode.js`
  itself beyond zero — it is reused, not modified.

## Sizing

Confirmed "Medium" per the parent doc's own estimate — most of the
underlying primitives (`watchProject`, `computeGraphDiff`,
`evaluateDriftPolicies`, `buildLineageGraph`/`buildGraphWithCoverage`)
already exist and are reused unmodified; the real new work is the
`buildGraphSnapshot` extraction (small, mechanical, already-tested module)
plus the CLI wiring + its own tests (the bulk of the effort, comparable in
shape to sub-project 8b's own Task 3, not its Tasks 1/2). Scoped as a
single implementation plan, likely 1-2 tasks (the snapshot refactor is
small enough to fold into the CLI task's own first step rather than stand
alone as a separately-reviewed task, per this repo's own "fold setup into
the task whose deliverable needs it" plan-writing convention) — see the
companion `-plan.md` for the exact task breakdown.
