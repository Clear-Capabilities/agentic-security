# M4 deliverable #9 — Watch-mode graph delta updates — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `agentic-security dataflow watch` — a long-running CLI
command that re-runs a deep lineage scan on every debounced file-system
change, reports the real `GraphDiff` since the last rescan (added/removed/
changed nodes/edges/dataElements/flows), and optionally evaluates
operator drift policies against it, all in-memory, with zero risk to the
commit-keyed `GraphSnapshot` history sub-project 8a/8b already ships.

**Architecture:** Reuse three already-shipped primitives unmodified —
`watch-mode.js`'s `watchProject` (fs-event subscription/debounce, built
for an earlier PRD, generic enough to reuse as-is), `graph-diff.js`'s
`computeGraphDiff`, and `drift-policy.js`'s `evaluateDriftPolicies` (both
sub-project 8b). The one piece of new logic is a small, additive
extraction in `graph-snapshot.js` (`buildGraphSnapshot`, pure/no-I/O) that
lets the CLI build `GraphSnapshot`-shaped records for two successive
rescans WITHOUT ever calling `persistGraphSnapshot` — avoiding the
real risk of overwriting real, commit-keyed snapshot history with
transient uncommitted-edit state (see the scoping doc's §2 for why this
matters). Everything else is new CLI wiring following `dataflow diff`'s
own already-established conventions.

**Tech Stack:** Node ≥ 24, ESM, `node:fs/promises` (`fs.watch`, already in
use by `watch-mode.js` — no new dependency), the existing `node --test`
runner.

**Spec:** `docs/superpowers/plans/2026-09-02-data-flow-explorer-m4-watch-mode-scoping.md`
— read in full before starting either task. It documents the real
investigation this plan is built on: `watchProject` is directly reusable
with zero changes; `GraphSnapshot`'s commit-keyed persistence must NOT be
reused for watch-mode's own "before" state (§2); `explore` has no
live-reload (§3, and this sub-project deliberately does not add one);
lineage analysis has no incremental-rebuild support (§4, a disclosed,
un-closed performance gap, not attempted here).

## Global Constraints

- Never call `persistGraphSnapshot` from watch-mode code — only the new
  `buildGraphSnapshot` (in-memory, no disk write). This is the single
  most load-bearing rule in this plan; violating it corrupts real,
  commit-keyed snapshot history sub-project 8a/8b already shipped.
- `watch-mode.js` itself (the `watchProject`/`computeDelta`/
  `persistStatus`/`renderStatusLine` module) is reused **unmodified** —
  zero changes to that file. Only `watchProject` is imported; the other
  three exports are SAST-finding-shaped and not used here.
- `dataflow watch` does NOT write `.agentic-security/lineage-graph.json`
  on any rescan (scoping doc §3's "decided here" note) — a deliberate,
  disclosed scope boundary.
- `--fail-on-drift` (mirroring `dataflow diff`'s own flag) changes ONLY
  how loudly a violation prints — it has no exit-code meaning for a
  long-running process (there is no single exit code to gate on).
- `AGENTIC_SECURITY_NO_WATCH=1` (already read by `watchProject` itself)
  is the opt-out; no new env var is introduced for this.
- Touching `scanner/bin/agentic-security.js` requires `npm run build`
  before the final commit, with the bundle + sha256 sidecar confirmed
  regenerated. If new `dist/*.index.js` chunks appear, `git add` them.
- Existing `graph-snapshot.js` tests (`test/lineage/graph-snapshot.test.js`)
  must pass **unmodified** after Task 1's refactor — that is the proof the
  refactor changed nothing observable about `persistGraphSnapshot`'s own
  behavior.

---

### Task 1: Extract `buildGraphSnapshot` from `persistGraphSnapshot`

**Files:**
- Modify: `scanner/src/lineage/graph-snapshot.js`
- Test: `scanner/test/lineage/graph-snapshot.test.js` (extend, don't
  replace — every existing test must keep passing unmodified)

**Interfaces:**
- Produces: `buildGraphSnapshot(graph, scanRoot, opts = {})` → the same
  validated `GraphSnapshot` record `persistGraphSnapshot` already builds
  today (`{id, version, graphId, schemaVersion, commit, capturedAt,
  coverage, graph}`), with **zero disk I/O** — never calls `fs.mkdirSync`/
  `fs.writeFileSync`, never checks `stateWritesEnabled()`. Throws the same
  "internal error — produced an invalid GraphSnapshot" error
  `persistGraphSnapshot` throws today, on the same (should-never-happen)
  condition.
- Consumes: nothing new — the exact same `_gitHead`/`snapshotId`/
  `validateGraphSnapshot` this file already imports/defines.

**Current code** (`scanner/src/lineage/graph-snapshot.js`, read it
directly first to confirm this is still accurate — it may have drifted):

```js
export function persistGraphSnapshot(graph, scanRoot, opts = {}) {
  const commit = _gitHead(scanRoot) || crypto.createHash('sha256').update(JSON.stringify(graph)).digest('hex').slice(0, 12);
  const capturedAt = opts.capturedAt ?? new Date().toISOString();
  const snapshot = {
    id: snapshotId({ graphId: graph.graphId, commit, capturedAt }),
    version: SNAPSHOT_VERSION,
    graphId: graph.graphId,
    schemaVersion: graph.schemaVersion,
    commit,
    capturedAt,
    coverage: graph.coverage ?? {},
    graph,
  };
  const { valid, errors } = validateGraphSnapshot(snapshot);
  if (!valid) {
    throw new Error(`persistGraphSnapshot: internal error — produced an invalid GraphSnapshot: ${JSON.stringify(errors)}`);
  }
  if (stateWritesEnabled()) {
    const dir = _historyDir(scanRoot);
    try { fs.mkdirSync(dir, { recursive: true }); } catch {}
    try { fs.writeFileSync(path.join(dir, `${commit}.json`), JSON.stringify(snapshot, null, 2)); } catch {}
  }
  return snapshot;
}
```

- [ ] **Step 1: Write the failing tests**

Add to `scanner/test/lineage/graph-snapshot.test.js` (this file's real,
existing fixture helpers — confirmed by reading the file directly — are
`_mkGitRepo()` (creates+returns a temp git repo dir) and `_realGraph(source,
opts = {})` (parses `source` as `source.js`, builds a call graph, returns
a real `buildGraphWithCoverage(...).graph`; note it does NOT take the repo
dir — it takes JS source text). Follow this file's own existing tests for
the exact call pattern, e.g. `_realGraph(SOURCE_A)`):

```js
test('buildGraphSnapshot: returns the same shape persistGraphSnapshot builds, with ZERO disk writes', () => {
  const dir = _mkGitRepo();
  try {
    const graph = _realGraph(SOURCE_A); // or this file's own existing source fixture
    const snapshot = buildGraphSnapshot(graph, dir);
    assert.equal(snapshot.commit, execFileSync('git', ['rev-parse', 'HEAD'], { cwd: dir, encoding: 'utf8' }).trim());
    assert.ok(snapshot.id.startsWith('snapshot:'));
    assert.deepEqual(snapshot.graph, graph);
    // The load-bearing assertion: no lineage-snapshots/ directory was created at all.
    assert.equal(fs.existsSync(path.join(dir, '.agentic-security', 'lineage-snapshots')), false,
      'buildGraphSnapshot must never touch disk');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('buildGraphSnapshot: two calls on the SAME commit with different capturedAt produce two independent objects, neither colliding on disk (because neither writes)', () => {
  const dir = _mkGitRepo();
  try {
    const graph = _realGraph(SOURCE_A);
    const a = buildGraphSnapshot(graph, dir, { capturedAt: '2026-01-01T00:00:00.000Z' });
    const b = buildGraphSnapshot(graph, dir, { capturedAt: '2026-01-01T00:00:01.000Z' });
    assert.equal(a.commit, b.commit); // same uncommitted HEAD
    assert.notEqual(a.capturedAt, b.capturedAt);
    assert.notEqual(a.id, b.id); // snapshotId's own discriminator includes capturedAt
    assert.equal(fs.existsSync(path.join(dir, '.agentic-security', 'lineage-snapshots')), false);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd scanner && node --test test/lineage/graph-snapshot.test.js`
Expected: FAIL — `buildGraphSnapshot is not defined` / not exported.

- [ ] **Step 3: Implement the refactor**

Replace the current `persistGraphSnapshot` with:

```js
export function buildGraphSnapshot(graph, scanRoot, opts = {}) {
  const commit = _gitHead(scanRoot) || crypto.createHash('sha256').update(JSON.stringify(graph)).digest('hex').slice(0, 12);
  const capturedAt = opts.capturedAt ?? new Date().toISOString();
  const snapshot = {
    id: snapshotId({ graphId: graph.graphId, commit, capturedAt }),
    version: SNAPSHOT_VERSION,
    graphId: graph.graphId,
    schemaVersion: graph.schemaVersion,
    commit,
    capturedAt,
    coverage: graph.coverage ?? {},
    graph,
  };
  const { valid, errors } = validateGraphSnapshot(snapshot);
  if (!valid) {
    throw new Error(`buildGraphSnapshot: internal error — produced an invalid GraphSnapshot: ${JSON.stringify(errors)}`);
  }
  return snapshot;
}

export function persistGraphSnapshot(graph, scanRoot, opts = {}) {
  const snapshot = buildGraphSnapshot(graph, scanRoot, opts);
  if (stateWritesEnabled()) {
    const dir = _historyDir(scanRoot);
    try { fs.mkdirSync(dir, { recursive: true }); } catch {}
    try { fs.writeFileSync(path.join(dir, `${snapshot.commit}.json`), JSON.stringify(snapshot, null, 2)); } catch {}
  }
  return snapshot;
}
```

Note the error-message prefix changes from `persistGraphSnapshot:` to
`buildGraphSnapshot:` on the internal-invariant-violation path (this
should never fire in real usage — it's a should-never-happen guard, not a
real user-facing error). Before assuming this is safe, grep the existing
test file for that exact string (`persistGraphSnapshot: internal error`)
— if any test pins it, update that one assertion to match, and confirm
no OTHER file references the old string.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd scanner && node --test test/lineage/graph-snapshot.test.js`
Expected: PASS, including every PRE-EXISTING test in the file, unmodified.

Then run the full scope: `npm run test:lineage` — must stay green,
same pass count as before this task except for the 2 new tests.

- [ ] **Step 5: Commit**

```bash
git add scanner/src/lineage/graph-snapshot.js scanner/test/lineage/graph-snapshot.test.js
git commit -m "refactor(lineage): extract buildGraphSnapshot (pure, no I/O) from persistGraphSnapshot"
```

---

### Task 2: `dataflow watch` CLI subcommand

**Files:**
- Modify: `scanner/bin/agentic-security.js`
- Modify: `commands/dataflow.md`
- Test: `scanner/test/cli/dataflow-watch.test.js`

**Interfaces:**
- Consumes: `buildGraphSnapshot` (Task 1), `computeGraphDiff` from
  `../src/lineage/graph-diff.js`, `loadDriftPolicies`/
  `evaluateDriftPolicies` from `../src/lineage/drift-policy.js`,
  `watchProject` from `../src/posture/watch-mode.js`, `runScan` (already
  imported in this file for `cmdScan`).
- Produces: a new `cmdDataflowWatch(args)` function; the `dataflow`
  dispatch `case` gains a third subcommand, `watch`.

**Design** (read `cmdDataflowDiff` in `bin/agentic-security.js` in full
first — this task mirrors its flag-parsing/validation/exit-code
conventions; read `bin/agentic-security.js`'s existing `--watch` handling
inside `cmdScan`, ~line 559-581, for the blocking/status-line/`Ctrl-C`
UX this task also mirrors):

- Dispatch site (`case 'dataflow':`, read it directly first — it may have
  drifted since this plan was written): add
  `else if (sub === 'watch') { process.exit(await cmdDataflowWatch(args)); }`
  alongside the existing `export`/`diff` branches, and update the
  fallback error text to name all three subcommands.
- `cmdDataflowWatch(args)` signature/flags: `dataflow watch [path]
  [--drift-policy <path>]` (`--fail-on-drift` also accepted — see the
  Global Constraints note on what it does here). No `--output`/
  `--format` — this command's whole output IS its live stderr stream,
  unlike `export`/`diff`.
- Validate `--drift-policy` the same way `cmdDataflowDiff` already
  does — reuse that exact validation shape (parse-then-shape-check
  before ever calling `loadDriftPolicies`, per sub-project 8b's own fix
  round for the identical malformed-shape risk). If you find yourself
  duplicating more than ~15 lines of that logic verbatim, consider
  whether it's worth extracting a small shared helper both `cmdDataflowDiff`
  and `cmdDataflowWatch` call — your call, disclose the decision either
  way in your own report.
- Set `process.env.AGENTIC_SECURITY_LINEAGE_DEEP = '1'` before the seed
  scan (mirroring how `cmdScan`'s own `--watch` branch sets
  `AGENTIC_SECURITY_INCREMENTAL`) — this flag is what makes `runScan`
  attach `scan.lineageGraph` at all; without it, every rescan produces no
  graph and this command has nothing to diff.
- **Seed**: `const seed = await runScan(targetAbs, {});` (mirrors the
  existing `--watch` seed exactly). If `seed.scan.lineageGraph` is
  missing (lineage build failed or produced nothing —
  `seed.scan.lineageStatus` names why), print a clear message and
  `return 1` — never start watching with nothing to diff against.
  Otherwise `let prevSnapshot = buildGraphSnapshot(seed.scan.lineageGraph, targetAbs);`
  — a plain closure variable, never persisted.
- **On each debounced change batch** (the `onChange` callback passed to
  `watchProject`): re-run `runScan(targetAbs, {})`, check
  `scan.lineageGraph` the same way, build a fresh snapshot via
  `buildGraphSnapshot`, then:
  - `let diff; try { diff = computeGraphDiff(prevSnapshot, currSnapshot); } catch (e) { print a clear "could not diff" message with e.message and continue watching (do not crash the process on one bad rescan) — mirror the existing --watch's own `catch (e) { process.stderr.write(...); }` pattern around its rescan. }`
  - If `driftPolicyProvided`, call `evaluateDriftPolicies(diff, policies, currSnapshot.graph)`.
  - Print one status line to stderr: counts of
    added/removed/changed nodes/edges/dataElements/flows (mirror
    `renderStatusLine`'s terse style, e.g. `[watch-dataflow] +2/-0 flows, +1/-0 nodes` —
    design the exact terse format yourself, matching the existing
    `[watch]` prefix convention), plus, if any drift violations fired, a
    louder, clearly-marked block naming each one (reuse
    `dataflow diff`'s own Markdown-free plain-text violation rendering
    shape as a model, not its literal Markdown-table code).
  - `prevSnapshot = currSnapshot;` — advance the closure variable.
- Startup banner (stderr, before entering the watch loop): state the
  scan root, that `Ctrl-C` stops it, and — per the scoping doc's own
  disclosed decision — that this command does NOT refresh
  `.agentic-security/lineage-graph.json`, so an already-running `explore`
  session won't reflect live edits.
- `return 0` after `watchProject` is set up (mirrors the existing
  `--watch` — the function itself returns quickly; the Node PROCESS
  stays alive because of the live `fs.watch` async iterator inside
  `watchProject`, not because this function is blocked awaiting
  anything — confirm this by reading `watch-mode.js`'s own
  `watchProject` implementation directly, it is NOT awaited internally.)

**Testing strategy — read this carefully before writing the test file.**
This command does not exit on its own; a test cannot `spawnSync`-and-wait
the way `dataflow-diff.test.js` does. Use ASYNC `spawn` (from
`node:child_process`) instead:

1. Build a real git fixture (mirror `test/cli/lineage-snapshot-persist.test.js`'s
   `mkGitFixture()` helper).
2. `const child = spawn(process.execPath, [BIN, 'dataflow', 'watch', dir], { env: {...process.env} });`
   — collect `child.stdout`/`child.stderr` into a buffer as data arrives
   (`child.stderr.on('data', chunk => { buf += chunk; })`).
3. Poll (a short `setInterval`/loop with a generous overall timeout — this
   repo's own convention is a bounded `until <condition>; do sleep; done`
   shape, translated to JS as a polling `await` loop, NOT a fixed
   `setTimeout` guess) until the buffered stderr contains the startup
   banner text — this proves the seed scan completed and the watcher is
   live.
4. Write a real code change to a file in the fixture (the same
   "add a route reading a sensitive field and logging/sending it"
   shape Task 1/2/3 of sub-project 8b's own test fixtures already use —
   reuse one of those exact fixture bodies rather than inventing a new
   one) — wait at least `DEBOUNCE_MS` (350, from `watch-mode.js` — import
   or hardcode with a comment citing the source) plus real rescan time,
   polling the buffered stderr for the expected delta status line rather
   than a fixed sleep.
5. Assert the status line reflects a real added flow (or whatever the
   fixture change produces — confirm empirically first, don't assume).
6. `child.kill('SIGINT')` (or `SIGTERM` if `SIGINT` doesn't cleanly stop
   `watchProject`'s abort controller — check `watch-mode.js`'s own
   `stop()` handling and whichever signal the process actually needs to
   receive to invoke it, if anything hooks it at all; if nothing in this
   codebase currently wires `SIGINT`→`stop()` for the existing `--watch`
   flag either, `child.kill()` alone — a hard process kill — is an
   acceptable, already-established test-teardown precedent; don't invent
   graceful-shutdown wiring this plan doesn't ask for).
7. Wrap the whole test in a generous top-level timeout (a few seconds
   over the expected debounce+rescan latency) so a genuine regression
   fails the test instead of hanging the suite forever; if this repo's
   test runner has an established per-test timeout convention, use it —
   check a few existing CLI test files for the pattern before inventing
   one.

At minimum, also test:
- `--drift-policy` with a real triggering rule surfaces the violation in
  the live stderr stream (reuse sub-project 8b's own "new PHI → external"
  fixture shape).
- A malformed `--drift-policy` file is a clear, early exit-2 error
  BEFORE the watcher ever starts (this one CAN use `spawnSync`, since it
  should fail fast and exit on its own, never entering the watch loop).
- No lineage build possible (seed scan produces no `scan.lineageGraph`)
  is a clear exit-1 error, not a crash, and does not enter the watch loop.

- [ ] **Step 1: Write the failing tests** (per the strategy above)
- [ ] **Step 2: Run to verify failure** (`node --test test/cli/dataflow-watch.test.js` — confirm each new test fails for the expected reason: unknown subcommand, `cmdDataflowWatch is not defined`, etc.)
- [ ] **Step 3: Wire the CLI** (`cmdDataflowWatch` + dispatch + `commands/dataflow.md`'s own new `watch` section — mirror the `diff` section's own options-table/exit-code-contract style; state plainly that `--fail-on-drift` only affects print volume, not exit code, and that `lineage-graph.json` is not refreshed)
- [ ] **Step 4: Run to verify pass**
- [ ] **Step 5: `npm run build`, confirm bundle sha256 regenerates (and any new dist chunk files are `git add`ed), commit**

```bash
cd scanner && npm run build
git add scanner/bin/agentic-security.js scanner/test/cli/dataflow-watch.test.js scanner/dist/ commands/dataflow.md
git commit -m "feat(dataflow): add \`dataflow watch\` CLI subcommand (M4 deliverable #9)"
```

## Self-review notes (per the writing-plans skill)

- **Spec coverage:** the scoping doc's 4 numbered investigation findings
  are all reflected: §1 (reuse `watchProject` unmodified — Task 2's own
  Interfaces section); §2 (the `buildGraphSnapshot` extraction — all of
  Task 1, plus the Global Constraint forbidding `persistGraphSnapshot`
  anywhere in Task 2's own code); §3 (no `explore` live-reload, no
  `lineage-graph.json` refresh — both named explicitly in Task 2's design
  and its own startup-banner requirement); §4 (no incremental lineage
  support — disclosed as a known limitation, not attempted, no task
  claims to close it).
- **Placeholder scan:** Task 1 has complete, literal code (a small,
  mechanical refactor — appropriate given its size). Task 2 is a design
  spec with exact interfaces, exact reuse targets, and an exact testing
  STRATEGY (not literal test code, since the precise status-line wording
  and exact fixture reuse need the implementer to look at current real
  code first) — this matches sub-project 8b's own Task 3 brief's level of
  detail for a comparably-shaped CLI task.
- **Type consistency:** `buildGraphSnapshot(graph, scanRoot, opts)`'s
  signature (Task 1) is exactly what Task 2 calls, twice (seed + each
  rescan) — confirmed consistent. `computeGraphDiff(before, after)` and
  `evaluateDriftPolicies(diff, policies, graphAfter)` are sub-project 8b's
  own already-shipped, already-tested signatures — reused verbatim, not
  reinvented.
- **Out-of-scope reminder:** no `explore` live-reload; no incremental
  lineage rebuild; no `lineage-graph.json` refresh from watch-mode; no
  change to `watch-mode.js`/the existing SAST `scan --watch` flag.
