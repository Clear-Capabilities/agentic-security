# M4 Deliverable #8, Sub-project 8a: GraphSnapshot Contract + Persistence + Comparability — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the `GraphSnapshot` §10.10 extension contract, a
persist/load history mechanism for the `DataFlowGraph v1`, and a
comparability check — the foundation sub-project 8b's `GraphDiff`
computation depends on.

**Architecture:** A new pure contract/validation module
(`graph-snapshot.js`, mirroring `obligation-mapping.js`/`decision-story.js`'s
own shape exactly); a persist/load mechanism mirroring
`posture/sbom-diff.js`'s own proven architecture (persist-by-git-commit,
most-recent-by-mtime lookup) adapted to graph entities; wired into the
scan flow additively, alongside — never replacing — the existing single
`.agentic-security/lineage-graph.json`.

**Tech Stack:** Plain ESM, no new dependencies. Reuses
`posture/state-dir.js`'s `statePath`/`stateWritesEnabled`,
`util/git-hardening.js`'s `hardenGitArgs`/`hardenGitEnv`.

**Spec:** `2026-09-02-data-flow-explorer-m4-fr503-time-machine-scoping.md`
(FR-503, DFG-022, PRD §14 lines 481-491, §10.10 lines 966-969, AC-27
lines 1739-1741 — read the scoping doc first, every design decision
below is grounded there).

## Global Constraints

- `GraphSnapshot` records are explicitly NOT `DataFlowGraph v1` entities
  (§10.10, same rule as `ObligationMapping`/`DecisionStory`) — never
  added to `dataflow-graph.schema.json`, never routed through
  `validate.js`.
- Never fabricate comparability. `snapshotsComparable` may only report
  `comparable: true` when a real, checkable signal (today: `schemaVersion`
  equality) actually holds — the disclosed `configHash`/analyzer-version
  gap (see the scoping doc) is a real, honest limitation, not silently
  papered over.
- **A real, load-bearing gap found during scoping investigation, binding
  on Task 1**: `engine.js`'s own call site to `buildLineageGraph` never
  passes `opts.commit` — every real graph's own `graphId` today embeds
  the literal string `uncommitted` regardless of the repo's actual git
  state (`graph-builder.js:430`'s own `opts.commit ?? 'uncommitted'`
  default always applies in practice). Snapshot keying CANNOT use the
  graph's own `graphId` commit component for this reason — it must
  resolve the real git HEAD independently, mirroring `sbom-diff.js`'s
  own `_gitHead(scanRoot)` helper exactly (hardened via
  `hardenGitArgs`/`hardenGitEnv`), never reading `graph.graphId` as if
  it reflected the real commit.
- Real-graph tests required for every new function — at least one test
  per new function must exercise a real `buildGraphWithCoverage`-built
  graph, not only hand-built objects.
- New test files must be added to `scanner/package.json`'s
  `test:lineage` script.

---

### Task 1: `graph-snapshot.js` — contract, persistence, comparability

**Files:**
- Create: `scanner/src/lineage/graph-snapshot.js`
- Modify: `scanner/src/lineage/ids.js` (add `snapshotId`)
- Test: `scanner/test/lineage/graph-snapshot.test.js`

**Interfaces:**
- Consumes: `statePath`, `stateWritesEnabled` from
  `../posture/state-dir.js`; `hardenGitArgs`, `hardenGitEnv` from
  `../util/git-hardening.js`; a real `DataFlowGraph v1` object.
- Produces: `validateGraphSnapshot(record)` (`{valid, errors}`, mirrors
  `validateObligationMapping`/`validateDecisionStory`'s own contract),
  `persistGraphSnapshot(graph, scanRoot, opts)` (writes and returns a
  `GraphSnapshot` record), `loadSnapshots(scanRoot)` (all persisted
  snapshots, newest first), `loadSnapshot(scanRoot, commitKey)` (one
  snapshot by its commit key, or `null`), `mostRecentPriorSnapshot(scanRoot,
  excludeCommitKey)` (the newest snapshot that isn't the given one, or
  `null` — the default "compare against" target sub-project 8b's CLI will
  use), `snapshotsComparable(a, b)` (`{comparable, reasons}`). Sub-project
  8b's `computeGraphDiff` consumes two `GraphSnapshot.graph` fields
  directly.

- [ ] **Step 1: Write the failing tests**

```js
// scanner/test/lineage/graph-snapshot.test.js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { execFileSync } from 'node:child_process';
import {
  validateGraphSnapshot, persistGraphSnapshot, loadSnapshots, loadSnapshot,
  mostRecentPriorSnapshot, snapshotsComparable,
} from '../../src/lineage/graph-snapshot.js';
import { buildGraphWithCoverage } from '../../src/lineage/coverage.js';
import { parseJsFile } from '../../src/ir/parser-js.js';
import { buildCallGraph } from '../../src/ir/callgraph.js';

function _mkGitRepo() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'graph-snapshot-'));
  execFileSync('git', ['init', '-q'], { cwd: dir });
  execFileSync('git', ['config', 'user.email', 'test@test.com'], { cwd: dir });
  execFileSync('git', ['config', 'user.name', 'Test'], { cwd: dir });
  fs.writeFileSync(path.join(dir, 'README.md'), 'x');
  execFileSync('git', ['add', '.'], { cwd: dir });
  execFileSync('git', ['commit', '-q', '-m', 'init'], { cwd: dir });
  return dir;
}

function _realGraph(source, opts = {}) {
  const perFile = { 'source.js': parseJsFile('source.js', source) };
  const callGraph = buildCallGraph(perFile);
  return buildGraphWithCoverage(callGraph, { repository: 'r', generatedAt: '1970-01-01T00:00:00.000Z', ...opts }).graph;
}

const SOURCE_A = `function h(req, logger) { logger.info('x', req.body.email); }`;

test('validateGraphSnapshot: rejects a record missing a required §10.10 field, accepts a well-formed one', () => {
  const bad = validateGraphSnapshot({ id: 'snapshot:abc' });
  assert.equal(bad.valid, false);
  assert.ok(bad.errors.length > 0);

  const good = validateGraphSnapshot({
    id: 'snapshot:abc123', version: '1', graphId: 'dfg:r:abc:default',
    schemaVersion: '1.0.0', commit: 'abc123', capturedAt: '1970-01-01T00:00:00.000Z',
    coverage: {}, graph: {},
  });
  assert.deepEqual(good.errors, []);
  assert.equal(good.valid, true);
});

test('persistGraphSnapshot: writes a real, valid GraphSnapshot keyed by the REAL git HEAD, never the graph\'s own always-"uncommitted" graphId', () => {
  const repo = _mkGitRepo();
  try {
    const graph = _realGraph(SOURCE_A);
    assert.ok(graph.graphId.includes(':uncommitted:'), 'fixture assumption: buildGraphWithCoverage never receives a real commit today — confirms the plan\'s own Global Constraint');

    const snap = persistGraphSnapshot(graph, repo, { capturedAt: '2020-01-01T00:00:00.000Z' });
    const { valid, errors } = validateGraphSnapshot(snap);
    assert.deepEqual(errors, []);
    assert.equal(valid, true);
    assert.notEqual(snap.commit, 'uncommitted', 'must resolve the REAL git HEAD, not the graph\'s own literal default');

    const realHead = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: repo, encoding: 'utf8' }).trim();
    assert.equal(snap.commit, realHead);

    const onDisk = fs.readFileSync(path.join(repo, '.agentic-security', 'lineage-snapshots', `${realHead}.json`), 'utf8');
    assert.deepEqual(JSON.parse(onDisk), snap);
  } finally {
    fs.rmSync(repo, { recursive: true, force: true });
  }
});

test('persistGraphSnapshot: with no git repo, falls back to a content-hash key, matching sbom-diff.js\'s own precedent', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'graph-snapshot-nogit-'));
  try {
    const graph = _realGraph(SOURCE_A);
    const snap = persistGraphSnapshot(graph, dir, { capturedAt: '2020-01-01T00:00:00.000Z' });
    assert.ok(snap.commit.length > 0);
    assert.notEqual(snap.commit, 'uncommitted');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('loadSnapshots + mostRecentPriorSnapshot: real round trip across two real commits', () => {
  const repo = _mkGitRepo();
  try {
    const graphA = _realGraph(SOURCE_A);
    const snapA = persistGraphSnapshot(graphA, repo, { capturedAt: '2020-01-01T00:00:00.000Z' });

    fs.writeFileSync(path.join(repo, 'README.md'), 'y');
    execFileSync('git', ['add', '.'], { cwd: repo });
    execFileSync('git', ['commit', '-q', '-m', 'second'], { cwd: repo });
    const graphB = _realGraph(`function h(req, logger, db) { logger.info('x', req.body.email); db.query(req.body.email); }`);
    const snapB = persistGraphSnapshot(graphB, repo, { capturedAt: '2020-01-02T00:00:00.000Z' });

    assert.notEqual(snapA.commit, snapB.commit, 'fixture assumption: two real commits must produce two distinct keys');

    const all = loadSnapshots(repo);
    assert.equal(all.length, 2);
    assert.deepEqual(all.map((s) => s.commit).sort(), [snapA.commit, snapB.commit].sort());

    assert.deepEqual(loadSnapshot(repo, snapA.commit), snapA);

    const prior = mostRecentPriorSnapshot(repo, snapB.commit);
    assert.deepEqual(prior, snapA, 'the most recent PRIOR snapshot, excluding the current one, must be snapA');
  } finally {
    fs.rmSync(repo, { recursive: true, force: true });
  }
});

test('loadSnapshots: an empty/nonexistent history directory returns [], never throws', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'graph-snapshot-empty-'));
  try {
    assert.deepEqual(loadSnapshots(dir), []);
    assert.equal(loadSnapshot(dir, 'anything'), null);
    assert.equal(mostRecentPriorSnapshot(dir, 'anything'), null);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('snapshotsComparable: same schemaVersion is comparable; a real, disclosed mismatch is not', () => {
  const graph = _realGraph(SOURCE_A);
  const a = persistGraphSnapshot(graph, _mkGitRepo(), { capturedAt: '2020-01-01T00:00:00.000Z' });
  const b = persistGraphSnapshot(graph, _mkGitRepo(), { capturedAt: '2020-01-02T00:00:00.000Z' });
  assert.deepEqual(snapshotsComparable(a, b), { comparable: true, reasons: [] });

  const mismatched = { ...b, schemaVersion: '2.0.0' };
  const result = snapshotsComparable(a, mismatched);
  assert.equal(result.comparable, false);
  assert.ok(result.reasons.length > 0);
  assert.match(result.reasons[0], /schemaVersion/);
});

test('snapshotsComparable: a missing snapshot is honestly not comparable, never a crash', () => {
  const graph = _realGraph(SOURCE_A);
  const a = persistGraphSnapshot(graph, _mkGitRepo(), { capturedAt: '2020-01-01T00:00:00.000Z' });
  assert.deepEqual(snapshotsComparable(a, null), { comparable: false, reasons: ['one or both snapshots are missing'] });
  assert.deepEqual(snapshotsComparable(null, null), { comparable: false, reasons: ['one or both snapshots are missing'] });
});

test('REAL CORPUS: sweeping bench/data-lineage/ fixtures never throws persisting or loading a snapshot', async () => {
  const { buildFixtureGraph } = await import('../../../bench/data-lineage/runner.mjs');
  const fs2 = await import('node:fs');
  const path2 = await import('node:path');
  const { fileURLToPath } = await import('node:url');
  const __dirname = path2.dirname(fileURLToPath(import.meta.url));
  const FIXTURES_ROOT = path2.join(__dirname, '../../../bench/data-lineage/fixtures');
  const fixtureIds = fs2.readdirSync(FIXTURES_ROOT).filter((f) => fs2.statSync(path2.join(FIXTURES_ROOT, f)).isDirectory());
  assert.ok(fixtureIds.length > 0);
  const dir = _mkGitRepo();
  try {
    let checked = 0;
    for (const fixtureId of fixtureIds) {
      const srcPath = path2.join(FIXTURES_ROOT, fixtureId, 'source.js');
      if (!fs2.existsSync(srcPath)) continue;
      const source = fs2.readFileSync(srcPath, 'utf8');
      const graph = buildFixtureGraph(fixtureId, source);
      assert.doesNotThrow(() => {
        const snap = persistGraphSnapshot(graph, dir, { capturedAt: '2020-01-01T00:00:00.000Z' });
        const { valid } = validateGraphSnapshot(snap);
        assert.ok(valid, `${fixtureId}: produced an invalid GraphSnapshot`);
      }, `${fixtureId}: persistGraphSnapshot threw`);
      checked++;
    }
    assert.ok(checked > 0, 'the sweep must exercise at least one real fixture, or this test is vacuous');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd scanner && node --test test/lineage/graph-snapshot.test.js`.
Expected: FAIL — `graph-snapshot.js` does not exist yet.

- [ ] **Step 3: Add `snapshotId` to `ids.js`**

Mirror `obligationId`/`storyId`'s exact shape (object-argument
signature, discriminated by every field that distinguishes two records):

```js
// In ids.js, near obligationId/storyId:
export function snapshotId(
  { graphId, commit, capturedAt },
  discriminatorParts = [],
) {
  return `snapshot:${_hash(_canon([graphId, commit, capturedAt, ...discriminatorParts]))}`;
}
```

- [ ] **Step 4: Write `graph-snapshot.js`**

```js
// graph-snapshot.js — M4 deliverable #8 (FR-503 §14, DFG-022): the
// GraphSnapshot extension contract + persist/load history + a
// comparability check.
//
// Mirrors obligation-mapping.js/decision-story.js's own contract shape
// exactly: a record is explicitly NOT a DataFlowGraph v1 entity (§10.10
// — "associated with, but not required inside, the immutable base
// graph"), never added to dataflow-graph.schema.json, never routed
// through validate.js.
//
// Persistence mirrors posture/sbom-diff.js's own proven architecture —
// persist-by-git-commit, most-recent-by-mtime lookup — the one real,
// already-shipped precedent in this codebase for "compare two scans."
// Not reused code (sbom-diff.js operates on flat SBOM components, not
// graph entities) but the same architecture, deliberately.
//
// A real, load-bearing gap found during scoping: engine.js's own call
// site to buildLineageGraph never passes opts.commit, so every real
// graph's own graphId today embeds the literal string 'uncommitted'
// regardless of the repo's real git state. Snapshot keying CANNOT read
// graph.graphId for the commit — it resolves the real git HEAD
// independently, exactly like sbom-diff.js's own _gitHead helper.

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { statePath, stateWritesEnabled } from '../posture/state-dir.js';
import { hardenGitArgs, hardenGitEnv } from '../util/git-hardening.js';
import { snapshotId } from './ids.js';

const SNAPSHOT_VERSION = '1.0.0';
const HISTORY_DIR = 'lineage-snapshots';

function _historyDir(scanRoot) {
  return statePath(scanRoot, HISTORY_DIR);
}

// scanRoot is the SCANNED project's repository, not this project's own
// checkout — hardened per the same FR-PROV-024 precedent sbom-diff.js's
// own _gitHead already established. rev-parse HEAD touches neither the
// working tree nor the index, so this is read-only.
function _gitHead(scanRoot) {
  try {
    return execFileSync('git', hardenGitArgs(['rev-parse', 'HEAD']), {
      cwd: scanRoot, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], env: hardenGitEnv(),
    }).trim();
  } catch { return null; }
}

function _isNonEmptyString(v) { return typeof v === 'string' && v.length > 0; }
function _isPlainObject(v) { return v !== null && typeof v === 'object' && !Array.isArray(v); }

/**
 * Structural validation only — mirrors
 * obligation-mapping.js#validateObligationMapping's own {valid, errors}
 * shape and "never throws" contract.
 */
export function validateGraphSnapshot(record) {
  const errors = [];
  const err = (p, message) => errors.push({ path: p, message });
  if (!record || typeof record !== 'object' || Array.isArray(record)) {
    err('$', 'GraphSnapshot record must be an object');
    return { valid: false, errors };
  }
  if (!_isNonEmptyString(record.id) || !record.id.startsWith('snapshot:')) {
    err('$.id', 'id is required and must start with "snapshot:"');
  }
  if (!_isNonEmptyString(record.version)) err('$.version', 'version is required');
  if (!_isNonEmptyString(record.graphId)) err('$.graphId', 'graphId is required');
  if (!_isNonEmptyString(record.schemaVersion)) err('$.schemaVersion', 'schemaVersion is required');
  if (!_isNonEmptyString(record.commit)) err('$.commit', 'commit is required');
  if (!_isNonEmptyString(record.capturedAt)) err('$.capturedAt', 'capturedAt is required');
  if (!_isPlainObject(record.coverage)) err('$.coverage', 'coverage is required and must be an object');
  if (!_isPlainObject(record.graph)) err('$.graph', 'graph is required and must be an object');
  return { valid: errors.length === 0, errors };
}

/**
 * Persist `graph` as a GraphSnapshot, keyed by the REAL current git
 * HEAD of `scanRoot` (never `graph.graphId`'s own commit component —
 * see this file's own header). Falls back to a content hash of the
 * graph when no git repo is present, matching sbom-diff.js's own
 * precedent. opts.capturedAt overrides wall-clock time (deterministic
 * test fixtures, mirroring every other M4 exporter's own opts.generatedAt
 * convention).
 */
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

/** All persisted snapshots for scanRoot, newest first by mtime. Never
 * throws — an empty/missing history directory returns []. */
export function loadSnapshots(scanRoot) {
  const dir = _historyDir(scanRoot);
  if (!fs.existsSync(dir)) return [];
  let files;
  try { files = fs.readdirSync(dir).filter((f) => f.endsWith('.json')); } catch { return []; }
  const withMtime = files.map((f) => {
    const full = path.join(dir, f);
    let mtimeMs = 0;
    try { mtimeMs = fs.statSync(full).mtimeMs; } catch {}
    return { full, mtimeMs };
  });
  withMtime.sort((a, b) => b.mtimeMs - a.mtimeMs);
  const out = [];
  for (const { full } of withMtime) {
    try { out.push(JSON.parse(fs.readFileSync(full, 'utf8'))); } catch {}
  }
  return out;
}

/** One snapshot by its commit key, or null. Never throws. */
export function loadSnapshot(scanRoot, commitKey) {
  const dir = _historyDir(scanRoot);
  const full = path.join(dir, `${commitKey}.json`);
  if (!fs.existsSync(full)) return null;
  try { return JSON.parse(fs.readFileSync(full, 'utf8')); } catch { return null; }
}

/** The newest persisted snapshot that is NOT excludeCommitKey — the
 * default "compare against" target. Null if none exists. */
export function mostRecentPriorSnapshot(scanRoot, excludeCommitKey) {
  const all = loadSnapshots(scanRoot);
  return all.find((s) => s.commit !== excludeCommitKey) ?? null;
}

/**
 * Are two snapshots validly diffable? Only ever reports true on a REAL,
 * checkable signal — today, schemaVersion equality. The graphId
 * configHash gap (see this sub-project's own scoping doc) is a real,
 * disclosed limitation: two snapshots with the same schemaVersion but a
 * genuinely different analyzer/config are reported comparable, since no
 * real signal exists yet to detect that difference — never silently
 * papered over, but not fabricated either.
 */
export function snapshotsComparable(a, b) {
  if (!a || !b) return { comparable: false, reasons: ['one or both snapshots are missing'] };
  const reasons = [];
  if (a.schemaVersion !== b.schemaVersion) {
    reasons.push(`schemaVersion differs (${a.schemaVersion} vs ${b.schemaVersion})`);
  }
  return { comparable: reasons.length === 0, reasons };
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd scanner && node --test test/lineage/graph-snapshot.test.js`.
Expected: all PASS.

- [ ] **Step 6: Wire into the scan flow, additively**

Read `scanner/src/engine.js`'s own lineage gate block (search for
`buildLineageGraph(callGraph, {` — the block Sub-project E1/E5's own
CLAUDE.md entry documents) and `scanner/bin/agentic-security.js`'s own
persistence of `scan.lineageGraph` to
`.agentic-security/lineage-graph.json` (search for `lineage-graph.json`).
Add a call to `persistGraphSnapshot(scan.lineageGraph, scanRoot)`
immediately after that existing persist step, inside the SAME
`_writesOnScan()`/`_isSafeStateDir()` gate — additive only, never
replacing the existing single-current-graph persistence. Register the
new `lineage-snapshots/` directory in `posture/artifact-registry.js`
(`classification: 'generated'`, `retentionClass: 'scan'`, matching
`lineage-graph.json`'s own entry — sub-project E5's own final review
already found and fixed the exact "forgot to register a new artifact,
so `reset` never deletes it" bug once; do not reintroduce it).

Write a real CLI-level regression test in
`scanner/test/cli/lineage-snapshot-persist.test.js` (mirroring
`test/lineage-artifact-write.test.js`'s own real-scan-then-check-disk
pattern): a real `AGENTIC_SECURITY_LINEAGE_DEEP=1` scan on a real git
fixture writes BOTH `.agentic-security/lineage-graph.json` (unchanged
behavior) AND a new file under
`.agentic-security/lineage-snapshots/<real-git-HEAD>.json`; running
`agentic-security reset --yes` deletes both.

- [ ] **Step 7: Run the full `test:lineage` scope, wire the new test files in, commit**

Add `test/lineage/graph-snapshot.test.js` and
`test/cli/lineage-snapshot-persist.test.js` to the appropriate scripts in
`scanner/package.json` (mirror where `test/lineage-artifact-write.test.js`
and `test/cli/dataflow-export-briefing.test.js` are each wired — read
the real current `package.json` to confirm which scope each precedent
uses, per this session's own "follow reality over a plan's guess"
precedent). Run the full scope and confirm the new tests are genuinely
included (compare the total test count before/after).

```bash
git add scanner/src/lineage/graph-snapshot.js scanner/src/lineage/ids.js \
  scanner/src/engine.js scanner/bin/agentic-security.js \
  scanner/src/posture/artifact-registry.js \
  scanner/test/lineage/graph-snapshot.test.js \
  scanner/test/cli/lineage-snapshot-persist.test.js \
  scanner/package.json
git commit -m "feat(lineage): GraphSnapshot contract + persistence + comparability (M4 deliverable #8, sub-project 8a)"
```

## Self-review notes (per the writing-plans skill)

- **Spec coverage:** the `GraphSnapshot` §10.10 field list (snapshot ID,
  graph/schema/analyzer/config digests, repository/commit/branch/release/
  environment, scan time/health/coverage, immutable graph reference) is
  only PARTIALLY covered by this task's own record shape — `branch`/
  `release`/`environment` and a real analyzer/config digest are NOT
  populated here (no real signal exists for them yet, per the scoping
  doc's own disclosed gaps); `repository` is available via
  `graph.graphId`'s own embedded component, not duplicated as a separate
  field. This is a deliberate, disclosed MVP subset satisfying AC-27's
  own binding example (compare by commit), not the full §10.10 shape —
  sub-project 8b or a later increment can extend the record with
  additional optional fields without a breaking change, since
  `validateGraphSnapshot` only requires the fields this task actually
  populates.
- **Placeholder scan:** Task 1 ships complete, real code grounded in two
  real precedents (`sbom-diff.js`'s persistence architecture,
  `obligation-mapping.js`'s contract shape). No TBDs.
- **Out-of-scope reminder for whoever picks up sub-project 8b:**
  `GraphDiff` computation, change-cause classification, drift policies,
  and CLI wiring are NOT in this plan — see the scoping doc's own split.
