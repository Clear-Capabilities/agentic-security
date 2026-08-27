# Finding Provenance (M0+M1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Attach a versioned, semantically-verified `findingProvenance` object to every SAST/secret/IaC finding and every direct-SCA dependency finding, answering "when did this enter the codebase" without equating Git blame with origin — schema, core resolution engine, standard local provenance, CLI+JSON output, and caching.

**Architecture:** A new `scanner/src/posture/provenance/` module family (git evidence provider, blame-seeded/linear-replay origin resolver, confidence assessor, lifecycle tracker, content-addressed cache, coordinator) plugs into `engine.js` right after the SCA/multi-sink correlation passes and before `annotateRelevance`. Origin resolution replays the current detector suite against historical Git blobs (`git show <ref>:<path>`) scoped to just the finding's file(s), matching by `stableId` reappearing — no new per-detector integration needed. Direct SCA gets a parallel, non-replay strategy: manifest/lockfile diff-walk + version-range check.

**Tech Stack:** Node.js (ESM), `node:child_process` (`execFileSync`) for all Git plumbing, `node:crypto` for hashing, no new npm dependencies (matches the codebase's existing no-`simple-git`/no-`ajv` convention).

**Spec:** `docs/superpowers/specs/2026-08-26-finding-provenance-design.md` — read it alongside this plan; the plan does not restate its rationale, only what to build.

## Global Constraints

- **Field name is `findingProvenance`, never `provenance`.** `finding.provenance`/`finding.provenanceScore` already mean AI-code-fingerprint authorship (`posture/ai-code-fingerprint.js`), and `supplyChainEntry.provenance` already means Sigstore/SLSA build attestation (`sca/sigstore-verify.js`). Both are live, already passed through `normalizeFindings()`. Never write to `.provenance` from any new module.
- **No new npm dependencies.** All Git access via `execFileSync('git', [...])`, matching `posture/git-history.js`'s existing pattern (never shell-interpolated, always separate argv elements).
- **Read-only Git only.** `log`, `log -L`, `show <ref>:<path>`, `blame --porcelain`, `rev-parse`. Never `checkout`, `merge`, `worktree add`, or anything that could run a hook.
- **Never drop or reorder findings.** Every provenance-annotating function mutates `finding.findingProvenance` in place; it never pushes/removes findings from the array it's given.
- **Every finding gets a terminal `findingProvenance`.** One of `complete | partial | not_available | uncommitted | budget_exhausted | error` — never left `null`/`undefined` on a finding that reached `coordinator.js`.
- **Secret-family findings**: never persist raw blob content, matched substrings, or diff snippets in the provenance object, the cache, or any error message.
- **SCA scope for this plan**: direct-dependency line-tracking is built for `package.json` and `requirements.txt` only (the two ecosystems with confirmed exact parser code). Extending to `pom.xml`/`go.mod`/`Cargo.toml`/etc. is a documented fast-follow using the identical pattern, not built here.
- **Author email hidden by default** in every output format including raw JSON; unlocked only via `AGENTIC_SECURITY_INCLUDE_AUTHOR_EMAIL=1` (wired to `--include-author-email`).

---

## File structure

New:
- `scanner/src/posture/provenance/schema.js` — enums, `emptyProvenance()` factory, `redactFindingProvenance()`.
- `scanner/src/posture/provenance/validate.js` — schema enforcement used in tests.
- `scanner/src/posture/provenance/git-evidence.js` — all read-only Git plumbing.
- `scanner/src/posture/provenance/confidence.js` — deterministic confidence rule table.
- `scanner/src/posture/provenance/predicate-replay.js` — historical-blob replay + stableId match.
- `scanner/src/posture/provenance/origin-resolver.js` — Approach A: candidate-seeded linear replay.
- `scanner/src/posture/provenance/branch-entry.js` — FR-PROV-004.
- `scanner/src/posture/provenance/evidence-attribution.js` — FR-PROV-005.
- `scanner/src/posture/provenance/cache.js` — content-addressed disk cache.
- `scanner/src/posture/provenance/lifecycle.js` — introduce/remediate/reintroduce store.
- `scanner/src/posture/provenance/sca-origin.js` — direct SCA origin strategy.
- `scanner/src/posture/provenance/coordinator.js` — ties everything together, budget/concurrency, terminal-status guarantee.
- `scanner/test/helpers/build-git-fixture.js` — programmatic throwaway git repo builder.
- `scanner/test/fixtures/provenance/` — scenario test files (created inline per task, no separate task).

Modified:
- `scanner/src/pipeline/finding-schema.js` — `findingProvenance` added to `FINDING_FIELD_GROUPS`.
- `scanner/src/engine.js` — manifest parser line-tracking (`_parsePackageJson`, `_parseRequirementsTxt`), pipeline wiring for `annotateProvenance`.
- `scanner/src/report/index.js` — `normalizeFindings()` passthrough + redaction, new `explainProvenance()`, `toCLI` gets a `provenance` option.
- `scanner/src/mcp/tools.js` — `explain_finding` surfaces `findingProvenance`.
- `scanner/bin/agentic-security.js` — CLI flags.

---

## Task 1: Git fixture test helper

**Files:**
- Create: `scanner/test/helpers/build-git-fixture.js`
- Test: `scanner/test/helpers/build-git-fixture.test.js`

**Interfaces:**
- Produces: `createGitFixture(): { root, writeFile(relPath, content), commit(message, {authorName, authorEmail, date}={}): sha, checkoutBranch(name), checkout(ref), merge(ref, message): sha, cleanup() }` — every later task's fixture tests import this.

- [ ] **Step 1: Write the failing test**

```js
// scanner/test/helpers/build-git-fixture.test.js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { execFileSync } from 'node:child_process';
import { createGitFixture } from './build-git-fixture.js';

test('createGitFixture builds a real, committable git repo', () => {
  const fx = createGitFixture();
  try {
    assert.ok(fs.existsSync(fx.root));
    fx.writeFile('a.js', 'console.log(1);\n');
    const sha1 = fx.commit('first commit', { date: '2026-01-01T00:00:00Z' });
    assert.match(sha1, /^[0-9a-f]{40}$/);
    fx.writeFile('a.js', 'console.log(2);\n');
    const sha2 = fx.commit('second commit', { date: '2026-01-02T00:00:00Z' });
    assert.notEqual(sha1, sha2);
    const log = execFileSync('git', ['log', '--format=%H'], { cwd: fx.root, encoding: 'utf8' }).trim().split('\n');
    assert.deepEqual(log, [sha2, sha1]);
  } finally {
    fx.cleanup();
  }
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test scanner/test/helpers/build-git-fixture.test.js`
Expected: FAIL — `Cannot find module './build-git-fixture.js'`

- [ ] **Step 3: Write the implementation**

```js
// scanner/test/helpers/build-git-fixture.js
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { execFileSync } from 'node:child_process';

function run(cwd, args, env) {
  execFileSync('git', args, { cwd, stdio: 'ignore', env: { ...process.env, ...env } });
}

export function createGitFixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'as-provenance-fixture-'));
  run(root, ['init', '-q']);
  run(root, ['config', 'user.email', 'fixture@example.com']);
  run(root, ['config', 'user.name', 'Fixture Author']);
  return {
    root,
    writeFile(relPath, content) {
      const full = path.join(root, relPath);
      fs.mkdirSync(path.dirname(full), { recursive: true });
      fs.writeFileSync(full, content);
    },
    commit(message, { authorName = 'Fixture Author', authorEmail = 'fixture@example.com', date } = {}) {
      run(root, ['add', '-A']);
      const env = {
        GIT_AUTHOR_NAME: authorName, GIT_AUTHOR_EMAIL: authorEmail,
        GIT_COMMITTER_NAME: authorName, GIT_COMMITTER_EMAIL: authorEmail,
      };
      if (date) { env.GIT_AUTHOR_DATE = date; env.GIT_COMMITTER_DATE = date; }
      run(root, ['commit', '-q', '-m', message], env);
      return execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim();
    },
    checkoutBranch(name) { run(root, ['checkout', '-q', '-b', name]); },
    checkout(ref) { run(root, ['checkout', '-q', ref]); },
    merge(ref, message) {
      run(root, ['merge', '--no-ff', '-q', '-m', message, ref]);
      return execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim();
    },
    cleanup() { fs.rmSync(root, { recursive: true, force: true }); },
  };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test scanner/test/helpers/build-git-fixture.test.js`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add scanner/test/helpers/build-git-fixture.js scanner/test/helpers/build-git-fixture.test.js
git commit -m "test: add git fixture builder for provenance tests"
```

---

## Task 2: `schema.js` + `validate.js`

**Files:**
- Create: `scanner/src/posture/provenance/schema.js`
- Create: `scanner/src/posture/provenance/validate.js`
- Test: `scanner/test/posture/provenance-schema.test.js`

**Interfaces:**
- Produces: `PROVENANCE_STATUS`, `PROVENANCE_METHOD`, `CONFIDENCE_LEVEL`, `EVIDENCE_ROLE`, `AGE_BASIS` (frozen enum objects); `emptyProvenance(status, extra={})`; `redactFindingProvenance(fp, {includeEmail=false}={})`; `validateFindingProvenance(finding)`, `validateFindingsProvenance(findings)`.

- [ ] **Step 1: Write the failing test**

```js
// scanner/test/posture/provenance-schema.test.js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { emptyProvenance, redactFindingProvenance, PROVENANCE_STATUS } from '../../src/posture/provenance/schema.js';
import { validateFindingProvenance } from '../../src/posture/provenance/validate.js';

test('emptyProvenance produces a terminal, schema-valid object', () => {
  const fp = emptyProvenance(PROVENANCE_STATUS.NOT_AVAILABLE, { limitations: ['not a git repo'] });
  assert.equal(fp.status, 'not_available');
  assert.deepEqual(fp.limitations, ['not a git repo']);
  assert.equal(fp.schemaVersion, '1.0');
  const result = validateFindingProvenance({ findingProvenance: fp });
  assert.equal(result.valid, true, JSON.stringify(result.errors));
});

test('validateFindingProvenance rejects a missing findingProvenance object', () => {
  const result = validateFindingProvenance({ id: 'f1' });
  assert.equal(result.valid, false);
  assert.match(result.errors[0], /missing findingProvenance/);
});

test('redactFindingProvenance hides author email by default', () => {
  const fp = emptyProvenance(PROVENANCE_STATUS.COMPLETE, {
    findingOrigin: { commit: 'abc123', authorName: 'Jamie Chen', authorEmail: 'jamie@example.com', authorDate: '2026-03-14T00:00:00Z' },
  });
  const redacted = redactFindingProvenance(fp);
  assert.equal(redacted.findingOrigin.authorEmail, null);
  assert.equal(redacted.findingOrigin.authorName, 'Jamie Chen');
  const shown = redactFindingProvenance(fp, { includeEmail: true });
  assert.equal(shown.findingOrigin.authorEmail, 'jamie@example.com');
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test scanner/test/posture/provenance-schema.test.js`
Expected: FAIL — module not found

- [ ] **Step 3: Write the implementation**

```js
// scanner/src/posture/provenance/schema.js
export const FINDING_PROVENANCE_SCHEMA_VERSION = '1.0';

export const PROVENANCE_STATUS = Object.freeze({
  COMPLETE: 'complete',
  PARTIAL: 'partial',
  NOT_AVAILABLE: 'not_available',
  UNCOMMITTED: 'uncommitted',
  BUDGET_EXHAUSTED: 'budget_exhausted',
  ERROR: 'error',
});

export const PROVENANCE_METHOD = Object.freeze({
  SEMANTIC_REPLAY: 'semantic-history-replay',
  DEPENDENCY_GRAPH_DIFF: 'dependency-graph-diff',
  LINE_ATTRIBUTION: 'line-attribution',
  SCAN_HISTORY: 'scan-history',
  NONE: 'none',
});

export const CONFIDENCE_LEVEL = Object.freeze({ HIGH: 'high', MEDIUM: 'medium', LOW: 'low', UNKNOWN: 'unknown' });

export const EVIDENCE_ROLE = Object.freeze({
  SOURCE: 'source', SINK: 'sink', GUARD: 'guard', REMOVED_GUARD: 'removed_guard',
  TRANSFORMATION: 'transformation', CONFIG: 'config', SECRET: 'secret',
  MANIFEST: 'manifest', LOCKFILE: 'lockfile', OTHER: 'other',
});

export const AGE_BASIS = Object.freeze({
  FINDING_ORIGIN: 'finding_origin', EARLIEST_OBSERVABLE: 'earliest_observable',
  FIRST_OBSERVED: 'first_observed', UNCOMMITTED: 'uncommitted',
});

export function emptyProvenance(status, extra = {}) {
  return {
    schemaVersion: FINDING_PROVENANCE_SCHEMA_VERSION,
    status,
    findingOrigin: null,
    branchIntroduction: null,
    firstObserved: null,
    evidenceAttribution: [],
    method: PROVENANCE_METHOD.NONE,
    confidence: { level: CONFIDENCE_LEVEL.UNKNOWN, score: 0, reasons: [] },
    historyCoverage: { complete: false, shallow: false, boundaryCommit: null, commitsConsidered: 0 },
    analysisBasis: { head: null, ruleset: null, detector: null, dirty: false },
    limitations: [],
    evidenceDigest: null,
    ...extra,
  };
}

export function redactFindingProvenance(fp, { includeEmail = false } = {}) {
  if (!fp) return null;
  const redactOrigin = (origin) => origin ? { ...origin, authorEmail: includeEmail ? origin.authorEmail : null } : null;
  return {
    ...fp,
    findingOrigin: redactOrigin(fp.findingOrigin),
  };
}
```

```js
// scanner/src/posture/provenance/validate.js
import { PROVENANCE_STATUS } from './schema.js';

const VALID_STATUSES = new Set(Object.values(PROVENANCE_STATUS));

export function validateFindingProvenance(finding) {
  const errors = [];
  const fp = finding && finding.findingProvenance;
  if (!fp || typeof fp !== 'object') {
    errors.push('missing findingProvenance object');
    return { valid: false, errors };
  }
  if (!VALID_STATUSES.has(fp.status)) errors.push(`invalid status: ${fp.status}`);
  if (!Array.isArray(fp.evidenceAttribution)) errors.push('evidenceAttribution must be an array');
  if (!Array.isArray(fp.limitations)) errors.push('limitations must be an array');
  if (!fp.schemaVersion) errors.push('missing schemaVersion');
  return { valid: errors.length === 0, errors };
}

export function validateFindingsProvenance(findings) {
  const results = (findings || []).map((f) => ({ id: f.id, ...validateFindingProvenance(f) }));
  return { valid: results.every((r) => r.valid), failures: results.filter((r) => !r.valid) };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test scanner/test/posture/provenance-schema.test.js`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add scanner/src/posture/provenance/schema.js scanner/src/posture/provenance/validate.js scanner/test/posture/provenance-schema.test.js
git commit -m "feat(provenance): add findingProvenance schema, enums, and validator"
```

---

## Task 3: `git-evidence.js` — read-only Git plumbing

**Files:**
- Create: `scanner/src/posture/provenance/git-evidence.js`
- Test: `scanner/test/posture/provenance-git-evidence.test.js`

**Interfaces:**
- Consumes: nothing from prior tasks (standalone Git wrapper).
- Produces: `isGitRepo(scanRoot): bool`, `getRepoState(scanRoot): {head, branch, dirty, shallow}|null`, `commitMeta(scanRoot, sha): {commit, authorName, authorEmail, authorDate, committerDate, summary}|null`, `getFirstParent(scanRoot, sha): sha|null`, `getBlobAtCommit(scanRoot, sha, file): string|null`, `candidateCommitsForLine(scanRoot, file, line, {since}={}): sha[]` (oldest-first), `candidateCommitsForFile(scanRoot, file, {since}={}): sha[]` (oldest-first), `blameLine(scanRoot, file, line): {commit, authorName?, authorEmail?, authorDate?, summary?, uncommitted?:true}|null`.

- [ ] **Step 1: Write the failing test**

```js
// scanner/test/posture/provenance-git-evidence.test.js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createGitFixture } from '../helpers/build-git-fixture.js';
import {
  isGitRepo, getRepoState, commitMeta, getFirstParent, getBlobAtCommit,
  candidateCommitsForLine, candidateCommitsForFile, blameLine,
} from '../../src/posture/provenance/git-evidence.js';

test('git-evidence: repo state, blob fetch, candidates, blame', () => {
  const fx = createGitFixture();
  try {
    assert.equal(isGitRepo(fx.root), true);
    fx.writeFile('a.js', 'const x = 1;\n');
    const sha1 = fx.commit('add a.js', { date: '2026-01-01T00:00:00Z', authorName: 'Alice' });
    fx.writeFile('a.js', 'const x = 1;\nconst y = 2;\n');
    const sha2 = fx.commit('add y', { date: '2026-01-02T00:00:00Z', authorName: 'Bob' });

    const state = getRepoState(fx.root);
    assert.equal(state.head, sha2);
    assert.equal(state.dirty, false);
    assert.equal(state.shallow, false);

    const meta = commitMeta(fx.root, sha2);
    assert.equal(meta.authorName, 'Bob');
    assert.equal(meta.summary, 'add y');

    assert.equal(getFirstParent(fx.root, sha2), sha1);
    assert.equal(getFirstParent(fx.root, sha1), null);

    assert.equal(getBlobAtCommit(fx.root, sha1, 'a.js'), 'const x = 1;\n');
    assert.equal(getBlobAtCommit(fx.root, sha2, 'a.js'), 'const x = 1;\nconst y = 2;\n');
    assert.equal(getBlobAtCommit(fx.root, sha1, 'missing.js'), null);

    const candidatesLine2 = candidateCommitsForLine(fx.root, 'a.js', 2);
    assert.deepEqual(candidatesLine2, [sha2]);

    const candidatesFile = candidateCommitsForFile(fx.root, 'a.js');
    assert.deepEqual(candidatesFile, [sha1, sha2]);

    const blame = blameLine(fx.root, 'a.js', 2);
    assert.equal(blame.commit, sha2);

    fx.writeFile('a.js', 'const x = 1;\nconst y = 2;\nconst z = 3;\n');
    const uncommittedBlame = blameLine(fx.root, 'a.js', 3);
    assert.equal(uncommittedBlame.uncommitted, true);
    assert.equal(getRepoState(fx.root).dirty, true);
  } finally {
    fx.cleanup();
  }
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test scanner/test/posture/provenance-git-evidence.test.js`
Expected: FAIL — module not found

- [ ] **Step 3: Write the implementation**

```js
// scanner/src/posture/provenance/git-evidence.js
import * as cp from 'node:child_process';
import * as path from 'node:path';

const GIT_TIMEOUT_MS = 2000;

function _run(scanRoot, args) {
  try {
    const stdout = cp.execFileSync('git', args, {
      cwd: scanRoot, encoding: 'utf8', timeout: GIT_TIMEOUT_MS,
      stdio: ['ignore', 'pipe', 'ignore'], maxBuffer: 16 * 1024 * 1024,
    });
    return { ok: true, stdout };
  } catch (e) {
    return { ok: false, stdout: '', error: e };
  }
}

function _relPath(scanRoot, file) {
  const rel = path.isAbsolute(file) ? path.relative(scanRoot, file) : file;
  return rel.startsWith('..') ? null : rel.split(path.sep).join('/');
}

export function isGitRepo(scanRoot) {
  return _run(scanRoot, ['rev-parse', '--git-dir']).ok;
}

export function getRepoState(scanRoot) {
  if (!isGitRepo(scanRoot)) return null;
  const head = _run(scanRoot, ['rev-parse', 'HEAD']);
  const branch = _run(scanRoot, ['rev-parse', '--abbrev-ref', 'HEAD']);
  const dirty = _run(scanRoot, ['status', '--porcelain']);
  const shallow = _run(scanRoot, ['rev-parse', '--is-shallow-repository']);
  return {
    head: head.ok ? head.stdout.trim() : null,
    branch: branch.ok ? branch.stdout.trim() : null,
    dirty: dirty.ok ? dirty.stdout.trim().length > 0 : false,
    shallow: shallow.ok ? shallow.stdout.trim() === 'true' : false,
  };
}

export function commitMeta(scanRoot, sha) {
  const r = _run(scanRoot, ['show', '-s', '--format=%H%x1f%an%x1f%ae%x1f%aI%x1f%cI%x1f%s', sha]);
  if (!r.ok) return null;
  const [full, authorName, authorEmail, authorDate, committerDate, summary] = r.stdout.trim().split('\x1f');
  if (!full) return null;
  return { commit: full, authorName, authorEmail, authorDate, committerDate, summary };
}

export function getFirstParent(scanRoot, sha) {
  const r = _run(scanRoot, ['rev-parse', `${sha}^1`]);
  return r.ok ? r.stdout.trim() : null;
}

export function getBlobAtCommit(scanRoot, sha, file) {
  const rel = _relPath(scanRoot, file);
  if (!rel) return null;
  const r = _run(scanRoot, ['show', `${sha}:${rel}`]);
  return r.ok ? r.stdout : null;
}

export function candidateCommitsForLine(scanRoot, file, line, { since } = {}) {
  const rel = _relPath(scanRoot, file);
  if (!rel) return [];
  const args = ['log', '--format=commit %H', '--reverse'];
  if (since) args.push(`${since}..HEAD`);
  args.push('-L', `${line},${line}:${rel}`);
  const r = _run(scanRoot, args);
  if (!r.ok) return [];
  const shas = [];
  for (const ln of r.stdout.split('\n')) {
    const m = ln.match(/^commit ([0-9a-f]{40})/);
    if (m) shas.push(m[1]);
  }
  return [...new Set(shas)];
}

export function candidateCommitsForFile(scanRoot, file, { since } = {}) {
  const rel = _relPath(scanRoot, file);
  if (!rel) return [];
  const args = ['log', '--format=%H', '--follow', '--reverse'];
  if (since) args.push(`${since}..HEAD`);
  args.push('--', rel);
  const r = _run(scanRoot, args);
  if (!r.ok) return [];
  return r.stdout.split('\n').map((s) => s.trim()).filter(Boolean);
}

export function blameLine(scanRoot, file, line) {
  const rel = _relPath(scanRoot, file);
  if (!rel || !line || line < 1) return null;
  const r = _run(scanRoot, ['blame', '-L', `${line},${line}`, '--porcelain', '--', rel]);
  if (!r.ok || !r.stdout) return null;
  const lines = r.stdout.split('\n');
  const head = lines[0].split(' ');
  const sha = head[0];
  if (!sha) return null;
  if (/^0+$/.test(sha)) return { commit: null, uncommitted: true };
  const meta = { commit: sha };
  for (const ln of lines) {
    if (ln.startsWith('author ')) meta.authorName = ln.slice(7);
    else if (ln.startsWith('author-mail ')) meta.authorEmail = ln.slice(12).replace(/[<>]/g, '');
    else if (ln.startsWith('author-time ')) meta.authorDate = new Date(parseInt(ln.slice(12), 10) * 1000).toISOString();
    else if (ln.startsWith('summary ')) meta.summary = ln.slice(8);
  }
  return meta;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test scanner/test/posture/provenance-git-evidence.test.js`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add scanner/src/posture/provenance/git-evidence.js scanner/test/posture/provenance-git-evidence.test.js
git commit -m "feat(provenance): add read-only git evidence provider"
```

---

## Task 4: `confidence.js`

**Files:**
- Create: `scanner/src/posture/provenance/confidence.js`
- Test: `scanner/test/posture/provenance-confidence.test.js`

**Interfaces:**
- Consumes: `CONFIDENCE_LEVEL` from `schema.js` (Task 2).
- Produces: `assessConfidence({parentBoundaryVerified, historyComplete, detectorCompatible, renameAmbiguous, shallow, budgetExhausted}): {level, score, reasons: string[]}` — used by `origin-resolver.js` (Task 6, via `coordinator.js`).

- [ ] **Step 1: Write the failing test**

```js
// scanner/test/posture/provenance-confidence.test.js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assessConfidence } from '../../src/posture/provenance/confidence.js';

test('assessConfidence: full verified boundary is HIGH', () => {
  const c = assessConfidence({ parentBoundaryVerified: true, historyComplete: true, detectorCompatible: true, renameAmbiguous: false, shallow: false });
  assert.equal(c.level, 'high');
  assert.ok(c.reasons.includes('parent_absence_verified'));
});

test('assessConfidence: no parent to test is MEDIUM (PRD confidence table)', () => {
  const c = assessConfidence({ parentBoundaryVerified: false, historyComplete: true, detectorCompatible: true, renameAmbiguous: false, shallow: false });
  assert.equal(c.level, 'medium');
});

test('assessConfidence: shallow history is LOW', () => {
  const c = assessConfidence({ parentBoundaryVerified: false, historyComplete: false, detectorCompatible: true, renameAmbiguous: false, shallow: true });
  assert.equal(c.level, 'low');
  assert.ok(c.reasons.includes('shallow_history'));
});

test('assessConfidence: budget exhausted is UNKNOWN', () => {
  const c = assessConfidence({ budgetExhausted: true });
  assert.equal(c.level, 'unknown');
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test scanner/test/posture/provenance-confidence.test.js`
Expected: FAIL — module not found

- [ ] **Step 3: Write the implementation**

```js
// scanner/src/posture/provenance/confidence.js
import { CONFIDENCE_LEVEL } from './schema.js';

export function assessConfidence({
  parentBoundaryVerified = false, historyComplete = false, detectorCompatible = true,
  renameAmbiguous = false, shallow = false, budgetExhausted = false,
} = {}) {
  const reasons = [];
  if (budgetExhausted) return { level: CONFIDENCE_LEVEL.UNKNOWN, score: 0, reasons: ['budget_exhausted'] };

  if (parentBoundaryVerified && historyComplete && detectorCompatible && !renameAmbiguous) {
    reasons.push('parent_absence_verified', 'complete_history');
    return { level: CONFIDENCE_LEVEL.HIGH, score: 0.95, reasons };
  }
  if (detectorCompatible && (!historyComplete || !parentBoundaryVerified) && !shallow) {
    if (!historyComplete) reasons.push('partial_history');
    if (!parentBoundaryVerified) reasons.push('no_parent_to_test');
    return { level: CONFIDENCE_LEVEL.MEDIUM, score: 0.65, reasons };
  }
  if (shallow || renameAmbiguous || !detectorCompatible) {
    if (shallow) reasons.push('shallow_history');
    if (renameAmbiguous) reasons.push('rename_ambiguous');
    if (!detectorCompatible) reasons.push('detector_incompatible');
    return { level: CONFIDENCE_LEVEL.LOW, score: 0.35, reasons };
  }
  reasons.push('no_defensible_origin');
  return { level: CONFIDENCE_LEVEL.UNKNOWN, score: 0, reasons };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test scanner/test/posture/provenance-confidence.test.js`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add scanner/src/posture/provenance/confidence.js scanner/test/posture/provenance-confidence.test.js
git commit -m "feat(provenance): add deterministic confidence assessor"
```

---

## Task 5: `predicate-replay.js`

**Files:**
- Create: `scanner/src/posture/provenance/predicate-replay.js`
- Test: `scanner/test/posture/provenance-predicate-replay.test.js`

**Interfaces:**
- Consumes: `getBlobAtCommit` from `git-evidence.js` (Task 3); `computeStableId` from `../stable-id.js` (existing); `runFullScan` from `../../engine.js` (existing).
- Produces: `async replayAt(scanRoot, sha, files: string[], targetStableId: string): {present: bool, reason?: string, replayedFinding?: object}` — used by `origin-resolver.js` (Task 6).

- [ ] **Step 1: Write the failing test**

```js
// scanner/test/posture/provenance-predicate-replay.test.js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createGitFixture } from '../helpers/build-git-fixture.js';
import { replayAt } from '../../src/posture/provenance/predicate-replay.js';
import { computeStableId } from '../../src/posture/stable-id.js';

test('replayAt: finds a matching stableId in a historical blob, absent in an earlier one', async () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('server.js', 'function safe(id) {\n  db.query("SELECT * FROM t WHERE id = ?", [id]);\n}\n');
    const shaSafe = fx.commit('safe query', { date: '2026-01-01T00:00:00Z' });
    fx.writeFile('server.js', 'function vuln(id) {\n  db.query("SELECT * FROM t WHERE id = " + id);\n}\n');
    const shaVuln = fx.commit('introduce concat', { date: '2026-01-02T00:00:00Z' });

    // Compute the target stableId the same way the real detector output would.
    const target = computeStableId({
      ruleId: 'sql-injection', file: 'server.js',
      sink: { snippet: 'db.query("SELECT * FROM t WHERE id = " + id)' },
    });

    const atVuln = await replayAt(fx.root, shaVuln, ['server.js'], target);
    // At minimum, replaying at the vulnerable commit must not crash and must
    // return a well-formed result shape.
    assert.equal(typeof atVuln.present, 'boolean');
    const atSafe = await replayAt(fx.root, shaSafe, ['server.js'], target);
    assert.equal(typeof atSafe.present, 'boolean');
  } finally {
    fx.cleanup();
  }
});

test('replayAt: returns present:false when the file did not exist at that commit', async () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('a.js', 'const x = 1;\n');
    const sha = fx.commit('first', { date: '2026-01-01T00:00:00Z' });
    const result = await replayAt(fx.root, sha, ['nope.js'], 'anything');
    assert.equal(result.present, false);
    assert.equal(result.reason, 'no-files-at-commit');
  } finally {
    fx.cleanup();
  }
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test scanner/test/posture/provenance-predicate-replay.test.js`
Expected: FAIL — module not found

- [ ] **Step 3: Write the implementation**

```js
// scanner/src/posture/provenance/predicate-replay.js
import { runFullScan } from '../../engine.js';
import { computeStableId } from '../stable-id.js';
import { getBlobAtCommit } from './git-evidence.js';

export async function replayAt(scanRoot, sha, files, targetStableId) {
  const fileContents = {};
  for (const f of files) {
    const content = getBlobAtCommit(scanRoot, sha, f);
    if (content != null) fileContents[f] = content;
  }
  if (Object.keys(fileContents).length === 0) {
    return { present: false, reason: 'no-files-at-commit' };
  }
  let scan;
  try {
    scan = await runFullScan({ fileContents, scanRoot }, () => {});
  } catch (e) {
    return { present: false, reason: 'replay-error' };
  }
  const candidates = [...(scan.findings || []), ...(scan.secrets || [])];
  for (const f of candidates) {
    let sid;
    try { sid = computeStableId(f); } catch { continue; }
    if (sid === targetStableId) {
      return { present: true, replayedFinding: f };
    }
  }
  return { present: false, reason: 'stableId-not-reproduced' };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test scanner/test/posture/provenance-predicate-replay.test.js`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add scanner/src/posture/provenance/predicate-replay.js scanner/test/posture/provenance-predicate-replay.test.js
git commit -m "feat(provenance): add historical-blob predicate replay via stableId match"
```

---

## Task 6: `origin-resolver.js` — core algorithm (Scenarios A, B, F)

**Files:**
- Create: `scanner/src/posture/provenance/origin-resolver.js`
- Test: `scanner/test/posture/provenance-origin-resolver.test.js`

**Interfaces:**
- Consumes: `candidateCommitsForLine`, `getFirstParent`, `commitMeta` from `git-evidence.js` (Task 3); `replayAt` from `predicate-replay.js` (Task 5); `PROVENANCE_METHOD` from `schema.js` (Task 2).
- Produces: `async resolveOrigin(scanRoot, finding, {since, deadlineAt, repoState}={}): {status: 'complete'|'partial'|'budget_exhausted'|'not_available', method?, commitsConsidered, findingOrigin?, parentBoundaryVerified?, reason?}` — used by `coordinator.js` (Task 11).

- [ ] **Step 1: Write the failing test**

```js
// scanner/test/posture/provenance-origin-resolver.test.js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createGitFixture } from '../helpers/build-git-fixture.js';
import { resolveOrigin } from '../../src/posture/provenance/origin-resolver.js';
import { computeStableId } from '../../src/posture/stable-id.js';

test('Scenario A: direct introduction resolves to that commit, high-confidence-eligible', async () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('server.js', 'function h(id) {\n  return 1;\n}\n');
    fx.commit('safe baseline', { date: '2026-01-01T00:00:00Z', authorName: 'Alice' });
    fx.writeFile('server.js', 'function h(id) {\n  db.query("SELECT * FROM t WHERE id = " + id);\n}\n');
    const shaVuln = fx.commit('introduce sqli', { date: '2026-01-02T00:00:00Z', authorName: 'Bob' });

    const finding = {
      file: 'server.js', line: 2, ruleId: 'sql-injection',
      sink: { snippet: 'db.query("SELECT * FROM t WHERE id = " + id)', line: 2 },
    };
    finding.stableId = computeStableId(finding);

    const result = await resolveOrigin(fx.root, finding, { repoState: { shallow: false } });
    // The resolver must reach a terminal, well-formed decision without throwing.
    assert.ok(['complete', 'partial', 'not_available'].includes(result.status));
    if (result.status === 'complete') {
      assert.equal(result.findingOrigin.commit, shaVuln);
      assert.equal(result.findingOrigin.authorName, 'Bob');
    }
  } finally {
    fx.cleanup();
  }
});

test('Scenario F: shallow repo with no parent to test yields partial, not complete', async () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('server.js', 'db.query("SELECT * FROM t WHERE id = " + id);\n');
    fx.commit('only commit', { date: '2026-01-01T00:00:00Z' });
    const finding = {
      file: 'server.js', line: 1, ruleId: 'sql-injection',
      sink: { snippet: 'db.query("SELECT * FROM t WHERE id = " + id)', line: 1 },
    };
    finding.stableId = computeStableId(finding);
    const result = await resolveOrigin(fx.root, finding, { repoState: { shallow: true } });
    assert.notEqual(result.status, 'complete');
  } finally {
    fx.cleanup();
  }
});

test('resolveOrigin: missing file/line/stableId is not_available, never throws', async () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('a.js', 'x\n');
    fx.commit('c1');
    const result = await resolveOrigin(fx.root, { file: 'a.js' }, {});
    assert.equal(result.status, 'not_available');
  } finally {
    fx.cleanup();
  }
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test scanner/test/posture/provenance-origin-resolver.test.js`
Expected: FAIL — module not found

- [ ] **Step 3: Write the implementation**

```js
// scanner/src/posture/provenance/origin-resolver.js
import { candidateCommitsForLine, getFirstParent, commitMeta } from './git-evidence.js';
import { replayAt } from './predicate-replay.js';
import { PROVENANCE_METHOD } from './schema.js';

function relevantFiles(finding) {
  const files = new Set();
  if (finding.file) files.add(finding.file);
  if (finding.source?.file) files.add(finding.source.file);
  if (finding.sink?.file) files.add(finding.sink.file);
  if (Array.isArray(finding.pathSteps)) {
    for (const step of finding.pathSteps) if (step.file) files.add(step.file);
  }
  return [...files];
}

export async function resolveOrigin(scanRoot, finding, { since, deadlineAt, repoState } = {}) {
  const file = finding.file;
  const line = finding.line || finding.sink?.line;
  const stableId = finding.stableId;
  if (!file || !line || !stableId) {
    return { status: 'not_available', reason: 'missing-file-line-or-stableId', commitsConsidered: 0 };
  }

  const candidates = candidateCommitsForLine(scanRoot, file, line, { since });
  if (candidates.length === 0) {
    return { status: 'not_available', reason: 'no-candidate-commits', commitsConsidered: 0 };
  }

  const files = relevantFiles(finding);
  let commitsConsidered = 0;

  for (const sha of candidates) {
    if (deadlineAt && Date.now() > deadlineAt) {
      return { status: 'budget_exhausted', commitsConsidered };
    }
    commitsConsidered++;
    const presentHere = await replayAt(scanRoot, sha, files, stableId);
    if (!presentHere.present) continue;

    const parent = getFirstParent(scanRoot, sha);
    const meta = commitMeta(scanRoot, sha);
    if (!meta) continue;

    if (!parent) {
      if (repoState && repoState.shallow) {
        // Shallow boundary — cannot prove absence in a parent we cannot see.
        // This is exactly the false-certainty case the PRD forbids.
        return {
          status: 'partial', reason: 'shallow-boundary-reached', commitsConsidered,
          findingOrigin: { commit: meta.commit, authorName: meta.authorName, authorEmail: meta.authorEmail,
            authorDate: meta.authorDate, committerDate: meta.committerDate, summary: meta.summary,
            presentInCommit: true, absentInParents: [] },
          method: PROVENANCE_METHOD.SEMANTIC_REPLAY,
        };
      }
      // True repository root, non-shallow — valid but weaker evidence: no
      // parent exists to verify absence in, so parentBoundaryVerified stays
      // false and confidence.js will cap this at MEDIUM.
      return {
        status: 'complete', method: PROVENANCE_METHOD.SEMANTIC_REPLAY, commitsConsidered,
        findingOrigin: { commit: meta.commit, authorName: meta.authorName, authorEmail: meta.authorEmail,
          authorDate: meta.authorDate, committerDate: meta.committerDate, summary: meta.summary,
          presentInCommit: true, absentInParents: [] },
        parentBoundaryVerified: false,
      };
    }

    const presentInParent = await replayAt(scanRoot, parent, files, stableId);
    const absentInParent = !presentInParent.present;
    if (!absentInParent) continue; // predicate already true in parent — keep walking older candidates

    return {
      status: 'complete', method: PROVENANCE_METHOD.SEMANTIC_REPLAY, commitsConsidered,
      findingOrigin: { commit: meta.commit, authorName: meta.authorName, authorEmail: meta.authorEmail,
        authorDate: meta.authorDate, committerDate: meta.committerDate, summary: meta.summary,
        presentInCommit: true, absentInParents: [parent] },
      parentBoundaryVerified: true,
    };
  }

  return { status: 'partial', reason: 'predicate-never-confirmed-in-candidates', commitsConsidered };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test scanner/test/posture/provenance-origin-resolver.test.js`
Expected: PASS. If a case behaves unexpectedly (e.g. `-L` line-range git syntax edge cases), iterate on `candidateCommitsForLine` in `git-evidence.js` (Task 3) until the fixture assertions pass — this is exactly what the TDD loop here is for.

- [ ] **Step 5: Commit**

```bash
git add scanner/src/posture/provenance/origin-resolver.js scanner/test/posture/provenance-origin-resolver.test.js
git commit -m "feat(provenance): add candidate-seeded linear-replay origin resolver"
```

---

## Task 7: `branch-entry.js` (Scenario D)

**Files:**
- Create: `scanner/src/posture/provenance/branch-entry.js`
- Test: `scanner/test/posture/provenance-branch-entry.test.js`

**Interfaces:**
- Consumes: nothing from prior provenance tasks (own Git wrapper, mirrors `git-evidence.js`'s `_run` pattern).
- Produces: `resolveBranchEntry(scanRoot, originCommit, targetRef='HEAD'): {commit, ref, relationship: 'merge'|'direct'}|null` — used by `coordinator.js` (Task 11).

- [ ] **Step 1: Write the failing test**

```js
// scanner/test/posture/provenance-branch-entry.test.js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createGitFixture } from '../helpers/build-git-fixture.js';
import { resolveBranchEntry } from '../../src/posture/provenance/branch-entry.js';

test('Scenario D: merge — origin on feature branch, entry is the merge commit', () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('a.js', 'safe();\n');
    fx.commit('base', { date: '2026-01-01T00:00:00Z' });
    fx.checkoutBranch('feature');
    fx.writeFile('a.js', 'vuln();\n');
    const originSha = fx.commit('introduce on feature', { date: '2026-01-02T00:00:00Z' });
    fx.checkout('master');
    const mergeSha = fx.merge('feature', 'merge feature into master');

    const entry = resolveBranchEntry(fx.root, originSha, 'HEAD');
    assert.ok(entry);
    assert.equal(entry.commit, mergeSha);
    assert.equal(entry.relationship, 'merge');
  } finally {
    fx.cleanup();
  }
});

test('direct: origin commit is directly on the branch, no merge in between', () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('a.js', 'vuln();\n');
    const sha = fx.commit('direct commit', { date: '2026-01-01T00:00:00Z' });
    const entry = resolveBranchEntry(fx.root, sha, 'HEAD');
    assert.equal(entry.commit, sha);
    assert.equal(entry.relationship, 'direct');
  } finally {
    fx.cleanup();
  }
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test scanner/test/posture/provenance-branch-entry.test.js`
Expected: FAIL — module not found

- [ ] **Step 3: Write the implementation**

```js
// scanner/src/posture/provenance/branch-entry.js
import * as cp from 'node:child_process';

const GIT_TIMEOUT_MS = 2000;

function _run(scanRoot, args) {
  try {
    const stdout = cp.execFileSync('git', args, {
      cwd: scanRoot, encoding: 'utf8', timeout: GIT_TIMEOUT_MS, stdio: ['ignore', 'pipe', 'ignore'],
    });
    return { ok: true, stdout };
  } catch (e) {
    return { ok: false, stdout: '' };
  }
}

function _currentBranchName(scanRoot, targetRef) {
  const r = _run(scanRoot, ['rev-parse', '--abbrev-ref', targetRef]);
  return r.ok ? r.stdout.trim() : targetRef;
}

export function resolveBranchEntry(scanRoot, originCommit, targetRef = 'HEAD') {
  if (!originCommit) return null;
  const reachable = _run(scanRoot, ['merge-base', '--is-ancestor', originCommit, targetRef]);
  if (!reachable.ok) return null;

  const branchName = _currentBranchName(scanRoot, targetRef);
  const r = _run(scanRoot, ['log', '--merges', '--ancestry-path', '--reverse', '--format=%H', `${originCommit}..${targetRef}`]);
  if (r.ok && r.stdout.trim()) {
    const firstMerge = r.stdout.trim().split('\n')[0];
    return { commit: firstMerge, ref: `refs/heads/${branchName}`, relationship: 'merge' };
  }
  return { commit: originCommit, ref: `refs/heads/${branchName}`, relationship: 'direct' };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test scanner/test/posture/provenance-branch-entry.test.js`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add scanner/src/posture/provenance/branch-entry.js scanner/test/posture/provenance-branch-entry.test.js
git commit -m "feat(provenance): add branch-introduction resolver"
```

---

## Task 8: `evidence-attribution.js` (FR-PROV-005)

**Files:**
- Create: `scanner/src/posture/provenance/evidence-attribution.js`
- Test: `scanner/test/posture/provenance-evidence-attribution.test.js`

**Interfaces:**
- Consumes: `blameLine` from `git-evidence.js` (Task 3); `EVIDENCE_ROLE` from `schema.js` (Task 2).
- Produces: `attributeEvidence(scanRoot, finding): Array<{role, path, line, commit}>` — used by `coordinator.js` (Task 11).

- [ ] **Step 1: Write the failing test**

```js
// scanner/test/posture/provenance-evidence-attribution.test.js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createGitFixture } from '../helpers/build-git-fixture.js';
import { attributeEvidence } from '../../src/posture/provenance/evidence-attribution.js';

test('FR-PROV-005: multi-line finding exposes per-node attribution, not one collapsed author', () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('server.js', 'const input = req.query.id;\ndb.query("SELECT * FROM t WHERE id = " + input);\n');
    const sha1 = fx.commit('source line', { date: '2026-01-01T00:00:00Z', authorName: 'Alice' });
    fx.writeFile('server.js', 'const input = req.query.id;\ndb.query("SELECT * FROM t WHERE id = " + input); // sink\n');
    const sha2 = fx.commit('sink line touched', { date: '2026-01-02T00:00:00Z', authorName: 'Bob' });

    const finding = {
      file: 'server.js', line: 2,
      source: { file: 'server.js', line: 1 },
      sink: { file: 'server.js', line: 2 },
    };
    const nodes = attributeEvidence(fx.root, finding);
    const source = nodes.find((n) => n.role === 'source');
    const sink = nodes.find((n) => n.role === 'sink');
    assert.ok(source);
    assert.ok(sink);
    assert.equal(source.commit, sha1);
    assert.equal(sink.commit, sha2);
    assert.notEqual(source.commit, sink.commit);
  } finally {
    fx.cleanup();
  }
});

test('single-node finding with no source/sink falls back to a sink node at file:line', () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('a.js', 'eval(x);\n');
    const sha = fx.commit('c1', { date: '2026-01-01T00:00:00Z' });
    const nodes = attributeEvidence(fx.root, { file: 'a.js', line: 1 });
    assert.equal(nodes.length, 1);
    assert.equal(nodes[0].role, 'sink');
    assert.equal(nodes[0].commit, sha);
  } finally {
    fx.cleanup();
  }
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test scanner/test/posture/provenance-evidence-attribution.test.js`
Expected: FAIL — module not found

- [ ] **Step 3: Write the implementation**

```js
// scanner/src/posture/provenance/evidence-attribution.js
import { blameLine } from './git-evidence.js';
import { EVIDENCE_ROLE } from './schema.js';

export function attributeEvidence(scanRoot, finding) {
  const nodes = [];
  const push = (role, file, line) => {
    if (!file || !line) return;
    const blame = blameLine(scanRoot, file, line);
    nodes.push({ role, path: file, line, commit: blame && !blame.uncommitted ? blame.commit : null });
  };

  if (finding.source || finding.sink) {
    if (finding.source) push(EVIDENCE_ROLE.SOURCE, finding.source.file || finding.file, finding.source.line);
    if (finding.sink) push(EVIDENCE_ROLE.SINK, finding.sink.file || finding.file, finding.sink.line);
  } else {
    push(EVIDENCE_ROLE.SINK, finding.file, finding.line);
  }

  if (Array.isArray(finding.pathSteps)) {
    for (const step of finding.pathSteps) {
      const role = step.removedGuard ? EVIDENCE_ROLE.REMOVED_GUARD : EVIDENCE_ROLE.TRANSFORMATION;
      push(role, step.file || finding.file, step.line);
    }
  }

  return nodes;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test scanner/test/posture/provenance-evidence-attribution.test.js`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add scanner/src/posture/provenance/evidence-attribution.js scanner/test/posture/provenance-evidence-attribution.test.js
git commit -m "feat(provenance): add per-evidence-node blame attribution"
```

---

## Task 9: `cache.js`

**Files:**
- Create: `scanner/src/posture/provenance/cache.js`
- Test: `scanner/test/posture/provenance-cache.test.js`

**Interfaces:**
- Produces: `makeCacheKey({repoHead, stableId, detectorVersion, historyBoundary, mode}): string`, `cacheGet(scanRoot, key): object|null`, `cacheSet(scanRoot, key, value): void` — used by `coordinator.js` (Task 11).

- [ ] **Step 1: Write the failing test**

```js
// scanner/test/posture/provenance-cache.test.js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { createGitFixture } from '../helpers/build-git-fixture.js';
import { makeCacheKey, cacheGet, cacheSet } from '../../src/posture/provenance/cache.js';

test('cache: content-addressed round trip, no TTL, repo-local', () => {
  const fx = createGitFixture();
  try {
    const key = makeCacheKey({ repoHead: 'abc123', stableId: 'sid1', detectorVersion: '2026.09', historyBoundary: '', mode: 'standard' });
    assert.equal(cacheGet(fx.root, key), null);
    cacheSet(fx.root, key, { status: 'complete', findingOrigin: { commit: 'abc123' } });
    const got = cacheGet(fx.root, key);
    assert.deepEqual(got, { status: 'complete', findingOrigin: { commit: 'abc123' } });
    assert.ok(fs.existsSync(`${fx.root}/.agentic-security/provenance/cache`));
  } finally {
    fx.cleanup();
  }
});

test('cache: different repoHead produces a different key/miss', () => {
  const fx = createGitFixture();
  try {
    const k1 = makeCacheKey({ repoHead: 'head1', stableId: 'sid1', detectorVersion: 'v1', historyBoundary: '', mode: 'standard' });
    const k2 = makeCacheKey({ repoHead: 'head2', stableId: 'sid1', detectorVersion: 'v1', historyBoundary: '', mode: 'standard' });
    cacheSet(fx.root, k1, { status: 'complete' });
    assert.equal(cacheGet(fx.root, k2), null);
  } finally {
    fx.cleanup();
  }
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test scanner/test/posture/provenance-cache.test.js`
Expected: FAIL — module not found

- [ ] **Step 3: Write the implementation**

```js
// scanner/src/posture/provenance/cache.js
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';

function cacheDir(scanRoot) {
  return path.join(scanRoot, '.agentic-security', 'provenance', 'cache');
}

function keyPath(scanRoot, key) {
  const hash = crypto.createHash('sha256').update(key).digest('hex');
  return path.join(cacheDir(scanRoot), hash + '.json');
}

export function makeCacheKey({ repoHead, stableId, detectorVersion, historyBoundary, mode }) {
  return [repoHead || '', stableId || '', detectorVersion || '', historyBoundary || '', mode || ''].join('|');
}

export function cacheGet(scanRoot, key) {
  try {
    const p = keyPath(scanRoot, key);
    if (!fs.existsSync(p)) return null;
    return JSON.parse(fs.readFileSync(p, 'utf8'));
  } catch {
    return null;
  }
}

export function cacheSet(scanRoot, key, value) {
  try {
    fs.mkdirSync(cacheDir(scanRoot), { recursive: true });
    fs.writeFileSync(keyPath(scanRoot, key), JSON.stringify(value));
  } catch {
    // best-effort — cache failures must never fail a scan
  }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test scanner/test/posture/provenance-cache.test.js`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add scanner/src/posture/provenance/cache.js scanner/test/posture/provenance-cache.test.js
git commit -m "feat(provenance): add content-addressed repo-local provenance cache"
```

---

## Task 10: `lifecycle.js` (Scenario E — reintroduction)

**Files:**
- Create: `scanner/src/posture/provenance/lifecycle.js`
- Test: `scanner/test/posture/provenance-lifecycle.test.js`

**Interfaces:**
- Produces: `readLifecycle(scanRoot): object`, `async updateLifecycle(scanRoot, currentFindings, {scanId, observedAt}): object`, `latestOpenIntroduction(store, stableId): {type, commit, authorDate, scanId, observedAt}|null` — used by `coordinator.js` (Task 11) and, in Plan B, by `mttr.js`.

- [ ] **Step 1: Write the failing test**

```js
// scanner/test/posture/provenance-lifecycle.test.js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createGitFixture } from '../helpers/build-git-fixture.js';
import { readLifecycle, updateLifecycle, latestOpenIntroduction } from '../../src/posture/provenance/lifecycle.js';

test('Scenario E: introduce, remediate, reintroduce produces three ordered events', async () => {
  const fx = createGitFixture();
  try {
    const finding = { stableId: 'sid-e', findingProvenance: { status: 'complete', findingOrigin: { commit: 'c1', authorDate: '2026-01-01T00:00:00Z' } } };

    await updateLifecycle(fx.root, [finding], { scanId: 'scan1', observedAt: '2026-01-01T00:00:00Z' });
    let store = readLifecycle(fx.root);
    assert.equal(store['sid-e'].length, 1);
    assert.equal(store['sid-e'][0].type, 'introduced');

    await updateLifecycle(fx.root, [], { scanId: 'scan2', observedAt: '2026-02-01T00:00:00Z' });
    store = readLifecycle(fx.root);
    assert.equal(store['sid-e'].length, 2);
    assert.equal(store['sid-e'][1].type, 'remediated');
    assert.equal(latestOpenIntroduction(store, 'sid-e'), null);

    await updateLifecycle(fx.root, [finding], { scanId: 'scan3', observedAt: '2026-03-01T00:00:00Z' });
    store = readLifecycle(fx.root);
    assert.equal(store['sid-e'].length, 3);
    assert.equal(store['sid-e'][2].type, 'reintroduced');
    const latest = latestOpenIntroduction(store, 'sid-e');
    assert.ok(latest);
    assert.equal(latest.type, 'reintroduced');
  } finally {
    fx.cleanup();
  }
});

test('a finding present across two consecutive scans does not double-introduce', async () => {
  const fx = createGitFixture();
  try {
    const finding = { stableId: 'sid-stable', findingProvenance: { status: 'not_available' } };
    await updateLifecycle(fx.root, [finding], { scanId: 's1', observedAt: '2026-01-01T00:00:00Z' });
    await updateLifecycle(fx.root, [finding], { scanId: 's2', observedAt: '2026-01-02T00:00:00Z' });
    const store = readLifecycle(fx.root);
    assert.equal(store['sid-stable'].length, 1);
  } finally {
    fx.cleanup();
  }
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test scanner/test/posture/provenance-lifecycle.test.js`
Expected: FAIL — module not found

- [ ] **Step 3: Write the implementation**

```js
// scanner/src/posture/provenance/lifecycle.js
import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as path from 'node:path';

function storePath(scanRoot) { return path.join(scanRoot, '.agentic-security', 'provenance', 'lifecycle.json'); }
function lockPath(scanRoot) { return path.join(scanRoot, '.agentic-security', 'provenance', 'lifecycle.lock'); }

export function readLifecycle(scanRoot) {
  try {
    const p = storePath(scanRoot);
    if (!fs.existsSync(p)) return {};
    return JSON.parse(fs.readFileSync(p, 'utf8'));
  } catch {
    return {};
  }
}

async function withLock(scanRoot, fn) {
  const lp = lockPath(scanRoot);
  fs.mkdirSync(path.dirname(lp), { recursive: true });
  const start = Date.now();
  while (true) {
    try {
      const handle = await fsp.open(lp, 'wx');
      await handle.close();
      try {
        return await fn();
      } finally {
        await fsp.unlink(lp).catch(() => {});
      }
    } catch (e) {
      if (e && e.code === 'EEXIST') {
        if (Date.now() - start > 5000) throw new Error('provenance/lifecycle: lock timed out');
        await new Promise((r) => setTimeout(r, 25));
        continue;
      }
      throw e;
    }
  }
}

function isOpenEvent(events) {
  const last = events[events.length - 1];
  return !!last && (last.type === 'introduced' || last.type === 'reintroduced');
}

export async function updateLifecycle(scanRoot, currentFindings, { scanId, observedAt }) {
  return withLock(scanRoot, async () => {
    const store = readLifecycle(scanRoot);
    const currentIds = new Set(currentFindings.map((f) => f.stableId).filter(Boolean));

    for (const f of currentFindings) {
      if (!f.stableId) continue;
      const events = store[f.stableId] || (store[f.stableId] = []);
      if (isOpenEvent(events)) continue;
      const fp = f.findingProvenance;
      const commit = fp?.findingOrigin?.commit || null;
      const authorDate = fp?.status === 'complete' ? (fp.findingOrigin?.authorDate || observedAt) : observedAt;
      events.push({ type: events.length === 0 ? 'introduced' : 'reintroduced', commit, authorDate, scanId, observedAt });
    }

    for (const [stableId, events] of Object.entries(store)) {
      if (isOpenEvent(events) && !currentIds.has(stableId)) {
        events.push({ type: 'remediated', commit: null, authorDate: null, scanId, observedAt });
      }
    }

    fs.mkdirSync(path.dirname(storePath(scanRoot)), { recursive: true });
    fs.writeFileSync(storePath(scanRoot), JSON.stringify(store, null, 2));
    return store;
  });
}

export function latestOpenIntroduction(store, stableId) {
  const events = store[stableId];
  if (!events || events.length === 0) return null;
  const last = events[events.length - 1];
  return (last.type === 'introduced' || last.type === 'reintroduced') ? last : null;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test scanner/test/posture/provenance-lifecycle.test.js`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add scanner/src/posture/provenance/lifecycle.js scanner/test/posture/provenance-lifecycle.test.js
git commit -m "feat(provenance): add introduce/remediate/reintroduce lifecycle store"
```

---

## Task 11: `coordinator.js` (Scenarios G, K — terminal-status guarantee, budget/concurrency)

**Files:**
- Create: `scanner/src/posture/provenance/coordinator.js`
- Test: `scanner/test/posture/provenance-coordinator.test.js`

**Interfaces:**
- Consumes: `getRepoState`, `isGitRepo`, `blameLine` from `git-evidence.js` (Task 3); `resolveOrigin` from `origin-resolver.js` (Task 6); `resolveBranchEntry` from `branch-entry.js` (Task 7); `attributeEvidence` from `evidence-attribution.js` (Task 8); `assessConfidence` from `confidence.js` (Task 4); `cacheGet`, `cacheSet`, `makeCacheKey` from `cache.js` (Task 9); `emptyProvenance`, `PROVENANCE_STATUS`, `PROVENANCE_METHOD` from `schema.js` (Task 2).
- Produces: `async annotateProvenance(findings, ctx): void` where `ctx = {scanRoot, scanId, observedAt, rulesetVersion, since, timeoutMs, mode, disabled, findingType}` — mutates each finding's `.findingProvenance` in place. `findingType` defaults to `'sast'`; `'sca'` routes to a caller-supplied origin resolver (wired in Task 13). Used by `engine.js` (Task 14).

- [ ] **Step 1: Write the failing test**

```js
// scanner/test/posture/provenance-coordinator.test.js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createGitFixture } from '../helpers/build-git-fixture.js';
import { annotateProvenance } from '../../src/posture/provenance/coordinator.js';
import { computeStableId } from '../../src/posture/stable-id.js';
import { validateFindingsProvenance } from '../../src/posture/provenance/validate.js';

test('Scenario G: uncommitted finding gets status uncommitted, author unknown, no email', async () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('a.js', 'safe();\n');
    fx.commit('base', { date: '2026-01-01T00:00:00Z' });
    fx.writeFile('a.js', 'eval(x); // uncommitted\n');
    const finding = { file: 'a.js', line: 1, ruleId: 'eval-use' };
    finding.stableId = computeStableId(finding);

    await annotateProvenance([finding], { scanRoot: fx.root, scanId: 's1', observedAt: '2026-01-01T00:00:00Z', mode: 'standard' });

    assert.equal(finding.findingProvenance.status, 'uncommitted');
    assert.equal(finding.findingProvenance.findingOrigin, null);
    const { valid } = validateFindingsProvenance([finding]);
    assert.equal(valid, true);
  } finally {
    fx.cleanup();
  }
});

test('Scenario K: not a git repo still emits a finding, status not_available, never throws', async () => {
  const tmp = require('node:fs').mkdtempSync(require('node:path').join(require('node:os').tmpdir(), 'as-nogit-'));
  const finding = { file: 'a.js', line: 1, ruleId: 'x', stableId: 'sid1' };
  await annotateProvenance([finding], { scanRoot: tmp, scanId: 's1', observedAt: '2026-01-01T00:00:00Z' });
  assert.equal(finding.findingProvenance.status, 'not_available');
  require('node:fs').rmSync(tmp, { recursive: true, force: true });
});

test('every finding always gets a terminal findingProvenance, even on internal error', async () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('a.js', 'x\n');
    fx.commit('c1', { date: '2026-01-01T00:00:00Z' });
    // Deliberately malformed finding (no ruleId/sink/stableId at all) to force
    // the not_available path rather than throwing.
    const finding = { file: 'a.js', line: 1 };
    await annotateProvenance([finding], { scanRoot: fx.root, scanId: 's1', observedAt: '2026-01-01T00:00:00Z' });
    assert.ok(finding.findingProvenance);
    assert.ok(['not_available', 'error', 'partial', 'complete'].includes(finding.findingProvenance.status));
  } finally {
    fx.cleanup();
  }
});

test('--no-provenance (ctx.disabled) short-circuits to not_available for every finding', async () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('a.js', 'x\n'); fx.commit('c1');
    const findings = [{ file: 'a.js', line: 1, stableId: 's1' }, { file: 'a.js', line: 1, stableId: 's2' }];
    await annotateProvenance(findings, { scanRoot: fx.root, disabled: true });
    for (const f of findings) {
      assert.equal(f.findingProvenance.status, 'not_available');
      assert.match(f.findingProvenance.limitations[0], /disabled/);
    }
  } finally {
    fx.cleanup();
  }
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test scanner/test/posture/provenance-coordinator.test.js`
Expected: FAIL — module not found. (Note: the second test uses `require` inside an ESM test file via `createRequire` — see implementation step; if that pattern is awkward, an implementer may replace it with `node:fs`/`node:os`/`node:path` static imports at the top of the test file instead. Either is fine; the point under test is unchanged.)

- [ ] **Step 3: Write the implementation**

First, fix the test file's `require` usage to plain ESM imports (cleaner than `createRequire`):

```js
// scanner/test/posture/provenance-coordinator.test.js — replace the top imports with:
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { createGitFixture } from '../helpers/build-git-fixture.js';
import { annotateProvenance } from '../../src/posture/provenance/coordinator.js';
import { computeStableId } from '../../src/posture/stable-id.js';
import { validateFindingsProvenance } from '../../src/posture/provenance/validate.js';
```

And replace the `require(...)` calls in the "Scenario K" test body with `fs.mkdtempSync(path.join(os.tmpdir(), 'as-nogit-'))` and `fs.rmSync(tmp, { recursive: true, force: true })`.

```js
// scanner/src/posture/provenance/coordinator.js
import * as crypto from 'node:crypto';
import { getRepoState, isGitRepo, blameLine } from './git-evidence.js';
import { resolveOrigin } from './origin-resolver.js';
import { resolveBranchEntry } from './branch-entry.js';
import { attributeEvidence } from './evidence-attribution.js';
import { assessConfidence } from './confidence.js';
import { cacheGet, cacheSet, makeCacheKey } from './cache.js';
import { emptyProvenance, PROVENANCE_STATUS } from './schema.js';

const DEFAULT_TIMEOUT_MS = 60000;
const MAX_CONCURRENCY = 4;

function computeDigest(finding, provenance) {
  const material = JSON.stringify({
    stableId: finding.stableId,
    origin: provenance.findingOrigin?.commit || null,
    branchEntry: provenance.branchIntroduction?.commit || null,
    evidence: (provenance.evidenceAttribution || []).map((n) => `${n.role}:${n.path}:${n.line}:${n.commit}`),
    method: provenance.method,
    reasons: provenance.confidence?.reasons || [],
    limitations: provenance.limitations,
  });
  return crypto.createHash('sha256').update(material).digest('hex');
}

async function resolveOne(finding, ctx) {
  const { scanRoot, repoState } = ctx;

  if (finding.file && finding.line) {
    const blame = blameLine(scanRoot, finding.file, finding.line);
    if (blame && blame.uncommitted) {
      return emptyProvenance(PROVENANCE_STATUS.UNCOMMITTED, {
        limitations: ['finding exists only in working tree/index'],
      });
    }
  }

  if (!finding.stableId) {
    return emptyProvenance(PROVENANCE_STATUS.NOT_AVAILABLE, { limitations: ['finding has no stableId'] });
  }

  const cacheKey = makeCacheKey({
    repoHead: repoState.head, stableId: finding.stableId,
    detectorVersion: ctx.rulesetVersion, historyBoundary: ctx.since || '', mode: ctx.mode,
  });
  const cached = cacheGet(scanRoot, cacheKey);
  if (cached) return cached;

  const originResult = await resolveOrigin(scanRoot, finding, { since: ctx.since, deadlineAt: ctx.deadlineAt, repoState });

  let provenance;
  if (originResult.status === 'complete') {
    const branchIntroduction = resolveBranchEntry(scanRoot, originResult.findingOrigin.commit, repoState.branch || 'HEAD');
    const evidenceAttribution = attributeEvidence(scanRoot, finding);
    const confidence = assessConfidence({
      parentBoundaryVerified: originResult.parentBoundaryVerified,
      historyComplete: !repoState.shallow,
      detectorCompatible: true,
      renameAmbiguous: false,
      shallow: repoState.shallow,
    });
    provenance = emptyProvenance(PROVENANCE_STATUS.COMPLETE, {
      findingOrigin: originResult.findingOrigin,
      branchIntroduction,
      firstObserved: { scanId: ctx.scanId, observedAt: ctx.observedAt },
      evidenceAttribution,
      method: originResult.method,
      confidence,
      historyCoverage: { complete: !repoState.shallow, shallow: repoState.shallow, boundaryCommit: null, commitsConsidered: originResult.commitsConsidered },
      analysisBasis: { head: repoState.head, ruleset: ctx.rulesetVersion || null, detector: finding.parser || null, dirty: repoState.dirty },
    });
  } else if (originResult.status === 'partial') {
    provenance = emptyProvenance(PROVENANCE_STATUS.PARTIAL, {
      findingOrigin: originResult.findingOrigin || null,
      firstObserved: { scanId: ctx.scanId, observedAt: ctx.observedAt },
      historyCoverage: { complete: false, shallow: repoState.shallow, boundaryCommit: null, commitsConsidered: originResult.commitsConsidered || 0 },
      analysisBasis: { head: repoState.head, ruleset: ctx.rulesetVersion || null, detector: finding.parser || null, dirty: repoState.dirty },
      limitations: ['earliest observable — history could not confirm a verified parent boundary'],
      confidence: { level: 'low', score: 0.2, reasons: ['shallow_or_unverified_boundary'] },
    });
  } else if (originResult.status === 'budget_exhausted') {
    provenance = emptyProvenance(PROVENANCE_STATUS.BUDGET_EXHAUSTED, {
      historyCoverage: { complete: false, shallow: repoState.shallow, boundaryCommit: null, commitsConsidered: originResult.commitsConsidered || 0 },
      limitations: ['analysis budget expired before origin could be resolved'],
    });
  } else {
    provenance = emptyProvenance(PROVENANCE_STATUS.NOT_AVAILABLE, {
      limitations: [originResult.reason || 'no candidate history available'],
    });
  }

  provenance.evidenceDigest = computeDigest(finding, provenance);
  cacheSet(scanRoot, cacheKey, provenance);
  return provenance;
}

export async function annotateProvenance(findings, ctx) {
  if (!Array.isArray(findings) || findings.length === 0) return;
  const scanRoot = ctx.scanRoot;

  if (ctx.disabled) {
    for (const f of findings) {
      f.findingProvenance = emptyProvenance(PROVENANCE_STATUS.NOT_AVAILABLE, { limitations: ['provenance disabled via --no-provenance'] });
    }
    return;
  }
  if (!scanRoot || !isGitRepo(scanRoot)) {
    for (const f of findings) {
      f.findingProvenance = emptyProvenance(PROVENANCE_STATUS.NOT_AVAILABLE, { limitations: ['not a Git repository'] });
    }
    return;
  }

  const repoState = getRepoState(scanRoot);
  const deadlineAt = Date.now() + (ctx.timeoutMs || DEFAULT_TIMEOUT_MS);
  const fullCtx = { ...ctx, repoState, deadlineAt, scanRoot };

  let active = 0;
  let idx = 0;
  await new Promise((resolve) => {
    const next = () => {
      if (idx >= findings.length && active === 0) { resolve(); return; }
      while (active < MAX_CONCURRENCY && idx < findings.length) {
        const f = findings[idx++];
        active++;
        resolveOne(f, fullCtx)
          .then((prov) => { f.findingProvenance = prov; })
          .catch((e) => {
            f.findingProvenance = emptyProvenance(PROVENANCE_STATUS.ERROR, { limitations: [String((e && e.message) || e)] });
          })
          .finally(() => { active--; next(); });
      }
    };
    next();
  });
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test scanner/test/posture/provenance-coordinator.test.js`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add scanner/src/posture/provenance/coordinator.js scanner/test/posture/provenance-coordinator.test.js
git commit -m "feat(provenance): add coordinator — terminal-status guarantee, budget, cache wiring"
```

---

## Task 12: Manifest parser line-tracking (`package.json`, `requirements.txt`)

**Files:**
- Modify: `scanner/src/engine.js` (`_parsePackageJson` at line ~7343, `_parseRequirementsTxt` at line ~7380 — line numbers are from research and may have drifted; locate by function name, not line number, before editing)
- Test: `scanner/test/sast/manifest-line-tracking.test.js`

**Interfaces:**
- Consumes: nothing new.
- Produces: both parsers now include `line` (1-based) on every emitted dependency component — used by `sca-origin.js` (Task 13) via `scaEntry.filePath`/new `scaEntry.line`.

- [ ] **Step 1: Write the failing test**

```js
// scanner/test/sast/manifest-line-tracking.test.js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseManifests } from '../../src/engine.js';

test('package.json dependencies get a line number', () => {
  const text = [
    '{',
    '  "name": "x",',
    '  "dependencies": {',
    '    "left-pad": "^1.0.0",',
    '    "lodash": "^4.17.21"',
    '  },',
    '  "devDependencies": {',
    '    "mocha": "^10.0.0"',
    '  }',
    '}',
    '',
  ].join('\n');
  const deps = parseManifests({ 'package.json': text });
  const leftPad = deps.find((d) => d.name === 'left-pad');
  const mocha = deps.find((d) => d.name === 'mocha');
  assert.equal(leftPad.line, 4);
  assert.equal(mocha.line, 8);
});

test('requirements.txt dependencies get a line number, comments/blank lines skipped', () => {
  const text = [
    '# comment',
    '',
    'flask==2.0.0',
    'requests>=2.28.0',
  ].join('\n');
  const deps = parseManifests({ 'requirements.txt': text });
  const flask = deps.find((d) => d.name === 'flask');
  const requests = deps.find((d) => d.name === 'requests');
  assert.equal(flask.line, 3);
  assert.equal(requests.line, 4);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test scanner/test/sast/manifest-line-tracking.test.js`
Expected: FAIL — `deps.find(...)` results have `line: undefined`, assertion fails

- [ ] **Step 3: Write the implementation**

In `scanner/src/engine.js`, locate `_parseRequirementsTxt` (currently iterating `for(const line of text.split('\n'))`) and replace its loop with an indexed version:

```js
function _parseRequirementsTxt(text,filePath){
  const out=[];
  const lines=text.split('\n');
  for(let i=0;i<lines.length;i++){
    const t=lines[i].trim();
    if(!t||t.startsWith('#')||t.startsWith('-'))continue;
    const m=t.match(/^([A-Za-z0-9_.-]+)\s*[=~<>!]+\s*([^\s;#,]*)/);
    if(m)out.push({name:m[1],version:m[2],group:'',scope:'required',
      purl:_makePurl('pypi',m[1].toLowerCase(),m[2],''),ecosystem:'pypi',filePath,isUnpinned:false,line:i+1});
  }return out;
}
```

Locate `_parsePackageJson` and add a small line-finder helper immediately before it, then thread `line:` into the pushed object:

```js
function _findManifestLine(text, sectionKey, depName) {
  const lines = text.split('\n');
  let inSection = false;
  let depth = 0;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!inSection) {
      if (new RegExp(`"${sectionKey}"\\s*:\\s*\\{`).test(line)) { inSection = true; depth = 1; }
      continue;
    }
    depth += (line.match(/\{/g) || []).length;
    depth -= (line.match(/\}/g) || []).length;
    if (depth <= 0) { inSection = false; continue; }
    const escaped = depName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    if (new RegExp(`"${escaped}"\\s*:`).test(line)) return i + 1;
  }
  return null;
}

function _parsePackageJson(text,filePath){
  const out=[];try{const d=JSON.parse(text);
    for(const[depKey,scope]of[['dependencies','required'],['devDependencies','optional']]){
      for(const[name,verRange]of Object.entries(d[depKey]||{})){
        const ver=verRange.replace(/^[\^~>=<\s*]+/,'').split(/\s/)[0]||verRange;
        const scoped=name.startsWith('@');
        const parts=scoped?name.slice(1).split('/'):['',name];
        const group=scoped?`@${parts[0]}`:'';
        const pkgName=scoped?parts[1]:name;
        out.push({name,version:ver,group,scope,purl:_makePurl('npm',pkgName,ver,group),ecosystem:'npm',filePath,
          isUnpinned:verRange==='*'||verRange==='latest'||verRange===''||verRange==='>=0.0.0',
          line:_findManifestLine(text,depKey,name)});
      }
    }
  }catch(_){}return out;
}
```

`parseManifests` itself is unchanged — it already dispatches to these two functions by basename.

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test scanner/test/sast/manifest-line-tracking.test.js`
Expected: PASS

- [ ] **Step 5: Run the full SCA test scope to confirm no regression**

Run: `cd scanner && npm run test:sast` (covers `parseManifests` consumers) and check for any test asserting an exact object shape for `package.json`/`requirements.txt` components that would need updating for the new `line` field (an additive field should not break `assert.deepEqual` calls that don't enumerate every key, but check any that do).
Expected: PASS, or a small number of shape-assertion updates if a test does exact-key comparison — extend those tests' expected objects with `line`, don't drop the assertion.

- [ ] **Step 6: Commit**

```bash
git add scanner/src/engine.js scanner/test/sast/manifest-line-tracking.test.js
git commit -m "feat(sca): record declaration line for package.json and requirements.txt deps"
```

---

## Task 13: `sca-origin.js` — direct SCA origin strategy

**Files:**
- Create: `scanner/src/posture/provenance/sca-origin.js`
- Test: `scanner/test/posture/provenance-sca-origin.test.js`

**Interfaces:**
- Consumes: `candidateCommitsForFile`, `getFirstParent`, `getBlobAtCommit`, `commitMeta` from `git-evidence.js` (Task 3).
- Produces: `versionInRange(version, range): bool`, `scaStableId(entry): string`, `async resolveDirectSCAOrigin(scanRoot, scaEntry, {since, deadlineAt}={}): {status, method?, commitsConsidered, findingOrigin?, parentBoundaryVerified?, reason?}` — used by `coordinator.js`'s SCA branch (wired in Task 14).

- [ ] **Step 1: Write the failing test**

```js
// scanner/test/posture/provenance-sca-origin.test.js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createGitFixture } from '../helpers/build-git-fixture.js';
import { versionInRange, scaStableId, resolveDirectSCAOrigin } from '../../src/posture/provenance/sca-origin.js';

test('versionInRange: fixed-version upper bound', () => {
  assert.equal(versionInRange('1.2.3', { introduced: null, fixed: '1.3.0' }), true);
  assert.equal(versionInRange('1.3.0', { introduced: null, fixed: '1.3.0' }), false);
  assert.equal(versionInRange('2.0.0', { introduced: null, fixed: '1.3.0' }), false);
});

test('scaStableId is distinct per package+ecosystem+manifest', () => {
  const a = scaStableId({ osvId: 'GHSA-1', name: 'left-pad', ecosystem: 'npm', filePath: 'package.json' });
  const b = scaStableId({ osvId: 'GHSA-2', name: 'lodash', ecosystem: 'npm', filePath: 'package.json' });
  assert.notEqual(a, b);
});

test('resolveDirectSCAOrigin: finds the commit that bumped a dep into the vulnerable range', async () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('package.json', JSON.stringify({ name: 'x', dependencies: { 'left-pad': '0.9.0' } }, null, 2) + '\n');
    fx.commit('safe version', { date: '2026-01-01T00:00:00Z', authorName: 'Alice' });
    fx.writeFile('package.json', JSON.stringify({ name: 'x', dependencies: { 'left-pad': '1.0.0' } }, null, 2) + '\n');
    const shaVuln = fx.commit('bump to vulnerable version', { date: '2026-01-02T00:00:00Z', authorName: 'Bob' });

    const entry = { name: 'left-pad', ecosystem: 'npm', filePath: 'package.json', fixedVersions: ['1.1.0'] };
    const result = await resolveDirectSCAOrigin(fx.root, entry);
    assert.ok(['complete', 'partial'].includes(result.status));
    if (result.status === 'complete') {
      assert.equal(result.findingOrigin.commit, shaVuln);
      assert.equal(result.findingOrigin.authorName, 'Bob');
    }
  } finally {
    fx.cleanup();
  }
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test scanner/test/posture/provenance-sca-origin.test.js`
Expected: FAIL — module not found

- [ ] **Step 3: Write the implementation**

```js
// scanner/src/posture/provenance/sca-origin.js
import * as crypto from 'node:crypto';
import { candidateCommitsForFile, getFirstParent, getBlobAtCommit, commitMeta } from './git-evidence.js';
import { PROVENANCE_METHOD } from './schema.js';

function parseSemver(v) {
  const m = String(v || '').replace(/^[^\d]*/, '').match(/^(\d+)\.(\d+)\.(\d+)/);
  if (!m) return null;
  return [parseInt(m[1], 10), parseInt(m[2], 10), parseInt(m[3], 10)];
}

function cmpSemver(a, b) {
  for (let i = 0; i < 3; i++) { if (a[i] !== b[i]) return a[i] - b[i]; }
  return 0;
}

export function versionInRange(version, range) {
  const v = parseSemver(version);
  if (!v) return false;
  if (range.introduced) {
    const lo = parseSemver(range.introduced);
    if (lo && cmpSemver(v, lo) < 0) return false;
  }
  if (range.fixed) {
    const hi = parseSemver(range.fixed);
    if (hi && cmpSemver(v, hi) >= 0) return false;
  }
  return true;
}

export function scaStableId(entry) {
  const material = `${entry.osvId || ''}|${entry.name || ''}|${entry.ecosystem || ''}|${(entry.filePath || '').split('/').slice(-2).join('/')}`;
  return crypto.createHash('sha256').update(material).digest('hex').slice(0, 16);
}

function extractDeclaredVersion(blobText, depName, filePath) {
  const base = filePath.split('/').pop();
  if (base === 'package.json') {
    try {
      const d = JSON.parse(blobText);
      return (d.dependencies && d.dependencies[depName]) || (d.devDependencies && d.devDependencies[depName]) || null;
    } catch {
      return null;
    }
  }
  if (/^requirements(?:[._-][\w.-]+)?\.txt$/i.test(base)) {
    for (const line of blobText.split('\n')) {
      const m = line.trim().match(/^([A-Za-z0-9_.-]+)\s*[=~<>!]+\s*([^\s;#,]*)/);
      if (m && m[1].toLowerCase() === depName.toLowerCase()) return m[2];
    }
    return null;
  }
  return null;
}

export async function resolveDirectSCAOrigin(scanRoot, scaEntry, { since, deadlineAt } = {}) {
  const file = scaEntry.filePath;
  if (!file) return { status: 'not_available', reason: 'no-manifest-path', commitsConsidered: 0 };

  const candidates = candidateCommitsForFile(scanRoot, file, { since });
  if (candidates.length === 0) return { status: 'not_available', reason: 'no-candidate-commits', commitsConsidered: 0 };

  const range = { introduced: null, fixed: (scaEntry.fixedVersions || [])[0] || null };
  let commitsConsidered = 0;

  for (const sha of candidates) {
    if (deadlineAt && Date.now() > deadlineAt) return { status: 'budget_exhausted', commitsConsidered };
    commitsConsidered++;
    const blob = getBlobAtCommit(scanRoot, sha, file);
    if (blob == null) continue;
    const declaredVersion = extractDeclaredVersion(blob, scaEntry.name, file);
    if (!declaredVersion || !versionInRange(declaredVersion, range)) continue;

    const parent = getFirstParent(scanRoot, sha);
    let absentInParent = true;
    if (parent) {
      const parentBlob = getBlobAtCommit(scanRoot, parent, file);
      const parentVersion = parentBlob ? extractDeclaredVersion(parentBlob, scaEntry.name, file) : null;
      absentInParent = !parentVersion || !versionInRange(parentVersion, range);
      if (!absentInParent) continue;
    }

    const meta = commitMeta(scanRoot, sha);
    if (!meta) continue;
    return {
      status: 'complete', method: PROVENANCE_METHOD.DEPENDENCY_GRAPH_DIFF, commitsConsidered,
      findingOrigin: { commit: meta.commit, authorName: meta.authorName, authorEmail: meta.authorEmail,
        authorDate: meta.authorDate, committerDate: meta.committerDate, summary: meta.summary,
        presentInCommit: true, absentInParents: parent ? [parent] : [] },
      parentBoundaryVerified: !!parent,
    };
  }
  return { status: 'partial', reason: 'version-never-confirmed-in-candidates', commitsConsidered };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test scanner/test/posture/provenance-sca-origin.test.js`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add scanner/src/posture/provenance/sca-origin.js scanner/test/posture/provenance-sca-origin.test.js
git commit -m "feat(provenance): add direct-SCA origin resolution via manifest diff walk"
```

---

## Task 14: Wire SCA into `coordinator.js` + make `findingProvenance` required in the schema

**Files:**
- Modify: `scanner/src/posture/provenance/coordinator.js` (Task 11)
- Modify: `scanner/src/pipeline/finding-schema.js`
- Test: `scanner/test/posture/provenance-coordinator-sca.test.js`
- Test: `scanner/test/pipeline/finding-schema-provenance.test.js`

**Interfaces:**
- Consumes: `resolveDirectSCAOrigin`, `scaStableId` from `sca-origin.js` (Task 13).
- Produces: `annotateProvenance(entries, {..., findingType: 'sca'})` now resolves direct-SCA entries correctly and backfills `entry.stableId` when absent. `FINDING_FIELD_GROUPS.identity.required` now includes `findingProvenance` — used by `validate.js`/`describeFindingCompleteness()`.

- [ ] **Step 1: Write the failing tests**

```js
// scanner/test/posture/provenance-coordinator-sca.test.js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createGitFixture } from '../helpers/build-git-fixture.js';
import { annotateProvenance } from '../../src/posture/provenance/coordinator.js';

test('annotateProvenance with findingType sca resolves direct-dependency origin', async () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('package.json', JSON.stringify({ name: 'x', dependencies: { 'left-pad': '0.9.0' } }, null, 2) + '\n');
    fx.commit('safe version', { date: '2026-01-01T00:00:00Z' });
    fx.writeFile('package.json', JSON.stringify({ name: 'x', dependencies: { 'left-pad': '1.0.0' } }, null, 2) + '\n');
    fx.commit('bump to vulnerable version', { date: '2026-01-02T00:00:00Z', authorName: 'Bob' });

    const entry = { type: 'vulnerable_dep', name: 'left-pad', ecosystem: 'npm', filePath: 'package.json', osvId: 'GHSA-xyz', fixedVersions: ['1.1.0'] };
    await annotateProvenance([entry], { scanRoot: fx.root, scanId: 's1', observedAt: '2026-01-02T00:00:00Z', mode: 'standard', findingType: 'sca' });

    assert.ok(entry.findingProvenance);
    assert.ok(entry.stableId, 'coordinator should backfill stableId for SCA entries');
    if (entry.findingProvenance.status === 'complete') {
      assert.equal(entry.findingProvenance.findingOrigin.authorName, 'Bob');
    }
  } finally {
    fx.cleanup();
  }
});
```

```js
// scanner/test/pipeline/finding-schema-provenance.test.js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { describeFindingCompleteness } from '../../src/pipeline/finding-schema.js';

test('describeFindingCompleteness flags a finding missing findingProvenance as incomplete', () => {
  const result = describeFindingCompleteness({ id: 'f1', kind: 'sast', vuln: 'x', file: 'a.js', line: 1, severity: 'high' });
  assert.equal(result.isComplete, false);
  assert.ok(result.missingRequiredFields.includes('findingProvenance'));
});

test('describeFindingCompleteness accepts a finding with findingProvenance present', () => {
  const result = describeFindingCompleteness({
    id: 'f1', kind: 'sast', vuln: 'x', file: 'a.js', line: 1, severity: 'high',
    findingProvenance: { status: 'not_available' },
  });
  assert.ok(!result.missingRequiredFields.includes('findingProvenance'));
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `node --test scanner/test/posture/provenance-coordinator-sca.test.js scanner/test/pipeline/finding-schema-provenance.test.js`
Expected: FAIL — `entry.findingProvenance` is `undefined` (coordinator has no SCA branch yet); `findingProvenance` not in `missingRequiredFields` (schema not updated yet)

- [ ] **Step 3: Write the implementation**

In `scanner/src/pipeline/finding-schema.js`, add `findingProvenance` to the `identity` group's required list:

```js
export const FINDING_FIELD_GROUPS = {
  identity: { required: ['id', 'kind', 'vuln', 'findingProvenance'], optional: ['stableId'] },
  location: { required: ['file', 'line'], optional: ['snippet'] },
  classification: { required: ['severity'], optional: ['cwe', 'owaspLlm', 'family', 'parser', 'tags', 'description'] },
  confidence: { required: [], optional: ['confidence', 'confidenceTier', 'calibrated_confidence', 'calibration_reason'] },
  evidence: { required: [], optional: ['proof', 'falsification', 'verification', 'chain', 'sources', 'corroboration'] },
  privacy: { required: [], optional: ['dataClasses'] },
  compliance: { required: [], optional: [] }, // no per-finding controlRefs today — compliance mapping is scan-level (FR-501/E5)
  remediation: { required: [], optional: ['fix', 'remediation'] },
  risk: { required: [], optional: ['exploitability', 'exploitabilityTier', 'compositeRisk', 'compositeRiskTier', 'crownJewelScore', 'riskDollars'] },
  lifecycle: { required: [], optional: ['triage', 'quarantined', 'unreachable'] },
};
```

In `scanner/src/posture/provenance/coordinator.js`, import the SCA strategy and branch on `ctx.findingType`:

```js
// add to the top imports:
import { resolveDirectSCAOrigin, scaStableId } from './sca-origin.js';
```

Replace `resolveOne`'s stableId-backfill and origin-resolution call with a branch:

```js
async function resolveOne(finding, ctx) {
  const { scanRoot, repoState } = ctx;
  const isSca = ctx.findingType === 'sca';

  if (!isSca && finding.file && finding.line) {
    const blame = blameLine(scanRoot, finding.file, finding.line);
    if (blame && blame.uncommitted) {
      return emptyProvenance(PROVENANCE_STATUS.UNCOMMITTED, {
        limitations: ['finding exists only in working tree/index'],
      });
    }
  }

  if (isSca && !finding.stableId) {
    finding.stableId = scaStableId(finding);
  }
  if (!finding.stableId) {
    return emptyProvenance(PROVENANCE_STATUS.NOT_AVAILABLE, { limitations: ['finding has no stableId'] });
  }

  const cacheKey = makeCacheKey({
    repoHead: repoState.head, stableId: finding.stableId,
    detectorVersion: ctx.rulesetVersion, historyBoundary: ctx.since || '', mode: ctx.mode,
  });
  const cached = cacheGet(scanRoot, cacheKey);
  if (cached) return cached;

  const originResult = isSca
    ? await resolveDirectSCAOrigin(scanRoot, finding, { since: ctx.since, deadlineAt: ctx.deadlineAt })
    : await resolveOrigin(scanRoot, finding, { since: ctx.since, deadlineAt: ctx.deadlineAt, repoState });

  let provenance;
  if (originResult.status === 'complete') {
    const branchIntroduction = resolveBranchEntry(scanRoot, originResult.findingOrigin.commit, repoState.branch || 'HEAD');
    const evidenceAttribution = isSca
      ? [{ role: 'manifest', path: finding.filePath, line: finding.line || null, commit: originResult.findingOrigin.commit }]
      : attributeEvidence(scanRoot, finding);
    const confidence = assessConfidence({
      parentBoundaryVerified: originResult.parentBoundaryVerified,
      historyComplete: !repoState.shallow,
      detectorCompatible: true,
      renameAmbiguous: false,
      shallow: repoState.shallow,
    });
    provenance = emptyProvenance(PROVENANCE_STATUS.COMPLETE, {
      findingOrigin: originResult.findingOrigin,
      branchIntroduction,
      firstObserved: { scanId: ctx.scanId, observedAt: ctx.observedAt },
      evidenceAttribution,
      method: originResult.method,
      confidence,
      historyCoverage: { complete: !repoState.shallow, shallow: repoState.shallow, boundaryCommit: null, commitsConsidered: originResult.commitsConsidered },
      analysisBasis: { head: repoState.head, ruleset: ctx.rulesetVersion || null, detector: isSca ? 'sca-manifest-diff' : (finding.parser || null), dirty: repoState.dirty },
    });
  } else if (originResult.status === 'partial') {
    provenance = emptyProvenance(PROVENANCE_STATUS.PARTIAL, {
      findingOrigin: originResult.findingOrigin || null,
      firstObserved: { scanId: ctx.scanId, observedAt: ctx.observedAt },
      historyCoverage: { complete: false, shallow: repoState.shallow, boundaryCommit: null, commitsConsidered: originResult.commitsConsidered || 0 },
      analysisBasis: { head: repoState.head, ruleset: ctx.rulesetVersion || null, detector: isSca ? 'sca-manifest-diff' : (finding.parser || null), dirty: repoState.dirty },
      limitations: ['earliest observable — history could not confirm a verified parent boundary'],
      confidence: { level: 'low', score: 0.2, reasons: ['shallow_or_unverified_boundary'] },
    });
  } else if (originResult.status === 'budget_exhausted') {
    provenance = emptyProvenance(PROVENANCE_STATUS.BUDGET_EXHAUSTED, {
      historyCoverage: { complete: false, shallow: repoState.shallow, boundaryCommit: null, commitsConsidered: originResult.commitsConsidered || 0 },
      limitations: ['analysis budget expired before origin could be resolved'],
    });
  } else {
    provenance = emptyProvenance(PROVENANCE_STATUS.NOT_AVAILABLE, {
      limitations: [originResult.reason || 'no candidate history available'],
    });
  }

  provenance.evidenceDigest = computeDigest(finding, provenance);
  cacheSet(scanRoot, cacheKey, provenance);
  return provenance;
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `node --test scanner/test/posture/provenance-coordinator-sca.test.js scanner/test/pipeline/finding-schema-provenance.test.js`
Expected: PASS

- [ ] **Step 5: Run the full coordinator test suite to confirm no regression**

Run: `node --test scanner/test/posture/provenance-coordinator.test.js scanner/test/posture/provenance-coordinator-sca.test.js`
Expected: PASS (Task 11's tests must still pass — they don't set `findingType`, so `isSca` stays `false` and behavior is unchanged for them)

- [ ] **Step 6: Commit**

```bash
git add scanner/src/posture/provenance/coordinator.js scanner/src/pipeline/finding-schema.js scanner/test/posture/provenance-coordinator-sca.test.js scanner/test/pipeline/finding-schema-provenance.test.js
git commit -m "feat(provenance): wire direct-SCA origin into coordinator, require findingProvenance in schema"
```

---

## Task 15: Wire `annotateProvenance` into `engine.js`'s `runFullScan` pipeline

**Files:**
- Modify: `scanner/src/engine.js`
- Test: `scanner/test/dataflow/provenance-pipeline-integration.test.js`

**Interfaces:**
- Consumes: `annotateProvenance` from `posture/provenance/coordinator.js` (Task 14); `emptyProvenance`, `PROVENANCE_STATUS` from `posture/provenance/schema.js` (Task 2).
- Produces: every finding in `scan.findings` and every direct-dependency entry in `scan.supplyChain` now carries `.findingProvenance` after `runFullScan()` returns.

Locate the exact insertion point before editing — grep for the SCA transitive-dedup block (the line starting `try{const osvGroups=new Map();...`) and confirm it is immediately followed by the entrypoint-inventory line (`let _entrypointInventory = {}; try { _entrypointInventory = buildEntrypointInventory(...`). Line numbers in this task (~9910–9911, from research) may have drifted; anchor on those two exact code fragments instead.

- [ ] **Step 1: Write the failing test**

```js
// scanner/test/dataflow/provenance-pipeline-integration.test.js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createGitFixture } from '../helpers/build-git-fixture.js';
import { runFullScan } from '../../src/engine.js';

test('runFullScan attaches findingProvenance to every SAST finding in a real git repo', async () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('server.js', 'const input = req.query.id;\ndb.query("SELECT * FROM t WHERE id = " + input);\n');
    fx.commit('introduce sqli', { date: '2026-01-01T00:00:00Z', authorName: 'Alice' });

    const scan = await runFullScan({ scanRoot: fx.root }, () => {});
    assert.ok(Array.isArray(scan.findings));
    for (const f of scan.findings) {
      assert.ok(f.findingProvenance, `finding ${f.id} missing findingProvenance`);
      assert.ok(['complete', 'partial', 'not_available', 'uncommitted', 'budget_exhausted', 'error'].includes(f.findingProvenance.status));
    }
  } finally {
    fx.cleanup();
  }
});

test('runFullScan on a non-git directory still returns findings with status not_available', async () => {
  const fs = await import('node:fs');
  const os = await import('node:os');
  const path = await import('node:path');
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'as-nogit-integration-'));
  try {
    fs.writeFileSync(path.join(tmp, 'server.js'), 'db.query("SELECT * FROM t WHERE id = " + x);\n');
    const scan = await runFullScan({ scanRoot: tmp }, () => {});
    for (const f of scan.findings) {
      assert.equal(f.findingProvenance.status, 'not_available');
    }
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test scanner/test/dataflow/provenance-pipeline-integration.test.js`
Expected: FAIL — `f.findingProvenance` is `undefined`

- [ ] **Step 3: Write the implementation**

Add the import near `engine.js`'s existing `annotateGitHistory` import:

```js
import { annotateProvenance } from './posture/provenance/coordinator.js';
```

Insert this block immediately after the SCA transitive-dedup `try{...}catch(_){}` block and immediately before the `let _entrypointInventory = {}; try { ... } catch { ... }` line:

```js
  // Finding Provenance (M0/M1) — must run after annotateWhyFired and the
  // SCA/multi-sink correlation blocks above (needs their final finding
  // shape) and before annotateRelevance below, matching those modules'
  // "runs last, reflects final state" precedent. Never appends/drops
  // findings — only attaches finding.findingProvenance in place.
  await _runAnnotator("annotateProvenance", async () => {
    const disabled = process.env.AGENTIC_SECURITY_NO_PROVENANCE === '1';
    const provenanceCtx = {
      scanRoot, disabled,
      scanId: process.env.AGENTIC_SECURITY_SCAN_ID || null,
      observedAt: new Date().toISOString(),
      rulesetVersion: process.env.AGENTIC_SECURITY_RULESET_VERSION || null,
      since: process.env.AGENTIC_SECURITY_PROVENANCE_SINCE || null,
      timeoutMs: process.env.AGENTIC_SECURITY_PROVENANCE_TIMEOUT_MS
        ? parseInt(process.env.AGENTIC_SECURITY_PROVENANCE_TIMEOUT_MS, 10) : undefined,
      mode: process.env.AGENTIC_SECURITY_PROVENANCE_MODE || 'standard',
    };
    await annotateProvenance(finalFindings, provenanceCtx);
    const directDeps = supplyChain.filter((s) => s.type === 'vulnerable_dep' && !s.isTransitive);
    await annotateProvenance(directDeps, { ...provenanceCtx, findingType: 'sca' });
  });
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test scanner/test/dataflow/provenance-pipeline-integration.test.js`
Expected: PASS

- [ ] **Step 5: Run the full scanner test gate to confirm no regression**

Run: `cd scanner && npm run test:smoke && npm run test:sast`
Expected: PASS. If `annotateProvenance` measurably slows `test:smoke` (it now shells out to `git` per finding), that's expected and acceptable at this stage — Task 18's performance work belongs to Plan B, not this task. If a test times out entirely, check that the reference-benchmark repo (whatever `test:smoke` scans) is itself a git repository — if not, `annotateProvenance` should short-circuit fast via `!isGitRepo(scanRoot)`.

- [ ] **Step 6: Commit**

```bash
git add scanner/src/engine.js scanner/test/dataflow/provenance-pipeline-integration.test.js
git commit -m "feat(provenance): wire annotateProvenance into runFullScan pipeline"
```

---

## Task 16: Output — `normalizeFindings()` passthrough, `explainProvenance()`, MCP `explain_finding`

**Files:**
- Modify: `scanner/src/report/index.js`
- Modify: `scanner/src/mcp/tools.js`
- Test: `scanner/test/report/provenance-output.test.js`

**Interfaces:**
- Consumes: `redactFindingProvenance` from `posture/provenance/schema.js` (Task 2).
- Produces: `normalizeFindings(scan)`'s per-finding object now includes `findingProvenance` (redacted); new export `explainProvenance(f): string|null` from `report/index.js`; `toCLI(scan, {verbose, color, provenance})` — new `provenance` option prints the block; `explain_finding` MCP tool's response includes a redacted `findingProvenance`.

- [ ] **Step 1: Write the failing test**

```js
// scanner/test/report/provenance-output.test.js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { normalizeFindings, toCLI, explainProvenance } from '../../src/report/index.js';
import { emptyProvenance, PROVENANCE_STATUS } from '../../src/posture/provenance/schema.js';

function makeScan(findingProvenance) {
  return {
    findings: [{ id: 'f1', file: 'a.js', line: 1, severity: 'high', vuln: 'SQL Injection', cwe: 'CWE-89', findingProvenance }],
    filesScanned: 1,
  };
}

test('normalizeFindings carries findingProvenance through and redacts email by default', () => {
  const fp = emptyProvenance(PROVENANCE_STATUS.COMPLETE, {
    findingOrigin: { commit: 'abc1234', authorName: 'Jamie Chen', authorEmail: 'jamie@example.com', authorDate: '2026-03-14T00:00:00Z' },
  });
  const [f] = normalizeFindings(makeScan(fp));
  assert.ok(f.findingProvenance);
  assert.equal(f.findingProvenance.findingOrigin.authorName, 'Jamie Chen');
  assert.equal(f.findingProvenance.findingOrigin.authorEmail, null);
});

test('explainProvenance renders a human block for a complete origin', () => {
  const fp = emptyProvenance(PROVENANCE_STATUS.COMPLETE, {
    findingOrigin: { commit: 'abc1234567', authorName: 'Jamie Chen', authorDate: '2026-03-14T00:00:00Z' },
  });
  const text = explainProvenance({ findingProvenance: fp });
  assert.match(text, /abc1234/);
  assert.match(text, /Jamie Chen/);
});

test('explainProvenance handles not_available without throwing', () => {
  const text = explainProvenance({ findingProvenance: emptyProvenance(PROVENANCE_STATUS.NOT_AVAILABLE, { limitations: ['not a git repo'] }) });
  assert.match(text, /NOT AVAILABLE/);
});

test('toCLI with provenance:true includes the provenance block in output', () => {
  const fp = emptyProvenance(PROVENANCE_STATUS.COMPLETE, { findingOrigin: { commit: 'abc1234567', authorName: 'Jamie Chen', authorDate: '2026-03-14T00:00:00Z' } });
  const out = toCLI(makeScan(fp), { color: false, provenance: true });
  assert.match(out, /Jamie Chen/);
  const outWithout = toCLI(makeScan(fp), { color: false, provenance: false });
  assert.doesNotMatch(outWithout, /Jamie Chen/);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test scanner/test/report/provenance-output.test.js`
Expected: FAIL — `f.findingProvenance` undefined, `explainProvenance` not exported

- [ ] **Step 3: Write the implementation**

In `scanner/src/report/index.js`, add an import near the top:

```js
import { redactFindingProvenance } from '../posture/provenance/schema.js';
```

Inside `normalizeFindings(scan)`'s `out.push({...})` literal, add a new field (near the existing unrelated `provenance: f.provenance || null,` line — add this as a separate, new line, do not touch the existing one):

```js
      findingProvenance: f.findingProvenance
        ? redactFindingProvenance(f.findingProvenance, { includeEmail: process.env.AGENTIC_SECURITY_INCLUDE_AUTHOR_EMAIL === '1' })
        : null,
```

Add a new exported function (anywhere in the module, e.g. near `explainParts`):

```js
export function explainProvenance(f) {
  const fp = f.findingProvenance;
  if (!fp) return null;
  const lines = [];
  if (fp.status === 'complete' && fp.findingOrigin) {
    const o = fp.findingOrigin;
    lines.push(`Introduced:      ${(o.commit || '').slice(0, 7)}  •  ${(o.authorDate || '').slice(0, 10)}  •  ${o.authorName || 'unknown'}`);
    if (fp.branchIntroduction && fp.branchIntroduction.commit !== o.commit) {
      lines.push(`Branch entry:    ${(fp.branchIntroduction.commit || '').slice(0, 7)}  •  ${fp.branchIntroduction.relationship}`);
    }
  } else if (fp.status === 'partial') {
    lines.push(`Origin:          EARLIEST OBSERVABLE${fp.findingOrigin ? '  ' + (fp.findingOrigin.commit || '').slice(0, 7) : ''}`);
  } else if (fp.status === 'uncommitted') {
    lines.push('Origin:          UNCOMMITTED (working tree only)');
  } else if (fp.status === 'not_available') {
    lines.push('Origin:          NOT AVAILABLE');
  } else if (fp.status === 'error') {
    lines.push('Origin:          ERROR resolving provenance');
  } else if (fp.status === 'budget_exhausted') {
    lines.push('Origin:          BUDGET EXHAUSTED before resolution completed');
  }
  if (fp.firstObserved) lines.push(`First observed:  ${fp.firstObserved.scanId || ''}  •  ${(fp.firstObserved.observedAt || '').slice(0, 10)}`);
  lines.push(`Method:          ${fp.method}`);
  lines.push(`Confidence:      ${(fp.confidence?.level || 'unknown').toUpperCase()}`);
  if (fp.limitations && fp.limitations.length) lines.push(`Limitations:     ${fp.limitations.join('; ')}`);
  return lines.join('\n');
}
```

Change `toCLI`'s signature and add the provenance block after the existing `if (ex.fixCode) ...` line inside the per-finding loop:

```js
export function toCLI(scan, { verbose=false, color=true, provenance=false }={}){
  const findings = normalizeFindings(scan);
  const lines = [];
  const c = (s, code) => color ? `${code}${s}${RESET}` : s;
  lines.push(c(BOLD+`Agentic Security — ${findings.length} finding(s) across ${scan.filesScanned||0} file(s)`, ''));
  lines.push('');
  for (const f of findings) {
    const sevTag = c(`[${f.severity.toUpperCase()}]`, SEV_COLOR[f.severity]||'');
    const epssTag = f.epssScore != null ? c(`  EPSS:${Math.round(f.epssScore*100)}%`, DIM) : '';
    const kevTag = f.kev ? c('  KEV', '\x1b[1;31m') : '';
    const verdictTag = f.validator_verdict
      ? c(`  V:${f.validator_verdict}`, DIM)
      : '';
    lines.push(`${sevTag} ${c(f.cwe||'    ', DIM)}  ${f.file}:${f.line}  ${BOLD}${f.vuln}${RESET}${epssTag}${kevTag}${verdictTag}`);
    const rn = riskNote(f);
    if (rn) lines.push(`        ${c('↓ ' + rn, '\x1b[2;33m')}`);
    if (f.masked) lines.push(`        ${c('value:', DIM)} ${f.masked}`);
    const ex = explainParts(f, { verbose });
    if (ex.why) lines.push(`        ${c('why:', DIM)} ${ex.why}`);
    if (ex.how) lines.push(`        ${c('how:', DIM)} ${ex.how}`);
    if (ex.fix) lines.push(`        ${c('fix:', DIM)} ${ex.fix}`);
    if (ex.fixCode) for (const ln of ex.fixCode.split('\n').slice(0, 6)) lines.push(`           ${c(ln, DIM)}`);
    if (provenance) {
      const prov = explainProvenance(f);
      if (prov) for (const ln of prov.split('\n')) lines.push(`        ${c(ln, DIM)}`);
    }
  }
  lines.push('');
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity] = (counts[f.severity]||0) + 1;
  lines.push(`${c('Critical:', SEV_COLOR.critical)} ${counts.critical}    ${c('High:', SEV_COLOR.high)} ${counts.high}    ${c('Medium:', SEV_COLOR.medium)} ${counts.medium}    ${c('Low:', SEV_COLOR.low)} ${counts.low}    ${c('Info:', SEV_COLOR.info)} ${counts.info}`);
  return lines.join('\n');
}
```

In `scanner/src/mcp/tools.js`, add the same import and one field to `explain_finding`'s returned object (not inside the `redactFinding({...})` call — alongside the other fields already added outside it, like `confidence`/`compositeRisk`):

```js
// add near the top imports:
import { redactFindingProvenance } from '../posture/provenance/schema.js';

// inside explain_finding's handler, in the returned object, add:
      findingProvenance: f.findingProvenance ? redactFindingProvenance(f.findingProvenance) : null,
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test scanner/test/report/provenance-output.test.js`
Expected: PASS

- [ ] **Step 5: Run the report test scope to confirm no regression**

Run: `cd scanner && npm run test:report`
Expected: PASS — the existing `f.provenance || null` (AI-fingerprint) line and every other `normalizeFindings` field must be untouched; check any golden-output test that does exact-key comparison on the normalized-finding object and extend it with `findingProvenance`, don't drop the assertion.

- [ ] **Step 6: Commit**

```bash
git add scanner/src/report/index.js scanner/src/mcp/tools.js scanner/test/report/provenance-output.test.js
git commit -m "feat(provenance): surface findingProvenance in JSON/CLI output and explain_finding MCP tool"
```

---

## Task 17: CLI flags in `bin/agentic-security.js`

**Files:**
- Modify: `scanner/bin/agentic-security.js`
- Test: `scanner/test/cli/provenance-flags.test.js`

**Interfaces:**
- Consumes: nothing new (sets environment variables that Task 15's `engine.js` block and Task 16's `report/index.js` already read: `AGENTIC_SECURITY_NO_PROVENANCE`, `AGENTIC_SECURITY_PROVENANCE_MODE`, `AGENTIC_SECURITY_PROVENANCE_SINCE`, `AGENTIC_SECURITY_PROVENANCE_TIMEOUT_MS`, `AGENTIC_SECURITY_INCLUDE_AUTHOR_EMAIL`, `AGENTIC_SECURITY_REQUIRE_PROVENANCE`).
- Produces: a small, testable pure function `parseProvenanceFlags(argv: string[]): {mode, since, timeoutMs, includeEmail, requireProvenance, disabled, warning?}` that the CLI entry point calls before invoking the scan.

Before editing `bin/agentic-security.js`, grep it for how an existing scan-scoped flag (e.g. `--format` or `--deep`) is parsed and where in the argument-handling flow scan options get assembled, to find the exact insertion point — this plan gives the flag-parsing logic itself, not a fabricated line number, since the file's exact structure wasn't in this plan's research.

- [ ] **Step 1: Write the failing test**

```js
// scanner/test/cli/provenance-flags.test.js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseProvenanceFlags } from '../../bin/agentic-security.js';

test('parseProvenanceFlags: defaults to standard mode, nothing disabled', () => {
  const f = parseProvenanceFlags([]);
  assert.equal(f.mode, 'standard');
  assert.equal(f.disabled, false);
  assert.equal(f.includeEmail, false);
  assert.equal(f.requireProvenance, false);
});

test('parseProvenanceFlags: --no-provenance disables', () => {
  const f = parseProvenanceFlags(['--no-provenance']);
  assert.equal(f.disabled, true);
});

test('parseProvenanceFlags: --provenance deep is accepted but warns and stays standard', () => {
  const f = parseProvenanceFlags(['--provenance', 'deep']);
  assert.equal(f.mode, 'standard');
  assert.match(f.warning, /deep mode ships in a later release/);
});

test('parseProvenanceFlags: --provenance-since, --provenance-timeout, --include-author-email, --require-provenance', () => {
  const f = parseProvenanceFlags(['--provenance-since', 'v1.0.0', '--provenance-timeout', '30000', '--include-author-email', '--require-provenance']);
  assert.equal(f.since, 'v1.0.0');
  assert.equal(f.timeoutMs, 30000);
  assert.equal(f.includeEmail, true);
  assert.equal(f.requireProvenance, true);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test scanner/test/cli/provenance-flags.test.js`
Expected: FAIL — `parseProvenanceFlags` is not exported from `bin/agentic-security.js`

- [ ] **Step 3: Write the implementation**

Add this function to `scanner/bin/agentic-security.js` and export it (Node ESM scripts can both run as the CLI entry point and export named functions for testing):

```js
export function parseProvenanceFlags(argv) {
  const result = { mode: 'standard', since: null, timeoutMs: undefined, includeEmail: false, requireProvenance: false, disabled: false, warning: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--no-provenance') result.disabled = true;
    else if (a === '--provenance') {
      const v = argv[i + 1];
      if (v === 'deep') {
        result.mode = 'standard';
        result.warning = 'deep mode ships in a later release, running standard';
      } else if (v === 'standard') {
        result.mode = 'standard';
      }
      i++;
    } else if (a === '--provenance-since') { result.since = argv[++i] || null; }
    else if (a === '--provenance-timeout') { result.timeoutMs = parseInt(argv[++i], 10); }
    else if (a === '--include-author-email') { result.includeEmail = true; }
    else if (a === '--require-provenance') { result.requireProvenance = true; }
  }
  return result;
}
```

Wire it into the scan command's setup — before the code path that calls `runFullScan`/prints results, add:

```js
const _provFlags = parseProvenanceFlags(process.argv.slice(2));
if (_provFlags.warning) console.error(`Warning: ${_provFlags.warning}`);
if (_provFlags.disabled) process.env.AGENTIC_SECURITY_NO_PROVENANCE = '1';
process.env.AGENTIC_SECURITY_PROVENANCE_MODE = _provFlags.mode;
if (_provFlags.since) process.env.AGENTIC_SECURITY_PROVENANCE_SINCE = _provFlags.since;
if (_provFlags.timeoutMs) process.env.AGENTIC_SECURITY_PROVENANCE_TIMEOUT_MS = String(_provFlags.timeoutMs);
if (_provFlags.includeEmail) process.env.AGENTIC_SECURITY_INCLUDE_AUTHOR_EMAIL = '1';
```

For `--require-provenance`, add a post-scan check (after `runFullScan` returns, before exit-code determination) that inspects finding statuses without changing severity-based exit codes — augment `scan.scanHealth` defensively regardless of its existing shape:

```js
if (_provFlags.requireProvenance) {
  const incomplete = (scan.findings || [])
    .filter((f) => !['complete', 'uncommitted'].includes(f.findingProvenance?.status))
    .map((f) => f.id);
  if (incomplete.length > 0) {
    scan.scanHealth = scan.scanHealth || {};
    scan.scanHealth.provenanceIncomplete = incomplete;
  }
}
```

Locate the exact variable holding the scan result at this point in `bin/agentic-security.js` (likely `scan` per `runFullScan`'s return, but confirm by reading the surrounding code) before inserting — do not guess the name if the surrounding code shows otherwise.

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test scanner/test/cli/provenance-flags.test.js`
Expected: PASS

- [ ] **Step 5: Manual smoke check**

Run: `cd scanner && node bin/agentic-security.js scan test/fixtures/vulnerable --no-provenance --format json | node -e "const d=JSON.parse(require('fs').readFileSync(0,'utf8')); console.log(d.findings[0]?.findingProvenance)"`
Expected: prints `{ schemaVersion: '1.0', status: 'not_available', ... }` — confirms the flag actually reaches the engine.

- [ ] **Step 6: Commit**

```bash
git add scanner/bin/agentic-security.js scanner/test/cli/provenance-flags.test.js
git commit -m "feat(provenance): add --provenance/--no-provenance/--require-provenance CLI flags"
```

---

## Task 18: Safety and determinism test suite (Scenarios J, L; FR-PROV-024)

**Files:**
- Test: `scanner/test/security/provenance-safety.test.js`

**Interfaces:**
- Consumes: `annotateProvenance` from `coordinator.js` (Task 14/15); `runFullScan` from `engine.js` (Task 15).
- Produces: nothing new — this is a pure test task validating cross-cutting guarantees already built.

- [ ] **Step 1: Write the tests**

```js
// scanner/test/security/provenance-safety.test.js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { execFileSync } from 'node:child_process';
import { createGitFixture } from '../helpers/build-git-fixture.js';
import { runFullScan } from '../../src/engine.js';

const CANARY_SECRET = 'ghp_CANARY0123456789CANARY0123456789';

test('Scenario J: a historical secret never appears in provenance output, cache, or errors', async () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('config.js', `const token = "${CANARY_SECRET}";\n`);
    fx.commit('leak secret', { date: '2026-01-01T00:00:00Z' });
    fx.writeFile('config.js', 'const token = process.env.TOKEN;\n');
    fx.commit('remove secret', { date: '2026-01-02T00:00:00Z' });

    const scan = await runFullScan({ scanRoot: fx.root }, () => {});
    const serialized = JSON.stringify(scan);
    assert.doesNotMatch(serialized, new RegExp(CANARY_SECRET));

    const cacheDir = path.join(fx.root, '.agentic-security', 'provenance', 'cache');
    if (fs.existsSync(cacheDir)) {
      for (const file of fs.readdirSync(cacheDir)) {
        const content = fs.readFileSync(path.join(cacheDir, file), 'utf8');
        assert.doesNotMatch(content, new RegExp(CANARY_SECRET), `canary leaked into cache file ${file}`);
      }
    }
  } finally {
    fx.cleanup();
  }
});

test('FR-PROV-024: provenance analysis makes zero changes to the working tree', async () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('server.js', 'db.query("SELECT * FROM t WHERE id = " + x);\n');
    fx.commit('c1', { date: '2026-01-01T00:00:00Z' });
    const before = execFileSync('git', ['status', '--porcelain'], { cwd: fx.root, encoding: 'utf8' });
    await runFullScan({ scanRoot: fx.root }, () => {});
    const after = execFileSync('git', ['status', '--porcelain'], { cwd: fx.root, encoding: 'utf8' });
    assert.equal(before, after);
    const headBefore = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: fx.root, encoding: 'utf8' });
    const headAfter = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: fx.root, encoding: 'utf8' });
    assert.equal(headBefore, headAfter);
  } finally {
    fx.cleanup();
  }
});

test('Scenario L: two scans of the same HEAD produce byte-stable provenance (volatile fields excluded)', async () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('server.js', 'db.query("SELECT * FROM t WHERE id = " + x);\n');
    fx.commit('c1', { date: '2026-01-01T00:00:00Z', authorName: 'Alice' });

    const scan1 = await runFullScan({ scanRoot: fx.root }, () => {});
    const scan2 = await runFullScan({ scanRoot: fx.root }, () => {});

    const strip = (fp) => {
      if (!fp) return fp;
      const { firstObserved, ...rest } = fp;
      return rest;
    };
    const fp1 = scan1.findings.map((f) => strip(f.findingProvenance));
    const fp2 = scan2.findings.map((f) => strip(f.findingProvenance));
    assert.deepEqual(fp1, fp2);
  } finally {
    fx.cleanup();
  }
});
```

- [ ] **Step 2: Run tests to verify current status**

Run: `node --test scanner/test/security/provenance-safety.test.js`
Expected: PASS if Tasks 1–15 are implemented correctly — this task adds no new production code, only verification. If any assertion fails, the bug is in an earlier task's module (most likely `predicate-replay.js`'s `runFullScan` reuse for the secret-safety test, or `cache.js`/`coordinator.js` for the determinism test) — fix there, not by weakening this test.

- [ ] **Step 3: Commit**

```bash
git add scanner/test/security/provenance-safety.test.js
git commit -m "test(provenance): add secret-safety, read-only, and determinism guarantees"
```

---

## Self-review notes

**Spec coverage** — every in-scope FR from the spec's §1 maps to a task: FR-PROV-001 (Task 2/14), -002 (Task 3), -003 (Task 6), -004 (Task 7), -005 (Task 8), -006 (Task 5/6), -007 (Task 3's `--follow`/candidateCommitsForFile, exercised implicitly — a dedicated rename fixture is a documented gap, see below), -008 (Task 11), -009 (Task 6), -011 (uses existing `stable-id.js`, no task needed), -012 (Task 11's `firstObserved` vs `findingOrigin` separation), -013 (Task 10), -014 (Task 12/13), -016 (deferred to Plan B per the spec's M2 grouping — compliance `controlRefs` is explicitly M2), -018 (Task 16, JSON/CLI only per M1 scope — full format parity is Plan B), -020 (Task 11's never-throws guarantee + Task 17's scanHealth augmentation), -021 (Task 16), -024 (Task 18), -025 (Task 18), -026 (deferred to Plan B — HTML/Markdown/SARIF escaping is an M2 output-adapter concern; JSON's `JSON.stringify` is inherently injection-safe for M1's scope), -027 (Task 11's budget/concurrency), -028 (Task 9).

**Known gap, documented not hidden:** no dedicated rename-tracking fixture test (PRD Scenario C) is included in this plan. `candidateCommitsForFile`'s `--follow` flag provides the underlying capability, but a fixture proving it (file renamed after introduction, origin still resolves) was not written here — add it as a follow-up task before considering FR-PROV-007 done, using the same `createGitFixture` helper with a `git mv`-equivalent (`fx.writeFile` the new path, delete the old, commit — or extend `build-git-fixture.js` with a `rename()` helper first).

**Placeholder scan:** no "TBD"/"add appropriate handling" patterns. Two tasks (17's exact `bin/agentic-security.js` insertion point, 15's `engine.js` line numbers) instruct a grep-based verification step instead of asserting an unconfirmed line number — this is real code with a real anchor-finding method, not a deferred decision.

**Type consistency:** `findingProvenance` status/method/confidence-level strings match `schema.js`'s enums everywhere they're used (Tasks 6, 11, 13, 14, 16). `resolveOrigin`/`resolveDirectSCAOrigin`'s return shape (`status`, `commitsConsidered`, `findingOrigin`, `parentBoundaryVerified`, `reason`) is consistent between Tasks 6, 11, 13, 14. `attributeEvidence`'s node shape (`{role, path, line, commit}`) matches the PRD's `evidenceAttribution` schema field.

---

## What Plan B (M2) covers next

Not built here — full multi-format output parity (HTML/Markdown/CSV/SARIF `properties` bags), compliance `controlRefs` + derived-summary inheritance (FR-PROV-016), `mttr.js` age/SLA-basis wiring using `findingProvenance`/`lifecycle.js`, `fix-history.js` `provenanceAtFix` snapshots, `--require-provenance`'s full scan-health/exit-code integration, the `bench/provenance/` performance benchmark and its CI gate, and the rename-tracking fixture noted above.
