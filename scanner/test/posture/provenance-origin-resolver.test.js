// Task 6: origin-resolver.js — candidate-seeded linear-replay origin
// resolution (Finding Provenance PRD Scenarios A, B, F).
//
// Scenario A and F derive their `finding` from a REAL detector run
// (`runFullScan`) against the fixture's own content, rather than hand-
// constructing a finding object with a fabricated `ruleId`/`sink.snippet`.
// `computeStableId` prefers `f.ruleId`, then falls back through
// `cwe:`/`fam:`/`parser:` — a real detected finding never carries the shape
// a hand-built test object might assume, so a hand-computed "target"
// stableId will almost certainly not match what replayAt's real detector
// suite reproduces from the historical blob. Deriving the finding (and its
// stableId) from an actual scan is the only reliable way to exercise the
// `complete` path.
//
// The vulnerable line — `db.query("SELECT * FROM t WHERE id = " + id);` —
// is chosen because it matches `js-framework-structural.js`'s taint-
// independent structural SQLi rule (`.query(` + string-concat), which fires
// on a bare snippet with no route/taint context and does not require deep
// mode.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createGitFixture } from '../helpers/build-git-fixture.js';
import { resolveOrigin } from '../../src/posture/provenance/origin-resolver.js';
import { runFullScan } from '../../src/engine.js';

const SAFE_SRC = 'function h(id) {\n  return 1;\n}\n';
const VULN_SRC = 'function h(id) {\n  db.query("SELECT * FROM t WHERE id = " + id);\n}\n';

async function realSqlInjectionFinding(content, filePath, scanRoot) {
  const scan = await runFullScan({ fileContents: { [filePath]: content }, scanRoot }, () => {});
  const finding = (scan.findings || []).find(
    (f) => f.file === filePath && f.family === 'sql-injection',
  );
  assert.ok(finding, `expected scanJsFrameworkStructural to fire on ${filePath}, got: ${JSON.stringify((scan.findings || []).map((f) => ({ file: f.file, family: f.family, parser: f.parser })))}`);
  assert.ok(finding.stableId, 'real finding must carry a stableId from the annotation pipeline');
  return finding;
}

test('Scenario A: direct introduction resolves to that commit, high-confidence-eligible', async () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('server.js', SAFE_SRC);
    fx.commit('safe baseline', { date: '2026-01-01T00:00:00Z', authorName: 'Alice' });
    fx.writeFile('server.js', VULN_SRC);
    const shaVuln = fx.commit('introduce sqli', { date: '2026-01-02T00:00:00Z', authorName: 'Bob' });

    const finding = await realSqlInjectionFinding(VULN_SRC, 'server.js', fx.root);

    const result = await resolveOrigin(fx.root, finding, { repoState: { shallow: false } });
    assert.equal(result.status, 'complete', `expected complete, got ${result.status} (${result.reason || ''})`);
    assert.equal(result.findingOrigin.commit, shaVuln);
    assert.equal(result.findingOrigin.authorName, 'Bob');
    assert.equal(result.method, 'semantic-history-replay');
    // The parent (safe baseline) genuinely lacks the finding, so the walk
    // should have verified absence there, not merely reached a boundary.
    assert.equal(result.parentBoundaryVerified, true);
    assert.equal(result.findingOrigin.absentInParents.length, 1);
    assert.ok(result.commitsConsidered >= 1);
  } finally {
    fx.cleanup();
  }
});

test('Scenario B: predicate present in every candidate (introduced before earliest candidate) does not falsely attribute to a later edit', async () => {
  const fx = createGitFixture();
  try {
    // Both commits carry the vulnerable shape at line 2 — a later commit
    // only changes an unrelated line, so the ONLY commit where the SQLi
    // predicate is absent-in-parent is unreachable from these two candidates
    // (there is no earlier safe state to diff against). The resolver must
    // not fabricate an origin at either candidate.
    fx.writeFile('server.js', VULN_SRC);
    fx.commit('already vulnerable at repo creation', { date: '2026-01-01T00:00:00Z', authorName: 'Alice' });
    fx.writeFile('server.js', VULN_SRC.replace('function h(id)', 'function h(id) '));
    fx.commit('unrelated whitespace tweak', { date: '2026-01-02T00:00:00Z', authorName: 'Carol' });

    const finding = await realSqlInjectionFinding(VULN_SRC, 'server.js', fx.root);
    const result = await resolveOrigin(fx.root, finding, { repoState: { shallow: false } });
    // Either the walk resolves to the true root commit (complete, but with
    // parentBoundaryVerified:false since there's nothing earlier to diff
    // against) or it can't confirm introduction among the candidates
    // (partial) — what it must NEVER do is claim `complete` at a later
    // commit whose parent still had the predicate present.
    assert.ok(['complete', 'partial'].includes(result.status));
    if (result.status === 'complete') {
      assert.equal(result.parentBoundaryVerified, false);
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

    const finding = await realSqlInjectionFinding('db.query("SELECT * FROM t WHERE id = " + id);\n', 'server.js', fx.root);
    const result = await resolveOrigin(fx.root, finding, { repoState: { shallow: true } });
    assert.notEqual(result.status, 'complete');
    assert.equal(result.status, 'partial');
    assert.equal(result.reason, 'shallow-boundary-reached');
  } finally {
    fx.cleanup();
  }
});

test('Scenario F counterpart: non-shallow repo hitting the true root commit reaches complete but with parentBoundaryVerified:false', async () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('server.js', 'db.query("SELECT * FROM t WHERE id = " + id);\n');
    fx.commit('only commit', { date: '2026-01-01T00:00:00Z', authorName: 'Dave' });

    const finding = await realSqlInjectionFinding('db.query("SELECT * FROM t WHERE id = " + id);\n', 'server.js', fx.root);
    const result = await resolveOrigin(fx.root, finding, { repoState: { shallow: false } });
    assert.equal(result.status, 'complete');
    assert.equal(result.parentBoundaryVerified, false);
    assert.equal(result.findingOrigin.authorName, 'Dave');
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
    assert.equal(result.reason, 'missing-file-line-or-stableId');
  } finally {
    fx.cleanup();
  }
});

test('resolveOrigin: no candidate commits (file never touched at that line) is not_available, never throws', async () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('a.js', 'x\n');
    fx.commit('c1');
    const result = await resolveOrigin(fx.root, { file: 'nope.js', line: 5, stableId: 'deadbeef' }, {});
    assert.equal(result.status, 'not_available');
    assert.equal(result.reason, 'no-candidate-commits');
  } finally {
    fx.cleanup();
  }
});

test('resolveOrigin: budget_exhausted when deadlineAt is already in the past', async () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('server.js', SAFE_SRC);
    fx.commit('safe baseline', { date: '2026-01-01T00:00:00Z' });
    fx.writeFile('server.js', VULN_SRC);
    fx.commit('introduce sqli', { date: '2026-01-02T00:00:00Z' });

    const finding = await realSqlInjectionFinding(VULN_SRC, 'server.js', fx.root);
    const result = await resolveOrigin(fx.root, finding, { deadlineAt: Date.now() - 1000 });
    assert.equal(result.status, 'budget_exhausted');
    assert.equal(result.commitsConsidered, 0);
  } finally {
    fx.cleanup();
  }
});
