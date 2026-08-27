import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { execFileSync } from 'node:child_process';
import { createGitFixture } from '../helpers/build-git-fixture.js';
import { runFullScan } from '../../src/engine.js';
import { annotateGitProvenance } from '../../src/posture/provenance/coordinator.js';
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

    await annotateGitProvenance([finding], { scanRoot: fx.root, scanId: 's1', observedAt: '2026-01-01T00:00:00Z', mode: 'standard' });

    assert.equal(finding.findingProvenance.status, 'uncommitted');
    assert.equal(finding.findingProvenance.findingOrigin, null);
    const { valid } = validateFindingsProvenance([finding]);
    assert.equal(valid, true);
  } finally {
    fx.cleanup();
  }
});

test('Scenario K: not a git repo still emits a finding, status not_available, never throws', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'as-nogit-'));
  const finding = { file: 'a.js', line: 1, ruleId: 'x', stableId: 'sid1' };
  await annotateGitProvenance([finding], { scanRoot: tmp, scanId: 's1', observedAt: '2026-01-01T00:00:00Z' });
  assert.equal(finding.findingProvenance.status, 'not_available');
  fs.rmSync(tmp, { recursive: true, force: true });
});

test('every finding always gets a terminal findingProvenance, even on internal error', async () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('a.js', 'x\n');
    fx.commit('c1', { date: '2026-01-01T00:00:00Z' });
    // Deliberately malformed finding (no ruleId/sink/stableId at all) to force
    // the not_available path rather than throwing.
    const finding = { file: 'a.js', line: 1 };
    await annotateGitProvenance([finding], { scanRoot: fx.root, scanId: 's1', observedAt: '2026-01-01T00:00:00Z' });
    assert.ok(finding.findingProvenance);
    assert.ok(['not_available', 'error', 'partial', 'complete'].includes(finding.findingProvenance.status));
  } finally {
    fx.cleanup();
  }
});

test('a throw inside per-finding resolution degrades to status error, never propagates', async () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('a.js', 'x\n');
    fx.commit('c1', { date: '2026-01-01T00:00:00Z' });
    // Simulate a downstream module throwing mid-resolution: reading .stableId
    // blows up, which is exactly the shape of any git/replay/cache failure
    // that escapes its own try/catch.
    const boom = { file: 'a.js', line: 1 };
    Object.defineProperty(boom, 'stableId', { get() { throw new Error('simulated downstream failure'); } });
    const ok = { file: 'a.js', line: 1, stableId: 'sid-ok' };

    await annotateGitProvenance([boom, ok], { scanRoot: fx.root, scanId: 's1', observedAt: '2026-01-01T00:00:00Z' });

    assert.equal(boom.findingProvenance.status, 'error');
    assert.match(boom.findingProvenance.limitations[0], /simulated downstream failure/);
    // The sibling finding is unaffected — one bad finding does not poison the batch.
    assert.ok(ok.findingProvenance);
    assert.notEqual(ok.findingProvenance.status, 'error');
    assert.equal(validateFindingsProvenance([boom, ok]).valid, true);
  } finally {
    fx.cleanup();
  }
});

test('the bounded-concurrency scheduler drains a list longer than MAX_CONCURRENCY', async () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('a.js', 'x\n');
    fx.commit('c1', { date: '2026-01-01T00:00:00Z' });
    // 9 > MAX_CONCURRENCY (4): the refill path in the scheduler has to run
    // twice and still settle. A hang or an early resolve both fail here.
    const findings = Array.from({ length: 9 }, (_, i) => ({ file: 'a.js', line: 1, stableId: `sid-${i}` }));
    await annotateGitProvenance(findings, { scanRoot: fx.root, scanId: 's1', observedAt: '2026-01-01T00:00:00Z' });
    for (const f of findings) assert.ok(f.findingProvenance, 'every finding annotated');
    assert.equal(validateFindingsProvenance(findings).valid, true);
  } finally {
    fx.cleanup();
  }
});

// ── Fix round: the five review findings, each pinned in the failing direction ──

test('the budget is checked BEFORE the blame call, not after it', async () => {
  // Ordering, not just presence. blameLine is a synchronous execFileSync with a
  // 2s timeout, so a deadline consulted below it lets every post-deadline
  // finding pay for its blame anyway — N findings overrunning by up to 2N
  // seconds. The observable consequence of getting the order right: an
  // uncommitted finding, given an already-expired budget, reports
  // budget_exhausted rather than uncommitted. Both terminal; the budget is the
  // one we can answer for free.
  const fx = createGitFixture();
  try {
    fx.writeFile('a.js', 'safe();\n');
    fx.commit('base', { date: '2026-01-01T00:00:00Z' });
    fx.writeFile('a.js', 'eval(x); // uncommitted\n');
    const finding = { file: 'a.js', line: 1, ruleId: 'eval-use' };
    finding.stableId = computeStableId(finding);

    await annotateGitProvenance([finding], {
      scanRoot: fx.root, scanId: 's1', observedAt: '2026-01-01T00:00:00Z', timeoutMs: -1,
    });

    assert.equal(finding.findingProvenance.status, 'budget_exhausted');
    assert.match(finding.findingProvenance.limitations[0], /budget expired/);
  } finally {
    fx.cleanup();
  }
});

test('a budget_exhausted result is NEVER cached, so a larger --timeout still works', async () => {
  // The cache key has no time component and the cache has no TTL, both by
  // design. Caching "we ran out of time" — a property of the RUN, not of the
  // repository — would therefore pin that timeout in place until HEAD moved,
  // including across a re-run with a bigger budget, silently defeating the
  // operator's only remedy.
  const fx = createGitFixture();
  try {
    fx.writeFile('a.js', 'db.query("SELECT * FROM t WHERE id = " + id);\n');
    fx.commit('c1', { date: '2026-01-01T00:00:00Z' });
    const cacheDir = path.join(fx.root, '.agentic-security', 'provenance', 'cache');
    const stableId = 'sid-budget';

    // A 5ms budget deliberately lands INSIDE resolveOrigin rather than in the
    // pre-flight check: the pre-flight runs microseconds after the deadline is
    // computed, then one git-subprocess blame call (tens of ms) burns the
    // budget, so resolveOrigin's own loop is what reports it. That is the path
    // that used to reach cacheSet — the pre-flight one returns before the cache
    // is ever touched, and would pass this test either way. The limitation
    // string is asserted precisely so that a mis-timed run fails LOUDLY instead
    // of silently degrading into the non-discriminating path.
    const starved = { file: 'a.js', line: 1, ruleId: 'r', stableId };
    await annotateGitProvenance([starved], {
      scanRoot: fx.root, scanId: 's1', observedAt: '2026-01-01T00:00:00Z', timeoutMs: 5,
    });
    assert.equal(starved.findingProvenance.status, 'budget_exhausted');
    assert.match(starved.findingProvenance.limitations[0], /origin could be resolved/,
      'this test is only meaningful on the resolveOrigin budget path');

    // Nothing was written — asserted directly, so this holds for BOTH
    // budget_exhausted paths (the pre-flight check and resolveOrigin's own).
    const cached = fs.existsSync(cacheDir) ? fs.readdirSync(cacheDir) : [];
    assert.deepEqual(cached, [], 'a budget_exhausted verdict must not be cached');

    // The remedy: same finding, same HEAD, generous budget — must be resolved
    // afresh rather than served the old timeout back.
    const retried = { file: 'a.js', line: 1, ruleId: 'r', stableId };
    await annotateGitProvenance([retried], {
      scanRoot: fx.root, scanId: 's2', observedAt: '2026-01-01T00:00:00Z',
    });
    assert.notEqual(retried.findingProvenance.status, 'budget_exhausted',
      'a re-run with a larger budget must not be served a cached timeout');
  } finally {
    fx.cleanup();
  }
});

test('a partial result carries its method and its reason, not "none" and a generic string', async () => {
  // origin-resolver's shallow-boundary case returns partial WITH a populated
  // findingOrigin AND method:'semantic-history-replay'. Dropping the method let
  // emptyProvenance's 'none' default stand, emitting "here is the origin commit,
  // found by no method" — self-contradictory, and it fed computeDigest. The two
  // partial reasons also mean different things and must stay distinguishable.
  //
  // A REAL shallow clone, not a {shallow:true} stub: the coordinator calls the
  // real getRepoState(), which is the whole point of threading it through.
  const origin = createGitFixture();
  const clonePath = fs.mkdtempSync(path.join(os.tmpdir(), 'as-shallow-'));
  try {
    origin.writeFile('server.js', 'function h(id) {\n  return 1;\n}\n');
    origin.commit('c1', { date: '2026-01-01T00:00:00Z' });
    origin.writeFile('server.js', 'function h(id) {\n  db.query("SELECT * FROM t WHERE id = " + id);\n}\n');
    origin.commit('c2', { date: '2026-01-02T00:00:00Z' });

    fs.rmSync(clonePath, { recursive: true, force: true });
    execFileSync('git', ['clone', '-q', '--depth=1', `file://${origin.root}`, clonePath], { stdio: 'ignore' });
    assert.equal(
      execFileSync('git', ['rev-parse', '--is-shallow-repository'], { cwd: clonePath, encoding: 'utf8' }).trim(),
      'true', 'fixture must actually be a shallow clone or this proves nothing');

    // Derive the finding from a real scan so its stableId is one replayAt can
    // reproduce from the historical blob (same reasoning as the Task 6 tests).
    const src = fs.readFileSync(path.join(clonePath, 'server.js'), 'utf8');
    const scan = await runFullScan({ fileContents: { 'server.js': src }, scanRoot: clonePath }, () => {});
    const finding = (scan.findings || []).find((f) => f.file === 'server.js' && f.family === 'sql-injection');
    assert.ok(finding && finding.stableId, 'expected a real sql-injection finding with a stableId');

    await annotateGitProvenance([finding], {
      scanRoot: clonePath, scanId: 's1', observedAt: '2026-01-01T00:00:00Z',
    });

    const fp = finding.findingProvenance;
    assert.equal(fp.status, 'partial');
    assert.equal(fp.method, 'semantic-history-replay',
      'a partial that found an origin must say HOW — "none" contradicts its own findingOrigin');
    assert.ok(fp.findingOrigin, 'the shallow-boundary case does report an origin commit');
    assert.match(fp.limitations[0], /shallow-boundary-reached/,
      'the specific reason must survive, not collapse into a generic string');
  } finally {
    origin.cleanup();
    fs.rmSync(clonePath, { recursive: true, force: true });
  }
});

test('--no-provenance (ctx.disabled) short-circuits to not_available for every finding', async () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('a.js', 'x\n'); fx.commit('c1');
    const findings = [{ file: 'a.js', line: 1, stableId: 's1' }, { file: 'a.js', line: 1, stableId: 's2' }];
    await annotateGitProvenance(findings, { scanRoot: fx.root, disabled: true });
    for (const f of findings) {
      assert.equal(f.findingProvenance.status, 'not_available');
      assert.match(f.findingProvenance.limitations[0], /disabled/);
    }
  } finally {
    fx.cleanup();
  }
});

// ---------------------------------------------------------------------------
// Final whole-branch review — I1: the budget is ONE budget for the whole scan.
// ---------------------------------------------------------------------------

test('I1: a caller-supplied deadlineAt wins over a freshly-computed one', async () => {
  // engine.js calls annotateGitProvenance TWICE per scan (SAST findings, then
  // direct SCA deps). With the deadline computed fresh inside each call, the
  // effective scan-level budget was 2x the operator's --provenance-timeout: an
  // operator asking for a 30s cap could wait 60s. The fix is a shared deadline
  // established once by the caller, which only works if the caller's value is
  // honoured over the local computation — asserted here by handing over an
  // ALREADY-EXPIRED deadline together with a generous timeoutMs. If timeoutMs
  // won, the finding would resolve normally.
  const fx = createGitFixture();
  try {
    fx.writeFile('a.js', 'const q = req.query.id;\ndb.query("SELECT " + q);\n');
    fx.commit('vuln', { date: '2026-01-01T00:00:00Z' });
    const finding = { file: 'a.js', line: 2, ruleId: 'js-sql-query' };
    finding.stableId = computeStableId(finding);

    await annotateGitProvenance([finding], {
      scanRoot: fx.root, scanId: 's1', observedAt: '2026-01-01T00:00:00Z',
      timeoutMs: 600000,           // generous — must NOT be what is used
      deadlineAt: Date.now() - 1,  // already expired — must win
    });

    assert.equal(finding.findingProvenance.status, 'budget_exhausted',
      'the caller-supplied global deadline was ignored, so the second annotator pass gets a fresh budget');
  } finally {
    fx.cleanup();
  }
});

test('I1: one finding cannot consume the whole budget — the per-finding sub-budget bounds it', async () => {
  // The spec's `max(2s, global/estimatedFindingCount)` sub-budget was never
  // implemented, so a single finding with a long candidate-commit list could
  // walk history until the GLOBAL deadline expired, leaving every finding
  // queued behind it `budget_exhausted` without a single git call spent on it.
  //
  // Observable form of the guarantee: with a global budget far larger than the
  // per-finding floor, a finding whose own share has expired reports the
  // PER-FINDING limitation, not the global one — proving the sub-budget is a
  // real second bound and not a relabelling of the global check. Here the
  // global deadline is still in the future when the result is built, which is
  // the branch that distinguishes them.
  const fx = createGitFixture();
  try {
    fx.writeFile('a.js', 'safe();\n');
    fx.commit('base', { date: '2026-01-01T00:00:00Z' });
    fx.writeFile('a.js', 'const q = req.query.id;\ndb.query("SELECT " + q);\n');
    fx.commit('vuln', { date: '2026-01-02T00:00:00Z' });
    const finding = { file: 'a.js', line: 2, ruleId: 'js-sql-query' };
    finding.stableId = computeStableId(finding);

    // Both bounds are exercised by the SAME call: the global deadline is 10
    // minutes out (so the top-of-loop global check passes and the blame runs),
    // while the per-finding share is one millisecond.
    await annotateGitProvenance([finding], {
      scanRoot: fx.root, scanId: 's1', observedAt: '2026-01-01T00:00:00Z',
      deadlineAt: Date.now() + 600000,
      perFindingBudgetMs: 1,
    });

    const prov = finding.findingProvenance;
    assert.equal(prov.status, 'budget_exhausted',
      `expected the per-finding sub-budget to stop the history walk; got ${prov.status}`);
    assert.match(prov.limitations[0], /per-finding share/,
      `a per-finding overrun must be reported as such, not as the global budget: ${JSON.stringify(prov.limitations)}`);
  } finally {
    fx.cleanup();
  }
});

test('I1: the default per-finding budget never falls below the 2s floor', async () => {
  // `global/estimatedFindingCount` alone divides a 60s budget across 200
  // findings into 300ms — less than a single `git blame`'s own 2s timeout — so
  // the quotient would starve every finding equally instead of bounding the
  // expensive few. The floor is what makes the sub-budget a bound rather than a
  // second, tighter global failure. Asserted through observable behaviour: a
  // large finding list under the DEFAULT budget still resolves normally.
  const fx = createGitFixture();
  try {
    fx.writeFile('a.js', 'const q = req.query.id;\ndb.query("SELECT " + q);\n');
    fx.commit('vuln', { date: '2026-01-01T00:00:00Z' });
    const findings = [];
    for (let i = 0; i < 40; i++) {
      const f = { file: 'a.js', line: 2, ruleId: `rule-${i}` };
      f.stableId = computeStableId(f);
      findings.push(f);
    }
    await annotateGitProvenance(findings, {
      scanRoot: fx.root, scanId: 's1', observedAt: '2026-01-01T00:00:00Z',
    });
    const exhausted = findings.filter((f) => f.findingProvenance.status === 'budget_exhausted');
    assert.equal(exhausted.length, 0,
      `${exhausted.length}/40 findings were starved by the sub-budget under the default global budget`);
  } finally {
    fx.cleanup();
  }
});
