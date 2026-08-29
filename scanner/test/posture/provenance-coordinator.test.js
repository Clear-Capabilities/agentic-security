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
import { CURRENT_RULESET_VERSION } from '../../src/posture/ruleset-version.js';

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
    const cacheDir = path.join(fx.root, '.agentic-security', 'provenance-cache');
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

// Second independent Finding Provenance PRD audit (Task 3): the rename-
// shaped miss (origin-resolver.js's `renameShapedMiss`) must surface its own
// specific reason end-to-end through the coordinator, not collapse into the
// generic `predicate-never-confirmed-in-candidates` string — same shape as
// the shallow-boundary test above, for the sibling reason. This does NOT
// assert the origin resolves correctly (it still doesn't — that is the
// separately-scoped, honestly-disclosed rename-follow gap; see
// bench/provenance-accuracy/fixtures/rename.mjs's header), only that the
// reason is now honest about WHY it stayed partial.
test('a rename-shaped partial result reports rename-detected-not-followed, not the generic reason', async () => {
  const fx = createGitFixture();
  try {
    fx.writeFile(
      'server.js',
      'function h(req) {\n  const input = req.query.id;\n  db.query("SELECT * FROM t WHERE id = " + input);\n}\n',
    );
    fx.commit('introduce sqli', { date: '2026-01-01T00:00:00Z', authorName: 'Bob' });

    const serverPath = path.join(fx.root, 'server.js');
    const content = fs.readFileSync(serverPath, 'utf8');
    fs.rmSync(serverPath);
    fx.writeFile('api.js', content + '\n// renamed module\n');
    fx.commit('rename server.js to api.js', { date: '2026-01-02T00:00:00Z', authorName: 'Carol' });

    const finding = { file: 'api.js', line: 3, vuln: 'SQL Injection', ruleId: 'sql-injection', cwe: 'CWE-89' };
    finding.stableId = computeStableId(finding);

    await annotateGitProvenance([finding], { scanRoot: fx.root, scanId: 's1', observedAt: '2026-01-01T00:00:00Z' });

    const fp = finding.findingProvenance;
    assert.equal(fp.status, 'partial');
    assert.match(fp.limitations[0], /renamed after that commit/,
      'the rename-specific limitation text must survive, not collapse into the generic reason');
    assert.ok(fp.confidence.reasons.includes('rename_detected_not_followed'));
    const { valid } = validateFindingsProvenance([finding]);
    assert.equal(valid, true);
  } finally {
    fx.cleanup();
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

test('annotateGitProvenance: two findings sharing a stableId resolve via one underlying walk, not two', async () => {
  // Two DISTINCT finding objects that happen to carry the identical
  // stableId (the realistic case: the same underlying condition surfaced
  // twice, e.g. once via the normal pass and once via a duplicate-detection
  // edge case) — both must resolve to the SAME provenance object identity,
  // proving the second one was served from the in-scan memo rather than
  // re-walked.
  const fx = createGitFixture();
  try {
    fx.writeFile('a.js', 'eval(x);\n');
    fx.commit('add eval');

    const findings = [
      { file: 'a.js', line: 1, stableId: 'dup-stable-id', parser: 'SAST' },
      { file: 'a.js', line: 1, stableId: 'dup-stable-id', parser: 'SAST' },
    ];
    await annotateGitProvenance(findings, { scanRoot: fx.root, scanId: 's1', observedAt: new Date().toISOString() });
    assert.ok(findings[0].findingProvenance);
    assert.ok(findings[1].findingProvenance);
    // Digest equality alone is NOT proof of memoization: computeDigest is a
    // pure function of the resolved data, so two fully independent
    // resolutions over the same fixture would very likely produce the same
    // digest even if the memo were completely broken. Object IDENTITY is the
    // discriminating check — each independent resolution constructs a fresh
    // object via emptyProvenance(), and f.findingProvenance = prov assigns
    // the resolved value directly with no cloning, so strictEqual can only
    // hold if both findings' `.then()` callbacks received the SAME resolved
    // value from the SAME shared promise.
    assert.strictEqual(findings[0].findingProvenance, findings[1].findingProvenance);
    assert.equal(findings[0].findingProvenance.evidenceDigest, findings[1].findingProvenance.evidenceDigest);
  } finally {
    fx.cleanup();
  }
});

// Item 2 fix (M4 final-review): the cache key had no field reflecting a
// resolved cross-repo lineage link (`.agentic-security/repo-lineage.json`,
// M4 §4.2). Since a cross-repo `partial` result IS cacheable, an operator
// who scans once (no lineage declared, caches the honest same-repo
// `complete` root answer), then DECLARES a lineage link and re-scans at the
// SAME HEAD, must get the cross-repo answer — not the stale pre-lineage
// cached one. End-to-end through `annotateGitProvenance` (not just
// `makeCacheKey` directly), because this is exactly the coordinator-level
// bug the review found: the cache key it builds never changed even though
// the declaration on disk did.
test('annotateGitProvenance: declaring a repo-lineage link after an earlier scan at the same HEAD invalidates the stale cached pre-lineage result', async (t) => {
  const linked = createGitFixture();
  const fx = createGitFixture();
  t.after(() => { fx.cleanup(); linked.cleanup(); });

  linked.writeFile('shared.js', 'eval(x);\n');
  const linkedSha = linked.commit('the real original introduction, in the OLD repo');

  fx.writeFile('shared.js', 'eval(x);\n');
  const ownSha = fx.commit("imported wholesale as this repo's first commit");

  const scan = await runFullScan({ fileContents: { 'shared.js': 'eval(x);\n' }, scanRoot: fx.root }, () => {});
  const findingBeforeLineage = (scan.findings || []).find((f) => f.file === 'shared.js' && f.family === 'code-injection');
  assert.ok(findingBeforeLineage, 'expected the code-injection detector to fire on shared.js');
  assert.ok(findingBeforeLineage.stableId);

  // First scan: no lineage declared yet. Resolves via the ordinary same-repo
  // true-root path and gets CACHED (status:'complete' is cacheable).
  await annotateGitProvenance([findingBeforeLineage], {
    scanRoot: fx.root, scanId: 's1', observedAt: '2026-01-01T00:00:00Z', mode: 'standard',
  });
  assert.equal(findingBeforeLineage.findingProvenance.status, 'complete');
  assert.equal(findingBeforeLineage.findingProvenance.findingOrigin.commit, ownSha);

  // Now the operator declares the lineage link, at the SAME HEAD.
  fs.mkdirSync(path.join(fx.root, '.agentic-security'), { recursive: true });
  fs.writeFileSync(
    path.join(fx.root, '.agentic-security', 'repo-lineage.json'),
    JSON.stringify({ linkedFrom: { path: linked.root, atCommit: linkedSha } }),
  );

  // A second, independent finding object carrying the SAME stableId/file/
  // line/HEAD as the first — everything the pre-fix cache key was built
  // from is unchanged. Only the on-disk lineage declaration differs.
  const findingAfterLineage = { ...findingBeforeLineage, findingProvenance: undefined };
  await annotateGitProvenance([findingAfterLineage], {
    scanRoot: fx.root, scanId: 's2', observedAt: '2026-01-01T00:00:01Z', mode: 'standard',
  });

  // Must NOT be the stale cached pre-lineage 'complete' answer pointing at
  // ownSha — it must resolve the cross-repo lineage link.
  assert.equal(findingAfterLineage.findingProvenance.status, 'partial');
  assert.equal(findingAfterLineage.findingProvenance.historyCoverage.crossRepoLineage, true);
  assert.equal(findingAfterLineage.findingProvenance.findingOrigin.commit, linkedSha);
});

// ---------------------------------------------------------------------------
// PRD "Evidence integrity" audit — computeDigest previously omitted 4 of the
// 11 named inputs (repository identity, analysis HEAD, detector/ruleset
// version, history boundary), which theoretically permitted a digest
// collision across two different repos/HEADs/ruleset-versions sharing the
// same stableId/origin/branch/evidence tuple. These two tests pin the
// security property directly: identical inputs in every OTHER digest-bound
// field must still produce different digests when repo identity, HEAD,
// detector, or ruleset differ.
// ---------------------------------------------------------------------------

test('computeDigest: repository identity and analysis HEAD are now bound (PRD Evidence integrity)', async () => {
  // --- Repository identity ---------------------------------------------
  // A full (non-shallow) clone of the SAME repo, at a different absolute
  // path, shares every commit SHA with the original — same HEAD, same
  // origin/branch resolution, same evidence. Only `scanRoot` (this task's
  // best-effort repository-identity value, per the brief) differs. Before
  // this fix, `computeDigest` never looked at `scanRoot` at all, so these
  // two would have collided.
  const fx = createGitFixture();
  const clonePath = fs.mkdtempSync(path.join(os.tmpdir(), 'as-repoid-clone-'));
  try {
    fx.writeFile('a.js', 'eval(x);\n');
    fx.commit('add eval');

    fs.rmSync(clonePath, { recursive: true, force: true });
    execFileSync('git', ['clone', '-q', `file://${fx.root}`, clonePath], { stdio: 'ignore' });
    assert.equal(
      execFileSync('git', ['rev-parse', 'HEAD'], { cwd: clonePath, encoding: 'utf8' }).trim(),
      execFileSync('git', ['rev-parse', 'HEAD'], { cwd: fx.root, encoding: 'utf8' }).trim(),
      'clone must share the original HEAD or this proves nothing',
    );

    const findingOrig = { file: 'a.js', line: 1, stableId: 'repoid-shared-stable-id', parser: 'SAST' };
    const findingClone = { file: 'a.js', line: 1, stableId: 'repoid-shared-stable-id', parser: 'SAST' };
    await annotateGitProvenance([findingOrig], { scanRoot: fx.root, scanId: 's1', observedAt: '2026-01-01T00:00:00Z' });
    await annotateGitProvenance([findingClone], { scanRoot: clonePath, scanId: 's2', observedAt: '2026-01-01T00:00:00Z' });

    // Sanity: everything else the digest binds really did resolve identically.
    assert.equal(findingOrig.findingProvenance.status, findingClone.findingProvenance.status);
    assert.deepEqual(findingOrig.findingProvenance.findingOrigin, findingClone.findingProvenance.findingOrigin);
    assert.equal(findingOrig.findingProvenance.analysisBasis.head, findingClone.findingProvenance.analysisBasis.head);
    assert.deepEqual(findingOrig.findingProvenance.evidenceAttribution, findingClone.findingProvenance.evidenceAttribution);

    assert.notEqual(
      findingOrig.findingProvenance.evidenceDigest, findingClone.findingProvenance.evidenceDigest,
      'two different repositories at the same HEAD must not collide on the same evidence digest',
    );
  } finally {
    fx.cleanup();
    fs.rmSync(clonePath, { recursive: true, force: true });
  }

  // --- Analysis HEAD -----------------------------------------------------
  // The SAME repo, resolved twice: once at the commit that introduced the
  // finding, once after an unrelated second commit that does not touch the
  // finding's file/origin/branch/evidence. HEAD is the only digest-bound
  // field that moves between the two resolutions.
  const fx2 = createGitFixture();
  try {
    fx2.writeFile('a.js', 'eval(x);\n');
    fx2.commit('add eval');

    const findingAtHead1 = { file: 'a.js', line: 1, stableId: 'head-shared-stable-id', parser: 'SAST' };
    await annotateGitProvenance([findingAtHead1], { scanRoot: fx2.root, scanId: 's1', observedAt: '2026-01-01T00:00:00Z' });

    fx2.writeFile('unrelated.js', 'safe();\n');
    fx2.commit('unrelated change');

    const findingAtHead2 = { file: 'a.js', line: 1, stableId: 'head-shared-stable-id', parser: 'SAST' };
    await annotateGitProvenance([findingAtHead2], { scanRoot: fx2.root, scanId: 's2', observedAt: '2026-01-01T00:00:01Z' });

    // Sanity: the unrelated commit did not change anything else the digest binds.
    assert.equal(findingAtHead1.findingProvenance.status, findingAtHead2.findingProvenance.status);
    assert.deepEqual(findingAtHead1.findingProvenance.findingOrigin, findingAtHead2.findingProvenance.findingOrigin);
    assert.deepEqual(findingAtHead1.findingProvenance.evidenceAttribution, findingAtHead2.findingProvenance.evidenceAttribution);
    assert.notEqual(
      findingAtHead1.findingProvenance.analysisBasis.head, findingAtHead2.findingProvenance.analysisBasis.head,
      'sanity: HEAD really did move between the two resolutions',
    );

    assert.notEqual(
      findingAtHead1.findingProvenance.evidenceDigest, findingAtHead2.findingProvenance.evidenceDigest,
      'two different analysis HEADs for the same finding must not collide on the same evidence digest',
    );
  } finally {
    fx2.cleanup();
  }
});

test('computeDigest: detector/ruleset version changes the digest', async () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('a.js', 'eval(x);\n');
    fx.commit('add eval');

    // --- Ruleset version --------------------------------------------------
    // Same finding (same stableId), resolved under two different
    // `ctx.rulesetVersion` values. The coordinator's cache key already
    // includes `ctx.rulesetVersion` (as `detectorVersion`), so this is a
    // clean, single-variable comparison.
    const findingRulesetV1 = { file: 'a.js', line: 1, stableId: 'ruleset-shared-stable-id', parser: 'SAST' };
    const findingRulesetV2 = { file: 'a.js', line: 1, stableId: 'ruleset-shared-stable-id', parser: 'SAST' };
    await annotateGitProvenance([findingRulesetV1], {
      scanRoot: fx.root, scanId: 's1', observedAt: '2026-01-01T00:00:00Z', rulesetVersion: 'ruleset-v1',
    });
    await annotateGitProvenance([findingRulesetV2], {
      scanRoot: fx.root, scanId: 's2', observedAt: '2026-01-01T00:00:00Z', rulesetVersion: 'ruleset-v2',
    });

    assert.equal(findingRulesetV1.findingProvenance.analysisBasis.ruleset, 'ruleset-v1');
    assert.equal(findingRulesetV2.findingProvenance.analysisBasis.ruleset, 'ruleset-v2');
    assert.notEqual(
      findingRulesetV1.findingProvenance.evidenceDigest, findingRulesetV2.findingProvenance.evidenceDigest,
      'two different ruleset versions for the same finding must not collide on the same evidence digest',
    );

    // --- Detector ------------------------------------------------------
    // Two distinct findings whose only functional difference is which
    // detector produced them (`finding.parser`, carried into
    // `analysisBasis.detector`). Distinct stableIds are used deliberately:
    // the coordinator's cache key does not include `finding.parser`, so two
    // findings sharing one stableId would be served the SAME cached
    // resolution regardless of parser — which is also the realistic shape
    // of this scenario, since a different detector naturally produces a
    // different stableId in practice.
    const findingDetectorSast = { file: 'a.js', line: 1, stableId: 'detector-sast-stable-id', parser: 'SAST' };
    const findingDetectorIrTaint = { file: 'a.js', line: 1, stableId: 'detector-ir-taint-stable-id', parser: 'IR-TAINT' };
    await annotateGitProvenance([findingDetectorSast], { scanRoot: fx.root, scanId: 's3', observedAt: '2026-01-01T00:00:00Z' });
    await annotateGitProvenance([findingDetectorIrTaint], { scanRoot: fx.root, scanId: 's4', observedAt: '2026-01-01T00:00:00Z' });

    assert.equal(findingDetectorSast.findingProvenance.analysisBasis.detector, 'SAST');
    assert.equal(findingDetectorIrTaint.findingProvenance.analysisBasis.detector, 'IR-TAINT');
    assert.notEqual(
      findingDetectorSast.findingProvenance.evidenceDigest, findingDetectorIrTaint.findingProvenance.evidenceDigest,
      'two different detectors must not collide on the same evidence digest',
    );
  } finally {
    fx.cleanup();
  }
});

// Second-audit remediation, Task 2 (FR-PROV-028 / "Evidence integrity"):
// engine.js used to build `provenanceCtx.rulesetVersion` from
// `process.env.AGENTIC_SECURITY_RULESET_VERSION || null` — an env var
// essentially never set in practice, so the cache key's `detectorVersion`
// slot and `computeDigest`'s `rulesetVersion` binding were always `null`
// and upgrading the scanner (or pinning a different ruleset) never
// invalidated cached provenance. The above two tests already prove the
// COORDINATOR honours a distinct `ctx.rulesetVersion` when handed one
// directly; this test proves the ENGINE actually threads the REAL
// effective ruleset version (posture/ruleset-version.js's
// `effectiveVersion`, via `_effectiveRulesetVersion` in engine.js) into
// that ctx field through a real `runFullScan`, end to end — the same
// "declare something on disk, rescan at the same HEAD, must not serve the
// stale cache entry" shape as the repo-lineage test just above.
test('runFullScan: rulesetVersion is the real effective version, and pinning a different one invalidates cached provenance at the same HEAD', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());

  fx.writeFile('a.js', 'eval(x);\n');
  fx.commit('add eval');

  const src = { 'a.js': 'eval(x);\n' };

  const scan1 = await runFullScan({ fileContents: src, scanRoot: fx.root }, () => {});
  const finding1 = (scan1.findings || []).find((f) => f.file === 'a.js' && f.family === 'code-injection');
  assert.ok(finding1, 'expected the code-injection detector to fire on a.js');
  const fp1 = finding1.findingProvenance;
  assert.ok(fp1, 'finding missing findingProvenance entirely');

  // Not null, and not derived from the never-set env var: it's the real
  // running scanner's ruleset version by default.
  assert.equal(fp1.analysisBasis.ruleset, CURRENT_RULESET_VERSION);
  assert.notEqual(fp1.analysisBasis.ruleset, null);

  // Operator pins a DIFFERENT ruleset version, at the SAME HEAD — no new
  // commit, so a cache keyed only on (HEAD, stableId, ...) would wrongly
  // keep serving the run-1 answer.
  fs.mkdirSync(path.join(fx.root, '.agentic-security'), { recursive: true });
  fs.writeFileSync(
    path.join(fx.root, '.agentic-security', 'ruleset-version.json'),
    JSON.stringify({ version: 'pinned-test-ruleset-v2', pinned: true }),
  );

  const scan2 = await runFullScan({ fileContents: src, scanRoot: fx.root }, () => {});
  const finding2 = (scan2.findings || []).find((f) => f.file === 'a.js' && f.family === 'code-injection');
  assert.ok(finding2, 'expected the code-injection detector to fire on a.js again');
  const fp2 = finding2.findingProvenance;
  assert.ok(fp2, 'finding missing findingProvenance entirely');

  assert.equal(fp2.analysisBasis.ruleset, 'pinned-test-ruleset-v2');
  assert.notEqual(
    fp1.analysisBasis.ruleset, fp2.analysisBasis.ruleset,
    'pinning a different ruleset version must change analysisBasis.ruleset',
  );
  assert.notEqual(
    fp1.evidenceDigest, fp2.evidenceDigest,
    'a ruleset-version change at the same HEAD must not collide on the same evidence digest (cache must not serve the stale entry)',
  );
});
