// Task 11 (Finding Provenance PRD completion plan, PRD P0 scope): real origin
// resolution for scan.secrets and blameable scan.logicVulns findings. Both
// channels were previously stamped an unconditional not_available with a
// "deferred to a later phase" limitation — the PRD's own Release Scope table
// names secrets as explicit P0 scope, so that deferral was a real gap, not a
// design choice.
//
// These tests drive the wiring end-to-end through a REAL scan (runScan), the
// same way test/posture/provenance-missing-control-wiring.test.js proves
// FR-PROV-017 — every other provenance test in this directory drives the
// coordinator/resolver directly with hand-built findings, but this wiring's
// correctness hinges on two things a hand-built finding can't exercise:
//
//   1. computeStableId's ruleId() fallback chain, and the fact that a real
//      scan.secrets finding sets NEITHER ruleId NOR family NOR parser, so
//      without the per-pattern ruleId backfill this task adds, every secret
//      type in a file collides onto the SAME stableId (they all share the
//      same fixed f.cwe, "CWE-798").
//   2. predicate-replay.js's replayAt() recomputing computeStableId() itself
//      on a RECURSIVE, nested runFullScan call — which only reproduces the
//      SAME stableId as the live scan if that nested call's own
//      scan.secrets/scan.logicVulns get the identical ruleId backfill. This
//      is why the backfill in engine.js runs unconditionally, outside the
//      `skipAnnotators` guard the nested call sets — see that comment for
//      the empirical trap this test suite would otherwise silently pass
//      despite the bug (every finding permanently landing on
//      status:'partial', reason:'predicate-never-confirmed-in-candidates',
//      which looks superficially like "provenance ran" but never actually
//      confirms an origin).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createGitFixture } from '../helpers/build-git-fixture.js';
import { runScan } from '../../src/runScan.js';
import { _runExclusive } from '../../src/posture/provenance/predicate-replay.js';
import { evaluateLicensePolicy } from '../../src/posture/license-policy.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SRC_DIR = path.resolve(__dirname, '..', '..', 'src');

test('secrets provenance: a real hardcoded AWS key resolves to its introducing commit', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());

  fx.writeFile('config.js', 'const awsAccessKey = "AKIAABCDEFGHIJKLMNOP";\n');
  const sha = fx.commit('add aws key', { date: '2026-01-01T00:00:00Z' });

  const { scan } = await runScan(fx.root, { network: false });
  const finding = (scan.secrets || []).find((s) => s.vuln === 'AWS Access Key ID');
  assert.ok(finding, `expected an AWS Access Key ID secret; got ${JSON.stringify((scan.secrets || []).map((s) => s.vuln))}`);
  assert.ok(finding.ruleId, 'expected a backfilled ruleId on the secret');
  assert.ok(finding.stableId, 'expected a computed stableId on the secret');

  const fp = finding.findingProvenance;
  assert.ok(fp, 'finding missing findingProvenance entirely');
  assert.equal(fp.status, 'complete', `expected status complete; got ${fp.status} (${JSON.stringify(fp.limitations)})`);
  assert.ok(fp.findingOrigin, 'expected a populated findingOrigin');
  assert.equal(fp.findingOrigin.commit, sha);
});

test('secrets provenance: two different secret types in the same file get DIFFERENT stableIds, not collided', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());

  const jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
    + '.eyJzdWIiOiI5OTk5IiwibmFtZSI6IkZpeHR1cmUgVGVzdCBVc2VyIiwicm9sZSI6ImFkbWluIn0'
    + '.sigABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  fx.writeFile(
    'config.js',
    `const awsAccessKey = "AKIAABCDEFGHIJKLMNOP";\nconst apiToken = "${jwt}";\n`,
  );
  fx.commit('add creds', { date: '2026-01-01T00:00:00Z' });

  const { scan } = await runScan(fx.root, { network: false });
  const aws = (scan.secrets || []).find((s) => s.vuln === 'AWS Access Key ID');
  const jwtFinding = (scan.secrets || []).find((s) => s.vuln === 'Exposed JWT Token');
  assert.ok(aws, 'expected an AWS Access Key ID secret');
  assert.ok(jwtFinding, 'expected an Exposed JWT Token secret');
  assert.notEqual(aws.ruleId, jwtFinding.ruleId, 'different secret patterns must get different backfilled ruleIds');
  assert.notEqual(aws.stableId, jwtFinding.stableId, 'different secret patterns must NOT collide onto the same stableId');
});

test('logicVulns provenance: a real blameable logic finding resolves to its introducing commit', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());

  fx.writeFile(
    'auth.js',
    "function login(req, res) {\n  // TODO: verify jwt token before granting session\n  res.send('ok');\n}\nmodule.exports = login;\n",
  );
  const sha = fx.commit('add login stub with a security TODO', { date: '2026-01-01T00:00:00Z' });

  const { scan } = await runScan(fx.root, { network: false });
  const finding = (scan.logicVulns || []).find((f) => f.vuln === 'Known-Broken Code Marker Near Security-Sensitive Logic');
  assert.ok(finding, `expected a scanTodosNearSecurity finding; got ${JSON.stringify((scan.logicVulns || []).map((f) => f.vuln))}`);
  assert.ok(finding.ruleId, 'expected a backfilled ruleId on the logic finding');
  assert.ok(finding.stableId, 'expected a computed stableId on the logic finding');

  const fp = finding.findingProvenance;
  assert.ok(fp, 'finding missing findingProvenance entirely');
  assert.equal(fp.status, 'complete', `expected status complete; got ${fp.status} (${JSON.stringify(fp.limitations)})`);
  assert.ok(fp.findingOrigin, 'expected a populated findingOrigin');
  assert.equal(fp.findingOrigin.commit, sha);
});

test('logicVulns provenance: license-policy/stack-playbook findings stay honestly not_available, never get a fabricated commit attribution', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());

  // stack-playbook: an express dependency triggers the Express security
  // checklist, whose entries carry a FIXED placeholder line (package.json:1)
  // — not a real diffable source location for the checklist item itself.
  fx.writeFile('package.json', JSON.stringify({ name: 'x', version: '1.0.0', dependencies: { express: '^4.18.0' } }, null, 2) + '\n');
  fx.writeFile('index.js', "module.exports = () => 1;\n");
  fx.commit('add package.json declaring express', { date: '2026-01-01T00:00:00Z' });

  const { scan } = await runScan(fx.root, { network: false });
  const synthetic = (scan.logicVulns || []).filter((f) => typeof f.id === 'string' && f.id.startsWith('stack-playbook:'));
  assert.ok(synthetic.length > 0, `expected at least one stack-playbook finding; got ${JSON.stringify((scan.logicVulns || []).map((f) => f.id))}`);

  for (const f of synthetic) {
    const fp = f.findingProvenance;
    assert.ok(fp, 'synthetic finding missing findingProvenance entirely');
    assert.equal(fp.status, 'not_available', `synthetic finding must stay not_available; got ${fp.status}`);
    assert.equal(fp.findingOrigin, null, 'synthetic finding must NEVER get a fabricated commit attribution');
    assert.ok(
      fp.limitations.some((l) => /origin resolution does not apply/.test(l)),
      `expected the permanent, principled limitation string; got ${JSON.stringify(fp.limitations)}`,
    );
  }
});

// ─── Reviewer follow-up (Task 11 review): dedicated regression pins for the
// _runExclusive reentrancy/concurrency fix ──────────────────────────────────
//
// The tests above happen to exercise real replay resolution, but none of them
// PROVE the `_runExclusive` queue in predicate-replay.js is load-bearing —
// nothing here would fail if that queue were deleted or replaced with a
// no-op passthrough. Two tests below close that gap:
//
//   1. A direct, deterministic unit test of `_runExclusive` itself, using a
//      shared-state shape that mirrors engine.js's real
//      snapshot/reset-during-nested-call/restore hazard on `_suppressionLog`
//      in miniature. It proves BOTH directions: the SAME racy operations
//      corrupt shared state when run unserialized (so the harness is known
//      to actually exercise the race, not just assert a tautology), and
//      `_runExclusive` prevents that corruption.
//   2. An integration-level pin using an ISOLATED tmpdir git fixture (not
//      this repo's own history, unlike the incidental FP-5 smoke-test
//      coverage this was originally caught by) that forces real concurrent
//      `replayAt` calls — 5 real secrets exceed coordinator.js's
//      MAX_CONCURRENCY of 4 — alongside real suppression-log content, and
//      asserts the suppression log survives intact. Verified empirically
//      before writing this comment: with `_runExclusive`'s body temporarily
//      replaced with a direct `fn()` call (bypassing serialization), this
//      exact fixture reproducibly lost both suppression entries (0/2) across
//      5 consecutive runs; restoring the real queue reproducibly kept both
//      (2/2) across 5 consecutive runs. This test is a genuine regression
//      pin, not an incidental pass-through.

test('_runExclusive serializes concurrent critical sections (regression pin for the Task 11 reentrancy fix)', async () => {
  // Mirrors engine.js's real _snapshotSuppressionLog / _resetSuppressions
  // (called inside the nested runFullScan) / _restoreSuppressionLog shape:
  // snapshot the shared log, reset it, do async work that writes to it (the
  // nested scan's own detection work), then restore the snapshot. This is
  // exactly the shape that corrupted the real `_suppressionLog` when two
  // `replayAt` calls interleaved — see the header comment above
  // `_runExclusive` in predicate-replay.js for the traced mechanism.
  const shared = { log: [] };
  const snapshot = () => shared.log.slice();
  const reset = () => { shared.log.length = 0; };
  const restore = (saved) => { shared.log.length = 0; shared.log.push(...saved); };

  async function racySection(id) {
    const saved = snapshot();
    reset();
    await new Promise((r) => setTimeout(r, 5));
    shared.log.push(`nested-${id}`);
    await new Promise((r) => setTimeout(r, 5));
    restore(saved);
    return id;
  }

  // Sanity leg FIRST: run the identical racy operations directly, with NO
  // serialization, and confirm the race actually corrupts the shared log on
  // THIS harness/runtime. If this assertion ever fails, the test below is
  // not proving anything (the "fix" would trivially "work" against a race
  // that never manifests), so it must be checked, not assumed.
  shared.log = ['seed-a', 'seed-b'];
  await Promise.all([1, 2, 3, 4].map((id) => racySection(id)));
  assert.notDeepEqual(
    shared.log,
    ['seed-a', 'seed-b'],
    'the unserialized race did not corrupt the shared log on this run -- the harness is not exercising the hazard, so the serialized assertion below cannot be trusted without this one holding',
  );

  // The real assertion: routed through _runExclusive, the same 4 concurrent
  // critical sections must NOT corrupt the shared log -- each one runs to
  // completion (snapshot -> reset -> async writes -> restore) before the
  // next begins, so every restore always sees the previous call's correct,
  // fully-restored state.
  shared.log = ['seed-a', 'seed-b'];
  await Promise.all([1, 2, 3, 4].map((id) => _runExclusive(() => racySection(id))));
  assert.deepEqual(
    shared.log,
    ['seed-a', 'seed-b'],
    '_runExclusive must serialize the critical section so concurrent callers never corrupt the shared log',
  );
});

test('secrets provenance under real concurrency: an isolated tmpdir fixture with 5 concurrently-resolved secrets never corrupts scan.suppressions', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());

  // Real, suppressible entropy-candidate content (JWT-doc-example shape,
  // same mechanism as test/fixtures/entropy-fp, but built fresh in an
  // isolated tmpdir here — this test's git history is NOT this repo's, so
  // its coverage of the reentrancy fix does not depend on where
  // test/fixtures/entropy-fp happens to live in-tree).
  fx.writeFile(
    'jwt-doc.js',
    [
      '// Sample/example JWT tokens — doc context, should NOT trigger entropy detection.',
      'const exampleAuthToken = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.E_fooBARbazQUUXqwertyuiopASDF1234";',
      'const sampleApiTokenSecret = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxLCJleHAiOjF9.dGhpcw";',
      '',
    ].join('\n'),
  );
  // 4 more real, resolvable secrets in separate files -- combined with the
  // real JWT secret above, this scan's aSecrets array has 5 entries. That
  // exceeds coordinator.js's MAX_CONCURRENCY (4), guaranteeing at least two
  // of these findings' resolveOrigin walks (and their replayAt calls) are
  // genuinely in flight at once, not just theoretically capable of it.
  for (let i = 0; i < 4; i++) {
    fx.writeFile(`svc${i}.js`, `const awsAccessKey${i} = "AKIAABCDEFGHIJKLMNOP";\n`);
  }
  fx.commit('add secrets and doc examples', { date: '2026-01-01T00:00:00Z' });

  const { scan } = await runScan(fx.root, { network: false });

  assert.ok((scan.secrets || []).length >= 5, `expected >=5 secrets to force concurrent resolution; got ${(scan.secrets || []).length}`);
  for (const s of scan.secrets || []) {
    assert.ok(s.findingProvenance, `secret in ${s.file} missing findingProvenance entirely`);
  }

  const entropySuppressions = (scan.suppressions || []).filter((s) => /Entropy/i.test(s.vuln));
  assert.equal(
    entropySuppressions.length,
    2,
    `expected exactly 2 entropy suppressions to survive concurrent replay resolution intact; got ${entropySuppressions.length}: ${JSON.stringify(scan.suppressions)}`,
  );
});

// ─── Reviewer follow-up (Task 11 review): pin SYNTHETIC_LOGIC_PREFIXES to
// what its 3 producer modules actually emit ────────────────────────────────
//
// `SYNTHETIC_LOGIC_PREFIXES` in engine.js (['license-policy:',
// 'deploy-platform:', 'stack-playbook:']) is a hand-duplicated copy of each
// producer's own id-prefix convention, with nothing tying the two together.
// If any producer's id format ever changes, its findings silently stop being
// classified as synthetic and start getting REAL git-blame origin
// resolution -- a fabricated commit attribution for dependency/config/policy
// state, precisely what Task 11 exists to prevent. Only `stack-playbook:`
// had real end-to-end coverage above (via a real `express` dependency);
// `deploy-platform:` is exercised indirectly through the source-text pin
// below only (its findings never survive into scan.logicVulns at all --
// see the "Concerns" section of the Task 11 report: deploy-platform.js sets
// `title` not `vuln`, and engine.js's `_shouldKeep` filter drops any
// non-SCA finding with no `vuln` string, unrelated to this task).
// `license-policy:` could not be driven through a REAL scan either (traced
// independently, confirming the reviewer's own finding): `evaluateLicensePolicy`
// needs `annotatedComponents` with a populated `.license` field, which in a
// real scan is populated ONLY via `queryRegistries`'s network call in
// engine.js -- not reachable offline/deterministically in this suite. Two
// tests below close the gap without a network dependency:
//
//   1. A direct producer test -- `evaluateLicensePolicy` (imported, not
//      re-typed) is fed a hand-built denied-license component and asserted
//      to emit an id with the literal `license-policy:` prefix. This is the
//      real function, not a source-text guess.
//   2. A source-text tripwire covering all 3 producers (including
//      deploy-platform:, which test 1's approach can't reach any more
//      directly than a real scan can) -- each module's source must still
//      contain its expected id prefix attached to an `id:` field. Cheap,
//      deterministic, and fails loudly if any producer's id format drifts
//      out of sync with engine.js's SYNTHETIC_LOGIC_PREFIXES list.

test('license-policy: producer emits ids with the exact prefix SYNTHETIC_LOGIC_PREFIXES expects (direct producer test, no network)', () => {
  const policy = { allow: [], deny: ['GPL-3.0'], review: [], unknown: 'allow' };
  const components = [
    { name: 'copyleft-pkg', version: '1.0.0', ecosystem: 'npm', license: 'GPL-3.0', filePath: 'package.json' },
  ];
  const findings = evaluateLicensePolicy(components, policy);
  assert.ok(findings.length > 0, 'expected at least one license-policy finding for a denied license');
  for (const f of findings) {
    assert.ok(
      typeof f.id === 'string' && f.id.startsWith('license-policy:'),
      `expected id to start with 'license-policy:' (matching engine.js's SYNTHETIC_LOGIC_PREFIXES); got ${JSON.stringify(f.id)}`,
    );
  }
});

test('SYNTHETIC_LOGIC_PREFIXES stays tied to what all 3 producer modules actually emit (source-text tripwire)', () => {
  const producers = [
    { prefix: 'license-policy:', file: path.join(SRC_DIR, 'posture', 'license-policy.js') },
    { prefix: 'deploy-platform:', file: path.join(SRC_DIR, 'posture', 'deploy-platform.js') },
    { prefix: 'stack-playbook:', file: path.join(SRC_DIR, 'posture', 'stack-playbook.js') },
  ];
  for (const { prefix, file } of producers) {
    const src = fs.readFileSync(file, 'utf8');
    const idLines = src.split('\n').filter((l) => /\bid:\s*[`'"]/.test(l));
    assert.ok(idLines.length > 0, `expected at least one 'id:' field in ${file}`);
    assert.ok(
      idLines.some((l) => l.includes(prefix)),
      `expected an 'id:' field in ${file} to start with the literal prefix ${JSON.stringify(prefix)} -- if this fails, engine.js's SYNTHETIC_LOGIC_PREFIXES is out of sync with this producer's real id format, meaning its findings will silently stop being classified as synthetic and start getting a FABRICATED git-blame origin. Update SYNTHETIC_LOGIC_PREFIXES in engine.js to match the new prefix.`,
    );
  }
});
