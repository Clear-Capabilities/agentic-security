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
import { createGitFixture } from '../helpers/build-git-fixture.js';
import { runScan } from '../../src/runScan.js';

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
