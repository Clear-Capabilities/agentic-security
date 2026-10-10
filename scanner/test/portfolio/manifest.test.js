// X-701: release assurance manifest. SYNTHETIC fixtures only; no real release is described.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { buildManifest, validateManifest, manifestId, deriveCoverage } from '../../src/posture/portfolio/manifest.js';
import { manifestFacts, syntheticManifest, sha, COMMIT, DEP_COMMIT } from './helpers.js';

const codes = (r) => r.errors.map((e) => `${e.code}@${e.path}`);
const clone = (x) => JSON.parse(JSON.stringify(x));
// re-seal after a deliberate edit so the id check does not mask the rule under test
const reseal = (m) => { m.coverage = deriveCoverage(m.checks, m.scope); m.complete = m.coverage.complete; m.id = manifestId(m); return m; };

describe('[X-701.AC01] the manifest binds revisions, build digests, scope, graph, invariant versions and receipts', () => {
  test('[X-701.AC01] a synthetic manifest validates and carries every bound identity', () => {
    const m = syntheticManifest();
    const r = validateManifest(m);
    assert.deepEqual(r.errors, []);
    assert.equal(m.synthetic, true);
    assert.equal(m.subject.commit, COMMIT);
    assert.deepEqual(m.dependencies, [{ name: 'lib', revision: DEP_COMMIT }]);
    assert.equal(m.artifacts.length, 1);
    assert.match(m.graphSnapshot.digest, /^sha256:/);
    assert.equal(m.invariantVersions[0].version, '3');
    assert.equal(m.verificationReceipts.length, 2);
    assert.match(m.id, /^ram:[0-9a-f]{16}$/);
  });

  test('[X-701.AC01] the id covers the bound identities: changing a build artifact digest or a dependency revision changes it', () => {
    const base = syntheticManifest();
    const art = syntheticManifest({ artifacts: [{ name: 'app.tgz', digest: sha('other') }] });
    const dep = syntheticManifest({ dependencies: [{ name: 'lib', revision: 'c'.repeat(40) }] });
    assert.notEqual(art.id, base.id);
    assert.notEqual(dep.id, base.id);
  });

  test('[X-701.AC01] negative: an unpinned subject commit, a missing artifact digest and a malformed graph digest are each rejected', () => {
    const f = manifestFacts();
    f.subject = { ...f.subject, commit: 'main' };
    assert.ok(codes(validateManifest(buildManifest(f))).some((c) => c.includes('subject.commit')));
    assert.ok(codes(validateManifest(buildManifest(manifestFacts({ artifacts: [] })))).includes('RULE_VIOLATION@artifacts'));
    assert.ok(codes(validateManifest(buildManifest(manifestFacts({ graphSnapshot: { digest: 'abc' } })))).some((c) => c.startsWith('BAD_DIGEST@graphSnapshot')));
  });
});

describe('[X-701.AC02] completed, incomplete, unsupported and waived checks are enumerated, with the exact blocking policy', () => {
  test('[X-701.AC02] all four groups are carried, partition the mandatory scope, and the policy digest equals the subject policy digest', () => {
    const f = manifestFacts();
    f.scope = { description: 'four-way', mandatory: ['a', 'b', 'c', 'd'] };
    f.checks = {
      completed: [{ id: 'a', statement: 'a', evidenceRefs: ['vrec:0001'] }],
      incomplete: [{ id: 'b', statement: 'b', evidenceRefs: [], gaps: ['timed out'] }],
      unsupported: [{ id: 'c', statement: 'c', evidenceRefs: [], gaps: ['language not supported'] }],
      waived: [{ id: 'd', statement: 'd', evidenceRefs: [], reason: 'accepted by owner', approvedBy: 'owner@example.test' }],
    };
    const m = buildManifest(f);
    assert.deepEqual(validateManifest(m).errors, []);
    assert.deepEqual([m.coverage.completed, m.coverage.incomplete, m.coverage.unsupported, m.coverage.waived], [1, 1, 1, 1]);
    assert.equal(m.complete, false);
    assert.equal(m.policy.digest, m.subject.policyDigest);
  });

  test('[X-701.AC02] negative: an incomplete check with no stated gap, a waiver with no approver, and a policy digest that is not the subject policy are rejected', () => {
    const noGap = reseal(clone(syntheticManifest())); noGap.checks.incomplete[0].gaps = [];
    assert.ok(codes(validateManifest(reseal(noGap))).includes('RULE_VIOLATION@checks.incomplete[0].gaps'));
    const f = manifestFacts();
    f.scope = { description: 's', mandatory: ['a'] };
    f.checks = { completed: [], incomplete: [], unsupported: [], waived: [{ id: 'a', statement: 'a', evidenceRefs: [], reason: 'r' }] };
    assert.ok(codes(validateManifest(buildManifest(f))).some((c) => c.includes('approvedBy')));
    const wrong = syntheticManifest({ policy: { id: 'policy-v1', digest: sha('different-policy'), blockingSeverity: 'high' } });
    assert.ok(codes(validateManifest(wrong)).includes('RULE_VIOLATION@policy.digest'));
  });

  test('[X-701.AC02] a manifest cannot claim complete while a check is incomplete', () => {
    const m = clone(syntheticManifest());
    m.complete = true;
    m.id = manifestId(m);
    assert.ok(codes(validateManifest(m)).includes('RULE_VIOLATION@complete'));
  });
});

describe('[X-701.AC03] validation rejects unbound evidence, mismatched commits and omitted mandatory scope, and keeps residual risk and coverage', () => {
  test('[X-701.AC03] unbound evidence: a completed check citing a receipt that is not declared is rejected', () => {
    const f = manifestFacts();
    f.checks.completed[0] = { id: 'sast', statement: 's', evidenceRefs: ['vrec:ghost'] };
    assert.ok(codes(validateManifest(buildManifest(f))).includes('DANGLING_REF@checks.completed[0].evidenceRefs[0]'));
  });

  test('[X-701.AC03] mismatched commits: a receipt about the subject at another commit, and one about an undeclared repository, are rejected', () => {
    const f = manifestFacts();
    f.verificationReceipts[0] = { ...f.verificationReceipts[0], commit: 'c'.repeat(40) };
    const r = validateManifest(buildManifest(f));
    assert.ok(r.errors.some((e) => e.code === 'RULE_VIOLATION' && /commit mismatch/.test(e.message)));
    const g = manifestFacts();
    g.verificationReceipts[1] = { ...g.verificationReceipts[1], repository: 'stranger' };
    assert.ok(codes(validateManifest(buildManifest(g))).includes('DANGLING_REF@verificationReceipts[1].repository'));
  });

  test('[X-701.AC03] omitted mandatory scope: a mandatory check listed nowhere is rejected, and the clean manifest is not', () => {
    const f = manifestFacts();
    f.checks.incomplete = []; // 'replay' is mandatory and now appears nowhere
    const r = validateManifest(buildManifest(f));
    assert.ok(r.errors.some((e) => /omitted mandatory scope: 'replay'/.test(e.message)));
    assert.deepEqual(validateManifest(syntheticManifest()).errors, []);
  });

  test('[X-701.AC03] residual risk and coverage survive as machine-readable fields, and a coverage block that disagrees with the lists is rejected', () => {
    const m = syntheticManifest();
    assert.deepEqual(m.coverage, { mandatory: 3, completed: 2, incomplete: 1, unsupported: 0, waived: 0, complete: false });
    assert.equal(m.residualRisks[0].id, 'rr-1');
    const forged = clone(m); forged.coverage = { ...forged.coverage, incomplete: 0, completed: 3, complete: true };
    forged.id = manifestId(forged);
    assert.ok(codes(validateManifest(forged)).includes('RULE_VIOLATION@coverage'));
  });

  test('[X-701.AC03] closed world and bounds: an unknown field and an oversized check list are rejected without throwing', () => {
    const m = clone(syntheticManifest()); m.verdict = 'safe';
    assert.ok(codes(validateManifest(m)).includes('UNKNOWN_FIELD@verdict'));
    assert.equal(validateManifest(null).ok, false);
    const big = manifestFacts();
    big.verificationReceipts = Array.from({ length: 2049 }, (_, i) => ({ id: `r${i}`, digest: sha(String(i)), repository: 'app', commit: COMMIT }));
    assert.ok(validateManifest(buildManifest(big)).errors.some((e) => /the limit is 2048/.test(e.message)));
  });
});
