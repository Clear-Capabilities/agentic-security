import { test } from 'node:test';
import assert from 'node:assert/strict';
import { resolveTransitiveSCAOrigin } from '../../src/posture/provenance/transitive-sca.js';
import { annotateGitProvenance } from '../../src/posture/provenance/coordinator.js';
import { createGitFixture } from '../helpers/build-git-fixture.js';

function lockfile(depsWithVersions) {
  // Minimal v2/v3-shaped package-lock.json: top-level "" entry (the root
  // package) plus one entry per dependency at a NESTED path to simulate a
  // transitive dependency (not a direct one, which would live at
  // "node_modules/<name>" with no further nesting under a direct parent).
  const packages = { '': { name: 'root', version: '1.0.0' } };
  for (const [pathSuffix, version] of Object.entries(depsWithVersions)) {
    packages[`node_modules/${pathSuffix}`] = { version };
  }
  return JSON.stringify({ name: 'root', lockfileVersion: 3, packages }, null, 2);
}

test('resolveTransitiveSCAOrigin: resolves the commit that moved a transitive dep into the vulnerable range', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  // NOTE on this fixture's version choice: `versionInRange` (reused verbatim
  // from sca-origin.js, not reimplemented here) treats a `fixed`-only range
  // (no `introduced` lower bound) as "anything below fixed is vulnerable" —
  // exactly the same documented ambiguity resolveDirectSCAOrigin's own tests
  // pin (see provenance-sca-origin.test.js's "CRITICAL regression" case). A
  // scenario that goes from a genuinely LOWER version to a HIGHER one that is
  // still below `fixed` can therefore never be told apart from "vulnerable
  // since inception, unrelated bump" — both parent and child score "in
  // range" and the result is `ambiguousBump`, by design. To exercise a
  // CONFIRMED transition (parent verifiably out of range, so
  // parentBoundaryVerified:true is honest) this fixture mirrors
  // resolveDirectSCAOrigin's own "confirmed transition" test: the parent
  // commit sits ON the fixed version (out of range) and the child commit
  // drops back below it (in range) — a real re-pin, not an ordinary bump.
  fx.writeFile('package-lock.json', lockfile({ 'express/node_modules/qs': '6.5.4' }));
  fx.commit('qs pinned at its fixed version');
  fx.writeFile('package-lock.json', lockfile({ 'express/node_modules/qs': '6.5.3' }));
  const reintroduceSha = fx.commit('re-pin qs back to the vulnerable version');

  const scaEntry = { name: 'qs', filePath: 'package-lock.json', fixedVersions: ['6.5.4'] };
  const result = await resolveTransitiveSCAOrigin(fx.root, scaEntry, {});
  assert.equal(result.status, 'complete');
  assert.equal(result.findingOrigin.commit, reintroduceSha);
  assert.equal(result.parentBoundaryVerified, true);
  assert.deepEqual(result.depChain, ['express', 'qs']);
});

test('resolveTransitiveSCAOrigin: an unsupported lockfile format resolves not_available with an explicit reason, never a guess', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('yarn.lock', 'qs@6.5.3:\n  version "6.5.3"\n');
  fx.commit('yarn lockfile');
  const scaEntry = { name: 'qs', filePath: 'yarn.lock', fixedVersions: ['6.5.3'] };
  const result = await resolveTransitiveSCAOrigin(fx.root, scaEntry, {});
  assert.equal(result.status, 'not_available');
  assert.equal(result.reason, 'unsupported-lockfile-format');
});

test('resolveTransitiveSCAOrigin: the root-commit fallback never fabricates a verified parent boundary', async (t) => {
  // Final whole-branch review item #2: originResult() used to hardcode
  // parentBoundaryVerified:true / absentInParents:[] for EVERY caller,
  // including the root-commit fallback below, where there is no parent to
  // have verified anything about. That produced status:'complete' with
  // confidence HIGH/0.95 for an origin that verified nothing — exactly the
  // false certainty this whole feature exists to prevent. This fixture has a
  // single commit: the vulnerable transitive version is present from the
  // repository's FIRST commit, so getFirstParent(scanRoot, sha) returns null
  // and the root-fallback branch is the only branch that can fire.
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('package-lock.json', lockfile({ 'express/node_modules/qs': '6.5.3' }));
  const rootSha = fx.commit('initial commit already carries the vulnerable transitive version');

  const scaEntry = { name: 'qs', filePath: 'package-lock.json', fixedVersions: ['6.5.4'] };
  const result = await resolveTransitiveSCAOrigin(fx.root, scaEntry, {});
  assert.equal(result.status, 'complete');
  assert.equal(result.findingOrigin.commit, rootSha);
  // The load-bearing facts: no parent existed to verify absence against.
  assert.equal(result.parentBoundaryVerified, false);
  assert.deepEqual(result.findingOrigin.absentInParents, []);

  // And the confidence this feeds downstream (via the coordinator, exactly
  // as a real scan would compute it) must NOT read as HIGH/0.95 off a
  // fabricated verified boundary.
  const entry = { name: 'qs', filePath: 'package-lock.json', fixedVersions: ['6.5.4'], isDirect: false };
  await annotateGitProvenance([entry], {
    scanRoot: fx.root, scanId: 's1', observedAt: new Date().toISOString(), findingType: 'sca-transitive',
  });
  const fp = entry.findingProvenance;
  assert.equal(fp.status, 'complete');
  assert.notEqual(fp.confidence.level, 'high');
  assert.notEqual(fp.confidence.score, 0.95);
});

test('resolveTransitiveSCAOrigin: with two nested copies of the same package, the finding\'s own depChain picks the RIGHT one, not the shortest-path guess', async (t) => {
  // Final whole-branch review item #7. extractTransitiveVersion's
  // shortest-path heuristic picks the copy closest to a direct dependency
  // when a lockfile has multiple nested copies of the same package name at
  // different depths — fine when the finding IS about that shallow copy,
  // wrong when it isn't. Here the vulnerable transition happens in the
  // DEEPER copy (body-parser/deep/qs) while the shallower copy
  // (express/qs) sits unchanged, exactly AT the fixed version (so it is
  // never itself "in range"). Without depChain guidance the shortest-path
  // heuristic always resolves to express/qs, sees it out of range at every
  // candidate commit, and never even looks at the copy the finding is
  // actually about — silently missing a real, resolvable transition.
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('package-lock.json', lockfile({
    'express/node_modules/qs': '6.5.4',
    'body-parser/node_modules/deep/node_modules/qs': '6.5.4',
  }));
  const parentSha = fx.commit('both copies safe');
  fx.writeFile('package-lock.json', lockfile({
    'express/node_modules/qs': '6.5.4', // unchanged, still out of range
    'body-parser/node_modules/deep/node_modules/qs': '6.5.3', // re-pinned into the vulnerable range
  }));
  const introducedSha = fx.commit('deep copy of qs re-pinned to the vulnerable version');

  const scaEntry = {
    name: 'qs', filePath: 'package-lock.json', fixedVersions: ['6.5.4'],
    depChain: ['body-parser', 'deep', 'qs'],
  };
  const result = await resolveTransitiveSCAOrigin(fx.root, scaEntry, {});
  assert.equal(result.status, 'complete',
    `expected the deep copy's transition to resolve; got ${JSON.stringify(result)}`);
  assert.equal(result.findingOrigin.commit, introducedSha);
  assert.deepEqual(result.depChain, ['body-parser', 'deep', 'qs']);
  assert.equal(result.parentBoundaryVerified, true);

  // And the negative control: withOUT depChain guidance, the pre-existing
  // shortest-path heuristic genuinely cannot find this transition — proving
  // the fix is load-bearing, not vacuous (same discipline as item #2's
  // pre-fix-must-fail check, applied here as a same-run control instead of a
  // git-stash revert since the fallback path is still reachable by omitting
  // depChain rather than needing the old code back).
  const scaEntryNoChain = { name: 'qs', filePath: 'package-lock.json', fixedVersions: ['6.5.4'] };
  const fallbackResult = await resolveTransitiveSCAOrigin(fx.root, scaEntryNoChain, {});
  assert.notEqual(fallbackResult.status, 'complete',
    'the shortest-path heuristic alone (no depChain) should NOT be able to resolve this transition — if it now can, the negative control no longer demonstrates the fix is load-bearing');
});

test('resolveTransitiveSCAOrigin: no candidate history resolves not_available, never fabricates', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('other.txt', 'x');
  fx.commit('unrelated');
  const scaEntry = { name: 'qs', filePath: 'package-lock.json', fixedVersions: ['6.5.3'] };
  const result = await resolveTransitiveSCAOrigin(fx.root, scaEntry, {});
  assert.equal(result.status, 'not_available');
  assert.equal(result.reason, 'no-candidate-commits');
});
