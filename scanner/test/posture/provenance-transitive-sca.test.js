import { test } from 'node:test';
import assert from 'node:assert/strict';
import { resolveTransitiveSCAOrigin } from '../../src/posture/provenance/transitive-sca.js';
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
