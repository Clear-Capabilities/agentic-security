// .github/workflows/release.yml no longer runs the release gate twice.
//
// WHAT WAS WRONG
// ---------------
// The publish job ran an explicit "Release gate" step (`release-check.mjs
// --no-cache`), then `npm publish` — which triggers scanner/package.json's
// prepublishOnly, itself `npm run build && sync-scanner-changelog.mjs &&
// release-check.mjs`. Measured on v0.143.0's release: 280s for the explicit
// step, 318s for the one inside prepublishOnly, on the SAME commit, SAME
// checkout, SAME runner, ~10 seconds apart. Caching could not have closed the
// gap even by design: this workflow always passes --no-cache (a cross-machine
// cache would reintroduce the reproducibility claim posture/attestation.js
// explicitly declines to make), so the first run never wrote anything for the
// second to reuse.
//
// THE FIX, AND WHY IT IS SAFE
// ----------------------------
// `npm publish --ignore-scripts` skips prepublishOnly on the actual publish
// step, because the three explicit steps immediately above it already did
// everything prepublishOnly would: built the bundle, synced the changelog,
// ran the full uncached gate. Nothing prepublishOnly produces is missing from
// disk by the time `npm publish` runs. This is a narrow, CI-specific
// optimization — scanner/package.json's prepublishOnly itself stays wired,
// because a LOCAL `npm publish` has no preceding explicit gate step to make
// it redundant (root CLAUDE.md's "Two publish paths" section).
//
// WHAT WOULD MAKE --ignore-scripts UNSAFE
// -----------------------------------------
// `--ignore-scripts` skips EVERY lifecycle script npm would run for this
// command, not just prepublishOnly — including prepack/postpack, which
// `npm publish` also triggers while building the tarball. If either is ever
// added to scanner/package.json, it would be silently skipped here without
// its effect being reproduced by an explicit step first, and the packed
// tarball could then be missing whatever that script was supposed to do. This
// file's second test is the tripwire for that.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..', '..');

function readWorkflow() {
  return fs.readFileSync(path.join(REPO, '.github', 'workflows', 'release.yml'), 'utf8');
}

test('the publish step runs --ignore-scripts, so prepublishOnly cannot re-run the gate', () => {
  const wf = readWorkflow();
  // Anchor on the actual `run:` invocation, not any of the several comment
  // lines above it that also say "npm publish" while explaining why.
  const idx = wf.indexOf('run: npm publish');
  assert.ok(idx !== -1, 'expected a `run: npm publish` step in release.yml');
  const line = wf.slice(wf.lastIndexOf('\n', idx) + 1, wf.indexOf('\n', idx));
  assert.match(line, /--ignore-scripts/,
    'npm publish must pass --ignore-scripts, or prepublishOnly reruns build+changelog-sync+release-check '
    + '(measured 280-320s) a second time on the same commit the explicit steps above it already verified');
});

test('the steps --ignore-scripts is standing in for still run explicitly, and run first', () => {
  const wf = readWorkflow();
  const order = ['name: Build the bundle', 'name: Sync scanner changelog', 'name: Release gate', 'run: npm publish'];
  const positions = order.map((marker) => {
    const i = wf.indexOf(marker);
    assert.ok(i !== -1, `expected to find "${marker}" in release.yml`);
    return i;
  });
  for (let i = 1; i < positions.length; i++) {
    assert.ok(positions[i] > positions[i - 1],
      `"${order[i]}" must appear after "${order[i - 1]}" — --ignore-scripts on npm publish is only safe `
      + 'because these run first and produce everything prepublishOnly would');
  }
});

test('scanner/package.json has no prepack/postpack scripts for --ignore-scripts to silently skip', () => {
  // --ignore-scripts skips ALL lifecycle scripts npm publish would trigger,
  // not just prepublishOnly. A prepack/postpack script added later would be
  // silently dropped from the CI publish path with nothing here to notice —
  // unless this test exists to notice it. If this ever needs to fail (a real
  // prepack/postpack is added on purpose), the fix is to reproduce its effect
  // in an explicit release.yml step before the publish step, the same way
  // build and changelog-sync already are — not to delete this test.
  const pkg = JSON.parse(fs.readFileSync(path.join(REPO, 'scanner', 'package.json'), 'utf8'));
  const found = Object.keys(pkg.scripts || {}).filter((k) => k === 'prepack' || k === 'postpack');
  assert.deepEqual(found, [],
    `scanner/package.json defines ${found.join(', ')} — release.yml's npm publish uses --ignore-scripts `
    + 'and will silently skip it. Reproduce its effect as an explicit step before "Publish with provenance" '
    + 'in .github/workflows/release.yml, then update this test.');
});

test('the dry-run path is untouched: npm pack does not trigger prepublishOnly, so it was never doubled', () => {
  // Documented here so nobody "fixes" the dry-run branch to match the publish
  // branch under the mistaken belief it has the same bug. `npm pack` runs
  // prepack/postpack, never prepublishOnly — the dry-run path only ever ran
  // the gate once (via the explicit "Release gate" step), which is why it
  // carries no --ignore-scripts and needs none.
  const wf = readWorkflow();
  const idx = wf.indexOf('npm pack --dry-run');
  assert.ok(idx !== -1, 'expected the dry-run branch to still call npm pack --dry-run');
});
