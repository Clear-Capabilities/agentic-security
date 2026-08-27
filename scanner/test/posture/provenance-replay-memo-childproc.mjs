// Child-process helper for the "resolveOrigin memoizes replayAt" test in
// provenance-origin-resolver.test.js (M2 §2.4 performance fix).
//
// WHY THIS IS A SEPARATE FILE, RUN AS A SEPARATE PROCESS:
//
// node:test's `t.mock.method(obj, 'name')` cannot intercept a NAMED ES-module
// export: `origin-resolver.js` does `import { replayAt } from
// './predicate-replay.js'`, and an ES module namespace object's exports are
// non-configurable by spec — `t.mock.method` on it throws "Cannot redefine
// property: replayAt" (verified directly against this repo's own modules,
// not assumed from docs).
//
// node:test's `mock.module(specifier, { exports/namedExports })` DOES work —
// it intercepts the module at the resolver level, so every importer
// (including origin-resolver.js) sees the mocked binding. But it requires
// the `--experimental-test-module-mocks` CLI flag at process START, and Node
// explicitly refuses that flag via NODE_OPTIONS ("--experimental-test-
// module-mocks is not allowed in NODE_OPTIONS" — verified by trying it), so
// it cannot be threaded into the already-running, flag-less `node --test`
// process that runs provenance-origin-resolver.test.js. Re-spawning `node
// --test <thisFile>` from inside a running test file is also out: node:test
// detects that reentrancy itself and refuses ("run() is being called
// recursively within a test file. skipping running files" — verified).
//
// So this file is a plain script (no node:test test() wrapper, no --test
// flag needed to invoke it) that the calling test launches directly via
// `node --experimental-test-module-mocks provenance-replay-memo-childproc.mjs`
// (child_process.execFileSync). It mocks predicate-replay.js's replayAt with
// a COUNTING, CALL-THROUGH wrapper (real behavior preserved — this proves
// call-count savings, not merely equivalent output), builds the same
// 3-commit chain as the other test, and exits non-zero (via a thrown
// AssertionError) if the memoized call count is wrong. Verified against
// BOTH directions before wiring this in: with the memo in place this script
// exits 0 with delta=2; with the memo manually reverted to raw replayAt
// calls (temporarily, for that check only, never committed), it exits 1
// with delta=3 — so this assertion is not vacuously true.

import assert from 'node:assert/strict';
import { mock } from 'node:test';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const predicateReplayPath = path.join(here, '../../src/posture/provenance/predicate-replay.js');

const SAFE_SRC = 'function h(id) {\n  return 1;\n}\n';
const VULN_SRC = 'function h(id) {\n  db.query("SELECT * FROM t WHERE id = " + id);\n}\n';

let callCount = 0;
const calls = [];
mock.module(predicateReplayPath, {
  namedExports: {
    // Call-through: count the call, then defer to the REAL implementation
    // via a cache-busted specifier (a different URL than the one being
    // mocked, so it resolves to the real, unmocked module).
    replayAt: async (...args) => {
      callCount++;
      calls.push(args[1]);
      const real = await import(`${predicateReplayPath}?real=1`);
      return real.replayAt(...args);
    },
  },
});

const { createGitFixture } = await import(path.join(here, '../helpers/build-git-fixture.js'));
const { runFullScan } = await import(path.join(here, '../../src/engine.js'));
const { resolveOrigin } = await import(path.join(here, '../../src/posture/provenance/origin-resolver.js'));

const fx = createGitFixture();
try {
  fx.writeFile('server.js', SAFE_SRC);
  fx.commit('safe baseline', { date: '2026-01-01T00:00:00Z', authorName: 'Alice' });
  fx.writeFile('server.js', VULN_SRC);
  const shaVuln = fx.commit('introduce sqli', { date: '2026-01-02T00:00:00Z', authorName: 'Bob' });
  const VULN_SRC_COMMENTED = VULN_SRC.replace('+ id);', '+ id); // reviewed');
  fx.writeFile('server.js', VULN_SRC_COMMENTED);
  fx.commit('add a comment, predicate still present', { date: '2026-01-03T00:00:00Z', authorName: 'Carol' });

  const scan = await runFullScan({ fileContents: { 'server.js': VULN_SRC_COMMENTED }, scanRoot: fx.root }, () => {});
  const finding = (scan.findings || []).find((f) => f.file === 'server.js' && f.family === 'sql-injection');
  assert.ok(finding, 'expected the SQLi structural rule to fire on the fixture content');

  // engine.js's own default pipeline already runs annotateGitProvenance
  // (which calls resolveOrigin, hence replayAt) on every finding, so
  // callCount is nonzero even before our own explicit call below. Measure
  // the DELTA around the explicit call under test, not the running total.
  const before = callCount;
  const result = await resolveOrigin(fx.root, finding, {});
  const delta = callCount - before;

  assert.equal(result.status, 'complete', `expected complete, got ${result.status} (${result.reason || ''})`);
  assert.equal(result.findingOrigin.commit, shaVuln);

  // Candidates oldest-first: [safe-baseline, introduce-sqli, add-comment].
  // The walk returns at candidate 2 (introduce-sqli) and never reaches
  // candidate 3. Without memoization that's 3 raw replayAt calls:
  //   presentHere(candidate1), presentHere(candidate2), presentInParent(candidate1)
  // presentInParent(candidate2's parent) asks about candidate1 again — the
  // SAME (scanRoot, sha, files, stableId) tuple candidate1's own presentHere
  // check already computed. The memo serves that third ask from cache, so
  // the real replayAt is invoked exactly twice.
  assert.equal(
    delta, 2,
    `expected exactly 2 memoized replayAt calls for this 3-commit chain, got ${delta} (shas: ${JSON.stringify(calls.slice(before))})`,
  );

  console.log(`OK: resolveOrigin invoked replayAt ${delta} times (memoized) for a chain that needs 3 without the memo`);
} finally {
  fx.cleanup();
}
