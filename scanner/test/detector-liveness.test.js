// PRD F11.4 — fail loudly, not silently.
//
// THE FAILURE CLASS. `sast/rate-limit.js` discarded 100% of the findings it
// produced, project-wide, from the day it was written until 2026-08-19. Its unit
// tests passed the whole time, because they called the detector directly. What
// nobody checked was whether the detector's output survived the pipeline.
//
// This file checks exactly that, end to end: every rule with a committed
// `vulnerable/` fixture must still produce at least one finding *through
// `runScan`*, not merely when called in isolation. It is the difference between
// "the function works" and "the product works".
//
// WHAT IT FOUND ON ITS FIRST RUN. Two of thirty fixtures were already dark, and
// both are genuine product defects rather than test problems — each detector
// produces findings when called directly and zero through a scan, because
// `shouldScan()` never lets the dispatch loop visit the file:
//
//   · k8s-admission  — `_isIaCFile` admits YAML as Kubernetes only when the path
//     contains a directory literally named `k8s/`. Its own comment reads "under
//     k8s/ or contains `kind:` — caller checks content", but the content half was
//     never implemented, so manifests under deploy/, manifests/, charts/,
//     kubernetes/ or the repo root are invisible. Called directly on the fixture
//     it returns 3 findings; through runScan, 0.
//   · install-script — `package.json` fails `shouldScan()` entirely, so
//     `scanInstallScripts` is wired into the dispatch and never invoked by it.
//     Directly: 1 finding ("Malicious-looking install hook — postinstall
//     download-exec"). Through runScan: 0.
//
// They are listed below rather than deleted or quietly skipped. A known-dark
// list that must SHRINK is a debt register; a silent skip is how the debt is
// forgotten. Both entries are also asserted to be *still* dark, so whoever fixes
// one is forced to remove it from the list rather than leave a stale exception
// (the same discipline `no-dead-modules.test.js` applies to its ALLOWLIST).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '../src/runScan.js';
import { setStateWritesEnabled } from '../src/posture/state-dir.js';

const FIXTURES = path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures');

// Fixtures whose detector is currently unreachable through `runScan`. Each entry
// must carry a diagnosed root cause — it is a debt register, not an accepted
// exclusion, and the second test below fails if an entry is no longer dark.
//
// EMPTY, and worth keeping empty. Both original entries were fixed rather than
// tolerated:
//   · k8s-admission  — the "contains kind:" content check its own comment
//     promised was implemented (`isKubernetesManifest`), and applied at BOTH
//     places that gate file admission. The second one is the reason the first
//     fix appeared not to work: `runScan` admits the file, and then
//     `runFullScan` re-filters the same list with `shouldScan()`.
//     Now 17 findings on the vulnerable tree, 0 on the clean one.
//   · install-script — `scanInstallScripts` now runs over depFileContents,
//     where package.json actually lives, instead of sitting unreachable in the
//     per-file SAST dispatch. Now 1 finding on vulnerable, 0 on clean.
const KNOWN_DARK = new Map([]);

function fixturesWithVulnerableTree() {
  if (!fs.existsSync(FIXTURES)) return [];
  return fs.readdirSync(FIXTURES).sort()
    .filter((name) => fs.existsSync(path.join(FIXTURES, name, 'vulnerable')));
}

async function findingCount(dir) {
  setStateWritesEnabled(false);
  try {
    const { scan } = await runScan(dir);
    return [...(scan.findings || []), ...(scan.secrets || []), ...(scan.logicVulns || [])].length;
  } finally {
    setStateWritesEnabled(true);
  }
}

test('every rule fixture still produces a finding THROUGH runScan, not just in isolation', async () => {
  const names = fixturesWithVulnerableTree();
  assert.ok(names.length >= 25,
    `expected the fixture corpus to be substantial, found ${names.length} — if fixtures moved, fix this path`);

  const dark = [];
  for (const name of names) {
    if (KNOWN_DARK.has(name)) continue;
    const n = await findingCount(path.join(FIXTURES, name, 'vulnerable'));
    if (n === 0) dark.push(name);
  }

  assert.deepEqual(dark, [],
    'These rules produce ZERO findings through a full scan. Either the detector broke, or — as '
    + 'with rate-limit.js — its output is being discarded somewhere downstream. Call the detector '
    + `directly to tell those apart:\n  ${dark.join('\n  ')}`);
});

test('the known-dark list contains no stale entries (fix one, remove it)', async () => {
  const revived = [];
  for (const [name] of KNOWN_DARK) {
    const dir = path.join(FIXTURES, name, 'vulnerable');
    if (!fs.existsSync(dir)) continue; // fixture removed; covered by the count assertion above
    if (await findingCount(dir) > 0) revived.push(name);
  }
  assert.deepEqual(revived, [],
    'These fixtures now produce findings, so they are no longer dark. Remove them from '
    + `KNOWN_DARK in this file — a stale exception hides the next regression:\n  ${revived.join('\n  ')}`);
});
