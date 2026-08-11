#!/usr/bin/env node
// Runs the repo's plain-Python regression tests (scripts/test_*.py) as part
// of `npm test`. These were previously reachable only via
// `python3 scripts/test_whatever.py`, run by hand — npm test never touched
// them, so a real regression (like CMP-8's weak-signal-only "Compliant" bug)
// could land and stay green forever. python3 is optional for this repo
// (the IR layer already degrades to a regex fallback without it), so this
// skips rather than fails when python3 is unavailable — never a silent
// pass dressed up as a real result: the skip is printed loudly.
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const probe = spawnSync('python3', ['--version'], { stdio: 'ignore' });
if (probe.status !== 0) {
  console.error('[test:python] SKIPPED — python3 not available on this host. ' +
    'These tests did not run; that is not the same as passing.');
  process.exit(0);
}

const testFiles = fs.readdirSync(path.join(REPO, 'scripts'))
  .filter((f) => f.startsWith('test_') && f.endsWith('.py'))
  .sort();

if (!testFiles.length) {
  console.error('[test:python] no scripts/test_*.py files found — nothing to run.');
  process.exit(0);
}

let failed = false;
for (const f of testFiles) {
  console.log(`[test:python] running scripts/${f}`);
  const r = spawnSync('python3', [path.join(REPO, 'scripts', f)], { stdio: 'inherit', cwd: REPO });
  if (r.status !== 0) failed = true;
}
process.exit(failed ? 1 : 0);
