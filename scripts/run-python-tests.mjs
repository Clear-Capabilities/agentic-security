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

// Stage 6 correctness audit: this used to be a flat, non-recursive
// readdirSync over scripts/ only, so scripts/nist-compliance/test_regex_redos.py
// (added to guard against reintroducing the ReDoS fixed in e0c669b) was never
// discovered or run by `npm test` — the exact silent-regression gap this
// runner exists to close, just one directory level deeper than it looked.
function _findTestFiles(dir) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === '__pycache__' || entry.name.startsWith('.')) continue;
    const fp = path.join(dir, entry.name);
    if (entry.isDirectory()) { out.push(..._findTestFiles(fp)); continue; }
    if (entry.name.startsWith('test_') && entry.name.endsWith('.py')) out.push(fp);
  }
  return out;
}

const testFiles = _findTestFiles(path.join(REPO, 'scripts'))
  .map((fp) => path.relative(REPO, fp))
  .sort();

if (!testFiles.length) {
  console.error('[test:python] no scripts/test_*.py files found — nothing to run.');
  process.exit(0);
}

let failed = false;
for (const f of testFiles) {
  console.log(`[test:python] running ${f}`);
  const r = spawnSync('python3', [path.join(REPO, f)], { stdio: 'inherit', cwd: REPO });
  if (r.status !== 0) failed = true;
}
process.exit(failed ? 1 : 0);
