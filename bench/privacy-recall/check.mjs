#!/usr/bin/env node
// FR-403 step 3's before/after recall gate. Mirrors bench/self-scan/check.mjs's
// exit-code contract exactly, for the same reason:
//   0  clean — fresh measurement matches BASELINE.json exactly, per fixture.
//   1  drift — a fixture's shallowCount or deepCount changed from the
//      committed baseline. This is the "your commit changed privacy-taint
//      detection behavior" case — could be a real improvement OR a real
//      regression; either way it must be reviewed and the baseline
//      deliberately re-generated, never silently accepted.
//   2  could not measure — usage error, missing/unreadable baseline, or the
//      measurement run itself threw. NOT a drift finding.
//
// Usage:
//   node bench/privacy-recall/check.mjs                  # gate: exit 0/1/2
//   node bench/privacy-recall/check.mjs --update-baseline  # regenerate BASELINE.json

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { disableStateWrites, purgeScanState } from '../_lib/tree-integrity.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..', '..');
const MEASURE = path.join(HERE, 'measure.mjs');
const BASELINE_PATH = path.join(HERE, 'BASELINE.json');

await disableStateWrites();
// D-0009: some annotators (threat-model/sbom-history) write relative to the
// measure.mjs subprocess's own cwd (HERE) rather than the fixture being
// scanned. Purge before AND after so a check run never leaves stray state
// alongside BASELINE.json.
purgeScanState(HERE);

function currentCommit() {
  try {
    return execFileSync('git', ['rev-parse', 'HEAD'], { cwd: REPO, encoding: 'utf8' }).trim();
  } catch {
    return 'unknown';
  }
}

function runMeasure() {
  const raw = execFileSync(process.execPath, [MEASURE, '--json'], {
    cwd: HERE,
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  });
  return JSON.parse(raw);
}

function fail(code, msg) {
  console.error(msg);
  process.exit(code);
}

const UPDATE = process.argv.includes('--update-baseline');

let now;
try {
  now = runMeasure();
} catch (e) {
  fail(2, `privacy-recall: measurement run threw — ${String((e && e.message) || e)}`);
} finally {
  purgeScanState(HERE);
}

if (UPDATE) {
  const baseline = { generatedAt: new Date().toISOString(), commit: currentCommit(), fixtures: now };
  fs.writeFileSync(BASELINE_PATH, JSON.stringify(baseline, null, 2) + '\n');
  console.log(`privacy-recall: baseline updated (${Object.keys(now).length} fixtures) -> ${path.relative(REPO, BASELINE_PATH)}`);
  process.exit(0);
}

let baseline;
try {
  baseline = JSON.parse(fs.readFileSync(BASELINE_PATH, 'utf8'));
} catch (e) {
  fail(2, `privacy-recall: could not read baseline at ${BASELINE_PATH} — ${String((e && e.message) || e)}`);
}

const before = baseline.fixtures || {};
const names = new Set([...Object.keys(before), ...Object.keys(now)]);
const drift = [];
for (const name of [...names].sort()) {
  const b = before[name] || { shallowCount: 0, deepCount: 0 };
  const n = now[name] || { shallowCount: 0, deepCount: 0 };
  if (b.shallowCount !== n.shallowCount || b.deepCount !== n.deepCount) {
    drift.push({ name, before: b, after: n });
  }
}

if (drift.length) {
  console.error('Privacy-recall gate: DRIFT DETECTED\n');
  for (const d of drift) {
    console.error(`  ${d.name}: shallow ${d.before.shallowCount}->${d.after.shallowCount}, deep ${d.before.deepCount}->${d.after.deepCount}`);
  }
  console.error('\nReview each change. If deliberate (a real capability improvement or an intentional narrowing), run:');
  console.error('  node bench/privacy-recall/check.mjs --update-baseline');
  process.exit(1);
}

console.log(`Privacy-recall gate: PASS — ${names.size} fixtures match baseline exactly.`);
for (const name of [...names].sort()) {
  const n = now[name];
  console.log(`  ${name}: shallow=${n.shallowCount} deep=${n.deepCount}`);
}
process.exit(0);
