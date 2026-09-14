// SARD_80_F1_SCANNER_PRD.md adversarial-premortem remediation, P2 item 11 —
// "no baseline/ablation exists... a reader has no way to tell whether 45.6%
// Java macro-F1 represents a sophisticated taint engine or a handful of
// high-recall pattern matches." bench/sard/scripts/naive-baseline.mjs is a
// deliberately taint-blind regex sink-name sweep, scored with the SAME
// scoreLegacy() infrastructure as the real scorer, giving macro-F1 an
// interpretable floor.
//
// This is a smoke test, not a full correctness suite: naive-baseline.mjs
// needs the real (already-cloned, --blind, NOT --scramble-identifiers)
// Java Juliet corpus on disk, which the fast unit-test suite doesn't
// provision on its own (a full clone+blind is a multi-minute network
// operation, wildly out of scope for `npm run test:dataflow`). Skips
// gracefully — reporting why, not silently — when that corpus isn't
// present locally; a real CI/local run that HAS run `npm run
// bench:sard:java` (or the naive-baseline script itself) at least once
// exercises this for real.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { execFileSync } from 'node:child_process';

const HERE = path.dirname(new URL(import.meta.url).pathname);
const SCRIPT = path.join(HERE, '..', '..', 'bench', 'sard', 'scripts', 'naive-baseline.mjs');
const CORPUS = path.join(HERE, 'benchmark', 'realworld', '.bench-cache',
  'sard-juliet-java-strict-8b5b9d6edf20482abef09bf9300600556ba4e4b0-blinded');

test('naive-baseline.mjs: runs end to end and produces a floor strictly below what a real taint-aware scanner should achieve', { skip: !fs.existsSync(CORPUS) && 'Java Juliet corpus not cloned locally (run `npm run bench:sard:java` once first) — skipping rather than provisioning a multi-minute clone in the fast suite' }, () => {
  const out = execFileSync(process.execPath, [SCRIPT, '--json'], { encoding: 'utf8' });
  const parsed = JSON.parse(out);
  const result = parsed.results[0];
  assert.equal(result.name, 'sard-java-naive-baseline-strict');
  assert.equal(result.language, 'java');
  assert.ok(result.scanned > 0, 'expected at least one naive finding');
  assert.ok(result.tp > 0, 'expected at least one genuine TP (the naive shapes ARE real sink APIs)');
  // The whole point of this tool: it must not accidentally BE a good
  // detector. A taint-blind sweep firing on every sink-shaped call
  // regardless of taint should have materially worse precision than any
  // real scanner result recorded in bench/sard/IMPLEMENTATION_STATUS.md
  // (all of which are comfortably above 50%).
  assert.ok(result.precision < 0.5, `expected low precision from a taint-blind sweep, got ${result.precision}`);
  // Per-CWE FP attribution (bench-realworld.js's bumpCwe fix, same
  // remediation pass) must actually attribute SOME FPs to a real CWE, not
  // leave every fp bucket empty the way the pre-fix `x.cwe` bug did.
  const cwesWithFp = Object.values(result.perCwe).filter(c => c.fp > 0);
  assert.ok(cwesWithFp.length > 0, 'expected at least one CWE bucket with attributed FPs (regression check for the reportedCwe fix)');
});

test('naive-baseline.mjs: --split test is symmetric (both expected AND actual are filtered), never inflating FP with out-of-split findings', { skip: !fs.existsSync(CORPUS) && 'Java Juliet corpus not cloned locally — skipping' }, () => {
  const full = JSON.parse(execFileSync(process.execPath, [SCRIPT, '--json'], { encoding: 'utf8' })).results[0];
  const testSplit = JSON.parse(execFileSync(process.execPath, [SCRIPT, '--split', 'test', '--json'], { encoding: 'utf8' })).results[0];
  assert.ok(testSplit.scanned < full.scanned, 'a --split test run must score fewer actual findings than the unfiltered full-corpus run');
  assert.ok(testSplit.tp <= full.tp);
  assert.ok(testSplit.fn <= full.fn);
});
