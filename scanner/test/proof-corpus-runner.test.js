// Tests for the proof-corpus runner's disclosure-boundary containment
// (FINDING 2: raw artifacts must always land under the fixed, gitignored
// bench/proof-corpus/results/raw/, regardless of what --out resolves to).
// No network access; does not invoke main().

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as path from 'node:path';
import { parseArgs, rawDirFor, RAW_DIR } from '../../bench/proof-corpus/runner.mjs';

test('RAW_DIR is the fixed, gitignored path', () => {
  assert.ok(RAW_DIR.endsWith(path.join('bench', 'proof-corpus', 'results', 'raw')));
});

test('rawDirFor: is under the fixed RAW_DIR even when --out points elsewhere', () => {
  const args = parseArgs(['--out', '/tmp/some-other-results-dir']);
  const raw = rawDirFor('ghost');
  assert.ok(raw.startsWith(RAW_DIR), 'raw artifacts must stay under the fixed RAW_DIR');
  assert.ok(!raw.startsWith(args.outDir), 'raw artifacts must not follow --out');
  assert.equal(raw, path.join(RAW_DIR, 'ghost'));
});

test('parseArgs: --out only controls where summary.json is written', () => {
  const args = parseArgs(['--out', '/tmp/some-other-results-dir']);
  assert.equal(args.outDir, '/tmp/some-other-results-dir');
});

test('parseArgs: default outDir is the standard results directory', () => {
  const args = parseArgs([]);
  assert.ok(args.outDir.endsWith(path.join('bench', 'proof-corpus', 'results')));
});
