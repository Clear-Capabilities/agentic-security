// Tests for the proof-corpus runner's disclosure-boundary containment
// (FINDING 2: raw artifacts must always land under the fixed, gitignored
// bench/proof-corpus/results/raw/, regardless of what --out resolves to).
// No network access; does not invoke main().

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as path from 'node:path';
import * as fs from 'node:fs';
import * as os from 'node:os';
import { parseArgs, rawDirFor, RAW_DIR, sarifDigest } from '../../bench/proof-corpus/runner.mjs';

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

// ── determinism must not be reportable from a truncated capture ─────────────
// Godot's two SARIF captures were both exactly 65,536 bytes (one OS pipe
// buffer) and both ended mid-token, so hashing them alone reported
// `identical: true` from a gate that could not fail. sarifDigest() refuses
// any capture that isn't a whole SARIF document.

function _tmpFile(name, content) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'proof-sarif-'));
  const f = path.join(dir, name);
  fs.writeFileSync(f, content);
  return f;
}

test('sarifDigest: accepts a whole SARIF document and counts its results', () => {
  const f = _tmpFile('ok.sarif', JSON.stringify({
    version: '2.1.0',
    runs: [{ results: [{ ruleId: 'a' }, { ruleId: 'b' }] }],
  }));
  const d = sarifDigest(f);
  assert.equal(d.ok, true, d.reason);
  assert.equal(d.results, 2);
  assert.match(d.sha, /^[0-9a-f]{64}$/);
});

test('sarifDigest: rejects a truncated capture even though two truncations hash equal', () => {
  const whole = JSON.stringify({ version: '2.1.0', runs: [{ results: [{ ruleId: 'a' }] }] });
  const cut = whole.slice(0, 20);
  const a = _tmpFile('a.sarif', cut);
  const b = _tmpFile('b.sarif', cut);
  const da = sarifDigest(a), db = sarifDigest(b);
  assert.equal(da.sha, db.sha, 'two identical truncations DO hash equal — that was the bug');
  assert.equal(da.ok, false);
  assert.match(da.reason, /truncated|not parseable/);
  assert.equal(da.ok && db.ok && da.sha === db.sha, false,
    'determinism must never be reportable from a truncated capture');
});

test('sarifDigest: rejects valid JSON that is not a SARIF document, and a missing file', () => {
  assert.equal(sarifDigest(_tmpFile('x.sarif', '{"runs":[]}')).ok, false);
  assert.equal(sarifDigest(_tmpFile('y.sarif', '{"hello":1}')).ok, false);
  const missing = sarifDigest(path.join(os.tmpdir(), 'definitely-not-here-1234.sarif'));
  assert.equal(missing.ok, false);
  assert.equal(missing.sha, null);
});
