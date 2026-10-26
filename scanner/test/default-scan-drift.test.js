// A change to what a default scan reports must be deliberate. bench/default-scan-drift scans fixed committed fixtures and compares
// every finding to a committed baseline; this runs that check in the ordinary test run so an undeclared change fails the gate.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { diff } from '../../bench/default-scan-drift/runner.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const RUNNER = path.join(HERE, '..', '..', 'bench', 'default-scan-drift', 'runner.mjs');

test('default-scan-drift: the default scan over the fixed fixtures matches the committed baseline', () => {
  const r = spawnSync(process.execPath, [RUNNER, '--check'], { encoding: 'utf8', timeout: 120000 });
  assert.equal(r.status, 0, `${r.stdout}\n${r.stderr}`);
});

test('default-scan-drift: diff reports an added, a removed and a line-only change, and nothing for an identical set', () => {
  const a = { root: 'r', file: 'f.js', line: null, vuln: 'X', severity: 'high', family: 'x', parser: 'REGEX' };
  const b = { ...a, line: 7 };
  assert.deepEqual(diff([a], [a]), { added: [], removed: [] });
  const d = diff([a], [b]);
  assert.equal(d.added.length, 1);
  assert.equal(d.removed.length, 1);
  assert.equal(diff([a], [a, a]).added.length, 1, 'a duplicated finding is a change');
});
