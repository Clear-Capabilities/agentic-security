// FR-LEARN-6 rule synthesis tests.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { synthesizeRules } from '../src/posture/rule-synthesis.js';

function _writeTriage(root, verdicts) {
  // Add a project marker so the state-dir safety check allows writes
  fs.writeFileSync(path.join(root, 'package.json'), '{"name":"test","version":"1.0.0"}');
  fs.mkdirSync(path.join(root, '.agentic-security'), { recursive: true });
  fs.writeFileSync(path.join(root, '.agentic-security', 'triage-feedback.json'),
                   JSON.stringify({ verdicts }, null, 2));
}

test('synthesizeRules emits a proposal when ≥ 5 FPs cluster by family + dir', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'as-rs-'));
  _writeTriage(root, [
    { file: 'src/api/users.js', line: 10, family: 'csrf', verdict: 'fp' },
    { file: 'src/api/users.js', line: 20, family: 'csrf', verdict: 'fp' },
    { file: 'src/api/items.js', line: 30, family: 'csrf', verdict: 'fp' },
    { file: 'src/api/orders.js', line: 40, family: 'csrf', verdict: 'fp' },
    { file: 'src/api/notes.js', line: 50, family: 'csrf', verdict: 'fp' },
    { file: 'src/api/tags.js',  line: 60, family: 'csrf', verdict: 'fp' },
  ]);
  const p = synthesizeRules(root, { dryRun: true });
  assert.equal(p.length, 1);
  assert.equal(p[0].family, 'csrf');
  assert.equal(p[0].count, 6);
  fs.rmSync(root, { recursive: true, force: true });
});

test('synthesizeRules emits nothing when below threshold', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'as-rs-'));
  _writeTriage(root, [
    { file: 'a.js', line: 1, family: 'csrf', verdict: 'fp' },
    { file: 'a.js', line: 2, family: 'csrf', verdict: 'fp' },
  ]);
  const p = synthesizeRules(root, { dryRun: true });
  assert.deepEqual(p, []);
  fs.rmSync(root, { recursive: true, force: true });
});

test('synthesizeRules writes a YAML when not dry-run', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'as-rs-'));
  const verdicts = Array.from({ length: 5 }, (_, i) => ({
    file: `src/x/file${i}.js`, line: i, family: 'idor', verdict: 'fp',
  }));
  _writeTriage(root, verdicts);
  const p = synthesizeRules(root, {});
  assert.equal(p.length, 1);
  assert.ok(fs.existsSync(p[0].file), 'proposed file should be written to disk');
  const yaml = fs.readFileSync(p[0].file, 'utf8');
  assert.ok(yaml.includes('id: auto-suppress-idor-'));
  assert.ok(yaml.includes('shadow: true'));
  fs.rmSync(root, { recursive: true, force: true });
});

test('synthesizeRules ignores non-fp verdicts', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'as-rs-'));
  _writeTriage(root, Array.from({ length: 6 }, (_, i) => ({
    file: `src/a/f${i}.js`, line: i, family: 'csrf', verdict: 'tp',
  })));
  const p = synthesizeRules(root, { dryRun: true });
  assert.deepEqual(p, []);
  fs.rmSync(root, { recursive: true, force: true });
});

test('synthesizeRules returns [] when triage-feedback missing', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'as-rs-'));
  const p = synthesizeRules(root, { dryRun: true });
  assert.deepEqual(p, []);
  fs.rmSync(root, { recursive: true, force: true });
});
