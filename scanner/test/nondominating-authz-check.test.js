// Authorization check nested under a data branch while the action runs on every path (CWE-862), src/sast/nondominating-authz-check.js.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanNondominatingAuthzCheck as scan } from '../src/sast/nondominating-authz-check.js';

const FIX = path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures', 'nondominating-authz-check');
const read = (side) => fs.readFileSync(path.join(FIX, side, 'views.py'), 'utf8');
const lineOf = (code, needle) => code.split('\n').findIndex((l) => l.includes(needle)) + 1;

test('a check under a data branch, with the protected data used after the branch, is reported at the check', () => {
  const code = read('vulnerable');
  const out = scan('views.py', code);
  assert.deepEqual(out.map((f) => f.line), [lineOf(code, 'if not perm.can():')]);
  assert.equal(out[0].cwe, 'CWE-862');
});

test('the fixed version, which reads the protected data only on the checked branch, is silent', () => {
  assert.deepEqual(scan('views.py', read('clean')), []);
});

test('a branch on the caller identity, a branch with an else, and a check that is not nested are silent', () => {
  const identity = read('vulnerable').replace('if exporter.needs_secret:', 'if g.current_user.is_staff:');
  assert.deepEqual(scan('views.py', identity), []);
  const withElse = read('vulnerable').replace('\n        result = exporter.run', '\n        else:\n            abort(403)\n        result = exporter.run');
  assert.deepEqual(scan('views.py', withElse), []);
  const flat = 'def post(self, rid):\n    rec = store.get(rid)\n    if not perm.can():\n        abort(403)\n    return exporter.run(rec.secret)\n';
  assert.deepEqual(scan('views.py', flat), []);
  assert.deepEqual(scan('views.js', read('vulnerable')), []);
});
