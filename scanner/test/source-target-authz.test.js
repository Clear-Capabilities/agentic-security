// Copy/move that checks the destination but not the origin (CWE-285), src/sast/source-target-authz.js.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanSourceTargetAuthz as scan } from '../src/sast/source-target-authz.js';

const FIX = path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures', 'source-target-authz');
const read = (side) => fs.readFileSync(path.join(FIX, side, 'boards.py'), 'utf8');

test('a copy that checks only the target, in a file that checks sources with the same method, is reported at the target check', () => {
  const code = read('vulnerable');
  const out = scan('boards.py', code);
  const lines = code.split('\n');
  const want = lines.findIndex((l, i) => i > lines.findIndex((x) => x.includes('def copy_cards')) && l.includes('target_board.check_access')) + 1;
  assert.deepEqual(out.map((f) => f.line), [want]);
  assert.equal(out[0].cwe, 'CWE-285');
});

test('the fixed version, which checks the source too, is silent', () => {
  assert.deepEqual(scan('boards.py', read('clean')), []);
});

test('without a file convention of checking sources, a target-only check is left alone', () => {
  const noConvention = read('vulnerable').replace(/        if not source_board\.check_access\(request\.user\):\n            raise PermissionDenied\("no access"\)\n/, '');
  assert.deepEqual(scan('boards.py', noConvention), []);
});

test('a check that does not receive the caller, test files and other languages are ignored', () => {
  const noCaller = read('vulnerable').replace(/target_board\.check_access\(request\.user\)/g, 'target_board.check_access(limit)');
  assert.deepEqual(scan('boards.py', noCaller), []);
  assert.deepEqual(scan('tests/test_boards.py', read('vulnerable')), []);
  assert.deepEqual(scan('boards.js', read('vulnerable')), []);
});
