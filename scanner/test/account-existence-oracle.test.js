// Handler that reveals whether an account exists for a request email (CWE-200), src/sast/account-existence-oracle.js.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanAccountExistenceOracle as scan } from '../src/sast/account-existence-oracle.js';

const FIX = path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures', 'account-existence-oracle');
const read = (side) => fs.readFileSync(path.join(FIX, side, 'MemberLookupController.php'), 'utf8');
const lineOf = (code, needle) => code.split('\n').findIndex((l) => l.includes(needle)) + 1;

test('a lookup by request email answered with an exists flag is reported at the lookup', () => {
  const code = read('vulnerable');
  const out = scan('MemberLookupController.php', code);
  assert.deepEqual(out.map((f) => f.line), [lineOf(code, 'findByEmail')]);
  assert.equal(out[0].cwe, 'CWE-200');
});

test('the fixed version, with an authorization check first, is silent', () => {
  assert.deepEqual(scan('MemberLookupController.php', read('clean')), []);
});

test('a lookup whose result is not returned as an answer, and an email not from the request, are silent', () => {
  const noAnswer = read('vulnerable').replace("return ['exists' => $member !== null];", 'return view("members.show", compact("member"));');
  assert.deepEqual(scan('MemberLookupController.php', noAnswer), []);
  const notRequest = read('vulnerable').replace("$request->input('email')", '$invite->email');
  assert.deepEqual(scan('MemberLookupController.php', notRequest), []);
});

test('the JavaScript form is reported, and a test file is ignored', () => {
  const js = "router.post('/check', async (req, res) => {\n  const u = await User.findOne({ email: req.body.email });\n  res.json({ exists: !!u });\n});\n";
  assert.equal(scan('routes/users.js', js).length, 1);
  assert.deepEqual(scan('routes/users.test.js', js), []);
});
