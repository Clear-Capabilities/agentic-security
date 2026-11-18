// The jsbn package's SecureRandom, seeded from Math.random outside browsers (CWE-338), src/sast/weak-randomness.js.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanJsbnSecureRandom as scan } from '../src/sast/weak-randomness.js';

const FIX = path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures', 'jsbn-secure-random');
const read = (side) => fs.readFileSync(path.join(FIX, side, 'keys.js'), 'utf8');

test('importing and instantiating jsbn SecureRandom is reported at the import', () => {
  const out = scan('keys.js', read('vulnerable'));
  assert.deepEqual(out.map((f) => f.line), [2]);
  assert.equal(out[0].cwe, 'CWE-338');
  assert.equal(out[0].family, 'weak-rng');
});

test('a CSPRNG-backed source, an import that is never instantiated, and another package are silent', () => {
  assert.deepEqual(scan('keys.js', read('clean')), []);
  assert.deepEqual(scan('a.js', "const { BigInteger, SecureRandom } = require('jsbn');\nmodule.exports = BigInteger;\n"), []);
  assert.deepEqual(scan('a.js', "const { SecureRandom } = require('./rng');\nconst r = new SecureRandom();\n"), []);
  assert.equal(scan('a.ts', "import { SecureRandom } from 'jsbn';\nconst r = new SecureRandom();\n").length, 1);
  assert.deepEqual(scan('a.py', "const { SecureRandom } = require('jsbn');\nnew SecureRandom();\n"), []);
});
