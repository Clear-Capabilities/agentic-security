// Empty-string fallback for a signing or HMAC key (CWE-287), src/sast/empty-hmac-key.js.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanEmptyHmacKey as scan } from '../src/sast/empty-hmac-key.js';

const FIX = path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures', 'empty-hmac-key');
const read = (side, f) => fs.readFileSync(path.join(FIX, side, f), 'utf8');
const lineOf = (code, needle) => code.split('\n').findIndex((l) => l.includes(needle)) + 1;

for (const [file, needle] of [['signer.rb', "key ||= ''"], ['webhook.js', "config.webhookSecret || ''"]]) {
  test(`${file}: the empty-string fallback that reaches the MAC is reported at the fallback`, () => {
    const code = read('vulnerable', file);
    const out = scan(file, code);
    assert.deepEqual(out.map((f) => f.line), [lineOf(code, needle)]);
    assert.equal(out[0].cwe, 'CWE-287');
  });
  test(`${file}: refusing the missing key is silent`, () => {
    assert.deepEqual(scan(file, read('clean', file)), []);
  });
}

test('Python and PHP fallbacks are recognised; a non-key name and a value that never reaches a MAC are not', () => {
  assert.equal(scan('a.py', "def sign(msg, cfg):\n    key = cfg.secret_key or b''\n    return hmac.new(key, msg, 'sha256').digest()\n").length, 1);
  assert.equal(scan('a.php', "<?php\nfunction s($d, $c) {\n    $secret = $c['secret'] ?? '';\n    return hash_hmac('sha256', $d, $secret);\n}\n").length, 1);
  assert.deepEqual(scan('a.rb', "def label(name)\n  name ||= ''\n  sign(name)\nend\n"), []);
  assert.deepEqual(scan('a.rb', "def show(key)\n  key ||= ''\n  puts key\nend\n"), []);
});

test('an emptiness check between the fallback and the MAC silences it, but one in a rescue after it does not', () => {
  assert.deepEqual(scan('a.rb', "def sign(d, key)\n  key ||= ''\n  raise 'no key' if key.empty?\n  OpenSSL::HMAC.digest('SHA256', key, d)\nend\n"), []);
  assert.equal(scan('a.rb', "def sign(d, key)\n  key ||= ''\n  OpenSSL::HMAC.digest('SHA256', key, d)\nrescue StandardError\n  raise 'x' if key == ''\nend\n").length, 1);
});
