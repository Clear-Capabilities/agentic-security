// Split-concatenation secret detector — PRD Tier 1.
// A credential split across concatenated literals to dodge contiguous-token
// secret regexes is reassembled and matched against provider prefixes.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanSecretConcat as s } from '../src/sast/secret-concat.js';

const hasSecret = (f) => f.some((x) => x.cwe === 'CWE-798');

test('AWS access key split across concat literals (JS)', () => {
  assert.ok(hasSecret(s('cfg.js', "const AWS_ACCESS_KEY = 'AKIA' + 'IOSFODNN7EXAMPLE';")));
});

test('GitHub token split across concat literals (Python)', () => {
  assert.ok(hasSecret(s('gh.py', "GITHUB_TOKEN = 'ghp' + '_1234567890abcdef1234567890abcdef12345678'")));
});

test('Stripe live key split across three literals (Python)', () => {
  assert.ok(hasSecret(s('pay.py', "STRIPE_KEY = 'sk' + '_live_51HxK0K2eZvKYlo2C0987654321' + 'abcdef'")));
});

test('credential-named field with a long joined literal flags even without a known prefix', () => {
  assert.ok(hasSecret(s('c.js', "const apiSecret = 'abcdefghij' + 'klmnopqrstuvwxyz0123';")));
});

test('benign concatenation does NOT flag', () => {
  assert.deepEqual(s('a.js', "const greeting = 'Hello, ' + 'world';"), []);
  assert.deepEqual(s('a.js', "const path = '/api/' + 'v1';"), []);
});

test('env-loaded secret (no literal concat) does NOT flag', () => {
  assert.deepEqual(s('cfg.js', 'const AWS_ACCESS_KEY = process.env.AWS_ACCESS_KEY;'), []);
});

test('non-code files are ignored', () => {
  assert.deepEqual(s('notes.txt', "key = 'AKIA' + 'IOSFODNN7EXAMPLE'"), []);
});
