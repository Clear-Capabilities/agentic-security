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

// Stage 4 correctness audit: every other secret detector in this codebase
// (scanCredentials, scanEntropySecrets, secret-history.js) uses the
// canonical family 'hardcoded-secret' — the key attack-taxonomy.js,
// compliance-policy.js, fix-style-mirror.js, persona-prioritization.js,
// threat-model-auto.js, time-to-fix.js, and risk-dollars.js all index by.
// secret-concat.js set the non-standard 'secret' instead, silently opting
// every split-concatenation finding out of ATT&CK/D3FEND mapping,
// compliance-control credit, fix-style hints, threat-actor weighting,
// STRIDE categorization, effort estimation, and dollar-risk modeling —
// even though these are some of the highest-intent findings (a secret
// deliberately split to evade detection).
test('family is the canonical "hardcoded-secret", not a detector-specific value', () => {
  const findings = s('cfg.js', "const AWS_ACCESS_KEY = 'AKIA' + 'IOSFODNN7EXAMPLE';");
  assert.ok(findings.length >= 1);
  for (const f of findings) assert.equal(f.family, 'hardcoded-secret');
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
