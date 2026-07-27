// Layer-3 validator prompt hardening: redact live-looking credentials out of
// the code excerpt/snippet BEFORE they reach the model API. Complements the
// existing prompt-injection hardening in src/llm-validator/index.js — this
// module protects against a different leak: real secrets sitting in the
// scanned source getting shipped off-box in a validation request.
//
// R10. See scanner/src/llm-validator/redact.js.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { redactSecrets } from '../src/llm-validator/redact.js';
import { _internal } from '../src/llm-validator/index.js';

const { renderPrompt } = _internal;

// ---------------------------------------------------------------------------
// Direction 1: each secret class is redacted, structure survives.
// ---------------------------------------------------------------------------

test('redactSecrets: apiKey assignment — value gone, structure survives', () => {
  const src = `const apiKey = "sk-live-1234567890abcdef1234567890abcdef";`;
  const { text, redactions } = redactSecrets(src);
  assert.ok(redactions >= 1, 'expected at least one redaction');
  assert.ok(!text.includes('sk-live-1234567890abcdef1234567890abcdef'), 'key value must be gone');
  assert.match(text, /const apiKey = "\[REDACTED-SECRET\]";/, 'variable name/operator/quotes/call-shape must survive');
});

test('redactSecrets: password in a connection string is stripped, host/user survive', () => {
  const src = `const dbUrl = "postgres://admin:S3cr3tP4ssw0rd!@db.example.com:5432/mydb";`;
  const { text, redactions } = redactSecrets(src);
  assert.ok(redactions >= 1);
  assert.ok(!text.includes('S3cr3tP4ssw0rd!'), 'password must be gone');
  assert.ok(text.includes('admin'), 'username should survive');
  assert.ok(text.includes('db.example.com:5432/mydb'), 'host/db should survive');
});

test('redactSecrets: bearer token in an Authorization header is stripped', () => {
  const src = `headers: { Authorization: 'Bearer ab12cd34ef56gh78ij90kl12mn34op56qr78st90' }`;
  const { text, redactions } = redactSecrets(src);
  assert.ok(redactions >= 1);
  assert.ok(!text.includes('ab12cd34ef56gh78ij90kl12mn34op56qr78st90'), 'bearer blob must be gone');
  assert.ok(text.includes('Authorization'), 'header name should survive');
  assert.ok(text.includes('Bearer'), 'scheme should survive');
});

test('redactSecrets: PEM private key block is stripped, BEGIN/END markers survive', () => {
  const src = [
    'const key = `',
    '-----BEGIN RSA PRIVATE KEY-----',
    'MIIEpAIBAAKCAQEA1c7+9z5Pad7OejecsQ0bu3aumnAxuNbaBzChcXteipDrjkVZ',
    'zBl+E0aQxSp1vE2rGgLqPvKKKR8vzKgH5DdKMV6t99pnwBqp2WPWqB0PqrX3EJmb',
    '-----END RSA PRIVATE KEY-----',
    '`;',
  ].join('\n');
  const { text, redactions } = redactSecrets(src);
  assert.ok(redactions >= 1);
  assert.ok(!text.includes('MIIEpAIBAAKCAQEA1c7+9z5Pad7OejecsQ0bu3aumnAxuNbaBzChcXteipDrjkVZ'));
  assert.ok(text.includes('-----BEGIN RSA PRIVATE KEY-----'), 'BEGIN marker should survive');
  assert.ok(text.includes('-----END RSA PRIVATE KEY-----'), 'END marker should survive');
});

test('redactSecrets: a long high-entropy string literal (no secret-ish key name) is redacted', () => {
  const src = `const blob = "Nk2mQzX9vLpR7tYbW3cJ8hF5aD1sG6eK0oU4iZ2xC9yQwErTyU";`;
  const { text, redactions } = redactSecrets(src);
  assert.ok(redactions >= 1);
  assert.ok(!text.includes('Nk2mQzX9vLpR7tYbW3cJ8hF5aD1sG6eK0oU4iZ2xC9yQwErTyU'));
  assert.match(text, /const blob = "\[REDACTED-SECRET\]";/);
});

test('redactSecrets: private_key / access_key / client_secret assignment forms', () => {
  const cases = [
    `private_key = "AbCdEfGhIjKlMnOpQrStUvWxYz123456"`,
    `access_key: "AKIAABCDEFGHIJKLMNOP"`,
    `client_secret = 'zXyWvUtSrQpOnMlKjIhGfEdCbA987654'`,
  ];
  for (const src of cases) {
    const { text, redactions } = redactSecrets(src);
    assert.ok(redactions >= 1, `expected redaction for: ${src}`);
    assert.ok(text.includes('[REDACTED-SECRET]'), `expected placeholder for: ${src}`);
  }
});

// ---------------------------------------------------------------------------
// Direction 2: ordinary code, no secrets, passes through byte-for-byte.
// ---------------------------------------------------------------------------

test('redactSecrets: ordinary non-secret code is unchanged (redactions === 0)', () => {
  const src = [
    'const tokenizer = new Tokenizer();',
    'password_field.label = "Password";',
    'const dataUri = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAUA";',
    'const commitSha = "a94a8fe5ccb19ba61c4c0873d391e987982fbbd";',
    '// check authorization for this endpoint before granting access',
    'function add(a, b) { return a + b; }',
    'const greeting = "hello world";',
  ].join('\n');
  const { text, redactions } = redactSecrets(src);
  assert.equal(redactions, 0, 'ordinary code must not be touched');
  assert.equal(text, src, 'ordinary code must pass through unchanged');
});

test('redactSecrets: empty string and non-secret single line', () => {
  assert.deepEqual(redactSecrets(''), { text: '', redactions: 0 });
  const { text, redactions } = redactSecrets('const x = 1;');
  assert.equal(redactions, 0);
  assert.equal(text, 'const x = 1;');
});

// ---------------------------------------------------------------------------
// Direction 3: integration — the prompt-building path never leaks the key.
// ---------------------------------------------------------------------------

test('renderPrompt: a live-looking key in the source file never reaches the built prompt', () => {
  const secretValue = 'sk-live-abcdefghijklmnopqrstuvwx0123456789';
  const fileContents = {
    'app/config.js': [
      '// app config',
      'function setup() {',
      `  const apiKey = "${secretValue}";`,
      '  return apiKey;',
      '}',
    ].join('\n'),
  };
  const finding = {
    file: 'app/config.js',
    line: 3,
    vuln: 'Hardcoded Credential',
    severity: 'high',
    cwe: 'CWE-798',
    snippet: `const apiKey = "${secretValue}";`,
  };
  const prompt = renderPrompt(finding, fileContents, 'challenge1234567', 'nonceabcdef123456');
  assert.ok(!prompt.includes(secretValue), 'secret value must not appear anywhere in the built prompt');
  assert.ok(prompt.includes('apiKey'), 'variable name should still be visible to the validator');
});
