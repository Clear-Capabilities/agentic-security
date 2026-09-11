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
// Direction 1b: unquoted `.env`/shell-export syntax + compound identifiers
// (premortem finding on the Ollama offline PRD, adversarial review 2026-09).
// Two DISTINCT gaps closed together since both were needed to actually stop
// the reported leak: KEY_VALUE_RE required a quote around the value at all
// (so `DB_PASSWORD=x` passed through untouched even before this fix), AND a
// plain `\b` treats `_` as a word character, so `password` never matched
// inside `DB_PASSWORD` in the first place — fixing only the quote
// requirement would still have missed every real-world `.env` name, since
// those are almost always `PREFIX_WORD`, not the bare word alone.
// ---------------------------------------------------------------------------

test('redactSecrets: unquoted .env-style KEY=value (the exact previously-documented gap) is now redacted', () => {
  const cases = [
    'DB_PASSWORD=SuperSecretPass123',
    'password=SuperSecretPass123',
    'export API_KEY=abc123def456ghi789',
  ];
  for (const src of cases) {
    const { text, redactions } = redactSecrets(src);
    assert.ok(redactions >= 1, `expected redaction for: ${src}`);
    assert.ok(!text.includes('SuperSecretPass123') && !text.includes('abc123def456ghi789'), `value must be gone for: ${src}`);
    assert.ok(text.includes('[REDACTED-SECRET]'), `expected placeholder for: ${src}`);
  }
});

test('redactSecrets: compound .env-style names (vendor/namespace prefix + secret word) redact in BOTH quoted and unquoted form', () => {
  const cases = [
    'STRIPE_API_KEY=sk_live_abcdefghijklmnop',
    'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIabcdef',
    'GITHUB_TOKEN=ghp_abcdef123456ghijkl',
    'JWT_SECRET=my-signing-secret-value',
    'const DB_PASSWORD = "SuperSecretPass123";',
    'STRIPE_API_KEY: "sk_live_abcdefghijklmnop"',
  ];
  for (const src of cases) {
    const { text, redactions } = redactSecrets(src);
    assert.ok(redactions >= 1, `expected redaction for: ${src}`);
    assert.ok(text.includes('[REDACTED-SECRET]'), `expected placeholder for: ${src}`);
  }
});

test('redactSecrets: unquoted form still respects the Bearer-scheme exception', () => {
  const src = 'authorization=Bearer abcdef123456ghijkl';
  const { text, redactions } = redactSecrets(src);
  assert.ok(redactions >= 1);
  assert.ok(text.includes('authorization=Bearer [REDACTED-SECRET]'), `scheme word must survive: ${text}`);
});

test('redactSecrets: unquoted matching is line-anchored — a mid-statement comparison or call is never mistaken for an .env assignment', () => {
  const cases = [
    'if (password == expected) {}',
    'if (password === expected) {}',
    'const x = 5; token != y;',
    'return this.password == null;',
  ];
  for (const src of cases) {
    const { text, redactions } = redactSecrets(src);
    assert.equal(redactions, 0, `must not redact: ${src}`);
    assert.equal(text, src, `must pass through unchanged: ${src}`);
  }
});

test('redactSecrets: the suffix-side boundary still holds for compound names — a field ABOUT a secret is not the secret itself', () => {
  const cases = [
    'PASSWORD_HINT=some_hint_text',
    'password_field = "hint"',
    'tokenExpiry=3600',
    'NODE_ENV=production',
  ];
  for (const src of cases) {
    const { text, redactions } = redactSecrets(src);
    assert.equal(redactions, 0, `must not redact: ${src}`);
    assert.equal(text, src, `must pass through unchanged: ${src}`);
  }
});

// ---------------------------------------------------------------------------
// Direction 1c: camelCase compounds, JSON-quoted keys, YAML colon syntax
// (second-round adversarial review of the FIRST redaction fix, 2026-09) — the
// original .env/compound-name fix closed the reported DB_PASSWORD-shaped gap
// but a fresh review found the SAME class of leak still reachable through
// three adjacent, at-least-as-common shapes.
// ---------------------------------------------------------------------------

test('redactSecrets: camelCase compound identifiers redact — the boundary fix generalized to snake_case/kebab-case originally, now to camelCase too', () => {
  const cases = [
    'authToken = "abcdef1234567890abcdef1234567890";',
    'apiSecret: "abcdef1234567890abcdef1234567890"',
    'userPassword="abcdef1234567890abcdef1234567890"',
    'myApiKey = "abcdef1234567890abcdef1234567890";',
  ];
  for (const src of cases) {
    const { text, redactions } = redactSecrets(src, { filePath: 'a.js' });
    assert.ok(redactions >= 1, `expected redaction for: ${src}`);
    assert.ok(text.includes('[REDACTED-SECRET]'), `expected placeholder for: ${src}`);
  }
});

test('redactSecrets: camelCase pass does NOT over-match a bare generic suffix ("Key" alone is not secret-shaped)', () => {
  const cases = [
    'primaryKey = "not-a-secret-just-a-db-key-name";',
    'cacheKey = "some-cache-identifier-value-here";',
    'sortKey = "some-sort-identifier-value-here";',
  ];
  for (const src of cases) {
    const { text, redactions } = redactSecrets(src, { filePath: 'a.js' });
    assert.equal(redactions, 0, `must not redact: ${src}`);
    assert.equal(text, src);
  }
});

test('redactSecrets: a JSON-quoted key ("password": "value") redacts — the key-name boundary logic already worked, the operator match did not consume the closing quote', () => {
  const src = '{"password": "SuperSecret123456", "username": "admin"}';
  const { text, redactions } = redactSecrets(src, { filePath: 'config.json' });
  assert.ok(redactions >= 1);
  assert.ok(!text.includes('SuperSecret123456'));
  assert.ok(text.includes('"username": "admin"'), 'unrelated fields must survive untouched');
});

test('redactSecrets: YAML unquoted key: value redacts ONLY when the file is actually YAML', () => {
  const yamlResult = redactSecrets('DB_PASSWORD: SuperSecret123456', { filePath: 'values.yaml' });
  assert.ok(yamlResult.redactions >= 1, 'a real .yaml file should redact this');
  assert.ok(!yamlResult.text.includes('SuperSecret123456'));

  const ymlResult = redactSecrets('DB_PASSWORD: SuperSecret123456', { filePath: 'values.yml' });
  assert.ok(ymlResult.redactions >= 1, '.yml extension must be recognized too');
});

test('redactSecrets: the YAML colon pattern is NEVER applied outside a .yml/.yaml file — this is what protects the existing TS-type-annotation and object-literal-key exclusions', () => {
  const cases = [
    ['DB_PASSWORD: SuperSecret123456', 'app.js'],
    ['password: string;', 'a.ts'],
    ['{ password: getSecret() }', 'a.js'],
    ['password: string;', undefined], // no filePath at all — must not accidentally enable YAML mode
  ];
  for (const [src, filePath] of cases) {
    const { text, redactions } = redactSecrets(src, { filePath });
    assert.equal(redactions, 0, `must not redact outside YAML: ${src} (${filePath})`);
    assert.equal(text, src);
  }
});

test('redactSecrets: filePath is optional — omitting it entirely still runs every non-YAML pass correctly', () => {
  const { text, redactions } = redactSecrets('apiKey = "abcdef1234567890abcdef1234567890";');
  assert.ok(redactions >= 1);
  assert.ok(text.includes('[REDACTED-SECRET]'));
});

// ---------------------------------------------------------------------------
// Direction 1d: split-string-concatenation secrets (third-round adversarial
// review, 2026-09) — `const secret = "Super" +\n "Secret123456";` used to
// redact only the FIRST segment, leaking the tail of the real value.
// ---------------------------------------------------------------------------

test('redactSecrets: a secret split across a string concatenation is fully redacted, not just its first segment', () => {
  const cases = [
    'const secret = "Super" +\n  "Secret123456";',
    'const apiKey = "sk_" + "live_" + "abcdef123456";',
    'const authToken = "abc" + "def123456";', // camelCase name + concatenation
  ];
  for (const src of cases) {
    const { text, redactions } = redactSecrets(src);
    assert.ok(redactions >= 1, `expected redaction for: ${src}`);
    assert.ok(!text.includes('Secret123456') && !text.includes('live_') && !text.includes('def123456'),
      `every segment's content must be gone, not just the first: ${text}`);
  }
});

test('redactSecrets: the concatenation pass never fires without a secret-shaped key name — ordinary string-building is untouched', () => {
  const src = 'const greeting = "hello" + " " + "world";';
  const { text, redactions } = redactSecrets(src);
  assert.equal(redactions, 0);
  assert.equal(text, src);
});

test('redactSecrets: a plain (non-concatenated) single-value assignment still redacts correctly after the concatenation-pass fix', () => {
  const { text, redactions } = redactSecrets('const apiKey = "single-value-no-concat-abcdefgh";');
  assert.ok(redactions >= 1);
  assert.ok(text.includes('[REDACTED-SECRET]'));
  assert.ok(!text.includes('single-value-no-concat-abcdefgh'));
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
