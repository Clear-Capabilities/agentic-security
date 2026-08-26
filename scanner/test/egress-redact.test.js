// Outbound-payload content redaction (assurance-hardening PRD FR-603).
//
// policy.js (FR-601/602) decides whether a call may leave the machine at
// all; this file tests the content-level companion — what is allowed to be
// IN the payload once a call is already permitted. Four categories:
// proprietary-path (whole-span), secrets (delegates to the already-tested
// llm-validator/redact.js), PII/PHI/PCI/FIN (delegates to the already-tested
// dataflow/privacy-taxonomy.js vocabulary), and operator-defined
// customer-data patterns.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import {
  redactPayload, redactPii, redactCustomerData, isProprietaryPath, _internals,
} from '../src/egress/redact.js';

// ---------------------------------------------------------------------------
// redactPii
// ---------------------------------------------------------------------------

test('redactPii: an SSN-shaped field value is redacted, key/operator/quotes survive', () => {
  const { text, redactions } = redactPii(`const ssn = "123-45-6789";`);
  assert.equal(redactions, 1);
  assert.equal(text, `const ssn = "[REDACTED-PII]";`);
  assert.ok(!text.includes('123-45-6789'));
});

test('redactPii: a PHI field (medication) is redacted', () => {
  const { text, redactions } = redactPii(`const medication = 'ibuprofen 400mg';`);
  assert.equal(redactions, 1);
  assert.ok(!text.includes('ibuprofen'));
});

test('redactPii: a PCI field (credit_card_number) is redacted', () => {
  const { text, redactions } = redactPii(`credit_card_number: "4111111111111111"`);
  assert.equal(redactions, 1);
  assert.ok(!text.includes('4111111111111111'));
});

test('redactPii: CREDENTIALS class is skipped — that is redactSecrets\' job, not this pass\'', () => {
  const { text, redactions } = redactPii(`const password = "hunter2superlongvalue";`);
  assert.equal(redactions, 0, 'PII pass must not touch credentials — avoids a confusing double-placeholder on the same span');
  assert.ok(text.includes('hunter2superlongvalue'), 'left for the secrets pass, which redactPayload runs first');
});

test('redactPii: ordinary code with no PII-shaped field is unchanged', () => {
  const { text, redactions } = redactPii(`function add(a, b) { return a + b; }`);
  assert.equal(redactions, 0);
  assert.equal(text, `function add(a, b) { return a + b; }`);
});

test('redactPii: non-string / empty input degrades to empty string, never throws', () => {
  assert.deepEqual(redactPii(null), { text: '', redactions: 0 });
  assert.deepEqual(redactPii(''), { text: '', redactions: 0 });
});

test('redactPii: a taxonomy field pattern with an internal capturing group (email/phone) still redacts correctly (regression: positional backreferences shift when an alternative has its own group)', () => {
  const { text, redactions } = redactPii(`const email = "user@example.com"; const phone = "555-0100";`);
  assert.equal(redactions, 2);
  assert.ok(!text.includes('user@example.com'));
  assert.ok(!text.includes('555-0100'));
  assert.match(text, /const email = "\[REDACTED-PII\]";/);
  assert.match(text, /const phone = "\[REDACTED-PII\]";/);
});

test('redactPii: an operator-supplied custom taxonomy class is honoured (FR-402 customization reused, not a parallel vocabulary)', () => {
  const taxonomy = { INTERNAL_ID: { severity: 'medium', patterns: ['\\bemployee[_-]?id\\b'] } };
  const { text, redactions } = redactPii(`const employee_id = "E-99213";`, { taxonomy });
  assert.equal(redactions, 1);
  assert.ok(!text.includes('E-99213'));
});

// ---------------------------------------------------------------------------
// redactCustomerData
// ---------------------------------------------------------------------------

test('redactCustomerData: no patterns configured is a no-op (category has no safe built-in default)', () => {
  const { text, redactions } = redactCustomerData('customer CUST-000123 called in', { patterns: [] });
  assert.equal(redactions, 0);
  assert.equal(text, 'customer CUST-000123 called in');
});

test('redactCustomerData: an operator-configured pattern is redacted', () => {
  const { text, redactions } = redactCustomerData('customer CUST-000123 called in', { patterns: [String.raw`CUST-\d{6}`] });
  assert.equal(redactions, 1);
  assert.ok(!text.includes('CUST-000123'));
  assert.ok(text.includes('[REDACTED-CUSTOMER-DATA]'));
});

test('redactCustomerData: an invalid operator regex is skipped, not thrown', () => {
  assert.doesNotThrow(() => redactCustomerData('some text', { patterns: ['(unterminated'] }));
});

// ---------------------------------------------------------------------------
// isProprietaryPath / proprietary-path whole-span replacement
// ---------------------------------------------------------------------------

test('isProprietaryPath: matches a configured glob, no-op with none configured', () => {
  assert.equal(isProprietaryPath('internal/proprietary/secret.js', { proprietaryPaths: ['internal/proprietary/**'] }), true);
  assert.equal(isProprietaryPath('src/app.js', { proprietaryPaths: ['internal/proprietary/**'] }), false);
  assert.equal(isProprietaryPath('internal/proprietary/secret.js', { proprietaryPaths: [] }), false);
  assert.equal(isProprietaryPath(null, { proprietaryPaths: ['**'] }), false, 'no path supplied — nothing to match, never throws');
});

// ---------------------------------------------------------------------------
// redactPayload — the full pipeline, in order
// ---------------------------------------------------------------------------

test('redactPayload: proprietary path short-circuits every other pass — whole span replaced, nothing else evaluated', () => {
  const text = 'const apiKey = "sk-live-abcdefghijklmnopqrstuvwx0123456789"; const ssn = "123-45-6789";';
  const { text: out, redactions, categories } = redactPayload({
    text, filePath: 'internal/proprietary/secret.js',
    policy: { proprietaryPaths: ['internal/proprietary/**'] },
  });
  assert.equal(out, '[REDACTED-PROPRIETARY-CONTENT]');
  assert.equal(redactions, 1);
  assert.deepEqual(categories, { proprietaryPath: 1, secrets: 0, pii: 0, customerData: 0 });
  assert.ok(!out.includes('sk-live'), 'the raw secret text must not survive even as an unredacted fragment');
});

test('redactPayload: secrets + PII + customer-data all apply together on an allowed path', () => {
  const text = 'const apiKey = "sk-live-abcdefghijklmnopqrstuvwx0123456789"; const ssn = "123-45-6789"; // ref CUST-000123';
  const { text: out, redactions, categories } = redactPayload({
    text, filePath: 'src/app.js',
    policy: { customerDataPatterns: [String.raw`CUST-\d{6}`] },
  });
  assert.equal(redactions, 3);
  assert.equal(categories.secrets, 1);
  assert.equal(categories.pii, 1);
  assert.equal(categories.customerData, 1);
  assert.ok(!out.includes('sk-live-abcdefghijklmnopqrstuvwx0123456789'));
  assert.ok(!out.includes('123-45-6789'));
  assert.ok(!out.includes('CUST-000123'));
});

test('redactPayload: redactPii=false in policy disables the PII pass only — secrets still redacted', () => {
  const text = 'const apiKey = "sk-live-abcdefghijklmnopqrstuvwx0123456789"; const ssn = "123-45-6789";';
  const { categories } = redactPayload({ text, filePath: 'src/app.js', policy: { redactPii: false } });
  assert.equal(categories.pii, 0);
  assert.equal(categories.secrets, 1);
});

test('redactPayload: clean code with none of the four categories present is unchanged', () => {
  const text = 'function add(a, b) { return a + b; }';
  const { text: out, redactions } = redactPayload({ text, filePath: 'src/math.js' });
  assert.equal(out, text);
  assert.equal(redactions, 0);
});

test('redactPayload: non-string / empty text degrades safely, never throws', () => {
  assert.deepEqual(redactPayload({ text: null }), { text: '', redactions: 0, categories: { proprietaryPath: 0, secrets: 0, pii: 0, customerData: 0 } });
  assert.deepEqual(redactPayload({ text: '' }), { text: '', redactions: 0, categories: { proprietaryPath: 0, secrets: 0, pii: 0, customerData: 0 } });
  assert.deepEqual(redactPayload({}), { text: '', redactions: 0, categories: { proprietaryPath: 0, secrets: 0, pii: 0, customerData: 0 } });
});

test('redactPayload: reads proprietaryPaths/customerDataPatterns/redactPii from egress-policy.yml when policy is not supplied directly', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'egress-redact-'));
  try {
    fs.mkdirSync(path.join(dir, '.agentic-security'), { recursive: true });
    fs.writeFileSync(
      path.join(dir, '.agentic-security', 'egress-policy.yml'),
      'proprietaryPaths:\n  - "internal/**"\ncustomerDataPatterns:\n  - "CUST-\\\\d{6}"\n',
    );
    const r1 = redactPayload({ text: 'secret sauce', filePath: 'internal/x.js', scanRoot: dir });
    assert.equal(r1.text, '[REDACTED-PROPRIETARY-CONTENT]');

    const r2 = redactPayload({ text: 'ref CUST-000123 in the code', filePath: 'src/app.js', scanRoot: dir });
    assert.equal(r2.categories.customerData, 1);
    assert.ok(!r2.text.includes('CUST-000123'));
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('_internals exposes the placeholder constants used by all four categories', () => {
  assert.equal(typeof _internals.PROPRIETARY_PLACEHOLDER, 'string');
  assert.equal(typeof _internals.PII_PLACEHOLDER, 'string');
  assert.equal(typeof _internals.CUSTOMER_DATA_PLACEHOLDER, 'string');
});
