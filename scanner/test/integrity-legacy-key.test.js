// The legacy hostname-derived key is GONE, and must stay gone.
//
// It was `sha256('agentic-security:last-scan:v1' + ':' + os.hostname())`. The
// salt is a constant in published source and a hostname is not a secret, so the
// "signature" was forgeable by anyone who could read one — which the 0.62.0
// changelog said in as many words when it introduced the per-install key:
// "hostname-derived and publicly forgeable in CI / containers". The legacy path
// was kept "for one release to migrate existing signed scans" and was still
// accepted at 0.132.0, seventy minor releases later.
//
// It mattered because `rule-overrides.js` gates `disable:` on `verifyLastScan`:
// a forged signature silently switched off arbitrary detectors and the scan
// reported clean. Demonstrated end to end before removal — a command-injection
// finding went from 1 reported to 0.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';

import { signLastScan, verifyLastScan, keyProvenance, _resetKeyCacheForTests }
  from '../src/posture/integrity.js';

const LEGACY_SALT = 'agentic-security:last-scan:v1';
const legacyKey = () => crypto.createHash('sha256').update(`${LEGACY_SALT}:${os.hostname()}`).digest();

function sigFile(body, key) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'intg-'));
  const fp = path.join(d, 'x.sig');
  fs.writeFileSync(fp, crypto.createHmac('sha256', key).update(body).digest('hex'));
  return { fp, dir: d };
}

test('a signature forged from the hostname is REJECTED', () => {
  const body = 'disable:\n  - Command Injection\n';
  const { fp, dir } = sigFile(body, legacyKey());
  try {
    assert.equal(verifyLastScan(body, fp), false,
      'the publicly-forgeable legacy key is accepted again — this is the exact vulnerability '
      + '0.62.0 claimed to fix, and it silently disables detectors');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('a signature under the real per-install key still verifies', () => {
  // Removing the fallback must not break legitimate signing.
  const body = 'disable:\n  - Command Injection\n';
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'intg-ok-'));
  try {
    const fp = path.join(d, 'x.sig');
    fs.writeFileSync(fp, signLastScan(body));
    assert.equal(verifyLastScan(body, fp), true);
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});

test('a tampered body fails even with a valid signature file', () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'intg-tam-'));
  try {
    const fp = path.join(d, 'x.sig');
    fs.writeFileSync(fp, signLastScan('original'));
    assert.equal(verifyLastScan('tampered', fp), false);
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});

test('an absent signature is null, not true — call sites decide fail-closed', () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'intg-abs-'));
  try {
    assert.equal(verifyLastScan('body', path.join(d, 'nope.sig')), null);
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});

test('the legacy salt no longer appears in the module source', () => {
  // A regression here would mean someone reintroduced the key rather than only
  // the constant, so the check is deliberately blunt.
  const src = fs.readFileSync(
    new URL('../src/posture/integrity.js', import.meta.url), 'utf8');
  assert.ok(!/_legacyHostnameKey\s*\(/.test(src.replace(/\/\/.*$/gm, '')),
    'the legacy hostname key function is back in live code');
});

// --- key provenance (P1-3) -------------------------------------------------

test('key provenance reports env when the key comes from the environment', () => {
  const saved = process.env.AGENTIC_SECURITY_HMAC_KEY;
  try {
    _resetKeyCacheForTests();
    process.env.AGENTIC_SECURITY_HMAC_KEY = 'ab'.repeat(32);
    signLastScan('x'); // forces key resolution
    assert.equal(keyProvenance(), 'env',
      'an env-supplied key must be reported as such — whoever set it could sign anything');
  } finally {
    if (saved === undefined) delete process.env.AGENTIC_SECURITY_HMAC_KEY;
    else process.env.AGENTIC_SECURITY_HMAC_KEY = saved;
    _resetKeyCacheForTests();
  }
});

test('key provenance reports a real source once resolved', () => {
  const saved = process.env.AGENTIC_SECURITY_HMAC_KEY;
  try {
    _resetKeyCacheForTests();
    delete process.env.AGENTIC_SECURITY_HMAC_KEY;
    signLastScan('x');
    assert.ok(['per-install', 'per-install-new', 'ephemeral'].includes(keyProvenance()),
      `unexpected provenance: ${keyProvenance()}`);
  } finally {
    if (saved !== undefined) process.env.AGENTIC_SECURITY_HMAC_KEY = saved;
    _resetKeyCacheForTests();
  }
});
