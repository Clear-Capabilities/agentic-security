// Tests for the post-quantum crypto migration scanner and plan emitter.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as path from 'node:path';
import * as os from 'node:os';
import { fileURLToPath } from 'node:url';

import { scanPqc } from '../src/sast/post-quantum-crypto.js';
import { buildMigrationPlan, persistMigrationPlan } from '../src/posture/pqc-migration-plan.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const FIX = path.join(__dirname, 'fixtures', 'pqc-migration');

function readFix(rel) {
  return fs.readFileSync(path.join(FIX, rel), 'utf8');
}

test('pqc: detects RSA generateKeyPair on JS, flagged HNDL on TLS context', () => {
  const src = readFix('vulnerable/rsa-key.js');
  const out = scanPqc('rsa-key.js', src);
  const keygen = out.find(f => f.subfamily === 'pqc-rsa-keygen');
  assert.ok(keygen, `expected rsa-keygen finding; got: ${out.map(f=>f.subfamily).join(',')}`);
  assert.equal(keygen.severity, 'high', 'TLS/HNDL context should bump severity');
  assert.equal(keygen.parser, 'PQC');
  assert.equal(keygen.cwe, 'CWE-327');
  assert.ok(keygen.pqcRecommendation?.primary?.includes('ML-DSA') || keygen.pqcRecommendation?.primary?.includes('ML-KEM'));
});

test('pqc: detects long-lived RS256 JWT', () => {
  const src = readFix('vulnerable/rsa-key.js');
  const out = scanPqc('rsa-key.js', src);
  assert.ok(out.some(f => f.subfamily === 'pqc-jwt-classical'), 'expected pqc-jwt-classical');
});

test('pqc: detects Python ec.generate_private_key + RSA OAEP', () => {
  const src = readFix('vulnerable/ecdh.py');
  const out = scanPqc('ecdh.py', src);
  assert.ok(out.some(f => f.subfamily === 'pqc-ecdh-kex'), 'ec.generate_private_key');
  assert.ok(out.some(f => f.subfamily === 'pqc-rsa-encrypt'), 'OAEP encrypt');
  assert.ok(out.some(f => f.subfamily === 'pqc-x25519'), 'X25519');
});

test('pqc: detects Java KeyPairGenerator RSA, ECDSA Signature, ECDH KeyAgreement', () => {
  const src = readFix('vulnerable/Signing.java');
  const out = scanPqc('Signing.java', src);
  const subs = new Set(out.map(f => f.subfamily));
  assert.ok(subs.has('pqc-rsa-keygen'));
  assert.ok(subs.has('pqc-ecdsa-sign'));
  assert.ok(subs.has('pqc-ecdh-kex'));
});

test('pqc: detects Go rsa.GenerateKey and ecdsa.GenerateKey', () => {
  const src = readFix('vulnerable/signer.go');
  const out = scanPqc('signer.go', src);
  assert.ok(out.some(f => f.subfamily === 'pqc-rsa-keygen'));
  assert.ok(out.some(f => f.subfamily === 'pqc-ecdsa-sign'));
});

test('pqc: detects C# RSA.Create, ECDsa.Create, ECDiffieHellman.Create', () => {
  const src = readFix('vulnerable/Crypto.cs');
  const out = scanPqc('Crypto.cs', src);
  const subs = new Set(out.map(f => f.subfamily));
  assert.ok(subs.has('pqc-rsa-keygen'));
  assert.ok(subs.has('pqc-ecdsa-sign'));
  assert.ok(subs.has('pqc-ecdh-kex'));
});

test('pqc: detects OpenSSL RSA_generate_key + EVP_PKEY_RSA in C', () => {
  const src = readFix('vulnerable/openssl.c');
  const out = scanPqc('openssl.c', src);
  assert.ok(out.some(f => f.subfamily === 'pqc-rsa-keygen'), 'RSA_generate_key');
  assert.ok(out.some(f => f.subfamily === 'pqc-rsa-sign'),   'EVP_PKEY_RSA');
});

test('pqc: clean files emit nothing', () => {
  for (const rel of ['clean/no-crypto.js', 'clean/symmetric.js']) {
    const out = scanPqc(rel, readFix(rel));
    assert.equal(out.length, 0, `expected 0 findings on ${rel}, got ${out.length}`);
  }
});

test('pqc: AGENTIC_SECURITY_NO_PQC=1 disables the detector', () => {
  process.env.AGENTIC_SECURITY_NO_PQC = '1';
  try {
    const out = scanPqc('rsa-key.js', readFix('vulnerable/rsa-key.js'));
    assert.equal(out.length, 0);
  } finally {
    delete process.env.AGENTIC_SECURITY_NO_PQC;
  }
});

test('pqc: migration plan aggregates findings and persists artifact', async () => {
  // Compose findings across files.
  const allFindings = [
    ...scanPqc('rsa-key.js', readFix('vulnerable/rsa-key.js')),
    ...scanPqc('Signing.java', readFix('vulnerable/Signing.java')),
    ...scanPqc('signer.go', readFix('vulnerable/signer.go')),
  ];
  assert.ok(allFindings.length >= 5);
  const plan = buildMigrationPlan(allFindings);
  assert.ok(plan, 'plan built');
  assert.equal(plan.summary.total, allFindings.length);
  assert.ok(plan.summary.filesAffected >= 3);
  assert.ok(plan.milestones.length === 4);

  const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'pqc-plan-'));
  try {
    persistMigrationPlan(tmp, plan);
    const jsonPath = path.join(tmp, '.agentic-security', 'pqc-migration-plan.json');
    const mdPath = path.join(tmp, '.agentic-security', 'pqc-migration-plan.md');
    assert.ok(fs.existsSync(jsonPath), 'JSON artifact written');
    assert.ok(fs.existsSync(mdPath), 'Markdown artifact written');
    const md = fs.readFileSync(mdPath, 'utf8');
    assert.ok(md.includes('post-quantum cryptography migration plan'.toLowerCase()) ||
              md.includes('Post-quantum cryptography migration plan'));
    assert.ok(md.includes('FIPS 203') || md.includes('ML-KEM'));
  } finally {
    await fsp.rm(tmp, { recursive: true, force: true });
  }
});

test('pqc: no plan when no pqc findings', () => {
  const plan = buildMigrationPlan([
    { family: 'sqli', file: 'a.js', line: 1 },
  ]);
  assert.equal(plan, null);
});
