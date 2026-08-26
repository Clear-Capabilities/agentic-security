// FR-705 (assurance-hardening PRD): "Encrypt state classes marked
// confidential when an encryption provider is configured or required |
// Required encryption absence fails before sensitive state is written."

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as path from 'node:path';
import * as os from 'node:os';
import {
  loadEncryptionPolicy, maybeEncryptForWrite, maybeDecryptForRead,
  isEncryptedEnvelope, ENCRYPTION_MARKER, ENCRYPTION_POLICY_FILE,
} from '../src/posture/encryption-provider.js';
import { confidentialOf } from '../src/posture/artifact-registry.js';

function withIsolatedXdgHome(fn) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'encryption-provider-xdg-'));
  const prev = process.env.XDG_CONFIG_HOME;
  process.env.XDG_CONFIG_HOME = home;
  try { return fn(home); }
  finally {
    if (prev === undefined) delete process.env.XDG_CONFIG_HOME; else process.env.XDG_CONFIG_HOME = prev;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

async function mkSession() {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'encryption-provider-'));
  await fsp.mkdir(path.join(dir, '.agentic-security'), { recursive: true });
  await fsp.writeFile(path.join(dir, 'package.json'), '{"name":"t"}');
  return { dir, cleanup: () => fsp.rm(dir, { recursive: true, force: true }) };
}

// ── confidentialOf ────────────────────────────────────────────────────────

test('confidentialOf: compliance-evidence.json/.md are marked confidential; an ordinary artifact is not', () => {
  assert.equal(confidentialOf('compliance-evidence.json'), true);
  assert.equal(confidentialOf('compliance-evidence.md'), true);
  assert.equal(confidentialOf('last-scan.json'), false, 'last-scan.json is deliberately deferred to a later phase — see artifact-registry.js header');
  assert.equal(confidentialOf('totally-unknown-file.xyz'), false);
});

// ── loadEncryptionPolicy ──────────────────────────────────────────────────

test('loadEncryptionPolicy: no file present returns null (not configured, not required — the safe default)', async () => {
  const s = await mkSession();
  try { assert.equal(loadEncryptionPolicy(s.dir), null); } finally { await s.cleanup(); }
});

test('loadEncryptionPolicy: malformed YAML degrades to null, never throws', async () => {
  const s = await mkSession();
  try {
    fs.writeFileSync(path.join(s.dir, '.agentic-security', ENCRYPTION_POLICY_FILE), '{ not: valid: [[[');
    assert.doesNotThrow(() => loadEncryptionPolicy(s.dir));
    assert.equal(loadEncryptionPolicy(s.dir), null);
  } finally { await s.cleanup(); }
});

test('loadEncryptionPolicy: a well-formed policy loads provider and required correctly', async () => {
  const s = await mkSession();
  try {
    fs.writeFileSync(path.join(s.dir, '.agentic-security', ENCRYPTION_POLICY_FILE), 'provider: local-key\nrequired: true\n');
    assert.deepEqual(loadEncryptionPolicy(s.dir), { provider: 'local-key', required: true });
  } finally { await s.cleanup(); }
});

test('loadEncryptionPolicy: an unrecognised provider name is not silently accepted as configured', async () => {
  const s = await mkSession();
  try {
    fs.writeFileSync(path.join(s.dir, '.agentic-security', ENCRYPTION_POLICY_FILE), 'provider: some-future-kms\n');
    assert.equal(loadEncryptionPolicy(s.dir).provider, null);
  } finally { await s.cleanup(); }
});

// ── maybeEncryptForWrite: the fail-closed gate ───────────────────────────

test('maybeEncryptForWrite: a non-confidential artifact is always unchanged, regardless of policy', async () => {
  const s = await mkSession();
  try {
    fs.writeFileSync(path.join(s.dir, '.agentic-security', ENCRYPTION_POLICY_FILE), 'provider: local-key\nrequired: true\n');
    const r = maybeEncryptForWrite(s.dir, 'last-scan.json', 'plaintext');
    assert.equal(r.ok, true);
    assert.equal(r.content, 'plaintext');
    assert.equal(r.encrypted, false);
  } finally { await s.cleanup(); }
});

test('maybeEncryptForWrite: confidential + no policy at all -> unchanged (encryption is opt-in by default)', async () => {
  const s = await mkSession();
  try {
    const r = maybeEncryptForWrite(s.dir, 'compliance-evidence.json', '{"x":1}');
    assert.equal(r.ok, true);
    assert.equal(r.content, '{"x":1}');
    assert.equal(r.encrypted, false);
  } finally { await s.cleanup(); }
});

test('maybeEncryptForWrite: confidential + policy present but no provider + required:false -> unchanged', async () => {
  const s = await mkSession();
  try {
    fs.writeFileSync(path.join(s.dir, '.agentic-security', ENCRYPTION_POLICY_FILE), 'required: false\n');
    const r = maybeEncryptForWrite(s.dir, 'compliance-evidence.json', '{"x":1}');
    assert.equal(r.ok, true);
    assert.equal(r.encrypted, false);
  } finally { await s.cleanup(); }
});

test('maybeEncryptForWrite: confidential + no provider + required:true -> FAILS CLOSED, ok:false, content never touched', async () => {
  const s = await mkSession();
  try {
    fs.writeFileSync(path.join(s.dir, '.agentic-security', ENCRYPTION_POLICY_FILE), 'required: true\n');
    const r = maybeEncryptForWrite(s.dir, 'compliance-evidence.json', '{"x":1}');
    assert.equal(r.ok, false);
    assert.match(r.reason, /encryption is required/);
    assert.ok(!('content' in r), 'a failed gate must not hand back content for the caller to write anyway');
  } finally { await s.cleanup(); }
});

test('maybeEncryptForWrite: confidential + provider configured -> encrypts, produces a real envelope with the marker', async () => {
  await withIsolatedXdgHome(async () => {
    const s = await mkSession();
    try {
      fs.writeFileSync(path.join(s.dir, '.agentic-security', ENCRYPTION_POLICY_FILE), 'provider: local-key\n');
      const r = maybeEncryptForWrite(s.dir, 'compliance-evidence.json', '{"real":"document"}');
      assert.equal(r.ok, true);
      assert.equal(r.encrypted, true);
      const envelope = JSON.parse(r.content);
      assert.equal(envelope[ENCRYPTION_MARKER], true);
      assert.equal(envelope.provider, 'local-key');
      assert.ok(envelope.iv && envelope.tag && envelope.ciphertext);
      assert.ok(!r.content.includes('real'), 'the plaintext must not appear anywhere in the encrypted output');
    } finally { await s.cleanup(); }
  });
});

// ── maybeDecryptForRead / round trip ──────────────────────────────────────

test('maybeDecryptForRead: plain (non-envelope) content is returned unchanged', () => {
  assert.equal(maybeDecryptForRead('just some plaintext'), 'just some plaintext');
  assert.equal(maybeDecryptForRead('{"ordinary":"json"}'), '{"ordinary":"json"}');
});

test('encrypt then decrypt round trip recovers the exact original content, byte for byte', async () => {
  await withIsolatedXdgHome(async () => {
    const s = await mkSession();
    try {
      fs.writeFileSync(path.join(s.dir, '.agentic-security', ENCRYPTION_POLICY_FILE), 'provider: local-key\n');
      const original = JSON.stringify({ framework: 'nist-ai-600-1', controls: [{ id: 'A-1', status: 'compliant' }] }, null, 2);
      const encrypted = maybeEncryptForWrite(s.dir, 'compliance-evidence.json', original);
      assert.equal(encrypted.encrypted, true);
      const recovered = maybeDecryptForRead(encrypted.content);
      assert.equal(recovered, original);
    } finally { await s.cleanup(); }
  });
});

test('maybeDecryptForRead: a tampered ciphertext degrades to returning the raw envelope back, never throws', async () => {
  await withIsolatedXdgHome(async () => {
    const s = await mkSession();
    try {
      fs.writeFileSync(path.join(s.dir, '.agentic-security', ENCRYPTION_POLICY_FILE), 'provider: local-key\n');
      const encrypted = maybeEncryptForWrite(s.dir, 'compliance-evidence.json', '{"x":1}');
      const envelope = JSON.parse(encrypted.content);
      envelope.ciphertext = Buffer.from('tampered-bytes-not-real-ciphertext').toString('base64');
      const tampered = JSON.stringify(envelope);
      assert.doesNotThrow(() => maybeDecryptForRead(tampered));
      assert.equal(maybeDecryptForRead(tampered), tampered, 'an undecryptable envelope must be returned as-is, not silently emptied');
    } finally { await s.cleanup(); }
  });
});

test('isEncryptedEnvelope: recognises a real envelope and rejects ordinary objects', () => {
  assert.equal(isEncryptedEnvelope({ [ENCRYPTION_MARKER]: true, iv: 'x', tag: 'y', ciphertext: 'z' }), true);
  assert.equal(isEncryptedEnvelope({ ordinary: 'object' }), false);
  assert.equal(isEncryptedEnvelope(null), false);
  assert.equal(isEncryptedEnvelope('not an object'), false);
});

test('the encryption key persists across separate calls (a second call can decrypt what a first call encrypted)', async () => {
  await withIsolatedXdgHome(async () => {
    const s1 = await mkSession();
    const s2 = await mkSession();
    try {
      fs.writeFileSync(path.join(s1.dir, '.agentic-security', ENCRYPTION_POLICY_FILE), 'provider: local-key\n');
      fs.writeFileSync(path.join(s2.dir, '.agentic-security', ENCRYPTION_POLICY_FILE), 'provider: local-key\n');
      const encrypted = maybeEncryptForWrite(s1.dir, 'compliance-evidence.json', 'session-one-content');
      // Different project, SAME per-install key (keyed by XDG_CONFIG_HOME, not by project).
      const recovered = maybeDecryptForRead(encrypted.content);
      assert.equal(recovered, 'session-one-content');
    } finally { await s1.cleanup(); await s2.cleanup(); }
  });
});

// ── real integration: emitEvidenceJsonLd/emitEvidenceMarkdown ───────────

const SAMPLE_POLICY_YAML = `
framework: "SOC2-light"
version: "1.0"
controls:
  CC6.1:
    title: "No hardcoded credentials"
    requires:
      - finding-family: "hardcoded-secret"
        must-be: zero
`;

async function realComplianceReport(dir) {
  const { loadPolicy, verifyPolicy } = await import('../src/posture/compliance-policy.js');
  await fsp.writeFile(path.join(dir, '.agentic-security', 'compliance.policy.yml'), SAMPLE_POLICY_YAML);
  const policy = loadPolicy(dir);
  return verifyPolicy(policy, { scanRoot: dir, findings: [], repository: 'org/repo', commit: 'abc123' });
}

test('emitEvidenceJsonLd (real integration): with a local-key provider configured, compliance-evidence.json on disk is a real, undecodable-without-the-key envelope', async () => {
  await withIsolatedXdgHome(async () => {
    const s = await mkSession();
    try {
      fs.writeFileSync(path.join(s.dir, '.agentic-security', ENCRYPTION_POLICY_FILE), 'provider: local-key\n');
      const { emitEvidenceJsonLd } = await import('../src/posture/compliance-policy.js');
      const report = await realComplianceReport(s.dir);
      const returned = emitEvidenceJsonLd(report, s.dir);
      assert.equal(returned['@type'], 'ComplianceEvidence', 'the IN-MEMORY return value must stay the real, plaintext document regardless of at-rest encryption');

      const evidencePath = path.join(s.dir, '.agentic-security', 'compliance-evidence.json');
      assert.ok(fs.existsSync(evidencePath), 'expected the (encrypted) file to still be written');
      const raw = fs.readFileSync(evidencePath, 'utf8');
      const parsed = JSON.parse(raw);
      assert.equal(isEncryptedEnvelope(parsed), true, 'compliance-evidence.json must be a real encrypted envelope, not plaintext JSON-LD, when a provider is configured');
      assert.ok(!raw.includes('ComplianceEvidence'), 'the plaintext @type must not be visible anywhere in the on-disk file');

      const decrypted = JSON.parse(maybeDecryptForRead(raw));
      assert.equal(decrypted['@type'], 'ComplianceEvidence', 'decrypting on read must recover the real document');
    } finally { await s.cleanup(); }
  });
});

test('emitEvidenceJsonLd + emitEvidenceMarkdown (real integration): required:true with no provider configured means NEITHER file is written, with a clear stderr message', async () => {
  const s = await mkSession();
  try {
    fs.writeFileSync(path.join(s.dir, '.agentic-security', ENCRYPTION_POLICY_FILE), 'required: true\n');
    const { emitEvidenceJsonLd, emitEvidenceMarkdown } = await import('../src/posture/compliance-policy.js');
    const report = await realComplianceReport(s.dir);

    const origWrite = process.stderr.write.bind(process.stderr);
    let captured = '';
    process.stderr.write = (chunk) => { captured += chunk; return true; };
    try {
      emitEvidenceJsonLd(report, s.dir);
      emitEvidenceMarkdown(report, s.dir);
    } finally { process.stderr.write = origWrite; }

    assert.ok(!fs.existsSync(path.join(s.dir, '.agentic-security', 'compliance-evidence.json')), 'compliance-evidence.json must not be written when required encryption is absent');
    assert.ok(!fs.existsSync(path.join(s.dir, '.agentic-security', 'compliance-evidence.md')), 'compliance-evidence.md must not be written when required encryption is absent');
    assert.match(captured, /compliance-evidence\.json NOT written/);
    assert.match(captured, /compliance-evidence\.md NOT written/);
  } finally { await s.cleanup(); }
});
