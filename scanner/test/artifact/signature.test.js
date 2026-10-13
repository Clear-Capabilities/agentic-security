import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { verifyImageSignature, verifyProvenanceAttestation, SIGNATURE_STATES } from '../../src/artifact/signature.js';

const DIGEST = 'sha256:' + 'a'.repeat(64);

function ed25519Pair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return { publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }), privateKey };
}

function ecdsaPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return { publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }), privateKey };
}

test('SIG/0: SIGNATURE_STATES is exactly the four PRD-named values, frozen', () => {
  assert.deepEqual([...SIGNATURE_STATES], ['verified', 'invalid', 'missing', 'unavailable']);
  assert.ok(Object.isFrozen(SIGNATURE_STATES));
});

test('SIG/1a: no signature/key supplied reads "missing", never "verified"', () => {
  const r = verifyImageSignature({ digest: DIGEST, signature: null, publicKeyPem: null });
  assert.equal(r.state, 'missing');
});

test('SIG/1b: a real Ed25519 signature over the digest verifies', () => {
  const { publicKeyPem, privateKey } = ed25519Pair();
  const signature = crypto.sign(null, Buffer.from(DIGEST, 'utf8'), privateKey);
  const r = verifyImageSignature({ digest: DIGEST, signature, publicKeyPem });
  assert.equal(r.state, 'verified');
  assert.equal(r.keyType, 'ed25519');
});

test('SIG/1c: a real ECDSA P-256 signature over the digest verifies', () => {
  const { publicKeyPem, privateKey } = ecdsaPair();
  const signature = crypto.sign('sha256', Buffer.from(DIGEST, 'utf8'), privateKey);
  const r = verifyImageSignature({ digest: DIGEST, signature, publicKeyPem });
  assert.equal(r.state, 'verified');
});

test('SIG/1d: a signature over a DIFFERENT digest than claimed is "invalid", not "verified"', () => {
  const { publicKeyPem, privateKey } = ed25519Pair();
  const signature = crypto.sign(null, Buffer.from('sha256:' + 'b'.repeat(64), 'utf8'), privateKey);
  const r = verifyImageSignature({ digest: DIGEST, signature, publicKeyPem });
  assert.equal(r.state, 'invalid');
});

test('SIG/1e: a signature verified under the WRONG public key is "invalid"', () => {
  const { privateKey } = ed25519Pair();
  const { publicKeyPem: wrongKey } = ed25519Pair();
  const signature = crypto.sign(null, Buffer.from(DIGEST, 'utf8'), privateKey);
  const r = verifyImageSignature({ digest: DIGEST, signature, publicKeyPem: wrongKey });
  assert.equal(r.state, 'invalid');
});

test('SIG/1f: a malformed public key is reported invalid, never thrown past the function', () => {
  const r = verifyImageSignature({ digest: DIGEST, signature: Buffer.from('x'), publicKeyPem: 'not a pem' });
  assert.equal(r.state, 'invalid');
});

test('SIG/1g: no digest at all reads "unavailable" (nothing to check against)', () => {
  const r = verifyImageSignature({ digest: null, signature: Buffer.from('x'), publicKeyPem: 'y' });
  assert.equal(r.state, 'unavailable');
});

function buildEnvelope({ digestHex = 'a'.repeat(64), predicateType = 'https://slsa.dev/provenance/v1', payloadType = 'application/vnd.in-toto+json', privateKey, wrongPrivateKey } = {}) {
  const statement = {
    _type: 'https://in-toto.io/Statement/v1',
    subject: [{ name: 'example', digest: { sha256: digestHex } }],
    predicateType,
    predicate: { builder: { id: 'https://example.com/builder' } },
  };
  const payload = Buffer.from(JSON.stringify(statement), 'utf8');
  const signatures = [];
  if (privateKey) {
    const pae = Buffer.concat([
      Buffer.from(`DSSEv1 ${Buffer.from(payloadType).length} ${payloadType} ${payload.length} `, 'ascii'),
      payload,
    ]);
    const keyType = privateKey.asymmetricKeyType;
    const algo = (keyType === 'ed25519' || keyType === 'ed448') ? null : 'sha256';
    signatures.push({ sig: crypto.sign(algo, pae, privateKey).toString('base64') });
  }
  if (wrongPrivateKey) {
    signatures.push({ sig: crypto.sign(null, Buffer.from('garbage'), wrongPrivateKey).toString('base64') });
  }
  return { payloadType, payload: payload.toString('base64'), signatures };
}

test('ATT/1a: no attestation supplied reads "missing"', () => {
  const r = verifyProvenanceAttestation({ digest: DIGEST, envelope: null, publicKeyPem: null });
  assert.equal(r.state, 'missing');
});

test('ATT/1b: a real DSSE-signed SLSA attestation whose subject matches verifies', () => {
  const { publicKeyPem, privateKey } = ed25519Pair();
  const envelope = buildEnvelope({ digestHex: 'a'.repeat(64), privateKey });
  const r = verifyProvenanceAttestation({ digest: DIGEST, envelope, publicKeyPem });
  assert.equal(r.state, 'verified');
  assert.equal(r.isSlsa, true);
});

test('ATT/1c: a subject digest mismatch is "invalid" even with a valid signature', () => {
  const { publicKeyPem, privateKey } = ed25519Pair();
  const envelope = buildEnvelope({ digestHex: 'f'.repeat(64), privateKey }); // different image
  const r = verifyProvenanceAttestation({ digest: DIGEST, envelope, publicKeyPem });
  assert.equal(r.state, 'invalid');
});

test('ATT/1d: a matching subject but no public key supplied reads "unavailable", never "verified"', () => {
  const { privateKey } = ed25519Pair();
  const envelope = buildEnvelope({ digestHex: 'a'.repeat(64), privateKey });
  const r = verifyProvenanceAttestation({ digest: DIGEST, envelope, publicKeyPem: null });
  assert.equal(r.state, 'unavailable');
});

test('ATT/1e: a matching subject with a signature from the WRONG key is "invalid"', () => {
  const { privateKey } = ed25519Pair();
  const { publicKeyPem: wrongKey } = ed25519Pair();
  const envelope = buildEnvelope({ digestHex: 'a'.repeat(64), privateKey });
  const r = verifyProvenanceAttestation({ digest: DIGEST, envelope, publicKeyPem: wrongKey });
  assert.equal(r.state, 'invalid');
});

test('ATT/1f: a non-SLSA predicateType is still verifiable, but isSlsa is false', () => {
  const { publicKeyPem, privateKey } = ed25519Pair();
  const envelope = buildEnvelope({ digestHex: 'a'.repeat(64), privateKey, predicateType: 'https://example.com/custom-predicate/v1' });
  const r = verifyProvenanceAttestation({ digest: DIGEST, envelope, publicKeyPem });
  assert.equal(r.state, 'verified');
  assert.equal(r.isSlsa, false);
});

test('ATT/2a: a non-DSSE-shaped envelope is rejected as invalid, not silently coerced', () => {
  const r = verifyProvenanceAttestation({ digest: DIGEST, envelope: { random: 'object' }, publicKeyPem: null });
  assert.equal(r.state, 'invalid');
});

test('ATT/2b: malformed base64 payload is rejected as invalid', () => {
  const r = verifyProvenanceAttestation({ digest: DIGEST, envelope: { payloadType: 'x', payload: '!!!not-base64!!!', signatures: [] }, publicKeyPem: null });
  assert.equal(r.state, 'invalid');
});

test('ATT/2c: a payload decoding to non-in-toto JSON is rejected', () => {
  const payload = Buffer.from(JSON.stringify({ not: 'in-toto' })).toString('base64');
  const r = verifyProvenanceAttestation({ digest: DIGEST, envelope: { payloadType: 'x', payload, signatures: [] }, publicKeyPem: null });
  assert.equal(r.state, 'invalid');
});
