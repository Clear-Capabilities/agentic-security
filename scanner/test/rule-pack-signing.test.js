// Rule-pack signing round trip. `signRulePack` once built an Ed25519 JWK with only the private `d`, which current Node rejects
// ("Invalid JWK OKP key"), so the documented `agentic-security-rule sign` workflow could not sign anything. A signature must be
// verifiable by the matching public key and by no other, and an edited pack must stop verifying.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { mkTestTmp } from './helpers/tmp.js';
import { keygen, signRulePack, verifyRulePack } from '../src/posture/rule-pack-signing.js';

const pack = (text = '- id: x/y\n  title: t\n') => { const f = path.join(mkTestTmp('sig-'), 'rule.yml'); fs.writeFileSync(f, text); return f; };

test('a signed pack verifies under its own key, and the signature is 64 raw bytes', () => {
  const k = keygen(); const f = pack();
  signRulePack(f, k.privateKey);
  assert.equal(fs.readFileSync(`${f}.sig`).length, 64);
  assert.deepEqual(verifyRulePack(f, [{ id: 'mine', alg: 'ed25519', publicKey: k.publicKey }]), { ok: true, keyId: 'mine' });
});

test('another key does not verify it, and an edited pack stops verifying', () => {
  const k = keygen(); const other = keygen(); const f = pack();
  signRulePack(f, k.privateKey);
  assert.equal(verifyRulePack(f, [{ id: 'other', alg: 'ed25519', publicKey: other.publicKey }]).ok, false);
  fs.writeFileSync(f, '- id: x/y\n  title: tampered\n');
  const r = verifyRulePack(f, [{ id: 'mine', alg: 'ed25519', publicKey: k.publicKey }]);
  assert.equal(r.ok, false); assert.equal(r.reason, 'bad-signature');
});

test('a private key that is not 32 bytes is refused with a clear message, and nothing is written', () => {
  const f = pack();
  assert.throws(() => signRulePack(f, Buffer.from('short').toString('base64')), /32 bytes/);
  assert.equal(fs.existsSync(`${f}.sig`), false);
});
