// Verified remediation M4-04: credential repair (FR-15). Source removal, re-encodings, replacement wiring against a host that accepts only
// the replacement, and the lifecycle a source change cannot complete. A skip is not a pass.
import { test, describe, before } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkRemoval, extractCredential, revoke } from '../../src/repair/credentials.js';
import { planRepair, runRepair } from '../../src/repair/coordinator.js';
import { queueProposer } from '../../src/repair/candidates.js';
import { validateProfile } from '../../src/repair/profile.js';
import { resolveAssuranceConfig } from '../../src/posture/assurance/config.js';
import { detectBackend } from '../../src/sandbox/capabilities.js';
import { probeControls, unmetControls } from '../../src/sandbox/control-probes.js';
import { DEFAULT_REQUIRED_CONTROLS } from '../../src/sandbox/trust-boundary.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FIX = path.join(HERE, '..', 'fixtures', 'repair', 'credential-client');
const ON = resolveAssuranceConfig({ env: {}, overrides: { features: { 'verification-oracles': true } } });
const V = 'acmepay_merchant_7Hq2xV9Lr4TzP0aB9cD7eF';
const LINE = `const API_KEY = '${V}';\n`;
const policy = { schema: 'agentic-security/repair-policy', schemaVersion: '1.0.0', budgets: { rounds: 3 } };

let ready = false; let whyNot = '';
before(async () => {
  const backend = detectBackend();
  const unmet = unmetControls(await probeControls({}), [...DEFAULT_REQUIRED_CONTROLS, 'network']);
  ready = (backend === 'userspace' || backend === 'namespace') && unmet.length === 0;
  whyNot = `SKIPPED, NOT PASSED: the trust boundary cannot run on this host (backend '${backend}'); the credential execution tests are UNVERIFIED here`;
});
const needs = (fn) => async (t) => (ready ? fn(t) : t.skip(whyNot));

const setup = () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'cred-'));
  fs.cpSync(FIX, root, { recursive: true });
  const profile = JSON.parse(fs.readFileSync(path.join(root, 'profile.json'), 'utf8'));
  const p = planRepair({ root, finding: { findingId: 'cred:payments', file: 'src/app.mjs' }, family: 'credential', profile, profileOrigin: 'repository-file' });
  assert.ok(p.plan, [...p.problems, ...p.blocked].join('; '));
  return { root, plan: p.plan, profile, original: fs.readFileSync(path.join(root, 'src', 'app.mjs'), 'utf8') };
};
const env = (o) => o.replace(LINE, () => 'const API_KEY = process.env.PAYMENTS_API_KEY;\n');

describe('[FR-15] removal and lifecycle (no execution)', () => {
  test('[AC-15.1] a re-encoded credential is not removed: base64, hex, reversed, split, percent-encoded and character codes are all found', () => {
    const found = (t) => checkRemoval(V, { 'a.js': t }).found.map((f) => f.form);
    assert.equal(checkRemoval(V, { 'a.js': 'const k = process.env.K;' }).ok, true);
    assert.ok(found(`x('${Buffer.from(V).toString('base64')}')`).includes('base64'));
    assert.ok(found(`x('${Buffer.from(V).toString('hex')}')`).includes('hex'));
    assert.ok(found(`x('${[...V].reverse().join('')}')`).includes('the value reversed'));
    assert.ok(found("x('acmepay_merc' + \"hant_7Hq2xV9Lr4TzP0aB9cD7eF\")").includes('the value split into joined string literals'));
    assert.ok(found(`x(\`\${'acmepay_mer'}\${'chant_7Hq2xV9Lr4TzP0aB9cD7eF'}\`)`).includes('the value split into joined string literals'));
    assert.ok(found(`String.fromCharCode(${[...V].map((c) => c.charCodeAt(0)).join(', ')})`).includes('the value as character codes'));
    assert.ok(found(`[${[...V].map((c) => c.charCodeAt(0)).join(',')}]`).includes('the value as character codes'));
  });

  test('the value is read from the declared line and never stored in the contract or the plan', () => {
    const s = setup();
    assert.equal(extractCredential(s.original, 2), V);
    assert.ok(!JSON.stringify(s.plan).includes(V));
    assert.ok(!JSON.stringify(s.plan).includes(Buffer.from(V).toString('base64')));
    const ob = s.plan.contract.obligations.find((o) => o.id === 'credential-removal');
    assert.deepEqual(Object.keys(ob.inputs).sort(), ['env', 'file', 'length', 'line', 'provider', 'revocation']);
  });

  test('[AC-15.3] only a connector receipt verifies revocation: an error, a refusal and a missing connector do not', async () => {
    assert.equal((await revoke(null, {})).status, 'unavailable');
    assert.equal((await revoke({ id: 'c', revoke: async () => { throw new Error('timeout'); } }, {})).status, 'failed');
    assert.equal((await revoke({ id: 'c', revoke: async () => ({ ok: true }) }, {})).status, 'failed', 'ok without a receipt is not verified');
    assert.equal((await revoke({ id: 'c', revoke: async () => ({ ok: true, receipt: 'rev-123' }) }, {})).status, 'verified');
  });

  test('[AC-15.5] a profile cannot ask for revocation or carry the value', () => {
    const s = setup();
    assert.match(validateProfile({ ...s.profile, credential: { ...s.profile.credential, revoke: true } }).join(' '), /unknown field 'revoke'/);
    assert.match(validateProfile({ ...s.profile, credential: { ...s.profile.credential, value: V } }).join(' '), /unknown field 'value'/);
  });
});

describe('[FR-15] credential repair, executed', () => {
  test('[AC-15.1/15.2] re-encodings and a fallback literal are rejected; the wrong variable fails the replacement; reading the declared variable is verified with the lifecycle incomplete', needs(async () => {
    const s = setup();
    const sub = (to) => s.original.replace(LINE, () => to);
    const items = [
      ['base64', sub(`const API_KEY = Buffer.from('${Buffer.from(V).toString('base64')}', 'base64').toString();\n`), 1],
      ['split', sub("const API_KEY = 'acmepay_merchant_7Hq2' + 'xV9Lr4TzP0aB9cD7eF';\n"), 1],
      ['fallback', sub(`const API_KEY = process.env.PAYMENTS_API_KEY || '${V}';\n`), 1],
      ['wrong-variable', sub('const API_KEY = process.env.PAYMENT_KEY;\n'), 2],
      ['env', env(s.original), 3],
    ].map(([strategy, t, round]) => ({ strategy, round, files: { 'src/app.mjs': t } }));
    const r = await runRepair({ root: s.root, plan: s.plan, config: ON, proposers: [queueProposer(items)], policy });
    const by = Object.fromEntries(r.record.candidates.map((c) => [c.strategy, c]));
    const st = (k, ob) => by[k].results.find((x) => x.obligation === ob)?.status;
    for (const k of ['base64', 'split', 'fallback']) assert.equal(st(k, 'credential-removal'), 'failed', k);
    assert.equal(st('fallback', 'credential-replacement-wired'), 'passed', 'the fallback works, so only removal catches it');
    assert.equal(st('wrong-variable', 'credential-removal'), 'passed');
    assert.equal(st('wrong-variable', 'credential-replacement-wired'), 'failed');
    assert.equal(by.env.status, 'verified-for-contract', r.record.reasons.join('; '));
    assert.equal(r.record.disposition, 'verified-for-contract');
    assert.deepEqual(r.record.lifecycle, { sourceRemoved: 'verified', replacementWired: 'verified', distribution: 'not-checked', revocation: 'required-not-verified', revocationReason: r.record.lifecycle.revocationReason, complete: false });
    assert.match(r.record.reasons.join(' '), /lifecycle incomplete/);
    const text = JSON.stringify(r.record);
    for (const form of [V, Buffer.from(V).toString('base64'), Buffer.from(V).toString('hex')]) assert.ok(!text.includes(form), 'no form of the value reaches the record');
  }));

  test('[AC-15.3] revocation is verified only when the operator invokes a connector that returns a receipt', needs(async () => {
    const s = setup();
    const items = [{ files: { 'src/app.mjs': env(s.original) } }];
    const failing = await runRepair({ root: s.root, plan: s.plan, config: ON, proposers: [queueProposer(items)], policy, revoke: true, deps: { revocationConnector: { id: 'payments-admin', revoke: async () => { throw new Error('503 from the provider'); } } } });
    assert.equal(failing.record.lifecycle.revocation, 'failed');
    assert.equal(failing.record.lifecycle.complete, false);
    const s2 = setup();
    const ok = await runRepair({ root: s2.root, plan: s2.plan, config: ON, proposers: [queueProposer(items)], policy, revoke: true, deps: { revocationConnector: { id: 'payments-admin', revoke: async () => ({ ok: true, receipt: 'revocation-7731' }) } } });
    assert.equal(ok.record.lifecycle.revocation, 'verified');
    assert.equal(ok.record.lifecycle.complete, true);
    const s3 = setup();
    const notInvoked = await runRepair({ root: s3.root, plan: s3.plan, config: ON, proposers: [queueProposer(items)], policy, deps: { revocationConnector: { id: 'payments-admin', revoke: async () => ({ ok: true, receipt: 'should-not-run' }) } } });
    assert.equal(notInvoked.record.lifecycle.revocation, 'required-not-verified', 'a connector is never called without the operator asking');
  }));
});
