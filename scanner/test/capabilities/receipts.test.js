// X-507: tamper-evident capability receipts.
//
// A receipt chain links task identity, capability (manifest) version, backend,
// decision, action and outcome; it is hash-chained and signed in the signer
// domain with the self-issued trust label; verification detects a missing,
// reordered or modified record and refuses to call an incomplete trail fully
// enforced; the report keeps requested, checked and enforced apart.
//
// Chain and signature tests run everywhere. The tests that execute a real task
// are gated on a probed userspace backend and skip loudly elsewhere. The one test
// that builds an `enforced` chain feeds the LABELLING logic synthetic runner
// output (it is not a Linux run and asserts nothing about Linux).
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { DOMAINS } from '../../src/sandbox/trust-domains.js';
import { decide } from '../../src/capabilities/decide.js';
import { toCapabilityDecisionRecord } from '../../src/capabilities/records.js';
import { buildCapabilityReport } from '../../src/capabilities/report.js';
import { requiredControlsFor } from '../../src/capabilities/probes.js';
import {
  createReceiptRecorder, receiptsFromRun, verifyChainIntegrity, assessCompleteness, signReceiptChain, verifyReceiptEnvelope,
  receiptReport, receiptDirectoryConflict, writeReceiptEnvelope, readReceiptEnvelope, RECEIPT_CHAIN_SCHEMA,
} from '../../src/capabilities/receipts.js';
import { SKIP, ON_LINUX, bind, run, tmp, ctxFor } from './helpers.js';

function keypair() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  return { privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }), publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }) };
}
const clone = (o) => JSON.parse(JSON.stringify(o));
const sign = (chain, keys) => signReceiptChain(chain, { domain: DOMAINS.SIGNER, privateKeyPem: keys.privateKeyPem });
const record = (domain, bound, result) => receiptsFromRun({ domain, bound, result });
const sha256 = (file) => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');

// A denied run: policy-level, produced by the real runner on any platform.
async function deniedRun() {
  const w = tmp('rcpt-den-');
  const bound = bind({ filesystem: { write: [w] } });
  const result = await run(bound, { executable: '/bin/echo', args: ['x'] });
  return { bound, result, w };
}

// A synthetic runner result for the labelling logic only. It is built from the
// real report and record builders but NOT from any run: it asserts nothing about
// a platform. `over` tweaks it to build the negative variants.
function syntheticEnforcedRun(over = {}) {
  const w = tmp('rcpt-syn-');
  const bound = bind({
    filesystem: { read: [w], write: [w] }, commands: [{ executable: '/bin/echo', args: { mode: 'any' } }],
    network: [{ host: 'api.example.com', port: 443, schemes: ['https'] }],
  });
  const required = requiredControlsFor(bound.manifest);
  const probeReport = {
    platform: 'synthetic', backend: 'namespace', probeDigest: `sha256:${'a'.repeat(64)}`,
    controls: Object.fromEntries(required.map((n) => [n, { state: over.unproved === n ? 'not-proved' : 'proved' }])),
  };
  const level = over.level ?? 'enforced';
  const report = buildCapabilityReport({ bound, probeReport, level, required });
  const cmd = decide(bound, { kind: 'command', executable: '/bin/echo', args: ['a'] }, ctxFor(bound));
  const enforced = level === 'enforced';
  const mk = (kind, subject, mediation = 'runner', enf = enforced) => toCapabilityDecisionRecord({ ...cmd, kind, subject }, { mediation, enforced: enf, backend: 'namespace', probeDigest: probeReport.probeDigest }).record;
  const records = [mk('command', '/bin/echo'), mk('filesystem-read', w), mk('filesystem-write', w), mk('network', 'https://api.example.com:443', 'proxy')];
  return {
    bound,
    result: {
      status: 'ok', executed: true, outcome: 'exited', exitCode: 0, level, enforced, backend: 'namespace', report,
      cleanup: { complete: true }, capabilityDecisions: over.dropDecision ? records.filter((r) => r.capability !== over.dropDecision) : records,
    },
  };
}

describe('[X-507.AC01] receipts link task identity, capability version, backend, decision, action and outcome with integrity protection', () => {
  test('a denied run produces a chain that names the task, the manifest digest and policy version on every receipt', async () => {
    const { bound, result } = await deniedRun();
    const chain = record(DOMAINS.VERIFIER, bound, result);
    assert.equal(chain.schema, RECEIPT_CHAIN_SCHEMA);
    assert.deepEqual(chain.receipts.map((r) => r.kind), ['start', 'decision', 'outcome', 'end']);
    for (const r of chain.receipts) {
      assert.equal(r.taskId, bound.binding.taskId);
      assert.equal(r.policyVersion, bound.binding.policyVersion);
      assert.equal(r.manifestDigest, bound.binding.digest);
      assert.match(r.hash, /^[0-9a-f]{64}$/);
    }
    const d = chain.receipts[1].body.record;
    assert.equal(d.decision, 'deny'); assert.equal(d.capability, 'command'); assert.equal(d.enforced, false);
    assert.match(d.reason, /command-not-listed/);
    const o = chain.receipts[2].body;
    assert.equal(o.outcome, 'not-run');
    assert.equal(chain.receipts[0].body.observed, null, 'a run that never reached a backend observed no controls');
    assert.equal(verifyChainIntegrity(chain).ok, true);
  });

  test('an executed run links backend, level, probe digest, decisions, action and outcome', { skip: SKIP }, async () => {
    const w = tmp('rcpt-run-');
    const bound = bind({ filesystem: { write: [w] }, commands: [{ executable: '/bin/echo', args: { mode: 'any' } }] });
    const result = await run(bound, { executable: '/bin/echo', args: ['receipt'] });
    assert.equal(result.executed, true);
    const chain = record(DOMAINS.VERIFIER, bound, result);
    const start = chain.receipts[0].body;
    // macOS: the userspace backend, host-proved, no enforcement claimed. Linux: the advertised namespace backend, enforced because every
    // control it depends on was proved (checked below, control by control).
    assert.equal(start.observed.backend, ON_LINUX ? 'namespace' : 'userspace');
    assert.equal(start.observed.level, ON_LINUX ? 'enforced' : 'host-proved');
    assert.equal(start.observed.enforced, ON_LINUX);
    assert.match(start.observed.probeDigest, /^sha256:/);
    assert.equal(start.observed.controls['write-confinement'], 'proved');
    const kinds = chain.receipts.filter((r) => r.kind === 'decision').map((r) => r.body.record.capability);
    assert.ok(kinds.includes('command') && kinds.includes('filesystem-write'));
    for (const r of chain.receipts.filter((x) => x.kind === 'decision')) {
      assert.equal(r.body.record.backend, ON_LINUX ? 'namespace' : 'userspace');
      assert.equal(r.body.record.enforced, ON_LINUX, ON_LINUX ? 'an enforced run records enforcement' : 'a host-proved run claims no enforcement');
    }
    const out = chain.receipts.find((r) => r.kind === 'outcome').body;
    assert.equal(out.outcome, 'exited'); assert.equal(out.exitCode, 0); assert.equal(out.cleanupComplete, true);
    const keys = keypair();
    const v = verifyReceiptEnvelope(sign(chain, keys), keys.publicKeyPem, { binding: { taskId: bound.binding.taskId, policyVersion: 1, digest: bound.binding.digest } });
    assert.equal(v.ok, true); assert.equal(v.complete, true); assert.equal(v.current, true);
    assert.equal(v.label, ON_LINUX ? 'fully-enforced' : 'host-proved-not-enforced');
    assert.equal(v.fullyEnforced, ON_LINUX);
    if (ON_LINUX) {
      // The claim is only as good as the probes behind it: the signed start receipt must carry every control the manifest depends on as proved.
      for (const c of requiredControlsFor(bound.manifest)) assert.equal(start.observed.controls[c], 'proved', `${c} is claimed enforced but is not proved`);
    }
  });

  test('the chain is signed in the signer domain with the self-issued trust label, and nothing else may sign or record', async () => {
    const { bound, result } = await deniedRun();
    const keys = keypair();
    const chain = record(DOMAINS.VERIFIER, bound, result);
    const env = sign(chain, keys);
    assert.equal(env.issuance.trustBasis, 'self-issued-local-key');
    assert.equal(env.issuance.independentlyCertified, false);
    assert.match(env.issuance.statement, /NOT independent/);
    assert.equal(env.signature.algorithm, 'ed25519');
    const v = verifyReceiptEnvelope(env, keys.publicKeyPem);
    assert.equal(v.trustBasis, 'self-issued-local-key'); assert.equal(v.independentlyCertified, false);
    for (const domain of [DOMAINS.WORKER, DOMAINS.TARGET, DOMAINS.VERIFIER, undefined]) {
      assert.throws(() => signReceiptChain(chain, { domain, privateKeyPem: keys.privateKeyPem }), (e) => e.code === 'domain-denied', `${String(domain)} cannot sign`);
    }
    for (const domain of [DOMAINS.WORKER, DOMAINS.TARGET, DOMAINS.SIGNER, undefined]) {
      assert.throws(() => createReceiptRecorder({ domain, bound, observed: null }), (e) => e.code === 'domain-denied', `${String(domain)} cannot record`);
      assert.throws(() => receiptsFromRun({ domain, bound, result }), (e) => e.code === 'domain-denied');
    }
    assert.throws(() => writeReceiptEnvelope(tmp('rcpt-w-'), env, { domain: DOMAINS.WORKER }), (e) => e.code === 'domain-denied');
    // a verifier that claims an independent basis is refused even with a valid signature
    const forged = clone(env); forged.issuance.independentlyCertified = true;
    assert.equal(verifyReceiptEnvelope(forged, keys.publicKeyPem).ok, false);
  });

  test('a key that is not the issuer, or an envelope without one, does not verify', async () => {
    const { bound, result } = await deniedRun();
    const keys = keypair(); const other = keypair();
    const env = sign(record(DOMAINS.VERIFIER, bound, result), keys);
    assert.equal(verifyReceiptEnvelope(env, other.publicKeyPem).ok, false);
    assert.equal(verifyReceiptEnvelope(env, undefined).ok, false);
    assert.equal(verifyReceiptEnvelope({ ...env, signature: undefined }, keys.publicKeyPem).ok, false);
    assert.equal(verifyReceiptEnvelope(null, keys.publicKeyPem).ok, false);
    assert.equal(verifyReceiptEnvelope({ schema: 'x' }, keys.publicKeyPem).ok, false);
  });

  test('workers cannot write or alter receipts: files are exclusive-create and owner-only, and a signed file edited on disk fails verification', async () => {
    const { bound, result } = await deniedRun();
    const keys = keypair();
    const dir = tmp('rcpt-store-');
    const env = sign(record(DOMAINS.VERIFIER, bound, result), keys);
    const file = writeReceiptEnvelope(dir, env, { domain: DOMAINS.VERIFIER });
    assert.equal(fs.statSync(file).mode & 0o777, 0o600);
    assert.throws(() => writeReceiptEnvelope(dir, env, { domain: DOMAINS.VERIFIER }), (e) => e.code === 'EEXIST', 'an existing receipt is never overwritten');
    assert.equal(verifyReceiptEnvelope(readReceiptEnvelope(file), keys.publicKeyPem).ok, true);
    const onDisk = JSON.parse(fs.readFileSync(file, 'utf8'));
    onDisk.chain.receipts[1].body.record.decision = 'allow';
    fs.writeFileSync(file, JSON.stringify(onDisk));
    assert.equal(verifyReceiptEnvelope(readReceiptEnvelope(file), keys.publicKeyPem).ok, false);
    // a directory that overlaps a task root is flagged, and the runner refuses it as a root
    const mine = tmp('rcpt-mine-');
    const b2 = bind({ filesystem: { write: [mine] }, commands: [{ executable: '/bin/echo', args: { mode: 'any' } }] });
    assert.equal(receiptDirectoryConflict(b2, path.join(mine, 'receipts')), mine);
    assert.equal(receiptDirectoryConflict(b2, tmp('rcpt-away-')), null);
    const blocked = await run(b2, { executable: '/bin/echo', args: [] }, { evidenceDirs: [mine] });
    assert.equal(blocked.status, 'blocked');
    assert.equal(blocked.policyCode, 'protected-path', 'a manifest root that is the receipt directory is refused before anything runs');
  });

  test('a confined worker cannot write, replace, delete or read receipts, even through an interpreter', { skip: SKIP }, async () => {
    const keys = keypair();
    const rdir = tmp('rcpt-guard-');
    const w = tmp('rcpt-work-');
    const { bound: db, result: dr } = await deniedRun();
    const file = writeReceiptEnvelope(rdir, sign(record(DOMAINS.VERIFIER, db, dr), keys), { domain: DOMAINS.VERIFIER });
    const before = sha256(file);
    const marker = 'RCPT-SECRET-MARKER';
    const script = [
      `echo forged > '${file}' 2>/dev/null && echo WROTE >> '${w}/log'`,
      `rm '${file}' 2>/dev/null && echo DELETED >> '${w}/log'`,
      `echo x > '${rdir}/new.json' 2>/dev/null && echo CREATED >> '${w}/log'`,
      `cat '${file}' > '${w}/copy' 2>/dev/null; [ -s '${w}/copy' ] && echo READ >> '${w}/log'`,
      `/bin/sh -c "echo y > '${file}'" 2>/dev/null && echo CHILD-WROTE >> '${w}/log'`,
      `echo done > '${w}/done'`,
    ].join('\n');
    const bound = bind({ filesystem: { write: [w] }, commands: [{ executable: '/bin/sh', interpreter: 'scoped', args: { mode: 'exact', values: ['-c', script] } }] });
    const r = await run(bound, { executable: '/bin/sh', args: ['-c', script] }, { evidenceDirs: [rdir], canaries: [marker] });
    assert.equal(r.executed, true);
    assert.equal(fs.readFileSync(path.join(w, 'done'), 'utf8').trim(), 'done', 'the script ran to the end');
    assert.ok(!fs.existsSync(path.join(w, 'log')), `no write, delete, create or read succeeded: ${fs.existsSync(path.join(w, 'log')) ? fs.readFileSync(path.join(w, 'log'), 'utf8') : ''}`);
    assert.equal(sha256(file), before, 'the receipt file is byte-identical');
    assert.ok(!fs.existsSync(path.join(rdir, 'new.json')));
  });
});

describe('[X-507.AC02] verification detects missing, reordered or modified records and never labels an incomplete trail fully enforced', () => {
  async function fixture() {
    const { bound, result } = await deniedRun();
    const w = tmp('rcpt-tmp-');
    // a richer chain: several decisions and outcomes, so there is something to remove
    const rec = createReceiptRecorder({ domain: DOMAINS.VERIFIER, bound, observed: null });
    const d = decide(bound, { kind: 'tool', tool: 'a' }, ctxFor(bound));
    for (const k of ['command', 'filesystem-read', 'filesystem-write']) rec.decision(toCapabilityDecisionRecord({ ...d, kind: k, subject: `s-${k}` }, { mediation: 'runner', enforced: false, backend: null }).record);
    rec.outcome({ action: 'task', outcome: 'exited', status: 'ok', exitCode: 0 });
    return { bound, result, chain: rec.seal(), w };
  }

  test('a removed receipt breaks the chain at a named position', async () => {
    const { chain } = await fixture();
    const c = clone(chain);
    c.receipts.splice(2, 1);
    const r = verifyChainIntegrity(c);
    assert.equal(r.ok, false); assert.equal(r.breakAt, 2);
    assert.match(r.reason, /sequence/);
  });

  test('a reordered pair of receipts is detected', async () => {
    const { chain } = await fixture();
    const c = clone(chain);
    [c.receipts[1], c.receipts[2]] = [c.receipts[2], c.receipts[1]];
    assert.equal(verifyChainIntegrity(c).ok, false);
  });

  test('a modified receipt (decision, outcome, task, policy) is detected', async () => {
    const { chain } = await fixture();
    for (const edit of [
      (c) => { c.receipts[1].body.record.decision = 'allow'; },
      (c) => { c.receipts[4].body.exitCode = 1; },
      (c) => { c.receipts[2].taskId = 'someone-else'; },
      (c) => { c.receipts[3].policyVersion = 9; },
      (c) => { c.receipts[0].body.requested.commands = 99; },
    ]) {
      const c = clone(chain); edit(c);
      assert.equal(verifyChainIntegrity(c).ok, false);
    }
    assert.equal(verifyChainIntegrity(clone(chain)).ok, true, 'the unedited copy still verifies');
  });

  test('a receipt re-hashed to hide an edit still breaks the link to its successor', async () => {
    const { chain } = await fixture();
    const c = clone(chain);
    c.receipts[2].body.record.reason = 'edited';
    const { hash, ...core } = c.receipts[2];
    c.receipts[2].hash = crypto.createHash('sha256').update((function cj(v) { if (v === null || typeof v !== 'object') return JSON.stringify(v ?? null); if (Array.isArray(v)) return `[${v.map(cj).join(',')}]`; return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${cj(v[k])}`).join(',')}}`; })(core)).digest('hex');
    const r = verifyChainIntegrity(c);
    assert.equal(r.ok, false);
    assert.equal(r.breakAt, 3, 'the next receipt no longer links');
  });

  test('every edit of a SIGNED envelope fails the signature, including report, issuance and added fields', async () => {
    const { chain } = await fixture();
    const keys = keypair();
    const env = sign(chain, keys);
    assert.equal(verifyReceiptEnvelope(env, keys.publicKeyPem).ok, true);
    const edits = {
      'a receipt body': (e) => { e.chain.receipts[1].body.record.subject = 'x'; },
      'the head': (e) => { e.chain.head = '0'.repeat(64); },
      'the binding': (e) => { e.chain.binding.policyVersion = 2; },
      'a removed receipt': (e) => { e.chain.receipts.splice(1, 1); e.chain.count -= 1; },
      'the issuer': (e) => { e.issuance.issuer.id = 'someone'; },
      'an added top-level field': (e) => { e.verdict = 'fully-enforced'; },
    };
    for (const [why, edit] of Object.entries(edits)) {
      const e = clone(env); edit(e);
      const v = verifyReceiptEnvelope(e, keys.publicKeyPem);
      assert.equal(v.ok, false, why);
      assert.equal(v.fullyEnforced, false, why);
      assert.equal(v.label, 'tampered', why);
    }
  });

  test('truncation: dropping the tail and fixing up count and head passes the chain check but not completeness', async () => {
    const { chain } = await fixture();
    const c = clone(chain);
    c.receipts = c.receipts.slice(0, 3);
    c.count = 3; c.head = c.receipts[2].hash;
    assert.equal(verifyChainIntegrity(c).ok, true, 'a prefix of a hash chain is a valid chain');
    const comp = assessCompleteness(c);
    assert.equal(comp.complete, false);
    assert.ok(comp.reasons.includes('missing-seal'));
    assert.ok(comp.reasons.includes('missing-outcome'));
  });

  test('a validly SIGNED but incomplete trail verifies as authentic and is labelled incomplete, never fully enforced', async () => {
    const { bound } = await fixture();
    const keys = keypair();
    // a recorder that never saw a decision the run produced
    const d = decide(bound, { kind: 'tool', tool: 'a' }, ctxFor(bound));
    const produced = toCapabilityDecisionRecord({ ...d, kind: 'command', subject: 'cmd' }, { mediation: 'runner', enforced: false, backend: null }).record;
    const rec = createReceiptRecorder({ domain: DOMAINS.VERIFIER, bound, observed: null });
    rec.outcome({ action: 'task', outcome: 'exited' });
    const env = sign(rec.seal(), keys);
    const v = verifyReceiptEnvelope(env, keys.publicKeyPem, { requiredDecisionIds: [produced.id] });
    assert.equal(v.ok, true, 'authentic');
    assert.equal(v.complete, false);
    assert.ok(v.reasons.includes('required-decision-missing'));
    assert.equal(v.fullyEnforced, false);
    assert.equal(v.label, 'incomplete-audit-trail');
    // a chain with no seal at all
    const rec2 = createReceiptRecorder({ domain: DOMAINS.VERIFIER, bound, observed: null });
    rec2.outcome({ action: 'task', outcome: 'exited' });
    assert.throws(() => signReceiptChain({ ...rec2.seal(), receipts: [] }, { domain: DOMAINS.SIGNER, privateKeyPem: keys.privateKeyPem }), (e) => e.code === 'chain-not-intact');
  });

  test('fully enforced is a verifier-computed label that every shortfall removes (synthetic runner output; asserts nothing about Linux)', () => {
    const keys = keypair();
    const label = (over, expected) => {
      const s = syntheticEnforcedRun(over);
      const env = sign(record(DOMAINS.VERIFIER, s.bound, s.result), keys);
      return verifyReceiptEnvelope(env, keys.publicKeyPem, expected);
    };
    const good = label({});
    assert.equal(good.label, 'fully-enforced');
    assert.equal(good.fullyEnforced, true);
    assert.equal(good.complete, true);
    // each shortfall removes the label
    const dropped = label({ dropDecision: 'filesystem-write' });
    assert.equal(dropped.complete, false); assert.equal(dropped.fullyEnforced, false); assert.equal(dropped.label, 'incomplete-audit-trail');
    const noCommand = label({ dropDecision: 'command' });
    assert.equal(noCommand.fullyEnforced, false);
    const unproved = label({ unproved: 'network-mediation' });
    assert.equal(unproved.fullyEnforced, false, 'an unproved control the report depends on');
    const hostProved = label({ level: 'host-proved' });
    assert.equal(hostProved.fullyEnforced, false); assert.equal(hostProved.label, 'host-proved-not-enforced');
    const s = syntheticEnforcedRun({});
    const superseded = verifyReceiptEnvelope(sign(record(DOMAINS.VERIFIER, s.bound, s.result), keys), keys.publicKeyPem, { binding: { ...s.bound.binding, policyVersion: 2, digest: 'sha256:other' } });
    assert.equal(superseded.fullyEnforced, false); assert.equal(superseded.label, 'superseded-policy');
    // an observed level that is not `enforced`, with every other field claiming enforcement
    const lv = syntheticEnforcedRun({});
    const rec = createReceiptRecorder({ domain: DOMAINS.VERIFIER, bound: lv.bound, observed: { backend: 'userspace', level: 'host-proved', enforced: true, probeDigest: lv.result.report.probeDigest, controls: {}, report: lv.result.report } });
    for (const r of lv.result.capabilityDecisions) rec.decision(r);
    rec.outcome({ action: 'task', outcome: 'exited', exitCode: 0 });
    const lvv = verifyReceiptEnvelope(sign(rec.seal(), keys), keys.publicKeyPem);
    assert.equal(lvv.complete, true);
    assert.equal(lvv.fullyEnforced, false, 'the level alone is enough to refuse the label');
    assert.equal(lvv.label, 'host-proved-not-enforced');
    // a decision receipt claiming a weaker record than the run's
    const mixed = syntheticEnforcedRun({});
    mixed.result.capabilityDecisions = mixed.result.capabilityDecisions.map((r, i) => (i === 0 ? toCapabilityDecisionRecord({ decision: 'allow', code: 'allowed', reason: 'x', kind: r.capability, subject: r.subject, taskId: r.taskId }, { mediation: 'runner', enforced: false, backend: 'namespace' }).record : r));
    const m = verifyReceiptEnvelope(sign(record(DOMAINS.VERIFIER, mixed.bound, mixed.result), keys), keys.publicKeyPem);
    assert.equal(m.fullyEnforced, false, 'one decision that was not enforced is enough');
  });
});

describe('[X-507.AC03] reports distinguish requested, checked and enforced controls, including platform and network-boundary limitations', () => {
  test('requested, checked and enforced are separate fields for each capability, read from the signed start receipt', () => {
    const s = syntheticEnforcedRun({ unproved: 'fs-read-confinement' });
    const chain = record(DOMAINS.VERIFIER, s.bound, s.result);
    const rep = receiptReport(chain);
    const fsr = rep.capabilities.find((c) => c.kind === 'filesystem-read');
    assert.deepEqual(Object.keys(fsr).filter((k) => ['requested', 'checked', 'enforced'].includes(k)).sort(), ['checked', 'enforced', 'requested']);
    assert.equal(fsr.checked['fs-read-confinement'], 'not-proved');
    assert.equal(fsr.enforced, false, 'requested and probed-for does not mean enforced');
    assert.ok(rep.capabilities.filter((c) => ['filesystem-write', 'command', 'network'].includes(c.kind)).every((c) => c.enforced === false), 'one control the manifest depends on is unproved, so nothing is claimed enforced');
    const good = receiptReport(record(DOMAINS.VERIFIER, syntheticEnforcedRun({}).bound, syntheticEnforcedRun({}).result));
    assert.ok(good.capabilities.filter((c) => ['filesystem-read', 'filesystem-write', 'command', 'network'].includes(c.kind)).every((c) => c.enforced === true), 'with every control proved on an enforced level each capability is enforced');
    assert.ok(rep.capabilities.find((c) => c.kind === 'tool').enforced === false && rep.capabilities.find((c) => c.kind === 'delegation').enforced === false, 'in-process policy is never enforced');
    assert.equal(rep.capabilities.find((c) => c.kind === 'tool').enforcedBy, 'in-process-policy');
  });

  test('a host-proved run reports every control as checked and none as enforced, and Linux as unverified', { skip: SKIP }, async () => {
    const w = tmp('rcpt-rep-');
    const bound = bind({
      filesystem: { write: [w] }, commands: [{ executable: '/bin/echo', args: { mode: 'any' } }],
      network: [{ host: 'api.example.com', port: 443, schemes: ['https'] }], resources: { maxProcesses: 1, maxMemoryMiB: 512 },
    });
    const result = await run(bound, { executable: '/bin/echo', args: ['r'] });
    if (!ON_LINUX) assert.equal(result.executed, true);
    const rep = receiptReport(record(DOMAINS.VERIFIER, bound, result));
    if (ON_LINUX) {
      // This manifest declares a network destination, which the namespace backend cannot mediate, so the run is blocked rather than executed.
      assert.equal(result.executed, false);
      assert.equal(result.status, 'blocked');
      assert.equal(rep.level, 'none');
    } else {
      assert.equal(rep.level, 'host-proved');
      assert.equal(rep.backend, 'userspace');
      for (const c of rep.capabilities.filter((x) => ['filesystem-read', 'filesystem-write', 'command', 'network'].includes(x.kind))) {
        assert.equal(c.enforced, false, `${c.kind}: host-proved is not enforced`);
        assert.ok(Object.values(c.checked).includes('proved'), `${c.kind}: but its controls were checked and proved on this host`);
      }
    }
    assert.equal(rep.platforms.linux.status, 'partially-verified', 'Linux is only partially verified, and only by the hosted job');
    assert.ok(rep.platforms.linux.unsupportedControls.includes('network-mediation'));
    assert.ok(rep.platforms.linux.verifiedControls.includes('process-cap'), 'the hosted sandbox-linux job proved the process-count cap');
    assert.deepEqual(rep.platforms.linux.unassertedControls, []);
    assert.equal(rep.platforms.darwin.status, 'host-proved-not-advertised');
    // macOS: the cap is per-user and system-wide, so it is never claimed. Linux: this run was blocked (a declared destination cannot be
    // mediated), so nothing was enforced even though the control itself is proved on this host.
    assert.equal(rep.resources.maxProcesses.enforced, false);
    assert.equal(rep.resources.maxProcesses.state, ON_LINUX ? 'proved' : 'unverified');
    assert.equal(rep.resources.maxMemoryMiB.state, 'not-enforced');
  });

  test('network-boundary limits travel with the report: the mediated door, plaintext-only filtering and the standing limitations', () => {
    const s = syntheticEnforcedRun({});
    const rep = receiptReport(record(DOMAINS.VERIFIER, s.bound, s.result));
    const net = rep.capabilities.find((c) => c.kind === 'network');
    assert.equal(net.enforcedBy, 'proxy');
    assert.equal(net.payloadFiltering, 'plaintext-http-only');
    assert.equal(rep.networkBoundary, 'proxy');
    const text = rep.limitations.join('\n');
    assert.match(text, /HTTPS is an opaque tunnel/);
    assert.match(text, /accepts connections from any local process/);
    assert.match(text, /descendant/i);
    assert.match(text, /process-count cap is enforced only on the Linux namespace backend/i);
    assert.equal(rep.platforms.linux.status, 'partially-verified');
    const noNet = syntheticEnforcedRun({});
    const bound2 = bind({ filesystem: { write: [tmp('rcpt-nn-')] }, commands: [{ executable: '/bin/echo', args: { mode: 'any' } }] });
    const rep2 = receiptReport(record(DOMAINS.VERIFIER, bound2, { ...noNet.result, report: buildCapabilityReport({ bound: bound2, probeReport: { backend: 'namespace', controls: {}, probeDigest: noNet.result.report.probeDigest }, level: 'none', required: requiredControlsFor(bound2.manifest) }) }));
    assert.equal(rep2.networkBoundary, 'runner', 'with no destinations the boundary is the runner\'s no-network default');
  });

  test('the report inside a verified envelope cannot be edited to say more than the runner observed', () => {
    const s = syntheticEnforcedRun({ level: 'host-proved' });
    const keys = keypair();
    const env = sign(record(DOMAINS.VERIFIER, s.bound, s.result), keys);
    const v = verifyReceiptEnvelope(env, keys.publicKeyPem);
    assert.equal(v.report.level, 'host-proved');
    assert.ok(v.report.capabilities.every((c) => c.enforced === false || c.kind === 'tool'));
    const edited = clone(env);
    edited.chain.receipts[0].body.report.capabilities.forEach((c) => { c.enforced = true; });
    edited.chain.receipts[0].body.observed.level = 'enforced';
    assert.equal(verifyReceiptEnvelope(edited, keys.publicKeyPem).ok, false);
    assert.equal(verifyReceiptEnvelope(edited, keys.publicKeyPem).fullyEnforced, false);
  });

  test('a refusal that never ran reports no observed controls and cannot read as enforced', async () => {
    const { bound, result } = await deniedRun();
    const keys = keypair();
    const v = verifyReceiptEnvelope(sign(record(DOMAINS.VERIFIER, bound, result), keys), keys.publicKeyPem);
    assert.equal(v.label, 'not-run');
    assert.equal(v.fullyEnforced, false);
    assert.equal(v.report.level, 'none');
    assert.deepEqual(v.report.capabilities, []);
  });
});
