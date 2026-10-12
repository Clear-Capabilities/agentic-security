import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { verifyFixWithProof } from '../../src/posture/proof-fabric/fix-proof.js';
import { saveProof, listProofs, latestProof } from '../../src/posture/proof-fabric/store.js';
import { runAttempt, languageSupport } from '../../src/posture/proof-fabric/runner.js';
import { sandboxAvailable } from '../../src/sandbox/index.js';

const finding = { id: 'F1', stableId: 'F1', parser: 'IR-TAINT' };
const repro = { schema: 'agentic-security/reproducer', version: 1, findingId: 'F1', lang: 'javascript', files: { 'a.mjs': 'x' }, run: ['{{NODE}}', 'a.mjs'], oracle: { type: 'command_execution', params: { canary: 'command' } } };
// Stub: fires only while the overlay still carries the vulnerable marker.
const stub = (log = []) => async (r, o) => { log.push(o?.overlay ?? null); const vuln = !o?.overlay; return { status: 'completed', oracle: { fired: vuln }, observation: {}, degraded: [], durationMs: 1, environment: { mode: 'local-confined', assurance: 'lower' } }; };
const okStatic = { ok: true, verifiedFull: true, degradedLegs: [], rescan: { ok: true } };

test('fix proof: confirmed before, blocked after, static ok -> FIX_VERIFIED', async () => {
  const r = await verifyFixWithProof({ finding, reproducer: repro, files: { 'a.js': 'patched' }, scanRoot: '.', staticVerification: okStatic, siblings: [], deps: { attemptFn: stub() } });
  assert.equal(r.state, 'FIX_VERIFIED'); assert.equal(r.verified, true);
});

test('fix proof: exploit still works after the patch -> not verified, says so', async () => {
  const r = await verifyFixWithProof({ finding, reproducer: repro, files: {}, scanRoot: '.', staticVerification: okStatic, siblings: [], deps: { attemptFn: async () => ({ status: 'completed', oracle: { fired: true }, observation: {}, degraded: [], durationMs: 1, environment: { mode: 'local-confined', assurance: 'lower' } }) } });
  assert.equal(r.verified, false); assert.equal(r.incompleteStep, 'post-patch-exploit');
});

test('fix proof: a patched replay that times out is inconclusive, never blocked', async () => {
  let n = 0;
  const attemptFn = async (r, o) => (o?.overlay ? { status: 'error', oracle: null, degraded: [], durationMs: 1, reasons: ['timeout'] } : stub()(r, o));
  const r = await verifyFixWithProof({ finding, reproducer: repro, files: { 'a.js': 'p' }, scanRoot: '.', staticVerification: okStatic, siblings: [], deps: { attemptFn } });
  void n;
  assert.equal(r.verified, false); assert.equal(r.incompleteStep, 'post-patch-replay'); assert.equal(r.completeness, 'INCOMPLETE');
});

test('fix proof: no pre-patch confirmation means nothing can be verified', async () => {
  const r = await verifyFixWithProof({ finding, reproducer: repro, files: {}, scanRoot: '.', staticVerification: okStatic, deps: { attemptFn: async () => ({ status: 'completed', oracle: { fired: false }, observation: {}, degraded: [], durationMs: 1 }) } });
  assert.equal(r.verified, false); assert.equal(r.incompleteStep, 'pre-patch-exploit');
});

test('fix proof: failing static verification blocks FIX_VERIFIED even when the exploit is blocked', async () => {
  const r = await verifyFixWithProof({ finding, reproducer: repro, files: { 'a.js': 'p' }, scanRoot: '.', staticVerification: { ok: false, rescan: { reason: 'introduced-new-findings' } }, deps: { attemptFn: stub() } });
  assert.equal(r.verified, false); assert.equal(r.state, 'FIX_REPLAY_BLOCKED');
});

test('store: round trip, no raw secrets, tamper detection', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'pf-store-'));
  fs.mkdirSync(path.join(root, '.git'));
  const rec = { findingId: 'F9', state: 'EXPLOIT_CONFIRMED', note: 'token ghp_abcdefghijklmnopqrstuvwxyz0123456789 leaked' };
  const s = saveProof(root, rec);
  assert.equal(s.ok, true, s.reason);
  const text = fs.readFileSync(s.file, 'utf8');
  assert.ok(!text.includes('ghp_abcdefghijklmnopqrstuvwxyz0123456789'));
  assert.equal(listProofs(root, 'F9')[0].tampered, false);
  fs.writeFileSync(s.file, text.replace('EXPLOIT_CONFIRMED', 'FIX_VERIFIED'));
  assert.equal(listProofs(root, 'F9')[0].tampered, true);
  assert.equal(latestProof(root, 'F9').tampered, true);
  fs.rmSync(root, { recursive: true, force: true });
});

test('runner: invalid and unsupported inputs never execute', async () => {
  assert.equal((await runAttempt({ lang: 'javascript' })).status, 'invalid');
  const r = await runAttempt({ ...repro, lang: 'csharp' }, { tools: { node: process.execPath } });
  assert.equal(r.status, 'unsupported'); assert.equal(r.executed, false);
  assert.equal(languageSupport('csharp', {}).supported, false);
});

test('runner: sources must stay inside the repository', { skip: !sandboxAvailable() }, async () => {
  const r = await runAttempt({ ...repro, sources: { 'dep.mjs': 'safe.mjs' } }, { sourceRoot: os.tmpdir() });
  assert.equal(r.status, 'invalid');
});

test('runner: real confined run decides by the oracle, not by the program output', { skip: !sandboxAvailable() }, async () => {
  const base = { ...repro, files: { 'a.mjs': "import fs from 'node:fs'; if (process.argv[2]==='go') fs.writeFileSync('{{CANARY:command}}','x'); console.log('command-executed');" } };
  const yes = await runAttempt({ ...base, run: ['{{NODE}}', 'a.mjs', 'go'] });
  assert.equal(yes.status, 'completed'); assert.equal(yes.oracle.fired, true);
  const no = await runAttempt(base);
  assert.equal(no.oracle.fired, false); // prints the words, creates no canary: output text alone proves nothing
  assert.ok(yes.degraded.includes('lower-assurance-local-confinement'));
  assert.ok(!JSON.stringify(yes).includes(yes.observation.nonce === '[redacted]' ? 'SECRET-' : 'zzz'));
});

test('runner: a hung target ends as incomplete evidence within its bound', { skip: !sandboxAvailable() }, async () => {
  const t0 = Date.now();
  const r = await runAttempt({ ...repro, files: { 'a.mjs': 'setInterval(()=>{},1000)' } }, { limits: { timeoutMs: 1500, graceMs: 300 } });
  assert.ok(Date.now() - t0 < 15000);
  assert.ok(r.observation?.timedOut || r.status !== 'completed');
  assert.notEqual(r.oracle?.fired, true);
  assert.equal(r.oracle?.inconclusive, true);
});
