import test from 'node:test';
import assert from 'node:assert/strict';
import { advance, EVIDENCE_STATES, toProofTier, fromProofTier } from '../../src/posture/proof-fabric/states.js';
import { evaluateOracle, ORACLE_TYPES } from '../../src/posture/proof-fabric/oracles.js';
import { validateReproducer, verifierView, isSafeRelPath } from '../../src/posture/proof-fabric/reproducer.js';
import { proveFinding, independentVerify, applySeverityPolicy } from '../../src/posture/proof-fabric/orchestrator.js';

const repro = (over = {}) => ({ schema: 'agentic-security/reproducer', version: 1, findingId: 'F1', lang: 'javascript', files: { 'a.mjs': 'x' }, run: ['{{NODE}}', 'a.mjs'], oracle: { type: 'command_execution', params: { canary: 'command' } }, ...over });
const att = (fired, status = 'completed', extra = {}) => async () => ({ status, executed: status === 'completed', oracle: status === 'completed' ? { fired, inconclusive: !!extra.inconclusive } : null, observation: {}, degraded: [], reasons: [], durationMs: 1, environment: { mode: 'local-confined', assurance: 'lower', backend: 'userspace' }, ...extra });
const finding = { id: 'F1', stableId: 'F1', severity: 'critical', parser: 'IR-TAINT' };

test('state ladder cannot skip rungs and never invents evidence', () => {
  assert.equal(advance('CANDIDATE', 'EXPLOIT_CONFIRMED').ok, false);
  assert.equal(advance('REPRODUCED', 'FIX_VERIFIED').ok, false);
  assert.equal(advance('REPRODUCED', 'EXPLOIT_CONFIRMED').ok, true);
  assert.equal(advance('EXPLOIT_CONFIRMED', 'CANDIDATE').ok, true);
  assert.equal(advance('NOPE', 'REPRODUCED').ok, false);
  assert.equal(EVIDENCE_STATES.length, 7);
});

test('bridges to the older proof-tier vocabulary never over-claim', () => {
  assert.equal(fromProofTier('execution-proven'), 'REPRODUCED');
  assert.equal(toProofTier('REPRODUCED'), 'taint-proven');
  assert.equal(toProofTier('EXPLOIT_CONFIRMED'), 'execution-proven');
  assert.equal(fromProofTier('proof-failed'), 'CANDIDATE');
});

test('every oracle type is deterministic over an observation and timeouts are inconclusive, not negative', () => {
  const base = { exitCode: 0, stdout: '', stderr: '', nonce: 'n', secrets: { http: 'S-http', db: 'S-db', auth: 'S-auth' }, canaries: { command: { exists: true, existedBefore: false }, fs: { exists: true, existedBefore: false }, db: { digestBefore: 'a', digestAfter: 'b' } }, callbacks: [{ nonce: 'n' }] };
  assert.equal(evaluateOracle({ type: 'command_execution' }, base).fired, true);
  assert.equal(evaluateOracle({ type: 'filesystem_mutation' }, base).fired, true);
  assert.equal(evaluateOracle({ type: 'database_mutation' }, base).fired, true);
  assert.equal(evaluateOracle({ type: 'outbound_callback' }, base).fired, true);
  assert.equal(evaluateOracle({ type: 'outbound_callback' }, { ...base, callbacks: [{ nonce: 'other' }] }).fired, false);
  assert.equal(evaluateOracle({ type: 'unauthorized_http_access' }, { ...base, stdout: 'x S-http' }).fired, true);
  assert.equal(evaluateOracle({ type: 'unauthorized_db_read' }, { ...base, stdout: 'S-db' }).fired, true);
  assert.equal(evaluateOracle({ type: 'authentication_bypass' }, { ...base, stdout: 'S-auth' }).fired, true);
  assert.equal(evaluateOracle({ type: 'authentication_bypass' }, base).fired, false);
  assert.equal(evaluateOracle({ type: 'crash_sanitizer' }, { ...base, signal: 'SIGSEGV' }).fired, true);
  assert.equal(evaluateOracle({ type: 'crash_sanitizer' }, { ...base, stderr: 'ERROR: AddressSanitizer: stack-buffer-overflow' }).fired, true);
  assert.equal(evaluateOracle({ type: 'arbitrary_assertion', params: { assert: { exitCode: 0 } } }, base).fired, true);
  const t = evaluateOracle({ type: 'command_execution' }, { ...base, canaries: { command: { exists: false } }, timedOut: true });
  assert.equal(t.fired, false); assert.equal(t.inconclusive, true);
  assert.equal(evaluateOracle({ type: 'made_up' }, base).unsupported, true);
  assert.equal(ORACLE_TYPES.length, 9);
});

test('reproducer validation rejects traversal, shell strings, unknown placeholders, reserved names', () => {
  assert.deepEqual(validateReproducer(repro()), []);
  assert.ok(validateReproducer(repro({ files: { '../x': 'a' } })).length);
  assert.ok(validateReproducer(repro({ files: { 'canary/x': 'a' } })).length);
  assert.ok(validateReproducer(repro({ files: { '__oracle_x': 'a' } })).length);
  assert.ok(validateReproducer(repro({ run: 'node a.mjs' })).length);
  assert.ok(validateReproducer(repro({ files: { 'a': '{{EVIL}}' } })).length);
  assert.ok(validateReproducer(repro({ oracle: { type: 'x' } })).length);
  assert.ok(validateReproducer(repro({ lang: 'cobol' })).length);
  assert.equal(isSafeRelPath('/etc/passwd'), false);
});

test('3/3 plus independent replay confirms; state ladder reached', async () => {
  const r = await proveFinding({ finding, reproducer: repro(), deps: { attemptFn: att(true) } });
  assert.equal(r.state, 'EXPLOIT_CONFIRMED');
  assert.equal(r.attempts.successes, 3);
  assert.equal(r.independentReplay.status, 'confirmed');
  assert.equal(r.completeness, 'DEGRADED'); // lower-assurance local confinement is disclosed, not hidden
});

test('2/3 does not confirm', async () => {
  let n = 0;
  const r = await proveFinding({ finding, reproducer: repro(), deps: { attemptFn: async (...a) => att(n++ < 2)(...a) } });
  assert.notEqual(r.state, 'EXPLOIT_CONFIRMED');
  assert.equal(r.outcome, 'reproduced-below-threshold');
});

test('timeouts are incomplete evidence, never clean and never confirmed', async () => {
  const r = await proveFinding({ finding, reproducer: repro(), deps: { attemptFn: att(false, 'error', { reasons: ['timed out'] }) } });
  assert.equal(r.completeness, 'INCOMPLETE');
  assert.equal(r.outcome, 'inconclusive');
  assert.ok(r.degradation.some((d) => d.startsWith('incomplete-attempts')));
  assert.notEqual(r.state, 'EXPLOIT_CONFIRMED');
});

test('decisive negatives report not-reproduced, with an explicit not-a-safety-proof note', async () => {
  const r = await proveFinding({ finding, reproducer: repro(), deps: { attemptFn: att(false) } });
  assert.equal(r.outcome, 'not-reproduced');
  assert.match(r.note, /not proof of safety/);
  assert.equal(r.state, 'REPRODUCER_GENERATED');
});

test('failed independent replay blocks confirmation', async () => {
  let n = 0;
  const r = await proveFinding({ finding, reproducer: repro(), deps: { attemptFn: async (...a) => att(n++ < 3)(...a) } });
  assert.equal(r.state, 'REPRODUCED');
  assert.equal(r.independentReplay.status, 'not-reproduced');
});

test('verifier rejects extra inputs such as prior reasoning', async () => {
  const v = { ...verifierView({ revision: 'abc', reproducer: repro(), findingId: 'F1', oracle: repro().oracle }), reasoning: 'the model thinks...' };
  assert.equal((await independentVerify(v, { attemptFn: att(true) })).status, 'rejected');
});

test('configurable threshold', async () => {
  let n = 0;
  const r = await proveFinding({ finding, reproducer: repro(), policy: { attempts: 5, required: 2 }, deps: { attemptFn: async (...a) => { const i = n++; return att(i < 2 || i >= 5)(...a); } } });
  assert.equal(r.attempts.run, 5);
  assert.equal(r.state, 'EXPLOIT_CONFIRMED');
});

test('severity policy is opt-in and demotes unproven criticals', () => {
  assert.equal(applySeverityPolicy({ severity: 'critical' }, 'CANDIDATE', undefined).severity, 'critical');
  const d = applySeverityPolicy({ severity: 'critical' }, 'REPRODUCED', { criticalRequires: ['EXPLOIT_CONFIRMED'] });
  assert.equal(d.severity, 'high'); assert.ok(d.severityPolicy);
  assert.equal(applySeverityPolicy({ severity: 'critical' }, 'EXPLOIT_CONFIRMED', { criticalRequires: ['EXPLOIT_CONFIRMED'] }).severity, 'critical');
});
