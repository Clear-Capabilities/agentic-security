// Threat-model PRD FR-06 (TM-08): under the restricted profile, a missing, malformed, unreadable or unsupported operator policy, an
// unknown operator mode and an invalid repository policy each deny BEFORE any model request; a valid policy is the positive control;
// a repository file can narrow the operator's policy and never widen it; the kill switch always wins. Proven through a real model
// caller (the validator) with transport counted at fetch.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { mkTestTmp } from './helpers/tmp.js';
import { evaluateEgress, loadPolicyState } from '../src/egress/policy.js';
import { validateMany } from '../src/llm-validator/index.js';
import { withReplayedModel } from './helpers/model-replay.js';

const KEYS = ['AGENTIC_SECURITY_EGRESS_PROFILE', 'AGENTIC_SECURITY_EGRESS_POLICY', 'AGENTIC_SECURITY_EGRESS_MODE', 'AGENTIC_SECURITY_EGRESS_DENY', 'AGENTIC_SECURITY_LLM_ENDPOINT', 'AGENTIC_SECURITY_LLM_API_KEY', 'AGENTIC_SECURITY_LLM_MODEL'];
async function withEnv(env, fn) {
  const was = Object.fromEntries(KEYS.map((k) => [k, process.env[k]]));
  for (const k of KEYS) delete process.env[k];
  Object.assign(process.env, env);
  try { return await fn(); } finally { for (const k of KEYS) { if (was[k] === undefined) delete process.env[k]; else process.env[k] = was[k]; } }
}
const SECRET = 'sk-test-SHOULD-NEVER-APPEAR-1234567890';
const MODEL = { AGENTIC_SECURITY_LLM_ENDPOINT: 'https://models.example.com/v1/chat/completions', AGENTIC_SECURITY_LLM_API_KEY: SECRET, AGENTIC_SECURITY_LLM_MODEL: 'm' };

function project({ repoPolicy = null } = {}) {
  const dir = mkTestTmp('egress-prof-');
  fs.writeFileSync(path.join(dir, 'app.js'), 'const x = 1;\neval(req.query.q);\n');
  if (repoPolicy !== null) { fs.mkdirSync(path.join(dir, '.agentic-security'), { recursive: true }); fs.writeFileSync(path.join(dir, '.agentic-security', 'egress-policy.yml'), repoPolicy); }
  return dir;
}
function operatorPolicy(text) { const d = mkTestTmp('egress-op-'); const p = path.join(d, 'operator-egress.yml'); fs.writeFileSync(p, text); return p; }

/** Run the validator on one finding and count the requests that reached transport. */
async function attempt(env, dir) {
  let requests = 0;
  const finding = { id: 'F1', file: 'app.js', line: 2, severity: 'high', vuln: 'Code injection', cwe: 'CWE-94', parser: 'SAST' };
  await withEnv({ ...MODEL, ...env }, () => withReplayedModel({ reply: { challenge: '{{challenge}}', file: '{{file}}', line: '{{line}}', verdict: 'accept', confidence: 0.9, reasoning: 'r' } }, async () => {
    const inner = global.fetch;
    global.fetch = async (...a) => { requests++; return inner(...a); };
    try { await validateMany([finding], { fileContents: { 'app.js': fs.readFileSync(path.join(dir, 'app.js'), 'utf8') }, scanRoot: dir }); } finally { global.fetch = inner; }
  }));
  const decision = await withEnv({ ...MODEL, ...env }, () => evaluateEgress({ scanRoot: dir, purpose: 'validate', endpoint: MODEL.AGENTIC_SECURITY_LLM_ENDPOINT }));
  return { requests, decision, finding };
}

test('AC-06A: every invalid restricted configuration denies before transport, with a distinct reason code', async () => {
  const dir = project();
  const unreadable = mkTestTmp('egress-dir-'); // a directory where a file was expected
  const cases = [
    ['absent', { AGENTIC_SECURITY_EGRESS_PROFILE: 'restricted' }, 'operator-policy-absent'],
    ['malformed', { AGENTIC_SECURITY_EGRESS_PROFILE: 'restricted', AGENTIC_SECURITY_EGRESS_POLICY: operatorPolicy('mode: [unclosed\n  - x: {') }, 'operator-policy-malformed'],
    ['unreadable', { AGENTIC_SECURITY_EGRESS_PROFILE: 'restricted', AGENTIC_SECURITY_EGRESS_POLICY: unreadable }, 'operator-policy-unreadable'],
    ['unsupported mode in the file', { AGENTIC_SECURITY_EGRESS_PROFILE: 'restricted', AGENTIC_SECURITY_EGRESS_POLICY: operatorPolicy('mode: sometimes\n') }, 'operator-policy-unsupported'],
    ['valid deny', { AGENTIC_SECURITY_EGRESS_PROFILE: 'restricted', AGENTIC_SECURITY_EGRESS_POLICY: operatorPolicy('mode: deny\n') }, 'policy-deny'],
    ['unknown operator mode', { AGENTIC_SECURITY_EGRESS_MODE: 'yolo' }, 'operator-mode-unknown'],
    ['unknown profile', { AGENTIC_SECURITY_EGRESS_PROFILE: 'paranoid' }, 'profile-unknown'],
  ];
  for (const [name, env, code] of cases) {
    const r = await attempt(env, dir);
    assert.equal(r.requests, 0, `${name}: no request reached transport`);
    assert.equal(r.decision.allowed, false, name);
    assert.equal(r.decision.reasonCode, code, name);
    assert.equal(r.decision.enforcement, 'enforced', name);
    const text = JSON.stringify(r.decision) + JSON.stringify(r.finding);
    assert.ok(!text.includes(SECRET), `${name}: the key never appears`);
    if (env.AGENTIC_SECURITY_EGRESS_POLICY) assert.ok(!text.includes(env.AGENTIC_SECURITY_EGRESS_POLICY), `${name}: the operator policy path is not disclosed`);
  }
});

test('AC-06A: a valid approved destination succeeds under the restricted profile, and the kill switch still wins', async () => {
  const dir = project();
  const allow = { AGENTIC_SECURITY_EGRESS_PROFILE: 'restricted', AGENTIC_SECURITY_EGRESS_POLICY: operatorPolicy('mode: allow\n') };
  const ok = await attempt(allow, dir);
  assert.equal(ok.decision.allowed, true, JSON.stringify(ok.decision));
  assert.equal(ok.requests, 1, 'the allowed control really reaches transport');
  assert.equal(ok.decision.profile, 'restricted'); assert.match(ok.decision.policyIdentity, /^sha256:[0-9a-f]{16}$/);
  const killed = await attempt({ ...allow, AGENTIC_SECURITY_EGRESS_DENY: '1' }, dir);
  assert.equal(killed.decision.allowed, false); assert.equal(killed.requests, 0);
});

test('AC-06B: a hostile repository policy can narrow the operator policy but never widen it; an invalid one denies', async () => {
  const op = { AGENTIC_SECURITY_EGRESS_PROFILE: 'restricted', AGENTIC_SECURITY_EGRESS_POLICY: operatorPolicy('mode: local-only\n') };
  const widen = await attempt(op, project({ repoPolicy: 'mode: allow\n' }));
  assert.equal(widen.decision.allowed, false, 'a repository mode: allow does not lift an operator local-only');
  assert.equal(widen.requests, 0);
  const narrowOp = { AGENTIC_SECURITY_EGRESS_PROFILE: 'restricted', AGENTIC_SECURITY_EGRESS_POLICY: operatorPolicy('mode: allow\n') };
  const narrowed = await attempt(narrowOp, project({ repoPolicy: 'mode: deny\n' }));
  assert.equal(narrowed.decision.allowed, false, 'the repository can add a deny'); assert.equal(narrowed.requests, 0);
  const broken = await attempt(narrowOp, project({ repoPolicy: 'mode: [\n' }));
  assert.equal(broken.decision.reasonCode, 'repository-policy-malformed'); assert.equal(broken.requests, 0);
});

test('outside the restricted profile the legacy default holds and an invalid present policy is reported, not hidden', async () => {
  const dir = project({ repoPolicy: 'mode: [deny\n' });
  const r = await withEnv(MODEL, () => evaluateEgress({ scanRoot: dir, purpose: 'validate', endpoint: MODEL.AGENTIC_SECURITY_LLM_ENDPOINT }));
  assert.equal(r.allowed, true, 'the documented legacy default');
  assert.equal(r.enforcement, 'legacy-default'); assert.equal(r.policyState.repository, 'malformed');
  assert.match(r.configurationWarning, /malformed and was ignored/);
  assert.equal(r.reasonCode, 'allowed-legacy-default');
  assert.equal(loadPolicyState(null).status, 'absent');
});
