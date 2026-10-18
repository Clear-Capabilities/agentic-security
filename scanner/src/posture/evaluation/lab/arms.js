// Arms: the things the Eval Lab measures (PRD 6). An arm is the deterministic scanner, or a model reached through a small
// operator-supplied command. There is deliberately no built-in provider client here: provider calls in this repository go through
// the feature gate, the egress policy, redaction and the audit chain, and the lab must not become a second path around them.
// An arm whose model is not local is therefore checked against the egress policy BEFORE it runs, and a denial is recorded as
// `blocked`, not as a score.
//
// Honesty rules enforced here:
//   * `local` is declared, never inferred, and a "local" arm that names a non-loopback endpoint is refused as a lie;
//   * there is no fallback from one arm to another, so a local model can never silently become a cloud call;
//   * the command receives its request in a FILE and answers on stdout; it never reads stdin, and it runs with a scrubbed
//     environment, a wall-clock timeout and cleanup of its whole process tree (`superviseSpawn`);
//   * everything the lab sends is passed through the leakage guard first, and a hit blocks the call;
//   * token and dollar usage are whatever the arm reports and are labelled `reported`; absent usage is `unknown`, never zero.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { superviseSpawn } from '../../../sandbox/supervise.js';
import { scrubEnv } from '../../../sandbox/trust-domains.js';
import { evaluateEgress } from '../../../egress/policy.js';
import { guardPrompt } from '../custody.js';
import { defaultScanFn } from '../runner.js';
import { LAYER_ENV } from '../scan-child.js';

export const TASKS = Object.freeze(['detect', 'falsify', 'exploit', 'patch']);
const ARM_KINDS = Object.freeze(['deterministic', 'model']);
const ID_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;
const LOOPBACK = /^(?:https?:\/\/)?(?:localhost|127(?:\.\d{1,3}){3}|\[::1\])(?::\d+)?(?:\/|$)/i;

export function validateArm(a) {
  const errors = [];
  const bad = (m) => errors.push(m);
  if (!a || typeof a !== 'object') return { ok: false, errors: ['arm must be an object'] };
  if (typeof a.id !== 'string' || !ID_RE.test(a.id)) bad('arm.id must be a lower-case identifier');
  if (!ARM_KINDS.includes(a.kind)) bad(`arm.kind must be one of ${ARM_KINDS.join(', ')}`);
  if (!Array.isArray(a.tasks) || !a.tasks.length || !a.tasks.every((t) => TASKS.includes(t))) bad(`arm.tasks must list some of ${TASKS.join(', ')}`);
  const ad = a.adapter;
  if (!ad || typeof ad !== 'object') bad('arm.adapter is required');
  else if (ad.type === 'builtin-scanner') {
    if (a.kind !== 'deterministic') bad('the builtin-scanner adapter is the deterministic arm');
    if (a.tasks?.some((t) => t !== 'detect')) bad('the deterministic scanner only performs the detect task');
    if (ad.layer !== undefined && !['deterministic-only', 'deep-taint'].includes(ad.layer)) bad('adapter.layer must be deterministic-only or deep-taint (a model layer is a model arm)');
  } else if (ad.type === 'command') {
    if (!Array.isArray(ad.argv) || !ad.argv.length || !ad.argv.every((x) => typeof x === 'string' && x.length < 2000 && !x.includes('\0'))) bad('adapter.argv must be a non-empty array of strings (no shell string)');
    if (ad.timeoutMs !== undefined && !(Number.isInteger(ad.timeoutMs) && ad.timeoutMs >= 1000 && ad.timeoutMs <= 3_600_000)) bad('adapter.timeoutMs must be between 1000 and 3600000');
  } else bad('adapter.type must be builtin-scanner or command');
  if (a.kind === 'model') {
    const m = a.model;
    if (!m || typeof m.id !== 'string' || !m.id || typeof m.provider !== 'string' || !m.provider) bad('a model arm needs model.id and model.provider');
    else {
      if (typeof m.local !== 'boolean') bad('model.local must be true or false; it is declared, never inferred');
      if (m.local === true && m.endpoint && !LOOPBACK.test(String(m.endpoint))) bad('model.local is true but model.endpoint is not a loopback address');
      if (m.local === false && (typeof m.endpoint !== 'string' || !m.endpoint)) bad('a non-local model arm must name its endpoint so the egress policy can judge it');
    }
    if (a.kind === 'model' && ad?.type === 'builtin-scanner') bad('a model arm needs a command adapter');
  }
  if (a.price !== undefined) {
    const p = a.price;
    if (!p || !(Number.isFinite(p.inputPerMTok) && p.inputPerMTok >= 0 && Number.isFinite(p.outputPerMTok) && p.outputPerMTok >= 0)) bad('arm.price needs non-negative inputPerMTok and outputPerMTok');
  }
  return { ok: errors.length === 0, errors };
}

/** Dollars from reported tokens and a declared price, or the arm's own reported figure. `unknown` is null, never zero. */
export function usageOf(arm, reported, latencyMs) {
  const u = reported && typeof reported === 'object' ? reported : {};
  const num = (x) => (Number.isFinite(x) && x >= 0 ? x : null);
  const inputTokens = num(u.inputTokens); const outputTokens = num(u.outputTokens);
  let usd = num(u.usd); let source = usd != null ? 'reported' : 'unknown';
  if (usd == null && arm.price && inputTokens != null && outputTokens != null) {
    usd = (inputTokens * arm.price.inputPerMTok + outputTokens * arm.price.outputPerMTok) / 1e6; source = 'computed-from-reported-tokens';
  }
  if (arm.kind === 'deterministic') { usd = 0; source = 'no-model'; }
  return { inputTokens, outputTokens, usd, usdSource: source, latencyMs };
}

const normalizeFinding = (f) => ({ file: String(f.file ?? ''), line: Number.isInteger(f.line) ? f.line : null, cwe: f.cwe ?? null, confidence: typeof f.confidence === 'number' ? f.confidence : null });

/**
 * Run one task for one arm. Never throws, never returns a score: it returns what happened.
 * @returns {{status: 'completed'|'timeout'|'error'|'blocked'|'unavailable', reason?: string, output?: object, usage: object}}
 */
export async function runArmTask({ arm, task, request, workspaceDir, terms = [], scanRoot, signal, timeoutMs = 120_000, egress = evaluateEgress, scanFn = defaultScanFn }) {
  const t0 = Date.now();
  const done = (status, extra = {}) => ({ status, usage: usageOf(arm, extra.reported, Date.now() - t0), ...extra, reported: undefined });
  if (!arm.tasks.includes(task)) return done('unavailable', { reason: `arm does not perform ${task}` });
  if (arm.adapter.type === 'builtin-scanner') {
    const layer = arm.adapter.layer ?? 'deep-taint';
    try {
      const res = await scanFn(workspaceDir, { layer, timeoutMs, env: { ...scrubEnv(process.env), ...LAYER_ENV[layer] } });
      return done('completed', { output: { findings: (res.findings || []).map(normalizeFinding) } });
    } catch (e) {
      return done(e.code === 'TIMEOUT' ? 'timeout' : e.code === 'UNAVAILABLE' ? 'unavailable' : 'error', { reason: String(e.message).slice(0, 200) });
    }
  }
  // model arm through the command adapter
  if (arm.model.local === false) {
    const d = egress({ scanRoot, purpose: 'eval-lab', endpoint: arm.model.endpoint, model: arm.model.id, provider: arm.model.provider, role: `eval-${task}`, dataClass: 'source-code' });
    if (!d.allowed) return done('blocked', { reason: `egress policy: ${d.reason}` });
  }
  const guard = guardPrompt(JSON.stringify(request), terms);
  if (!guard.ok) return done('blocked', { reason: `leakage guard: the request contained a protected term (${guard.leaks[0]?.kind})` });
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'eval-arm-'));
  try {
    const reqFile = path.join(dir, 'request.json');
    fs.writeFileSync(reqFile, JSON.stringify(request));
    const argv = arm.adapter.argv.map((x) => x.split('{{REQUEST}}').join(reqFile));
    const env = { ...scrubEnv(process.env), AGENTIC_EVAL_REQUEST: reqFile, AGENTIC_EVAL_TASK: task };
    const r = await superviseSpawn(argv[0], argv.slice(1), { cwd: dir, env, timeoutMs: arm.adapter.timeoutMs ?? timeoutMs, signal, maxOutputBytes: MAX_RESPONSE_BYTES });
    if (r.spawnError) return done('error', { reason: `could not start the arm: ${r.spawnError}` });
    if (r.timedOut) return done('timeout', { reason: 'the arm did not answer within its time limit' });
    if (r.cancelled) return done('error', { reason: 'cancelled' });
    if (r.outputCapped) return done('error', { reason: 'the arm answered with more output than allowed' });
    if (r.exitCode !== 0) return done('error', { reason: `the arm exited ${r.exitCode}${r.exitSignal ? ` (${r.exitSignal})` : ''}` });
    let body;
    try { body = JSON.parse(r.stdout); } catch { return done('error', { reason: 'invalid-response: the arm did not print JSON' }); }
    if (!body || typeof body !== 'object' || Array.isArray(body)) return done('error', { reason: 'invalid-response: expected a JSON object' });
    const out = {};
    if (task === 'detect') { if (!Array.isArray(body.findings)) return done('error', { reason: 'invalid-response: detect needs "findings"', reported: body.usage }); out.findings = body.findings.slice(0, 5000).filter((f) => f && typeof f === 'object').map(normalizeFinding); }
    else if (task === 'falsify') { if (!body.verdicts || typeof body.verdicts !== 'object') return done('error', { reason: 'invalid-response: falsify needs "verdicts"', reported: body.usage }); out.verdicts = Object.fromEntries(Object.entries(body.verdicts).slice(0, 5000).map(([k, v]) => [k, ['confirmed', 'refuted', 'uncertain'].includes(v) ? v : 'uncertain'])); }
    else if (task === 'exploit') { if (!body.reproducer || typeof body.reproducer !== 'object') return done('completed', { output: { reproducer: null }, reported: body.usage }); out.reproducer = body.reproducer; }
    else if (task === 'patch') { if (!body.files || typeof body.files !== 'object' || Array.isArray(body.files)) return done('completed', { output: { files: null }, reported: body.usage }); out.files = Object.fromEntries(Object.entries(body.files).slice(0, 64).filter(([k, v]) => typeof k === 'string' && typeof v === 'string' && v.length < 1_000_000)); }
    return done('completed', { output: out, reported: body.usage });
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}
