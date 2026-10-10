// Execution profile: finite limits, scoped permissions, suite -> argv mapping.
// Validation is strict because the profile is the only thing standing between
// an unattended worker and an unbounded or over-permissive run.
import { readFileSync, existsSync } from 'node:fs';
import { resolve, relative, isAbsolute } from 'node:path';
import { sha256, canonicalJson } from './util.mjs';
import { STALE_AFTER_MS } from './state.mjs';
import { validateClosureConfig } from './closure-config.mjs';

export class ProfileError extends Error {
  constructor(problems) { super(`invalid execution profile:\n  - ${problems.join('\n  - ')}`); this.name = 'ProfileError'; this.problems = problems; }
}

const REQUIRED_LIMITS = ['heartbeatSeconds', 'workerIdleSeconds', 'noProgressSeconds', 'subprocessWallSeconds', 'killGraceSeconds', 'claudeAttemptSeconds', 'claudeMaxTurns',
  'attemptsPerRequirement', 'sameFailureRepeats', 'runWallSeconds', 'runMaxAttempts', 'claudeBudgetUsd', 'perAttemptBudgetUsd', 'retryBackoffMaxSeconds'];

export function loadProfile(path) {
  let raw;
  try { raw = readFileSync(path, 'utf8'); } catch (e) { throw new ProfileError([`cannot read ${path}: ${e.code || e.message}`]); }
  let p;
  try { p = JSON.parse(raw); } catch (e) { throw new ProfileError([`${path} is not valid JSON: ${e.message}`]); }
  return { profile: p, sha256: sha256(canonicalJson(p)) };
}

export const SUPPORTED_PROFILE_VERSION = 1;
const WORKSTREAM_KINDS = ['product', 'foundation', 'loop', 'documentation', 'release'];

// Optional workstream grouping (backwards compatible: a profile without a
// `workstreams` block behaves exactly as before). A requirement belongs to
// exactly one workstream, chosen by ordered prefix/number-range rules.
export function workstreamMatches(ws, id) {
  const m = /^([A-Z]+)-(\d+)$/.exec(id);
  if (!m || !ws || !Array.isArray(ws.assign)) return [];
  const n = Number(m[2]);
  return ws.assign.filter((r) => r.prefix === m[1] && (r.from === undefined || (n >= r.from && n <= r.to))).map((r) => r.workstream);
}

function validateWorkstreams(ws, problems) {
  if (typeof ws !== 'object' || ws === null || Array.isArray(ws)) { problems.push('workstreams must be an object'); return; }
  const order = ws.order;
  if (!Array.isArray(order) || !order.length || order.some((x) => typeof x !== 'string' || !x) || new Set(order).size !== order.length) { problems.push('workstreams.order must be a non-empty list of unique names'); return; }
  const defs = ws.definitions || {};
  for (const name of order) {
    const d = defs[name];
    if (!d) { problems.push(`workstreams.definitions.${name} is missing`); continue; }
    if (typeof d.label !== 'string' || !d.label) problems.push(`workstreams.definitions.${name}.label is required`);
    if (!WORKSTREAM_KINDS.includes(d.kind)) problems.push(`workstreams.definitions.${name}.kind must be one of ${WORKSTREAM_KINDS.join(', ')}`);
    if (!Array.isArray(d.watch) || !d.watch.length || d.watch.some((g) => typeof g !== 'string' || !g)) problems.push(`workstreams.definitions.${name}.watch must be a non-empty list of globs (every requirement needs an evidence watch set)`);
  }
  for (const name of Object.keys(defs)) if (!order.includes(name)) problems.push(`workstreams.definitions.${name} is not listed in workstreams.order`);
  if (ws.globalWatch !== undefined && (!Array.isArray(ws.globalWatch) || ws.globalWatch.some((g) => typeof g !== 'string' || !g))) problems.push('workstreams.globalWatch must be a list of globs');
  if (!Array.isArray(ws.assign) || !ws.assign.length) { problems.push('workstreams.assign must be a non-empty list of rules'); return; }
  ws.assign.forEach((r, i) => {
    if (typeof r.prefix !== 'string' || !/^[A-Z]+$/.test(r.prefix)) problems.push(`workstreams.assign[${i}].prefix must be an upper-case ID prefix`);
    if (!order.includes(r.workstream)) problems.push(`workstreams.assign[${i}].workstream "${r.workstream}" is not a defined workstream`);
    const hasRange = r.from !== undefined || r.to !== undefined;
    if (hasRange && (!Number.isInteger(r.from) || !Number.isInteger(r.to) || r.from > r.to)) problems.push(`workstreams.assign[${i}] needs integer from <= to`);
  });
}

// Disclosure list of PRD-named controls this controller cannot enforce.
function validateUnenforced(list, problems) {
  if (!Array.isArray(list)) { problems.push('unenforced must be a list'); return; }
  list.forEach((u, i) => {
    if (!u || typeof u.field !== 'string' || !u.field) problems.push(`unenforced[${i}].field is required`);
    if (!u || typeof u.note !== 'string' || !u.note.trim()) problems.push(`unenforced[${i}].note must say why the control is not enforced`);
  });
}

// Why a profile cannot launch even though it is structurally valid: suites that
// are declared not runnable yet, or whose supervisor-authored wrapper is
// missing. Returns [{ suite, reason }]. Suites workers write themselves
// (no protectedWrapper flag) are never blocked here, so existing profiles are unaffected.
export function suiteLaunchBlockers(profile, repoRoot) {
  const out = [];
  for (const [name, s] of Object.entries(profile.suites || {})) {
    if (s.notYetRunnable) { out.push({ suite: name, reason: `declared not yet runnable: ${s.notYetRunnable.reason}` }); continue; }
    if (s.protectedWrapper && s.kind === 'node-test') {
      const missing = (s.files || []).filter((f) => !existsSync(resolve(repoRoot, s.cwd || '.', f)));
      if (missing.length) out.push({ suite: name, reason: `protected wrapper file(s) not found: ${missing.join(', ')}; author them in the supervising session before launch` });
    }
  }
  return out;
}

export function insideRepo(repoRoot, p) {
  if (isAbsolute(p)) return false;
  const abs = resolve(repoRoot, p);
  const rel = relative(repoRoot, abs);
  return rel === '' || (!rel.startsWith('..') && !isAbsolute(rel));
}

export function validateProfile(p, repoRoot) {
  const problems = [];
  if (!p || typeof p !== 'object') throw new ProfileError(['profile must be an object']);
  if (p.profileVersion !== SUPPORTED_PROFILE_VERSION) problems.push(`profileVersion ${JSON.stringify(p.profileVersion)} is not supported: this controller reads profileVersion ${SUPPORTED_PROFILE_VERSION}; migrate the profile or use a controller that supports it`);
  const L = p.limits || {};
  for (const k of REQUIRED_LIMITS) {
    if (typeof L[k] !== 'number' || !Number.isFinite(L[k]) || L[k] <= 0) problems.push(`limits.${k} must be a finite positive number (budgets are never unbounded)`);
  }
  if (typeof L.heartbeatSeconds === 'number' && L.heartbeatSeconds * 3 > STALE_AFTER_MS / 1000) problems.push(`limits.heartbeatSeconds ${L.heartbeatSeconds} is too slow: a controller is judged stale after ${STALE_AFTER_MS / 1000}s, so the heartbeat must be at most ${STALE_AFTER_MS / 3000}s`);
  if (p.finalVerification !== undefined && (typeof p.finalVerification !== 'object' || p.finalVerification === null || typeof p.finalVerification.required !== 'boolean')) problems.push('finalVerification must be { required: boolean }');
  if (p.finalVerification?.closure !== undefined) {
    if (!p.finalVerification.required) problems.push('finalVerification.closure needs finalVerification.required to be true');
    problems.push(...validateClosureConfig(p.finalVerification.closure, (p.finalGates || []).map((g) => g.id)));
  }
  if (L.claudeBudgetUsd && L.perAttemptBudgetUsd && L.perAttemptBudgetUsd > L.claudeBudgetUsd) problems.push('limits.perAttemptBudgetUsd exceeds the whole-run budget');
  const W = p.worker || {};
  if (W.concurrency !== 1) problems.push('worker.concurrency must be 1 (isolated worktrees are required before raising it)');
  if (!['dontAsk', 'acceptEdits', 'default', 'manual', 'plan'].includes(W.permissionMode)) problems.push(`worker.permissionMode "${W.permissionMode}" is not an approved non-bypass mode`);
  if (!Array.isArray(W.allowedTools) || !W.allowedTools.length) problems.push('worker.allowedTools must be a non-empty scoped allow list');
  else for (const t of W.allowedTools) {
    if (t === 'Bash' || t === 'Bash(*)' || t === '*' || /^Bash\(\*?:?\*\)$/.test(t)) problems.push(`worker.allowedTools contains unscoped "${t}"`);
  }
  if (!Array.isArray(W.disallowedTools) || !W.disallowedTools.length) problems.push('worker.disallowedTools must deny publishing/host-changing operations');
  else {
    for (const need of ['Bash(git push:*)', 'Bash(npm publish:*)', 'Bash(nixos-rebuild:*)']) if (!W.disallowedTools.includes(need)) problems.push(`worker.disallowedTools must include ${need}`);
  }
  const serve = p.serve || {};
  if (serve.host !== '127.0.0.1') problems.push('serve.host must be 127.0.0.1 (loopback only)');
  const approved = new Set(p.approvedExecutables || []);
  if (!approved.size) problems.push('approvedExecutables is empty');
  const checkCmd = (label, c) => {
    if (!c || typeof c !== 'object') { problems.push(`${label}: missing`); return; }
    if (!approved.has(c.executable)) problems.push(`${label}: executable "${c.executable}" is not approved`);
    if (!Array.isArray(c.args) || c.args.some((a) => typeof a !== 'string')) problems.push(`${label}: args must be an array of strings (no shell strings)`);
    if (typeof c.cwd !== 'string' || !insideRepo(repoRoot, c.cwd)) problems.push(`${label}: cwd "${c.cwd}" must be a relative path inside the repository`);
    if (!Number.isInteger(c.timeoutSeconds) || c.timeoutSeconds <= 0) problems.push(`${label}: timeoutSeconds must be a positive integer`);
  };
  if (!p.suites || !Object.keys(p.suites).length) problems.push('suites is empty');
  for (const [name, s] of Object.entries(p.suites || {})) {
    if (!['node-test', 'controller-final'].includes(s.kind)) problems.push(`suite ${name}: unknown kind ${s.kind}`);
    if (s.kind === 'node-test') {
      checkCmd(`suite ${name}`, { ...s, args: ['--test', ...(s.files || [])] });
      if (!s.files || !s.files.length) problems.push(`suite ${name}: node-test suite must name at least one test file`);
      if (s.notYetRunnable !== undefined && (typeof s.notYetRunnable?.reason !== 'string' || !s.notYetRunnable.reason.trim())) problems.push(`suite ${name}: notYetRunnable needs a reason`);
      for (const f of s.files || []) if (!f.endsWith('.test.js') || f.startsWith('/') || f.includes('..')) problems.push(`suite ${name}: bad test file path "${f}"`);
    }
  }
  for (const [name, s] of Object.entries(p.suites || {})) {
    if (!s.remote) continue;
    const r = s.remote;
    if (typeof r.workflow !== 'string' || !/^[A-Za-z0-9._-]+\.yml$/.test(r.workflow)) problems.push(`suite ${name}: remote.workflow must be a workflow file name`);
    if (!['nix', 'nixos'].includes(r.target)) problems.push(`suite ${name}: remote.target must be nix or nixos`);
    if (!Array.isArray(r.legs) || !r.legs.length || r.legs.some((l) => typeof l !== 'string' || !l)) problems.push(`suite ${name}: remote.legs must name at least one leg`);
    if (!Number.isInteger(r.timeoutSeconds) || r.timeoutSeconds <= 0) problems.push(`suite ${name}: remote.timeoutSeconds must be a positive integer`);
    if (!(s.requiresTools || []).length) problems.push(`suite ${name}: remote is only reached when a required tool is missing, so requiresTools must name one`);
  }
  for (const g of [...(p.baselineGates || []), ...(p.finalGates || [])]) checkCmd(`gate ${g.id}`, g);
  if (p.workstreams !== undefined) validateWorkstreams(p.workstreams, problems);
  if (p.unenforced !== undefined) validateUnenforced(p.unenforced, problems);
  if (!p.watch || !p.watch.LOOP) problems.push('watch globs missing');
  if (problems.length) throw new ProfileError(problems);
  return true;
}

export function suiteCommand(suite) {
  return { executable: suite.executable, args: ['--test', ...suite.files], cwd: suite.cwd };
}
