// Execution profile: finite limits, scoped permissions, suite -> argv mapping.
// Validation is strict because the profile is the only thing standing between
// an unattended worker and an unbounded or over-permissive run.
import { readFileSync } from 'node:fs';
import { resolve, relative, isAbsolute } from 'node:path';
import { sha256, canonicalJson } from './util.mjs';

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

export function insideRepo(repoRoot, p) {
  if (isAbsolute(p)) return false;
  const abs = resolve(repoRoot, p);
  const rel = relative(repoRoot, abs);
  return rel === '' || (!rel.startsWith('..') && !isAbsolute(rel));
}

export function validateProfile(p, repoRoot) {
  const problems = [];
  if (!p || typeof p !== 'object') throw new ProfileError(['profile must be an object']);
  const L = p.limits || {};
  for (const k of REQUIRED_LIMITS) {
    if (typeof L[k] !== 'number' || !Number.isFinite(L[k]) || L[k] <= 0) problems.push(`limits.${k} must be a finite positive number (budgets are never unbounded)`);
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
  if (!p.watch || !p.watch.LOOP) problems.push('watch globs missing');
  if (problems.length) throw new ProfileError(problems);
  return true;
}

export function suiteCommand(suite) {
  return { executable: suite.executable, args: ['--test', ...suite.files], cwd: suite.cwd };
}
