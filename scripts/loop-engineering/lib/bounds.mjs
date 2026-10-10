// Finite bounds for everything the controller itself launches or calls out to (LOOP-002).
//
// Three controls live here, all driven by the execution profile's `limits`:
//   * subprocessWallSeconds / killGraceSeconds: a HELPER subprocess (git, a tool probe, anything with no declared per-command timeout of
//     its own) is bounded by subprocessWallSeconds and killed as a PROCESS GROUP: TERM, the grace period, then KILL. Suites, gates and the
//     worker are not helpers; each has its own declared timeoutSeconds (a suite's is held to its class ceiling by the profile validator),
//     and runBounded (proc.mjs) already kills those as a group too.
//   * networkRequestSeconds / networkRetries / retryBackoffMaxSeconds: see netbound.mjs, which reads the policy configured here.
//
// A plain `timeout` on execFileSync kills only the direct child, which is the defect this module exists to remove: a hung git hook or an
// ssh helper below the direct child would outlive its bound. runBoundedSync runs the command under a tiny group-leader process that
// signals the whole group, then sweeps the group when the command ends, so nothing it started can outlive it.
import { spawnSync } from 'node:child_process';

export const DEFAULT_BOUNDS = Object.freeze({ subprocessWallSeconds: 120, killGraceSeconds: 10 });

let configured = { ...DEFAULT_BOUNDS, networkRequestSeconds: null, networkRetries: null, retryBackoffMaxSeconds: 60 };

/** Called once the profile is loaded. Unset network fields leave network calls on their legacy behaviour (profiles that predate them). */
export function configureBounds(limits = {}) {
  const pick = (k, d) => (Number.isFinite(limits[k]) && limits[k] > 0 ? limits[k] : d);
  configured = {
    subprocessWallSeconds: pick('subprocessWallSeconds', DEFAULT_BOUNDS.subprocessWallSeconds),
    killGraceSeconds: pick('killGraceSeconds', DEFAULT_BOUNDS.killGraceSeconds),
    networkRequestSeconds: Number.isFinite(limits.networkRequestSeconds) && limits.networkRequestSeconds > 0 ? limits.networkRequestSeconds : null,
    networkRetries: Number.isInteger(limits.networkRetries) && limits.networkRetries >= 0 ? limits.networkRetries : null,
    retryBackoffMaxSeconds: pick('retryBackoffMaxSeconds', 60),
  };
  return getBounds();
}
export const getBounds = () => ({ ...configured });

/** The wall time a helper subprocess gets: its own declared bound if shorter, never more than subprocessWallSeconds. */
export function helperWallSeconds(declaredSeconds, b = configured) {
  const cap = b.subprocessWallSeconds;
  return Number.isFinite(declaredSeconds) && declaredSeconds > 0 ? Math.min(declaredSeconds, cap) : cap;
}

// The group leader. argv: wallMs graceMs command args...  Exit 124 on a timeout (the conventional code), else the command's own code.
const SYNC_RUNNER = `
import { spawn } from 'node:child_process';
const [wallMs, graceMs, cmd, ...args] = process.argv.slice(1);
const c = spawn(cmd, args, { stdio: ['ignore', 'inherit', 'inherit'], detached: true });
const sig = (s) => { try { process.kill(-c.pid, s); } catch { /* the group is already gone */ } };
const groupAlive = () => { try { process.kill(-c.pid, 0); return true; } catch { return false; } };
let timedOut = false;
const t = setTimeout(() => {
  timedOut = true;
  sig('SIGTERM');
  const end = Date.now() + Number(graceMs);
  const poll = setInterval(() => {
    if (!groupAlive() || Date.now() >= end) { clearInterval(poll); sig('SIGKILL'); setTimeout(() => process.exit(124), 30); }
  }, 25);
}, Number(wallMs));
c.on('error', (e) => { console.error('could not start: ' + e.message); process.exit(127); });
c.on('exit', (code, signal) => { if (timedOut) return; clearTimeout(t); sig('SIGKILL'); process.exit(code ?? (signal ? 128 : 1)); });
`;

/**
 * Run a helper command to completion with a hard bound. Never throws for a failing command; returns
 * { status, signal, timedOut, error, stdout, stderr }. status is null on a timeout.
 */
export function runBoundedSync(cmd, args = [], opts = {}) {
  const b = opts.bounds || configured;
  const wallS = helperWallSeconds(opts.wallSeconds, b);
  const graceS = Number.isFinite(opts.graceSeconds) && opts.graceSeconds >= 0 ? opts.graceSeconds : b.killGraceSeconds;
  const r = spawnSync(process.execPath, ['--input-type=module', '-e', SYNC_RUNNER, String(Math.round(wallS * 1000)), String(Math.round(graceS * 1000)), cmd, ...args], {
    cwd: opts.cwd, env: opts.env, encoding: opts.encoding === 'buffer' ? 'buffer' : 'utf8', maxBuffer: opts.maxBuffer || 64 * 1024 * 1024,
    // backstop only: the runner enforces the bound itself; this exists so a wedged runner cannot hold the caller
    timeout: Math.round((wallS + graceS) * 1000) + 10_000, killSignal: 'SIGKILL',
  });
  const timedOut = r.status === 124 || r.error?.code === 'ETIMEDOUT';
  return {
    status: timedOut ? null : r.status, signal: r.signal || null, timedOut,
    error: r.error && r.error.code !== 'ETIMEDOUT' ? String(r.error.message) : null,
    stdout: r.stdout ?? '', stderr: r.stderr ?? '', wallSeconds: wallS, graceSeconds: graceS,
  };
}

/** execFileSync-shaped: returns stdout, throws (with status, stdout, stderr, timedOut) on a non-zero exit, a timeout or a start failure. */
export function execBoundedSync(cmd, args = [], opts = {}) {
  const r = runBoundedSync(cmd, args, opts);
  if (r.timedOut || r.error || r.status !== 0) {
    const e = new Error(r.timedOut ? `${cmd} exceeded its ${r.wallSeconds}s bound and its process group was killed` : r.error ? `${cmd}: ${r.error}` : `${cmd} exited ${r.status}`);
    Object.assign(e, { status: r.status, signal: r.signal, timedOut: r.timedOut, stdout: r.stdout, stderr: r.stderr });
    throw e;
  }
  return r.stdout;
}

// ---------------------------------------------------------------- profile validation (pure; imported by profile.mjs)

export const SUITE_CLASSES = Object.freeze(['standard', 'runtime-integration', 'full-evaluation']);
const num = (v) => typeof v === 'number' && Number.isFinite(v) && v > 0;

export function validateBoundsConfig(p, problems) {
  const L = p.limits || {};
  const hasReq = L.networkRequestSeconds !== undefined, hasRet = L.networkRetries !== undefined;
  if (hasReq || hasRet) {
    if (!num(L.networkRequestSeconds) || L.networkRequestSeconds > 3600) problems.push('limits.networkRequestSeconds must be a finite number of seconds in (0, 3600] (set together with networkRetries)');
    if (!Number.isInteger(L.networkRetries) || L.networkRetries < 0 || L.networkRetries > 10) problems.push('limits.networkRetries must be an integer in [0, 10] (set together with networkRequestSeconds)');
  }
  if (L.unknownBillingReserveUsd !== undefined) {
    if (!num(L.unknownBillingReserveUsd)) problems.push('limits.unknownBillingReserveUsd must be a finite positive number: unknown billing is never zero-cost');
    else if (num(L.claudeBudgetUsd) && L.unknownBillingReserveUsd > L.claudeBudgetUsd) problems.push('limits.unknownBillingReserveUsd exceeds the whole-run claudeBudgetUsd, so no paid attempt could ever start');
  }
  if (L.suiteCeilings !== undefined) {
    const C = L.suiteCeilings;
    if (!C || typeof C !== 'object') problems.push('limits.suiteCeilings must be an object');
    else {
      for (const k of SUITE_CLASSES) {
        const c = C[k];
        if (!c || !num(c.ceilingSeconds) || !num(c.childLeaseSeconds)) { problems.push(`limits.suiteCeilings.${k} needs finite positive ceilingSeconds and childLeaseSeconds`); continue; }
        if (c.childLeaseSeconds > c.ceilingSeconds) problems.push(`limits.suiteCeilings.${k}.childLeaseSeconds ${c.childLeaseSeconds} exceeds its ceilingSeconds ${c.ceilingSeconds}`);
      }
      for (const k of Object.keys(C)) if (!SUITE_CLASSES.includes(k)) problems.push(`limits.suiteCeilings.${k} is not a suite class (${SUITE_CLASSES.join(', ')})`);
      for (const [name, s] of Object.entries(p.suites || {})) {
        if (s.kind !== 'node-test') continue;
        const c = C[s.class];
        if (!SUITE_CLASSES.includes(s.class) || !c) { problems.push(`suite ${name}: class must be one of ${SUITE_CLASSES.join(', ')} when limits.suiteCeilings is set`); continue; }
        if (num(s.timeoutSeconds) && s.timeoutSeconds > c.ceilingSeconds) problems.push(`suite ${name}: timeoutSeconds ${s.timeoutSeconds} exceeds the ${s.class} ceiling of ${c.ceilingSeconds}s`);
        if (s.childLeaseSeconds !== undefined && (!num(s.childLeaseSeconds) || s.childLeaseSeconds > c.ceilingSeconds)) problems.push(`suite ${name}: childLeaseSeconds must be finite and no more than the ${s.class} ceiling of ${c.ceilingSeconds}s`);
      }
    }
  } else {
    for (const [name, s] of Object.entries(p.suites || {})) if (s.class !== undefined || s.childLeaseSeconds !== undefined) problems.push(`suite ${name}: class/childLeaseSeconds need limits.suiteCeilings`);
  }
  const E = p.providerEnvelope;
  if (E !== undefined) {
    if (!E || typeof E !== 'object' || typeof E.enabled !== 'boolean') problems.push('providerEnvelope must be { enabled: boolean, capUsd, unknownBillingReserveUsd, preauthorization }');
    else {
      if (!num(E.capUsd)) problems.push('providerEnvelope.capUsd must be a finite positive number (the envelope is separate from claudeBudgetUsd and is never unbounded)');
      if (!num(E.unknownBillingReserveUsd) || (num(E.capUsd) && E.unknownBillingReserveUsd > E.capUsd)) problems.push('providerEnvelope.unknownBillingReserveUsd must be a finite positive number no more than capUsd');
      if (E.enabled) {
        const a = E.preauthorization;
        if (!a || typeof a.by !== 'string' || !a.by.trim() || Number.isNaN(Date.parse(a.at)) || !num(a.capUsd)) problems.push('providerEnvelope.enabled needs preauthorization { by, at, capUsd }: an envelope is spent only when a person authorized it in the profile');
        else if (num(E.capUsd) && a.capUsd < E.capUsd) problems.push(`providerEnvelope.preauthorization.capUsd ${a.capUsd} is below the envelope cap ${E.capUsd}`);
      }
    }
  }
  for (const g of [...(p.baselineGates || []), ...(p.finalGates || []), ...((p.finalVerification?.closure?.measuredGates) || [])]) {
    if (g.costUsd !== undefined && !num(g.costUsd)) problems.push(`gate ${g.id}: costUsd must be a finite positive number`);
    if (g.costUnknown !== undefined && typeof g.costUnknown !== 'boolean') problems.push(`gate ${g.id}: costUnknown must be a boolean`);
    if (g.costUsd !== undefined && g.costUnknown) problems.push(`gate ${g.id}: declare costUsd or costUnknown, not both`);
    if ((g.costUsd !== undefined || g.costUnknown) && !E) problems.push(`gate ${g.id}: a paid step needs a providerEnvelope block (even a disabled one, so the refusal is explicit)`);
  }
}

/** The ceiling and per-child lease for a suite, or null when the profile has no suiteCeilings. */
export function suiteBounds(profile, suiteName) {
  const C = profile.limits?.suiteCeilings;
  const s = profile.suites?.[suiteName];
  if (!C || !s) return null;
  const c = C[s.class];
  if (!c) return null;
  return { class: s.class, ceilingSeconds: c.ceilingSeconds, childLeaseSeconds: Math.min(s.childLeaseSeconds ?? c.childLeaseSeconds, c.ceilingSeconds) };
}
