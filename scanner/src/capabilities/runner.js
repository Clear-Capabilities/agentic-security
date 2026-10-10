// The capability runner (X-502, X-503, X-504): where a manifest stops being a
// description and becomes a boundary.
//
// `runCapabilityTask(bound, request, opts)` executes ONE structured command (an
// absolute executable plus an argument array, never a shell string) for one
// bound task, and what it can touch is decided by the operating system, not by
// this file or by a hook:
//
//   filesystem  reads are confined to the declared roots (plus the handful of
//               system paths a process needs to start), writes to the declared
//               write roots and a private per-run scratch directory, protected
//               host paths are read-denied on top; a symbolic link or `..` that
//               leaves the roots is stopped by the kernel
//   commands    the executable and arguments are checked against the manifest
//               first (decide.js); the argument array reaches `exec` as an array,
//               so command substitution and expansion in an argument stay text;
//               shells, language runtimes and launchers are refused unless the
//               manifest declares them scoped with their exact arguments
//   network     no network at all unless the manifest declares destinations; then
//               exactly one door, the loopback mediation proxy (proxy.js); the
//               proxy settings are in the environment of the whole process tree,
//               and a socket opened any other way is refused by the kernel
//   descendants inherit all of the above (the confinement is inherited by every
//               child), are tracked, and are terminated on deadline,
//               cancellation, output flood or exit, with the evidence returned
//
// Gate, in order, each step typed and none of them a warning:
//   1. the `capability-enforcement` feature (operator-only: a project file cannot
//      turn it on), then the kill switches
//   2. the platform: only an advertised backend is `enforced`. A backend that is
//      not advertised (macOS) is `unsupported` for isolation-required tasks
//      unless the caller opts in with `allowUnadvertisedBackend`, in which case
//      the run is labelled `host-proved` and nothing is claimed enforced
//   3. the binding, the secret-free environment, the command policy, protected
//      paths
//   4. the active probes: any control the manifest depends on that is not
//      `proved` BLOCKS the run, and the target is never executed
//
// Incomplete backend controls block; they are never a warning and never a quiet
// fallback to less. On Linux the namespace backend does not implement the
// controls this needs yet, so every Linux run is blocked with the missing control
// named, and the platform statement says `unverified`.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { resolveAssuranceConfig, featureStatus, typed, limitValues } from '../posture/assurance/config.js';
import { detectBackend } from '../sandbox/capabilities.js';
import { runConfinedSupervised } from '../sandbox/supervise.js';
import { protectedReadPaths, assertNoSecretMaterial } from '../sandbox/trust-domains.js';
import { mediate } from './recovery.js';
import { reasonText } from './reasons.js';
import { canonicalPath, overlaps } from './paths.js';
import { probeCapabilityControls, requiredControlsFor, unmetControls, isAdvertisedBackend } from './probes.js';
import { startMediationProxy } from './proxy.js';
import { sanitizeLogText } from './outbound.js';
import { toCapabilityDecisionRecord } from './records.js';
import { buildCapabilityReport } from './report.js';

const FEATURE = 'capability-enforcement';

function blocked(code, reason, extra = {}) {
  return typed('blocked', code, reason, { executed: false, outcome: 'not-run', ...extra });
}

// X-506: a denial carries the missing capability and a reviewable proposed manifest
// change. The proposal is data for an operator; nothing here applies it.
function denied(m, extra = {}) {
  const d = m.decision;
  return blocked('capability-denied', `${d.code}: ${d.reason}`, {
    policyCode: d.code, decisions: [d], missing: m.missing, proposal: m.proposal,
    attemptsRemaining: m.attemptsRemaining, exhausted: m.exhausted, ...extra,
  });
}

function scrub(text, canaries) {
  return sanitizeLogText(text, canaries);
}

/**
 * @param {{manifest: object, binding: object}} bound  from `bindManifest`
 * @param {{executable: string, args?: string[], env?: object, cwd?: string}} request
 * @param {object} opts
 * @param {{taskId:string, revision:string, policyVersion:number}} opts.binding  the identity the caller acts for
 * @param {object} [opts.config]   resolved assurance config; default resolves from `opts.scanRoot` and the environment
 * @param {string} [opts.scanRoot]
 * @param {string[]} [opts.labelDirs]    sealed-label directories (never readable by the task)
 * @param {string[]} [opts.evidenceDirs] authoritative-evidence directories (never readable by the task)
 * @param {string[]} [opts.protectedPaths] further paths the task may never read
 * @param {string[]} [opts.canaries]     values that must not appear in arguments, environment, outbound payloads or returned output
 * @param {boolean} [opts.allowUnadvertisedBackend] run on a host-proved, non-advertised backend (development)
 * @param {AbortSignal} [opts.signal]
 * @param {string} [opts.force]          backend override (tests: 'disabled')
 * @param {object} [opts.controlProbes]  probe overrides (test seam)
 * @param {(host:string)=>Promise<string[]>} [opts.resolve] name resolution seam for the proxy
 * @param {string} [opts.home]           home directory whose credential directories are protected
 * @param {object} [opts.denialGuard]    from recovery.js `createDenialGuard`: bounds repeated denials of one action (X-506.AC03)
 */
export async function runCapabilityTask(bound, request, opts = {}) {
  const {
    binding, scanRoot = null, labelDirs = [], evidenceDirs = [], protectedPaths: extraProtected = [], canaries = [],
    allowUnadvertisedBackend = false, signal, force, controlProbes, resolve, home, denialGuard,
  } = opts;

  if (!request || typeof request !== 'object') return blocked('invalid-config', 'no task request');

  // 1. feature gate
  const config = opts.config || resolveAssuranceConfig({ scanRoot: scanRoot || undefined });
  const gate = featureStatus(config, FEATURE);
  let platformOptIn = false;
  if (gate.status === 'unsupported' && gate.code === 'platform-unsupported' && allowUnadvertisedBackend) platformOptIn = true;
  else if (gate.status !== 'ok') return { ...gate, executed: false, outcome: 'not-run' };

  if (!bound?.manifest || !bound?.binding) return blocked('invalid-config', 'no bound capability manifest');
  const ctx = { binding, canaries, protectedPaths: [] };

  // 3a. a secret-free environment, before anything else looks at the request
  const env = request && typeof request.env === 'object' && request.env ? request.env : {};
  const secrets = assertNoSecretMaterial(env);
  if (!secrets.ok) return blocked('capability-denied', `secret-looking environment variables are refused for tasks: ${secrets.offenders.join(', ')}`, { policyCode: 'secret-in-argument' });
  for (const [k, v] of Object.entries(env)) {
    if (typeof v !== 'string') return blocked('capability-denied', `environment variable ${k} is not a string`, { policyCode: 'args-invalid' });
    if (canaries.some((c) => c && String(v).includes(c))) return blocked('capability-denied', `environment variable ${k} carries a registered canary`, { policyCode: 'secret-in-argument' });
  }

  // 3b. command policy (also checks the binding)
  const protectedPaths = protectedReadPaths({ ...(home ? { home } : {}), labelDirs, evidenceDirs, extra: extraProtected });
  ctx.protectedPaths = protectedPaths;
  const cmdM = mediate(bound, { kind: 'command', executable: request?.executable, args: request?.args ?? [] }, ctx, { guard: denialGuard });
  const cmd = cmdM.decision;
  if (cmdM.status !== 'ok') return denied(cmdM);

  // 3c. the manifest's own roots may not contain protected paths
  const m = bound.manifest;
  const roots = [...m.filesystem.read, ...m.filesystem.write];
  for (const r of roots) {
    const cr = canonicalPath(r) ?? r;
    const clash = protectedPaths.find((p) => overlaps(cr, canonicalPath(p) ?? p));
    if (clash) return blocked('capability-denied', `protected-path: ${reasonText('protected-path')}`, { policyCode: 'protected-path', decisions: [] });
  }
  let cwdRequest = null;
  if (request.cwd !== undefined) {
    const cwdM = mediate(bound, { kind: 'filesystem-read', path: request.cwd }, ctx, { guard: denialGuard });
    if (cwdM.status !== 'ok') return denied(cwdM);
    cwdRequest = request.cwd;
  }

  // 2/4. backend and active probes
  const backend = detectBackend({ force });
  if (backend === 'disabled') {
    return typed('blocked', 'missing-execution-backend', 'no confinement backend works on this host; the task was not executed', { executed: false, outcome: 'not-run', backend });
  }
  const advertised = isAdvertisedBackend(backend);
  if (!advertised && !allowUnadvertisedBackend) {
    return typed('unsupported', 'platform-unsupported',
      `the ${backend} backend on ${process.platform} is not an advertised backend for enforced capability tasks; isolation-required tasks are unsupported here`,
      { executed: false, outcome: 'not-run', backend });
  }
  const probeReport = await probeCapabilityControls({ force, probes: controlProbes || {} });
  const required = requiredControlsFor(m);
  const unmet = unmetControls(probeReport, required);
  if (unmet.length) {
    return typed('blocked', 'missing-execution-backend',
      `incomplete backend controls block the task: ${unmet.map((u) => `${u.control} is ${u.state}`).join('; ')}`,
      {
        executed: false, outcome: 'not-run', backend, unmet,
        report: buildCapabilityReport({ bound, probeReport, level: 'none', required }),
      });
  }
  const level = advertised ? 'enforced' : 'host-proved';

  // 5. build the confinement and run
  const scratch = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'agsec-cap-run-')));
  let proxy = null;
  try {
    const exeReal = fs.realpathSync(request.executable);
    const limits = limitValues(config);
    const timeoutMs = m.resources.timeoutMs ?? limits.timeoutMs;
    const maxOutputBytes = m.resources.maxOutputBytes ?? limits.maxOutputBytes;
    const taskEnv = { ...env };
    if (m.network.length) {
      proxy = await startMediationProxy({ bound, canaries, resolve, scanRoot });
      for (const k of ['HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy', 'ALL_PROXY', 'all_proxy']) taskEnv[k] = proxy.url;
      taskEnv.NO_PROXY = ''; taskEnv.no_proxy = '';
    }
    const cwd = cwdRequest || (m.filesystem.write[0] ?? scratch);
    const r = await runConfinedSupervised([request.executable, ...(request.args ?? [])], {
      root: scratch, cwd,
      readRoots: [...m.filesystem.read, ...m.filesystem.write, exeReal],
      writeRoots: m.filesystem.write,
      denyReadPaths: protectedPaths,
      env: taskEnv, networkProxyPort: proxy ? proxy.port : null,
      timeoutMs, graceMs: 1000, maxOutputBytes, signal, force,
      limits: m.resources.maxFileSizeKb ? { maxFileSizeKb: m.resources.maxFileSizeKb } : {},
    });
    const executed = r.supervised === true;
    if (!executed) {
      return typed('blocked', 'missing-execution-backend', `the confined run could not start: ${scrub(String(r.stderr || '').split('\n')[0], canaries)}`, {
        executed: false, outcome: 'not-run', backend, report: buildCapabilityReport({ bound, probeReport, level: 'none', required }),
      });
    }
    const term = r.termination || { signalled: null, killedPids: [], survivors: [] };
    let outcome = 'exited';
    if (r.cancelled) outcome = 'cancelled';
    else if (r.timedOut) outcome = 'timeout';
    else if (r.outputCapped) outcome = 'output-limit';
    const cleanup = { signalled: term.signalled, killedPids: [...term.killedPids], survivors: [...term.survivors], complete: term.survivors.length === 0 };
    const report = buildCapabilityReport({ bound, probeReport, level, required });
    const enforced = level === 'enforced';
    const mk = (d, mediation) => toCapabilityDecisionRecord(d, { mediation, enforced, backend, probeDigest: probeReport.probeDigest });
    const records = [mk(cmd, 'runner')];
    for (const root of m.filesystem.read) records.push(mk({ ...cmd, kind: 'filesystem-read', subject: root }, 'runner'));
    for (const root of m.filesystem.write) records.push(mk({ ...cmd, kind: 'filesystem-write', subject: root }, 'runner'));
    if (proxy) {
      for (const n of proxy.records) {
        records.push(mk({
          kind: 'network', decision: n.outcome, code: n.code, reason: reasonText(n.code), taskId: m.taskId,
          subject: `${n.scheme ?? 'unknown'}://${n.destinationClass}#${n.hostDigest}:${n.port ?? 0}`,
        }, 'proxy'));
      }
    }
    const status = cleanup.complete ? 'ok' : 'degraded';
    return typed(status, cleanup.complete ? null : 'limit-exceeded',
      cleanup.complete ? `ran under ${level} confinement (${backend})` : 'processes survived termination', {
        executed: true, outcome, level, enforced, backend, exitCode: r.exitCode, denied: r.denied === true,
        timedOut: r.timedOut === true, cancelled: r.cancelled === true, outputCapped: r.outputCapped === true,
        // Everything the task printed is data from an untrusted party.
        output: { trust: 'untrusted', stdout: scrub(r.stdout, canaries), stderr: scrub(r.stderr, canaries) },
        cleanup, decisions: [cmd], capabilityDecisions: records.filter((x) => x.ok).map((x) => x.record),
        network: proxy ? { records: [...proxy.records], stats: { ...proxy.stats } } : null,
        report,
      });
  } finally {
    if (proxy) await proxy.close();
    try { fs.rmSync(scratch, { recursive: true, force: true }); } catch { /* best effort */ }
  }
}
