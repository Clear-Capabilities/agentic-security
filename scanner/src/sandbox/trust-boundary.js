// The execution boundary between target/worker code and the verifier
// (CORE-003). Every verifier-side execution of untrusted code goes through
// `runInBoundary`; it is where the trust domains are ENFORCED rather than
// described.
//
// Order of operations, and why each step exists:
//   1. Refuse secret material in the environment bound for the target.
//   2. Refuse a workspace that overlaps a protected path (a root that CONTAINS
//      the key directory would hand the target the keys by construction).
//   3. Probe the backend's controls actively (cached per process). Any required
//      control that is not `proved` makes the result `blocked` and NOTHING runs.
//      Insufficient isolation is never a pass and never a warning.
//   4. Run supervised, with protected paths read-denied, a scrubbed environment
//      and a process-tree deadline.
//   5. Report. The status is formed from what the boundary observed, never from
//      what the target printed; target output is returned labelled untrusted.
import fs from 'node:fs';
import path from 'node:path';
import { detectBackend } from './capabilities.js';
import { runConfinedSupervised } from './supervise.js';
import { probeControls, unmetControls } from './control-probes.js';
import {
  protectedReadPaths, assertNoSecretMaterial, classifyRun, countStatusLikeLines,
} from './trust-domains.js';

export const DEFAULT_REQUIRED_CONTROLS = Object.freeze([
  'write-confinement', 'read-denial', 'env-scrub', 'tree-termination', 'file-size-limit',
]);

function _real(p) { try { return fs.realpathSync(p); } catch { return path.resolve(p); } }
function _overlaps(a, b) {
  const x = _real(a), y = _real(b);
  return x === y || x.startsWith(y + path.sep) || y.startsWith(x + path.sep);
}

function _blocked(reasons, extra = {}) {
  return {
    status: 'blocked', blocked: true, executed: false, denied: false, reasons,
    verificationStatus: 'not-run', targetOutput: null, ...extra,
  };
}

/**
 * @param {string[]} argv
 * @param {object}   o
 * @param {string}   o.root          the target's only writable directory
 * @param {string[]} [o.labelDirs]     sealed-label directories (read-denied)
 * @param {string[]} [o.evidenceDirs]  authoritative-evidence directories (read-denied, and write-denied by confinement)
 * @param {string[]} [o.denyReadPaths] further host paths to read-deny
 * @param {object}   [o.env]           explicit variables for the target; secret-looking ones are refused
 * @param {string[]} [o.require]       controls that must be `proved`
 * @param {string}   [o.home]          home directory whose credential dirs are denied
 * @param {boolean}  [o.allowNetwork]
 * @param {AbortSignal} [o.signal]     cancel
 * @param {object}   [o.controlProbes] probe overrides (test seam)
 */
export async function runInBoundary(argv, o = {}) {
  const {
    root, labelDirs = [], evidenceDirs = [], denyReadPaths = [], env = {},
    allowNetwork = false, timeoutMs = 10000, graceMs = 1000, signal, force, limits,
    maxOutputBytes, controlProbes,
  } = o;
  const required = [...(o.require || DEFAULT_REQUIRED_CONTROLS)];
  if (!allowNetwork && !required.includes('network')) required.push('network');

  if (!root || typeof root !== 'string') return _blocked(['no workspace root']);
  const backend = detectBackend({ force });
  if (backend === 'disabled') {
    return _blocked(['no confinement backend works on this host; the target was not executed'], { backend });
  }

  const secrets = assertNoSecretMaterial(env);
  if (!secrets.ok) {
    return _blocked([`secret-looking variables refused for the target: ${secrets.offenders.join(', ')}`], { backend });
  }

  const protectedPaths = protectedReadPaths({
    ...(o.home ? { home: o.home } : {}), labelDirs, evidenceDirs, extra: denyReadPaths,
  });
  const clash = protectedPaths.filter((p) => _overlaps(root, p));
  if (clash.length) {
    return _blocked([`the workspace overlaps protected path(s): ${clash.join(', ')}`], { backend });
  }

  const report = await probeControls({ force, probes: controlProbes || {} });
  const unmet = unmetControls(report, required);
  if (unmet.length) {
    return _blocked(
      unmet.map((u) => `control '${u.control}' is ${u.state}: ${u.reason}`),
      { backend, controls: report.controls },
    );
  }

  const r = await runConfinedSupervised(argv, {
    root, timeoutMs, graceMs, signal, force, allowNetwork, limits, maxOutputBytes,
    env, denyReadPaths: protectedPaths,
  });
  const executed = r.status !== 'disabled' && !(r.status === 'error' && !r.supervised);
  const run = { ...r, executed };
  return {
    status: r.status, blocked: false, executed, denied: r.denied, backend: r.backend,
    reasons: [], controls: report.controls,
    verificationStatus: classifyRun(run),
    // Target output is DATA. It is capped and labelled; it is never parsed for
    // a status. The count below is informational only.
    targetOutput: {
      trust: 'untrusted', stdout: r.stdout, stderr: r.stderr,
      statusLikeLines: countStatusLikeLines(r.stdout) + countStatusLikeLines(r.stderr),
    },
    exitCode: r.exitCode, timedOut: r.timedOut, cancelled: !!r.cancelled,
    outputCapped: !!r.outputCapped, termination: r.termination,
  };
}
