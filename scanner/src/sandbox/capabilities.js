// Detects which OS confinement primitive is available. Fail-closed: when none
// is found we report 'disabled', which REFUSES execution rather than running
// target code unconfined.
//
// DETECTION IS FUNCTIONAL, NOT PRESENCE-BASED. An earlier version concluded
// "available" from "the confinement binary is executable". That is a different
// question from the one callers are actually asking. Verified on a Linux CI
// runner: the kernel-namespace tool is installed and executable, but the
// distribution restricts unprivileged user-namespace creation, so every
// privilege variant fails and no confined command can start. Presence-based
// detection reported the backend as available anyway, and `sandboxAvailable()`
// — the signal callers use to decide whether it is safe to EXECUTE UNTRUSTED
// CODE — answered true while nothing could actually be confined. False
// assurance about confinement is precisely the failure this module exists to
// prevent, so a backend now counts as available only if it just ran a trivial
// command through its real code path.
//
// The probe result is cached for the process (one spawn, not one per call —
// detection sits on the path of ordinary scans) and cleared by
// `resetCapabilityCache()`.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { runUserspace } from './backend-userspace.js';
import { runNamespace } from './backend-namespace.js';

// Referenced by path, never by product name (see Global Constraints).
//
// Each family lists every plausible install location, probed in order. A
// single hardcoded path is safe (a miss fails closed to 'disabled') but it is
// a FALSE NEGATIVE: a host that does have the primitive somewhere else loses
// the sandbox silently. Probing the candidate set removes that failure mode.
export const CONFINE_BINS_USERSPACE = Object.freeze([
  '/usr/bin/sandbox-exec',
  '/usr/local/bin/sandbox-exec',
]);
export const CONFINE_BINS_NAMESPACE = Object.freeze([
  '/usr/bin/unshare',
  '/bin/unshare',
  '/usr/local/bin/unshare',
  '/sbin/unshare',
  '/usr/sbin/unshare',
]);

// The filesystem-attach utility used by the namespace backend to establish
// write confinement (read-only rebind of the whole mount tree, read-write
// rebind of the sandbox root). Resolved by path for the same reason as the
// others. Absent => the namespace backend cannot establish write confinement
// and fails closed; it never runs a command with the filesystem open.
export const CONFINE_BINS_MOUNT = Object.freeze([
  '/usr/bin/mount',
  '/bin/mount',
  '/sbin/mount',
  '/usr/sbin/mount',
]);

// The privilege-dropping utility used to remove CAP_SYS_ADMIN (and everything
// else) from the confined process *after* the mounts are in place, so the
// payload cannot simply undo the read-only rebinds. Best-effort hardening on
// top of the mount confinement, not the confinement itself: when it is absent
// the run still happens under the read-only mount tree and the result declares
// `privilegeDrop` unenforced rather than staying silent about it.
export const CONFINE_BINS_PRIVDROP = Object.freeze([
  '/usr/bin/setpriv',
  '/bin/setpriv',
  '/sbin/setpriv',
  '/usr/sbin/setpriv',
]);

// Back-compat single-path exports: the first (canonical) candidate.
export const CONFINE_BIN_USERSPACE = CONFINE_BINS_USERSPACE[0];
export const CONFINE_BIN_NAMESPACE = CONFINE_BINS_NAMESPACE[0];

let _cached = null;

// Which namespace-flag variant actually works on this host, keyed by the
// requested confinement shape. Probing costs a process spawn, so it is done
// once; `undefined` means "not probed yet", `null` means "probed and nothing
// worked" (which the backend turns into a fail-closed error, never a run).
const _nsVariant = new Map();

export function resetCapabilityCache() { _cached = null; _nsVariant.clear(); }

export function cachedNamespaceVariant(key) {
  return _nsVariant.has(key) ? _nsVariant.get(key) : undefined;
}
export function cacheNamespaceVariant(key, value) { _nsVariant.set(key, value); }

/** First executable candidate, or null when none of them exists. */
export function resolveConfineBin(candidates) {
  for (const p of candidates) if (_isExecutable(p)) return p;
  return null;
}

export function resolveUserspaceBin() { return resolveConfineBin(CONFINE_BINS_USERSPACE); }
export function resolveNamespaceBin() { return resolveConfineBin(CONFINE_BINS_NAMESPACE); }
export function resolveMountBin() { return resolveConfineBin(CONFINE_BINS_MOUNT); }
export function resolvePrivDropBin() { return resolveConfineBin(CONFINE_BINS_PRIVDROP); }

// Bounded on purpose: a capability check must never hang a scan. The probe is
// a single `exit 0` under confinement, so anything beyond a couple of seconds
// is a host that is not going to answer.
const PROBE_TIMEOUT_MS = Math.max(
  250,
  Number(process.env.AGENTIC_SECURITY_SANDBOX_PROBE_TIMEOUT_MS) || 4000,
);

/**
 * Run a trivial command through a backend's real code path and report whether
 * confinement actually worked. Anything other than a clean confined run — a
 * missing binary, a refused namespace, a timeout, a throw — is `false`. There
 * is deliberately no branch that relaxes confinement to make a probe pass: a
 * backend that can only succeed with a flag dropped is not available, it is
 * `'disabled'`.
 */
function _probeThroughBackend(runner) {
  let root = null;
  try {
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'agsec-sbx-probe-'));
    const r = runner(['/bin/sh', '-c', 'exit 0'], { root, timeoutMs: PROBE_TIMEOUT_MS });
    return r?.status === 'ok';
  } catch {
    return false;
  } finally {
    if (root) { try { fs.rmSync(root, { recursive: true, force: true }); } catch { /* best effort */ } }
  }
}

/**
 * The real probes, one per backend. The binary check stays only as a cheap
 * pre-filter that avoids a pointless temp dir on a host that plainly lacks the
 * primitive — it is no longer the answer, just the fast negative.
 */
export function defaultProbes() {
  return {
    userspace: () => (resolveUserspaceBin() ? _probeThroughBackend(runUserspace) : false),
    namespace: () => (resolveNamespaceBin() ? _probeThroughBackend(runNamespace) : false),
  };
}

/** Backends worth probing on a platform, most-appropriate first. */
export function backendCandidates(platform = process.platform) {
  if (platform === 'darwin') return ['userspace'];
  if (platform === 'linux') return ['namespace'];
  return [];
}

/**
 * @param {object}   [o]
 * @param {string}   [o.force]      Bypass detection entirely (tests, and callers
 *                                  that want the disabled path deliberately).
 * @param {object}   [o.probes]     Probe map override — a seam for tests to drive
 *                                  the selection contract with stand-ins on any
 *                                  platform. Cannot cause unconfined execution:
 *                                  dispatch still goes to the real backend.
 * @param {string[]} [o.candidates] Candidate order override (same seam).
 */
export function detectBackend({ force, probes, candidates } = {}) {
  if (force) return force;
  if (_cached) return _cached;

  const probeMap = probes || defaultProbes();
  const order = candidates || backendCandidates();

  let b = 'disabled';
  for (const name of order) {
    const probe = probeMap[name];
    if (typeof probe !== 'function') continue;
    let works = false;
    try { works = probe() === true; } catch { works = false; }
    if (works) { b = name; break; }
    // Otherwise fall through to the next candidate, and ultimately to
    // 'disabled' — never to "run it anyway".
  }
  _cached = b;
  return b;
}

function _isExecutable(p) {
  try { fs.accessSync(p, fs.constants.X_OK); return true; } catch { return false; }
}
