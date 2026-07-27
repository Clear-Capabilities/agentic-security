// Detects which OS confinement primitive is available. Fail-closed: when none
// is found we report 'disabled', which REFUSES execution rather than running
// target code unconfined.
import fs from 'node:fs';

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

// Back-compat single-path exports: the first (canonical) candidate.
export const CONFINE_BIN_USERSPACE = CONFINE_BINS_USERSPACE[0];
export const CONFINE_BIN_NAMESPACE = CONFINE_BINS_NAMESPACE[0];

let _cached = null;

export function resetCapabilityCache() { _cached = null; }

/** First executable candidate, or null when none of them exists. */
export function resolveConfineBin(candidates) {
  for (const p of candidates) if (_isExecutable(p)) return p;
  return null;
}

export function resolveUserspaceBin() { return resolveConfineBin(CONFINE_BINS_USERSPACE); }
export function resolveNamespaceBin() { return resolveConfineBin(CONFINE_BINS_NAMESPACE); }

export function detectBackend({ force } = {}) {
  if (force) return force;
  if (_cached) return _cached;
  let b = 'disabled';
  if (process.platform === 'darwin' && resolveUserspaceBin()) b = 'userspace';
  else if (process.platform === 'linux' && resolveNamespaceBin()) b = 'namespace';
  _cached = b;
  return b;
}

function _isExecutable(p) {
  try { fs.accessSync(p, fs.constants.X_OK); return true; } catch { return false; }
}
