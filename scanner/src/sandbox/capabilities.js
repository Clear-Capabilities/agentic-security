// Detects which OS confinement primitive is available. Fail-closed: when none
// is found we report 'disabled', which REFUSES execution rather than running
// target code unconfined.
import fs from 'node:fs';

// Referenced by path, never by product name (see Global Constraints).
export const CONFINE_BIN_USERSPACE = '/usr/bin/sandbox-exec';
export const CONFINE_BIN_NAMESPACE = '/usr/bin/unshare';

let _cached = null;

export function resetCapabilityCache() { _cached = null; }

export function detectBackend({ force } = {}) {
  if (force) return force;
  if (_cached) return _cached;
  let b = 'disabled';
  if (process.platform === 'darwin' && _isExecutable(CONFINE_BIN_USERSPACE)) b = 'userspace';
  else if (process.platform === 'linux' && _isExecutable(CONFINE_BIN_NAMESPACE)) b = 'namespace';
  _cached = b;
  return b;
}

function _isExecutable(p) {
  try { fs.accessSync(p, fs.constants.X_OK); return true; } catch { return false; }
}
