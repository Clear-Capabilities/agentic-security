// Single entry point for confined execution.
//
// Fail-closed by construction: when no confinement primitive is available the
// disabled backend is selected, which REFUSES to execute. There is deliberately
// no code path that runs target code unconfined.
//
// Result shape (identical for every backend):
//   { status, denied, stdout, stderr, exitCode, timedOut, backend }
// status: 'ok' | 'blocked' | 'nonzero' | 'timeout' | 'disabled' | 'error'.
// See result.js for what 'blocked' vs 'nonzero' mean and, importantly, what
// `denied:false` does NOT prove. runConfined never throws — a bad root or an
// invalid limit returns status 'error', because a caller that catches and
// falls back is a route to unconfined execution.
import { detectBackend } from './capabilities.js';
import { runDisabled } from './backend-disabled.js';
import { runUserspace } from './backend-userspace.js';
import { runNamespace } from './backend-namespace.js';

export { detectBackend, resetCapabilityCache } from './capabilities.js';

export function sandboxAvailable() {
  return detectBackend() !== 'disabled';
}

export function runConfined(argv, opts = {}) {
  const backend = detectBackend({ force: opts.force });
  if (backend === 'userspace') return runUserspace(argv, opts);
  if (backend === 'namespace') return runNamespace(argv, opts);
  return runDisabled(argv, opts);
}
