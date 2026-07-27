// Single entry point for confined execution.
//
// Fail-closed by construction: when no confinement primitive is available the
// disabled backend is selected, which REFUSES to execute. There is deliberately
// no code path that runs target code unconfined.
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
