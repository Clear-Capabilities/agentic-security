// Fail-closed backend. Selected when no confinement primitive is available.
// It must NEVER execute the command — an unavailable sandbox disables
// execution features, it does not bypass them.
export function runDisabled(_argv, _opts) {
  return {
    status: 'disabled',
    denied: false,
    stdout: '',
    stderr: 'agentic-security: refusing to execute — no confinement primitive available on this host.',
    exitCode: null,
    timedOut: false,
    backend: 'disabled',
  };
}
