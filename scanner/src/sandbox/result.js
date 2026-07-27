// Shared result construction for every real backend.
//
// WHY THIS EXISTS (the misread it prevents): status used to be derived purely
// from the exit code — `exitCode !== 0` was reported as `'blocked'`. That
// conflates two entirely different outcomes:
//
//   1. A program that ran fine and chose to exit non-zero (a failing test, a
//      grep with no match) was labelled 'blocked' — a false confinement claim.
//   2. A program whose out-of-root write was DENIED but which still exited 0
//      was labelled 'ok' — the caller saw a clean run and could not tell that
//      the sandbox had refused something. Verified by execution: the denied
//      write returns exit 0 when the command swallows the failure.
//
// So the two signals are now separated:
//
//   - `denied`  — a confinement violation was OBSERVED in the child's error
//                 output. Best effort, see the honesty note below.
//   - `status`  — 'blocked' when a denial was observed, 'nonzero' when the
//                 command merely exited non-zero with no denial signal, 'ok'
//                 only when it exited 0 with no denial signal.
//
// HONESTY NOTE — what `denied:false` does and does not mean. The denial signal
// is read from the confined process's own stderr (the OS primitives here do
// not hand the parent a structured violation channel). A program that writes
// out of root and swallows its own error message produces NO signal, so
// `denied:false` means "no denial was observed", NOT "no denial occurred".
// Never treat `status:'ok'` as proof that nothing was refused. It is proof
// only that the command exited 0 and said nothing about a refusal.

const DENIAL_PATTERNS = [
  /operation not permitted/i,
  /permission denied/i,
  /read-only file system/i,
  /deny file-write/i,
  /deny network/i,
  /network is unreachable/i,
];

/** True iff the confined process's error output shows an observed denial. */
export function detectDenial(stderr) {
  const s = String(stderr || '');
  return DENIAL_PATTERNS.some((re) => re.test(s));
}

/**
 * Build the single result shape every backend returns. `status` is one of
 * 'ok' | 'blocked' | 'nonzero' | 'timeout' | 'disabled' | 'error'.
 */
export function buildResult({ backend, spawnResult, unsupported = [] }) {
  const r = spawnResult;
  const rawStderr = r.stderr ?? '';
  const timedOut = r.error?.code === 'ETIMEDOUT';
  const denied = detectDenial(rawStderr);

  let status;
  if (timedOut) status = 'timeout';
  else if (r.error) status = 'error';
  else if (denied) status = 'blocked';
  else if (r.status !== 0) status = 'nonzero';
  else status = 'ok';

  return {
    status,
    denied,
    stdout: r.stdout ?? '',
    stderr: rawStderr + (unsupported.length ? `\n[sandbox] limits not enforceable here: ${unsupported.join(', ')}` : ''),
    exitCode: r.status ?? null,
    timedOut,
    backend,
  };
}

/** Documented-shape error result: runConfined never throws at its callers. */
export function errorResult(backend, message) {
  return {
    status: 'error',
    denied: false,
    stdout: '',
    stderr: `agentic-security: ${message}`,
    exitCode: null,
    timedOut: false,
    backend,
  };
}

/**
 * Minimal environment handed to untrusted code. The parent environment is NOT
 * forwarded: it routinely carries credentials (tokens, cloud keys, registry
 * auth) and the confined program can read and exfiltrate them. This is a
 * distinct exposure from the accepted "reads are not confined" scope cut —
 * that one is about files on disk, this one is about secrets the parent hands
 * over for free. Callers that need extra variables pass them explicitly via
 * `opts.env`, which is merged on top of this base.
 */
export function buildConfinedEnv({ root, env = {} } = {}) {
  return {
    PATH: '/usr/bin:/bin:/usr/sbin:/sbin',
    ROOT: root,
    HOME: root,
    TMPDIR: root,
    LANG: 'C',
    ...env,
  };
}
