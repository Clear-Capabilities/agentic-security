// Resource caps applied as a shell prelude, shared by every real backend.
//
// Address-space capping (`ulimit -v`) is NOT enforced on the macOS family —
// verified by execution. We therefore DECLARE it unsupported rather than
// emitting a limit that silently does nothing, which would be a false
// assurance of containment.
export function buildLimitPrelude({
  maxProcs = 64,
  maxFileSizeKb = 65536,
  maxAddressSpaceKb = null,
} = {}) {
  const parts = [];
  const unsupported = [];

  if (maxProcs != null) parts.push(`ulimit -u ${_num('maxProcs', maxProcs)}`);
  if (maxFileSizeKb != null) parts.push(`ulimit -f ${_num('maxFileSizeKb', maxFileSizeKb)}`);

  if (maxAddressSpaceKb != null) {
    if (process.platform === 'linux') parts.push(`ulimit -v ${_num('maxAddressSpaceKb', maxAddressSpaceKb)}`);
    else unsupported.push('maxAddressSpaceKb');
  }

  const prelude = parts.length ? parts.join('; ') + '; ' : '';
  return { prelude, unsupported };
}

/**
 * Limit values are interpolated into a shell fragment, so a non-numeric value
 * is shell text. Verified by execution: `maxProcs: '999; echo INJECTED'`
 * emitted `ulimit -u 999; echo INJECTED` and the payload ran. That is not a
 * sandbox escape (the prelude runs INSIDE the confinement) but it lets a
 * config-derived value silently DISABLE the very limits it was meant to set —
 * e.g. `'0 2>/dev/null; true'` swallows the failure. Coerce and reject
 * anything that is not a finite, non-negative number.
 */
function _num(name, v) {
  const n = Number(v);
  if (!Number.isFinite(n) || n < 0) {
    throw new RangeError(`${name} must be a finite, non-negative number (got ${JSON.stringify(v)})`);
  }
  return Math.floor(n);
}
