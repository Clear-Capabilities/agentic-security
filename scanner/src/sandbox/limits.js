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

  if (maxProcs != null) parts.push(`ulimit -u ${maxProcs}`);
  if (maxFileSizeKb != null) parts.push(`ulimit -f ${maxFileSizeKb}`);

  if (maxAddressSpaceKb != null) {
    if (process.platform === 'linux') parts.push(`ulimit -v ${maxAddressSpaceKb}`);
    else unsupported.push('maxAddressSpaceKb');
  }

  const prelude = parts.length ? parts.join('; ') + '; ' : '';
  return { prelude, unsupported };
}
