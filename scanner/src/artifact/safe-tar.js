// Hand-rolled, hardened POSIX/GNU tar reader for OCI/Docker image archives.
//
// Why hand-rolled instead of a dependency: this repo has no tar library (see
// `src/artifact/CLAUDE.md`), and PRD 5's own Safety Requirements ask for exact
// control over the failure modes a generic tar library treats as implementation
// detail: malicious entry paths, decompression bombs, giant layers, oversized
// archives. Rolling it ourselves means every one of those limits is a named,
// tested constant in this file rather than a library default we'd have to audit.
//
// Scope: ustar + GNU longname ('L' typeflag) + base-256 size fields. PAX extended
// headers ('x'/'g') and GNU longlink ('K') are structurally skipped (their data
// block is consumed so offsets stay correct, but their content is not applied) —
// a disclosed limitation, not a silent one. Real docker-save/oci-archive output
// from Go's archive/tar for images in this size/complexity class essentially
// never needs them; synthetic fixtures in this codebase never emit them either.
import zlib from 'node:zlib';

const BLOCK = 512;

export const DEFAULT_LIMITS = Object.freeze({
  maxEntries: 200_000,
  maxEntrySize: 512 * 1024 * 1024, // 512MB per tar entry
  maxTotalSize: 4 * 1024 * 1024 * 1024, // 4GB per archive (sum of entry sizes)
  maxGunzipOutput: 4 * 1024 * 1024 * 1024, // decompression-bomb guard
});

export class TarSafetyError extends Error {
  constructor(message, code) {
    super(message);
    this.name = 'TarSafetyError';
    this.code = code;
  }
}

function parseSizeField(buf) {
  if (buf[0] & 0x80) {
    // GNU base-256 extension for sizes that don't fit in octal-ASCII.
    let n = 0n;
    for (let i = 1; i < buf.length; i++) n = (n << 8n) | BigInt(buf[i]);
    return Number(n);
  }
  const s = buf.toString('ascii').replace(/\0.*$/, '').trim();
  if (!s) return 0;
  const n = parseInt(s, 8);
  return Number.isFinite(n) ? n : 0;
}

function cstr(buf) {
  return buf.toString('utf8').replace(/\0.*$/, '');
}

// A tar entry name is unsafe when it would escape a virtual extraction root:
// absolute paths, `..` segments, embedded NULs, or an unreasonable length.
// Because this module never writes to a real filesystem path (every caller
// keeps extracted content in an in-memory Map keyed by this string), the
// classic zip-slip *write* vulnerability cannot occur here — but a hostile
// name must still never be silently treated as an ordinary path by downstream
// manifest/package-DB matching, so unsafe entries are flagged, never dropped
// silently and never accepted as-is.
export function isSafeEntryName(name) {
  if (typeof name !== 'string' || name.length === 0 || name.length > 4096) return false;
  if (name.includes('\0')) return false;
  const norm = name.replace(/\\/g, '/');
  if (norm.startsWith('/')) return false;
  if (norm.split('/').some((p) => p === '..')) return false;
  return true;
}

export function isWhiteoutName(name) {
  return (name.split('/').pop() || '').startsWith('.wh.');
}

// Resolves a whiteout entry name to what it deletes. `.wh..wh..opq` marks a
// directory as "opaque" (everything from earlier layers under it is hidden,
// not individually deleted) — reported distinctly so callers don't conflate
// it with a single-file deletion.
export function whiteoutTarget(name) {
  const parts = name.split('/');
  const base = parts.pop();
  if (base === '.wh..wh..opq') return { opaque: true, dir: parts.join('/') };
  return { opaque: false, path: [...parts, base.slice(4)].join('/') };
}

// Decompresses a gzip member with a hard output-size cap (Node's native
// ERR_BUFFER_TOO_LARGE on overflow — no custom streaming counter needed).
// Returns the input unchanged when it isn't gzip-magic (plain tar).
export function decompressIfGzip(buf, limits = DEFAULT_LIMITS) {
  if (buf.length >= 2 && buf[0] === 0x1f && buf[1] === 0x8b) {
    try {
      return zlib.gunzipSync(buf, { maxOutputLength: limits.maxGunzipOutput });
    } catch (err) {
      if (err && err.code === 'ERR_BUFFER_TOO_LARGE') {
        throw new TarSafetyError('decompressed layer exceeds the decompression-bomb guard', 'gunzip_too_large');
      }
      throw new TarSafetyError(`gzip stream is malformed: ${err.message}`, 'gunzip_malformed');
    }
  }
  return buf;
}

/**
 * Reads a decompressed tar buffer and yields one record per entry:
 *   { name, size, typeflag, linkname, data, unsafe }
 * `data` is a Buffer view into `buf` (never copied) for safe entries, `null`
 * for unsafe ones. Throws TarSafetyError (never returns a partial result) the
 * moment any configured limit is exceeded.
 */
export function* readTarEntries(buf, limits = DEFAULT_LIMITS) {
  if (!Buffer.isBuffer(buf)) throw new TarSafetyError('tar input must be a Buffer', 'bad_input');
  let offset = 0;
  let count = 0;
  let totalSize = 0;
  let pendingLongName = null;

  while (offset + BLOCK <= buf.length) {
    const header = buf.subarray(offset, offset + BLOCK);
    if (header.every((b) => b === 0)) {
      offset += BLOCK;
      continue; // end-of-archive zero-fill padding
    }

    count += 1;
    if (count > limits.maxEntries) {
      throw new TarSafetyError(`tar archive has more than ${limits.maxEntries} entries`, 'too_many_entries');
    }

    let name = cstr(header.subarray(0, 100));
    const typeflag = String.fromCharCode(header[156] || 0);
    const linkname = cstr(header.subarray(157, 257));
    const magic = header.subarray(257, 263).toString('ascii');
    const prefix = magic.startsWith('ustar') ? cstr(header.subarray(345, 500)) : '';
    if (prefix) name = `${prefix}/${name}`;
    const size = parseSizeField(header.subarray(124, 136));

    offset += BLOCK;

    if (size < 0 || !Number.isFinite(size)) {
      throw new TarSafetyError(`tar entry "${name}" has an invalid size field`, 'bad_size');
    }
    if (size > limits.maxEntrySize) {
      throw new TarSafetyError(`tar entry "${name}" (${size} bytes) exceeds the per-entry size limit`, 'entry_too_large');
    }
    totalSize += size;
    if (totalSize > limits.maxTotalSize) {
      throw new TarSafetyError('tar archive exceeds the total-size limit', 'archive_too_large');
    }

    const dataBlocks = Math.ceil(size / BLOCK);
    if (offset + size > buf.length) {
      throw new TarSafetyError(`tar entry "${name}" claims more data than the archive contains`, 'truncated');
    }
    const data = size > 0 ? buf.subarray(offset, offset + size) : Buffer.alloc(0);
    offset += dataBlocks * BLOCK;

    const resolvedName = pendingLongName ? pendingLongName : name;
    pendingLongName = null;

    if (typeflag === 'L') {
      // GNU longname: this entry's data IS the next entry's real name.
      pendingLongName = cstr(data);
      continue;
    }
    if (typeflag === 'K' || typeflag === 'x' || typeflag === 'g') {
      // GNU longlink / PAX extended header — structurally skipped (see header comment).
      continue;
    }

    if (!isSafeEntryName(resolvedName)) {
      yield { name: resolvedName, size, typeflag, linkname, data: null, unsafe: true };
      continue;
    }

    yield { name: resolvedName.replace(/\\/g, '/'), size, typeflag, linkname, data, unsafe: false };
  }
}
