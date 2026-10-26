// File-serving calls that confine the path to a root directory.
//
// `res.sendFile(p, { root: DIR })` and `res.download(p, name, { root: DIR })`
// resolve `p` relative to DIR and reject a path that climbs above it (the
// underlying file sender answers 403 for a path with a `..` segment when `root`
// is set). With `root` the user-controlled part is a path inside DIR, not an
// arbitrary filesystem path, so it is not a traversal sink. Without `root` the
// path must be absolute and the caller owns containment, so the finding stays.
//
// Only a literal `root:` property in an inline options object is recognised.
// `{ ...opts }`, a variable `opts`, or `root` only set elsewhere is not seen and
// leaves the finding in place: unknown stays conservative.

import { callArgumentsAt } from './_call-args.js';

const SEND_FILE_CALL_RE = /\b(?:sendFile|download)\s*\(/;

/**
 * Is the file-serving call at `line` given an options object with a `root`?
 * Returns null when no such call is found, else true/false.
 */
export function sendFileConfinedToRootAt(lines, line) {
  const args = callArgumentsAt(lines, line, SEND_FILE_CALL_RE);
  if (!args) return null;
  if (args.length < 2) return false;
  return args.slice(1).some((a) => /^\s*\{[^]*?\broot\s*:/.test(a));
}
