// Path handling for capability decisions (X-502). The OS boundary is what
// actually blocks an access; these helpers only let a policy decision and a
// pre-flight check agree with it about what a path names, including `..`
// segments and symbolic links.
import fs from 'node:fs';
import path from 'node:path';

const MAX_PATH = 4096;

/**
 * Lexical form of an absolute path: normalized, no trailing separator.
 * `dotdot` reports whether the caller wrote a parent-directory segment, which
 * is kept so a decision can say "traversal" rather than just "outside".
 */
export function lexicalPath(p) {
  if (typeof p !== 'string' || p.length === 0 || p.length > MAX_PATH || p.includes('\0')) return { ok: false };
  if (!path.isAbsolute(p)) return { ok: false };
  const dotdot = p.split(path.sep).includes('..');
  let n = path.normalize(p);
  if (n.length > 1 && n.endsWith(path.sep)) n = n.slice(0, -1);
  return { ok: true, path: n, dotdot };
}

/**
 * Canonical form: symbolic links resolved for the longest existing prefix, the
 * not-yet-existing remainder appended lexically. This is what a write to a new
 * file is judged by.
 */
export function canonicalPath(p) {
  const lex = lexicalPath(p);
  if (!lex.ok) return null;
  let head = lex.path;
  const tail = [];
  for (let i = 0; i < 4096; i++) {
    try {
      const real = fs.realpathSync(head);
      return tail.length ? path.join(real, ...tail.reverse()) : real;
    } catch (e) {
      if (e.code !== 'ENOENT' && e.code !== 'ENOTDIR') return null;
      const parent = path.dirname(head);
      if (parent === head) return null;
      tail.push(path.basename(head));
      head = parent;
    }
  }
  return null;
}

/** `child` equals `root` or lies beneath it. Both must already be normalized. */
export function isWithin(child, root) {
  return child === root || child.startsWith(root.endsWith(path.sep) ? root : root + path.sep);
}

/** True when two normalized paths overlap in either direction. */
export function overlaps(a, b) {
  return isWithin(a, b) || isWithin(b, a);
}
