// File discovery on top of the Node standard library only.
//
// Two entry points, both replacing a third-party glob package that used to be a
// production dependency:
//
//   listFiles(root, {ignore})  — the scan-tree walk behind readScan/readTree.
//   globFiles(pattern, {cwd})  — resolve a user-supplied glob to regular files.
//
// `globFiles` is a thin wrapper: `fs.promises.glob` matches the old behaviour
// for the way those call sites used it (dot:false, onlyFiles:true, symlinks
// followed), so all it adds is the files-only filter.
//
// `listFiles` cannot be a thin wrapper, and the reasons are worth stating
// precisely, because each one is a way file discovery could silently change:
//
//   * dot — the built-in glob (like every minimatch-derived matcher) will not
//     let `*` or `**` match a path segment starting with `.`, and exposes no
//     option to change that. The scan tree must include hidden files and must
//     descend into hidden directories, so the walk is done with fs.readdir
//     instead, where visibility is simply not a concept.
//   * onlyFiles — a glob walk yields directories as well; only regular files
//     are wanted. readdir's Dirent gives that directly, with no extra stat.
//   * followSymbolicLinks:false — the built-in glob follows symlinked
//     directories with no option to stop it, which would let a link inside the
//     tree pull unrelated content (or content outside the scan root) into the
//     scan. readdir's Dirent is lstat-derived: a symlink reports isSymbolicLink
//     and neither isDirectory nor isFile, so links are skipped by construction
//     and their targets are never reached.
//   * suppressErrors — an unreadable directory must not abort the walk. Each
//     readdir is individually guarded.
//   * ignore — patterns are still matched with the built-in path.matchesGlob;
//     only the dot-blindness above is compensated for (see unhide()).
//
// Ordering matches the previous implementation's breadth-first shape: every
// entry of one depth is emitted before any entry of the next.
import * as fs from 'node:fs/promises';
import * as path from 'node:path';

// Two properties of path.matchesGlob have to be corrected, and both are
// corrected the same way: by rewriting the subject *and* the pattern through
// the same injective transform, so the built-in matcher does the actual glob
// work while the transform carries the semantics it will not.
//
//  1. Dot-blindness. A wildcard will not match a path segment starting with
//     `.`, and there is no option to change that. Rewriting a segment's leading
//     dot to a control character makes wildcards dot-permissive while keeping
//     an explicitly-named segment literal: pattern `.git` becomes `<1>git`,
//     which still matches a directory named `.git` and still does not match one
//     named `git`. Only applied where dot-permissive matching is wanted.
//  2. Partial case-folding. The matcher folds case in some positions — e.g.
//     `UPPER/MiXeD.JS` matches `**/*.js` — while `Test/a.js` does not match
//     `**/test/**`. That inconsistency is worse than either rule on its own,
//     and case-folding is not what the previous implementation did. Encoding
//     each upper-case letter as a control character plus its lower-case form
//     makes matching case-sensitive everywhere: no folded comparison can
//     reintroduce the marker.
//
// Neither control character can appear in a filename produced by any of the
// filesystems this runs on, so the transform cannot collide with real content.
const DOT = String.fromCharCode(1);
const UP = String.fromCharCode(2);
const HAS_UPPER = /[A-Z]/;
const ALL_UPPER = /[A-Z]/g;
const foldUp = c => UP + c.toLowerCase();

function prepPath(p, dot) {
  let s = p;
  if (dot && s.includes('.')) {
    const segs = s.split('/');
    for (let i = 0; i < segs.length; i++) {
      if (segs[i].charCodeAt(0) === 46) segs[i] = DOT + segs[i].slice(1);
    }
    s = segs.join('/');
  }
  return HAS_UPPER.test(s) ? s.replace(ALL_UPPER, foldUp) : s;
}

/**
 * True when `rel` (a '/'-separated relative path) matches any of `patterns`.
 * Case-sensitive; wildcards match hidden segments.
 */
export function matchesAnyGlob(rel, patterns) {
  if (!patterns || patterns.length === 0) return false;
  const subject = prepPath(rel, true);
  for (const pat of patterns) {
    if (path.matchesGlob(subject, prepPath(pat, true))) return true;
  }
  return false;
}

// A directory may be skipped wholesale only when a pattern provably excludes
// every possible descendant. `<prefix>/**` is exactly that shape: `**` absorbs
// any number of trailing segments, so if the directory matches `<prefix>` then
// nothing beneath it can survive. Anything else (`<prefix>/*`, `**/*.min.js`)
// may exclude some descendants and keep others, so those directories are walked
// and their files filtered individually. Pruning is therefore only ever a
// speed-up: correctness comes from the per-file check.
function prunable(subject, prepared) {
  for (const p of prepared) {
    if (p.subtree && path.matchesGlob(subject, p.subtree)) return true;
  }
  return false;
}

function prepare(patterns) {
  return patterns.map(pat => {
    const glob = prepPath(pat, true);
    return { glob, subtree: glob.endsWith('/**') ? glob.slice(0, -3) : null };
  });
}

/**
 * Every regular file under `root`, as '/'-separated paths relative to `root`.
 * Hidden entries included; directories and symlinks excluded; unreadable
 * directories skipped; `ignore` globs applied to each file path.
 */
export async function listFiles(root, { ignore = [] } = {}) {
  const prepared = prepare(ignore);
  const out = [];
  let level = [''];
  while (level.length) {
    const next = [];
    for (const dir of level) {
      let entries;
      try {
        entries = await fs.readdir(dir ? path.join(root, dir) : root, { withFileTypes: true });
      } catch {
        continue; // unreadable or vanished — skip it, keep walking
      }
      for (const e of entries) {
        const rel = dir ? `${dir}/${e.name}` : e.name;
        const subject = prepared.length ? prepPath(rel, true) : '';
        if (e.isDirectory()) {
          if (!prunable(subject, prepared)) next.push(rel);
        } else if (e.isFile()) {
          let skip = false;
          for (const p of prepared) {
            if (path.matchesGlob(subject, p.glob)) { skip = true; break; }
          }
          if (!skip) out.push(rel);
        }
        // symlinks, sockets, fifos and block/char devices are not files
      }
    }
    level = next;
  }
  return out;
}

/**
 * Resolve a user-supplied glob to regular files, relative to `cwd`. Hidden
 * paths are not matched (the built-in default) and symlinks are followed, both
 * matching the previous behaviour at these call sites.
 *
 * Two corrections are layered on the built-in walk: results are narrowed to
 * regular files (a glob yields directories too), and the partial case-folding
 * described above is undone by re-checking each result against the pattern
 * case-sensitively — a `.SARIF` file must not answer to `*.sarif`. Symlink
 * cycles are the one place this is deliberately not bug-compatible: the
 * built-in stops at a cycle instead of re-enumerating the tree through it.
 */
export async function globFiles(pattern, { cwd = process.cwd() } = {}) {
  const strict = prepPath(pattern, false);
  const out = [];
  for await (const p of fs.glob(pattern, { cwd })) {
    if (!path.matchesGlob(prepPath(p, false), strict)) continue;
    try {
      const st = await fs.stat(path.isAbsolute(p) ? p : path.join(cwd, p));
      if (st.isFile()) out.push(p);
    } catch { /* vanished or dangling link — not a file */ }
  }
  return out;
}
