import * as cp from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { hardenGitArgs, hardenGitEnv } from '../../util/git-hardening.js';

// 2s keeps a single call bounded for the common case; `-L`/`--follow` walks on a
// very large history can be slower, at which point they just return an empty/
// null result rather than blocking the caller — degrading gracefully was judged
// preferable to a longer timeout that lets one pathological repo stall a scan.
const GIT_TIMEOUT_MS = 2000;

// Second independent Finding Provenance PRD audit (FR-PROV-024 / Section 8
// control 3): this scanRoot is a SCANNED repository, not this project's own
// trusted checkout — its .git/config is attacker-influenceable. Every git
// invocation in this module MUST route through this one function so the
// hardening applies uniformly; see util/git-hardening.js for what each flag
// closes and why it was verified necessary.
function _run(scanRoot, args) {
  try {
    const stdout = cp.execFileSync('git', hardenGitArgs(args), {
      cwd: scanRoot, encoding: 'utf8', timeout: GIT_TIMEOUT_MS,
      stdio: ['ignore', 'pipe', 'ignore'], maxBuffer: 16 * 1024 * 1024,
      env: hardenGitEnv(),
    });
    return { ok: true, stdout };
  } catch (e) {
    return { ok: false, stdout: '', error: e };
  }
}

// Exported so other resolvers in this directory that build their own git
// invocations (rather than adding a new wrapper function here) still route
// path/revision arguments through the same validation, instead of
// reimplementing it and risking drift — see missing-control-resolver.js.
export function _relPath(scanRoot, file) {
  const abs = path.resolve(scanRoot, file);
  const rel = path.relative(scanRoot, abs);
  if (rel === '' || rel.startsWith('..') || path.isAbsolute(rel)) return null;
  // Lexical containment alone isn't enough: `file` could be a symlink whose
  // TARGET resolves outside scanRoot even though its own path lexically
  // sits inside it. realpathSync follows every symlink in the chain; if the
  // real (post-symlink) path escapes scanRoot, treat it the same as any
  // other traversal attempt.
  //
  // realpathSync can throw for reasons other than "doesn't exist": ELOOP
  // (a symlink cycle), EACCES (permission denied partway through
  // resolution), ENOTDIR (a path component that should be a directory
  // isn't). None of those have the "historical commit, file plausibly
  // doesn't exist right now" excuse -- they mean something genuinely
  // couldn't be verified, so they fail CLOSED (return null), matching
  // every other fail-closed check in this module. ENOENT is the one
  // exception and fails OPEN: most callers are asking about a file's state
  // at some HISTORICAL commit, which git-evidence.js reads from git
  // objects, not the working tree, so the working tree may not have this
  // file at all, or may have it under a different name after a rename --
  // that is routine and must not be treated as a proven escape.
  try {
    const real = fs.realpathSync(abs);
    const realRoot = fs.realpathSync(scanRoot);
    const realRel = path.relative(realRoot, real);
    if (realRel === '' || realRel.startsWith('..') || path.isAbsolute(realRel)) return null;
  } catch (e) {
    if (e.code !== 'ENOENT') return null;
  }
  return rel.split(path.sep).join('/');
}

// Git SHAs (full or abbreviated) are always lowercase/uppercase hex, 4-40 chars.
// Rejecting anything else closes off flag injection (e.g. a "sha" of
// "--output=/tmp/pwned" reaching `git show`/`git log` as a bare argv token).
const SHA_RE = /^[0-9a-f]{4,40}$/i;
function _isSha(sha) {
  return typeof sha === 'string' && SHA_RE.test(sha);
}

// `since` is only ever used as the left side of a `<since>..HEAD` revision
// range, so it must look like a ref/tag/sha — never start with `-` (which
// git would parse as an option) and contain only characters refs can hold.
const SINCE_RE = /^[A-Za-z0-9._/-]+$/;
export function _isSafeRevision(since) {
  return typeof since === 'string' && since.length > 0 && !since.startsWith('-') && SINCE_RE.test(since);
}

export function isGitRepo(scanRoot) {
  return _run(scanRoot, ['rev-parse', '--git-dir']).ok;
}

// FR-PROV-022: repository-identity signal for provider enrichment
// (providers/github.js / providers/gitlab.js parse owner/repo out of this
// URL). No `origin` remote (a local-only repo, or a fixture that never added
// one) degrades to null rather than throwing — same convention as every
// other `_run`-backed helper here.
export function getRemoteUrl(scanRoot) {
  const r = _run(scanRoot, ['remote', 'get-url', 'origin']);
  return r.ok ? r.stdout.trim() : null;
}

export function getRepoState(scanRoot) {
  if (!isGitRepo(scanRoot)) return null;
  const head = _run(scanRoot, ['rev-parse', 'HEAD']);
  const branch = _run(scanRoot, ['rev-parse', '--abbrev-ref', 'HEAD']);
  const dirty = _run(scanRoot, ['status', '--porcelain']);
  const shallow = _run(scanRoot, ['rev-parse', '--is-shallow-repository']);
  return {
    head: head.ok ? head.stdout.trim() : null,
    branch: branch.ok ? branch.stdout.trim() : null,
    dirty: dirty.ok ? dirty.stdout.trim().length > 0 : false,
    shallow: shallow.ok ? shallow.stdout.trim() === 'true' : false,
  };
}

export function commitMeta(scanRoot, sha) {
  if (!_isSha(sha)) return null;
  // `--no-textconv`: verified this specific invocation (`-s`, no diff/blob
  // content rendered) is NOT reachable via a hostile `.gitattributes`
  // textconv driver in current git — kept for defense-in-depth /
  // uniformity with every other `show` call in this module, not because a
  // live exploit path was found here.
  const r = _run(scanRoot, ['show', '-s', '--no-textconv', '--format=%H%x1f%an%x1f%ae%x1f%aI%x1f%cI%x1f%s', sha]);
  if (!r.ok) return null;
  const [full, authorName, authorEmail, authorDate, committerDate, summary] = r.stdout.trim().split('\x1f');
  if (!full) return null;
  return { commit: full, authorName, authorEmail, authorDate, committerDate, summary };
}

export function getFirstParent(scanRoot, sha) {
  if (!_isSha(sha)) return null;
  const r = _run(scanRoot, ['rev-parse', `${sha}^1`]);
  return r.ok ? r.stdout.trim() : null;
}

// M3 §3.1: the full parent list, not just the first. `git rev-parse
// <sha>^@` expands to every parent SHA, one per line — the same mechanism
// `<sha>^1` (getFirstParent) uses for a single parent, generalized. A
// commit with no parents (the repo root) returns empty stdout, which
// `.filter(Boolean)` turns into `[]` rather than `['']`.
export function getAllParents(scanRoot, sha) {
  if (!_isSha(sha)) return [];
  const r = _run(scanRoot, ['rev-parse', `${sha}^@`]);
  if (!r.ok) return [];
  return r.stdout.split('\n').map((s) => s.trim()).filter(Boolean);
}

// M3 §3.1: the diff a commit introduces, as a normalized patch string — used
// by dag-walk.js to confirm a claimed revert is a REAL structural inverse of
// an earlier commit's diff, not just a commit whose MESSAGE says "Revert" (a
// spoofable, unreliable signal on its own per the spec). `--no-color` and a
// fixed context of 0 lines keep the two diffs comparable independent of
// terminal/config state; `-U0` removes context lines so unrelated nearby
// edits between the two commits don't defeat the comparison.
export function commitDiff(scanRoot, sha) {
  if (!_isSha(sha)) return null;
  // `--no-textconv`: VERIFIED exploitable without it — a hostile
  // `.gitattributes` `diff=<name>` attribute + a matching
  // `diff.<name>.textconv` config value runs an attacker script on this
  // exact invocation shape (`show -U0`, real diff content rendered). This
  // is the call the second audit named explicitly.
  const r = _run(scanRoot, ['show', '--no-color', '--no-textconv', '-U0', '--format=', sha]);
  return r.ok ? r.stdout : null;
}

// M4 §4.2: does `ancestor` reach `descendant` by following parent links —
// true for `ancestor === descendant` too, matching `git merge-base
// --is-ancestor`'s own semantics. Used by cross-repo lineage continuation
// (origin-resolver.js's `tryCrossRepoLineage`) to keep a candidate drawn from
// the LINKED repo's own (possibly still-developing) history from resolving
// to something that postdates the declared `atCommit` boundary — the
// DECLARED lineage link only vouches for history up to and including
// atCommit, never past it.
export function isAncestor(scanRoot, ancestor, descendant) {
  if (!_isSha(ancestor) || !_isSha(descendant)) return false;
  return _run(scanRoot, ['merge-base', '--is-ancestor', ancestor, descendant]).ok;
}

export function getBlobAtCommit(scanRoot, sha, file) {
  if (!_isSha(sha)) return null;
  const rel = _relPath(scanRoot, file);
  if (!rel) return null;
  // `./` makes git resolve `rel` relative to cwd (scanRoot) rather than the
  // repo root — load-bearing when scanRoot is a SUBDIRECTORY of the actual
  // git repository (e.g. one package of a monorepo). Without it, `git show
  // <sha>:<bare-relative-path>` resolves the bare path against the repo
  // root and silently fails for every caller whose scanRoot != repo root.
  //
  // `--no-textconv`: verified this blob-cat form of `show` (`<sha>:<path>`,
  // not a diff) is NOT reachable via a hostile textconv driver in current
  // git — kept for defense-in-depth / uniformity, same as commitMeta above.
  const r = _run(scanRoot, ['show', '--no-textconv', `${sha}:./${rel}`]);
  return r.ok ? r.stdout : null;
}

export function candidateCommitsForLine(scanRoot, file, line, { since } = {}) {
  const rel = _relPath(scanRoot, file);
  if (!rel) return [];
  if (since && !_isSafeRevision(since)) return [];
  const args = ['log', '--format=commit %H', '--reverse'];
  if (since) args.push(`${since}..HEAD`);
  // `-L` renders per-commit line-history diff content, which VERIFIED goes
  // through a hostile textconv driver the same way `commitDiff`'s `show
  // -U0` does — `--no-textconv` is required here for the same real reason.
  args.push('-L', `${line},${line}:${rel}`, '--no-textconv');
  const r = _run(scanRoot, args);
  if (!r.ok) return [];
  const shas = [];
  for (const ln of r.stdout.split('\n')) {
    const m = ln.match(/^commit ([0-9a-f]{40})/);
    if (m) shas.push(m[1]);
  }
  return [...new Set(shas)];
}

export function candidateCommitsForFile(scanRoot, file, { since } = {}) {
  const rel = _relPath(scanRoot, file);
  if (!rel) return [];
  if (since && !_isSafeRevision(since)) return [];
  const args = ['log', '--format=%H', '--follow', '--reverse'];
  if (since) args.push(`${since}..HEAD`);
  args.push('--', rel);
  const r = _run(scanRoot, args);
  if (!r.ok) return [];
  return r.stdout.split('\n').map((s) => s.trim()).filter(Boolean);
}

export function blameLine(scanRoot, file, line) {
  const rel = _relPath(scanRoot, file);
  if (!rel || !line || line < 1) return null;
  // `--no-textconv`: VERIFIED exploitable without it — `git blame` applies
  // a hostile `.gitattributes` textconv driver by default in current git.
  const r = _run(scanRoot, ['blame', '-L', `${line},${line}`, '--porcelain', '--no-textconv', '--', rel]);
  if (!r.ok || !r.stdout) return null;
  const lines = r.stdout.split('\n');
  const head = lines[0].split(' ');
  const sha = head[0];
  if (!sha) return null;
  if (/^0+$/.test(sha)) return { commit: null, uncommitted: true };
  const meta = { commit: sha };
  for (const ln of lines) {
    if (ln.startsWith('author ')) meta.authorName = ln.slice(7);
    else if (ln.startsWith('author-mail ')) meta.authorEmail = ln.slice(12).replace(/[<>]/g, '');
    else if (ln.startsWith('author-time ')) meta.authorDate = new Date(parseInt(ln.slice(12), 10) * 1000).toISOString();
    else if (ln.startsWith('summary ')) meta.summary = ln.slice(8);
  }
  return meta;
}
