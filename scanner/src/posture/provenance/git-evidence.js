import * as cp from 'node:child_process';
import * as path from 'node:path';

// 2s keeps a single call bounded for the common case; `-L`/`--follow` walks on a
// very large history can be slower, at which point they just return an empty/
// null result rather than blocking the caller — degrading gracefully was judged
// preferable to a longer timeout that lets one pathological repo stall a scan.
const GIT_TIMEOUT_MS = 2000;

function _run(scanRoot, args) {
  try {
    const stdout = cp.execFileSync('git', args, {
      cwd: scanRoot, encoding: 'utf8', timeout: GIT_TIMEOUT_MS,
      stdio: ['ignore', 'pipe', 'ignore'], maxBuffer: 16 * 1024 * 1024,
    });
    return { ok: true, stdout };
  } catch (e) {
    return { ok: false, stdout: '', error: e };
  }
}

function _relPath(scanRoot, file) {
  const abs = path.resolve(scanRoot, file);
  const rel = path.relative(scanRoot, abs);
  return (rel === '' || rel.startsWith('..') || path.isAbsolute(rel)) ? null : rel.split(path.sep).join('/');
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
function _isSafeRevision(since) {
  return typeof since === 'string' && since.length > 0 && !since.startsWith('-') && SINCE_RE.test(since);
}

export function isGitRepo(scanRoot) {
  return _run(scanRoot, ['rev-parse', '--git-dir']).ok;
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
  const r = _run(scanRoot, ['show', '-s', '--format=%H%x1f%an%x1f%ae%x1f%aI%x1f%cI%x1f%s', sha]);
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

export function getBlobAtCommit(scanRoot, sha, file) {
  if (!_isSha(sha)) return null;
  const rel = _relPath(scanRoot, file);
  if (!rel) return null;
  const r = _run(scanRoot, ['show', `${sha}:${rel}`]);
  return r.ok ? r.stdout : null;
}

export function candidateCommitsForLine(scanRoot, file, line, { since } = {}) {
  const rel = _relPath(scanRoot, file);
  if (!rel) return [];
  if (since && !_isSafeRevision(since)) return [];
  const args = ['log', '--format=commit %H', '--reverse'];
  if (since) args.push(`${since}..HEAD`);
  args.push('-L', `${line},${line}:${rel}`);
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
  const r = _run(scanRoot, ['blame', '-L', `${line},${line}`, '--porcelain', '--', rel]);
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
