// Cross-repository lineage declaration (Finding Provenance PRD, M4 §4.2).
//
// Git has no native cross-repo history — this is an OPERATOR-DECLARED link,
// read from .agentic-security/repo-lineage.json:
//   { "linkedFrom": { "path": "../old-repo-clone", "atCommit": "<sha>" } }
//
// Scoped to LOCAL clones only — no remote fetch, matching this codebase's
// "no runtime cloud calls" convention. Never throws; a missing, malformed,
// or unreachable link degrades to null, which origin-resolver.js reads as
// "no lineage available" and proceeds exactly as it did before M4.
//
// NOTE on git-evidence.js reuse (checked as of M3's final fix round): that
// module exports `_relPath` and `_isSafeRevision`, but NOT `_isSha` and NOT
// its `GIT_TIMEOUT_MS` constant (the latter is a local, non-exported const
// there). Neither exported helper is a fit here even if they were exported
// more broadly: `_isSafeRevision` intentionally accepts ref/branch names
// (it backs a `<since>..HEAD` revision range), which is looser than the
// full-SHA-only check this module needs for `atCommit`; `_relPath` resolves
// a path relative to `scanRoot`, but this module's whole job is validating
// a path OUTSIDE scanRoot (the linked repo). So the SHA_RE/timeout/
// execFileSync pattern below is intentionally re-declared, not copied
// carelessly — see the M3 §3.3 finding in missing-control-resolver.js's
// history for what reimplementing this WITHOUT checking first cost.
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as cp from 'node:child_process';
import { statePath } from '../state-dir.js';

const GIT_TIMEOUT_MS = 2000;
const SHA_RE = /^[0-9a-f]{4,40}$/i;

function _isLocallyReachableGitRepo(absPath) {
  try {
    if (!fs.statSync(absPath).isDirectory()) return false;
  } catch { return false; }
  try {
    cp.execFileSync('git', ['rev-parse', '--git-dir'], {
      cwd: absPath, encoding: 'utf8', timeout: GIT_TIMEOUT_MS, stdio: ['ignore', 'pipe', 'ignore'],
    });
    return true;
  } catch { return false; }
}

function _commitExists(absPath, sha) {
  try {
    cp.execFileSync('git', ['cat-file', '-e', `${sha}^{commit}`], {
      cwd: absPath, encoding: 'utf8', timeout: GIT_TIMEOUT_MS, stdio: ['ignore', 'pipe', 'ignore'],
    });
    return true;
  } catch { return false; }
}

/**
 * Returns { path: <absolute, verified-reachable local git repo>, atCommit: <verified-existing sha> }
 * or null on ANY problem — missing config, malformed JSON, missing fields,
 * an unsafe-looking atCommit, a path that isn't a real local git repo, or a
 * commit that doesn't exist there. This function's whole job is to hand
 * back either a fully-verified link or nothing; it never hands back a
 * half-verified one for a caller to trust blindly.
 */
export function loadRepoLineage(scanRoot) {
  const configPath = statePath(scanRoot, 'repo-lineage.json');
  let text;
  try { text = fs.readFileSync(configPath, 'utf8'); } catch { return null; }
  let doc;
  try { doc = JSON.parse(text); } catch { return null; }
  const linked = doc?.linkedFrom;
  if (!linked || typeof linked !== 'object') return null;
  const { path: relOrAbsPath, atCommit } = linked;
  if (typeof relOrAbsPath !== 'string' || !relOrAbsPath) return null;
  if (typeof atCommit !== 'string' || !SHA_RE.test(atCommit)) return null;

  const absPath = path.isAbsolute(relOrAbsPath) ? relOrAbsPath : path.resolve(scanRoot, relOrAbsPath);
  if (!_isLocallyReachableGitRepo(absPath)) return null;
  if (!_commitExists(absPath, atCommit)) return null;

  return { path: absPath, atCommit };
}
