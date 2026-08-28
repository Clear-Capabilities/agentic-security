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
// NOTE on git-evidence.js reuse (checked as of M3's final fix round, and
// re-checked against the file's FULL export surface after a review caught
// an incomplete first pass): `_isSha` and its `GIT_TIMEOUT_MS` constant are
// NOT exported there (both are module-local), and the two exported
// low-level helpers (`_relPath`, `_isSafeRevision`) genuinely don't fit —
// `_isSafeRevision` intentionally accepts ref/branch names, looser than the
// full-SHA-only check `atCommit` needs, and `_relPath` resolves paths
// relative to `scanRoot`, which is the wrong side of this module's job
// (validating a path OUTSIDE scanRoot). BUT two of the file's HIGHER-level
// exports are directly reusable and are used below instead of being
// reimplemented: `isGitRepo(scanRoot)` treats its argument purely as a cwd
// for `git rev-parse --git-dir`, with no assumption that cwd is "the"
// scanned repo, so it works unchanged on the linked repo's path; and
// `commitMeta(scanRoot, sha)` already runs `atCommit` through the file's own
// hardened `_isSha` guard before ever invoking `git show`, and returns
// `null` on both an invalid shape and a nonexistent commit — exactly what
// this module's existence check needs, with real commit metadata as a
// bonus. See the M3 §3.3 finding in missing-control-resolver.js's history
// for what skipping this check cost there.
import * as fs from 'node:fs';
import * as path from 'node:path';
import { isGitRepo, commitMeta } from './git-evidence.js';
import { statePath } from '../state-dir.js';

// Kept as a local pre-check, deliberately NOT dropped even though
// `commitMeta` re-validates internally: this regex must reject an
// unsafe-looking `atCommit` (e.g. `--upload-pack=evil`) BEFORE the value is
// even handed to `commitMeta`/`isGitRepo`, so the argument-injection defense
// fires as the first line of defense rather than relying solely on a
// downstream module's own guard.
const SHA_RE = /^[0-9a-f]{4,40}$/i;

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
  // No separate fs.statSync/isDirectory pre-check: isGitRepo's underlying
  // `git rev-parse --git-dir` call already degrades to false (not a throw)
  // when `absPath` doesn't exist at all — verified directly rather than
  // assumed — so a second existence check here would just be the same
  // reimplementation-avoidance lesson applied halfway.
  if (!isGitRepo(absPath)) return null;
  if (commitMeta(absPath, atCommit) === null) return null;

  return { path: absPath, atCommit };
}
