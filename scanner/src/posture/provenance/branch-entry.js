// Branch-introduction resolver (Finding Provenance PRD, Scenario D).
//
// Given a finding's already-resolved origin commit, answers "where did this
// land on the target branch" — either the origin commit itself (it was
// committed directly on the branch) or the merge commit that brought it in
// from a feature branch (`git merge --no-ff`). This is a second, distinct
// question from origin-resolver.js's "which commit introduced this": a
// commit can be the true origin and still never have existed on the branch
// people actually deploy from until a later merge folded it in.
//
// Same input-validation posture as git-evidence.js, and for the same reason:
// `originCommit`/`targetRef` are attacker-influenceable-shaped strings
// (finding data, CLI args) flowing into `execFileSync('git', [...])`. A
// value like `--output=/tmp/pwned` must never reach argv as a bare token —
// see git-evidence.js's SHA_RE/SINCE_RE comments for the incident this
// guards against (a nominally read-only git call gaining write side effects
// via flag injection).

import * as cp from 'node:child_process';

const GIT_TIMEOUT_MS = 2000;

function _run(scanRoot, args) {
  try {
    const stdout = cp.execFileSync('git', args, {
      cwd: scanRoot, encoding: 'utf8', timeout: GIT_TIMEOUT_MS,
      stdio: ['ignore', 'pipe', 'ignore'], maxBuffer: 16 * 1024 * 1024,
    });
    return { ok: true, stdout };
  } catch (e) {
    return { ok: false, stdout: '' };
  }
}

// Git SHAs (full or abbreviated) are always lowercase/uppercase hex, 4-40
// chars. Rejecting anything else closes off flag injection.
const SHA_RE = /^[0-9a-f]{4,40}$/i;
function _isSha(sha) {
  return typeof sha === 'string' && SHA_RE.test(sha);
}

// `targetRef` is used as a revision (both standalone and as the right side
// of a `originCommit..targetRef` range), so it must look like a ref/branch/
// sha — never start with `-` (which git would parse as an option) and
// contain only characters refs can hold.
const REF_RE = /^[A-Za-z0-9._/-]+$/;
function _isSafeRef(ref) {
  return typeof ref === 'string' && ref.length > 0 && !ref.startsWith('-') && REF_RE.test(ref);
}

function _currentBranchName(scanRoot, targetRef) {
  const r = _run(scanRoot, ['rev-parse', '--abbrev-ref', targetRef]);
  return r.ok ? r.stdout.trim() : targetRef;
}

export function resolveBranchEntry(scanRoot, originCommit, targetRef = 'HEAD') {
  if (!_isSha(originCommit)) return null;
  if (!_isSafeRef(targetRef)) return null;

  const reachable = _run(scanRoot, ['merge-base', '--is-ancestor', originCommit, targetRef]);
  if (!reachable.ok) return null;

  const branchName = _currentBranchName(scanRoot, targetRef);
  const r = _run(scanRoot, ['log', '--merges', '--ancestry-path', '--reverse', '--format=%H', `${originCommit}..${targetRef}`]);
  if (r.ok && r.stdout.trim()) {
    const firstMerge = r.stdout.trim().split('\n')[0];
    return { commit: firstMerge, ref: `refs/heads/${branchName}`, relationship: 'merge' };
  }
  return { commit: originCommit, ref: `refs/heads/${branchName}`, relationship: 'direct' };
}
