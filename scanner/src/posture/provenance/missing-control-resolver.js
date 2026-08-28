// Missing-control regression resolution (Finding Provenance PRD, M3 §3.3).
//
// Architecturally inverted from every other resolver in this directory:
// "when did a previously-observed safeguard DISAPPEAR," not "when did a bad
// pattern APPEAR." Walks backward from HEAD (newest-first — the opposite
// direction candidateCommitsForLine's oldest-first convention uses, because
// this resolver is searching for the MOST RECENT transition from present to
// absent, not the earliest transition from absent to present).
//
// The one invariant this module exists to enforce, verbatim from the spec:
// if the control is absent at EVERY reachable commit including the
// repository's own root, status is 'unknown' — NEVER attributed to the root
// commit. Every other resolver in this milestone treats "absent at the
// root, present now" as real evidence of introduction (the root IS the
// beginning of everything this repo can prove). This resolver's question is
// the mirror image — "when did it disappear" — and a control absent
// EVERYWHERE has no disappearance to date, which is a fundamentally
// different, weaker claim than "introduced at the beginning." Collapsing
// them would be exactly the false certainty the whole feature forbids.

import { getFirstParent, commitMeta, _relPath, _isSafeRevision } from './git-evidence.js';
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
    return { ok: false, stdout: '', error: e };
  }
}

// The commits touching `file` on the path from `since`/root to HEAD,
// NEWEST-FIRST (the reverse of git-evidence.js's candidateCommitsForFile,
// which is oldest-first — this resolver needs to walk backward from the
// present).
//
// This module reimplements its own git-invocation helper (`_run` above)
// rather than adding a new wrapper to git-evidence.js, but that must not
// mean skipping the argument-injection guards every OTHER resolver in this
// directory gets for free by routing through git-evidence.js. `since` feeds
// straight into a `<since>..HEAD` revision range and `file` becomes a bare
// argv token after `--` — both reuse git-evidence.js's own exported guards
// (`_isSafeRevision`, `_relPath`) rather than re-deriving the validation
// logic here, so a caller-supplied `since` shaped like a git flag (e.g.
// `--upload-pack=evil`) or a `file` that escapes scanRoot can never reach
// git's argv as an unvalidated token — same contract candidateCommitsForFile
// enforces for the forward-walking resolvers.
function candidateCommitsNewestFirst(scanRoot, file, since) {
  const rel = _relPath(scanRoot, file);
  if (!rel) return [];
  if (since && !_isSafeRevision(since)) return [];
  const args = ['log', '--format=%H', '--follow'];
  if (since) args.push(`${since}..HEAD`);
  args.push('--', rel);
  const r = _run(scanRoot, args);
  if (!r.ok) return [];
  return r.stdout.split('\n').map((s) => s.trim()).filter(Boolean);
}

export async function resolveMissingControl(scanRoot, { file, predicate, since, deadlineAt } = {}) {
  if (!file || typeof predicate !== 'function') {
    return { status: 'unknown', commitsConsidered: 0 };
  }
  const candidates = candidateCommitsNewestFirst(scanRoot, file, since);
  if (candidates.length === 0) return { status: 'unknown', commitsConsidered: 0 };

  let commitsConsidered = 0;
  let priorPresentCommit = null; // the most-recently-checked commit where the control WAS present (walking backward, so this is the newest such commit seen so far)

  for (const sha of candidates) {
    if (deadlineAt && Date.now() > deadlineAt) return { status: 'budget_exhausted', commitsConsidered };
    commitsConsidered++;
    let presentHere;
    try { presentHere = await predicate(scanRoot, sha, file); } catch { presentHere = false; }

    if (presentHere) {
      // Found a commit where it WAS present. If we've already seen a LATER
      // (newer) commit where it was NOT present, that later commit's own
      // transition (or the commit just after this one, going forward) is
      // the removal — but walking newest-first, the removal transition is
      // between THIS commit (present) and the previous iteration's commit
      // (absent, checked earlier in this loop = newer in time). So: if
      // priorPresentCommit is unset AND we've already walked past at least
      // one absent commit, that means HEAD-side history is absent and THIS
      // commit is present — the transition is between this commit and the
      // one checked immediately before it in the loop.
      if (commitsConsidered > 1 && priorPresentCommit === null) {
        // The immediately-prior (newer) candidate was absent, and this one
        // is present — that prior candidate (or the gap right after this
        // commit) is where it disappeared. Report THIS commit (the last
        // proven-present one) as the evidence anchor, and the prior
        // candidate as the removal point.
        const removedMeta = commitMeta(scanRoot, candidates[commitsConsidered - 2]);
        const presentMeta = commitMeta(scanRoot, sha);
        if (removedMeta && presentMeta) {
          return {
            status: 'complete',
            removedAt: { commit: removedMeta.commit, authorName: removedMeta.authorName, authorDate: removedMeta.authorDate, summary: removedMeta.summary },
            presentAt: { commit: presentMeta.commit, authorDate: presentMeta.authorDate },
            commitsConsidered,
          };
        }
      }
      priorPresentCommit = sha;
      // Present at the oldest commit we've checked so far and no removal
      // found yet — keep walking older history in case there's an EARLIER
      // removal-then-readd cycle; but for M3's scope (the Scenario I
      // acceptance case is "never present, resolves unknown" and "present
      // then removed, resolves complete"), stop here: control is present
      // at this point in history and we have not yet found where it was
      // removed relative to HEAD. Continue the loop.
    }
    // presentHere === false: keep walking older history (newest-first),
    // looking for the presence that precedes this absence.
  }

  // Walked every candidate and never found a present→absent transition —
  // either the control was NEVER present in any reachable commit (the
  // Scenario I case — must resolve 'unknown', never attributed to the
  // oldest candidate as if that were meaningful), or it has been present
  // at every commit checked (no removal to report, which for THIS
  // resolver's question — "when did it disappear" — is also 'unknown':
  // there is no disappearance to date).
  return { status: 'unknown', commitsConsidered };
}
