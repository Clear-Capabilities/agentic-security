// Candidate-seeded linear-replay origin resolution (Finding Provenance PRD,
// Scenarios A/B/F).
//
// Given a finding, walk the commits git identifies as having touched its
// line (oldest-first, via `candidateCommitsForLine`) and, for each one,
// semantically replay the detector at that commit's blob content
// (`predicate-replay.js`) to answer "did this finding's condition hold
// here". The origin commit is the OLDEST candidate where the predicate is
// present AND absent in that commit's first parent — i.e. the commit that
// introduced it, not merely a commit that happens to contain it (a later
// candidate might just be an unrelated edit to the same line that leaves
// the vulnerable shape intact).
//
// The one subtlety this module exists to get right: a commit with no first
// parent is ambiguous. It might genuinely be the repository's root commit
// (real evidence: nothing precedes it, so "absent in parent" is vacuously
// true) — or it might be the boundary of a SHALLOW clone, where a parent
// exists in real history but was never fetched. Those two cases must never
// be reported the same way: reporting a shallow boundary as `complete`
// would be exactly the false certainty the PRD forbids (claiming to have
// proven the finding wasn't present a commit earlier, when the truth is we
// simply couldn't look). `repoState.shallow` is the caller-supplied signal
// that disambiguates them; see the branch below for exactly how each is
// handled.

import { candidateCommitsForLine, getFirstParent, commitMeta, getBlobAtCommit, isAncestor } from './git-evidence.js';
import { replayAt } from './predicate-replay.js';
import { PROVENANCE_METHOD } from './schema.js';
import { checkAbsentInSomeParent, detectRevert, detectCherryPick } from './dag-walk.js';
import { loadRepoLineage } from './repo-lineage.js';

function relevantFiles(finding) {
  const files = new Set();
  if (finding.file) files.add(finding.file);
  if (finding.source?.file) files.add(finding.source.file);
  if (finding.sink?.file) files.add(finding.sink.file);
  if (Array.isArray(finding.pathSteps)) {
    for (const step of finding.pathSteps) if (step.file) files.add(step.file);
  }
  return [...files];
}

function originFrom(meta, { absentInParents }) {
  return {
    commit: meta.commit, authorName: meta.authorName, authorEmail: meta.authorEmail,
    authorDate: meta.authorDate, committerDate: meta.committerDate, summary: meta.summary,
    presentInCommit: true, absentInParents, revertOf: null, cherryPickOf: null,
  };
}

/**
 * Best-effort cross-repo continuation when the standard walk reaches this
 * repo's TRUE root commit (no parent, non-shallow) without resolving. Only
 * fires when a repo-lineage link is declared and verified (`loadRepoLineage`
 * — Task 4). Confirms the SAME relative file path exists in the linked repo
 * at atCommit, and that the finding's line content is textually present
 * there (a presence check, NOT a predicate replay — the detector pipeline
 * that proved the finding's predicate true in THIS repo cannot be assumed
 * identical in the linked one). On a match, walks `candidateCommitsForLine`
 * in the linked repo, restricted to candidates reachable from atCommit (via
 * `isAncestor`, so nothing the linked repo's own later development added
 * can leak in), and reports the oldest such candidate as a best-effort
 * origin.
 *
 * Returns null on ANY failure to extend (no lineage, file/line absent
 * there, nothing further resolves) — the caller falls through to its
 * existing not-linked-or-unresolved behavior unchanged.
 */
function tryCrossRepoLineage(scanRoot, finding, rootMeta) {
  const lineage = loadRepoLineage(scanRoot);
  if (!lineage) return null;

  const blob = getBlobAtCommit(lineage.path, lineage.atCommit, finding.file);
  if (blob == null) return null;
  const lines = blob.split('\n');
  const lineNo = finding.line || finding.sink?.line;
  if (!lineNo || lineNo > lines.length) return null;
  // A cheap, honest presence check: the SOURCE LINE's own text (trimmed) is
  // literally there. Not the finding's full predicate — that would require
  // re-running the detector pipeline, out of scope for a best-effort link.
  if (!lines[lineNo - 1] || !lines[lineNo - 1].trim()) return null;

  const linkedCandidates = candidateCommitsForLine(lineage.path, finding.file, lineNo, {});
  // Only candidates reachable from (at or before) atCommit are eligible —
  // the lineage link says history was imported AT that commit, so anything
  // the linked repo's own timeline added after it is not part of what
  // became this repo. `isAncestor` (git-evidence.js, backed by `git
  // merge-base --is-ancestor`) is true for atCommit itself as well as any
  // real ancestor of it, so this both bounds the walk and keeps atCommit
  // itself eligible.
  const eligible = linkedCandidates.filter((sha) => isAncestor(lineage.path, sha, lineage.atCommit));
  if (eligible.length === 0) return null;

  const oldestMatch = eligible[0];
  const meta = commitMeta(lineage.path, oldestMatch);
  if (!meta) return null;

  return {
    status: 'partial',
    reason: 'cross-repo-lineage-best-effort',
    commitsConsidered: eligible.length,
    findingOrigin: originFrom(meta, { absentInParents: [] }),
    method: PROVENANCE_METHOD.SEMANTIC_REPLAY,
    crossRepoLineage: true,
  };
}

export async function resolveOrigin(scanRoot, finding, { since, deadlineAt, repoState, mode } = {}) {
  const file = finding?.file;
  const line = finding?.line || finding?.sink?.line;
  const stableId = finding?.stableId;
  if (!file || !line || !stableId) {
    return { status: 'not_available', reason: 'missing-file-line-or-stableId', commitsConsidered: 0 };
  }

  const candidates = candidateCommitsForLine(scanRoot, file, line, { since });
  if (candidates.length === 0) {
    return { status: 'not_available', reason: 'no-candidate-commits', commitsConsidered: 0 };
  }

  const files = relevantFiles(finding);
  let commitsConsidered = 0;

  // M2 §2.4 performance fix: within ONE resolveOrigin call, replayAt(sha) is
  // pure given (scanRoot, sha, files, stableId) — all fixed for this call.
  // The SAME sha is asked about twice whenever one candidate's first parent
  // equals the previous candidate: candidate i's "presentHere" check IS
  // candidate i+1's "presentInParent" check when parent(candidate i+1) ===
  // candidate i, which is the common case for a file with no gaps in its
  // edit history. Memoized here (not in predicate-replay.js itself) so the
  // cache stays scoped to one finding's walk — a cross-finding cache is
  // coordinator.js's job (Task 7), not this module's.
  const replayCache = new Map();
  const replay = (sha) => {
    if (replayCache.has(sha)) return replayCache.get(sha);
    const p = replayAt(scanRoot, sha, files, stableId);
    replayCache.set(sha, p);
    return p;
  };

  for (const sha of candidates) {
    if (deadlineAt && Date.now() > deadlineAt) {
      return { status: 'budget_exhausted', commitsConsidered };
    }
    commitsConsidered++;
    const presentHere = await replay(sha);
    if (!presentHere.present) continue;

    const parent = getFirstParent(scanRoot, sha);
    const meta = commitMeta(scanRoot, sha);
    if (!meta) continue;

    if (!parent) {
      if (repoState && repoState.shallow) {
        // Shallow boundary — cannot prove absence in a parent we cannot see.
        // This is exactly the false-certainty case the PRD forbids.
        return {
          status: 'partial', reason: 'shallow-boundary-reached', commitsConsidered,
          findingOrigin: originFrom(meta, { absentInParents: [] }),
          method: PROVENANCE_METHOD.SEMANTIC_REPLAY,
        };
      }
      // True repository root, non-shallow. Before settling for "no parent
      // exists to verify absence in" (M2/M3's existing weaker-evidence
      // path), try extending the walk into a declared cross-repo lineage
      // link (M4 §4.2) — this repo's root may not be where the code was
      // actually first written, just where THIS repo's history starts.
      const crossRepo = tryCrossRepoLineage(scanRoot, finding, meta);
      if (crossRepo) return crossRepo;
      // True repository root, non-shallow, no lineage link (or the link
      // didn't extend the answer) — valid but weaker evidence: no parent
      // exists to verify absence in, so parentBoundaryVerified stays false
      // and confidence.js will cap this at MEDIUM.
      return {
        status: 'complete', method: PROVENANCE_METHOD.SEMANTIC_REPLAY, commitsConsidered,
        findingOrigin: originFrom(meta, { absentInParents: [] }),
        parentBoundaryVerified: false,
      };
    }

    const presentInParent = await replay(parent);
    const absentInParent = !presentInParent.present;
    if (!absentInParent) continue; // predicate already true in parent — keep walking older candidates

    return {
      status: 'complete', method: PROVENANCE_METHOD.SEMANTIC_REPLAY, commitsConsidered,
      findingOrigin: originFrom(meta, { absentInParents: [parent] }),
      parentBoundaryVerified: true,
    };
  }

  // M3 §3.1: `--provenance deep`. The standard walk above only ever checks a
  // candidate's FIRST parent for absence — correct for linear history, but a
  // vulnerability introduced via a merged feature branch can be absent from
  // a NON-first parent while the first parent (inherited from mainline
  // before the merge) already carries it — the standard check never looks
  // past parents[0], so it never sees that other, absent parent. Deep mode
  // re-checks the SAME candidates the standard walk already found, this
  // time via `checkAbsentInSomeParent` — absence in AT LEAST ONE parent, not
  // necessarily the first. See that function's own doc comment in
  // dag-walk.js for why "any parent absent" (a strict superset of the
  // first-parent-only check) is the correct generalization here, and why
  // `checkAbsentInAllParents` (a strict SUBSET, used only for lifecycle
  // safety checks elsewhere) can never resolve anything this retry couldn't
  // already resolve via the primary loop above.
  if (mode === 'deep') {
    for (const sha of candidates) {
      if (deadlineAt && Date.now() > deadlineAt) {
        return { status: 'budget_exhausted', commitsConsidered };
      }
      const presentHere = await replay(sha);
      if (!presentHere.present) continue;
      commitsConsidered++;
      const { absentInSome, absentParents, rootCommit } = await checkAbsentInSomeParent(scanRoot, sha, replay);
      if (!absentInSome) continue;
      const meta = commitMeta(scanRoot, sha);
      if (!meta) continue;
      if (rootCommit && repoState && repoState.shallow) {
        return {
          status: 'partial', reason: 'shallow-boundary-reached', commitsConsidered,
          findingOrigin: originFrom(meta, { absentInParents: [] }),
          method: PROVENANCE_METHOD.SEMANTIC_REPLAY,
        };
      }
      const { isRevert, revertsCommit } = detectRevert(scanRoot, sha, candidates);
      const { isCherryPick, originalCommit } = detectCherryPick(scanRoot, sha);
      const origin = originFrom(meta, { absentInParents: absentParents });
      origin.revertOf = isRevert ? revertsCommit : null;
      origin.cherryPickOf = isCherryPick ? originalCommit : null;
      return {
        status: 'complete', method: PROVENANCE_METHOD.SEMANTIC_REPLAY, commitsConsidered,
        findingOrigin: origin,
        parentBoundaryVerified: !rootCommit,
      };
    }
  }

  return { status: 'partial', reason: 'predicate-never-confirmed-in-candidates', commitsConsidered };
}
