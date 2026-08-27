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

import { candidateCommitsForLine, getFirstParent, commitMeta } from './git-evidence.js';
import { replayAt } from './predicate-replay.js';
import { PROVENANCE_METHOD } from './schema.js';

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
    presentInCommit: true, absentInParents,
  };
}

export async function resolveOrigin(scanRoot, finding, { since, deadlineAt, repoState } = {}) {
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

  for (const sha of candidates) {
    if (deadlineAt && Date.now() > deadlineAt) {
      return { status: 'budget_exhausted', commitsConsidered };
    }
    commitsConsidered++;
    const presentHere = await replayAt(scanRoot, sha, files, stableId);
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
      // True repository root, non-shallow — valid but weaker evidence: no
      // parent exists to verify absence in, so parentBoundaryVerified stays
      // false and confidence.js will cap this at MEDIUM.
      return {
        status: 'complete', method: PROVENANCE_METHOD.SEMANTIC_REPLAY, commitsConsidered,
        findingOrigin: originFrom(meta, { absentInParents: [] }),
        parentBoundaryVerified: false,
      };
    }

    const presentInParent = await replayAt(scanRoot, parent, files, stableId);
    const absentInParent = !presentInParent.present;
    if (!absentInParent) continue; // predicate already true in parent — keep walking older candidates

    return {
      status: 'complete', method: PROVENANCE_METHOD.SEMANTIC_REPLAY, commitsConsidered,
      findingOrigin: originFrom(meta, { absentInParents: [parent] }),
      parentBoundaryVerified: true,
    };
  }

  return { status: 'partial', reason: 'predicate-never-confirmed-in-candidates', commitsConsidered };
}
