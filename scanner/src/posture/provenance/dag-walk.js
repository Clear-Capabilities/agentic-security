// Non-linear DAG analysis for --provenance deep (Finding Provenance PRD,
// M3 §3.1). Three independent capabilities, each documented at its export:
//
//  1. checkAbsentInAllParents — generalizes origin-resolver.js's existing
//     first-parent-only absence check to EVERY parent of a candidate commit.
//     A vulnerability introduced via a merged feature branch (not mainline)
//     needs this: checking only the first parent would see the predicate
//     already present there (inherited from mainline before the merge) and
//     wrongly conclude the merge commit isn't the origin, when the real
//     introduction happened on the feature branch's own history — which the
//     first-parent-only walk never visits at all.
//
//  2. detectRevert / detectCherryPick — lifecycle event classification, not
//     origin resolution. A reintroduction that is actually a revert-of-a-fix
//     or propagation of an earlier introduction via cherry-pick is a
//     DIFFERENT lifecycle story than an unrelated re-introduction, and
//     lifecycle.js's event vocabulary (Task 4) needs to say so.
import { getAllParents, commitDiff } from './git-evidence.js';
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
const SHA_RE = /^[0-9a-f]{4,40}$/i;
function _isSha(sha) { return typeof sha === 'string' && SHA_RE.test(sha); }

/**
 * Check whether a predicate is absent in EVERY parent of `sha`, not just the
 * first. `replay` is the caller's (sha) => Promise<{present:boolean}> closure
 * (origin-resolver.js already has one via its own memoized `replay`).
 */
export async function checkAbsentInAllParents(scanRoot, sha, replay) {
  const parents = getAllParents(scanRoot, sha);
  if (parents.length === 0) return { absentInAll: true, parents: [], rootCommit: true };
  const results = await Promise.all(parents.map((p) => replay(p)));
  const absentInAll = results.every((r) => !r.present);
  return { absentInAll, parents, rootCommit: false };
}

/**
 * Check whether a predicate is absent in AT LEAST ONE parent of `sha` (not
 * necessarily all of them). This is the mathematically correct
 * generalization of origin-resolver.js's first-parent-only check: "absent in
 * the first parent" is the special case where that one parent happens to be
 * absent, so "absent in ANY parent" is a strict SUPERSET of what the
 * first-parent check alone can find — it additionally catches a merge
 * candidate whose FIRST parent has the predicate (inherited from that
 * line's own earlier history) but a DIFFERENT parent's line did not, which
 * means that other line's merge into this one is genuinely where the
 * predicate became reachable via THIS path. `checkAbsentInAllParents`
 * (above) answers a different question — "did every contributing line lack
 * it" — and is a strict SUBSET of the first-parent check instead, which is
 * why it can never resolve anything the first-parent check couldn't already
 * resolve on its own; it exists as a safety/non-regression check, not a
 * resolving-power check. Do not conflate the two.
 */
export async function checkAbsentInSomeParent(scanRoot, sha, replay) {
  const parents = getAllParents(scanRoot, sha);
  if (parents.length === 0) return { absentInSome: true, absentParents: [], parents: [], rootCommit: true };
  const results = await Promise.all(parents.map((p) => replay(p)));
  const absentParents = parents.filter((_, i) => !results[i].present);
  return { absentInSome: absentParents.length > 0, absentParents, parents, rootCommit: false };
}

// git's own convention when using `git revert` (no -n/--no-edit override):
// "Revert \"<original subject>\"". Message alone is spoofable, so this is
// only the FIRST half of detection — see detectRevert.
const REVERT_MESSAGE_RE = /^Revert "/;

/**
 * A commit is a real revert only when its message matches git's own Revert
 * convention AND its diff is a genuine structural inverse of an EARLIER
 * candidate commit's diff (message-only detection is spoofable). Checked
 * against each of `candidateShas` (typically the same candidate list the
 * caller's walk already has, oldest-first) — the first one whose diff is the
 * exact reverse wins.
 */
export function detectRevert(scanRoot, sha, candidateShas) {
  if (!_isSha(sha)) return { isRevert: false, revertsCommit: null };
  const meta = _run(scanRoot, ['show', '-s', '--format=%s', sha]);
  if (!meta.ok || !REVERT_MESSAGE_RE.test(meta.stdout.trim())) {
    return { isRevert: false, revertsCommit: null };
  }
  const thisDiff = commitDiff(scanRoot, sha);
  if (!thisDiff) return { isRevert: false, revertsCommit: null };
  const invertedThisDiff = _invertUnifiedDiff(thisDiff);
  for (const candidate of candidateShas || []) {
    if (candidate === sha) continue;
    const candidateDiff = commitDiff(scanRoot, candidate);
    if (candidateDiff && candidateDiff.trim() === invertedThisDiff.trim()) {
      return { isRevert: true, revertsCommit: candidate };
    }
  }
  return { isRevert: false, revertsCommit: null };
}

// Produce what the INVERSE of a `-U0` unified diff would look like, so it
// can be string-compared against a candidate's real diff.
//
// DEVIATION FROM THE M3 BRIEF: the brief specified a per-LINE +/- swap
// ("this is intentionally a simple line-level swap ... -U0 makes this
// sufficient"). That is not sufficient — verified empirically against real
// `git revert` output before shipping this version. A unified diff hunk
// lists its removed lines as a BLOCK followed by its added lines as a
// BLOCK (git's own convention, not something -U0 changes); a real reverse
// diff swaps those two BLOCKS (additions become the new removal block,
// removals become the new addition block, in their respective original
// orders) — it does not swap each line's marker in place. For a hunk with
// one removal and one addition (the common single-line-change case) a
// per-line swap silently reverses the two lines' relative order versus
// what git itself produces, so the string comparison in detectRevert never
// matched a real revert: `-safe\n+eval(x)\n` inverted to `+safe\n-eval(x)\n`,
// but git's actual reverse diff is `-eval(x)\n+safe\n`. The `index a..b`
// header line's two blob hashes and a hunk header's `-x,y +p,q` ranges also
// swap under a real reversal and were previously left untouched, which
// mismatches too whenever the two commits touch different blobs (always,
// in practice). This version fixes both: it groups each contiguous run of
// -/+ content lines into a block and swaps the two blocks (not each line),
// and it swaps the index-line hash pair and the hunk-header range pair.
// Confirmed against both a single-line change and a two-hunk multi-line
// change, string-compared to `git diff <new> <old>`'s real output.
//
// POST-REVIEW FIX (M3 §3.1 review, finding #1): a whole-file add or delete
// was still mishandled. `git show -U0` on a commit that ADDS a file emits
// `new file mode <mode>` and a `---`/`+++` pair of `--- /dev/null` /
// `+++ b/<path>`; a commit that DELETES a file emits `deleted file mode
// <mode>` and the mirror pair, `--- a/<path>` / `+++ /dev/null`. Neither
// was touched before, so inverting an add-diff still read as an add (still
// `new file mode`, still `--- /dev/null`), which never matches a real
// delete diff and made `detectRevert` miss a revert-of-an-add or
// revert-of-a-delete entirely (fails safe — under-detection, not
// misattribution, but still a real gap `detectRevert` should not have).
// Fixed by: swapping `new file mode` <-> `deleted file mode` line-for-line,
// and — since the two file-mode header lines are independent per-line but
// the `---`/`+++` pair must be read TOGETHER to know which side is
// /dev/null — handling `---`/`+++` as a pair: an add's `--- /dev/null` +
// `+++ b/<path>` becomes a delete's `--- a/<path>` + `+++ /dev/null`, and
// vice versa; an ordinary modify's `--- a/<path>` + `+++ b/<path>` (neither
// side /dev/null) is left as-is, matching the existing a/ b/ convention
// that already made the plain-modify case direction-invariant. Confirmed
// against real git output for both a file addition reverted (delete) and a
// file deletion reverted (re-add), plus a regression check that the
// existing plain-modify case is unaffected.
function _invertUnifiedDiff(diffText) {
  const lines = diffText.split('\n');
  const out = [];
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    if (line.startsWith('new file mode ')) {
      out.push('deleted file mode ' + line.slice('new file mode '.length));
      i++;
      continue;
    }
    if (line.startsWith('deleted file mode ')) {
      out.push('new file mode ' + line.slice('deleted file mode '.length));
      i++;
      continue;
    }
    if (line.startsWith('index ')) {
      const m = line.match(/^index ([0-9a-f]+)\.\.([0-9a-f]+)(.*)$/);
      out.push(m ? `index ${m[2]}..${m[1]}${m[3]}` : line);
      i++;
      continue;
    }
    if (line.startsWith('@@')) {
      const m = line.match(/^@@ -(\S+) \+(\S+) @@(.*)$/);
      out.push(m ? `@@ -${m[2]} +${m[1]} @@${m[3]}` : line);
      i++;
      continue;
    }
    if (line.startsWith('--- ')) {
      const next = lines[i + 1];
      if (typeof next === 'string' && next.startsWith('+++ ')) {
        const oldSide = line.slice(4);
        const newSide = next.slice(4);
        if (oldSide === '/dev/null' && newSide.startsWith('b/')) {
          // Add -> inverted to a delete.
          out.push('--- a/' + newSide.slice(2));
          out.push('+++ /dev/null');
        } else if (newSide === '/dev/null' && oldSide.startsWith('a/')) {
          // Delete -> inverted to an add.
          out.push('--- /dev/null');
          out.push('+++ b/' + oldSide.slice(2));
        } else {
          // Ordinary modify: a/ and b/ labels are direction-invariant.
          out.push(line);
          out.push(next);
        }
        i += 2;
        continue;
      }
      out.push(line);
      i++;
      continue;
    }
    if (line.startsWith('+++') || line.startsWith('diff ')) {
      out.push(line);
      i++;
      continue;
    }
    if (line.startsWith('-') || line.startsWith('+')) {
      const removals = [];
      const additions = [];
      while (i < lines.length && (lines[i].startsWith('-') || lines[i].startsWith('+'))) {
        if (lines[i].startsWith('-')) removals.push(lines[i].slice(1));
        else additions.push(lines[i].slice(1));
        i++;
      }
      for (const a of additions) out.push('-' + a);
      for (const r of removals) out.push('+' + r);
      continue;
    }
    out.push(line);
    i++;
  }
  return out.join('\n');
}

// `git cherry-pick -x` leaves this exact trailer format in the new commit's
// message body: "(cherry picked from commit <full-or-abbrev-sha>)".
const CHERRY_PICK_TRAILER_RE = /\(cherry picked from commit ([0-9a-f]{4,40})\)/;

export function detectCherryPick(scanRoot, sha) {
  if (!_isSha(sha)) return { isCherryPick: false, originalCommit: null };
  const r = _run(scanRoot, ['show', '-s', '--format=%B', sha]);
  if (!r.ok) return { isCherryPick: false, originalCommit: null };
  const m = r.stdout.match(CHERRY_PICK_TRAILER_RE);
  if (!m) return { isCherryPick: false, originalCommit: null };
  return { isCherryPick: true, originalCommit: m[1] };
}
