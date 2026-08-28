// Historical-blob predicate replay (Finding Provenance PRD).
//
// Given a finding's stableId and the commit it is being investigated against,
// answer "does this finding's condition hold at that point in history" by
// re-running the FULL detector suite (`runFullScan`) scoped to just the
// finding's file(s) at that commit's blob content, and checking whether the
// same stableId reappears. This deliberately reuses the real pipeline instead
// of hand-mapping a finding to one of 60+ detector modules — it costs a real
// (if narrowly-scoped) scan, not a cheap pattern match, which is the tradeoff
// `origin-resolver.js` (Task 6) accepts for correctness.

import { runFullScan, _snapshotSuppressionLog, _restoreSuppressionLog } from '../../engine.js';
import { computeStableId } from '../stable-id.js';
import { getBlobAtCommit } from './git-evidence.js';

// Task 11 concurrency fix: `coordinator.js` resolves several findings' origins
// CONCURRENTLY (its own comment: "the scheduler runs these four at a time"),
// and each finding's `resolveOrigin` walk can call `replayAt` more than once
// sequentially -- so two DIFFERENT findings' replay calls can legitimately be
// in flight at the same time, interleaved at `runFullScan`'s own internal
// await points. `runFullScan` clears+writes a module-level suppression log
// (engine.js's `_suppressionLog`) unconditionally on every call; a plain
// snapshot/restore around one call is not safe under that interleaving.
//
// The actual failure shape (traced through, not guessed): call A snapshots
// the outer log, then awaits its nested `runFullScan`, which resets the log
// to empty and starts writing its OWN (nested-scan) entries. Before A's
// nested call finishes, call B starts: B's snapshot now captures A's
// in-progress nested state, not the outer scan's real log. When A finishes
// and restores ITS (correct) snapshot, that's fine -- but B's `finally` then
// restores what B snapshotted (A's nested state), overwriting A's correct
// restore with garbage that belongs to neither scan. It is not simply "the
// last restore wins" as a symmetric race between two correct values; the
// corrupting snapshot (B's) was already wrong the moment it was taken,
// because it read the log mid-mutation by a DIFFERENT nested scan.
//
// This queue serializes every `replayAt` call process-wide so the
// snapshot -> runFullScan -> restore critical section below is never entered
// by two calls at once -- call B cannot snapshot until call A has fully
// restored, so B always sees a clean outer-scan log. Correctness over
// throughput: `replayAt` is already the expensive path (a full nested scan
// per call, ~39ms fixed overhead) and this queue only serializes that nested
// scan itself, not the rest of each finding's concurrent resolution walk
// (blame calls, cache reads, etc. all still run unserialized).
//
// Exported (test-only) so a dedicated regression test can drive this queue
// directly and prove it serializes -- see
// test/posture/provenance-secrets-logic.test.js's "_runExclusive serializes
// concurrent critical sections" test, which fails if this queue is ever
// removed or replaced with a no-op passthrough.
let _replayQueue = Promise.resolve();
export function _runExclusive(fn) {
  const run = _replayQueue.then(fn, fn);
  // Never let one rejected replay poison the queue for subsequent callers --
  // `run`'s own rejection still propagates to ITS caller below.
  _replayQueue = run.then(() => {}, () => {});
  return run;
}

export async function replayAt(scanRoot, sha, files, targetStableId) {
  const fileContents = {};
  for (const f of files) {
    const content = getBlobAtCommit(scanRoot, sha, f);
    if (content != null) fileContents[f] = content;
  }
  if (Object.keys(fileContents).length === 0) {
    return { present: false, reason: 'no-files-at-commit' };
  }
  let scan;
  try {
    scan = await _runExclusive(async () => {
      // Task 11 reentrancy fix: `runFullScan` clears its module-level
      // suppression log unconditionally at the top of every call. This
      // function calls `runFullScan` recursively FROM WITHIN an outer, still-
      // running scan's provenance resolution -- without a snapshot/restore
      // around it, the nested call below silently wipes the OUTER scan's
      // suppression log before its own return value reads it (found via
      // `test/fixtures/entropy-fp`'s suppression count going to 0 once
      // scan.secrets was wired into real provenance resolution and started
      // reaching this recursive call for the first time). The nested scan's
      // own suppression output is never read below, so nothing is lost by
      // discarding it here. Safe from the concurrency hazard described above
      // ONLY because this whole callback runs inside `_runExclusive`.
      const _suppSnapshot = _snapshotSuppressionLog();
      try {
        // `provenance:false` is mandatory, not an optimisation: runFullScan
        // now runs the provenance pass, which lands back here — an unbounded
        // scan→provenance→replay→scan recursion that never returns. See the
        // comment on runFullScan's signature.
        //
        // `skipAnnotators:true` (FR-PROV-029): this function only ever reads
        // `scan.findings`/`scan.secrets` to recompute `computeStableId()`
        // below — it never reads anything any of runFullScan's ~54 post-
        // detection annotators set, nor the other finalization steps the
        // same option also skips (secret dedup, orphan classification,
        // freeze, checkpoint-close — see the guard comment in engine.js).
        // Skipping all of it avoids paying its cost (measured ~39ms fixed
        // overhead per call) on every one of the ~2 replay calls per finding
        // the resolution walk already makes. Verified empirically (byte-
        // identical computeStableId output with and without annotators, over
        // a real scan) before this was wired in — see the FR-PROV-029 commit
        // message for methodology.
        return await runFullScan({ fileContents, scanRoot, provenance: false, skipAnnotators: true }, () => {});
      } finally {
        _restoreSuppressionLog(_suppSnapshot);
      }
    });
  } catch (e) {
    return { present: false, reason: 'replay-error' };
  }
  // scan.logicVulns is included here too (Task 11, PRD P0 secrets/logicVulns
  // scope). This is safe even though scan.logicVulns includes the 3
  // synthetic-line producers (license-policy:/deploy-platform:/stack-playbook:
  // — fixed placeholder `line`, read scanRoot-level files directly rather than
  // from the `fileContents` this replay scan is scoped to) because those
  // producers are NEVER routed through resolveOrigin in the first place (see
  // engine.js's isSyntheticLogicFinding classification) — replayAt is never
  // asked to match against them. Their presence in this array when SOME OTHER
  // finding's replay runs is harmless: they just won't match that other
  // finding's stableId. Do NOT be tempted to wire ALL of scan.logicVulns
  // through provenance without reading the plan this task came from — see
  // docs/superpowers/plans/2026-08-28-finding-provenance-prd-completion.md's
  // "Global Research Findings" section.
  const candidates = [...(scan.findings || []), ...(scan.secrets || []), ...(scan.logicVulns || [])];
  for (const f of candidates) {
    let sid;
    try { sid = computeStableId(f); } catch { continue; }
    if (sid === targetStableId) {
      return { present: true, replayedFinding: f };
    }
  }
  return { present: false, reason: 'stableId-not-reproduced' };
}
