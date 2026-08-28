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

import { runFullScan } from '../../engine.js';
import { computeStableId } from '../stable-id.js';
import { getBlobAtCommit } from './git-evidence.js';

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
    // `provenance:false` is mandatory, not an optimisation: runFullScan now
    // runs the provenance pass, which lands back here — an unbounded
    // scan→provenance→replay→scan recursion that never returns. See the
    // comment on runFullScan's signature.
    //
    // `skipAnnotators:true` (FR-PROV-029): this function only ever reads
    // `scan.findings`/`scan.secrets` to recompute `computeStableId()` below —
    // it never reads anything any of runFullScan's ~54 post-detection
    // annotators set. Skipping the whole annotator pipeline avoids paying
    // its cost (measured ~39ms fixed overhead per call) on every one of the
    // ~2 replay calls per finding the resolution walk already makes.
    // Verified empirically (byte-identical computeStableId output with and
    // without annotators, over a real scan) before this was wired in — see
    // the FR-PROV-029 commit message for methodology.
    scan = await runFullScan({ fileContents, scanRoot, provenance: false, skipAnnotators: true }, () => {});
  } catch (e) {
    return { present: false, reason: 'replay-error' };
  }
  const candidates = [...(scan.findings || []), ...(scan.secrets || [])];
  for (const f of candidates) {
    let sid;
    try { sid = computeStableId(f); } catch { continue; }
    if (sid === targetStableId) {
      return { present: true, replayedFinding: f };
    }
  }
  return { present: false, reason: 'stableId-not-reproduced' };
}
