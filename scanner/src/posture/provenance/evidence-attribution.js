import { blameLine } from './git-evidence.js';
import { EVIDENCE_ROLE } from './schema.js';

// Second independent Finding Provenance PRD audit: `opts.removedGuard` and
// `opts.secret` let coordinator.js tell this function WHICH question a
// no-source/no-sink finding is actually answering, instead of every such
// finding collapsing onto the generic `sink` role. Both are cheap,
// coordinator-level hints — no new detector work:
//   - `removedGuard` — set for a `missingControlCandidate` finding
//     (today, rate-limit.js's routes) once `resolveMissingControl` has
//     confirmed a present->absent transition. The finding's own file:line
//     IS the site where the (now-removed) control was expected, so that
//     single evidence node is `removed_guard`, not `sink`.
//   - `secret` — set for every finding routed through the coordinator with
//     `findingType: 'secret'`. A hardcoded-credential finding's evidence
//     node names where the SECRET sits, not a taint sink.
// `guard` and `config` are NOT wired: no current detector's evidence
// naturally maps to either without new detector-side work (a "control is
// PRESENT" observation, or a misconfigured-setting location) — see
// schema.js's EVIDENCE_ROLE comment for the honest disclosure.
export function attributeEvidence(scanRoot, finding, opts = {}) {
  const nodes = [];
  const push = (role, file, line) => {
    if (!file || !line) return;
    const blame = blameLine(scanRoot, file, line);
    nodes.push({ role, path: file, line, commit: blame && !blame.uncommitted ? blame.commit : null });
  };
  const fallbackRole = opts.removedGuard
    ? EVIDENCE_ROLE.REMOVED_GUARD
    : opts.secret
    ? EVIDENCE_ROLE.SECRET
    : EVIDENCE_ROLE.SINK;

  if (finding.source || finding.sink) {
    if (finding.source) push(EVIDENCE_ROLE.SOURCE, finding.source.file || finding.file, finding.source.line);
    if (finding.sink) push(EVIDENCE_ROLE.SINK, finding.sink.file || finding.file, finding.sink.line);
  } else {
    push(fallbackRole, finding.file, finding.line);
  }

  // `step.removedGuard` — a per-STEP (not whole-finding) removed-guard
  // marker for a taint-flow backward slice, e.g. "a sanitizer that used to
  // sit on this path is gone." Honest disclosure (second independent audit):
  // no producer sets this today — `dataflow/backward.js`'s
  // `annotateBackwardSlices` is the only `pathSteps` writer and only ever
  // sets `{type, label, line}`, never `removedGuard`. Left in place as the
  // intended hook for a future taint-based guard-removal detector; the
  // finding-level `opts.removedGuard` hint above is the one currently-live
  // path to a `removed_guard` node (the rate-limit / missing-control case,
  // which has no `pathSteps` at all).
  if (Array.isArray(finding.pathSteps)) {
    for (const step of finding.pathSteps) {
      const role = step.removedGuard ? EVIDENCE_ROLE.REMOVED_GUARD : EVIDENCE_ROLE.TRANSFORMATION;
      push(role, step.file || finding.file, step.line);
    }
  }

  return nodes;
}
