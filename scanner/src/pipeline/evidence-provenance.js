// Evidence provenance (assurance-hardening PRD, Milestone 1, FR-107).
//
// A real scanned finding carries ~90 flat fields (verified against a live
// scan of test/fixtures/vulnerable-js before writing this) — a mix of what
// the detector directly OBSERVED (file, line, matched snippet, rule id) and
// what LATER ANNOTATORS INFERRED from it (confidence, calibrated_confidence,
// severity adjustments, exploitability, compositeRisk, crownJewelScore,
// riskDollars, toxicity, blastRadius, and dozens more). Nothing about the
// flat shape tells a reviewer which is which — that distinction exists only
// as tribal knowledge of which field name means what. FR-107's acceptance
// criterion is exactly this: "A reviewer can distinguish observed facts from
// inferred confidence, severity, and risk."
//
// `posture/why-fired.js` ALREADY captures genuine raw evidence — sink/source
// snippets, path steps, sanitizers considered — nested under
// `finding.whyFired.evidence`, and is already wired into engine.js's default
// pipeline (confirmed: `annotateWhyFired` runs on every scan). That module
// solves "what did the detector see" for the detection step itself. This
// module does the complementary, coarser-grained job FR-107 actually asks
// for: given ANY finding, cleanly partition its top-level fields into
// observed vs. derived, so a reviewer (or a report) can ask the question
// without already knowing which of ~90 field names is which.
//
// DESIGN: an explicit ALLOWLIST of observed fields, not a blocklist of
// derived ones. A blocklist enumerating ~80 derived field names would need
// updating every time a new annotator ships a new field — exactly the kind
// of drift this session has repeatedly found and fixed elsewhere (producer
// registry, artifact registry, egress completeness guard). An allowlist of
// the small, stable set of fields a DETECTOR sets before any annotator runs
// is self-maintaining: anything not on it is derived by construction, so a
// new annotator's new field is correctly classified `derived` automatically,
// with zero maintenance here.
//
// Additive, non-throwing, Milestone-1 observability — like FR-105's
// describeFindingCompleteness, this does not mutate findings, gate anything,
// or run from engine.js's default pipeline.

import { FINDING_SCHEMA_VERSION } from './finding-schema.js';

// The fields a detector sets to describe WHAT it found and WHERE, before any
// annotator has touched the finding. Matches report/index.js's
// normalizeFindings() identity/location field names (not invented — read
// from the actual canonical shape, per this session's D-0003 discipline).
export const RAW_OBSERVED_FIELDS = Object.freeze([
  'id', 'stableId', 'kind', 'vuln', 'cwe', 'owaspLlm', 'stride', 'family', 'parser',
  'file', 'line', 'snippet',
]);

/**
 * Split one finding's fields into what was directly observed by a detector
 * vs. what was inferred by a later annotator.
 *
 * @param {object} finding - one entry from report/index.js#normalizeFindings()'s
 *   output (the same contract describeFindingCompleteness uses) — NOT a raw
 *   pre-normalization engine finding. Some detector families only set `line`/
 *   `snippet` nested under `f.source`/`f.sink` internally; normalizeFindings()
 *   is what guarantees they land as flat top-level keys, which is what this
 *   function's field partition depends on.
 * @returns {{schemaVersion:number, observed:object, derived:object}}
 *   `observed` — RAW_OBSERVED_FIELDS present on the finding, plus
 *   `detectorEvidence` (finding.whyFired.evidence, when annotateWhyFired has
 *   run) — the snippets/path/sanitizers a detector directly saw.
 *   `derived` — every OTHER non-null field: confidence, severity,
 *   exploitability, compositeRisk, riskDollars, and everything else any
 *   annotator computed. Named `derived` rather than enumerated because the
 *   set of annotator-added fields grows over time and enumerating it here
 *   would silently go stale (see module header).
 */
export function describeEvidenceProvenance(finding) {
  const f = finding && typeof finding === 'object' ? finding : {};
  const observedSet = new Set(RAW_OBSERVED_FIELDS);
  const observed = {};
  const derived = {};

  for (const [key, value] of Object.entries(f)) {
    if (value === null || value === undefined) continue;
    if (observedSet.has(key)) observed[key] = value;
    else derived[key] = value;
  }

  // whyFired.evidence is itself raw (what the detector saw); whyFired as a
  // whole still lands in `derived` above since it also carries `considered`
  // (pipeline-processing outcomes) and `scanner` (ruleset provenance) —
  // neither is "what the detector observed", so only the evidence slice is
  // promoted into `observed`, not the whole wrapper object.
  if (f.whyFired && typeof f.whyFired === 'object' && f.whyFired.evidence) {
    observed.detectorEvidence = f.whyFired.evidence;
  }

  return { schemaVersion: FINDING_SCHEMA_VERSION, observed, derived };
}
