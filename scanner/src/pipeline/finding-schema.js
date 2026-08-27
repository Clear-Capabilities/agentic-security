// Finding schema (assurance-hardening PRD, Milestone 0, FR-105).
//
// The PRD's §10.1 envelope (schemaVersion/stableId/producerId/... in ten
// named groups) describes an IDEAL shape. This engine's actual canonical
// shape already exists — it is report/index.js's `normalizeFindings()`,
// which every JSON/SARIF/HTML/CSV/JUnit/OSCAL output format calls (verified
// by grepping every call site in report/index.js, oscal.js, and
// bin/agentic-security.js before writing this module — see
// docs/implementation/assurance-hardening-decisions.md D-0003's rule: read
// the existing mechanism before building a parallel one). `normalizeFindings`
// already enforces an explicit allowlist with an honest `null` default for
// every optional field, which is most of what FR-105 asks for; it was simply
// never versioned or independently callable as "does this finding satisfy
// the contract".
//
// This module does two things, both additive (Milestone 0 scope — no gate
// wiring, no new required fields, nothing gets rejected):
//   1. Names FINDING_SCHEMA_VERSION so future breaking changes to the
//      normalizeFindings shape have something to bump (FR-105 acceptance:
//      "select a supported output contract during migration" per §12.1's
//      `--schema-version` flag, not yet wired to a CLI flag in this cycle).
//   2. Provides describeFindingCompleteness(), a pure, non-throwing function
//      that reports which of the CURRENT canonical fields a given finding
//      actually has non-null values for — observability, not enforcement.
//      Full enforcement (every producer's output must pass validation before
//      it can reach a reporter) is Milestone 1's FR-103/FR-104, which
//      requires producer isolation (FR-201) to exist first so a rejected
//      finding can be attributed to the producer that emitted it.
//
// One MCP correctness bug was found and fixed alongside this (not scope
// creep — it's the exact FR-105 acceptance criterion "...and MCP outputs
// derive from the same validated object"): mcp/tools.js's scan_diff hand-
// rolled a 3-of-4-channel finding merge instead of calling
// normalizeFindings(), which both risked field-mapping drift and silently
// excluded the supplyChain channel. Fixed in mcp/tools.js; see that file's
// comment for the residual limitation (scan_diff still never populates
// depFileContents, so supply-chain detection does not reach it today for an
// unrelated, deeper reason this schema module does not address).

export const FINDING_SCHEMA_VERSION = 1;

// Field groups mirror the PRD's §10.1 structure, using the CURRENT field
// names normalizeFindings() actually produces (see decision D-0003: extend
// what exists, don't invent a parallel vocabulary no real finding uses).
// `required` fields are ones every finding channel (sast/secret/logic/sca)
// sets to a real (non-null) value today; `optional` fields are legitimately
// null on many findings (e.g. a finding no annotator has enriched yet).
export const FINDING_FIELD_GROUPS = {
  // `findingProvenance` is REQUIRED, not optional, and that is deliberate:
  // posture/provenance/coordinator.js guarantees every finding it sees leaves
  // with a TERMINAL provenance object, expressing every failure mode as a
  // status ('not_available', 'uncommitted', 'budget_exhausted', 'error')
  // rather than as an absent field. So a missing findingProvenance never means
  // "provenance didn't apply here" — it means the finding escaped annotation
  // entirely, which is exactly the condition this group exists to surface.
  identity: { required: ['id', 'kind', 'vuln', 'findingProvenance'], optional: ['stableId'] },
  location: { required: ['file', 'line'], optional: ['snippet'] },
  classification: { required: ['severity'], optional: ['cwe', 'owaspLlm', 'family', 'parser', 'tags', 'description'] },
  confidence: { required: [], optional: ['confidence', 'confidenceTier', 'calibrated_confidence', 'calibration_reason'] },
  evidence: { required: [], optional: ['proof', 'falsification', 'verification', 'chain', 'sources', 'corroboration'] },
  privacy: { required: [], optional: ['dataClasses'] },
  compliance: { required: [], optional: [] }, // no per-finding controlRefs today — compliance mapping is scan-level (FR-501/E5)
  remediation: { required: [], optional: ['fix', 'remediation'] },
  risk: { required: [], optional: ['exploitability', 'exploitabilityTier', 'compositeRisk', 'compositeRiskTier', 'crownJewelScore', 'riskDollars'] },
  lifecycle: { required: [], optional: ['triage', 'quarantined', 'unreachable'] },
};

/**
 * Reports, for one normalized finding (i.e. an item from
 * report/index.js#normalizeFindings' output — this function does NOT accept
 * a raw pre-normalization finding), which canonical groups have their
 * required fields present and which optional fields are populated.
 *
 * Pure, non-throwing, additive-only: does not mutate the finding, does not
 * gate anything, and is not called from engine.js's default pipeline. It
 * exists to be run over a real scan's output for observability (a future
 * `--explain-health`-style report, per PRD §12.1) — see this module's
 * header comment for what is deliberately NOT yet true of it.
 *
 * @param {object} finding - one entry from normalizeFindings(scan)
 * @returns {{schemaVersion:number, missingRequiredFields:string[], populatedOptionalFields:string[], missingOptionalFields:string[], isComplete:boolean}}
 */
export function describeFindingCompleteness(finding) {
  const f = finding && typeof finding === 'object' ? finding : {};
  const missingRequiredFields = [];
  const populatedOptionalFields = [];
  const missingOptionalFields = [];

  const isPopulated = (v) => v !== null && v !== undefined && !(Array.isArray(v) && v.length === 0);

  for (const group of Object.values(FINDING_FIELD_GROUPS)) {
    for (const field of group.required) {
      if (!isPopulated(f[field])) missingRequiredFields.push(field);
    }
    for (const field of group.optional) {
      if (isPopulated(f[field])) populatedOptionalFields.push(field);
      else missingOptionalFields.push(field);
    }
  }

  return {
    schemaVersion: FINDING_SCHEMA_VERSION,
    missingRequiredFields,
    populatedOptionalFields,
    missingOptionalFields,
    isComplete: missingRequiredFields.length === 0,
  };
}
