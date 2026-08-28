import * as crypto from 'node:crypto';

export const FINDING_PROVENANCE_SCHEMA_VERSION = '1.0';

export const PROVENANCE_STATUS = Object.freeze({
  COMPLETE: 'complete',
  PARTIAL: 'partial',
  NOT_AVAILABLE: 'not_available',
  UNCOMMITTED: 'uncommitted',
  BUDGET_EXHAUSTED: 'budget_exhausted',
  ERROR: 'error',
});

export const PROVENANCE_METHOD = Object.freeze({
  SEMANTIC_REPLAY: 'semantic-history-replay',
  DEPENDENCY_GRAPH_DIFF: 'dependency-graph-diff',
  LINE_ATTRIBUTION: 'line-attribution',
  SCAN_HISTORY: 'scan-history',
  // FR-PROV-017: a missing-control-resolver.js regression — "commit removed a
  // previously-present safeguard" — not a code-INTRODUCTION event, so it is
  // kept distinct from SEMANTIC_REPLAY (which always names the commit that
  // introduced a bad pattern). A reader relying on `method` to interpret what
  // `findingOrigin` means must be able to tell the two apart.
  MISSING_CONTROL_REGRESSION: 'missing-control-regression',
  NONE: 'none',
});

export const CONFIDENCE_LEVEL = Object.freeze({ HIGH: 'high', MEDIUM: 'medium', LOW: 'low', UNKNOWN: 'unknown' });

export const EVIDENCE_ROLE = Object.freeze({
  SOURCE: 'source', SINK: 'sink', GUARD: 'guard', REMOVED_GUARD: 'removed_guard',
  TRANSFORMATION: 'transformation', CONFIG: 'config', SECRET: 'secret',
  MANIFEST: 'manifest', LOCKFILE: 'lockfile', OTHER: 'other',
});

// M3: the AGE_BASIS enum, re-added now that M2 shipped its two consumers
// (mttr.js's ageBasis field, fix-history.js's provenanceAtFix.ageBasis) —
// both previously used bare string literals matching this vocabulary
// without importing a shared source of truth for it.
export const AGE_BASIS = Object.freeze({
  FINDING_ORIGIN: 'finding_origin',
  EARLIEST_OBSERVABLE: 'earliest_observable',
  FIRST_OBSERVED: 'first_observed',
  UNCOMMITTED: 'uncommitted',
});

// The `['complete', 'uncommitted']` "provenance is healthy enough to trust"
// check independently existed in TWO places (bin/agentic-security.js's
// --require-provenance block and pipeline/assurance-mode.js's strict check),
// both re-deriving the same status set locally; unified into this one shared
// predicate, so a future change to what counts as "healthy" is a one-line
// edit, not a grep-and-fix-N-places. mttr.js's/fix-history.js's ageBasis
// tiering is a DIFFERENT thing — it buckets a finding's age basis for
// reporting, not a healthy/unhealthy gate — and was never converted to use
// this predicate; do not conflate the two.
export function isProvenanceHealthy(findingProvenance) {
  return ['complete', 'uncommitted'].includes(findingProvenance?.status);
}

export function emptyProvenance(status, extra = {}) {
  return {
    schemaVersion: FINDING_PROVENANCE_SCHEMA_VERSION,
    status,
    findingOrigin: null,
    branchIntroduction: null,
    // FR-PROV-022: PR/reviewer/CODEOWNERS metadata is a distinct concern from
    // "which commit/branch introduced this" (branchIntroduction) — a sibling
    // top-level field, not nested inside it, matching this schema's existing
    // convention of keeping origin/branch-entry/evidence-attribution as
    // separate top-level objects. Populated only when a provider is
    // configured AND a PR/MR was actually found for the origin commit;
    // otherwise stays at this default (never a half-filled object).
    providerEnrichment: null,
    firstObserved: null,
    evidenceAttribution: [],
    method: PROVENANCE_METHOD.NONE,
    confidence: { level: CONFIDENCE_LEVEL.UNKNOWN, score: 0, reasons: [] },
    historyCoverage: { complete: false, shallow: false, boundaryCommit: null, commitsConsidered: 0, crossRepoLineage: false },
    analysisBasis: { head: null, ruleset: null, detector: null, dirty: false },
    limitations: [],
    evidenceDigest: null,
    ...extra,
  };
}

/**
 * A stable, one-way pseudonym for an author -- PRD Section 8: "support
 * organization policy to pseudonymize names while retaining an internal
 * stable identity reference." Keyed on email when available (more stable
 * across commits than a display name, which can vary in capitalization or
 * formatting across different commits by the same person) with a fallback
 * to name alone. Deterministic: the SAME author always gets the SAME
 * pseudonym within one run (and across runs, since it's a pure function of
 * the input, not randomized) -- this is what "stable identity reference"
 * means: a reader can tell "these five findings share an author" without
 * learning who that author is.
 */
export function pseudonymizeAuthor(authorName, authorEmail) {
  const key = authorEmail || authorName || '';
  if (!key) return 'Contributor-unknown';
  const hash = crypto.createHash('sha256').update(key).digest('hex').slice(0, 8);
  return `Contributor-${hash}`;
}

export function redactFindingProvenance(fp, { includeEmail = false, pseudonymize = false } = {}) {
  if (!fp) return null;
  const redactOrigin = (origin) => origin
    ? {
        ...origin,
        authorEmail: includeEmail ? origin.authorEmail : null,
        authorName: pseudonymize ? pseudonymizeAuthor(origin.authorName, origin.authorEmail) : origin.authorName,
      }
    : null;
  return {
    ...fp,
    findingOrigin: redactOrigin(fp.findingOrigin),
  };
}

// Untrusted commit metadata (author name, commit summary) must never reach
// a terminal or a Markdown/HTML renderer un-sanitized — PRD FR-PROV-026.
// Strips ANSI/control escape sequences (a malicious author name containing
// \x1b[2J or similar could manipulate terminal state) and collapses
// newlines (a multi-line "author name" could forge extra output lines).
// This is layered UNDER the existing HTML-escaping path (which already
// protects the HTML renderer via JSON-escaping before embedding) — this
// helper is specifically for the CLI/terminal text path, which had none.
//
// Lives here (rather than in report/index.js, which re-exports it) because
// it has consumers on opposite sides of the report/posture boundary:
// report/index.js's explainProvenance/toMarkdown, and
// posture/auditor-walkthrough.js's renderWalkthrough — both of which are
// console.log'd verbatim (bin/agentic-security.js), so both need the
// terminal-safety guarantee. Putting it in report/ would make posture/
// depend on report/, backwards from every other dependency in this tree.
//
// A Markdown-specific sibling (backslash-escaping CommonMark punctuation)
// was added and then removed here: it was applied to renderWalkthrough's
// output, but that text's only LIVE consumer is bin/agentic-security.js's
// raw `console.log`, and its file-writing sibling (persistWalkthrough) has
// zero callers anywhere in the CLI/command surface — nothing in this repo
// ever runs this text through an actual Markdown renderer. Backslash-
// escaping is only inert once a real renderer processes it; printed raw or
// read as a plain-text file, `Jean-Luc Picard` becoming `Jean\-Luc Picard`
// and `dependabot[bot]` becoming `dependabot\[bot\]` is a visible
// regression on ordinary, common real-world names, not a security fix. If
// a genuine Markdown-rendering consumer of this text is added later, revisit
// this decision informed by that consumer's actual escaping requirements —
// don't reintroduce blind punctuation-escaping speculatively.
export function sanitizeForTerminal(str) {
  if (typeof str !== 'string') return str;
  // eslint-disable-next-line no-control-regex
  return str.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '').replace(/[\r\n]+/g, ' ').trim();
}
