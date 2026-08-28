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

export function redactFindingProvenance(fp, { includeEmail = false } = {}) {
  if (!fp) return null;
  const redactOrigin = (origin) => origin ? { ...origin, authorEmail: includeEmail ? origin.authorEmail : null } : null;
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
// it has two consumers on opposite sides of the report/posture boundary:
// report/index.js's explainProvenance/toMarkdown, and
// posture/auditor-walkthrough.js's renderWalkthrough — both of which are
// also console.log'd verbatim (bin/agentic-security.js), so both need the
// terminal-safety guarantee. Putting it in report/ would make posture/
// depend on report/, backwards from every other dependency in this tree.
export function sanitizeForTerminal(str) {
  if (typeof str !== 'string') return str;
  // eslint-disable-next-line no-control-regex
  return str.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '').replace(/[\r\n]+/g, ' ').trim();
}

// Markdown-specific sibling of sanitizeForTerminal — a DIFFERENT injection
// class (FR-PROV-026 names "commit messages" explicitly, and Markdown
// injection via `[text](javascript:...)`, `![x](url)`, raw `<img onerror=…>`,
// or a code-fence breakout is not something ANSI-stripping defends against).
// Terminal control characters are stripped first (this text can ALSO reach a
// terminal — e.g. renderWalkthrough() is both written to a .md file AND
// console.log'd by `agentic-security compliance --walkthrough`), then every
// CommonMark punctuation character that could turn plain author text into a
// live link/image/raw-HTML/code-span/emphasis run is backslash-escaped, so
// it renders as inert literal text instead of being interpreted as Markdown.
export function sanitizeForMarkdown(str) {
  if (typeof str !== 'string') return str;
  return sanitizeForTerminal(str).replace(/[\\`*_{}[\]()#+\-.!<>|]/g, (c) => '\\' + c);
}
