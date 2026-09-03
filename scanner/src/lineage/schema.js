//
// DataFlowGraph v1 — canonical envelope and enum contract (Data Flow
// Explorer PRD section 10). This module carries only pure constants and
// the empty-envelope constructor; no analysis logic lives here. A change
// to any array below is a schema-version-bumping change.
//
// Isolated from scanner/src/dataflow/ on purpose (PRD section 18.1): this
// package may read pure, stateless exports from dataflow/privacy-taxonomy.js
// but must never import scanner/src/dataflow/engine.js or touch its taint
// state.

export const SCHEMA_VERSION = '1.0.0';

export const NODE_KINDS = Object.freeze([
  'source', 'process', 'transform', 'api', 'store', 'queue',
  'log', 'sink', 'external', 'boundary', 'unresolved',
]);

export const MAPPING_TYPES = Object.freeze([
  'identity', 'rename', 'projection', 'serialization', 'deserialization',
  'transformation', 'aggregation', 'join', 'filter', 'sort', 'conditional', 'unknown',
]);

export const TRANSFORM_KINDS = Object.freeze([
  'mask', 'redact', 'tokenize', 'hash', 'encrypt', 'decrypt', 'encode',
  'decode', 'aggregate', 'truncate', 'normalize', 'custom', 'unknown',
]);

export const REVERSIBILITY_VALUES = Object.freeze(['reversible', 'irreversible', 'unknown']);

// FR-403's single-path handling TAXONOMY (Milestone 2, Sub-project D,
// increment 1 — DESIGN_HANDLING_ANALYZER.md). Lives on `flow.handling`, a
// STRING enum — deliberately NOT the same thing as `protection.js`'s
// `PROTECTION_DIMENSIONS`' own `handling` dimension (an per-EDGE
// `{verdict, evidenceGrade}` object scored from `PROTECTION_VERDICTS`).
// The two share a name because this taxonomy IS what a later Milestone 2
// analyzer will read to populate that verdict (transform-catalog.js's own
// header: "Recognizing that a `mask` happened is this module's job.
// Deciding whether that `mask` earns 'protected' is Milestone 2's FR-401-
// 405 analyzers, reading this module's output.") — but the two fields are
// never the same value, never interchangeable, and this increment sets
// only `flow.handling`, never `edge.protection.handling`.
export const HANDLING_VALUES = Object.freeze([
  'raw', 'masked', 'redacted', 'hashed', 'tokenized', 'encrypted', 'aggregated', 'unknown',
]);

export const EXTERNALITY_VALUES = Object.freeze(['internal', 'external', 'unknown']);

export const COVERAGE_STATUS_VALUES = Object.freeze(['modeled', 'partial', 'candidate', 'unsupported', 'manual']);

// Milestone 5, language coverage-tier disclosure: a product-level tier for
// an entire LANGUAGE (per docs/METRICS.md's own curated recall measurements),
// deliberately NOT a reuse of COVERAGE_STATUS_VALUES above — that enum
// answers a different question (is this one NODE's own classification
// confident), not "does this language, as a whole, clear the PRD's own
// field-to-sink recall bar." 'full' is real and reachable (a future
// docs/METRICS.md update crossing 85% needs no code change here to report
// it) even though no language currently resolves to it.
export const LANGUAGE_COVERAGE_TIER_VALUES = Object.freeze(['full', 'partial', 'pattern-only', 'unknown']);

export const DESTINATION_RESOLUTION_VALUES = Object.freeze([
  'literal', 'resolved_from_constant', 'resolved_from_config', 'resolved_from_schema',
  'declared_service', 'runtime_corroborated', 'dynamic', 'unknown',
]);

// Milestone 2, Sub-project F, increment 1 (FR-304): which mechanism
// discovered this edge. Deliberately value-aligned with (but a
// distinct field from) EVIDENCE_TYPES — 'code'/'schema'/'manual'/
// 'runtime' are FR-304's own four categories, reusing EVIDENCE_TYPES's
// existing spellings rather than inventing a second vocabulary for the
// same four concepts. Only 'code' has a real producer today
// (graph-builder.js sets it unconditionally); 'schema'/'manual'/
// 'runtime' are reserved for Sub-project F2/F3, not yet implemented —
// see scanner/src/lineage/CLAUDE.md.
export const EDGE_PROVENANCE_VALUES = Object.freeze(['code', 'schema', 'manual', 'runtime']);

// Milestone 2, Sub-project E, increment 2 (`node.storeDetail.operation`,
// DESIGN_STORE_DETAIL.md). `save` deliberately maps to `'upsert'`, never
// `'create'` — see graph-builder.js's own method-name mapping comment for
// the full reasoning (Mongoose's `.save()` is an INSERT on a new document
// but an UPDATE on one loaded from the database, genuinely undecidable
// statically from the call site alone; `'upsert'` is the honest umbrella,
// not a guess at which one).
export const STORE_OPERATION_VALUES = Object.freeze(['create', 'read', 'update', 'delete', 'upsert', 'unknown']);

// Milestone 2, Sub-project E, increment 3 (`node.queueDetail.operation`,
// DESIGN_QUEUE_DETAIL.md). Only two values, deliberately — both real
// PRIVACY_SINK_CATALOG queue entries (`sendMessage`, `publish`) are
// unambiguously a WRITE/publish operation, unlike the database case's real
// `create`/`update`/`upsert` spread; there is no `read`/`delete`/`create`
// ambiguity to disclose here. Every queue site this increment recognizes
// gets `operation: 'publish'` — never `'unknown'` in practice today (no
// catalog entry produces anything else), but the value exists so
// `validate.js`'s structural check has a real enum to check against, the
// same "define the vocabulary even if only one value is reachable today"
// precedent `HANDLING_VALUES`/`STORE_OPERATION_VALUES` both already
// established.
export const QUEUE_OPERATION_VALUES = Object.freeze(['publish', 'unknown']);

export const POLICY_STATES = Object.freeze([
  'prohibited', 'permitted', 'conditionally_permitted', 'manual_review_required', 'not_evaluated',
]);

export const EVIDENCE_TYPES = Object.freeze([
  'code', 'ir', 'configuration', 'iac', 'schema', 'service_declaration', 'policy', 'manual', 'runtime',
]);

export const FLOW_SUMMARY_VALUES = Object.freeze(['protected', 'unprotected', 'mixed', 'unknown', 'not_assessed']);

// Not named in the PRD's own envelope example (section 10.2) but required
// by Appendix D.1's "no special-casing by name" rule: the UI needs a
// GENERIC signal for the "Illustrative demo data" ribbon, not a check
// against a specific fixture filename or node id.
export const GRAPH_SCOPE_SOURCES = Object.freeze(['scan', 'fixture']);

// PRD section 11 (FR-101) source categories and section 12 (FR-201) sink
// categories — the fixed vocabulary a node's `subtype`/an inventory row's
// category field draws from. This is the TAXONOMY only; the pattern-
// matching registries that recognize one of these categories in real
// source code (source-registry.js / sink-registry.js, PRD DFG-003) are
// Milestone 1, not this module.
export const SOURCE_CATEGORIES = Object.freeze([
  'http-body', 'http-query', 'http-route', 'http-header', 'http-cookie', 'http-upload',
  'graphql-argument', 'grpc-field', 'cli-argument', 'env-value', 'queue-message',
  'database-read', 'storage-read', 'user-input', 'external-api-response',
  'webhook-payload', 'ai-model-output', 'ai-tool-result', 'ai-retrieved-document',
  'ai-memory', 'declared',
]);

export const SINK_CATEGORIES = Object.freeze([
  'log', 'stdout', 'http-response', 'client-storage', 'database', 'file', 'object-storage',
  'cache', 'queue', 'analytics', 'monitoring', 'email', 'sms', 'push-notification', 'collaboration',
  'external-api', 'webhook', 'ai-model-provider', 'ai-local-model', 'ai-agent', 'ai-tool',
  'ai-vector-store', 'ai-memory', 'ai-training', 'ai-evaluation', 'ai-telemetry',
  'backup', 'export', 'declared',
]);

/**
 * A fresh DataFlowGraph v1 envelope with every required top-level key
 * present. Callers overlay real content; every array starts empty and
 * every nested object starts as `{}` except `scope.source`, which
 * defaults to `'scan'` (a fixture builder must set it to `'fixture'`
 * explicitly — the safe default assumes real analyzer output).
 */
export function emptyGraphEnvelope(overrides = {}) {
  const { graphId, generatedAt, scope, ...rest } = overrides;
  return {
    schemaVersion: SCHEMA_VERSION,
    graphId: graphId || null,
    generatedAt: generatedAt || new Date().toISOString(),
    scope: { source: 'scan', ...(scope || {}) },
    scanHealth: {},
    taxonomy: {},
    nodes: [],
    edges: [],
    dataElements: [],
    transformations: [],
    flows: [],
    controls: [],
    policies: [],
    evidence: [],
    coverage: {},
    limitations: [],
    extensions: {},
    ...rest,
  };
}
