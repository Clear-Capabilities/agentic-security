// runtime-observation.js — the RuntimeObservation §10.10 extension contract
// (M5 deliverable #7, "Runtime-Corroborated Digital Twin" — this deliverable
// ships ONLY the runtime-observed half, "7b"; the config-declared half "7a"
// is out of scope for this whole sub-project — see the scoping doc's §4.0).
// FR-505, AC-29 ("Runtime observation remains metadata-only and
// non-exclusionary" — the Milestone 5 exit-gate clause this module is
// gated on). Pure by contract: zero imports, no fs, no I/O, never throws —
// mirrors `impact-assessment.js`'s/`flow-grade.js`'s own precedent exactly.
//
// ── Why this module is CLOSED-WORLD when every sibling §10.10 contract is
//    open-world ──────────────────────────────────────────────────────────
//
// Every other extension-contract validator in this package
// (`impact-assessment.js`, `recipient-profile.js`, `scenario.js`,
// `obligation-mapping.js`, `graph-snapshot.js`) is open-world: it checks
// that the fields it cares about are well-formed and is silent about
// anything else on the record. That is the right default for a record
// built from the scanner's OWN already-vetted graph content.
//
// A RuntimeObservation is different in kind: it is built from an OPERATOR-
// SUPPLIED telemetry export (OpenTelemetry spans, access logs, a queue's
// own delivery metadata) that this codebase never generated and cannot
// vouch for. PRD line 983 states the requirement directly: "Runtime
// records use approved metadata schemas and **reject** fields capable of
// carrying payload values." AC-29 clause 5 restates it as the acceptance
// bar: "no captured payload, prompt, response, record, log message, or
// sensitive value exists in the observation artifact." Both are REJECT
// requirements, not "redact" or "best-effort" requirements — an open-world
// validator that merely checks the fields it recognizes and ignores the
// rest would satisfy neither: any attribute name nobody thought to name in
// advance sails through unexamined, and a telemetry payload field is
// exactly the kind of key nobody names in advance (a caller controls the
// export, not this codebase). A scrub-known-bad DENYLIST has the identical
// failure mode one level down — it fails open on every attribute name
// nobody thought of. So this module allowlists both the top-level record
// shape (`RUNTIME_OBSERVATION_FIELDS`) and the attribute-key vocabulary
// (`RUNTIME_ATTRIBUTE_KEYS`), and rejects anything outside either. A future
// "simplification" that widens either sweep from "reject unknown" to
// "ignore unknown" is a silent AC-29 falsification, not a cleanup — it
// would let an unreviewed payload-shaped field or attribute key pass
// straight through this artifact.
//
// ── Reports, never mutates ─────────────────────────────────────────────
//
// `validateRuntimeObservation`/`validateObservationAttributes` never
// mutate, delete, or scrub their input — they return `{valid, errors}` and
// leave the record untouched (RO/4h). A scrubbing validator would let a
// caller persist the SCRUBBED REMAINDER as though it had been clean all
// along, silently laundering a rejected record into an accepted one one
// call site downstream. Reject-and-report keeps that decision visible to
// the caller, matching PRD line 983's own "reject" wording rather than an
// implied "redact".
//
// ── eventCountBand is a band, not a count ──────────────────────────────
//
// PRD line 971 specifies a "count/frequency band," not a raw number — an
// exact event count is itself a weak information channel (it can leak
// approximate traffic volume/business metrics through an artifact whose
// only job is "this destination was or wasn't observed"). `EVENT_COUNT_BANDS`
// is therefore a closed set of coarse buckets; `validateRuntimeObservation`
// rejects any numeric or free-form value in that field, banded or not.
//
// ── 'ambiguous' is enforced, not just documented ───────────────────────
//
// FR-505 requires that an ambiguous observation (more than one candidate
// node matched) remain a CANDIDATE and never silently merge distinct data
// elements. This module enforces that as a real cross-field rule (RO/6f):
// `matchedNodeIds.length > 1` REQUIRES `matchConfidence === 'ambiguous'` —
// a caller cannot report two candidate nodes at `'high'`/`'medium'`/`'low'`
// confidence, which would read as a confident but silently-arbitrary pick
// between them.
//
// ── OBSERVATION_LAYERS is three-valued on purpose ──────────────────────
//
// PRD line 2098 forbids treating "not observed" as "not occurring" — an
// unobserved flow may simply be outside the telemetry window, not absent
// from the system. `OBSERVATION_LAYERS` therefore keeps
// `not_observed_in_window` (evaluated, genuinely absent from the evidence)
// and `not_evaluated` (no attempt was made at all) as two GENUINELY
// DIFFERENT answers — the same distinction `flow.policyVerdict`'s own
// `not_evaluated` value already draws for a missing `privacy-policy.json`
// (Milestone 2, Sub-project G). Collapsing the two into one "no runtime
// evidence" bucket would silently misrepresent an unevaluated flow as one
// the operator actually checked and found nothing for.
//
// ── Scope: 7b only ──────────────────────────────────────────────────────
//
// This deliverable ships the RUNTIME-OBSERVED half of the Digital Twin
// only. The CONFIG-DECLARED half (7a — inferring an edge from IaC/config
// rather than from executed code) is Milestone 2 Sub-project F2/F3's own
// job (scoping doc §4.0) and is explicitly out of scope here — nothing in
// this module mints a non-code-derived edge or otherwise touches
// `edge.provenance`.
//
// ── Data/artifact layer only ────────────────────────────────────────────
//
// AC-29's clauses are satisfied here at the data/artifact layer alone — no
// UI displays a RuntimeObservation record yet (scoping doc §4.7). A later
// UI increment inherits five properties from this contract it must not
// break: (1) closed-world field/attribute allowlisting, (2) report-not-
// mutate validation, (3) banded (never exact) event counts, (4) enforced
// (never advisory) ambiguity handling, (5) the three-valued observation
// layer. Breaking any of those at the UI layer would reopen exactly the
// gap this module exists to close.

export const RUNTIME_OBSERVATION_VERSION = '1.0.0';

// The 18 allowed top-level keys of a RuntimeObservation record — the
// closed-world sweep in `validateRuntimeObservation` rejects anything
// outside this set and requires everything inside it.
export const RUNTIME_OBSERVATION_FIELDS = Object.freeze([
  'id', 'version', 'adapter', 'source', 'environment', 'windowStart', 'windowEnd',
  'matchedNodeIds', 'matchedEdgeIds', 'matchedFlowIds', 'attributes', 'eventCountBand',
  'firstObservedAt', 'lastObservedAt', 'matchMethod', 'matchConfidence', 'retention', 'importedAt',
]);

// Only one adapter is actually implemented today — an unimplemented
// adapter name must be rejected, not accepted on faith that it will
// someday exist (RO/3b).
export const RUNTIME_OBSERVATION_ADAPTERS = Object.freeze(['native-jsonl']);

// FR-505's own four named metadata families: service/workload identity,
// endpoint/destination identity, protocol/TLS metadata, and schema/
// attribute NAMES already approved for telemetry (never attribute VALUES,
// which is exactly the payload channel AC-29 forbids).
export const RUNTIME_ATTRIBUTE_KEYS = Object.freeze([
  // service/workload identity
  'service.name', 'service.namespace', 'service.version', 'service.instance.id',
  'workload.name', 'workload.kind',
  // endpoint or destination identity
  'destination.host', 'destination.port', 'destination.scheme', 'destination.path', 'destination.service',
  // protocol/TLS metadata
  'network.protocol', 'network.transport', 'tls.version', 'tls.cipher', 'tls.verified',
  // schema/attribute NAMES already approved for telemetry
  'schema.name', 'schema.attributeNames',
]);

// The one attribute key whose value is an array rather than a scalar —
// itself must be a member of RUNTIME_ATTRIBUTE_KEYS.
export const RUNTIME_ARRAY_ATTRIBUTE_KEYS = Object.freeze(['schema.attributeNames']);

export const RUNTIME_ATTRIBUTE_MAX_VALUE_LENGTH = 256;
export const RUNTIME_ATTRIBUTE_MAX_ARRAY_LENGTH = 64;
export const RUNTIME_ATTRIBUTE_MAX_KEYS = 32;

// A count/frequency BAND (PRD line 971) — never a raw number. An exact
// event count is itself a weak information channel.
export const EVENT_COUNT_BANDS = Object.freeze(['1', '2-10', '11-100', '101-1k', '1k+']);

export const RUNTIME_MATCH_METHODS = Object.freeze(['destination_literal', 'store_table', 'queue_topic', 'unmatched']);
export const RUNTIME_MATCH_CONFIDENCE = Object.freeze(['high', 'medium', 'low', 'ambiguous']);

// Three-valued deliberately — see the header comment above for why
// `not_observed_in_window` and `not_evaluated` must never collapse into
// one "no evidence" bucket (PRD line 2098).
export const OBSERVATION_LAYERS = Object.freeze(['runtime_observed', 'not_observed_in_window', 'not_evaluated']);

const _RETENTION_KEYS = ['expiresAt'];

function _isPlainObject(v) {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function _isNonEmptyString(v, maxLen) {
  if (typeof v !== 'string' || v.length === 0) return false;
  if (typeof maxLen === 'number' && v.length > maxLen) return false;
  return true;
}

const _ISO_DATE_TIME_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;

function _isIsoDateTime(v) {
  return typeof v === 'string' && _ISO_DATE_TIME_RE.test(v) && Number.isFinite(Date.parse(v));
}

function _isPrefixedIdArray(v, prefix) {
  return Array.isArray(v) && v.every((x) => typeof x === 'string' && x.startsWith(prefix));
}

/**
 * Closed-world validation of a RuntimeObservation record's `attributes`
 * map (AC-29 clause 5's own core enforcement point). Never throws.
 */
export function validateObservationAttributes(attributes) {
  const errors = [];
  const err = (p, message) => errors.push({ path: p, message });

  if (!_isPlainObject(attributes)) {
    err('$.attributes', 'attributes must be a plain object');
    return { valid: false, errors };
  }

  const keys = Object.keys(attributes);
  if (keys.length > RUNTIME_ATTRIBUTE_MAX_KEYS) {
    err('$.attributes', `attributes may carry at most ${RUNTIME_ATTRIBUTE_MAX_KEYS} keys, got ${keys.length}`);
  }

  for (const [key, value] of Object.entries(attributes)) {
    if (!RUNTIME_ATTRIBUTE_KEYS.includes(key)) {
      err(`$.attributes["${key}"]`, 'unapproved attribute key — RuntimeObservation attributes are closed-world (FR-505): only the approved metadata allowlist is accepted, and an unrecognized key is rejected, never ignored');
      continue; // the value of an unapproved key is not further inspected
    }
    if (RUNTIME_ARRAY_ATTRIBUTE_KEYS.includes(key)) {
      if (!Array.isArray(value) || value.length > RUNTIME_ATTRIBUTE_MAX_ARRAY_LENGTH
        || !value.every((x) => typeof x === 'string' && x.length <= RUNTIME_ATTRIBUTE_MAX_VALUE_LENGTH)) {
        err(`$.attributes["${key}"]`, `must be an array of at most ${RUNTIME_ATTRIBUTE_MAX_ARRAY_LENGTH} strings, each at most ${RUNTIME_ATTRIBUTE_MAX_VALUE_LENGTH} characters`);
      }
      continue;
    }
    const t = typeof value;
    if (t === 'string') {
      if (value.length > RUNTIME_ATTRIBUTE_MAX_VALUE_LENGTH) {
        err(`$.attributes["${key}"]`, `string value exceeds ${RUNTIME_ATTRIBUTE_MAX_VALUE_LENGTH} characters — a long "metadata" value is how a payload arrives disguised`);
      }
    } else if (t === 'number') {
      if (!Number.isFinite(value)) {
        err(`$.attributes["${key}"]`, 'numeric attribute values must be finite');
      }
    } else if (t === 'boolean') {
      // fine
    } else {
      err(`$.attributes["${key}"]`, `attribute value must be a string, number, or boolean scalar, got ${value === null ? 'null' : t}`);
    }
  }

  return { valid: errors.length === 0, errors };
}

/**
 * Closed-world structural validation of a RuntimeObservation record
 * (M5 deliverable #7b, FR-505 §10.10, AC-29 clause 5). Never throws.
 * Reports, never mutates (RO/4h).
 */
export function validateRuntimeObservation(record) {
  const errors = [];
  const err = (p, message) => errors.push({ path: p, message });

  if (!_isPlainObject(record)) {
    err('$', 'RuntimeObservation record must be an object');
    return { valid: false, errors };
  }

  // Closed-world sweep FIRST, before anything else — an unrecognized
  // top-level key is always an error, regardless of whatever else is
  // wrong or right about the record.
  for (const key of Object.keys(record)) {
    if (!RUNTIME_OBSERVATION_FIELDS.includes(key)) {
      err(`$.${key}`, 'unknown field — RuntimeObservation records are closed-world (PRD line 983): only approved metadata fields are accepted, and an unrecognized field is rejected, never ignored');
    }
  }

  // Missing-required sweep — closed-world cuts both ways.
  for (const field of RUNTIME_OBSERVATION_FIELDS) {
    if (!(field in record)) {
      err(`$.${field}`, `${field} is required`);
    }
  }

  // Per-field type/enum checks — each guarded so a malformed field
  // doesn't get double-reported by a cross-field rule below.
  const idOk = _isNonEmptyString(record.id) && record.id.startsWith('observation:');
  if ('id' in record && !idOk) err('$.id', 'id is required and must start with "observation:"');

  if ('version' in record && !_isNonEmptyString(record.version)) err('$.version', 'version is required');

  if ('adapter' in record && !RUNTIME_OBSERVATION_ADAPTERS.includes(record.adapter)) {
    err('$.adapter', `adapter must be one of ${RUNTIME_OBSERVATION_ADAPTERS.join('|')}`);
  }

  if ('source' in record && !_isNonEmptyString(record.source, 512)) {
    err('$.source', 'source is required and must be at most 512 characters');
  }

  if ('environment' in record && !_isNonEmptyString(record.environment, 64)) {
    err('$.environment', 'environment is required and must be at most 64 characters');
  }

  const windowStartOk = 'windowStart' in record && _isIsoDateTime(record.windowStart);
  if ('windowStart' in record && !windowStartOk) err('$.windowStart', 'windowStart must be a parseable ISO-8601 date-time');

  const windowEndOk = 'windowEnd' in record && _isIsoDateTime(record.windowEnd);
  if ('windowEnd' in record && !windowEndOk) err('$.windowEnd', 'windowEnd must be a parseable ISO-8601 date-time');

  const matchedNodeIdsOk = 'matchedNodeIds' in record && _isPrefixedIdArray(record.matchedNodeIds, 'node:');
  if ('matchedNodeIds' in record && !matchedNodeIdsOk) {
    err('$.matchedNodeIds', 'matchedNodeIds must be an array of node:-prefixed ids');
  }

  const matchedEdgeIdsOk = 'matchedEdgeIds' in record && _isPrefixedIdArray(record.matchedEdgeIds, 'edge:');
  if ('matchedEdgeIds' in record && !matchedEdgeIdsOk) {
    err('$.matchedEdgeIds', 'matchedEdgeIds must be an array of edge:-prefixed ids');
  }

  const matchedFlowIdsOk = 'matchedFlowIds' in record && _isPrefixedIdArray(record.matchedFlowIds, 'flow:');
  if ('matchedFlowIds' in record && !matchedFlowIdsOk) {
    err('$.matchedFlowIds', 'matchedFlowIds must be an array of flow:-prefixed ids');
  }

  if ('attributes' in record) {
    const attrResult = validateObservationAttributes(record.attributes);
    errors.push(...attrResult.errors);
  }

  const eventCountBandOk = 'eventCountBand' in record && EVENT_COUNT_BANDS.includes(record.eventCountBand);
  if ('eventCountBand' in record && !eventCountBandOk) {
    err('$.eventCountBand', `eventCountBand must be a band (${EVENT_COUNT_BANDS.join('|')}) — an exact count is itself an information channel`);
  }

  const firstObservedAtOk = 'firstObservedAt' in record && _isIsoDateTime(record.firstObservedAt);
  if ('firstObservedAt' in record && !firstObservedAtOk) err('$.firstObservedAt', 'firstObservedAt must be a parseable ISO-8601 date-time');

  const lastObservedAtOk = 'lastObservedAt' in record && _isIsoDateTime(record.lastObservedAt);
  if ('lastObservedAt' in record && !lastObservedAtOk) err('$.lastObservedAt', 'lastObservedAt must be a parseable ISO-8601 date-time');

  const matchMethodOk = 'matchMethod' in record && RUNTIME_MATCH_METHODS.includes(record.matchMethod);
  if ('matchMethod' in record && !matchMethodOk) {
    err('$.matchMethod', `matchMethod must be one of ${RUNTIME_MATCH_METHODS.join('|')}`);
  }

  const matchConfidenceOk = 'matchConfidence' in record && RUNTIME_MATCH_CONFIDENCE.includes(record.matchConfidence);
  if ('matchConfidence' in record && !matchConfidenceOk) {
    err('$.matchConfidence', `matchConfidence must be one of ${RUNTIME_MATCH_CONFIDENCE.join('|')}`);
  }

  // retention: closed-key object with exactly `expiresAt`, which is
  // either null or a parseable ISO-8601 date-time.
  if ('retention' in record) {
    const retention = record.retention;
    if (!_isPlainObject(retention)) {
      err('$.retention', 'retention must be an object with exactly the key expiresAt');
    } else {
      for (const key of Object.keys(retention)) {
        if (!_RETENTION_KEYS.includes(key)) {
          err(`$.retention.${key}`, 'unknown field — retention is closed-world: only expiresAt is accepted');
        }
      }
      const expiresAt = retention.expiresAt;
      const expiresAtOk = expiresAt === null || _isIsoDateTime(expiresAt);
      if (!expiresAtOk) {
        err('$.retention.expiresAt', 'retention.expiresAt must be null or a parseable ISO-8601 date-time');
      }
    }
  }

  if ('importedAt' in record && !_isIsoDateTime(record.importedAt)) {
    err('$.importedAt', 'importedAt must be a parseable ISO-8601 date-time');
  }

  // ── Cross-field rules — each guarded so it only fires when both
  //    operands are already well-formed (never cascade a window-ordering
  //    error off a malformed date). ──────────────────────────────────

  if (windowStartOk && windowEndOk) {
    if (Date.parse(record.windowStart) > Date.parse(record.windowEnd)) {
      err('$.windowEnd', 'windowEnd must not be before windowStart');
    }
  }

  if (firstObservedAtOk && lastObservedAtOk) {
    if (Date.parse(record.firstObservedAt) > Date.parse(record.lastObservedAt)) {
      err('$.lastObservedAt', 'lastObservedAt must not be before firstObservedAt');
    }
  }

  if (firstObservedAtOk && windowStartOk) {
    if (Date.parse(record.firstObservedAt) < Date.parse(record.windowStart)) {
      err('$.firstObservedAt', 'firstObservedAt must fall on or after windowStart');
    }
  }

  if (lastObservedAtOk && windowEndOk) {
    if (Date.parse(record.lastObservedAt) > Date.parse(record.windowEnd)) {
      err('$.lastObservedAt', 'lastObservedAt must fall on or before windowEnd');
    }
  }

  if (matchMethodOk && matchedNodeIdsOk && matchedEdgeIdsOk && matchedFlowIdsOk) {
    const allEmpty = record.matchedNodeIds.length === 0 && record.matchedEdgeIds.length === 0
      && record.matchedFlowIds.length === 0;
    if (record.matchMethod === 'unmatched') {
      if (!allEmpty) {
        err('$.matchMethod', 'matchMethod "unmatched" requires every matched*Ids array to be empty — a matched id contradicts an "unmatched" record');
      }
    } else if (record.matchedNodeIds.length === 0) {
      err('$.matchedNodeIds', 'a non-"unmatched" matchMethod requires at least one matched node id');
    }
  }

  // Deliberately scoped to matchedNodeIds only — edges and flows derive
  // from a matched node, so several of them is normal and not itself an
  // ambiguity; a rule over the union of all three arrays would fire on
  // every ordinary match (a node with 2 edges and 3 flows, say).
  if (matchedNodeIdsOk && matchConfidenceOk && record.matchedNodeIds.length > 1
    && record.matchConfidence !== 'ambiguous') {
    err('$.matchConfidence', 'more than one matched node requires matchConfidence "ambiguous" — an ambiguous observation must remain a candidate and never silently merge data elements (FR-505)');
  }

  return { valid: errors.length === 0, errors };
}
