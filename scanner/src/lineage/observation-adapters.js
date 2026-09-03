// observation-adapters.js — the RuntimeObservation ADAPTER interface, plus
// the one shipped implementation (`native-jsonl`) (M5 deliverable #7,
// "Runtime-Corroborated Digital Twin" — the runtime-observed half only,
// "7b"; "7a", config-declared edges, is out of scope for this whole
// sub-project — see the scoping doc's §4.0). FR-505, AC-29. Pure by
// contract: zero imports (mirrors `runtime-observation.js`'s/
// `observation-correlation.js`'s/`flow-grade.js`'s own precedent, one step
// stricter even than `observation-correlation.js`'s single-file import
// list — see AD/6a), no fs, no I/O, never throws.
//
// ── Why only ONE adapter ships here ─────────────────────────────────────
//
// FR-505 itself names an open-ended adapter list: "beginning with approved
// OpenTelemetry traces/service graphs, gateway/mesh metadata, cloud flow
// metadata, and application-provided schema-safe events." The scoping
// doc's §4.3 ruling is to ship the INTERFACE plus a native, operator-
// authored JSONL adapter first, and defer OTLP to a second increment —
// not because OTLP is unimportant, but because an OTLP `resourceSpans`
// document carries an unbounded attribute surface (`http.url` with a live
// query string, `db.statement`, `messaging.message.payload`, arbitrary
// `gen_ai.*` prompt/completion attributes under active, ongoing extension
// by the OpenTelemetry semantic-conventions project). Mapping that surface
// safely means writing and defending an allowlist against an adversarial,
// EVOLVING external vocabulary — real, separately-scoped work with its
// own review, not something to bundle into the increment that also
// invents the RuntimeObservation contract (Task 1), the correlation match
// ladder (Task 2), and the import-keyed store (Task 4). This module exists
// so THAT increment is "write a second implementation of an
// already-proven interface," not "invent the interface and the mapping at
// the same time."
//
// ── Why external evidence arrives as a FILE, never live ingestion ──────
//
// FR-505's own no-egress rule, the root `CLAUDE.md`'s "no runtime cloud
// calls" convention, and `posture/runtime-correlation.js`'s own already-
// proven offline-file contract (an operator-supplied eBPF trace JSONL,
// read from disk, never pulled from a live collector by this codebase)
// all point the same direction: this module takes a TEXT STRING an
// operator has already exported and already has on disk, and returns
// drafts — it has no fetch, no socket, no fs call of any kind (AD/6a pins
// this structurally, not just by convention). The CLI that will eventually
// call this (a future task) is what reads the file; this module never
// does.
//
// ── Why the wire key set is CLOSED, exactly like the record it feeds ───
//
// `runtime-observation.js`'s own header explains at length why a
// RuntimeObservation is closed-world rather than open-world: it is built
// from operator-supplied telemetry this codebase never generated and
// cannot vouch for, and PRD line 983's own "reject fields capable of
// carrying payload values" requirement is a REJECT requirement, not a
// redact-and-hope one. That reasoning applies one layer further out, at
// the WIRE itself: `NATIVE_JSONL_RECORD_KEYS` is a closed allowlist of the
// only top-level JSON keys a native-JSONL record may carry, and any other
// top-level key — an attacker's `prompt`, an operator's well-meaning
// `note`, or (the smuggling attempt nobody would think to test on their
// own) a pre-declared `matchedNodeIds`/`matchConfidence` — is rejected,
// never ignored (AD/4c). `id`/`matchedNodeIds`/`matchedEdgeIds`/
// `matchedFlowIds`/`matchMethod`/`matchConfidence` are refused from the
// wire for a reason specific to THIS module: those six fields are
// minted/derived downstream (an id at import time, a match at correlation
// time) — if the wire could supply them directly, a compromised exporter,
// or an operator simply copy-pasting an already-matched record from one
// import into a hand-edited new one, could dictate what the graph BELIEVES
// was observed, bypassing the match ladder (`observation-correlation.js`,
// Task 2) entirely. None of the six are members of `NATIVE_JSONL_RECORD_KEYS`,
// so the SAME closed-world sweep that rejects an unrecognized field also
// rejects every one of these — there is no separate check to keep in sync
// (AD/4b, error 4).
//
// ── The two-layer rejection split (this module vs. `validateRuntimeObservation`) ──
//
// This module enforces the WIRE SHAPE only: `attributes` must be a plain
// object whose every value is a scalar (string/number/boolean) or an
// array of strings, no top-level key outside `NATIVE_JSONL_RECORD_KEYS`,
// and `eventCountBand`/`firstObservedAt`/`lastObservedAt` must each be a
// non-empty string. It does NOT validate WHICH attribute keys are
// approved — `validateRuntimeObservation` (Task 1, `runtime-observation.js`)
// is the single authority on that allowlist, and this module never
// duplicates it (a duplicated allowlist is exactly the kind of thing that
// silently drifts). Against the payload fixture, this means the adapter
// itself catches only 2 of the fixture's 4 smuggling attempts (line 3's
// top-level `prompt`, line 4's `matchedNodeIds`/`matchConfidence`) — the
// other two (line 1's `http.url` attribute key, line 2's `db.statement`
// attribute key) are structurally fine at the wire layer and are caught
// one layer up, by `validateRuntimeObservation`, at IMPORT time
// (`CLI/import-4`, a future task's own test — not a hole in this one).
// Any adapter error means the whole file yields nothing usable: this
// module always returns whatever drafts it produced regardless of
// `errors.length`, but the IMPORT command (a future task) refuses the
// file WHOLE the moment `errors.length > 0` — that refuse-the-whole-import
// behavior is that future task's own to prove, not this module's.
//
// ── The native-JSONL wire format, worked example ────────────────────────
//
// One JSON object per line (no comments — JSONL admits none), each with
// up to 5 top-level keys (`NATIVE_JSONL_RECORD_KEYS`):
//
//   {"environment":"production","attributes":{"destination.host":"api.stripe.com","destination.scheme":"https","tls.version":"1.3"},"eventCountBand":"101-1k","firstObservedAt":"2026-08-02T10:00:00.000Z","lastObservedAt":"2026-08-30T10:00:00.000Z"}
//
// `environment` is optional per line — when omitted, the record inherits
// the default environment of the surrounding call, `context.environment`
// (supplied by the CALLER, never by the file). `attributes` keys must be
// drawn from `RUNTIME_ATTRIBUTE_KEYS` (`runtime-observation.js`) — this
// module does not check that, but a key outside that list will be
// rejected one layer up, at import time. `eventCountBand` is a BAND
// (`RUNTIME_OBSERVATION_VERSION`'s sibling `EVENT_COUNT_BANDS`, e.g.
// `'1'`/`'2-10'`/`'11-100'`/`'101-1k'`/`'1k+'`), never a raw count.
// `firstObservedAt`/`lastObservedAt` are ISO-8601 date-times.
//
// ── `version` is caller-supplied, not read from `runtime-observation.js` ──
//
// This is precisely why this module has NO import at all, not even of
// `runtime-observation.js`'s own `RUNTIME_OBSERVATION_VERSION` constant:
// the CLI (a future task) passes that value in as `context.version`. A
// zero-import module can never itself drift from the contract it feeds —
// there is no cached/stale constant here to go stale.

// The 5 allowed top-level keys of a native-JSONL wire record. Any other
// top-level key — including every one of the six RuntimeObservation
// fields that are minted/derived downstream (`id`, `matchedNodeIds`,
// `matchedEdgeIds`, `matchedFlowIds`, `matchMethod`, `matchConfidence`) —
// is rejected by the closed-world sweep below, never ignored.
export const NATIVE_JSONL_RECORD_KEYS = Object.freeze([
  'environment', 'attributes', 'eventCountBand', 'firstObservedAt', 'lastObservedAt',
]);

function _isPlainObject(v) {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function _isNonEmptyString(v) {
  return typeof v === 'string' && v.length > 0;
}

function _isScalar(v) {
  const t = typeof v;
  return t === 'string' || t === 'number' || t === 'boolean';
}

// The WIRE shape only — never which attribute keys are approved. A value
// must be a scalar, or an array of strings (mirroring
// `RUNTIME_ARRAY_ATTRIBUTE_KEYS`'s own shape one layer up, without this
// module knowing which specific key that applies to).
function _attributesShapeOk(attrs) {
  if (!_isPlainObject(attrs)) return false;
  for (const value of Object.values(attrs)) {
    if (Array.isArray(value)) {
      if (!value.every((x) => typeof x === 'string')) return false;
    } else if (!_isScalar(value)) {
      return false;
    }
  }
  return true;
}

/**
 * Parses native-JSONL runtime-observation text into RuntimeObservation
 * DRAFTS — every field a RuntimeObservation record needs EXCEPT `id`,
 * `matchedNodeIds`, `matchedEdgeIds`, `matchedFlowIds`, `matchMethod`,
 * `matchConfidence`, which are minted/derived downstream and can never be
 * supplied by the wire. `context` is
 * `{version, adapter, source, environment, windowStart, windowEnd, importedAt, retention}`
 * — every draft carries these verbatim, EXCEPT `environment`, which a
 * per-line `environment` key overrides.
 *
 * Never throws. `text` must be a string and `context` a plain object, or
 * this returns `{drafts: [], errors: [{line: 0, message: '...'}]}`
 * immediately. Blank lines (and the trailing newline JSONL files
 * ordinarily end with) are skipped silently — never reported as errors.
 * A malformed line (invalid JSON, wrong top-level shape, an unapproved
 * top-level key, a malformed `attributes`/`eventCountBand`/
 * `firstObservedAt`/`lastObservedAt`) yields exactly ONE `{line, message}`
 * error for that line (`line` 1-based) and is skipped — every OTHER line
 * still parses, so an operator sees every problem in one pass rather than
 * stopping at the first.
 */
export function parseNativeJsonlObservations(text, context) {
  if (typeof text !== 'string' || !_isPlainObject(context)) {
    return {
      drafts: [],
      errors: [{ line: 0, message: 'parseNativeJsonlObservations requires a string text and a plain-object context' }],
    };
  }

  const {
    version, adapter, source, environment: defaultEnvironment,
    windowStart, windowEnd, importedAt, retention,
  } = context;

  const drafts = [];
  const errors = [];

  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const rawLine = lines[i];
    if (rawLine.trim().length === 0) continue; // blank line, or the trailing newline's own empty tail
    const line = i + 1;

    let record;
    try {
      record = JSON.parse(rawLine);
    } catch {
      // M2 (final review): every OTHER rejection path in this module is
      // key-only/value-free by design — V8's own JSON.parse error message
      // quotes a snippet of the offending input (`e.message`), which would
      // make this the sole value-echo channel in the whole command. Name
      // only the line number, never the parse error's own text.
      errors.push({ line, message: `invalid JSON on line ${line}` });
      continue;
    }

    if (!_isPlainObject(record)) {
      const gotType = record === null ? 'null' : Array.isArray(record) ? 'array' : typeof record;
      errors.push({ line, message: `record must be a JSON object, got ${gotType}` });
      continue;
    }

    const unknownKeys = Object.keys(record).filter((k) => !NATIVE_JSONL_RECORD_KEYS.includes(k));
    if (unknownKeys.length > 0) {
      errors.push({
        line,
        message: `unknown field(s) not permitted on the wire: ${unknownKeys.join(', ')} — native-JSONL records are closed-world (mirroring RuntimeObservation's own closed-world rule): only ${NATIVE_JSONL_RECORD_KEYS.join('/')} are accepted, and this rejects every one of id/matchedNodeIds/matchedEdgeIds/matchedFlowIds/matchMethod/matchConfidence too, since none are members of that allowlist`,
      });
      continue;
    }

    if (!_attributesShapeOk(record.attributes)) {
      errors.push({
        line,
        message: 'attributes must be a plain object whose every value is a scalar (string/number/boolean) or an array of strings',
      });
      continue;
    }

    if (!_isNonEmptyString(record.eventCountBand)
      || !_isNonEmptyString(record.firstObservedAt)
      || !_isNonEmptyString(record.lastObservedAt)) {
      errors.push({
        line,
        message: 'eventCountBand, firstObservedAt, and lastObservedAt must each be present and a non-empty string',
      });
      continue;
    }

    drafts.push({
      version,
      adapter,
      source,
      environment: 'environment' in record ? record.environment : defaultEnvironment,
      windowStart,
      windowEnd,
      attributes: record.attributes,
      eventCountBand: record.eventCountBand,
      firstObservedAt: record.firstObservedAt,
      lastObservedAt: record.lastObservedAt,
      retention,
      importedAt,
    });
  }

  return { drafts, errors };
}

// The adapter registry — a frozen, module-level lookup. `adapterFor`
// returns `null` for anything unknown, NEVER a default: an unimplemented
// adapter name (e.g. `'otlp'`, deferred per the scoping doc's §4.3 ruling)
// must be rejected outright, not silently accepted on faith that it will
// someday exist.
const _ADAPTERS = Object.freeze({
  'native-jsonl': Object.freeze({ name: 'native-jsonl', parse: parseNativeJsonlObservations }),
});

/**
 * `adapterFor(name) -> {name, parse} | null` — the registry lookup.
 * `parse` has the `(text, context) -> {drafts, errors}` signature of
 * `parseNativeJsonlObservations` above.
 */
export function adapterFor(name) {
  if (typeof name !== 'string') return null;
  return Object.prototype.hasOwnProperty.call(_ADAPTERS, name) ? _ADAPTERS[name] : null;
}
