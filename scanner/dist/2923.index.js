export const id = 2923;
export const ids = [2923];
export const modules = {

/***/ 12923:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   adapterFor: () => (/* binding */ adapterFor)
/* harmony export */ });
/* unused harmony exports NATIVE_JSONL_RECORD_KEYS, parseNativeJsonlObservations, parseOtelJsonObservations, parseEnvoyAccessLogObservations, parseK8sAuditLogObservations, parseHttpAccessLogObservations */
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
const NATIVE_JSONL_RECORD_KEYS = Object.freeze([
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
function parseNativeJsonlObservations(text, context) {
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

// ── The four PRD "Runtime-Corroborated Security Twin" adapters ─────────
//
// Each of the four parsers below follows the identical contract the
// native-jsonl adapter above already established: pure (zero imports, no
// fs, never throws), `(text, context) -> {drafts, errors}`, one
// `{line, message}` error per malformed line (never a value echo), every
// OTHER line still parses. Each produces drafts carrying ONLY attribute
// keys already on `RUNTIME_ATTRIBUTE_KEYS` (`runtime-observation.js`) —
// none of these parsers imports that file (this module stays zero-import
// by contract), so an attribute key typo here is caught one layer up, at
// import time, exactly like the native-jsonl adapter's own documented
// two-layer split. Each adapter deliberately DROPS every field of its
// source format with no safe, approved destination — a raw URL path/query
// string, a user agent, a client IP, a trace/span id, a username/identity
// — rather than inventing a new attribute key to carry it (PRD "Privacy
// Protection" P0-7: schema/field classification only, never a captured
// value). What each adapter keeps and drops is documented at its own
// definition.

const _IDENTIFIER_ATTR_RE = /^[A-Za-z0-9._:-]{1,128}$/;

// Only ever WRITES a value that already looks like an approved identifier
// — never force-sanitizes an unsafe value into a misleadingly different
// one. Returns `null` (meaning "drop this attribute") for anything that
// doesn't already look safe, rather than guessing.
function _safeIdentifierOrNull(v) {
  if (typeof v !== 'string' || v.length === 0) return null;
  return _IDENTIFIER_ATTR_RE.test(v) ? v : null;
}

// `"host:port"` -> `{host, port}` (port `null` when absent/unparseable).
// Never a full URL parse — this shape (Envoy's `upstream_host`, a bare
// `host:port` pair) has no scheme/path to confuse it with.
function _splitHostPort(v) {
  if (typeof v !== 'string' || v.length === 0) return { host: null, port: null };
  const i = v.lastIndexOf(':');
  if (i === -1) return { host: _safeIdentifierOrNull(v), port: null };
  const host = v.slice(0, i);
  const portStr = v.slice(i + 1);
  const port = /^[0-9]{1,5}$/.test(portStr) ? Number(portStr) : null;
  return { host: _safeIdentifierOrNull(host), port };
}

// Identity is recorded ONLY as a keyed-hash token, and only when the importer supplied the tokenizer (`context.tokenizeIdentity`).
// This module stays zero-import and holds no key: with no tokenizer, identity is dropped, never stored raw and never hashed without a
// key (an unkeyed hash of a username is reversible by guessing). A raw value that is not a plausible identity string is dropped too.
function _identityToken(context, raw) {
  if (typeof context?.tokenizeIdentity !== 'function') return null;
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > 256 || /[\u0000-\u001f]/.test(raw)) return null;
  const t = context.tokenizeIdentity(raw);
  return typeof t === 'string' && /^idt_[0-9a-f]{16}$/.test(t) ? t : null;
}

function _draftBase(context, environmentOverride) {
  const { version, adapter, source, environment, windowStart, windowEnd, importedAt, retention } = context;
  return {
    version, adapter, source,
    environment: environmentOverride !== undefined ? environmentOverride : environment,
    windowStart, windowEnd, retention, importedAt,
  };
}

/**
 * OpenTelemetry JSON trace export (the standard OTLP/JSON `resourceSpans`
 * document — a SINGLE JSON object, never JSONL; this is the format
 * `otlptracehttp` with `OTEL_EXPORTER_OTLP_TRACES_PROTOCOL=http/json`
 * writes). One draft per span. Reads only well-known OpenTelemetry
 * semantic-convention attribute keys — `server.address`/`net.peer.name`,
 * `server.port`/`net.peer.port`, `url.scheme`/`http.scheme`,
 * `network.protocol.name`, `db.system`/`db.name`,
 * `messaging.destination.name` — mapped onto the approved
 * `destination.*`/`network.protocol`/`schema.name` keys; `resource`-level
 * `service.name` is carried as `service.name`. Every other span
 * attribute (`http.url`'s full query string, `http.request.header.*`,
 * `gen_ai.*` prompt/completion content, trace/span ids themselves) is
 * dropped — none has a safe, approved destination. `eventCountBand` is
 * always `'1'`: a single exported span is a single observed event, never
 * an aggregate count OTel itself does not report.
 */
function parseOtelJsonObservations(text, context) {
  if (typeof text !== 'string' || !_isPlainObject(context)) {
    return { drafts: [], errors: [{ line: 0, message: 'parseOtelJsonObservations requires a string text and a plain-object context' }] };
  }

  let doc;
  try {
    doc = JSON.parse(text);
  } catch {
    return { drafts: [], errors: [{ line: 0, message: 'invalid JSON: expected one OTLP/JSON resourceSpans document' }] };
  }
  if (!_isPlainObject(doc) || !Array.isArray(doc.resourceSpans)) {
    return { drafts: [], errors: [{ line: 0, message: 'expected a JSON object with a top-level "resourceSpans" array (the OTLP/JSON export shape)' }] };
  }

  const _attrMap = (attrs) => {
    const m = {};
    if (!Array.isArray(attrs)) return m;
    for (const a of attrs) {
      if (!_isPlainObject(a) || typeof a.key !== 'string' || !_isPlainObject(a.value)) continue;
      const v = a.value;
      if (typeof v.stringValue === 'string') m[a.key] = v.stringValue;
      else if (typeof v.intValue === 'number' || typeof v.intValue === 'string') m[a.key] = String(v.intValue);
      else if (typeof v.boolValue === 'boolean') m[a.key] = v.boolValue;
    }
    return m;
  };

  // Nanoseconds-since-epoch (OTLP's own wire unit) as a string or number
  // -> ISO-8601. Returns null (never a fabricated "now") when absent or
  // unparseable, letting the caller fall back to the import window.
  const _isoFromUnixNano = (v) => {
    if (v === undefined || v === null) return null;
    const n = typeof v === 'string' ? Number(v) : v;
    if (!Number.isFinite(n) || n <= 0) return null;
    const ms = Math.round(n / 1e6);
    const d = new Date(ms);
    return Number.isFinite(d.getTime()) ? d.toISOString() : null;
  };

  const drafts = [];
  for (const rs of doc.resourceSpans) {
    if (!_isPlainObject(rs)) continue;
    const resourceAttrs = _attrMap(rs.resource?.attributes);
    const serviceName = _safeIdentifierOrNull(resourceAttrs['service.name']);

    for (const ss of Array.isArray(rs.scopeSpans) ? rs.scopeSpans : []) {
      if (!_isPlainObject(ss)) continue;
      for (const span of Array.isArray(ss.spans) ? ss.spans : []) {
        if (!_isPlainObject(span)) continue;
        const a = _attrMap(span.attributes);

        const attributes = {};
        if (serviceName) attributes['service.name'] = serviceName;
        const host = _safeIdentifierOrNull(a['server.address'] ?? a['net.peer.name']);
        if (host) attributes['destination.host'] = host;
        const portRaw = a['server.port'] ?? a['net.peer.port'];
        const port = /^[0-9]{1,5}$/.test(String(portRaw ?? '')) ? Number(portRaw) : null;
        if (port !== null) attributes['destination.port'] = port;
        const scheme = _safeIdentifierOrNull(a['url.scheme'] ?? a['http.scheme']);
        if (scheme) attributes['destination.scheme'] = scheme;
        const protocol = _safeIdentifierOrNull(a['network.protocol.name']);
        if (protocol) attributes['network.protocol'] = protocol;
        const storeService = _safeIdentifierOrNull(a['db.system'] ?? a['db.name'] ?? a['messaging.destination.name']);
        if (storeService) attributes['destination.service'] = storeService;

        if (Object.keys(attributes).length === 0) continue; // nothing safe to report for this span
        { const idt = _identityToken(context, a['enduser.id']); if (idt) attributes['identity.token'] = idt; }

        const at = _isoFromUnixNano(span.startTimeUnixNano) ?? context.windowStart;
        drafts.push({
          ..._draftBase(context),
          attributes,
          eventCountBand: '1',
          firstObservedAt: at,
          lastObservedAt: _isoFromUnixNano(span.endTimeUnixNano) ?? at,
        });
      }
    }
  }

  return { drafts, errors: [] };
}

/**
 * Envoy's default JSON access log (`json_format` logging, one JSON
 * object per line). Reads `upstream_host` (split into
 * `destination.host`/`destination.port`), `upstream_cluster` (as
 * `destination.service`), `protocol` (normalized — Envoy writes
 * `"HTTP/1.1"`, which contains `/` and is not an approved identifier
 * shape; lowercased and `/` stripped, e.g. `"http1.1"`), and
 * `response_flags` (`'-'`/empty means no flag, i.e. allowed; `"UAEX"`, the
 * external authorization service denying the request, is `'denied'` via
 * `network.securityDecision`; any other flag, such as an upstream failure or
 * a missing route, is an operational outcome and carries no decision). `start_time`/`end_time` (or
 * `start_time` alone, with `duration` in milliseconds added) feed
 * `firstObservedAt`/`lastObservedAt`. Everything else — client address,
 * request path/query, user agent, request id, response code's own exact
 * value — is dropped.
 */
function parseEnvoyAccessLogObservations(text, context) {
  if (typeof text !== 'string' || !_isPlainObject(context)) {
    return { drafts: [], errors: [{ line: 0, message: 'parseEnvoyAccessLogObservations requires a string text and a plain-object context' }] };
  }

  const drafts = [];
  const errors = [];
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const rawLine = lines[i];
    if (rawLine.trim().length === 0) continue;
    const line = i + 1;

    let record;
    try {
      record = JSON.parse(rawLine);
    } catch {
      errors.push({ line, message: `invalid JSON on line ${line}` });
      continue;
    }
    if (!_isPlainObject(record)) {
      errors.push({ line, message: `record on line ${line} must be a JSON object` });
      continue;
    }

    const { host, port } = _splitHostPort(record.upstream_host);
    const cluster = _safeIdentifierOrNull(record.upstream_cluster);
    const protocol = typeof record.protocol === 'string'
      ? _safeIdentifierOrNull(record.protocol.toLowerCase().replace(/\//g, ''))
      : null;

    const attributes = {};
    if (host) attributes['destination.host'] = host;
    if (port !== null) attributes['destination.port'] = port;
    if (cluster) attributes['destination.service'] = cluster;
    if (protocol) attributes['network.protocol'] = protocol;
    if (typeof record.response_flags === 'string') {
      // Only a flag that records an authorization decision is a security decision. UAEX is the external authorization service
      // denying the request. Every other flag (UF upstream connection failure, NR no route, UT timeout, DC client disconnect) is
      // an operational outcome, and calling it "denied" would invent a denial, so those make no claim either way.
      const flags = record.response_flags.trim();
      const tokens = flags.split(',').map((t) => t.trim()).filter(Boolean);
      if (flags.length === 0 || flags === '-') attributes['network.securityDecision'] = 'allowed';
      else if (tokens.includes('UAEX')) attributes['network.securityDecision'] = 'denied';
    }

    if (Object.keys(attributes).length === 0) continue; // nothing safe/present to report for this line

    const startIso = typeof record.start_time === 'string' && Number.isFinite(Date.parse(record.start_time))
      ? record.start_time : context.windowStart;
    let endIso = typeof record.end_time === 'string' && Number.isFinite(Date.parse(record.end_time))
      ? record.end_time : null;
    if (endIso === null && typeof record.duration === 'number' && Number.isFinite(record.duration)) {
      endIso = new Date(Date.parse(startIso) + record.duration).toISOString();
    }

    drafts.push({
      ..._draftBase(context),
      attributes,
      eventCountBand: '1',
      firstObservedAt: startIso,
      lastObservedAt: endIso ?? startIso,
    });
  }

  return { drafts, errors };
}

/**
 * Kubernetes `audit.k8s.io` audit-event JSONL (one event object per
 * line — the default `webhook`/file backend format). Reads `objectRef`
 * (`namespace` + `resource`, joined as `"<namespace>:<resource>"` into
 * `destination.service` — never `objectRef.name`, which is frequently a
 * user-chosen, potentially sensitive resource name) and
 * `responseStatus.code` (mapped to `network.securityDecision`: `< 400`
 * is `'allowed'`, `401`/`403` is `'denied'`, anything else carries no
 * decision: a not-found or a conflict is not an authorization outcome). `requestReceivedTimestamp`/
 * `stageTimestamp` feed the observed-at window. **`user.username` and
 * every request/response body field are deliberately never read** — a
 * K8s audit event's `user` block is exactly the "authenticated identity"
 * PRD 2 names, and `runtime-observation.js`'s own contract has no
 * approved field for it (a deliberate, disclosed scope boundary — see
 * this PRD's implementation-status doc).
 */
function parseK8sAuditLogObservations(text, context) {
  if (typeof text !== 'string' || !_isPlainObject(context)) {
    return { drafts: [], errors: [{ line: 0, message: 'parseK8sAuditLogObservations requires a string text and a plain-object context' }] };
  }

  const drafts = [];
  const errors = [];
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const rawLine = lines[i];
    if (rawLine.trim().length === 0) continue;
    const line = i + 1;

    let record;
    try {
      record = JSON.parse(rawLine);
    } catch {
      errors.push({ line, message: `invalid JSON on line ${line}` });
      continue;
    }
    if (!_isPlainObject(record)) {
      errors.push({ line, message: `record on line ${line} must be a JSON object` });
      continue;
    }

    const objectRef = _isPlainObject(record.objectRef) ? record.objectRef : {};
    const namespace = _safeIdentifierOrNull(objectRef.namespace);
    const resource = _safeIdentifierOrNull(objectRef.resource);
    const code = record.responseStatus && typeof record.responseStatus === 'object' ? record.responseStatus.code : undefined;

    const attributes = {};
    if (namespace && resource) attributes['destination.service'] = `${namespace}:${resource}`;
    else if (resource) attributes['destination.service'] = resource;
    if (typeof code === 'number' && Number.isFinite(code)) {
      // 401 and 403 are the authentication and authorization outcomes. Any other client or server error (404 not found, 409 conflict,
      // 422 invalid, 5xx) is an operational outcome and makes no claim, the same rule as the proxy adapters.
      if (code < 400) attributes['network.securityDecision'] = 'allowed';
      else if (code === 401 || code === 403) attributes['network.securityDecision'] = 'denied';
    }

    if (Object.keys(attributes).length === 0) continue;
    { const idt = _identityToken(context, _isPlainObject(record.user) ? record.user.username : undefined); if (idt) attributes['identity.token'] = idt; }

    const observedAt = typeof record.requestReceivedTimestamp === 'string' && Number.isFinite(Date.parse(record.requestReceivedTimestamp))
      ? record.requestReceivedTimestamp
      : (typeof record.stageTimestamp === 'string' && Number.isFinite(Date.parse(record.stageTimestamp)) ? record.stageTimestamp : context.windowStart);

    drafts.push({
      ..._draftBase(context),
      attributes,
      eventCountBand: '1',
      firstObservedAt: observedAt,
      lastObservedAt: observedAt,
    });
  }

  return { drafts, errors };
}

/**
 * A generic JSON-lines HTTP access log (one JSON object per line — the
 * shape a structured reverse proxy or load-balancer access log normalizes
 * to; deliberately not an Apache/Nginx TEXT combined-log parser, which
 * would need its own separate, much larger format-string handling).
 * Reads `host`/`destination_host` -> `destination.host`,
 * `upstream`/`upstream_service` -> `destination.service`, `scheme` ->
 * `destination.scheme`. `timestamp` (or `time`) feeds the observed-at
 * window. Request path/query, client IP, user agent, status code's own
 * value, and every header are dropped.
 */
function parseHttpAccessLogObservations(text, context) {
  if (typeof text !== 'string' || !_isPlainObject(context)) {
    return { drafts: [], errors: [{ line: 0, message: 'parseHttpAccessLogObservations requires a string text and a plain-object context' }] };
  }

  const drafts = [];
  const errors = [];
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const rawLine = lines[i];
    if (rawLine.trim().length === 0) continue;
    const line = i + 1;

    let record;
    try {
      record = JSON.parse(rawLine);
    } catch {
      errors.push({ line, message: `invalid JSON on line ${line}` });
      continue;
    }
    if (!_isPlainObject(record)) {
      errors.push({ line, message: `record on line ${line} must be a JSON object` });
      continue;
    }

    const host = _safeIdentifierOrNull(record.host ?? record.destination_host);
    const upstream = _safeIdentifierOrNull(record.upstream ?? record.upstream_service);
    const scheme = _safeIdentifierOrNull(record.scheme);

    const attributes = {};
    if (host) attributes['destination.host'] = host;
    if (upstream) attributes['destination.service'] = upstream;
    if (scheme) attributes['destination.scheme'] = scheme;

    if (Object.keys(attributes).length === 0) continue;
    { const idt = _identityToken(context, record.user ?? record.remote_user ?? record.authenticated_user); if (idt) attributes['identity.token'] = idt; }

    const ts = record.timestamp ?? record.time;
    const observedAt = typeof ts === 'string' && Number.isFinite(Date.parse(ts)) ? ts : context.windowStart;

    drafts.push({
      ..._draftBase(context),
      attributes,
      eventCountBand: '1',
      firstObservedAt: observedAt,
      lastObservedAt: observedAt,
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
  'otel-json': Object.freeze({ name: 'otel-json', parse: parseOtelJsonObservations }),
  'envoy-access-log': Object.freeze({ name: 'envoy-access-log', parse: parseEnvoyAccessLogObservations }),
  'k8s-audit-log': Object.freeze({ name: 'k8s-audit-log', parse: parseK8sAuditLogObservations }),
  'http-access-log': Object.freeze({ name: 'http-access-log', parse: parseHttpAccessLogObservations }),
});

/**
 * `adapterFor(name) -> {name, parse} | null` — the registry lookup.
 * `parse` has the `(text, context) -> {drafts, errors}` signature of
 * `parseNativeJsonlObservations` above.
 */
function adapterFor(name) {
  if (typeof name !== 'string') return null;
  return Object.prototype.hasOwnProperty.call(_ADAPTERS, name) ? _ADAPTERS[name] : null;
}


/***/ })

};
