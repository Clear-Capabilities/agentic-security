// observation-adapters.test.js — Task 3 of the M5 "Runtime-Corroborated
// Digital Twin" (7b) sub-project. `observation-adapters.js` is the adapter
// INTERFACE plus the one shipped implementation (`native-jsonl`) — pure
// text-in/drafts-out, zero imports (see AD/6a below).
//
// ── The two-layer rejection split (AD/4a), stated once, here ────────────
//
// `observation-adapters.js` enforces the WIRE shape only: an unknown
// top-level wire key, a pre-declared match (`id`/`matchedNodeIds`/
// `matchedEdgeIds`/`matchedFlowIds`/`matchMethod`/`matchConfidence` — none
// of these are members of `NATIVE_JSONL_RECORD_KEYS`, so the same
// closed-world sweep that rejects an unrecognized field also rejects every
// one of these), and that `attributes` is a plain object whose every value
// is a scalar or an array of strings. It deliberately does NOT check
// WHICH attribute keys are approved — `validateRuntimeObservation` (Task 1,
// `runtime-observation.js`) is the single authority on that allowlist, so
// this module never duplicates it. Against `native-payload.jsonl`, this
// means the adapter itself catches only 2 of the fixture's 4 smuggling
// attempts (line 3's top-level `prompt`, line 4's `matchedNodeIds`/
// `matchConfidence`) — the other two (line 1's `http.url` attribute key,
// line 2's `db.statement` attribute key) are structurally fine at the WIRE
// layer and are caught one layer up, by `validateRuntimeObservation`, at
// IMPORT time (`CLI/import-4`, a future task's own test — not a hole in
// this one). Line 5 (added by the final review's B1 fix round) is a
// VALUE-axis smuggling attempt through an APPROVED key (`schema.name`
// carrying a raw SQL statement) — structurally fine at the wire layer
// (a scalar string), so it also parses to a draft here; it is caught one
// layer up by `validateRuntimeObservation`'s new identifier-shaped value
// grammar (B1 Part 2), never by this module.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  NATIVE_JSONL_RECORD_KEYS,
  parseNativeJsonlObservations,
  parseOtelJsonObservations,
  parseEnvoyAccessLogObservations,
  parseK8sAuditLogObservations,
  parseHttpAccessLogObservations,
  adapterFor,
} from '../../src/lineage/observation-adapters.js';
import {
  RUNTIME_OBSERVATION_VERSION,
  validateRuntimeObservation,
} from '../../src/lineage/runtime-observation.js';
import { observationId } from '../../src/lineage/ids.js';
import { matchObservationToGraph } from '../../src/lineage/observation-correlation.js';

const FIXTURES_DIR = fileURLToPath(new URL('../fixtures/runtime-observations/', import.meta.url));
const CLEAN_TEXT = fs.readFileSync(path.join(FIXTURES_DIR, 'native-clean.jsonl'), 'utf8');
const PAYLOAD_TEXT = fs.readFileSync(path.join(FIXTURES_DIR, 'native-payload.jsonl'), 'utf8');

function baseContext(overrides = {}) {
  return {
    version: RUNTIME_OBSERVATION_VERSION,
    adapter: 'native-jsonl',
    source: 'native.jsonl:test-fixture',
    environment: 'production',
    windowStart: '2026-07-01T00:00:00.000Z',
    windowEnd: '2026-08-31T00:00:00.000Z',
    importedAt: '2026-08-31T12:00:00.000Z',
    retention: { expiresAt: null },
    ...overrides,
  };
}

// =====================================================================
// AD/6a — the module's boundary. One step stricter than
// observation-correlation.js's own boundary test: zero imports at all.
// =====================================================================

test('AD/6a: observation-adapters.js imports NOTHING — its static specifier list is EXACTLY [], no dynamic import(, no node:fs', () => {
  const modulePath = fileURLToPath(new URL('../../src/lineage/observation-adapters.js', import.meta.url));
  const src = fs.readFileSync(modulePath, 'utf8');
  const specifiers = [...src.matchAll(/(?:from|import)\s*\(?\s*['"]([^'"]+)['"]/g)].map((m) => m[1]);
  assert.deepEqual(specifiers, [], 'observation-adapters.js must import nothing at all — version is caller-supplied specifically so this module never needs runtime-observation.js');
  assert.equal(/\bimport\s*\(/.test(src), false, 'no dynamic import( anywhere in the source');
  assert.equal(/node:fs/.test(src), false, 'no node:fs anywhere in the source — external evidence arrives as a file the CALLER reads, never fs access from inside this module');
});

// =====================================================================
// AD/1 — the registry.
// =====================================================================

test('AD/1a: adapterFor returns the native-jsonl adapter, and null for anything unimplemented or absent', () => {
  const native = adapterFor('native-jsonl');
  assert.equal(native.name, 'native-jsonl');
  assert.equal(typeof native.parse, 'function');

  assert.equal(adapterFor('otlp'), null, 'the full OTLP semantic-conventions vocabulary is deferred — otel-json below is this codebase\'s own minimal reader, never accepted under the name "otlp"');
  assert.equal(adapterFor(null), null);
  assert.equal(adapterFor(undefined), null);
  assert.equal(adapterFor('NATIVE-JSONL'), null, 'adapter names are not case-folded');
});

test('AD/1b: adapterFor returns all four PRD "Runtime-Corroborated Security Twin" adapters', () => {
  for (const name of ['otel-json', 'envoy-access-log', 'k8s-audit-log', 'http-access-log']) {
    const a = adapterFor(name);
    assert.equal(a.name, name);
    assert.equal(typeof a.parse, 'function');
  }
});

// =====================================================================
// AD/2 — the clean fixture.
// =====================================================================

test('AD/2a: the clean fixture parses to exactly 4 drafts and 0 errors', () => {
  const { drafts, errors } = parseNativeJsonlObservations(CLEAN_TEXT, baseContext());
  assert.equal(errors.length, 0);
  assert.equal(drafts.length, 4);
});

test('AD/2b: each draft carries every context field verbatim', () => {
  const ctx = baseContext();
  const { drafts } = parseNativeJsonlObservations(CLEAN_TEXT, ctx);
  for (const d of drafts) {
    assert.equal(d.adapter, ctx.adapter);
    assert.equal(d.source, ctx.source);
    assert.equal(d.windowStart, ctx.windowStart);
    assert.equal(d.windowEnd, ctx.windowEnd);
    assert.deepEqual(d.retention, ctx.retention);
    assert.equal(d.importedAt, ctx.importedAt);
    assert.equal(d.version, ctx.version);
  }
});

test('AD/2c: a per-line environment overrides the context default; a line without one inherits it', () => {
  const ctx = baseContext({ environment: 'production' });
  const { drafts } = parseNativeJsonlObservations(CLEAN_TEXT, ctx);
  assert.equal(drafts.length, 4);
  assert.equal(drafts[0].environment, 'production');
  assert.equal(drafts[1].environment, 'production');
  assert.equal(drafts[2].environment, 'staging', 'line 3 declares its own environment');
  assert.equal(drafts[3].environment, 'production');
});

test('AD/2d: no draft ever carries id/matchedNodeIds/matchedEdgeIds/matchedFlowIds/matchMethod/matchConfidence', () => {
  const { drafts } = parseNativeJsonlObservations(CLEAN_TEXT, baseContext());
  assert.ok(drafts.length > 0);
  for (const d of drafts) {
    for (const k of ['id', 'matchedNodeIds', 'matchedEdgeIds', 'matchedFlowIds', 'matchMethod', 'matchConfidence']) {
      assert.equal(k in d, false, `draft must never carry ${k} — minted/derived downstream only`);
    }
  }
});

// =====================================================================
// AD/3 — malformed JSON.
// =====================================================================

test('AD/3a: a malformed JSON line yields one {line, message} error naming the 1-based line number; other lines still parse; blank/trailing lines are silently skipped', () => {
  const text = '{"attributes":{},"eventCountBand":"1","firstObservedAt":"2026-08-01T00:00:00.000Z","lastObservedAt":"2026-08-01T00:00:00.000Z"}\n'
    + 'not json at all\n'
    + '\n'
    + '{"attributes":{},"eventCountBand":"1","firstObservedAt":"2026-08-01T00:00:00.000Z","lastObservedAt":"2026-08-01T00:00:00.000Z"}\n';
  const { drafts, errors } = parseNativeJsonlObservations(text, baseContext());
  assert.equal(drafts.length, 2, 'lines 1 and 4 still parse');
  assert.equal(errors.length, 1);
  assert.equal(errors[0].line, 2);
  assert.equal(typeof errors[0].message, 'string');
});

test('AD/3b (M2, final review): the malformed-JSON error never echoes the raw offending text — V8\'s own JSON.parse error message quotes a snippet of the input', () => {
  const secret = 'this-line-is-not-json-MALFORMEDSECRET-4111111111111111';
  const { errors } = parseNativeJsonlObservations(`${secret}\n`, baseContext());
  assert.equal(errors.length, 1);
  assert.equal(errors[0].message, 'invalid JSON on line 1');
  assert.equal(errors[0].message.includes('MALFORMEDSECRET'), false, 'the raw line must never be echoed back');
  assert.equal(errors[0].message.includes('4111111111111111'), false, 'the raw line must never be echoed back');
});

// =====================================================================
// AD/4 — the two-layer split, against the payload fixture.
// =====================================================================

test('AD/4a: the payload fixture yields exactly 2 errors and 3 drafts — the two-layer rejection split', () => {
  const { drafts, errors } = parseNativeJsonlObservations(PAYLOAD_TEXT, baseContext());
  // Lines 1, 2, and 5 carry a structurally-fine (scalar) but either
  // UNAPPROVED attribute key (`http.url`, `db.statement`) or an approved
  // key with a non-identifier-shaped VALUE (`schema.name` carrying a raw
  // SQL statement, B1) — this module has no opinion on either axis, so all
  // three parse to drafts here. `validateRuntimeObservation` is what
  // rejects them, one layer up (CLI/import-4).
  assert.equal(drafts.length, 3);
  // Lines 3 and 4 carry a top-level wire key outside NATIVE_JSONL_RECORD_KEYS
  // (`prompt`, `matchedNodeIds`/`matchConfidence`) — caught here.
  assert.equal(errors.length, 2);
});

test('AD/4b: both adapter-level errors carry a correct 1-based line and name the offending field', () => {
  const { errors } = parseNativeJsonlObservations(PAYLOAD_TEXT, baseContext());
  const byLine = Object.fromEntries(errors.map((e) => [e.line, e]));
  assert.equal(byLine[3].line, 3);
  assert.match(byLine[3].message, /prompt/);
  assert.equal(byLine[4].line, 4);
  assert.match(byLine[4].message, /matchedNodeIds/);
});

test('AD/4c: a line with an unknown top-level wire key not in NATIVE_JSONL_RECORD_KEYS is an error naming it', () => {
  const text = '{"attributes":{},"note":"x"}\n';
  const { drafts, errors } = parseNativeJsonlObservations(text, baseContext());
  assert.equal(drafts.length, 0);
  assert.equal(errors.length, 1);
  assert.equal(errors[0].line, 1);
  assert.match(errors[0].message, /note/);
});

// =====================================================================
// AD/5 — never throws, honest empties.
// =====================================================================

test('AD/5a: an empty file is an empty import, not a failure', () => {
  assert.deepEqual(parseNativeJsonlObservations('', baseContext()), { drafts: [], errors: [] });
});

test('AD/5b: never throws on malformed input shapes', () => {
  const inputs = [
    ['', null],
    [null, baseContext()],
    [42, baseContext()],
    ['{}', baseContext()],
    ['null\n', baseContext()],
    ['[]\n', baseContext()],
    ['"x"\n', baseContext()],
  ];
  for (const [text, context] of inputs) {
    const result = parseNativeJsonlObservations(text, context);
    assert.equal(typeof result, 'object');
    assert.ok(Array.isArray(result.drafts));
    assert.ok(Array.isArray(result.errors));
  }
});

test('AD/5c: a line that is valid JSON but not an object is one error, not a crash', () => {
  for (const text of ['[1,2]\n', '"x"\n', '7\n', 'null\n']) {
    const { drafts, errors } = parseNativeJsonlObservations(text, baseContext());
    assert.equal(drafts.length, 0);
    assert.equal(errors.length, 1);
    assert.equal(errors[0].line, 1);
  }
});

// =====================================================================
// AD/7 — round-trip against Task 1/Task 2.
// =====================================================================

test('AD/7a: every draft from the clean fixture round-trips through observationId/matchObservationToGraph into a valid RuntimeObservation', () => {
  const { drafts, errors } = parseNativeJsonlObservations(CLEAN_TEXT, baseContext());
  assert.equal(errors.length, 0);
  assert.ok(drafts.length > 0);

  const graph = { nodes: [], edges: [], flows: [] };

  for (const draft of drafts) {
    const record = {
      ...draft,
      id: observationId(draft, [JSON.stringify(draft.attributes)]),
      ...matchObservationToGraph(graph, draft),
    };
    const result = validateRuntimeObservation(record);
    assert.deepEqual(result, { valid: true, errors: [] }, `draft must round-trip cleanly: ${JSON.stringify(result.errors)}`);
  }
});

// =====================================================================
// NATIVE_JSONL_RECORD_KEYS — frozen, exact shape.
// =====================================================================

test('NATIVE_JSONL_RECORD_KEYS is frozen and exactly the 5 documented keys', () => {
  assert.deepEqual(NATIVE_JSONL_RECORD_KEYS, ['environment', 'attributes', 'eventCountBand', 'firstObservedAt', 'lastObservedAt']);
  assert.ok(Object.isFrozen(NATIVE_JSONL_RECORD_KEYS));
});

// =====================================================================
// The four PRD "Runtime-Corroborated Security Twin" adapters.
// Each draft is round-tripped through `validateRuntimeObservation` the
// same way AD/7a proves native-jsonl's own drafts — this is the real
// proof each adapter produces something the closed-world contract
// actually accepts, not just that its own parse function returns.
// =====================================================================

function _roundTrip(draft) {
  const graph = { nodes: [], edges: [], flows: [] };
  const record = {
    ...draft,
    id: observationId(draft, [JSON.stringify(draft.attributes)]),
    ...matchObservationToGraph(graph, draft),
  };
  return validateRuntimeObservation(record);
}

test('AD/OTEL-1: a real OTLP/JSON resourceSpans document produces one draft per span with safe attributes only', () => {
  const doc = {
    resourceSpans: [{
      resource: { attributes: [{ key: 'service.name', value: { stringValue: 'checkout-service' } }] },
      scopeSpans: [{
        spans: [
          {
            name: 'POST /charge',
            startTimeUnixNano: '1785664800000000000',
            endTimeUnixNano: '1785664800500000000',
            attributes: [
              { key: 'server.address', value: { stringValue: 'api.stripe.com' } },
              { key: 'server.port', value: { intValue: '443' } },
              { key: 'url.scheme', value: { stringValue: 'https' } },
              { key: 'http.url', value: { stringValue: 'https://api.stripe.com/v1/charges?key=secret' } },
              { key: 'http.request.header.authorization', value: { stringValue: 'Bearer sk_live_xxx' } },
            ],
          },
        ],
      }],
    }],
  };
  const { drafts, errors } = parseOtelJsonObservations(JSON.stringify(doc), baseContext({ adapter: 'otel-json' }));
  assert.equal(errors.length, 0);
  assert.equal(drafts.length, 1);
  const d = drafts[0];
  assert.deepEqual(d.attributes, {
    'service.name': 'checkout-service',
    'destination.host': 'api.stripe.com',
    'destination.port': 443,
    'destination.scheme': 'https',
  });
  assert.ok(!('http.url' in d.attributes) && !('http.request.header.authorization' in d.attributes),
    'the query string and the auth header must never be carried — neither has a safe destination');
  assert.equal(d.eventCountBand, '1');
  assert.deepEqual(_roundTrip(d), { valid: true, errors: [] });
});

test('AD/OTEL-2: a malformed or non-OTLP-shaped document is one honest error, never a crash', () => {
  for (const text of ['not json', '{}', '{"resourceSpans": "x"}', JSON.stringify({ foo: 'bar' })]) {
    const { drafts, errors } = parseOtelJsonObservations(text, baseContext({ adapter: 'otel-json' }));
    assert.equal(drafts.length, 0);
    assert.equal(errors.length, 1);
  }
});

test('AD/ENVOY-1: a real Envoy JSON access log line maps upstream_host/cluster/protocol/response_flags safely', () => {
  const line = JSON.stringify({
    upstream_host: '10.0.4.12:8443',
    upstream_cluster: 'payments-service',
    protocol: 'HTTP/1.1',
    response_flags: '-',
    start_time: '2026-08-02T10:00:00.000Z',
    duration: 42,
    'x-forwarded-for': '203.0.113.9', // deliberately NOT an approved field — must never appear in attributes
  });
  const { drafts, errors } = parseEnvoyAccessLogObservations(line + '\n', baseContext({ adapter: 'envoy-access-log' }));
  assert.equal(errors.length, 0);
  assert.equal(drafts.length, 1);
  const d = drafts[0];
  assert.deepEqual(d.attributes, {
    'destination.host': '10.0.4.12',
    'destination.port': 8443,
    'destination.service': 'payments-service',
    'network.protocol': 'http1.1',
    'network.securityDecision': 'allowed',
  });
  assert.ok(!('x-forwarded-for' in d.attributes), 'the client IP header must never be carried');
  assert.equal(d.lastObservedAt, new Date(Date.parse('2026-08-02T10:00:00.000Z') + 42).toISOString());
  assert.deepEqual(_roundTrip(d), { valid: true, errors: [] });
});

test('AD/ENVOY-2: a non-empty response_flags reads network.securityDecision as denied', () => {
  const line = JSON.stringify({ upstream_host: '10.0.4.12:8443', response_flags: 'UAEX' });
  const { drafts } = parseEnvoyAccessLogObservations(line + '\n', baseContext({ adapter: 'envoy-access-log' }));
  assert.equal(drafts[0].attributes['network.securityDecision'], 'denied');
});

test('AD/ENVOY-3: a malformed line is one error naming its line number; other lines still parse', () => {
  const text = 'not json\n' + JSON.stringify({ upstream_host: 'a.b:443' }) + '\n';
  const { drafts, errors } = parseEnvoyAccessLogObservations(text, baseContext({ adapter: 'envoy-access-log' }));
  assert.equal(errors.length, 1);
  assert.equal(errors[0].line, 1);
  assert.equal(drafts.length, 1);
});

test('AD/K8S-1: a real k8s audit event maps objectRef/responseStatus safely, never the username', () => {
  const line = JSON.stringify({
    objectRef: { apiVersion: 'v1', resource: 'secrets', namespace: 'payments', name: 'db-credentials' },
    verb: 'get',
    responseStatus: { code: 403 },
    requestReceivedTimestamp: '2026-08-02T11:00:00.000Z',
    user: { username: 'alice@example.com' }, // deliberately NOT an approved field — must never appear
  });
  const { drafts, errors } = parseK8sAuditLogObservations(line + '\n', baseContext({ adapter: 'k8s-audit-log' }));
  assert.equal(errors.length, 0);
  assert.equal(drafts.length, 1);
  const d = drafts[0];
  assert.deepEqual(d.attributes, {
    'destination.service': 'payments:secrets',
    'network.securityDecision': 'denied',
  });
  assert.ok(!('user' in d) && JSON.stringify(d).indexOf('alice') === -1, 'the username must never be carried anywhere in the draft');
  assert.deepEqual(_roundTrip(d), { valid: true, errors: [] });
});

test('AD/K8S-2: a successful (< 400) response reads network.securityDecision as allowed', () => {
  const line = JSON.stringify({ objectRef: { resource: 'pods', namespace: 'default' }, responseStatus: { code: 200 } });
  const { drafts } = parseK8sAuditLogObservations(line + '\n', baseContext({ adapter: 'k8s-audit-log' }));
  assert.equal(drafts[0].attributes['network.securityDecision'], 'allowed');
});

test('AD/HTTP-1: a generic JSON access-log line maps host/upstream/scheme safely', () => {
  const line = JSON.stringify({
    host: 'gateway.internal', upstream: 'checkout-service', scheme: 'https',
    path: '/charge?card=4111111111111111', user_agent: 'curl/8.0', // deliberately NOT approved fields
  });
  const { drafts, errors } = parseHttpAccessLogObservations(line + '\n', baseContext({ adapter: 'http-access-log' }));
  assert.equal(errors.length, 0);
  assert.equal(drafts.length, 1);
  const d = drafts[0];
  assert.deepEqual(d.attributes, {
    'destination.host': 'gateway.internal',
    'destination.service': 'checkout-service',
    'destination.scheme': 'https',
  });
  assert.ok(!('path' in d.attributes) && !('user_agent' in d.attributes), 'the path/query string and user agent must never be carried');
  assert.deepEqual(_roundTrip(d), { valid: true, errors: [] });
});

test('AD/HTTP-2: a line with nothing safe to report yields no draft, never a fabricated one', () => {
  const line = JSON.stringify({ path: '/x', user_agent: 'curl' });
  const { drafts, errors } = parseHttpAccessLogObservations(line + '\n', baseContext({ adapter: 'http-access-log' }));
  assert.equal(errors.length, 0);
  assert.equal(drafts.length, 0);
});

test('AD/NEW-ADAPTERS: all four new adapters never throw on malformed input shapes', () => {
  for (const parse of [parseOtelJsonObservations, parseEnvoyAccessLogObservations, parseK8sAuditLogObservations, parseHttpAccessLogObservations]) {
    for (const bad of [null, undefined, 42, {}, []]) {
      assert.doesNotThrow(() => parse(bad, baseContext()));
    }
    for (const bad of [null, undefined, 'x', 42, []]) {
      assert.doesNotThrow(() => parse('{}', bad));
    }
  }
});
