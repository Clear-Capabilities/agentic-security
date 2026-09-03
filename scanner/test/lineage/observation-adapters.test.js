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
// this one).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  NATIVE_JSONL_RECORD_KEYS,
  parseNativeJsonlObservations,
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

  assert.equal(adapterFor('otlp'), null, 'OTLP is deferred to increment 2 (scoping doc §4.3) — never silently accepted');
  assert.equal(adapterFor(null), null);
  assert.equal(adapterFor(undefined), null);
  assert.equal(adapterFor('NATIVE-JSONL'), null, 'adapter names are not case-folded');
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

// =====================================================================
// AD/4 — the two-layer split, against the payload fixture.
// =====================================================================

test('AD/4a: the payload fixture yields exactly 2 errors and 2 drafts — the two-layer rejection split', () => {
  const { drafts, errors } = parseNativeJsonlObservations(PAYLOAD_TEXT, baseContext());
  // Lines 1 and 2 carry a structurally-fine (scalar) but UNAPPROVED
  // attribute key (`http.url`, `db.statement`) — this module has no
  // opinion on the attribute-key allowlist, so both parse to drafts here.
  // `validateRuntimeObservation` is what rejects them, one layer up
  // (CLI/import-4, a future task's own test).
  assert.equal(drafts.length, 2);
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
