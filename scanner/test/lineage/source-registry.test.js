//
// Sub-project D, increment D2 — permanent test suite for
// src/lineage/source-registry.js. Ported from the design-phase PoC
// (test/lineage/registry-mapping-poc.test.js), re-pointed at the shipped
// `reclassifySource`, per DESIGN_REGISTRIES.md §9.1: D2 is the FIRST lander
// (D3/sink-registry.js has not landed yet), so the PoC file itself is left
// in place for D3 to absorb its own (disjoint) sink/privacy half from —
// this file absorbs only the source-side content.
//

import test from 'node:test';
import assert from 'node:assert/strict';

import { CATALOG } from '../../src/dataflow/catalog.js';
import {
  NODE_KINDS, SOURCE_CATEGORIES, COVERAGE_STATUS_VALUES, EXTERNALITY_VALUES,
} from '../../src/lineage/schema.js';
import {
  reclassifySource,
  PROVENANCE_MAP,
  AGENT_TOOL_REFINEMENT,
  CPP_DESCRIPTOR_GENERIC_PROVENANCE,
  NO_PROVENANCE_OVERRIDES,
  SOURCE_CATEGORY_EXTERNALITY,
  SOURCE_ENTRIES,
} from '../../src/lineage/source-registry.js';

// ───────────────────────────────────────────────────────────────────────────
// Ground truth, extracted programmatically from the LIVE catalog — never a
// hardcoded snapshot (DESIGN_REGISTRIES.md §2).
// ───────────────────────────────────────────────────────────────────────────

const SOURCES = CATALOG.filter((e) => e.kind === 'source');
const byId = new Map(CATALOG.map((e) => [e.id, e]));

/** Every distinct `provenance` string on a source entry that HAS one. */
const DISTINCT_PROVENANCE = new Set(SOURCES.filter((e) => e.provenance).map((e) => e.provenance));
/** Every source entry id that carries NO `provenance` field at all. */
const NO_PROVENANCE_IDS = new Set(SOURCES.filter((e) => !e.provenance).map((e) => e.id));

test('sanity: SOURCE_ENTRIES matches CATALOG filtered live, not a stale snapshot', () => {
  assert.deepEqual(SOURCE_ENTRIES.map((e) => e.id).sort(), SOURCES.map((e) => e.id).sort());
});

// ───────────────────────────────────────────────────────────────────────────
// Completeness guards — the single most important tests in this file
// (DESIGN_REGISTRIES.md §9's D2 item 4). Each is a REAL, mutation-tested
// guard: a hand-built catalog-shaped entry with a provenance value not in
// PROVENANCE_MAP (or an id not in NO_PROVENANCE_OVERRIDES) was temporarily
// added during development to confirm each guard fails loudly, then
// removed to confirm it goes clean again — see task-1-report.md for that
// verification transcript. What ships here is the permanent, always-run
// form of that same check, run against the live catalog on every test run.
// ───────────────────────────────────────────────────────────────────────────

test('completeness/1a: every distinct source `provenance` string in CATALOG has a PROVENANCE_MAP row, and vice versa', () => {
  const unmapped = [...DISTINCT_PROVENANCE].filter((p) => !(p in PROVENANCE_MAP)).sort();
  assert.deepEqual(unmapped, [], `catalog.js gained provenance value(s) with no mapping: ${unmapped.join(', ')}`);
  const stale = Object.keys(PROVENANCE_MAP).filter((p) => !DISTINCT_PROVENANCE.has(p)).sort();
  assert.deepEqual(stale, [], `PROVENANCE_MAP has rows for provenance values no entry carries: ${stale.join(', ')}`);
});

test('completeness/1b: NO_PROVENANCE_OVERRIDES covers EXACTLY the unprovenanced source entries, and vice versa', () => {
  const overrideIds = new Set(Object.keys(NO_PROVENANCE_OVERRIDES));
  const missing = [...NO_PROVENANCE_IDS].filter((id) => !overrideIds.has(id)).sort();
  const stale = [...overrideIds].filter((id) => !NO_PROVENANCE_IDS.has(id)).sort();
  assert.deepEqual(missing, [], `source entries with no provenance and no override: ${missing.join(', ')}`);
  assert.deepEqual(stale, [], `override rows for entries that no longer need one: ${stale.join(', ')}`);
});

test('completeness/1c: every agent-tool source entry has an AGENT_TOOL_REFINEMENT row, and vice versa', () => {
  const agentToolIds = new Set(SOURCES.filter((e) => e.provenance === 'agent-tool').map((e) => e.id));
  const refIds = new Set(Object.keys(AGENT_TOOL_REFINEMENT));
  const missing = [...agentToolIds].filter((id) => !refIds.has(id)).sort();
  const stale = [...refIds].filter((id) => !agentToolIds.has(id)).sort();
  assert.deepEqual(missing, [], `agent-tool source entries with no refinement row: ${missing.join(', ')}`);
  assert.deepEqual(stale, [], `refinement rows for entries that are no longer agent-tool sources: ${stale.join(', ')}`);
});

// ───────────────────────────────────────────────────────────────────────────
// Totality — every entry gets a valid decision, none throws.
// ───────────────────────────────────────────────────────────────────────────

test('totality: every source entry produces a valid, non-throwing, fully-shaped decision', () => {
  for (const e of SOURCES) {
    const r = reclassifySource(e);
    assert.equal(r.kind, 'source', `${e.id}: node kind must always be 'source' (§7.1)`);
    assert.ok(NODE_KINDS.includes(r.kind), `${e.id}: bad node kind ${r.kind}`);
    assert.ok(COVERAGE_STATUS_VALUES.includes(r.coverageStatus), `${e.id}: bad coverageStatus ${r.coverageStatus}`);
    assert.notEqual(r.coverageStatus, 'manual', `${e.id}: a registry must never emit 'manual' (§6.5)`);
    assert.notEqual(r.coverageStatus, 'split', `${e.id}: 'split' is an internal marker only`);
    if (r.category !== null) assert.ok(SOURCE_CATEGORIES.includes(r.category), `${e.id}: ${r.category} not in SOURCE_CATEGORIES`);
    assert.ok(EXTERNALITY_VALUES.includes(r.externality), `${e.id}: bad externality ${r.externality}`);
    assert.ok(r.reason && r.reason.length > 0, `${e.id}: every decision must carry a reason (AC-11)`);
    assert.ok(!('subtype' in r), `${e.id}: a registry decision must never carry a literal 'subtype' field (§9.0)`);
  }
});

test('every source entry maps to node kind `source` — never `boundary`', () => {
  // Checked, not assumed: `boundary` models a trust-zone crossing, which is
  // a property of an EDGE between two systems, and no catalog entry carries
  // system/zone information at all.
  const kinds = new Set(SOURCES.map((e) => reclassifySource(e).kind));
  assert.deepEqual([...kinds], ['source']);
});

// ───────────────────────────────────────────────────────────────────────────
// Representative real reclassifications, end to end.
// ───────────────────────────────────────────────────────────────────────────

test('representative real entries produce the stated (category, coverageStatus) pairs', () => {
  const expected = [
    // id                          category                  coverageStatus
    ['js-req-body',                'http-body',              'modeled'],
    ['js-req-query',               'http-query',              'modeled'],
    ['js-req-params',              'http-route',              'modeled'],
    ['js-req-headers',             'http-header',             'modeled'],
    ['js-req-cookies',             'http-cookie',             'modeled'],
    ['js-process-env',             'env-value',               'modeled'],
    ['js-loc-hash',                'http-query',              'partial'],   // url-fragment, lossy
    ['cpp-gets',                   'user-input',              'partial'],   // stdin, lossy
    ['go-chi-urlparam',            'http-route',              'candidate'],
    ['php-symfony-files',          'http-upload',             'candidate'],
    ['js-mcp-resource-contents',   'ai-retrieved-document',   'modeled'],
    ['js-mcp-tool-result',         'ai-tool-result',          'modeled'],
    ['py-mcp-tool',                'ai-model-output',         'partial'],
  ];
  for (const [id, category, status] of expected) {
    const e = byId.get(id);
    assert.ok(e, `catalog entry ${id} no longer exists — the sample needs updating`);
    const r = reclassifySource(e);
    assert.equal(r.category, category, `${id}: category`);
    assert.equal(r.coverageStatus, status, `${id}: coverageStatus`);
  }
});

// ───────────────────────────────────────────────────────────────────────────
// The cpp descriptor-generic refinement (§4.2) — its own dedicated test.
// ───────────────────────────────────────────────────────────────────────────

test('cpp refinement: the 5 descriptor-generic C entries are `partial` with the right reason', () => {
  const expected = {
    'cpp-recv': 'external-api-response',
    'cpp-recvfrom': 'external-api-response',
    'cpp-read': 'storage-read',
    'cpp-fread': 'storage-read',
    'cpp-fgets': 'storage-read',
  };
  for (const [id, category] of Object.entries(expected)) {
    const e = byId.get(id);
    assert.ok(e, `catalog entry ${id} no longer exists`);
    assert.equal(e.language, 'cpp');
    assert.ok(CPP_DESCRIPTOR_GENERIC_PROVENANCE.has(e.provenance));
    const r = reclassifySource(e);
    assert.equal(r.category, category, `${id}: category is unchanged by the refinement`);
    assert.equal(r.coverageStatus, 'partial', `${id}: must not claim modeled`);
    assert.match(r.reason, /LOSSY/);
  }
});

test('cpp refinement is scoped: non-cpp entries in the same provenance buckets stay `modeled`', () => {
  for (const id of ['js-fetch-json', 'py-requests-json', 'py-open-read']) {
    const e = byId.get(id);
    assert.ok(e, `catalog entry ${id} no longer exists`);
    assert.notEqual(e.language, 'cpp');
    assert.equal(reclassifySource(e).coverageStatus, 'modeled', id);
  }
});

test('cpp entries NOT in the descriptor-generic buckets are unaffected by the refinement', () => {
  // cpp-getenv (env) and cpp-gets/cpp-scanf (stdin) are cpp but outside the
  // {network, file-read} refinement set — env stays modeled (no cpp special
  // case there), stdin was already partial for the adjacent broadening
  // reason, not the descriptor-generic one.
  const env = byId.get('cpp-getenv');
  assert.equal(reclassifySource(env).coverageStatus, 'modeled');
  const gets = byId.get('cpp-gets');
  assert.equal(reclassifySource(gets).coverageStatus, 'partial');
  assert.match(reclassifySource(gets).reason, /broadens to the generic category/);
});

// ───────────────────────────────────────────────────────────────────────────
// Honest candidate / unsupported cases, proven against real (and, for the
// defensive-fallback branch, synthetic) entries.
// ───────────────────────────────────────────────────────────────────────────

test('candidate: an honest real no-provenance entry is `candidate`, never silently upgraded', () => {
  const e = byId.get('go-chi-urlparam');
  assert.ok(e);
  assert.equal(e.provenance, undefined);
  const r = reclassifySource(e);
  assert.equal(r.coverageStatus, 'candidate');
  assert.equal(r.category, 'http-route');
  assert.match(r.reason, /inferred from entry id\/label\/framework/);
});

test('unsupported (defensive fallback): a synthetic entry with an unmapped provenance value is `unsupported`, not thrown', () => {
  // The live catalog has 0 unsupported source entries today (every declared
  // provenance and every unprovenanced id is covered — see the pinned
  // coverage-count test below), so this path is unreachable from real
  // CATALOG data. It still must behave correctly and not throw, since a
  // FUTURE catalog entry with a genuinely new provenance value must fail
  // the completeness guard above loudly, not this function silently.
  const synthetic = { kind: 'source', id: 'synthetic-unmapped', language: 'js', provenance: 'nonexistent-provenance-value' };
  const r = reclassifySource(synthetic);
  assert.equal(r.category, null);
  assert.equal(r.coverageStatus, 'unsupported');
  assert.equal(r.kind, 'source');
  assert.match(r.reason, /unmapped provenance/);
});

test('unsupported (defensive fallback): a synthetic no-provenance entry with an unknown id is `unsupported`, not thrown', () => {
  const synthetic = { kind: 'source', id: 'synthetic-no-override', language: 'js' };
  const r = reclassifySource(synthetic);
  assert.equal(r.category, null);
  assert.equal(r.coverageStatus, 'unsupported');
  assert.match(r.reason, /no provenance field and no override/);
});

// ───────────────────────────────────────────────────────────────────────────
// Pinned coverage counts — equality, not a floor (bench/layer-recall has
// already shown in this repo that a floor-only gate lets a stale published
// number survive silently for weeks).
// ───────────────────────────────────────────────────────────────────────────

test('pinned coverage counts: re-measured after merging the Rust + Java SARD catalog additions', () => {
  const results = SOURCES.map(reclassifySource);
  // SARD_AGENTIC_SECURITY_PRD.md work added 5 no-provenance Java/PHP source
  // entries (java-io-readline, java-resultset-getstring/-getobject,
  // php-session, php-env) — each resolves via NO_PROVENANCE_OVERRIDES (§4.3),
  // which is always `candidate` by construction, so 82 -> 87, 180 -> 185.
  // Rust joined the catalog (SARD 80% F1 push) with 38 new source entries —
  // 3 annotation-based extractor rows with no matching PROVENANCE_MAP row of
  // their own so they resolve `candidate` (rs-extract-httprequest/-request,
  // rs-closure-extract-request via NO_PROVENANCE_OVERRIDES), the rest carry
  // real `provenance` values and resolve `modeled`. Java's own SARD push
  // separately added 3 more no-provenance servlet sources (getAttribute,
  // getQueryString, Cookie.getValue), also `candidate` via
  // NO_PROVENANCE_OVERRIDES. C#'s SARD push added 8 more sources: 2
  // (`cs-req-params`/`cs-request-lc-params`) declare `provenance: 'url-param'`
  // directly and resolve `modeled`; 6 (3 console/stream reads, 3 ADO.NET
  // result-set reads) originally shipped with invented, unrecognized
  // provenance strings (`'io-read'`/`'database'`) that made them resolve
  // `unsupported` — fixed at the source (provenance field removed, two new
  // NO_PROVENANCE_OVERRIDES rows added mirroring java-io-readline/
  // java-resultset-getstring exactly), so they resolve `candidate`. PHP's
  // own SARD push added 1 source (`php-readline`, `provenance: 'stdin'`,
  // the same existing LOSSY convention as `cpp-gets`/`cpp-scanf`) —
  // `partial`. All four branches landed in the same merge; the figures
  // below are re-measured against the merged catalog, not summed by hand
  // from any branch's own delta.
  // 260 -> 442 (146 -> 284 modeled, 15 -> 59 partial, candidate unchanged at 99): the Haskell source model adds 182 entries,
  // generated from language/haskell-models.js: 91 call-form sources for the taint engine and 91 member-form twins
  // (`$hs.<Module.name>`) that the lineage view of a Haskell function reads. Re-measured against the live catalog.
  // 442 -> 444 (candidate 99 -> 101): two Haskell sources, a text parameter of an exported function (taint form) and a record
  // parameter of one (lineage form). Neither carries a request provenance, so both resolve `candidate` through
  // NO_PROVENANCE_OVERRIDES (category user-input). Re-measured against the live catalog.
  // 444 -> 460 and 101 -> 117 candidate: QA-006 added 16 request-bound sources (2 implicit handler parameters, 14 Laravel request
  // accessors). None declares a `provenance`, so each resolves through NO_PROVENANCE_OVERRIDES and, like every such entry, is `candidate`.
  assert.equal(SOURCES.length, 460);
  assert.equal(results.filter((r) => r.coverageStatus === 'modeled').length, 284);
  assert.equal(results.filter((r) => r.coverageStatus === 'partial').length, 59);
  assert.equal(results.filter((r) => r.coverageStatus === 'candidate').length, 117);
  assert.equal(results.filter((r) => r.coverageStatus === 'unsupported').length, 0);
  assert.equal(284 + 59 + 117, SOURCES.length);
});

// ───────────────────────────────────────────────────────────────────────────
// Unreachable SOURCE_CATEGORIES — the disclosed gap (§7.2), pinned as an
// exact list so it cannot go stale silently.
// ───────────────────────────────────────────────────────────────────────────

test('unreachable source categories match the pinned list from DESIGN_REGISTRIES.md §7.2', () => {
  const reachable = new Set(SOURCES.map((e) => reclassifySource(e).category).filter(Boolean));
  const unreachable = SOURCE_CATEGORIES.filter((c) => !reachable.has(c)).sort();
  // database-read became reachable once java-resultset-getstring/-getobject
  // were added and classified via NO_PROVENANCE_OVERRIDES (§4.3).
  assert.deepEqual(unreachable, [
    'ai-memory', 'declared', 'graphql-argument',
    'grpc-field', 'queue-message', 'webhook-payload',
  ], 'source-side coverage gap changed — re-read DESIGN_REGISTRIES.md §7.2');
  assert.equal(reachable.size, 15);
});

// ───────────────────────────────────────────────────────────────────────────
// Externality (§9.0's shape). No source-side table is specified in the
// binding design (only §7.5's sink-focused CATEGORY_EXTERNALITY exists), so
// this module resolves it itself (see source-registry.js's own header
// comment on SOURCE_CATEGORY_EXTERNALITY) — pinned here so the resolution
// cannot silently drift.
// ───────────────────────────────────────────────────────────────────────────

test('externality is present on every decision and drawn from EXTERNALITY_VALUES', () => {
  for (const e of SOURCES) {
    const r = reclassifySource(e);
    assert.ok(EXTERNALITY_VALUES.includes(r.externality), `${e.id}: ${r.externality}`);
  }
});

test('externality: ordinary in-app collection points are internal, matching the flagship fixture precedent', () => {
  for (const id of ['js-req-body', 'js-req-query', 'js-process-env', 'go-chi-urlparam', 'php-get']) {
    const e = byId.get(id);
    assert.ok(e, id);
    assert.equal(reclassifySource(e).externality, 'internal', id);
  }
});

test('externality: third-party-origin categories are external', () => {
  for (const id of ['js-fetch-json', 'js-mcp-tool-result', 'js-mcp-resource-contents', 'py-mcp-tool']) {
    const e = byId.get(id);
    assert.ok(e, id);
    assert.equal(reclassifySource(e).externality, 'external', id);
  }
});

test('externality: store-shaped categories are unknown', () => {
  const e = byId.get('py-open-read'); // file-read -> storage-read
  assert.ok(e);
  assert.equal(reclassifySource(e).externality, 'unknown');
});

test('SOURCE_CATEGORY_EXTERNALITY covers every category this registry can ever emit', () => {
  const reachable = new Set(SOURCES.map((e) => reclassifySource(e).category).filter(Boolean));
  for (const c of reachable) {
    assert.ok(c in SOURCE_CATEGORY_EXTERNALITY, `no externality entry for reachable category ${c}`);
  }
});

test('SOURCE_CATEGORY_EXTERNALITY exactly equals SOURCE_CATEGORIES, both directions — the stronger pin: the table is total over the whole schema vocabulary, not merely the subset this catalog snapshot happens to reach today', () => {
  assert.deepEqual(
    Object.keys(SOURCE_CATEGORY_EXTERNALITY).sort(),
    [...SOURCE_CATEGORIES].sort(),
  );
});
