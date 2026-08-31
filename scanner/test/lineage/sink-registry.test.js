//
// Sub-project D, increment D3 — permanent test suite for
// src/lineage/sink-registry.js. Ported from the design-phase PoC
// (test/lineage/registry-mapping-poc.test.js), re-pointed at the shipped
// `reclassifySink`/`reclassifyPrivacySink`, per DESIGN_REGISTRIES.md §9.1.
// D3 is the SECOND lander (D2/source-registry.js landed first) — this file
// absorbs the PoC's sink/privacy half; the PoC itself is deleted in the
// same commit that lands this file, per §9.1's protocol.
//

import test from 'node:test';
import assert from 'node:assert/strict';

import { CATALOG } from '../../src/dataflow/catalog.js';
import { PRIVACY_SINK_CATALOG, PRIVACY_SINK_CATEGORIES } from '../../src/dataflow/privacy-catalog.js';
import {
  NODE_KINDS, SINK_CATEGORIES, COVERAGE_STATUS_VALUES, EXTERNALITY_VALUES,
} from '../../src/lineage/schema.js';
import {
  reclassifySink,
  reclassifyPrivacySink,
  CWE_MAP,
  DOM_FRAMEWORKS,
  CATEGORY_NODE_KIND,
  CATEGORY_EXTERNALITY,
  PRIVACY_CATEGORY_MAP,
  SINK_ENTRIES,
  PRIVACY_SINK_ENTRIES,
} from '../../src/lineage/sink-registry.js';

// ───────────────────────────────────────────────────────────────────────────
// Ground truth, extracted programmatically from the LIVE catalogs — never a
// hardcoded snapshot (DESIGN_REGISTRIES.md §2).
// ───────────────────────────────────────────────────────────────────────────

const SINKS = CATALOG.filter((e) => e.kind === 'sink');
const byId = new Map(CATALOG.map((e) => [e.id, e]));

/** Every distinct `vuln.cwe` on a sink entry — the sink side's only classification signal. */
const DISTINCT_SINK_CWE = new Set(SINKS.map((e) => e.vuln?.cwe ?? '<<none>>'));
/** Every distinct `category` actually used by a privacy-catalog entry. */
const DISTINCT_PRIVACY_CATEGORY = new Set(PRIVACY_SINK_CATALOG.map((e) => e.category));

test('sanity: SINK_ENTRIES / PRIVACY_SINK_ENTRIES match the live catalogs, not a stale snapshot', () => {
  assert.deepEqual(SINK_ENTRIES.map((e) => e.id).sort(), SINKS.map((e) => e.id).sort());
  assert.deepEqual(PRIVACY_SINK_ENTRIES.map((e) => e.id).sort(), PRIVACY_SINK_CATALOG.map((e) => e.id).sort());
});

// ───────────────────────────────────────────────────────────────────────────
// Completeness guards — the single most important tests in this file
// (DESIGN_REGISTRIES.md §9's D3 checklist, mirroring D2's own
// `completeness/1a`-`1c`). Each is a REAL, mutation-tested guard: a
// hand-built catalog-shaped entry with an unmapped classification value was
// temporarily added during development to confirm each guard fails loudly,
// then removed to confirm it goes clean again — see task-1-report.md for
// that verification transcript. What ships here is the permanent,
// always-run form of that same check, run against the live catalogs on
// every test run.
// ───────────────────────────────────────────────────────────────────────────

test('completeness/1a: every distinct sink `vuln.cwe` in CATALOG has a CWE_MAP row, and vice versa', () => {
  const unmapped = [...DISTINCT_SINK_CWE].filter((c) => !(c in CWE_MAP)).sort();
  assert.deepEqual(unmapped, [], `catalog.js gained sink CWE(s) with no mapping: ${unmapped.join(', ')}`);
  const stale = Object.keys(CWE_MAP).filter((c) => !DISTINCT_SINK_CWE.has(c)).sort();
  assert.deepEqual(stale, [], `CWE_MAP has rows for CWEs no sink entry carries: ${stale.join(', ')}`);
});

test('completeness/1c (hotfix regression guard): no PRIVACY_SINK_CATALOG CWE value is ever present in CWE_MAP — privacy entries must stay routed by category, never accidentally picked up by CWE-keyed reclassification', async () => {
  const { PRIVACY_SINK_CATALOG } = await import('../../src/dataflow/privacy-catalog.js');
  const privacyCwes = new Set(PRIVACY_SINK_CATALOG.map((e) => e.vuln?.cwe).filter(Boolean));
  assert.ok(privacyCwes.size > 0, 'sanity: privacy entries really do carry CWE values worth checking');
  for (const cwe of privacyCwes) {
    assert.equal(CWE_MAP[cwe], undefined, `CWE_MAP must never map ${cwe} — it is a privacy-catalog CWE, and mapping it would let reclassifySink silently reclassify a privacy-catalog entry as if it were a general-catalog one`);
  }
});

test('completeness/1b: every distinct privacy-catalog `category` has a PRIVACY_CATEGORY_MAP row, and vice versa', () => {
  const unmapped = [...DISTINCT_PRIVACY_CATEGORY].filter((c) => !(c in PRIVACY_CATEGORY_MAP)).sort();
  assert.deepEqual(unmapped, [], `privacy-catalog.js gained category(ies) with no mapping: ${unmapped.join(', ')}`);
  // PRIVACY_SINK_CATEGORIES is the DECLARED vocabulary (nine values); assert
  // the mapping covers the declared list too, not just the values entries
  // happen to use today.
  const undeclared = PRIVACY_SINK_CATEGORIES.filter((c) => !(c in PRIVACY_CATEGORY_MAP)).sort();
  assert.deepEqual(undeclared, [], `declared privacy categories with no mapping: ${undeclared.join(', ')}`);
  const staleRows = Object.keys(PRIVACY_CATEGORY_MAP).filter((c) => !PRIVACY_SINK_CATEGORIES.includes(c)).sort();
  assert.deepEqual(staleRows, [], `PRIVACY_CATEGORY_MAP has rows for categories not in PRIVACY_SINK_CATEGORIES: ${staleRows.join(', ')}`);
});

test('the privacy vocabulary is NINE values, confirmed live, not the eight the scoping doc once assumed', () => {
  assert.equal(PRIVACY_SINK_CATEGORIES.length, 9);
  assert.deepEqual([...PRIVACY_SINK_CATEGORIES].sort(), [
    'emailSend', 'fileWrite', 'log', 'outboundHttp', 'queues', 'response',
    's3Upload', 'storage', 'thirdPartySdk',
  ]);
});

test('D1/8b (restored, task review M2): no sink entry carries its own `category` field, and every sink entry carries `vuln.cwe` — the two facts CWE_MAP-keying rests on', () => {
  // The PoC's D1/8b pinned both halves of this directly; it was not carried
  // forward into either registry's own suite when the PoC was absorbed and
  // deleted (§9.1) — restored here per the task review's own finding, since
  // the CWE keying `completeness/1a` above depends on it. The "every entry
  // has a cwe" half is also indirectly covered by completeness/1a's own
  // `<<none>>` fallback, but the "no entry has category" half was genuinely
  // unguarded before this test.
  assert.equal(SINKS.filter((e) => e.category).length, 0,
    'a live catalog.js sink entry now carries its own `category` field — CWE_MAP-keying assumption broken');
  assert.equal(SINKS.filter((e) => e.vuln?.cwe).length, SINKS.length,
    'a live catalog.js sink entry has no vuln.cwe — CWE_MAP cannot key it');
});

test('D1/8d (restored, task review M2): no sink entry carries host/url/provider/destination/externality/system fields — the stated justification for deriving externality from CATEGORY_EXTERNALITY rather than per-entry data', () => {
  // Cited by sink-registry.js's own module header as the reason externality
  // must be category-derived, never entry-derived — this pin is what keeps
  // that header's claim honest against a future catalog.js change.
  const perEntryFields = ['host', 'url', 'provider', 'destination', 'externality', 'system'];
  for (const field of perEntryFields) {
    const withField = SINKS.filter((e) => field in e);
    assert.equal(withField.length, 0,
      `a live catalog.js sink entry now carries a '${field}' field — CATEGORY_EXTERNALITY's derivation justification may need re-checking`);
  }
});

// ───────────────────────────────────────────────────────────────────────────
// Totality — every entry gets a valid decision, none throws.
// ───────────────────────────────────────────────────────────────────────────

test('totality: every sink entry produces a valid, non-throwing, fully-shaped decision', () => {
  for (const e of SINKS) {
    const r = reclassifySink(e);
    assert.ok(NODE_KINDS.includes(r.kind), `${e.id}: bad node kind ${r.kind}`);
    assert.ok(COVERAGE_STATUS_VALUES.includes(r.coverageStatus), `${e.id}: bad coverageStatus ${r.coverageStatus}`);
    assert.notEqual(r.coverageStatus, 'manual', `${e.id}: a registry must never emit 'manual' (§6.5)`);
    assert.notEqual(r.coverageStatus, 'split', `${e.id}: 'split' is an internal marker only`);
    if (r.category !== null) assert.ok(SINK_CATEGORIES.includes(r.category), `${e.id}: ${r.category} not in SINK_CATEGORIES`);
    assert.ok(EXTERNALITY_VALUES.includes(r.externality), `${e.id}: bad externality ${r.externality}`);
    assert.ok(r.reason && r.reason.length > 0, `${e.id}: every decision must carry a reason (AC-11)`);
    assert.ok(!('subtype' in r), `${e.id}: a registry decision must never carry a literal 'subtype' field (§9.0)`);
  }
});

test('totality: every privacy-catalog entry produces a valid, non-throwing, fully-shaped decision', () => {
  for (const e of PRIVACY_SINK_CATALOG) {
    const r = reclassifyPrivacySink(e);
    assert.ok(NODE_KINDS.includes(r.kind), `${e.id}: bad node kind ${r.kind}`);
    assert.ok(COVERAGE_STATUS_VALUES.includes(r.coverageStatus), `${e.id}: bad coverageStatus ${r.coverageStatus}`);
    assert.notEqual(r.coverageStatus, 'manual', `${e.id}: a registry must never emit 'manual' (§6.5)`);
    if (r.category !== null) assert.ok(SINK_CATEGORIES.includes(r.category), `${e.id}: ${r.category} not in SINK_CATEGORIES`);
    assert.ok(EXTERNALITY_VALUES.includes(r.externality), `${e.id}: bad externality ${r.externality}`);
    assert.ok(r.reason && r.reason.length > 0, `${e.id}: every decision must carry a reason (AC-11)`);
    assert.ok(!('subtype' in r), `${e.id}: a registry decision must never carry a literal 'subtype' field (§9.0)`);
  }
});

// ───────────────────────────────────────────────────────────────────────────
// Node kind: category-derived, NOT uniformly `'sink'` (§7.1) — the
// `unsupported` → `process` preservation test, mirroring D1's own `D1/3c`.
// ───────────────────────────────────────────────────────────────────────────

test("D3/3c: sink node kinds are category-derived, and the biconditional kind === 'process' iff coverageStatus === 'unsupported' holds today", () => {
  // NOTE (documented fragility, per DESIGN_REGISTRIES.md §7.1's own boxed
  // note): this biconditional holds ONLY because `ai-local-model` — the
  // one OTHER category that maps to `process` — is vacuously unreachable
  // today (§7.2). Sub-project H's AC-07 closure made the FIRST ai-* sink
  // category reachable (`ai-model-provider`, via CWE-201), and the
  // biconditional survived it unchanged — measured, not assumed — precisely
  // because `CATEGORY_NODE_KIND['ai-model-provider']` is `'external'`, not
  // `'process'`. The moment an `ai-local-model` sink entry lands, that
  // sink will have `kind: 'process'` with a non-null category and a
  // non-`unsupported` status, and the REVERSE implication
  // (`kind === 'process'` ⟹ `unsupported`) becomes false — a correct
  // consequence of new coverage, not a regression, and NOT this task's
  // problem to fix. Asserted as a full biconditional here deliberately,
  // because until then it is true and catches more.
  const kinds = new Set(SINKS.map((e) => reclassifySink(e).kind));
  assert.deepEqual([...kinds].sort(), ['external', 'process', 'sink', 'store']);
  for (const e of SINKS) {
    const r = reclassifySink(e);
    if (r.coverageStatus === 'unsupported') assert.equal(r.kind, 'process', `${e.id}`);
    if (r.kind === 'process') assert.equal(r.coverageStatus, 'unsupported', `${e.id}`);
  }
});

// ───────────────────────────────────────────────────────────────────────────
// The `unsupported` → `process` preservation test (§9's D3 item 3) — proving
// these 82 entries are never dropped, mirroring D1's own `D1/5a`/`D1/5b`.
// ───────────────────────────────────────────────────────────────────────────

test('D3/preservation: a real entry with no confident mapping is `unsupported` and RETAINED as a `process` node, never dropped', () => {
  const e = byId.get('js-exec'); // child_process.exec, CWE-78
  assert.ok(e);
  const r = reclassifySink(e);
  assert.equal(r.category, null);
  assert.equal(r.coverageStatus, 'unsupported');
  assert.equal(r.kind, 'process');             // still a graph node — AC-11
  assert.match(r.reason, /process execution/);  // with a coverage reason — AC-11
});

test('D3/preservation: every `unsupported` sink entry carries a non-empty reason (no silent drop is possible)', () => {
  const unsupported = SINKS.map(reclassifySink).filter((r) => r.coverageStatus === 'unsupported');
  assert.equal(unsupported.length, 82);
  for (const r of unsupported) {
    assert.equal(r.kind, 'process');
    assert.ok(r.reason && r.reason.length > 0);
    assert.equal(r.category, null);
    assert.equal(r.externality, 'internal');
  }
});

// ───────────────────────────────────────────────────────────────────────────
// The CWE-79 refinement (§5.2) — its own dedicated tests.
// ───────────────────────────────────────────────────────────────────────────

test('CWE-79 refinement: DOM/React sinks are `client-storage`/`partial`; every other framework is `http-response`/`modeled`', () => {
  const cwe79 = SINKS.filter((e) => e.vuln?.cwe === 'CWE-79');
  assert.equal(cwe79.length, 16);
  let domCount = 0;
  let otherCount = 0;
  for (const e of cwe79) {
    const r = reclassifySink(e);
    if (DOM_FRAMEWORKS.has(e.framework)) {
      domCount += 1;
      assert.equal(r.category, 'client-storage', e.id);
      assert.equal(r.coverageStatus, 'partial', e.id);
      assert.equal(r.kind, 'store', e.id);
    } else {
      otherCount += 1;
      assert.equal(r.category, 'http-response', e.id);
      assert.equal(r.coverageStatus, 'modeled', e.id);
      assert.equal(r.kind, 'sink', e.id);
    }
  }
  assert.equal(domCount, 6);   // 4 dom + 2 react
  assert.equal(otherCount, 10);
});

// ───────────────────────────────────────────────────────────────────────────
// Representative real reclassifications, end to end — mixed CWE / language /
// framework.
// ───────────────────────────────────────────────────────────────────────────

test('representative real entries produce the stated (kind, category, coverageStatus) triples', () => {
  const expected = [
    // id                              kind        category           coverageStatus
    ['js-sql-query',                   'store',    'database',        'modeled'],
    ['js-fetch',                       'external', 'external-api',    'modeled'],
    ['js-fs-readFile',                 'store',    'file',            'modeled'],
    ['js-res-redirect',                'sink',     'http-response',   'modeled'],
    ['js-response-setheader',          'sink',     'http-response',   'modeled'],
    ['js-innerHTML-assign',            'store',    'client-storage',  'partial'],
    ['js-express-res-send',            'sink',     'http-response',   'modeled'],
    ['java-ldap-search',               'store',    'database',        'candidate'],
    ['js-exec',                        'process',  null,              'unsupported'],
    ['js-execSync',                    'process',  null,              'unsupported'],
  ];
  for (const [id, kind, category, status] of expected) {
    const e = byId.get(id);
    assert.ok(e, `catalog entry ${id} no longer exists — the sample needs updating`);
    const r = reclassifySink(e);
    assert.equal(r.kind, kind, `${id}: kind`);
    assert.equal(r.category, category, `${id}: category`);
    assert.equal(r.coverageStatus, status, `${id}: coverageStatus`);
  }
});

test('AC-07 closure: all 4 new AI-model-provider entries reclassify to ai-model-provider/modeled/external', () => {
  for (const id of ['js-openai-chat-completions-create', 'js-openai-responses-create', 'js-anthropic-messages-create', 'js-bedrock-invoke-model-command']) {
    const entry = byId.get(id);
    assert.ok(entry, `${id} must exist in CATALOG`);
    assert.equal(entry.vuln.cwe, 'CWE-201', `${id}: CWE-359 is FORBIDDEN here — see completeness/1c`);
    const decision = reclassifySink(entry);
    assert.equal(decision.category, 'ai-model-provider');
    assert.equal(decision.coverageStatus, 'modeled');
    assert.equal(decision.externality, 'external');
    assert.equal(decision.kind, 'external');
  }
});

// ───────────────────────────────────────────────────────────────────────────
// The privacy-catalog reconciliation, on real entries (mirrors D1's own
// D1/4a-D1/4d).
// ───────────────────────────────────────────────────────────────────────────

test('D3/4a: at least one real entry from EVERY privacy category resolves to a SINK_CATEGORIES value', () => {
  const expected = {
    'log': 'log',
    'response': 'http-response',
    'outboundHttp': 'external-api',
    'thirdPartySdk': 'analytics',
    'fileWrite': 'file',
    's3Upload': 'object-storage',
    'emailSend': 'email',
    'storage': 'database',
    'queues': 'queue',
  };
  assert.deepEqual(Object.keys(expected).sort(), [...PRIVACY_SINK_CATEGORIES].sort());
  for (const [cat, want] of Object.entries(expected)) {
    const entry = PRIVACY_SINK_CATALOG.find((e) => e.category === cat);
    assert.ok(entry, `no privacy entry uses category ${cat}`);
    assert.equal(reclassifyPrivacySink(entry).category, want, `privacy ${cat}`);
  }
});

test("D3/4b: `storage` does NOT split today — proven from the real entries, not assumed", () => {
  // The scoping doc anticipated `storage` splitting across
  // database/object-storage/cache. Both entries that actually carry it are
  // mongodb inserts, so it resolves 1:1 to `database`. A future redis/S3
  // entry filed under `storage` must fail loudly instead of being silently
  // mis-mapped to `database` — this test is the guard.
  const entries = PRIVACY_SINK_CATALOG.filter((e) => e.category === 'storage');
  assert.equal(entries.length, 2);
  for (const e of entries) {
    assert.match(e.framework, /^mongodb$/);
    assert.equal(reclassifyPrivacySink(e).category, 'database');
    assert.equal(reclassifyPrivacySink(e).coverageStatus, 'modeled');
  }
});

// ───────────────────────────────────────────────────────────────────────────
// The `thirdPartySdk` open-item test (§9's D3 item 4) — proving it resolves
// to `partial` with a DISCLOSED-ambiguity reason, never a silent guess.
// ───────────────────────────────────────────────────────────────────────────

test("D3/thirdPartySdk: resolves to `analytics`/`partial` with a disclosed-ambiguity reason, never a silent guess", () => {
  const entries = PRIVACY_SINK_CATALOG.filter((e) => e.category === 'thirdPartySdk');
  assert.equal(entries.length, 2);
  for (const e of entries) {
    const r = reclassifyPrivacySink(e);
    assert.equal(r.category, 'analytics');
    assert.equal(r.coverageStatus, 'partial');
    // The reason must actually disclose the ambiguity and the other
    // candidate categories a match-time consumer could resolve to — never
    // a bare "analytics" claim with no caveat.
    assert.match(r.reason, /monitoring/);
    assert.match(r.reason, /external-api/);
    assert.match(r.reason, /collaboration/);
    assert.match(r.reason, /match time/i);
  }
  // Real evidence for the disclosed ambiguity: the receiver alternation
  // really does span all four categories' providers.
  const e = entries[0];
  const recv = e.match.receiverTypeIn[0];
  for (const provider of ['sentry', 'datadog', 'stripe', 'intercom', 'segment']) {
    assert.ok(recv.includes(provider), `expected ${provider} in the receiver alternation`);
  }
});

// ───────────────────────────────────────────────────────────────────────────
// FR-203 (§9's D3 item 5) — its own dedicated tests, kept structurally
// distinct from the UNRELATED §16.7 degraded-analysis `unresolved` case.
// ───────────────────────────────────────────────────────────────────────────

test('D3/FR-203: a recognized sink whose destination cannot be resolved gets kind `unresolved`, retained category, externality `unknown`, and a reason naming the blocking expression', () => {
  const e = byId.get('js-fetch'); // CWE-918 -> external-api, modeled
  assert.ok(e);
  const base = reclassifySink(e);
  assert.equal(base.category, 'external-api');
  assert.equal(base.coverageStatus, 'modeled');

  const r = reclassifySink(e, { destinationUnresolved: true, blockingExpression: 'fetch(url)' });
  assert.equal(r.kind, 'unresolved');
  assert.equal(r.category, 'external-api', 'category is RETAINED, never nulled');
  assert.equal(r.externality, 'unknown');
  assert.equal(r.coverageStatus, 'modeled', 'coverageStatus is UNCHANGED from the category mapping (a different axis than destination resolution)');
  assert.match(r.reason, /fetch\(url\)/, 'reason names the blocking expression');
});

test('D3/FR-203: coverageStatus carries over whatever the category mapping assigned — proven for both `modeled` and `partial` base entries', () => {
  // A `partial` base entry (js-innerHTML-assign: client-storage, partial)
  // stays `partial` under FR-203 too — this is the field-by-field proof
  // that coverageStatus tracks the CATEGORY mapping, not a fixed constant
  // the FR-203 branch invents.
  const e = byId.get('js-innerHTML-assign');
  const r = reclassifySink(e, { destinationUnresolved: true, blockingExpression: 'el.innerHTML = expr' });
  assert.equal(r.kind, 'unresolved');
  assert.equal(r.category, 'client-storage');
  assert.equal(r.coverageStatus, 'partial');
  assert.equal(r.externality, 'unknown');
});

test('D3/FR-203: an unsupported (null-category) sink is NEVER pushed into `unresolved` — it must stay `process`/`unsupported`, preserving the D1/3c biconditional', () => {
  const e = byId.get('js-exec'); // CWE-78, unsupported
  const r = reclassifySink(e, { destinationUnresolved: true, blockingExpression: 'exec(cmd)' });
  // destinationUnresolved is IGNORED here: there is no category to retain,
  // and letting this branch fire would break kind === 'process' iff
  // coverageStatus === 'unsupported' (coverageStatus would stay
  // 'unsupported' while kind became 'unresolved' instead of 'process').
  assert.equal(r.kind, 'process');
  assert.equal(r.coverageStatus, 'unsupported');
  assert.equal(r.category, null);
});

test('D3/opts-null (task review N4): reclassifySink(entry, null) does not throw — an explicit `null` second argument is treated the same as omitting it', () => {
  const e = byId.get('js-exec');
  assert.doesNotThrow(() => reclassifySink(e, null));
  assert.deepEqual(reclassifySink(e, null), reclassifySink(e));
});

test('D3/FR-203 vs §16.7: the two `unresolved`-kind cases are structurally DISTINCT, never conflated', () => {
  // §16.7's degraded-analysis case (DESIGN_PATH_PROVENANCE.md §16.7 Finding
  // 2, carried forward as binding on Sub-project D by DESIGN_REGISTRIES.md's
  // own "Carried forward from Sub-project C" section) is produced ELSEWHERE
  // entirely — a future Sub-project E graph builder reading path-store.js's
  // diagnostics for a truncation-terminal node, never this registry. It is
  // reproduced here ONLY as the literal shape the design doc specifies, to
  // prove FR-203's own output is distinguishable from it on the one field
  // that actually differs: `coverageStatus`.
  const degradedAnalysisShape = Object.freeze({
    kind: 'unresolved',
    coverageStatus: 'partial',          // ALWAYS partial — no category mapping behind it at all
    externality: 'unknown',
    reason: 'context-cap degradation: callee body was never analyzed',
  });

  // A MODELED sink (not partial) run through FR-203 must keep its OWN
  // coverageStatus (`modeled`) — proving the two cases cannot be
  // distinguished by `kind`/`externality` alone (both share those two
  // values) but ARE distinguishable by `coverageStatus`, which is exactly
  // the field DESIGN_REGISTRIES.md §9's D3 item 5 says must not be
  // conflated.
  const fr203Shape = reclassifySink(byId.get('js-fetch'), {
    destinationUnresolved: true, blockingExpression: 'fetch(url)',
  });

  assert.equal(fr203Shape.kind, degradedAnalysisShape.kind, 'both share kind: unresolved');
  assert.equal(fr203Shape.externality, degradedAnalysisShape.externality, 'both share externality: unknown');
  assert.notEqual(
    fr203Shape.coverageStatus, degradedAnalysisShape.coverageStatus,
    'FR-203 (modeled sink) must NOT collapse to §16.7\'s unconditional partial — they are different axes (§9 D3 item 5)',
  );
  assert.equal(fr203Shape.coverageStatus, 'modeled');
  assert.equal(degradedAnalysisShape.coverageStatus, 'partial');
});

// ───────────────────────────────────────────────────────────────────────────
// Pinned coverage counts — equality, not a floor (bench/layer-recall has
// already shown in this repo that a floor-only gate lets a stale published
// number survive silently for weeks).
// ───────────────────────────────────────────────────────────────────────────

test('pinned sink coverage counts: 101 modeled / 6 partial / 9 candidate / 82 unsupported', () => {
  // 194 -> 198 entries and 97 -> 101 modeled: Sub-project H's AC-07 closure
  // added the four CWE-201 AI-model-provider sink entries (OpenAI
  // chat.completions/responses, Anthropic messages, Bedrock
  // InvokeModelCommand). Re-measured against the live catalog, not adjusted
  // by arithmetic.
  const results = SINKS.map((e) => reclassifySink(e));
  assert.equal(SINKS.length, 198);
  assert.equal(results.filter((r) => r.coverageStatus === 'modeled').length, 101);
  assert.equal(results.filter((r) => r.coverageStatus === 'partial').length, 6);      // the 6 DOM/React CWE-79 entries
  assert.equal(results.filter((r) => r.coverageStatus === 'candidate').length, 9);    // the 9 CWE-90 LDAP entries
  assert.equal(results.filter((r) => r.coverageStatus === 'unsupported').length, 82);
  assert.equal(101 + 6 + 9 + 82, SINKS.length);
});

test('pinned privacy-catalog coverage counts: 16 modeled / 2 partial / 0 candidate / 0 unsupported', () => {
  const results = PRIVACY_SINK_CATALOG.map((e) => reclassifyPrivacySink(e));
  assert.equal(PRIVACY_SINK_CATALOG.length, 18);
  assert.equal(results.filter((r) => r.coverageStatus === 'modeled').length, 16);
  assert.equal(results.filter((r) => r.coverageStatus === 'partial').length, 2);   // both thirdPartySdk entries
  assert.equal(results.filter((r) => r.coverageStatus === 'candidate').length, 0);
  assert.equal(results.filter((r) => r.coverageStatus === 'unsupported').length, 0);
  assert.equal(16 + 2, PRIVACY_SINK_CATALOG.length);
});

// ───────────────────────────────────────────────────────────────────────────
// Unreachable SINK_CATEGORIES — the disclosed gap (§7.2), pinned as an exact
// list so it cannot go stale silently. Mirrors D1's own D1/6b.
// ───────────────────────────────────────────────────────────────────────────

test('unreachable sink categories match the pinned list from DESIGN_REGISTRIES.md §7.2 — all ai-* EXCEPT ai-model-provider, closed by the AC-07 catalog bridge', () => {
  const reachable = new Set([
    ...SINKS.map((e) => reclassifySink(e).category),
    ...PRIVACY_SINK_CATALOG.map((e) => reclassifyPrivacySink(e).category),
  ].filter(Boolean));
  const unreachable = SINK_CATEGORIES.filter((c) => !reachable.has(c)).sort();
  assert.deepEqual(unreachable, [
    'ai-agent', 'ai-evaluation', 'ai-local-model', 'ai-memory',
    'ai-telemetry', 'ai-tool', 'ai-training',
    'ai-vector-store', 'backup', 'cache', 'collaboration', 'declared',
    'export', 'monitoring', 'push-notification', 'sms', 'stdout', 'webhook',
  ], 'sink-side coverage gap changed — re-read DESIGN_REGISTRIES.md §7.2');
  assert.equal(reachable.size, 11);
  const aiSinks = SINK_CATEGORIES.filter((c) => c.startsWith('ai-'));
  assert.equal(aiSinks.length, 9);
  for (const c of aiSinks) {
    if (c === 'ai-model-provider') { assert.ok(reachable.has(c), 'ai-model-provider must now be reachable — AC-07 closure'); continue; }
    assert.ok(!reachable.has(c), `${c} unexpectedly reachable`);
  }
});

test('the category vocabularies are 21 source / 29 sink — SINK_CATEGORIES has 29 values, not 28', () => {
  assert.equal(SINK_CATEGORIES.length, 29);
  assert.equal(new Set(SINK_CATEGORIES).size, 29, 'no duplicate hiding the count');
});

// ───────────────────────────────────────────────────────────────────────────
// Externality (§7.5's CATEGORY_EXTERNALITY, fully specified by D1).
// ───────────────────────────────────────────────────────────────────────────

test('externality is present on every decision and drawn from EXTERNALITY_VALUES', () => {
  for (const e of SINKS) {
    const r = reclassifySink(e);
    assert.ok(EXTERNALITY_VALUES.includes(r.externality), `${e.id}: ${r.externality}`);
  }
  for (const e of PRIVACY_SINK_CATALOG) {
    const r = reclassifyPrivacySink(e);
    assert.ok(EXTERNALITY_VALUES.includes(r.externality), `${e.id}: ${r.externality}`);
  }
});

test('externality: an unsupported/process sink is `internal` — the asymmetric opposite of the source-side unsupported fallback', () => {
  const e = byId.get('js-exec');
  assert.equal(reclassifySink(e).externality, 'internal');
});

test('externality: store-shaped categories (database/file/object-storage/etc.) match CATEGORY_EXTERNALITY exactly', () => {
  assert.equal(reclassifySink(byId.get('js-sql-query')).externality, 'unknown');  // database
  assert.equal(reclassifySink(byId.get('js-fs-readFile')).externality, 'internal'); // file
  assert.equal(reclassifyPrivacySink(PRIVACY_SINK_CATALOG.find((e) => e.category === 's3Upload')).externality, 'unknown'); // object-storage
});

test('externality: remote-party categories are external', () => {
  assert.equal(reclassifySink(byId.get('js-fetch')).externality, 'external'); // external-api
  assert.equal(reclassifyPrivacySink(PRIVACY_SINK_CATALOG.find((e) => e.category === 'emailSend')).externality, 'external'); // email
});

test('CATEGORY_EXTERNALITY exactly equals SINK_CATEGORIES, both directions — total over the whole schema vocabulary', () => {
  assert.deepEqual(Object.keys(CATEGORY_EXTERNALITY).sort(), [...SINK_CATEGORIES].sort());
});

test('CATEGORY_NODE_KIND exactly equals SINK_CATEGORIES, both directions', () => {
  assert.deepEqual(Object.keys(CATEGORY_NODE_KIND).sort(), [...SINK_CATEGORIES].sort());
});
