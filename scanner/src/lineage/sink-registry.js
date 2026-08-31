//
// sink-registry.js — Data Flow Explorer, Sub-project D, increment D3.
//
// Reclassifies TWO separate catalogs into DataFlowGraph v1's
// `SINK_CATEGORIES` / `coverageStatus` vocabulary (`schema.js`):
//   - scanner/src/dataflow/catalog.js's `kind: 'sink'` entries (194 as of
//     this writing — re-derive via `CATALOG.filter(e => e.kind ===
//     'sink').length` rather than trusting this comment; the
//     dataflow/CLAUDE.md count has already drifted twice), keyed on
//     `vuln.cwe` — reclassifySink(entry).
//   - scanner/src/dataflow/privacy-catalog.js's PRIVACY_SINK_CATALOG (18
//     entries), keyed on `category` — reclassifyPrivacySink(entry).
//
// TWO separate functions, deliberately, not a unified dispatcher: the two
// catalogs key on different fields (DESIGN_REGISTRIES.md §2.1), and
// privacy-catalog.js is deliberately NOT merged into CATALOG (merging it
// would make every already-active general source spuriously trigger
// privacy-leak findings — see that file's own header). Reclassifying the two
// through separate functions respects that boundary; a unified dispatcher
// would have to re-merge them internally to work at all.
//
// This module is the MECHANICAL implementation of a binding, independently
// reviewed design — it is not a fresh design decision (except where noted
// below for FR-203, which the design specifies field-by-field but not as
// runnable code). Every mapping row traces to `DESIGN_REGISTRIES.md`:
//   §5.1  — CWE_MAP, the primary sink-side mapping (keyed on `vuln.cwe`,
//           21 rows — 20 from D1, plus CWE-201 added by Sub-project H's
//           AC-07 closure).
//   §5.2  — the CWE-79 `framework` refinement: DOM/React sinks are
//           `client-storage` (partial); every other framework is
//           `http-response` (modeled).
//   §5.3  — PRIVACY_CATEGORY_MAP, the privacy-catalog mapping (9 rows).
//           `thirdPartySdk` is the one entry that DOES split at match time
//           and cannot be resolved by a registry at all — see item 4 below.
//   §6    — the `coverageStatus` decision procedure (modeled/partial/
//           candidate/unsupported — never `manual`, §6.5).
//   §7.1  — CATEGORY_NODE_KIND: sink-side node kind is category-derived,
//           NOT uniformly `'sink'` (unlike D2's uniform `'source'`). A
//           `null` category (`unsupported`) always yields `'process'`, and
//           `kind === 'process'` iff `coverageStatus === 'unsupported'`
//           (D1/3c's biconditional — contingent, per §7.1's own boxed note,
//           on no AI-sink detection existing yet; not this task's problem
//           to fix, but this module's own FR-203 branch below must not
//           accidentally break it).
//   §7.5  — CATEGORY_EXTERNALITY: category-derived, with the null-category
//           (`unsupported`/`process`) fallback hardcoded to `'internal'` —
//           the asymmetric OPPOSITE of source-registry.js's own
//           unsupported fallback (`'unknown'`), per §7.5's own
//           "2026-08-31 implementation note (D2, Task 1)" asymmetry #1: a
//           sink's unsupported call site is still IN this program
//           (genuinely internal); a source's unsupported construct is one
//           we don't even understand (no honest internal claim to make).
//   §9.0  — the shared `{kind, category, coverageStatus, externality,
//           reason}` decision shape. `category` is this module's OWN field
//           name — never a field literally called `subtype` (that's
//           Sub-project E's graph builder's job, writing this decision's
//           `category` onto `node.subtype`).
//   §9's D3 checklist item 3 — the `unsupported` → `process` node with its
//           reason string must be PRESERVED, never dropped (the single
//           easiest way to violate AC-11/FR-201, per that item's own text).
//   §9's D3 checklist item 4 — `thirdPartySdk` is a known, disclosed open
//           item: resolves to `analytics` (the plurality of its receiver
//           alternation) with `coverageStatus: 'partial'`, never a silent,
//           undisclosed guess. A later match-time consumer that knows which
//           receiver actually matched (segment/amplitude/mixpanel/posthog →
//           analytics; sentry/datadog → monitoring; stripe → external-api;
//           intercom/braze → collaboration) can promote `partial` →
//           `modeled` — this registry cannot, since it reclassifies
//           ENTRIES, never match-site receivers.
//   §9's D3 checklist item 5 — FR-203: closed below. See the dedicated
//           comment on `reclassifySink`'s `opts.destinationUnresolved`
//           branch for the full reasoning, including how it is kept
//           DISTINCT from the unrelated, already-shipped §16.7
//           degraded-analysis `unresolved` case (a different module
//           entirely — a future Sub-project E graph builder reading
//           `path-store.js` diagnostics, never this registry).
//           DISCLOSED ASYMMETRY: `reclassifyPrivacySink` has no equivalent
//           `opts.destinationUnresolved` parameter. Item 5's own text names
//           only `reclassifySink`; nothing in the design scopes FR-203 out
//           of the privacy side, and the design's own worked examples
//           (a fetch() call with a computed URL) map onto privacy
//           categories like `outboundHttp`/`thirdPartySdk` just as
//           plausibly as onto a general CATALOG sink. Left unresolved here,
//           not silently — no consumer exists yet to need it (Sub-project E
//           hasn't landed), so there was nothing to prove this signature
//           against; closing it is deferred to whichever increment adds
//           the first real caller.
//
// Pure reclassification layer: reads catalog entries as DATA and maps them
// onto the target vocabulary. It never re-derives what a call site
// matches — `matchSinkOrSanitizer()` / `matchPrivacySink()` already own
// that, and duplicating it here would fork a matcher the corpus proves
// against one that nothing proves (DESIGN_REGISTRIES.md §1).
//
// Isolation: imports ONLY `CATALOG` from ../dataflow/catalog.js and the
// privacy catalog's own exports from ../dataflow/privacy-catalog.js.
// Never dataflow/engine.js, never dataflow/summaries.js, never matcher
// internals (this PRD's §18.1 isolation principle, the same basis
// source-registry.js and Sub-project A/B/C use for their own `dataflow/`
// reuse).

import { CATALOG } from '../dataflow/catalog.js';
import { PRIVACY_SINK_CATALOG } from '../dataflow/privacy-catalog.js';

// ─────────────────────────────────────────────────────────────────────────
// §5.1 — CWE_MAP: the primary sink-side mapping, keyed on the entry's
// `vuln.cwe` field (21 rows). A `null` category is NOT a dropped entry —
// see §6.4: it is retained with node kind `process` and a stated reason,
// which is what AC-11 / FR-201 require.
// ─────────────────────────────────────────────────────────────────────────

export const CWE_MAP = Object.freeze({
  'CWE-89':   Object.freeze({ category: 'database',      status: 'modeled',     why: 'a SQL query call is unambiguously a database destination' }),
  'CWE-943':  Object.freeze({ category: 'database',      status: 'modeled',     why: 'NoSQL $where — still a database destination' }),
  'CWE-22':   Object.freeze({ category: 'file',          status: 'modeled',     why: 'path traversal sinks are filesystem reads/writes' }),
  'CWE-73':   Object.freeze({ category: 'file',          status: 'modeled',     why: 'arbitrary file write' }),
  'CWE-918':  Object.freeze({ category: 'external-api',  status: 'modeled',     why: 'SSRF sinks are outbound HTTP client calls' }),
  'CWE-601':  Object.freeze({ category: 'http-response', status: 'modeled',     why: 'a redirect is written as a response header' }),
  'CWE-113':  Object.freeze({ category: 'http-response', status: 'modeled',     why: 'response splitting — the sink IS the response header writer' }),
  // The sink side's ONE documented refinement (§5.2). `status: 'split'` is
  // an INTERNAL marker only — reclassifySink() intercepts it before it can
  // ever reach a caller as a coverageStatus (mirrors PROVENANCE_MAP's own
  // `agent-tool` row in source-registry.js).
  'CWE-79':   Object.freeze({ category: null,            status: 'split',       why: "REFINED ON `framework`: browser-DOM sinks and server-side response writers are different destinations" }),
  'CWE-90':   Object.freeze({ category: 'database',      status: 'candidate',   why: 'an LDAP directory is a queryable store, structurally like a DB, but FR-201 never names directory services' }),
  // AC-07 closure (Sub-project H): the AI-sink catalog bridge. CWE-201
  // (Insertion of Sensitive Information Into Sent Data) is the general
  // CATALOG's own key for the four OpenAI/Anthropic/Bedrock sink entries.
  // Deliberately NOT CWE-359 — that CWE belongs exclusively to
  // PRIVACY_SINK_CATALOG's "Privacy Leak" family, and this file's own
  // `completeness/1c` test fails the build if CWE_MAP ever maps it.
  'CWE-201':  Object.freeze({ category: 'ai-model-provider', status: 'modeled', why: 'a call to a named AI model provider SDK (OpenAI/Anthropic/Bedrock) is unambiguously an AI-model-provider destination' }),
  // Everything below: the data's destination is IN-PROCESS COMPUTATION (an
  // interpreter, parser, template engine, regex engine, loader, or raw
  // memory). FR-201's category list is an EGRESS taxonomy and models none
  // of them — the single largest structural finding of D1 (§3/§7.1).
  'CWE-78':   Object.freeze({ category: null, status: 'unsupported', why: 'shell/process execution — no FR-201 category models process execution' }),
  'CWE-95':   Object.freeze({ category: null, status: 'unsupported', why: 'code evaluation (eval/Function/exec/compile) — destination is an interpreter' }),
  'CWE-94':   Object.freeze({ category: null, status: 'unsupported', why: 'code injection / template compilation — destination is an interpreter or template engine' }),
  'CWE-1336': Object.freeze({ category: null, status: 'unsupported', why: 'SSTI — destination is a template engine, not a data destination' }),
  'CWE-502':  Object.freeze({ category: null, status: 'unsupported', why: 'deserialization — destination is a deserializer' }),
  'CWE-611':  Object.freeze({ category: null, status: 'unsupported', why: 'XXE — destination is an XML parser' }),
  'CWE-643':  Object.freeze({ category: null, status: 'unsupported', why: 'XPath injection — destination is a query engine over an in-memory document' }),
  'CWE-120':  Object.freeze({ category: null, status: 'unsupported', why: 'buffer overflow — destination is raw memory' }),
  'CWE-787':  Object.freeze({ category: null, status: 'unsupported', why: 'out-of-bounds write — destination is raw memory' }),
  'CWE-1333': Object.freeze({ category: null, status: 'unsupported', why: 'ReDoS — destination is the regex engine' }),
  'CWE-114':  Object.freeze({ category: null, status: 'unsupported', why: 'untrusted library load — destination is the dynamic loader' }),
});

// §5.2 — CWE-79's refinement key. FR-201 lumps "browser DOM or client
// storage" into one SINK_CATEGORIES value (`client-storage`), which
// correctly targets the PRD's own bullet but under-names the DOM half —
// disclosed via `status: 'partial'`, never silently upgraded to `modeled`
// (DESIGN_REGISTRIES.md §7.4(b); not this task's to patch).
export const DOM_FRAMEWORKS = new Set(['dom', 'react']);

// ─────────────────────────────────────────────────────────────────────────
// §7.1 — CATEGORY_NODE_KIND: sink category → node kind. Every sink category
// any catalog can currently produce, plus the in-process fallback
// (`null` category → `'process'`, handled directly in the functions below,
// not via this table).
// ─────────────────────────────────────────────────────────────────────────

export const CATEGORY_NODE_KIND = Object.freeze({
  'log': 'log', 'stdout': 'log',
  'http-response': 'sink',
  'database': 'store', 'file': 'store', 'object-storage': 'store',
  'cache': 'store', 'client-storage': 'store', 'backup': 'store', 'export': 'store',
  'queue': 'queue',
  'external-api': 'external', 'webhook': 'external', 'email': 'external',
  'sms': 'external', 'push-notification': 'external', 'collaboration': 'external',
  'analytics': 'external', 'monitoring': 'external',
  'ai-model-provider': 'external', 'ai-agent': 'external', 'ai-tool': 'external',
  'ai-vector-store': 'external', 'ai-memory': 'external', 'ai-training': 'external',
  'ai-evaluation': 'external', 'ai-telemetry': 'external',
  'ai-local-model': 'process',
  'declared': 'sink',
});

// ─────────────────────────────────────────────────────────────────────────
// §7.5 — CATEGORY_EXTERNALITY: sink category → externality. Fully specified
// by D1 (unlike source-registry.js's SOURCE_CATEGORY_EXTERNALITY, which D2
// had to build fresh — see that module's own header for why). The
// null-category (`unsupported`/`process`) case is handled directly in the
// functions below as a hardcoded `'internal'`, not via this table — a
// sink's unsupported call site is still IN this program, genuinely
// internal, the asymmetric opposite of the source side's `'unknown'`.
// ─────────────────────────────────────────────────────────────────────────

export const CATEGORY_EXTERNALITY = Object.freeze({
  'log': 'internal', 'stdout': 'internal', 'http-response': 'internal',
  'file': 'internal', 'client-storage': 'internal',
  'database': 'unknown', 'object-storage': 'unknown', 'cache': 'unknown',
  'queue': 'unknown', 'backup': 'unknown', 'export': 'unknown',
  'external-api': 'external', 'webhook': 'external', 'email': 'external',
  'sms': 'external', 'push-notification': 'external', 'collaboration': 'external',
  'analytics': 'external', 'monitoring': 'external',
  'ai-model-provider': 'external', 'ai-agent': 'external', 'ai-tool': 'external',
  'ai-vector-store': 'external', 'ai-memory': 'external', 'ai-training': 'external',
  'ai-evaluation': 'external', 'ai-telemetry': 'external', 'ai-local-model': 'internal',
  'declared': 'unknown',
});

// ─────────────────────────────────────────────────────────────────────────
// §5.3 — PRIVACY_CATEGORY_MAP: the privacy-catalog mapping, keyed on the
// entry's `category` field (9 rows — confirmed against the live
// privacy-catalog.js's PRIVACY_SINK_CATEGORIES, NINE, not the eight the
// scoping doc originally assumed; see this module's own test suite's
// completeness guard).
// ─────────────────────────────────────────────────────────────────────────

export const PRIVACY_CATEGORY_MAP = Object.freeze({
  'log':          Object.freeze({ category: 'log',            status: 'modeled', why: 'console/logger calls' }),
  'response':     Object.freeze({ category: 'http-response',  status: 'modeled', why: 'res.send / res.json' }),
  'outboundHttp': Object.freeze({ category: 'external-api',   status: 'modeled', why: 'fetch / axios.post' }),
  'fileWrite':    Object.freeze({ category: 'file',           status: 'modeled', why: 'fs.writeFile / writeFileSync' }),
  's3Upload':     Object.freeze({ category: 'object-storage', status: 'modeled', why: 's3.putObject' }),
  'emailSend':    Object.freeze({ category: 'email',          status: 'modeled', why: 'nodemailer sendMail' }),
  'storage':      Object.freeze({ category: 'database',       status: 'modeled', why: 'both current entries are mongodb insertOne/insertMany with a collection|db|mongo receiver — the name is broader than its entries, but nothing splits TODAY (D1/4b, proven against real entries)' }),
  'queues':       Object.freeze({ category: 'queue',          status: 'modeled', why: "sqs sendMessage / sns|kafka publish; FR-201's `queue` covers 'queues, topics, streams, and event buses'" }),
  // §9's D3 checklist item 4: a KNOWN, DISCLOSED open item, never a silent
  // guess. The single receiverTypeIn alternation
  // (stripe|sentry|datadog|segment|amplitude|mixpanel|posthog|braze|
  // intercom|analytics) spans FOUR SINK_CATEGORIES values — analytics
  // (segment/amplitude/mixpanel/posthog), monitoring (sentry/datadog),
  // external-api (stripe), collaboration (intercom/braze) — and which one
  // is correct is only decidable AT MATCH TIME, from the receiver that
  // actually matched: information a registry reclassifying ENTRIES never
  // sees. Resolves to `analytics` (the plurality) with `coverageStatus:
  // 'partial'`, so the ambiguity is visible on every node this produces,
  // never hidden behind a confident `modeled`. A later match-time consumer
  // that knows which receiver fired can promote `partial` → `modeled`.
  'thirdPartySdk': Object.freeze({ category: 'analytics', status: 'partial', why: 'DISCLOSED OPEN ITEM, not a silent guess: the receiverTypeIn alternation also matches sentry|datadog (monitoring), stripe (external-api) and intercom|braze (collaboration) — the true category is only decidable at MATCH TIME from the matched receiver, which a registry reclassifying ENTRIES never sees. A match-time consumer that knows the matched receiver can promote this partial to modeled.' }),
});

/**
 * Reclassify a single `kind: 'sink'` catalog entry (from CATALOG) into
 * DataFlowGraph v1's vocabulary. Total: every entry gets a decision, none
 * throws, none is silently dropped (§6). `kind` is category-derived, NOT
 * uniformly `'sink'` (§7.1) — a `null` category (`unsupported`) always
 * yields `'process'`, never dropped, always carrying a non-empty `reason`
 * (§9's D3 item 3 / AC-11).
 *
 * @param {object} entry a CATALOG entry with `kind === 'sink'`
 * @param {object} [opts]
 * @param {boolean} [opts.destinationUnresolved] FR-203 (§9's D3 item 5):
 *   set by a FUTURE per-call-site caller (Sub-project E's graph builder —
 *   no catalog entry carries per-call-site destination information, §7.5,
 *   so this can never be true from CATALOG data alone today) when the
 *   RECOGNIZED sink's actual destination could not be statically resolved
 *   (`fetch(url)` with a computed `url`; an SDK client built from config).
 *   Ignored when the entry's own category is unmapped (`null`) — see the
 *   branch below for why.
 * @param {string} [opts.blockingExpression] the expression that prevented
 *   resolution, named in the returned `reason` (FR-203 requires the
 *   evidence panel to show it).
 * @returns {{kind: string, category: string|null, coverageStatus: string, externality: string, reason: string}}
 */
export function reclassifySink(entry, opts = {}) {
  opts = opts ?? {}; // guard an explicit `null` too, not just `undefined`
  const cwe = entry.vuln?.cwe ?? '<<none>>';
  let row = CWE_MAP[cwe];
  if (!row) {
    // Defensive fallback only — D1/1c-equivalent completeness guard below
    // proves every real CATALOG sink CWE is mapped, so this is unreachable
    // from live data. A future genuinely-new CWE must fail that guard
    // loudly, not this function silently.
    return {
      kind: 'process', category: null, coverageStatus: 'unsupported',
      externality: 'internal', reason: `unmapped CWE ${cwe}`,
    };
  }
  if (row.status === 'split') {
    // The single documented refinement on the sink side (§5.2).
    row = DOM_FRAMEWORKS.has(entry.framework)
      ? { category: 'client-storage', status: 'partial', why: "LOSSY: the destination is the rendered browser DOM; schema.js's `client-storage` is its encoding of FR-201's 'browser DOM or client storage' bullet, and under-names the DOM half" }
      : { category: 'http-response', status: 'modeled', why: 'a server-side response writer (res.send / PrintWriter / echo / Fprintf)' };
  }

  const category = row.category;
  const kind = category === null ? 'process' : (CATEGORY_NODE_KIND[category] ?? 'sink');
  const externality = category === null ? 'internal' : (CATEGORY_EXTERNALITY[category] ?? 'unknown');
  const base = { kind, category, coverageStatus: row.status, externality, reason: row.why };

  // FR-203 (§9's D3 item 5) — CLOSED here, and kept structurally distinct
  // from the UNRELATED, already-shipped §16.7 degraded-analysis
  // `unresolved` case (DESIGN_PATH_PROVENANCE.md §16.7 Finding 2, carried
  // forward as binding on Sub-project D; produced elsewhere entirely — a
  // FUTURE Sub-project E graph builder reading path-store.js's
  // `orphanedPeerSources`/context-cap-degraded diagnostics, never this
  // registry). Both cases share `kind: 'unresolved'` and
  // `externality: 'unknown'`, and it would be a real mistake to conflate
  // them (item 5's own text warns against exactly this):
  //   - FR-203 (this branch): the CLASSIFICATION succeeded — the registry
  //     knows the sink's category from its CWE/framework — but a SPECIFIC
  //     call site's destination expression could not be resolved
  //     (`fetch(url)` with a computed `url`). `coverageStatus` is
  //     UNCHANGED from whatever the category mapping already assigned
  //     (`base.coverageStatus` above) — destination resolution is a
  //     DIFFERENT AXIS from classification confidence (this item's own
  //     opening sentence), so a `modeled` sink whose destination happens
  //     to be dynamic stays `modeled`.
  //   - §16.7 (NOT this branch, NOT this module): the ANALYSIS itself is
  //     incomplete — a truncation-terminal path node with no catalog entry
  //     behind it at all, hence `coverageStatus: 'partial'` UNCONDITIONALLY
  //     (§16.7's own text: "the analyzer genuinely observed this flow and
  //     lost only its continuation" — §6.2's lossy-but-sure shape, not a
  //     category-mapping carry-over, since there is no category mapping to
  //     carry over).
  // Guarded ONLY when `category !== null`: an unsupported/process sink has
  // no category to retain (`category retained` is FR-203's own explicit
  // requirement, and there is nothing to retain here), and letting this
  // branch fire on a null-category entry would silently break D1/3c's
  // `kind === 'process'` iff `coverageStatus === 'unsupported'`
  // biconditional (coverageStatus would stay `'unsupported'` while kind
  // became `'unresolved'` instead of `'process'`) — a bug this task must
  // not introduce, even though fixing the biconditional's own documented
  // future fragility (§7.1's boxed note, AI-sink detection) is explicitly
  // not this task's problem.
  if (opts.destinationUnresolved && category !== null) {
    return {
      kind: 'unresolved',
      category,
      coverageStatus: row.status,
      externality: 'unknown',
      reason: opts.blockingExpression
        ? `destination could not be statically resolved: ${opts.blockingExpression}`
        : 'destination could not be statically resolved to a fixed value',
    };
  }

  return base;
}

/**
 * Reclassify a single privacy-catalog entry (from PRIVACY_SINK_CATALOG) into
 * DataFlowGraph v1's vocabulary. A SEPARATE function from `reclassifySink`,
 * deliberately — see this module's own header for why (§2.1: the two
 * catalogs key on different fields, and privacy-catalog.js is deliberately
 * not merged into CATALOG).
 *
 * @param {object} entry a PRIVACY_SINK_CATALOG entry
 * @returns {{kind: string, category: string|null, coverageStatus: string, externality: string, reason: string}}
 */
export function reclassifyPrivacySink(entry) {
  const row = PRIVACY_CATEGORY_MAP[entry.category];
  if (!row) {
    // Defensive fallback only — the completeness guard in this module's own
    // test suite proves every real privacy-catalog category is mapped
    // (both against the entries actually used AND against the DECLARED
    // PRIVACY_SINK_CATEGORIES vocabulary), so this is unreachable from live
    // data.
    return {
      kind: 'process', category: null, coverageStatus: 'unsupported',
      externality: 'internal', reason: `unmapped privacy category ${entry.category}`,
    };
  }
  return {
    kind: CATEGORY_NODE_KIND[row.category] ?? 'sink',
    category: row.category,
    coverageStatus: row.status,
    externality: CATEGORY_EXTERNALITY[row.category] ?? 'unknown',
    reason: row.why,
  };
}

// Re-exported for callers that want the raw sink-entry slice without
// re-filtering CATALOG themselves (the completeness guards in this
// module's own test suite are the primary consumer) — mirrors
// source-registry.js's own SOURCE_ENTRIES precedent.
export const SINK_ENTRIES = Object.freeze(CATALOG.filter((e) => e.kind === 'sink'));

// Re-exported for the same reason, on the privacy side — callers that want
// the privacy sink entries without importing dataflow/privacy-catalog.js
// directly. Deliberately NOT a merge with SINK_ENTRIES (see this module's
// own header).
export const PRIVACY_SINK_ENTRIES = PRIVACY_SINK_CATALOG;
