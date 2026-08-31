//
// coverage.js — Sub-project E, increment 4 (E4).
//
// Implements DESIGN_GRAPH_BUILDER.md §9.4/§10 exactly: finishes the coverage
// ledger E1/E3 shipped only as a sketch (`graph-builder.js`'s own inline
// `graph.coverage = {...}` block — still present, still the DEFAULT when a
// caller uses `buildDataFlowGraph` directly; this module supersedes it only
// for a caller that opts in via `buildGraphWithCoverage`), and closes FR-203
// (a recognized sink whose destination expression could not be statically
// resolved — `fetch(url)` with a computed `url`; an SDK client built from
// config).
//
// §9.4 item 3 ("ship §5's enumerator union as a real module function") is
// ALREADY DONE — `graph-builder.js` exports `degradedTerminals(store)` as a
// real, tested function (E3). This module reads its result via `built.degraded`,
// it does not reimplement it.
//
// §9.4 item 5's hook-vs-post-processing-pass decision: an `opts` hook on
// `buildDataFlowGraph` (`resolveSiteDecision`, shipped in Task 1), not a
// post-processing pass over the built graph — see graph-builder.js's own
// header for why a post-processing pass was rejected (FR-203 changes a
// node's identity discriminator, so "adjust after minting" means re-minting).
//
// Reuse boundary: imports ONLY `reclassifySink` from `./sink-registry.js`,
// `DEFAULTS` from `./path-query.js`, and `buildDataFlowGraph` from
// `./graph-builder.js` — all three already-shipped `src/lineage/` modules.
// Never `dataflow/engine.js`, never `dataflow/summaries.js`.
//
// Disclosure: FR-203's own headline example ("fetch(url) with a computed
// url") is currently unreachable on this project's real fixture through
// the privacy-catalog guard below — `vulnerable-js`'s only `external-api`
// sites are `privacy-js-axios-post`, and `reclassifyPrivacySink` has no
// `opts.destinationUnresolved` parameter for `resolveSiteDecision` to
// invoke (a disclosed, deliberate asymmetry — see `sink-registry.js`'s own
// header). Correct and deliberate; recorded here so the gap is visible
// rather than silently true of the only real fixture in this tree today.

import { reclassifySink } from './sink-registry.js';
import { DEFAULTS as PATH_QUERY_DEFAULTS } from './path-query.js';
import { buildDataFlowGraph } from './graph-builder.js';

// =========================================================================
// FR-203 — the destination-unresolved heuristic.
//
// No catalog entry carries per-call-site destination information
// (DESIGN_REGISTRIES.md §7.5), so this heuristic works from the two shapes
// a real call site actually offers: the CALLEE (is the receiver a plain
// bound identifier, or a computed expression — "an SDK client built from
// config"?) and the first ARGUMENT (is it a literal, or a computed
// expression — "fetch(url) with a computed url"?). Either one firing is
// enough; the two are deliberately not required to agree, since a call
// site can be unresolvable via only one of the two shapes.
// =========================================================================

function isPlainIdent(e) {
  return Boolean(e) && typeof e === 'object' && e.kind === 'ident' && typeof e.name === 'string';
}

/** Renders an IR expression node as a short, human-readable string for a
 * FR-203 `reason` — never throws, never returns an empty string. */
export function renderExpr(e, depth = 0) {
  if (depth > 4 || e == null) return '<computed expression>';
  if (typeof e === 'string') return e;
  if (typeof e !== 'object') return '<computed expression>';
  if (e.kind === 'ident' && typeof e.name === 'string') return e.name;
  if (e.kind === 'literal') return JSON.stringify(e.value);
  if (e.kind === 'member' && typeof e.prop === 'string') return `${renderExpr(e.object, depth + 1)}.${e.prop}`;
  return '<computed expression>';
}

/**
 * §9.4 item 2's heuristic. `site` is one entry from `enumerateSinkSites`'s
 * `sites[]` (post Task 1: carries `.calleeExpr` and `.args`). Returns
 * `null` when nothing here looks unresolvable — never a guess in the
 * unresolved direction. The result names WHICH signal fired (`via`):
 * `'receiver'` (a computed callee receiver — "an SDK client built from
 * config") or `'arg0'` (a non-literal first argument — "fetch(url) with a
 * computed url"). `resolveSiteDecision` uses `via` to apply the narrower
 * category gate the arg0 signal needs (see `FR203_ARG0_DESTINATION_CATEGORIES`
 * below) — this function itself stays category-blind, since it has no
 * access to the site's decision/category and is also exercised directly,
 * without a category, by this module's own unit tests.
 */
export function detectUnresolvedDestination(site) {
  const callee = site.calleeExpr;
  if (callee && typeof callee === 'object' && callee.kind === 'member' && typeof callee.prop === 'string' && !isPlainIdent(callee.object)) {
    return { blockingExpression: `${renderExpr(callee.object)}.${callee.prop}`, via: 'receiver' };
  }
  const arg0 = (site.args ?? [])[0];
  if (arg0 && typeof arg0 === 'object' && arg0.kind !== 'literal') {
    return { blockingExpression: renderExpr(arg0), via: 'arg0' };
  }
  return null;
}

// Categories whose node kind genuinely has a "destination" concept — a
// target system or location an argument/receiver could name. Excludes
// 'sink' (http-response/declared — the destination IS the call itself,
// always fixed) and 'log' (same reasoning). Mirrors sink-registry.js's own
// CATEGORY_NODE_KIND vocabulary; not re-derived, just filtered against.
// This is the RECEIVER signal's own eligibility set — the receiver is the
// destination handle in every one of these (an SDK client, a DB cursor, a
// queue channel), so the receiver check applies to all three.
//
// 'queue' is currently unreachable in practice: no `sink-registry.js`
// `CWE_MAP` row maps to `queue` (only `PRIVACY_CATEGORY_MAP`'s `queues` row
// does, and privacy-catalog sites are excluded above by the `vuln.cwe ===
// undefined` guard) — kept for forward-compatibility with a future
// CWE_MAP row, not a bug.
const FR203_ELIGIBLE_KINDS = Object.freeze(['external', 'store', 'queue']);

// The ARGUMENT signal's own, NARROWER eligibility set (MUST-FIX 1). Unlike
// the receiver, the first argument only actually NAMES the destination for
// these three categories (`fetch(url)`, `fs.writeFile(path, data)`,
// `s3.putObject(key, body)`) — everywhere else in `FR203_ELIGIBLE_KINDS`
// (overwhelmingly `database`/`client-storage`), the first argument is the
// PAYLOAD being sent TO an already-resolved destination named by the
// receiver (`cursor.execute(sql)`, `document.write(html)`), so treating a
// non-literal payload as "destination unresolved" is a false positive —
// measured live: 54 of 86 FR-203-eligible catalog entries (63%) are
// `database`(48)/`client-storage`(6), where the payload argument is
// non-literal by construction, so the un-gated arg0 signal fired
// unconditionally there and carried no information.
const FR203_ARG0_DESTINATION_CATEGORIES = Object.freeze(['external-api', 'file', 'object-storage']);

/**
 * The exact shape `buildDataFlowGraph`'s `opts.resolveSiteDecision` hook
 * expects: `(site) -> decision | undefined`. Composes with §4.3's
 * multi-candidate ambiguity resolution rather than silently discarding it
 * — see the Global Constraints note in this plan and the comment below.
 */
export function resolveSiteDecision(site) {
  // Privacy-catalog entries have no `vuln.cwe` — reclassifySink's `opts`
  // parameter is specified only for the general (CWE-keyed) catalog
  // (sink-registry.js's own disclosed asymmetry). Never applied here.
  if (site.entry?.vuln?.cwe === undefined) return undefined;
  // Defensive: `resolveSiteDecision` is exported as a hook contract (passed
  // straight into `buildDataFlowGraph`'s `opts.resolveSiteDecision`), so it
  // should be as defensive against a malformed site as
  // `detectUnresolvedDestination`/`renderExpr` already are — a site with no
  // `.decision` at all must not throw here.
  if (!site.decision) return undefined;
  // A null-category (unsupported/process) decision has no category to
  // retain — reclassifySink's own guard already refuses this combination;
  // checking it here too avoids computing a heuristic result that would
  // just be thrown away.
  if (site.decision.category === null) return undefined;
  if (!FR203_ELIGIBLE_KINDS.includes(site.decision.kind)) return undefined;

  const unresolved = detectUnresolvedDestination(site);
  if (!unresolved) return undefined;
  // MUST-FIX 1: the arg0 signal only actually names a destination for the
  // narrower FR203_ARG0_DESTINATION_CATEGORIES set — see that constant's
  // own comment. The receiver signal has no such extra gate (it's eligible
  // for everything FR203_ELIGIBLE_KINDS already allowed above).
  if (unresolved.via === 'arg0' && !FR203_ARG0_DESTINATION_CATEGORIES.includes(site.decision.category)) return undefined;

  const fr203 = reclassifySink(site.entry, {
    destinationUnresolved: true,
    blockingExpression: unresolved.blockingExpression,
  });

  // §4.3's plurality resolution already demoted `site.decision.coverageStatus`
  // to 'partial' and appended an "AMBIGUOUS..." reason, entirely at the SITE
  // level — `site.entry` is only the winning candidate's raw entry, so a
  // bare `reclassifySink(site.entry, opts)` call knows nothing about that
  // demotion and would silently produce `fr203.coverageStatus` from
  // CWE_MAP fresh, discarding it. Carry the site-level adjustment forward
  // when it happened; otherwise `fr203`'s own values already agree with
  // `site.decision`'s (nothing to carry).
  const ambiguityAdjusted = site.ambiguity?.resolvedBy === 'plurality';
  return {
    ...fr203,
    coverageStatus: ambiguityAdjusted ? site.decision.coverageStatus : fr203.coverageStatus,
    reason: ambiguityAdjusted ? `${fr203.reason} (site: ${site.decision.reason})` : fr203.reason,
  };
}

// =========================================================================
// The coverage ledger (§10).
// =========================================================================

// Worst-wins precedence when a category's sites/seeds carry more than one
// coverageStatus — mirrors protection.js's aggregateVerdicts() and
// flow-grade.js's _PRECEDENCE risk-precedence-reduction convention, the
// established pattern in this package for "one summary value from several
// individually-graded inputs, worst wins".
const STATUS_PRECEDENCE = Object.freeze(['unsupported', 'candidate', 'partial', 'modeled']);
function worstStatus(a, b) {
  const ia = STATUS_PRECEDENCE.indexOf(a);
  const ib = STATUS_PRECEDENCE.indexOf(b);
  if (ia === -1) return b;
  if (ib === -1) return a;
  return ia <= ib ? a : b;
}

function byCategorySorted(build) {
  const out = {};
  for (const key of [...build.keys()].sort()) out[key] = build.get(key);
  return out;
}

/** §10's `sources.byCategory` — from `built.seeds` (already category- and
 * coverageStatus-tagged by source-registry.js's `reclassifySource`, per
 * `source-seeding.js`'s own seed shape). Null-category seeds are excluded
 * — the source registry's own tests already prove every source category
 * is non-null (source-registry.js has no `unsupported` tier, D2's own
 * measured 84/14/82/0 split), so this is a defensive exclusion, not a
 * documented real case. */
function sourcesByCategory(seeds) {
  const m = new Map();
  for (const s of seeds) {
    if (s.category == null) continue;
    if (!m.has(s.category)) m.set(s.category, { sites: 0, coverageStatus: s.coverageStatus });
    const e = m.get(s.category);
    e.sites += 1;
    e.coverageStatus = worstStatus(e.coverageStatus, s.coverageStatus);
  }
  return byCategorySorted(m);
}

/** §10's `sinks.byCategory` — from `built.sites` (post any
 * `opts.resolveSiteDecision` override, and post Task 1's `site.connected`
 * stamp). Null-category (process/unsupported) sites are excluded — their
 * existence is already guaranteed visible via AC-11's coarse half (every
 * discovered sink becomes a node, `kind: 'process'`), so a per-category
 * breakdown for a category that by definition doesn't exist would be
 * misleading, not informative. */
function sinksByCategory(sites) {
  const m = new Map();
  for (const s of sites) {
    if (s.decision.category == null) continue;
    if (!m.has(s.decision.category)) m.set(s.decision.category, { sites: 0, connected: 0, coverageStatus: s.decision.coverageStatus });
    const e = m.get(s.decision.category);
    e.sites += 1;
    if (s.connected) e.connected += 1;
    e.coverageStatus = worstStatus(e.coverageStatus, s.decision.coverageStatus);
  }
  return byCategorySorted(m);
}

// Language dispatch — mirrors ir/index.js's own extension-based dispatch
// (never imported directly: that module has no exported "which language is
// this file" function, only its own internal parse dispatch, and importing
// ir/index.js here would cross a reuse boundary no other src/lineage/
// module crosses). A small, stable, independently-testable duplicate.
const LANGUAGE_EXT_PATTERNS = Object.freeze([
  [/\.(?:js|jsx|ts|tsx|mjs|cjs)$/i, 'js'],
  [/\.py$/i, 'python'],
  [/\.cs$/i, 'csharp'],
  [/\.kt$/i, 'kotlin'],
  [/\.go$/i, 'go'],
  [/\.(?:php|phtml)$/i, 'php'],
  [/\.rb$/i, 'ruby'],
  [/\.(?:c|cc|cpp|cxx|h|hh|hpp|hxx)$/i, 'cpp'],
]);
function languageForFile(file) {
  for (const [re, lang] of LANGUAGE_EXT_PATTERNS) if (re.test(file)) return lang;
  return 'unknown';
}

/**
 * §10's finished coverage-ledger contract. `built` is `buildDataFlowGraph`'s
 * own return value (`{graph, store, hops, seeds, unseedable, sites,
 * nonStatementSites, degraded, stats, decisionsByNodeId}`) — this function
 * reads it, never rebuilds any of it.
 *
 * @param {object} built
 * @param {object} [opts]
 * @param {Record<string, object>} [opts.perFile] the same `{file: irRecord}`
 *   map `runScan`'s `_sharedIR.perFile` holds — used ONLY to count
 *   successfully-analyzed files per language. Optional: a caller with no
 *   file list (e.g. a unit test building a callGraph by hand) gets
 *   `languages: []`, honestly empty, never fabricated.
 * @param {Array<{file: string, language?: string, message?: string}>} [opts.parseFailures]
 *   per-file parse-failure records. A `callGraph`-only builder cannot see
 *   these itself (a parse failure never reaches `callGraph` at all —
 *   DESIGN_GRAPH_BUILDER.md §9.4 item 5b's own note); a caller with the
 *   real file list (E5/`runScan`) supplies them. Optional, defaults to `[]`.
 * @param {object} [opts.budget] the same budget object passed to
 *   `buildDataFlowGraph`'s own `opts.budget` — used only to report which
 *   values were ACTUALLY in effect (merged over path-query.js's DEFAULTS,
 *   the same way `reconstructPaths` itself merges them).
 */
export function buildCoverageLedger(built, opts = {}) {
  const perFile = opts.perFile ?? {};
  const parseFailures = (opts.parseFailures ?? []).map((f) => ({
    file: f.file, language: f.language ?? languageForFile(f.file), message: f.message ?? null,
  }));

  const filesAnalyzedByLang = new Map();
  for (const file of Object.keys(perFile)) {
    const lang = languageForFile(file);
    filesAnalyzedByLang.set(lang, (filesAnalyzedByLang.get(lang) ?? 0) + 1);
  }
  const filesFailedByLang = new Map();
  for (const f of parseFailures) filesFailedByLang.set(f.language, (filesFailedByLang.get(f.language) ?? 0) + 1);
  const allLangs = new Set([...filesAnalyzedByLang.keys(), ...filesFailedByLang.keys()]);
  const languages = [...allLangs].sort().map((language) => {
    const filesAnalyzed = filesAnalyzedByLang.get(language) ?? 0;
    return { language, filesExpected: filesAnalyzed + (filesFailedByLang.get(language) ?? 0), filesAnalyzed };
  });

  const unresolvedDestinations = built.sites.filter((s) => s.decision.kind === 'unresolved').length;

  return {
    languages, parseFailures,
    destinationResolutionStatus: 'not-attempted', // FR-202 is Milestone 2 — unchanged from E3's sketch
    pathBudgetTruncation: built.stats.truncatedQueries > 0,

    sources: {
      matched: built.seeds.length,
      unseedable: built.unseedable.length,
      dataElements: built.graph.dataElements.length,
      byCategory: sourcesByCategory(built.seeds),
    },
    sinks: {
      callStatementSites: built.sites.length,
      connected: built.stats.connectedSinkSites,
      disconnected: built.sites.length - built.stats.connectedSinkSites,
      nonStatementSitesNotEnumerable: built.nonStatementSites.length,
      byCategory: sinksByCategory(built.sites),
    },

    degradedTerminals: built.degraded.length,
    unresolvedDestinations,

    paths: { enumerated: built.stats.pathsEnumerated, projected: built.stats.pathsProjected, truncatedQueries: built.stats.truncatedQueries },
    budgets: { ...PATH_QUERY_DEFAULTS, ...(opts.budget ?? {}) },

    provenance: { hops: built.hops.length, pnodes: built.store.stats().nodes, pedges: built.store.stats().edges },
  };
}

/**
 * Convenience entry point: `buildDataFlowGraph` with FR-203 closed by
 * default and the finished coverage ledger in place of E3's sketch.
 * Returns the same shape `buildDataFlowGraph` returns — `built.graph.coverage`
 * is the only field this function changes.
 */
export function buildGraphWithCoverage(callGraph, opts = {}) {
  // NITPICK 4: compose with a caller-supplied `opts.resolveSiteDecision`
  // rather than silently clobbering it — a caller's own hook always wins,
  // matching `buildDataFlowGraph`'s own "the hook, when present, replaces
  // `site.decision`" contract rather than this convenience wrapper quietly
  // overriding that caller's choice.
  const built = buildDataFlowGraph(callGraph, { ...opts, resolveSiteDecision: opts.resolveSiteDecision ?? resolveSiteDecision });
  built.graph.coverage = buildCoverageLedger(built, opts);
  return built;
}
