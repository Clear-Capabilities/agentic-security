//
// graph-builder.js — Sub-project E, increment 3 (E3).
//
// Extracts the already-designed-and-proven graph-projection mechanism out of
// `DESIGN_GRAPH_BUILDER.md` §4-§8 (binding ADR) and its throwaway
// proof-of-concept (`test/lineage/graph-builder-poc.test.js`'s
// `receiverJustified`/`resolveSinkAtCallSite`/`enumerateSinkSites`/
// `degradedTerminals`/`calleeDescriptor`/`buildDataFlowGraph`, `E1/6`-`E1/13`)
// into a real, permanent, shipped module. This produces, for the first time
// in this codebase, a real, `validateGraph()`-clean `DataFlowGraph v1`
// document from an actual repository's real code.
//
// This is mechanical porting of an already-reviewed design, not a redesign
// — see `DESIGN_GRAPH_BUILDER.md` §4-§9.3 in full for the binding rules this
// file implements, and its own header for why the PoC (not this document)
// is authoritative if the two ever disagree.
//
// **Signature discrepancy, resolved per that stated policy**:
// `DESIGN_GRAPH_BUILDER.md` §9.3 item 1 originally stated the signature as
// `buildDataFlowGraph(perFileIR, callGraph, opts)` (three arguments), but
// the PoC's own shipped, tested implementation is
// `buildDataFlowGraph(callGraph, opts)` (two arguments) — it never used a
// separate `perFileIR` parameter, reading everything it needs from
// `callGraph.functions[*].cfg`. Per §9.1's own policy ("where this document
// and that PoC disagree, the PoC is right and this document is stale — fix
// it here, do not fork it"), this module ships the PoC's actual
// two-argument signature; §9.3 item 1's own prose was corrected to match in
// the same commit that shipped this file.
//
// E4 addition (DESIGN_GRAPH_BUILDER.md §9.4 item 5b): `opts.resolveSiteDecision`
// is the chosen resolution of that item's open hook-vs-post-processing-pass
// question. A post-processing pass over the BUILT GRAPH was rejected: FR-203
// changes a decision's `kind`/`externality`, which are part of a node's own
// identity discriminator (§6.1) — adjusting them after nodes are already
// minted would mean re-minting nodes and re-linking every edge/dataElement
// reference by hand, in effect reimplementing this function a second time.
// Intercepting the DECISION before minting, once, right after
// `enumerateSinkSites`, is the only point where an override is both
// consistent (every later read of `site.decision` sees it) and cheap
// (one small hook, zero structural changes to the projection below).
//
// Milestone 2, Sub-project A, increment 1 addition (FR-202, DESIGN_
// DESTINATION_RESOLVER.md): `opts.resolveDestination`, a SEPARATE,
// additive hook applied at the exact same point as `opts.resolveSiteDecision`
// above, right after it — same reasoning (a node's `destination` field is
// set once, at mint time, so intercepting before minting is the only
// consistent point). Composes with `resolveSiteDecision`, never collapses
// into it: the two hooks answer independent questions (is this sink's
// CLASSIFICATION resolvable vs. what does its DESTINATION EXPRESSION look
// like) and a site can carry both an `unresolved` decision and a `dynamic`
// destination at once.
//
// Milestone 2, Sub-project D, increment 1 addition (FR-403, DESIGN_
// HANDLING_ANALYZER.md): every emitted `flow` gains a `flow.handling`
// taxonomy label (`classifyHandling(p, callGraph)`, `./handling-analyzer.js`
// — a new import, mirroring `recognizeTransformation`'s own reuse boundary
// one line above), computed once inside the `groupsByFlowKey` flow-
// construction loop below, from that flow's own representative
// reconstructed `Path`. This is the same attachment-point discipline
// `emptyProtection()` already established one loop up for `edge.protection`
// — set once, at mint time, never a post-processing pass. See
// `DESIGN_HANDLING_ANALYZER.md` for the exact `transform-catalog.js` `kind`
// -> `HANDLING_VALUES` mapping and why this is NOT the same field as
// `protection.js`'s own `PROTECTION_DIMENSIONS`' `handling` dimension.
//
// Milestone 2, Sub-project B, increment 2 addition (FR-401, DESIGN_
// TRANSIT_PROTECTION.md §6): `opts.resolveTransitProtection`, a SEPARATE,
// additive hook applied at the exact same edge-construction point as
// `opts.resolveDestination` above — composing into the edge's `protection`
// object (`protection: { ...emptyProtection(), transit: resolved ??
// emptyProtection().transit }`) rather than replacing it. Writes ONLY
// `protection.transit`; `.atRest`/`.handling` stay `emptyProtection()`'s
// own defaults. A no-op when omitted, mirroring every prior additive
// hook's own "byte-identical when the hook is absent" contract.
//
// Reuse boundary (§12, confirmed against the source): imports ONLY
// `matchSource`/`matchSinkOrSanitizer` from `../dataflow/catalog.js`,
// `matchPrivacySink` from `../dataflow/privacy-catalog.js`, and
// `accessPathOf` from `../dataflow/access-paths.js` — never
// `dataflow/engine.js`'s live taint state, never `dataflow/summaries.js`'s
// SummaryCache, never `dataflow/index.js`'s `runDeepAnalysis` (PRD §18.1).
// This module MIRRORS that shape (an opt-in, best-effort orchestration
// entry point), it does not wrap it.

import { matchSinkOrSanitizer } from '../dataflow/catalog.js';
import { matchPrivacySink } from '../dataflow/privacy-catalog.js';
import { matchOrmWrite } from '../dataflow/orm-write-catalog.js';
// Milestone 2, Sub-project G, increment 1 (FR-408/AC-09): `isSinkPermitted`/
// `permittingRules` are pure, vocabulary-agnostic functions (no hardcoded
// sink-name check anywhere in that module — confirmed by direct read) that
// this module reuses UNMODIFIED, mirroring dataflow/privacy-taint.js's own
// real usage precedent exactly. See the flow-construction loop below for
// the actual `flow.policyVerdict` computation.
import { isSinkPermitted, permittingRules } from '../dataflow/privacy-sink-policy.js';

import { runFieldIdentityAnalysis } from './driver.js';
import { PathStore } from './path-store.js';
import { reconstructPaths } from './path-query.js';
import { gradePath, DEGRADED_LOSS_REASONS } from './flow-grade.js';
import { reclassifySink, reclassifyPrivacySink, reclassifyOrmWrite } from './sink-registry.js';
import { recognizeTransformation } from './transform-catalog.js';
import { classifyHandling } from './handling-analyzer.js';
import { emptyGraphEnvelope } from './schema.js';
import { emptyProtection, aggregateVerdicts } from './protection.js';
import * as ids from './ids.js';
import { planSeeds, seedEntryStateFactory, exprRoots, walkExpr } from './source-seeding.js';
import { RECIPIENT_FACT_FIELDS } from './recipient-profile.js';

// =========================================================================
// §4.2 / §4.3 — registry-backed sink enumeration, multi-candidate resolution
// =========================================================================

/**
 * §4.2. Did the matcher accept this candidate BECAUSE of a textual receiver
 * constraint it declared? `receiverTypeIn` deliberately does NOT count: it
 * gates on a CHA-resolved class TYPE and is vacuously allowed whenever no
 * `receiverType` is supplied, which is always, here (D5 measured exactly
 * this trap). Reading a returned candidate's own declared constraint is not
 * re-deriving the match — `matchSinkOrSanitizer` already ran it.
 */
function receiverJustified(entry) {
  return Boolean(entry.match && (entry.match.receiver || entry.match.receiverBase));
}

/** §4.3. Multi-candidate sink resolution: represent, never silently pick. */
function resolveSinkAtCallSite(calleeExpr, file) {
  const general = (matchSinkOrSanitizer(calleeExpr, file, undefined) ?? []).filter((h) => h.kind === 'sink');
  const privacy = matchPrivacySink(calleeExpr, file, undefined) ?? [];
  const cands = [
    ...general.map((e) => ({ entry: e, decision: reclassifySink(e) })),
    ...privacy.map((e) => ({ entry: e, decision: reclassifyPrivacySink(e) })),
  ];
  if (cands.length === 0) return null;
  if (cands.length === 1) return { ...cands[0], ambiguity: null };

  const justified = cands.filter((c) => receiverJustified(c.entry));
  if (justified.length === 1) {
    return {
      ...justified[0],
      ambiguity: { resolvedBy: 'receiver', alternatives: cands.filter((c) => c !== justified[0]).map((c) => c.entry.id).sort() },
    };
  }
  const pool = justified.length > 1 ? justified : cands;
  const cats = [...new Set(pool.map((c) => c.decision.category))];
  if (cats.length === 1) {
    return { ...pool[0], ambiguity: { resolvedBy: 'unanimous-category', alternatives: pool.slice(1).map((c) => c.entry.id).sort() } };
  }
  const counts = new Map();
  for (const c of pool) counts.set(c.decision.category, (counts.get(c.decision.category) ?? 0) + 1);
  const winner = [...counts.entries()].sort((a, b) => (b[1] - a[1]) || (String(a[0]) < String(b[0]) ? -1 : 1))[0][0];
  const chosen = pool.find((c) => c.decision.category === winner);
  const others = [...counts.keys()].filter((c) => c !== winner).sort();
  return {
    entry: chosen.entry,
    decision: {
      ...chosen.decision,
      coverageStatus: 'partial',
      reason: `${chosen.decision.reason}; AMBIGUOUS at this call site: also matches ${others.join(', ')} (candidates: ${pool.map((c) => c.entry.id).sort().join(', ')})`,
    },
    ambiguity: { resolvedBy: 'plurality', alternatives: others },
  };
}

/**
 * Milestone 2, Sub-project E, increment 1 (ORM-write sink recognition,
 * `docs/superpowers/plans/2026-08-31-data-flow-explorer-m2-subproject-e1-plan.md`).
 * A SEPARATE resolver from `resolveSinkAtCallSite` above, deliberately —
 * `ORM_WRITE_CATALOG` is its own isolated catalog (never merged into
 * `CATALOG`/`PRIVACY_SINK_CATALOG`; see `dataflow/orm-write-catalog.js`'s
 * own header) and needs a precision signal `resolveSinkAtCallSite`'s two
 * matchers never do: the call's FIRST ARGUMENT must be an object-literal
 * expression (`kind: 'object'` — confirmed against `parser-js.js`'s real
 * `ObjectExpression` lowering, NOT `resolve-destination.js`'s `isLiteral`
 * helper, which tests for the unrelated `kind: 'literal'`). That check
 * cannot live inside `matchOrmWrite` itself (its signature mirrors
 * `matchPrivacySink`'s and never receives the call's arguments), so it is
 * applied HERE, as a hard exclusion, before a match is returned at all —
 * not a `coverageStatus` downgrade the way `resolveSinkAtCallSite`'s own
 * ambiguity handling works. A call whose first argument is not an object
 * literal (`User.create(req.body)`, a bare identifier) never becomes an
 * ORM-write sink candidate.
 *
 * No multi-candidate ambiguity resolution: `ORM_WRITE_CATALOG`'s entries
 * never share a callee name with each other or with `CATALOG`/
 * `PRIVACY_SINK_CATALOG` (verified directly — no bare `create`/`save`/
 * `update`/`upsert` entry with an unconstrained or capitalized-identifier
 * receiver exists in either catalog today), so `ambiguity` is always
 * `null` here, unlike `resolveSinkAtCallSite`'s return shape.
 */
/**
 * Milestone 2, Sub-project E, increment 2 (`node.storeDetail.operation`,
 * DESIGN_STORE_DETAIL.md §4). Mapping logic, not an enum — lives here, not
 * `schema.js`, per this package's own established separation. `save` maps
 * to `'upsert'`, NOT `'create'` — a deliberate, disclosed judgment call:
 * Mongoose's `.save()` performs an INSERT on a new document but an UPDATE
 * on one loaded from the database, which is genuinely undecidable
 * statically from the call site alone; `'upsert'` is the honest umbrella
 * covering both, not a guess at which one it is.
 */
const ORM_OPERATION_MAP = Object.freeze({
  create: 'create',
  update: 'update',
  upsert: 'upsert',
  save: 'upsert',
});

/**
 * Milestone 2, Sub-project E, increment 2 (DESIGN_STORE_DETAIL.md §5).
 * `arg0.props` entries are EITHER `{key: <string>, value: <exprDesc>}` (a
 * real or literal-computed property) OR `{spread: true, value: <exprDesc>}`
 * (an object spread — no key at all), per `parser-js.js`'s real
 * `ObjectExpression` lowering (confirmed by direct read, ~line 116-159). A
 * spread entry has no key to report; a `'*'`-keyed entry is a genuinely
 * UNKNOWN column name (a non-literal computed key, `resolveObjectKey`'s
 * own convention), not a literal column named `"*"` — reporting either
 * would be a fabrication. Deduplicated since two distinct-value properties
 * can share a key in real (if unusual) source (`{email: a, email: b}`).
 */
function ormWriteColumns(arg0) {
  const props = Array.isArray(arg0?.props) ? arg0.props : [];
  const keys = props
    .filter((p) => !p.spread && typeof p.key === 'string' && p.key !== '*')
    .map((p) => p.key);
  return [...new Set(keys)];
}

/**
 * Milestone 2, Sub-project E, increment 3 (`node.queueDetail.topic`,
 * DESIGN_QUEUE_DETAIL.md §3). A small local copy of `resolve-destination
 * .js`'s `isLiteral` check shape (not imported — this package's own
 * established "small local copy over cross-module dependency" precedent,
 * already used by `ormWriteColumns`/`calleeDescriptor` elsewhere in this
 * file), scoped to this file's own extraction needs.
 */
function isLiteral(e) {
  return Boolean(e) && typeof e === 'object' && e.kind === 'literal';
}

// Milestone 2, Sub-project E, increment 3 (DESIGN_QUEUE_DETAIL.md §3.1). A
// short, disclosed alias list — deliberately not widened speculatively.
// Checked in this order: the first alias with a matching, literal-valued
// property wins.
const QUEUE_TOPIC_KEY_ALIASES = Object.freeze(['QueueUrl', 'TopicArn', 'topic', 'queueName']);

/**
 * `extractQueueDetail(args)` — only needs `args`: `operation` is always
 * `'publish'` when this is called at all (every real
 * `PRIVACY_SINK_CATALOG` queue entry — `sendMessage`/`publish` — is
 * unambiguously a write), so no `calleeExpr`/callee-name parameter is
 * needed, unlike `resolveOrmWriteAtCallSite`'s `table`/`operation`
 * extraction, which did need the callee.
 *
 * `topic` extraction reuses `ormWriteColumns`'s exact filter shape
 * (exclude spread entries, exclude `'*'`-keyed computed entries) but wants
 * the VALUE of one specific matching key, not every key name — a
 * different, smaller function, not a call to `ormWriteColumns` itself.
 * Covers `privacy-js-queue-sendMessage`'s shape
 * (`sqs.sendMessage({QueueUrl: '...', MessageBody: ...})`) directly. For
 * `privacy-js-queue-publish`'s shape (`topic.publish(...)`), the topic
 * identity typically lives in a SEPARATE, earlier statement that
 * constructed the receiver — a cross-statement lookup this package has no
 * primitive for — so that shape's own call arguments never carry a
 * matching key here, and `topic` stays `null`, honestly, exactly as it
 * would for any other call whose object-literal argument (if any) carries
 * none of the recognized aliases. This is a disclosed, deferred gap, not a
 * half-attempt — see DESIGN_QUEUE_DETAIL.md §3.2.
 */
function extractQueueDetail(args) {
  const arg0 = Array.isArray(args) ? args[0] : undefined;
  const props = Array.isArray(arg0?.props) ? arg0.props : [];
  let topic = null;
  for (const alias of QUEUE_TOPIC_KEY_ALIASES) {
    const prop = props.find((p) => !p.spread && p.key === alias);
    if (prop && isLiteral(prop.value)) {
      topic = String(prop.value.value);
      break;
    }
  }
  return { provider: null, topic, operation: 'publish' };
}

function resolveOrmWriteAtCallSite(calleeExpr, args, file) {
  const hits = matchOrmWrite(calleeExpr, file);
  if (!hits) return null;
  const arg0 = Array.isArray(args) ? args[0] : undefined;
  if (!arg0 || arg0.kind !== 'object') return null;
  const entry = hits[0];
  // DESIGN_STORE_DETAIL.md §3: `table` re-verifies defensively rather than
  // assuming the shape `_ormReceiverIsCapitalizedIdent` already checked
  // inside `matchOrmWrite` survived unchanged into this file.
  const table = typeof calleeExpr?.object?.name === 'string' ? calleeExpr.object.name : null;
  const operation = ORM_OPERATION_MAP[entry.match?.callee] ?? null;
  const storeDetail = {
    provider: null, host: null, database: null, schema: null,
    table, operation, columns: ormWriteColumns(arg0),
  };
  return { entry, decision: reclassifyOrmWrite(entry), ambiguity: null, storeDetail };
}

/**
 * §4.1. Registry-backed sink enumeration — the replacement for
 * `sinkCandidates()`. A CFG `call` STATEMENT node is the only shape that
 * produces an `escape` provenance node (engine.js `step()` case 'call' →
 * `write-out`/`call-arg`), so it is the only shape a sink-rooted
 * reconstruction can start from. Every OTHER call expression is counted,
 * never silently dropped.
 */
export function enumerateSinkSites(callGraph) {
  const sites = [];
  const nonStatementSites = [];
  for (const fn of callGraph.functions.values()) {
    for (const [nid, node] of Object.entries(fn.cfg?.nodes ?? {})) {
      if (node.kind === 'call' && node.callee) {
        const r = resolveSinkAtCallSite(node.callee, fn.file);
        if (r) {
          sites.push({ file: fn.file, qid: fn.qid, nodeId: nid, line: node.line ?? null, calleeExpr: node.callee, args: node.args ?? [], ...r });
          // Milestone 2, Sub-project E, increment 3: queue/topic identity
          // extraction, a conditional POST-step on the already-pushed site
          // object — not a change to `resolveSinkAtCallSite`'s own
          // signature (that function has no `args` parameter today, and
          // adding one would be a wider, unnecessary change for a fact
          // only the queue category needs).
          if (r.decision.category === 'queue') {
            const site = sites[sites.length - 1];
            site.queueDetail = extractQueueDetail(node.args ?? []);
          }
        }
        // Milestone 2, Sub-project E, increment 1: ORM-write recognition,
        // additive and independent of the general/privacy match above —
        // see `resolveOrmWriteAtCallSite`'s own header for why no
        // interaction between the two is expected or handled.
        const ormR = resolveOrmWriteAtCallSite(node.callee, node.args ?? [], fn.file);
        if (ormR) sites.push({ file: fn.file, qid: fn.qid, nodeId: nid, line: node.line ?? null, calleeExpr: node.callee, args: node.args ?? [], ...ormR });
      }
      for (const root of exprRoots(node)) {
        walkExpr(root, (e) => {
          if (e.kind !== 'call') return;
          const r = resolveSinkAtCallSite(e.callee, fn.file);
          if (!r) return;
          if (sites.some((x) => x.qid === fn.qid && x.nodeId === nid && x.entry.id === r.entry.id && x.calleeExpr === e.callee)) return;
          nonStatementSites.push({ file: fn.file, qid: fn.qid, nodeId: nid, line: node.line ?? null, nodeKind: node.kind, entryId: r.entry.id });
        });
      }
    }
  }
  return { sites, nonStatementSites };
}

/**
 * §5. `DESIGN_PATH_PROVENANCE.md` §16.7 Finding 2's enumerator half, via
 * the `diagnostics()`-union mechanism rather than a sixth `path-store.js`
 * node kind: "a `path` node with zero out-edges whose in-edges carry a
 * context-cap-degraded annotation". Computed from the PUBLIC read API only
 * — `nodes()`, `edgesFrom()`, `edgesTo()` — with no change to
 * `path-store.js` whatsoever.
 */
export function degradedTerminals(store) {
  const out = [];
  for (const n of store.nodes()) {
    if (store.edgesFrom(n.id).length !== 0) continue;
    const inEdges = store.edgesTo(n.id);
    if (inEdges.length === 0) continue;
    const degraded = inEdges.some((e) =>
      (e.lossReasons ?? []).some((r) => DEGRADED_LOSS_REASONS.includes(r))
      || (e.annotations ?? []).some((a) => DEGRADED_LOSS_REASONS.includes(a.lossReason)));
    if (degraded) out.push(n);
  }
  return out;
}

function calleeDescriptor(calleeExpr) {
  if (typeof calleeExpr === 'string') return { type: 'call', callee: calleeExpr };
  if (!calleeExpr) return null;
  if (calleeExpr.kind === 'ident' && calleeExpr.name) return { type: 'call', callee: calleeExpr.name };
  if (calleeExpr.kind === 'member' && typeof calleeExpr.prop === 'string') {
    const obj = calleeExpr.object && calleeExpr.object.kind === 'ident' ? calleeExpr.object.name : null;
    return obj ? { type: 'member-call', object: obj, method: calleeExpr.prop } : { type: 'call', callee: calleeExpr.prop };
  }
  return null;
}
const calleeDisplay = (d) => (!d ? null : d.type === 'member-call' ? `${d.object}.${d.method}` : d.callee);

const nodeLabel = (kind, category, reason) => (category
  ? `${category} (${kind})`
  : `unsupported ${kind}: ${String(reason).split(';')[0].slice(0, 80)}`);

// =========================================================================
// §6-§8 — THE PROJECTION. A `DataFlowGraph v1` node is a REGISTRY DECISION,
// not a provenance node and not a call site: its identity is
// `(kind, subtypeKey, coverageStatus, externality, destination)`. Edges and
// flows stay field- and path-granular, so nothing FR-305 protects is lost.
// =========================================================================

/**
 * `buildDataFlowGraph(callGraph, opts)` — mirrors `dataflow/index.js`'s
 * `runDeepAnalysis` SHAPE (an opt-in, best-effort orchestration entry
 * point) and imports NOTHING from it. Seeds and drives the field-identity
 * analysis, builds a `PathStore`, enumerates registry-backed sink
 * candidates, resolves multi-candidate matches, reconstructs paths per
 * sink, and projects the result into a `validateGraph()`-clean
 * `DataFlowGraph v1` envelope.
 *
 * See the module header for the two-argument-vs-three-argument signature
 * discrepancy this ships against, and the module's DESIGN_GRAPH_BUILDER.md
 * §6-§8 for the projection rules implemented below.
 */
export function buildDataFlowGraph(callGraph, opts = {}) {
  const repository = opts.repository ?? 'repo';
  const { seeds, unseedable } = planSeeds(callGraph, { repository });
  const hops = [];
  runFieldIdentityAnalysis(callGraph, {
    recordHop: (h) => hops.push(h),
    seedEntryState: seedEntryStateFactory(seeds),
    ...(opts.maxContextsPerFn === undefined ? {} : { maxContextsPerFn: opts.maxContextsPerFn }),
  });
  const store = new PathStore();
  store.addHops(hops);

  const cfgByQid = new Map();
  for (const fn of callGraph.functions.values()) cfgByQid.set(fn.qid, { fn, nodes: fn.cfg?.nodes ?? {} });

  const seedByDe = new Map();
  const seedSitesByDe = new Map();
  for (const s of seeds) {
    if (!seedByDe.has(s.dataElementId)) seedByDe.set(s.dataElementId, s);
    if (!seedSitesByDe.has(s.dataElementId)) seedSitesByDe.set(s.dataElementId, []);
    seedSitesByDe.get(s.dataElementId).push(s);
  }

  const graph = emptyGraphEnvelope({
    graphId: ids.graphId({ repository, commit: opts.commit ?? 'uncommitted', configHash: opts.configHash ?? 'default' }),
    // Determinism (§9.3 item 4): `generatedAt` must be injectable via
    // `opts.generatedAt` rather than defaulting to `new Date().toISOString()`
    // (which `emptyGraphEnvelope()` itself would fall back to if this
    // module ever passed `undefined`/omitted the key entirely).
    generatedAt: opts.generatedAt ?? '1970-01-01T00:00:00.000Z',
  });

  const nodesById = new Map();
  const edgesById = new Map();
  const flowsById = new Map();
  const transformsById = new Map();
  const deById = new Map();
  // Every registry decision that landed on each node id — the raw material
  // for the "no two DIFFERENT decisions collided onto one node" check.
  const decisionsByNodeId = new Map();
  // Milestone 2, Sub-project G, increment 1 (FR-408/AC-09): the first real
  // populator of `graph.evidence[]` (`evidenceId` — `ids.js` — was minted
  // but never called until this increment). One entry per DISTINCT
  // permitting policy rule actually applied to a flow, deduplicated by
  // content hash exactly like `transformsById`/`edgesById` above.
  const evidenceById = new Map();
  // Milestone 4, FR-506 (Third-Party and Cross-Border Intelligence): every
  // non-null `opts.buildRecipientProfile(site, graph)` result, deduplicated
  // by the record's own `id` — the same recipient reached by two different
  // sink sites in one scan must not mint two records; a duplicate
  // resolution merges its `site.nodeId` into the first record's
  // `contributingGraphIds` instead of overwriting it.
  const recipientProfilesById = new Map();

  const mintNode = ({ kind, category, coverageStatus, externality, coverageReason, subtypeKey, lifecycleStages, destination, storeDetail, queueDetail }) => {
    // NOTE (Milestone 2, Sub-project A, increment 1; Sub-project E,
    // increments 2 and 3): neither `destination` nor `storeDetail` nor
    // `queueDetail` is part of this discriminator — the node identity
    // model stays exactly what it was in Milestone 1 (a registry decision,
    // never a per-call-site fact), so two sites sharing one
    // (kind, subtypeKey, coverageStatus, externality) tuple still mint/
    // collide onto ONE node, and that node's `destination`/`storeDetail`/
    // `queueDetail` is whichever site's resolution was applied FIRST
    // (mintNode only sets it at creation, same as every other field
    // below) — a known, disclosed coarsening, not a bug; see
    // DESIGN_DESTINATION_RESOLVER.md, DESIGN_STORE_DETAIL.md, and
    // DESIGN_QUEUE_DETAIL.md respectively.
    const id = ids.nodeId(kind, [repository, subtypeKey ?? category ?? '', coverageStatus, externality, /* destination, always null in M1 */ '']);
    let n = nodesById.get(id);
    if (!n) {
      n = {
        id, kind,
        // Decision 1 (DESIGN_REGISTRIES.md §9.0): the registry's `category`
        // becomes the node's `subtype`; a null category becomes a null
        // subtype and `kind` + the reason carry the meaning.
        subtype: category ?? null,
        label: nodeLabel(kind, category, coverageReason),
        aliases: [],
        // A category-granular node has no single source location. The
        // flagship fixture sets `location: null` on all 14 of its own
        // nodes, so this matches the one shipped precedent.
        location: null,
        system: { application: repository, environment: null },
        destination: destination ?? null,
        storeDetail: storeDetail ?? null,
        queueDetail: queueDetail ?? null,
        externality: { value: externality, evidenceRefs: [] },
        lifecycleStages, governanceRefs: {},
        dataElementIds: [], evidenceRefs: [],
        confidence: coverageStatus === 'modeled' ? { score: 0.9, tier: 'high' } : { score: 0.6, tier: 'medium' },
        coverageStatus,
        coverageReason,
      };
      nodesById.set(id, n);
      decisionsByNodeId.set(id, []);
    }
    decisionsByNodeId.get(id).push({ kind, category, coverageStatus, externality });
    return n;
  };
  const sourceNodeFor = (s) => mintNode({
    kind: 'source', category: s.category, coverageStatus: s.coverageStatus, externality: s.externality,
    coverageReason: s.reason, subtypeKey: s.category ?? `unsupported-source:${s.entryId}`,
    lifecycleStages: ['collection'],
  });
  const sinkNodeFor = (site) => mintNode({
    kind: site.decision.kind, category: site.decision.category,
    coverageStatus: site.decision.coverageStatus, externality: site.decision.externality,
    coverageReason: site.decision.reason,
    subtypeKey: site.decision.category ?? `unsupported-sink:${site.entry.vuln?.cwe ?? site.entry.id}`,
    lifecycleStages: [site.decision.externality === 'external' ? 'sharing' : 'storage'],
    destination: site.destination ?? null,
    storeDetail: site.storeDetail ?? null,
    queueDetail: site.queueDetail ?? null,
  });
  const mintDataElement = (s) => {
    let d = deById.get(s.dataElementId);
    if (!d) {
      d = {
        id: s.dataElementId, name: s.canonicalName, aliases: [], declaredType: null,
        dataClasses: s.dataClasses, aiContexts: [], sourceLocations: [],
        dataSubjectCategory: null, classificationEvidence: [], manualOverride: false,
      };
      deById.set(s.dataElementId, d);
      for (const site of seedSitesByDe.get(s.dataElementId) ?? []) {
        const loc = { file: site.file, line: site.line, scope: site.qid, path: site.seedPath };
        if (!d.sourceLocations.some((l) => l.file === loc.file && l.line === loc.line && l.path === loc.path)) d.sourceLocations.push(loc);
      }
    }
    return d;
  };

  const { sites, nonStatementSites } = enumerateSinkSites(callGraph);
  // E4's FR-203 closure hook (DESIGN_GRAPH_BUILDER.md §9.4 item 5b): a
  // caller may substitute an adjusted decision for a site — e.g.
  // coverage.js's `resolveSiteDecision`, which reclassifies a sink whose
  // destination expression is not statically resolvable. Applied once,
  // before anything else reads `site.decision`, so every later use in
  // this build (node minting, coverage counting, flow limitations) sees
  // the same, consistent decision. A no-op when omitted — every existing
  // caller's behavior is unchanged.
  if (typeof opts.resolveSiteDecision === 'function') {
    for (const site of sites) {
      const override = opts.resolveSiteDecision(site);
      if (override) site.decision = override;
    }
  }
  // Milestone 2, Sub-project A, increment 1 (FR-202): a SEPARATE,
  // additive hook — composes with, never replaces, `resolveSiteDecision`
  // above. A site can be BOTH `kind: 'unresolved'` (FR-203's node-
  // classification answer) AND carry a `resolutionStatus: 'dynamic'`
  // destination (this hook's own, narrower "what does the destination
  // expression look like" answer) — the two questions are independent,
  // per DESIGN_DESTINATION_RESOLVER.md. Applied at the exact same point in
  // the pipeline, right after `resolveSiteDecision`, for the same reason:
  // once, before anything else reads `site.destination`
  // (`sinkNodeFor`/the edge-protocol block below). A no-op when omitted —
  // `site.destination` stays `undefined`, `sinkNodeFor` normalizes that to
  // `null`, and the edge's `protocol.destinationResolution` stays
  // `'unknown'` — byte-identical to pre-M2 behavior.
  if (typeof opts.resolveDestination === 'function') {
    for (const site of sites) {
      const destination = opts.resolveDestination(site);
      if (destination) site.destination = destination;
    }
  }
  const escapesBySite = new Map();
  for (const e of store.nodes()) {
    if (e.kind !== 'escape') continue;
    const k = `${e.scope}|${e.siteNodeId}`;
    if (!escapesBySite.has(k)) escapesBySite.set(k, []);
    escapesBySite.get(k).push(e);
  }

  const stats = { connectedSinkSites: 0, pathsEnumerated: 0, pathsProjected: 0, truncatedQueries: 0, unknownTransforms: 0 };
  const groupsByFlowKey = new Map();

  for (const site of sites) {
    let connected = false;
    for (const esc of escapesBySite.get(`${site.qid}|${site.nodeId}`) ?? []) {
      const r = reconstructPaths(store, esc.id, opts.budget ?? {});
      if (r.truncated) stats.truncatedQueries += 1;
      stats.pathsEnumerated += r.enumeratedPathCount;
      for (const p of r.paths) {
        const seed = seedByDe.get(p.dataElementId);
        if (!seed) continue;
        connected = true;
        stats.pathsProjected += 1;
        const g = gradePath(p);

        // ---- §7. transformations on this path ----
        const tIds = [];
        const unattributed = [];
        for (const h of p.hops) {
          const cfg = cfgByQid.get(h.scope);
          const cn = cfg?.nodes?.[h.siteNodeId];
          if (!cn) continue;
          const calls = [];
          for (const root of exprRoots(cn)) walkExpr(root, (e) => { if (e.kind === 'call') calls.push(e); });
          if (cn.kind === 'call' && cn.callee) calls.unshift({ kind: 'call', callee: cn.callee, args: cn.args ?? [] });
          const widened = (h.widenReasons ?? []).includes('unresolved-call')
            || (h.annotations ?? []).some((a) => a.widenReason === 'unresolved-call');

          let d = null;
          let rec = null;
          for (const c of calls) {
            const d0 = calleeDescriptor(c.callee);
            const r0 = d0 && recognizeTransformation(d0);
            if (r0) { d = d0; rec = r0; break; }
          }
          if (!rec) {
            // §7.2's `unknown` case, scoped so attribution is never a
            // guess: emit an entity only when the widening hop's CFG node
            // carries exactly ONE call expression.
            if (!widened) continue;
            if (calls.length !== 1) {
              unattributed.push(`an unrecognized call widened this value at ${cfg.fn.file}:${h.line ?? '?'}; ${calls.length} call expressions at that site, so the transforming callee is not attributable`);
              continue;
            }
            d = calleeDescriptor(calls[0].callee);
            if (!d) { unattributed.push(`an unrecognized call widened this value at ${cfg.fn.file}:${h.line ?? '?'}; its callee is not a resolvable name`); continue; }
            stats.unknownTransforms += 1;
          }
          const anchor = sinkNodeFor(site).id;
          const t = {
            id: ids.transformationId(anchor, calleeDisplay(d), [cfg.fn.file, h.line ?? '', h.fromPath ?? '', h.toPath ?? '']),
            inputPath: h.fromPath ?? null, outputPath: h.toPath ?? null,
            callee: calleeDisplay(d), function: h.scope,
            location: { file: cfg.fn.file, line: h.line ?? null },
            kind: rec ? rec.kind : 'unknown',
            reversibility: rec ? rec.reversibility : 'unknown',
            algorithm: rec ? rec.algorithm : null,
            confidence: rec
              ? { score: rec.confidence === 'high' ? 0.9 : 0.6, tier: rec.confidence }
              : { score: 0.3, tier: 'low' },
            evidence: rec
              ? rec.evidence
              : `a call to ${calleeDisplay(d)} widened this value's identity (hop record: unresolved-call); transform-catalog.js recognizes no transformation for this callee`,
            // §7.3: honest absences at MINT time. `appliesToAllPaths`
            // needs FR-307's all-path proof, which nothing in this
            // per-hop loop does — it can only be answered once every
            // flow group sharing this transform's coarse (source, sink,
            // dataElement) key is known, which is not true yet at this
            // point in the build. Milestone 2, Sub-project D, increment 2
            // overwrites this `null` with a real `true`/`false` in the
            // aggregation pass below (after `groupsByFlowKey` is fully
            // populated) — see DESIGN_HANDLING_ANALYZER.md §5. There is
            // still NO separate control-credit key of any kind — not even
            // a bare `false` here would read as "considered and denied"
            // this early (Decision 2); the real answer is written once,
            // later, by the pass that can actually prove it.
            appliesToAllPaths: null,
          };
          if (!transformsById.has(t.id)) transformsById.set(t.id, t);
          if (!tIds.includes(t.id)) tIds.push(t.id);
        }

        const src = sourceNodeFor(seed);
        const snk = sinkNodeFor(site);
        const de = mintDataElement(seed);
        if (!src.dataElementIds.includes(de.id)) src.dataElementIds.push(de.id);
        if (!snk.dataElementIds.includes(de.id)) snk.dataElementIds.push(de.id);

        const mappingType = tIds.length > 0 ? 'transformation' : (g.grade === 'explicit' ? 'identity' : 'unknown');
        const fromPath = seed.seedPath;
        // A call ARGUMENT is not an access path. Never fabricate one —
        // DESIGN_PATH_PROVENANCE.md Decision 5's forbidden bug class.
        const toPath = null;
        const sortedT = [...tIds].sort();
        const edgeIdStr = ids.edgeId(src.id, snk.id, 'data_flow', [fromPath, toPath ?? '', de.id, mappingType, ...sortedT]);
        if (!edgesById.has(edgeIdStr)) {
          edgesById.set(edgeIdStr, {
            id: edgeIdStr, from: src.id, to: snk.id, relationship: 'data_flow',
            fieldMappings: [{ fromPath, toPath, dataElementIds: [de.id], mappingType, transformationIds: sortedT }],
            protocol: { name: 'in-process', destinationResolution: site.destination?.resolutionStatus ?? 'unknown' },
            boundaryCrossings: [],
            // Milestone 2, Sub-project F, increment 1 (FR-304): which
            // mechanism discovered this edge. Every edge minted here today
            // is genuinely code-derived — this is an unconditional, honest
            // literal, never a guess (see schema.js's EDGE_PROVENANCE_VALUES
            // comment for the full rationale).
            provenance: 'code',
            // Milestone 2, Sub-project B, increment 2 (FR-401):
            // `opts.resolveTransitProtection(site) -> {verdict, evidenceGrade}
            // | undefined`, applied at this exact point — the same block
            // that already reads `site.destination` above — mirroring
            // `opts.resolveDestination`'s own additive-hook contract
            // exactly: composes with `emptyProtection()`'s default, never
            // replaces it wholesale, and is a no-op (byte-identical output)
            // when the hook is omitted or returns falsy. This increment
            // writes ONLY `.transit` — `.atRest`/`.handling` stay
            // `emptyProtection()`'s own defaults, Sub-project C's and a
            // later increment's own jobs respectively.
            protection: { ...emptyProtection(), transit: opts.resolveTransitProtection?.(site) ?? emptyProtection().transit },
            evidenceRefs: [], coverageStatus: snk.coverageStatus,
          });
        }
        // §6.4 / FR-305: the flow key carries every signal that makes two
        // paths MATERIALLY different (shape, evidence grade, the ordered
        // transformation set). Everything else collapses — including the
        // per-function entry CONTEXT dimension, which is absent from this
        // key by design and therefore never splits a flow.
        const flowKey = [src.id, snk.id, de.id, p.shape, g.grade, sortedT.join(',')].join('|');
        if (!groupsByFlowKey.has(flowKey)) groupsByFlowKey.set(flowKey, []);
        groupsByFlowKey.get(flowKey).push({ p, g, src, snk, de, edgeIdStr, sortedT, site, unattributed, truncated: r.truncated, truncationReasons: r.truncationReasons });
      }
    }
    site.connected = connected;
    if (connected) stats.connectedSinkSites += 1;
    // AC-11's coarse half: a sink node exists whether or not anything
    // reached it. A disconnected sink is a node with no flow, never absent.
    sinkNodeFor(site);
  }

  for (const [, group] of [...groupsByFlowKey.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1))) {
    const { p, g, src, snk, de, edgeIdStr, sortedT, site } = group[0];
    const fId = ids.flowId(src.id, snk.id, [de.id], [p.shape, g.grade, sortedT.join(',')]);
    const limitations = [...new Set([
      ...g.factors.map((f) => `evidence: ${f}`),
      ...group.flatMap((x) => x.unattributed),
      ...group.flatMap((x) => (x.truncated ? x.truncationReasons.map((t) => `reconstruction truncated: ${t}`) : [])),
      ...(g.complete ? [] : [`path incomplete: terminal reason ${p.terminal.reason}`]),
      ...(site.ambiguity && site.ambiguity.resolvedBy === 'plurality'
        ? [`sink category ambiguous at ${site.file}:${site.line}: also matches ${site.ambiguity.alternatives.join(', ')}`]
        : []),
    ])].sort();
    // Milestone 2, Sub-project D, increment 1 (FR-403): computed once,
    // here, from this flow's own representative reconstructed path — never
    // `null` in this increment (DESIGN_HANDLING_ANALYZER.md §4's own
    // disclosed simplification: every flow gets a real taxonomy label,
    // including the honest `'raw'` answer, since nothing here yet
    // distinguishes a sink category with no natural "handling" concept
    // from one that does).
    const handlingResult = classifyHandling(p, callGraph).handling;
    // Milestone 2, Sub-project C, increment 1 (FR-402, application-layer
    // at-rest evidence): reuses the SAME `classifyHandling` result above
    // for `flow.handling` — never a second call — to also decide
    // `edge.protection.atRest`. `'encrypted'` is the only `HANDLING_VALUES`
    // member that is at-rest PROTECTION evidence per FR-402 (see
    // DESIGN_HANDLING_ANALYZER.md's new §7); every other value (including
    // `'masked'`/`'hashed'`/`'tokenized'`) leaves `atRest` at
    // `emptyProtection()`'s own honest default. Gated to `snk.kind ===
    // 'store'` (`CATEGORY_NODE_KIND`'s `database`/`file`/`object-storage`/
    // `cache`/`client-storage`/`backup`/`export` — `queue` has its own
    // distinct `kind: 'queue'` and is deliberately excluded here). FR-402's
    // own anti-pattern guard ("a cipher present anywhere in the same file
    // or repository cannot alone establish protection for an unrelated
    // store") holds by construction, not by extra code here:
    // `classifyHandling` walks THIS flow's own reconstructed path only,
    // never the whole file/repo, so an unrelated `encrypt()` call
    // elsewhere is structurally invisible to it.
    if (handlingResult === 'encrypted' && snk.kind === 'store') {
      const edge = edgesById.get(edgeIdStr);
      // Defensive only — `edgeIdStr` is the SAME id this flow's own
      // `edgeIds: [edgeIdStr]` uses below, minted earlier in this same
      // `buildDataFlowGraph` call, so `edge` should always be found. Never
      // assume, per this package's own established convention.
      if (edge) edge.protection.atRest = { verdict: 'protected', evidenceGrade: 'code' };
    }
    // Milestone 2, Sub-project G, increment 1 (FR-408/AC-09):
    // `flow.policyVerdict` — real computed logic, replacing the
    // `'not_evaluated'` literal §8 shipped as a Milestone-1 honest default.
    // `classes`/`sinkKind` reuse fields this loop's own earlier passes
    // already read for other purposes (`de.dataClasses`, `snk.subtype` —
    // the FINE-grained SINK_CATEGORIES value; `snk.kind` is the coarser
    // `'store'`/`'log'`/etc. Sub-project C1's own atRest gate above uses).
    // `ctx.destination` reuses Sub-project A's `site.destination
    // ?.literalValue` — never fabricated when unresolved, per
    // `_matchesDestination`'s own fail-closed contract in
    // privacy-sink-policy.js.
    const policyClasses = de.dataClasses ?? [];
    const policySinkKind = snk.subtype;
    const policyCtx = {
      environment: opts.environment || process.env.AGENTIC_SECURITY_ENVIRONMENT || null,
      destination: site.destination?.literalValue ?? null,
    };
    // `policyLoaded` gates on the OPTS FIELD being present (`!= null`),
    // never on `opts.privacySinkPolicy.allow.length > 0` — a policy that
    // genuinely exists but permits nothing yet must still read
    // `'prohibited'` (deny-by-default), while an opt that was never
    // supplied at all (no policy evaluation attempted) must read
    // `'not_evaluated'`. `index.js` is what keeps this distinction real —
    // it only sets `opts.privacySinkPolicy` when a policy file genuinely
    // exists on disk, never coercing a missing file to the loader's own
    // `{allow: []}` "no policy configured" default (see that file's own
    // comment for why `loadPrivacySinkPolicy`'s return value alone cannot
    // make this distinction).
    const policyLoaded = opts.privacySinkPolicy != null;
    let policyVerdict = 'not_evaluated';
    const policyEvidenceRefs = [];
    // A flow whose data element carries NO recognized data class has
    // nothing for a policy engine to have an opinion about — `'prohibited'`
    // would overstate a judgment that never happened (isSinkPermitted's own
    // `if (!classes.length) return false` early return exists for a
    // DIFFERENT reason, precision on the FINDING side, not this field), so
    // this stays the honest `'not_evaluated'` default rather than calling
    // into the policy at all.
    if (policyLoaded && policyClasses.length && policySinkKind) {
      if (isSinkPermitted(policyClasses, policySinkKind, opts.privacySinkPolicy, policyCtx)) {
        policyVerdict = 'permitted';
        const rules = permittingRules(policyClasses, policySinkKind, opts.privacySinkPolicy, policyCtx);
        for (const r of rules) {
          const claim = `Privacy policy permits ${r.class ?? 'any data class'} data to reach sink "${r.sink}"`
            + (r.environment ? ` in environment "${r.environment}"` : '')
            + (r.destination ? ` for a destination matching /${r.destination}/` : '')
            + (r.reason ? `: ${r.reason}` : '');
          const evId = ids.evidenceId(claim, `${site.file}:${site.line}`, [de.id, r.sink, r.class ?? '', r.environment ?? '', r.destination ?? '']);
          if (!evidenceById.has(evId)) {
            evidenceById.set(evId, {
              id: evId, claim, evidenceType: 'policy',
              location: { file: site.file, line: site.line },
              producer: 'privacy-sink-policy', confidenceTier: null,
              snippet: null, timestamp: null, commit: null,
              limitations: [], conflict: null,
            });
          }
          if (!policyEvidenceRefs.includes(evId)) policyEvidenceRefs.push(evId);
        }
      } else {
        policyVerdict = 'prohibited';
      }
    }
    // Milestone 2, Sub-project I, increment 1 (PRD line 909): replaces
    // the §8 `protectionSummary: 'not_assessed'` literal — that line
    // stored an "unsupported independent claim", exactly what PRD line
    // 909 forbids ("must be derived from the individual edge verdicts").
    // `aggregateVerdicts`'s own `_PRECEDENCE` table (protection.js) is
    // documented as built for CROSS-BRANCH, same-dimension aggregation
    // (PRD §8.4's own wording: "one branch protected, one branch
    // unprotected") — NOT for combining one edge's own three DIFFERENT
    // dimensions. Reusing it here is safe ONLY because, for every real
    // edge today, at most ONE of transit/atRest/handling can ever be
    // non-default: `resolveTransitProtectionForSite` is gated to
    // `category === 'external-api'` (-> `kind: 'external'` only) and the
    // atRest block above is gated to `snk.kind === 'store'` only — these
    // two node kinds are mutually exclusive by construction, and
    // `edge.protection.handling` is never written by any code at all.
    // So this reduces, in practice, to "whichever single dimension
    // actually applies to this edge, use its own real verdict; the
    // others are honestly not_assessed and never mask it." **If a
    // future analyzer ever makes TWO of these three dimensions
    // genuinely co-applicable to the SAME edge, this reasoning breaks**
    // — a `protected` dimension could then mask a genuinely-unassessed,
    // RELEVANT other dimension, exactly the false-protected bug class
    // Sub-project H's own gate exists to catch (PRD line 121: "missing
    // evidence is displayed as unknown or not assessed, never as
    // protected"). Revisit this call (a filter-to-evaluated-dimensions
    // rule, or a dedicated cross-dimension precedence) before that
    // happens — do not assume this reasoning still holds.
    //
    // A second, separate disclosed fragility: `PROTECTION_VERDICTS`
    // includes `'not_applicable'`, which is NOT a `FLOW_SUMMARY_VALUES`
    // member (schema.js) — confirmed directly. No producer today ever
    // sets a dimension's verdict to `'not_applicable'`, so
    // `aggregateVerdicts` can never actually return it here — but if a
    // future analyzer ever does, `flow.protectionSummary` could fail
    // `validateGraph`. See `test/lineage/protection-summary.test.js`'s
    // `I1/5` for the currently-true, narrower claim this rests on.
    const flowEdge = edgesById.get(edgeIdStr);
    // Defensive only, mirroring this loop's own established convention
    // (see the atRest block above) — `flowEdge` should always be found,
    // the SAME id this flow's own `edgeIds: [edgeIdStr]` uses below.
    const protectionSummary = flowEdge
      ? aggregateVerdicts([
          flowEdge.protection.transit.verdict,
          flowEdge.protection.atRest.verdict,
          flowEdge.protection.handling.verdict,
        ])
      : 'not_assessed';
    flowsById.set(fId, {
      id: fId, dataElementIds: [de.id], source: src.id, sink: snk.id,
      edgeIds: [edgeIdStr], transformationIds: sortedT,
      alternatePathCount: group.length - 1,
      policyVerdict,
      protectionSummary,
      evidenceRefs: policyEvidenceRefs,
      confidence: g.grade === 'explicit' ? { score: 0.8, tier: 'high' } : { score: 0.5, tier: 'medium' },
      // Deliverable #10 (DFG-020, graph-derived DPIA/RoPA migration):
      // opts.resolveGovernanceRefs(dataClasses) -> governance-field record,
      // applied at this exact mint point — same additive-hook shape every
      // sibling hook in this file uses (resolveSiteDecision/resolveDestination/
      // resolveTransitProtection), byte-identical graph when omitted. Never
      // fabricates a governance fact — the hook itself (composed by
      // coverage.js's default) only ever attaches operator-supplied config or
      // the MANUAL_REQUIRED sentinel dataflow/privacy-governance.js already
      // establishes; this mint site has no opinion of its own.
      coverageStatus: snk.coverageStatus, findingRefs: [],
      governanceRefs: opts.resolveGovernanceRefs?.(de.dataClasses ?? []) ?? {},
      limitations,
      evidenceGrade: g.grade,
      handling: handlingResult,
    });
  }

  // Milestone 2, Sub-project D, increment 2 (FR-307): appliesToAllPaths.
  // Must run AFTER groupsByFlowKey is fully populated (every flow group for
  // every sink has been discovered) and BEFORE transformsById is read into
  // graph.transformations — see DESIGN_HANDLING_ANALYZER.md §5 for the full
  // rule and why no special-casing is needed for a truncated/incomplete path.
  const coarseGroups = new Map();
  for (const [, group] of groupsByFlowKey) {
    const { src, snk, de, sortedT } = group[0];
    const coarseKey = `${src.id}|${snk.id}|${de.id}`;
    if (!coarseGroups.has(coarseKey)) coarseGroups.set(coarseKey, []);
    coarseGroups.get(coarseKey).push(sortedT);
  }
  for (const flowsSortedT of coarseGroups.values()) {
    const relevantIds = new Set(flowsSortedT.flat());
    for (const tid of relevantIds) {
      const appliesToAll = flowsSortedT.every((st) => st.includes(tid));
      const t = transformsById.get(tid);
      t.appliesToAllPaths = t.appliesToAllPaths === null ? appliesToAll : (t.appliesToAllPaths && appliesToAll);
    }
  }

  // AC-11's coarse half, source side: every seeded source is a node and a
  // data element even when nothing reached a sink from it.
  for (const s of seeds) {
    const n = sourceNodeFor(s);
    const d = mintDataElement(s);
    if (!n.dataElementIds.includes(d.id)) n.dataElementIds.push(d.id);
  }

  // §5's enumerator union: §16.7's degraded terminals become `unresolved`
  // nodes with the vocabulary DESIGN_REGISTRIES.md already fixed.
  const degraded = degradedTerminals(store);
  for (const dn of degraded) {
    const n = mintNode({
      kind: 'unresolved', category: null, coverageStatus: 'partial', externality: 'unknown',
      coverageReason: 'analysis degraded: a context-cap-degraded hop ends here, so this endpoint\'s continuation was never analyzed (DESIGN_PATH_PROVENANCE.md §16.7 Finding 2)',
      subtypeKey: 'context-cap-degraded', lifecycleStages: [],
    });
    const seed = seedByDe.get(dn.dataElementId);
    if (seed) {
      const d = mintDataElement(seed);
      if (!n.dataElementIds.includes(d.id)) n.dataElementIds.push(d.id);
    }
  }

  const byId = (a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
  graph.nodes = [...nodesById.values()].sort(byId);
  graph.dataElements = [...deById.values()].sort(byId);
  graph.edges = [...edgesById.values()].sort(byId);
  graph.transformations = [...transformsById.values()].sort(byId);
  graph.flows = [...flowsById.values()].sort(byId);
  // Milestone 2, Sub-project G, increment 1: the first real populator of
  // `graph.evidence[]` — every permitting policy rule minted above.
  graph.evidence = [...evidenceById.values()].sort(byId);
  // Milestone 4, FR-506 (Third-Party and Cross-Border Intelligence): a
  // THIRD, SEPARATE, additive hook of the identical shape — composes with,
  // never replaces, `resolveDestination`/`resolveSiteDecision` above.
  // Deliberately NOT gated on `site.destination` being present: unlike a
  // protection/policy verdict, a recipient's technical-provider match can
  // resolve from `site.entry.framework` alone (e.g. a receiver-based
  // `anthropic.messages.create()` SDK call, AC-07's own real fixture shape,
  // whose destination frequently never resolves past 'unknown'/'dynamic' —
  // there is no literal URL to resolve) — skipping every site with no
  // destination would silently drop exactly that real-world case. Runs
  // here, after nodes/edges/flows/dataElements are populated (not right
  // after resolveDestination, where it originally ran), specifically so
  // `computeGraphDigest(graph)` inside `buildRecipientProfile` hashes real
  // graph content instead of the still-empty envelope (fix-round-1, B2). A
  // no-op when omitted, mirroring every sibling hook's own proven
  // contract.
  if (typeof opts.buildRecipientProfile === 'function') {
    for (const site of sites) {
      const profile = opts.buildRecipientProfile(site, graph);
      if (profile) {
        // fix-round-1, B3: `sinkNodeFor(site).id` is the real, stable
        // graph node id (`mintNode` dedups by id, so calling it again
        // here is idempotent) — `site.nodeId` is a CFG-parse-local
        // counter value (`parser-js.js`'s `_nodeIdSeq`, e.g. `"n6"`),
        // never a real graph node id, which made `--filter` a permanent
        // no-op against `contributingGraphIds`.
        const nodeId = sinkNodeFor(site).id;
        const existing = recipientProfilesById.get(profile.id);
        if (existing) {
          existing.contributingGraphIds = [...new Set([...existing.contributingGraphIds, nodeId])];
          // fix-round-1, M6: an order-dependent dedup previously kept only
          // the FIRST-seen site's whole profile, silently dropping a
          // later site's non-null facts (e.g. a `technicalEndpoint` the
          // first site never resolved). Merge any fact field the existing
          // record left empty from this later, non-empty profile.
          for (const field of RECIPIENT_FACT_FIELDS) {
            const existingEmpty = existing[field] == null || (Array.isArray(existing[field]) && existing[field].length === 0);
            const incomingPopulated = profile[field] != null && !(Array.isArray(profile[field]) && profile[field].length === 0);
            if (existingEmpty && incomingPopulated) {
              existing[field] = profile[field];
              existing.fieldEvidence[field] = profile.fieldEvidence[field];
            }
          }
        } else {
          recipientProfilesById.set(profile.id, { ...profile, contributingGraphIds: [nodeId] });
        }
      }
    }
  }
  // Milestone 4, FR-506: unlike `graph.evidence[]` immediately above
  // (which IS required/core-schema, validated by `validate.js`'s
  // `_validateEvidence`/`EVIDENCE_TYPES`), `graph.recipientProfiles` is
  // the FIRST §10.10 extension-record array ever attached directly to
  // the graph object — every prior extension contract
  // (ObligationMapping/DecisionStory/GraphSnapshot) is a wholly separate
  // artifact, never stored on the built graph itself. Never in
  // `dataflow-graph.schema.json`, never routed through `validateGraph()`.
  graph.recipientProfiles = [...recipientProfilesById.values()].sort(byId);
  // §10's SKETCH of the coverage ledger. E4 owns the finished contract.
  graph.coverage = {
    languages: [], parseFailures: [],
    destinationResolutionStatus: 'not-attempted',
    pathBudgetTruncation: stats.truncatedQueries > 0,
    sources: { matched: seeds.length, unseedable: unseedable.length, dataElements: deById.size },
    sinks: {
      callStatementSites: sites.length,
      connected: stats.connectedSinkSites,
      disconnected: sites.length - stats.connectedSinkSites,
      nonStatementSitesNotEnumerable: nonStatementSites.length,
    },
    degradedTerminals: degraded.length,
    paths: { enumerated: stats.pathsEnumerated, projected: stats.pathsProjected, truncatedQueries: stats.truncatedQueries },
    provenance: { hops: hops.length, pnodes: store.stats().nodes, pedges: store.stats().edges },
  };
  graph.limitations = [
    'Protection verdicts are not assessed in Milestone 1: every edge carries not_assessed/none on all three dimensions.',
    'Policy verdicts are not evaluated in Milestone 1.',
    'External destinations are not resolved (FR-202 is Milestone 2); protocol.destinationResolution is "unknown" on every edge.',
  ];
  graph.scanHealth = { status: 'complete', reason: 'lineage-graph-builder' };
  graph.taxonomy = { version: '1.0.0', source: 'built-in + CONFIDENTIAL extension' };

  return { graph, store, hops, seeds, unseedable, sites, nonStatementSites, degraded, stats, decisionsByNodeId };
}
