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

import { runFieldIdentityAnalysis } from './driver.js';
import { PathStore } from './path-store.js';
import { reconstructPaths } from './path-query.js';
import { gradePath, DEGRADED_LOSS_REASONS } from './flow-grade.js';
import { reclassifySink, reclassifyPrivacySink } from './sink-registry.js';
import { recognizeTransformation } from './transform-catalog.js';
import { emptyGraphEnvelope } from './schema.js';
import { emptyProtection } from './protection.js';
import * as ids from './ids.js';
import { planSeeds, seedEntryStateFactory, exprRoots, walkExpr } from './source-seeding.js';

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
        if (r) sites.push({ file: fn.file, qid: fn.qid, nodeId: nid, line: node.line ?? null, calleeExpr: node.callee, args: node.args ?? [], ...r });
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

  const mintNode = ({ kind, category, coverageStatus, externality, coverageReason, subtypeKey, lifecycleStages, destination }) => {
    // NOTE (Milestone 2, Sub-project A, increment 1): `destination` is
    // deliberately NOT part of this discriminator — the node identity
    // model stays exactly what it was in Milestone 1 (a registry decision,
    // never a per-call-site fact), so two sites sharing one
    // (kind, subtypeKey, coverageStatus, externality) tuple still mint/
    // collide onto ONE node, and that node's `destination` is whichever
    // site's resolution was applied FIRST (mintNode only sets it at
    // creation, same as every other field below) — a known, disclosed
    // coarsening, not a bug; see DESIGN_DESTINATION_RESOLVER.md.
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
            // §7.3: honest absences. `appliesToAllPaths` needs FR-307's
            // all-path proof, which nothing here does. There is NO
            // control-credit key of any kind — not even `false`, which
            // would read as "considered and denied" (Decision 2).
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
            boundaryCrossings: [], protection: emptyProtection(),
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
    flowsById.set(fId, {
      id: fId, dataElementIds: [de.id], source: src.id, sink: snk.id,
      edgeIds: [edgeIdStr], transformationIds: sortedT,
      alternatePathCount: group.length - 1,
      // §8's defaults, both honest and both derived, never asserted.
      policyVerdict: 'not_evaluated',
      protectionSummary: 'not_assessed',
      evidenceRefs: [],
      confidence: g.grade === 'explicit' ? { score: 0.8, tier: 'high' } : { score: 0.5, tier: 'medium' },
      coverageStatus: snk.coverageStatus, findingRefs: [], governanceRefs: {},
      limitations,
      evidenceGrade: g.grade,
    });
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
