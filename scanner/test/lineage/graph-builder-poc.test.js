//
// graph-builder-poc.test.js — Sub-project E, increment 1's DESIGN-SPIKE
// proof-of-concept.
//
// ┌───────────────────────────────────────────────────────────────────────┐
// │ THIS FILE IS DELIBERATELY THROWAWAY. DELETE IT, DO NOT EXTEND IT.     │
// │                                                                       │
// │ It mirrors the convention every prior sub-project's first increment   │
// │ already established (C4's path-store PoC, C5's path-query PoC, C6's   │
// │ flow-grade PoC, D1's registry-mapping PoC — all four named            │
// │ `*-poc.test.js`, all four absorbed and deleted by the increment that  │
// │ shipped the real module). The ABSORPTION PROTOCOL is stated exactly,  │
// │ not left implicit, in `src/lineage/DESIGN_GRAPH_BUILDER.md` §9.1:     │
// │   - E2 absorbs the SEEDING half (E1/1 – E1/5, PLUS E1/14, the         │
// │     escalated engine limitation — E1/14 is about seeding reaching a   │
// │     sink, not about projection) into                                  │
// │     `test/lineage/source-seeding.test.js` and deletes those tests     │
// │     from here.                                                        │
// │   - E3 absorbs the PROJECTION half (E1/6 – E1/13) into                │
// │     `test/lineage/graph-builder.test.js`.                             │
// │   - Whichever of E2/E3 lands SECOND deletes this file, removes it     │
// │     from `package.json`'s `test:lineage` script, and removes its row  │
// │     from `src/lineage/CLAUDE.md` — after confirming the other's       │
// │     absorption is complete. Neither may delete it unilaterally.       │
// │     (D1 §9.1's two-lander rule, reused verbatim.)                     │
// └───────────────────────────────────────────────────────────────────────┘
//
// Everything below the "MECHANISM" banner is a LOCAL prototype of what
// E2's `source-seeding.js` and E3's `graph-builder.js` will ship. It lives
// in the test file on purpose: a design spike proves a mechanism against
// real code without committing shipped modules to it. The ONE shipped
// change this increment made is the additive `opts.seedEntryState` hook on
// `driver.js` (plus the cache-key fix that hook makes load-bearing) —
// proven backward-compatible in `driver.test.js`, not here.
//

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

import { buildProjectIR } from '../../src/ir/index.js';
// ── the reuse boundary this increment confirms (E1 item (g)) ─────────────
// Three PURE, module-level functions from `src/dataflow/`, and nothing else
// from that package. Never `dataflow/engine.js`'s live taint state, never
// `dataflow/summaries.js`'s SummaryCache (PRD §18.1). `E1/12` asserts this
// file's own import list mechanically, in the shape `path-query.js`'s own
// `['./ids.js']` boundary test established.
import { matchSource, matchSinkOrSanitizer } from '../../src/dataflow/catalog.js';
import { matchPrivacySink } from '../../src/dataflow/privacy-catalog.js';
import { accessPathOf } from '../../src/dataflow/access-paths.js';

import { emptyState, addIdentity } from '../../src/lineage/field-identity.js';
import { runFieldIdentityAnalysis } from '../../src/lineage/driver.js';
import { PathStore } from '../../src/lineage/path-store.js';
import { reconstructPaths } from '../../src/lineage/path-query.js';
import { gradePath, DEGRADED_LOSS_REASONS } from '../../src/lineage/flow-grade.js';
import { reclassifySource } from '../../src/lineage/source-registry.js';
import { reclassifySink, reclassifyPrivacySink } from '../../src/lineage/sink-registry.js';
import { recognizeTransformation } from '../../src/lineage/transform-catalog.js';
import {
  emptyGraphEnvelope, SOURCE_CATEGORIES, SINK_CATEGORIES, COVERAGE_STATUS_VALUES,
} from '../../src/lineage/schema.js';
import { emptyProtection } from '../../src/lineage/protection.js';
import { classifyDataElementName } from '../../src/lineage/classification.js';
import * as ids from '../../src/lineage/ids.js';
import { validateGraph } from '../../src/lineage/validate.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const VULN_JS_DIR = path.join(__dirname, '..', 'fixtures', 'vulnerable-js');

// =========================================================================
// MECHANISM — the prototype E2/E3 implement. See DESIGN_GRAPH_BUILDER.md.
// =========================================================================

/**
 * §3.1. The expression ROOTS a CFG node carries, matching `engine.js`'s own
 * `step()` switch exactly — `assign`→`source`, `call`→`callee`+`args`,
 * `return`→`value`. Deliberately NOT `fn.reads`/`fn.calls`: D5 already
 * measured that a call used as an assignment RHS never reaches `fn.calls[]`
 * at all, so those side-channels are incomplete for this purpose.
 */
function exprRoots(node) {
  const r = [];
  if (node.kind === 'assign' && node.source) r.push(node.source);
  if (node.kind === 'call') { if (node.callee) r.push(node.callee); for (const a of node.args ?? []) r.push(a); }
  if (node.kind === 'return' && node.value) r.push(node.value);
  return r;
}

function exprChildren(e) {
  switch (e.kind) {
    case 'member': return [e.object];
    case 'call': return [e.callee, ...(e.args ?? [])];
    case 'tpl': return e.parts ?? [];
    case 'binary': case 'logical': return [e.left, e.right];
    case 'union': return e.options ?? [];
    case 'array': return e.elements ?? [];
    case 'object': return (e.props ?? []).map((p) => p.value);
    case 'assign-expr': return [e.source ?? e.value];
    default: return [];
  }
}

function walkExpr(e, visit, parent = null) {
  if (!e || typeof e !== 'object') return;
  visit(e, parent);
  for (const c of exprChildren(e)) walkExpr(c, visit, e);
}

/**
 * §3.2, THE SEED-PATH RULE. `matchSource` matches the CONTAINER
 * (`req.body`), but the thing with a field identity is the FIELD
 * (`req.body.card_number`). Extend the matched expression outward through
 * every enclosing pure-member access, then take `accessPathOf` of the
 * outermost. Falls back to the matched expression's own path when it is not
 * the object of a member access (`User.create(req.body)`), which is exactly
 * the container-level seed that case deserves.
 */
function seedPathFor(expr, parentOf) {
  let cur = expr;
  for (;;) {
    const p = parentOf.get(cur);
    if (p && p.kind === 'member' && p.object === cur && typeof p.prop === 'string') { cur = p; continue; }
    break;
  }
  return accessPathOf(cur);
}

/** §3.3. Plan the seeds for a whole project. Pure: runs no analysis. */
function planSeeds(callGraph, { repository }) {
  const seeds = [];
  const unseedable = [];
  for (const fn of callGraph.functions.values()) {
    for (const [nid, node] of Object.entries(fn.cfg?.nodes ?? {})) {
      const parentOf = new Map();
      for (const root of exprRoots(node)) walkExpr(root, (e, p) => { if (p) parentOf.set(e, p); });
      for (const root of exprRoots(node)) {
        walkExpr(root, (e) => {
          const entry = matchSource(e, fn.file);
          if (!entry) return;
          const decision = reclassifySource(entry);
          const seedPath = seedPathFor(e, parentOf);
          if (!seedPath) {
            unseedable.push({ file: fn.file, qid: fn.qid, nodeId: nid, line: node.line ?? null, entryId: entry.id, reason: 'accessPathOf returned null for the matched expression' });
            return;
          }
          const canonicalName = seedPath.slice(seedPath.lastIndexOf('.') + 1);
          seeds.push({
            file: fn.file, qid: fn.qid, nodeId: nid, line: node.line ?? null,
            entryId: entry.id, seedPath, canonicalName,
            category: decision.category, coverageStatus: decision.coverageStatus,
            externality: decision.externality, reason: decision.reason,
            // §3.4's minting rule. `canonicalName` alone is forbidden by
            // PRD §10.4; the discriminator carries the system proxy
            // (repository + file), the access path, and the category.
            dataElementId: ids.dataElementId(canonicalName, [repository, fn.file, seedPath, decision.category ?? '']),
            dataClasses: classifyDataElementName(canonicalName).classes,
          });
        });
      }
    }
  }
  return { seeds, unseedable };
}

/** §3.5. The `opts.seedEntryState(fn)` hook `driver.js` now accepts. */
function seedEntryStateFactory(seeds) {
  const byQid = new Map();
  for (const s of seeds) {
    if (!byQid.has(s.qid)) byQid.set(s.qid, []);
    byQid.get(s.qid).push(s);
  }
  return (fn) => {
    const list = byQid.get(fn.qid);
    if (!list) return null;
    let st = emptyState();
    for (const s of list) st = addIdentity(st, s.seedPath, s.dataElementId);
    return st;
  };
}

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
function enumerateSinkSites(callGraph) {
  const sites = [];
  const nonStatementSites = [];
  for (const fn of callGraph.functions.values()) {
    for (const [nid, node] of Object.entries(fn.cfg?.nodes ?? {})) {
      if (node.kind === 'call' && node.callee) {
        const r = resolveSinkAtCallSite(node.callee, fn.file);
        if (r) sites.push({ file: fn.file, qid: fn.qid, nodeId: nid, line: node.line ?? null, calleeExpr: node.callee, ...r });
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
 * `path-store.js` whatsoever. `E1/9` proves it fires on real parsed code.
 */
function degradedTerminals(store) {
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

/**
 * §6. THE PROJECTION. A `DataFlowGraph v1` node is a REGISTRY DECISION, not
 * a provenance node and not a call site: its identity is
 * `(kind, subtypeKey, coverageStatus, externality, destination)`. Edges and
 * flows stay field- and path-granular, so nothing FR-305 protects is lost.
 */
function buildDataFlowGraph(callGraph, opts = {}) {
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
    generatedAt: opts.generatedAt ?? '1970-01-01T00:00:00.000Z',
  });

  const nodesById = new Map();
  const edgesById = new Map();
  const flowsById = new Map();
  const transformsById = new Map();
  const deById = new Map();
  // Every registry decision that landed on each node id — the raw material
  // for `E1/8`'s "no two DIFFERENT decisions collided onto one node" check.
  const decisionsByNodeId = new Map();

  const mintNode = ({ kind, category, coverageStatus, externality, coverageReason, subtypeKey, lifecycleStages }) => {
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
        destination: null,
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
            protocol: { name: 'in-process', destinationResolution: 'unknown' },
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
  graph.scanHealth = { status: 'complete', reason: 'lineage-poc' };
  graph.taxonomy = { version: '1.0.0', source: 'built-in + CONFIDENTIAL extension' };

  return { graph, store, hops, seeds, unseedable, sites, nonStatementSites, degraded, stats, decisionsByNodeId };
}

// =========================================================================
// Fixture helpers
// =========================================================================

function irOf(fileContents) {
  const { callGraph } = buildProjectIR(fileContents);
  return callGraph;
}

function vulnerableJs() {
  return { 'app.js': fs.readFileSync(path.join(VULN_JS_DIR, 'app.js'), 'utf8') };
}

// =========================================================================
// E1/1 – E1/5: THE SEEDING HALF (E2 absorbs these)
// =========================================================================

test('E1/1: the SHIPPED driver still emits exactly ZERO hops on real code with no seeding hook — the measured gap this increment exists to close', () => {
  for (const fc of [vulnerableJs()]) {
    const callGraph = irOf(fc);
    const hops = [];
    runFieldIdentityAnalysis(callGraph, { recordHop: (h) => hops.push(h) });
    const store = new PathStore();
    store.addHops(hops);
    assert.equal(hops.length, 0, 'no seeding hook => no identity can enter the analysis => no hop can fire');
    assert.equal(store.stats().nodes, 0);
    assert.equal(store.stats().edges, 0);
  }
});

test('E1/2: matchSource/reclassifySource/accessPathOf compose into real seeds on real parsed code — 9 call-site matches, 3 distinct catalog entries, 6 data elements', () => {
  const callGraph = irOf(vulnerableJs());
  const { seeds, unseedable } = planSeeds(callGraph, { repository: 'vuln' });

  assert.equal(seeds.length, 9, 'nine matched source call sites (the scoping doc\'s own §2.3 measurement, reproduced)');
  assert.equal(unseedable.length, 0, 'every matched source expression has an access path');
  assert.deepEqual([...new Set(seeds.map((s) => s.entryId))].sort(), ['js-req-body', 'js-req-params', 'js-req-query']);
  assert.deepEqual([...new Set(seeds.map((s) => s.category))].sort(), ['http-body', 'http-query', 'http-route']);
  assert.ok(seeds.every((s) => COVERAGE_STATUS_VALUES.includes(s.coverageStatus)));

  // §3.2's seed-path rule lands on the FIELD, not the container: the
  // matched expression is `req.body`, the seeded path is `req.body.host`.
  const paths = [...new Set(seeds.map((s) => s.seedPath))].sort();
  assert.deepEqual(paths, [
    'req.body', 'req.body.expr', 'req.body.host', 'req.body.password', 'req.params.id', 'req.query.name',
  ], 'the seed path is the longest enclosing pure-member chain, so a field keeps its own identity');

  // Field-level naming is what makes classification possible at all.
  const pw = seeds.find((s) => s.canonicalName === 'password');
  assert.ok(pw, 'req.body.password mints a data element literally named "password"');
  assert.deepEqual(pw.dataClasses, ['CREDENTIALS'],
    'classifyDataElementName only works because the seed path reaches the field — a container-level "body" seed classifies as nothing');

  assert.equal(new Set(seeds.map((s) => s.dataElementId)).size, 6,
    'nine call sites collapse to six data elements: two reads of req.params.id in one function are ONE element');
});

test('E1/3: the dataElementId discriminator satisfies PRD §10.4 — same field name in two files/services is two elements, and the id is never a function of the name alone', () => {
  const same = 'function h(req){ sink(req.body.email); }';
  const cgA = irOf({ 'serviceA/api.js': same });
  const cgB = irOf({ 'serviceB/api.js': same });
  const a = planSeeds(cgA, { repository: 'r' }).seeds;
  const b = planSeeds(cgB, { repository: 'r' }).seeds;
  assert.equal(a.length, 1);
  assert.equal(b.length, 1);
  assert.equal(a[0].canonicalName, 'email');
  assert.equal(b[0].canonicalName, 'email');
  assert.notEqual(a[0].dataElementId, b[0].dataElementId,
    'PRD §10.4: `email` in two unrelated services must remain TWO data elements');

  // Two DIFFERENT fields in ONE file are also two elements...
  const cgC = irOf({ 'one.js': 'function h(req){ sink(req.body.email); sink(req.body.ssn); }' });
  const c = planSeeds(cgC, { repository: 'r' }).seeds;
  assert.equal(new Set(c.map((s) => s.dataElementId)).size, 2);
  // ...and the SAME field read twice in one file is ONE element.
  const cgD = irOf({ 'one.js': 'function h(req){ sink(req.body.email); log(req.body.email); }' });
  const d = planSeeds(cgD, { repository: 'r' }).seeds;
  assert.equal(d.length, 2, 'two matched call sites');
  assert.equal(new Set(d.map((s) => s.dataElementId)).size, 1, 'one logical field => one data element');

  // The same repository+file+path+category always mints the same id, and
  // the id is a content hash, never a counter.
  assert.equal(
    ids.dataElementId('email', ['r', 'serviceA/api.js', 'req.body.email', 'http-body']),
    a[0].dataElementId,
  );
  assert.notEqual(ids.dataElementId('email', []), a[0].dataElementId,
    'the bare name alone must never produce this id');
});

test('E1/4: the real seeding mechanism produces real hops through the SHIPPED driver — 0 becomes 23 on vulnerable-js', () => {
  const callGraph = irOf(vulnerableJs());
  const { seeds } = planSeeds(callGraph, { repository: 'vuln' });
  const hops = [];
  runFieldIdentityAnalysis(callGraph, { recordHop: (h) => hops.push(h), seedEntryState: seedEntryStateFactory(seeds) });
  const store = new PathStore();
  store.addHops(hops);

  // Numbers updated (hotfix, 2026-08-31 — scanner/src/lineage/engine.js's
  // unresolved-`call` receiver-identity fix; see DESIGN_GRAPH_BUILDER.md
  // §11's now-RESOLVED escalation entry): before the fix, `pan.slice(0, 4)`
  // (and every other method call whose RECEIVER, not its arguments, carried
  // the only identity in play) silently dropped that identity, so real
  // seeding on vulnerable-js undercounted. Re-measured against real parsed
  // code: 19 -> 23 hops, 14 -> 15 nodes, edges unchanged at 8 -> now 9.
  assert.equal(hops.length, 23, 'measured: real seeding emits 23 hops where the shipped driver emits 0');
  const st = store.stats();
  assert.equal(st.nodes, 15);
  assert.equal(st.edges, 9);
  assert.deepEqual(store.diagnostics().malformed, [], 'no malformed hop reaches the store');
  assert.deepEqual(store.diagnostics().unclassified, [], 'every out-half matches one of §14.3\'s rules');

  // Real seeding is deliberately NARROWER than the synthetic per-parameter
  // seed the scoping doc measured (21 hops / 16 pnodes / 9 pedges — this
  // synthetic figure is UNCHANGED by the hotfix, re-measured directly
  // against the fixed engine): it seeds only paths a registry actually
  // matched, not every parameter, and that narrower footprint is still
  // reflected in a strictly smaller NODE count (15 < 16). The prior raw
  // HOP-COUNT comparison (real < synthetic) no longer holds numerically
  // post-fix: recursively resolving a method call's receiver emits its own
  // additional intraprocedural hops wherever a receiver carries an
  // identity, and the fixture's specific field-precise seed paths happen to
  // hit more such receiver call sites than the coarser per-parameter seed
  // does here — a real, disclosed, and expected side effect of correctly
  // no longer dropping receiver-borne identity, not a regression in
  // narrowness of WHAT gets seeded.
  assert.ok(st.nodes < 16, 'a real seed still produces a strict subset of "one identity per parameter"\'s pnode count');

  const kinds = [...new Set(store.nodes().map((n) => n.kind))].sort();
  assert.deepEqual(kinds, ['escape', 'path'],
    'real code reaches `path` and `escape` only — still zero `loss`, zero `origin`, zero `return`, matching §2.1\'s own finding');
});

test('E1/5: a seeded flow is field-precise end to end — two distinct fields of the SAME container reach two different sinks without merging (FR-301 through the whole pipeline)', () => {
  const callGraph = irOf({
    'r.js': 'function h(req, db, logger){ const a = req.body.card_number; const b = req.body.nickname; db.query(a); logger.info(b); }',
  });
  const { graph } = buildDataFlowGraph(callGraph, { repository: 'fp' });
  assert.equal(graph.dataElements.length, 2);
  const byName = Object.fromEntries(graph.dataElements.map((d) => [d.name, d]));
  assert.deepEqual(byName.card_number.dataClasses, ['PCI']);
  assert.deepEqual(byName.nickname.dataClasses, []);

  assert.equal(graph.flows.length, 2);
  for (const f of graph.flows) {
    assert.equal(f.dataElementIds.length, 1, 'a flow carries exactly the field that reached that sink, never both');
  }
  const sinkKinds = graph.flows.map((f) => graph.nodes.find((n) => n.id === f.sink).subtype).sort();
  assert.deepEqual(sinkKinds, ['database', 'log']);
  const cardFlow = graph.flows.find((f) => f.dataElementIds[0] === byName.card_number.id);
  assert.equal(graph.nodes.find((n) => n.id === cardFlow.sink).subtype, 'database',
    'the PCI field reached the DATABASE, and the graph says exactly that — no cross-field merge anywhere in the chain');
});

// =========================================================================
// E1/6 – E1/12: THE PROJECTION HALF (E3 absorbs these)
// =========================================================================

test('E1/6: the projection produces a validated, flagship-scale DataFlowGraph v1 from real parsed code', () => {
  const callGraph = irOf(vulnerableJs());
  const r = buildDataFlowGraph(callGraph, { repository: 'vulnerable-js', generatedAt: '2026-08-31T00:00:00.000Z' });

  const v = validateGraph(r.graph);
  assert.deepEqual(v.errors, [], 'validateGraph must return no errors');
  assert.equal(v.valid, true);

  assert.equal(r.graph.nodes.length, 9);
  assert.equal(r.graph.edges.length, 6);
  assert.equal(r.graph.dataElements.length, 6);
  assert.equal(r.graph.flows.length, 6);

  // §2.4's warning: validity alone proves nothing. An EMPTY graph also
  // validates, so pin non-emptiness as its own assertion.
  const empty = emptyGraphEnvelope({ graphId: ids.graphId({ repository: 'x' }) });
  assert.equal(validateGraph(empty).valid, true, 'an empty graph validates too — this is why the counts above are asserted');

  // The order-of-magnitude claim, against the ONE reference artifact that
  // exists: the hand-built flagship fixture is 14 nodes for a whole
  // synthetic payments platform.
  assert.ok(r.graph.nodes.length <= 14,
    'a 42-line fixture must not out-node a whole synthetic platform (flagship: 14)');
  // Updated (hotfix, 2026-08-31 — scanner/src/lineage/engine.js's
  // unresolved-`call` receiver-identity fix, see E1/4's own comment for the
  // full explanation): 19 -> 23. Node/edge/dataElement/flow counts above
  // are UNCHANGED by the fix — the extra hops are additional
  // intraprocedural provenance detail for identity that was already
  // reaching its sink through other paths, not a change to which
  // sources/sinks/fields the projection connects.
  assert.equal(r.hops.length, 23);
});

test('E1/7: node count is SYSTEM-granular and provably invariant under code growth, while edges/flows/dataElements stay field-granular', () => {
  const base = fs.readFileSync(path.join(VULN_JS_DIR, 'app.js'), 'utf8');
  const measured = [];
  for (const copies of [1, 10, 50]) {
    const fc = {};
    for (let i = 0; i < copies; i += 1) fc[`svc${i}/app.js`] = base;
    const r = buildDataFlowGraph(irOf(fc), { repository: 'scale' });
    assert.deepEqual(validateGraph(r.graph).errors, [], `copies=${copies} must still validate`);
    measured.push({ copies, nodes: r.graph.nodes.length, edges: r.graph.edges.length, flows: r.graph.flows.length, de: r.graph.dataElements.length });
  }
  assert.deepEqual(measured, [
    { copies: 1, nodes: 9, edges: 6, flows: 6, de: 6 },
    { copies: 10, nodes: 9, edges: 60, flows: 60, de: 60 },
    { copies: 50, nodes: 9, edges: 300, flows: 300, de: 300 },
  ], 'nodes stay at 9 across a 50x code-size increase; edges/flows/dataElements scale linearly — this IS the projection rule');
});

test('E1/8: the assertions validate.js structurally CANNOT make (§2.4\'s two failure modes)', () => {
  const r = buildDataFlowGraph(irOf(vulnerableJs()), { repository: 'vulnerable-js' });
  const { graph } = r;

  // (a) every node.subtype is a real registry-vocabulary value, or null.
  //     `validate.js` has no check for this at all.
  const vocab = new Set([...SOURCE_CATEGORIES, ...SINK_CATEGORIES]);
  for (const n of graph.nodes) {
    assert.ok(n.subtype === null || vocab.has(n.subtype),
      `node.subtype "${n.subtype}" must be a SOURCE_CATEGORIES/SINK_CATEGORIES member or null (Decision 1)`);
    assert.ok(typeof n.coverageReason === 'string' && n.coverageReason.length > 0,
      'AC-11: every node carries a non-empty coverage reason');
  }

  // (b) node.dataElementIds is only checked to be an ARRAY by validate.js.
  const deIds = new Set(graph.dataElements.map((d) => d.id));
  for (const n of graph.nodes) {
    for (const id of n.dataElementIds) assert.ok(deIds.has(id), `node ${n.id} references unknown dataElement ${id}`);
  }

  // (c) no two DIFFERENT registry decisions collided onto one node id.
  for (const [nodeId, decisions] of r.decisionsByNodeId) {
    const distinct = new Set(decisions.map((d) => JSON.stringify(d)));
    assert.equal(distinct.size, 1, `node ${nodeId} was minted from ${distinct.size} different registry decisions — the discriminator is under-specified`);
  }

  // (d) flow.edgeIds are real `edge:` ids, never `pedge:`/`ppath:` ones.
  for (const f of graph.flows) {
    for (const e of f.edgeIds) assert.ok(e.startsWith('edge:'), `flow.edgeIds must never carry a provenance id — got ${e}`);
    assert.ok(f.id.startsWith('flow:'));
  }
  for (const e of graph.edges) assert.ok(e.id.startsWith('edge:'));
  for (const t of graph.transformations) assert.ok(t.id.startsWith('transform:'));

  // (e) id uniqueness within each entity array (validate.js does check this,
  //     but only because the discriminators below are complete — pin them).
  for (const key of ['nodes', 'edges', 'dataElements', 'flows', 'transformations']) {
    const list = graph[key].map((x) => x.id);
    assert.equal(new Set(list).size, list.length, `${key} contains a duplicate id`);
  }
});

test('E1/9 (item d): multi-candidate sink resolution — promote via the receiver where it disambiguates, else ONE node at the plurality category, `partial`, with the alternatives named', () => {
  const cg = irOf({ 'a.js': 'function h(res, x){ res.send(x); }' });
  const site = enumerateSinkSites(cg).sites[0];
  assert.equal(site.entry.id, 'js-express-res-send');
  assert.equal(site.decision.category, 'http-response');
  assert.equal(site.decision.coverageStatus, 'modeled', 'a receiver-resolved match keeps its own coverage status — no demotion');
  assert.equal(site.ambiguity.resolvedBy, 'receiver');
  assert.deepEqual(site.ambiguity.alternatives, ['js-koa-send', 'privacy-js-res-send'],
    'the scoping doc measured 2 candidates via matchSinkOrSanitizer alone; adding matchPrivacySink makes it 3');

  // Same callee, a receiver NOTHING declares a constraint for: no candidate
  // is receiver-justified, the categories disagree, so the plurality rule
  // fires — one node, `partial`, alternatives named in the reason.
  const cg2 = irOf({ 'b.js': 'function h(ctx, x){ ctx.send(x); }' });
  const site2 = enumerateSinkSites(cg2).sites[0];
  assert.equal(site2.ambiguity.resolvedBy, 'plurality');
  assert.equal(site2.decision.coverageStatus, 'partial', 'never a silent pick at full confidence');
  assert.ok(site2.decision.reason.includes('AMBIGUOUS at this call site'));
  for (const alt of site2.ambiguity.alternatives) {
    assert.ok(site2.decision.reason.includes(alt), `the reason must name the alternative category ${alt}`);
  }
  assert.ok(site2.decision.reason.includes('js-koa-send') && site2.decision.reason.includes('privacy-js-res-send'),
    'and every candidate entry id, mirroring sink-registry.js\'s own thirdPartySdk convention');

  // Determinism: the plurality tie-break is lexicographic over the category
  // name, so the same input always resolves the same way.
  const again = enumerateSinkSites(irOf({ 'b.js': 'function h(ctx, x){ ctx.send(x); }' })).sites[0];
  assert.equal(again.decision.category, site2.decision.category);
});

test('E1/10 (item e): §16.7 Finding 2\'s enumerator is computable from path-store.js\'s PUBLIC read API alone, and fires on real degraded code', () => {
  const code = 'function id(v){ return v; }\n'
    + 'function h(req){ const a = req.body.a; const b = req.query.b; const c = req.params.c;\n'
    + '  const x = id(a); const y = id(b); const z = id(c); sinkA(x); sinkB(y); sinkC(z); }';
  const callGraph = irOf({ 'd.js': code });
  const { seeds } = planSeeds(callGraph, { repository: 'd' });
  assert.equal(seeds.length, 3, 'three distinct sources, so `id` is resolved under three distinct entry contexts');

  const run = (cap) => {
    const hops = [];
    runFieldIdentityAnalysis(callGraph, { recordHop: (h) => hops.push(h), seedEntryState: seedEntryStateFactory(seeds), maxContextsPerFn: cap });
    const store = new PathStore();
    store.addHops(hops);
    return { store, hops };
  };

  const wide = run(16);
  assert.equal(wide.hops.filter((h) => h.lossReason).length, 0, 'no degradation under the default cap');
  assert.equal(degradedTerminals(wide.store).length, 0, 'and therefore no degraded terminal — the enumerator does not over-fire');

  const tight = run(2);
  const lossReasons = [...new Set(tight.hops.filter((h) => h.lossReason).map((h) => h.lossReason))];
  assert.deepEqual(lossReasons, ['context-cap-degraded'], 'a real context-cap degradation is reachable from real parsed code');
  const dt = degradedTerminals(tight.store);
  assert.equal(dt.length, 1, 'exactly one truncation-terminal: a `path` node with zero out-edges whose in-edge is degraded');
  assert.equal(dt[0].kind, 'path');
  assert.equal(tight.store.edgesFrom(dt[0].id).length, 0, 'zero out-edges — invisible to sinkCandidates(), which is §16.7 Finding 2 exactly');
  assert.ok(tight.store.edgesTo(dt[0].id).length > 0, 'but reachable through edgesTo()');

  // It is NOT a sinkCandidates() result, which is the whole point.
  assert.ok(!['return', 'escape', 'loss'].includes(dt[0].kind));

  // The node the projection mints for it uses the ALREADY-FIXED vocabulary
  // (DESIGN_REGISTRIES.md's closing section) — never a re-derived one.
  const r = buildDataFlowGraph(callGraph, { repository: 'd', maxContextsPerFn: 2 });
  const unresolved = r.graph.nodes.filter((n) => n.kind === 'unresolved');
  assert.equal(unresolved.length, 1);
  assert.equal(unresolved[0].coverageStatus, 'partial');
  assert.equal(unresolved[0].externality.value, 'unknown');
  assert.ok(unresolved[0].coverageReason.includes('context-cap'), 'the reason names the degradation');
  assert.deepEqual(validateGraph(r.graph).errors, []);
});

test('E1/11 (Step 5): transformation entities — a recognized `mask`, an honest `unknown`, and NO control-credit field of any kind', () => {
  const code = 'function maskCard(pan){ return \'****\' + pan; }\n'
    + 'function handle(req, logger){\n'
    + '  const card = req.body.card_number;\n'
    + '  const masked = maskCard(card);\n'
    + '  logger.info(masked);\n'
    + '  const shaped = reshapeForVendor(card);\n'
    + '  logger.warn(shaped);\n'
    + '}';
  const r = buildDataFlowGraph(irOf({ 'x.js': code }), { repository: 'tx' });
  assert.deepEqual(validateGraph(r.graph).errors, []);

  const byCallee = Object.fromEntries(r.graph.transformations.map((t) => [t.callee, t]));
  assert.ok(byCallee.maskCard, 'a recognized transform is attributed by callee name');
  assert.equal(byCallee.maskCard.kind, 'mask');
  assert.equal(byCallee.maskCard.reversibility, 'irreversible');
  assert.equal(byCallee.maskCard.confidence.tier, 'medium', 'transform-catalog.js\'s own naming-convention tier, carried through unchanged');

  // §7.2: `recognizeTransformation` returned null but the hop record says a
  // call widened the value — the entity's kind is `unknown`, never
  // `custom` ("custom" asserts a real transform we merely can't name).
  assert.ok(byCallee.reshapeForVendor, 'the unknown case is genuinely reachable on real parsed code');
  assert.equal(byCallee.reshapeForVendor.kind, 'unknown');
  assert.equal(byCallee.reshapeForVendor.reversibility, 'unknown');
  assert.equal(byCallee.reshapeForVendor.algorithm, null);
  assert.ok(byCallee.reshapeForVendor.evidence.includes('unresolved-call'));

  for (const t of r.graph.transformations) {
    assert.equal(t.appliesToAllPaths, null, 'FR-307\'s all-path proof does not exist yet; null, never true/false');
    const keys = Object.keys(t).join(' ');
    assert.ok(!/credit|granted|denied|verdict|protected/i.test(keys),
      `Decision 2: a transformation entity must carry NO control-credit field, not even false — got keys: ${keys}`);
  }

  // §8's flow/edge defaults, on every flow and every edge, always.
  for (const f of r.graph.flows) {
    assert.equal(f.protectionSummary, 'not_assessed');
    assert.equal(f.policyVerdict, 'not_evaluated');
  }
  for (const e of r.graph.edges) {
    assert.deepEqual(e.protection, emptyProtection(),
      '§10.7\'s "derived from the individual edge verdicts" is satisfied trivially because every edge verdict is not_assessed');
  }
});

test('E1/12 (item g): the reuse boundary — this PoC imports three PURE functions from src/dataflow/ and nothing else from that package', async () => {
  const self = fileURLToPath(import.meta.url);
  const src = fs.readFileSync(self, 'utf8');
  const specifiers = [...src.matchAll(/(?:from|import)\s*\(?\s*['"]([^'"]+)['"]/g)].map((m) => m[1]);

  const dataflowImports = specifiers.filter((s) => s.includes('/dataflow/'));
  assert.deepEqual(dataflowImports.sort(), [
    '../../src/dataflow/access-paths.js',
    '../../src/dataflow/catalog.js',
    '../../src/dataflow/privacy-catalog.js',
  ], 'exactly three dataflow modules, all of them pure data + pure functions');

  for (const s of specifiers) {
    assert.ok(!/dataflow\/(engine|summaries|index)\.js$/.test(s),
      `PRD §18.1: never import dataflow's taint engine, its SummaryCache, or its package entry point — found ${s}`);
  }

  // And confirm what we rely on is a MODULE-LEVEL export of catalog.js,
  // reachable without going through dataflow/engine.js at all.
  const catalogSrc = fs.readFileSync(path.join(__dirname, '..', '..', 'src', 'dataflow', 'catalog.js'), 'utf8');
  assert.ok(/^export function matchSource\(/m.test(catalogSrc));
  assert.ok(/^export function matchSinkOrSanitizer\(/m.test(catalogSrc));
  const privacySrc = fs.readFileSync(path.join(__dirname, '..', '..', 'src', 'dataflow', 'privacy-catalog.js'), 'utf8');
  assert.ok(/^export function matchPrivacySink\(/m.test(privacySrc));
  const apSrc = fs.readFileSync(path.join(__dirname, '..', '..', 'src', 'dataflow', 'access-paths.js'), 'utf8');
  assert.ok(/^export function accessPathOf\(/m.test(apSrc));

  // These three matchers are stateless: calling one twice with the same
  // input returns the same answer, and none of them mutates a graph the
  // lineage package owns.
  const e = { kind: 'member', object: { kind: 'ident', name: 'req' }, prop: 'body' };
  assert.equal(matchSource(e, 'a.js'), matchSource(e, 'a.js'));
  assert.equal(accessPathOf(e), 'req.body');
});

test('E1/13 (AC-11 coarse half): a sink nothing reaches is still a node with a coverage reason, and the ledger counts the sites the enumerator cannot reach', () => {
  const r = buildDataFlowGraph(irOf(vulnerableJs()), { repository: 'vulnerable-js' });
  const connectedSinkIds = new Set(r.graph.flows.map((f) => f.sink));
  const disconnected = r.graph.nodes.filter((n) => n.kind !== 'source' && !connectedSinkIds.has(n.id));
  assert.ok(disconnected.length > 0, 'vulnerable-js really does contain a matched sink nothing reaches');
  for (const n of disconnected) {
    assert.ok(n.coverageReason.length > 0, 'AC-11: visible, with a reason');
    assert.ok(COVERAGE_STATUS_VALUES.includes(n.coverageStatus));
  }

  // The per-CALL-SITE half of AC-11 lives in the ledger, because the node
  // layer is deliberately category-granular (see DESIGN_GRAPH_BUILDER.md
  // §6.5's flagged, unresolved question for E4/H).
  assert.equal(r.graph.coverage.sinks.callStatementSites, 11);
  assert.equal(r.graph.coverage.sinks.connected, 6);
  assert.equal(r.graph.coverage.sinks.disconnected, 5);
  assert.equal(r.graph.coverage.sinks.nonStatementSitesNotEnumerable, 1,
    'a sink call expression with no `escape` provenance node is COUNTED, never silently dropped');
  assert.equal(r.graph.coverage.sources.matched, 9);
  assert.equal(r.graph.coverage.sources.unseedable, 0);
  // Updated (hotfix, 2026-08-31 — see E1/4's own comment for the full
  // explanation): 19 -> 23, the same measured hop-count change, unaffected
  // sink/source coverage counts above.
  assert.equal(r.graph.coverage.provenance.hops, 23);
});

test('E1/14 (measured limitation, RESOLVED by hotfix): lineage/engine.js now keeps RECEIVER-borne identity through a method call, so the bench corpus\'s own masked-log flow connects', () => {
  // `pan + 'x'` and `String(pan)` always kept the identity; `pan.slice(0,4)`
  // used to lose it, because engine.js's unresolved-`call` branch unioned
  // only `expr.args`, never `expr.callee.object`. dataflow/engine.js had
  // already solved exactly this with `_calleeReceiverTainted`; this
  // package had not inherited it. Fixed (hotfix, 2026-08-31): the
  // unresolved-`call` branch now also unions the receiver's own resolved
  // identities into its flat result, the same way arguments already are.
  const masked = 'function maskCard(pan){ return pan.slice(0, 4) + \'********\' + pan.slice(-4); }\n'
    + 'function handleCheckout(req, logger){\n'
    + '  const cardNumber = req.body.card_number;\n'
    + '  const maskedPan = maskCard(cardNumber);\n'
    + '  logger.info(\'processing payment\', { pan: maskedPan });\n'
    + '}';
  const r = buildDataFlowGraph(irOf({ 'source.js': masked }), { repository: 'm' });
  assert.equal(r.seeds.length, 1, 'the source IS matched and seeded');
  assert.equal(r.sites.length, 1, 'the logger.info sink IS enumerated');
  // FIXED (hotfix, 2026-08-31 — see DESIGN_GRAPH_BUILDER.md §11's now-
  // RESOLVED escalation entry and scanner/src/lineage/engine.js's
  // unresolved-`call` receiver-identity fix): the identity used to die
  // inside maskCard at `pan.slice(...)` because the unresolved-call branch
  // only unioned `expr.args`, never the receiver. It now survives, so the
  // corpus fixture's own masked-log flow connects — 2 flows, matching the
  // receiver-free control fixture's own structure below (one real
  // cross-scope path through maskCard, one caller-side bypass FR-305/§14.7
  // correctly marks `ambiguousCorrelation`). The cross-scope path's grade
  // is `widened` here (not `explicit`, unlike the receiver-free control
  // below) because it still passes through an UNRESOLVED call — the
  // receiver's identity is recovered, but the call's return remains
  // honestly modeled as unknown structure, per DESIGN_INTRAPROCEDURAL.md's
  // structure-flattening rule for `call`.
  assert.equal(r.graph.flows.length, 2,
    'the identity now survives `pan.slice(...)` inside maskCard: this is the corpus fixture bench/data-lineage/fixtures/js-api-to-log-masked, verbatim, now connecting.');
  assert.deepEqual(r.graph.flows.map((f) => f.evidenceGrade).sort(), ['ambiguous', 'widened'],
    'the cross-scope path through the still-unresolved maskCard call grades widened, never explicit');
  assert.equal(r.graph.transformations.length, 1);
  assert.equal(r.graph.transformations[0].kind, 'mask');
  assert.ok(r.graph.flows.every((f) => f.transformationIds.length === 1),
    'both carry the recognized mask transformation');

  // The same shape with a receiver-free transform DOES connect, which
  // isolates the cause to receiver-borne identity specifically.
  const ok = masked.replace('return pan.slice(0, 4) + \'********\' + pan.slice(-4);', 'return \'****\' + pan;');
  const r2 = buildDataFlowGraph(irOf({ 'source.js': ok }), { repository: 'm' });
  assert.equal(r2.graph.transformations.length, 1);
  assert.equal(r2.graph.transformations[0].kind, 'mask');
  // TWO flows, not one, and that is FR-305 working rather than a defect:
  // the same source/sink/field is reached by two MATERIALLY different
  // reconstructed paths — the real cross-scope path through maskCard, and
  // the caller-side bypass §14.7 marks `ambiguousCorrelation`. They carry
  // different evidence grades, so collapsing them would hide exactly what
  // FR-305/FR-306 forbid hiding.
  assert.equal(r2.graph.flows.length, 2, 'identical structure, receiver-free transform => flows appear');
  assert.deepEqual(r2.graph.flows.map((f) => f.evidenceGrade).sort(), ['ambiguous', 'explicit']);
  assert.ok(r2.graph.flows.every((f) => f.transformationIds.length === 1),
    'both carry the recognized mask transformation');
});
