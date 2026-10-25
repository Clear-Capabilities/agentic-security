// Evidence measurements for one directory: witness-bundle replay and tamper
// rejection, the reported flows (for false-source-attribution scoring), and
// call/return realizability of reconstructed witnesses under correlation
// versions 1 and 2.
//
// Runs inside a child process (see run.mjs). Everything here is produced by
// the shipped modules; this file only drives them and counts. Nothing in
// scanner/src is tuned for these numbers.
//
// The call/return checker below is INDEPENDENT of the correlation-version-2
// machinery: it re-derives call and return direction from node scope/context
// versus edge scope/context (the same relation witness-bundle.js records as a
// call-site binding) and walks each witness source to sink with a stack. A
// return that does not match the call site and callee last entered is an
// impossible witness. It does not read invocation ids, so it can judge a
// version 1 path, which has none.
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { listFiles } from './scan-unit.mjs';
import { buildProjectIR } from '../../../scanner/src/ir/index.js';
import { buildLineageGraph } from '../../../scanner/src/lineage/index.js';
import { planSeeds, seedEntryStateFactory } from '../../../scanner/src/lineage/source-seeding.js';
import { runFieldIdentityAnalysis } from '../../../scanner/src/lineage/driver.js';
import { PathStore } from '../../../scanner/src/lineage/path-store.js';
import { reconstructPaths, sinkCandidates } from '../../../scanner/src/lineage/path-query.js';
import {
  buildWitnessBundle, signWitnessBundle, verifyWitness, exportProvenanceArtifact,
} from '../../../scanner/src/posture/witness-bundle.js';

const SOURCE_EXT = /\.(?:js|mjs|cjs|jsx|ts|tsx)$/;
const MAX_FILE_BYTES = 1024 * 1024;
export const WITNESS_BUNDLES_PER_UNIT = 60;
export const TAMPER_SAMPLE_PER_UNIT = 40;
export const SINK_CAP = 2000;

export function loadSources(dir, prefix) {
  const fc = {};
  for (const f of listFiles(dir)) {
    if (!SOURCE_EXT.test(f)) continue;
    const stat = fs.statSync(f);
    if (stat.size > MAX_FILE_BYTES) continue;
    fc[path.relative(dir, f).split(path.sep).join('/')] = fs.readFileSync(f, 'utf8');
  }
  return fc;
}

function analyse(callGraph, seeds, correlationVersion) {
  const hops = [];
  const analysis = runFieldIdentityAnalysis(callGraph, {
    recordHop: (h) => hops.push(h),
    seedEntryState: seedEntryStateFactory(seeds),
    ...(correlationVersion === 2 ? { correlationVersion: 2 } : null),
  });
  const store = new PathStore({}, correlationVersion === 2 ? { correlationVersion: 2 } : undefined);
  store.addHops(hops);
  return { hops, analysis, store };
}

// ---------------------------------------------------------------- flows

function compactFlows(graph, prefix) {
  const nodeById = new Map(graph.nodes.map((n) => [n.id, n]));
  const deById = new Map(graph.dataElements.map((d) => [d.id, d]));
  const norm = (f) => (prefix ? path.posix.join(prefix, f) : f);
  return graph.flows.map((f) => {
    const s = nodeById.get(f.source);
    const k = nodeById.get(f.sink);
    const des = (f.dataElementIds || []).map((id) => deById.get(id)).filter(Boolean);
    return {
      fields: des.map((d) => d.name),
      sources: des.flatMap((d) => (d.sourceLocations || []).map((l) => ({ field: d.name, file: norm(l.file), line: l.line, path: l.path }))),
      files: [...new Set(des.flatMap((d) => (d.sourceLocations || []).map((l) => norm(l.file))))].sort(),
      sourceKind: s ? s.subtype : null,
      sinkKind: k ? k.kind : null,
      sinkSub: k ? k.subtype : null,
    };
  });
}

// ------------------------------------------------- call/return realizability

/**
 * Walk one witness source to sink. Returns {calls, returns, unmatchedReturns, invalidBindings, violation}.
 * violation is null or {hopIndex, reason}.
 */
export function checkCallReturn(store, p) {
  const stack = [];
  const out = { calls: 0, returns: 0, unmatchedReturns: 0, invalidBindings: 0, violation: null };
  p.hops.forEach((h, i) => {
    const from = store.getNode(h.fromNodeId);
    const to = store.getNode(h.toNodeId);
    if (!from || !to) return;
    const fromPeer = from.scope !== h.scope || from.context !== h.context;
    const toPeer = to.scope !== h.scope || to.context !== h.context;
    if (fromPeer && toPeer) { out.invalidBindings += 1; return; }
    if (toPeer) {
      out.calls += 1;
      stack.push({ site: h.siteNodeId, scope: h.scope, context: h.context, calleeScope: to.scope, calleeContext: to.context });
    } else if (fromPeer) {
      out.returns += 1;
      if (!stack.length) { out.unmatchedReturns += 1; return; } // the witness began inside the callee
      const top = stack.pop();
      if (!out.violation && (top.site !== h.siteNodeId || top.scope !== h.scope || top.context !== h.context
          || top.calleeScope !== from.scope || top.calleeContext !== from.context)) {
        out.violation = { hopIndex: i, reason: top.site !== h.siteNodeId ? 'returned-through-another-call-site' : 'returned-to-another-activation' };
      }
    }
  });
  return out;
}

function realizability(store, version) {
  const sinks = sinkCandidates(store).filter((n) => n.kind === 'escape').sort((a, b) => (a.id < b.id ? -1 : 1));
  const capped = sinks.length > SINK_CAP;
  const r = {
    version, sinks: Math.min(sinks.length, SINK_CAP), sinksCapped: capped, paths: 0, pathsWithCallOrReturn: 0,
    impossible: 0, impossibleReasons: {}, unmatchedReturnPaths: 0, invalidBindingPaths: 0,
    balancingPrunedEdges: 0, unbalancedTerminals: 0, contextWidenedPaths: 0, truncatedQueries: 0,
  };
  for (const s of sinks.slice(0, SINK_CAP)) {
    const res = reconstructPaths(store, s.id);
    if (res.truncated) r.truncatedQueries += 1;
    if (res.balancing) { r.balancingPrunedEdges += res.balancing.unbalancedPruned; r.contextWidenedPaths += res.balancing.contextWidenedPaths; }
    for (const p of res.paths) {
      r.paths += 1;
      if (p.terminal && p.terminal.reason === 'unbalanced-call') r.unbalancedTerminals += 1;
      const c = checkCallReturn(store, p);
      if (c.calls + c.returns > 0) r.pathsWithCallOrReturn += 1;
      if (c.unmatchedReturns > 0) r.unmatchedReturnPaths += 1;
      if (c.invalidBindings > 0) r.invalidBindingPaths += 1;
      if (c.violation) { r.impossible += 1; r.impossibleReasons[c.violation.reason] = (r.impossibleReasons[c.violation.reason] || 0) + 1; }
    }
  }
  return r;
}

// -------------------------------------------------------- witness replay

function witnessMeasure(fc, graph, hops, analysis, store) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const PUB = publicKey.export({ type: 'spki', format: 'pem' });
  const PRIV = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const incomplete = (analysis && analysis.completion && analysis.completion.incomplete) || [];
  const provenance = exportProvenanceArtifact({ hops, incomplete });
  const sinks = sinkCandidates(store).filter((n) => n.kind === 'escape').sort((a, b) => (a.id < b.id ? -1 : 1));
  const out = {
    sinks: sinks.length, sinksWithPaths: 0, bundlesAttempted: 0, buildRefused: 0, buildRefusedReasons: {},
    built: 0, builtCrossScope: 0, replayed: 0, replayedCrossScope: 0, replayFailed: 0, replayFailureCodes: {},
    completeBundles: 0, hopStream: provenance.hops.length, bundleCap: WITNESS_BUNDLES_PER_UNIT,
    tamper: {
      'edge-altered-resigned': { attempted: 0, rejected: 0 },
      'edge-altered-unsigned': { attempted: 0, rejected: 0 },
      'source-blob-altered': { attempted: 0, rejected: 0 },
      'graph-altered': { attempted: 0, rejected: 0 },
    },
    tamperSampleCap: TAMPER_SAMPLE_PER_UNIT,
  };
  const clone = (v) => JSON.parse(JSON.stringify(v));
  const good = [];
  for (const s of sinks) {
    if (out.bundlesAttempted >= WITNESS_BUNDLES_PER_UNIT) break;
    const result = reconstructPaths(store, s.id);
    if (!result.paths.length) continue;
    out.sinksWithPaths += 1;
    const pick = result.paths.find((p) => p.crossScopeCount > 0) || result.paths[0];
    out.bundlesAttempted += 1;
    const r = buildWitnessBundle({ result, path: pick, store, graph, provenance, sourceBlobs: fc });
    if (!r.ok) {
      out.buildRefused += 1;
      const k = String(r.reason).replace(/[0-9a-f]{12,}/g, '<id>').slice(0, 90);
      out.buildRefusedReasons[k] = (out.buildRefusedReasons[k] || 0) + 1;
      continue;
    }
    out.built += 1;
    const cross = pick.crossScopeCount > 0;
    if (cross) out.builtCrossScope += 1;
    if (r.bundle.completion.overall === 'complete') out.completeBundles += 1;
    const signed = signWitnessBundle(r.bundle, PRIV);
    const artifacts = { graph, provenance, sources: fc };
    const v = verifyWitness(signed, PUB, artifacts);
    if (v.ok && v.verdict === 'replayed') { out.replayed += 1; if (cross) out.replayedCrossScope += 1; good.push({ signed, artifacts }); }
    else {
      out.replayFailed += 1;
      for (const f of ((v.replay && v.replay.failures) || [])) out.replayFailureCodes[f.code] = (out.replayFailureCodes[f.code] || 0) + 1;
    }
  }

  for (const { signed, artifacts } of good.slice(0, TAMPER_SAMPLE_PER_UNIT)) {
    // 1. recorded edge changed and the bundle re-signed: only replay can catch it.
    {
      const t = clone(signed); delete t.signature; delete t.issuance;
      t.path.edges[t.path.edges.length - 1].line = 99999;
      const v = verifyWitness(signWitnessBundle(t, PRIV), PUB, artifacts);
      out.tamper['edge-altered-resigned'].attempted += 1;
      if (!v.ok) out.tamper['edge-altered-resigned'].rejected += 1;
    }
    // 2. recorded edge changed, signature left as it was.
    {
      const t = clone(signed);
      t.path.edges[0].inKind = t.path.edges[0].inKind === 'production' ? 'selection' : 'production';
      const v = verifyWitness(t, PUB, artifacts);
      out.tamper['edge-altered-unsigned'].attempted += 1;
      if (!v.ok) out.tamper['edge-altered-unsigned'].rejected += 1;
    }
    // 3. a bound source blob altered.
    if (signed.sources && signed.sources.length) {
      const f = signed.sources[0].file;
      const v = verifyWitness(signed, PUB, { ...artifacts, sources: { ...artifacts.sources, [f]: `${artifacts.sources[f]}\n// altered` } });
      out.tamper['source-blob-altered'].attempted += 1;
      if (!v.ok) out.tamper['source-blob-altered'].rejected += 1;
    }
    // 4. the graph artifact replaced by a different graph.
    {
      const g = clone(artifacts.graph); g.nodes = [...g.nodes, { id: 'node:tamper', kind: 'process' }];
      const v = verifyWitness(signed, PUB, { ...artifacts, graph: g });
      out.tamper['graph-altered'].attempted += 1;
      if (!v.ok) out.tamper['graph-altered'].rejected += 1;
    }
  }
  return out;
}

/** spec: { id, dir, prefix } */
export function evidenceProbe(spec) {
  const fc = loadSources(spec.dir, spec.prefix);
  const t0 = Date.now();
  const { perFile, callGraph } = buildProjectIR(fc);
  const lr = buildLineageGraph(callGraph, { deterministic: true, perFile, fileContents: fc, repository: 'bench' });
  const graph = lr.graph || { graphId: 'dfg:bench:none', nodes: [], edges: [], flows: [], dataElements: [], coverage: {} };
  const { seeds } = planSeeds(callGraph, { repository: 'bench' });
  const v1 = analyse(callGraph, seeds, 1);
  const v2 = analyse(callGraph, seeds, 2);
  return {
    id: spec.id, status: 'ok', files: Object.keys(fc).length, lineageStatus: lr.status,
    flows: compactFlows(graph, spec.prefix),
    witness: witnessMeasure(fc, graph, v1.hops, v1.analysis, v1.store),
    callReturn: { v1: realizability(v1.store, 1), v2: realizability(v2.store, 2) },
    ms: Date.now() - t0, peakRssMb: Math.round(process.resourceUsage().maxRSS / 1024),
  };
}
