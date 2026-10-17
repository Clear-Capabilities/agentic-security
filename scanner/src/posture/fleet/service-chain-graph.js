// Multi-repo, multi-service chain graph (E5-06).
//
// fleet-graph.js knows which repos depend on which packages. That says a defect in a shared library can reach its dependants, but not whether any route
// of any service reaches the defect. This module adds the layers that answer that, over the same fleet:
//
//   call      inside one repo: function A calls function B (taken from the semantic graph's resolved call edges, supplied as facts)
//   library   a function in repo A uses a symbol that a package published by repo L exports; the edge is made only when A's manifest depends on L
//             (the existing dependency graph), and it is marked `vulnerable` when A's declared version is in L's advisory list
//   api       a function in repo A calls an HTTP route of ANOTHER service; the edge goes to the route that service exposes
//   topic     a function publishes an event topic and a function in another repo consumes it
//
// A CHAIN is route -> ... -> sink, found by walking those edges. Each step carries the evidence that made it and a confidence; a chain's confidence is
// the product of its steps'.
//
// WRONG-SERVICE EDGES ARE THE FAILURE TO AVOID. Two services often expose the same path (`/health`, `/charge`). An outbound call that names its target
// service links ONLY to that service's route. A call that names no service links to a route only when exactly ONE service in the tenant exposes it;
// when several do, no edge is made and the call is listed under `ambiguous` with the candidates, never resolved by guessing.
//
// BUDGETS. `maxRepos`, `maxNodes`, `maxEdges`, `maxDepth`, `maxChains` bound the work. Hitting one stops that step and sets `truncated` with the name of
// the budget; a result that was cut short never looks complete.
//
// TENANT ISOLATION. Every repo belongs to one tenant, every node id is prefixed with it, and a graph is built for one tenant. A repo from another tenant
// is not read at all (counted in `refusedOtherTenant`), and a link that would cross tenants is refused. Nothing here reads outside the facts passed in.
import { buildFleetDependencyGraph } from './fleet-graph.js';

export const DEFAULT_BUDGETS = Object.freeze({ maxRepos: 200, maxNodes: 20000, maxEdges: 60000, maxDepth: 12, maxChains: 200 });

const nid = (tenant, repo, kind, key) => `${tenant}:${repo}:${kind}:${key}`;
const routeKey = (r) => `${(r.method || 'ANY').toUpperCase()} ${r.path}`;
const ver = (v) => String(v || '').replace(/^[^\d]*/, '').split('.').map((n) => parseInt(n, 10) || 0);
const cmp = (a, b) => { for (let i = 0; i < 3; i++) { const d = (a[i] || 0) - (b[i] || 0); if (d) return d; } return 0; };
function isVulnerable(version, advisories) {
  if (!version || !Array.isArray(advisories)) return false;
  const v = ver(version);
  return advisories.some((a) => (a.exact && cmp(v, ver(a.exact)) === 0) || (a.lt && cmp(v, ver(a.lt)) < 0 && (!a.gte || cmp(v, ver(a.gte)) >= 0)));
}

/**
 * @param {object[]} repos RepoFacts:
 *   { id, path, tenant, service?: string, environment?: string,
 *     routes?: [{method?, path, handler, classification?}], calls?: [{from, to}],
 *     outboundCalls?: [{from, service?, method?, path}],
 *     topics?: { publishes?: [{topic, from}], consumes?: [{topic, handler}] },
 *     libraryUses?: [{package, symbol, from}], exports?: [{package, symbol, qid}],
 *     functions?: [{qid, sinks?: [{kind, cwe?}]}], advisories?: [{exact?|lt?, gte?}], dependencyVersions?: {pkg: version},
 *   }  `path` is the repo directory: its manifests (package.json, go.mod, ...) are read by fleet-graph.js to decide who publishes and who depends on what
 * @param {{tenant:string, budgets?:object}} opts
 */
export function buildServiceChainGraph(repos, opts = {}) {
  const tenant = opts.tenant;
  if (typeof tenant !== 'string' || !tenant) throw new Error('tenant is required: a fleet graph is built for exactly one tenant');
  const B = { ...DEFAULT_BUDGETS, ...(opts.budgets || {}) };
  const truncated = []; const trunc = (name) => { if (!truncated.includes(name)) truncated.push(name); };
  const refusedOtherTenant = []; const ambiguous = []; const unresolved = [];
  let mine = [];
  for (const r of repos || []) { if (r.tenant !== tenant) refusedOtherTenant.push(r.id); else mine.push(r); }
  if (mine.length > B.maxRepos) { trunc('maxRepos'); mine = mine.slice(0, B.maxRepos); }

  const nodes = new Map(); const edges = []; const edgeSet = new Set();
  const addNode = (id, n) => { if (nodes.has(id)) return true; if (nodes.size >= B.maxNodes) { trunc('maxNodes'); return false; } nodes.set(id, { id, ...n }); return true; };
  const addEdge = (from, to, e) => {
    const key = `${e.kind}|${from}|${to}`; if (edgeSet.has(key)) return;
    if (edges.length >= B.maxEdges) { trunc('maxEdges'); return; }
    if (!addNode(from, {}) || !addNode(to, {})) return;
    edgeSet.add(key); edges.push({ from, to, ...e });
  };

  // the existing manifest-based dependency graph decides which library edges are allowed at all
  const dep = buildFleetDependencyGraph(mine.map((r) => ({ id: r.id, path: r.path || '' })));
  const dependsOn = new Set(dep.edges.map((e) => `${e.from}>${e.to}`));
  const publishedBy = new Map();
  for (const r of mine) { const n = (dep.nodes.find((x) => x.id === r.id) || {}).declaredName; if (n) publishedBy.set(n, r); }

  for (const r of mine) {
    for (const fn of r.functions || []) { addNode(nid(tenant, r.id, 'fn', fn.qid), { kind: 'function', repo: r.id, qid: fn.qid, sinks: (fn.sinks || []).map((s) => s.kind) }); }
    for (const rt of r.routes || []) {
      const rid = nid(tenant, r.id, 'route', routeKey(rt));
      addNode(rid, { kind: 'route', repo: r.id, service: r.service || r.id, route: routeKey(rt), classification: rt.classification || null });
      addEdge(rid, nid(tenant, r.id, 'fn', rt.handler), { kind: 'handler', confidence: 0.95, evidence: `route ${routeKey(rt)} is handled by ${rt.handler}`, repo: r.id });
    }
    for (const c of r.calls || []) addEdge(nid(tenant, r.id, 'fn', c.from), nid(tenant, r.id, 'fn', c.to), { kind: 'call', confidence: 0.9, evidence: 'resolved call edge in the semantic graph', repo: r.id });
    for (const fn of r.functions || []) for (const s of fn.sinks || []) {
      const sid = nid(tenant, r.id, 'sink', `${fn.qid}#${s.kind}`);
      addNode(sid, { kind: 'sink', repo: r.id, sink: s.kind, cwe: s.cwe || null });
      addEdge(nid(tenant, r.id, 'fn', fn.qid), sid, { kind: 'sink', confidence: 0.9, evidence: `${fn.qid} reaches a ${s.kind} sink`, repo: r.id });
    }
  }

  // library edges: only along a declared dependency, and only for a symbol the library publishes
  for (const r of mine) for (const u of r.libraryUses || []) {
    const lib = publishedBy.get(u.package);
    if (!lib) { unresolved.push({ repo: r.id, kind: 'library', package: u.package, reason: 'no repo in this tenant publishes this package' }); continue; }
    if (lib.id === r.id) continue;
    if (!dependsOn.has(`${r.id}>${lib.id}`)) { unresolved.push({ repo: r.id, kind: 'library', package: u.package, reason: 'the repo does not declare a dependency on the publishing repo' }); continue; }
    const exp = (lib.exports || []).find((x) => x.symbol === u.symbol && (!x.package || x.package === u.package));
    if (!exp) { unresolved.push({ repo: r.id, kind: 'library', package: u.package, symbol: u.symbol, reason: 'the publishing repo does not export this symbol' }); continue; }
    const v = (r.dependencyVersions || {})[u.package];
    const vulnerable = isVulnerable(v, lib.advisories);
    addEdge(nid(tenant, r.id, 'fn', u.from), nid(tenant, lib.id, 'fn', exp.qid), { kind: 'library', confidence: 0.85, evidence: `${r.id} depends on ${lib.id} and uses ${u.package}.${u.symbol}`, repo: r.id, toRepo: lib.id, package: u.package, version: v || null, vulnerable });
  }

  // api edges: named service links only to that service; unnamed links only when exactly one service exposes the route
  const exposers = (path, method) => mine.filter((x) => (x.routes || []).some((rt) => rt.path === path && (!method || !rt.method || rt.method.toUpperCase() === method.toUpperCase())));
  for (const r of mine) for (const c of r.outboundCalls || []) {
    const cands = exposers(c.path, c.method).filter((x) => x.id !== r.id);
    let target = null;
    if (c.service) {
      target = cands.find((x) => (x.service || x.id) === c.service) || null;
      if (!target) { unresolved.push({ repo: r.id, kind: 'api', path: c.path, service: c.service, reason: 'the named service does not expose this route' }); continue; }
    } else if (cands.length === 1) target = cands[0];
    else if (cands.length > 1) { ambiguous.push({ repo: r.id, from: c.from, path: c.path, candidates: cands.map((x) => x.service || x.id).sort() }); continue; }
    else { unresolved.push({ repo: r.id, kind: 'api', path: c.path, reason: 'no service in this tenant exposes this route' }); continue; }
    const rt = (target.routes || []).find((x) => x.path === c.path && (!c.method || !x.method || x.method.toUpperCase() === c.method.toUpperCase()));
    addEdge(nid(tenant, r.id, 'fn', c.from), nid(tenant, target.id, 'route', routeKey(rt)), { kind: 'api', confidence: c.service ? 0.9 : 0.7, evidence: c.service ? `call names service ${c.service}` : `only service exposing ${c.path}`, repo: r.id, toRepo: target.id, classification: rt.classification || null });
  }

  // topic edges
  for (const r of mine) for (const p of (r.topics && r.topics.publishes) || []) for (const o of mine) {
    if (o.id === r.id) continue;
    for (const cn of (o.topics && o.topics.consumes) || []) if (cn.topic === p.topic) addEdge(nid(tenant, r.id, 'fn', p.from), nid(tenant, o.id, 'fn', cn.handler), { kind: 'topic', confidence: 0.75, evidence: `topic ${p.topic}`, repo: r.id, toRepo: o.id, topic: p.topic });
  }
  return { tenant, nodes: [...nodes.values()], edges, ambiguous, unresolved, refusedOtherTenant, truncated, budgets: B, dependencyEdges: dep.edges.length };
}

/** Walk route -> ... -> sink. Cycles are not followed; depth and chain count are budgeted and reported. */
export function findChains(graph, { sinkKind = null, fromRepo = null } = {}) {
  const B = graph.budgets; const out = new Map();
  for (const e of graph.edges) { (out.get(e.from) || out.set(e.from, []).get(e.from)).push(e); }
  const byId = new Map(graph.nodes.map((n) => [n.id, n]));
  const chains = []; const truncated = [];
  for (const start of graph.nodes.filter((n) => n.kind === 'route' && (!fromRepo || n.repo === fromRepo))) {
    const stack = [{ at: start.id, steps: [], seen: new Set([start.id]) }];
    while (stack.length) {
      const { at, steps, seen } = stack.pop();
      const node = byId.get(at);
      if (node && node.kind === 'sink' && (!sinkKind || node.sink === sinkKind)) {
        if (chains.length >= B.maxChains) { if (!truncated.includes('maxChains')) truncated.push('maxChains'); break; }
        chains.push({ route: start.route, service: start.service, repo: start.repo, sink: node.sink, steps, confidence: Math.round(steps.reduce((p, s) => p * s.confidence, 1) * 1000) / 1000, crossesServices: steps.some((s) => s.kind === 'api' || s.kind === 'topic'), throughLibrary: steps.filter((s) => s.kind === 'library').map((s) => ({ package: s.package, version: s.version, vulnerable: s.vulnerable })), repos: [...new Set([start.repo, ...steps.map((s) => s.toRepo || s.repo)])], dataClassifications: [...new Set([start.classification, ...steps.map((s) => s.classification)].filter(Boolean))].sort() });
        continue;
      }
      if (steps.length >= B.maxDepth) { if (!truncated.includes('maxDepth')) truncated.push('maxDepth'); continue; }
      for (const e of out.get(at) || []) {
        if (seen.has(e.to)) continue;
        stack.push({ at: e.to, steps: [...steps, { kind: e.kind, from: e.from, to: e.to, confidence: e.confidence, evidence: e.evidence, ...(e.package ? { package: e.package, version: e.version, vulnerable: e.vulnerable } : {}), ...(e.toRepo ? { toRepo: e.toRepo } : {}), ...(e.repo ? { repo: e.repo } : {}), ...(e.classification ? { classification: e.classification } : {}) }], seen: new Set([...seen, e.to]) });
      }
    }
  }
  chains.sort((a, b) => b.confidence - a.confidence || (a.route < b.route ? -1 : 1));
  return { chains, truncated };
}
