// The enterprise graph (PRD 4, requirements 6 to 8): the repositories, APIs, queues, databases, external providers and trust zones
// of an organization, with every edge carrying the evidence it came from.
//
// Two kinds of edge, never confused:
//   * `depends-on` edges come from each repository's own package manifest (the declared name and the spec it pins). A flaw in the
//     dependency can affect the dependent. They are NOT movement an attacker makes.
//   * REACH edges are what an attacker can move along: a call from one service to another, a producer to a queue, a queue to its
//     consumer, a service to a database or an external provider, and the Internet to anything declared Internet-facing. Those come
//     from the fleet manifest, which is operator-declared. They are labelled `source: fleet-manifest` and are exactly as good as the
//     operator's declaration; nothing here pretends to have discovered them. (Code-derived call and queue edges are what the Data
//     Flow Explorer's per-repository graph provides; joining that in is not built.)
//
// A graph edge without evidence is a bug, and `validateEnterpriseGraph` says so: "every graph edge traceable to source evidence".
import { createHash } from 'node:crypto';

const ENTERPRISE_GRAPH_SCHEMA = 'agentic-security/enterprise-graph';
export const INTERNET = 'internet';
const MAX_PATHS = 200;
export const MAX_DEPTH = 8;
const AUTH_CWES = new Set(['CWE-287', 'CWE-306', 'CWE-285', 'CWE-862', 'CWE-863', 'CWE-384', 'CWE-613', 'CWE-639', 'CWE-290', 'CWE-294', 'CWE-308', 'CWE-1390']);

const edgeId = (type, from, to) => `edge:${type}:${from}:${to}`;
const hash = (v) => createHash('sha256').update(JSON.stringify(v)).digest('hex');

export function buildEnterpriseGraph({ manifest, dependencyGraph }) {
  const nodes = new Map();
  const edges = new Map();
  const addNode = (n) => nodes.set(n.id, n);
  const addEdge = (type, from, to, evidence, reach) => {
    const id = edgeId(type, from, to);
    const e = edges.get(id) ?? { id, type, from, to, reach, evidence: [] };
    e.evidence.push(evidence);
    edges.set(id, e);
  };
  addNode({ id: INTERNET, type: 'internet', kind: 'internet', internetFacing: false, environment: null, dataClasses: [], trustZone: 'internet', required: false });
  for (const r of manifest.repositories) addNode({ id: r.id, type: 'repository', kind: r.kind, internetFacing: r.internetFacing, environment: r.environment, dataClasses: r.dataClasses, trustZone: r.trustZone, required: r.required });
  for (const r of manifest.resources ?? []) addNode({ id: r.id, type: r.kind, kind: r.kind, internetFacing: r.internetFacing, environment: r.environment, dataClasses: r.dataClasses, trustZone: r.trustZone, required: false });

  const ev = (repo, field, value) => ({ source: 'fleet-manifest', repo, field, value });
  for (const n of [...nodes.values()]) if (n.internetFacing) addEdge('exposes', INTERNET, n.id, ev(n.id, 'internetFacing', true), true);
  for (const r of manifest.repositories) {
    for (const t of r.calls) addEdge('calls', r.id, t, ev(r.id, 'calls', t), true);
    for (const t of r.produces) addEdge('produces', r.id, t, ev(r.id, 'produces', t), true);
    for (const t of r.consumes) addEdge('consumes', t, r.id, ev(r.id, 'consumes', t), true);
    for (const t of r.reads) addEdge('reads', r.id, t, ev(r.id, 'reads', t), true);
    for (const t of r.writes) addEdge('writes', r.id, t, ev(r.id, 'writes', t), true);
    for (const t of r.providers) addEdge('uses-provider', r.id, t, ev(r.id, 'providers', t), true);
  }
  for (const d of dependencyGraph?.edges ?? []) addEdge('depends-on', d.from, d.to, d.evidence?.[0] ?? { source: 'package-manifest', repo: d.from, file: null, declared: d.via, spec: null }, false);
  return { schema: ENTERPRISE_GRAPH_SCHEMA, version: 1, organization: manifest.organization, nodes: [...nodes.values()], edges: [...edges.values()], digest: null };
}

export function finalizeGraph(graph) { return { ...graph, digest: hash({ n: graph.nodes, e: graph.edges }) }; }

/** Every edge has evidence, every endpoint exists. Returns a list of problems. */
export function validateEnterpriseGraph(g) {
  const errs = [];
  const ids = new Set((g?.nodes ?? []).map((n) => n.id));
  for (const e of g?.edges ?? []) {
    if (!Array.isArray(e.evidence) || !e.evidence.length || !e.evidence.every((x) => x && typeof x.source === 'string')) errs.push(`edge ${e.id} has no source evidence`);
    if (!ids.has(e.from) || !ids.has(e.to)) errs.push(`edge ${e.id} points at a node that is not in the graph`);
  }
  return errs;
}

const nodeOf = (g, id) => g.nodes.find((n) => n.id === id);

/** Repositories that match a "vulnerable code" selector, and everything that depends on them. */
export function vulnerableSet({ graph, findingsByRepo = new Map(), selector }) {
  const direct = new Set(); const why = new Map();
  if (selector.repo) { direct.add(selector.repo); why.set(selector.repo, 'named'); }
  for (const [repo, findings] of findingsByRepo) {
    const hit = (findings ?? []).find((f) => (selector.family === 'auth' ? (AUTH_CWES.has(String(f.cwe)) || /auth/i.test(String(f.family ?? ''))) : selector.family ? new RegExp(selector.family, 'i').test(String(f.family ?? f.vuln ?? '')) : false) || (selector.cwe && selector.cwe.includes(String(f.cwe))));
    if (hit) { direct.add(repo); why.set(repo, `finding ${hit.id ?? hit.stableId ?? ''} ${hit.cwe ?? ''}`.trim()); }
  }
  const incoming = new Map();
  for (const e of graph.edges) if (e.type === 'depends-on') { if (!incoming.has(e.to)) incoming.set(e.to, []); incoming.get(e.to).push(e.from); }
  const all = new Set(direct); const stack = [...direct];
  while (stack.length) { const c = stack.pop(); for (const f of incoming.get(c) ?? []) if (!all.has(f)) { all.add(f); why.set(f, `depends on ${c}`); stack.push(f); } }
  return { direct, all, why };
}

/**
 * Attack paths: simple paths from the Internet to any node holding `toDataClass`, along reach edges only. A path is "involving"
 * when it passes through a repository in `involving`. Bounded in depth and count; `truncated` says when a bound was hit.
 */
export function attackPaths({ graph, toDataClass, from = INTERNET, involving = null, maxDepth = MAX_DEPTH, maxPaths = MAX_PATHS }) {
  const out = new Map();
  for (const e of graph.edges) if (e.reach) { if (!out.has(e.from)) out.set(e.from, []); out.get(e.from).push(e); }
  const results = []; let truncated = false;
  const targets = new Set(graph.nodes.filter((n) => n.dataClasses.includes(toDataClass)).map((n) => n.id));
  const walk = (id, nodePath, edgePath) => {
    if (results.length >= maxPaths) { truncated = true; return; }
    if (targets.has(id) && nodePath.length > 1) {
      const inv = involving ? nodePath.filter((n) => involving.all.has(n)) : [];
      if (!involving || inv.length) results.push({ nodes: [...nodePath], edges: edgePath.map((e) => e.id), involving: inv, evidence: edgePath.flatMap((e) => e.evidence.map((x) => ({ edge: e.id, ...x }))) });
    }
    if (nodePath.length > maxDepth) { truncated = true; return; }
    for (const e of out.get(id) ?? []) if (!nodePath.includes(e.to)) walk(e.to, [...nodePath, e.to], [...edgePath, e]);
  };
  if (nodeOf(graph, from)) walk(from, [from], []);
  return { dataClass: toDataClass, targets: [...targets], paths: results, truncated, bounds: { maxDepth, maxPaths } };
}

/** The shared-component report: who depends on `component` (transitively), and how many of them are exposed, in production, or hold regulated data. */
export function componentBlastRadius({ graph, component, version = null }) {
  if (!nodeOf(graph, component)) return null;
  const incoming = new Map();
  for (const e of graph.edges) if (e.type === 'depends-on') { if (!incoming.has(e.to)) incoming.set(e.to, []); incoming.get(e.to).push(e); }
  const found = new Map(); const queue = [{ id: component, path: [component], vm: 'not-asked' }];
  while (queue.length) {
    const { id, path, vm: parentVm } = queue.shift();
    for (const e of incoming.get(id) ?? []) {
      if (found.has(e.from)) continue;
      const spec = e.evidence.map((x) => x.spec).find((x) => x != null) ?? null;
      // only the dependents that pin the component itself can be judged against a version; one reached THROUGH another repository
      // inherits that repository's status, and is not reached at all when the repository in between was ruled out
      const direct = id === component;
      const vm = direct ? (version == null ? 'not-asked' : spec == null ? 'unknown' : String(spec).includes(version) ? 'matched' : 'mismatch') : parentVm;
      found.set(e.from, { id: e.from, depth: path.length, path: [...path, e.from], spec, versionMatch: vm, inherited: !direct, evidence: e.evidence });
      if (vm !== 'mismatch') queue.push({ id: e.from, path: [...path, e.from], vm });
    }
  }
  const all = [...found.values()].sort((a, b) => a.depth - b.depth || a.id.localeCompare(b.id));
  const counted = all.filter((d) => d.versionMatch !== 'mismatch');
  const attrs = (d) => nodeOf(graph, d.id);
  const classes = {};
  for (const d of counted) for (const c of attrs(d).dataClasses) classes[c] = (classes[c] ?? 0) + 1;
  return {
    component, version, dependents: all,
    counts: { repositories: counted.length, internetFacing: counted.filter((d) => attrs(d).internetFacing).length, production: counted.filter((d) => attrs(d).environment === 'production').length, byDataClass: classes },
    excludedByVersion: all.filter((d) => d.versionMatch === 'mismatch').map((d) => d.id),
    unknownVersion: counted.filter((d) => d.versionMatch === 'unknown').map((d) => d.id),
  };
}

export function renderBlastRadius(r) {
  const n = (k, one, many) => `${k} ${k === 1 ? one : many}`;
  const L = [`${r.component}${r.version ? `@${r.version}` : ''}`, '', 'Used by:', n(r.counts.repositories, 'repository', 'repositories'), n(r.counts.internetFacing, 'Internet-facing service', 'Internet-facing services'), n(r.counts.production, 'production app', 'production apps')];
  for (const [c, k] of Object.entries(r.counts.byDataClass).sort()) L.push(n(k, `${c.toUpperCase()}-scoped service`, `${c.toUpperCase()}-scoped services`));
  if (r.excludedByVersion.length) L.push('', `Excluded, their pinned version does not match: ${r.excludedByVersion.join(', ')}`);
  if (r.unknownVersion.length) L.push('', `Counted, but their pinned version could not be read: ${r.unknownVersion.join(', ')}`);
  return L.join('\n');
}
