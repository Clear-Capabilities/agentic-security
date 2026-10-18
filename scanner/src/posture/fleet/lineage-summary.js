// A bounded summary of one repository's Code Boundaries graph (the Data Flow Explorer's `DataFlowGraph v1`), for the enterprise graph
// (PRD 4: "federate Code Boundaries across repositories"). The whole graph is not copied: a fleet of hundreds of repositories does not
// need each node, only what crosses a repository boundary or changes what the organization knows about it:
//   * the data classes that appear in the code (so a repository holding payment data is known to, even if the manifest forgot to say);
//   * the external destinations the code sends data to, by host;
//   * the queue topics it publishes to or consumes from;
//   * the stores it touches, by host/database/table name;
//   * counts, including flows that carry sensitive classes across a trust boundary.
// Pure; hostile input (the graph came out of a scan of someone's code), so every string is bounded and shape-checked.
const MAX_ITEMS = 64;
const SENSITIVE = new Set(['pii', 'phi', 'pci', 'fin', 'credentials']);
const arr = (v) => (Array.isArray(v) ? v : []);
const clean = (v, max = 120) => (typeof v === 'string' && v.length > 0 && v.length <= max && !/[\s\u0000-\u001f]/.test(v) ? v : null);

function hostOf(literal) {
  if (typeof literal !== 'string') return null;
  try { const h = new URL(literal).hostname.toLowerCase(); return clean(h, 253); } catch { /* not a URL */ }
  const bare = literal.toLowerCase().replace(/:\d+$/, '');
  return /^[a-z0-9][a-z0-9.-]{0,252}$/.test(bare) ? bare : null;
}

export function summarizeLineage(graph) {
  if (!graph || typeof graph !== 'object') return null;
  const classes = new Set();
  for (const d of arr(graph.dataElements)) for (const c of arr(d?.dataClasses)) { if (typeof c !== 'string') continue; const l = clean(c.toLowerCase(), 31); if (l && /^[a-z][a-z0-9-]*$/.test(l)) classes.add(l); }
  const ext = new Map(); const queues = new Map(); const stores = new Map();
  for (const n of arr(graph.nodes)) {
    if (!n || typeof n !== 'object') continue;
    if (n.kind === 'external') {
      const host = hostOf(n.destination?.literalValue);
      const key = `${n.subtype ?? 'external'}|${host ?? ''}`;
      if (!ext.has(key) && ext.size < MAX_ITEMS) ext.set(key, { subtype: clean(n.subtype, 60) ?? 'external', host });
    } else if (n.kind === 'queue') {
      const topic = clean(n.queueDetail?.topic, 120); const op = n.queueDetail?.operation === 'consume' || n.queueDetail?.operation === 'receive' ? 'consume' : 'publish';
      if (topic && queues.size < MAX_ITEMS) queues.set(`${topic}|${op}`, { topic, operation: op });
    } else if (n.kind === 'store') {
      const d = n.storeDetail ?? {};
      const item = { subtype: clean(n.subtype, 60) ?? 'store', host: hostOf(d.host), database: clean(d.database, 120), table: clean(d.table, 120) };
      const key = JSON.stringify(item);
      if (stores.size < MAX_ITEMS) stores.set(key, item);
    }
  }
  const edges = arr(graph.edges);
  const crossing = new Set(edges.filter((e) => arr(e?.boundaryCrossings).length).map((e) => e.id));
  const dataById = new Map(arr(graph.dataElements).map((d) => [d?.id, d]));
  const sensitiveCrossing = arr(graph.flows).filter((f) => arr(f?.edgeIds).some((id) => crossing.has(id)) && arr(f?.dataElementIds).some((id) => arr(dataById.get(id)?.dataClasses).some((c) => SENSITIVE.has(String(c).toLowerCase())))).length;
  return {
    schema: 'agentic-security/fleet-lineage-summary', version: 1,
    dataClasses: [...classes].sort().slice(0, MAX_ITEMS),
    externalDestinations: [...ext.values()],
    queues: [...queues.values()],
    stores: [...stores.values()],
    counts: { nodes: arr(graph.nodes).length, edges: edges.length, flows: arr(graph.flows).length, boundaryCrossingEdges: crossing.size, sensitiveFlowsCrossingBoundary: sensitiveCrossing },
  };
}
