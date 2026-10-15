//
// Incremental invalidation and route diffs.
//
// Invalidation is by RECOMPUTATION, not by prediction: the symbol graph is rebuilt from the current snapshot (cheap,
// local, no model) and every bundle is content-addressed. A review is reused only when the bundle it was made from has
// exactly the same context hash, so:
//   * a change to a shared authorization middleware changes the text of every route that includes it, so all of their
//     hashes change and all of their cached reviews are invalidated, though no handler file was touched;
//   * an unrelated edit leaves untouched bundles byte-identical, so their reviews are cache hits;
//   * a dirty worktree or a different branch is a different snapshot, so a review of another state is never replayed
//     as current.
// There is no optimistic reuse path: if the previous index cannot be read or verified, everything is a miss.
import { readStoreJson, readManifest } from './store.js';

/** symbol / file -> the entry points whose bundles include it. Used to EXPLAIN invalidation, never to skip a rebuild. */
export function reverseDependencies(manifests) {
  const bySymbol = new Map();
  const byFile = new Map();
  for (const m of manifests) {
    for (const s of m.reachableSymbols) {
      if (!bySymbol.has(s.symbolId)) bySymbol.set(s.symbolId, new Set());
      bySymbol.get(s.symbolId).add(m.entrypointId);
      if (!byFile.has(s.file)) byFile.set(s.file, new Set());
      byFile.get(s.file).add(m.entrypointId);
    }
  }
  const toObj = (map) => Object.fromEntries([...map.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1)).map(([k, v]) => [k, [...v].sort()]));
  return { symbols: toObj(bySymbol), files: toObj(byFile) };
}

function routeKey(m) { return `${m.entrypoint.kind}|${m.entrypoint.method}|${m.entrypoint.path}|${m.entrypoint.registrationSite.file}`; }
const ctlKey = (c) => `${c.kind}|${c.file}|${c.line}|${c.evidence}|${c.basis}`;
const sensKey = (s) => `${s.kind}|${s.file}|${s.basis}`;
const unkKey = (u) => `${u.reason}|${u.calleeName}|${u.site.split(':')[0]}`;
const symKey = (s) => `${s.symbolId}|${s.spanHash}`;

function setDiff(a, b) {
  const A = new Set(a), B = new Set(b);
  return { added: [...B].filter(x => !A.has(x)).sort(), removed: [...A].filter(x => !B.has(x)).sort() };
}

/** Diff two sets of manifests (each an array). */
export function diffManifestSets(fromManifests, toManifests) {
  const from = new Map(fromManifests.map(m => [routeKey(m), m]));
  const to = new Map(toManifests.map(m => [routeKey(m), m]));
  const added = [], removed = [], changed = [], unchanged = [];
  for (const [k, m] of [...to.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1))) {
    const prev = from.get(k);
    if (!prev) { added.push({ route: `${m.entrypoint.method} ${m.entrypoint.path}`.trim(), file: m.entrypoint.registrationSite.file, integrity: m.context.integrity }); continue; }
    if (prev.contextHash === m.contextHash) { unchanged.push(k); continue; }
    const controls = setDiff(prev.controls.map(ctlKey), m.controls.map(ctlKey));
    const sensitive = setDiff(prev.sensitiveOperations.map(sensKey), m.sensitiveOperations.map(sensKey));
    const unknowns = setDiff(prev.unknowns.filter(u => u.material).map(unkKey), m.unknowns.filter(u => u.material).map(unkKey));
    const deps = setDiff(prev.reachableSymbols.map(symKey), m.reachableSymbols.map(symKey));
    const protection = {};
    for (const dim of Object.keys(m.protection)) {
      const a = prev.protection?.[dim]?.state; const b = m.protection[dim].state;
      if (a !== b) protection[dim] = { from: a || null, to: b };
    }
    changed.push({
      route: `${m.entrypoint.method} ${m.entrypoint.path}`.trim(), file: m.entrypoint.registrationSite.file,
      contextHash: { from: prev.contextHash, to: m.contextHash },
      integrity: { from: prev.context.integrity, to: m.context.integrity },
      authControlChanges: controls, newSensitiveOperations: sensitive.added, removedSensitiveOperations: sensitive.removed,
      unknownEdgeChanges: unknowns, dependencyChanges: { addedOrChangedSymbols: deps.added.length, removedOrChangedSymbols: deps.removed.length }, protectionChanges: protection,
    });
  }
  for (const [k, m] of [...from.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1))) {
    if (!to.has(k)) removed.push({ route: `${m.entrypoint.method} ${m.entrypoint.path}`.trim(), file: m.entrypoint.registrationSite.file });
  }
  return { added, removed, changed, unchangedCount: unchanged.length };
}

/**
 * Cache accounting against the stored index: for each current bundle, is the same context hash already stored, and if
 * not, why (new route, or which previous hash it replaced).
 */
export function cacheReport(root, currentManifests, { hasReview = () => false } = {}) {
  const idx = readStoreJson(root, 'index.json');
  const previous = new Map();
  let indexStatus = 'missing';
  if (idx.ok && idx.value && Array.isArray(idx.value.entrypoints)) {
    indexStatus = 'ok';
    for (const e of idx.value.entrypoints) previous.set(e.entrypointId, e.contextHash);
  } else if (!idx.ok && idx.code === 'corrupt-json') indexStatus = 'corrupt';
  const rep = { indexStatus, hits: 0, misses: 0, invalidated: 0, newRoutes: 0, reviewCacheHits: 0, details: [] };
  for (const m of currentManifests) {
    const stored = readManifest(root, m.contextHash);
    const prevHash = previous.get(m.entrypointId);
    if (stored.ok && stored.value.manifestHash === m.manifestHash) rep.hits++;
    else rep.misses++;
    if (prevHash === undefined) { rep.newRoutes++; }
    else if (prevHash !== m.contextHash) { rep.invalidated++; rep.details.push({ entrypointId: m.entrypointId, route: `${m.entrypoint.method} ${m.entrypoint.path}`.trim(), previous: prevHash, current: m.contextHash }); }
    if (hasReview(m)) rep.reviewCacheHits++;
  }
  return rep;
}
