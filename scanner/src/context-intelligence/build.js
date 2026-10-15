//
// Orchestration: source snapshot -> symbol graph -> entry points -> per-entry-point reachability -> bundles + manifests.
// Pure with respect to the repository (read-only); persistence is store.js's job. No model, no network.
import { graphFromSource } from './adapters/existing-ir.js';
import { validateGraph } from './graph-schema.js';
import { collectEntrypoints, countDispositions } from './entrypoints.js';
import { reachFrom } from './reachability.js';
import { packContext } from './packer.js';
import { buildManifest } from './manifest.js';
import { readSnapshot } from './files.js';
import { repositoryInfo } from './repo-info.js';
import { loadHieMetadata, mergeHieIntoGraph } from './adapters/haskell-hie.js';

/**
 * Build every bundle for a project.
 *   opts.config   normalised DCI config
 *   opts.route    optional filter: a label substring or an entrypoint id
 *   opts.onEvent  optional progress callback (JSON-serialisable events)
 */
export async function buildContext(root, opts = {}) {
  const config = opts.config;
  const emit = typeof opts.onEvent === 'function' ? opts.onEvent : () => {};
  const snap = opts.snapshot || await readSnapshot(root, { maxFiles: config.maxFiles });
  if (!snap.ok) return { ok: false, reason: snap.reason, detail: snap };
  const { fileContents } = snap;
  emit({ event: 'snapshot', files: Object.keys(fileContents).length, skipped: snap.skipped.length });

  let { graph, perFile, callGraph } = graphFromSource(fileContents);
  let semantic = { source: ['static-ir'], status: 'off', diff: null };
  if (config.semanticMetadata.mode === 'import') {
    const meta = loadHieMetadata(snap.rootReal, config.semanticMetadata.haskellHieDir, { fileContents });
    const merged = mergeHieIntoGraph(graph, meta, fileContents);
    graph = merged.graph;
    semantic = merged.semantic;
  }
  const problems = validateGraph(graph, fileContents);
  if (problems.length) return { ok: false, reason: 'graph-invalid', detail: problems.slice(0, 20) };
  emit({ event: 'graph', symbols: graph.symbols.length, edges: graph.edges.length, hash: graph.hash });

  let entrypoints = await collectEntrypoints({ fileContents, graph, config });
  const counts = countDispositions(entrypoints);
  emit({ event: 'entrypoints', ...counts });
  if (opts.route) entrypoints = entrypoints.filter(e => e.id === opts.route || e.label.includes(opts.route));

  const repository = snap.commit ? { commit: snap.commit, dirty: false, snapshotHash: snap.snapshotHash } : repositoryInfo(snap.rootReal, snap.snapshotHash);
  const bundles = [];
  for (const ep of entrypoints) {
    if (ep.disposition === 'excluded_by_policy') { bundles.push({ entrypoint: ep, manifest: null, pack: null, reach: null }); continue; }
    const reach = reachFrom({ graph, fileContents, entrypoint: ep, limits: { maxSymbols: config.context.maxSymbols, maxDepth: config.context.maxDepth } });
    const pack = packContext({ entrypoint: ep, reach, graph, fileContents, config: { profile: config.context.profile, maxTokens: config.context.maxTokens, pruneLowValue: config.context.pruneLowValue, tokenizer: opts.tokenizer } });
    const manifest = buildManifest({ entrypoint: ep, reach, pack, graph, fileContents, repository, semanticSource: semantic.source });
    bundles.push({ entrypoint: ep, manifest, pack, reach });
    emit({ event: 'bundle', entrypoint: ep.id, integrity: pack.integrity, packages: pack.packages.length });
  }
  const built = bundles.filter(b => b.manifest);
  return {
    ok: true, root: snap.rootReal, repository, graph, semantic, ir: { perFile, callGraph }, snapshotHash: snap.snapshotHash, entrypoints, bundles, fileContents, skipped: snap.skipped,
    summary: {
      entrypointsFound: counts.total, resolved: counts.resolved, partial: counts.partially_resolved, unresolved: counts.unresolved, excluded: counts.excluded_by_policy,
      bundlesBuilt: built.length,
      complete: built.filter(b => b.manifest.context.integrity === 'complete').length,
      partialBundles: built.filter(b => b.manifest.context.integrity === 'partial').length,
      unavailable: built.filter(b => b.manifest.context.integrity === 'unavailable').length,
      unresolvedEdges: built.reduce((n, b) => n + b.manifest.unknowns.filter(u => u.material).length, 0),
      tokens: built.reduce((n, b) => n + b.pack.packages.reduce((m, p) => m + p.tokensEstimated, 0), 0),
    },
  };
}
