//
// Persist a build: every bundle (manifest + package texts), the index that maps entry points to their current bundle,
// and the reverse-dependency map. Nothing else about the repository is written.
import { writeBundle, writeStoreJson } from './store.js';
import { reverseDependencies } from './diff.js';
import { hashOf } from './canonical.js';

export const INDEX_SCHEMA = 'context-index/1';

export function persistBuild(root, built, config) {
  const failures = [];
  const manifests = [];
  for (const b of built.bundles) {
    if (!b.manifest) continue;
    const r = writeBundle(root, b);
    if (!r.ok) { failures.push({ entrypointId: b.entrypoint.id, code: r.code, reason: r.reason }); continue; }
    manifests.push(b.manifest);
  }
  const index = {
    schemaVersion: INDEX_SCHEMA,
    graph: { schemaVersion: built.graph.schemaVersion, hash: built.graph.hash, source: built.semantic.source },
    repository: built.repository,
    configHash: hashOf(config),
    summary: built.summary,
    entrypoints: built.entrypoints.map(e => {
      const b = built.bundles.find(x => x.entrypoint.id === e.id);
      return {
        entrypointId: e.id, label: e.label, kind: e.kind, disposition: e.disposition, file: e.registrationSite.file,
        contextHash: b && b.manifest ? b.manifest.contextHash : null,
        integrity: b && b.manifest ? b.manifest.context.integrity : null,
        resolutionReasons: e.resolutionReasons,
      };
    }),
  };
  const wi = writeStoreJson(root, 'index.json', index);
  if (!wi.ok) failures.push({ code: wi.code, reason: wi.reason, what: 'index.json' });
  const wr = writeStoreJson(root, 'reverse-dependencies.json', reverseDependencies(manifests));
  if (!wr.ok) failures.push({ code: wr.code, reason: wr.reason, what: 'reverse-dependencies.json' });
  return { ok: failures.length === 0, failures, written: manifests.length };
}
