//
// context-manifest/1: the inspectable record behind every bundle.
//
// A manifest answers, without any model: which entry point, which exact source spans (with hashes), which controls
// were seen and how they were established, what could not be resolved, what was left out and why, and how complete
// the bundle is. `validateManifest` enforces the contract's hard rules, so a manifest that over-claims is an error,
// not a warning.
import { hashOf, safeRelPath, sha256, sliceLines } from './canonical.js';
import { evaluateProtection } from './reachability.js';

export const MANIFEST_SCHEMA_VERSION = 'context-manifest/1';
export const INTEGRITY_VALUES = Object.freeze(['complete', 'partial', 'unavailable']);

/** Content-addressed key of a bundle set. Depends on what the model would see and how it was built, never on the commit. */
export function contextHashOf({ entrypoint, pack, graphSchema }) {
  return hashOf({
    algorithm: 'context-hash/1',
    graphSchema,
    entrypoint: { kind: entrypoint.kind, method: entrypoint.method, path: entrypoint.pathTemplate, handler: entrypoint.handlerSymbol },
    profile: pack.profile, maxTokens: pack.maxTokens, prune: pack.pruneLowValue,
    packages: pack.packages.map(p => p.sha256),
    integrity: pack.integrity,
  });
}

export function buildManifest({ entrypoint, reach, pack, graph, fileContents, repository, semanticSource = ['static-ir'] }) {
  const omittedWithControls = pack.omissions.some(o => o.reason === 'omitted_due_to_budget' && o.symbolId && reach.facts.some(f => f.symbolId === o.symbolId));
  const protection = evaluateProtection({ facts: reach.facts, unknowns: reach.unknowns, omittedWithControls, capped: reach.capped });
  const byId = new Map(graph.symbols.map(s => [s.id, s]));

  const reachableSymbols = reach.visited.map(v => {
    const s = byId.get(v.symbolId);
    return { symbolId: v.symbolId, file: s.file, start: { line: s.startLine, column: 1 }, end: { line: s.endLine, column: 1 }, spanHash: s.spanHash, spanPrecision: s.spanPrecision, reason: v.reason, depth: v.depth, pathFromRoot: v.path, confidence: v.confidence };
  });
  const includedSymbols = new Set(pack.packages.flatMap(p => p.segments.flatMap(s => s.symbolIds)));
  for (const r of reachableSymbols) r.included = includedSymbols.has(r.symbolId) || (reach.root && reach.root.kind === 'inline-block' && r.reason === 'handler');

  const manifest = {
    schemaVersion: MANIFEST_SCHEMA_VERSION,
    entrypointId: entrypoint.id,
    entrypoint: {
      kind: entrypoint.kind, method: entrypoint.method, path: entrypoint.pathTemplate, framework: entrypoint.framework, language: entrypoint.language,
      handlerSymbol: entrypoint.handlerSymbol, handlerKind: entrypoint.handlerKind, handlerConfidence: entrypoint.handlerConfidence,
      registrationSite: entrypoint.registrationSite, authScheme: entrypoint.authScheme, middleware: entrypoint.middleware,
    },
    repository,
    graph: { schemaVersion: graph.schemaVersion, hash: graph.hash, source: semanticSource },
    context: {
      profile: pack.profile, maxTokens: pack.maxTokens, integrity: pack.integrity, integrityReasons: [...pack.integrityReasons].sort(),
      tokenizer: pack.tokenizer, pruneLowValue: pack.pruneLowValue,
      packages: pack.packages.map(p => ({ index: p.index, total: p.total, setId: p.setId, sha256: p.sha256, tokensEstimated: p.tokensEstimated, standalone: p.standalone, integrity: p.integrity, segments: p.segments })),
    },
    reachableSymbols,
    // observed and inferred are kept apart on purpose: a name is not an observation
    controls: reach.facts.filter(f => f.category === 'control').map(f => ({ symbolId: f.symbolId, file: f.file, line: f.line, kind: f.kind, evidence: f.evidence, basis: f.basis, rejectionSeen: f.rejectionSeen, order: f.effLine === -1 ? 'before-handler' : null, status: 'included' })),
    sensitiveOperations: reach.facts.filter(f => f.category === 'sensitive').map(f => ({ symbolId: f.symbolId, file: f.file, line: f.line, kind: f.kind, basis: f.basis })),
    protection,
    unknowns: reach.unknowns.map(u => ({ type: u.type, site: u.site, calleeName: u.calleeName || null, reason: u.reason, material: u.material, candidates: u.candidates || [] })),
    boundaries: reach.boundaries,
    omissions: pack.omissions,
    traversal: { capped: reach.capped, cycles: reach.cycles, limits: reach.limits, unvisited: reach.unvisited },
    status: { entrypoint: entrypoint.disposition, reachability: reach.capped || reach.unknowns.some(u => u.material) ? 'partial' : (reach.root ? 'complete' : 'unavailable'), bundle: pack.integrity },
    resolutionReasons: entrypoint.resolutionReasons,
  };
  manifest.contextHash = contextHashOf({ entrypoint, pack, graphSchema: graph.schemaVersion });
  manifest.manifestHash = hashOf({ ...manifest, repository: undefined });
  return manifest;
}

/**
 * Contract validation. Returns problems (empty = valid). With `fileContents` it also verifies every span hash against
 * the current source, which is what turns a stale manifest into an error instead of a quiet mismatch.
 */
export function validateManifest(m, { fileContents = null } = {}) {
  const p = [];
  if (!m || m.schemaVersion !== MANIFEST_SCHEMA_VERSION) return ['unsupported-schema-version'];
  if (!INTEGRITY_VALUES.includes(m.context?.integrity)) p.push('bad-integrity-value');
  const materialUnknowns = (m.unknowns || []).some(u => u.material);
  const budgetOmissions = (m.omissions || []).some(o => o.reason === 'omitted_due_to_budget');
  if (m.context?.integrity === 'complete' && (materialUnknowns || budgetOmissions || m.traversal?.capped)) p.push('complete-with-material-gaps');
  if (m.context?.integrity === 'complete' && m.status?.entrypoint && m.status.entrypoint !== 'resolved') p.push('complete-with-unresolved-entrypoint');
  for (const pk of m.context?.packages || []) {
    if (pk.total > 1 && pk.integrity === 'complete') p.push(`standalone-complete-in-split-set:${pk.index}`);
    for (const s of pk.segments || []) {
      if (!safeRelPath(s.file) || s.file !== safeRelPath(s.file)) p.push(`unsafe-path:${s.file}`);
      if (fileContents) {
        const t = fileContents[s.file];
        if (typeof t !== 'string') { p.push(`missing-file:${s.file}`); continue; }
        if (s.startLine < 1 || s.endLine > t.split('\n').length || s.endLine < s.startLine) { p.push(`span-out-of-range:${s.file}:${s.startLine}`); continue; }
        if (sha256(sliceLines(t, s.startLine, s.endLine)) !== s.spanHash) p.push(`stale-span:${s.file}:${s.startLine}-${s.endLine}`);
      }
    }
  }
  const probe = { ...m };
  delete probe.manifestHash;
  if (hashOf({ ...probe, repository: undefined }) !== m.manifestHash) p.push('manifest-hash-mismatch');
  if (JSON.stringify(m).match(/"(?:file|site)":"(?:\/|[A-Za-z]:)/)) p.push('absolute-host-path');
  return p;
}
