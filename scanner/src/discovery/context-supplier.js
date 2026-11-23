// Verified context for the hunt and its challengers (Epic B-01 of the contract-driven verification programme).
//
// The context-intelligence store holds, per entry point, a hash-bound bundle: the manifest (`context-manifest/1`) with its controls
// and protection verdicts, and numbered package texts whose segments carry the span hash of the source they were built from. This
// module reads that store for one scanned root and answers three questions the discovery pipeline asks:
//
//   forArea(files, maxChars)   the package texts whose segments touch these files, for the hunter's prompt, within a budget
//   forCandidate(file, line)   the segments that contain a cited line, the exact source span, and the entry points that reach it with
//                              their controls and protection, for a challenger's prompt and for the qualification record
//   verifyCitation(c)          the context layer's own citation check (`resolveCitation`), so a hunter's or a refuter's citation is
//                              judged against the bundle it was shown, never against the whole repository
//
// A missing or unverifiable store is reported as `available: false` with a reason, and every consumer then records its context as
// `unavailable`; it is never silently treated as "nothing to see". Package texts are re-checked against their hashes on every read
// (`readPackageText`), and a span whose source no longer hashes to its segment is `stale`.
import { readStoreJson, readManifest, readPackageText } from '../context-intelligence/store.js';
import { resolveCitation } from '../context-intelligence/review.js';
import { sha256, sliceLines } from '../context-intelligence/canonical.js';

const CONTEXT_STATES = Object.freeze(['complete', 'partial', 'unavailable', 'stale']); // the values `state` takes below

/** Build a supplier over a scanned root. `fileContents` is the hunt's own snapshot (repository-relative paths). Never throws. */
export function makeContextSupplier({ scanRoot, fileContents = {}, built = null } = {}) {
  const unavailable = (reason) => ({ available: false, reason, forArea: () => ({ packages: [], omitted: 0, state: 'unavailable', reason }), forCandidate: () => ({ state: 'unavailable', reason, segments: [], entrypoints: [], controls: [] }), verifyCitation: () => 'context-unavailable', summary: () => ({ state: 'unavailable', reason, entrypoints: 0 }) });
  // An in-memory build (the evaluation lab's staged workspace) is read directly; a scanned root is read from its store, re-verified.
  let index; const bundles = []; const memText = new Map();
  if (built && built.ok !== false && Array.isArray(built.bundles)) {
    index = { graph: { hash: built.graph?.hash ?? null }, repository: built.repository ?? null, configHash: null, entrypoints: [] };
    for (const b of built.bundles) {
      if (!b.manifest) continue;
      const entry = { entrypointId: b.entrypoint.id, label: b.entrypoint.label, contextHash: b.manifest.contextHash };
      index.entrypoints.push(entry);
      bundles.push({ entry, manifest: b.manifest, problem: null });
      for (const p of b.pack?.packages || []) memText.set(`${b.manifest.contextHash}#${p.index}`, p.text);
    }
  } else {
    if (!scanRoot) return unavailable('no scan root: the context store is per project');
    const idx = readStoreJson(scanRoot, 'index.json');
    if (!idx.ok) return unavailable(`no context build for this root (${idx.code}): run \`context build\` first`);
    index = idx.value;
    for (const e of index.entrypoints || []) {
      if (!e.contextHash) continue;
      const m = readManifest(scanRoot, e.contextHash);
      if (!m.ok) { bundles.push({ entry: e, manifest: null, problem: `manifest-${m.code}` }); continue; }
      bundles.push({ entry: e, manifest: m.value, problem: null });
    }
  }
  const packageText = (manifest, index2) => {
    const k = `${manifest.contextHash}#${index2}`;
    if (memText.has(k)) { const text = memText.get(k); const pk = manifest.context.packages.find((p) => p.index === index2); return pk && sha256(text) === pk.sha256 ? { ok: true, text } : { ok: false, code: 'hash-mismatch' }; }
    return readPackageText(scanRoot, manifest, index2);
  };
  if (!bundles.length) return unavailable('the context build has no bundles');

  const segmentsOf = (manifest) => manifest.context.packages.flatMap((p) => p.segments.map((s) => ({ ...s, packageIndex: p.index })));
  const staleness = (seg) => {
    const text = fileContents[seg.file];
    if (typeof text !== 'string') return 'file-not-in-snapshot';
    if (typeof seg.spanHash !== 'string') return null;
    return sha256(sliceLines(text, seg.startLine, seg.endLine)) === seg.spanHash ? null : 'stale';
  };

  function forArea(files, maxChars = 24_000) {
    const want = new Set(files || []);
    const chosen = [];
    for (const b of bundles) {
      if (!b.manifest) continue;
      const segs = segmentsOf(b.manifest);
      if (!segs.some((s) => want.has(s.file))) continue;
      for (const pk of b.manifest.context.packages) {
        const t = packageText(b.manifest, pk.index);
        if (!t.ok) { chosen.push({ entrypoint: b.entry.label, contextHash: b.manifest.contextHash, index: pk.index, text: null, problem: t.code }); continue; }
        chosen.push({ entrypoint: b.entry.label, contextHash: b.manifest.contextHash, index: pk.index, text: t.text, chars: t.text.length, integrity: b.manifest.context.integrity, controls: b.manifest.controls || [], protection: b.manifest.protection || {}, stale: segsStale(segs) });
      }
    }
    // Smallest first, so many small bundles beat one large one under a budget; the omitted count is reported, never hidden.
    chosen.sort((a, b) => (a.chars || 0) - (b.chars || 0) || (a.contextHash < b.contextHash ? -1 : 1));
    const packages = []; let used = 0; let omitted = 0;
    for (const c of chosen) {
      if (c.text === null) { omitted += 1; continue; }
      if (used + c.chars > maxChars) { omitted += 1; continue; }
      packages.push(c); used += c.chars;
    }
    const states = packages.map((p) => (p.stale ? 'stale' : p.integrity));
    const state = !packages.length ? 'unavailable' : states.includes('stale') ? 'stale' : states.every((s) => s === 'complete') && omitted === 0 ? 'complete' : 'partial';
    if (!CONTEXT_STATES.includes(state)) throw new Error(`unknown context state ${state}`);
    return { packages, omitted, state, reason: omitted ? `${omitted} package(s) omitted for the budget or unreadable` : null };
  }
  const segsStale = (segs) => segs.some((s) => staleness(s) === 'stale');

  function forCandidate(file, line) {
    const hits = [];
    for (const b of bundles) {
      if (!b.manifest) continue;
      const segs = segmentsOf(b.manifest).filter((s) => s.file === file && line >= s.startLine && line <= s.endLine);
      if (!segs.length) continue;
      hits.push({ entrypoint: b.entry.label, entrypointId: b.entry.entrypointId, contextHash: b.manifest.contextHash, integrity: b.manifest.context.integrity, segments: segs.map((s) => ({ ...s, staleness: staleness(s) })), controls: (b.manifest.controls || []).map((c) => ({ kind: c.kind, file: c.file, line: c.line, evidence: c.evidence, basis: c.basis, symbolId: c.symbolId })), protection: b.manifest.protection || {} });
    }
    if (!hits.length) return { state: 'unavailable', reason: 'no bundle contains the cited line', segments: [], entrypoints: [], controls: [] };
    const anyStale = hits.some((h) => h.segments.some((s) => s.staleness === 'stale'));
    const text = fileContents[file];
    const span = typeof text === 'string' ? { startLine: Math.max(1, line - 12), endLine: Math.min(text.split('\n').length, line + 12) } : null;
    const state = anyStale ? 'stale' : hits.every((h) => h.integrity === 'complete') ? 'complete' : 'partial';
    return {
      state, reason: anyStale ? 'a segment no longer matches the source it was built from' : null,
      segments: hits.flatMap((h) => h.segments),
      entrypoints: hits.map((h) => ({ label: h.entrypoint, entrypointId: h.entrypointId, contextHash: h.contextHash, integrity: h.integrity, protection: h.protection })),
      controls: dedupe(hits.flatMap((h) => h.controls)),
      span: span ? { ...span, text: sliceLines(text, span.startLine, span.endLine) } : null,
    };
  }

  function verifyCitation(c) {
    if (!c || typeof c.file !== 'string') return 'range-invalid';
    const segs = bundles.filter((b) => b.manifest).flatMap((b) => segmentsOf(b.manifest));
    return resolveCitation({ file: c.file, startLine: c.startLine, endLine: c.endLine ?? c.startLine, claim: c.claim ?? c.explanation ?? '' }, segs, fileContents);
  }

  return {
    available: true, reason: null,
    index: { graphHash: index.graph?.hash ?? null, repository: index.repository ?? null, configHash: index.configHash ?? null, entrypoints: bundles.length },
    forArea, forCandidate, verifyCitation,
    summary: () => ({ state: bundles.every((b) => b.manifest && b.manifest.context.integrity === 'complete') ? 'complete' : 'partial', entrypoints: bundles.length, problems: bundles.filter((b) => b.problem).map((b) => b.problem) }),
  };
}

function dedupe(controls) {
  const seen = new Set(); const out = [];
  for (const c of controls) { const k = `${c.kind}|${c.file}|${c.line}|${c.basis}`; if (seen.has(k)) continue; seen.add(k); out.push(c); }
  return out;
}
