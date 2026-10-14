//
// Security-preserving context packer.
//
// Takes the deterministic reachability result and produces one or more bounded, readable bundles. The rules, in the
// order they bind:
//
//   1. NOTHING that holds a control or a sensitive operation is ever pruned for size reasons. Pruning for "low value"
//      removes only whole symbols that (a) look like telemetry by name, AND (b) have no control, sensitive operation or
//      material unknown anywhere in their own subtree. There is no line-level pruning: a line cannot be proven
//      irrelevant, a whole telemetry helper can.
//   2. Over budget: de-duplicate (overlapping spans merge), keep the mandatory core (registration, handler, middleware),
//      then fill by priority (symbols with controls / sensitive operations first). What does not fit goes into a LINKED
//      package, not into the void; what fits in no package is recorded as omitted_due_to_budget.
//   3. If even the mandatory core does not fit the budget the bundle is `unavailable`. It is never truncated into
//      something that looks whole.
//   4. A bundle is `complete` only when nothing is unresolved, capped, omitted, imprecise or split.
//
// The bundle text is machine-generated: the entry point, the resolution status, the list of unknowns and omissions,
// and the numbered source. No model writes any of it.
import { sha256, hashOf, sliceLines } from './canonical.js';
import { looksLikeTelemetry } from './controls.js';

export const PROFILES = Object.freeze({ compact: 8000, standard: 32000, extended: 100000 });
export const TOKENIZER_ESTIMATE = 'chars/4-estimate';
export const MAX_PACKAGES = 4;

export function estimateTokens(text, tokenizer) {
  if (typeof tokenizer === 'function') {
    try { const n = tokenizer(text); if (Number.isFinite(n) && n >= 0) return { tokens: Math.ceil(n), tokenizer: tokenizer.tokenizerName || 'injected', estimated: false }; } catch { /* fall through */ }
  }
  return { tokens: Math.ceil(text.length / 4), tokenizer: TOKENIZER_ESTIMATE, estimated: true };
}

function renderSegment(seg, lines) {
  const width = String(seg.endLine).length;
  const body = [];
  for (let n = seg.startLine; n <= seg.endLine; n++) body.push(`${String(n).padStart(width, ' ')}| ${lines[n - 1] ?? ''}`);
  return `=== SOURCE ${seg.file}:${seg.startLine}-${seg.endLine} | ${seg.reasons.join('+')} ===\n${body.join('\n')}`;
}

/** Merge overlapping spans in one file into single segments; reasons and symbol ids are unioned, priority is the best. */
function mergeOverlaps(items) {
  const byFile = new Map();
  for (const it of items) { if (!byFile.has(it.file)) byFile.set(it.file, []); byFile.get(it.file).push(it); }
  const out = [];
  for (const file of [...byFile.keys()].sort()) {
    const arr = byFile.get(file).sort((a, b) => a.startLine - b.startLine || b.endLine - a.endLine);
    let cur = null;
    for (const it of arr) {
      if (cur && it.startLine <= cur.endLine) {
        cur.endLine = Math.max(cur.endLine, it.endLine);
        cur.symbolIds = [...new Set([...cur.symbolIds, ...it.symbolIds])];
        cur.reasons = [...new Set([...cur.reasons, ...it.reasons])];
        cur.priority = Math.min(cur.priority, it.priority);
        cur.order = Math.min(cur.order, it.order);
        cur.hasFacts = cur.hasFacts || it.hasFacts;
        cur.imprecise = cur.imprecise || it.imprecise;
      } else {
        if (cur) out.push(cur);
        cur = { ...it, symbolIds: [...it.symbolIds], reasons: [...it.reasons] };
      }
    }
    if (cur) out.push(cur);
  }
  return out;
}

/**
 * Pack.
 *   entrypoint, reach (reachFrom result), graph, fileContents
 *   config { profile, maxTokens, pruneLowValue, tokenizer? }
 */
export function packContext({ entrypoint, reach, graph, fileContents, config = {} }) {
  const profile = Object.hasOwn(PROFILES, config.profile) ? config.profile : 'standard';
  const maxTokens = Number.isInteger(config.maxTokens) && config.maxTokens > 0 ? config.maxTokens : PROFILES[profile];
  const prune = config.pruneLowValue !== false;
  const byId = new Map(graph.symbols.map(s => [s.id, s]));
  const linesCache = new Map();
  const linesOf = (f) => { if (!linesCache.has(f)) linesCache.set(f, (fileContents[f] || '').split('\n')); return linesCache.get(f); };

  const omissions = [];
  const factSyms = new Set(reach.facts.map(f => f.symbolId));
  const unknownFrom = new Set(reach.unknowns.filter(u => u.material).map(u => u.from));

  // ---- 1. pruning (whole symbols only, with proof) -------------------------------------------------------
  const prunable = new Set();
  if (prune) {
    const visitedById = new Map(reach.visited.map(v => [v.symbolId, v]));
    for (const v of reach.visited) {
      if (v.reason !== 'callee') continue;
      const sym = byId.get(v.symbolId);
      if (!sym || !looksLikeTelemetry(sym.name)) continue;
      const subtree = reach.visited.filter(w => w.path.includes(v.symbolId));
      const clean = subtree.every(w => !factSyms.has(w.symbolId) && !unknownFrom.has(w.symbolId) && w.reason !== 'middleware' && w.reason !== 'inherited-middleware');
      if (!clean) continue;
      for (const w of subtree) {
        prunable.add(w.symbolId);
        omissions.push({ symbolId: w.symbolId, reason: 'non-security-telemetry', proof: `name '${byId.get(v.symbolId).name}' is telemetry-shaped and no control, sensitive operation or material unknown exists in its subtree` });
      }
    }
    void visitedById;
  }

  // ---- 2. candidate segments -----------------------------------------------------------------------------
  const items = [];
  const root = reach.root;
  let order = 0;
  if (root) {
    // the registration block is always shown: it is where inherited wiring is visible
    if (entrypoint.rootSpan) {
      items.push({ file: entrypoint.rootSpan.file, startLine: entrypoint.rootSpan.startLine, endLine: entrypoint.rootSpan.endLine, symbolIds: [], reasons: ['registration'], priority: 0, order: order++, hasFacts: true, imprecise: false });
    }
    if (root.kind === 'inline-block') {
      items.push({ file: root.file, startLine: root.startLine, endLine: root.endLine, symbolIds: root.symbolId ? [root.symbolId] : [], reasons: ['handler'], priority: 0, order: order++, hasFacts: true, imprecise: false });
    }
  }
  for (const v of reach.visited) {
    if (prunable.has(v.symbolId)) continue;
    const sym = byId.get(v.symbolId);
    if (!sym) continue;
    if (v.reason === 'handler' && root && root.kind === 'inline-block') continue; // shown as the registration block above
    const mandatory = v.reason === 'handler' || v.reason === 'middleware' || v.reason === 'inherited-middleware';
    const hasFacts = factSyms.has(v.symbolId) || unknownFrom.has(v.symbolId);
    items.push({
      file: sym.file, startLine: sym.startLine, endLine: sym.endLine, symbolIds: [sym.id],
      reasons: [v.reason === 'name-match-candidate' ? 'candidate-for-unresolved-call' : v.reason],
      priority: mandatory ? 0 : (v.reason === 'name-match-candidate' ? 4 : (hasFacts ? 2 : 3)),
      order: order++, hasFacts, imprecise: sym.spanPrecision === 'cfg-lower-bound',
    });
  }
  const segments = mergeOverlaps(items);

  // ---- 3. budget and linked packages ---------------------------------------------------------------------
  const headerFor = (idx, total, setId, localOmitted) => {
    const lines = [];
    lines.push(`# DETERMINISTIC CONTEXT PACKAGE ${idx}/${total} (set ${setId})`);
    lines.push(`entrypoint: ${entrypoint.label}  kind=${entrypoint.kind}  disposition=${entrypoint.disposition}`);
    lines.push(`handler: ${entrypoint.handlerSymbol || '(none resolved)'}  registration: ${entrypoint.registrationSite.file}:${entrypoint.registrationSite.line}`);
    if (entrypoint.middleware.length) lines.push(`middleware: ${entrypoint.middleware.map(m => `${m.name || '?'}[${m.resolution}${m.inherited ? ',inherited' : ''}]`).join(', ')}`);
    if (total > 1) lines.push(`NOTE: this is one of ${total} linked packages for the same entry point; it is NOT a standalone view.`);
    for (const u of reach.unknowns.filter(x => x.material).slice(0, 12)) lines.push(`UNRESOLVED: ${u.site} call '${u.calleeName || '?'}' (${u.reason}); its body is NOT shown unless listed as a candidate`);
    for (const o of localOmitted.slice(0, 12)) lines.push(`NOT INCLUDED: ${o.symbolId || o.range} (${o.reason})`);
    if (reach.capped) lines.push(`LIMIT: traversal stopped at ${reach.limits.maxSymbols} symbols / depth ${reach.limits.maxDepth}; ${reach.unvisited.length} symbol(s) not visited`);
    lines.push('# SOURCE (numbered; the text before the first "| " on each line is the line number)');
    return lines.join('\n');
  };

  const sorted = [...segments].sort((a, b) => a.priority - b.priority || a.order - b.order);
  const mandatory = sorted.filter(s => s.priority === 0);
  const rest = sorted.filter(s => s.priority !== 0);
  const charBudget = maxTokens * 4;
  const segText = new Map(sorted.map(s => [s, renderSegment(s, linesOf(s.file))]));
  const sizeOf = (s) => segText.get(s).length + 1;
  const HEADER_RESERVE = 1800;

  const result = { entrypointId: entrypoint.id, profile, maxTokens, pruneLowValue: prune, packages: [], omissions, integrity: 'complete', integrityReasons: [], tokenizer: null };

  const mandatoryChars = mandatory.reduce((n, s) => n + sizeOf(s), 0);
  if (!root) {
    result.integrity = 'unavailable';
    result.integrityReasons.push('no-handler-or-registration');
    return result;
  }
  if (mandatoryChars + HEADER_RESERVE > charBudget) {
    result.integrity = 'unavailable';
    result.integrityReasons.push('mandatory-core-exceeds-budget');
    for (const s of sorted) omissions.push({ range: `${s.file}:${s.startLine}-${s.endLine}`, symbolId: s.symbolIds[0] || null, reason: 'omitted_due_to_budget', proof: 'minimum bundle (registration, handler, middleware) does not fit the token budget' });
    return result;
  }

  const bins = [{ segs: [...mandatory], chars: mandatoryChars }];
  const unplaced = [];
  for (const s of rest) {
    const need = sizeOf(s);
    let placed = false;
    for (const bin of bins) {
      if (bin.chars + need + HEADER_RESERVE <= charBudget) { bin.segs.push(s); bin.chars += need; placed = true; break; }
    }
    if (!placed) {
      if (bins.length < MAX_PACKAGES && need + HEADER_RESERVE <= charBudget && s.priority <= 2) { bins.push({ segs: [s], chars: need }); }
      else unplaced.push(s);
    }
  }
  for (const s of unplaced) omissions.push({ range: `${s.file}:${s.startLine}-${s.endLine}`, symbolId: s.symbolIds[0] || null, reason: 'omitted_due_to_budget', proof: 'did not fit any bounded package' });

  const total = bins.length;
  const setId = hashOf(sorted.map(s => [s.file, s.startLine, s.endLine])).slice(0, 12);
  const pkgs = bins.map((bin, i) => {
    const segs = bin.segs.sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : 0) || a.startLine - b.startLine);
    const otherSegs = bins.filter((_, j) => j !== i).flatMap(b => b.segs);
    const localOmitted = [
      ...otherSegs.map(s => ({ range: `${s.file}:${s.startLine}-${s.endLine}`, symbolId: s.symbolIds[0] || null, reason: 'in-linked-package' })),
      ...omissions.filter(o => o.reason === 'omitted_due_to_budget' || o.reason === 'non-security-telemetry'),
    ];
    const body = segs.map(s => segText.get(s)).join('\n');
    const text = `${headerFor(i + 1, total, setId, localOmitted)}\n${body}\n`;
    const est = estimateTokens(text, config.tokenizer);
    result.tokenizer = { name: est.tokenizer, estimated: est.estimated, uncertainty: est.estimated ? 'about 30% either way; chars/4 is not a model tokenizer' : 'exact for the named tokenizer' };
    return {
      index: i + 1, total, setId,
      standalone: total === 1,
      tokensEstimated: est.tokens,
      sha256: sha256(text),
      text,
      segments: segs.map(s => ({ file: s.file, startLine: s.startLine, endLine: s.endLine, symbolIds: s.symbolIds, reasons: s.reasons, spanHash: sha256(sliceLines(fileContents[s.file], s.startLine, s.endLine)) })),
    };
  });
  result.packages = pkgs;

  // ---- 4. integrity --------------------------------------------------------------------------------------
  const why = result.integrityReasons;
  if (entrypoint.disposition !== 'resolved') why.push(`entrypoint-${entrypoint.disposition}`);
  if (reach.unknowns.some(u => u.material)) why.push('material-unresolved-call');
  if (reach.capped) why.push('traversal-limit-reached');
  if (omissions.some(o => o.reason === 'omitted_due_to_budget')) why.push('omitted-for-budget');
  if (segments.some(s => s.imprecise)) why.push('imprecise-span');
  const setReasons = why.filter(r => r !== 'split-into-linked-packages');
  // Set level: every package is present and nothing else is wrong. Package level: a package that has siblings is never
  // standalone-complete, because it is missing the dependencies that live in the others.
  result.integrity = setReasons.length ? 'partial' : 'complete';
  for (const p of pkgs) p.integrity = total === 1 ? result.integrity : 'partial';
  if (total > 1) why.push('split-into-linked-packages');
  return result;
}
