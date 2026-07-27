// R6 (threat-model-first scoping) + R9 (attack-surface-forward analysis).
//
// Every other precision mechanism in this engine kills a false positive by
// PATTERN — a sanitizer on the path, a proof that didn't reproduce, a
// confidence model fit to labelled families. This module kills one by
// RELEVANCE: a finding sitting on a path an attacker can actually reach,
// inside something the threat model says is worth attacking, matters more
// than one that is neither. It is a different axis, and it composes with
// (never replaces) the sink-driven taint engine.
//
//   R9 — start at the attack surface and reason FORWARD. `entrypoint-
//        inventory.js` already enumerates every attacker-reachable entry
//        point (HTTP/queue/cron/CLI/env/upload/webhook). Here that inventory
//        stops being a report and starts being an input: we walk the module
//        import graph out from every entry-point file and record which files
//        are reachable from the attack surface at all.
//   R6 — `threat-model.js` already derives assets, trust boundaries and a
//        STRIDE classification. Here that model re-ranks: a finding on a
//        modelled asset, or one classified into a modelled STRIDE bucket,
//        outranks an identical finding that is in neither.
//
// ── Recall-preserving contract (non-negotiable) ────────────────────────────
// Same precedent as `falsification.js` and `dataflow/proof-gate.js`:
//   • Never removes a finding. The array in is the array out, same length,
//     same order, same objects.
//   • Never touches `severity`. Ever. Severity is the customer's triage
//     contract; relevance is an ordinal re-rank underneath it.
//   • Never asserts `unreachable` without POSITIVE evidence. "I could not
//     determine it" is `entrypointReachable: null` / `relevanceTier:
//     'unknown'` — a distinct state from "I determined it is not reachable".
//     A negative verdict additionally requires the intra-repo import graph to
//     be provably COMPLETE: one unresolved relative import anywhere means the
//     graph has a hole an attacker's path could be hiding in, and every
//     would-be `unreachable` degrades to `unknown`.
//   • Demotion has a floor. An unreachable finding's exploitability is scaled,
//     never zeroed — a wrong reachability call must cost rank, not visibility.
//
// Fields set on each finding:
//   entrypointReachable : true | false | null   (null ≠ false)
//   relevance           : number 0..1
//   relevanceTier       : 'direct' | 'indirect' | 'unreachable' | 'unknown'
//   relevanceFactors    : string[]  (human-readable, like exploitabilityFactors)

// ── Tunables ───────────────────────────────────────────────────────────────
const BASE_SCORE = {
  direct: 0.75,
  indirect: 0.50,
  unreachable: 0.15,
  unknown: 0.40,
};
// Cap so that no accumulation of R6 bonuses can push an evidenced-unreachable
// finding into the same band as a reachable one.
const UNREACHABLE_CAP = 0.30;

// Exploitability re-rank multipliers (R6's "re-rank exploitability").
const EXPLOIT_MULT = { direct: 1.15, indirect: 1.0, unreachable: 0.6, unknown: 1.0 };
const EXPLOIT_FLOOR = 0.05;   // demotion never zeroes a finding out

const IMPORT_EXTS = ['', '.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx', '/index.js', '/index.ts', '/index.mjs'];
const MAX_FILES = 5000;       // graph-size guard: bail to 'unknown' beyond this

// ── Source-level import extraction ─────────────────────────────────────────
// Static, literal specifiers only. Anything non-literal is recorded as a hole.
const RE_IMPORT_FROM = /\bimport\s[^;'"`]*?from\s*['"]([^'"]+)['"]/g;
const RE_IMPORT_BARE = /\bimport\s*['"]([^'"]+)['"]/g;
const RE_EXPORT_FROM = /\bexport\s[^;'"`]*?from\s*['"]([^'"]+)['"]/g;
const RE_REQUIRE = /\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)/g;
const RE_DYN_IMPORT = /\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g;
const RE_PY_FROM = /^\s*from\s+([.\w]+)\s+import\s/gm;
const RE_PY_IMPORT = /^\s*import\s+([.\w]+)/gm;
const RE_JAVA_IMPORT = /^\s*import\s+(?:static\s+)?([\w.]+);/gm;
// Non-literal module loads: the graph cannot see through these.
const RE_DYNAMIC_HOLE = /\brequire\s*\(\s*[^'")\s]|\bimport\s*\(\s*[^'")\s]/;

function _entries(fileContents) {
  if (!fileContents) return [];
  if (fileContents instanceof Map) {
    return [...fileContents.entries()].filter(([k, v]) => typeof k === 'string' && typeof v === 'string');
  }
  if (typeof fileContents === 'object') {
    return Object.entries(fileContents).filter(([k, v]) => typeof k === 'string' && typeof v === 'string');
  }
  return [];
}

function _norm(p) {
  const parts = String(p).replace(/\\/g, '/').split('/');
  const out = [];
  for (const seg of parts) {
    if (seg === '' || seg === '.') continue;
    if (seg === '..') { out.pop(); continue; }
    out.push(seg);
  }
  return out.join('/');
}

function _dirOf(file) {
  const i = String(file).replace(/\\/g, '/').lastIndexOf('/');
  return i < 0 ? '' : String(file).slice(0, i);
}

// Resolve one specifier to a key in `known`. Returns the key, or null.
function _resolve(spec, fromFile, known, suffixIndex) {
  if (!spec) return null;
  const relative = spec.startsWith('.');
  const base = relative ? _norm(`${_dirOf(fromFile)}/${spec}`) : null;

  if (relative) {
    for (const ext of IMPORT_EXTS) {
      const cand = base + ext;
      if (known.has(cand)) return cand;
    }
    // Also try the raw (already-extensioned) form as written.
    if (known.has(base)) return base;
    return null;
  }

  // Non-relative: python dotted module, java FQCN, or a bare package name.
  const dotted = spec.replace(/\./g, '/');
  for (const ext of ['.py', '.java', '.js', '.ts', '/__init__.py']) {
    const hit = suffixIndex.get(dotted + ext);
    if (hit) return hit;
  }
  return null;
}

/**
 * Build the attack-surface reachability view.
 *
 * @returns {{
 *   entryFiles: Set<string>, unauthEntryFiles: Set<string>,
 *   reachableFiles: Set<string>, knownFiles: Set<string>,
 *   graphComplete: boolean, holes: number,
 * }}
 */
function buildReachabilityGraph(fileContents, opts = {}) {
  const knownFiles = new Set();
  const entryFiles = new Set();
  const unauthEntryFiles = new Set();
  const reachableFiles = new Set();
  let graphComplete = false;
  let holes = 0;

  try {
    const files = _entries(fileContents);
    if (files.length === 0 || files.length > MAX_FILES) {
      return { entryFiles, unauthEntryFiles, reachableFiles, knownFiles, graphComplete: false, holes: 1 };
    }
    for (const [k] of files) knownFiles.add(k);

    // Index by path suffix so a python/java module name can find its file.
    const suffixIndex = new Map();
    for (const k of knownFiles) {
      const norm = k.replace(/\\/g, '/');
      const segs = norm.split('/');
      for (let i = 0; i < segs.length; i++) {
        const suf = segs.slice(i).join('/');
        if (!suffixIndex.has(suf)) suffixIndex.set(suf, k);
      }
    }

    // 1) Entry-point files, from the inventory and/or the raw route list.
    const inv = opts.entrypointInventory;
    const invEntries = inv && Array.isArray(inv.entrypoints) ? inv.entrypoints
      : Array.isArray(opts.entrypoints) ? opts.entrypoints : [];
    for (const e of invEntries) {
      if (!e || typeof e.file !== 'string' || !e.file) continue;
      entryFiles.add(e.file);
      if (e.trust !== 'authenticated') unauthEntryFiles.add(e.file);
    }
    for (const r of (Array.isArray(opts.routes) ? opts.routes : [])) {
      if (!r || typeof r.file !== 'string' || !r.file) continue;
      entryFiles.add(r.file);
      if (r.hasAuth !== true) unauthEntryFiles.add(r.file);
    }

    // 2) Import edges. A hole is an edge the graph cannot see: an unresolved
    //    intra-repo (relative) specifier, or a non-literal module load. Holes
    //    are recorded PER FILE because only holes in files that turn out to be
    //    REACHABLE can hide a path into somewhere we'd otherwise call
    //    unreachable — a hidden edge always originates in the importing file,
    //    so a hole inside an already-unreachable file cannot make anything
    //    reachable. Anything else would make a negative verdict impossible in
    //    any real repository (one `require(varName)` anywhere would veto all).
    const edges = new Map();
    const holeFiles = new Set();
    for (const [file, src] of files) {
      const out = new Set();
      if (RE_DYNAMIC_HOLE.test(src)) { holes++; holeFiles.add(file); }
      for (const re of [RE_IMPORT_FROM, RE_EXPORT_FROM, RE_IMPORT_BARE, RE_REQUIRE, RE_DYN_IMPORT,
        RE_PY_FROM, RE_PY_IMPORT, RE_JAVA_IMPORT]) {
        re.lastIndex = 0;
        let m;
        while ((m = re.exec(src))) {
          const spec = m[1];
          if (!spec) continue;
          const target = _resolve(spec, file, knownFiles, suffixIndex);
          if (target && target !== file) out.add(target);
          // Only an unresolved INTRA-repo (relative) specifier is a hole:
          // a bare package name points at a third-party module that was
          // never part of `fileContents` in the first place.
          else if (!target && spec.startsWith('.')) { holes++; holeFiles.add(file); }
        }
      }
      edges.set(file, out);
    }

    // 3) Forward BFS from the attack surface.
    const queue = [...entryFiles].filter(f => knownFiles.has(f));
    for (const f of queue) reachableFiles.add(f);
    while (queue.length) {
      const cur = queue.shift();
      for (const next of (edges.get(cur) || [])) {
        if (reachableFiles.has(next)) continue;
        reachableFiles.add(next);
        queue.push(next);
      }
    }

    // A negative verdict is admissible only when we actually found an attack
    // surface AND no file reachable from it has an invisible edge.
    let reachableHole = false;
    for (const f of reachableFiles) if (holeFiles.has(f)) { reachableHole = true; break; }
    graphComplete = !reachableHole && entryFiles.size > 0;
  } catch (_) {
    return { entryFiles, unauthEntryFiles, reachableFiles, knownFiles, graphComplete: false, holes: holes || 1 };
  }
  return { entryFiles, unauthEntryFiles, reachableFiles, knownFiles, graphComplete, holes };
}

// ── R6: threat-model bonuses ───────────────────────────────────────────────
function _threatBonus(f, threatModel, factors) {
  let bonus = 0;
  if (!threatModel || typeof threatModel !== 'object') return bonus;

  const assets = Array.isArray(threatModel.assets) ? threatModel.assets : [];
  for (const a of assets) {
    if (!a || a.file !== f.file) continue;
    const exposed = a.exposure === 'public-api' || a.exposure === 'external-api';
    bonus += exposed ? 0.10 : 0.07;
    factors.push(`modelled asset in file: ${a.category || a.name || 'asset'}${exposed ? ` (${a.exposure})` : ''}`);
    break;
  }

  const boundaries = Array.isArray(threatModel.trustBoundaries) ? threatModel.trustBoundaries : [];
  if (boundaries.some(b => b && b.file === f.file)) {
    bonus += 0.05;
    factors.push('trust boundary crossed in this file');
  }

  const stride = threatModel.stride && typeof threatModel.stride === 'object' ? threatModel.stride : null;
  if (stride) {
    for (const [cat, items] of Object.entries(stride)) {
      if (!Array.isArray(items)) continue;
      if (items.some(it => it && it.file === f.file && (it.line === f.line || it.vuln === f.vuln))) {
        bonus += 0.08;
        factors.push(`modelled STRIDE threat: ${cat}`);
        break;
      }
    }
  }
  return bonus;
}

/**
 * Pure scorer. Does NOT mutate the finding.
 *
 * @param graph  the object returned by buildReachabilityGraph (or a subset
 *               with entryFiles / reachableFiles / knownFiles / graphComplete).
 * @returns {{ tier, score, reachable, factors }}
 */
function scoreRelevance(f, graph, threatModel) {
  const factors = [];
  const g = graph || {};
  const entryFiles = g.entryFiles instanceof Set ? g.entryFiles : new Set();
  const reachableFiles = g.reachableFiles instanceof Set ? g.reachableFiles : new Set();
  const knownFiles = g.knownFiles instanceof Set ? g.knownFiles : new Set();
  const unauthEntryFiles = g.unauthEntryFiles instanceof Set ? g.unauthEntryFiles : new Set();
  const file = f && typeof f.file === 'string' ? f.file : null;

  let tier;
  let reachable;
  if (!file || entryFiles.size === 0) {
    tier = 'unknown';
    reachable = null;
    factors.push(entryFiles.size === 0
      ? 'no attack surface enumerated — reachability not determinable'
      : 'finding has no file — reachability not determinable');
  } else if (entryFiles.has(file)) {
    tier = 'direct';
    reachable = true;
    factors.push('finding sits in an entry-point file (direct attack surface)');
    if (unauthEntryFiles.has(file)) factors.push('entry point is unauthenticated');
  } else if (reachableFiles.has(file)) {
    tier = 'indirect';
    reachable = true;
    factors.push('reachable from an entry point via the module import graph');
  } else if (g.graphComplete === true && knownFiles.has(file)) {
    tier = 'unreachable';
    reachable = false;
    factors.push('no import path from any enumerated entry point (import graph complete)');
  } else {
    tier = 'unknown';
    reachable = null;
    factors.push(knownFiles.has(file)
      ? 'import graph incomplete — no reachability verdict admissible'
      : 'file not present in the scanned set — reachability not determinable');
  }

  let score = BASE_SCORE[tier];
  score += _threatBonus(f || {}, threatModel, factors);
  if (tier === 'direct' && unauthEntryFiles.has(file)) score += 0.10;
  if (tier === 'unreachable') score = Math.min(score, UNREACHABLE_CAP);
  score = Math.max(0, Math.min(1, score));

  return { tier, score: Math.round(score * 1000) / 1000, reachable, factors };
}

/**
 * Default-on annotator. Recall-preserving: never removes a finding, never
 * touches severity, never asserts 'unreachable' without positive evidence.
 *
 * @param ctx.fileContents          Map|object of scanned sources
 * @param ctx.entrypointInventory   output of buildEntrypointInventory()
 * @param ctx.routes                route list (fallback attack surface)
 * @param ctx.threatModel           output of buildThreatModel()
 */
export function annotateRelevance(findings, ctx = {}) {
  if (!Array.isArray(findings)) return findings;
  let graph;
  try {
    const c = ctx && typeof ctx === 'object' ? ctx : {};
    graph = buildReachabilityGraph(c.fileContents, {
      entrypointInventory: c.entrypointInventory,
      entrypoints: c.entrypoints,
      routes: c.routes,
    });
  } catch (_) {
    graph = { entryFiles: new Set(), unauthEntryFiles: new Set(), reachableFiles: new Set(), knownFiles: new Set(), graphComplete: false, holes: 1 };
  }
  const threatModel = ctx && typeof ctx === 'object' ? ctx.threatModel : null;

  for (const f of findings) {
    if (!f || typeof f !== 'object') continue;
    try {
      const r = scoreRelevance(f, graph, threatModel);
      f.entrypointReachable = r.reachable;
      f.relevance = r.score;
      f.relevanceTier = r.tier;
      f.relevanceFactors = r.factors;

      // R6 re-rank: exploitability is an ordinal priority, so scaling it by
      // relevance is exactly the intended re-ranking. Severity is untouched,
      // and demotion has a floor — a wrong call costs rank, not visibility.
      const mult = EXPLOIT_MULT[r.tier];
      if (typeof f.exploitability === 'number' && Number.isFinite(f.exploitability) && mult !== 1) {
        const adjusted = Math.max(EXPLOIT_FLOOR, Math.min(1, f.exploitability * mult));
        f.exploitability = Math.round(adjusted * 100) / 100;
        if (typeof f.priorityScore === 'number') f.priorityScore = f.exploitability;
        if (Array.isArray(f.exploitabilityFactors)) f.exploitabilityFactors.push(`relevance:${r.tier}`);
        // Keep the tier label consistent with the re-ranked score. Same
        // thresholds as annotateExploitability; severity is NOT derived here.
        if (f.exploitability >= 0.80) f.exploitabilityTier = 'critical';
        else if (f.exploitability >= 0.60) f.exploitabilityTier = 'high';
        else if (f.exploitability >= 0.35) f.exploitabilityTier = 'medium';
        else f.exploitabilityTier = 'low';
      }
    } catch (_) {
      f.entrypointReachable = null;
      f.relevance = BASE_SCORE.unknown;
      f.relevanceTier = 'unknown';
      f.relevanceFactors = ['relevance scoring failed — no verdict'];
    }
  }
  return findings;
}

// Test-only surface (underscore-prefixed: not part of the public API).
export const _internals = { buildReachabilityGraph, scoreRelevance, BASE_SCORE, EXPLOIT_MULT };
