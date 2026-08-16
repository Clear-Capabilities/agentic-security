// Per-layer recall attribution — the pure half.
//
// A corpus entry passing tells you the vulnerability was detected. It does not
// tell you WHICH analysis layer detected it, and that distinction is the whole
// point of this instrument: the CVE-replay corpus was 210/210 green with 20
// Ruby entries while a Ruby fixture (`params[:c]` → `system(c)`) produced zero
// IR-TAINT findings. The regex layer was carrying the language, and no gate
// could see it.
//
// Kept separate from the runner so the counting rules are unit-testable without
// driving 210 scans.

/** The deep taint engine's parser label, as stamped on findings by dataflow/. */
export const LAYER_TAINT = 'IR-TAINT';

/** A finding that records no parser is attributed, never dropped. */
const UNATTRIBUTED = '(unattributed)';

/**
 * The distinct analysis layers that produced these findings, sorted.
 *
 * An unattributed finding is counted under its own label rather than skipped:
 * dropping it would shrink the denominator of whichever layer we care about and
 * flatter the result, which is the direction a measurement must never lean.
 */
export function layersOf(findings) {
  const out = new Set();
  for (const f of findings || []) out.add((f && f.parser) || UNATTRIBUTED);
  return [...out].sort();
}

/**
 * Aggregate per-entry rows into a language × layer matrix.
 *
 * Each row: { language, detected, layers[] }.
 *
 * `total` counts every entry for the language, detected or not. `taintRecall`
 * divides by `total`, NOT by `detected` — dividing by detected would report
 * 100% taint recall for a language where taint fired once and regex carried the
 * other nineteen, which is exactly the illusion this instrument exists to break.
 */
export function buildMatrix(rows) {
  const m = {};
  for (const r of rows || []) {
    const lang = r.language || '(unknown)';
    const cell = m[lang] || (m[lang] = { total: 0, detected: 0, byLayer: {}, taintRecall: 0 });
    cell.total++;
    if (r.detected) cell.detected++;
    for (const layer of r.layers || []) {
      cell.byLayer[layer] = (cell.byLayer[layer] || 0) + 1;
    }
  }
  for (const cell of Object.values(m)) {
    cell.taintRecall = cell.total ? (cell.byLayer[LAYER_TAINT] || 0) / cell.total : 0;
  }
  return m;
}

/** Language for an entry: the manifest's own label, else inferred from files. */
const EXT_LANG = {
  '.js': 'js/ts', '.jsx': 'js/ts', '.ts': 'js/ts', '.tsx': 'js/ts', '.mjs': 'js/ts', '.cjs': 'js/ts',
  '.py': 'python', '.php': 'php', '.rb': 'ruby', '.java': 'java', '.go': 'go',
  '.cs': 'c#', '.kt': 'kotlin', '.c': 'c/c++', '.cc': 'c/c++', '.cpp': 'c/c++', '.h': 'c/c++',
};

const MANIFEST_ALIASES = {
  javascript: 'js/ts', typescript: 'js/ts', js: 'js/ts', ts: 'js/ts', node: 'js/ts',
  py: 'python', rb: 'ruby', csharp: 'c#', cs: 'c#', kt: 'kotlin', cpp: 'c/c++', c: 'c/c++',
};

export function languageOf(manifest, files) {
  const declared = String(manifest?.language || '').toLowerCase();
  if (declared) return MANIFEST_ALIASES[declared] || declared;
  const counts = {};
  for (const f of files || []) {
    const dot = f.lastIndexOf('.');
    const lang = dot >= 0 ? EXT_LANG[f.slice(dot).toLowerCase()] : null;
    if (lang) counts[lang] = (counts[lang] || 0) + 1;
  }
  const ranked = Object.entries(counts).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  return ranked.length ? ranked[0][0] : '(unknown)';
}

/**
 * Reduce per-entry rows to the summary shape the corpus baseline and the
 * scorecard both consume: total entries scored, and per-language taint /
 * total counts. Extracted from what `runner.mjs` used to build inline so it
 * can be called twice — once over every row, once over a tier-filtered
 * subset (deep-tier only) — without duplicating the reduction logic.
 *
 * A language present in `totalByLanguage` but absent from `taintByLanguage`
 * means zero taint recall for that language — deliberately not a zero-valued
 * key, so "zero" and "not measured" stay distinguishable downstream.
 */
export function summarize(rows) {
  const taintByLanguage = {};
  const totalByLanguage = {};
  for (const r of rows || []) {
    const lang = r.language || '(unknown)';
    totalByLanguage[lang] = (totalByLanguage[lang] || 0) + 1;
    if ((r.layers || []).includes(LAYER_TAINT)) {
      taintByLanguage[lang] = (taintByLanguage[lang] || 0) + 1;
    }
  }
  return { entriesScored: (rows || []).length, taintByLanguage, totalByLanguage };
}
