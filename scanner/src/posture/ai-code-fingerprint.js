// FR-LEARN-10 — AI-generated-code fingerprinting.
//
// Heuristic detection of code regions likely written by an AI assistant
// (Claude, GPT, Copilot). The goal is NOT forensics — it is RISK ROUTING.
// AI-generated code disproportionately reproduces training-set patterns,
// which include known-vulnerable Stack Overflow idioms. Tagging regions
// `ai-likely` lets downstream rule packs raise scrutiny for those regions
// without ham-fisting the whole codebase.
//
// Signal sources (each contributes a weighted score; the composite is a
// 0..1 score with three tier bands: `ai-likely` >= 0.55, `mixed` >= 0.30,
// `human-likely` otherwise):
//
//   1. Comment-to-code ratio above ~0.3 (AI over-comments boilerplate).
//   2. Exhaustive null-checking on every parameter ("if (!x) return;").
//   3. Variable names like `result`, `data`, `temp`, `helper`, `utility`.
//   4. Try/catch wrapping every operation that could possibly fail.
//   5. JSDoc-like `@param` blocks on every function in a JS file (no TS).
//   6. Identical structural patterns across nearby functions (boilerplate).
//   7. Presence of an `as const` assertion (TS) or `typing.Final` (Py) on
//      every constant — AI loves redundant type narrowing.
//   8. Comments in the imperative "We do X then Y" register.
//
// Hallucinated imports are scored separately — see annotateHallucinatedImports.

const AI_VARIABLE_NAMES = new Set([
  'result', 'data', 'temp', 'helper', 'utility', 'value', 'item', 'output',
  'response', 'processedData', 'finalResult', 'resultData',
]);

const AI_COMMENT_PATTERNS = [
  /^\s*\/\/\s*We (?:do|then|finally|next|now|here|will)\b/i,
  /^\s*\/\/\s*This (?:function|method|helper|utility) (?:will|does|is responsible)/i,
  /^\s*\/\/\s*Note(?:\s+that)?:?\s/i,
  /^\s*\/\/\s*Important:?\s/i,
  /^\s*\/\/\s*(?:Step|Stage|Phase)\s+\d/i,
];

function scoreCommentRatio(text) {
  const lines = text.split(/\n/);
  let code = 0, comment = 0;
  for (const ln of lines) {
    const t = ln.trim();
    if (!t) continue;
    if (t.startsWith('//') || t.startsWith('#') || t.startsWith('*')) comment++;
    else code++;
  }
  if (code === 0) return 0;
  const ratio = comment / code;
  if (ratio > 0.5) return 0.30;
  if (ratio > 0.30) return 0.18;
  if (ratio > 0.20) return 0.08;
  return 0;
}

function scoreVariableNames(text) {
  const ids = text.match(/\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)/g) || [];
  if (ids.length < 3) return 0;
  let hits = 0;
  for (const id of ids) {
    const name = id.replace(/^\s*(?:const|let|var)\s+/, '');
    if (AI_VARIABLE_NAMES.has(name)) hits++;
  }
  const ratio = hits / ids.length;
  if (ratio > 0.4) return 0.20;
  if (ratio > 0.25) return 0.10;
  if (ratio > 0.10) return 0.04;
  return 0;
}

function scoreNullChecks(text) {
  const fns = text.match(/function\s+\w+\s*\([^)]+\)\s*\{|=>\s*\{/g) || [];
  const guards = text.match(/if\s*\(\s*!\s*[A-Za-z_$][\w$]*\s*\)\s*(?:return|throw)/g) || [];
  if (fns.length === 0) return 0;
  const ratio = guards.length / fns.length;
  if (ratio > 0.8) return 0.18;
  if (ratio > 0.5) return 0.10;
  return 0;
}

function scoreAiComments(text) {
  const lines = text.split(/\n/);
  let hits = 0;
  for (const ln of lines) {
    if (AI_COMMENT_PATTERNS.some(re => re.test(ln))) hits++;
  }
  if (hits >= 5) return 0.22;
  if (hits >= 2) return 0.12;
  if (hits >= 1) return 0.04;
  return 0;
}

function scoreTryCatch(text) {
  const fns = (text.match(/function\s+\w+|=>/g) || []).length;
  const tries = (text.match(/\btry\s*\{/g) || []).length;
  if (fns === 0) return 0;
  const ratio = tries / fns;
  if (ratio > 0.6) return 0.10;
  if (ratio > 0.3) return 0.04;
  return 0;
}

export function fingerprintFile(text) {
  if (!text || typeof text !== 'string' || text.length < 100) {
    return { score: 0, provenance: 'unknown', signals: [] };
  }
  const signals = [];
  let total = 0;
  const checks = [
    ['comment-ratio', scoreCommentRatio],
    ['boilerplate-var-names', scoreVariableNames],
    ['exhaustive-null-checks', scoreNullChecks],
    ['ai-style-comments', scoreAiComments],
    ['try-catch-everywhere', scoreTryCatch],
  ];
  for (const [name, fn] of checks) {
    const s = fn(text);
    if (s > 0) { signals.push({ name, score: Number(s.toFixed(2)) }); total += s; }
  }
  const score = Math.min(1, total);
  let provenance = 'human-likely';
  if (score >= 0.55) provenance = 'ai-likely';
  else if (score >= 0.30) provenance = 'mixed';
  return { score: Number(score.toFixed(2)), provenance, signals };
}

// Annotate every finding with the host-file provenance tag. Allows downstream
// scoring to raise/lower confidence based on origin.
export function annotateAiProvenance(findings, fileContents) {
  if (!Array.isArray(findings) || !fileContents) return findings;
  const cache = new Map();
  for (const f of findings) {
    if (!f || typeof f !== 'object') continue;
    const fp = f.file;
    if (!fp || !fileContents[fp]) continue;
    let fp_res = cache.get(fp);
    if (!fp_res) { fp_res = fingerprintFile(fileContents[fp]); cache.set(fp, fp_res); }
    f.provenance = fp_res.provenance;
    f.provenanceScore = fp_res.score;
    f.provenanceSignals = fp_res.signals;
  }
  return findings;
}

// Hallucinated-import detection — packages an AI invented that aren't on the
// public registry. This is a coordinator hook: the SCA pipeline already has
// the dep list and a registry probe; we surface the candidate names from
// import statements for downstream verification.
export function extractImportedPackageNames(text) {
  if (!text || typeof text !== 'string') return [];
  const names = new Set();
  for (const m of text.matchAll(/(?:^|\n)\s*import\s+(?:[\w*${},\s]+\s+from\s+)?["']([^"']+)["']/g)) {
    const spec = m[1];
    if (spec.startsWith('.') || spec.startsWith('/')) continue;
    if (spec.startsWith('node:') || spec.startsWith('bun:')) continue;
    const pkg = spec.startsWith('@')
      ? spec.split('/').slice(0, 2).join('/')
      : spec.split('/')[0];
    names.add(pkg);
  }
  for (const m of text.matchAll(/require\(\s*["']([^"']+)["']\s*\)/g)) {
    const spec = m[1];
    if (spec.startsWith('.') || spec.startsWith('/')) continue;
    if (spec.startsWith('node:')) continue;
    const pkg = spec.startsWith('@')
      ? spec.split('/').slice(0, 2).join('/')
      : spec.split('/')[0];
    names.add(pkg);
  }
  return [...names];
}
