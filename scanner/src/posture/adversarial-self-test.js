// FR-LEARN-8 — Adversarial self-test (mutation harness).
//
// Generate adversarial source-code variants from known-vuln fixtures and
// re-scan them. Variants that the scanner FAILS to detect (false negatives)
// are surfaced as `rule-gap` records for review and prioritization in the
// next rule-pack release. Variants that the scanner still catches confirm
// robustness.
//
// This module exposes:
//   mutateSnippet(code, family)  — produces 1..N adversarial variants of `code`
//                                  intended to defeat the family's detector
//   buildMutationCorpus(fixtures) — applies mutations across the fixture set
//
// It does NOT run the scanner itself — that's a CLI / bench-runner concern.
// The orchestrator is `scripts/run-self-test.mjs` (created separately).
//
// Mutation strategies per family:
//   sql-injection:
//     - rename `query` → `q`, `db` → `client` (identifier obfuscation)
//     - wrap concat in `String(x)` or `${x}` (template-literal obfuscation)
//     - reorder: build the string in a helper that returns it
//   command-injection:
//     - swap `exec` → `execSync` → `spawn` (variant API surface)
//     - introduce a no-op `sanitize(x)` that doesn't sanitize
//   xss:
//     - swap `innerHTML` for `outerHTML`, `insertAdjacentHTML`, `document.write`
//   path-traversal:
//     - introduce a noop `path.normalize` (allowed under the regex but still
//       traversable when input is `..%2F` style)
//   ssrf:
//     - swap `fetch` for `axios`, `got`, `node-fetch`
//   prototype-pollution:
//     - swap `__proto__` for `["__proto__"]`, then for `["__pro" + "to__"]`

const STRATEGIES = {
  'sql-injection': [
    (code) => code.replace(/\bquery\b/g, 'q').replace(/\bdb\b/g, 'client'),
    (code) => code.replace(/'.*?\+.*?'/g, (m) => '`' + m.replace(/'/g, '') + '`'),
    (code) => 'function buildQ(x) { return ' + JSON.stringify(code) + '; } buildQ(userInput);',
  ],
  'command-injection': [
    (code) => code.replace(/\bexec\b/g, 'execSync'),
    (code) => code.replace(/\bexec\b/g, 'spawn'),
    (code) => `function sanitize(x) { return x; }\n${code.replace(/exec\(([^)]+)\)/, 'exec(sanitize($1))')}`,
  ],
  'xss': [
    (code) => code.replace(/\.innerHTML\s*=/g, '.outerHTML ='),
    (code) => code.replace(/\.innerHTML\s*=\s*(\w+)/, '.insertAdjacentHTML("beforeend", $1)'),
    (code) => code.replace(/\.innerHTML\s*=\s*(\w+)/, 'document.write($1)'),
  ],
  'path-traversal': [
    (code) => `const path = require('path');\n${code.replace(/readFile\(/, 'readFile(path.normalize(')}`,
  ],
  'ssrf': [
    (code) => code.replace(/\bfetch\b/g, 'axios.get'),
    (code) => code.replace(/\bfetch\b/g, 'require("got")'),
    (code) => code.replace(/\bfetch\b/g, 'require("node-fetch")'),
  ],
  'prototype-pollution': [
    (code) => code.replace(/__proto__/g, '["__proto__"]'),
    (code) => code.replace(/__proto__/g, '["__pro" + "to__"]'),
  ],
  'webhook-no-signature': [
    (code) => `${code}\nfunction verify(){ return true; }`,
  ],
};

export function mutateSnippet(code, family) {
  if (!code || typeof code !== 'string') return [];
  const strategies = STRATEGIES[family] || [];
  const variants = [];
  for (const fn of strategies) {
    try {
      const v = fn(code);
      if (v && v !== code) variants.push(v);
    } catch {}
  }
  return variants;
}

// Build a mutation corpus from a fixture record { id, family, code }.
// Returns array of { fixtureId, family, originalCode, mutations: [{ strategy, code }] }.
export function buildMutationCorpus(fixtures) {
  if (!Array.isArray(fixtures)) return [];
  const out = [];
  for (const fx of fixtures) {
    if (!fx || !fx.family || !fx.code) continue;
    const muts = mutateSnippet(fx.code, fx.family);
    out.push({
      fixtureId: fx.id || `${fx.family}-${fx.file || 'inline'}`,
      family: fx.family,
      originalCode: fx.code,
      mutations: muts.map((c, i) => ({ strategy: `mut-${i + 1}`, code: c })),
    });
  }
  return out;
}

// Format a self-test report given a list of mutation runs and detector hits.
// Each run: { fixtureId, family, mutation, detectedByScanner }. The report
// lists ungapped strategies (still detected) and gaps (missed mutations).
export function summarizeSelfTest(runs) {
  if (!Array.isArray(runs)) return { gaps: [], confirmed: [], totalRuns: 0 };
  const gaps = runs.filter(r => r.detectedByScanner === false).map(r => ({
    family: r.family,
    fixtureId: r.fixtureId,
    strategy: r.mutation?.strategy,
    suggestion: `Add a fixture pair in scanner/test/fixtures/ that captures this mutation, then strengthen the ${r.family} detector to match.`,
  }));
  const confirmed = runs.filter(r => r.detectedByScanner === true).map(r => ({
    family: r.family, fixtureId: r.fixtureId, strategy: r.mutation?.strategy,
  }));
  return { gaps, confirmed, totalRuns: runs.length };
}
