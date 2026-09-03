// language-coverage-tiers.js — Milestone 5, language coverage-tier
// disclosure. A small, curated, static table answering "how much can this
// codebase's Data Flow Explorer actually see for language X today" —
// PRD §22.1's own explicitly-sanctioned alternative to claiming a language
// is fully "supported" before it clears §22.3's 85% field-to-sink-recall
// bar (as of docs/METRICS.md, measured 2026-08-19, NONE of the 9
// lineage-wired languages do — best is python at 66%).
//
// Every number here is copied VERBATIM from docs/METRICS.md's own
// currently-committed table (bench/layer-recall's IR-TAINT column — the
// closest existing proxy for the PRD's own field-to-sink recall definition,
// not a byte-identical measurement of it). This module does not re-measure
// anything; re-run bench/layer-recall and update BOTH docs/METRICS.md and
// this table together if the numbers ever change, or this file goes stale
// silently. Zero imports — a pure, static data module, mirroring
// flow-grade.js's own "zero imports" precedent for a self-contained
// vocabulary/data table.
//
// The 9 keys below are languageForFile's own normalized vocabulary
// (coverage.js) — js/python/java/csharp/kotlin/go/php/ruby/cpp — the exact
// languages with real IR-to-lineage wiring today. The 4 pattern-only keys
// (rust/solidity/swift/dart) have ZERO lineage/taint wiring: they exist
// only as tree-sitter grammar loads feeding sast/tree-sitter-sinks.js's
// pattern matching, never scanner/src/lineage/ or scanner/src/dataflow/ —
// confirmed by the M5 top-level scoping doc's own investigation. No
// lineage engine ever runs against them, so they carry no recall number at
// all (irTaintRecallPct: null) — never a fabricated 0%, which would read
// as "measured and found to be zero" rather than "never measured, because
// nothing here can produce a lineage finding for this language yet."

export const LANGUAGE_COVERAGE_TIERS = Object.freeze([
  Object.freeze({ language: 'python', tier: 'partial', irTaintRecallPct: 66, measuredAt: '2026-08-19', source: 'docs/METRICS.md' }),
  Object.freeze({ language: 'go', tier: 'partial', irTaintRecallPct: 59, measuredAt: '2026-08-19', source: 'docs/METRICS.md' }),
  Object.freeze({ language: 'js', tier: 'partial', irTaintRecallPct: 58, measuredAt: '2026-08-19', source: 'docs/METRICS.md' }),
  Object.freeze({ language: 'csharp', tier: 'partial', irTaintRecallPct: 57, measuredAt: '2026-08-19', source: 'docs/METRICS.md' }),
  Object.freeze({ language: 'ruby', tier: 'partial', irTaintRecallPct: 55, measuredAt: '2026-08-19', source: 'docs/METRICS.md' }),
  Object.freeze({ language: 'java', tier: 'partial', irTaintRecallPct: 52, measuredAt: '2026-08-19', source: 'docs/METRICS.md' }),
  Object.freeze({ language: 'php', tier: 'partial', irTaintRecallPct: 52, measuredAt: '2026-08-19', source: 'docs/METRICS.md' }),
  Object.freeze({ language: 'kotlin', tier: 'partial', irTaintRecallPct: 48, measuredAt: '2026-08-19', source: 'docs/METRICS.md' }),
  Object.freeze({ language: 'cpp', tier: 'partial', irTaintRecallPct: 18, measuredAt: '2026-08-19', source: 'docs/METRICS.md' }),
  Object.freeze({ language: 'rust', tier: 'pattern-only', irTaintRecallPct: null, measuredAt: null, source: null }),
  Object.freeze({ language: 'solidity', tier: 'pattern-only', irTaintRecallPct: null, measuredAt: null, source: null }),
  Object.freeze({ language: 'swift', tier: 'pattern-only', irTaintRecallPct: null, measuredAt: null, source: null }),
  Object.freeze({ language: 'dart', tier: 'pattern-only', irTaintRecallPct: null, measuredAt: null, source: null }),
]);

const _byLanguage = new Map(LANGUAGE_COVERAGE_TIERS.map((e) => [e.language, e]));

/**
 * `coverageTierForLanguage(language) -> entry | null`. Never fabricates —
 * returns `null` for any language string not in the curated table above
 * (including coverage.js's own `'unknown'` fallback), so a caller must
 * decide its own honest default (coverage.js's ledger uses `'unknown'`).
 */
export function coverageTierForLanguage(language) {
  if (typeof language !== 'string' || language.length === 0) return null;
  return _byLanguage.get(language) ?? null;
}
