// The single source of truth for how a protection verdict renders — every
// view/component must call protectionVisual() rather than hardcoding a
// color or glyph, so AC-20 (verdicts distinguishable without color) holds
// everywhere by construction, not by convention.
//
// These verdict strings are NOT imported from scanner/src/lineage/protection.js
// — the browser bundle never imports anything under scanner/src/lineage/ at
// runtime (see frontend/CLAUDE.md). Keep this list in sync by hand if the
// backend's PROTECTION_VERDICTS/FLOW_SUMMARY_VALUES enums ever change.

// PRD §8.4, exact quoted precedence: "unprotected/prohibited → mixed →
// unknown/manual_required → protected/permitted → not_assessed". Read as
// display priority when aggregating multiple verdicts into one, not a raw
// severity order: not_assessed is LOWEST priority because it means "no
// information," and any real signal (even a protected one) should be shown
// instead of "not assessed." not_applicable isn't named in the PRD list;
// treated at the same lowest priority as not_assessed (both mean "nothing
// to prioritize").
export const VERDICT_PRECEDENCE = Object.freeze([
  'unprotected',
  'mixed',
  'unknown',
  'protected',
  'not_assessed',
  'not_applicable',
]);

const VISUALS = Object.freeze({
  protected: { verdict: 'protected', label: 'Protected', glyph: '✓', lineStyle: 'solid', colorVar: '--status-protected' },
  unprotected: { verdict: 'unprotected', label: 'Unprotected', glyph: '✗', lineStyle: 'solid', colorVar: '--status-unprotected' },
  mixed: { verdict: 'mixed', label: 'Mixed', glyph: '±', lineStyle: 'solid', colorVar: '--status-unprotected' },
  unknown: { verdict: 'unknown', label: 'Unknown', glyph: '?', lineStyle: 'dashed', colorVar: '--status-unknown' },
  not_applicable: { verdict: 'not_applicable', label: 'Not applicable', glyph: '·', lineStyle: 'dotted', colorVar: '--text-secondary' },
  not_assessed: { verdict: 'not_assessed', label: 'Not assessed', glyph: '–', lineStyle: 'dotted', colorVar: '--status-unknown' },
});

export function protectionVisual(verdict) {
  return VISUALS[verdict] ?? VISUALS.not_assessed;
}

export function worstVerdict(verdicts) {
  for (const tier of VERDICT_PRECEDENCE) {
    if (verdicts.includes(tier)) return tier;
  }
  return 'not_assessed';
}
