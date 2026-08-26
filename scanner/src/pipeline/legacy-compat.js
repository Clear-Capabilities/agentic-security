// Legacy field compatibility adapter (assurance-hardening PRD, Milestone 1,
// FR-108: "Publish a compatibility adapter for legacy finding consumers.
// Existing integrations receive a deprecation warning and equivalent legacy
// fields for one documented transition period.")
//
// This codebase's own stated convention (repeated three times across
// CHANGELOG.md: "No breaking changes. All new capabilities are additive")
// means a finding field should almost never be renamed or removed out from
// under an existing consumer. But it can happen for a good reason — this
// same session's FR-804 renamed `riskDollars.confidenceFloor` to
// `confidenceWeight` because the old name was actively misleading (the
// field stopped being a floor once the bug it named was fixed) — and when
// it does, a consumer reading the old field name should not silently start
// getting `undefined`. That rename is the concrete, real case this adapter
// exists for, not a hypothetical one.
//
// LEGACY_FIELD_ALIASES names every known rename. applyLegacyCompat(finding)
// backfills the OLD dotted path from the NEW one's current value whenever
// the new value is present and nothing already occupies the old path — an
// existing integration reading the deprecated name keeps working, unchanged,
// for the documented transition period. legacyFieldDeprecationNotice()
// turns that into the single, honest, report-level notice FR-108 asks for,
// rather than silently reintroducing the old shape forever with no signal
// that it is scheduled for removal.

export const LEGACY_FIELD_ALIASES = Object.freeze([
  Object.freeze({
    oldPath: 'riskDollars.confidenceFloor',
    newPath: 'riskDollars.confidenceWeight',
    deprecatedInVersion: '0.143.0', // FR-804, same session as this adapter
    sunsetAfter: '2027-02-24', // ~6 months from this adapter's introduction
    reason: "renamed because the field stopped being a floor — Math.max(0.4, f.confidence || 0.8)'s unconditional floor and 0-as-falsy inflation were removed as part of FR-804's fix",
  }),
]);

function _getPath(obj, dottedPath) {
  return dottedPath.split('.').reduce((o, k) => (o && typeof o === 'object' ? o[k] : undefined), obj);
}

function _setPath(obj, dottedPath, value) {
  const parts = dottedPath.split('.');
  let o = obj;
  for (let i = 0; i < parts.length - 1; i++) {
    // Only backfill onto a parent object that already exists — if
    // riskDollars itself is null/absent, there is nothing to attach a
    // legacy alias to, and creating a fake `{confidenceFloor: ...}` shell
    // would be actively misleading (it would look like a real annotation
    // that never ran).
    if (o[parts[i]] == null || typeof o[parts[i]] !== 'object') return false;
    o = o[parts[i]];
  }
  o[parts[parts.length - 1]] = value;
  return true;
}

/**
 * Backfill deprecated field names on ONE finding from their current
 * replacements. Mutates the finding in place (matches every other
 * annotator's convention in this codebase). Additive only — never
 * overwrites a value already present at the old path, so a caller that set
 * the legacy field explicitly (e.g. a hand-built test fixture) is never
 * clobbered.
 *
 * @returns {string[]} which legacy field paths were actually backfilled —
 *   empty for the common, eventual steady state where nothing legacy fired.
 */
export function applyLegacyCompat(finding) {
  if (!finding || typeof finding !== 'object') return [];
  const applied = [];
  for (const alias of LEGACY_FIELD_ALIASES) {
    const newValue = _getPath(finding, alias.newPath);
    if (newValue === undefined) continue; // nothing to backfill from
    if (_getPath(finding, alias.oldPath) !== undefined) continue; // already set — don't clobber
    if (_setPath(finding, alias.oldPath, newValue)) applied.push(alias.oldPath);
  }
  if (applied.length) finding._legacyFields = applied;
  return applied;
}

/**
 * A single, report-level deprecation notice summarizing every legacy alias
 * actually used across a finding set. Returns null when none fired.
 */
export function legacyFieldDeprecationNotice(findings) {
  if (!Array.isArray(findings)) return null;
  const used = new Set();
  for (const f of findings) {
    if (Array.isArray(f?._legacyFields)) for (const p of f._legacyFields) used.add(p);
  }
  if (used.size === 0) return null;
  const fields = [...used].sort().map(oldPath => {
    const alias = LEGACY_FIELD_ALIASES.find(a => a.oldPath === oldPath);
    return alias
      ? { oldPath, newPath: alias.newPath, deprecatedInVersion: alias.deprecatedInVersion, sunsetAfter: alias.sunsetAfter, reason: alias.reason }
      : { oldPath, newPath: null, deprecatedInVersion: null, sunsetAfter: null, reason: null };
  });
  return {
    message: 'This report includes deprecated legacy field name(s), backfilled from their current replacements for backward compatibility. Update integrations to read the new field name(s) before the documented sunset date.',
    fields,
  };
}
