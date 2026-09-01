// Shared, deduplicated row-vs-active-filters matcher — was previously two
// near-identical private copies (privacy-view.js's and inventory-view.js's
// own rowMatchesFilters). Every check here reads a PRE-ATTACHED row
// property (never the graph directly) — the caller's own row-computation
// step is responsible for attaching whichever of these properties make
// sense for that row's own shape (see lib/filter-rail.js's own facet list
// and each view's own row-building code). A facet whose property the row
// does not carry AT ALL is skipped (never a hide) — this is what makes it
// safe for a single shared function to serve row shapes as different as a
// Privacy flow-row and an Inventory dataElement-row.
const LIST_FACETS = [
  ['dataClass', 'dataClasses', true], // true = row property is itself an array (dataClasses), match if ANY overlaps
  ['protection', 'protectionSummary', false], // false = row property is a single value, match if included in the filter's list
  ['transitVerdict', 'transitVerdict', false],
  ['atRestVerdict', 'atRestVerdict', false],
  ['handlingVerdict', 'handlingVerdict', false],
  ['sourceCategory', 'sourceCategory', false],
  ['sinkCategory', 'sinkCategory', false],
  ['destinationExternality', 'destinationExternality', false],
  ['policyVerdict', 'policyVerdict', false],
];

export function matchesFilters(row, filters) {
  for (const [filterKey, rowProp, rowIsArray] of LIST_FACETS) {
    const activeValues = filters[filterKey];
    if (!activeValues?.length) continue; // this facet isn't active at all
    if (!(rowProp in row)) continue; // row doesn't carry this property — unaffected, not hidden
    if (rowIsArray) {
      if (!(row[rowProp] ?? []).some((v) => activeValues.includes(v))) return false;
    } else {
      if (row[rowProp] !== undefined && !activeValues.includes(row[rowProp])) return false;
    }
  }
  // Unlike the 9 facets above (list-of-selected-values), `ai` is a single
  // boolean toggle, matching its existing shape in both views — kept as
  // its own explicit check, not folded into LIST_FACETS's generic loop,
  // since it's structurally different (a boolean flag, not a multi-select).
  // Checked for ANY row carrying `isAiRelevant` — this is the real fix for
  // Inventory's own previously-missing AI check (its private
  // rowMatchesFilters never checked `ai` at all; Privacy's did).
  if (filters.ai && 'isAiRelevant' in row && !row.isAiRelevant) return false;
  return true;
}
