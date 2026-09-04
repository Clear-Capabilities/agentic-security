// Shared cross-view selection/filter state, persisted in the URL hash so
// switching views preserves the selected canonical ID and filters (AC-16),
// and so state is shareable/bookmarkable without a server. Per PRD §7.11:
// "URL state contains canonical IDs and non-sensitive filter expressions,
// never source snippets, field values, or secret-bearing endpoints" — this
// module only ever carries canonical IDs and filter keys/values the caller
// supplies, never arbitrary text.
//
// `state.filters` is an opaque, caller-defined object — this module never
// validates individual keys inside it, only that the blob as a whole is
// valid JSON. Milestone 3, sub-project M3-UX-Query adds `filters.query`
// (PRD §15.2's query-language string, a plain string) as one more key
// alongside the pre-existing `dataClass`/`protection`/`ai` keys — it
// round-trips through the hash for free via the same generic JSON
// serialize/parse path below, with no code change needed here beyond this
// note. Validating/parsing the query text itself is `lib/query-language.js`'s
// and `components/query-bar.js`'s job, not this module's — exactly like
// `dataClass`/`protection`/`ai` are validated by their own consumers
// (filter-rail.js, privacy-view.js, inventory-view.js), never here.

const VALID_VIEWS = new Set(['architecture', 'privacy', 'trace', 'inventory']);

// PRD §7.6's own 11 required inventory categories, in the order that
// section lists them. The canonical id list — inventory-view.js's
// per-category compute dispatch and its sub-nav strip both key off this
// exact array, so a rename here must update both call sites too.
export const INVENTORY_TABLES = Object.freeze([
  'sources',
  'sinks',
  'fields',
  'externalDestinations',
  'stores',
  'aiSystems',
  'transformations',
  'unprotectedEdges',
  'policyPermittedFlows',
  'manualGovernanceGaps',
  'unsupportedCandidates',
]);

const DEFAULT_STATE = Object.freeze({ view: 'architecture', selectedId: null, filters: {}, table: INVENTORY_TABLES[0] });

export function parseStateFromHash(hash) {
  const raw = String(hash ?? '').replace(/^#/, '');
  if (!raw) return { ...DEFAULT_STATE, filters: {} };

  let params;
  try {
    params = new URLSearchParams(raw);
  } catch {
    return { ...DEFAULT_STATE, filters: {} };
  }

  const view = params.get('view');
  const selectedId = params.get('selected');
  const filtersRaw = params.get('filters');
  const tableRaw = params.get('table');

  let filters = {};
  if (filtersRaw) {
    try {
      const parsed = JSON.parse(filtersRaw);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) filters = parsed;
    } catch {
      filters = {};
    }
  }

  return {
    view: VALID_VIEWS.has(view) ? view : DEFAULT_STATE.view,
    selectedId: selectedId || null,
    filters,
    table: INVENTORY_TABLES.includes(tableRaw) ? tableRaw : DEFAULT_STATE.table,
  };
}

export function serializeStateToHash(state) {
  const params = new URLSearchParams();
  params.set('view', VALID_VIEWS.has(state.view) ? state.view : DEFAULT_STATE.view);
  if (state.selectedId) params.set('selected', state.selectedId);
  if (state.filters && Object.keys(state.filters).length > 0) params.set('filters', JSON.stringify(state.filters));
  if (state.table && state.table !== DEFAULT_STATE.table) params.set('table', state.table);
  return `#${params.toString()}`;
}
