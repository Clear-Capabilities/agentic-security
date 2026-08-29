// Shared cross-view selection/filter state, persisted in the URL hash so
// switching views preserves the selected canonical ID and filters (AC-16),
// and so state is shareable/bookmarkable without a server. Per PRD §7.11:
// "URL state contains canonical IDs and non-sensitive filter expressions,
// never source snippets, field values, or secret-bearing endpoints" — this
// module only ever carries canonical IDs and filter keys/values the caller
// supplies, never arbitrary text.

const VALID_VIEWS = new Set(['architecture', 'privacy', 'trace']);
const DEFAULT_STATE = Object.freeze({ view: 'architecture', selectedId: null, filters: {} });

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
  };
}

export function serializeStateToHash(state) {
  const params = new URLSearchParams();
  params.set('view', VALID_VIEWS.has(state.view) ? state.view : DEFAULT_STATE.view);
  if (state.selectedId) params.set('selected', state.selectedId);
  if (state.filters && Object.keys(state.filters).length > 0) params.set('filters', JSON.stringify(state.filters));
  return `#${params.toString()}`;
}
