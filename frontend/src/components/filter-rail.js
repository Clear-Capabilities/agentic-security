import { el, clear } from '../lib/dom.js';

// A fixed enum, not derived from "whatever protectionSummary values happen
// to be present in this fixture" — a filter chip for `unprotected` must
// still exist even on a graph where nothing currently is, so a user can
// confirm that's genuinely true rather than the chip silently not existing.
const PROTECTION_TIERS = Object.freeze(['protected', 'unprotected', 'mixed', 'unknown']);

export function computeFilterFacets(graph) {
  const dataClasses = [...new Set((graph.dataElements ?? []).flatMap((d) => d.dataClasses ?? []))].sort();
  const sourceCategories = [...new Set(graph.nodes.filter((n) => n.kind === 'source').map((n) => n.subtype).filter(Boolean))].sort();
  const sinkCategories = [...new Set(graph.nodes.filter((n) => n.kind === 'sink').map((n) => n.subtype).filter(Boolean))].sort();
  const destinationExternalities = [...new Set(graph.nodes.map((n) => n.externality?.value).filter(Boolean))].sort();
  const transitVerdicts = [...new Set(graph.edges.map((e) => e.protection.transit.verdict))].sort();
  const atRestVerdicts = [...new Set(graph.edges.map((e) => e.protection.atRest.verdict))].sort();
  const handlingVerdicts = [...new Set(graph.edges.map((e) => e.protection.handling.verdict))].sort();
  const policyVerdicts = [...new Set(graph.flows.map((f) => f.policyVerdict))].sort();
  return {
    dataClasses, protectionTiers: PROTECTION_TIERS,
    sourceCategories, sinkCategories, destinationExternalities,
    transitVerdicts, atRestVerdicts, handlingVerdicts, policyVerdicts,
  };
}

/**
 * @param {ReturnType<typeof computeFilterFacets>} facets
 * @param {{dataClass?: string[], protection?: string[], ai?: boolean}} currentFilters
 * @param {HTMLElement} railEl
 * @param {(next: object) => void} onFiltersChange
 */
export function renderFilterRail(facets, currentFilters, railEl, onFiltersChange) {
  clear(railEl);

  const dataClassChips = el(
    'div',
    { class: 'filter-rail-group' },
    [el('h4', {}, 'Data class'), ...facets.dataClasses.map((cls) => renderChip(cls, currentFilters.dataClass?.includes(cls) ?? false, () => toggleListFilter(currentFilters, 'dataClass', cls, onFiltersChange)))],
  );

  const protectionChips = el(
    'div',
    { class: 'filter-rail-group' },
    [el('h4', {}, 'Protection'), ...facets.protectionTiers.map((tier) => renderChip(tier, currentFilters.protection?.includes(tier) ?? false, () => toggleListFilter(currentFilters, 'protection', tier, onFiltersChange)))],
  );

  const aiChip = el(
    'div',
    { class: 'filter-rail-group' },
    [el('h4', {}, 'AI'), renderChip('AI processing', currentFilters.ai === true, () => onFiltersChange({ ...currentFilters, ai: !currentFilters.ai }))],
  );

  railEl.appendChild(el('div', { class: 'filter-rail' }, [dataClassChips, protectionChips, aiChip]));
}

function toggleListFilter(currentFilters, key, value, onFiltersChange) {
  const current = currentFilters[key] ?? [];
  const next = current.includes(value) ? current.filter((v) => v !== value) : [...current, value];
  onFiltersChange({ ...currentFilters, [key]: next });
}

function renderChip(label, active, onClick) {
  return el(
    'button',
    {
      class: 'filter-chip',
      'data-active': String(active),
      'aria-pressed': String(active),
      onClick,
    },
    label,
  );
}
