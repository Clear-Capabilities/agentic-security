// Query bar: PRD §15.2's query-language DSL, wired into a real text input
// plus two saved-view chips. Split the same way every other component/view
// in this repo is: a pure compute function and a thin DOM-building render
// function.
//
// `computeQueryBarViewModel` is deliberately SYNTAX-only (it calls
// `parseQuery`, never `compileQuery`) — it operates on `state` alone, no
// graph, matching the exact signature this task's own brief specifies. A
// query can still fail at EVALUATION time even after parsing cleanly (an
// unrecognized field name — see query-language.js's own `compileQuery`
// comment), which needs a real graph to detect. `compileQuerySafely` below
// is the graph-aware superset app.js actually uses to build a safe-to-call
// predicate; `computeQueryBarViewModel` stays graph-free so it can be
// unit-tested in total isolation, per the brief's own contract.

import { parseQuery, compileQuery } from '../lib/query-language.js';
import { el, clear } from '../lib/dom.js';

// The two saved-view query strings this sub-project's own task brief names,
// spot-checked against the real flagship fixture (frontend/src/data/
// flagship-graph.js) before finalizing: `class:PCI` matches 5 of 8 real
// flows, `class:(PII,PHI) AND ai:true` matches 1 of 8 — both non-empty and
// sensible (a broad PCI-exposure view vs. a narrow AI+regulated-data
// intersection), so neither needed adjustment from the brief's own text.
export const SAVED_VIEWS = Object.freeze([
  Object.freeze({ label: 'PCI Exposure', query: 'class:PCI' }),
  Object.freeze({ label: 'AI + Regulated Data', query: 'class:(PII,PHI) AND ai:true' }),
]);

/**
 * @param {{filters?: {query?: string}}} state
 * @returns {{queryText: string, error: {message: string, pos: number} | null}}
 */
export function computeQueryBarViewModel(state) {
  const queryText = state.filters?.query ?? '';
  const { error } = parseQuery(queryText);
  return { queryText, error: error ?? null };
}

/**
 * Compiles a query string end-to-end against a real graph: parse, compile,
 * and a trial evaluation against every real flow in `graph` — so a caller
 * gets EITHER a real, safe-to-call predicate OR a structured error, never a
 * predicate that might throw partway through filtering some rows and not
 * others. A malformed query (a syntax error, OR an unrecognized field name,
 * which only throws at EVALUATION time — see query-language.js's own
 * compileQuery comment) never narrows the active filter: on error this
 * returns a pass-through predicate (`() => true`, matching every flow), so
 * views render exactly as if no query were active rather than silently
 * hiding all/some rows.
 *
 * @param {object} graph
 * @param {string} queryText
 * @returns {{predicate: (flow: object) => boolean, error: {message: string, pos: number|null} | null}}
 */
export function compileQuerySafely(graph, queryText) {
  const { ast, error } = parseQuery(queryText ?? '');
  if (error) return { predicate: () => true, error };
  try {
    const predicate = compileQuery(ast, graph);
    for (const flow of graph.flows) predicate(flow);
    return { predicate, error: null };
  } catch (err) {
    return { predicate: () => true, error: { message: err && err.message ? err.message : String(err), pos: null } };
  }
}

function renderError(errorEl, error) {
  errorEl.textContent = error ? `Query error: ${error.message}${typeof error.pos === 'number' ? ` (position ${error.pos})` : ''}` : '';
  errorEl.setAttribute('data-visible', String(Boolean(error)));
}

/**
 * @param {ReturnType<typeof computeQueryBarViewModel>} viewModel
 * @param {HTMLElement} railEl
 * @param {(nextQuery: string) => void} onQueryChange - called ONLY with a
 *   query that parses cleanly. On a parse error the input's own displayed
 *   value still updates (so the user can see/fix what they typed) but this
 *   is never invoked with the broken text — the caller's active filter
 *   never changes on a malformed query.
 */
export function renderQueryBar(viewModel, railEl, onQueryChange) {
  clear(railEl);

  const errorEl = el('div', { class: 'query-bar__error' }, '');

  const input = el('input', {
    type: 'text',
    class: 'query-bar__input',
    value: viewModel.queryText,
    placeholder: 'e.g. class:PCI AND ai:true',
    'aria-label': 'Query',
    onInput: () => {
      const text = input.value;
      const { error } = parseQuery(text);
      renderError(errorEl, error ?? null);
      if (!error) onQueryChange(text);
    },
  });
  renderError(errorEl, viewModel.error);
  input.setAttribute('aria-invalid', String(Boolean(viewModel.error)));

  const chips = el(
    'div',
    { class: 'query-bar__saved-views' },
    SAVED_VIEWS.map((view) =>
      el(
        'button',
        {
          class: 'query-bar__saved-view-chip',
          type: 'button',
          'data-query': view.query,
          onClick: () => {
            input.value = view.query;
            input.setAttribute('value', view.query);
            renderError(errorEl, null);
            onQueryChange(view.query);
          },
        },
        view.label,
      ),
    ),
  );

  railEl.appendChild(el('div', { class: 'query-bar' }, [input, errorEl, chips]));
}
