import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createDomShim } from './dom-shim.js';
import { FLAGSHIP_GRAPH } from '../src/data/flagship-graph.js';
import { computeQueryBarViewModel, renderQueryBar, compileQuerySafely, SAVED_VIEWS } from '../src/components/query-bar.js';
import { parseQuery, compileQuery } from '../src/lib/query-language.js';

function findByTag(root, tag, predicate = () => true) {
  let found = null;
  const walk = (node) => {
    for (const child of node.childNodes) {
      if (child.nodeType === 'element') {
        if (child.tagName === tag && predicate(child)) found = found ?? child;
        walk(child);
      }
    }
  };
  walk(root);
  return found;
}

// --- computeQueryBarViewModel (pure, syntax-only) ---

test('computeQueryBarViewModel: empty query has no error', () => {
  const vm = computeQueryBarViewModel({ filters: {} });
  assert.equal(vm.queryText, '');
  assert.equal(vm.error, null);
});

test('computeQueryBarViewModel: a valid query has no error', () => {
  const vm = computeQueryBarViewModel({ filters: { query: 'class:PCI' } });
  assert.equal(vm.queryText, 'class:PCI');
  assert.equal(vm.error, null);
});

test('computeQueryBarViewModel: a syntactically malformed query surfaces a structured error, not a throw', () => {
  const vm = computeQueryBarViewModel({ filters: { query: 'class:' } });
  assert.equal(vm.queryText, 'class:');
  assert.ok(vm.error, 'expected a structured error for an incomplete comparison');
  assert.equal(typeof vm.error.message, 'string');
  assert.equal(typeof vm.error.pos, 'number');
});

// --- SAVED_VIEWS, spot-checked against the real fixture ---

test('SAVED_VIEWS: both named saved views produce non-empty, sensible match counts against the real flagship fixture', () => {
  for (const view of SAVED_VIEWS) {
    const { ast, error } = parseQuery(view.query);
    assert.equal(error, undefined, `saved view "${view.label}"'s query "${view.query}" must parse cleanly`);
    const predicate = compileQuery(ast, FLAGSHIP_GRAPH);
    const matchCount = FLAGSHIP_GRAPH.flows.filter((f) => predicate(f)).length;
    assert.ok(matchCount > 0, `saved view "${view.label}" matched zero flows against the real fixture`);
    assert.ok(matchCount < FLAGSHIP_GRAPH.flows.length, `saved view "${view.label}" matched every flow — not a meaningful narrowing`);
  }
});

// --- compileQuerySafely (graph-aware, used by app.js) ---

test('compileQuerySafely: a valid query returns a real predicate that narrows the real fixture', () => {
  const { predicate, error } = compileQuerySafely(FLAGSHIP_GRAPH, 'class:PCI');
  assert.equal(error, null);
  const matches = FLAGSHIP_GRAPH.flows.filter((f) => predicate(f));
  assert.ok(matches.length > 0 && matches.length < FLAGSHIP_GRAPH.flows.length);
});

test('compileQuerySafely: an empty query string returns a pass-through predicate matching every flow', () => {
  const { predicate, error } = compileQuerySafely(FLAGSHIP_GRAPH, '');
  assert.equal(error, null);
  assert.ok(FLAGSHIP_GRAPH.flows.every((f) => predicate(f)));
});

test('compileQuerySafely: a syntax error returns a pass-through predicate plus a structured error, never throws', () => {
  const { predicate, error } = compileQuerySafely(FLAGSHIP_GRAPH, 'class:');
  assert.ok(error);
  assert.ok(FLAGSHIP_GRAPH.flows.every((f) => predicate(f)), 'a malformed query must never narrow — every flow should still match');
});

test('compileQuerySafely: an unrecognized field name (a semantic error, not a syntax error) is caught, not thrown, and also falls back to pass-through', () => {
  assert.doesNotThrow(() => compileQuerySafely(FLAGSHIP_GRAPH, 'not_a_real_field:foo'));
  const { predicate, error } = compileQuerySafely(FLAGSHIP_GRAPH, 'not_a_real_field:foo');
  assert.ok(error, 'expected a structured error for an unrecognized field name');
  assert.ok(FLAGSHIP_GRAPH.flows.every((f) => predicate(f)), 'a semantically invalid query must never narrow — every flow should still match');
});

// --- renderQueryBar (render-level) ---

test('renderQueryBar: renders the current query text and saved-view chips', () => {
  const { document } = createDomShim();
  globalThis.document = document;

  const railEl = document.createElement('div');
  renderQueryBar({ queryText: 'class:PCI', error: null }, railEl, () => {});

  const input = findByTag(railEl, 'INPUT');
  assert.ok(input);
  assert.equal(input.getAttribute('value'), 'class:PCI');

  const chipLabels = [];
  const walk = (node) => {
    for (const child of node.childNodes) {
      if (child.nodeType === 'element') {
        if (child.tagName === 'BUTTON') chipLabels.push(child.textContent);
        walk(child);
      }
    }
  };
  walk(railEl);
  assert.deepEqual(chipLabels, SAVED_VIEWS.map((v) => v.label));
});

test('renderQueryBar: an initial parse error is displayed in the error area', () => {
  const { document } = createDomShim();
  globalThis.document = document;

  const railEl = document.createElement('div');
  renderQueryBar({ queryText: 'class:', error: { message: 'expected a value', pos: 6 } }, railEl, () => {});

  const errorEl = findByTag(railEl, 'DIV', (n) => n.getAttribute('data-visible') !== null);
  assert.ok(errorEl);
  assert.equal(errorEl.getAttribute('data-visible'), 'true');
  assert.match(errorEl.textContent, /expected a value/);
});

test('renderQueryBar: typing a MALFORMED query updates the input display but NEVER calls onQueryChange — the active filter must never change on a bad query', () => {
  const { document } = createDomShim();
  globalThis.document = document;

  const railEl = document.createElement('div');
  const calls = [];
  renderQueryBar({ queryText: '', error: null }, railEl, (q) => calls.push(q));

  const input = findByTag(railEl, 'INPUT');
  input.value = 'class:'; // simulates the user having typed an incomplete comparison
  input.dispatch('input', { target: input });

  assert.equal(calls.length, 0, 'onQueryChange must never be called with a query that fails to parse');
  const errorEl = findByTag(railEl, 'DIV', (n) => n.getAttribute('data-visible') !== null);
  assert.equal(errorEl.getAttribute('data-visible'), 'true', 'the error area should now show the parse error even though onQueryChange was not called');
});

test('renderQueryBar: typing a VALID query updates the input and calls onQueryChange exactly once with the typed text', () => {
  const { document } = createDomShim();
  globalThis.document = document;

  const railEl = document.createElement('div');
  const calls = [];
  renderQueryBar({ queryText: '', error: null }, railEl, (q) => calls.push(q));

  const input = findByTag(railEl, 'INPUT');
  input.value = 'class:PCI';
  input.dispatch('input', { target: input });

  assert.deepEqual(calls, ['class:PCI']);
});

test('renderQueryBar: clicking a saved-view chip calls onQueryChange with that chip\'s exact query text', () => {
  const { document } = createDomShim();
  globalThis.document = document;

  const railEl = document.createElement('div');
  const calls = [];
  renderQueryBar({ queryText: '', error: null }, railEl, (q) => calls.push(q));

  const pciChip = findByTag(railEl, 'BUTTON', (n) => n.textContent === 'PCI Exposure');
  assert.ok(pciChip, 'expected a rendered "PCI Exposure" saved-view chip');
  pciChip.dispatch('click');

  assert.deepEqual(calls, ['class:PCI']);

  const aiChip = findByTag(railEl, 'BUTTON', (n) => n.textContent === 'AI + Regulated Data');
  assert.ok(aiChip, 'expected a rendered "AI + Regulated Data" saved-view chip');
  aiChip.dispatch('click');

  assert.deepEqual(calls, ['class:PCI', 'class:(PII,PHI) AND ai:true']);
});
