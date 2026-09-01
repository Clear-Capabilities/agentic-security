// Tests for mountShell()'s external state contract (AC-16): getState,
// setSelection, setFilters, onStateChange, destroy, and that existing
// view-tab-click / hash-sync behavior still works. Uses the same
// dependency-free document/window shim as dom.test.js (test/dom-shim.js)
// since shell.js needs real `document`/`window` globals and this repo has
// no jsdom.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createDomShim } from './dom-shim.js';

const { document, window } = createDomShim();
globalThis.document = document;
globalThis.window = window;

const { mountShell } = await import('../src/shell.js');

function makeGraph(overrides = {}) {
  return {
    scope: { repository: 'test-repo', environment: 'test-env', source: 'fixture' },
    scanHealth: { status: 'ok' },
    coverage: { status: 'partial' },
    nodes: [{}, {}],
    edges: [{}],
    flows: [{}],
    ...overrides,
  };
}

function hashParams() {
  return new URLSearchParams(String(window.location.hash).replace(/^#/, ''));
}

test('setSelection updates getState().selectedId and the URL hash', () => {
  window.location.hash = '';
  const root = document.createElement('div');
  const shell = mountShell(root, makeGraph());

  shell.setSelection('node:abc');

  assert.equal(shell.getState().selectedId, 'node:abc');
  assert.equal(hashParams().get('selected'), 'node:abc');

  shell.destroy();
});

test('setFilters updates getState().filters and the URL hash', () => {
  window.location.hash = '';
  const root = document.createElement('div');
  const shell = mountShell(root, makeGraph());

  shell.setFilters({ class: ['PCI'] });

  assert.deepEqual(shell.getState().filters, { class: ['PCI'] });
  assert.deepEqual(JSON.parse(hashParams().get('filters')), { class: ['PCI'] });

  shell.destroy();
});

test('onStateChange fires with the new state on setSelection, setFilters, and setActiveView, and the unsubscribe function stops it', () => {
  window.location.hash = '';
  const root = document.createElement('div');
  const shell = mountShell(root, makeGraph());
  const seen = [];
  const unsubscribe = shell.onStateChange((state) => seen.push(state));

  shell.setSelection('node:1');
  shell.setFilters({ class: ['PHI'] });
  shell.setActiveView('trace');

  assert.equal(seen.length, 3);
  assert.equal(seen[0].selectedId, 'node:1');
  assert.deepEqual(seen[1].filters, { class: ['PHI'] });
  assert.equal(seen[2].view, 'trace');

  unsubscribe();
  shell.setSelection('node:2');
  assert.equal(seen.length, 3, 'listener must not fire again once unsubscribed');

  shell.destroy();
});

test('destroy() removes exactly the hashchange listener mountShell registered, and a post-destroy hashchange notifies nothing and does not change state', () => {
  window.location.hash = '';
  const before = window.hashListenerCount;
  const root = document.createElement('div');
  const shell = mountShell(root, makeGraph());

  assert.equal(window.hashListenerCount, before + 1, 'mountShell should register exactly one new hashchange listener');

  const seen = [];
  shell.onStateChange((state) => seen.push(state));

  shell.destroy();
  assert.equal(window.hashListenerCount, before, "destroy() must remove exactly the listener it added (proves it named the handler and removed the same reference)");

  // Simulate the browser firing hashchange after destroy (e.g. the user
  // navigating back/forward). Since destroy() deregistered the shell's own
  // handler, this must reach no subscriber and must not mutate the shell's
  // internal state.
  const stateBeforeDispatch = shell.getState();
  window.location.hash = '#view=privacy';
  window.dispatchHashChange();

  assert.equal(seen.length, 0, 'no onStateChange subscriber should fire once destroy() has removed the hashchange listener');
  assert.deepEqual(shell.getState(), stateBeforeDispatch, "internal state must be untouched by a hashchange that fires after destroy() (proves destroy()'s listener removal is real, not just cosmetic)");
});

test('destroy() clears stateChangeListeners so a subscriber registered before destroy() is never called again', () => {
  window.location.hash = '';
  const root = document.createElement('div');
  const shell = mountShell(root, makeGraph());
  let calls = 0;
  shell.onStateChange(() => { calls += 1; });

  shell.setSelection('node:x');
  assert.equal(calls, 1);

  shell.destroy();
  // setSelection after destroy() still updates state/hash (destroy() only
  // un-wires the hashchange listener and clears subscribers, per spec) --
  // the point under test is that the *listener* must not fire again.
  shell.setSelection('node:y');
  assert.equal(calls, 1, 'a listener registered before destroy() must not be invoked after destroy()');
});

test('view-tab clicking still updates aria-selected and the URL hash, and also now notifies onStateChange subscribers', () => {
  window.location.hash = '';
  const root = document.createElement('div');
  const shell = mountShell(root, makeGraph());
  const seen = [];
  shell.onStateChange((state) => seen.push(state));

  const tabs = root.querySelectorAll('[data-view-id]');
  const traceTab = tabs.find((t) => t.getAttribute('data-view-id') === 'trace');
  assert.ok(traceTab, 'expected a rendered tab button for the trace view');
  assert.equal(traceTab.getAttribute('aria-selected'), 'false');

  traceTab.dispatch('click');

  assert.equal(traceTab.getAttribute('aria-selected'), 'true');
  assert.equal(shell.getState().view, 'trace');
  assert.equal(hashParams().get('view'), 'trace');
  assert.equal(seen.length, 1);
  assert.equal(seen[0].view, 'trace');

  shell.destroy();
});

test('mountShell exposes getContextRailEl returning the context rail element', () => {
  window.location.hash = '';
  const root = document.createElement('div');
  const shell = mountShell(root, makeGraph());

  const contextRailEl = shell.getContextRailEl();

  assert.ok(contextRailEl);
  assert.equal(contextRailEl.className, 'shell__context-rail');

  shell.destroy();
});

test('mountShell exposes getLeftRailEl returning the left rail element', () => {
  window.location.hash = '';
  const root = document.createElement('div');
  const shell = mountShell(root, makeGraph());

  const leftRailEl = shell.getLeftRailEl();

  assert.ok(leftRailEl);
  assert.equal(leftRailEl.className, 'shell__left-rail');

  shell.destroy();
});

test('the view tab bar includes an Inventory tab', () => {
  window.location.hash = '';
  const root = document.createElement('div');
  const shell = mountShell(root, makeGraph());

  const tabs = root.querySelectorAll('[data-view-id]');
  const inventoryTab = tabs.find((t) => t.getAttribute('data-view-id') === 'inventory');
  assert.ok(inventoryTab, 'expected a rendered tab button for the inventory view');

  shell.destroy();
});

test('an external hashchange (e.g. back/forward navigation) still updates state and notifies subscribers', () => {
  window.location.hash = '';
  const root = document.createElement('div');
  const shell = mountShell(root, makeGraph());
  const seen = [];
  shell.onStateChange((state) => seen.push(state));

  window.location.hash = '#view=privacy&selected=node%3Aexternal';
  window.dispatchHashChange();

  assert.equal(shell.getState().view, 'privacy');
  assert.equal(shell.getState().selectedId, 'node:external');
  assert.equal(seen.length, 1);
  assert.equal(seen[0].view, 'privacy');

  shell.destroy();
});
