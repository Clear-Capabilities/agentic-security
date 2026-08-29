// Unit tests for lib/dom.js's el()/clear(), using a minimal dependency-free
// document shim (test/dom-shim.js) rather than pulling in jsdom. This closes
// the exact gap that let issue #1 (escapeHtml + el() double-escaping) ship
// undetected: el()'s text-child path was never exercised end-to-end against
// a real DOM tree.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createDomShim } from './dom-shim.js';

const { document } = createDomShim();
globalThis.document = document;

const { el, clear } = await import('../src/lib/dom.js');

test('el() inserts a raw, unescaped string as a text child via createTextNode', () => {
  // This is the regression proof for the shell.js double-escaping bug: a
  // real repo name containing HTML-significant characters must render as
  // its literal text, not as HTML-entity-encoded text. createTextNode never
  // interprets its argument as markup, so el() must NOT be fed a
  // pre-escaped string.
  const raw = "Acme & Sons' <repo>";
  const node = el('div', {}, raw);
  assert.equal(node.textContent, raw);
  assert.ok(!node.textContent.includes('&amp;'), 'text content must not be HTML-entity-encoded');
});

test('el() sets attributes via setAttribute, not innerHTML', () => {
  const node = el('button', { 'data-view-id': 'trace', class: 'shell__view-tab' });
  assert.equal(node.getAttribute('data-view-id'), 'trace');
  assert.equal(node.className, 'shell__view-tab');
});

test('el() wires onX props via addEventListener', () => {
  let clicked = false;
  const node = el('button', { onClick: () => { clicked = true; } });
  node.dispatch('click');
  assert.equal(clicked, true);
});

test('el() skips null/undefined/false attributes and children', () => {
  const node = el('div', { 'data-x': null, 'data-y': undefined, 'data-z': false }, [null, false, 'ok']);
  assert.equal(node.getAttribute('data-x'), null);
  assert.equal(node.getAttribute('data-y'), null);
  assert.equal(node.getAttribute('data-z'), null);
  assert.equal(node.textContent, 'ok');
});

test('el() accepts a single child element (not just an array)', () => {
  const child = el('span', {}, 'inner');
  const parent = el('div', {}, child);
  assert.equal(parent.childNodes.length, 1);
  assert.equal(parent.textContent, 'inner');
});

test('el() concatenates multiple text/element children in order', () => {
  const node = el('div', {}, ['a', el('b', {}, 'B'), 'c']);
  assert.equal(node.textContent, 'aBc');
});

test('clear() removes all children of a node', () => {
  const parent = el('div', {}, ['a', 'b']);
  assert.equal(parent.childNodes.length, 2);
  clear(parent);
  assert.equal(parent.childNodes.length, 0);
});
