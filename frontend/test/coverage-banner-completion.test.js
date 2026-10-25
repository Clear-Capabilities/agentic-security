// DAG-07 R07.2: the shell's coverage banner states a stopped analysis, and
// does so when zero flows are shown.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createDomShim } from './dom-shim.js';

const { document, window } = createDomShim();
globalThis.document = document;
globalThis.window = window;
const { mountShell } = await import('../src/shell.js');

function bannerText(graph) {
  window.location.hash = '';
  const root = document.createElement('div');
  mountShell(root, graph);
  const find = (n) => {
    if (n.className === 'shell__coverage-banner' || (n.attributes && n.attributes.class === 'shell__coverage-banner')) return n;
    for (const c of n.childNodes || []) { const r = find(c); if (r) return r; }
    return null;
  };
  const b = find(root);
  assert.ok(b, 'banner exists');
  return b.textContent;
}

const base = { scope: { repository: 'r', environment: 'e' }, nodes: [], edges: [], flows: [] };

test('a partial analysis is stated outright, including with zero flows', () => {
  const t = bannerText({ ...base, scanHealth: { status: 'partial', analysisCompletion: { status: 'partial' } }, coverage: { analysisCompletion: { status: 'partial' } } });
  assert.match(t, /Analysis partial/);
  assert.match(t, /no flows shown/);
  assert.match(t, /not evidence that none exists/);
});

test('a cancelled analysis says cancelled', () => {
  assert.match(bannerText({ ...base, flows: [{}], scanHealth: { status: 'cancelled' }, coverage: { analysisCompletion: { status: 'cancelled' } } }), /Analysis cancelled/);
});

test('a complete analysis keeps the ordinary coverage wording', () => {
  assert.match(bannerText({ ...base, scanHealth: { status: 'complete' }, coverage: {} }), /^Coverage: complete/);
});
