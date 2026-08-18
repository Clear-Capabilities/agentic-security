// PRD T3.2 — cross-file / stored (second-order) taint.
//
// Two gaps closed, both found by root-causing the 12 stored/cross-file entries.
//
// 1. The registry REQUIRED the field name to match a closed list
//    (bio|description|about|…). That is the same closed-enumeration bug this
//    audit found four other times in this engine (blessed auth dependencies,
//    `id`/`userId`-only object ids, snake_case-only guard names). Real schemas
//    name fields whatever they like — Ghost's is `mobiledoc`. Admission is now
//    by PROVENANCE: the value side must reference a request source.
//
// 2. Sinks were XSS-only, so a stored value reaching a network, filesystem or
//    shell sink was invisible AND would have been mislabelled CWE-79 if seen.
//    The forcing entry is GHSA-g366-23fw-ggp6: Ghost re-renders stored post
//    content and hands an image src to an unguarded fetch — stored SSRF.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildStoredTaintRegistry, crossStoredTaint } from '../src/engine.js';

const WRITER = [
  'async function savePost(req, res) {',
  '  await Post.create({ mobiledoc: req.body.mobiledoc, authorId: req.user.id });',
  '  return res.json({ ok: true });',
  '}',
].join('\n');

test('a field outside the old closed list is registered by provenance', () => {
  const reg = buildStoredTaintRegistry({ 'a.js': WRITER });
  assert.ok(Object.keys(reg).includes('mobiledoc'),
    `'mobiledoc' matches no prose-name pattern but carries request data: ${JSON.stringify(Object.keys(reg))}`);
});

test('a field with no request provenance is NOT registered', () => {
  const reg = buildStoredTaintRegistry({
    'a.js': 'async function f() {\n  await Post.create({ description: "static text" });\n}',
  });
  assert.deepEqual(Object.keys(reg), [], 'a constant is not stored user input');
});

test('bookkeeping columns are never registered', () => {
  const reg = buildStoredTaintRegistry({
    'a.js': 'async function f(req) {\n  await Post.create({ id: req.body.id, createdAt: req.body.createdAt });\n}',
  });
  for (const k of Object.keys(reg)) assert.ok(!/^(?:id|createdAt)$/i.test(k), `${k} should be excluded`);
});

test('stored SSRF is found cross-file and labelled CWE-918, not XSS', () => {
  const fc = {
    'a/writer.js': WRITER,
    'b/render.js': 'async function rerender(post) {\n  const size = await getImageSizeFromUrl(mobiledoc);\n  apply(size);\n}',
  };
  const f = crossStoredTaint(fc, buildStoredTaintRegistry(fc));
  assert.equal(f.length, 1, `got ${JSON.stringify(f.map(x => x.vuln))}`);
  assert.equal(f[0].cwe, 'CWE-918');
  assert.match(f[0].vuln, /Stored SSRF/);
  assert.equal(f[0].isCrossFile, true);
});

test('stored XSS still works and keeps CWE-79', () => {
  const fc = {
    'a.js': 'async function save(req) {\n  await P.create({ bio: req.body.bio });\n}',
    'b.js': 'function show(bio) {\n  el.innerHTML = bio;\n}',
  };
  const f = crossStoredTaint(fc, buildStoredTaintRegistry(fc));
  assert.equal(f.length, 1);
  assert.equal(f[0].cwe, 'CWE-79');
});

test('FIX-DISCRIMINATION: a family-appropriate guard silences it', () => {
  const fc = {
    'a/writer.js': WRITER,
    'b/render.js': 'async function rerender(post) {\n  if (!isAllowed(mobiledoc)) return;\n  const size = await getImageSizeFromUrl(mobiledoc);\n}',
  };
  assert.deepEqual(crossStoredTaint(fc, buildStoredTaintRegistry(fc)), [],
    'an SSRF allow-list check is the fix for the SSRF family');
});

test('the sink must be in a DIFFERENT file — this is cross-file taint', () => {
  const oneFile = { 'a.js': WRITER + '\nfunction r() { return getImageSizeFromUrl(mobiledoc); }' };
  assert.deepEqual(crossStoredTaint(oneFile, buildStoredTaintRegistry(oneFile)), []);
});
