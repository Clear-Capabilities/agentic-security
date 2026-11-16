// M0-06: a correct XSS fix that introduced a local escape helper was refused because only library escapers were recognised by name.
// The helper is now recognised by what it does. Both directions are pinned, and the near misses keep the finding.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { localHtmlEscapers, responseReflectsRequestInputAt } from '../../src/sast/reflected-input.js';

const ROUTE = (helper) => `${helper}\nexports.hello = (req, res) => {\n  res.send('<h1>Hello ' + esc(req.query.name) + '</h1>');\n};\n`;
const at = (src) => responseReflectsRequestInputAt(src.split('\n'), src.split('\n').findIndex((l) => l.includes('res.send')) + 1);

test('a local helper that encodes &, < and > is an escaper', () => {
  const full = ROUTE("const esc = (s) => String(s).replace(/[&<>\"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '\"': '&quot;', \"'\": '&#39;' }[c]));");
  assert.deepEqual(localHtmlEscapers(full), ['esc']);
  assert.equal(at(full), false);
  const chained = ROUTE("function esc(s) {\n  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');\n}");
  assert.equal(at(chained), false);
});

test('near misses keep the finding: only &, a pass-through, a name with no body', () => {
  assert.equal(at(ROUTE("const esc = (s) => String(s).replace(/&/g, '&amp;');")), true);
  assert.equal(at(ROUTE('const esc = (s) => s;')), true);
  assert.equal(at(ROUTE("const esc = require('./esc');")), true);
  assert.equal(at(ROUTE("const esc = (s) => s; // &amp; &lt; &gt;")), true, 'entity names in a comment are not a replacement');
});
