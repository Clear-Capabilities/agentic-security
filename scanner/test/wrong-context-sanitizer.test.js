import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { scanWrongContextSanitizer } from '../src/sast/wrong-context-sanitizer.js';

const FX = path.resolve(import.meta.dirname, 'fixtures', 'wrong-context-sanitizer');
const read = (rel) => fs.readFileSync(path.join(FX, rel), 'utf8');

test('flags HTML-entity encoder feeding a URL sink (href/src)', () => {
  const f = scanWrongContextSanitizer('vulnerable/app.js', read('vulnerable/app.js'));
  assert.ok(f.length >= 2, `expected >=2 findings, got ${f.length}`);
  assert.ok(f.every(x => x.cwe === 'CWE-79' && x.family === 'xss'));
  assert.match(f[0].vuln, /Wrong-context output encoding/);
});

test('does NOT flag when a scheme check guards the URL, or HTML body context', () => {
  const f = scanWrongContextSanitizer('clean/app.js', read('clean/app.js'));
  assert.equal(f.length, 0, `expected clean, got: ${JSON.stringify(f)}`);
});

test('does NOT flag encodeURIComponent in a URL (different, non-XSS issue) or bare escape', () => {
  const src = "el.href = encodeURIComponent(u);\nel.src = escape(u);\n";
  assert.equal(scanWrongContextSanitizer('a.js', src).length, 0);
});

test('does NOT flag HTML-entity encoding used for HTML body text', () => {
  const src = "el.innerText = escapeHtml(u);\nel.textContent = he.encode(u);\n";
  assert.equal(scanWrongContextSanitizer('a.js', src).length, 0);
});

test('ignores non-JS/PHP files', () => {
  assert.equal(scanWrongContextSanitizer('a.go', 'el.href = escapeHtml(u)').length, 0);
});
