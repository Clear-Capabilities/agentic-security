// A regular expression naming the dangerous URL schemes as the only check before an href or src (CWE-79): the shape of several
// Markdown renderer advisories, found by reading one development-split entry of the independent population. The rule reports the
// test line, where the allow-list replaces it, and stays silent when the file carries an allow-list or a scheme-aware sanitizer.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanUrlSchemeDenylist } from '../src/sast/wrong-context-sanitizer.js';
import { runFullScan } from '../src/engine.js';
import { setStateWritesEnabled } from '../src/posture/state-dir.js';

setStateWritesEnabled(false);
const HERE = path.dirname(fileURLToPath(import.meta.url));
const fixture = (side) => fs.readFileSync(path.join(HERE, 'fixtures', 'url-scheme-denylist', side, 'render.js'), 'utf8');

test('the denylist before an href is reported at the test line, in JavaScript', () => {
  const r = scanUrlSchemeDenylist('render.js', fixture('vulnerable'));
  assert.deepEqual(r.map((f) => [f.line, f.cwe, f.family]), [[5, 'CWE-79', 'xss']]);
  assert.match(r[0].id, /^url-scheme-denylist:render\.js:5$/);
});

test('an allow-list of schemes after stripping control characters is the fix and is silent', () => {
  assert.deepEqual(scanUrlSchemeDenylist('render.js', fixture('clean')), []);
});

test('the same denylist in Python, PHP and Ruby, before an href, is reported; a denylist whose value never reaches a URL attribute is not', () => {
  const py = "import re\ndef link(href, text):\n    if re.match(r'^\\s*(javascript|vbscript|data):', href, re.I):\n        return text\n    return '<a href=\"%s\">%s</a>' % (escape(href), text)\n";
  assert.deepEqual(scanUrlSchemeDenylist('r.py', py).map((f) => f.line), [3]);
  const php = "<?php\nfunction link($href, $text) {\n  if (preg_match('/^\\s*(javascript|vbscript|data):/i', $href)) { return $text; }\n  return '<a href=\"' . htmlspecialchars($href) . '\">' . $text . '</a>';\n}\n";
  assert.deepEqual(scanUrlSchemeDenylist('r.php', php).map((f) => f.line), [3]);
  const rb = "def link(href, text)\n  return text if href =~ /\\A\\s*(javascript|vbscript|data):/i\n  \"<a href=\\\"#{h(href)}\\\">#{text}</a>\"\nend\n";
  assert.deepEqual(scanUrlSchemeDenylist('r.rb', rb).map((f) => f.line), [2]);
  const noAttr = "const bad = /^(javascript|vbscript|data):/i.test(u);\nif (bad) console.log('refused', u);\n";
  assert.deepEqual(scanUrlSchemeDenylist('r.js', noAttr), []);
});

test('a scheme-aware sanitizer in the same file means the denylist is not the only defence: silent', () => {
  const guarded = "function link(href) {\n  if (/^(javascript|data):/i.test(href)) return '';\n  if (!DOMPurify.isValidAttribute('a', 'href', href)) return '';\n  return '<a href=\"' + href + '\">x</a>';\n}\n";
  assert.deepEqual(scanUrlSchemeDenylist('r.js', guarded), []);
  const parsed = "function link(href) {\n  if (/^(javascript|data):/i.test(href)) return '';\n  const u = new URL(href, base); if (u.protocol !== 'https:') return '';\n  return '<a href=\"' + u.href + '\">x</a>';\n}\n";
  assert.deepEqual(scanUrlSchemeDenylist('r.js', parsed), []);
});

test('end to end: the vulnerable fixture is flagged by the engine and the clean one is not', async () => {
  const scan = async (text) => (await runFullScan({ fileContents: { 'render.js': text }, scanRoot: null })).findings.filter((f) => /URL scheme denylist/.test(f.vuln));
  assert.equal((await scan(fixture('vulnerable'))).length, 1);
  assert.equal((await scan(fixture('clean'))).length, 0);
});
