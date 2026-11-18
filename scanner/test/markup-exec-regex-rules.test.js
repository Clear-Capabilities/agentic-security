// Structural recall rules: PHP attribute interpolation and JS mark-safe markup (CWE-79), dot-only regex escaping (CWE-185), a function
// parameter in a shell command string (CWE-78), and caller-supplied code written to a file and run (CWE-94).
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanPhpHtmlAttrInterpolation } from '../src/sast/php-html-attr-interpolation.js';
import { scanJsMarkupMarkSafe } from '../src/sast/js-markup-mark-safe.js';
import { scanJsIncompleteRegexEscape } from '../src/sast/js-incomplete-regex-escape.js';
import { scanJsExecParamInterpolation } from '../src/sast/js-exec-param-interpolation.js';
import { scanPythonRunWrittenCode } from '../src/sast/python-run-written-code.js';
import { runScan } from '../src/runScan.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const RULES = [
  { name: 'php-html-attr-interpolation', file: 'Thumbnail.php', scan: scanPhpHtmlAttrInterpolation, lines: [8], cwe: 'CWE-79' },
  { name: 'js-markup-mark-safe', file: 'head.ts', scan: scanJsMarkupMarkSafe, lines: [4, 9, 13], cwe: 'CWE-79' },
  { name: 'js-incomplete-regex-escape', file: 'hosts.js', scan: scanJsIncompleteRegexEscape, lines: [3, 8], cwe: 'CWE-185' },
  { name: 'js-exec-param-interpolation', file: 'sysinfo.js', scan: scanJsExecParamInterpolation, lines: [4, 9], cwe: 'CWE-78', optIn: 'AGENTIC_SECURITY_LIBRARY_SOURCES' },
  { name: 'python-run-written-code', file: 'runner.py', scan: scanPythonRunWrittenCode, lines: [10, 20], cwe: 'CWE-94' },
];
// Run fn with the rule's opt-in flag set (if it has one), restoring the environment afterwards.
const withOptIn = async (r, fn) => {
  if (!r.optIn) return fn();
  const prev = process.env[r.optIn]; process.env[r.optIn] = '1';
  try { return await fn(); } finally { if (prev === undefined) delete process.env[r.optIn]; else process.env[r.optIn] = prev; }
};
const read = (r, kind) => fs.readFileSync(path.join(here, 'fixtures', r.name, kind, r.file), 'utf8');

describe('markup, exec and regex structural rules', () => {
  for (const r of RULES) {
    test(`${r.name}: vulnerable fires at the expected lines, clean is silent`, () => withOptIn(r, () => {
      const v = r.scan(r.file, read(r, 'vulnerable'));
      assert.deepEqual(v.map((f) => f.line).sort((a, b) => a - b), r.lines);
      assert.ok(v.every((f) => f.cwe === r.cwe && f.family && f.parser && f.remediation && f.description));
      assert.deepEqual(r.scan(r.file, read(r, 'clean')), []);
    }));
  }

  test('js-exec-param-interpolation is off unless AGENTIC_SECURITY_LIBRARY_SOURCES=1: a library parameter is caller input, not attacker input', () => {
    const r = RULES.find((x) => x.name === 'js-exec-param-interpolation');
    const prev = process.env.AGENTIC_SECURITY_LIBRARY_SOURCES; delete process.env.AGENTIC_SECURITY_LIBRARY_SOURCES;
    try { assert.deepEqual(r.scan(r.file, read(r, 'vulnerable')), []); }
    finally { if (prev !== undefined) process.env.AGENTIC_SECURITY_LIBRARY_SOURCES = prev; }
  });

  test('language gating: each rule is silent on another language', () => {
    assert.deepEqual(scanPhpHtmlAttrInterpolation('a.js', 'return "<img src=\'$u\'>";'), []);
    assert.deepEqual(scanJsMarkupMarkSafe('a.php', 'markHTMLString(`<b>${x}</b>`)'), []);
    assert.deepEqual(scanPythonRunWrittenCode('a.js', read(RULES[4], 'vulnerable')), []);
  });

  test('php: element text, a cast and an escaper are silent; braces and escaped double quotes fire', () => {
    const l = (code) => scanPhpHtmlAttrInterpolation('a.php', `<?php\n${code}`).map((f) => f.line - 1);
    assert.deepEqual(l('function f($n) { return "<td>$n</td>"; }'), []);
    assert.deepEqual(l('function f($u) { $u = e($u);\n return "<a href=\'$u\'>x</a>"; }'), []);
    assert.deepEqual(l('function f($u) { echo "<a href=\\"{$u}\\">x</a>"; }'), [1]);
  });

  test('js markup: a tag name, a call and a constant JSON payload are silent', () => {
    const l = (code) => scanJsMarkupMarkSafe('a.js', code).map((f) => f.line);
    assert.deepEqual(l('markHTMLString(`<${tag}>`)'), []);
    assert.deepEqual(l('markHTMLString(`<p>${render(x)}</p>`)'), []);
    assert.deepEqual(l('const s = `<script>var c = ${JSON.stringify(CONFIG)}</script>`;'), []);
    assert.deepEqual(l('const s = `<script>var c = ${JSON.stringify(state)}</script>`;'), [1]);
    assert.deepEqual(l('const h = `<p>${x}</p>`;\nnew Handlebars.SafeString(h);'), [1]);
  });

  test('regex: a complete escape on the same value and a non-regex use are silent', () => {
    const l = (code) => scanJsIncompleteRegexEscape('a.js', `// RegExp\n${code}`).map((f) => f.line - 1);
    assert.deepEqual(l("const re = new RegExp(h.replace(/\\./g, '\\\\.'));"), [1]);
    assert.deepEqual(l("const re = new RegExp(h.replace(/\\*/g, '.*').replace(/\\./g, '\\\\.'));"), []);
    assert.deepEqual(l("const label = h.replace(/\\./g, '\\\\.');"), []);
  });

  test('end to end through the engine', async () => {
    for (const r of RULES) {
      const dir = (kind) => path.join(here, 'fixtures', r.name, kind);
      const hits = async (d) => [...new Set((await runScan(d)).scan.findings.filter((f) => f.id.startsWith(`${r.name}:`) || f.id.startsWith('js-markup-') && r.name === 'js-markup-mark-safe').map((f) => f.line))].sort((a, b) => a - b);
      await withOptIn(r, async () => {
        assert.deepEqual(await hits(dir('vulnerable')), r.lines, r.name);
        assert.deepEqual(await hits(dir('clean')), [], r.name);
      });
    }
  });
});
