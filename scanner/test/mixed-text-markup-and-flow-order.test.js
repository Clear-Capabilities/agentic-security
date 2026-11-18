// Two XSS (CWE-79) changes: a rule for DOM content serialised by joining decoded text with markup, and flow order in the regex
// source-to-sink pass (an assignment above the line that introduced a value cannot carry that value).
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanJsMixedTextMarkup } from '../src/sast/js-mixed-text-markup.js';
import { runScan } from '../src/runScan.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const fixture = (name, kind) => path.join(here, 'fixtures', name, kind);
const read = (name, kind, file) => fs.readFileSync(path.join(fixture(name, kind), file), 'utf8');

describe('js-mixed-text-markup', () => {
  test('vulnerable fires at the node-type branch, clean is silent', () => {
    const v = scanJsMixedTextMarkup('caption.js', read('js-mixed-text-markup', 'vulnerable', 'caption.js'));
    assert.deepEqual(v.map((f) => f.line), [5, 13]);
    assert.ok(v.every((f) => f.cwe === 'CWE-79' && f.family === 'xss' && f.parser && f.remediation && f.description));
    assert.deepEqual(scanJsMixedTextMarkup('caption.js', read('js-mixed-text-markup', 'clean', 'caption.js')), []);
  });

  test('jQuery getters count; a setter, an escaper and a non-node-type test do not', () => {
    const l = (code) => scanJsMixedTextMarkup('a.js', code).map((f) => f.line);
    assert.deepEqual(l('s += this.nodeType === 3 ? $(this).text() : this.outerHTML;'), [1]);
    assert.deepEqual(l('s += this.nodeType === 3 ? $(this).text() : $(this).html();'), [1]);
    assert.deepEqual(l('s += this.nodeType === 3 ? esc($(this).text()) : this.outerHTML;'), []);
    assert.deepEqual(l('s += isPlain ? el.textContent : el.innerHTML;'), []);
    assert.deepEqual(l('s += this.nodeType === 3 ? $(this).text("x") : this.outerHTML;'), []);
  });

  test('language gating: silent on a non-JavaScript file', () => {
    assert.deepEqual(scanJsMixedTextMarkup('a.php', 's += n.nodeType === 3 ? n.textContent : n.outerHTML;'), []);
  });

  test('end to end through the engine', async () => {
    const hits = async (d) => (await runScan(d)).scan.findings.filter((f) => String(f.id).startsWith('js-mixed-text-markup:')).map((f) => f.line).sort((a, b) => a - b);
    assert.deepEqual(await hits(fixture('js-mixed-text-markup', 'vulnerable')), [5, 13]);
    assert.deepEqual(await hits(fixture('js-mixed-text-markup', 'clean')), []);
  });
});

describe('regex source-to-sink pass: flow order', () => {
  const xss = async (d) => (await runScan(d)).scan.findings.filter((f) => f.cwe === 'CWE-79' && f.parser === 'REGEX').map((f) => f.line);
  test('a value read from node data and written as markup below it is reported', async () => {
    assert.deepEqual(await xss(fixture('regex-flow-order', 'vulnerable')), [5]);
  });
  test('an assignment above the read does not carry it to a sink', async () => {
    assert.deepEqual(await xss(fixture('regex-flow-order', 'clean')), []);
  });
});
