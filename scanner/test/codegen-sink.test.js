// PRD T4.3 — code generation as an injection sink. 5 of the 96 root-caused
// real-world misses.
//
// A new sink CATEGORY. Every other injection rule asks "does untrusted data
// reach a dangerous call"; here there is no dangerous call at all. The program
// writes a FILE, the file is source code, and something else imports and runs
// it later — in a different process, possibly much later. That is why no
// eval/exec appears near these lines and why existing rules cannot see them.
//
// Fixtures are built as arrays of real source lines (not shell heredocs) so
// escaping cannot silently change what is under test.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanCodegenSink } from '../src/sast/codegen-sink.js';

const VULN = [
  'def emit(schema, out_path):',
  '    t = schema["extras"]["x-python-type"]',
  '    src = f"from typing import Any\\nvalue: {t} = None\\n"',
  '    with open(out_path + "model.py", "w") as f:',
  '        f.write(src)',
].join('\n');

test('a schema field interpolated into generated Python source fires', () => {
  const f = scanCodegenSink('generator.py', VULN);
  assert.equal(f.length, 1, `got ${JSON.stringify(f.map(x => x.vuln))}`);
  assert.equal(f[0].cwe, 'CWE-94');
  assert.equal(f[0].subfamily, 'generated-source');
  assert.ok(f[0].checkedFor, 'an absence-claim must record what it looked for (T2.2)');
});

test('FIX-DISCRIMINATION: an isidentifier() check silences it', () => {
  // This is the fix these advisories actually shipped.
  const fixed = VULN.replace(
    '    src = f"',
    '    if not t.isidentifier():\n        raise ValueError("bad type")\n    src = f"');
  assert.deepEqual(scanCodegenSink('generator.py', fixed), []);
});

test('REFUSES: an allow-list on the value also silences it', () => {
  const fixed = VULN.replace(
    '    src = f"',
    '    ALLOWED_TYPES = {"int", "str"}\n    if t not in ALLOWED_TYPES:\n        raise ValueError("bad")\n    src = f"');
  assert.deepEqual(scanCodegenSink('generator.py', fixed), []);
});

test('REFUSES: templating HTML is not code generation', () => {
  const html = [
    'def emit(config, out):',
    '    page = f"<div>{config[\'title\']}</div>"',
    '    with open(out + "index.html", "w") as f:',
    '        f.write(page)',
  ].join('\n');
  assert.deepEqual(scanCodegenSink('site.py', html), []);
});

test('REFUSES: generated source with no interpolated external value', () => {
  const literal = [
    'def emit(out_path):',
    '    src = "import os\\nx = 1\\n"',
    '    with open(out_path + "model.py", "w") as f:',
    '        f.write(src)',
  ].join('\n');
  assert.deepEqual(scanCodegenSink('generator.py', literal), []);
});

test('REFUSES: an interpolation that is never written to a code file', () => {
  const nofile = [
    'def build(schema):',
    '    t = schema["extras"]["x-python-type"]',
    '    return f"from typing import Any\\nvalue: {t}\\n"',
  ].join('\n');
  assert.deepEqual(scanCodegenSink('generator.py', nofile), []);
});

test('non-source files are skipped cheaply', () => {
  assert.deepEqual(scanCodegenSink('a.go', 'f.Write([]byte("import x"))'), []);
});
