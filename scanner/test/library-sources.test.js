// Caller-controlled parameters of exported JavaScript/TypeScript functions (`js:caller-controlled`). The parser states which parameters
// belong to functions the module exports; the catalog source that turns them into taint is opt-in (AGENTIC_SECURITY_LIBRARY_SOURCES=1)
// until its precision cost is measured on the independent population's development split.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { parseJsFile } from '../src/ir/parser-js.js';
import { matchAnnotationParams } from '../src/dataflow/catalog.js';
import { runScan } from '../src/runScan.js';

const annotated = (file, src) => Object.fromEntries(parseJsFile(file, src).functions.filter((f) => f.paramAnnotations).map((f) => [f.name, f.paramAnnotations.filter((a) => a.decorator === 'js:caller-controlled').map((a) => a.name)]));

describe('exported-function parameters in the JS/TS IR', () => {
  test('CommonJS: module.exports objects, shorthand names, exports.x and module.exports.x; an internal function is not annotated', () => {
    const a = annotated('lib.js', `
      function readIt(p) { return p; }
      function internal(q) { return q; }
      module.exports = { readIt, other: function (x) { return x; }, m(y) { return y; } };
      exports.direct = (z) => z;
      module.exports.alsoDirect = function (w) { return w; };
    `);
    assert.deepEqual(a, { readIt: ['p'], other: ['x'], m: ['y'], direct: ['z'], alsoDirect: ['w'] });
  });

  test('ES modules: export function, export const, export default, export { name }, exported classes; private and underscore methods, and non-text TypeScript types, are not', () => {
    const a = annotated('lib.ts', `
      export function esm(a: string, n: number, ok: boolean, cb: () => void) {}
      export const arrow = (c) => c;
      export class K { run(d) {} _hidden(e) {} #priv(f) {} get g() { return 1; } }
      class L { go(h) {} }
      export { L };
      export default function (i) {}
      function notExported(j) {}
    `);
    assert.deepEqual(a, { esm: ['a'], arrow: ['c'], run: ['d'], go: ['h'], anon: ['i'] });
  });

  test('a re-export from another module and a nested function are not annotated', () => {
    const a = annotated('lib.js', `
      export { thing } from './other.js';
      export function outer(x) { function inner(y) { return y; } return inner(x); }
    `);
    assert.deepEqual(a, { outer: ['x'] });
  });
});

describe('the opt-in caller-controlled source', () => {
  test('the annotation is a source only while AGENTIC_SECURITY_LIBRARY_SOURCES=1', () => {
    const ann = [{ index: 0, name: 'p', decorator: 'js:caller-controlled' }];
    const prev = process.env.AGENTIC_SECURITY_LIBRARY_SOURCES;
    try {
      delete process.env.AGENTIC_SECURITY_LIBRARY_SOURCES;
      assert.equal(matchAnnotationParams(ann, 'lib.js').size, 0);
      process.env.AGENTIC_SECURITY_LIBRARY_SOURCES = '1';
      assert.deepEqual([...matchAnnotationParams(ann, 'lib.js')], ['p']);
      assert.equal(matchAnnotationParams(ann, 'lib.py').size, 0, 'JavaScript and TypeScript files only');
    } finally {
      if (prev === undefined) delete process.env.AGENTIC_SECURITY_LIBRARY_SOURCES; else process.env.AGENTIC_SECURITY_LIBRARY_SOURCES = prev;
    }
  });

  test('end to end: a command built from an exported function\'s parameter is reported only with the source enabled, and a fixed command never', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'libsrc-'));
    fs.writeFileSync(path.join(dir, 'package.json'), '{"name":"libsrc","version":"1.0.0","main":"lib.js"}\n');
    fs.writeFileSync(path.join(dir, 'lib.js'), "const { execSync } = require('child_process');\nfunction status(iface) {\n  return execSync(`ip link show ${iface}`).toString();\n}\nfunction fixed() { return execSync('uptime').toString(); }\nmodule.exports = { status, fixed };\n");
    const prev = { deep: process.env.AGENTIC_SECURITY_DEEP, lib: process.env.AGENTIC_SECURITY_LIBRARY_SOURCES, inCi: process.env.AGENTIC_SECURITY_DEEP_IN_CI };
    const cmdi = async () => (await runScan(dir)).scan.findings.filter((f) => f.cwe === 'CWE-78').map((f) => f.line);
    try {
      process.env.AGENTIC_SECURITY_DEEP = '1';
      process.env.AGENTIC_SECURITY_DEEP_IN_CI = '1'; // under CI deep mode is off unless opted in
      delete process.env.AGENTIC_SECURITY_LIBRARY_SOURCES;
      assert.deepEqual(await cmdi(), []);
      process.env.AGENTIC_SECURITY_LIBRARY_SOURCES = '1';
      assert.deepEqual(await cmdi(), [3]);
    } finally {
      for (const [k, v] of Object.entries({ AGENTIC_SECURITY_DEEP: prev.deep, AGENTIC_SECURITY_LIBRARY_SOURCES: prev.lib, AGENTIC_SECURITY_DEEP_IN_CI: prev.inCi })) if (v === undefined) delete process.env[k]; else process.env[k] = v;
    }
  });
});
