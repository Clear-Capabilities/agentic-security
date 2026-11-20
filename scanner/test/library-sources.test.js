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
import {
  libraryMode, nameWords, isByDesignParamName, isRoleParamName, sinkClassOf, packagePurpose, mainExportName, callDistance,
  judgeLibraryFinding, createLibraryPolicy, LIBRARY_SOURCE_ID, moduleBindings, sinkPlausible, isConfigParamName,
} from '../src/dataflow/library-sources.js';

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

// ── The narrowed library model (dataflow/library-sources.js) ──────────────────────────────────────────────────────────────────────────
const withEnv = async (vars, fn) => {
  const prev = {};
  for (const k of Object.keys(vars)) prev[k] = process.env[k];
  try {
    for (const [k, v] of Object.entries(vars)) if (v === undefined) delete process.env[k]; else process.env[k] = v;
    return await fn();
  } finally {
    for (const [k, v] of Object.entries(prev)) if (v === undefined) delete process.env[k]; else process.env[k] = v;
  }
};
// Scan a throwaway project in deep mode with the library source in `mode` ('narrow' | 'broad' | undefined) and return `cwe:line` for every
// command, markup or SQL finding in `lib.js`.
async function libScan(files, mode) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'libnarrow-'));
  for (const [rel, text] of Object.entries(files)) { fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true }); fs.writeFileSync(path.join(dir, rel), text); }
  return withEnv({ AGENTIC_SECURITY_DEEP: '1', AGENTIC_SECURITY_DEEP_IN_CI: '1', AGENTIC_SECURITY_LIBRARY_SOURCES: mode }, async () => {
    const { scan } = await runScan(dir);
    return [...new Set(scan.findings.filter((f) => f.file === 'lib.js' && /^CWE-(?:78|79|89)$/.test(f.cwe || '')).map((f) => `${f.cwe}:${f.line}`))].sort();
  });
}
const PKG = '{"name":"plain-lib","version":"1.0.0","description":"Network status helpers","main":"lib.js"}\n';
const CP = "const cp = require('child_process');\n";

describe('narrowed library model: the policy pieces', () => {
  test('mode: 1 and narrow are the narrowed model, broad the original, anything else off', () => {
    assert.equal(libraryMode({ AGENTIC_SECURITY_LIBRARY_SOURCES: '1' }), 'narrow');
    assert.equal(libraryMode({ AGENTIC_SECURITY_LIBRARY_SOURCES: 'narrow' }), 'narrow');
    assert.equal(libraryMode({ AGENTIC_SECURITY_LIBRARY_SOURCES: 'broad' }), 'broad');
    assert.equal(libraryMode({ AGENTIC_SECURITY_LIBRARY_SOURCES: 'yes' }), 'off');
    assert.equal(libraryMode({}), 'off');
  });

  test('parameter names: code, commands and callbacks by design are excluded by their last word; other names are not', () => {
    assert.deepEqual(nameWords('shellCommand'), ['shell', 'command']);
    assert.deepEqual(nameWords('_file_path'), ['file', 'path']);
    for (const n of ['cmd', 'command', 'script', 'code', 'template', 'fn', 'callback', 'handler', 'expression', 'shellCommand', 'onDoneCallback']) assert.equal(isByDesignParamName(n), true, n);
    for (const n of ['iface', 'name', 'commandName', 'codeLength', 'user', 'id', 'value']) assert.equal(isByDesignParamName(n), false, n);
  });

  test('role names: a parameter named for what the sink consumes is excluded only for that sink class', () => {
    assert.equal(isRoleParamName('sql', 'sql'), true);
    assert.equal(isRoleParamName('query', 'sql'), true);
    assert.equal(isRoleParamName('query', 'ssrf'), false, 'a query string is not a request target');
    assert.equal(isRoleParamName('baseUrl', 'ssrf'), true);
    assert.equal(isRoleParamName('filePath', 'path'), true);
    assert.equal(isRoleParamName('fileName', 'path'), true);
    assert.equal(isRoleParamName('pattern', 'regex'), true);
    assert.equal(isRoleParamName('args', 'cmd'), true);
    for (const [n, c] of [['iface', 'cmd'], ['file', 'cmd'], ['userId', 'sql'], ['name', 'path'], ['term', 'regex'], ['key', 'proto']]) assert.equal(isRoleParamName(n, c), false, `${n}/${c}`);
  });

  test('configuration parameters: an options object steers pattern, path and code sinks by design, not command or query sinks', () => {
    for (const n of ['options', 'opts', 'parserOptions', 'config', 'settings']) for (const c of ['regex', 'path', 'code']) assert.equal(isConfigParamName(n, c), true, `${n}/${c}`);
    for (const c of ['cmd', 'sql', 'ssrf', 'deser', 'proto']) assert.equal(isConfigParamName('options', c), false, c);
    assert.equal(isConfigParamName('optionName', 'regex'), false);
  });

  test('sink classes: dangerous classes are judged, output-encoding classes are not', () => {
    for (const [cwe, cls] of [['CWE-78', 'cmd'], ['CWE-94', 'code'], ['CWE-95', 'code'], ['CWE-22', 'path'], ['CWE-89', 'sql'], ['CWE-918', 'ssrf'], ['CWE-502', 'deser'], ['CWE-1321', 'proto'], ['CWE-1333', 'regex']]) assert.equal(sinkClassOf(cwe), cls);
    for (const cwe of ['CWE-79', 'CWE-113', 'CWE-601', 'CWE-117', 'CWE-20', null]) assert.equal(sinkClassOf(cwe), null);
  });

  test('package purpose: from the manifest name, description and keywords, and from the main export name', () => {
    assert.ok(packagePurpose({ name: 'x', description: 'Run shell commands from Node' }).has('cmd'));
    assert.ok(packagePurpose({ name: 'cross-spawn' }).has('cmd'));
    assert.ok(packagePurpose({ name: 'x', keywords: ['template engine'] }).has('code'));
    assert.ok(packagePurpose({ name: 'x', keywords: ['query builder'] }).has('sql'));
    assert.ok(packagePurpose({ name: 'x', description: 'A tiny HTTP client' }).has('ssrf'));
    assert.ok(packagePurpose({ name: 'x' }, 'module.exports = function exec(c) { return c; };').has('cmd'));
    assert.ok(packagePurpose({ name: 'x' }, 'export default function render(t) {}').has('code'));
    const none = packagePurpose({ name: 'network-status', description: 'Network status helpers', keywords: ['network'] }, 'module.exports = { status };');
    assert.equal(none.size, 0, [...none].join(','));
    assert.equal(mainExportName('module.exports = status;\n'), 'status');
    assert.equal(mainExportName('module.exports = { a, b };'), null);
  });

  test('call distance: 0 in the exported function, 1 one call away, null when the chain does not pass through it', () => {
    assert.equal(callDistance({ _funcQid: 'f' }, 'f'), 0);
    assert.equal(callDistance({ _hops: ['g', 'f'] }, 'f'), 1);
    assert.equal(callDistance({ _hops: ['h', 'g', 'f'] }, 'f'), 2);
    assert.equal(callDistance({ _hops: ['h', 'g'] }, 'f'), null);
  });

  test('judgement: only findings resting solely on caller-controlled parameters are judged', () => {
    const rec = (varName, fnQid = 'f') => ({ sourceId: LIBRARY_SOURCE_ID, varName, fnQid });
    const policy = { bindingsOf: () => new Map([['cp', 'child_process']]), purposeOf: () => new Set() };
    const base = { cwe: 'CWE-78', _funcQid: 'f', callee: { kind: 'member', object: { kind: 'ident', name: 'cp' }, prop: 'execSync' } };
    const j = (f) => judgeLibraryFinding(f, 'lib.js', { mode: 'narrow', policy });
    assert.deepEqual(j({ ...base, trace: [rec('iface')] }), { library: true, keep: true, reason: 'caller-controlled', param: 'iface', distance: 0 });
    assert.equal(j({ ...base, trace: [rec('cmd')] }).reason, 'param-name');
    assert.equal(j({ ...base, cwe: 'CWE-79', trace: [rec('iface')] }).reason, 'sink-class');
    assert.equal(j({ ...base, _hops: ['h', 'g', 'f'], trace: [rec('iface')] }).reason, 'call-depth');
    assert.equal(j({ ...base, _hops: ['g', 'f'], trace: [rec('iface')] }).keep, true);
    assert.equal(judgeLibraryFinding({ ...base, _sanitizersOnPath: ['shellEscape'], trace: [rec('iface')] }, 'lib.js', { mode: 'narrow', policy, sanitizerCovers: () => true }).reason, 'sanitized');
    assert.equal(j({ ...base, trace: [rec('iface'), { sourceId: 'js-express-req-query', varName: 'q' }] }).library, false, 'a request origin beside it: not judged');
    assert.equal(judgeLibraryFinding({ ...base, cwe: 'CWE-79', trace: [rec('iface')] }, 'lib.js', { mode: 'broad' }).keep, true);
    const purposeful = { ...policy, purposeOf: () => new Set(['cmd']) };
    assert.equal(j({ ...base, callee: { kind: 'member', object: { kind: 'ident', name: 'pattern' }, prop: 'exec' }, trace: [rec('text')] }).reason, 'sink-shape');
    assert.equal(judgeLibraryFinding({ ...base, trace: [rec('iface')] }, 'lib.js', { mode: 'narrow', policy: purposeful }).reason, 'package-purpose');
  });

  test('module bindings: require, destructuring, default, namespace and named imports', () => {
    const b = moduleBindings([
      "const cp = require('child_process');",
      "const { execSync, spawn: sp } = require('node:child_process');",
      "import vm from 'vm';",
      "import * as hb from 'handlebars';",
      "import { exec as run } from 'child_process';",
      "const fs = require('fs');",
    ].join('\n'));
    assert.equal(b.get('cp'), 'child_process');
    assert.equal(b.get('execSync'), 'child_process');
    assert.equal(b.get('sp'), 'child_process');
    assert.equal(b.get('vm'), 'vm');
    assert.equal(b.get('hb'), 'handlebars');
    assert.equal(b.get('run'), 'child_process');
    assert.equal(b.get('fs'), 'fs');
    assert.equal(b.has('spawn'), false, 'a renamed binding is known by its local name');
  });

  test('sink shape: the call is the API its class names and the tainted argument is its operand', () => {
    const cp = new Map([['cp', 'child_process'], ['execSync', 'child_process'], ['vm', 'vm']]);
    const m = (base, prop) => ({ kind: 'member', object: { kind: 'ident', name: base }, prop });
    const id = (name) => ({ kind: 'ident', name });
    assert.equal(sinkPlausible({ callee: m('cp', 'execSync') }, 'cmd', cp), true);
    assert.equal(sinkPlausible({ callee: id('execSync') }, 'cmd', cp), true);
    assert.equal(sinkPlausible({ callee: { kind: 'member', object: { kind: 'call', callee: id('require'), args: [{ kind: 'literal', value: 'child_process' }] }, prop: 'exec' } }, 'cmd', new Map()), true);
    assert.equal(sinkPlausible({ callee: m('pattern', 'exec') }, 'cmd', cp), false, "a regex's exec is not a process");
    assert.equal(sinkPlausible({ callee: id('exec') }, 'cmd', new Map()), false, 'an exec the file does not import from a process module');
    assert.equal(sinkPlausible({ callee: id('eval') }, 'code', cp), true);
    assert.equal(sinkPlausible({ callee: m('vm', 'runInNewContext') }, 'code', cp), true);
    assert.equal(sinkPlausible({ callee: m('ajv', 'compile') }, 'code', cp), false);
    assert.equal(sinkPlausible({ callee: m('socket', 'setTimeout'), _argShape: { composite: true } }, 'code', cp), false);
    assert.equal(sinkPlausible({ callee: id('setTimeout'), _argShape: { composite: false } }, 'code', cp), false, 'a timer given the value whole: a number or a function');
    assert.equal(sinkPlausible({ callee: id('setTimeout'), _argShape: { composite: true } }, 'code', cp), true);
    assert.equal(sinkPlausible({ callee: m('db', 'query') }, 'sql', cp), true);
    assert.equal(sinkPlausible({ callee: id('execute') }, 'sql', cp), false, 'a local function named like a query call');
    assert.equal(sinkPlausible({ argIndex: 0 }, 'path', cp), true);
    assert.equal(sinkPlausible({ argIndex: 1 }, 'path', cp), false, 'the data written, not the path');
    assert.equal(sinkPlausible({ _argShape: { leadTainted: true } }, 'ssrf', cp), true);
    assert.equal(sinkPlausible({ _argShape: { leadTainted: false } }, 'ssrf', cp), false, 'a fixed host with a caller-chosen path');
    assert.equal(sinkPlausible({ _argShape: { composite: true } }, 'regex', cp), true);
    assert.equal(sinkPlausible({ _argShape: { composite: false } }, 'regex', cp), false, 'a pattern handed over whole is a pattern by design');
  });

  test('the per-scan policy reads the nearest package.json among the scan\'s own files, never above the scan root', () => {
    const manifestContents = {
      'package.json': '{"name":"plain","description":"Colour helpers"}',
      'packages/runner/package.json': '{"name":"runner","main":"src/index.js"}',
      'packages/other/package.json': '{"name":"other"}',
    };
    const fileContents = { 'packages/runner/src/index.js': 'module.exports = function spawnTask(c) {};', 'src/a.js': '' };
    const pol = createLibraryPolicy({ fileContents, manifestContents });
    assert.equal(pol.purposeOf('src/a.js').size, 0);
    assert.ok(pol.purposeOf('packages/runner/src/index.js').has('cmd'));
    assert.ok(pol.purposeOf('packages/runner/src/deep/x.js').has('cmd'), 'the nearest manifest up the tree');
    assert.equal(pol.purposeOf('packages/other/lib.js').size, 0);
    assert.equal(createLibraryPolicy({ fileContents, manifestContents: {} }).purposeOf('src/a.js').size, 0, 'no manifest in the scan: no purpose');
    assert.equal(pol.purposeOf('/abs/elsewhere/x.js').size, 0, 'a path outside the scan is not resolved');
    assert.equal(pol.bindingsOf('packages/runner/src/index.js').size, 0);
  });
});

describe('narrowed library model: what the IR and the catalog seed', () => {
  test('a JSDoc function, number or boolean type and a TypeScript Function reference are not caller-controlled text', () => {
    const a = annotated('lib.js', `
      /**
       * @param {Function} cb
       * @param {string} name
       * @param {function(string): void} [later]
       * @param {(x: number) => void} arrow
       * @param {number|null} n
       * @param {Object} opts
       */
      function go(cb, name, later, arrow, n, opts) {}
      module.exports = { go };
    `);
    assert.deepEqual(a, { go: ['name', 'opts'] });
    const t = annotated('lib.ts', 'export function t(f: Function, u: (() => void) | undefined, s: string, m: string | (() => void)) {}');
    assert.deepEqual(t, { t: ['s', 'm'] });
  });

  test('a parameter that is code or a callback by its name is not seeded under the narrowed model, and is under broad', async () => {
    const ann = [{ index: 0, name: 'callback', decorator: 'js:caller-controlled' }, { index: 1, name: 'iface', decorator: 'js:caller-controlled' }];
    await withEnv({ AGENTIC_SECURITY_LIBRARY_SOURCES: '1' }, () => assert.deepEqual([...matchAnnotationParams(ann, 'lib.js')], ['iface']));
    await withEnv({ AGENTIC_SECURITY_LIBRARY_SOURCES: 'broad' }, () => assert.deepEqual([...matchAnnotationParams(ann, 'lib.js')].sort(), ['callback', 'iface']));
    await withEnv({ AGENTIC_SECURITY_LIBRARY_SOURCES: undefined }, () => assert.equal(matchAnnotationParams(ann, 'lib.js').size, 0));
  });
});

describe('narrowed library model: end to end', () => {
  test('sink reachability: a sink in the exported function or one call away is reported; two calls away only under broad', async () => {
    const lib = (exportsLine) => CP + [
      "function inner(x) { return cp.execSync('ip addr show ' + x); }", // line 2
      'function middle(y) { return inner(y); }',
      'function far(z) { return middle(z); }',
      'function near(w) { return inner(w); }',
      exportsLine,
    ].join('\n') + '\n';
    // `near` calls `inner` directly; `far` reaches it through `middle`, two calls away.
    assert.deepEqual(await libScan({ 'package.json': PKG, 'lib.js': lib('module.exports = { near };') }, 'narrow'), ['CWE-78:2']);
    const onlyFar = { 'package.json': PKG, 'lib.js': lib('module.exports = { far };') };
    assert.deepEqual(await libScan(onlyFar, 'narrow'), [], 'two calls away is not attributed to the exported parameter');
    assert.deepEqual(await libScan(onlyFar, 'broad'), ['CWE-78:2']);
    assert.deepEqual(await libScan(onlyFar, undefined), []);
  });

  test('sink class: an HTML write from an exported parameter is reported only under broad; a command under both', async () => {
    const files = { 'package.json': PKG, 'lib.js': CP + [
      'function show(el, label) { el.innerHTML = label; }',
      "function status(iface) { return cp.execSync('ip link show ' + iface); }",
      'module.exports = { show, status };',
    ].join('\n') + '\n' };
    const broad = await libScan(files, 'broad');
    assert.ok(broad.includes('CWE-79:2') && broad.includes('CWE-78:3'), broad.join(','));
    assert.deepEqual(await libScan(files, 'narrow'), ['CWE-78:3']);
  });

  test('parameter names: a parameter that is the command by design is not reported; another parameter is', async () => {
    const files = { 'package.json': PKG, 'lib.js': CP + [
      'function run(cmd) { return cp.execSync(cmd); }',
      "function status(iface) { return cp.execSync('ip link show ' + iface); }",
      'module.exports = { run, status };',
    ].join('\n') + '\n' };
    assert.deepEqual(await libScan(files, 'narrow'), ['CWE-78:3']);
    assert.ok((await libScan(files, 'broad')).includes('CWE-78:2'));
  });

  test('package purpose: nothing of the command class in a package that says it runs commands, by manifest or by main export', async () => {
    const lib = CP + "function status(iface) { return cp.execSync('ip link show ' + iface); }\nmodule.exports = { status };\n";
    assert.deepEqual(await libScan({ 'package.json': PKG, 'lib.js': lib }, 'narrow'), ['CWE-78:2']);
    assert.deepEqual(await libScan({ 'package.json': '{"name":"x","description":"Execute shell commands with a friendly API","main":"lib.js"}', 'lib.js': lib }, 'narrow'), []);
    // The shell-interpolation rule (parser JS-EXEC) fires on a template literal; it is removed by the same manifest rule.
    const tpl = CP + "function status(iface) { return cp.execSync(`ip link show ${iface}`); }\nmodule.exports = { status };\n";
    assert.deepEqual(await libScan({ 'package.json': PKG, 'lib.js': tpl }, 'narrow'), ['CWE-78:2']);
    assert.deepEqual(await libScan({ 'package.json': '{"name":"x","description":"Execute shell commands with a friendly API","main":"lib.js"}', 'lib.js': tpl }, 'narrow'), []);
    const mainNamed = CP + "function exec(iface) { return cp.execSync('ip link show ' + iface); }\nmodule.exports = exec;\n";
    assert.deepEqual(await libScan({ 'package.json': '{"name":"x","main":"lib.js"}', 'lib.js': mainNamed }, 'narrow'), []);
    assert.deepEqual(await libScan({ 'package.json': '{"name":"x","main":"lib.js"}', 'lib.js': mainNamed }, 'broad'), ['CWE-78:2']);
  });

  test('sanitizer: a value escaped for the shell before the call is not reported under the narrowed model', async () => {
    const files = { 'package.json': PKG, 'lib.js': CP + [
      "function ping(host) { return cp.execSync('ping -c 1 ' + shellEscape([host])); }",
      "function trace(host) { return cp.execSync('traceroute ' + host); }",
      'module.exports = { ping, trace };',
    ].join('\n') + '\n' };
    assert.deepEqual(await libScan(files, 'narrow'), ['CWE-78:3']);
  });
});
