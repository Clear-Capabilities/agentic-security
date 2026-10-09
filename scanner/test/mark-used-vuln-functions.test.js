// markUsedVulnFunctions: function-level reachability by text match. It used to compile one expression per (file, package,
// function) and split every file into lines for every package, which made a large project (thousands of files) spend more
// time here than in parsing. The expressions are now compiled once and a file is only split when it contains the text a
// match needs. This pins that the answer is exactly the original algorithm's (the oracle below is the original body,
// verbatim) and that the number of expressions compiled no longer grows with the number of files.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { markUsedVulnFunctions, VULN_FUNCTION_HINTS } from '../src/engine.js';
import { extractRustImportMap } from '../src/sast/rust.js';

// The original implementation, kept as the oracle.
function oracle(supplyChain, fc) {
  const used = {};
  const perFile = {};
  for (const [fp, content] of Object.entries(fc)) {
    const lines = content.split('\n');
    let _rustImports = null;
    if (/\.rs$/i.test(fp)) { try { _rustImports = extractRustImportMap(content); } catch (_) { /* none */ } }
    for (const [pkg, fns] of Object.entries(VULN_FUNCTION_HINTS)) {
      if (!perFile[pkg]) perFile[pkg] = [];
      for (const fn of fns) {
        const re = new RegExp(`\\b(?:${pkg.replace(/\W/g, '\\$&')}|_)\\.${fn}\\b`, 'g');
        const rustBareRe = _rustImports ? new RegExp(`\\b${fn.replace(/\W/g, '\\$&')}\\s*[(<]`, 'g') : null;
        for (let li = 0; li < lines.length; li++) {
          let matched = re.test(lines[li]);
          re.lastIndex = 0;
          if (!matched && rustBareRe) {
            if (rustBareRe.test(lines[li]) && (_rustImports.map.get(fn) === pkg || _rustImports.map.get(fn) === pkg.replace(/-/g, '_') || _rustImports.globs.has(pkg) || _rustImports.globs.has(pkg.replace(/-/g, '_')))) matched = true;
            rustBareRe.lastIndex = 0;
          }
          if (matched) {
            perFile[pkg].push({ pkg, fn, file: fp, line: li + 1 });
            if (!used[pkg]) used[pkg] = new Set();
            used[pkg].add(fn);
          }
          re.lastIndex = 0;
        }
      }
    }
  }
  for (const sc of supplyChain || []) {
    if (sc.type !== 'vulnerable_dep') continue;
    const hardcoded = VULN_FUNCTION_HINTS[sc.name] || [];
    const osvFns = Array.isArray(sc.osvVulnFunctions) ? sc.osvVulnFunctions.map((f) => { const d = f.lastIndexOf('.'); return d > 0 ? f.slice(d + 1) : f; }) : [];
    const allFns = [...new Set([...hardcoded, ...osvFns])];
    if (!allFns.length) { sc.functionReachable = 'unknown'; sc.noKnownCallSite = true; sc._hintSource = 'none'; continue; }
    sc._hintSource = osvFns.length ? (hardcoded.length ? 'hardcoded+osv' : 'osv') : 'hardcoded';
    if (osvFns.length && !hardcoded.length) {
      for (const [fp, content] of Object.entries(fc)) {
        const lines = content.split('\n');
        for (const fn of osvFns) {
          const shortFn = fn.lastIndexOf('.') > 0 ? fn.slice(fn.lastIndexOf('.') + 1) : fn;
          const re = new RegExp(`\\b${shortFn.replace(/\W/g, '\\$&')}\\b`, 'g');
          for (let li = 0; li < lines.length; li++) {
            if (re.test(lines[li])) {
              if (!perFile[sc.name]) perFile[sc.name] = [];
              perFile[sc.name].push({ pkg: sc.name, fn: shortFn, file: fp, line: li + 1 });
              if (!used[sc.name]) used[sc.name] = new Set();
              used[sc.name].add(shortFn);
            }
            re.lastIndex = 0;
          }
        }
      }
    }
    sc.usedVulnerableFunctions = [...(used[sc.name] || [])];
    const sites = (perFile[sc.name] || []);
    const seen = new Set();
    sc.vulnerableFunctionCallSites = sites.filter((s) => { const k = `${s.file}:${s.line}:${s.fn}`; if (seen.has(k)) return false; seen.add(k); return true; });
    if (!sc.usedVulnerableFunctions.length) sc.noKnownCallSite = true;
  }
  return supplyChain;
}

const deps = () => [
  { type: 'vulnerable_dep', name: 'lodash', version: '4.17.0' },
  { type: 'vulnerable_dep', name: 'axios', version: '0.21.0' },
  { type: 'vulnerable_dep', name: 'some-unhinted-lib', version: '1.0.0', osvVulnFunctions: ['some-unhinted-lib.parseDangerous', 'other.Unsafe.load'] },
  { type: 'vulnerable_dep', name: 'never-called', version: '1.0.0', osvVulnFunctions: ['neverCalledFn'] },
  { type: 'vulnerable_dep', name: 'express', version: '4.0.0' },
  { type: 'dependency', name: 'not-vulnerable', version: '1.0.0' },
];

const FILES = {
  'a.js': "const _ = require('lodash');\n_.merge(a, b);\nlodash.template(t);\nconst x = 1;\naxios.get('/x');\n",
  'b.js': "// nothing relevant here\nconst y = foo.mergeish();\nexpress.static('/pub');\n",
  'c.py': 'import something\nparseDangerous(x)\nlodash.mergeX(a)\n',
  'd.js': 'function f() { return other.parseDangerous(1); }\nunrelated.Unsafe_load();\n',
  'e.rs': 'use serde_yaml::from_str;\nfn main() { from_str(x); }\n',
  'f.txt': 'lodash.set(a, b)\n_.defaultsDeep(a)\n',
  'g.js': '',
};

test('markUsedVulnFunctions: results are identical to the original algorithm', () => {
  const got = markUsedVulnFunctions(deps(), { ...FILES });
  const want = oracle(deps(), { ...FILES });
  assert.deepEqual(got, want);
  // and the case actually exercises the paths, so an empty-equals-empty pass cannot hide a broken fixture
  const lodash = got.find((d) => d.name === 'lodash');
  assert.ok(lodash.vulnerableFunctionCallSites.length >= 3, JSON.stringify(lodash.vulnerableFunctionCallSites));
  assert.ok(got.find((d) => d.name === 'some-unhinted-lib').usedVulnerableFunctions.includes('parseDangerous'));
  assert.equal(got.find((d) => d.name === 'never-called').noKnownCallSite, true);
});

test('markUsedVulnFunctions: randomised file sets agree with the original algorithm', () => {
  const names = ['lodash', '_', 'axios', 'express', 'some-unhinted-lib', 'other'];
  const fns = ['merge', 'template', 'get', 'static', 'parseDangerous', 'from_str', 'set', 'Unsafe'];
  let seed = 7;
  const rnd = () => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed / 0x7fffffff; };
  for (let n = 0; n < 60; n++) {
    const fc = {};
    const count = 1 + Math.floor(rnd() * 6);
    for (let i = 0; i < count; i++) {
      let text = '';
      const lines = Math.floor(rnd() * 8);
      for (let l = 0; l < lines; l++) text += `${names[Math.floor(rnd() * names.length)]}.${fns[Math.floor(rnd() * fns.length)]}(x);${rnd() < 0.3 ? ' // c' : ''}\n`;
      fc[`f${i}${rnd() < 0.3 ? '.rs' : '.js'}`] = text;
    }
    assert.deepEqual(markUsedVulnFunctions(deps(), { ...fc }), oracle(deps(), { ...fc }), JSON.stringify(fc));
  }
});

test('markUsedVulnFunctions: expressions compiled do not grow with the number of files', () => {
  const countCompiles = (impl, nFiles) => {
    const fc = {};
    for (let i = 0; i < nFiles; i++) fc[`src/file${i}.js`] = `const v${i} = lodash.merge(${i});\nfunction g${i}() { return v${i}; }\n`;
    const Real = globalThis.RegExp;
    let compiled = 0;
    globalThis.RegExp = new Proxy(Real, { construct(target, args, nt) { compiled++; return Reflect.construct(target, args, nt); } });
    try { impl(deps(), fc); } finally { globalThis.RegExp = Real; }
    return compiled;
  };
  const small = countCompiles(markUsedVulnFunctions, 20);
  const large = countCompiles(markUsedVulnFunctions, 40);
  assert.ok(small > 0, 'the counter must observe expression construction');
  // The original compiled (hints x files) expressions, so doubling the files doubled the count; now it is independent of them.
  assert.ok(large <= small + 5, `doubling the files must not add compilations (${small} -> ${large})`);
  // Sanity of the counter itself: the original algorithm does grow with the files.
  const oldSmall = countCompiles(oracle, 20);
  const oldLarge = countCompiles(oracle, 40);
  assert.ok(oldLarge >= oldSmall * 1.8, `the original algorithm should scale with files (${oldSmall} -> ${oldLarge})`);
  assert.ok(large * 20 < oldLarge, `the compiled-expression count must be far below the original (${large} vs ${oldLarge})`);
});
