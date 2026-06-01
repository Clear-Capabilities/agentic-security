// R7 — import-aware SCA reachability tests (JS/TS + Python).
// Verifies the import-map parsing, alias/namespace call-site resolution, the
// precision gate (no import → no site), and the additive augmenter.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  extractJsImports, extractPyImports, findImportAwareCallSites,
  augmentReachabilityViaImports, pkgMatches,
} from '../src/sca/import-reachability.js';

test('extractJsImports: named, alias, namespace, default, CJS, scoped', () => {
  const js = extractJsImports(`
    import { merge as deepMerge, pick } from 'lodash';
    import * as _ from 'lodash';
    import express from 'express';
    const { template: tpl } = require('lodash');
    const axios = require('axios');
    import { x } from '@scope/pkg/sub';
  `);
  assert.deepEqual(js.named.get('deepMerge'), { pkg: 'lodash', imported: 'merge' });
  assert.deepEqual(js.named.get('pick'), { pkg: 'lodash', imported: 'pick' });
  assert.equal(js.ns.get('_'), 'lodash');
  assert.equal(js.ns.get('express'), 'express');           // default binding
  assert.deepEqual(js.named.get('tpl'), { pkg: 'lodash', imported: 'template' }); // CJS rename
  assert.equal(js.ns.get('axios'), 'axios');               // CJS whole-module
  assert.deepEqual(js.named.get('x'), { pkg: '@scope/pkg', imported: 'x' }); // scoped + subpath
  assert.ok(js.packages.has('lodash') && js.packages.has('@scope/pkg'));
});

test('extractPyImports: from-import alias, plain import, dotted module', () => {
  const py = extractPyImports([
    'from jinja2 import Template as T, escape',
    'import yaml',
    'import numpy as np',
    'from os.path import join',
  ].join('\n'));
  assert.deepEqual(py.named.get('T'), { pkg: 'jinja2', imported: 'Template' });
  assert.deepEqual(py.named.get('escape'), { pkg: 'jinja2', imported: 'escape' });
  assert.equal(py.ns.get('yaml'), 'yaml');
  assert.equal(py.ns.get('np'), 'numpy');
  assert.deepEqual(py.named.get('join'), { pkg: 'os', imported: 'join' }); // dotted → base pkg
});

test('findImportAwareCallSites: resolves aliased + namespace calls (the FN fix)', () => {
  const content = `
    import { merge as deepMerge } from 'lodash';
    import * as _ from 'lodash';
    function h(req){
      deepMerge({}, req.body);
      _.merge(a, b);
    }
  `;
  const imports = extractJsImports(content);
  const sites = findImportAwareCallSites(content, 'js', imports, 'lodash', ['merge']);
  const fns = sites.map((s) => `${s.fn}:${s.via}`).sort();
  assert.deepEqual(fns, ['merge:alias', 'merge:namespace']);
});

test('findImportAwareCallSites: precision gate — no import of pkg → no sites', () => {
  // merge() is called but lodash is never imported here.
  const content = `function merge(a,b){return {...a,...b};} merge(x, y);`;
  const imports = extractJsImports(content);
  const sites = findImportAwareCallSites(content, 'js', imports, 'lodash', ['merge']);
  assert.equal(sites.length, 0);
});

test('augmentReachabilityViaImports: adds aliased call site the regex missed', () => {
  const fc = {
    'app.js': `
      import { merge as deepMerge } from 'lodash';
      export function handler(req, res){ res.json(deepMerge({}, req.body)); }
    `,
    'unrelated.js': `function merge(a,b){return a;} merge(1,2);`, // must NOT count (no import)
  };
  const supplyChain = [{
    type: 'vulnerable_dep', ecosystem: 'npm', name: 'lodash',
    osvVulnFunctions: ['merge'], vulnerableFunctionCallSites: [], noKnownCallSite: true,
  }];
  augmentReachabilityViaImports(supplyChain, fc);
  const sc = supplyChain[0];
  assert.equal(sc.noKnownCallSite, false, 'should now have a known call site');
  assert.ok(sc.vulnerableFunctionCallSites.some((s) => /app\.js$/.test(s.file) && s.fn === 'merge' && s.via === 'alias'),
    `expected aliased merge site in app.js; got ${JSON.stringify(sc.vulnerableFunctionCallSites)}`);
  // The coincidental merge() in unrelated.js (no lodash import) must NOT be a site.
  assert.ok(!sc.vulnerableFunctionCallSites.some((s) => /unrelated\.js$/.test(s.file)),
    'coincidental call in a non-importing file must not be counted (precision gate)');
  assert.ok(sc._importAwareCallSites >= 1);
});

test('augmentReachabilityViaImports: additive — preserves pre-existing sites, no-op for other ecosystems', () => {
  const fc = { 'a.py': 'from jinja2 import Template\nTemplate("x")' };
  const supplyChain = [
    { type: 'vulnerable_dep', ecosystem: 'pypi', name: 'jinja2', osvVulnFunctions: ['Template'],
      vulnerableFunctionCallSites: [{ pkg: 'jinja2', fn: 'Template', file: 'pre.py', line: 1 }] },
    { type: 'vulnerable_dep', ecosystem: 'maven', name: 'org.foo:bar', osvVulnFunctions: ['exec'],
      vulnerableFunctionCallSites: [] },
  ];
  augmentReachabilityViaImports(supplyChain, fc);
  // pre-existing site retained + new a.py site added
  assert.ok(supplyChain[0].vulnerableFunctionCallSites.some((s) => s.file === 'pre.py'));
  assert.ok(supplyChain[0].vulnerableFunctionCallSites.some((s) => /a\.py$/.test(s.file)));
  // maven untouched (regex pass owns it)
  assert.equal(supplyChain[1].vulnerableFunctionCallSites.length, 0);
  assert.equal(supplyChain[1]._importAwareCallSites, undefined);
});

test('augmentReachabilityViaImports: falls back to VULN_FUNCTION_HINTS when OSV lists no functions', () => {
  const fc = { 'app.js': `import { merge as deepMerge } from 'lodash';\nfunction h(req){ deepMerge({}, req.body); }` };
  const supplyChain = [{ type: 'vulnerable_dep', ecosystem: 'npm', name: 'lodash', osvVulnFunctions: [], vulnerableFunctionCallSites: [] }];
  // Hints keyed by base name AND a versioned key — both must resolve to 'lodash'.
  augmentReachabilityViaImports(supplyChain, fc, { lodash: ['merge', 'set'], 'lodash@<4.17.21': ['template'] });
  assert.ok(supplyChain[0].vulnerableFunctionCallSites.some((s) => s.fn === 'merge' && s.via === 'alias'),
    'hint-sourced function name should still resolve the aliased call site');
});

test('pkgMatches: npm exact, pypi case/-/_ insensitive', () => {
  assert.equal(pkgMatches('lodash', 'lodash', 'js'), true);
  assert.equal(pkgMatches('lodash', 'lodahs', 'js'), false);
  assert.equal(pkgMatches('Flask-Cors', 'flask_cors', 'py'), true);
});
