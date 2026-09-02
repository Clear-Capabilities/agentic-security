import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { bundleFrontendModules } from '../scripts/bundle-frontend.mjs';

function _mkTmpTree(files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agsec-bundle-'));
  for (const [rel, content] of Object.entries(files)) {
    const abs = path.join(root, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content);
  }
  return root;
}

test('bundleFrontendModules: single file, no imports, no rewriting needed', () => {
  const root = _mkTmpTree({ 'a.js': 'export function greet() { return "hi"; }' });
  const out = bundleFrontendModules(path.join(root, 'a.js'));
  assert.doesNotMatch(out, /\bimport\b/);
  assert.doesNotMatch(out, /\bexport\b/);
  const fn = new Function(`${out}\nreturn typeof greet === 'function' ? greet() : 'MISSING';`);
  assert.equal(fn(), 'hi');
});

test('bundleFrontendModules: two-file import chain resolves correctly', () => {
  const root = _mkTmpTree({
    'a.js': `import { greet } from './b.js';\nexport function hello() { return greet() + '!'; }`,
    'b.js': `export function greet() { return 'hi'; }`,
  });
  const out = bundleFrontendModules(path.join(root, 'a.js'));
  const fn = new Function(`${out}\nreturn hello();`);
  assert.equal(fn(), 'hi!');
});

test('bundleFrontendModules: two files independently declaring the same local name do not collide', () => {
  // Both files use `helper` as a PRIVATE (non-exported) top-level name.
  // The bundler's own IIFE-per-module wrapping must keep these in separate
  // scopes — a naive flat-concatenation bundler would collide them.
  const root = _mkTmpTree({
    'a.js': `import { fromB } from './b.js';\nfunction helper() { return 'A'; }\nexport function fromA() { return helper() + fromB(); }`,
    'b.js': `function helper() { return 'B'; }\nexport function fromB() { return helper(); }`,
  });
  const out = bundleFrontendModules(path.join(root, 'a.js'));
  const fn = new Function(`${out}\nreturn fromA();`);
  assert.equal(fn(), 'AB');
});

test('bundleFrontendModules: diamond dependency (two importers, one shared module) is not duplicated/broken', () => {
  const root = _mkTmpTree({
    'entry.js': `import { x } from './a.js';\nimport { y } from './b.js';\nexport function run() { return x() + y(); }`,
    'a.js': `import { shared } from './shared.js';\nexport function x() { return 'A' + shared(); }`,
    'b.js': `import { shared } from './shared.js';\nexport function y() { return 'B' + shared(); }`,
    'shared.js': `export function shared() { return 'S'; }`,
  });
  const out = bundleFrontendModules(path.join(root, 'entry.js'));
  const fn = new Function(`${out}\nreturn run();`);
  assert.equal(fn(), 'ASBS');
});

test('bundleFrontendModules: a multi-line import statement is parsed correctly', () => {
  const root = _mkTmpTree({
    'a.js': `import {\n  x,\n  y,\n} from './b.js';\nexport function run() { return x() + y(); }`,
    'b.js': `export function x() { return 'X'; }\nexport function y() { return 'Y'; }`,
  });
  const out = bundleFrontendModules(path.join(root, 'a.js'));
  const fn = new Function(`${out}\nreturn run();`);
  assert.equal(fn(), 'XY');
});

test('bundleFrontendModules: throws a clear error on an unsupported import form (default/namespace/side-effect)', () => {
  const root = _mkTmpTree({ 'a.js': `import foo from './b.js';\nexport function run() {}`, 'b.js': 'export default 1;' });
  assert.throws(() => bundleFrontendModules(path.join(root, 'a.js')), /unsupported import/i);
});
