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

// Regression for a real bug this task's own review found: `visiting` (the
// currently-on-the-DFS-stack set) must be checked BEFORE `parsed` (the
// fully-resolved memo), or a cycle back to an ancestor hits the `parsed`
// check first and returns silently instead of throwing — verified live
// pre-fix (the bundle built "successfully" and only failed later, as a
// confusing ReferenceError, when the broken output was executed).
test('bundleFrontendModules: a real circular import throws a clear build-time error, never silently succeeds', () => {
  const root = _mkTmpTree({
    'entry.js': `import { fromB } from './b.js';\nexport function run() { return fromB(); }`,
    'b.js': `import { run } from './entry.js';\nexport function fromB() { return 'B' + typeof run; }`,
  });
  assert.throws(() => bundleFrontendModules(path.join(root, 'entry.js')), /circular import detected/i);
});

test('bundleFrontendModules: entry and a non-entry dependency each declaring their own private same-named binding do not collide', () => {
  const root = _mkTmpTree({
    'entry.js': `import { fromB } from './b.js';\nfunction helper() { return 'ENTRY'; }\nexport function run() { return helper() + fromB(); }`,
    'b.js': `function helper() { return 'B'; }\nexport function fromB() { return helper(); }`,
  });
  const out = bundleFrontendModules(path.join(root, 'entry.js'));
  const fn = new Function(`${out}\nreturn run();`);
  assert.equal(fn(), 'ENTRYB');
});

// Regression for three real, unsupported forms the final whole-branch
// review found built with NO error and only failed later, as a page-load
// SyntaxError blanking the whole page silently — one of them
// (`export async function`) already exists in the real frontend/ tree
// today (lib/api-client.js), outside the bundled entry point's own
// reachable graph only by luck.
test('bundleFrontendModules: throws a clear error on `export async function`', () => {
  const root = _mkTmpTree({ 'a.js': `export async function run() {}` });
  assert.throws(() => bundleFrontendModules(path.join(root, 'a.js')), /unsupported import\/export form/i);
});

test('bundleFrontendModules: throws a clear error on an `export { x };` re-export list', () => {
  const root = _mkTmpTree({ 'a.js': `function run() {}\nexport { run };` });
  assert.throws(() => bundleFrontendModules(path.join(root, 'a.js')), /unsupported import\/export form/i);
});

test('bundleFrontendModules: throws a clear error on `import { x as y }` renames', () => {
  const root = _mkTmpTree({
    'a.js': `import { greet as hi } from './b.js';\nexport function run() { return hi(); }`,
    'b.js': `export function greet() { return 'hi'; }`,
  });
  assert.throws(() => bundleFrontendModules(path.join(root, 'a.js')), /unsupported .*rename/i);
});

// The general safety net: even an unsupported form none of the named
// guards above anticipates must still be caught, since the final bundle
// is validated as syntactically valid JS before being returned — this is
// what makes the promise in this module's own header comment
// ("throws a clear error on anything else") actually true, rather than
// true only for the specific forms someone thought to name.
test('bundleFrontendModules: the final syntax-validation safety net catches a genuinely unanticipated broken bundle', () => {
  // Not an import/export form at all — a plain syntax error inside a
  // module's own body. None of the named regex guards look at a file's
  // body beyond import/export lines, so nothing upstream of the final
  // `new Function(bundled)` check could ever catch this — proving the
  // safety net's own value: it catches ANY reason the assembled bundle
  // fails to parse, not just the specific forms someone thought to name.
  const root = _mkTmpTree({ 'a.js': `export function run( { return 1; }` });
  assert.throws(() => bundleFrontendModules(path.join(root, 'a.js')), /not valid JavaScript/i);
});
