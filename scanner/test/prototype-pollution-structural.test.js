// The key-walk prototype pollution rule (CWE-1321) for library code: no request input is needed, a walk plus a keyed write is, and the
// guards real fixes ship silence it. Shapes from two real advisories (a path setter, a recursive extend) are reproduced here in miniature.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanPrototypePollutionStructural as scan } from '../src/sast/prototype-pollution-structural.js';

const FIX = path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures', 'prototype-pollution-walk');
const lines = (src, file = 'x.js') => scan(file, src).map((f) => f.line);

test('the vulnerable fixture is reported at both writes, the clean one not at all', () => {
  const v = scan('set-path.js', fs.readFileSync(path.join(FIX, 'vulnerable', 'set-path.js'), 'utf8'));
  assert.deepEqual(v.map((f) => [f.line, f.cwe]), [[5, 'CWE-1321'], [14, 'CWE-1321']]);
  assert.deepEqual(scan('set-path.js', fs.readFileSync(path.join(FIX, 'clean', 'set-path.js'), 'utf8')), []);
});

test('walks that are found: a split path, a popped last segment, recursion over for..in and Object.keys, a reduce descent', () => {
  assert.equal(lines("export function set(o, p, v) { const parts = p.split('.'); const last = parts.pop(); let cur = o; for (const k of parts) { if (!cur[k]) cur[k] = {}; cur = cur[k]; } cur[last] = v; }").length, 1);
  assert.equal(lines('function merge(t, s) { for (const k of Object.keys(s)) { t[k] = typeof s[k] === "object" ? merge(t[k] || {}, s[k]) : s[k]; } return t; }').length, 1);
  assert.equal(lines("function extend(deep, target, src) { let copy; for (const name in src) { copy = src[name]; if (deep && copy && typeof copy === 'object') target[name] = extend(deep, target[name] || {}, copy); else target[name] = copy; } return target; }").length, 1);
  assert.equal(lines("export const put = (o, p, v) => { const keys = p.split('.'); keys.slice(0, -1).reduce((acc, k) => (acc[k] = acc[k] || {}), o)[keys[keys.length - 1]] = v; };").length, 1);
});

test('guards that silence it: a comparison, a list of the keys, a module-level set or helper, own-property checks, a null-prototype target', () => {
  const merge = (guard) => `function merge(t, s) { for (const k in s) { ${guard} t[k] = merge(t[k] || {}, s[k]); } return t; }`;
  assert.deepEqual(lines(merge("if (k === '__proto__') continue;")), []);
  assert.deepEqual(lines(merge("if (['__proto__', 'constructor'].includes(k)) continue;")), []);
  assert.deepEqual(lines(merge('if (!Object.hasOwn(s, k)) continue;')), []);
  assert.deepEqual(lines(`const BAD = new Set(['__proto__', 'constructor', 'prototype']);\n${merge('if (BAD.has(k)) continue;')}`), []);
  assert.deepEqual(lines(`function unsafe(k) { return k === '__proto__' || k === 'constructor'; }\n${merge('if (unsafe(k)) continue;')}`), []);
  assert.deepEqual(lines('function merge(t, s) { const out = Object.create(null); for (const k in s) out[k] = merge(t[k], s[k]); return out; }'), []);
});

test('not a walk, or not a prototype write: a flat copy, array indexing, counting words, a fresh clone, an own-key rewrite, a mention of constructor that is not a key test', () => {
  assert.deepEqual(lines('function copy(t, s) { for (const k in s) t[k] = s[k]; return t; }'), []);
  assert.deepEqual(lines('function fill(a, n) { for (let i = 0; i < n; i++) a[i] = 0; }'), []);
  assert.deepEqual(lines("function count(words) { const m = {}; for (const w of words.split(' ')) { m[w] = (m[w] || 0) + 1; } return m; }"), []);
  assert.deepEqual(lines('function clone(v) { const out = {}; for (const k of Object.keys(v)) out[k] = clone(v[k]); return out; }'), []);
  assert.deepEqual(lines('function r(v) { for (const k of Object.keys(v)) { const x = r(v[k]); if (x !== v[k]) v[k] = x; } return v; }'), []);
  assert.equal(lines("function isPlain(o) { return Object.prototype.hasOwnProperty.call(o, 'x'); }\nfunction extend(t, s) { for (const k in s) { t[k] = isPlain(s[k]) ? extend(t[k] || {}, s[k]) : s[k]; } return t; }").length, 1, 'a helper that checks the VALUE (Quasar\'s isPlainObject) does not guard the key');
  assert.equal(lines("function isPlain(o) { return o.constructor === Object && 'constructor' in o; }\nfunction extend(t, s) { for (const k in s) { t[k] = isPlain(s[k]) ? extend(t[k] || {}, s[k]) : s[k]; } return t; }").length, 1, 'a helper that reads o.constructor is not a guard of the key');
});

test('TypeScript and unparseable input', () => {
  assert.equal(lines("export function set<T extends object>(o: T, p: string, v: unknown): T { const keys = (p as string).split('.'); let c: any = o; keys.slice(0, -1).forEach((k) => { if (!(k in c)) c[k] = {}; c = c[k]; }); c[keys[keys.length - 1]] = v; return o; }", 'x.ts').length, 1);
  assert.deepEqual(scan('x.js', 'function ( {'), []);
  assert.deepEqual(scan('x.py', 'def f(): pass'), []);
});
