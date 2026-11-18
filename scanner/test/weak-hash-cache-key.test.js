// A 31/33-multiplier string hash used as a cache key for request data (CWE-328), src/sast/weak-hash-cache-key.js.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanWeakHashCacheKey as scan } from '../src/sast/weak-hash-cache-key.js';

const FIX = path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures', 'weak-hash-cache-key');
const read = (side) => fs.readFileSync(path.join(FIX, side, 'response-cache.ts'), 'utf8');
const lineOf = (code, needle) => code.split('\n').findIndex((l) => l.includes(needle)) + 1;

test('the fold line of a 32-bit hash whose result keys a request cache is reported', () => {
  const code = read('vulnerable');
  const out = scan('response-cache.ts', code);
  assert.deepEqual(out.map((f) => f.line), [lineOf(code, 'Math.imul(31, h)')]);
  assert.equal(out[0].cwe, 'CWE-328');
});

test('the full key is silent, and the same hash used for an id or colour is silent', () => {
  assert.deepEqual(scan('response-cache.ts', read('clean')), []);
  const idUse = read('vulnerable').replace('const cacheKey = shortHash(', 'const elementId = shortHash(').replace('return cacheKey;', 'return elementId;')
    .replace('return cache.get(cacheKeyFor(request));', 'return cacheKeyFor(request);');
  assert.deepEqual(scan('response-cache.ts', idUse), []);
  assert.deepEqual(scan('response-cache.py', read('vulnerable')), []);
});
