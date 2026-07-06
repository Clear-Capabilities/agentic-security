// CWE-434 unrestricted file upload detector (#6) — a whole CWE that had no
// detector. Precision is the point: guarded uploads must not fire.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanFileUpload } from '../src/sast/file-upload.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fx = (rel) => fs.readFileSync(path.join(__dirname, 'fixtures', 'file-upload', rel), 'utf8');

test('vulnerable JS: multer-unrestricted + client-filename destination both fire', () => {
  const f = scanFileUpload('vulnerable/upload.js', fx('vulnerable/upload.js'));
  assert.ok(f.length >= 2, `expected ≥2 findings, got ${f.length}`);
  assert.ok(f.every(x => x.cwe === 'CWE-434'));
  assert.ok(f.some(x => x.subfamily === 'multer-unrestricted'));
  assert.ok(f.some(x => x.subfamily === 'client-filename-dest'));
});

test('vulnerable Python: save() with client filename fires', () => {
  const f = scanFileUpload('vulnerable/upload.py', fx('vulnerable/upload.py'));
  assert.ok(f.length >= 1, `expected ≥1, got ${f.length}`);
  assert.equal(f[0].cwe, 'CWE-434');
  assert.equal(f[0].subfamily, 'client-filename-dest');
});

test('clean JS: guarded multer + server-generated name → no findings', () => {
  assert.equal(scanFileUpload('clean/upload.js', fx('clean/upload.js')).length, 0);
});

test('clean Python: secure_filename + uuid → no findings', () => {
  assert.equal(scanFileUpload('clean/upload.py', fx('clean/upload.py')).length, 0);
});

test('non-upload file → no findings (relevance gate)', () => {
  assert.equal(scanFileUpload('a.js', 'function add(a, b) { return a + b; }\n').length, 0);
  assert.equal(scanFileUpload('a.go', 'package main').length, 0); // unsupported ext
});
