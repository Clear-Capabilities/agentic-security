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

test('vulnerable: client mimetype trusted as stored Content-Type fires', () => {
  const code = [
    "const file = { mimetype: req.file.mimetype };",
    "const stored = { type: file.mimetype, path: dest };",
    "storage.save(stored);",
  ].join('\n');
  const f = scanFileUpload('routes/files.js', code);
  assert.equal(f.length, 1);
  assert.equal(f[0].subfamily, 'client-mimetype-trusted');
  assert.equal(f[0].cwe, 'CWE-434');
});

test('clean: mimetype used only for fileFilter validation, not stored → no finding', () => {
  // Real shape from the clean fixture's own guarded multer() config.
  const code = "cb(null, /^image\\/(png|jpe?g)$/.test(file.mimetype));";
  assert.equal(scanFileUpload('routes/files.js', code).length, 0);
});

test('clean: type derived via mime.lookup() nearby, not the raw client mimetype → no finding', () => {
  // Same `type: x.mimetype` shape the detector matches on, but with a
  // mime.lookup() call in the surrounding window — the suppression this
  // detector is meant to respect (the vibecoder derived it properly).
  const code = [
    "const derivedType = mime.lookup(file.originalname) || 'application/octet-stream';",
    "const stored = { type: file.mimetype, actualType: derivedType, path: dest };",
    "storage.save(stored);",
  ].join('\n');
  assert.equal(scanFileUpload('routes/files.js', code).length, 0);
});

test('non-upload file → no findings (relevance gate)', () => {
  assert.equal(scanFileUpload('a.js', 'function add(a, b) { return a + b; }\n').length, 0);
  assert.equal(scanFileUpload('a.go', 'package main').length, 0); // unsupported ext
});
