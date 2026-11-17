// `repair profile-draft`: facts read from the code are filled in with their basis; everything else is a TODO the validator refuses.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { draftProfile } from '../../src/repair/profile-draft.js';
import { validateProfile } from '../../src/repair/profile.js';

const FIX = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'repair');
const copy = (name) => { const d = fs.mkdtempSync(path.join(os.tmpdir(), 'draft-')); fs.cpSync(path.join(FIX, name), d, { recursive: true }); fs.rmSync(path.join(d, 'profile.json'), { force: true }); return d; };

test('a SQL-injection fixture: entry, imports, factory, SQLite schema, identity header and the route around the finding are read; secrets and legitimate values are TODO', () => {
  const root = copy('sql-notes');
  const text = fs.readFileSync(path.join(root, 'src/app.mjs'), 'utf8');
  const line = text.split('\n').findIndex((l) => /SELECT/.test(l)) + 1;
  const d = draftProfile({ root, finding: { file: 'src/app.mjs', line }, family: 'sql-injection' });
  assert.equal(d.profile.application.export, 'createApp');
  assert.ok(d.profile.application.files.includes('src/app.mjs'));
  assert.equal(d.profile.database.engine, 'sqlite');
  assert.ok(d.todo.some((t) => /planted secret/.test(t)), 'a planted secret is never guessed');
  assert.ok(d.todo.some((t) => /legitimate value/.test(t)), 'a legitimate value is never guessed');
  assert.match(validateProfile(d.profile).join(' '), /unfinished draft/);
});

test('an SSRF fixture: the policy and the approved hosts are never guessed', () => {
  const root = copy('ssrf-preview');
  const d = draftProfile({ root, finding: { file: 'src/app.mjs', line: 8 }, family: 'ssrf' });
  assert.equal(d.profile.application.export, 'createApp');
  assert.match(d.profile.ssrf.policy, /^TODO:/);
  assert.match(d.profile.ssrf.approved[0], /^TODO:/);
  assert.equal(d.profile.ssrf.inputs[0].path, '/preview?url={{value}}');
  assert.equal(d.profile.ssrf.inputs[0].method, 'GET');
});

test('the validator refuses a TODO anywhere, as a value or as a key, and accepts the finished profiles', () => {
  const finished = JSON.parse(fs.readFileSync(path.join(FIX, 'sql-notes', 'profile.json'), 'utf8'));
  assert.deepEqual(validateProfile(finished), []);
  assert.match(validateProfile({ ...finished, actors: [{ ...finished.actors[0], headers: { 'TODO: header': 'x' } }, ...finished.actors.slice(1)] }).join(' '), /unfinished draft/);
});

test('imports outside the root are not followed', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'draft-'));
  fs.mkdirSync(path.join(root, 'src'));
  fs.writeFileSync(path.join(root, 'src', 'app.mjs'), "import x from '../../outside.mjs';\nimport y from './lib.mjs';\nexport function createApp() { return (req, res) => res.end(); }\n");
  fs.writeFileSync(path.join(root, 'src', 'lib.mjs'), 'export default 1;\n');
  const d = draftProfile({ root, finding: { file: 'src/app.mjs', line: 3 }, family: 'ssrf' });
  assert.deepEqual(d.profile.application.files, ['src/app.mjs', 'src/lib.mjs']);
});
