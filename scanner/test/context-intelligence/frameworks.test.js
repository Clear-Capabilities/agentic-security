import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { tempProject, cleanup, build, byLabel } from './helpers.js';
import { validateManifest } from '../../src/context-intelligence/manifest.js';
import { buildImportMap } from '../../src/context-intelligence/imports.js';

const text = (b) => b.pack.packages.map(p => p.text).join('\n');
const states = (b) => Object.fromEntries(Object.entries(b.manifest.protection).map(([k, v]) => [k, v.state]));

for (const [fw, label] of [['servant', 'GET /items/:id'], ['wai', 'ANY /items/:param'], ['yesod', 'GET /items/:param']]) {
  test(`haskell ${fw}: the route resolves and its handler and query are in the bundle`, async () => {
    const dir = tempProject(`frameworks/${fw}`);
    try {
      const built = await build(dir);
      assert.equal(built.ok, true);
      const b = byLabel(built, label);
      assert.ok(b && b.manifest, `${label} bundle`);
      assert.equal(b.entrypoint.disposition, 'resolved');
      assert.match(text(b), /SELECT \* FROM items WHERE id/);
      assert.deepEqual(validateManifest(b.manifest, { fileContents: built.fileContents }), []);
      assert.equal(states(b).ownership, 'not_present', 'no ownership scoping in the fixture is stated, not assumed away');
    } finally { cleanup(dir); }
  });
}

test('fastapi: a Depends() guard is a resolved dependency, and the bound parameter is the principal', async () => {
  const dir = tempProject('frameworks/fastapi');
  try {
    const built = await build(dir);
    const open = byLabel(built, '/items/');
    const owned = byLabel(built, '/mine/');
    for (const b of [open, owned]) {
      assert.equal(b.manifest.context.integrity, 'complete');
      assert.equal(b.manifest.entrypoint.middleware[0].resolution, 'resolved');
      assert.equal(states(b).authentication, 'present');
      assert.match(text(b), /def require_user/);
    }
    assert.equal(states(open).ownership, 'not_present', 'authenticated is not owned');
    assert.equal(states(owned).ownership, 'present');
  } finally { cleanup(dir); }
});

test('python imports: a single-line import does not swallow the following lines', () => {
  const files = { 'a.py': 'from fastapi import FastAPI, Depends\nfrom db import get_db, require_user\n\napp = FastAPI()\n', 'db.py': 'def get_db(): pass\ndef require_user(): pass\n' };
  const imps = buildImportMap(files).filter(i => i.file === 'a.py');
  assert.deepEqual(imps.map(i => i.local).sort(), ['Depends', 'FastAPI', 'get_db', 'require_user']);
  assert.equal(imps.find(i => i.local === 'require_user').kind, 'repo');
  const multi = buildImportMap({ 'a.py': 'from db import (\n    get_db,\n    require_user,\n)\n', 'db.py': '' }).filter(i => i.file === 'a.py');
  assert.deepEqual(multi.map(i => i.local).sort(), ['get_db', 'require_user']);
});

test('an inaccessible reference (an import that does not resolve) keeps the bundle from being complete', async () => {
  const dir = tempProject('eval/corpus/c01/b');
  try {
    const p = path.join(dir, 'src', 'app.js');
    let src = fs.readFileSync(p, 'utf8');
    src = "const { gone } = require('./missing-module');\n" + src.replace("res.json(note);", "gone(note); res.json(note);");
    fs.writeFileSync(p, src);
    const built = await build(dir);
    const b = byLabel(built, '/notes/:id');
    assert.notEqual(b.manifest.context.integrity, 'complete');
    assert.ok(b.manifest.unknowns.some(u => u.material));
  } finally { cleanup(dir); }
});
