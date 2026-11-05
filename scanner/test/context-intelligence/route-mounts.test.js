// route-mounts.test.js: GA-03.2 (0.195.26), router mount composition in the entry point collector.
//
// RM/1  a router mounted under a prefix is reachable at the composed path, in another file, through require
// RM/2  mounts compose through an intermediate router, and a router mounted twice yields one entry point per prefix
// RM/3  middleware on the mount statement is inherited by every mounted route, scoped to that mount
// RM/4  a router mounted nowhere keeps the honest reason; a dynamic prefix is not composed
// RM/5  deterministic ids, and the registered path is kept beside the composed one
// RM/6  a citation whose context span changed since the bundle was built is refused as stale
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { build, cleanup } from './helpers.js';
import { resolveCitation } from '../../src/context-intelligence/review.js';
import { sha256 } from '../../src/context-intelligence/canonical.js';

const APP = `
const express = require('express');
const app = express();
const auth = require('./auth');
const users = require('./routes/users');
app.use(express.json());
app.use('/api', auth, users);
app.use('/v2', require('./routes/users'));
const lost = require('./routes/lost');
app.use(dynamicPrefix(), lost);
app.get('/health', (req, res) => { res.send('ok'); });
module.exports = app;
`;
const USERS = `
const express = require('express');
const router = express.Router();
const pets = require('./pets');
router.get('/:id', (req, res) => { res.json({ id: req.params.id }); });
router.use('/pets', pets);
module.exports = router;
`;
const PETS = `
const express = require('express');
const router = express.Router();
router.get('/list', (req, res) => { res.send('pets'); });
module.exports = router;
`;
const LOST = `
const express = require('express');
const router = express.Router();
router.get('/nowhere', (req, res) => { res.send('lost'); });
module.exports = router;
`;
const AUTH = `
function auth(req, res, next) { if (!req.headers.authorization) return res.status(401).end(); next(); }
module.exports = auth;
`;

function project(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dci-mounts-'));
  fs.writeFileSync(path.join(dir, 'package.json'), '{"name":"mounts","version":"1.0.0"}');
  for (const [f, t] of Object.entries(files)) { fs.mkdirSync(path.dirname(path.join(dir, f)), { recursive: true }); fs.writeFileSync(path.join(dir, f), t); }
  return dir;
}
const FILES = { 'app.js': APP, 'routes/users.js': USERS, 'routes/pets.js': PETS, 'routes/lost.js': LOST, 'auth.js': AUTH };
const eps = (built) => built.entrypoints.filter(e => e.kind === 'http').map(e => ({ path: e.pathTemplate, registered: e.registeredPath, file: e.registrationSite.file, mount: e.mount, reasons: e.resolutionReasons, middleware: e.middleware, disposition: e.disposition, id: e.id }));

test('RM/1: a router mounted under a prefix from another file is reachable at the composed path, and the mount is recorded', async () => {
  const dir = project(FILES);
  try {
    const built = await build(dir);
    assert.equal(built.ok, true);
    const all = eps(built);
    const api = all.find(e => e.path === '/api/:id');
    assert.ok(api, `expected /api/:id among ${all.map(e => e.path).join(', ')}`);
    assert.equal(api.registered, '/:id');
    assert.equal(api.file, 'routes/users.js');
    assert.equal(api.mount.prefix, '/api');
    assert.deepEqual(api.mount.chain.map(h => [h.file, h.receiver, h.prefix]), [['app.js', 'app', '/api']]);
    assert.ok(!api.reasons.includes('router-mount-not-resolved'));
    assert.equal(api.disposition, 'resolved');
  } finally { cleanup(dir); }
});

test('RM/2: mounts compose through an intermediate router, and a router mounted at two prefixes is one entry point per prefix', async () => {
  const dir = project(FILES);
  try {
    const all = eps(await build(dir));
    const paths = all.map(e => e.path).sort();
    for (const p of ['/api/:id', '/v2/:id', '/api/pets/list', '/v2/pets/list']) assert.ok(paths.includes(p), `${p} missing from ${paths.join(', ')}`);
    const nested = all.find(e => e.path === '/v2/pets/list');
    assert.deepEqual(nested.mount.chain.map(h => [h.file, h.receiver, h.prefix]), [['app.js', 'app', '/v2'], ['routes/users.js', 'router', '/pets']]);
    assert.equal(nested.mount.alternatives, 2);
    assert.equal(all.filter(e => e.registered === '/:id').length, 2);
  } finally { cleanup(dir); }
});

test('RM/3: middleware named on the mount statement is inherited by the mounted routes, scoped to that mount, and only there', async () => {
  const dir = project(FILES);
  try {
    const all = eps(await build(dir));
    const api = all.find(e => e.path === '/api/:id');
    const viaMount = api.middleware.filter(m => m.viaMount);
    assert.deepEqual(viaMount.map(m => [m.name, m.scope, m.resolution]), [['auth', '/api', 'resolved']]);
    const v2 = all.find(e => e.path === '/v2/:id');
    assert.equal(v2.middleware.filter(m => m.viaMount).length, 0);
    const deep = all.find(e => e.path === '/api/pets/list');
    assert.deepEqual(deep.middleware.filter(m => m.viaMount).map(m => [m.name, m.scope]), [['auth', '/api']]);
  } finally { cleanup(dir); }
});

test('RM/4: a router mounted with a dynamic prefix is not composed and keeps the honest reason; the plain app route is untouched', async () => {
  const dir = project(FILES);
  try {
    const all = eps(await build(dir));
    const lost = all.find(e => e.file === 'routes/lost.js');
    assert.equal(lost.path, '/nowhere');
    assert.equal(lost.mount, null);
    assert.ok(lost.reasons.includes('router-mount-not-resolved'));
    assert.equal(lost.disposition, 'partially_resolved');
    const health = all.find(e => e.path === '/health');
    assert.equal(health.mount, null);
    assert.ok(!health.reasons.includes('router-mount-not-resolved'));
  } finally { cleanup(dir); }
});

test('RM/5: two builds give the same ids, and the composed and registered paths both survive', async () => {
  const dir = project(FILES);
  try {
    const a = eps(await build(dir)); const b = eps(await build(dir));
    assert.deepEqual(a.map(e => [e.id, e.path, e.registered]), b.map(e => [e.id, e.path, e.registered]));
    assert.equal(new Set(a.map(e => e.id)).size, a.length, 'ids are distinct across the per-prefix records');
  } finally { cleanup(dir); }
});

test('RM/6: a citation inside a context segment whose lines changed since the bundle was built is refused as stale, not grounded', () => {
  const text = 'const a = 1;\nconst secret = process.env.KEY;\nreturn secret;\n';
  const seg = { file: 'x.js', startLine: 1, endLine: 3, spanHash: sha256(text.split('\n').slice(0, 3).join('\n')) };
  const c = { file: 'x.js', startLine: 2, endLine: 2, claim: 'secret' };
  assert.equal(resolveCitation(c, [seg], { 'x.js': text }), null);
  const edited = 'const a = 1;\nconst secret = readKey();\nreturn secret;\n';
  assert.equal(resolveCitation(c, [seg], { 'x.js': edited }), 'stale-context');
  const noHash = { file: 'x.js', startLine: 1, endLine: 3 };
  assert.equal(resolveCitation(c, [noHash], { 'x.js': edited }), null, 'a segment without a recorded hash cannot be judged stale');
});
