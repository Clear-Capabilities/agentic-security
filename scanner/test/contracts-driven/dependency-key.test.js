// D-AC05: a change to a route's middleware, a control or boundary file, the contract or the declared environment invalidates the
// context a hunt reads and the review results the queue caches, even when every packed segment still matches its source.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildContext } from '../../src/context-intelligence/build.js';
import { persistBuild } from '../../src/context-intelligence/persist.js';
import { normalizeConfig } from '../../src/context-intelligence/config.js';
import { planJobs } from '../../src/context-intelligence/queue.js';
import { packById } from '../../src/context-intelligence/prompts/packs.js';
import { readStoreJson } from '../../src/context-intelligence/store.js';
import { dependencyKeyOf, dependencyFilesOf, dependencyChanges } from '../../src/context-intelligence/dependency-key.js';
import { setStateWritesEnabled } from '../../src/posture/state-dir.js';
import { makeContextSupplier } from '../../src/discovery/context-supplier.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FIXTURE = path.join(HERE, '..', 'fixtures', 'contract-slice');

async function built() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dep-key-'));
  for (const f of ['service.mjs', 'server.js']) fs.copyFileSync(path.join(FIXTURE, f), path.join(dir, f));
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'dep-key', private: true, type: 'module' }) + '\n');
  setStateWritesEnabled(true);
  const config = normalizeConfig({}).config;
  const b = await buildContext(dir, { config });
  assert.equal(b.ok, true);
  assert.equal(persistBuild(dir, b, config).ok, true);
  return { dir, b, cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
}

test('the key changes with middleware, a dependency file, the contract and the environment, and with nothing else', async () => {
  const { b, cleanup } = await built();
  try {
    const m = b.bundles.find((x) => x.manifest).manifest;
    assert.ok(dependencyFilesOf(m).includes('server.js'), 'the registration file is a dependency');
    const base = dependencyKeyOf({ manifest: m, fileContents: b.fileContents });
    assert.equal(dependencyKeyOf({ manifest: m, fileContents: { ...b.fileContents } }).key, base.key, 'the same inputs give the same key');
    const edited = { ...b.fileContents, 'server.js': b.fileContents['server.js'].replace('app.use(requireSession);', 'app.use(readJsonBody);  ') };
    const k2 = dependencyKeyOf({ manifest: m, fileContents: edited });
    assert.notEqual(k2.key, base.key);
    assert.deepEqual(dependencyChanges(base, k2), ['file:server.js']);
    const gone = { ...b.fileContents }; delete gone['server.js'];
    assert.equal(dependencyKeyOf({ manifest: m, fileContents: gone }).files['server.js'], null, 'a deleted file is recorded as null, never matched');
    const withMw = dependencyKeyOf({ manifest: { ...m, entrypoint: { ...m.entrypoint, middleware: [...(m.entrypoint.middleware || []), 'allowAll'] } }, fileContents: b.fileContents });
    assert.deepEqual(dependencyChanges(base, withMw), ['middleware']);
    const c = dependencyKeyOf({ manifest: m, fileContents: b.fileContents, contractRef: 'invoices-service@1.0.0#aaaaaaaaaaaaaaaa' });
    const c2 = dependencyKeyOf({ manifest: m, fileContents: b.fileContents, contractRef: 'invoices-service@1.0.1#bbbbbbbbbbbbbbbb' });
    assert.deepEqual(dependencyChanges(base, c), ['contract']); assert.notEqual(c.key, c2.key);
    const e = dependencyKeyOf({ manifest: m, fileContents: b.fileContents, environment: { id: 'staging' } });
    assert.deepEqual(dependencyChanges(base, e), ['environment']);
  } finally { cleanup(); }
});

test('the hunt\'s supplier marks a bundle stale when a dependency changed, with the reason; an unchanged snapshot stays fresh', async () => {
  const { dir, b, cleanup } = await built();
  try {
    const idx = readStoreJson(dir, 'index.json'); assert.equal(idx.ok, true); const index = idx.value;
    assert.ok(index.entrypoints.filter((e) => e.contextHash).every((e) => typeof e.dependencies?.key === 'string'), 'the index records a dependency key per bundle');
    const line = b.fileContents['server.js'].split('\n').findIndex((l) => l.includes("app.get('/invoices/:id'")) + 1;
    const fresh = makeContextSupplier({ scanRoot: dir, fileContents: b.fileContents });
    const a = fresh.forCandidate('server.js', line + 2);
    assert.notEqual(a.state, 'stale', JSON.stringify(a.reason));
    // the same line count, so every packed span keeps its numbers; only the middleware the route sits behind changes
    const edited = { ...b.fileContents, 'server.js': b.fileContents['server.js'].replace('app.use(requireSession);', 'app.use(readJsonBody);  ') };
    const after = makeContextSupplier({ scanRoot: dir, fileContents: edited }).forCandidate('server.js', line + 2);
    assert.equal(after.state, 'stale');
    assert.match(after.reason, /dependencies changed since the build \(.*file:server\.js/);
    const area = makeContextSupplier({ scanRoot: dir, fileContents: edited }).forArea(['server.js']);
    assert.equal(area.state, 'stale');
    assert.ok(area.packages.every((p) => p.stale && p.dependencyChanged.includes('file:server.js')));
  } finally { cleanup(); }
});

test('a cached review misses when a dependency, the contract or the environment changes (job keys differ)', async () => {
  const { b, cleanup } = await built();
  try {
    const packs = [packById('authz-idor')].filter(Boolean);
    assert.ok(packs.length, 'a question pack exists');
    const model = { provider: 'test', model: 'scripted' };
    const keys = (o) => planJobs({ bundles: b.bundles, packs, model, fileContents: b.fileContents, ...o }).jobs.map((j) => j.key).sort();
    const base = keys({});
    assert.ok(base.length > 0);
    assert.deepEqual(keys({}), base, 'the same inputs plan the same jobs (a cache hit stays possible)');
    const edited = { ...b.fileContents, 'server.js': b.fileContents['server.js'].replace('app.use(requireSession);', 'app.use(readJsonBody);  ') };
    const changedFile = planJobs({ bundles: b.bundles, packs, model, fileContents: edited }).jobs.map((j) => j.key).sort();
    for (const k of changedFile) assert.ok(!base.includes(k), 'a dependency change reaches every job of a dependent bundle');
    for (const o of [{ contractRef: 'invoices-service@1.0.0#aaaaaaaaaaaaaaaa' }, { environment: { id: 'production' } }]) {
      for (const k of keys(o)) assert.ok(!base.includes(k), JSON.stringify(o));
    }
  } finally { cleanup(); }
});
