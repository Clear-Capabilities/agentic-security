import { test } from 'node:test';
import assert from 'node:assert/strict';
import { tempProject, cleanup, build } from './helpers.js';
import { validateManifest } from '../../src/context-intelligence/manifest.js';

test('python flask fixture: the decorated route resolves and its handler span is in the bundle', async () => {
  const dir = tempProject('eval/corpus/c10/a');
  try {
    const built = await build(dir);
    assert.equal(built.ok, true);
    const b = built.bundles.find(x => x.entrypoint.method === 'GET');
    assert.ok(b && b.manifest, 'a GET bundle exists');
    assert.equal(b.entrypoint.language, 'py');
    assert.deepEqual(validateManifest(b.manifest, { fileContents: built.fileContents }), []);
    const text = b.pack.packages.map(p => p.text).join('\n');
    assert.match(text, /FROM notes WHERE id/);
  } finally { cleanup(dir); }
});

test('haskell scotty fixture: the route handler is found through the web model', async () => {
  const dir = tempProject('eval/corpus/c11/a');
  try {
    const built = await build(dir);
    assert.equal(built.ok, true);
    assert.ok(built.entrypoints.length >= 1);
    const b = built.bundles.find(x => x.manifest && /items/.test(x.entrypoint.label));
    assert.ok(b, 'items route bundle');
    assert.match(b.pack.packages.map(p => p.text).join('\n'), /FROM items WHERE id/);
    assert.deepEqual(validateManifest(b.manifest, { fileContents: built.fileContents }), []);
  } finally { cleanup(dir); }
});

test('python and haskell builds are deterministic', async () => {
  for (const f of ['eval/corpus/c10/b', 'eval/corpus/c11/b']) {
    const dir = tempProject(f);
    try {
      const a = await build(dir); const b = await build(dir);
      assert.deepEqual(a.bundles.map(x => x.manifest && x.manifest.contextHash), b.bundles.map(x => x.manifest && x.manifest.contextHash));
    } finally { cleanup(dir); }
  }
});
