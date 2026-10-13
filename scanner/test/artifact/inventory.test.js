import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildImageInventory } from '../../src/artifact/inventory.js';
import { parseManifests } from '../../src/sca/index.js';
import { buildDockerArchive, buildOciArchive } from '../helpers/build-tar-fixture.js';

test('INV/1: OS packages, app packages, and config metadata are all populated from one archive', () => {
  const buf = buildDockerArchive({
    config: { labels: { 'org.opencontainers.image.revision': 'abc123' }, entrypoint: ['/app/start'] },
    layers: [
      { files: [{ name: 'var/lib/dpkg/status', content: 'Package: curl\nVersion: 7.68.0-1\nStatus: install ok installed\n' }] },
      { files: [{ name: 'app/package.json', content: JSON.stringify({ dependencies: { lodash: '4.17.15' } }) }] },
    ],
  });
  const { inventory } = buildImageInventory(buf, { manifestParser: parseManifests });
  assert.match(inventory.digest, /^sha256:[0-9a-f]{64}$/);
  assert.equal(inventory.os, 'linux');
  assert.equal(inventory.architecture, 'amd64');
  assert.equal(inventory.osPackages.length, 1);
  assert.equal(inventory.osPackages[0].name, 'curl');
  assert.equal(inventory.appPackages.length, 1);
  assert.equal(inventory.appPackages[0].name, 'lodash');
  assert.deepEqual(inventory.entrypoint, ['/app/start']);
  assert.equal(inventory.buildLabels['org.opencontainers.image.revision'], 'abc123');
  assert.equal(inventory.layers.length, 2);
});

test('INV/2: no declared base-image label reads baseImage: null, never a guess', () => {
  const buf = buildDockerArchive({ config: {}, layers: [{ files: [{ name: 'a.txt', content: 'x' }] }] });
  const { inventory } = buildImageInventory(buf, { manifestParser: parseManifests });
  assert.equal(inventory.baseImage, null);
});

test('INV/3: a declared base-image label is surfaced as structured baseImage info', () => {
  const buf = buildDockerArchive({
    config: { labels: { 'org.opencontainers.image.base.name': 'node:20-slim', 'org.opencontainers.image.base.digest': 'sha256:deadbeef' } },
    layers: [{ files: [{ name: 'a.txt', content: 'x' }] }],
  });
  const { inventory } = buildImageInventory(buf, { manifestParser: parseManifests });
  assert.deepEqual(inventory.baseImage, { name: 'node:20-slim', digest: 'sha256:deadbeef', source: 'label' });
});

test('INV/4: works identically against an oci-archive input', () => {
  const buf = buildOciArchive({
    config: { labels: {} },
    layers: [{ files: [{ name: 'requirements.txt', content: 'flask==1.0.0\n' }] }],
  });
  const { inventory } = buildImageInventory(buf, { manifestParser: parseManifests });
  assert.ok(inventory.appPackages.some((p) => p.name === 'flask'));
});

test('INV/5: requires a manifestParser function', () => {
  const buf = buildDockerArchive({ config: {}, layers: [{ files: [] }] });
  assert.throws(() => buildImageInventory(buf, {}), TypeError);
});

test('INV/6: a manifest parser that throws on hostile layer content never aborts inventory extraction', () => {
  const buf = buildDockerArchive({ config: {}, layers: [{ files: [{ name: 'package.json', content: 'not json at all {{{' }] }] });
  const { inventory } = buildImageInventory(buf, { manifestParser: () => { throw new Error('boom'); } });
  assert.deepEqual(inventory.appPackages, []);
});

test('INV/7: unsafe entries from the outer archive AND from layers are both surfaced on the inventory', () => {
  // A layer containing a path-traversal entry: readLayers flags it; the outer
  // archive here is clean, so this exercises the layer-side half of the union.
  const buf = buildDockerArchive({ config: {}, layers: [{ files: [{ name: '../evil.txt', content: 'x' }] }] });
  const { inventory } = buildImageInventory(buf, { manifestParser: parseManifests });
  assert.equal(inventory.unsafeEntries.some((e) => e.name === '../evil.txt'), true);
});
