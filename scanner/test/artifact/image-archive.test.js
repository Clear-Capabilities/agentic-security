import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseImageArchive, ImageArchiveError } from '../../src/artifact/image-archive.js';
import { buildDockerArchive, buildOciArchive, buildTar } from '../helpers/build-tar-fixture.js';

test('IA/1a: parses a docker-archive, extracting labels/entrypoint/layers', () => {
  const buf = buildDockerArchive({
    config: { labels: { 'org.opencontainers.image.revision': 'abc123' }, entrypoint: ['/app/start'] },
    layers: [{ files: [{ name: 'app/package.json', content: '{}' }] }],
  });
  const img = parseImageArchive(buf);
  assert.equal(img.format, 'docker-archive');
  assert.equal(img.digestKind, 'config');
  assert.match(img.digest, /^sha256:[0-9a-f]{64}$/);
  assert.equal(img.config.labels['org.opencontainers.image.revision'], 'abc123');
  assert.deepEqual(img.config.entrypoint, ['/app/start']);
  assert.equal(img.layers.length, 1);
  assert.ok(Buffer.isBuffer(img.layers[0].tar));
});

test('IA/1b: parses an oci-archive, digest is the manifest digest (not the config digest)', () => {
  const buf = buildOciArchive({
    config: { labels: { x: '1' } },
    layers: [{ files: [{ name: 'a.txt', content: 'x' }] }],
  });
  const img = parseImageArchive(buf);
  assert.equal(img.format, 'oci-archive');
  assert.equal(img.digestKind, 'manifest');
  assert.match(img.digest, /^sha256:[0-9a-f]{64}$/);
});

test('IA/2a: multi-layer archives preserve layer order', () => {
  const buf = buildDockerArchive({
    config: {},
    layers: [
      { files: [{ name: 'one.txt', content: '1' }] },
      { files: [{ name: 'two.txt', content: '2' }] },
      { files: [{ name: 'three.txt', content: '3' }] },
    ],
  });
  const img = parseImageArchive(buf);
  assert.deepEqual(img.layers.map((l) => l.index), [0, 1, 2]);
});

test('IA/3a: an archive with neither manifest.json nor oci-layout is rejected, never guessed at', () => {
  const buf = buildTar([{ name: 'random-file.txt', content: 'not an image' }]);
  assert.throws(() => parseImageArchive(buf), (err) => err instanceof ImageArchiveError && err.code === 'unrecognized_format');
});

test('IA/3b: a manifest.json referencing a missing config blob is rejected', () => {
  const buf = buildTar([{ name: 'manifest.json', content: JSON.stringify([{ Config: 'missing.json', RepoTags: [], Layers: [] }]) }]);
  assert.throws(() => parseImageArchive(buf), (err) => err instanceof ImageArchiveError && err.code === 'missing_blob');
});

test('IA/3c: a manifest.json describing more than one image is rejected (image scan expects exactly one)', () => {
  const buf = buildTar([
    { name: 'manifest.json', content: JSON.stringify([{ Config: 'a.json', RepoTags: [], Layers: [] }, { Config: 'b.json', RepoTags: [], Layers: [] }]) },
    { name: 'a.json', content: '{}' },
    { name: 'b.json', content: '{}' },
  ]);
  assert.throws(() => parseImageArchive(buf), (err) => err instanceof ImageArchiveError && err.code === 'multi_image_archive');
});

test('IA/3d: malformed JSON in manifest.json is rejected with a clear error, not a raw parse exception', () => {
  const buf = buildTar([{ name: 'manifest.json', content: '{not json' }]);
  assert.throws(() => parseImageArchive(buf), (err) => err instanceof ImageArchiveError && err.code === 'malformed_manifest');
});

test('IA/3e: index.json with no manifests is rejected', () => {
  const buf = buildTar([
    { name: 'oci-layout', content: JSON.stringify({ imageLayoutVersion: '1.0.0' }) },
    { name: 'index.json', content: JSON.stringify({ schemaVersion: 2, manifests: [] }) },
  ]);
  assert.throws(() => parseImageArchive(buf), (err) => err instanceof ImageArchiveError && err.code === 'empty_manifest');
});

test('IA/4: unsafe entries in the outer archive are surfaced, not silently dropped', () => {
  const buf = buildTar([
    { name: 'manifest.json', content: JSON.stringify([{ Config: 'cfg.json', RepoTags: [], Layers: [] }]) },
    { name: 'cfg.json', content: '{}' },
    { name: '../escape.txt', content: 'evil' },
  ]);
  const img = parseImageArchive(buf);
  assert.equal(img.unsafeEntries.length, 1);
  assert.equal(img.unsafeEntries[0].name, '../escape.txt');
});

test('IA/5: config history/rootfs/os/arch fields are extracted with closed-world defaults, never undefined', () => {
  const buf = buildDockerArchive({ config: {}, layers: [{ files: [{ name: 'f.txt', content: 'x' }] }] });
  const img = parseImageArchive(buf);
  assert.equal(typeof img.config.architecture, 'string');
  assert.equal(typeof img.config.os, 'string');
  assert.ok(Array.isArray(img.config.history));
  assert.ok(Array.isArray(img.config.rootfsDiffIds));
  assert.equal(img.config.entrypoint, null);
});
