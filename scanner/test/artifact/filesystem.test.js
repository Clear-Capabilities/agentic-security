import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readLayers, mergeLayers, DEFAULT_FS_LIMITS } from '../../src/artifact/filesystem.js';
import { buildTar } from '../helpers/build-tar-fixture.js';

test('FS/1: a file deleted by a whiteout in a later layer disappears from the merged view', () => {
  const layer0 = buildTar([{ name: 'secrets/key.pem', content: 'secret-value' }]);
  const layer1 = buildTar([{ name: 'secrets/key.pem', whiteout: true }, { name: 'app/pkg.json', content: '{}' }]);
  const rl = readLayers([{ index: 0, tar: layer0 }, { index: 1, tar: layer1 }]);
  const merged = mergeLayers(rl);
  assert.equal(merged.files.has('secrets/key.pem'), false);
  assert.equal(merged.files.has('app/pkg.json'), true);
  assert.deepEqual(merged.deletedPaths, [{ path: 'secrets/key.pem', deletedAtLayer: 1, opaque: false }]);
});

test('FS/2: the raw per-layer view still has the deleted file\'s content (recoverability source)', () => {
  const layer0 = buildTar([{ name: 'secrets/key.pem', content: 'secret-value' }]);
  const layer1 = buildTar([{ name: 'secrets/key.pem', whiteout: true }]);
  const rl = readLayers([{ index: 0, tar: layer0 }, { index: 1, tar: layer1 }]);
  const entry = rl.layers[0].entries.find((e) => e.name === 'secrets/key.pem');
  assert.equal(entry.data.toString(), 'secret-value');
});

test('FS/3: a later layer overwriting a path wins (last layer, not first, is authoritative)', () => {
  const layer0 = buildTar([{ name: 'a.txt', content: 'v1' }]);
  const layer1 = buildTar([{ name: 'a.txt', content: 'v2' }]);
  const rl = readLayers([{ index: 0, tar: layer0 }, { index: 1, tar: layer1 }]);
  const merged = mergeLayers(rl);
  assert.equal(merged.fileContents['a.txt'], 'v2');
  assert.equal(merged.files.get('a.txt').sourceLayerIndex, 1);
});

test('FS/4: an opaque-directory whiteout removes every path under that directory from earlier layers', () => {
  const layer0 = buildTar([{ name: 'conf/a.txt', content: '1' }, { name: 'conf/sub/b.txt', content: '2' }, { name: 'other.txt', content: '3' }]);
  const layer1 = buildTar([{ name: 'conf/.wh..wh..opq', content: '' }]);
  const rl = readLayers([{ index: 0, tar: layer0 }, { index: 1, tar: layer1 }]);
  const merged = mergeLayers(rl);
  assert.equal(merged.files.has('conf/a.txt'), false);
  assert.equal(merged.files.has('conf/sub/b.txt'), false);
  assert.equal(merged.files.has('other.txt'), true);
  assert.deepEqual(merged.deletedPaths, [{ path: 'conf', deletedAtLayer: 1, opaque: true }]);
});

test('FS/5: content over the per-file cap is tracked in `files` metadata but absent from `fileContents`', () => {
  const big = Buffer.alloc(200, 'x'.charCodeAt(0));
  const layer0 = buildTar([{ name: 'big.bin', content: big }]);
  const rl = readLayers([{ index: 0, tar: layer0 }]);
  const merged = mergeLayers(rl, { ...DEFAULT_FS_LIMITS, maxFileBytes: 10 });
  assert.equal(merged.files.get('big.bin').sizeBytes, 200);
  assert.equal(merged.fileContents['big.bin'], undefined);
});

test('FS/6: exceeding the total materialization cap stops adding content and sets materializationTruncated', () => {
  const layer0 = buildTar([
    { name: 'a.txt', content: Buffer.alloc(50, 'a'.charCodeAt(0)) },
    { name: 'b.txt', content: Buffer.alloc(50, 'b'.charCodeAt(0)) },
  ]);
  const rl = readLayers([{ index: 0, tar: layer0 }]);
  const merged = mergeLayers(rl, { maxFileBytes: 100, maxMaterializedTotalBytes: 60 });
  assert.equal(merged.materializationTruncated, true);
  assert.equal(Object.keys(merged.fileContents).length, 1);
});

test('FS/7: unsafe entries inside a layer tar are surfaced on readLayers, never merged', () => {
  const layer0 = buildTar([{ name: '../escape.txt', content: 'evil' }, { name: 'ok.txt', content: 'fine' }]);
  const rl = readLayers([{ index: 0, tar: layer0 }]);
  assert.equal(rl.unsafeEntries.length, 1);
  assert.equal(rl.unsafeEntries[0].name, '../escape.txt');
  const merged = mergeLayers(rl);
  assert.equal(merged.files.has('ok.txt'), true);
  assert.equal(merged.files.has('../escape.txt'), false);
});
