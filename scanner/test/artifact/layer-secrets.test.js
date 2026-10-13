import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeLayerSecrets } from '../../src/artifact/layer-secrets.js';
import { readLayers, mergeLayers } from '../../src/artifact/filesystem.js';
import { buildTar } from '../helpers/build-tar-fixture.js';

// A trivial fake detector mirroring scanCredentials' (filePath, rawText) ->
// Finding[] contract and its redact-before-return discipline, so this suite
// never needs the real engine.js (keeping src/artifact/ import-isolated).
function fakeDetect(fp, text) {
  const out = [];
  for (const m of text.matchAll(/SECRET-[A-Z0-9]+/g)) {
    out.push({ vuln: 'Fake Secret', severity: 'critical', masked: m[0].slice(0, 7) + '••••' });
  }
  return out;
}

function scenario() {
  const layer0 = buildTar([{ name: 'secrets/key.pem', content: 'token=SECRET-ABC123' }]);
  const layer1 = buildTar([{ name: 'secrets/key.pem', whiteout: true }, { name: 'app/ok.txt', content: 'no secret here' }]);
  const layers = [{ index: 0, tar: layer0 }, { index: 1, tar: layer1 }];
  const rl = readLayers(layers);
  const merged = mergeLayers(rl);
  return { rl, merged };
}

test('LS/1: a secret added in layer 0 and deleted in layer 1 is reported as recoverable', () => {
  const { rl, merged } = scenario();
  const report = analyzeLayerSecrets({ readLayersResult: rl, deletedPaths: merged.deletedPaths, detectFn: fakeDetect });
  assert.equal(report.findings.length, 1);
  assert.equal(report.deletedButRecoverable.length, 1);
  const f = report.deletedButRecoverable[0];
  assert.equal(f.path, 'secrets/key.pem');
  assert.equal(f.addedAtLayer, 0);
  assert.equal(f.deletedAtLayer, 1);
  assert.equal(f.recoverable, true);
});

test('LS/2: the finding never carries the raw secret value, only the detector\'s masked form', () => {
  const { rl, merged } = scenario();
  const report = analyzeLayerSecrets({ readLayersResult: rl, deletedPaths: merged.deletedPaths, detectFn: fakeDetect });
  const dump = JSON.stringify(report);
  assert.ok(!dump.includes('SECRET-ABC123'));
  assert.ok(dump.includes('••••'));
});

test('LS/3: a secret that is still present in the final image is reported but NOT marked recoverable-from-deletion', () => {
  const layer0 = buildTar([{ name: 'app/.env', content: 'key=SECRET-STILLHERE' }]);
  const rl = readLayers([{ index: 0, tar: layer0 }]);
  const merged = mergeLayers(rl);
  const report = analyzeLayerSecrets({ readLayersResult: rl, deletedPaths: merged.deletedPaths, detectFn: fakeDetect });
  assert.equal(report.findings.length, 1);
  assert.equal(report.deletedButRecoverable.length, 0);
  assert.equal(report.findings[0].recoverable, false);
});

test('LS/4: an opaque-directory whiteout marks everything under it as recoverable too', () => {
  const layer0 = buildTar([{ name: 'conf/db/key.txt', content: 'db=SECRET-OPAQUE1' }]);
  const layer1 = buildTar([{ name: 'conf/db/.wh..wh..opq', content: '' }]);
  const rl = readLayers([{ index: 0, tar: layer0 }, { index: 1, tar: layer1 }]);
  const merged = mergeLayers(rl);
  assert.equal(merged.files.has('conf/db/key.txt'), false);
  const report = analyzeLayerSecrets({ readLayersResult: rl, deletedPaths: merged.deletedPaths, detectFn: fakeDetect });
  assert.equal(report.deletedButRecoverable.length, 1);
  assert.equal(report.deletedButRecoverable[0].deletedAtLayer, 1);
});

test('LS/5: a file over the per-file scan cap is skipped and disclosed, never silently treated as clean', () => {
  const big = Buffer.alloc(2000, 'a'.charCodeAt(0));
  const layer0 = buildTar([{ name: 'big.bin', content: big }]);
  const rl = readLayers([{ index: 0, tar: layer0 }]);
  const report = analyzeLayerSecrets({ readLayersResult: rl, deletedPaths: [], detectFn: fakeDetect, limits: { maxFileBytes: 100 } });
  assert.equal(report.findings.length, 0);
  assert.equal(report.materializationSkipped.length, 1);
  assert.equal(report.materializationSkipped[0].path, 'big.bin');
});

test('LS/6: a detector that throws on hostile content never aborts the sweep', () => {
  function throwingDetect() { throw new Error('boom'); }
  const layer0 = buildTar([{ name: 'ok.txt', content: 'x' }]);
  const rl = readLayers([{ index: 0, tar: layer0 }]);
  const report = analyzeLayerSecrets({ readLayersResult: rl, deletedPaths: [], detectFn: throwingDetect });
  assert.deepEqual(report.findings, []);
});

test('LS/7: requires a detectFn function, never silently no-ops', () => {
  assert.throws(() => analyzeLayerSecrets({ readLayersResult: { layers: [] }, deletedPaths: [], detectFn: null }), TypeError);
});
