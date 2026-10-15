import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { tempProject, cleanup, build } from './helpers.js';
import { loadHieMetadata, mergeHieIntoGraph, HIE_EXPORT_FILE } from '../../src/context-intelligence/adapters/haskell-hie.js';
import { sha256 } from '../../src/context-intelligence/canonical.js';

function exportFor(dir, built, over = {}) {
  const files = Object.keys(built.fileContents).filter(f => f.endsWith('.hs')).map(f => ({ path: f, sha256: sha256(built.fileContents[f]) }));
  const doc = { schemaVersion: 'hie-export/1', compiler: { name: 'ghc', version: '9.6.0' }, tool: { name: 'fixture', version: '1' }, files, declarations: [], references: [], ...over };
  fs.mkdirSync(path.join(dir, 'hie'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'hie', HIE_EXPORT_FILE), JSON.stringify(doc));
  return doc;
}

test('no directory configured: adapter is off, scan unaffected', () => {
  assert.equal(loadHieMetadata('/nonexistent', null, { fileContents: {} }).status, 'off');
});

test('missing, malformed, wrong-schema and unsafe exports degrade instead of throwing', async () => {
  const dir = tempProject('eval/corpus/c11/a');
  try {
    const built = await build(dir);
    const root = fs.realpathSync(dir);
    assert.equal(loadHieMetadata(root, 'hie', { fileContents: built.fileContents }).reason, 'export-not-found');
    fs.mkdirSync(path.join(dir, 'hie'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'hie', HIE_EXPORT_FILE), '{not json');
    assert.equal(loadHieMetadata(root, 'hie', { fileContents: built.fileContents }).reason, 'invalid-json');
    exportFor(dir, built, { schemaVersion: 'hie-export/9' });
    assert.equal(loadHieMetadata(root, 'hie', { fileContents: built.fileContents }).reason, 'unsupported-schema-version');
    exportFor(dir, built, { files: [{ path: '../../etc/passwd', sha256: 'x' }] });
    assert.equal(loadHieMetadata(root, 'hie', { fileContents: built.fileContents }).reason, 'unsafe-path-in-export');
    assert.equal(loadHieMetadata(root, '../outside', { fileContents: built.fileContents }).status, 'degraded');
  } finally { cleanup(dir); }
});

test('an export built from different source bytes is rejected as a snapshot mismatch', async () => {
  const dir = tempProject('eval/corpus/c11/a');
  try {
    const built = await build(dir);
    const doc = exportFor(dir, built);
    doc.files[0].sha256 = '0'.repeat(64);
    fs.writeFileSync(path.join(dir, 'hie', HIE_EXPORT_FILE), JSON.stringify(doc));
    const r = loadHieMetadata(fs.realpathSync(dir), 'hie', { fileContents: built.fileContents });
    assert.equal(r.status, 'degraded');
    assert.equal(r.reason, 'source-snapshot-mismatch');
  } finally { cleanup(dir); }
});

test('a valid export is imported and reported as an additional, provenance-tagged source; the static graph is not mutated', async () => {
  const dir = tempProject('eval/corpus/c11/a');
  try {
    const built = await build(dir);
    exportFor(dir, built);
    const meta = loadHieMetadata(fs.realpathSync(dir), 'hie', { fileContents: built.fileContents });
    assert.equal(meta.status, 'ok');
    const before = JSON.stringify(built.graph.edges);
    const merged = mergeHieIntoGraph(built.graph, meta, built.fileContents);
    assert.equal(JSON.stringify(built.graph.edges), before, 'input graph untouched');
    assert.deepEqual(merged.semantic.source, ['static-ir', 'hie-import']);
    const degraded = mergeHieIntoGraph(built.graph, { status: 'degraded', reason: 'x', declarations: [], references: [] }, built.fileContents);
    assert.equal(degraded.graph, built.graph);
    assert.equal(degraded.semantic.status, 'degraded');
  } finally { cleanup(dir); }
});
