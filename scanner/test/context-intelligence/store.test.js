import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { tempProject, cleanup, build } from './helpers.js';
import { persistBuild } from '../../src/context-intelligence/persist.js';
import { loadConfig } from '../../src/context-intelligence/config.js';
import { storeRoot, verifyStoredBundle, listStoredBundles, writeStoreFile, readStoreFile, readManifest } from '../../src/context-intelligence/store.js';

async function stored() {
  const dir = tempProject('js-app');
  const built = await build(dir);
  const res = persistBuild(dir, built, loadConfig(dir).config);
  return { dir, built, res };
}

test('persisted bundles verify and list', async () => {
  const { dir, built, res } = await stored();
  try {
    assert.equal(res.ok, true);
    const listed = listStoredBundles(dir);
    assert.equal(listed.length, built.bundles.filter(b => b.manifest).length);
    for (const b of built.bundles) assert.equal(verifyStoredBundle(dir, b.manifest.contextHash, { fileContents: built.fileContents }).ok, true);
  } finally { cleanup(dir); }
});

test('a tampered package file is detected', async () => {
  const { dir, built } = await stored();
  try {
    const h = built.bundles[0].manifest.contextHash;
    const root = storeRoot(dir);
    const walk = (d) => fs.readdirSync(d, { withFileTypes: true }).flatMap(e => e.isDirectory() ? walk(path.join(d, e.name)) : [path.join(d, e.name)]);
    const pkg = walk(root).find(f => f.includes(h) && !f.endsWith('manifest.json'));
    assert.ok(pkg, 'a package file exists for the bundle');
    fs.appendFileSync(pkg, '\n// injected\n');
    const v = verifyStoredBundle(dir, h, { fileContents: built.fileContents });
    assert.equal(v.ok, false);
  } finally { cleanup(dir); }
});

test('verification fails when the source changed after the bundle was written', async () => {
  const { dir, built } = await stored();
  try {
    const h = built.bundles[0].manifest.contextHash;
    const seg = built.bundles[0].manifest.context.packages[0].segments[0];
    const lines = built.fileContents[seg.file].split('\n');
    lines[seg.startLine - 1] += ' // edited';
    const changed = { ...built.fileContents, [seg.file]: lines.join('\n') };
    assert.equal(verifyStoredBundle(dir, h, { fileContents: changed }).ok, false);
  } finally { cleanup(dir); }
});

test('the store refuses unsafe paths and will not follow a symlink', async () => {
  const { dir } = await stored();
  try {
    assert.equal(writeStoreFile(dir, '../escape.txt', 'x').ok, false);
    assert.equal(writeStoreFile(dir, '/abs.txt', 'x').ok, false);
    const target = path.join(dir, 'outside.txt');
    fs.writeFileSync(target, 'orig');
    fs.symlinkSync(target, path.join(storeRoot(dir), 'link.txt'));
    assert.equal(readStoreFile(dir, 'link.txt').ok, false);
    writeStoreFile(dir, 'link.txt', 'replaced'); // atomic rename replaces the link itself, never writes through it
    assert.equal(fs.readFileSync(target, 'utf8'), 'orig');
    assert.equal(readManifest(dir, '../../etc/passwd').ok, false);
  } finally { cleanup(dir); }
});
