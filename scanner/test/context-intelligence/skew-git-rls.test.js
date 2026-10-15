import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { tempProject, cleanup, build, byLabel } from './helpers.js';
import { readGitSnapshot } from '../../src/context-intelligence/files.js';
import { loadHieMetadata, HIE_EXPORT_FILE } from '../../src/context-intelligence/adapters/haskell-hie.js';
import { sha256 } from '../../src/context-intelligence/canonical.js';

const git = (dir, ...a) => spawnSync('git', ['-c', 'user.email=t@t', '-c', 'user.name=t', '-c', 'commit.gpgsign=false', ...a], { cwd: dir, encoding: 'utf8' });

test('metadata from a different tool or compiler than it claims is refused, never half-trusted', async () => {
  const dir = tempProject('eval/corpus/c11/a');
  try {
    const built = await build(dir);
    const files = Object.keys(built.fileContents).filter(f => f.endsWith('.hs')).map(f => ({ path: f, sha256: sha256(built.fileContents[f]) }));
    fs.mkdirSync(path.join(dir, 'hie'), { recursive: true });
    const write = (over) => fs.writeFileSync(path.join(dir, 'hie', HIE_EXPORT_FILE), JSON.stringify({ schemaVersion: 'hie-export/1', compiler: { name: 'ghc', version: '9.6.0' }, tool: { name: 'x', version: '1' }, files, declarations: [], references: [], ...over }));
    const root = fs.realpathSync(dir);
    write({ compiler: { name: 'clang', version: '17' } });
    assert.equal(loadHieMetadata(root, 'hie', { fileContents: built.fileContents }).reason, 'compiler-not-identified');
    write({ compiler: { name: 'ghc' } });
    assert.equal(loadHieMetadata(root, 'hie', { fileContents: built.fileContents }).reason, 'compiler-not-identified');
    write({ tool: { name: 'x' } });
    assert.equal(loadHieMetadata(root, 'hie', { fileContents: built.fileContents }).reason, 'tool-not-identified');
    write({ declarations: [{ name: 'main', file: files[0].path, startLine: 1, endLine: 99999 }] });
    assert.equal(loadHieMetadata(root, 'hie', { fileContents: built.fileContents }).reason, 'declaration-span-out-of-range');
    write({});
    assert.equal(loadHieMetadata(root, 'hie', { fileContents: built.fileContents }).status, 'ok');
  } finally { cleanup(dir); }
});

test('git snapshots: a bad or unknown ref is refused, a ref reads committed content not the working tree, a symlink is skipped', () => {
  const dir = tempProject('eval/corpus/c01/b');
  try {
    git(dir, 'init', '-q');
    const outside = path.join(dir, 'target.js');
    fs.writeFileSync(outside, 'module.exports = 1;\n');
    fs.symlinkSync(outside, path.join(dir, 'src', 'link.js'));
    git(dir, 'add', '-A'); assert.equal(git(dir, 'commit', '-qm', 'base').status, 0);
    const app = path.join(dir, 'src', 'app.js');
    fs.writeFileSync(app, fs.readFileSync(app, 'utf8') + '\n// uncommitted edit\n');
    assert.equal(readGitSnapshot(dir, '--upload-pack=x').reason, 'bad-ref');
    assert.equal(readGitSnapshot(dir, 'no-such-ref').reason, 'unknown-ref');
    const snap = readGitSnapshot(dir, 'HEAD');
    assert.equal(snap.ok, true);
    assert.ok(!snap.fileContents['src/app.js'].includes('uncommitted edit'));
    assert.ok(snap.skipped.some(s => s.file === 'src/link.js'));
    assert.match(snap.commit, /^[0-9a-f]{40}$/);
  } finally { cleanup(dir); }
});

test('database-level policy is invisible to static analysis: no scoping in code is reported as not_present, never as safe', async () => {
  const dir = tempProject('eval/corpus/c01/a');
  try {
    const p = path.join(dir, 'src', 'app.js');
    fs.writeFileSync(p, fs.readFileSync(p, 'utf8') + '\n// row level security policies may be enforced by the database\n');
    const built = await build(dir);
    const b = byLabel(built, '/notes/:id');
    assert.equal(b.manifest.protection.ownership.state, 'not_present');
    assert.match(b.manifest.protection.ownership.why, /resolved context is complete and contains no control/);
    assert.ok(!JSON.stringify(b.manifest).match(/"safe"|"secure"/i));
  } finally { cleanup(dir); }
});
