// CORE-002: unified discovery, file exclusions and incremental invalidation.
// Suite "language-discovery" (HASKELL_NIXOS_FULL_CAPABILITY_PRD.md).
//
// Everything below drives the real walker (readTree), the real scan (runScan),
// the real checkpoint and the real watch filter over temporary trees; nothing
// is derived from fixture names.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { readTree, runScan } from '../../src/runScan.js';
import { shouldScan } from '../../src/engine.js';
import {
  describeSource, buildImportGraph, importClosure, computeLanguageDigests,
  withLanguageClosure, impactedFiles, readExplicitExports,
  isLanguageSource, isLanguageManifest, isLanguageExcludedPath, isExplicitExport,
} from '../../src/language/discovery.js';
import { openCheckpoint, recordFileDone, closeCheckpoint, invalidatedFiles, completedFiles, computeGlobalKey } from '../../src/posture/scan-checkpoint.js';
import { _internals as watch } from '../../src/posture/watch-mode.js';

function tmp() { return fs.mkdtempSync(path.join(os.tmpdir(), 'as-lang-disc-')); }
function mk(root, files) {
  for (const [rel, content] of Object.entries(files)) {
    const abs = path.join(root, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content);
  }
  return root;
}
const rm = (d) => fs.rmSync(d, { recursive: true, force: true });

test('[CORE-002.AC01] root and nested Haskell/Nix sources and manifests are collected by a real scan', async () => {
  const root = mk(tmp(), {
    'app/Main.hs': 'module Main where\nimport Lib.Util\nmain = pure ()\n',
    'src/Lib/Util.lhs': '> module Lib.Util where\n> util = 1\n',
    'pkg/sub/Foo.hsc': '#include <stdio.h>\nmodule Foo where\n',
    'src/Foo.hs-boot': 'module Foo where\n',
    'flake.nix': '{ outputs = { self }: { }; }\n',
    'nix/mod.nix': '{ x = 1; }\n',
    'proj.cabal': 'name: proj\n',
    'cabal.project': 'packages: .\n',
    'pkg/stack.yaml': 'resolver: lts-22.0\n',
    'flake.lock': '{"nodes":{}}\n',
  });
  try {
    const { fileContents, depFileContents } = await readTree(root);
    for (const s of ['app/Main.hs', 'src/Lib/Util.lhs', 'pkg/sub/Foo.hsc', 'src/Foo.hs-boot', 'flake.nix', 'nix/mod.nix']) {
      assert.ok(s in fileContents, `source ${s} must be collected`);
    }
    for (const m of ['proj.cabal', 'cabal.project', 'pkg/stack.yaml', 'flake.lock', 'flake.nix']) {
      assert.ok(m in depFileContents, `manifest ${m} must be collected`);
    }
    const { scan } = await runScan(root);
    assert.ok(scan._scanMeta.filesScanned >= 6, `real scan analysed ${scan._scanMeta.filesScanned} files, expected the 6 Haskell/Nix sources`);
  } finally { rm(root); }
});

test('[CORE-002.AC01] literate, boot and hsc inputs keep declared scope and source locations', () => {
  const lhs = describeSource('src/Foo.lhs', 'Prose here\n> module Foo where\n> import Bar\n\\begin{code}\nx = 1\n\\end{code}\nmore prose\n');
  assert.equal(lhs.kind, 'literate');
  assert.equal(lhs.declaredModule, 'Foo');
  const lines = lhs.code.split('\n');
  assert.equal(lines.length, lhs.lineCount, 'line count preserved');
  assert.equal(lines[0], '');
  assert.equal(lines[1].indexOf('module'), 2, 'column of code preserved past the bird track');
  assert.equal(lines[4], 'x = 1', 'code-block line stays on its original line');
  assert.equal(lines[6], '');

  const boot = describeSource('src/Foo.hs-boot', 'module Foo where\ndata T\n');
  assert.equal(boot.scope, 'boot-interface');
  assert.equal(boot.kind, 'boot');

  const sig = describeSource('src/Sig.hsig', 'signature Sig where\n');
  assert.equal(sig.scope, 'signature');
  assert.equal(sig.declaredModule, 'Sig');

  const hsc = describeSource('src/Foo.hsc', '#include <x.h>\nmodule Foo where\nx = #{size foo}\n');
  assert.equal(hsc.scope, 'preprocessed');
  const h = hsc.code.split('\n');
  assert.equal(h[0], '', 'preprocessor line blanked, not removed');
  assert.equal(h[1], 'module Foo where');
  assert.equal(hsc.declaredModule, 'Foo');
});

test('[CORE-002.AC02] a changed imported module invalidates its importers and nothing else', () => {
  const base = { 'src/A.hs': 'module A where\nimport B\n', 'src/B.hs': 'module B where\nimport C\n', 'src/C.hs': 'module C where\n', 'src/D.hs': 'module D where\n' };
  const before = computeLanguageDigests(base).digests;
  const after = computeLanguageDigests({ ...base, 'src/C.hs': 'module C where\nx = 1\n' }).digests;
  assert.notEqual(before.get('src/A.hs'), after.get('src/A.hs'), 'transitive importer invalidated');
  assert.notEqual(before.get('src/B.hs'), after.get('src/B.hs'));
  assert.notEqual(before.get('src/C.hs'), after.get('src/C.hs'));
  assert.equal(before.get('src/D.hs'), after.get('src/D.hs'), 'unrelated module keeps its digest');
  const hit = impactedFiles(base, {}, ['src/C.hs']);
  assert.deepEqual(hit, ['src/A.hs', 'src/B.hs', 'src/C.hs']);
});

test('[CORE-002.AC02] lockfile, project flag, target configuration and library-model changes invalidate every source', () => {
  const src = { 'src/A.hs': 'module A where\n', 'nix/x.nix': '{ }\n' };
  const digest = (manifests, models = {}) => computeLanguageDigests(src, { manifests, models }).digests;
  const m0 = { 'cabal.project': 'packages: .\n', 'flake.lock': '{"a":1}\n' };
  const d0 = digest(m0);
  for (const [name, m, models] of [
    ['lockfile', { ...m0, 'flake.lock': '{"a":2}\n' }, {}],
    ['project flag', { ...m0, 'cabal.project': 'packages: .\noptimization: 2\n' }, {}],
    ['target configuration', { ...m0, 'proj.cabal': 'executable app\n' }, {}],
    ['explicit export', { ...m0, 'dist-newstyle/cache/plan.json': '{"install-plan":[]}' }, {}],
    ['library model', m0, { 'models/lib.yml': 'sinks: [x]' }],
  ]) {
    const d1 = digest(m, models);
    for (const k of Object.keys(src)) assert.notEqual(d0.get(k), d1.get(k), `${name} change must invalidate ${k}`);
  }
  assert.deepEqual(impactedFiles(src, {}, ['flake.lock']), ['nix/x.nix', 'src/A.hs']);
});

test('[CORE-002.AC02] the real checkpoint re-analyses an importer when an imported module changes', () => {
  const root = tmp();
  try {
    const fc1 = { 'src/A.hs': 'module A where\nimport B\n', 'src/B.hs': 'module B where\n', 'src/C.hs': 'module C where\n' };
    const h1 = openCheckpoint(root, { globalKey: 'k', fileContents: withLanguageClosure(fc1, {}) });
    assert.ok(h1.enabled);
    assert.ok(recordFileDone(h1, 'src/A.hs', { findings: [] }));
    assert.ok(recordFileDone(h1, 'src/C.hs', { findings: [] }));
    closeCheckpoint(h1);
    const fc2 = { ...fc1, 'src/B.hs': 'module B where\nx = 1\n' };
    const h2 = openCheckpoint(root, { globalKey: 'k', fileContents: withLanguageClosure(fc2, {}) });
    const stale = invalidatedFiles(h2).map((x) => x.file);
    const done = completedFiles(h2);
    closeCheckpoint(h2);
    assert.deepEqual(stale, ['src/A.hs']);
    assert.ok(done.has('src/C.hs'));
    assert.ok(!done.has('src/A.hs'));
  } finally { rm(root); }
});

test('[CORE-002.AC02] a lockfile or flag change moves the global key and watch results widen to impacted files', async () => {
  const root = mk(tmp(), {
    'src/A.hs': 'module A where\nimport B\n', 'src/B.hs': 'module B where\n', 'src/C.hs': 'module C where\n',
    'cabal.project.freeze': 'constraints: any.base ==4.18\n',
  });
  try {
    const t1 = await readTree(root);
    assert.ok('cabal.project.freeze' in t1.depFileContents);
    const key = (dep) => computeGlobalKey({ engineVersion: 'x', rulesetVersion: 'y', bundleSha: 'z', depFileContents: dep, env: {} });
    const k1 = key(t1.depFileContents);
    fs.writeFileSync(path.join(root, 'cabal.project.freeze'), 'constraints: any.base ==4.19\n');
    const t2 = await readTree(root);
    assert.notEqual(k1, key(t2.depFileContents));

    const abs = (r) => path.join(root, r);
    const viaImport = await watch.expandChangedBatch(root, [abs('src/B.hs')]);
    assert.deepEqual(viaImport.map((p) => path.relative(root, p)).sort(), ['src/A.hs', 'src/B.hs']);
    const viaLock = await watch.expandChangedBatch(root, [abs('cabal.project.freeze')]);
    const rels = viaLock.map((p) => path.relative(root, p));
    for (const r of ['src/A.hs', 'src/B.hs', 'src/C.hs']) assert.ok(rels.includes(r), `${r} impacted by lockfile`);
    const other = [abs('README.js')];
    assert.equal(await watch.expandChangedBatch(root, other), other, 'non-language batches pass through untouched');

    assert.ok(watch._isScanable('src/A.hs'));
    assert.ok(watch._isScanable('flake.lock'));
    assert.ok(watch._isScanable('dist-newstyle/cache/plan.json'));
    assert.ok(!watch._isScanable('dist-newstyle/build/x/Gen.hs'));
    assert.ok(!watch._isScanable('.stack-work/x/Gen.hs'));
  } finally { rm(root); }
});

test('[CORE-002.AC03] symlink escapes and cycles are never followed and cannot hang a scan', async () => {
  const outside = mk(tmp(), { 'Evil.hs': 'module Evil where\n', 'evil.nix': '{ }\n' });
  const root = mk(tmp(), { 'src/Ok.hs': 'module Ok where\n' });
  try {
    fs.symlinkSync(outside, path.join(root, 'linkdir'));
    fs.symlinkSync(path.join(outside, 'Evil.hs'), path.join(root, 'src/Leak.hs'));
    fs.symlinkSync(root, path.join(root, 'src/loop'));
    fs.symlinkSync('.', path.join(root, 'self'));
    const { fileContents } = await readTree(root);
    assert.deepEqual(Object.keys(fileContents).filter(isLanguageSource).sort(), ['src/Ok.hs']);

    // A Nix path literal that climbs out of the root yields no edge and is reported.
    const nix = { 'a.nix': 'import ../../outside.nix\n', 'sub/b.nix': '{ imports = [ ../a.nix ]; }\n' };
    const { graph, escaped } = buildImportGraph(nix);
    assert.deepEqual(graph.get('a.nix'), []);
    assert.deepEqual(graph.get('sub/b.nix'), ['a.nix']);
    assert.equal(escaped.length, 1);
    assert.equal(escaped[0].file, 'a.nix');
  } finally { rm(root); rm(outside); }
});

test('[CORE-002.AC03] import cycles and long chains terminate within budget and report truncation', () => {
  const cyc = { 'A.hs': 'module A where\nimport B\n', 'B.hs': 'module B where\nimport A\n' };
  const { graph } = buildImportGraph(cyc);
  assert.deepEqual(importClosure(graph, 'A.hs').files, ['B.hs']);
  assert.ok(computeLanguageDigests(cyc).digests.get('A.hs'));

  const chain = {};
  for (let i = 0; i < 30; i++) chain[`M${i}.hs`] = `module M${i} where\n${i < 29 ?`import M${i + 1}\n` : ''}`;
  const g = buildImportGraph(chain).graph;
  const shallow = importClosure(g, 'M0.hs', { maxDepth: 5 });
  assert.equal(shallow.truncated, true);
  assert.equal(shallow.files.length, 5);
  assert.equal(importClosure(g, 'M0.hs').truncated, false);
  const wide = importClosure(g, 'M0.hs', { maxNodes: 3 });
  assert.equal(wide.truncated, true);
});

test('[CORE-002.AC03] explicit exports are read by exact path without scanning build or store directories', async () => {
  const outside = mk(tmp(), { 'secret.json': '{"leak":true}' });
  const root = mk(tmp(), {
    'cabal.project': 'packages: .\n',
    'dist-newstyle/cache/plan.json': '{"install-plan":[]}',
    'dist-newstyle/build/x86_64/Gen.hs': 'module Gen where\n',
    'dist-newstyle/build/x86_64/other.json': '{}',
    '.stack-work/install/Gen2.hs': 'module Gen2 where\n',
    'nix/store/abc-pkg/default.nix': '{ }\n',
    'nix/store/abc-pkg/lib/Lib.hs': 'module Lib where\n',
    'pkg/cabal.project': 'packages: .\n',
    'pkg/dist-newstyle/cache/plan.json': '{"nested":true}',
    'src/Ok.hs': 'module Ok where\n',
  });
  try {
    const { fileContents, depFileContents } = await readTree(root);
    assert.deepEqual(Object.keys(fileContents).filter(isLanguageSource).sort(), ['src/Ok.hs']);
    assert.ok('dist-newstyle/cache/plan.json' in depFileContents, 'root export accepted');
    assert.ok('pkg/dist-newstyle/cache/plan.json' in depFileContents, 'nested project export accepted');
    assert.ok(!('dist-newstyle/build/x86_64/other.json' in depFileContents), 'neighbouring build files are not read');
    for (const k of [...Object.keys(fileContents), ...Object.keys(depFileContents)]) {
      assert.ok(!/Gen2?\.hs|nix\/store/.test(k), `${k} came from a build or store directory`);
    }

    // A symlinked export is refused, not followed out of the root.
    const r2 = mk(tmp(), { 'cabal.project': 'packages: .\n' });
    fs.mkdirSync(path.join(r2, 'dist-newstyle/cache'), { recursive: true });
    fs.symlinkSync(path.join(outside, 'secret.json'), path.join(r2, 'dist-newstyle/cache/plan.json'));
    const res = readExplicitExports(r2, ['cabal.project']);
    assert.deepEqual(res.contents, {});
    assert.deepEqual(res.skipped.map((s) => s.reason), ['symlink']);
    rm(r2);
  } finally { rm(root); rm(outside); }
});

test('[CORE-002.AC03] a huge manifest and ignored paths are skipped without hanging', async () => {
  const root = mk(tmp(), {
    'src/Ok.hs': 'module Ok where\n',
    'test/Spec.hs': 'module Spec where\n',
    'node_modules/pkg/Foo.hs': 'module Foo where\n',
    'vendor/Bar.nix': '{ }\n',
  });
  try {
    fs.writeFileSync(path.join(root, 'flake.lock'), Buffer.alloc(10_000_001, 0x61));
    const t0 = Date.now();
    const { fileContents, depFileContents } = await readTree(root);
    assert.ok(Date.now() - t0 < 30_000, 'walk finished promptly');
    assert.ok(!('flake.lock' in depFileContents), 'manifest over the byte cap is dropped');
    assert.deepEqual(Object.keys(fileContents).filter(isLanguageSource).sort(), ['src/Ok.hs']);
  } finally { rm(root); }
});

test('[CORE-002.AC04] existing discovery and exclusion semantics for other languages are unchanged', async () => {
  const root = mk(tmp(), {
    'src/app.js': 'const a = 1;\n',
    'src/svc.py': 'x = 1\n',
    'main.go': 'package main\n',
    'infra/main.tf': 'resource "a" "b" {}\n',
    'requirements.txt': 'flask==2.0.0\n',
    'package.json': '{"name":"x"}\n',
    'node_modules/dep/index.js': 'x\n',
    'dist/out.js': 'x\n',
    'build/out.js': 'x\n',
    'test/a.js': 'x\n',
    'src/a.test.js': 'x\n',
    'src/min.min.js': 'x\n',
    'notes.md': '# notes\n',
  });
  try {
    const { fileContents, depFileContents } = await readTree(root);
    assert.deepEqual(Object.keys(fileContents).sort(), ['infra/main.tf', 'main.go', 'src/app.js', 'src/svc.py']);
    assert.deepEqual(Object.keys(depFileContents).sort(), ['infra/main.tf', 'package.json', 'requirements.txt']);

    const expected = {
      'src/app.js': true, 'src/svc.py': true, 'main.go': true, 'infra/main.tf': true,
      'node_modules/dep/index.js': false, 'dist/out.js': false, 'test/a.test.js': false,
      'src/a.test.js': false, 'src/x.min.js': false, 'notes.md': false, 'package.json': false,
    };
    for (const [p, want] of Object.entries(expected)) assert.equal(shouldScan(p), want, `shouldScan(${p})`);
    // Haskell/Nix: sources are admitted, generated and store paths are not.
    assert.equal(shouldScan('src/Foo.hs'), true);
    assert.equal(shouldScan('nix/mod.nix'), true);
    assert.equal(shouldScan('dist-newstyle/build/Gen.hs'), false);
    assert.equal(shouldScan('nix/store/x/default.nix'), false);
  } finally { rm(root); }
});

test('[CORE-002.AC04] the one documented fix: build-output directories for these toolchains are pruned from the walk', async () => {
  const root = mk(tmp(), { 'src/app.js': 'x\n', '.direnv/cache.js': 'x\n', '.stack-work/gen.js': 'x\n' });
  try {
    const { fileContents } = await readTree(root);
    assert.deepEqual(Object.keys(fileContents), ['src/app.js']);
    assert.ok(isLanguageExcludedPath('.direnv/a') && isLanguageExcludedPath('x/nix/store/y'));
    assert.ok(isLanguageManifest('proj.cabal') && isExplicitExport('pkg/dist-newstyle/cache/plan.json'));
  } finally { rm(root); }
});
