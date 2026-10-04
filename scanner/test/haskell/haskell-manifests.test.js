// HS-007: Cabal, Hpack and Stack declared manifests.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  parseVersionRange, versionSatisfies, compareVersions, rangeKind,
  parseCabalFile, parseHpackFile, parseCabalProject, parseStackYaml, parseStackLock,
  analyzeHaskellManifests, analyzeHaskellManifestsInDir,
} from '../../src/language/haskell-manifests.js';

const HEX = 'a'.repeat(64);

const CABAL_LINES = [
  'cabal-version: 3.0',
  'name:          demo',
  'version:       0.1.2.3.4',
  'build-type:    Custom',
  '',
  '-- a comment',
  'flag dev',
  '  description: dev mode',
  '  default: False',
  '  manual: True',
  '',
  'source-repository head',
  '  type: git',
  '  location: https://example.com/demo.git',
  '  tag: 0123456789abcdef0123456789abcdef01234567',
  '',
  'custom-setup',
  '  setup-depends: base >= 4 && < 5, Cabal >= 3.0',
  '',
  'common warnings',
  '  ghc-options: -Wall -fplugin=My.Plugin',
  '  build-depends: containers ^>= 0.6.5',
  '',
  'library',
  '  import: warnings',
  '  build-depends:',
  '      base >= 4.14 && < 4.20',
  '    , text >= 2.0 && < 2.2',
  '    , aeson',
  '  if flag(dev)',
  '    build-depends: pretty-simple',
  '  if flag(ghost)',
  '    build-depends: ghost-pkg',
  '  else',
  '    build-depends: other-pkg == 1.0.*',
  '',
  'test-suite spec',
  '  type: exitcode-stdio-1.0',
  '  main-is: Spec.hs',
  '  build-depends: base, hspec ==2.11.1',
  '',
];
const CABAL = CABAL_LINES.join('\n');
const lineOf = (lines, sub) => lines.findIndex((l) => l.includes(sub)) + 1;
const depOf = (comp, name) => comp.dependencies.find((d) => d.name === name);
const comp = (r, name) => r.components.find((c) => c.name === name);

test('[HS-007.AC01] cabal inventory: bounds, component scope, flags, conditions, repo refs, precise locations', () => {
  const r = parseCabalFile(CABAL, { file: 'demo.cabal' });
  assert.equal(r.package.name, 'demo');
  assert.equal(r.package.version, '0.1.2.3.4');
  assert.deepEqual(r.components.map((c) => `${c.kind}:${c.name}:${c.scope}`).sort(),
    ['custom-setup:setup:setup', 'library:demo:runtime', 'test-suite:spec:test']);

  const lib = comp(r, 'demo');
  const base = depOf(lib, 'base');
  assert.equal(base.declaredRange, '>= 4.14 && < 4.20');
  assert.equal(base.rangeKind, 'bounded');
  assert.equal(base.resolvedVersion, null);
  // Continuation line + leading-comma style keep exact line AND column.
  for (const name of ['base', 'text', 'aeson']) {
    const d = depOf(lib, name);
    const wantLine = CABAL_LINES.findIndex((l, i) => i >= 24 && new RegExp(`(?:^|[ ,])${name}(?:\\s|$)`).test(l)) + 1;
    assert.equal(d.line, wantLine, `${name} line`);
    assert.equal(CABAL_LINES[d.line - 1].slice(d.column, d.column + name.length), name, `${name} column`);
  }
  assert.equal(depOf(lib, 'aeson').declaredRange, null);
  assert.equal(depOf(lib, 'aeson').rangeKind, 'unbounded');

  // Dependency pulled in by `import:` keeps the line of the common stanza.
  const cont = depOf(lib, 'containers');
  assert.equal(cont.via, 'common:warnings');
  assert.equal(cont.line, lineOf(CABAL_LINES, 'containers ^>='));
  assert.equal(cont.scope, 'runtime');

  // Conditionals and flag references.
  assert.deepEqual(depOf(lib, 'pretty-simple').conditions, ['flag(dev)']);
  assert.deepEqual(depOf(lib, 'ghost-pkg').flagRefs, ['ghost']);
  assert.deepEqual(depOf(lib, 'other-pkg').conditions, ['!(flag(ghost))']);
  assert.equal(depOf(lib, 'other-pkg').declaredRange, '== 1.0.*');

  // Component scope.
  const spec = comp(r, 'spec');
  assert.equal(depOf(spec, 'hspec').scope, 'test');
  assert.equal(depOf(spec, 'hspec').exactPin, '2.11.1');
  assert.equal(depOf(spec, 'hspec').resolvedVersion, null);
  const setup = comp(r, 'setup');
  assert.equal(depOf(setup, 'Cabal').scope, 'setup');

  // Flags and source repository.
  assert.deepEqual(r.flags.map((f) => [f.name, f.default, f.manual, f.line]), [['dev', false, true, lineOf(CABAL_LINES, 'flag dev')]]);
  assert.equal(r.sourceRepositories.length, 1);
  const repo = r.sourceRepositories[0];
  assert.equal(repo.type, 'git');
  assert.equal(repo.location, 'https://example.com/demo.git');
  assert.equal(repo.tag, '0123456789abcdef0123456789abcdef01234567');
  assert.equal(repo.pinned, true);
  assert.equal(repo.line, lineOf(CABAL_LINES, 'source-repository head'));

  // Supply-chain surfaces.
  const kinds = r.surfaces.map((s) => s.kind).sort();
  assert.deepEqual(kinds, ['build-type-custom', 'custom-setup', 'ghc-plugin']);
  assert.equal(r.surfaces.find((s) => s.kind === 'ghc-plugin').detail, '-fplugin=My.Plugin');
});

test('[HS-007.AC01] hpack inventory: package-wide, per-component and conditional dependencies', () => {
  const lines = [
    'name: demo',
    'version: 0.1.0.0',
    'github: acme/demo',
    'build-type: Custom',
    'flags:',
    '  dev:',
    '    manual: true',
    '    default: false',
    'custom-setup:',
    '  dependencies:',
    '    - base',
    '    - Cabal >= 3.0',
    'dependencies:',
    '  - base >= 4.14 && < 5',
    '  - text',
    'library:',
    '  source-dirs: src',
    '  ghc-options: -Wall -fplugin=Some.Plugin',
    '  dependencies:',
    '    - containers ^>= 0.6',
    '  when:',
    '    - condition: flag(dev)',
    '      dependencies: pretty-simple',
    '    - condition: flag(nope)',
    '      dependencies: ghost',
    'executables:',
    '  demo-exe:',
    '    main: Main.hs',
    '    dependencies: demo',
    'tests:',
    '  spec:',
    '    main: Spec.hs',
    '    dependencies:',
    '      - hspec == 2.11.1',
    '',
  ];
  const r = parseHpackFile(lines.join('\n'), { file: 'package.yaml' });
  assert.equal(r.incomplete, false);
  assert.equal(r.package.name, 'demo');
  assert.deepEqual(r.packageDependencies.map((d) => [d.name, d.scope]), [['base', 'package'], ['text', 'package']]);
  const pb = r.packageDependencies[0];
  assert.equal(pb.declaredRange, '>= 4.14 && < 5');
  assert.equal(pb.line, lineOf(lines, 'base >= 4.14'), 'package-wide base is not confused with custom-setup base');
  assert.equal(pb.resolvedVersion, null);

  const lib = comp(r, 'demo');
  assert.equal(lib.kind, 'library');
  assert.equal(depOf(lib, 'containers').line, lineOf(lines, 'containers ^>='));
  assert.deepEqual(depOf(lib, 'pretty-simple').conditions, ['flag(dev)']);
  assert.equal(depOf(comp(r, 'demo-exe'), 'demo').scope, 'runtime');
  assert.equal(depOf(comp(r, 'spec'), 'hspec').scope, 'test');
  assert.equal(depOf(comp(r, 'spec'), 'hspec').exactPin, '2.11.1');
  assert.equal(depOf(comp(r, 'setup'), 'Cabal').scope, 'setup');
  assert.deepEqual(r.flags.map((f) => [f.name, f.default, f.manual]), [['dev', false, true]]);
  assert.equal(r.sourceRepositories[0].location, 'https://github.com/acme/demo');
  assert.deepEqual(r.surfaces.map((s) => s.kind).sort(), ['build-type-custom', 'custom-setup', 'ghc-plugin']);
  assert.deepEqual(r.unknownFlags.map((f) => f.flag), ['nope']);
});

test('[HS-007.AC01] multi-package project is discovered from disk; build/store dirs are not read', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'hs007-'));
  try {
    const w = (rel, text) => { fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true }); fs.writeFileSync(path.join(root, rel), text); };
    w('cabal.project', 'packages:\n  pkg-a/\n  pkg-b/*.cabal\n\nsource-repository-package\n  type: git\n  location: https://example.com/dep.git\n  tag: deadbeefdeadbeef\n  --sha256: ' + HEX + '\n');
    w('pkg-a/pkg-a.cabal', 'name: pkg-a\nversion: 1.0\nlibrary\n  build-depends: base >=4 && <5, pkg-b\n');
    w('pkg-b/pkg-b.cabal', 'name: pkg-b\nversion: 2.0\nlibrary\n  build-depends: base >=4.10\nexecutable pb\n  build-depends: base, pkg-b, optparse-applicative ^>=0.18\n');
    w('dist-newstyle/cache/ghost.cabal', 'name: ghost\nlibrary\n  build-depends: evil\n');
    const r = analyzeHaskellManifestsInDir(root);
    assert.deepEqual(r.packages.map((p) => p.name).sort(), ['pkg-a', 'pkg-b']);
    assert.ok(!r.dependencies.some((d) => d.name === 'evil'));
    const mine = r.dependencies.filter((d) => d.package === 'pkg-b' && d.name === 'base');
    assert.deepEqual(mine.map((d) => [d.component, d.manifest, d.scope]), [['pkg-b', 'pkg-b/pkg-b.cabal', 'runtime'], ['pb', 'pkg-b/pkg-b.cabal', 'runtime']]);
    assert.equal(r.dependencies.find((d) => d.package === 'pkg-a' && d.name === 'pkg-b').line, 4);
    assert.deepEqual(r.projects[0].packages.map((p) => p.pattern), ['pkg-a/', 'pkg-b/*.cabal']);
    const sr = r.sourceRepositories.find((s) => s.source === 'cabal.project');
    assert.equal(sr.location, 'https://example.com/dep.git');
    assert.equal(sr.tag, 'deadbeefdeadbeef');
    assert.equal(sr.sha256, HEX);
    assert.equal(sr.line, 5);
    assert.equal(r.coverage.discovered, 3);
    assert.equal(r.coverage.failed, 0);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('[HS-007.AC02] snapshot selectors are recorded as selectors, never as resolved package sets', () => {
  const lts = parseStackYaml('resolver: lts-22.10\npackages:\n  - .\n', { file: 'stack.yaml' });
  assert.equal(lts.snapshot.kind, 'lts');
  assert.equal(lts.snapshot.selector, 'lts-22.10');
  assert.equal(lts.snapshot.resolved, false);
  assert.equal(lts.snapshot.floating, false);
  assert.deepEqual(lts.packages, ['.']);

  const floating = parseStackYaml('resolver: lts-22\n', { file: 'stack.yaml' });
  assert.equal(floating.snapshot.floating, true);
  assert.ok(floating.diagnostics.some((d) => d.kind === 'floating_snapshot'));

  const url = parseStackYaml('snapshot:\n  url: https://example.com/snap.yaml\n', { file: 'stack.yaml' });
  assert.equal(url.snapshot.kind, 'url');
  assert.equal(url.snapshot.pinnedByHash, false);
  assert.ok(url.diagnostics.some((d) => d.kind === 'unpinned_snapshot_url'));

  const none = parseStackYaml('packages: [.]\n', { file: 'stack.yaml' });
  assert.equal(none.snapshot, null);
  assert.ok(none.diagnostics.some((d) => d.kind === 'missing_snapshot'));

  const lock = parseStackLock([
    'packages:',
    '- completed:',
    '    hackage: acme-1.2.3@sha256:' + HEX + ',1234',
    '    pantry-tree:',
    '      sha256: ' + 'b'.repeat(64),
    '      size: 500',
    '  original:',
    '    hackage: acme-1.2.3',
    'snapshots:',
    '- completed:',
    '    sha256: ' + 'c'.repeat(64),
    '    size: 640',
    '    url: https://raw.githubusercontent.com/commercialhaskell/stackage-snapshots/master/lts/22/10.yaml',
    '  original: lts-22.10',
    '',
  ].join('\n'), { file: 'stack.yaml.lock' });
  assert.equal(lock.packages[0].name, 'acme');
  assert.equal(lock.packages[0].version, '1.2.3');
  assert.equal(lock.packages[0].sha256, HEX);
  assert.equal(lock.packages[0].pantryTree.size, 500);
  assert.equal(lock.snapshots[0].original, 'lts-22.10');
  assert.equal(lock.snapshots[0].sha256, 'c'.repeat(64));
});

test('[HS-007.AC02] stack extra-deps keep hashes, revisions and unpinned sources honestly', () => {
  const r = parseStackYaml([
    'resolver: lts-22.10',
    'extra-deps:',
    '  - acme-1.2.3@sha256:' + HEX + ',1234',
    '  - rev-0.1@rev:2',
    '  - plain-3.4',
    '  - git: https://example.com/g.git',
    '    commit: abc123abc123',
    '  - git: https://example.com/floating.git',
    '  - url: https://example.com/a.tar.gz',
    '',
  ].join('\n'), { file: 'stack.yaml' });
  const by = (n) => r.extraDeps.find((e) => e.name === n || e.locator === n);
  assert.deepEqual([by('acme').version, by('acme').sha256, by('acme').size, by('acme').integrity], ['1.2.3', HEX, 1234, 'sha256']);
  assert.deepEqual([by('rev').revision, by('rev').integrity], [2, 'revision']);
  assert.equal(by('plain').integrity, 'none');
  assert.equal(by('https://example.com/g.git').integrity, 'commit');
  assert.equal(by('acme').line, 3);
  const unpinned = r.diagnostics.filter((d) => d.kind === 'unpinned_extra_dep').map((d) => d.message);
  assert.equal(unpinned.length, 2);
  assert.ok(unpinned.some((m) => m.includes('floating.git')));
  assert.ok(unpinned.some((m) => m.includes('a.tar.gz')));
});

test('[HS-007.AC02] freeze pins are locks; bounds and project constraints are not installed versions', () => {
  const freeze = parseCabalProject([
    'active-repositories: hackage.haskell.org:merge',
    'constraints: any.base ==4.18.2.1,',
    '             any.text ==2.0.2,',
    '             any.mtl installed,',
    '             demo +dev -other,',
    '             any.vector >=0.13',
    'index-state: hackage.haskell.org 2024-01-01T00:00:00Z',
    '',
  ].join('\n'), { file: 'cabal.project.freeze' });
  assert.equal(freeze.kind, 'cabal-freeze');
  assert.deepEqual(freeze.lockedPackages.map((l) => [l.name, l.version]), [['base', '4.18.2.1'], ['text', '2.0.2'], ['mtl', null]]);
  assert.equal(freeze.lockedPackages[2].installed, true);
  assert.deepEqual(freeze.flagSettings.map((f) => [f.package, f.name, f.value]), [['demo', 'dev', true], ['demo', 'other', false]]);
  assert.equal(freeze.indexState, 'hackage.haskell.org 2024-01-01T00:00:00Z');
  assert.ok(!freeze.lockedPackages.some((l) => l.name === 'vector'), 'a >= bound is not a lock');

  const project = parseCabalProject('constraints: text ==2.0.2, aeson >=2 && <2.3\nallow-newer: base\n', { file: 'cabal.project' });
  assert.equal(project.kind, 'cabal-project');
  assert.deepEqual(project.lockedPackages, [], 'a project constraint is a declaration, not a resolution');
  assert.equal(project.allowRelaxations[0].target, 'base');

  const r = analyzeHaskellManifests([{ path: 'demo.cabal', text: CABAL }]);
  assert.ok(r.dependencies.length > 5);
  assert.ok(r.dependencies.every((d) => d.resolvedVersion === null));
  assert.deepEqual(r.lockedPackages, []);
});

test('[HS-007.AC02] unknown flags are reported for cabal conditions, stack and project settings', () => {
  const cabal = parseCabalFile(CABAL, { file: 'demo.cabal' });
  assert.deepEqual(cabal.unknownFlags.map((f) => f.flag), ['ghost']);
  assert.equal(cabal.unknownFlags[0].line, lineOf(CABAL_LINES, 'if flag(ghost)'));
  assert.ok(cabal.diagnostics.some((d) => d.kind === 'unknown_flag' && d.flag === 'ghost'));
  assert.ok(!cabal.diagnostics.some((d) => d.kind === 'unknown_flag' && d.flag === 'dev'));

  const r = analyzeHaskellManifests([
    { path: 'demo.cabal', text: 'name: demo\nflag dev\n  default: False\nlibrary\n  build-depends: base\n' },
    { path: 'stack.yaml', text: 'resolver: lts-22.10\nflags:\n  demo:\n    dev: true\n    missing: true\n  elsewhere:\n    x: true\n' },
    { path: 'cabal.project', text: 'packages: .\npackage demo\n  flags: +dev +nonesuch\n' },
  ]);
  const unknown = r.diagnostics.filter((d) => d.kind === 'unknown_flag').map((d) => `${d.package}:${d.flag}`).sort();
  assert.deepEqual(unknown, ['demo:missing', 'demo:nonesuch']);
  const elsewhere = r.flagSettings.find((s) => s.package === 'elsewhere');
  assert.equal(elsewhere.verified, false, 'a flag on a package we did not parse is unverified, not unknown');
});

test('[HS-007.AC02] import overrides: unread, remote and conflicting imports are disclosed', () => {
  const unread = parseCabalProject('import: shared.config\nconstraints: foo ==1.0\n', { file: 'cabal.project' });
  assert.equal(unread.imports[0].resolved, false);
  assert.ok(unread.diagnostics.some((d) => d.kind === 'unresolved_import'));

  const remote = parseCabalProject('import: https://example.com/cabal.config\n', { file: 'cabal.project' });
  assert.ok(remote.diagnostics.some((d) => d.kind === 'remote_import_not_fetched'));
  assert.ok(remote.surfaces.some((s) => s.kind === 'remote-import'));

  const files = { 'shared.config': 'constraints: foo ==2.0, bar >=1\n' };
  const merged = parseCabalProject('constraints: foo ==1.0\nimport: shared.config\n', { file: 'cabal.project', readFile: (p) => files[p] ?? null });
  assert.equal(merged.imports[0].resolved, true);
  assert.ok(merged.diagnostics.some((d) => d.kind === 'import_override' && d.name === 'foo'));
  assert.deepEqual(merged.constraints.filter((c) => c.name === 'bar').map((c) => c.importedFrom), ['shared.config']);

  const cyc = { 'a.config': 'import: b.config\n', 'b.config': 'import: a.config\n' };
  const cycle = parseCabalProject('import: a.config\n', { file: 'cabal.project', readFile: (p) => cyc[p] ?? null });
  assert.ok(cycle.diagnostics.some((d) => d.kind === 'import_cycle' || d.kind === 'budget_exceeded'));

  const escape = parseCabalProject('import: ../outside.config\n', { file: 'cabal.project', readFile: () => 'constraints: x ==1\n' });
  assert.ok(escape.diagnostics.some((d) => d.kind === 'import_outside_root'));
  assert.equal(escape.constraints.length, 0);
});

test('[HS-007.AC02] mismatched Hpack and generated cabal metadata are reported', () => {
  const pyaml = 'name: demo\nversion: 0.2.0.0\ndependencies:\n  - base\n  - text\nlibrary: {}\n';
  const gen = [
    '-- This file has been generated from package.yaml by hpack version 0.36.0.',
    '--',
    '-- see: https://github.com/sol/hpack',
    '',
    'name:           demo',
    'version:        0.1.0.0',
    'build-type:     Simple',
    '',
    'library',
    '  build-depends:',
    '      aeson',
    '    , base',
    '',
  ].join('\n');
  const r = analyzeHaskellManifests([{ path: 'demo.cabal', text: gen }, { path: 'package.yaml', text: pyaml }]);
  const mism = r.diagnostics.filter((d) => d.kind === 'hpack_cabal_mismatch');
  assert.deepEqual(mism.map((d) => d.field).sort(), ['dependencies', 'version']);
  const dep = mism.find((d) => d.field === 'dependencies');
  assert.deepEqual(dep.onlyInHpack, ['text']);
  assert.deepEqual(dep.onlyInCabal, ['aeson']);
  const cabalDeps = r.dependencies.filter((d) => d.manifestType === 'cabal');
  assert.ok(cabalDeps.every((d) => d.provenance === 'hpack-generated' && d.shadowedBy === 'package.yaml'));
  assert.equal(r.packages[0].provenance.generatedBy, 'hpack');

  const hand = analyzeHaskellManifests([{ path: 'demo.cabal', text: 'name: demo\nlibrary\n  build-depends: base\n' }, { path: 'package.yaml', text: pyaml }]);
  assert.ok(hand.diagnostics.some((d) => d.kind === 'cabal_not_hpack_generated'));
  assert.equal(hand.dependencies.find((d) => d.manifestType === 'cabal').provenance, 'hand-written');

  const orphan = analyzeHaskellManifests([{ path: 'demo.cabal', text: gen }]);
  assert.ok(orphan.diagnostics.some((d) => d.kind === 'generated_cabal_source_missing'));

  const stackLock = analyzeHaskellManifests([
    { path: 'stack.yaml', text: 'resolver: lts-22.10\nextra-deps:\n  - acme-1.2.4\n' },
    { path: 'stack.yaml.lock', text: 'packages:\n- completed:\n    hackage: acme-1.2.3@sha256:' + HEX + ',10\n  original:\n    hackage: acme-1.2.3\nsnapshots: []\n' },
  ]);
  assert.ok(stackLock.diagnostics.some((d) => d.kind === 'stack_lock_mismatch'));
});

test('[HS-007.AC03] version ranges: more than three components, trailing zeros, big numbers', () => {
  assert.equal(versionSatisfies('>=1.2.3.4.5', '1.2.3.4.5'), true);
  assert.equal(versionSatisfies('>=1.2.3.4.5', '1.2.3.4.4'), false);
  assert.equal(versionSatisfies('>=1.2.3.4.5', '1.2.3.5'), true);
  assert.equal(versionSatisfies('==1.2.3.4.5', '1.2.3.4.5.0'), true);
  assert.equal(versionSatisfies('==1.0', '1.0.0.0'), true);
  assert.equal(compareVersions('1.10', '1.9'), 1, 'numeric, not lexical');
  assert.equal(compareVersions('1.2.3.4.5', '1.2.3.4.5.0'), 0);
  assert.equal(compareVersions('0.1', '0.1.0.1'), -1);
  assert.equal(versionSatisfies('<99999999999999999999.1', '99999999999999999998'), true);
});

test('[HS-007.AC03] version ranges: conjunction, disjunction, parentheses and caret', () => {
  const r = '>=1 && <2 || >=3 && <4';
  assert.deepEqual(['1', '1.5', '2', '2.5', '3', '3.9', '4'].map((v) => versionSatisfies(r, v)), [true, true, false, false, true, true, false]);
  assert.equal(versionSatisfies('(>=1 && <2) || ==5', '5'), true);
  assert.equal(versionSatisfies('(>=1 && <2) || ==5', '4'), false);
  assert.equal(versionSatisfies('>=1 && (<2 || >=3)', '3.5'), true);
  assert.equal(versionSatisfies('>=1 && (<2 || >=3)', '2.5'), false);

  assert.equal(versionSatisfies('^>=1.2.3', '1.2.3'), true);
  assert.equal(versionSatisfies('^>=1.2.3', '1.2.99'), true);
  assert.equal(versionSatisfies('^>=1.2.3', '1.2.2'), false);
  assert.equal(versionSatisfies('^>=1.2.3', '1.3'), false);
  assert.equal(versionSatisfies('^>=1.2.3.4', '1.2.9.9'), true);
  assert.equal(versionSatisfies('^>=1.2.3.4', '1.3.0.0'), false);
  assert.equal(versionSatisfies('^>=1', '1.0.5'), true);
  assert.equal(versionSatisfies('^>=1', '1.1'), false);
  assert.equal(versionSatisfies('^>= 0.6.5 || ^>= 0.7', '0.7.3'), true);
  assert.equal(versionSatisfies('^>= 0.6.5 || ^>= 0.7', '0.8'), false);
});

test('[HS-007.AC03] version ranges: equality boundaries, wildcards, any/none and range kinds', () => {
  assert.deepEqual(['1.2', '1.2.0', '1.2.9', '1.3', '1.1.9', '1.20'].map((v) => versionSatisfies('==1.2.*', v)), [true, true, true, false, false, false]);
  assert.equal(versionSatisfies('<2', '2.0.0'), false);
  assert.equal(versionSatisfies('<2', '1.99.99'), true);
  assert.equal(versionSatisfies('<=2', '2.0.0.0'), true);
  assert.equal(versionSatisfies('<=2', '2.0.0.1'), false);
  assert.equal(versionSatisfies('>2', '2'), false);
  assert.equal(versionSatisfies('>2', '2.0.0.1'), true);
  assert.equal(versionSatisfies('>=2', '2'), true);
  assert.equal(versionSatisfies('-any', '0'), true);
  assert.equal(versionSatisfies('-none', '0'), false);
  assert.equal(versionSatisfies('', '3.1'), true);
  assert.equal(rangeKind(parseVersionRange('==1.2.3').ast), 'exact');
  assert.equal(rangeKind(parseVersionRange('==1.2.*').ast), 'bounded');
  assert.equal(rangeKind(parseVersionRange('>=1').ast), 'bounded');
  assert.equal(rangeKind(parseVersionRange('-any').ast), 'unbounded');
});

test('[HS-007.AC03] malformed ranges and manifests are bounded and reported, never thrown', () => {
  for (const bad of ['>=', '>= 1 &&', '1.2', '^>= 1.2.*', '>=1 &)', '>=1 >=', '<>1', 'foo']) {
    const r = parseVersionRange(bad);
    assert.equal(r.ok, false, bad);
    assert.equal(typeof r.error, 'string');
  }
  const deep = parseVersionRange('('.repeat(100) + '>=1' + ')'.repeat(100));
  assert.equal(deep.ok, false);
  assert.match(deep.error, /nested too deeply/);
  const long = parseVersionRange('('.repeat(5000) + '>=1' + ')'.repeat(5000));
  assert.equal(long.ok, false);
  assert.match(long.error, /token budget/);
  assert.throws(() => versionSatisfies('>=', '1'), SyntaxError);

  // Malformed dependency bound is preserved, flagged, and does not stop the parse.
  const c = parseCabalFile('name: x\nlibrary\n  build-depends: base >=, text >=2 && <3\n', { file: 'x.cabal' });
  const lib = comp(c, 'x');
  assert.equal(depOf(lib, 'base').rangeKind, 'unparsed');
  assert.equal(depOf(lib, 'base').declaredRange, '>=');
  assert.equal(depOf(lib, 'text').rangeKind, 'bounded');
  assert.ok(c.diagnostics.some((d) => d.kind === 'invalid_version_range' && d.line === 3));

  // Malformed YAML.
  const y = parseHpackFile('name: x\ndependencies: [base, \n  - nope: {', { file: 'package.yaml' });
  assert.equal(y.incomplete, true);
  const yd = y.diagnostics.find((d) => d.kind === 'malformed_yaml');
  assert.equal(yd.severity, 'error');
  assert.ok(yd.message.length <= 200);
  assert.equal(parseStackYaml('resolver: [unclosed', { file: 'stack.yaml' }).incomplete, true);
  assert.equal(parseStackLock('packages: {', { file: 'stack.yaml.lock' }).incomplete, true);
  assert.equal(parseHpackFile('- just\n- a list\n', {}).diagnostics[0].kind, 'malformed_manifest');
  assert.equal(parseHpackFile('', {}).diagnostics[0].kind, 'empty_manifest');
  assert.equal(parseHpackFile(undefined, {}).incomplete, true);

  // Budgets.
  const many = 'name: x\ndependencies:\n' + Array.from({ length: 50 }, (_, i) => `  - pkg${i}`).join('\n') + '\n';
  const b = parseHpackFile(many, { file: 'package.yaml', budgets: { maxNodes: 5 } });
  assert.equal(b.incomplete, true);
  assert.ok(b.diagnostics.some((d) => d.kind === 'budget_exceeded'));
  const big = parseCabalFile('name: x\nlibrary\n  build-depends: ' + 'a, '.repeat(100) + 'b\n', { file: 'x.cabal', budgets: { maxBytes: 50 } });
  assert.ok(big.diagnostics.some((d) => d.kind === 'budget_exceeded'));
  assert.equal(parseHpackFile('x: ' + 'y'.repeat(100), { budgets: { maxBytes: 10 } }).incomplete, true);

  // Garbage in a cabal file, a cyclic common import, and a stack file of the wrong shape.
  const g = parseCabalFile('???\nname x\nlibrary\n  import: loop\ncommon loop\n  import: loop\n  build-depends: base\n', { file: 'g.cabal' });
  assert.ok(g.diagnostics.some((d) => d.kind === 'unrecognized_line'));
  assert.ok(g.diagnostics.some((d) => d.kind === 'import_cycle'));
  assert.ok(parseStackYaml('extra-deps: nope\nresolver: lts-1.1\n', {}).diagnostics.some((d) => d.kind === 'malformed_manifest'));

  // Analysis keeps going when one manifest is broken.
  const mixed = analyzeHaskellManifests([
    { path: 'bad/package.yaml', text: 'name: [' },
    { path: 'ok/ok.cabal', text: 'name: ok\nlibrary\n  build-depends: base\n' },
  ]);
  assert.equal(mixed.coverage.failed, 1);
  assert.equal(mixed.coverage.parsed, 1);
  assert.equal(mixed.dependencies.length, 1);
});
