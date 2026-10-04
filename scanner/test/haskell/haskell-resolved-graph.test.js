// HS-008: resolved Haskell dependencies and graph scopes.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { analyzeHaskellManifests } from '../../src/language/haskell-manifests.js';
import { buildResolvedGraph, analyzeResolvedHaskell, linkModulesToPackages } from '../../src/language/haskell-resolved-graph.js';

const CABAL = [
  'cabal-version: 3.0',
  'name:          demo',
  'version:       0.1.0.0',
  'build-type:    Custom',
  '',
  'flag dev',
  '  default: False',
  '  manual: True',
  '',
  'custom-setup',
  '  setup-depends: base, Cabal >= 3.0',
  '',
  'library',
  '  build-depends:',
  '      base >= 4.14 && < 4.20',
  '    , text >= 2.0 && < 2.2',
  '    , aeson == 2.1.*',
  '',
  'test-suite spec',
  '  type: exitcode-stdio-1.0',
  '  main-is: Spec.hs',
  '  build-depends: base, demo, hspec ==2.11.1',
  '',
].join('\n');
const PROJECT = 'packages: .\nwith-compiler: ghc-9.4.7\n';
const FREEZE = 'constraints: aeson ==2.1.2.1,\n             text ==2.0.2\n';

const manifests = (extra = []) => analyzeHaskellManifests([
  { path: 'demo.cabal', text: CABAL },
  { path: 'cabal.project', text: PROJECT },
  ...extra,
]);

const pre = (id, name, version, depends = []) => ({ type: 'pre-existing', id, 'pkg-name': name, 'pkg-version': version, depends });
const hackage = (id, name, version, depends, flags = {}) => ({
  type: 'configured', id, 'pkg-name': name, 'pkg-version': version, flags, style: 'global',
  'pkg-src': { type: 'repo-tar', repo: { type: 'secure-repo', uri: 'http://hackage.haskell.org/' } },
  'pkg-src-sha256': 'b'.repeat(64), 'component-name': 'lib', depends,
});
const local = (id, component, depends, flags = { dev: false }, extra = {}) => ({
  type: 'configured', id, 'pkg-name': 'demo', 'pkg-version': '0.1.0.0', flags, style: 'local',
  'pkg-src': { type: 'local', path: '/proj/.' }, 'component-name': component, depends, ...extra,
});

function goodPlan(over = {}) {
  return {
    'cabal-version': '3.10.2.0', 'compiler-id': 'ghc-9.4.7', os: 'linux', arch: 'x86_64',
    'install-plan': [
      pre('ghc-prim-0.9.1', 'ghc-prim', '0.9.1'),
      pre('base-4.17.2.1', 'base', '4.17.2.1', ['ghc-prim-0.9.1']),
      pre('text-2.0.2', 'text', '2.0.2', ['base-4.17.2.1']),
      pre('Cabal-3.8.1.0', 'Cabal', '3.8.1.0', ['base-4.17.2.1']),
      hackage('th-abstraction-0.5.0.0-def', 'th-abstraction', '0.5.0.0', ['base-4.17.2.1']),
      hackage('aeson-2.1.2.1-abc', 'aeson', '2.1.2.1', ['base-4.17.2.1', 'text-2.0.2', 'th-abstraction-0.5.0.0-def'], { 'ordered-keymap': true }),
      hackage('aeson-2.1.2.1-xyz', 'aeson', '2.1.2.1', ['base-4.17.2.1'], { 'ordered-keymap': false }),
      hackage('hspec-2.11.1-ggg', 'hspec', '2.11.1', ['base-4.17.2.1']),
      local('demo-0.1.0.0-inplace', 'lib', ['aeson-2.1.2.1-abc', 'base-4.17.2.1', 'text-2.0.2']),
      local('demo-0.1.0.0-inplace-spec', 'test:spec', ['base-4.17.2.1', 'demo-0.1.0.0-inplace', 'hspec-2.11.1-ggg']),
      local('demo-0.1.0.0-setup', 'setup', ['Cabal-3.8.1.0', 'base-4.17.2.1'], {}, { style: 'global' }),
    ],
    ...over,
  };
}
const withUnits = (fn) => { const p = goodPlan(); p['install-plan'] = fn(p['install-plan']); return p; };
const unit = (g, id) => g.units.find((u) => u.id === id);
const edgeSet = (g, from) => g.edges.filter((e) => e.from === from).map((e) => `${e.kind}:${e.to}`).sort();

test('[HS-008.AC01] cabal plan: exact labelled units, edges, scopes, distinct unit ids and transitive deps', () => {
  const g = buildResolvedGraph({ manifests: manifests(), plan: goodPlan() });
  assert.equal(g.source, 'cabal-plan');
  assert.equal(g.graphAvailable, true);
  assert.equal(g.freshness.status, 'fresh', JSON.stringify(g.freshness.reasons));
  assert.deepEqual(g.compiler, { id: 'ghc-9.4.7', name: 'ghc', version: '9.4.7' });
  assert.equal(g.units.length, 11);

  // Local packages are local, never downloaded Hackage packages.
  for (const id of ['demo-0.1.0.0-inplace', 'demo-0.1.0.0-inplace-spec', 'demo-0.1.0.0-setup']) assert.equal(unit(g, id).origin, 'local', id);
  assert.equal(unit(g, 'aeson-2.1.2.1-abc').origin, 'hackage');
  assert.equal(unit(g, 'th-abstraction-0.5.0.0-def').origin, 'hackage');
  // Compiler/boot packages are preserved and labelled.
  assert.equal(unit(g, 'base-4.17.2.1').origin, 'compiler');
  assert.equal(unit(g, 'base-4.17.2.1').boot, true);
  assert.equal(unit(g, 'aeson-2.1.2.1-abc').boot, false);

  // Distinct units for one package under different flags.
  const aesons = g.units.filter((u) => u.name === 'aeson');
  assert.equal(aesons.length, 2);
  assert.deepEqual(aesons.map((u) => u.flags['ordered-keymap']).sort(), [false, true]);

  // Exact edges, including transitive ones.
  assert.deepEqual(edgeSet(g, 'demo-0.1.0.0-inplace'), ['depends:aeson-2.1.2.1-abc', 'depends:base-4.17.2.1', 'depends:text-2.0.2']);
  assert.deepEqual(edgeSet(g, 'aeson-2.1.2.1-abc'), ['depends:base-4.17.2.1', 'depends:text-2.0.2', 'depends:th-abstraction-0.5.0.0-def']);
  assert.deepEqual(edgeSet(g, 'th-abstraction-0.5.0.0-def'), ['depends:base-4.17.2.1']);
  assert.deepEqual(edgeSet(g, 'base-4.17.2.1'), ['depends:ghc-prim-0.9.1']);
  // lib 3, aeson-abc 3, aeson-xyz 1, th-abstraction 1, hspec 1, text 1, base 1, Cabal 1, spec 3, setup 2
  assert.equal(g.edges.length, 17);

  // Scopes: runtime / test / setup, propagated transitively; an unreachable variant has none.
  // The library is a runtime root and is also in the test closure (the spec depends on it).
  assert.deepEqual(unit(g, 'demo-0.1.0.0-inplace').scopes, ['runtime', 'test']);
  assert.deepEqual(unit(g, 'demo-0.1.0.0-inplace-spec').scopes, ['test']);
  assert.deepEqual(unit(g, 'demo-0.1.0.0-setup').scopes, ['setup']);
  assert.deepEqual(unit(g, 'th-abstraction-0.5.0.0-def').scopes, ['runtime', 'test']);
  assert.deepEqual(unit(g, 'hspec-2.11.1-ggg').scopes, ['test']);
  assert.deepEqual(unit(g, 'Cabal-3.8.1.0').scopes, ['setup']);
  assert.deepEqual(unit(g, 'ghc-prim-0.9.1').scopes, ['runtime', 'setup', 'test']);
  assert.deepEqual(unit(g, 'aeson-2.1.2.1-xyz').scopes, []);
  assert.deepEqual(unit(g, 'demo-0.1.0.0-inplace-spec').component, { kind: 'test', name: 'spec' });

  // Declared inventory is joined to the resolved version; bounds stay declarations.
  const decl = (n, scope) => g.declared.find((d) => d.name === n && d.scope === scope);
  assert.equal(decl('aeson', 'runtime').resolvedVersion, '2.1.2.1');
  assert.equal(decl('aeson', 'runtime').declaredRange, '== 2.1.*');
  assert.deepEqual(decl('aeson', 'runtime').resolution.unitIds.sort(), ['aeson-2.1.2.1-abc', 'aeson-2.1.2.1-xyz']);
  assert.equal(decl('base', 'runtime').resolution.origin, 'compiler');
  assert.equal(decl('hspec', 'test').resolvedVersion, '2.11.1');
  assert.equal(g.closure.complete, true);

  // Module -> package links only with verified metadata.
  const links = linkModulesToPackages(g, { 'aeson-2.1.2.1-abc': ['Data.Aeson'] }, ['Data.Aeson', 'Data.Unknown']);
  assert.deepEqual(links[0], { module: 'Data.Aeson', status: 'verified', units: ['aeson-2.1.2.1-abc'], packages: ['aeson'] });
  assert.equal(links[1].status, 'unlinked');
});

test('[HS-008.AC01] stack resolved export: local vs hackage vs boot, edges, scope from envelope', () => {
  const stackManifests = analyzeHaskellManifests([
    { path: 'stack.yaml', text: 'snapshot: lts-22.10\npackages:\n  - .\n' },
    { path: 'package.yaml', text: 'name: demo\nversion: 0.1.0.0\ndependencies:\n  - base\n  - aeson\nlibrary: {}\n' },
  ]);
  const exp = {
    snapshot: 'lts-22.10', compiler: 'ghc-9.6.4', scope: 'runtime',
    packages: [
      { name: 'demo', version: '0.1.0.0', dependencies: ['base', 'aeson'] },
      { name: 'aeson', version: '2.1.2.1', location: { type: 'hackage', url: 'https://hackage.haskell.org/package/aeson-2.1.2.1' }, dependencies: ['base', 'th-abstraction'] },
      { name: 'th-abstraction', version: '0.5.0.0', location: { type: 'hackage' }, dependencies: ['base'] },
      { name: 'base', version: '4.18.2.0', dependencies: ['ghc-prim'] },
      { name: 'ghc-prim', version: '0.10.0', dependencies: [] },
    ],
  };
  const g = buildResolvedGraph({ manifests: stackManifests, stackExport: exp });
  assert.equal(g.source, 'stack-export');
  assert.equal(g.freshness.status, 'fresh', JSON.stringify(g.freshness.reasons));
  const u = (n) => g.units.find((x) => x.name === n);
  assert.equal(u('demo').origin, 'local');
  assert.equal(u('aeson').origin, 'hackage');
  assert.equal(u('base').origin, 'compiler');
  assert.equal(u('base').boot, true);
  assert.deepEqual(u('aeson').scopes, ['runtime']);
  assert.deepEqual(edgeSet(g, 'aeson-2.1.2.1'), ['depends:base-4.18.2.0', 'depends:th-abstraction-0.5.0.0']);
  assert.deepEqual(edgeSet(g, 'demo-0.1.0.0'), ['depends:aeson-2.1.2.1', 'depends:base-4.18.2.0']);
  assert.equal(g.closure.complete, true);
  assert.equal(g.declared.find((d) => d.name === 'aeson').resolvedVersion, '2.1.2.1');
});

test('[HS-008.AC02] a plan for a different compiler, flags, manifest or target is stale and downgraded', () => {
  const variants = {
    compiler_mismatch: [{ plan: goodPlan({ 'compiler-id': 'ghc-9.6.4' }) }],
    flags_mismatch: [{ plan: withUnits((l) => l.map((u) => (u.id === 'demo-0.1.0.0-inplace' ? { ...u, flags: { dev: true } } : u))) }],
    local_package_missing: [{ plan: withUnits((l) => l.filter((u) => u['pkg-name'] !== 'demo')) }],
    declared_dependency_missing: [{ plan: withUnits((l) => l.filter((u) => u['pkg-name'] !== 'text' && !(u.depends || []).includes('text-2.0.2')).map((u) => ({ ...u, depends: (u.depends || []).filter((d) => d !== 'text-2.0.2') }))) }],
    bounds_violated: [{ plan: withUnits((l) => l.map((u) => (u['pkg-name'] === 'aeson' ? { ...u, 'pkg-version': '2.2.0.0' } : u))) }],
    local_version_mismatch: [{ plan: withUnits((l) => l.map((u) => (u['pkg-name'] === 'demo' ? { ...u, 'pkg-version': '0.2.0.0' } : u))) }],
    target_missing: [{ plan: goodPlan(), expected: { targets: ['demo:exe:demo-app'] } }],
    plan_older_than_manifest: [{ plan: goodPlan(), expected: { planMtimeMs: 1000, manifestMtimeMs: 2000 } }],
    platform_mismatch: [{ plan: goodPlan(), expected: { os: 'osx' } }],
  };
  for (const [reason, [v]] of Object.entries(variants)) {
    const g = buildResolvedGraph({ manifests: manifests(), plan: v.plan, expected: v.expected });
    assert.equal(g.freshness.status, 'stale', reason);
    assert.ok(g.freshness.reasons.some((r) => r.kind === reason), `${reason}: ${JSON.stringify(g.freshness.reasons.map((r) => r.kind))}`);
    assert.equal(g.closure.complete, false, reason);
    assert.ok(g.gaps.some((x) => x.kind === 'stale_resolved_data'), reason);
    // Downgrade: no declared dependency borrows a version from the stale plan.
    assert.ok(g.declared.length > 0, reason);
    for (const d of g.declared) { assert.equal(d.resolvedVersion, null, `${reason}:${d.name}`); assert.equal(d.resolution.reason, 'stale_resolved_data'); }
  }
  // rejectStale drops the graph entirely.
  const rej = buildResolvedGraph({ manifests: manifests(), plan: goodPlan({ 'compiler-id': 'ghc-9.6.4' }), rejectStale: true });
  assert.equal(rej.units, null);
  assert.equal(rej.edges, null);
  assert.equal(rej.graphAvailable, false);
  assert.equal(rej.closure.reason, 'rejected_stale');

  // A fresh plan with the same input is not marked stale (the checks do not just always fire).
  assert.equal(buildResolvedGraph({ manifests: manifests(), plan: goodPlan() }).freshness.status, 'fresh');

  // Project-level flag setting that disagrees with the plan.
  const flagged = analyzeHaskellManifests([
    { path: 'demo.cabal', text: CABAL }, { path: 'cabal.project', text: `${PROJECT}flags: +dev\n` },
  ]);
  const gf = buildResolvedGraph({ manifests: flagged, plan: goodPlan() });
  assert.equal(gf.freshness.status, 'stale');
  assert.ok(gf.freshness.reasons.some((r) => r.kind === 'flags_mismatch' && r.flag === 'dev'));
});

test('[HS-008.AC02] freeze or lock alone never claims a complete closure; unlabelled or mismatched stack export is not fresh', () => {
  const frozen = manifests([{ path: 'cabal.project.freeze', text: FREEZE }]);
  assert.ok(frozen.lockedPackages.length >= 2);
  const g = buildResolvedGraph({ manifests: frozen });
  assert.equal(g.closure.complete, false);
  assert.equal(g.closure.reason, 'lock_only');
  assert.equal(g.units, null);
  assert.equal(g.edges, null);
  assert.ok(g.gaps.some((x) => x.kind === 'lock_is_not_closure'));
  const aeson = g.declared.find((d) => d.name === 'aeson');
  assert.equal(aeson.lockedVersion, '2.1.2.1');
  assert.equal(aeson.resolvedVersion, null);

  const lockText = 'packages:\n- completed:\n    hackage: aeson-2.1.2.1@sha256:' + 'a'.repeat(64) + ',1234\n    pantry-tree:\n      sha256: ' + 'c'.repeat(64) + '\n      size: 10\n  original:\n    hackage: aeson-2.1.2.1\nsnapshots: []\n';
  const stackM = analyzeHaskellManifests([
    { path: 'stack.yaml', text: 'snapshot: lts-22.10\npackages:\n  - .\n' },
    { path: 'package.yaml', text: 'name: demo\nversion: 0.1.0.0\ndependencies:\n  - aeson\n' },
    { path: 'stack.yaml.lock', text: lockText },
  ]);
  const gl = buildResolvedGraph({ manifests: stackM });
  assert.equal(gl.closure.complete, false);
  assert.equal(gl.closure.reason, 'lock_only');
  assert.equal(gl.declared.find((d) => d.name === 'aeson').resolvedVersion, null);

  const entries = [
    { name: 'demo', version: '0.1.0.0', dependencies: ['aeson'] },
    { name: 'aeson', version: '2.1.2.1', location: { type: 'hackage' }, dependencies: [] },
  ];
  // Bare array: cannot be matched to stack.yaml -> unverified, no complete claim.
  const bare = buildResolvedGraph({ manifests: stackM, stackExport: entries });
  assert.equal(bare.freshness.status, 'unverified');
  assert.equal(bare.closure.complete, false);
  assert.equal(bare.declared.find((d) => d.name === 'aeson').resolvedVersion, null);
  // Envelope for another snapshot: stale.
  const other = buildResolvedGraph({ manifests: stackM, stackExport: { snapshot: 'lts-21.0', compiler: 'ghc-9.4.7', packages: entries } });
  assert.equal(other.freshness.status, 'stale');
  assert.ok(other.freshness.reasons.some((r) => r.kind === 'snapshot_mismatch'));
  assert.equal(other.closure.complete, false);
  // Extra-dep pin disagreeing with the export.
  const pinned = analyzeHaskellManifests([
    { path: 'stack.yaml', text: 'snapshot: lts-22.10\npackages:\n  - .\nextra-deps:\n  - aeson-2.0.0.0\n' },
    { path: 'package.yaml', text: 'name: demo\nversion: 0.1.0.0\n' },
  ]);
  const gp = buildResolvedGraph({ manifests: pinned, stackExport: { snapshot: 'lts-22.10', packages: entries } });
  assert.ok(gp.freshness.reasons.some((r) => r.kind === 'extra_dep_mismatch'));
  assert.equal(gp.freshness.status, 'stale');
});

test('[HS-008.AC03] missing resolved data keeps declared inventory with unresolved versions and an explicit gap', () => {
  const m = manifests();
  const g = buildResolvedGraph({ manifests: m });
  assert.equal(g.graphAvailable, false);
  assert.equal(g.units, null, 'unknown graph is null, never an empty list');
  assert.equal(g.edges, null);
  assert.equal(g.closure.complete, false);
  assert.equal(g.closure.reason, 'no_resolved_data');
  assert.ok(g.gaps.some((x) => x.kind === 'no_resolved_data' && /Nothing was fetched/.test(x.message)));
  const names = g.declared.map((d) => `${d.scope}:${d.name}`).sort();
  assert.deepEqual(names, [...m.dependencies.map((d) => `${d.scope}:${d.name}`)].sort());
  assert.ok(g.declared.length >= 7);
  for (const d of g.declared) {
    assert.equal(d.resolvedVersion, null, d.name);
    assert.equal(d.resolution.status, 'unresolved');
    assert.equal(d.resolution.reason, 'no_resolved_data');
  }
  assert.equal(g.declared.find((d) => d.name === 'aeson').declaredRange, '== 2.1.*');
});

test('[HS-008.AC03] malformed, partial and dangling plans disclose gaps instead of reporting zero dependencies', () => {
  for (const bad of [{}, { 'install-plan': 'nope' }, []]) {
    const g = buildResolvedGraph({ manifests: manifests(), plan: bad });
    assert.equal(g.graphAvailable, false);
    assert.equal(g.units, null);
    assert.equal(g.edges, null);
    assert.ok(g.gaps.some((x) => x.kind === 'malformed_plan'));
    assert.equal(g.closure.complete, false);
    assert.ok(g.declared.length >= 7);
    assert.ok(g.declared.every((d) => d.resolvedVersion === null));
  }

  // A unit whose dependency is absent: the edge is a gap, not an invented node and not silently dropped.
  const dangling = withUnits((l) => [...l, hackage('lens-5.2-qqq', 'lens', '5.2', ['missing-unit-1.0']), { not: 'a unit' }]);
  const g = buildResolvedGraph({ manifests: manifests(), plan: dangling });
  assert.equal(g.graphAvailable, true);
  assert.ok(g.gaps.some((x) => x.kind === 'dangling_edge' && x.from === 'lens-5.2-qqq' && x.to === 'missing-unit-1.0'));
  assert.ok(g.gaps.some((x) => x.kind === 'malformed_unit'));
  assert.equal(g.units.some((u) => u.id === 'missing-unit-1.0'), false);
  assert.equal(g.closure.complete, false);
  assert.equal(g.closure.reason, 'graph_gaps');

  // A declared dependency absent from a fresh-looking graph stays unresolved with a reason.
  const lone = analyzeHaskellManifests([{ path: 'demo.cabal', text: CABAL.replace('aeson == 2.1.*', 'aeson == 2.1.*\n    , zlib') }, { path: 'cabal.project', text: PROJECT }]);
  const gz = buildResolvedGraph({ manifests: lone, plan: goodPlan() });
  const zlib = gz.declared.find((d) => d.name === 'zlib');
  assert.equal(zlib.resolvedVersion, null);
  assert.equal(gz.freshness.status, 'stale');
});

test('[HS-008.AC03] directory entry point reads only the explicit plan path and never fetches', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'hs008-'));
  try {
    fs.writeFileSync(path.join(root, 'demo.cabal'), CABAL);
    fs.writeFileSync(path.join(root, 'cabal.project'), PROJECT);
    fs.mkdirSync(path.join(root, 'dist-newstyle', 'cache'), { recursive: true });
    fs.writeFileSync(path.join(root, 'dist-newstyle', 'cache', 'plan.json'), JSON.stringify(goodPlan()));

    // No explicit path: the plan sitting on disk is NOT discovered.
    const none = analyzeResolvedHaskell(root);
    assert.equal(none.graph.units, null);
    assert.equal(none.graph.closure.reason, 'no_resolved_data');
    assert.ok(none.manifests.dependencies.length >= 7);

    const ok = analyzeResolvedHaskell(root, { planPath: 'dist-newstyle/cache/plan.json' });
    assert.equal(ok.graph.units.length, 11);
    assert.equal(ok.graph.freshness.status, 'fresh', JSON.stringify(ok.graph.freshness.reasons));
    assert.equal(ok.graph.closure.complete, true);

    const missing = analyzeResolvedHaskell(root, { planPath: 'dist-newstyle/cache/absent.json' });
    assert.equal(missing.graph.units, null);
    assert.ok(missing.graph.gaps.some((x) => x.kind === 'resolved_file_missing'));

    const escaped = analyzeResolvedHaskell(root, { planPath: '../outside.json' });
    assert.equal(escaped.graph.units, null);
    assert.ok(escaped.graph.gaps.some((x) => x.kind === 'path_outside_root'));

    fs.writeFileSync(path.join(root, 'dist-newstyle', 'cache', 'bad.json'), '{not json');
    const bad = analyzeResolvedHaskell(root, { planPath: 'dist-newstyle/cache/bad.json' });
    assert.equal(bad.graph.units, null);
    assert.ok(bad.graph.gaps.some((x) => x.kind === 'malformed_plan'));
    assert.ok(bad.graph.declared.every((d) => d.resolvedVersion === null));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
