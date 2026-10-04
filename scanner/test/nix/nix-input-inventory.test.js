// NIX-007: Flake, legacy input and declared package inventory.
// Suite "nix-input-inventory" (HASKELL_NIXOS_FULL_CAPABILITY_PRD.md). Real flake.nix/flake.lock/.nix fixtures
// under test/fixtures/nix-inputs/; labels live in this file.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyzeNixInputs, parseFlakeLock } from '../../src/language/nix-inventory.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const FIX = join(HERE, '..', 'fixtures', 'nix-inputs');
const load = (d) => Object.fromEntries(readdirSync(join(FIX, d)).filter((f) => !f.startsWith('.')).map((f) => [f, readFileSync(join(FIX, d, f), 'utf8')]));
const run = (d) => analyzeNixInputs({ files: load(d) });
const edgeStr = (e) => `${e.from}.${e.name}->${e.to}`;

test('[NIX-007.AC01] nested follows resolve to exact edges with no duplicate or dangling edge', () => {
  const r = run('nested-follows');
  const f = r.flakes[0];
  assert.equal(f.lock.status, 'ok'); assert.equal(f.lock.version, 7);
  const edges = f.graph.edges;
  assert.deepEqual(edges.map(edgeStr).sort(), [
    'flake-utils.systems->systems', 'home-manager.nixpkgs->nixpkgs', 'home-manager.utils->flake-utils',
    'root.flake-utils->flake-utils', 'root.home-manager->home-manager', 'root.legacy-src->legacy-src', 'root.nixpkgs->nixpkgs', 'root.tools->tools',
  ]);
  assert.equal(new Set(edges.map((e) => `${e.from}\u0000${e.name}`)).size, edges.length, 'no duplicate edge');
  assert.ok(edges.every((e) => e.status === 'ok' && e.to), 'no dangling edge');
  const fol = edges.filter((e) => e.via === 'follows');
  assert.deepEqual(fol.map((e) => [e.from, e.name, e.followsPath.join('/')]).sort(), [['home-manager', 'nixpkgs', 'nixpkgs'], ['home-manager', 'utils', 'flake-utils']]);
  assert.deepEqual(f.graph.cycles, []); assert.deepEqual(f.graph.dangling, []); assert.deepEqual(f.graph.orphans, []);
  assert.deepEqual(r.gaps, []);
});

test('[NIX-007.AC01] nonflake and local-path inputs are labelled, with original and locked fetch metadata', () => {
  const f = run('nested-follows').flakes[0];
  const by = Object.fromEntries(f.declared.map((d) => [d.name, d]));
  assert.equal(by['legacy-src'].sourceKind, 'nonflake-source'); assert.equal(by['legacy-src'].flake, false);
  assert.equal(by.nixpkgs.sourceKind, 'flake');
  assert.deepEqual(by.nixpkgs.lockedFetch, { type: 'github', owner: 'NixOS', repo: 'nixpkgs', rev: '3333333333333333333333333333333333333333', narHash: 'sha256-cccccccccccccccccccccccccccccccccccccccccc=', lastModified: 1718100000 });
  assert.deepEqual(by.nixpkgs.originalFetch, { type: 'github', owner: 'NixOS', repo: 'nixpkgs', ref: 'nixos-24.05' });
  assert.equal(by.nixpkgs.resolution, 'locked-rev-and-hash');
  assert.equal(by.tools.resolution, 'local-path');
  assert.ok(by.tools.warnings.some((w) => w.kind === 'local-path'));
  assert.deepEqual(by['home-manager'].nestedFollows.map((n) => n.follows).sort(), ['flake-utils', 'nixpkgs']);
  assert.deepEqual(f.outputs.map((o) => o.kind).sort(), ['devShells', 'nixosConfigurations', 'packages'], 'target output declarations');
});

test('[NIX-007.AC01] missing locks, invalid locks and cycles stay visible', () => {
  const missing = run('missing-lock');
  assert.equal(missing.flakes[0].lock.status, 'missing');
  assert.deepEqual(missing.flakes[0].declared.map((d) => d.status), ['unlocked', 'unlocked']);
  assert.ok(missing.gaps.some((g) => g.kind === 'missing-flake-lock'));
  const invalid = run('invalid-lock');
  assert.equal(invalid.flakes[0].lock.status, 'invalid');
  assert.ok(invalid.flakes[0].lock.error);
  assert.deepEqual(invalid.flakes[0].declared.map((d) => d.status), ['lock-unusable']);
  assert.ok(invalid.gaps.some((g) => g.kind === 'invalid-flake-lock'));
  const cyc = run('cycle');
  const g = cyc.flakes[0].graph;
  assert.deepEqual(g.cycles.sort(), ['root -> a -> b -> a', 'root -> c -> c']);
  assert.deepEqual(g.dangling.map((d) => `${d.from}.${d.name}`).sort(), ['c.missing', 'root.ghost']);
  assert.deepEqual(g.orphans, ['orphan']);
  assert.deepEqual(cyc.gaps.map((x) => x.kind).sort(), ['lock-cycle', 'lock-cycle', 'lock-dangling-edge', 'lock-dangling-edge']);
  assert.ok(cyc.flakes[0].warnings.some((w) => w.kind === 'stale-lock-input' && w.name === 'ghost'), 'lock input no longer declared');
  assert.ok(g.edges.some((e) => e.status === 'dangling') && g.edges.some((e) => e.status === 'ok'));
  // a follows cycle (a.dep -> b, b.dep -> a expressed as follows) does not hang the resolver
  const loop = parseFlakeLock(JSON.stringify({ nodes: { root: { inputs: { a: 'a', b: 'b' } }, a: { inputs: { x: ['b', 'x'] } }, b: { inputs: { x: ['a', 'x'] } } }, root: 'root', version: 7 }));
  assert.ok(loop.cycles.some((c) => /->/.test(c)) && loop.edges.some((e) => e.status === 'cycle'));
  assert.equal(parseFlakeLock('not json').status, 'invalid');
  assert.equal(parseFlakeLock(JSON.stringify({ nodes: {}, root: 'root' })).status, 'invalid');
});

test('[NIX-007.AC02] input, selector and resolved package are labelled separately, and no version is invented', () => {
  const r = run('selectors');
  assert.ok(r.selectors.length >= 8);
  for (const s of r.selectors) {
    assert.equal(s.componentClass, 'selector'); assert.equal(s.kind, 'software-package');
    assert.equal(s.version, null); assert.equal(s.versionResolved, false); assert.equal(s.status, 'selector-only');
    assert.equal(s.providerEvidence.status, 'module-argument', 'pkgs is a module argument: no claim about where it comes from');
  }
  const by = (re) => r.selectors.filter((s) => re.test(s.selector));
  assert.deepEqual(by(/^pkgs\.(git|curl|openssl)$/).map((s) => [s.attr, s.role, s.via]).sort(), [['curl', 'system', 'with pkgs'], ['git', 'system', 'with pkgs'], ['openssl', 'system', 'with pkgs']]);
  assert.equal(by(/htop/)[0].role, 'user'); assert.equal(by(/nginxMainline/)[0].role, 'service');
  assert.equal(by(/cmake/)[0].role, 'build'); assert.equal(by(/zlib/)[0].role, 'build');
  assert.equal(by(/haskellPackages\.aeson/)[0].attr, 'haskellPackages.aeson');
  const classes = new Set(r.components.map((c) => c.componentClass));
  assert.ok(classes.has('selector') && !classes.has('resolved-package'), 'this module never produces a resolved package');
  // a locked nixpkgs does NOT turn a selector into a versioned package
  const withLock = analyzeNixInputs({ files: { ...load('nested-follows'), 'configuration.nix': load('selectors')['configuration.nix'] } });
  const sel = withLock.selectors.find((s) => s.selector === 'pkgs.htop');
  assert.equal(sel.version, null); assert.equal(sel.versionResolved, false);
  assert.equal(sel.providerEvidence.input, 'nixpkgs', 'the candidate provider input is named');
  assert.match(sel.providerEvidence.note, /not claimed/);
});

test('[NIX-007.AC02] a lock graph is never reported as a complete runtime closure', () => {
  for (const d of ['nested-follows', 'selectors', 'legacy']) {
    const r = run(d);
    assert.equal(r.closure.complete, false);
    assert.equal(r.closure.status, 'not-computed');
    assert.match(r.closure.reason, /source inputs and package selectors/);
  }
  const r = run('nested-follows');
  for (const c of r.components.filter((x) => x.componentClass === 'input')) { assert.equal(c.kind, 'source-dependency'); assert.equal(c.versionResolved, false); }
  assert.deepEqual(r.components.filter((c) => c.componentClass === 'input').map((c) => c.name).sort(), ['flake-utils', 'home-manager', 'legacy-src', 'nixpkgs', 'systems', 'tools']);
});

test('[NIX-007.AC03] legacy, unpinned and local-path forms keep their lower resolution and trust warnings', () => {
  const r = run('legacy');
  const by = (k) => r.legacy.filter((l) => l.kind === k);
  assert.deepEqual(by('angle-bracket').map((l) => l.value), ['<nixpkgs>']);
  assert.ok(by('angle-bracket')[0].warnings.some((w) => w.kind === 'nix-path'));
  assert.equal(by('nixPath').length, 2);
  assert.equal(by('channel')[0].resolution, 'floating-channel');
  assert.ok(by('channel')[0].warnings.some((w) => w.kind === 'floating-channel'));
  const tar = by('fetchTarball');
  const floating = tar.find((t) => /nixos-unstable/.test(t.value));
  const pinned = tar.find((t) => /0123456789abcdef/.test(t.value));
  assert.equal(floating.resolution, 'floating-ref'); assert.deepEqual(floating.warnings.map((w) => w.kind).sort(), ['no-integrity', 'unpinned-fetch']);
  assert.equal(pinned.resolution, 'hash-pinned'); assert.deepEqual(pinned.warnings, []);
  assert.equal(by('local-path')[0].resolution, 'absolute-path');
  assert.ok(by('local-path')[0].warnings.some((w) => w.kind === 'local-path'));
  assert.equal(r.flakes.length, 0, 'no flake is forced onto a legacy configuration');
  for (const l of r.legacy) assert.ok(l.file && Number.isInteger(l.line));
});

test('[NIX-007.AC03] the analysis makes no network call and forces no flake evaluation', async () => {
  const real = globalThis.fetch; let calls = 0;
  globalThis.fetch = () => { calls++; throw new Error('network is not allowed'); };
  try {
    run('nested-follows'); run('legacy'); run('missing-lock'); run('cycle');
  } finally { globalThis.fetch = real; }
  assert.equal(calls, 0);
  const src = readFileSync(join(HERE, '..', '..', 'src', 'language', 'nix-inventory.js'), 'utf8');
  assert.ok(!/from 'node:(?:fs|child_process|net|http|https|dgram)'|require\(|\bfetch\(/.test(src), 'no fs, network or process import');
});

test('[NIX-007.AC03] hostile input is bounded and never throws', () => {
  const huge = { nodes: { root: { inputs: {} } }, root: 'root', version: 7 };
  for (let i = 0; i < 30000; i++) huge.nodes[`n${i}`] = {};
  assert.equal(parseFlakeLock(JSON.stringify(huge)).status, 'budget_exceeded');
  const r = analyzeNixInputs({ files: { 'flake.nix': '{ inputs = ', 'flake.lock': '{}', 'x.nix': '{ a = <' } });
  assert.ok(Array.isArray(r.gaps));
  assert.equal(parseFlakeLock(JSON.stringify({ nodes: { root: { inputs: { a: 5 } } }, root: 'root', version: 99 })).versionSupported, false);
});
