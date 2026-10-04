// X-010: SBOM/PBOM, dependency edges and policy/export parity for Hackage and Nix. Tests are tagged [X-010.ACnn].
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { languageBom, genericPurl, purlFromGitHost, purlFromUpstreamUrl } from '../../src/language/bom.js';
import { validateCycloneDX16, validateSPDX23, validatePurl } from '../../src/language/bom-validate.js';
import { toCycloneDX, toSPDX } from '../../src/posture/sbom.js';
import { diffSboms, persistSbom } from '../../src/posture/sbom-diff.js';
import { analyzeHaskellManifests } from '../../src/language/haskell-manifests.js';
import { buildResolvedGraph } from '../../src/language/haskell-resolved-graph.js';
import { importNixClosure } from '../../src/language/nix-closure.js';
import { runFullScan } from '../../src/engine.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CABAL = ['cabal-version: 3.0', 'name: demo', 'version: 0.1.0.0', 'library', '  build-depends:', '      base >= 4.14 && < 4.20', '    , aeson == 2.1.*', 'test-suite spec', '  type: exitcode-stdio-1.0', '  main-is: Spec.hs', '  build-depends: base, demo, hspec ==2.11.1', ''].join('\n');
const PROJECT = 'packages: .\nwith-compiler: ghc-9.4.7\n';
const pre = (id, name, version, depends = []) => ({ type: 'pre-existing', id, 'pkg-name': name, 'pkg-version': version, depends });
const hackage = (id, name, version, depends, flags = {}) => ({ type: 'configured', id, 'pkg-name': name, 'pkg-version': version, flags, style: 'global', 'pkg-src': { type: 'repo-tar', repo: { type: 'secure-repo', uri: 'http://hackage.haskell.org/' } }, 'pkg-src-sha256': 'b'.repeat(64), 'component-name': 'lib', depends });
const local = (id, component, depends) => ({ type: 'configured', id, 'pkg-name': 'demo', 'pkg-version': '0.1.0.0', flags: {}, style: 'local', 'pkg-src': { type: 'local', path: '/proj/.' }, 'component-name': component, depends });
const plan = (aesonVersion = '2.1.2.1') => ({ 'cabal-version': '3.10.2.0', 'compiler-id': 'ghc-9.4.7', os: 'linux', arch: 'x86_64', 'install-plan': [
  pre('base-4.17.2.1', 'base', '4.17.2.1'),
  hackage(`aeson-${aesonVersion}-abc`, 'aeson', aesonVersion, ['base-4.17.2.1'], { 'ordered-keymap': true }),
  hackage(`aeson-${aesonVersion}-xyz`, 'aeson', aesonVersion, ['base-4.17.2.1'], { 'ordered-keymap': false }),
  hackage('hspec-2.11.1-g', 'hspec', '2.11.1', ['base-4.17.2.1']),
  local('demo-0.1.0.0-inplace', 'lib', [`aeson-${aesonVersion}-abc`, 'base-4.17.2.1']),
  local('demo-0.1.0.0-inplace-spec', 'test:spec', ['base-4.17.2.1', 'demo-0.1.0.0-inplace', 'hspec-2.11.1-g']),
] });
const files = { 'demo.cabal': CABAL, 'cabal.project': PROJECT };
const resolved = (v) => buildResolvedGraph({ manifests: analyzeHaskellManifests(Object.entries(files).map(([p, t]) => ({ path: p, text: t }))), plan: plan(v) });

const D = path.join(HERE, '..', 'fixtures', 'nix-closure', 'target-a');
const read = (f) => readFileSync(path.join(D, f), 'utf8');
const LOCK = 'f'.repeat(64);
const prov = (cmd) => ({ tool: 'nix', toolVersion: '2.24.0', command: cmd, target: { system: 'x86_64-linux', installable: '.#myapp' }, revision: { flake: 'abc123' }, flakeLockSha256: LOCK, generatedAt: '2026-10-02T00:00:00Z' });
const closure = () => importNixClosure({ exports: [{ schema: 'nix-path-info-json', text: read('pathinfo.json'), provenance: prov('nix path-info --json --recursive .#myapp') }, { schema: 'nix-derivation-show-json', text: read('drvshow.json'), provenance: prov('nix derivation show --recursive .#myapp') }], expected: { system: 'x86_64-linux', installable: '.#myapp', revision: { flake: 'abc123' }, flakeLockSha256: LOCK }, now: Date.parse('2026-10-03T00:00:00Z') });
const FLAKE = '{ inputs = { nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05"; hs.url = "github:Example/Hs-Lib"; }; outputs = { self, nixpkgs, ... }: { }; }\n';
const LOCKFILE = JSON.stringify({ version: 7, root: 'root', nodes: {
  root: { inputs: { nixpkgs: 'nixpkgs', hs: 'hs' } },
  nixpkgs: { locked: { type: 'github', owner: 'NixOS', repo: 'nixpkgs', rev: 'a'.repeat(40), narHash: 'sha256-AAAA' }, original: { type: 'github', owner: 'NixOS', repo: 'nixpkgs', ref: 'nixos-24.05' } },
  hs: { inputs: { nixpkgs: ['nixpkgs'] }, locked: { type: 'github', owner: 'Example', repo: 'Hs-Lib', rev: 'c'.repeat(40), narHash: 'sha256-BBBB' }, original: { type: 'github', owner: 'Example', repo: 'Hs-Lib' } },
} });
const NIXFILES = { 'flake.nix': FLAKE, 'flake.lock': LOCKFILE, 'configuration.nix': '{ pkgs, ... }: { environment.systemPackages = with pkgs; [ git curl ]; }\n' };

const cdx = (scan) => toCycloneDX(scan, { startedAt: '2026-10-03T00:00:00.000Z', engineVersion: 'test' });
const spdx = (scan) => toSPDX(scan, { startedAt: '2026-10-03T00:00:00.000Z', engineVersion: 'test' });
const refs = (doc) => new Set([...doc.components.map((c) => c['bom-ref']), doc.metadata.component['bom-ref']].filter(Boolean));

test('[X-010.AC01] a resolved Haskell plan yields valid CycloneDX and SPDX whose components and edges match the inventory', () => {
  const bom = languageBom(files, { resolved: resolved('2.1.2.1') });
  const scan = { components: [], supplyChain: [{ type: 'vulnerable_dep', ecosystem: 'hackage', name: 'aeson', version: '2.1.2.1', osvId: 'HSEC-2023-0001', severity: 'medium', cveAliases: ['CVE-2022-3433'] }], languageBom: bom };
  const c = cdx(scan);
  assert.deepEqual(validateCycloneDX16(c).errors, []);
  assert.deepEqual(validateSPDX23(spdx(scan)).errors, []);
  const names = c.components.map((x) => `${x.name}@${x.version}`).sort();
  assert.deepEqual(names, ['aeson@2.1.2.1', 'aeson@2.1.2.1', 'base@4.17.2.1', 'hspec@2.11.1']);
  assert.equal(new Set(c.components.map((x) => x['bom-ref'])).size, 4, 'two flag variants of aeson stay two components');
  assert.equal(c.metadata.component.name, 'demo');
  // edges: the application depends on aeson (runtime) and the test suite's hspec edge is present
  const root = c.dependencies.find((d) => d.ref === c.metadata.component['bom-ref']);
  assert.ok(root && root.dependsOn.length >= 2);
  const aeson = c.components.filter((x) => x.name === 'aeson');
  assert.ok(root.dependsOn.some((r) => aeson.some((a) => a['bom-ref'] === r)));
  // existing component identifiers are referenced by the vulnerability
  assert.ok(c.vulnerabilities[0].affects.every((a) => refs(c).has(a.ref)));
  assert.equal(c.compositions[0].aggregate, 'complete');
  const rel = spdx(scan).relationships;
  assert.ok(rel.some((r) => r.relationshipType === 'DEPENDS_ON'));
  assert.ok(rel.some((r) => r.relationshipType === 'TEST_DEPENDENCY_OF'), 'a test-only dependency keeps its scope in SPDX');
});

test('[X-010.AC01] a Nix closure and flake inputs produce valid documents with reference edges and target provenance', () => {
  const cl = closure();
  assert.equal(cl.status, 'ok');
  const bom = languageBom(NIXFILES, { closure: cl });
  const scan = { components: [], supplyChain: [], languageBom: bom };
  const c = cdx(scan);
  assert.deepEqual(validateCycloneDX16(c).errors, []);
  assert.deepEqual(validateSPDX23(spdx(scan)).errors, []);
  const byName = (n) => c.components.filter((x) => x.name === n);
  assert.ok(byName('curl').length >= 1 && byName('glibc').length >= 1 && byName('nixpkgs').length === 1);
  const pr = (comp, key) => (comp.properties.find((p) => p.name === `agentic-security:${key}`) || {}).value;
  const g = byName('glibc')[0];
  assert.match(pr(g, 'nix:storePath'), /^\/nix\/store\/[0-9a-z]{32}-glibc/);
  assert.equal(pr(g, 'nix:system'), 'x86_64-linux');
  assert.equal(pr(g, 'nix:installable'), '.#myapp');
  const md = Object.fromEntries(c.metadata.properties.map((p) => [p.name.replace('agentic-security:', ''), p.value]));
  assert.equal(md['nix:target.installable'], '.#myapp');
  assert.equal(md['nix:target.system'], 'x86_64-linux');
  assert.equal(md['nix:exactRuntimeClosure'], 'true');
  // reference edges between store outputs exist and every ref resolves
  assert.ok(c.dependencies.some((d) => d.dependsOn.length > 0));
  const nixpkgs = byName('nixpkgs')[0];
  assert.equal(nixpkgs.purl, `pkg:github/nixos/nixpkgs@${'a'.repeat(40)}`);
  assert.equal(nixpkgs.version, 'a'.repeat(40));
});

test('[X-010.AC02] declared ranges, unresolved versions, unknown licenses and input-only inventories are never fabricated', () => {
  const bom = languageBom(files, {});                                  // manifests only: no plan, no freeze
  const scan = { components: [], supplyChain: [], languageBom: bom };
  const c = cdx(scan);
  assert.deepEqual(validateCycloneDX16(c).errors, []);
  // base and aeson are ranges: no version. hspec is an exact pin (==2.11.1), so its version IS stated.
  for (const comp of c.components) {
    const stated = comp.name === 'hspec';
    assert.equal('version' in comp, stated, `${comp.name}: version only where one is stated`);
    assert.equal(/@/.test(comp.purl || ''), stated, `${comp.name}: purl carries @version only when a version is stated`);
    assert.equal('licenses' in comp, false, 'an unknown license is left out, not guessed');
  }
  assert.ok(c.components.find((x) => x.name === 'aeson').properties.some((p) => p.name === 'agentic-security:haskell:declaredRange' && /2\.1/.test(p.value)), 'the declared range is a property, not a version');
  assert.ok(c.compositions.every((x) => x.aggregate === 'incomplete'), 'a declared inventory is never called complete');
  assert.ok(bom.gaps.some((g) => g.kind === 'declared-inventory-only'));
  // a freeze pins aeson, so only aeson gains a version
  const frozen = languageBom({ ...files, 'cabal.project.freeze': 'constraints: aeson ==2.1.2.1\n' }, {});
  const fc = cdx({ components: [], supplyChain: [], languageBom: frozen });
  assert.equal(fc.components.find((x) => x.name === 'aeson').version, '2.1.2.1');
  assert.equal('version' in fc.components.find((x) => x.name === 'base'), false, 'an unpinned range stays versionless');
  assert.ok(fc.compositions.every((x) => x.aggregate === 'incomplete'), 'a freeze file is not a closure');
  // Nix: a lock is inputs, not a closure; a package selector is not a component
  const n = languageBom(NIXFILES, {});
  const nc = cdx({ components: [], supplyChain: [], languageBom: n });
  assert.deepEqual(validateCycloneDX16(nc).errors, []);
  assert.deepEqual(nc.components.map((x) => x.name).sort(), ['hs', 'nixpkgs'], '`git` and `curl` selectors are not components');
  assert.ok(nc.compositions.every((x) => x.aggregate === 'incomplete'));
  assert.ok(n.gaps.some((g) => g.kind === 'inputs-are-not-a-closure'));
  // a stale or missing plan does not claim a closure
  const staleGraph = buildResolvedGraph({ manifests: analyzeHaskellManifests([{ path: 'demo.cabal', text: CABAL.replace('aeson == 2.1.*', 'aeson == 2.1.*, zlib') }, { path: 'cabal.project', text: PROJECT }]), plan: plan() });
  const sb = cdx({ components: [], supplyChain: [], languageBom: languageBom({ 'demo.cabal': CABAL.replace('aeson == 2.1.*', 'aeson == 2.1.*, zlib'), 'cabal.project': PROJECT }, { resolved: staleGraph }) });
  assert.ok(sb.compositions.every((x) => x.aggregate !== 'complete'), 'a stale plan is not a complete closure');
});

test('[X-010.AC03] purls follow the registered type rules and escaping, with a labelled generic fallback and Nix provenance beside identity', () => {
  assert.equal(genericPurl('gtk+3', '1.0+git', { vcs_url: 'git+https://example.test/r.git@abc' }), 'pkg:generic/gtk%2B3@1.0%2Bgit?vcs_url=git%2Bhttps%3A%2F%2Fexample.test%2Fr.git%40abc');
  assert.equal(purlFromGitHost('github', 'NixOS', 'Nixpkgs', 'abc'), 'pkg:github/nixos/nixpkgs@abc');
  assert.equal(purlFromGitHost('sourcehut', 'o', 'r', null), null, 'an unregistered host is not guessed');
  assert.equal(purlFromUpstreamUrl('https://github.com/Foo/Bar/releases/download/v1/x.tar.gz', '1'), 'pkg:github/foo/bar@1');
  assert.equal(purlFromUpstreamUrl('https://example.invalid/x.tar.gz', '1'), null);
  // grammar checks bite
  for (const bad of ['pkg:github/Owner/Repo@1', 'pkg:hackage/a/b@1', 'pkg:generic/x@1?b=1&a=2', 'pkg:generic/x?unknown=1', 'pkg:Hackage/x', 'pkg:generic/x@', 'github/x']) assert.equal(validatePurl(bad).valid, false, bad);
  for (const good of ['pkg:hackage/aeson@2.1.2.1', 'pkg:hackage/text-short', 'pkg:github/nixos/nixpkgs@abc', 'pkg:generic/zlib@1.3?download_url=https%3A%2F%2Fx.test%2Fz.tgz']) assert.equal(validatePurl(good).valid, true, good);
  const cl = closure();
  const bom = languageBom({}, { closure: cl });
  for (const comp of bom.components) assert.equal(validatePurl(comp.purl).valid, true, comp.purl);
  const app = bom.components.find((c) => c.name === 'myapp');
  assert.ok(app, 'the target output is present');
  const basis = (c) => c.properties.find((p) => p.name === 'agentic-security:nix:purlBasis').value;
  assert.equal(basis(app), 'generic-fallback', 'an unrecognised upstream host is a labelled generic identity');
  assert.ok(app.properties.some((p) => p.name === 'agentic-security:nix:storePath'), 'build provenance accompanies the identity');
  // a validated upstream host yields a registered-type purl
  const gh = JSON.parse(JSON.stringify(cl)); const n = gh.nodes.find((x) => x.pname === 'myapp' && x.kind === 'output'); n.upstream = { urls: ['https://github.com/Example/MyApp/archive/v1.2.3.tar.gz'] };
  const up = languageBom({}, { closure: gh }).components.find((c) => c.name === 'myapp');
  assert.equal(up.purl, 'pkg:github/example/myapp@1.2.3');
  assert.equal(basis(up), 'validated-upstream-host');
});

test('[X-010.AC03] resolved builds that differ are never merged, and SBOM deltas follow identity across versions', () => {
  const a = languageBom(files, { resolved: resolved('2.1.2.1') });
  assert.equal(a.components.filter((c) => c.name === 'aeson').length, 2, 'flag variants');
  const b = languageBom(files, { resolved: resolved('2.2.0.0') });
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'x010-')); fs.writeFileSync(path.join(root, 'package.json'), '{}');
  try {
    const before = persistSbom(root, a.components);
    const after = { sha: 'next', components: b.components.map((c) => ({ ecosystem: c.ecosystem, name: c.name, version: c.version, purl: c.purl, identityKey: c.identityKey, bomRef: c.bomRef })) };
    const diff = diffSboms(before, after);
    assert.equal(diff.summary.bumped, 2, 'both aeson variants are version bumps');
    assert.equal(diff.summary.added, 0); assert.equal(diff.summary.removed, 0);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
  // two Nix store outputs with the same name and version but different hashes stay distinct
  const cl = closure(); const twin = JSON.parse(JSON.stringify(cl));
  const z = twin.nodes.find((n) => n.pname === 'zlib' && n.kind === 'output'); const copy = { ...z, id: z.id.replace(/^\/nix\/store\/[0-9a-z]{32}/, '/nix/store/' + 'x'.repeat(32)), hash: 'x'.repeat(32), sameNameDifferentBuild: true };
  twin.nodes.push(copy);
  const bom = languageBom({}, { closure: twin });
  assert.equal(bom.components.filter((c) => c.name === 'zlib').length, 2);
  assert.equal(new Set(bom.components.map((c) => c.bomRef)).size, bom.components.length);
});

test('[X-010.AC03] a real scan exposes the language BOM, license data stays unknown, and the CLI-facing emitters validate', async () => {
  const hs = 'module Main where\nmain :: IO ()\nmain = pure ()\n';
  const s = await runFullScan({ fileContents: { 'Main.hs': hs, 'configuration.nix': NIXFILES['configuration.nix'] }, depFileContents: { 'demo.cabal': CABAL, 'cabal.project': PROJECT, 'cabal.project.freeze': 'constraints: aeson ==2.1.2.1\n', 'flake.nix': FLAKE, 'flake.lock': LOCKFILE }, scanRoot: null });
  assert.ok(s.languageBom, 'the scan carries the language BOM');
  const c = toCycloneDX(s, { startedAt: '2026-10-03T00:00:00.000Z' });
  assert.deepEqual(validateCycloneDX16(c).errors, []);
  assert.deepEqual(validateSPDX23(toSPDX(s, { startedAt: '2026-10-03T00:00:00.000Z' })).errors, []);
  assert.ok(c.components.some((x) => x.purl === 'pkg:hackage/aeson@2.1.2.1'));
  assert.ok(c.components.some((x) => /^pkg:github\/nixos\/nixpkgs@/.test(x.purl || '')));
  assert.ok((s.licenseGraph ? JSON.stringify(s.licenseGraph) : '').indexOf('GPL') < 0, 'no license was invented for a language component');
  for (const comp of c.components.filter((x) => x.purl && /^pkg:(hackage|github)/.test(x.purl))) assert.equal('licenses' in comp, false);
});

test('[X-010.AC01] the validators reject real defects (they are not rubber stamps)', () => {
  const good = cdx({ components: [], supplyChain: [], languageBom: languageBom(files, { resolved: resolved() }) });
  const mut = (f) => { const d = JSON.parse(JSON.stringify(good)); f(d); return validateCycloneDX16(d).valid; };
  assert.equal(mut(() => {}), true);
  assert.equal(mut((d) => { d.components[0]['bom-ref'] = d.components[1]['bom-ref']; }), false, 'duplicate bom-ref');
  assert.equal(mut((d) => { d.dependencies[0].dependsOn.push('ghost'); }), false, 'dangling dependency');
  assert.equal(mut((d) => { d.components[0].scope = 'maybe'; }), false, 'bad scope');
  assert.equal(mut((d) => { d.components[0].version = null; }), false, 'null version');
  assert.equal(mut((d) => { d.components[0].hashes = [{ alg: 'SHA-256', content: 'zz' }]; }), false, 'bad hash');
  assert.equal(mut((d) => { d.compositions[0].aggregate = 'total'; }), false, 'bad aggregate');
  const sp = spdx({ components: [], supplyChain: [], languageBom: languageBom(files, { resolved: resolved() }) });
  const smut = (f) => { const d = JSON.parse(JSON.stringify(sp)); f(d); return validateSPDX23(d).valid; };
  assert.equal(smut(() => {}), true);
  assert.equal(smut((d) => { d.relationships.push({ spdxElementId: 'SPDXRef-Nope', relatedSpdxElement: 'SPDXRef-DOCUMENT', relationshipType: 'DEPENDS_ON' }); }), false);
  assert.equal(smut((d) => { d.packages[0].SPDXID = 'bad id'; }), false);
  assert.equal(smut((d) => { d.packages[0].downloadLocation = ''; }), false);
});

test('[X-010.AC03] the PBOM lists Haskell and Nix fetch and pin facts without fetching anything', async () => {
  const { languagePbom } = await import('../../src/language/bom.js');
  const { toPBOM } = await import('../../src/sast/pipeline.js');
  const proj = 'packages: .\nsource-repository-package\n  type: git\n  location: https://example.test/r.git\n  tag: main\n';
  const all = { ...files, 'cabal.project': proj, ...NIXFILES };
  const lb = languagePbom(all);
  assert.equal(lb.haskell.packages[0].name, 'demo');
  assert.ok(lb.haskell.sourceRepositories.some((r) => r.location.includes('example.test') && r.pinned === false), 'an unpinned source repository is visible');
  assert.deepEqual(lb.nix.inputs.map((i) => i.name).sort(), ['hs', 'nixpkgs']);
  assert.equal(lb.nix.inputs.find((i) => i.name === 'nixpkgs').rev, 'a'.repeat(40));
  assert.equal(lb.nix.closure.complete, false);
  const p = toPBOM({}, { startedAt: '2026-10-03T00:00:00.000Z' }, { languageBuild: lb });
  assert.ok(p.languageBuild && p.languageBuild.nix && p.languageBuild.haskell);
  assert.equal(toPBOM({}, {}, {}).languageBuild, undefined, 'a project with neither language is unchanged');
});
