// Defects the live Hackage feed run (bench/live-feed) left open, each pinned in both directions with synthetic advisories and manifests:
//   1. distinct declared ranges collapsed by package and scope hid a worse use behind a milder one
//   2. cabal.project `constraints:` / `allow-newer` / `allow-older` were not applied to declared ranges
//   3. compiler-provided (GHC boot) packages drowned the dependency findings: one finding per advisory, decided against the project's compiler
// The advisory ids and version numbers are invented for these tests; nothing here reads the bench corpus.
import test from 'node:test';
import assert from 'node:assert/strict';
import { AdvisoryDb, baseRangeForGhc } from '../../src/language/haskell-sca.js';
import { analyzeHaskellSupply, hackageComponents, projectCompiler } from '../../src/language/haskell-supply.js';
import { analyzeHaskellManifests } from '../../src/language/haskell-manifests.js';
import { resolvedHackageComponents } from '../../src/language/resolved-pass.js';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const NOW = Date.parse('2026-10-03T00:00:00Z');
const rec = (id, pkg, events, extra = {}) => ({ id, summary: `synthetic ${id}`, modified: '2026-01-01T00:00:00Z', affected: [{ package: { name: pkg, ecosystem: 'Hackage' }, ranges: [{ type: 'ECOSYSTEM', events }] }], ...extra });
const db = (...records) => new AdvisoryDb({ records, source: 'synthetic', generatedAt: '2026-10-01T00:00:00Z', now: NOW });
const cabal = (name, deps, extra = '') => `cabal-version: 2.4\nname: ${name}\nversion: 0.1\nbuild-type: Simple\n${extra}`.replace(/\n?$/, '\n') + deps;
const exe = (name, buildDepends) => `executable ${name}\n  main-is: Main.hs\n  default-language: Haskell2010\n  build-depends: ${buildDepends}\n`;
const lib = (buildDepends) => `library\n  default-language: Haskell2010\n  build-depends: ${buildDepends}\n`;
const run = (files, database, opts = {}) => analyzeHaskellSupply(files, { db: database, ...opts });
const one = (r, pkg) => r.supplyChain.filter((f) => f.type === 'vulnerable_dep' && f.name === pkg);

// foo is affected in [1.0, 2.0)
const FOO = rec('HSEC-T-0001', 'foo', [{ introduced: '1.0' }, { fixed: '2.0' }]);

// ── 1. worst status per package and scope ───────────────────────────────────────────────────────────────

test('[bounds-1] a worse declared use in a later manifest is reported, not hidden behind the first one', () => {
  for (const order of [['a', 'b'], ['b', 'a']]) {
    const f = {
      'a/a.cabal': cabal('a', exe('a', 'base, foo >=1.2 && <2.5')),     // straddles the fix: possibly-affected
      'b/b.cabal': cabal('b', exe('b', 'base, foo >=1.0 && <1.5')),      // wholly inside [1.0, 2.0): affected
    };
    const files = Object.fromEntries(order.map((k) => [`${k}/${k}.cabal`, f[`${k}/${k}.cabal`]]));
    const hits = one(run(files, db(FOO)), 'foo');
    assert.equal(hits.length, 1, 'one finding per package, scope and advisory');
    assert.equal(hits[0].matchStatus, 'affected', `order ${order}`);
    assert.deepEqual(hits[0].carriedBy.map((c) => c.file), ['b/b.cabal'], 'the component that carries the worst status is listed');
    assert.deepEqual(hits[0].otherUses.map((u) => u.matchStatus), ['possibly-affected'], 'the milder use is recorded, not dropped');
  }
});

test('[bounds-1] negatives: equal statuses list every carrier; one use alone is unchanged; each use keeps its status row', () => {
  const same = { 'a/a.cabal': cabal('a', exe('a', 'foo >=1.2 && <2.5')), 'b/b.cabal': cabal('b', exe('b', 'foo >=1.4 && <3')) };
  const r = run(same, db(FOO));
  const hits = one(r, 'foo');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].matchStatus, 'possibly-affected');
  assert.deepEqual(hits[0].carriedBy.map((c) => c.file).sort(), ['a/a.cabal', 'b/b.cabal']);
  assert.equal(hits[0].otherUses, undefined);
  assert.equal(r.statuses.filter((s) => s.name === 'foo').length, 2, 'both uses keep a status row');
  const solo = one(run({ 'a/a.cabal': same['a/a.cabal'] }, db(FOO)), 'foo');
  assert.equal(solo.length, 1);
  assert.equal(solo[0].matchStatus, 'possibly-affected');
  assert.equal(solo[0].otherUses, undefined);
});

test('[bounds-1] a not-affected use never outranks or replaces an affected one, and scopes stay separate', () => {
  const files = { 'a.cabal': cabal('a', `${exe('a', 'foo >=3.0')}test-suite t\n  type: exitcode-stdio-1.0\n  main-is: T.hs\n  default-language: Haskell2010\n  build-depends: foo >=1.0 && <1.5\n`) };
  const r = run(files, db(FOO));
  const hits = one(r, 'foo');
  assert.equal(hits.length, 1, 'only the test-suite use is affected; the executable use is not');
  assert.equal(hits[0].scope, 'test');
  assert.equal(hits[0].matchStatus, 'affected');
});

// ── 2. cabal.project constraints and relaxations ────────────────────────────────────────────────────────

const proj = (body) => `packages: .\n${body}\n`;
const APP = (deps) => cabal('app', exe('app', deps));

test('[bounds-2] a project constraint that excludes the affected range turns possibly-affected into not-affected, and one that sits inside turns it affected', () => {
  const app = { 'app.cabal': APP('base, foo') };
  const without = one(run(app, db(FOO)), 'foo');
  assert.equal(without[0].matchStatus, 'possibly-affected');
  assert.equal(one(run({ ...app, 'cabal.project': proj('constraints: foo >=2.0') }, db(FOO)), 'foo').length, 0, 'foo >=2.0 leaves no affected version');
  const inside = one(run({ ...app, 'cabal.project': proj('constraints: foo >=1.2 && <1.9') }, db(FOO)), 'foo');
  assert.equal(inside[0].matchStatus, 'affected');
  assert.match(inside[0].matchReason, /narrowed by project constraints: >=1\.2 && <1\.9/);
  assert.deepEqual(inside[0].projectConstraints.map((c) => c.text), ['>=1.2 && <1.9']);
});

test('[bounds-2] constraints intersect with the declared range, they do not replace it', () => {
  // declared foo >=1.0 && <1.5 is affected; a constraint foo >=1.2 keeps it affected, and foo >=1.6 leaves nothing in common with it
  const app = { 'app.cabal': APP('foo >=1.0 && <1.5') };
  assert.equal(one(run({ ...app, 'cabal.project': proj('constraints: foo >=1.2') }, db(FOO)), 'foo')[0].matchStatus, 'affected');
  const none = run({ ...app, 'cabal.project': proj('constraints: foo >=1.6') }, db(FOO));
  assert.equal(one(none, 'foo').length, 1, 'an empty intersection is unknown, never a clean bill');
  assert.equal(one(none, 'foo')[0].matchStatus, 'unknown');
  assert.match(one(none, 'foo')[0].matchReason, /admit no common version/);
});

test('[bounds-2] an exact pin inside the declared range is the resolved version; a pin outside the affected range is not-affected, inside is affected', () => {
  const app = { 'app.cabal': APP('foo >=1.0 && <3') };
  const pinOut = run({ ...app, 'cabal.project': proj('constraints: foo ==2.4') }, db(FOO));
  assert.equal(one(pinOut, 'foo').length, 0);
  assert.ok(pinOut.statuses.some((s) => s.name === 'foo' && s.status === 'not-affected' && s.version === '2.4'));
  const pinIn = one(run({ ...app, 'cabal.project': proj('constraints: foo ==1.3') }, db(FOO)), 'foo');
  assert.equal(pinIn[0].matchStatus, 'affected');
  assert.equal(pinIn[0].version, '1.3');
  assert.equal(pinIn[0].resolution, 'resolved');
  assert.equal(pinIn[0].versionSource.file, 'cabal.project');
});

test('[bounds-2] a constraint is NOT applied when it is conditional, qualified for setup, for a package the project does not govern, or when a freeze already resolved the version', () => {
  const app = { 'app.cabal': APP('foo') };
  const cond = run({ ...app, 'cabal.project': proj('if os(windows)\n  constraints: foo >=2.0') }, db(FOO));
  assert.equal(one(cond, 'foo')[0].matchStatus, 'possibly-affected');
  assert.ok(cond.gaps.some((g) => g.kind === 'conditional-constraints-not-applied'), 'the skipped conditional constraint is disclosed');
  const setup = run({ ...app, 'cabal.project': proj('constraints: setup.foo >=2.0') }, db(FOO));
  assert.equal(one(setup, 'foo')[0].matchStatus, 'possibly-affected');
  // a project in another directory, and a project whose packages: list does not name this manifest
  const elsewhere = run({ 'pkg/app.cabal': APP('foo'), 'other/cabal.project': proj('constraints: foo >=2.0') }, db(FOO));
  assert.equal(one(elsewhere, 'foo')[0].matchStatus, 'possibly-affected');
  const notListed = run({ 'pkg-b/b.cabal': APP('foo'), 'cabal.project': 'packages: pkg-a\nconstraints: foo >=2.0\n' }, db(FOO));
  assert.equal(one(notListed, 'foo')[0].matchStatus, 'possibly-affected');
  const listed = run({ 'pkg-a/a.cabal': APP('foo'), 'cabal.project': 'packages: pkg-a\nconstraints: foo >=2.0\n' }, db(FOO));
  assert.equal(one(listed, 'foo').length, 0, 'the same constraint applies once the package is listed');
  const frozen = run({ ...app, 'cabal.project': proj('constraints: foo >=2.0'), 'cabal.project.freeze': 'constraints: any.foo ==1.3\n' }, db(FOO));
  assert.equal(one(frozen, 'foo')[0].matchStatus, 'affected', 'the freeze file wins: 1.3 is resolved');
  assert.equal(one(frozen, 'foo')[0].resolution, 'resolved');
});

test('[bounds-2] allow-newer widens a declared range (disclosed), allow-older widens the lower end, and neither narrows', () => {
  const BAR = rec('HSEC-T-0002', 'bar', [{ introduced: '3.0' }, { fixed: '4.0' }]);    // affected [3.0, 4.0)
  const app = { 'app.cabal': APP('bar >=1.0 && <2.0') };                                  // as written: cannot reach 3.x
  assert.equal(one(run(app, db(BAR)), 'bar').length, 0);
  const widened = one(run({ ...app, 'cabal.project': proj('allow-newer: bar') }, db(BAR)), 'bar');
  assert.equal(widened[0].matchStatus, 'possibly-affected');
  assert.match(widened[0].matchReason, /widened by allow-newer/);
  assert.deepEqual(widened[0].relaxation.map((r) => r.direction), ['newer']);
  // allow-older on a package whose declared range sits ABOVE the affected range
  const older = { 'app.cabal': APP('bar >=5.0') };
  assert.equal(one(run(older, db(BAR)), 'bar').length, 0);
  assert.equal(one(run({ ...older, 'cabal.project': proj('allow-older: bar') }, db(BAR)), 'bar')[0].matchStatus, 'possibly-affected');
  // allow-newer does not make an already-affected range look milder
  const inside = { 'app.cabal': APP('bar >=3.1 && <3.5') };
  assert.equal(one(run({ ...inside, 'cabal.project': proj('allow-newer: bar') }, db(BAR)), 'bar')[0].matchStatus, 'possibly-affected', 'the upper bound is gone, so versions past the fix are allowed too');
  assert.equal(one(run(inside, db(BAR)), 'bar')[0].matchStatus, 'affected');
});

test('[bounds-2] allow-newer for another package, or allow-older when only the upper end matters, changes nothing; a constraint still narrows a widened range', () => {
  const BAR = rec('HSEC-T-0002', 'bar', [{ introduced: '3.0' }, { fixed: '4.0' }]);
  const app = { 'app.cabal': APP('bar >=1.0 && <2.0') };
  assert.equal(one(run({ ...app, 'cabal.project': proj('allow-newer: other') }, db(BAR)), 'bar').length, 0, 'a relaxation naming another package is not applied');
  assert.equal(one(run({ ...app, 'cabal.project': proj('allow-older: bar') }, db(BAR)), 'bar').length, 0, 'allow-older drops lower bounds only');
  const both = run({ ...app, 'cabal.project': proj('allow-newer: bar\nconstraints: bar <2.5') }, db(BAR));
  assert.equal(one(both, 'bar').length, 0, 'widened to open-ended, then the project constraint caps it below the affected range');
  const all = run({ ...app, 'cabal.project': proj('allow-newer: all') }, db(BAR));
  assert.equal(one(all, 'bar')[0].matchStatus, 'possibly-affected', 'allow-newer: all widens every package');
});

// ── 3. compiler-provided packages ───────────────────────────────────────────────────────────────────────

// base is affected from 3.0.3.1 with no fix; process is affected in [1.0, 1.6.23); base 4.15.0.0 alone has a second advisory
const BASE_UNFIXED = rec('HSEC-T-0010', 'base', [{ introduced: '3.0.3.1' }]);
const BASE_ONE = rec('HSEC-T-0011', 'base', [{ introduced: '4.15.0.0' }, { fixed: '4.15.1.0' }]);
const PROC = rec('HSEC-T-0012', 'process', [{ introduced: '1.0.0.0' }, { fixed: '1.6.23.0' }]);
const BOOT = db(BASE_UNFIXED, BASE_ONE, PROC, FOO);
const MULTI = (project = '') => ({
  'p/p.cabal': cabal('p', `${lib('base >=4.8 && <5, process >=1.6 && <1.7, foo >=1.2 && <2.5')}test-suite t\n  type: exitcode-stdio-1.0\n  main-is: T.hs\n  default-language: Haskell2010\n  build-depends: base >=4.11 && <5, p\n`),
  'q/q.cabal': cabal('q', exe('q', 'base >=4.8 && <5, process')),
  'cabal.project': `packages: p q\n${project}`,
});

test('[ghc-group] boot-library advisories are one finding per advisory with every member kept, and stay out of the dependency count', () => {
  const r = run(MULTI(), BOOT);
  const ghc = r.supplyChain.filter((f) => f.grouped === 'compiler');
  const deps = r.supplyChain.filter((f) => f.type === 'vulnerable_dep' && !f.ghcComponent);
  assert.deepEqual(deps.map((f) => f.name), ['foo']);
  assert.equal(r.counts.dependencyFindings, 1, 'a compiler advisory is not a dependency finding');
  assert.equal(r.counts.compilerAdvisories, ghc.length);
  const byAdv = Object.fromEntries(ghc.map((g) => [g.osvId, g]));
  assert.deepEqual(Object.keys(byAdv).sort(), ['HSEC-T-0010', 'HSEC-T-0011', 'HSEC-T-0012']);
  const baseGroup = byAdv['HSEC-T-0010'];
  assert.equal(baseGroup.name, 'base');
  assert.ok(baseGroup.memberCount >= 2, 'base is used by a library, a test suite and an executable in two packages');
  assert.equal(baseGroup.members.length, baseGroup.memberCount);
  assert.equal(baseGroup.compiler.label, 'unknown compiler');
  assert.match(baseGroup.remediation, /compiler is unknown/);
  assert.match(baseGroup.remediation, /upgrade GHC/i);
  // nothing is dropped: every use still has its own status row and the group's member total equals the compiler findings before grouping
  const ghcRows = r.statuses.filter((s) => s.status.startsWith('ghc-component:'));
  assert.ok(ghcRows.length >= ghc.reduce((n, g) => n + g.memberCount, 0));
  assert.equal(r.counts.compilerMemberRows, ghc.reduce((n, g) => n + g.memberCount, 0));
  assert.ok(ghcRows.every((s) => s.compiler === 'unknown compiler'));
});

test('[ghc-group] a pinned compiler decides whether a base advisory applies; an unpinned one says "unknown compiler" instead of guessing', () => {
  const pinned94 = run(MULTI('with-compiler: ghc-9.4.7\n'), BOOT);
  const adv = (r, id) => r.supplyChain.find((f) => f.grouped === 'compiler' && f.osvId === id);
  assert.equal(adv(pinned94, 'HSEC-T-0010').matchStatus, 'affected', 'base 4.17 is wholly inside an unfixed-from-3.0.3.1 advisory');
  assert.equal(adv(pinned94, 'HSEC-T-0011'), undefined, 'GHC 9.4 ships base 4.17, outside [4.15.0.0, 4.15.1.0): not affected, so no finding (the status rows say so)');
  assert.ok(pinned94.statuses.some((s) => s.name === 'base' && s.advisory === 'HSEC-T-0011' && s.status === 'not-affected'));
  assert.equal(adv(pinned94, 'HSEC-T-0010').compiler.label, 'GHC 9.4.7');
  assert.match(adv(pinned94, 'HSEC-T-0010').remediation, /builds with GHC 9\.4\.7 \(with-compiler\)/);
  assert.match(adv(pinned94, 'HSEC-T-0010').members[0].compilerDerived.rule, /base series of GHC 9\.4\.7/);
  const pinned90 = run(MULTI('with-compiler: ghc-9.0.2\n'), BOOT);
  assert.equal(adv(pinned90, 'HSEC-T-0011').matchStatus, 'possibly-affected', 'GHC 9.0 ships base 4.15.x; the record covers only 4.15.0.0, and the patch level is not known without a plan: possibly-affected, never not-affected');
  const unpinned = run(MULTI(), BOOT);
  assert.equal(adv(unpinned, 'HSEC-T-0011').matchStatus, 'possibly-affected', 'declared >=4.8 && <5 straddles the advisory');
  assert.equal(adv(unpinned, 'HSEC-T-0011').compiler.version, null);
});

test('[ghc-group] a series the table does not know is not guessed', () => {
  assert.equal(baseRangeForGhc('9.6.4'), '>=4.18 && <4.19');
  assert.equal(baseRangeForGhc('9.14.1'), '>=4.22 && <4.23');
  assert.equal(baseRangeForGhc('7.10.3'), null);
  assert.equal(baseRangeForGhc('99.1.0'), null);
  assert.equal(baseRangeForGhc(null), null);
  const r = run(MULTI('with-compiler: ghc-7.10.3\n'), BOOT);
  const g = r.supplyChain.find((f) => f.grouped === 'compiler' && f.osvId === 'HSEC-T-0011');
  assert.equal(g.matchStatus, 'possibly-affected', 'an unlisted series leaves base judged by its declared range');
  assert.equal(g.compiler.label, 'GHC 7.10.3');
  assert.equal(g.members[0].compilerDerived, undefined);
});

test('[ghc-group] projectCompiler: pins, tested-with, conflicts and ambiguity', () => {
  const m = (files) => analyzeHaskellManifests(Object.entries(files).map(([path, text]) => ({ path, text })));
  const comp = (files, resolved = null) => projectCompiler(files, m(files), resolved);
  assert.equal(comp({ 'cabal.project': 'with-compiler: ghc-9.6.4\n', 'a.cabal': APP('base') }).version, '9.6.4');
  assert.equal(comp({ 'cabal.project': 'with-compiler: /opt/ghc/bin/ghc-9.8.2\n', 'a.cabal': APP('base') }).version, '9.8.2');
  assert.equal(comp({ 'cabal.project': 'with-compiler: ghc\n', 'a.cabal': APP('base') }).version, null, 'a bare ghc names no version');
  // tested-with counts only when every item is the same exact version
  assert.equal(comp({ 'a.cabal': cabal('a', exe('a', 'base'), 'tested-with: GHC == 9.6.4\n') }).version, '9.6.4');
  const several = comp({ 'a.cabal': cabal('a', exe('a', 'base'), 'tested-with: GHC == 9.4.7, GHC == 9.6.4\n') });
  assert.equal(several.version, null);
  assert.match(several.reason, /several GHC versions/);
  assert.equal(comp({ 'a.cabal': cabal('a', exe('a', 'base'), 'tested-with: GHC >= 9.4\n') }).version, null, 'a range is not a version');
  // a plan's compiler-id agrees, adds, or conflicts
  const plan = { name: 'ghc', version: '9.6.4' };
  assert.equal(comp({ 'a.cabal': APP('base') }, { compiler: plan }).version, '9.6.4');
  assert.equal(comp({ 'cabal.project': 'with-compiler: ghc-9.6.4\n', 'a.cabal': APP('base') }, { compiler: plan }).basis, 'with-compiler + plan compiler-id');
  const conflict = comp({ 'cabal.project': 'with-compiler: ghc-9.4.7\n', 'a.cabal': APP('base') }, { compiler: plan });
  assert.equal(conflict.version, null);
  assert.match(conflict.reason, /conflicting compilers/);
  assert.equal(comp({ 'a.cabal': APP('base') }).label, 'unknown compiler');
});

test('[ghc-group] a plan supplies the exact boot-library version, and is read from a real plan file', () => {
  const pre = (id, name, version) => ({ type: 'pre-existing', id, 'pkg-name': name, 'pkg-version': version, depends: [] });
  const local = { type: 'configured', id: 'app-0.1-inplace-app', 'pkg-name': 'app', 'pkg-version': '0.1', flags: {}, style: 'local', 'pkg-src': { type: 'local', path: '/proj/.' }, 'component-name': 'exe:app', depends: ['base-4.18.2.1'] };
  const plan = { 'cabal-version': '3.10.2.0', 'compiler-id': 'ghc-9.6.4', os: 'linux', arch: 'x86_64', 'install-plan': [pre('base-4.18.2.1', 'base', '4.18.2.1'), local] };
  const files = { 'app.cabal': APP('base >=4.8 && <5'), 'cabal.project': 'packages: .\n', 'dist-newstyle/cache/plan.json': JSON.stringify(plan) };
  const resolved = resolvedHackageComponents(files);
  assert.deepEqual(resolved.bootLibraries.map((b) => `${b.name}@${b.version}`), ['base@4.18.2.1']);
  assert.equal(resolved.compiler.version, '9.6.4');
  const r = run(files, db(BASE_UNFIXED, BASE_ONE), { resolved });
  const g = r.supplyChain.find((f) => f.grouped === 'compiler');
  assert.equal(g.osvId, 'HSEC-T-0010');
  assert.equal(g.members[0].version, '4.18.2.1');
  assert.equal(g.members[0].matchStatus, 'affected');
  assert.equal(g.compiler.label, 'GHC 9.6.4');
  assert.equal(r.supplyChain.find((f) => f.osvId === 'HSEC-T-0011'), undefined, 'base 4.18.2.1 is outside [4.15.0.0, 4.15.1.0)');
});

test('[bounds-regression] hackageComponents keeps its one-per-package-and-scope inventory while exposing every distinct use', () => {
  const files = { 'a/a.cabal': cabal('a', exe('a', 'foo >=1.2 && <2.5')), 'b/b.cabal': cabal('b', exe('b', 'foo >=1.0 && <1.5')), 'c/c.cabal': cabal('c', exe('c', 'foo >=1.0 && <1.5')) };
  const hc = hackageComponents(files);
  assert.equal(hc.components.filter((c) => c.name === 'foo').length, 1);
  const uses = hc.uses.filter((c) => c.name === 'foo');
  assert.equal(uses.length, 2, 'identical effective ranges merge');
  assert.deepEqual(uses.find((c) => c.declaredRange === '>=1.0 && <1.5').carriers.map((c) => c.file).sort(), ['b/b.cabal', 'c/c.cabal']);
});

// ── 4. blast-radius text for a dependency advisory ──────────────────────────────────────────────────────

test('[blast-text] a Hackage advisory finding (no `vuln` field) gets a truthful narrative, never "undefined on ..."', async () => {
  const { enrichWithBlastRadius } = await import('../../src/posture/blast-radius.js');
  const root = mkdtempSync(join(tmpdir(), 'agsec-blast-'));
  const hackage = { type: 'vulnerable_dep', ecosystem: 'hackage', name: 'foo', version: '1.3', osvId: 'HSEC-T-0001', severity: 'high', file: 'app.cabal', line: 12 };
  const lineless = { type: 'vulnerable_dep', ecosystem: 'hackage', name: 'bar', osvId: 'HSEC-T-0002', severity: 'high' };
  const named = { type: 'vulnerable_dep', name: 'baz', severity: 'high', file: 'x.cabal', line: 3 };
  const scan = { supplyChain: [hackage, lineless, named] };
  enrichWithBlastRadius(scan, root);
  for (const f of scan.supplyChain) assert.doesNotMatch(f.blastRadius.narrative, /undefined/, f.blastRadius.narrative);
  assert.match(hackage.blastRadius.narrative, /^Advisory HSEC-T-0001 in foo 1\.3 on `app\.cabal:12` /);
  assert.match(lineless.blastRadius.narrative, /^Advisory HSEC-T-0002 in bar could /, 'no file, so no location clause');
  assert.match(named.blastRadius.narrative, /^Vulnerable dependency baz on `x\.cabal:3` /);
  assert.equal(hackage.vuln, undefined, 'the narrative builds its own label; the finding (and its identity) is not given a vuln field');
});

test('[blast-text] a finding that has a vuln keeps it verbatim', async () => {
  const { enrichWithBlastRadius } = await import('../../src/posture/blast-radius.js');
  const root = mkdtempSync(join(tmpdir(), 'agsec-blast-'));
  const sast = { id: 's1', severity: 'high', vuln: 'SQL injection', cwe: 'CWE-89', file: 'a.js', line: 4 };
  enrichWithBlastRadius({ findings: [sast] }, root);
  assert.match(sast.blastRadius.narrative, /^SQL injection on `a\.js:4` /);
});

// ── 5. the live feed is fetched before the expensive passes ─────────────────────────────────────────────

test('[feed-order] the Hackage feed lookup runs before the npm OSV check, i.e. early in the scan, and still covers the project', async () => {
  const { runScan } = await import('../../src/runScan.js');
  const proj = mkdtempSync(join(tmpdir(), 'agsec-order-proj-'));
  writeFileSync(join(proj, 'app.cabal'), cabal('app', exe('app', 'base, foo >=1.2 && <2.5')));
  writeFileSync(join(proj, 'Main.hs'), 'module Main where\nmain :: IO ()\nmain = putStrLn "hi"\n');
  writeFileSync(join(proj, 'package.json'), JSON.stringify({ name: 'x', version: '1.0.0', dependencies: { [`agsec-order-probe-${process.pid}-${Date.now()}`]: '1.2.3' } }));   // a name no disk cache can hold, so the npm check really queries
  const xdg = mkdtempSync(join(tmpdir(), 'agsec-order-xdg-'));
  const calls = [];
  const json = (obj) => ({ status: 200, ok: true, text: async () => JSON.stringify(obj), json: async () => obj });
  const fake = async (url, init = {}) => {
    const u = String(url);
    if (!/^https:\/\/api\.osv\.dev\//.test(u)) return { status: 404, ok: false, text: async () => '', json: async () => ({}) };
    if (u.endsWith('/v1/querybatch')) {
      const { queries } = JSON.parse(init.body);
      for (const q of queries) calls.push(q.package.ecosystem);
      return json({ results: queries.map((q) => ({ vulns: q.package.ecosystem === 'Hackage' && q.package.name === 'foo' ? [{ id: FOO.id, modified: FOO.modified }] : [] })) });
    }
    if (u.endsWith(`/v1/vulns/${FOO.id}`)) return json(FOO);
    return json({});
  };
  const saved = { fetch: globalThis.fetch, xdg: process.env.XDG_CONFIG_HOME, live: process.env.AGENTIC_SECURITY_HACKAGE_ADVISORIES_LIVE, off: process.env.AGENTIC_SECURITY_OFFLINE };
  process.env.XDG_CONFIG_HOME = xdg;
  delete process.env.AGENTIC_SECURITY_OFFLINE;
  process.env.AGENTIC_SECURITY_HACKAGE_ADVISORIES_LIVE = '1';
  globalThis.fetch = fake;
  let scan;
  try { scan = (await runScan(proj, {})).scan; } finally {
    globalThis.fetch = saved.fetch;
    for (const [k, v] of [['XDG_CONFIG_HOME', saved.xdg], ['AGENTIC_SECURITY_HACKAGE_ADVISORIES_LIVE', saved.live], ['AGENTIC_SECURITY_OFFLINE', saved.off]]) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  }
  assert.ok(calls.includes('Hackage'), `the Hackage feed was queried: ${calls}`);
  const firstOther = calls.findIndex((e) => e !== 'Hackage');
  assert.notEqual(firstOther, -1, `the npm check must have queried, or this test proves nothing: ${calls}`);
  assert.ok(calls.indexOf('Hackage') < firstOther, `Hackage before the npm check: ${calls}`);
  assert.ok((scan.supplyChain || []).some((f) => f.ecosystem === 'hackage' && f.name === 'foo' && f.osvId === FOO.id), 'results are unchanged: the finding is still produced');
});
