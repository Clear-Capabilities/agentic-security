// NIX-008: Resolved derivation and closure inventory.
// Suite "nix-resolved-closure" (HASKELL_NIXOS_FULL_CAPABILITY_PRD.md). Controlled exports in
// test/fixtures/nix-closure/target-a/ follow the documented tool schemas (see src/language/nix-closure.js).

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { generateKeyPairSync, createSign } from 'node:crypto';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { importNixClosure, parseStorePath, signedBody, detectSchema, CLOSURE_BUDGETS } from '../../src/language/nix-closure.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const SCANNER = join(HERE, '..', '..');
const D = join(HERE, '..', 'fixtures', 'nix-closure', 'target-a');
const read = (f) => readFileSync(join(D, f), 'utf8');
const IDX = JSON.parse(read('_index.json'));
const P = IDX.paths; const DRV = IDX.drvs;
const NAME = Object.fromEntries([...Object.entries(P).map(([k, v]) => [v, k]), ...Object.entries(DRV).map(([k, v]) => [v, `${k}.drv`])]);
NAME[JSON.parse(read('drvshow.json'))[DRV.glibc].outputs.dev.path] = 'glibc_dev';
const NOW = Date.parse('2026-10-03T00:00:00Z');
const LOCK = 'f'.repeat(64);
const prov = (cmd, over = {}) => ({ tool: 'nix', toolVersion: '2.24.0', command: cmd, target: { system: 'x86_64-linux', installable: '.#myapp' }, revision: { flake: 'abc123' }, flakeLockSha256: LOCK, generatedAt: '2026-09-30T00:00:00Z', ...over });
const EXPECTED = { system: 'x86_64-linux', installable: '.#myapp', revision: { flake: 'abc123' }, flakeLockSha256: LOCK };
const PI = (over) => ({ schema: 'nix-path-info-json', text: read('pathinfo.json'), provenance: prov('nix path-info --json --recursive .#myapp', over) });
const DS = (over) => ({ schema: 'nix-derivation-show-json', text: read('drvshow.json'), provenance: prov('nix derivation show --recursive .#myapp', over) });
const imp = (exports, extra = {}) => importNixClosure({ exports, expected: EXPECTED, now: NOW, ...extra });
const byName = (r) => Object.fromEntries(r.nodes.map((n) => [NAME[n.id] || n.id, n]));
const kinds = (r) => r.disclosures.map((d) => d.kind).sort();

test('[NIX-008.AC01] a controlled target export yields the exact runtime closure, build graph and scopes', () => {
  const r = imp([PI(), DS()]);
  assert.equal(r.status, 'ok'); assert.deepEqual(r.disclosures, []);
  assert.equal(r.claims.exactRuntimeClosure, true); assert.equal(r.claims.exactBuildGraph, true); assert.equal(r.claims.exactInventory, true);
  assert.deepEqual(r.roots.map((x) => NAME[x]), ['app']);
  const n = byName(r);
  const scoped = (s) => Object.entries(n).filter(([, v]) => v.kind === 'output' && v.scopes.includes(s)).map(([k]) => k).sort();
  assert.deepEqual(scoped('runtime'), ['app', 'curl_a', 'glibc', 'libfoo', 'zlib'], 'runtime closure = references of the target output');
  assert.deepEqual(Object.entries(n).filter(([, v]) => v.kind === 'output' && v.scopes.includes('build') && !v.scopes.includes('runtime')).map(([k]) => k).sort(), ['app_dev', 'bash', 'cmake', 'curl_b', 'gcc', 'glibc_dev', 'pytest'], 'build-only outputs');
  assert.deepEqual(scoped('test'), ['pytest']);
  assert.deepEqual(Object.entries(n).filter(([, v]) => v.kind === 'source').map(([k]) => k).sort(), ['patch', 'src']);
  assert.ok(n.app_dev && !n.app_dev.scopes.includes('runtime'), 'a dev output is not in the runtime closure unless referenced');
  // exact edges
  const ref = r.edges.filter((e) => e.kind === 'reference').map((e) => `${NAME[e.from]}>${NAME[e.to]}`).sort();
  assert.deepEqual(ref, ['app>curl_a', 'app>glibc', 'app>libfoo', 'curl_a>glibc', 'curl_a>zlib', 'libfoo>glibc', 'libfoo>zlib', 'zlib>glibc']);
  const inp = r.edges.filter((e) => e.kind === 'input-drv' && NAME[e.from] === 'app.drv').map((e) => `${NAME[e.to]}:${e.role}`).sort();
  assert.deepEqual(inp, ['bash.drv:build', 'cmake.drv:build', 'curl_a.drv:build+runtime', 'curl_b.drv:build', 'gcc.drv:build', 'glibc.drv:build', 'libfoo.drv:build+runtime', 'pytest.drv:test']);
  assert.deepEqual(r.edges.filter((e) => e.kind === 'input-src').map((e) => NAME[e.to]).sort(), ['patch', 'src']);
  assert.equal(new Set(r.edges.map((e) => `${e.from}|${e.to}|${e.kind}`)).size, r.edges.length, 'no duplicate edge');
});

test('[NIX-008.AC01] same-name different-build components stay separate, with their own patches and outputs', () => {
  const n = byName(imp([PI(), DS()]));
  assert.notEqual(n.curl_a.id, n.curl_b.id);
  assert.equal(n.curl_a.pname, 'curl'); assert.equal(n.curl_b.pname, 'curl'); assert.equal(n.curl_a.version, n.curl_b.version);
  assert.equal(n.curl_a.sameNameDifferentBuild, true); assert.equal(n.curl_b.sameNameDifferentBuild, true);
  assert.deepEqual(n.curl_a.patches, []);
  assert.deepEqual(n.curl_b.patches.map((p) => p.name), ['curl-fix-for-CVE-2024-2398.patch']);
  assert.ok(n.curl_a.scopes.includes('runtime') && !n.curl_b.scopes.includes('runtime'), 'the patched build is build-only');
  assert.equal(n.app.sameNameDifferentBuild, false, 'out and dev of ONE derivation are one build');
  assert.deepEqual(n.glibc.outputs, [], 'output nodes carry no outputs list; the derivation does');
  const drv = byName(imp([PI(), DS()]))['glibc.drv'];
  assert.deepEqual(drv.outputs.map((o) => o.name).sort(), ['dev', 'out']);
  assert.equal(n.app.upstream.urls[0], 'https://example.invalid/releases/myapp-1.2.3.tar.gz');
  assert.deepEqual(n.app.patches.map((p) => p.name), ['CVE-2024-0001.patch']);
});

test('[NIX-008.AC01] the older array form of path-info and the wrapped derivation form give the same graph', () => {
  const base = imp([PI(), DS()]);
  const arr = imp([{ ...PI(), text: read('pathinfo-array.json') }, DS()]);
  assert.deepEqual(arr.edges, base.edges);
  assert.deepEqual(arr.nodes.map((n) => [n.id, n.scopes]), base.nodes.map((n) => [n.id, n.scopes]));
  // wrapped form: {derivations, version}, paths without /nix/store/, inputs.{drvs,srcs}
  const old = JSON.parse(read('drvshow.json'));
  const strip = (p) => p.replace('/nix/store/', '');
  const derivations = {};
  for (const [k, v] of Object.entries(old)) {
    derivations[strip(k)] = { outputs: Object.fromEntries(Object.entries(v.outputs).map(([n, o]) => [n, { path: strip(o.path) }])), system: v.system, builder: v.builder, args: v.args, env: v.env,
      inputs: { drvs: Object.fromEntries(Object.entries(v.inputDrvs).map(([d, o]) => [strip(d), { outputs: o, dynamicOutputs: {} }])), srcs: v.inputSrcs.map(strip) } };
  }
  const wrapped = imp([PI(), { ...DS(), text: JSON.stringify({ version: 4, derivations }) }]);
  assert.equal(wrapped.claims.exactBuildGraph, true);
  assert.deepEqual(wrapped.edges.filter((e) => e.kind === 'input-drv').length, base.edges.filter((e) => e.kind === 'input-drv').length);
  assert.equal(detectSchema(JSON.parse(read('pathinfo.json'))), 'nix-path-info-json');
  assert.equal(detectSchema(JSON.parse(read('drvshow.json'))), 'nix-derivation-show-json');
  assert.equal(detectSchema(undefined, read('store-query.txt')), 'nix-store-query-text');
});

test('[NIX-008.AC02] a foreign target, foreign revision or stale export is disclosed and removes the exact claim', () => {
  const foreignSys = imp([PI({ target: { system: 'aarch64-linux', installable: '.#myapp' } }), DS()]);
  assert.ok(kinds(foreignSys).includes('foreign-target'));
  const foreignInst = imp([PI({ target: { system: 'x86_64-linux', installable: '.#other' } }), DS()]);
  assert.ok(kinds(foreignInst).includes('foreign-target'));
  const foreignRev = imp([PI({ revision: { flake: 'zzz999' } }), DS()]);
  assert.ok(kinds(foreignRev).includes('foreign-revision'));
  const staleLock = imp([PI({ flakeLockSha256: 'e'.repeat(64) }), DS()]);
  assert.ok(kinds(staleLock).includes('stale-export'));
  const old = imp([PI({ generatedAt: '2025-01-01T00:00:00Z' }), DS()]);
  assert.ok(kinds(old).includes('stale-export'));
  const changed = importNixClosure({ exports: [PI(), DS()], expected: { ...EXPECTED, inputsChangedAtMs: Date.parse('2026-10-01T00:00:00Z') }, now: NOW });
  assert.ok(changed.disclosures.some((d) => d.kind === 'stale-export' && /inputs changed after/.test(d.detail)));
  for (const r of [foreignSys, foreignInst, foreignRev, staleLock, old, changed]) {
    assert.equal(r.claims.exactInventory, false); assert.equal(r.claims.completeness, 'not-claimed');
    assert.ok(r.nodes.length > 0, 'the data is still listed: disclosed, not discarded');
  }
});

test('[NIX-008.AC02] missing provenance, missing metadata and output-only identity never support an exact claim', () => {
  const noProv = imp([{ schema: 'nix-path-info-json', text: read('pathinfo.json') }, { schema: 'nix-derivation-show-json', text: read('drvshow.json') }]);
  assert.ok(kinds(noProv).includes('unverified-provenance')); assert.equal(noProv.claims.exactInventory, false);
  assert.deepEqual(noProv.provenance.map((p) => p.level), ['none', 'none']);
  const wrongTool = imp([PI({ tool: 'sbomnix' }), DS()]);
  assert.ok(wrongTool.disclosures.some((d) => /not a supported source/.test(d.detail)));
  const wrongCmd = imp([PI({ command: 'curl https://example.invalid/closure.json' }), DS()]);
  assert.ok(wrongCmd.disclosures.some((d) => /does not produce/.test(d.detail)));
  // output-only: a bare `nix-store -qR` listing
  const text = importNixClosure({ exports: [{ schema: 'nix-store-query-text', text: read('store-query.txt'), provenance: prov('nix-store --query --requisites /nix/store/x') }], expected: EXPECTED, now: NOW });
  assert.ok(kinds(text).includes('output-only-identity'));
  assert.ok(text.nodes.every((n) => n.identity === 'output-only' && n.versionAuthority === 'inferred-from-store-path'));
  assert.equal(text.claims.exactRuntimeClosure, false);
  // missing metadata: path-info without deriver / without references
  const pi = JSON.parse(read('pathinfo.json'));
  const [k0, k1] = Object.keys(pi);
  delete pi[k0].deriver; delete pi[k1].references;
  const miss = imp([{ ...PI(), text: JSON.stringify(pi) }, DS()]);
  assert.ok(kinds(miss).includes('missing-metadata'));
  assert.ok(miss.nodes.find((n) => n.id === k0).missing.includes('deriver'));
  assert.equal(miss.claims.exactRuntimeClosure, false);
  // a derivation without env is not authoritative
  const dr = JSON.parse(read('drvshow.json')); const dk = Object.keys(dr)[0]; delete dr[dk].env;
  const noEnv = imp([PI(), { ...DS(), text: JSON.stringify(dr) }]);
  assert.equal(noEnv.claims.exactBuildGraph, false);
  assert.equal(noEnv.nodes.find((n) => n.id === dk).identity, 'drv-path-only');
  // an open closure (a referenced path is not in the export)
  const pi2 = JSON.parse(read('pathinfo.json')); delete pi2[P.zlib];
  const open = imp([{ ...PI(), text: JSON.stringify(pi2) }, DS()]);
  assert.ok(kinds(open).includes('open-closure')); assert.equal(open.claims.exactRuntimeClosure, false);
  assert.equal(imp([]).claims.exactInventory, false);
});

test('[NIX-008.AC02] a signed export is attested, a forged one is rejected, an unsigned one fails a signed-only policy', () => {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const pem = publicKey.export({ type: 'spki', format: 'pem' });
  const ex = PI();
  const sig = (e) => { const s = createSign('sha256'); s.update(signedBody(e)); return s.sign(privateKey).toString('base64'); };
  const good = importNixClosure({ exports: [{ ...ex, signature: sig(ex) }, DS()], expected: { ...EXPECTED, publicKeyPem: pem }, now: NOW });
  assert.equal(good.provenance[0].level, 'signed');
  const forged = importNixClosure({ exports: [{ ...ex, text: ex.text.replace('"narSize": 1000', '"narSize": 1001'), signature: sig(ex) }, DS()], expected: { ...EXPECTED, publicKeyPem: pem }, now: NOW });
  assert.ok(kinds(forged).includes('invalid-signature')); assert.equal(forged.claims.exactRuntimeClosure, false);
  const unsigned = importNixClosure({ exports: [PI(), DS()], expected: { ...EXPECTED, requireSigned: true }, now: NOW });
  assert.ok(kinds(unsigned).includes('unsigned')); assert.equal(unsigned.claims.exactInventory, false);
});

test('[NIX-008.AC03] large, cyclic and malformed closures are bounded and never throw', () => {
  const A = '0123456789abcdfghijklmnpqrsvwxyz';
  const hh = (i) => { let s = ''; let x = i + 1; for (let j = 0; j < 32; j++) { s += A[x % 32]; x = Math.floor(x / 32) + j * 7 + 1; } return s; };
  const path = (i) => `/nix/store/${hh(i)}-pkg${i}-1.0`;
  // 3000-node chain with every node also pointing back at node 0 (cycles everywhere)
  const big = {};
  for (let i = 0; i < 3000; i++) big[path(i)] = { narHash: 'sha256-x', references: [path(i), path((i + 1) % 3000), path(0)], deriver: null };
  const t0 = Date.now();
  const ok = importNixClosure({ exports: [{ schema: 'nix-path-info-json', data: big, provenance: prov('nix path-info --json --recursive .#myapp') }], expected: EXPECTED, now: NOW });
  assert.ok(Date.now() - t0 < 20000, 'bounded work');
  assert.equal(ok.coverage.outputs, 3000);
  assert.equal(ok.nodes.filter((n) => n.scopes.includes('runtime')).length <= 3000, true);
  // budget: cut off
  const cut = importNixClosure({ exports: [{ schema: 'nix-path-info-json', data: big, provenance: prov('nix path-info --json --recursive .#myapp') }], expected: EXPECTED, now: NOW, budgets: { maxNodes: 100 } });
  assert.equal(cut.status, 'partial'); assert.ok(kinds(cut).includes('truncated')); assert.equal(cut.claims.exactInventory, false);
  assert.ok(cut.nodes.length <= 100 + 1);
  // cyclic inputDrvs
  const cyc = { [`/nix/store/${hh(1)}-a-1.drv`]: { outputs: { out: { path: path(1) } }, inputDrvs: { [`/nix/store/${hh(2)}-b-1.drv`]: ['out'] }, inputSrcs: [], system: 'x86_64-linux', env: { name: 'a-1' } }, [`/nix/store/${hh(2)}-b-1.drv`]: { outputs: { out: { path: path(2) } }, inputDrvs: { [`/nix/store/${hh(1)}-a-1.drv`]: ['out'] }, inputSrcs: [], system: 'x86_64-linux', env: { name: 'b-1' } } };
  const c = importNixClosure({ exports: [{ schema: 'nix-derivation-show-json', data: cyc, provenance: prov('nix derivation show --recursive .#myapp') }], expected: EXPECTED, now: NOW });
  assert.ok(c.nodes.length >= 2);
  // malformed everything
  const bad = importNixClosure({ exports: [{ schema: 'nix-path-info-json', text: '{ not json' }, { text: '[1,2,3]' }, { schema: 'nix-derivation-show-json', data: { 'x.drv': 5, '/nix/store/short.drv': {} } }, { schema: 'nix-path-info-json', data: { [path(1)]: 7, [path(2)]: { references: 'nope' } } }], expected: EXPECTED, now: NOW });
  assert.ok(Array.isArray(bad.diagnostics) && bad.diagnostics.length >= 3);
  assert.equal(bad.claims.exactInventory, false);
  const huge = importNixClosure({ exports: [{ schema: 'nix-path-info-json', text: '{' + ' '.repeat(100), provenance: prov('nix path-info --json --recursive .#myapp') }], expected: EXPECTED, now: NOW, budgets: { maxBytes: 50 } });
  assert.ok(kinds(huge).includes('truncated'));
  assert.ok(CLOSURE_BUDGETS.maxNodes > 1000);
});

test('[NIX-008.AC03] store-looking paths are validated as strings, never read, and never run', () => {
  assert.ok(parseStorePath(P.app));
  for (const bad of ['/nix/store/../etc/passwd', `/nix/store/${P.app.slice(11, 43)}-x/../../etc/shadow`, '/etc/passwd', '/nix/store/short-name', `/nix/store/${'e'.repeat(32)}-name`, `${P.app}/bin/app`, '', null, 5, `/nix/store/${P.app.slice(11, 43)}-na\u0000me`]) assert.equal(parseStorePath(bad), null, String(bad));
  const hostile = { [P.app]: { references: ['/etc/shadow', '/nix/store/../../root/.ssh/id_rsa', P.glibc], deriver: '/usr/bin/evil' }, [P.glibc]: { references: [] } };
  const r = importNixClosure({ exports: [{ schema: 'nix-path-info-json', data: hostile, provenance: prov('nix path-info --json --recursive .#myapp') }], expected: EXPECTED, now: NOW });
  assert.ok(r.diagnostics.some((d) => d.kind === 'invalid-store-path'));
  assert.ok(!r.nodes.some((n) => /etc\/shadow|id_rsa/.test(n.id)));
  // static: no filesystem or process access is imported
  const src = readFileSync(join(SCANNER, 'src', 'language', 'nix-closure.js'), 'utf8');
  assert.ok(!/from 'node:(?:fs|child_process|net|http|https|dgram|os|path)'|require\(/.test(src));
  // dynamic: under the permission model (no fs beyond the sources, no child processes) the import still works
  const probe = `import { importNixClosure } from ${JSON.stringify(`file://${join(SCANNER, 'src', 'language', 'nix-closure.js')}`)}; const r = importNixClosure({ exports: [{ schema: 'nix-path-info-json', data: { '${P.app}': { references: ['/etc/shadow', '/root/.ssh/id_rsa'], deriver: '/usr/bin/evil' } } }] }); console.log(JSON.stringify({ nodes: r.nodes.length, diag: r.diagnostics.length }));`;
  const env = { ...process.env }; delete env.NODE_TEST_CONTEXT;
  const p = spawnSync(process.execPath, ['--permission', `--allow-fs-read=${SCANNER}`, '--input-type=module', '-e', probe], { encoding: 'utf8', env, cwd: SCANNER, timeout: 60000 });
  assert.equal(p.status, 0, `${p.stdout}\n${p.stderr}`);
  assert.deepEqual(JSON.parse(p.stdout.trim()), { nodes: 1, diag: 1 });
});
