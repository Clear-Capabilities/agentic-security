// The Haskell packages inside an imported Nix closure are what the live Hackage feed must also cover. The closure is read exactly as a scan
// reads it: a `nix-export.json` bound to the project's own `flake.lock` by hash, so an export for another lock is refused and contributes nothing.

import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { nixHaskellPackageNames } from '../../src/language/resolved-pass.js';

const NOW = Date.parse('2026-10-03T00:00:00Z');
const A = '0123456789abcdfghijklmnpqrsvwxyz';
const hh = (i) => { let s = ''; let x = i * 2654435761 % 4294967296; for (let j = 0; j < 32; j++) { s += A[x % 32]; x = (Math.floor(x / 32) + j * 11 + i) % 4294967296; } return s; };
const out = (i, n) => `/nix/store/${hh(i)}-${n}`;
const drv = (i, n) => `/nix/store/${hh(i + 500)}-${n}.drv`;

/** A project file set whose export describes `specs` (each {pname, version, env}) and is bound to `lockText` unless `lockForExport` says otherwise. */
function project(specs, { lockText = '{"nodes":{},"root":"root","version":7}', lockForExport = null } = {}) {
  const sha = createHash('sha256').update(lockForExport ?? lockText).digest('hex');
  const app = { path: out(1, 'app-1.0'), drv: drv(1, 'app-1.0') };
  const pathinfo = {}; const drvs = {};
  specs.forEach((s, k) => {
    const i = 10 + k;
    s.path = out(i, `${s.pname}-${s.version}`); s.drv = drv(i, `${s.pname}-${s.version}`);
    drvs[s.drv] = { outputs: { out: { path: s.path } }, inputSrcs: [], inputDrvs: {}, system: 'x86_64-linux', builder: '/nix/store/bash', args: [], env: { name: `${s.pname}-${s.version}`, pname: s.pname, version: s.version, out: s.path, outputs: 'out', ...(s.env || {}) } };
    pathinfo[s.path] = { narHash: 'sha256-x', narSize: 1, references: [], deriver: s.drv };
  });
  pathinfo[app.path] = { narHash: 'sha256-x', narSize: 1, references: [app.path, ...specs.map((s) => s.path)], deriver: app.drv };
  drvs[app.drv] = { outputs: { out: { path: app.path } }, inputSrcs: [], inputDrvs: Object.fromEntries(specs.map((s) => [s.drv, ['out']])), system: 'x86_64-linux', builder: '/nix/store/bash', args: [], env: { name: 'app-1.0', pname: 'app', version: '1.0', out: app.path, buildInputs: specs.map((s) => s.path).join(' ') } };
  const prov = (cmd) => ({ tool: 'nix', command: cmd, target: { system: 'x86_64-linux', installable: '.#app' }, revision: {}, flakeLockSha256: sha, generatedAt: '2026-10-01T00:00:00Z' });
  const exportFile = { exports: [{ schema: 'nix-path-info-json', data: pathinfo, provenance: prov('nix path-info --json --recursive .#app') }, { schema: 'nix-derivation-show-json', data: drvs, provenance: prov('nix derivation show --recursive .#app') }] };
  return { 'flake.lock': lockText, 'nix-export.json': JSON.stringify(exportFile) };
}

const HS = { libraryHaskellDepends: 'x', isLibrary: '1' };

test('closure: only the packages whose derivation carries Haskell build attributes are named', () => {
  const files = project([{ pname: 'aeson', version: '2.2.1.0', env: HS }, { pname: 'curl', version: '8.7.1', env: {} }, { pname: 'text-iso8601', version: '0.1', env: { executableHaskellDepends: 'y' } }]);
  assert.deepEqual(nixHaskellPackageNames(files, { now: NOW }).sort(), ['aeson', 'text-iso8601']);
});

test('closure: an export bound to a different flake.lock is refused and names nothing', () => {
  const files = project([{ pname: 'aeson', version: '2.2.1.0', env: HS }], { lockForExport: '{"nodes":{"other":{}},"root":"other","version":7}' });
  assert.deepEqual(nixHaskellPackageNames(files, { now: NOW }), [], 'an export that does not describe this project is not evidence about it');
});

test('closure: a project with no export names nothing', () => {
  assert.deepEqual(nixHaskellPackageNames({ 'flake.nix': '{ outputs = _: {}; }' }, { now: NOW }), []);
});
