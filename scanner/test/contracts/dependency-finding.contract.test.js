// Contract test for the dependency finding (docs/reference/dependency-finding-contract.md): a real scan over a project whose advisory
// data is seeded into a private home, so the result is the same on a warm machine and a cold runner. The finding is held to the page's
// table in both directions, the tiers and verdicts to their tables, and the "what an empty result means" rule is pinned: a scan that could
// not consult advisories says so and is not `complete`.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { seedAdvisory } from '../helpers/seed-osv-cache.js';
import { readPage, fieldsUnder, sameFields } from '../helpers/contract-page.js';
import { mkTestTmp } from '../helpers/tmp.js';

// the advisory cache location is read when the engine loads, so the home is set before it is imported
const HOME = mkTestTmp('agsec-dep-contract-home-');
process.env.HOME = HOME;
process.env.AGENTIC_SECURITY_OFFLINE = '1';
const { runScan } = await import('../../src/runScan.js');
const { SCA_VERDICTS } = await import('../../src/posture/sca-verdict.js');

const PAGE = readPage('docs/reference/dependency-finding-contract.md');

function project({ imports = true, route = false } = {}) {
  const dir = mkTestTmp('agsec-dep-contract-');
  fs.writeFileSync(`${dir}/package.json`, JSON.stringify({ name: 'p', version: '1.0.0', dependencies: { lodash: '4.17.4' } }));
  fs.writeFileSync(`${dir}/package-lock.json`, JSON.stringify({ name: 'p', version: '1.0.0', lockfileVersion: 3, packages: { '': { name: 'p', version: '1.0.0', dependencies: { lodash: '4.17.4' } }, 'node_modules/lodash': { version: '4.17.4' } } }));
  const code = route
    ? "const express=require('express');const _=require('lodash');const app=express();\napp.post('/m',(req,res)=>{ res.json(_.merge({}, req.body)); });\n"
    : imports ? "const _=require('lodash');\nmodule.exports=(x)=>_.merge({},x);\n" : "module.exports=(x)=>x;\n";
  fs.writeFileSync(`${dir}/app.js`, code);
  return dir;
}
seedAdvisory(HOME, { ecosystem: 'npm', name: 'lodash', version: '4.17.4', id: 'GHSA-contract-0001', description: 'Prototype pollution in lodash', fixedVersions: ['4.17.21'], severity: 'high' });
const scanOf = async (dir) => (await runScan(dir, {})).scan;

test('contract: a dependency finding has exactly the documented fields, and the comparison itself fails when one is added or dropped', async () => {
  const { supplyChain } = await scanOf(project());
  assert.equal(supplyChain.length, 1);
  const f = Object.fromEntries(Object.entries(supplyChain[0]).filter(([k]) => !k.startsWith('_')));
  const documented = fieldsUnder(PAGE, 'Finding fields');
  sameFields(f, documented, 'dependency finding');
  assert.equal(f.type, 'vulnerable_dep');
  assert.throws(() => sameFields({ ...f, extra: 1 }, documented, 'x'));
  const { name, ...rest } = f;
  assert.throws(() => sameFields(rest, documented, 'x'));
  assert.equal(name, 'lodash');
});

test('contract: the finding carries the seeded advisory and a fix, and the verdict is one of the documented five', async () => {
  const { supplyChain } = await scanOf(project());
  const f = supplyChain[0];
  assert.equal(f.osvId, 'GHSA-contract-0001');
  assert.deepEqual(f.fixedVersions, ['4.17.21']);
  assert.ok(SCA_VERDICTS.includes(f.scaVerdict));
  assert.deepEqual(fieldsUnder(PAGE, 'Triage verdicts').sort(), [...SCA_VERDICTS].sort());
});

test('contract: the tier follows the evidence, and every tier produced is a documented one', async () => {
  const documented = fieldsUnder(PAGE, 'Reachability tiers');
  const tiers = new Set();
  for (const opts of [{ imports: true }, { imports: false }, { route: true }]) {
    const { supplyChain } = await scanOf(project(opts));
    for (const f of supplyChain) tiers.add(f.reachabilityTier);
    if (opts.imports === false) assert.equal(supplyChain[0].reachabilityTier, 'manifest-only', 'a declared package nothing imports');
    if (opts.imports === true) assert.equal(supplyChain[0].reachabilityTier, 'import-reachable', 'an imported package with no function-level evidence');
  }
  for (const t of tiers) assert.ok(documented.includes(t), `${t} is a documented tier`);
  const source = fs.readFileSync(new URL('../../src/engine.js', import.meta.url), 'utf8');
  for (const t of documented) assert.ok(source.includes(`'${t}'`), `${t} exists in the engine`);
});

test('contract: unknown function reachability is unknown, never unreachable', async () => {
  const { supplyChain } = await scanOf(project());
  assert.notEqual(supplyChain[0].functionReachable, 'unreachable');
  assert.ok(['reachable', 'unreachable', 'unknown'].includes(supplyChain[0].functionReachable));
});

test('contract: a scan with advisory data it could use is complete, and says where the data came from', async () => {
  const s = await scanOf(project());
  const a = s.scanHealth.freshness.advisories;
  sameFields(a, fieldsUnder(PAGE, 'Advisory coverage'), 'advisory coverage');
  assert.equal(a.unanswered, 0);
  assert.equal(a.answered, a.componentsChecked);
  assert.ok(['cache', 'live'].includes(a.source));
  assert.equal(s.scanHealth.status, 'complete');
});

test('contract: a scan that could not consult advisories reports it, is partial, and says an empty result is not evidence of safety', async () => {
  // a component version the private cache has no answer for, offline
  const dir = project();
  const lock = JSON.parse(fs.readFileSync(`${dir}/package-lock.json`, 'utf8'));
  lock.packages['node_modules/lodash'].version = '4.17.5';
  lock.packages[''].dependencies.lodash = '4.17.5';
  fs.writeFileSync(`${dir}/package-lock.json`, JSON.stringify(lock));
  fs.writeFileSync(`${dir}/package.json`, JSON.stringify({ name: 'p', version: '1.0.0', dependencies: { lodash: '4.17.5' } }));
  const s = await scanOf(dir);
  assert.equal(s.supplyChain.length, 0, 'no advisory data, so no finding');
  const a = s.scanHealth.freshness.advisories;
  assert.equal(a.source, 'offline-cache-only');
  assert.equal(a.unanswered, 1);
  assert.equal(s.scanHealth.status, 'partial');
  assert.ok(s.scanHealth.conditions.some((c) => /not evidence that the dependency is safe/.test(c)));
  assert.ok(PAGE.includes('offline-cache-only'));
});

test('contract: a project with no dependencies needs no advisory data and stays complete', async () => {
  const dir = mkTestTmp('agsec-dep-contract-none-');
  fs.writeFileSync(`${dir}/package.json`, '{"name":"p","version":"1.0.0"}');
  fs.writeFileSync(`${dir}/app.js`, 'module.exports = 1;\n');
  const s = await scanOf(dir);
  assert.equal(s.scanHealth.status, 'complete');
  assert.notEqual(s.scanHealth.freshness.advisories?.unanswered > 0, true);
});
