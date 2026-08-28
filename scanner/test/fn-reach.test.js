// 0.6.0 Feat-1: function-level SCA reachability tests.
// Verifies that the engine tags supplyChain findings with functionReachable
// based on whether vulnerable functions are called from a route-reachable path.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '../src/runScan.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIX = (name) => path.join(__dirname, 'fixtures', 'sca-fn-reachability', name);

function lodashSc(scan) {
  return (scan.supplyChain || []).filter(s => s.type === 'vulnerable_dep' && s.name === 'lodash');
}

test('Function-level reachability — reachable: lodash.merge in a route handler', async () => {
  const { scan } = await runScan(FIX('reachable'));
  const sc = lodashSc(scan);
  assert.ok(sc.length >= 1, `expected ≥1 lodash CVE finding, got ${sc.length}`);
  // At least one of the lodash CVEs must be tagged 'reachable'.
  assert.ok(sc.some(s => s.functionReachable === 'reachable'),
    `expected functionReachable='reachable' on ≥1 lodash CVE; got: ${sc.map(s => s.functionReachable).join(', ')}`);
  // Call site is captured
  const withSites = sc.find(s => Array.isArray(s.vulnerableFunctionCallSites) && s.vulnerableFunctionCallSites.length);
  assert.ok(withSites, 'expected vulnerableFunctionCallSites on at least one lodash CVE');
  assert.ok(withSites.vulnerableFunctionCallSites.some(c => /app\.js$/.test(c.file) && c.fn === 'merge'),
    `expected merge call site in app.js; got: ${JSON.stringify(withSites.vulnerableFunctionCallSites)}`);
});

test('Function-level reachability — unreachable: vuln fn lives in unused helper', async () => {
  const { scan } = await runScan(FIX('unreachable'));
  const sc = lodashSc(scan);
  assert.ok(sc.length >= 1, `expected ≥1 lodash CVE finding, got ${sc.length}`);
  assert.ok(sc.every(s => s.functionReachable === 'unreachable'),
    `expected functionReachable='unreachable' on every lodash CVE; got: ${sc.map(s => s.functionReachable).join(', ')}`);
});

test('Function-level reachability — unknown: dep imported, no vuln fn invoked', async () => {
  const { scan } = await runScan(FIX('not-called'));
  const sc = lodashSc(scan);
  assert.ok(sc.length >= 1, `expected ≥1 lodash CVE finding, got ${sc.length}`);
  // No call sites for vulnerable functions → unknown reachability
  assert.ok(sc.every(s => s.functionReachable === 'unknown'),
    `expected functionReachable='unknown' on every lodash CVE; got: ${sc.map(s => s.functionReachable).join(', ')}`);
});

test('R7 — aliased import: lodash merge via {merge as deepMerge} is reachable (regex pass misses it)', async () => {
  const { scan } = await runScan(FIX('aliased'));
  const sc = lodashSc(scan);
  assert.ok(sc.length >= 1, `expected ≥1 lodash CVE finding, got ${sc.length}`);
  // The regex pass keys on lodash.merge / _.merge and cannot see deepMerge(...).
  // R7's import-aware augmenter resolves the alias → route-reachable → 'reachable'.
  assert.ok(sc.some(s => s.functionReachable === 'reachable'),
    `expected functionReachable='reachable' via the aliased import; got: ${sc.map(s => s.functionReachable).join(', ')}`);
  const aliasSite = sc.flatMap(s => s.vulnerableFunctionCallSites || []).find(c => c.fn === 'merge' && c.via === 'alias');
  assert.ok(aliasSite && /app\.js$/.test(aliasSite.file),
    `expected an alias-resolved merge call site in app.js; got ${JSON.stringify(sc.flatMap(s => s.vulnerableFunctionCallSites || []))}`);
});

test('Provenance: depChain field is present on vulnerable_dep findings (M3 §3.2)', async () => {
  // M3 §3.2 propagates depChain (dependency ancestry) onto every vulnerable_dep
  // finding. This is additive and purely informational — direct deps have empty
  // or single-element chains, transitive deps have multi-element chains.
  const { scan } = await runScan(FIX('reachable'));
  const sc = lodashSc(scan);
  assert.ok(sc.length >= 1, `expected ≥1 lodash CVE finding, got ${sc.length}`);
  // Every vulnerable_dep must have a depChain field (array).
  for (const finding of sc) {
    assert.ok(Array.isArray(finding.depChain), `expected depChain to be an array on ${finding.name}@${finding.version}; got ${typeof finding.depChain}`);
    // Direct deps should have a short chain (0-1 elements).
    if (finding.isDirect) {
      assert.ok(finding.depChain.length <= 1, `expected direct dep ${finding.name} to have chain length ≤1; got ${finding.depChain.length}`);
    }
    // No trailing slashes (cosmetic artifact from path parsing).
    for (const segment of finding.depChain) {
      assert.ok(!segment.endsWith('/'), `expected no trailing slash in depChain segment; got "${segment}"`);
    }
  }
});
