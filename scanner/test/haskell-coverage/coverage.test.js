import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { runScan } from '../../src/runScan.js';
import { buildHaskellCoverage } from '../../src/language/haskell-coverage.js';
import { mkTestTmp } from '../helpers/tmp.js';

function proj(files) {
  const dir = mkTestTmp('as-hscov-');
  for (const [rel, c] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), c);
  }
  return dir;
}
const GOOD = 'module Lib where\n\nhello :: String -> String\nhello x = x ++ "!"\n';
const CABAL = 'cabal-version: 2.4\nname: demo\nversion: 0.1\nlibrary\n  exposed-modules: Lib\n  hs-source-dirs: src\n  build-depends: base\n';

test('end to end: stages are counted separately and rule families are listed with zero findings', async () => {
  const dir = proj({ 'demo.cabal': CABAL, 'src/Lib.hs': GOOD, 'src/Old.lhs': '> module Old where\n> x = 1\n' });
  const { scan } = await runScan(dir);
  const h = scan.scanHealth.languageCoverage.haskell;
  assert.equal(h.schema, 'haskell-coverage/1');
  assert.equal(h.byFile['src/Lib.hs'].parse, 'parsed');
  assert.equal(h.byFile['src/Lib.hs'].graphInclusion, 'included');
  assert.equal(h.byFile['src/Old.lhs'].graphInclusion, 'parse-only');
  assert.equal(h.byFile['src/Old.lhs'].ruleEvaluation, 'unsupported-form');
  assert.equal(h.byFile['src/Lib.hs'].package, 'demo');
  assert.ok(h.ruleFamilies.length >= 4);
  assert.ok(h.ruleFamilies.find((f) => f.id === 'hs-security-rules').ran);
  assert.equal(h.totals.eligibleHs, 1);
  assert.ok(h.capability.limitations.some((l) => /parse-only/.test(l)));
});

test('a recognised extension is not "analyzed": unparsed file stays in the denominator and fails the rate', () => {
  const files = { 'a/A.hs': GOOD, 'a/B.hs': GOOD };
  const parses = new Map([['a/A.hs', { status: 'parsed', functions: [1], errors: [], boundaries: [] }], ['a/B.hs', { status: 'failed', functions: [], errors: [{}], boundaries: [] }]]);
  const c = buildHaskellCoverage({ files, parses, ir: null, deepEnabled: true, ruleRuns: {} });
  assert.equal(c.totals.eligibleHs, 2);
  assert.equal(c.stages.parse.rate, 0.5);
  assert.equal(c.stages.parse.failed, 1);
  assert.equal(c.capability.status, 'incomplete');
  assert.ok(c.incompleteEntries.some((e) => e.file === 'a/B.hs'));
  assert.equal(c.meetsThresholds, false);
});

test('explicitly disabling deep analysis is an incomplete capability, never complete', () => {
  const files = { 'A.hs': GOOD };
  const parses = new Map([['A.hs', { status: 'parsed', functions: [1], errors: [], boundaries: [] }]]);
  const ruleRuns = { 'hs-security-rules': { ran: true }, 'hs-web': { ran: true }, 'hs-llm': { ran: true }, 'hs-sca': { ran: true } };
  const c = buildHaskellCoverage({ files, parses, ir: null, deepEnabled: false, ruleRuns });
  assert.equal(c.capability.status, 'incomplete');
  assert.match(c.capability.reasons.join(' '), /deep analysis is disabled/);
  assert.equal(c.byFile['A.hs'].flowAnalysis, 'not-run:deep-analysis-disabled');
  assert.equal(c.ruleFamilies.find((f) => f.id === 'ir-taint').ran, false);
});

test('oversize and excluded files are accounted for with reasons and are not eligible-parsed', () => {
  const c = buildHaskellCoverage({
    files: { 'A.hs': GOOD }, parses: new Map([['A.hs', { status: 'parsed', functions: [], errors: [], boundaries: [] }]]),
    ir: null, deepEnabled: true, ruleRuns: { 'hs-security-rules': { ran: true }, 'hs-web': { ran: true } },
    sizeSkipped: [{ file: 'Big.hs', bytes: 9e6, cap: 5e5 }], policyExcluded: ['test/T.hs'], excludedPaths: ['dist-newstyle/G.hs'],
  });
  assert.equal(c.totals.discovered, 4);
  assert.equal(c.byFile['Big.hs'].read, 'oversize');
  assert.equal(c.byFile['test/T.hs'].eligible, false);
  assert.equal(c.byFile['dist-newstyle/G.hs'].eligible, false);
  assert.equal(c.totals.eligibleHs, 2);
  assert.equal(c.capability.status, 'incomplete');
});

test('explicit source map overrides manifest package assignment', () => {
  const c = buildHaskellCoverage({
    files: { 'buck/svc/A.hs': GOOD }, parses: new Map([['buck/svc/A.hs', { status: 'parsed', functions: [], errors: [], boundaries: [] }]]),
    ir: null, deepEnabled: true, ruleRuns: {}, sourceMap: { packages: { 'svc-api': ['buck/svc'] } },
  });
  assert.equal(c.byFile['buck/svc/A.hs'].package, 'svc-api');
  assert.ok(c.byPackage['svc-api']);
});

test('the same coverage state reaches JSON, SARIF properties, HTML and the CLI verdict', async () => {
  const { toSARIF, toHTML, toJSON, toShipVerdict, haskellCoverageSummary } = await import('../../src/report/index.js');
  const dir = proj({ 'demo.cabal': CABAL, 'src/Lib.hs': GOOD });
  const { scan } = await runScan(dir);
  const sum = haskellCoverageSummary(scan);
  assert.ok(sum && sum.eligibleHs === 1);
  const sarif = JSON.parse(JSON.stringify(toSARIF(scan)));
  assert.deepEqual(sarif.runs[0].invocations[0].properties.haskellCoverage.status, sum.status);
  assert.match(toHTML(scan), /Haskell coverage/);
  assert.match(toShipVerdict(scan, { color: false }) || '', /Haskell coverage/);
  assert.ok(JSON.stringify(toJSON(scan)).includes('haskell-coverage/1'));
});

test('strict assurance fails a Haskell scan whose deep analysis was explicitly disabled; the coverage record says incomplete', async () => {
  const { evaluateAssuranceMode } = await import('../../src/pipeline/assurance-mode.js');
  const dir = proj({ 'demo.cabal': CABAL, 'src/Lib.hs': GOOD });
  const { scan } = await runScan(dir, { deep: false });
  const h = scan.scanHealth.languageCoverage.haskell;
  const strict = evaluateAssuranceMode('strict', scan.scanHealth, scan.findings || []);
  assert.equal(h.capability.status, 'incomplete');
  assert.equal(strict.ok, false);
  assert.ok(strict.conditions.some((c) => /haskell:taint/.test(c)));
  assert.equal(h.byFile['src/Lib.hs'].flowAnalysis, 'not-run:deep-analysis-disabled');
});

test('--haskell-source-map assigns files to a Buck-style package without running a build', async () => {
  const dir = proj({ 'buck/svc/A.hs': GOOD, 'map.json': JSON.stringify({ packages: { 'svc-api': ['buck/svc'] } }) });
  const { scan } = await runScan(dir, { haskellSourceMap: 'map.json' });
  assert.equal(scan.scanHealth.languageCoverage.haskell.byFile['buck/svc/A.hs'].package, 'svc-api');
});

test('Buck-declared Haskell dependencies are a coverage gap, not a clean result (PRD FR 08)', async () => {
  const dir = proj({ 'svc/Lib.hs': GOOD, 'svc/BUCK': 'haskell_library(name = "lib", srcs = ["Lib.hs"], deps = ["//third-party:aeson"])\n' });
  const { scan } = await runScan(dir);
  const conds = scan.scanHealth.conditions || [];
  const lc = scan.scanHealth.languageCoverage.conditions || [];
  assert.ok([...conds, ...lc].some((c) => /Buck target file/.test(c)), JSON.stringify(lc));
});
