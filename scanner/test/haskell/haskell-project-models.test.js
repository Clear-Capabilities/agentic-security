// Declarative project models for Haskell wrappers (PRD FR 03): accepted only with provenance and a paired
// positive/negative test, scoped to one scan, and reported when rejected.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { runScan } from '../../src/runScan.js';
import { loadProjectModels, projectFileExists } from '../../src/language/haskell-project-models.js';
import { matchSinkOrSanitizer } from '../../src/dataflow/catalog.js';
import { mkTestTmp } from '../helpers/tmp.js';

const CABAL = 'cabal-version: 2.4\nname: demo\nversion: 0.1\nexecutable demo\n  main-is: Main.hs\n  hs-source-dirs: src\n  build-depends: base\n';
const MAIN = 'module Main where\nimport Acme.Sql (runRaw)\n\nmain :: IO ()\nmain = do\n  n <- getLine\n  runRaw "conn" ("SELECT * FROM t WHERE n = " ++ n)\n';
const SAFE = 'module Safe where\nimport Acme.Sql (runRaw)\n\nok :: IO ()\nok = runRaw "conn" "SELECT 1"\n';
const model = (o = {}) => ({
  id: 'acme-runraw', role: 'sink', module: 'Acme.Sql', name: 'runRaw', family: 'sql', cwe: 'CWE-89', argIndex: 1,
  provenance: { reviewer: 'appsec', reviewedAt: '2026-11-01', reason: 'runRaw forwards its text argument to the database unparameterised' },
  tests: { positive: 'test/Vuln.hs', negative: 'test/Safe.hs' }, ...o,
});

function proj(models) {
  const dir = mkTestTmp('hs-pm-');
  const w = (rel, c) => { fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true }); fs.writeFileSync(path.join(dir, rel), c); };
  w('demo.cabal', CABAL); w('src/Main.hs', MAIN); w('test/Vuln.hs', MAIN); w('test/Safe.hs', SAFE);
  if (models) w('.agentic-security/haskell-models.json', JSON.stringify({ schema: 'haskell-project-models/1', models }));
  return dir;
}
const sqlFindings = (scan) => scan.findings.filter((f) => f.parser === 'IR-TAINT' && f.cwe === 'CWE-89' && f.file === 'src/Main.hs');

test('without a model the unknown wrapper is opaque and nothing is reported', async () => {
  const { scan } = await runScan(proj(null));
  assert.equal(sqlFindings(scan).length, 0);
});

test('a reviewed model with paired tests makes the wrapper a sink for that scan only', async () => {
  const dir = proj([model()]);
  const { scan } = await runScan(dir);
  assert.ok(sqlFindings(scan).length >= 1, JSON.stringify(scan.findings.map((f) => [f.file, f.cwe, f.parser])));
  const lim = scan.scanHealth.languageCoverage.limitations.find((l) => l.kind === 'project-models');
  assert.deepEqual(lim.ids, ['acme-runraw']);
  assert.equal(matchSinkOrSanitizer('Acme.Sql.runRaw', 'x.hs'), null, 'the declaration must not outlive the scan');
});

test('a model without provenance, tests or a real family is rejected with the reason, and has no effect', async () => {
  const exists = projectFileExists(proj([]));
  const bad = [
    model({ id: 'a', provenance: undefined }),
    model({ id: 'b', tests: { positive: 'test/Vuln.hs' } }),
    model({ id: 'c', tests: { positive: 'test/Vuln.hs', negative: 'test/Missing.hs' } }),
    model({ id: 'd', tests: { positive: 'test/Vuln.hs', negative: 'test/Vuln.hs' } }),
    model({ id: 'e', family: 'magic' }),
    model({ id: 'f', role: 'sanitizer', appliesTo: ['*'] }),
    model({ id: 'g', name: 'Not-A-Name' }),
    model({ id: 'h', tests: { positive: '../etc/passwd', negative: 'test/Safe.hs' } }),
  ];
  const r = loadProjectModels({ schema: 'haskell-project-models/1', models: bad }, exists);
  assert.equal(r.accepted.length, 0);
  assert.equal(r.rejected.length, bad.length);
  assert.match(r.rejected[0].reason, /not a model/);
  assert.equal(r.catalog.length, 0);

  const { scan } = await runScan(proj([model({ provenance: undefined })]));
  assert.equal(sqlFindings(scan).length, 0);
  assert.ok([...(scan.scanHealth.conditions || []), ...(scan.scanHealth.languageCoverage.conditions || [])].some((c) => /project model\(s\) were rejected/.test(c)));
});

test('a sanitizer model applies only to the families it names', () => {
  const r = loadProjectModels({ schema: 'haskell-project-models/1', models: [model({ id: 's', role: 'sanitizer', name: 'quoteSql', appliesTo: ['sql'], argIndex: undefined })] }, projectFileExists(proj([])));
  assert.equal(r.accepted.length, 1);
  assert.deepEqual(r.catalog[0].appliesTo, ['sql']);
});

test('overlapping scans in one process: a project entry is matched only inside the scope of its own root', async () => {
  const { registerProjectCatalogEntries, unregisterProjectCatalogEntries, scanOwner } = await import('../../src/dataflow/catalog.js');
  const entry = { kind: 'sink', id: 'x-owner-test', language: 'hs', match: { type: 'call', callee: 'Owner.Test.run' }, vuln: 'x', cwe: 'CWE-89', family: 'sql', severity: 'high' };
  registerProjectCatalogEntries('/root/a', [entry]);
  try {
    const call = { kind: 'ident', name: 'Owner.Test.run' };
    assert.ok(scanOwner.run('/root/a', () => matchSinkOrSanitizer(call, 'x.hs')), 'the owning scan matches it');
    assert.equal(scanOwner.run('/root/b', () => matchSinkOrSanitizer(call, 'x.hs')), null, 'another root in the same process does not');
  } finally { unregisterProjectCatalogEntries('/root/a'); }
});

test('after a scan, its project models are gone from the shared catalog and no scan scope leaks', async () => {
  const { scanOwner } = await import('../../src/dataflow/catalog.js');
  assert.equal(scanOwner.getStore(), undefined, 'no scan scope leaks outside a scan');
  const dir = proj([model()]);
  await runScan(dir);
  assert.equal(matchSinkOrSanitizer({ kind: 'ident', name: 'Acme.Sql.runRaw' }, 'x.hs'), null);
});
