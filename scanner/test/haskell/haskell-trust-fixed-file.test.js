// Content read from a file at a location the program text fixes is the program's own data: lowered to `low` (kept, with the reason). Pinned in both
// directions: a read whose path is a name, a parameter or a request value keeps its severity, and so does a parameter spliced under a fixed
// directory (the library function builds the path, and lets its caller leave the directory). Sources are written for this file.

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { runScan } from '../../src/runScan.js';
import { mkTestTmp } from '../helpers/tmp.js';

async function scanAll(files) {
  const dir = mkTestTmp('hs-fixedfile-');
  writeFileSync(join(dir, 'package.json'), '{}');
  for (const [f, text] of Object.entries(files)) { mkdirSync(dirname(join(dir, f)), { recursive: true }); writeFileSync(join(dir, f), text); }
  const r = await runScan(dir, { deep: true });
  return [...(r.scan.findings || [])].filter((f) => f.parser === 'IR-TAINT');
}
const at = (fs, line, cwe) => fs.filter((f) => f.line === line && (!cwe || f.cwe === cwe));

const CABAL = `name: app
version: 0.1
cabal-version: >=1.10
build-type: Simple
library
  exposed-modules: Lib
  build-depends: base, directory, filepath, process
  default-language: Haskell2010
`;

test('fixed-file: a path built from the content of a literal-path file is low, with the reason', async () => {
  const fs = await scanAll({
    'app.cabal': CABAL,
    'Lib.hs': `module Lib (loadSchema) where
import System.FilePath

loadSchema :: IO String
loadSchema = do
  ref <- readFile "config/schema-ref.txt"
  readFile ("schemas" </> ref)
`,
  });
  const f = at(fs, 7, 'CWE-22');
  assert.equal(f.length, 1, JSON.stringify(fs.map((x) => [x.line, x.cwe, x.severity])));
  assert.equal(f[0].severity, 'low');
  assert.equal(f[0].originalSeverity, 'high');
  assert.equal(f[0].trustBoundary.verdict, 'data-input');
  assert.match(f[0].trustBoundary.reason, /literal path/);
});

test('fixed-file: the same read from a path held in a name, a parameter or standard input keeps its severity', async () => {
  const fs = await scanAll({
    'app.cabal': CABAL,
    'Lib.hs': `module Lib (viaName, viaParam, viaStdin) where
import System.FilePath

viaName :: IO String
viaName = do
  let p = "config/schema-ref.txt"
  ref <- readFile p
  readFile ("schemas" </> ref)

viaParam :: FilePath -> IO String
viaParam p = do
  ref <- readFile p
  readFile ("schemas" </> ref)

viaStdin :: IO String
viaStdin = do
  ref <- getLine
  readFile ("schemas" </> ref)
`,
  });
  for (const line of [8, 13, 18]) {
    const f = at(fs, line, 'CWE-22');
    assert.ok(f.length >= 1, `line ${line} still reported: ${JSON.stringify(fs.map((x) => [x.line, x.severity]))}`);
    for (const x of f) assert.notEqual(x.severity, 'low', `line ${line} must not be lowered by the fixed-file rule: ${x.severity}`);
  }
});

test('fixed-file: a parameter appended under a fixed directory is still reported at its severity', async () => {
  const fs = await scanAll({
    'app.cabal': CABAL,
    'Lib.hs': `module Lib (joinUnder) where

joinUnder :: FilePath -> IO String
joinUnder name = readFile ("/srv/data/" ++ name)
`,
  });
  const f = at(fs, 4, 'CWE-22');
  assert.equal(f.length, 1);
  assert.equal(f[0].trustBoundary.verdict, 'entry-parameter');
  assert.ok(['high', 'critical', 'medium'].includes(f[0].severity), f[0].severity);
});
