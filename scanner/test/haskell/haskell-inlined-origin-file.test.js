// An origin recorded in a callee keeps the callee's file when the finding is merged into its caller (round 4;
// docs/superpowers/plans/2026-11-14-haskell-real-code-precision.md). The taint engine's collector stamped every evidence-chain hop with the file
// of the function the finding was COLLECTED under, which for a summary finding merged into its caller is the caller's file, so IHP's
// `SchemaCompiler/Cache.hs:45` said "file content at SchemaCompiler.hs:38": the right line in the wrong file (line 38 of that file is an import).
// The fixed-file rule then looked for a read at that place, found none, and kept the finding at `high`. A hop now names the file its record was
// made in. This fixture pins the shape (a read of a project-constant file inside the callee, reached from another module) at the low severity the
// fixed-file rule gives it; the real-code effect is measured by `bench/haskell-precision`.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { mkTestTmp } from '../helpers/tmp.js';

process.env.AGENTIC_SECURITY_DEEP = '1';
delete process.env.CI;

const CABAL = 'cabal-version: 2.4\nname: p\nversion: 0.1\nlibrary\n    exposed-modules: Compile, Cache\n    hs-source-dirs: src\n    build-depends: base, filepath\n';
const CACHE = `module Cache (cacheFile, loadSchema) where
import System.FilePath ((</>))

cacheFile :: FilePath
cacheFile = "build/schema-ref.txt"

loadSchema :: String -> IO String
loadSchema key = do
    ref <- readFile cacheFile
    readFile ("schemas" </> key </> ref)
`;
const COMPILE = `module Compile (compile) where
import qualified Cache

compile :: IO String
compile = Cache.loadSchema "default"
`;

test('a source read inside a callee whose finding is merged into its caller is attributed to the callee\'s file, so the fixed-file rule can judge it', async () => {
  const { runScan } = await import('../../src/runScan.js');
  const dir = mkdtempSync(join(mkTestTmp('hs-inlined-origin'), 'p-'));
  for (const [k, v] of Object.entries({ 'p.cabal': CABAL, 'src/Cache.hs': CACHE, 'src/Compile.hs': COMPILE })) { mkdirSync(dirname(join(dir, k)), { recursive: true }); writeFileSync(join(dir, k), v); }
  const { scan } = await runScan(dir);
  const f = scan.findings.find((x) => x.file === 'src/Cache.hs' && x.cwe === 'CWE-22' && x.line === 10);
  assert.ok(f, JSON.stringify(scan.findings.filter((x) => /\.hs$/.test(x.file)).map((x) => [x.file, x.line, x.cwe, x.severity])));
  const reads = (f.chain || []).filter((c) => c.provenance === 'file-read');
  assert.ok(reads.length >= 1, JSON.stringify(f.chain));
  for (const c of reads) assert.equal(c.file, 'src/Cache.hs', `the read at line ${c.line} is in the helper's file: ${JSON.stringify(c)}`);
  assert.equal(f.severity, 'low', JSON.stringify(f.trustBoundary));
  assert.equal(f.originalSeverity, 'high');
});
