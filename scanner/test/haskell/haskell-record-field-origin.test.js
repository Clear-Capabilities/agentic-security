// A source stored in a record field keeps its origin when the record is handed on whole (docs/superpowers/plans/2026-11-14-haskell-real-code-precision.md,
// lever 2). Found on IHP's compile-time database tool: fourteen flagged sites whose paths come from `AutoDatabase { adbRoot = root }` built from
// environment settings and the project directory, every one `unattributed` ("the engine recorded no origin for the value"), because the record
// construction lowers to `database.adbRoot = root` and a source recorded on a FIELD did not match a read of the whole record. The trust verdict
// then had nothing to classify. With the origin kept, the same program gets the verdict its origins warrant.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { mkTestTmp } from '../helpers/tmp.js';

process.env.AGENTIC_SECURITY_DEEP = '1';
delete process.env.CI;

const MAIN = `module Main where
import System.Environment (lookupEnv)
import System.Directory (getCurrentDirectory)
import System.FilePath ((</>))
import Data.Maybe (fromMaybe)

data AutoDatabase = AutoDatabase { adbRoot :: !FilePath, adbName :: !String }

main :: IO ()
main = do
    configured <- lookupEnv "TOOL_ROOT"
    cwd <- getCurrentDirectory
    let root = fromMaybe (cwd </> "build") configured
    let database = AutoDatabase { adbRoot = root, adbName = "db" }
    appendLifecycleLog database "started"
    direct root

appendLifecycleLog :: AutoDatabase -> String -> IO ()
appendLifecycleLog AutoDatabase { adbRoot } message =
    appendFile (adbRoot </> "watchdog.log") (message <> "\\n")

direct :: FilePath -> IO ()
direct root = appendFile (root </> "direct.log") "x\\n"
`;
const CABAL = 'cabal-version: 2.4\nname: probe\nversion: 0.1\nexecutable probe\n    main-is: Main.hs\n    hs-source-dirs: .\n    build-depends: base, directory, filepath\n';

test('the path read back out of the record names the environment variable as its origin, like the path handed on directly', async () => {
  const { runScan } = await import('../../src/runScan.js');
  const dir = mkdtempSync(join(mkTestTmp('hs-record-origin'), 'p-'));
  writeFileSync(join(dir, 'Main.hs'), MAIN); writeFileSync(join(dir, 'probe.cabal'), CABAL);
  const { scan } = await runScan(dir);
  const paths = scan.findings.filter((f) => f.file === 'Main.hs' && f.cwe === 'CWE-22');
  const viaRecord = paths.find((f) => f.line === 20);
  const direct = paths.find((f) => f.line === 16);   // the summary finding of `direct` is reported at its call site in main
  assert.ok(viaRecord && direct, JSON.stringify(paths.map((f) => [f.line, f.vuln])));
  for (const f of [direct, viaRecord]) {
    assert.equal(f.trustBoundary.verdict, 'operator-controlled', JSON.stringify(f.trustBoundary));
    assert.notEqual(f.trustBoundary.inferred, true, `${f.line}: the verdict must come from a recorded origin, not from the absence of one`);
    assert.ok(f.trustBoundary.roots.some((r) => r.provenance === 'env'), JSON.stringify(f.trustBoundary.roots));
  }
});
