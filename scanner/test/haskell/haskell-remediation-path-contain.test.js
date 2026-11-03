// hs-path-contain (0.195.16), from the two dhall test-server true positives (a read and an existence test under one FilePath parameter,
// bench/dag/dev-haskell fresh set): a guard equation is added before the function's first equation, rejecting a ".." segment or an
// absolute path with the function's own not-found value, so no body line moves. The check is the shape the taint engine's guard
// recogniser already understands, so the rescan gate judges the semantics. Type-checked under GHC with no stubs: directory and
// filepath ship with GHC, and the request path is read from standard input (a stub Network.Wai would shadow the library model).
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { planHaskellFix, validateHaskellFix } from '../../src/language/haskell-fix.js';
import { mkTestTmp } from '../helpers/tmp.js';

process.env.GHC_ENVIRONMENT = '-';
process.env.AGENTIC_SECURITY_DEEP = '1';
delete process.env.CI;
const GHC = !spawnSync('ghc', ['--numeric-version'], { encoding: 'utf8' }).error;
const SERVER = `module Server (serve) where
import System.Directory (doesFileExist)
import qualified System.FilePath as FilePath

serve :: IO (Maybe String)
serve = do
    requested <- getLine
    case words requested of
        ("tests" : rest) -> do
            let shortPath = "tests" FilePath.</> FilePath.joinPath rest
            serveFixture shortPath
        _ -> pure Nothing

serveFixture :: FilePath -> IO (Maybe String)
serveFixture shortPath = do
    mPath <- resolve shortPath
    case mPath of
        Nothing -> pure Nothing
        Just path -> Just <$> readFile path
 where
  resolve :: FilePath -> IO (Maybe FilePath)
  resolve p = firstExisting ["dhall" FilePath.</> p, ".." FilePath.</> "dhall" FilePath.</> p]
  firstExisting [] = pure Nothing
  firstExisting (path : paths) = do
    exists <- doesFileExist path
    if exists then pure (Just path) else firstExisting paths
`;
const finding = (file, line, vuln = 'Path Traversal') => ({ cwe: 'CWE-22', rule: 'hs-sink-path', parser: 'IR-TAINT', file, line, severity: 'high', vuln });

async function scanOf(files) {
  const { runScan } = await import('../../src/runScan.js');
  const dir = mkdtempSync(join(mkTestTmp('hs-path-contain'), 'p-'));
  for (const [k, v] of Object.entries(files)) { mkdirSync(dirname(join(dir, k)), { recursive: true }); writeFileSync(join(dir, k), v); }
  const { scan } = await runScan(dir);
  return scan.findings.filter((x) => /\.hs$/.test(x.file) && x.cwe === 'CWE-22' && x.severity !== 'info');
}

test('both sites under one FilePath parameter get the same guard equation; the rescan shows both gone and GHC accepts the patch', async () => {
  const files = { 'Server.hs': SERVER };
  const before = await scanOf(files);
  assert.ok(before.length >= 2, JSON.stringify(before.map((x) => [x.line, x.vuln])));
  const readSite = before.find((x) => x.line === 19); const existsSite = before.find((x) => x.line === 25);
  assert.ok(readSite && existsSite, JSON.stringify(before.map((x) => x.line)));
  for (const f of [readSite, existsSite]) {
    const plan = planHaskellFix(f, files);
    assert.equal(plan.ok, true, JSON.stringify(plan));
    assert.equal(plan.ruleId, 'hs-path-contain'); assert.equal(plan.label, 'MITIGATION');
    assert.match(plan.after, /^serveFixture shortPath\n    \| "\.\." `elem` FilePath\.splitDirectories shortPath \|\| FilePath\.isAbsolute shortPath = pure Nothing\nserveFixture shortPath = do$/m);
    const v = await validateHaskellFix(f, { files, compile: true });
    assert.equal(v.gates.syntax.ok, true, JSON.stringify(v.gates.syntax));
    assert.equal(v.gates.effective.ok, true, JSON.stringify(v.gates.effective));
    assert.equal(v.gates.rescan && v.gates.rescan.originalGone, true, JSON.stringify(v.gates.rescan));
    if (GHC) { assert.equal(v.gates.compile.ran, true); assert.equal(v.gates.compile.ok, true, JSON.stringify(v.gates.compile)); assert.equal(v.status, 'verified', v.reason); }
  }
  const after = await scanOf({ ...files, 'Server.hs': planHaskellFix(readSite, files).after });
  assert.equal(after.length, 0, JSON.stringify(after.map((x) => [x.line, x.vuln])));
});

test('a bare Maybe result gets Nothing; an unqualified System.FilePath import gets the names added', () => {
  const files = { 'P.hs': 'module P (pick) where\nimport System.FilePath ((</>))\n\npick :: FilePath -> Maybe FilePath\npick p = if null p then Nothing else Just ("base" </> p)\n' };
  const plan = planHaskellFix(finding('P.hs', 5), files);
  assert.equal(plan.ok, true, JSON.stringify(plan));
  assert.match(plan.after, /^import System\.FilePath \(\(<\/>\), splitDirectories, isAbsolute\)$/m);
  assert.match(plan.after, /^pick p\n    \| "\.\." `elem` splitDirectories p \|\| isAbsolute p = Nothing\npick p = /m);
});

test('refused: two path parameters, a result with no not-found value, an already-checked parameter', () => {
  const two = { 'T.hs': 'module T (f) where\nf :: FilePath -> FilePath -> IO (Maybe String)\nf a b = Just <$> readFile (a ++ b)\n' };
  assert.equal(planHaskellFix(finding('T.hs', 3), two).ok, false);
  const unit = { 'U.hs': 'module U (f) where\nf :: FilePath -> IO ()\nf p = readFile p >>= putStrLn\n' };
  assert.equal(planHaskellFix(finding('U.hs', 3), unit).ok, false);
  const checked = { 'C.hs': 'module C (f) where\nimport System.FilePath (splitDirectories)\nf :: FilePath -> IO (Maybe String)\nf p = if ".." `elem` splitDirectories p then pure Nothing else Just <$> readFile p\n' };
  assert.equal(planHaskellFix(finding('C.hs', 4), checked).ok, false);
});
