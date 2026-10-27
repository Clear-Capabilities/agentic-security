// Trust-boundary precision for Haskell, pinned in BOTH directions. Every precision change made for real-code false positives is paired with the
// vulnerable form that must still be found and a near-miss that shares its surface. The sources are written for this file in the idioms of real
// Haskell programs; none is copied from a corpus case or from a project.
//
// Groups: 1 where the origin of tainted data is recorded (derived values, return values, parameters across hops), 2 the trust verdicts (a request or
// a socket is not the operator; arguments, environment and a command-line program's own files are), 3 pass-through wrappers, 4 reachability of
// platform variants, 5 the rules that read the function around a call (weak hash, randomness, unbounded reads, partial functions, cookies, unsafe
// names), 6 the framework web/auth handlers keep their findings.

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { analyzeHaskellRules } from '../../src/language/haskell-security-rules.js';
import { runScan } from '../../src/runScan.js';
import { mkTestTmp } from '../helpers/tmp.js';

const mod = (imports, body, header = 'module Svc where') => `${header}\n\n${imports.join('\n')}\n\n${body}\n`;
const rules = (src) => analyzeHaskellRules({ 'Svc.hs': src }).findings;

async function scanAll(files) {
  const dir = mkTestTmp('hs-trust-');
  writeFileSync(join(dir, 'package.json'), '{}');
  for (const [f, text] of Object.entries(files)) { mkdirSync(dirname(join(dir, f)), { recursive: true }); writeFileSync(join(dir, f), text); }
  const r = await runScan(dir, { deep: true });
  return [...(r.scan.findings || [])];
}
// a finding a default scan would flag: not lowered to info and not proven clean
const flagged = (fs, cwe) => fs.filter((f) => f.parser === 'IR-TAINT' && (!cwe || f.cwe === cwe) && f.severity !== 'info' && !(f.proof && /^proven-/.test(f.proof.verdict)));
const lowered = (fs, cwe) => fs.filter((f) => f.parser === 'IR-TAINT' && (!cwe || f.cwe === cwe) && f.severity === 'info' && f.trustBoundary);

// ── 1. where tainted data came from ──────────────────────────────────────────

test('origin: a value derived from an environment read keeps its origin across a record, a return value and two calls', async () => {
  const fs = await scanAll({
    'Dirs.hs': mod(['import System.Environment', 'import System.FilePath', 'import System.Directory', 'import Control.Monad'], `data Dirs = Dirs { baseDir :: FilePath }

getAllDirs :: IO Dirs
getAllDirs = do
  home <- getEnv "HOME"
  let base = home </> ".tool"
  pure (Dirs { baseDir = base })

toolDir :: Dirs -> String -> FilePath
toolDir ds ver = baseDir ds </> "tools" </> ver

removeTool :: Dirs -> String -> IO ()
removeTool ds ver = do
  let d = toolDir ds ver
  e <- doesDirectoryExist d
  when e $ removeFile (d </> "marker")`, 'module Dirs (Dirs(..), getAllDirs, toolDir, removeTool) where'),
    'Main.hs': mod(['import Dirs'], 'main :: IO ()\nmain = do\n  ds <- getAllDirs\n  removeTool ds "9.4"', 'module Main (main) where'),
  });
  const path = fs.filter((f) => f.parser === 'IR-TAINT' && f.cwe === 'CWE-22');
  assert.ok(path.length >= 1, 'the flow is still reported (as information)');
  for (const f of path) {
    assert.ok(Array.isArray(f.sourceRoots) && f.sourceRoots.some((r) => r.provenance === 'env'), `the origin is the environment: ${JSON.stringify(f.sourceRoots)}`);
    assert.equal(f.trustBoundary.verdict, 'operator-controlled');
    assert.equal(f.severity, 'info');
  }
});

test('origin: the same shape fed by a request value is attacker-reachable and keeps its severity', async () => {
  const fs = await scanAll({
    'Svc.hs': mod(['import Web.Scotty', 'import System.FilePath', 'import System.Directory', 'import Control.Monad.IO.Class (liftIO)'], `toolDir :: String -> FilePath
toolDir ver = "/srv/tools" </> ver

removeTool :: String -> IO ()
removeTool ver = removeFile (toolDir ver </> "marker")

main :: IO ()
main = scotty 3000 $ post "/tools/:v" $ do
  v <- param "v"
  liftIO (removeTool v)
  text "ok"`, 'module Svc (main) where'),
  });
  const path = flagged(fs, 'CWE-22');
  assert.equal(path.length, 1, JSON.stringify(path.map((f) => [f.line, f.severity])));
  assert.equal(path[0].trustBoundary.verdict, 'attacker-reachable');
  assert.ok(path[0].sourceRoots === undefined || path[0].sourceRoots.every((r) => r.provenance !== 'env'));
});

// ── 2. the verdicts ──────────────────────────────────────────────────────────

test('operator: a command-line argument or an environment variable reaching a command in a command-line program names no boundary; a request value does', async () => {
  const cli = await scanAll({ 'Main.hs': mod(['import System.Environment', 'import System.Process'], 'main :: IO ()\nmain = do\n  [pkg] <- getArgs\n  callCommand ("cabal install " ++ pkg)', 'module Main (main) where') });
  assert.equal(flagged(cli, 'CWE-78').length, 0, 'the person who runs the program chose the argument');
  const low = lowered(cli, 'CWE-78');
  assert.equal(low.length, 1);
  assert.equal(low[0].trustBoundary.verdict, 'operator-controlled');
  assert.equal(low[0].originalSeverity, 'critical', 'the severity it would have had is kept');
  const env = await scanAll({ 'Main.hs': mod(['import System.Environment', 'import System.Process'], 'main :: IO ()\nmain = do\n  cmd <- getEnv "BUILD_CMD"\n  callCommand cmd', 'module Main (main) where') });
  assert.equal(flagged(env, 'CWE-78').length, 0);
  const web = await scanAll({ 'Main.hs': mod(['import Web.Scotty', 'import System.Process', 'import Control.Monad.IO.Class (liftIO)'], 'main :: IO ()\nmain = scotty 3000 $ post "/build/:pkg" $ do\n  pkg <- param "pkg"\n  liftIO (callCommand ("cabal install " ++ pkg))\n  text "ok"', 'module Main (main) where') });
  assert.equal(flagged(web, 'CWE-78').length, 1);
  assert.equal(flagged(web, 'CWE-78')[0].trustBoundary.verdict, 'attacker-reachable');
});

test('operator: standard input in a command-line program is still data the program processes, so a flow from it stays reported', async () => {
  const fs = await scanAll({ 'Main.hs': mod(['import System.Process'], 'main :: IO ()\nmain = do\n  l <- getLine\n  callCommand l', 'module Main (main) where') });
  const f = flagged(fs, 'CWE-78');
  assert.equal(f.length, 1);
  assert.equal(f[0].trustBoundary.verdict, 'data-input');
});

test('operator: a remote response read by a command-line program is not the operator, so a download that reaches a command stays reported', async () => {
  const fs = await scanAll({ 'Main.hs': mod(['import Network.HTTP.Simple', 'import System.Process', 'import qualified Data.ByteString.Lazy.Char8 as L'], `main :: IO ()
main = do
  resp <- httpLBS "https://example.org/install.sh"
  callCommand (L.unpack (getResponseBody resp))`, 'module Main (main) where') });
  const f = flagged(fs, 'CWE-78');
  assert.equal(f.length, 1, JSON.stringify(fs.map((x) => [x.parser, x.line, x.severity, x.trustBoundary && x.trustBoundary.verdict])));
  assert.equal(f[0].trustBoundary.verdict, 'attacker-reachable');
});

test('operator: files a command-line program reads are the operator\'s; the same read in a web service is not', async () => {
  const cliSrc = mod(['import System.Directory', 'import System.Process'], 'main :: IO ()\nmain = do\n  target <- readFile "target.txt"\n  removeFile target', 'module Main (main) where');
  const cli = await scanAll({ 'Main.hs': cliSrc });
  assert.equal(flagged(cli, 'CWE-22').length, 0);
  assert.equal(lowered(cli, 'CWE-22')[0].trustBoundary.verdict, 'operator-controlled');
  const svc = await scanAll({ 'Main.hs': mod(['import Web.Scotty', 'import System.Directory', 'import Control.Monad.IO.Class (liftIO)'], 'main :: IO ()\nmain = scotty 3000 $ post "/purge" $ do\n  target <- liftIO (readFile "target.txt")\n  liftIO (removeFile target)\n  text "ok"', 'module Main (main) where') });
  const f = flagged(svc, 'CWE-22');
  assert.equal(f.length, 1, 'a service shares its files with its clients');
  assert.equal(f[0].trustBoundary.verdict, 'data-input');
});

// ── 3. pass-through wrappers ─────────────────────────────────────────────────

test('wrapper: a function that hands its parameters whole to a process is a thin wrapper, one that builds the command around a parameter is not', async () => {
  const wrapper = await scanAll({ 'Svc.hs': mod(['import System.Process'], 'run :: FilePath -> [String] -> IO ()\nrun exe args = callProcess exe args', 'module Svc (run) where') });
  assert.equal(flagged(wrapper, 'CWE-78').length + flagged(wrapper, 'CWE-88').length, 0);
  assert.ok(lowered(wrapper).some((f) => f.trustBoundary.verdict === 'api-contract'));
  const builds = await scanAll({ 'Svc.hs': mod(['import System.Process'], 'unpackIt :: String -> IO ()\nunpackIt name = callCommand ("tar xf " ++ name ++ " -C /srv/data")', 'module Svc (unpackIt) where') });
  assert.equal(flagged(builds, 'CWE-78').length, 1, 'the function chose the program and splices the parameter into it');
  assert.equal(flagged(builds, 'CWE-78')[0].trustBoundary.verdict, 'entry-parameter');
  const element = await scanAll({ 'Svc.hs': mod(['import System.Process'], 'thumb :: String -> IO ()\nthumb n = callProcess "convert" [n, "out.png"]', 'module Svc (thumb) where') });
  assert.equal(flagged(element, 'CWE-88').length, 1, 'a fixed program with a caller-chosen argument is argument injection');
});

test('wrapper: a path operation on a caller-named file is kept (the vulnerable synthetic shape), because only the shell/process wrappers are judged pass-through', async () => {
  const fs = await scanAll({ 'Svc.hs': mod(['import System.IO'], 'saveUpload :: String -> String -> IO ()\nsaveUpload name content = withFile name WriteMode (\\h -> hPutStr h content)', 'module Svc (saveUpload) where') });
  assert.equal(flagged(fs, 'CWE-22').length, 1);
});

// ── 4. platform variants ─────────────────────────────────────────────────────

test('reachability: two modules that both satisfy an import (one per platform) are both called, so neither is an uncalled entry point', async () => {
  const body = (m, extra = '') => mod(['import System.Directory'], `readLog :: FilePath -> IO String\nreadLog name = readFile ("/var/log/tool/" ++ name)${extra}`, `module ${m} (readLog) where`);
  const files = {
    'src/Plat/Posix.hs': body('Plat.Posix'),
    'src/Plat/Windows.hs': body('Plat.Windows'),
    'src/Plat.hs': '{-# LANGUAGE CPP #-}\nmodule Plat (readLog) where\n\n#if defined(PLATFORM_IS_WINDOWS)\nimport Plat.Windows\n#else\nimport Plat.Posix\n#endif\n',
    'app/Main.hs': mod(['import Plat'], 'main :: IO ()\nmain = readLog "today.log" >>= putStr', 'module Main (main) where'),
  };
  const fs = await scanAll(files);
  assert.equal(flagged(fs, 'CWE-22').length, 0, JSON.stringify(flagged(fs, 'CWE-22').map((f) => [f.file, f.line])));
  // the same function with nothing calling it anywhere is an entry point whose callers are unknown
  const orphan = await scanAll({ 'src/Plat/Posix.hs': body('Plat.Posix') });
  assert.equal(flagged(orphan, 'CWE-22').length, 1);
});

// ── 5. rules that read the function around a call ────────────────────────────

test('weak hash: MD5/SHA-1 is a finding where a verification, a secret or a credential depends on it, and a note where it only names something', () => {
  const imp = ['import qualified Crypto.Hash.MD5 as MD5', 'import qualified Data.ByteString as B', 'import qualified Data.ByteString.Char8 as BC'];
  const sev = (body) => rules(mod(imp, body)).filter((f) => f.rule === 'hs-weak-hash').map((f) => f.severity);
  assert.deepEqual(sev('verify :: B.ByteString -> B.ByteString -> Bool\nverify body expected = MD5.hash body == expected'), ['medium'], 'the digest is compared with an expected value');
  assert.deepEqual(sev('sign :: B.ByteString -> B.ByteString -> B.ByteString\nsign secret msg = MD5.hash (secret <> msg)'), ['medium'], 'a secret is hashed');
  assert.deepEqual(sev('sessionToken :: B.ByteString -> String\nsessionToken seed = BC.unpack (MD5.hash seed)'), ['medium'], 'the result is a credential');
  assert.deepEqual(sev('cacheName :: B.ByteString -> FilePath\ncacheName body = BC.unpack (MD5.hash body) ++ ".bin"'), ['info'], 'a file name');
  assert.deepEqual(sev('etag :: B.ByteString -> B.ByteString\netag body = MD5.hash body'), ['info'], 'a helper handed on to callers says nothing about its use');
  assert.deepEqual(sev('stamp :: B.ByteString -> IO ()\nstamp body = do\n  let h = BC.unpack (MD5.hash body)\n  r <- pure 0\n  if r == (0 :: Int) then putStrLn h else pure ()'), ['info'], 'an unrelated comparison does not make the digest a verification');
});

test('randomness: a token, nonce or key from a non-cryptographic generator is a finding, a salt (unique, not secret) is not', () => {
  const imp = ['import System.Random', 'import Control.Monad (replicateM)'];
  const has = (body) => rules(mod(imp, body)).some((f) => f.rule === 'hs-predictable-random');
  assert.ok(has('newToken :: IO String\nnewToken = replicateM 16 (randomRIO (\'a\', \'z\'))'));
  assert.ok(has('freshNonce :: IO Int\nfreshNonce = randomRIO (1, 1000000000)'));
  assert.ok(!has('genSalt :: IO String\ngenSalt = replicateM 16 (randomRIO (\'a\', \'z\'))'));
});

test('cookies: a session cookie built from a variable lacks the flags; one whose whole value is a constant (a cleared login) is not a credential', () => {
  const imp = ['import Network.HTTP.Types.Header', 'import qualified Data.ByteString.Char8 as BC'];
  const has = (body) => rules(mod(imp, body)).some((f) => f.rule === 'hs-insecure-cookie');
  assert.ok(has('mk :: String -> (HeaderName, BC.ByteString)\nmk sid = (hSetCookie, BC.pack ("session_id=" ++ sid ++ "; Path=/"))'));
  assert.ok(!has('clear :: (HeaderName, BC.ByteString)\nclear = (hSetCookie, BC.pack "session_id=0; Path=/")'));
});

test('unsafe names: a parameter called constructor or toString is not an unsafe boundary, an unsafePerformIO is', () => {
  const body = 'wrap :: (Int -> Int) -> Int -> [Int]\nwrap constructor n = [constructor n, toString n, valueOf n, hasOwnProperty n]\n\ntoString :: Int -> Int\ntoString = id\nvalueOf :: Int -> Int\nvalueOf = id\nhasOwnProperty :: Int -> Int\nhasOwnProperty = id';
  assert.equal(rules(mod([], body)).filter((f) => f.rule === 'hs-unsafe-io-boundary').length, 0);
  const real = rules(mod(['import System.IO.Unsafe (unsafePerformIO)'], 'counter :: Int\ncounter = unsafePerformIO (pure 1)'));
  assert.equal(real.filter((f) => f.rule === 'hs-unsafe-io-boundary').length, 1);
});

test('unbounded reads: a socket handle or an uncalled entry point that slurps stdin is reported; a file, a child pipe and a program\'s own stdin are not', () => {
  const has = (imports, body) => rules(mod(imports, body)).some((f) => f.rule === 'hs-unbounded-input-read');
  assert.ok(has(['import System.IO'], 'slurp :: IO String\nslurp = getContents'), 'nothing calls it: its callers are unknown');
  assert.ok(!has(['import System.IO'], 'slurp :: IO String\nslurp = getContents\n\nmain :: IO ()\nmain = slurp >>= putStr'), 'the program reads its own standard input');
  assert.ok(!has(['import System.IO'], 'readLog :: FilePath -> IO String\nreadLog p = withFile p ReadMode hGetContents'), 'a local file');
  assert.ok(has(['import System.IO', 'import Network'], 'serve :: PortID -> IO String\nserve p = do\n  s <- listenOn p\n  (h, _, _) <- accept s\n  hGetContents h'), 'a peer fills a socket handle');
});

test('partial functions: head of a parameter of an uncalled function and of a handler parameter is reported, head inside a helper the program calls is not', () => {
  const handler = rules(mod(['import Web.Scotty', 'import qualified Data.Text as T'], 'greet :: T.Text -> ActionM ()\ngreet name = text (T.pack [T.head name])'));
  assert.ok(handler.some((f) => f.rule === 'hs-partial-function-on-input'), 'a framework handler\'s parameter is request input wherever the handler is registered');
  const has = (imports, body) => rules(mod(imports, body)).some((f) => f.rule === 'hs-partial-function-on-input');
  assert.ok(has([], 'firstWord :: String -> String\nfirstWord s = head (words s)'), 'an uncalled exported function');
  assert.ok(!has([], 'firstWord :: String -> String\nfirstWord s = head (words s)\n\nmain :: IO ()\nmain = putStrLn (firstWord "a b")'), 'called by the program, whose callers decide the value');
});
