// Round 6 of the real-code work (docs/superpowers/plans/2026-11-14-haskell-real-code-precision.md): the sites the earlier rounds left.
//   1. SSRF: a reverse proxy whose request record takes host, port and scheme from CONFIGURATION and only the path, query, headers and body from the
//      client's request sends the client's text to the operator's destination (keter's `simpleReverseProxy`). `fixedHostRequest` follows the sink's
//      argument into the project function that builds the record and accepts a destination field whose expression contains no request source and
//      names nothing a request source in that function reads from; the result is lowered to info (never refuted: the path is the client's).
//      A destination field read from the request (`requestHeaderHost req`, or a name that `rawPathInfo` is applied to) keeps the finding.
//   2. api-contract (discovery batch 3): a Yesod route whose path was INFERRED from the handler's name (`conventional`) is not compared with a
//      contract (hledger-web's UI pages against its JSON API's OpenAPI); a contract at the repository root governs a route only when the route's
//      own package is the root or the repository holds one package besides the root (graphql-engine's root `metadata.openapi.json` against the
//      data-connector agent's routes in `server/lib/dc-api`, a package of its own among many).
//   3. `api-contract` trust verdict: a caller-controlled parameter handed on WHOLE through a chain of project calls to the path operation (snap's
//      `initJsonFileAuthManager fp` to `loadUserCache fp`), and a parameter that is the BASE directory of a join whose tail is not the parameter
//      (happstack's `joinPath (localPath : rqPaths rq)`): the caller chose the location, as for the thin wrapper.
//   4. `hs-predictable-random` (clock): a clock reading that is only an operand of time arithmetic or a time comparison (`expiresAt = e + now`,
//      `diffUTCTime exp now`) in a token-shaped function is an expiry computation, not a security value (Hasura's token refresh).
//   5. A function whose declared result is a Template Haskell `Q` type (`Q Exp`, `Q [Dec]`) runs at compile time: a file operation in it is the
//      build's, lowered to info (hledger-web's `staticFileRoute`).
//   6. Yesod's `redirect` of a TUPLE is a typed route with query parameters (`(route, params)`): the destination is this site by construction,
//      lowered to info; `redirect text` stays reported.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { mkTestTmp } from '../helpers/tmp.js';

process.env.AGENTIC_SECURITY_DEEP = '1';
delete process.env.CI;

async function scanOf(prefix, files) {
  const { runScan } = await import('../../src/runScan.js');
  const dir = mkdtempSync(join(mkTestTmp(prefix), 'p-'));
  for (const [k, v] of Object.entries(files)) { mkdirSync(dirname(join(dir, k)), { recursive: true }); writeFileSync(join(dir, k), v); }
  const { scan } = await runScan(dir, { deep: true });
  return scan.findings.filter((f) => /\.hs$/.test(f.file));
}
const ssrf = (fs) => fs.filter((f) => f.parser === 'IR-TAINT' && f.cwe === 'CWE-918');

const PROXY = (hostExpr) => `{-# LANGUAGE OverloadedStrings #-}
module Proxy (ProxyConfig(..), mkRequest, proxyApp) where

import Network.Wai
import Network.HTTP.Client
import Network.HTTP.Types (status502)
import Data.Text (Text)
import Data.Text.Encoding (encodeUtf8)

data ProxyConfig = ProxyConfig { targetHost :: Text, targetPort :: Int, targetSsl :: Bool }

mkRequest :: ProxyConfig -> Request -> Network.HTTP.Client.Request
mkRequest cfg req = defaultRequest
  { host = ${hostExpr}
  , port = targetPort cfg
  , secure = targetSsl cfg
  , path = rawPathInfo req
  , queryString = rawQueryString req
  , requestHeaders = requestHeaders req
  }

proxyApp :: Manager -> ProxyConfig -> Application
proxyApp mgr cfg req respond = do
  res <- httpLbs (mkRequest cfg req) mgr
  respond (responseLBS (responseStatus res) [] (responseBody res))
`;

test('SSRF: a reverse proxy whose destination comes from configuration is lowered to info; a destination read from the request keeps the finding', async () => {
  const fixed = ssrf(await scanOf('hs-round6-proxy', { 'package.json': '{}', 'src/Proxy.hs': PROXY('encodeUtf8 (targetHost cfg)') }));
  assert.ok(fixed.length >= 1, 'the flow is still reported (as information)');
  for (const f of fixed) {
    assert.equal(f.severity, 'info', JSON.stringify([f.line, f.severity, f.guardNote]));
    assert.equal(f.guardNote && f.guardNote.kind, 'fixed-host-request');
    assert.ok(!f.refutation, 'the client still chooses the path: lowered, never refuted');
  }
  const fromRequest = ssrf(await scanOf('hs-round6-proxy', { 'package.json': '{}', 'src/Proxy.hs': PROXY('maybe "" id (requestHeaderHost req)') }));
  assert.ok(fromRequest.some((f) => f.severity !== 'info'), JSON.stringify(fromRequest.map((f) => [f.line, f.severity, f.guardNote && f.guardNote.kind])));
  // the host is a value the request's own path was taken from: not configuration either
  const viaName = ssrf(await scanOf('hs-round6-proxy', { 'package.json': '{}', 'src/Proxy.hs': PROXY('encodeUtf8 (targetHost cfg) <> rawPathInfo req') }));
  assert.ok(viaName.some((f) => f.severity !== 'info'), JSON.stringify(viaName.map((f) => [f.line, f.severity, f.guardNote && f.guardNote.kind])));
});

import { runApiContractScan } from '../../src/posture/api-contract.js';
import { analyzeHaskellRules } from '../../src/language/haskell-security-rules.js';

const OPENAPI = JSON.stringify({ openapi: '3.0.0', info: { title: 'p', version: '1' }, paths: { '/users': { get: { responses: { 200: { description: 'ok' } } } } } });
const tmpTree = (prefix, files) => { const dir = mkdtempSync(join(mkTestTmp(prefix), 'p-')); for (const [k, v] of Object.entries(files)) { mkdirSync(dirname(join(dir, k)), { recursive: true }); writeFileSync(join(dir, k), v); } return dir; };
const undocumented = (out) => out.filter((f) => f.subfamily === 'undocumented-endpoint').map((f) => f.line);

test('api-contract: a route whose path was inferred from a handler name is not compared; a root contract governs only the root package or a lone sub-package', () => {
  const dir = tmpTree('hs-round6-contract', { 'openapi.json': OPENAPI, 'package.json': '{}', 'src/A.hs': 'module A where\n' });
  assert.deepEqual(undocumented(runApiContractScan(dir, [{ method: 'GET', path: '/add', file: 'src/A.hs', line: 7, conventional: true }], {})), []);
  assert.deepEqual(undocumented(runApiContractScan(dir, [{ method: 'GET', path: '/add', file: 'src/A.hs', line: 7 }], {})), [7]);
  // several packages under the root: the root contract describes one of them, which one is not known, so none is compared
  const many = tmpTree('hs-round6-contract', { 'openapi.json': OPENAPI, 'server/p.cabal': 'name: p\n', 'server/lib/dc-api/dc-api.cabal': 'name: dc-api\n', 'cli/go.mod': 'module x\n', 'server/lib/dc-api/src/API.hs': 'module API where\n' });
  assert.deepEqual(undocumented(runApiContractScan(many, [{ method: 'POST', path: '/explain', file: 'server/lib/dc-api/src/API.hs', line: 134 }], {})), []);
  // one package beside the root: the root contract is that package's
  const one = tmpTree('hs-round6-contract', { 'openapi.json': OPENAPI, 'server/p.cabal': 'name: p\n', 'server/src/API.hs': 'module API where\n' });
  assert.deepEqual(undocumented(runApiContractScan(one, [{ method: 'POST', path: '/explain', file: 'server/src/API.hs', line: 9 }], {})), [9]);
});

const pathLib = (body) => scanOf('hs-round6-wrapper', { 'p.cabal': 'cabal-version: 2.4\nname: p\nversion: 0.1\nlibrary\n    exposed-modules: Lib\n    hs-source-dirs: src\n    build-depends: base\n', 'src/Lib.hs': `module Lib (initAuth, serveDir, serveNamed) where\n\nimport System.Directory (doesFileExist)\nimport System.FilePath (joinPath)\n\n${body}` });
const cwe22 = (fs) => fs.filter((f) => f.parser === 'IR-TAINT' && f.cwe === 'CWE-22');

test('api-contract verdict: a parameter handed on whole through two project calls, and a parameter that is the base directory of a join, are the caller\'s choice; a parameter under a fixed directory is not', async () => {
  const fs = await pathLib([
    'initAuth :: FilePath -> IO Bool', 'initAuth fp = do', '  putStrLn "loading"', '  mkAuth fp', '',
    'mkAuth :: FilePath -> IO Bool', 'mkAuth fp = do', '  putStrLn "cache"', '  loadUsers fp', '',
    'loadUsers :: FilePath -> IO Bool', 'loadUsers fp = do', '  e <- doesFileExist fp', '  pure e', '',
    'serveDir :: FilePath -> [String] -> IO Bool', 'serveDir base pieces = do', '  e <- doesFileExist (joinPath (base : pieces))', '  pure e', '',
    'serveNamed :: FilePath -> IO Bool', 'serveNamed name = do', '  e <- doesFileExist (joinPath ["/srv/static", name])', '  pure e',
  ].join('\n') + '\n');
  const at = (line) => cwe22(fs).filter((f) => f.line === line);
  const lines = cwe22(fs).map((f) => [f.line, f.severity, f.trustBoundary && f.trustBoundary.verdict]);
  assert.ok(at(18).length, `loadUsers reports the read ${JSON.stringify(lines)}`); assert.ok(at(23).length, `serveDir reports the read ${JSON.stringify(lines)}`); assert.ok(at(28).length, `serveNamed reports the read ${JSON.stringify(lines)}`);
  for (const f of at(18)) assert.equal(f.trustBoundary.verdict, 'api-contract', JSON.stringify(f.trustBoundary));
  for (const f of at(23)) assert.equal(f.trustBoundary.verdict, 'api-contract', JSON.stringify(f.trustBoundary));
  for (const f of at(28)) assert.equal(f.trustBoundary.verdict, 'entry-parameter', JSON.stringify(f.trustBoundary));
});

const clock = (body) => analyzeHaskellRules({ 'Svc.hs': `module Svc where\nimport Data.Time.Clock\nimport Data.Time.Clock.POSIX\nimport Control.Concurrent (threadDelay)\n\n${body}` }).findings.filter((f) => f.rule === 'hs-predictable-random');

test('clock: a reading that only enters time arithmetic or a time comparison in a token-shaped function is an expiry, not a security value; a clock that becomes the token is', () => {
  assert.equal(clock('refreshToken :: Int -> IO Int\nrefreshToken ttl = do\n  now <- getPOSIXTime\n  pure (round now + ttl)\n').length, 0, 'expiry = now + ttl');
  assert.equal(clock('tokenExpiryHandler :: UTCTime -> IO ()\ntokenExpiryHandler expTime = do\n  currTime <- getCurrentTime\n  threadDelay (round (diffUTCTime expTime currTime))\n').length, 0, 'diffUTCTime exp now');
  assert.equal(clock('newToken :: IO String\nnewToken = do\n  now <- getPOSIXTime\n  pure (show now)\n').length, 1, 'the token is the time');
});

const TH = `{-# LANGUAGE TemplateHaskell #-}
module Settings (staticFileRoute, checkFile) where

import Language.Haskell.TH
import System.Directory (doesFileExist)
import System.FilePath ((</>))

staticFileRoute :: FilePath -> Q Exp
staticFileRoute f = do
  exists <- runIO (doesFileExist ("static" </> f))
  if exists then [| f |] else fail "missing"

checkFile :: FilePath -> IO Bool
checkFile f = doesFileExist ("static" </> f)
`;

test('compile time: a file operation in a function returning a Template Haskell Q type is the build\'s, lowered to info; the runtime twin keeps its finding', async () => {
  const fs = cwe22(await scanOf('hs-round6-th', { 'p.cabal': 'cabal-version: 2.4\nname: p\nversion: 0.1\nlibrary\n    exposed-modules: Settings\n    hs-source-dirs: src\n    build-depends: base\n', 'src/Settings.hs': TH }));
  const th = fs.filter((f) => f.line === 10); const rt = fs.filter((f) => f.line === 14);
  assert.ok(th.length && rt.length, JSON.stringify(fs.map((f) => [f.line, f.severity])));
  for (const f of th) { assert.equal(f.severity, 'info', JSON.stringify([f.line, f.severity, f.guardNote])); assert.equal(f.guardNote && f.guardNote.kind, 'compile-time-splice'); }
  for (const f of rt) assert.notEqual(f.severity, 'info');
});

const YESOD_REDIRECT = (target) => `{-# LANGUAGE OverloadedStrings #-}
module Handler.Go (getGoR) where

import Yesod.Core
import Data.Maybe (fromMaybe)
import Data.Text (Text)

data App = App
mkYesodData "App" [parseRoutes| /go GoR GET
/bar BarR GET |]

getGoR :: HandlerFor App ()
getGoR = do
  q <- lookupGetParam "q"
  redirect ${target}
`;

test('redirect: a Yesod redirect of a tuple is a typed route with query parameters (this site); a redirect of request text stays reported', async () => {
  const typed = (await scanOf('hs-round6-redirect', { 'p.cabal': 'cabal-version: 2.4\nname: p\nversion: 0.1\nlibrary\n    exposed-modules: Handler.Go\n    hs-source-dirs: src\n    build-depends: base\n', 'src/Handler/Go.hs': YESOD_REDIRECT('(BarR, [("q", fromMaybe "" q)])') })).filter((f) => f.cwe === 'CWE-601');
  for (const f of typed) { assert.equal(f.severity, 'info', JSON.stringify([f.line, f.severity, f.guardNote])); assert.equal(f.guardNote && f.guardNote.kind, 'typed-route-redirect'); }
  const text = (await scanOf('hs-round6-redirect', { 'p.cabal': 'cabal-version: 2.4\nname: p\nversion: 0.1\nlibrary\n    exposed-modules: Handler.Go\n    hs-source-dirs: src\n    build-depends: base\n', 'src/Handler/Go.hs': YESOD_REDIRECT('(fromMaybe "" q)') })).filter((f) => f.cwe === 'CWE-601');
  assert.ok(text.some((f) => f.severity !== 'info'), JSON.stringify(text.map((f) => [f.line, f.severity])));
});

// happstack's shape: the exported function holds the parameter, an intermediate builds the join into a LOCAL and hands it to the function with the
// sink, which is also reached by recursion; the finding is collected under the intermediate or the recursive function, not the exported one
const SERVE = `module Serve (serveDirectory, doIndex) where

import System.Directory (doesFileExist)
import System.FilePath (joinPath, (</>))

serveDirectory :: [String] -> FilePath -> IO Bool
serveDirectory ixFiles localPath = do
  putStrLn "serving"
  fileServe' ixFiles localPath

fileServe' :: [String] -> FilePath -> IO Bool
fileServe' pieces localPath = do
  let fp = joinPath (localPath : pieces)
  e <- doesFileExist fp
  if e then serveFileUsing fp else pure False

serveFileUsing :: FilePath -> IO Bool
serveFileUsing fp = do
  e <- doesFileExist fp
  pure e

doIndex :: [String] -> FilePath -> IO Bool
doIndex ixFiles localPath = do
  putStrLn "index"
  tryIndex ixFiles localPath

tryIndex :: [String] -> FilePath -> IO Bool
tryIndex [] _ = pure False
tryIndex (index:rest) fp = do
  let path = fp </> index
  e <- doesFileExist path
  if e then pure True else tryIndex rest fp
`;

test('api-contract verdict: the handoff is traced from the function that holds the parameter, through an intermediate\'s local join and into a recursive callee', async () => {
  const fs = cwe22(await scanOf('hs-round6-serve', { 'p.cabal': 'cabal-version: 2.4\nname: p\nversion: 0.1\nlibrary\n    exposed-modules: Serve\n    hs-source-dirs: src\n    build-depends: base\n', 'src/Serve.hs': SERVE }));
  const lines = fs.map((f) => [f.line, f.severity, f.trustBoundary && f.trustBoundary.verdict]);
  assert.ok(fs.length >= 3, JSON.stringify(lines));
  for (const f of fs) assert.equal(f.trustBoundary.verdict, 'api-contract', JSON.stringify([f.line, f.trustBoundary]));
});
