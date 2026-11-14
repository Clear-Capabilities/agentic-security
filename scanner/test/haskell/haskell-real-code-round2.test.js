// Round 2 of the real-code precision work (docs/superpowers/plans/2026-11-14-haskell-real-code-precision.md, follow-up): four general mechanisms,
// each taken from a labelled false positive on the fresh or discovery sets and pinned here on synthetic code written from the shape.
//   1. WAI hands a handler only the Request: a text parameter of a function returning `IO ResponseReceived` is the caller's value, not request input
//      (IHP `renderFile`). The function is still a WAI entry handler for reachability.
//   2. An uploaded part's `fileContent` is a FilePath only under `tempFileBackEnd`, where the FRAMEWORK chose it: a path operation on it is not
//      attacker-steerable (wai-request-params `readTempFileLazily`). Its `fileName` is the browser's text and stays a path source.
//   3. `case length xs of 3 -> xs !! 1` tests the length (the IR lowers the alternative to a `<match>` on the length scratch variable, which the
//      partial-function rule read only as `==` or an `if`). IHP `renderDefaultWithoutType`.
//   4. An XSRF double-submit cookie is readable by design: HttpOnly is not missing on it; Secure still is (servant-auth-server, three sites).
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { mkTestTmp } from '../helpers/tmp.js';
import { buildHaskellIR } from '../../src/language/haskell-ir.js';
import { analyzeHaskellRules } from '../../src/language/haskell-security-rules.js';

process.env.AGENTIC_SECURITY_DEEP = '1';
delete process.env.CI;

async function scanOf(files) {
  const { runScan } = await import('../../src/runScan.js');
  const dir = mkdtempSync(join(mkTestTmp('hs-round2'), 'p-'));
  for (const [k, v] of Object.entries(files)) { mkdirSync(dirname(join(dir, k)), { recursive: true }); writeFileSync(join(dir, k), v); }
  const { scan } = await runScan(dir);
  return scan.findings.filter((f) => /\.hs$/.test(f.file));
}
const CABAL = 'cabal-version: 2.4\nname: p\nversion: 0.1\nlibrary\n    exposed-modules: Render, Upload\n    hs-source-dirs: src\n    build-depends: base\n';

// ── 1. WAI: a text parameter of an `IO ResponseReceived` function is not request input ───────────────────────────────────────────────
const RENDER = `{-# LANGUAGE ImplicitParams, OverloadedStrings #-}
module Render (renderFile, app) where
import Network.Wai
import Network.HTTP.Types (status200, hContentType)
import qualified Data.ByteString.Char8 as B8
import qualified Data.Text as T

renderFile :: (?respond :: Response -> IO ResponseReceived) => String -> B8.ByteString -> IO ResponseReceived
renderFile filePath contentType = ?respond (responseFile status200 [(hContentType, contentType)] filePath Nothing)

app :: Application
app req respond = respond (responseFile status200 [] ("static/" ++ T.unpack (T.intercalate "/" (pathInfo req))) Nothing)
`;
test('WAI: the String parameter of renderFile is the caller\'s value (not request input), while a path built from the Request stays attacker-reachable, and both are entry handlers', async () => {
  const fs = await scanOf({ 'p.cabal': CABAL, 'src/Render.hs': RENDER, 'src/Upload.hs': 'module Upload where\n' });
  const paths = fs.filter((f) => f.file === 'src/Render.hs' && f.cwe === 'CWE-22');
  const helper = paths.find((f) => f.line === 9); const direct = paths.find((f) => f.line === 12);
  assert.ok(direct, JSON.stringify(paths.map((f) => [f.line, f.severity, f.trustBoundary && f.trustBoundary.verdict])));
  assert.equal(direct.trustBoundary.verdict, 'attacker-reachable');
  if (helper) {
    assert.notEqual(helper.trustBoundary.verdict, 'attacker-reachable', JSON.stringify(helper.trustBoundary));
    assert.ok(!helper.trustBoundary.roots.some((r) => r.provenance === 'url-param'), 'no request provenance was invented for the caller\'s parameter');
  }
  const ir = buildHaskellIR({ 'src/Render.hs': RENDER });
  const fns = Object.values(ir.perFile)[0].functions;
  assert.equal(fns.find((f) => /\.renderFile$/.test(f.name)).hs.entryHandler, 'wai', 'reachability still treats the WAI-typed function as a root');
  assert.equal(fns.find((f) => /\.app$/.test(f.name)).hs.entryHandler, 'wai');
});

// ── 2. an uploaded part's fileContent as a path is the framework's temporary file ─────────────────────────────────────────────────────
const UPLOAD = `{-# LANGUAGE OverloadedStrings #-}
module Upload (readTempFileLazily, saveUpload) where
import Network.Wai.Parse (FileInfo, fileContent, fileName)
import qualified Data.ByteString.Lazy as LBS
import qualified Data.ByteString.Char8 as B8
import System.FilePath ((</>))

readTempFileLazily :: FileInfo FilePath -> IO LBS.ByteString
readTempFileLazily fileInfo = LBS.readFile (fileContent fileInfo)

saveUpload :: FileInfo LBS.ByteString -> IO ()
saveUpload fi = LBS.writeFile ("uploads" </> B8.unpack (fileName fi)) (fileContent fi)
`;
test('upload: a path operation on fileContent is lowered as the framework\'s temporary file; a path built from fileName stays reported', async () => {
  const fs = await scanOf({ 'p.cabal': CABAL, 'src/Upload.hs': UPLOAD, 'src/Render.hs': 'module Render where\n' });
  const paths = fs.filter((f) => f.file === 'src/Upload.hs' && f.cwe === 'CWE-22');
  const temp = paths.find((f) => f.line === 9); const named = paths.find((f) => f.line === 12);
  assert.ok(temp && named, JSON.stringify(paths.map((f) => [f.line, f.severity, f.trustBoundary && f.trustBoundary.verdict])));
  assert.equal(temp.severity, 'info'); assert.equal(temp.originalSeverity, 'high');
  assert.equal(temp.trustBoundary.verdict, 'framework-controlled');
  assert.match(temp.guardNote.reason, /tempFileBackEnd/);
  assert.notEqual(named.severity, 'info'); assert.equal(named.trustBoundary.verdict, 'attacker-reachable');
});

// ── 3. a case on the length is a bounds test ───────────────────────────────────────────────────────────────────────────────────────
const FRAMEWORK = `{-# LANGUAGE ImplicitParams #-}
module IHP.Controller.Param (param) where
import Data.Text (Text)
import qualified Data.Text as T
import Network.Wai (Request, queryString)
param :: (?request :: Request) => Text -> Text
param name = maybe "" (T.pack . show) (lookup (T.unpack name) (map (\\(k, v) -> (show k, v)) (queryString ?request)))
`;
const LAYOUT = (body) => `{-# LANGUAGE ImplicitParams, OverloadedStrings #-}
module Layout (showAction) where
import Data.Text (Text)
import qualified Data.Text as T
import IHP.Controller.Param (param)
import Network.Wai (Request)

showAction :: (?request :: Request) => IO ()
showAction = do
    let columnDefault = param "default"
    print (renderDefault columnDefault)

renderDefault :: Text -> Text
${body}
`;
test('partial function: `case length xs of 3 -> xs !! 1` is total on that branch; the same index with no length test is reported', () => {
  const partials = (src) => analyzeHaskellRules({ 'IHP/Controller/Param.hs': FRAMEWORK, 'Layout.hs': src }).findings.filter((f) => f.rule === 'hs-partial-function-on-input' && /!!/.test(f.description));
  const bare = partials(LAYOUT('renderDefault input = (T.splitOn "\'" input) !! 1'));
  assert.ok(bare.length >= 1, 'the index on a list split from request text is reported');
  const guarded = LAYOUT('renderDefault input = case length (T.splitOn "\'" input) of\n        3 -> (T.splitOn "\'" input) !! 1\n        _ -> input');
  assert.deepEqual(partials(guarded).map((f) => f.line), [], 'the alternative runs only when the list has three elements');
});

// ── 4. an XSRF cookie is readable by design ────────────────────────────────────────────────────────────────────────────────────────
const COOKIES = (xsrf, session) => `{-# LANGUAGE OverloadedStrings #-}
module Cookies (makeCookies) where
import Web.Cookie
import Data.Default (def)

data Settings = Settings { xsrfCookieName :: ByteString, sessionCookieName :: ByteString }

makeCookies :: Settings -> ByteString -> ByteString -> (SetCookie, SetCookie)
makeCookies settings token sid = (xsrf, session)
  where
    xsrf = def
      { setCookieName = xsrfCookieName settings
      , setCookieValue = token
      ${xsrf}
      }
    session = def
      { setCookieName = sessionCookieName settings
      , setCookieValue = sid
      ${session}
      }
`;
test('cookie: an XSRF double-submit cookie without HttpOnly is by design; without Secure it is still reported; the session cookie needs both', () => {
  const cookies = (src) => analyzeHaskellRules({ 'Cookies.hs': src }).findings.filter((f) => f.rule === 'hs-insecure-cookie').map((f) => [f.line, f.description.replace(/^[^:]*: /, '')]);
  assert.deepEqual(cookies(COOKIES(', setCookieHttpOnly = False\n      , setCookieSecure = True', ', setCookieHttpOnly = True\n      , setCookieSecure = True')), []);
  assert.deepEqual(cookies(COOKIES(', setCookieHttpOnly = False\n      , setCookieSecure = False', ', setCookieHttpOnly = True\n      , setCookieSecure = True')), [[11, 'Secure missing']]);
  assert.deepEqual(cookies(COOKIES(', setCookieHttpOnly = False\n      , setCookieSecure = True', ', setCookieHttpOnly = False\n      , setCookieSecure = True')), [[17, 'HttpOnly missing']]);
});

test('cookie: an attribute set from configuration is not missing, it is unjudged (info); a cookie cleared with a constant value carries no credential', () => {
  const all = (src) => analyzeHaskellRules({ 'Cookies.hs': src }).findings.filter((f) => f.rule === 'hs-insecure-cookie').map((f) => [f.line, f.severity, f.description.replace(/^[^:]*: /, '')]);
  // servant-auth-server: `setCookieSecure = case cookieIsSecure cookieSettings of Secure -> True; NotSecure -> False` (the NotSecure setting has its own rule)
  const configured = COOKIES(', setCookieHttpOnly = False\n      , setCookieSecure = case secureSetting settings of { 1 -> True; _ -> False }', ', setCookieHttpOnly = True\n      , setCookieSecure = case secureSetting settings of { 1 -> True; _ -> False }')
    .replace('data Settings = Settings { xsrfCookieName :: ByteString, sessionCookieName :: ByteString }', 'data Settings = Settings { xsrfCookieName :: ByteString, sessionCookieName :: ByteString, secureSetting :: Int }');
  assert.deepEqual(all(configured), [[11, 'info', 'Secure set from configuration, not judged'], [17, 'info', 'Secure set from configuration, not judged']]);
  const cleared = `{-# LANGUAGE OverloadedStrings #-}\nmodule Cookies (clearXsrf) where\nimport Web.Cookie\nimport Data.Default (def)\n\nclearXsrf :: SetCookie\nclearXsrf = def { setCookieName = "NO-XSRF-TOKEN", setCookieValue = "" }\n`;
  assert.deepEqual(all(cleared), [], 'a constant value is not a per-user credential');
});

test('cookie: a helper that decorates a cookie it was handed cannot be judged for the attributes it leaves alone (servant-auth-server applies Secure in one helper and HttpOnly in another)', () => {
  const all = (src) => analyzeHaskellRules({ 'Cookies.hs': src }).findings.filter((f) => f.rule === 'hs-insecure-cookie').map((f) => [f.line, f.severity, f.description.replace(/^[^:]*: /, '')]);
  const helpers = `{-# LANGUAGE OverloadedStrings #-}
module Cookies (applyXsrf, applySession, fresh) where
import Web.Cookie
import Data.Default (def)

data Settings = Settings { xsrfCookieName :: ByteString, sessionCookieName :: ByteString }

applyXsrf :: Settings -> SetCookie -> SetCookie
applyXsrf settings setCookie = setCookie { setCookieName = xsrfCookieName settings, setCookieHttpOnly = False }

applySession :: Settings -> SetCookie -> SetCookie
applySession settings setCookie = setCookie { setCookieName = sessionCookieName settings, setCookieHttpOnly = True }

fresh :: Settings -> ByteString -> SetCookie
fresh settings sid = def { setCookieName = sessionCookieName settings, setCookieValue = sid, setCookieHttpOnly = True }
`;
  assert.deepEqual(all(helpers), [
    [9, 'info', 'Secure set elsewhere, not judged'],
    [12, 'info', 'Secure set elsewhere, not judged'],
    [15, 'medium', 'Secure missing'],
  ]);
});
