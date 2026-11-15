// Round 4 of the real-code work (docs/superpowers/plans/2026-11-14-haskell-real-code-precision.md): one remediation gap and one false positive.
//   1. `hs-request-body-bound` rewrites `lazyRequestBody` as it rewrites `strictRequestBody`: the three discovery-set true positives (servant-server's
//      ReqBody handler, wai-extra's MethodOverridePost, wai-frontend-monadcgi) read the body lazily with no bound. The bounded reader returns a lazy
//      ByteString already, so the same helper serves; the stated consequence is that the body is now read eagerly, up to the limit.
//   2. A cookie built from the enclosing function's PARAMETERS is a helper's definition (scotty's `makeSimpleCookie n v`), judged at the call that
//      passes a session name, not where the record is built.
import test from 'node:test';
import assert from 'node:assert/strict';
import { planHaskellFix, validateHaskellFix, BODY_HELPER } from '../../src/language/haskell-fix.js';
import { analyzeHaskellRules } from '../../src/language/haskell-security-rules.js';

process.env.GHC_ENVIRONMENT = '-';
process.env.AGENTIC_SECURITY_DEEP = '1';
delete process.env.CI;

const STUB_WAI = `module Network.Wai (Request, getRequestBodyChunk, strictRequestBody, lazyRequestBody, mkRequest) where
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import Data.IORef
-- documented: getRequestBodyChunk :: Request -> IO ByteString (empty at the end); strictRequestBody, lazyRequestBody :: Request -> IO L.ByteString.
data Request = Request (IORef [B.ByteString])
mkRequest :: [B.ByteString] -> IO Request
mkRequest cs = Request <$> newIORef cs
getRequestBodyChunk :: Request -> IO B.ByteString
getRequestBodyChunk (Request r) = do
  cs <- readIORef r
  case cs of
    [] -> pure B.empty
    (c:rest) -> writeIORef r rest >> pure c
strictRequestBody :: Request -> IO L.ByteString
strictRequestBody req = go []
  where go acc = do { c <- getRequestBodyChunk req; if B.null c then pure (L.fromChunks (reverse acc)) else go (c : acc) }
lazyRequestBody :: Request -> IO L.ByteString
lazyRequestBody = strictRequestBody
`;
const MW = { 'src/Mw.hs': 'module Mw (setPost) where\n\nimport Network.Wai\nimport Data.ByteString.Lazy (toChunks)\nimport Data.IORef\n\nsetPost :: Request -> IO (IORef [a])\nsetPost req = do\n  body <- (mconcat . toChunks) `fmap` lazyRequestBody req\n  newIORef [body]\n', 'Network/Wai.hs': STUB_WAI };

test('request body: lazyRequestBody becomes the bounded reader too; the consequence says the body is now read eagerly up to the limit', async () => {
  const before = analyzeHaskellRules(MW).findings.filter((f) => f.rule === 'hs-unbounded-request-body');
  assert.equal(before.length, 1, JSON.stringify(before.map((f) => [f.line, f.description])));
  const plan = planHaskellFix(before[0], MW);
  assert.equal(plan.ok, true, JSON.stringify(plan));
  assert.equal(plan.ruleId, 'hs-request-body-bound'); assert.equal(plan.label, 'MITIGATION');
  assert.match(plan.after, /boundedRequestBody req\n/);
  assert.doesNotMatch(plan.after.replace(BODY_HELPER, ''), /lazyRequestBody/);
  assert.ok(plan.after.includes(BODY_HELPER));
  assert.ok(plan.consequences.some((c) => /eagerly|whole body is read/i.test(c)), JSON.stringify(plan.consequences));
  const v = await validateHaskellFix(before[0], { files: MW, compile: true });
  assert.equal(v.gates.syntax.ok, true, JSON.stringify(v.gates.syntax));
  assert.equal(v.gates.effective.ok, true, JSON.stringify(v.gates.effective));
  assert.equal(v.gates.rescan && v.gates.rescan.originalGone, true, JSON.stringify(v.gates.rescan));
  if (v.gates.compile && v.gates.compile.ran) assert.equal(v.gates.compile.ok, true, JSON.stringify(v.gates.compile));
  assert.deepEqual(analyzeHaskellRules({ ...MW, 'src/Mw.hs': plan.after }).findings.filter((f) => f.rule === 'hs-unbounded-request-body' && f.severity !== 'info'), []);
});

test('cookie: a cookie built from the function\'s own parameters is a helper definition, not reported; the call that passes a session name is', () => {
  const HELPER = `{-# LANGUAGE OverloadedStrings #-}
module Web.Scotty.Cookie (makeSimpleCookie, setSimpleCookie) where
import Web.Cookie
import qualified Data.Text as T
import qualified Data.Text.Encoding as T

makeSimpleCookie :: T.Text -> T.Text -> SetCookie
makeSimpleCookie n v = defaultSetCookie { setCookieName = T.encodeUtf8 n
                                        , setCookieValue = T.encodeUtf8 v
                                        }

setSimpleCookie :: T.Text -> T.Text -> IO ()
setSimpleCookie n v = print (makeSimpleCookie n v)
`;
  const CALLER = `{-# LANGUAGE OverloadedStrings #-}
module Session (createUserSession) where
import Web.Scotty.Cookie (setSimpleCookie)
import qualified Data.Text as T

createUserSession :: T.Text -> IO ()
createUserSession sid = setSimpleCookie "sess_id" sid
`;
  const cookies = (files) => analyzeHaskellRules(files).findings.filter((f) => f.rule === 'hs-insecure-cookie').map((f) => [f.file, f.line, f.severity]);
  assert.deepEqual(cookies({ 'Web/Scotty/Cookie.hs': HELPER }), [], 'the helper takes its name and value from its caller');
  assert.deepEqual(cookies({ 'Web/Scotty/Cookie.hs': HELPER, 'Session.hs': CALLER }), [['Session.hs', 7, 'medium']], 'the session cookie is reported where the name is chosen');
});
