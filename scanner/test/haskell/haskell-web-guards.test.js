// Auth-guard strictness and coverage (HS-006), pinned in both directions with fixtures written here.
//
//  1. A NAMED guard function (a shared `requireAuth`) is credited only when its rejection really ends the handler. Scotty's `status 401` only
//     sets the code, so it needs a halting call (finish, raise, raiseStatus, redirect); raiseStatus rejects and halts by itself.
//  2. An INLINE guard (the handler reads a credential and rejects before its first sensitive operation) is recognised for WAI, Servant and
//     Yesod handlers, not only Scotty. Each framework has the negatives: a header that is not a credential, a rejection with no credential
//     read, a check that runs after the sensitive operation, and a "rejection" that does not stop the handler.
//
// The IR reports a tail-position call at the enclosing line, so for the frameworks whose rejection ends the handler by itself the ordering
// that is judged is the credential READ against the first sensitive operation; these tests pin the observable behaviour, including the
// documented gap (see the last test).

import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeHaskellWeb } from '../../src/language/haskell-web.js';

const status = (files, method, path) => {
  const r = analyzeHaskellWeb(files);
  const route = r.routes.find((x) => x.method === method && x.path === path);
  assert.ok(route, `route ${method} ${path} found in: ${r.routes.map((x) => `${x.method} ${x.path}`).join(', ')}`);
  return { auth: route.auth.status, evidence: route.auth.evidence[0] || null, kind: route.auth.kind, findings: r.findings.filter((f) => f.route.path === path).map((f) => f.rule) };
};
const protectedRoute = (s) => { assert.equal(s.auth, 'authenticated', JSON.stringify(s)); assert.ok(!s.findings.includes('hs-route-missing-auth'), JSON.stringify(s)); };
const open = (s) => { assert.equal(s.auth, 'none', JSON.stringify(s)); assert.ok(s.findings.includes('hs-route-missing-auth'), JSON.stringify(s)); };

// ── 1. named guards (Scotty) ─────────────────────────────────────────────────
const scottyNamed = (guard) => ({
  'Named.hs': `{-# LANGUAGE OverloadedStrings #-}
module Main where
import Web.Scotty
import Network.HTTP.Types (status401)
import Control.Monad (when)
import Control.Monad.IO.Class (liftIO)
import Data.Maybe (isNothing)
import Database.PostgreSQL.Simple

${guard}

main :: IO ()
main = scotty 3000 $ do
  post "/wipe" $ do
    gate
    conn <- liftIO (connectPostgreSQL "dbname=app")
    _ <- liftIO (execute_ conn "DELETE FROM sessions")
    text "done"
`,
});

test('named guard: a Scotty status 401 counts only when the function also halts the handler', () => {
  const halts = {
    'case alternative, status then finish': 'gate :: ActionM ()\ngate = do\n  h <- header "Authorization"\n  case h of\n    Nothing -> status status401 >> finish\n    Just _ -> pure ()',
    'when, status then finish in a do block': 'gate :: ActionM ()\ngate = do\n  h <- header "Authorization"\n  when (isNothing h) $ do\n    status status401\n    finish',
    'status and finish as separate statements': 'gate :: ActionM ()\ngate = do\n  h <- header "Authorization"\n  when (isNothing h) $ status status401\n  when (isNothing h) finish',
    'raiseStatus rejects and halts by itself': 'gate :: ActionM ()\ngate = do\n  h <- header "Authorization"\n  when (isNothing h) (raiseStatus status401 "no credential")',
  };
  for (const [name, guard] of Object.entries(halts)) { const s = status(scottyNamed(guard), 'POST', '/wipe'); assert.equal(s.auth, 'authenticated', name); assert.equal(s.evidence.kind, 'handler-guard', name); }
});

test('named guard: a Scotty status 401 with nothing that halts the handler does not protect it', () => {
  const keepsRunning = {
    'case alternative sets the code only': 'gate :: ActionM ()\ngate = do\n  h <- header "Authorization"\n  case h of\n    Nothing -> status status401\n    Just _ -> pure ()',
    'when sets the code only': 'gate :: ActionM ()\ngate = do\n  h <- header "Authorization"\n  when (isNothing h) (status status401)',
    'unconditional status in a do block': 'gate :: ActionM ()\ngate = do\n  h <- header "Authorization"\n  status status401\n  pure ()',
  };
  for (const [name, guard] of Object.entries(keepsRunning)) open(status(scottyNamed(guard), 'POST', '/wipe'));
  // neighbours that were never guards stay that way
  open(status(scottyNamed('gate :: ActionM ()\ngate = do\n  _ <- header "Authorization"\n  pure ()'), 'POST', '/wipe'));                   // reads, never rejects
  open(status(scottyNamed('gate :: ActionM ()\ngate = do\n  h <- header "X-Request-Id"\n  when (isNothing h) (status status401 >> finish)'), 'POST', '/wipe')); // not a credential
});

// ── 1b. Scotty inline guards (the strictness the named-guard path now shares) ───
const scottyInline = (guard) => ({
  'Inline.hs': `{-# LANGUAGE OverloadedStrings #-}
module Main where
import Web.Scotty
import Network.HTTP.Types (status401)
import Control.Monad (when)
import Control.Monad.IO.Class (liftIO)
import Data.Maybe (isNothing)
import Database.PostgreSQL.Simple

main :: IO ()
main = scotty 3000 $ do
  post "/wipe" $ do
${guard}
    conn <- liftIO (connectPostgreSQL "dbname=app")
    _ <- liftIO (execute_ conn "DELETE FROM sessions")
    text "done"
`,
});

test('Scotty inline guard: status 401 needs a halting call after the credential read, before the write', () => {
  protectedRoute(status(scottyInline('    h <- header "Authorization"\n    when (isNothing h) (status status401 >> finish)'), 'POST', '/wipe'));
  protectedRoute(status(scottyInline('    h <- header "Authorization"\n    when (isNothing h) (raiseStatus status401 "no")'), 'POST', '/wipe'));
  open(status(scottyInline('    h <- header "Authorization"\n    when (isNothing h) (status status401)'), 'POST', '/wipe'));
  // a status-only rejection BEFORE the read, and a finish after it that is not itself a rejection: nothing rejects on the credential
  open(status(scottyInline('    when False (status status401)\n    h <- header "Authorization"\n    when (isNothing h) finish'), 'POST', '/wipe'));
});

// ── 2a. WAI inline guards ────────────────────────────────────────────────────
const wai = (body) => ({
  'Wai.hs': `{-# LANGUAGE OverloadedStrings #-}
module Main where
import Network.Wai
import Network.Wai.Handler.Warp (run)
import Network.HTTP.Types (status200, status401, hAuthorization)
import Control.Monad.IO.Class (liftIO)
import Database.PostgreSQL.Simple

app :: Application
app req respond = case (requestMethod req, pathInfo req) of
  ("POST", ["wipe"]) -> do
${body}
  _ -> respond (responseLBS status200 [] "hi")

main :: IO ()
main = run 3000 app
`,
});
const WIPE = '        conn <- connectPostgreSQL "dbname=app"\n        _ <- execute_ conn "DELETE FROM sessions"\n        respond (responseLBS status200 [] "done")';
const waiGuard = (key, reject = 'respond (responseLBS status401 [] "no")') => `    case lookup ${key} (requestHeaders req) of\n      Nothing -> ${reject}\n      Just _ -> do\n${WIPE}`;

test('WAI inline guard: the Authorization header is read and a 401 response is handed back before the database write', () => {
  protectedRoute(status(wai(waiGuard('"Authorization"')), 'POST', '/wipe'));
  const s = status(wai(waiGuard('hAuthorization')), 'POST', '/wipe');
  protectedRoute(s);
  assert.equal(s.evidence.kind, 'inline-guard'); assert.equal(s.kind, 'token');
});

test('WAI inline guard negatives: another header, no credential read, check after the write, not a rejection, response not handed back', () => {
  open(status(wai(waiGuard('"X-Request-Id"')), 'POST', '/wipe'));
  open(status(wai(`    case Nothing :: Maybe Int of\n      Just _ -> respond (responseLBS status401 [] "no")\n      Nothing -> do\n${WIPE}`), 'POST', '/wipe'));
  open(status(wai(waiGuard('"Authorization"', 'respond (responseLBS status200 [] "no")')), 'POST', '/wipe'));
  // the write happens first; the credential is only looked at afterwards
  open(status(wai('    conn <- liftIO (connectPostgreSQL "dbname=app")\n    _ <- liftIO (execute_ conn "DELETE FROM sessions")\n    case lookup "Authorization" (requestHeaders req) of\n      Nothing -> respond (responseLBS status401 [] "no")\n      Just _ -> respond (responseLBS status200 [] "done")'), 'POST', '/wipe'));
  // a 401 response is built, looked at, and never handed back: it rejects nothing
  open(status(wai(`    let denied = responseLBS status401 [] "no"\n    case lookup "Authorization" (requestHeaders req) of\n      Nothing -> liftIO (print (responseStatus denied))\n      Just _ -> pure ()\n${WIPE.replace(/^ {4}/gm, '')}`), 'POST', '/wipe'));
});

// ── 2b. Servant inline guards ────────────────────────────────────────────────
const servant = (api, handler) => ({
  'Api.hs': `{-# LANGUAGE OverloadedStrings, DataKinds, TypeOperators #-}
module Main where
import Servant
import Network.Wai.Handler.Warp (run)
import Control.Monad.IO.Class (liftIO)
import Control.Monad (when)
import Data.Maybe (isNothing)
import Database.PostgreSQL.Simple
import Data.Text (Text)

type API = ${api}

${handler}

server :: Server API
server = h

main :: IO ()
main = run 3000 (serve (Proxy :: Proxy API) server)
`,
});
const API = '"wipe" :> Header "Authorization" Text :> ReqBody \'[JSON] Int :> Post \'[JSON] Int';
const WRITE = '  conn <- liftIO (connectPostgreSQL "dbname=app")\n  _ <- liftIO (execute_ conn "DELETE FROM sessions")\n  return n';

test('Servant inline guard: a Header "Authorization" argument is examined and throwError err401 precedes the write', () => {
  const forms = {
    'when isNothing': `h :: Maybe Text -> Int -> Handler Int\nh mAuth n = do\n  when (isNothing mAuth) (throwError err401)\n${WRITE}`,
    'case on the header': `h :: Maybe Text -> Int -> Handler Int\nh mAuth n = do\n  case mAuth of\n    Nothing -> throwError err401\n    Just _ -> do\n  ${WRITE.replace(/\n/g, '\n  ')}`,
    'err401 with a record update': `h :: Maybe Text -> Int -> Handler Int\nh mAuth n = do\n  when (isNothing mAuth) (throwError err401 { errBody = "no" })\n${WRITE}`,
  };
  for (const [name, handler] of Object.entries(forms)) { const s = status(servant(API, handler), 'POST', '/wipe'); protectedRoute(s); assert.equal(s.evidence.kind, 'inline-guard', name); }
});

test('Servant inline guard negatives: another header, credential never examined, check after the write, a non-auth error', () => {
  const other = '"wipe" :> Header "X-Request-Id" Text :> ReqBody \'[JSON] Int :> Post \'[JSON] Int';
  open(status(servant(other, `h :: Maybe Text -> Int -> Handler Int\nh mReq n = do\n  when (isNothing mReq) (throwError err401)\n${WRITE}`), 'POST', '/wipe'));
  open(status(servant(API, `h :: Maybe Text -> Int -> Handler Int\nh _ n = do\n  when (n < 0) (throwError err401)\n${WRITE}`), 'POST', '/wipe'));
  open(status(servant(API, `h :: Maybe Text -> Int -> Handler Int\nh mAuth n = do\n  conn <- liftIO (connectPostgreSQL "dbname=app")\n  _ <- liftIO (execute_ conn "DELETE FROM sessions")\n  when (isNothing mAuth) (throwError err401)\n  return n`), 'POST', '/wipe'));
  open(status(servant(API, `h :: Maybe Text -> Int -> Handler Int\nh mAuth n = do\n  when (isNothing mAuth) (throwError err404)\n${WRITE}`), 'POST', '/wipe'));
  open(status(servant(API, `h :: Maybe Text -> Int -> Handler Int\nh mAuth n = do\n  _ <- return mAuth\n${WRITE}`), 'POST', '/wipe'));
});

// ── 2c. Yesod inline guards ──────────────────────────────────────────────────
const yesod = (handler) => ({
  'App.hs': `{-# LANGUAGE OverloadedStrings, QuasiQuotes, TemplateHaskell, TypeFamilies #-}
module Main where
import Yesod
import Control.Monad.IO.Class (liftIO)
import Database.PostgreSQL.Simple

data App = App

mkYesod "App" [parseRoutes|
/wipe WipeR POST
|]

instance Yesod App where

${handler}

main :: IO ()
main = warp 3000 App
`,
});
const YWRITE = 'liftIO (connectPostgreSQL "dbname=app" >>= \\c -> execute_ c "DELETE FROM sessions")';

test('Yesod inline guard: the session principal or a credential header is read and notAuthenticated / permissionDenied precedes the write', () => {
  const principal = `postWipeR :: Handler Html\npostWipeR = do\n  mu <- maybeAuthId\n  case mu of\n    Nothing -> notAuthenticated\n    Just _ -> do\n      _ <- ${YWRITE}\n      redirect WipeR`;
  const header = `postWipeR :: Handler Html\npostWipeR = do\n  mh <- lookupHeader "Authorization"\n  case mh of\n    Nothing -> permissionDenied "no credential"\n    Just _ -> do\n      _ <- ${YWRITE}\n      redirect WipeR`;
  const a = status(yesod(principal), 'POST', '/wipe'); protectedRoute(a); assert.equal(a.evidence.kind, 'inline-guard'); assert.equal(a.kind, 'session');
  const b = status(yesod(header), 'POST', '/wipe'); protectedRoute(b); assert.equal(b.kind, 'token');
});

test('Yesod inline guard negatives: another header, rejection without a read, check after the write, principal read but never rejected', () => {
  open(status(yesod(`postWipeR :: Handler Html\npostWipeR = do\n  mh <- lookupHeader "X-Request-Id"\n  case mh of\n    Nothing -> permissionDenied "no"\n    Just _ -> do\n      _ <- ${YWRITE}\n      redirect WipeR`), 'POST', '/wipe'));
  // rejects unconditionally and reads no credential; with no sensitive operation there is nothing to report, but it is not a guard either
  assert.equal(status(yesod('postWipeR :: Handler Html\npostWipeR = permissionDenied "always"'), 'POST', '/wipe').auth, 'none');
  open(status(yesod(`postWipeR :: Handler Html\npostWipeR = do\n  _ <- ${YWRITE}\n  mu <- maybeAuthId\n  case mu of\n    Nothing -> notAuthenticated\n    Just _ -> redirect WipeR`), 'POST', '/wipe'));
  open(status(yesod(`postWipeR :: Handler Html\npostWipeR = do\n  mu <- maybeAuthId\n  _ <- ${YWRITE}\n  redirect WipeR`), 'POST', '/wipe'));
});

test('Yesod: requireAuthId reached through the umbrella `import Yesod` is a guard, and its absence is not', () => {
  const guarded = status(yesod(`postWipeR :: Handler Html\npostWipeR = do\n  _ <- requireAuthId\n  _ <- ${YWRITE}\n  redirect WipeR`), 'POST', '/wipe');
  protectedRoute(guarded);
  open(status(yesod(`postWipeR :: Handler Html\npostWipeR = do\n  _ <- ${YWRITE}\n  redirect WipeR`), 'POST', '/wipe'));
});

test('Yesod named guard: a shared function that reads the principal and calls notAuthenticated is a guard; one that never rejects is not', () => {
  const gate = (reject) => yesod(`gate :: Handler ()\ngate = do\n  mu <- maybeAuthId\n  case mu of\n    Nothing -> ${reject}\n    Just _ -> pure ()\n\npostWipeR :: Handler Html\npostWipeR = do\n  gate\n  _ <- ${YWRITE}\n  redirect WipeR`);
  const s = status(gate('notAuthenticated'), 'POST', '/wipe'); protectedRoute(s); assert.equal(s.evidence.kind, 'handler-guard');
  open(status(gate('pure ()'), 'POST', '/wipe'));
});

// ── 3. the order of rejection and write (WAI, Servant, Yesod) ──────────────────
const late = (s, order) => {
  assert.equal(s.auth, 'late', JSON.stringify(s));
  assert.equal(s.evidence.kind, 'late-guard', JSON.stringify(s));
  assert.equal(s.evidence.order, order, JSON.stringify(s));
  assert.ok(s.findings.includes('hs-route-late-auth'), JSON.stringify(s));
  assert.ok(!s.findings.includes('hs-route-missing-auth'), JSON.stringify(s));
};
const lateFinding = (files, path) => analyzeHaskellWeb(files).findings.find((f) => f.rule === 'hs-route-late-auth' && f.route.path === path);
const yHandler = (...lines) => `postWipeR :: Handler Html\npostWipeR = do\n${lines.map((l) => `  ${l}`).join('\n')}`;

test('Yesod order: reject-before-write is a guard; read, write, then reject is late', () => {
  // guards, in several shapes
  protectedRoute(status(yesod(yHandler('mu <- maybeAuthId', 'when (isNothing mu) notAuthenticated', `_ <- ${YWRITE}`, 'redirect WipeR')), 'POST', '/wipe'));
  protectedRoute(status(yesod(yHandler('mu <- maybeAuthId', 'unless (isJust mu) $ permissionDenied "no"', `_ <- ${YWRITE}`, 'redirect WipeR')), 'POST', '/wipe'));
  protectedRoute(status(yesod(yHandler('mu <- maybeAuthId', 'case mu of', '  Nothing -> notAuthenticated', '  Just _ -> pure ()', `_ <- ${YWRITE}`, 'redirect WipeR')), 'POST', '/wipe'));
  // the write sits in the branch that is NOT the rejecting one: still guarded
  protectedRoute(status(yesod(yHandler('mh <- lookupHeader "Authorization"', 'if isNothing mh then permissionDenied "no" else do', `  _ <- ${YWRITE}`, '  redirect WipeR')), 'POST', '/wipe'));
  // read, write, THEN reject: late, in each shape a late check takes
  const afterTail = yesod(yHandler('mu <- maybeAuthId', `_ <- ${YWRITE}`, 'case mu of', '  Nothing -> notAuthenticated', '  Just _ -> redirect WipeR'));
  late(status(afterTail, 'POST', '/wipe'), 'after');
  late(status(yesod(yHandler('mu <- maybeAuthId', `_ <- ${YWRITE}`, 'when (isNothing mu) notAuthenticated', 'redirect WipeR')), 'POST', '/wipe'), 'after');
  late(status(yesod(yHandler('mh <- lookupHeader "Authorization"', `_ <- ${YWRITE}`, 'unless (isJust mh) $ permissionDenied "no"', 'redirect WipeR')), 'POST', '/wipe'), 'after');
  const f = lateFinding(afterTail, '/wipe');
  assert.equal(f.cwe, 'CWE-306'); assert.match(f.description, /runs after the first sensitive operation/);
  // the write sits INSIDE the rejecting branch, before the rejection
  late(status(yesod(yHandler('mu <- maybeAuthId', 'case mu of', '  Nothing -> do', `    _ <- ${YWRITE}`, '    notAuthenticated', '  Just _ -> redirect WipeR')), 'POST', '/wipe'), 'after');
});

test('Yesod order negatives: a rejection that is only built, another header, no credential read', () => {
  // `permissionDenied` bound by a let is a value that is never run: it ends nothing, so nothing guards the write
  open(status(yesod(yHandler('mu <- maybeAuthId', 'let denied = permissionDenied "no"', `_ <- ${YWRITE}`, 'redirect WipeR')), 'POST', '/wipe'));
  // a header that is not a credential, and no credential read: no guard at all (reported as missing authentication)
  open(status(yesod(yHandler('mh <- lookupHeader "X-Request-Id"', 'when (isNothing mh) $ permissionDenied "no"', `_ <- ${YWRITE}`, 'redirect WipeR')), 'POST', '/wipe'));
  open(status(yesod(yHandler(`_ <- ${YWRITE}`, 'redirect WipeR')), 'POST', '/wipe'));
});

test('order that cannot be established is late with the reason, never authenticated', () => {
  // the rejection and the write share one opaque expression: their order is not modelled
  const files = yesod(yHandler('mu <- maybeAuthId', `maybe notAuthenticated (\\_ -> ${YWRITE} >> redirect WipeR) mu`));
  late(status(files, 'POST', '/wipe'), 'unknown');
  const f = lateFinding(files, '/wipe');
  assert.match(f.description, /cannot be shown to run before/);
  assert.equal(f.evidence[0].order, 'unknown'); assert.ok(f.evidence[0].reason.length > 10);
  // the same shape in Servant
  const sv = servant(API, 'h :: Maybe Text -> Int -> Handler Int\nh mAuth n = do\n  maybe (throwError err401) (\\_ -> liftIO (connectPostgreSQL "dbname=app" >>= \\c -> execute_ c "DELETE FROM sessions") >> return n) mAuth');
  late(status(sv, 'POST', '/wipe'), 'unknown');
});

const WAI_WRITE = '    conn <- liftIO (connectPostgreSQL "dbname=app")\n    _ <- liftIO (execute_ conn "DELETE FROM sessions")';
const WAI_LOOKUP = '    let mAuth = lookup "Authorization" (requestHeaders req)';

test('WAI order: reject-before-write is a guard; read, write, then reject is late', () => {
  protectedRoute(status(wai(waiGuard('"Authorization"')), 'POST', '/wipe'));
  protectedRoute(status(wai(`${WAI_LOOKUP}\n    case mAuth of\n      Nothing -> respond (responseLBS status401 [] "no")\n      Just _ -> do\n${WIPE}`), 'POST', '/wipe'));
  // read (the lookup), write, then hand back the 401
  const readFirst = wai(`${WAI_LOOKUP}\n${WAI_WRITE}\n    case mAuth of\n      Nothing -> respond (responseLBS status401 [] "no")\n      Just _ -> respond (responseLBS status200 [] "done")`);
  late(status(readFirst, 'POST', '/wipe'), 'after');
  const f = lateFinding(readFirst, '/wipe');
  assert.equal(f.cwe, 'CWE-306'); assert.match(f.description, /runs after the first sensitive operation/);
});

test('WAI order negatives: a respond mid-block does not end the handler; another header; no credential read', () => {
  // `respond` hands the response to the server and returns; the next statement still runs, so the write goes ahead
  late(status(wai(`${WAI_LOOKUP}\n    when (isNothing mAuth) $ respond (responseLBS status401 [] "no")\n${WAI_WRITE}\n    respond (responseLBS status200 [] "done")`), 'POST', '/wipe'), 'after');
  // the credential is first looked at AFTER the write: not a read-before-write, so no guard (reported as missing, unchanged)
  open(status(wai(`${WAI_WRITE}\n    case lookup "Authorization" (requestHeaders req) of\n      Nothing -> respond (responseLBS status401 [] "no")\n      Just _ -> respond (responseLBS status200 [] "done")`), 'POST', '/wipe'));
  open(status(wai(waiGuard('"X-Request-Id"')), 'POST', '/wipe'));
  open(status(wai(`    let mReq = lookup "X-Request-Id" (requestHeaders req)\n    case mReq of\n      Nothing -> respond (responseLBS status401 [] "no")\n      Just _ -> do\n${WIPE}`), 'POST', '/wipe'));
});

test('Servant order: reject-before-write is a guard; read, write, then reject is late', () => {
  protectedRoute(status(servant(API, `h :: Maybe Text -> Int -> Handler Int\nh mAuth n = do\n  when (isNothing mAuth) (throwError err401)\n${WRITE}`), 'POST', '/wipe'));
  protectedRoute(status(servant(API, `h :: Maybe Text -> Int -> Handler Int\nh mAuth n = do\n  case mAuth of\n    Nothing -> throwError err403\n    Just _ -> pure ()\n${WRITE}`), 'POST', '/wipe'));
  const afterWrite = servant(API, 'h :: Maybe Text -> Int -> Handler Int\nh mAuth n = do\n  let ok = isJust mAuth\n  conn <- liftIO (connectPostgreSQL "dbname=app")\n  _ <- liftIO (execute_ conn "DELETE FROM sessions")\n  when (not ok) (throwError err401)\n  return n');
  late(status(afterWrite, 'POST', '/wipe'), 'after');
  const f = lateFinding(afterWrite, '/wipe');
  assert.equal(f.cwe, 'CWE-306'); assert.match(f.description, /runs after the first sensitive operation/);
  late(status(servant(API, 'h :: Maybe Text -> Int -> Handler Int\nh mAuth n = do\n  _ <- return mAuth\n  conn <- liftIO (connectPostgreSQL "dbname=app")\n  _ <- liftIO (execute_ conn "DELETE FROM sessions")\n  case mAuth of\n    Nothing -> throwError err401\n    Just _ -> return n'), 'POST', '/wipe'), 'after');
});

test('Servant order negatives: a throwError that is only built, another header, a credential never examined, a non-auth error', () => {
  open(status(servant(API, `h :: Maybe Text -> Int -> Handler Int\nh mAuth n = do\n  let denied = throwError err401 :: Handler ()\n  _ <- return (isNothing mAuth)\n${WRITE}`), 'POST', '/wipe'));
  const other = '"wipe" :> Header "X-Request-Id" Text :> ReqBody \'[JSON] Int :> Post \'[JSON] Int';
  open(status(servant(other, `h :: Maybe Text -> Int -> Handler Int\nh mReq n = do\n  when (isNothing mReq) (throwError err401)\n${WRITE}`), 'POST', '/wipe'));
  open(status(servant(API, `h :: Maybe Text -> Int -> Handler Int\nh _ n = do\n  when (n < 0) (throwError err401)\n${WRITE}`), 'POST', '/wipe'));
  open(status(servant(API, `h :: Maybe Text -> Int -> Handler Int\nh mAuth n = do\n  when (isNothing mAuth) (throwError err404)\n${WRITE}`), 'POST', '/wipe'));
  // the only rejection runs BEFORE the credential is examined and does not depend on it: it cannot be the guard of the write
  late(status(servant(API, `h :: Maybe Text -> Int -> Handler Int\nh mAuth n = do\n  when (n < 0) (throwError err401)\n  _ <- return mAuth\n${WRITE}`), 'POST', '/wipe'), 'after');
});

test('structure, not position: a check and a write on ONE source line are ordered by the handler, not by the line', () => {
  const w = 'liftIO (connectPostgreSQL "dbname=app" >>= \\c -> execute_ c "DELETE FROM sessions")';
  protectedRoute(status(servant(API, `h :: Maybe Text -> Int -> Handler Int\nh mAuth n = when (isNothing mAuth) (throwError err401) >> ${w} >> return n`), 'POST', '/wipe'));
  late(status(servant(API, `h :: Maybe Text -> Int -> Handler Int\nh mAuth n = let ok = isJust mAuth in ${w} >> when (not ok) (throwError err401) >> return n`), 'POST', '/wipe'), 'after');
});
