// Round 10, second half: the pattern layer's misses and false positives on unseen-v7 (a development set since 2026-11-15, see its USE-LOG).
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { mkTestTmp } from '../helpers/tmp.js';

process.env.AGENTIC_SECURITY_DEEP = '1';
process.env.AGENTIC_SECURITY_DEEP_IN_CI = '1';
delete process.env.CI;

async function scanOf(prefix, files) {
  const { runScan } = await import('../../src/runScan.js');
  const dir = mkdtempSync(join(mkTestTmp(prefix), 'p-'));
  for (const [k, v] of Object.entries(files)) { mkdirSync(dirname(join(dir, k)), { recursive: true }); writeFileSync(join(dir, k), v); }
  const { scan } = await runScan(dir, { deep: true });
  return scan.findings.filter((f) => /\.hs$/.test(f.file));
}
const live = (fs, cwe) => fs.filter((f) => f.cwe === cwe && f.severity !== 'info' && !(f.proof && /^proven-/.test(f.proof.verdict)));
const show = (fs) => JSON.stringify(fs.map((f) => [f.parser, f.cwe, f.line, f.severity, f.vuln && f.vuln.slice(0, 40)]));
const lib = 'cabal-version: 2.4\nname: p\nversion: 0.1\nlibrary\n    hs-source-dirs: src\n    build-depends: base\n';
const exe = 'cabal-version: 2.4\nname: p\nversion: 0.1\nexecutable p\n    main-is: Main.hs\n    hs-source-dirs: src\n    build-depends: base\n';

// 1. PBKDF2's parameters written positionally (`Parameters 10 32`): the first field is the iteration count.
test('pbkdf2: a positional Parameters with a low iteration count is reported like the record form', async () => {
  const src = `{-# LANGUAGE OverloadedStrings #-}
module Portal.Login (derive) where

import Crypto.Hash.Algorithms (SHA256(..))
import qualified Crypto.KDF.PBKDF2 as PBKDF2
import Data.ByteString (ByteString)

derive :: ByteString -> ByteString -> ByteString
derive pw salt = PBKDF2.generate (PBKDF2.prfHMAC SHA256) (PBKDF2.Parameters 10 32) pw salt
`;
  const fs = await scanOf('hs-r10-pbkdf2', { 'p.cabal': lib, 'src/Portal/Login.hs': src });
  assert.ok(live(fs, 'CWE-916').some((f) => f.line === 9), show(fs));
});

// 2. A bound tested as a record field (`when (copies job > maxCopies) throwError`) clamps the enumeration sized by that field.
test('enumeration: a size tested as a record field before the enumeration is bounded', async () => {
  const src = `{-# LANGUAGE DataKinds, DeriveGeneric, OverloadedStrings, TypeOperators #-}
module Labels.Reprint (ReprintApi, reprintServer) where

import Control.Concurrent.Async (mapConcurrently_)
import Control.Monad (when)
import Control.Monad.IO.Class (liftIO)
import Data.Aeson (FromJSON)
import Data.Text (Text)
import GHC.Generics (Generic)
import Servant

import Printers (printLabel)

data ReprintJob = ReprintJob { shipmentRef :: Text, printer :: Text, copies :: Int } deriving (Generic)
instance FromJSON ReprintJob

type ReprintApi = "labels" :> "reprint" :> ReqBody '[JSON] ReprintJob :> PostNoContent

maxCopies :: Int
maxCopies = 25

reprintServer :: Server ReprintApi
reprintServer job = do
  when (copies job < 1 || copies job > maxCopies) $
    throwError err422 { errBody = "copies must be between 1 and 25" }
  liftIO (mapConcurrently_ (const (printLabel (printer job) (shipmentRef job))) [1 .. copies job])
  pure NoContent
`;
  const fs = await scanOf('hs-r10-enum-field', { 'p.cabal': lib, 'src/Labels/Reprint.hs': src });
  assert.equal(live(fs, 'CWE-770').length, 0, show(fs));
});

// 3. Snap's `Cookie {..}` record built in a helper with both flags False, handed to addResponseCookie.
test('cookie: a Snap Cookie record with cookieSecure and cookieHttpOnly False is reported where it is built', async () => {
  const src = `{-# LANGUAGE OverloadedStrings #-}
module Badges.Session (badgeLoginHandler) where

import Control.Monad.IO.Class (liftIO)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import Snap.Core
import System.Entropy (getEntropy)

badgeLoginHandler :: Snap ()
badgeLoginHandler = do
  token <- liftIO (B16.encode <$> getEntropy 32)
  modifyResponse (addResponseCookie (sessionCookie token))
  writeBS "badge session opened"

sessionCookie :: BS.ByteString -> Cookie
sessionCookie token = Cookie
  { cookieName = "badge_session"
  , cookieValue = token
  , cookieExpires = Nothing
  , cookieDomain = Nothing
  , cookiePath = Just "/"
  , cookieSecure = False
  , cookieHttpOnly = False
  }
`;
  const fs = await scanOf('hs-r10-snap-cookie', { 'p.cabal': lib, 'src/Badges/Session.hs': src });
  assert.ok(live(fs, 'CWE-1004').length >= 1, show(fs));
});

// 4. scotty-cookie's `makeSimpleCookie` wrapped in a record update that sets HttpOnly and Secure is not a finding.
test('cookie: a record update over makeSimpleCookie that sets HttpOnly and Secure is not reported', async () => {
  const src = `{-# LANGUAGE OverloadedStrings #-}
module Portal.Authenticate (authRoutes) where

import Control.Monad.IO.Class (liftIO)
import qualified Data.ByteString.Base16 as B16
import qualified Data.Text.Encoding as TE
import System.Entropy (getEntropy)
import Web.Cookie (sameSiteLax, setCookieHttpOnly, setCookieSameSite, setCookieSecure)
import Web.Scotty
import Web.Scotty.Cookie (makeSimpleCookie, setCookie)

authRoutes :: ScottyM ()
authRoutes =
  post "/signin" $ do
    token <- liftIO (TE.decodeUtf8 . B16.encode <$> getEntropy 32)
    let cookie = (makeSimpleCookie "session" token)
          { setCookieHttpOnly = True
          , setCookieSecure = True
          , setCookieSameSite = Just sameSiteLax
          }
    setCookie cookie
    redirect "/dashboard"
`;
  const fs = await scanOf('hs-r10-cookie-update', { 'p.cabal': lib, 'src/Portal/Authenticate.hs': src });
  assert.equal(live(fs, 'CWE-1004').length, 0, show(fs));
});

// 5. servant-auth: a query scoped by a field of the `Authenticated caller` principal is ownership-checked.
test('object authorization: a lookup constrained by a field of the authenticated principal is not reported', async () => {
  const src = `{-# LANGUAGE DataKinds, DeriveGeneric, OverloadedStrings, TypeOperators #-}
module Invoices.Detail (InvoiceApi, invoiceServer, Caller(..)) where

import Control.Monad.IO.Class (liftIO)
import Data.Aeson (FromJSON, ToJSON)
import Data.Text (Text)
import Database.PostgreSQL.Simple
import GHC.Generics (Generic)
import Servant
import Servant.Auth.Server

data Caller = Caller { callerId :: Int, callerEmail :: Text } deriving (Generic)
instance FromJSON Caller
instance ToJSON Caller
instance FromJWT Caller
instance ToJWT Caller

data Invoice = Invoice { number :: Text, total :: Double } deriving (Generic)
instance ToJSON Invoice
instance FromRow Invoice where
  fromRow = Invoice <$> field <*> field

type InvoiceApi = Auth '[JWT] Caller :> "invoices" :> Capture "id" Int :> Get '[JSON] Invoice

invoiceServer :: Connection -> Server InvoiceApi
invoiceServer conn (Authenticated caller) iid = do
  rows <- liftIO (query conn "SELECT number, total FROM invoices WHERE id = ? AND customer_id = ?" (iid, callerId caller))
  case rows of
    (inv:_) -> pure inv
    [] -> throwError err404
invoiceServer _ _ _ = throwAll err401
`;
  const fs = await scanOf('hs-r10-bola-principal', { 'p.cabal': lib, 'src/Invoices/Detail.hs': src });
  assert.equal(live(fs, 'CWE-639').length, 0, show(fs));
});

// 6. servant: alternatives are judged one by one; a state-changing one with no auth combinator is unauthenticated whatever its siblings carry.
test('servant: a POST alternative without an auth combinator beside two BasicAuth ones is reported as unauthenticated', async () => {
  const src = `{-# LANGUAGE DataKinds, OverloadedStrings, TypeOperators #-}
module Search.Admin (AdminApi, adminServer) where

import Control.Monad.IO.Class (liftIO)
import Data.Text (Text)
import Servant

import Search.Index (listSnapshots, purgeIndex, reindexAll)
import Operators (Operator)

type AdminApi =
       BasicAuth "ops" Operator :> "admin" :> "snapshots" :> Get '[JSON] [Text]
  :<|> BasicAuth "ops" Operator :> "admin" :> "purge" :> PostNoContent
  :<|> "admin" :> "reindex" :> PostNoContent

adminServer :: Server AdminApi
adminServer = snapshots :<|> purge :<|> reindex
  where
    snapshots _op = liftIO listSnapshots
    purge _op = liftIO purgeIndex >> pure NoContent
    reindex = liftIO reindexAll >> pure NoContent
`;
  const fs = await scanOf('hs-r10-servant-alt', { 'p.cabal': lib, 'src/Search/Admin.hs': src });
  assert.ok(live(fs, 'CWE-306').length >= 1, show(fs));
});

// 7. yesod: a state-changing route whose isAuthorized clause can only answer Authorized is public by policy, handler or no handler.
test('yesod: a POST route that isAuthorized always authorises is reported', async () => {
  const src = `{-# LANGUAGE OverloadedStrings, QuasiQuotes, TemplateHaskell, TypeFamilies #-}
module Foundation.Badges where

import Yesod.Core
import Yesod.Auth

import Badges.Types (BadgeId)

data App = App

mkYesodData "App" [parseRoutes|
/                        HomeR        GET
/auth                    AuthR        Auth getAuth
/badges                  BadgesR      GET POST
/badges/#BadgeId         BadgeR       GET
/badges/#BadgeId/revoke  BadgeRevokeR POST
|]

requireOperator :: Handler AuthResult
requireOperator = do
  mu <- maybeAuthId
  pure (maybe AuthenticationRequired (const Authorized) mu)

instance Yesod App where
  isAuthorized HomeR _ = pure Authorized
  isAuthorized (AuthR _) _ = pure Authorized
  isAuthorized (BadgeRevokeR _) _ = pure Authorized
  isAuthorized _ _ = requireOperator
`;
  const fs = await scanOf('hs-r10-yesod-public', { 'p.cabal': lib, 'src/Foundation/Badges.hs': src });
  assert.ok(live(fs, 'CWE-306').some((f) => f.line === 27), show(fs));
});

// 8. `head` on the words of a message a caller read from a socket: the parameter carries request text one hop.
test('partial function: head of the words of a parameter fed by a websocket message is reported', async () => {
  const src = `{-# LANGUAGE OverloadedStrings #-}
module Main (main) where

import Control.Monad (forever)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Network.WebSockets as WS

import Dispatch (assignDriver, releaseDriver, listOpen)

main :: IO ()
main = WS.runServer "0.0.0.0" 9200 dispatch

dispatch :: WS.ServerApp
dispatch pending = do
  conn <- WS.acceptRequest pending
  forever $ do
    msg <- WS.receiveData conn :: IO Text
    reply <- handle msg
    WS.sendTextData conn reply

handle :: Text -> IO Text
handle msg =
  let parts = T.words msg
      cmd = head parts
  in case cmd of
       "ASSIGN" | [_, shipment, driver] <- parts -> assignDriver shipment driver
       "RELEASE" | [_, driver] <- parts -> releaseDriver driver
       "LIST" -> listOpen
       _ -> pure "ERR unknown command"
`;
  const fs = await scanOf('hs-r10-head-msg', { 'p.cabal': exe, 'src/Main.hs': src });
  assert.ok(live(fs, 'CWE-248').some((f) => f.line === 26) || live(fs, 'CWE-248').length >= 1, show(fs));
});

// 9. blaze's `preEscapedToHtml` over a stored record field inserts the field's text into the page unescaped.
test('raw html: preEscapedToHtml of a record field is reported; of a literal it is not', async () => {
  const mk = (arg) => `{-# LANGUAGE OverloadedStrings #-}
module Tickets.Comments (renderComment) where

import Data.Text (Text)
import Text.Blaze.Html (Html, preEscapedToHtml, toHtml)
import qualified Text.Blaze.Html5 as H

data Comment = Comment { commentAuthor :: Text, commentBody :: Text }

renderComment :: Comment -> Html
renderComment c = H.div $ do
  H.span (toHtml (commentAuthor c))
  H.p (preEscapedToHtml ${arg})
`;
  const field = await scanOf('hs-r10-rawhtml', { 'p.cabal': lib, 'src/Tickets/Comments.hs': mk('(commentBody c)') });
  assert.ok(live(field, 'CWE-79').some((f) => f.line === 13), show(field));
  const lit = await scanOf('hs-r10-rawhtml', { 'p.cabal': lib, 'src/Tickets/Comments.hs': mk('("<hr>" :: String)') });
  assert.equal(live(lit, 'CWE-79').length, 0, show(lit));
});
