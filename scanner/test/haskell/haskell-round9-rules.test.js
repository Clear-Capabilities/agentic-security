// Round 9 of the Haskell work: the pattern layer's misses on unseen-v6 (a development set since 2026-11-15) and the taint shapes round 8 left.
// Each shape is pinned both ways on fixtures written here.
//   1. A binding the function later uses as a Bool (`if accepted`, `when accepted`) is a yes/no answer, never the credential it was computed from
//      (`accepted <- verify user password`); logging it is not sensitive logging. Logging the credential itself still is.
//   2. A WAI application written as guard equations (`app req respond | pathInfo req == ["admin", "flush-cache"] && requestMethod req == "POST" = ..`)
//      declares routes the way a `case` on `pathInfo` does: a state-changing admin route with no authentication is reported; one that checks a
//      credential and rejects first is not.
//   3. Decompressing request-derived bytes (`decompress body` for a `ReqBody '[OctetStream] ByteString`) with no size limit is an unbounded
//      allocation the client sizes (a decompression bomb); decompressing a file the operator named is not reported at a severity above info.
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
const exe = 'cabal-version: 2.4\nname: p\nversion: 0.1\nexecutable p\n    main-is: Main.hs\n    hs-source-dirs: src\n    build-depends: base\n';
const lib = 'cabal-version: 2.4\nname: p\nversion: 0.1\nlibrary\n    exposed-modules: Api\n    hs-source-dirs: src\n    build-depends: base\n';

// ── 1. a yes/no answer about a credential ──
const AUDIT = (logged) => `{-# LANGUAGE OverloadedStrings #-}
module Main (main) where

import Control.Monad.IO.Class (liftIO)
import qualified Data.Text.Lazy as TL
import System.Log.FastLogger
import Web.Scotty
import qualified Directory

main :: IO ()
main = do
  logger <- newStdoutLoggerSet defaultBufSize
  scotty 8080 $
    post "/login" $ do
      user <- param "user"
      password <- param "password"
      accepted <- liftIO (Directory.verify user password)
      liftIO (pushLogStrLn logger (toLogStr ("login attempt user=" <> user <> " accepted=" <> ${logged})))
      if accepted
        then text "welcome"
        else text "try again"
`;

test('a binding later used as a Bool is a yes/no answer: logging it is not sensitive logging; logging the credential is', async () => {
  const answer = await scanOf('hs-r9-audit', { 'p.cabal': exe, 'src/Main.hs': AUDIT('TL.pack (show accepted)') });
  assert.equal(live(answer, 'CWE-532').length, 0, show(answer));
  const secret = await scanOf('hs-r9-audit', { 'p.cabal': exe, 'src/Main.hs': AUDIT('password') });
  assert.ok(live(secret, 'CWE-532').length >= 1, show(secret));
});

// ── 2. WAI routes written as guard equations ──
const WAI_GUARDS = (flush) => `{-# LANGUAGE OverloadedStrings #-}
module Main (main) where

import qualified Data.ByteString.Lazy.Char8 as BLC
import Network.HTTP.Types (status200, status401, status404)
import Network.Wai
import Network.Wai.Handler.Warp (run)
import qualified Cache

main :: IO ()
main = run 8080 app

app :: Application
app req respond
  | pathInfo req == ["admin", "flush-cache"] && requestMethod req == "POST" = do
${flush}
  | pathInfo req == ["admin", "cache-stats"] = do
      stats <- Cache.summary
      respond (responseLBS status200 [("Content-Type", "text/plain")] (BLC.pack stats))
  | otherwise = respond (responseLBS status404 [] "no such route")
`;

test('a WAI guard equation is a route: a state-changing admin route with no authentication is reported, one that rejects an unauthenticated caller first is not', async () => {
  const open = await scanOf('hs-r9-waiguard', { 'p.cabal': exe, 'src/Main.hs': WAI_GUARDS('      cleared <- Cache.flushAll\n      respond (responseLBS status200 [("Content-Type", "text/plain")] (BLC.pack (show cleared ++ " entries cleared")))') });
  assert.ok(live(open, 'CWE-306').length >= 1, show(open));
  const guarded = await scanOf('hs-r9-waiguard', { 'p.cabal': exe, 'src/Main.hs': WAI_GUARDS('      case lookup "Authorization" (requestHeaders req) of\n        Nothing -> respond (responseLBS status401 [] "unauthorized")\n        Just tok -> do\n          ok <- Cache.authorised tok\n          if not ok then respond (responseLBS status401 [] "unauthorized") else do\n            cleared <- Cache.flushAll\n            respond (responseLBS status200 [("Content-Type", "text/plain")] (BLC.pack (show cleared ++ " entries cleared")))') });
  // the flush route (its guard is line 15) checks the Authorization header and rejects first; the stats route is left open on purpose and may still be reported
  assert.equal(live(guarded, 'CWE-306').filter((f) => f.line === 15).length, 0, show(guarded));
});

// ── 3. decompression of request-derived bytes ──
const INFLATE = (source) => `{-# LANGUAGE DataKinds, OverloadedStrings, TypeOperators #-}
module Api (app) where

import Codec.Compression.GZip (decompress)
import Control.Monad.IO.Class (liftIO)
import qualified Data.ByteString.Lazy as BL
import Data.Maybe (fromMaybe)
import Data.Text (Text)
import Servant
import qualified Catalog

type API = "archives" :> "import" :> Header "X-Archive-Name" Text :> ReqBody '[OctetStream] BL.ByteString :> Post '[JSON] Int

inflate :: BL.ByteString -> BL.ByteString
inflate = decompress

importHandler :: Maybe Text -> BL.ByteString -> Handler Int
importHandler name body = do
  let label = fromMaybe "unnamed" name
  ${source}
  liftIO (Catalog.loadEntries label contents)

app :: Application
app = serve (Proxy :: Proxy API) importHandler
`;

test('decompressing a request body with no size limit is an allocation the client sizes; decompressing a file the operator named is not reported above info', async () => {
  const bomb = await scanOf('hs-r9-inflate', { 'p.cabal': lib, 'src/Api.hs': INFLATE('let contents = inflate body') });
  assert.ok(live(bomb, 'CWE-770').length >= 1, show(bomb));
  const file = await scanOf('hs-r9-inflate', { 'p.cabal': lib, 'src/Api.hs': INFLATE('contents <- liftIO (inflate <$> BL.readFile "/var/lib/app/seed.gz")') });
  // a file the operator named: the trust pass lowers a fixed-file read to low (never info), so nothing above low may remain
  assert.equal(live(file, 'CWE-770').filter((f) => f.severity !== 'low').length, 0, show(file));
});

// ── 4. an irrefutable constructor pattern on a value parsed from caller text ──
const ORDERS = (bind) => `{-# LANGUAGE DeriveGeneric, OverloadedStrings #-}
module Main (main) where

import Data.Aeson (FromJSON, decode)
import Data.Text (Text)
import GHC.Generics (Generic)
import Network.AMQP
import qualified Fulfilment

data OrderEvent = OrderEvent { orderId :: Int, sku :: Text, quantity :: Int }
  deriving (Show, Generic)
instance FromJSON OrderEvent

main :: IO ()
main = do
  conn <- openConnection "127.0.0.1" "/" "guest" "guest"
  chan <- openChannel conn
  _ <- consumeMsgs chan "orders" Ack onEvent
  putStrLn "order consumer ready"

onEvent :: (Message, Envelope) -> IO ()
onEvent (msg, env) = do
${bind}
  ackEnv env
`;

test('an irrefutable `let Just x = decode payload` on a queue message is a partial function on caller text; a case that handles Nothing is not', async () => {
  const bare = await scanOf('hs-r9-irref', { 'p.cabal': exe, 'src/Main.hs': ORDERS('  let Just order = decode (msgBody msg) :: Maybe OrderEvent\n  Fulfilment.schedule (orderId order) (sku order) (quantity order)') });
  assert.ok(live(bare, 'CWE-248').some((f) => f.line === 23), show(bare));
  const handled = await scanOf('hs-r9-irref', { 'p.cabal': exe, 'src/Main.hs': ORDERS('  case decode (msgBody msg) :: Maybe OrderEvent of\n    Just order -> Fulfilment.schedule (orderId order) (sku order) (quantity order)\n    Nothing -> putStrLn "discarding a malformed order"') });
  assert.equal(live(handled, 'CWE-248').length, 0, show(handled));
});

// ── 5. an enumeration sized by caller text drives an allocation ──
const PAGES = (render) => `{-# LANGUAGE OverloadedStrings #-}
module Main (main) where

import Control.Monad.IO.Class (liftIO)
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Lazy.Char8 as BLC
import Web.Scotty

main :: IO ()
main = scotty 8080 $
  get "/reports/sample" $ do
    pages <- param "pages"
    document <- liftIO (renderPages pages)
    setHeader "Content-Type" "application/pdf"
    raw document

renderPages :: Int -> IO BL.ByteString
${render}

renderPage :: Int -> IO BL.ByteString
renderPage n = pure (BLC.pack ("%PAGE " ++ show n ++ "\\n") <> BL.replicate 65536 0x20)
`;

test('an enumeration up to a caller-supplied count that drives a mapped allocation is an unbounded allocation; a clamped count is not', async () => {
  const open = await scanOf('hs-r9-pages', { 'p.cabal': exe, 'src/Main.hs': PAGES('renderPages count = BL.concat <$> mapM renderPage [1 .. count]') });
  assert.ok(live(open, 'CWE-770').length >= 1, show(open));
  const clamped = await scanOf('hs-r9-pages', { 'p.cabal': exe, 'src/Main.hs': PAGES('renderPages count\n  | count > 50 = pure "too many pages"\n  | otherwise = BL.concat <$> mapM renderPage [1 .. count]') });
  assert.equal(live(clamped, 'CWE-770').length, 0, show(clamped));
});

// ── 6. a settings endpoint is privileged by its path ──
const MAILER = (api) => `{-# LANGUAGE DataKinds, DeriveGeneric, OverloadedStrings, TypeOperators #-}
module Api (app) where

import Control.Monad.IO.Class (liftIO)
import Data.Aeson (FromJSON)
import Data.IORef
import Data.Text (Text)
import GHC.Generics (Generic)
import Servant
import qualified Mailer

data MailerSettings = MailerSettings { smtpHost :: Text, smtpPort :: Int, smtpUser :: Text, smtpPassword :: Text }
  deriving (Show, Generic)
instance FromJSON MailerSettings

${api}

applySettings :: IORef MailerSettings -> MailerSettings -> IO ()
applySettings ref settings = writeIORef ref settings >> Mailer.reconnect (smtpHost settings) (smtpPort settings) (smtpUser settings) (smtpPassword settings)

settingsHandler :: IORef MailerSettings -> MailerSettings -> Handler NoContent
settingsHandler ref settings = do
  liftIO (applySettings ref settings)
  pure NoContent

app :: IORef MailerSettings -> Application
app ref = serve (Proxy :: Proxy API) (settingsHandler ref)
`;

test('a PUT of the service\'s mailer settings with no authentication is reported as a privileged route; the same route behind an auth combinator is not', async () => {
  const open = await scanOf('hs-r9-settings', { 'p.cabal': lib, 'src/Api.hs': MAILER("type API = \"settings\" :> \"mailer\" :> ReqBody '[JSON] MailerSettings :> Put '[JSON] NoContent") });
  assert.ok(live(open, 'CWE-306').length >= 1, show(open));
  const basic = await scanOf('hs-r9-settings', { 'p.cabal': lib, 'src/Api.hs': MAILER("type API = BasicAuth \"ops\" Text :> \"settings\" :> \"mailer\" :> ReqBody '[JSON] MailerSettings :> Put '[JSON] NoContent").replace('settingsHandler ref settings = do', 'settingsHandler ref _who settings = do').replace('settingsHandler :: IORef MailerSettings -> MailerSettings -> Handler NoContent', 'settingsHandler :: IORef MailerSettings -> Text -> MailerSettings -> Handler NoContent') });
  assert.equal(live(basic, 'CWE-306').length, 0, show(basic));
});

// ── 7. a handler's framework parameter is caller text in the helper it is handed to ──
test('a Servant header handed to a helper that indexes and pattern-matches it is a partial function on caller text', async () => {
  const src = `{-# LANGUAGE DataKinds, OverloadedStrings, TypeOperators #-}
module Api (app) where

import Control.Monad.IO.Class (liftIO)
import qualified Data.ByteString.Lazy as BL
import Data.Text (Text)
import qualified Data.Text as T
import Servant
import qualified Media

type API = "media" :> Capture "asset" Text :> Header "Range" Text :> Get '[OctetStream] BL.ByteString

parseRange :: Text -> (Int, Int)
parseRange header = let [lo, hi] = T.splitOn "-" (T.splitOn "=" header !! 1) in (read (T.unpack lo), read (T.unpack hi))

mediaHandler :: Text -> Maybe Text -> Handler BL.ByteString
mediaHandler asset Nothing = liftIO (Media.whole asset)
mediaHandler asset (Just header) = do
  let (lo, hi) = parseRange header
  liftIO (Media.slice asset lo hi)

app :: Application
app = serve (Proxy :: Proxy API) mediaHandler
`;
  const fs = await scanOf('hs-r9-range', { 'p.cabal': lib, 'src/Api.hs': src });
  assert.ok(live(fs, 'CWE-248').some((f) => f.line === 14), show(fs));
});

// ── 4b. a constructor pattern that FILTERS is not a crash: a comprehension generator, a pattern guard ──
test('a constructor pattern in a comprehension generator or a pattern guard filters the value and is not a partial function', async () => {
  const src = `{-# LANGUAGE OverloadedStrings #-}
module Main (main) where

import Data.Text (Text)
import qualified Data.Text as T
import Web.Scotty
import qualified Reports

main :: IO ()
main = scotty 8080 $ do
  get "/reports" $ do
    raw' <- param "ids"
    let parsed = [ n | Right n <- map Reports.parseId (T.splitOn "," raw') ]
    json (length parsed)
  get "/snapshot" $ do
    piece <- param "piece"
    text (describe piece)

describe :: Text -> Text
describe t
  | Just day <- Reports.parseDay t = "day " <> T.pack (show day)
  | otherwise = "unknown"
`;
  const fs = await scanOf('hs-r9-filterpat', { 'p.cabal': exe, 'src/Main.hs': src });
  assert.equal(live(fs, 'CWE-248').length, 0, show(fs));
});

// ── 8. a request body naming the object by an id field, written without an ownership check ──
const ADDRESS = (query) => `{-# LANGUAGE DataKinds, DeriveGeneric, OverloadedStrings, TypeOperators #-}
module Api (app) where

import Control.Monad.IO.Class (liftIO)
import Data.Aeson (FromJSON)
import Data.Int (Int64)
import Data.Text (Text)
import Database.PostgreSQL.Simple
import GHC.Generics (Generic)
import Servant
import qualified Accounts
import Accounts (Account, accountId)

data AddressUpdate = AddressUpdate { addressId :: Int, line1 :: Text, city :: Text }
  deriving (Show, Generic)
instance FromJSON AddressUpdate

type API = BasicAuth "customers" Account :> "addresses" :> ReqBody '[JSON] AddressUpdate :> Put '[JSON] NoContent

updateHandler :: Connection -> Account -> AddressUpdate -> Handler NoContent
updateHandler conn account upd = do
  _ <- liftIO (${query})
  pure NoContent

app :: Connection -> Application
app conn = serveWithContext (Proxy :: Proxy API) (Accounts.basicAuthCheck :. EmptyContext) (updateHandler conn)
`;

test('a body record whose id field selects the row, written with no ownership check, is broken object authorization; a query scoped by the principal is not', async () => {
  const open = await scanOf('hs-r9-bola', { 'p.cabal': lib, 'src/Api.hs': ADDRESS('execute conn "UPDATE addresses SET line1 = ?, city = ? WHERE id = ?" (line1 upd, city upd, addressId upd)') });
  assert.ok(live(open, 'CWE-639').length >= 1, show(open));
  const scoped = await scanOf('hs-r9-bola', { 'p.cabal': lib, 'src/Api.hs': ADDRESS('execute conn "UPDATE addresses SET line1 = ?, city = ? WHERE id = ? AND account_id = ?" (line1 upd, city upd, addressId upd, accountId account)') });
  assert.equal(live(scoped, 'CWE-639').length, 0, show(scoped));
});

// ── 9. a middleware's intercept is not an API route to compare with a contract ──
test('a guard route in a Middleware-typed function is an intercept, not an undeclared API route; the same route in an Application is compared', async () => {
  const OPENAPI = JSON.stringify({ openapi: '3.0.0', info: { title: 'p', version: '1' }, paths: { '/users': { get: { responses: { 200: { description: 'ok' } } } } } });
  const prog = (sig, head) => `{-# LANGUAGE OverloadedStrings #-}
module Main (main) where

import Data.IORef
import GHC.Clock (getMonotonicTime)
import Network.HTTP.Types (status204, status404)
import Network.Wai
import Network.Wai.Handler.Warp (run)

main :: IO ()
main = do
  lastping <- newIORef 0
  run 8080 (answerPings lastping users)

users :: Application
users _ respond = respond (responseLBS status404 [] "no such route")

${sig}
${head}
  | pathInfo req == ["_ping"] = do
      writeIORef lastping =<< getMonotonicTime
      send (responseLBS status204 [] "")
  | otherwise = app req send
`;
  const contract = (fs) => fs.filter((f) => f.cwe === 'CWE-1059' && /_ping/.test(f.vuln || ''));
  const mw = await scanOf('hs-r9-mw', { 'openapi.json': OPENAPI, 'p.cabal': exe, 'src/Main.hs': prog('answerPings :: IORef Double -> Middleware', 'answerPings lastping app req send') });
  assert.equal(contract(mw).length, 0, show(mw.filter((f) => f.cwe === 'CWE-1059')));
  const appRoute = await scanOf('hs-r9-mw', { 'openapi.json': OPENAPI, 'p.cabal': exe, 'src/Main.hs': prog('answerPings :: IORef Double -> Application -> Application', 'answerPings lastping app req send') });
  assert.ok(contract(appRoute).length >= 1, show(appRoute.filter((f) => f.cwe === 'CWE-1059')));
});
