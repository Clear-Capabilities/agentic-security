// Round 8 of the Haskell work: taint recall (docs/superpowers/plans/2026-11-14-haskell-real-code-precision.md, round 8). The shapes are the
// general causes behind unseen-v6's taint misses (a development set since 2026-11-15, see its USE-LOG) and simplex-chat's two false positives,
// each pinned both ways on fixtures written here.
//   1. Sources the registry lacked: a websockets message (`receiveData`), a Snap request header (`getHeader`), a Snap cookie (`getCookie`,
//      `cookieValue`), an AMQP message body (`msgBody`). `haskell-models.js`.
//   2. A Servant `ReqBody` whose type is a project record is request input whatever its type: its fields read from the handler's parameter are
//      tainted (`servantEndpointParams` no longer requires a text type for a body). A record parameter that is not an API read stays untainted.
//   3. A point-free handler, `handler = liftIO . work`, is `handler x = liftIO (work x)`: the API's reads pair with the parameter the composition
//      takes (`lambdaBodied` eta-expands a composition chain under a signature of at least one arrow).
//   4. A lookup in a constant map (`Map.lookup slug templates` with `templates = Map.fromList [("welcome", "/srv/..."), ..]`) yields one of the
//      map's literal VALUES: the key's taint does not reach the result (an allow-list by construction). A map built from anything else keeps the flow.
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
const live = (fs, cwe) => fs.filter((f) => f.parser === 'IR-TAINT' && f.cwe === cwe && f.severity !== 'info' && !(f.proof && /^proven-/.test(f.proof.verdict)));
const show = (fs) => JSON.stringify(fs.map((f) => [f.parser, f.cwe, f.line, f.severity, f.proof && f.proof.verdict, f.trustBoundary && f.trustBoundary.verdict]));
const cabal = (mods) => `cabal-version: 2.4\nname: p\nversion: 0.1\nexecutable p\n    main-is: Main.hs\n    other-modules: ${mods}\n    hs-source-dirs: src\n    build-depends: base\n`;

// ── 1. sources ──
test('a websockets message reaching a shell is command injection', async () => {
  const src = `{-# LANGUAGE OverloadedStrings #-}
module Main (main) where

import Control.Monad (forever)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Network.WebSockets as WS
import Turtle (empty, shells)

main :: IO ()
main = WS.runServer "127.0.0.1" 9160 consoleApp

consoleApp :: WS.ServerApp
consoleApp pending = do
  conn <- WS.acceptRequest pending
  forever $ do
    msg <- WS.receiveData conn :: IO Text
    let target = T.strip (T.drop 6 msg)
    shells ("make -C /srv/project " <> target) empty
    WS.sendTextData conn ("started " <> target)
`;
  const fs = await scanOf('hs-r8-ws', { 'p.cabal': cabal(''), 'src/Main.hs': src });
  assert.ok(live(fs, 'CWE-78').some((f) => f.line === 19), show(fs));
});

test('a Snap request header handed through a helper to a typed-process shell is command injection', async () => {
  const src = `{-# LANGUAGE OverloadedStrings #-}
module Main (main) where

import Control.Monad.IO.Class (liftIO)
import qualified Data.ByteString.Char8 as B
import Snap.Core
import Snap.Http.Server (quickHttpServe)
import System.Process.Typed (runProcess_, setWorkingDir, shell)

main :: IO ()
main = quickHttpServe $ route [("mirror", method POST mirrorHandler)]

mirrorHandler :: Snap ()
mirrorHandler = do
  req <- getRequest
  case getHeader "X-Repo-Url" req of
    Nothing -> writeBS "repo url header required"
    Just url -> do
      liftIO (cloneInto "/var/mirrors" (B.unpack url))
      writeBS "mirror started"

cloneInto :: FilePath -> String -> IO ()
cloneInto base url = runProcess_ (setWorkingDir base (shell ("git clone --mirror " ++ url)))
`;
  const fs = await scanOf('hs-r8-snaphdr', { 'p.cabal': cabal(''), 'src/Main.hs': src });
  assert.ok(live(fs, 'CWE-78').length >= 1, show(fs));
});

test('a Snap cookie value written raw into Lucid markup is cross-site scripting', async () => {
  const src = `{-# LANGUAGE OverloadedStrings #-}
module Main (main) where

import Data.Text (Text)
import qualified Data.Text.Encoding as TE
import Lucid
import Snap.Core
import Snap.Http.Server (quickHttpServe)

main :: IO ()
main = quickHttpServe $ route [("banner", method GET bannerHandler)]

bannerHandler :: Snap ()
bannerHandler = do
  cookie <- getCookie "display_name"
  let displayName = maybe "Guest" (TE.decodeLatin1 . cookieValue) cookie
  modifyResponse (setContentType "text/html; charset=utf-8")
  writeLBS (renderBS (banner displayName))

banner :: Text -> Html ()
banner displayName = html_ $ body_ $ do
  div_ [class_ "banner"] $ do
    span_ "Welcome back, "
    strong_ (toHtmlRaw displayName)
  p_ "Your dashboard is ready."
`;
  const fs = await scanOf('hs-r8-snapcookie', { 'p.cabal': cabal(''), 'src/Main.hs': src });
  assert.ok(live(fs, 'CWE-79').length >= 1, show(fs));
});

test('an AMQP message body decoded into a record whose field names a file is path traversal', async () => {
  const src = `{-# LANGUAGE DeriveGeneric, OverloadedStrings, RecordWildCards #-}
module Main (main) where

import Data.Aeson (FromJSON, decode)
import qualified Data.ByteString.Lazy as BL
import Data.Text (Text)
import qualified Data.Text as T
import GHC.Generics (Generic)
import Network.AMQP

data ExportRequest = ExportRequest { accountId :: Int, outputName :: Text }
  deriving (Show, Generic)
instance FromJSON ExportRequest

exportRoot :: FilePath
exportRoot = "/var/exports/"

main :: IO ()
main = do
  conn <- openConnection "127.0.0.1" "/" "guest" "guest"
  chan <- openChannel conn
  _ <- consumeMsgs chan "exports" Ack onMessage
  putStrLn "export worker ready"
  where
    onMessage (msg, env) = do
      case decode (msgBody msg) of
        Just req -> runExport req
        Nothing -> putStrLn "discarding malformed export request"
      ackEnv env

runExport :: ExportRequest -> IO ()
runExport ExportRequest{..} = BL.writeFile (exportRoot ++ T.unpack outputName) "rows"
`;
  const fs = await scanOf('hs-r8-amqp', { 'p.cabal': cabal(''), 'src/Main.hs': src });
  assert.ok(live(fs, 'CWE-22').length >= 1, show(fs));
});

// ── 2 and 3. Servant request bodies of a record type, and a point-free handler ──
const SERVANT_BODY = (handler) => `{-# LANGUAGE DataKinds, DeriveGeneric, OverloadedStrings, TypeOperators #-}
module Api (app) where

import Control.Monad.IO.Class (liftIO)
import Data.Aeson (FromJSON, ToJSON)
import Data.Text (Text)
import qualified Data.Text as T
import Database.SQLite.Simple
import GHC.Generics (Generic)
import Servant

data SearchRequest = SearchRequest { searchTerm :: Text, includeClosed :: Bool }
  deriving (Show, Generic)
instance FromJSON SearchRequest

type API = "tickets" :> "search" :> ReqBody '[JSON] SearchRequest :> Post '[JSON] [Int]

findTickets :: Connection -> SearchRequest -> IO [Int]
findTickets conn req = map fromOnly <$> query_ conn (Query ("SELECT id FROM tickets WHERE title LIKE '%" <> searchTerm req <> "%'"))

${handler}

app :: Connection -> Application
app conn = serve (Proxy :: Proxy API) (server conn)
`;
const lib = 'cabal-version: 2.4\nname: p\nversion: 0.1\nlibrary\n    exposed-modules: Api\n    hs-source-dirs: src\n    build-depends: base\n';

test('a Servant request body of a record type is request input: a field of it reaching a query is SQL injection', async () => {
  const fs = await scanOf('hs-r8-reqbody', { 'p.cabal': lib, 'src/Api.hs': SERVANT_BODY('server :: Connection -> Server API\nserver conn req = liftIO (findTickets conn req)') });
  assert.ok(live(fs, 'CWE-89').length >= 1, show(fs));
});

test('a point-free Servant handler (`liftIO . work`) takes the body as its parameter', async () => {
  const fs = await scanOf('hs-r8-pointfree', { 'p.cabal': lib, 'src/Api.hs': SERVANT_BODY('server :: Connection -> Server API\nserver conn = liftIO . findTickets conn') });
  assert.ok(live(fs, 'CWE-89').length >= 1, show(fs));
});

test('a record parameter that is not an API read is still not request input', async () => {
  const src = `{-# LANGUAGE OverloadedStrings #-}
module Main (main) where

import Data.Text (Text)
import qualified Data.Text as T
import Database.SQLite.Simple

data Filter = Filter { term :: Text }

main :: IO ()
main = do
  conn <- open "tickets.db"
  rows <- findTickets conn (Filter "open")
  print (length rows)

findTickets :: Connection -> Filter -> IO [Int]
findTickets conn f = map fromOnly <$> query_ conn (Query ("SELECT id FROM tickets WHERE title LIKE '%" <> term f <> "%'"))
`;
  const fs = await scanOf('hs-r8-record-plain', { 'p.cabal': cabal(''), 'src/Main.hs': src });
  assert.equal(live(fs, 'CWE-89').length, 0, show(fs));
});

// ── 4. a lookup in a constant map ──
const LOOKUP = (table) => `{-# LANGUAGE OverloadedStrings #-}
module Main (main) where

import qualified Data.ByteString.Char8 as B
import qualified Data.Map.Strict as Map
import Snap.Core
import Snap.Http.Server (quickHttpServe)

${table}

main :: IO ()
main = quickHttpServe $ route [("preview/:slug", method GET previewHandler)]

previewHandler :: Snap ()
previewHandler = do
  slug <- getParam "slug"
  maybe missing serveTemplate (slug >>= flip Map.lookup templates)

serveTemplate :: FilePath -> Snap ()
serveTemplate file = do
  modifyResponse (setContentType "text/html; charset=utf-8")
  sendFile file

missing :: Snap ()
missing = writeBS "no such template"
`;

test('a value looked up in a constant map of literals is one of those literals: no path flow; a map built at run time keeps it', async () => {
  const constant = 'templates :: Map.Map B.ByteString FilePath\ntemplates = Map.fromList\n  [ ("welcome", "/srv/templates/welcome.html")\n  , ("receipt", "/srv/templates/receipt.html")\n  ]';
  const fs = await scanOf('hs-r8-lookup', { 'p.cabal': cabal(''), 'src/Main.hs': LOOKUP(constant) });
  assert.equal(live(fs, 'CWE-22').length, 0, show(fs));
  // control: the map's values come from somewhere else (built from the request itself), so the lookup result is not a constant
  const dynamic = 'templates :: Map.Map B.ByteString FilePath\ntemplates = Map.fromList [ (k, "/srv/templates/" ++ B.unpack k) | k <- ["welcome", "receipt"] ]';
  const fs2 = await scanOf('hs-r8-lookup', { 'p.cabal': cabal(''), 'src/Main.hs': LOOKUP(dynamic).replace('(slug >>= flip Map.lookup templates)', '(fmap (\\s -> Map.findWithDefault (B.unpack s) s templates) slug)') });
  assert.ok(live(fs2, 'CWE-22').length >= 1, show(fs2));
});

// ── 3b. a handler passed to `serve` is paired with that API's reads whatever its own result type ──
test('a handler handed to serve (Proxy :: Proxy API) takes the API reads as its parameters, point-free or not', async () => {
  const src = `{-# LANGUAGE DataKinds, DeriveGeneric, OverloadedStrings, TypeOperators #-}
module Api (app) where

import Control.Lens ((^.))
import Control.Monad.IO.Class (liftIO)
import Data.Aeson (FromJSON, ToJSON, object, (.=))
import Data.Text (Text)
import qualified Data.Text as T
import GHC.Generics (Generic)
import Network.Wreq (post, responseStatus, statusCode)
import Servant

data TestRequest = TestRequest { endpoint :: Text, sampleEvent :: Text }
  deriving (Show, Generic)
instance FromJSON TestRequest

type API = "webhooks" :> "test" :> ReqBody '[JSON] TestRequest :> Post '[JSON] Int

deliverSample :: TestRequest -> IO Int
deliverSample req = do
  response <- post (T.unpack (endpoint req)) (object ["event" .= sampleEvent req])
  pure (response ^. responseStatus . statusCode)

testHandler :: TestRequest -> Handler Int
testHandler = liftIO . deliverSample

app :: Application
app = serve (Proxy :: Proxy API) testHandler
`;
  const fs = await scanOf('hs-r8-serve', { 'p.cabal': lib, 'src/Api.hs': src });
  assert.ok(live(fs, 'CWE-918').length >= 1, show(fs));
});

// ── 5. a sanitizer beside the value is not a sanitizer of the value ──
test('a sanitizer applied only to a literal next to the tainted value (`T.drop (T.length "build ") msg`) does not sanitize the value', async () => {
  const src = `{-# LANGUAGE OverloadedStrings #-}
module Main (main) where

import Control.Monad (forever)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Network.WebSockets as WS
import Turtle (empty, shells)

main :: IO ()
main = WS.runServer "127.0.0.1" 9160 consoleApp

consoleApp :: WS.ServerApp
consoleApp pending = do
  conn <- WS.acceptRequest pending
  forever $ do
    msg <- WS.receiveData conn :: IO Text
    let target = T.strip (T.drop (T.length "build ") msg)
    if "build " \`T.isPrefixOf\` msg
      then shells ("make -C /srv/project " <> target) empty
      else WS.sendTextData conn ("unknown command" :: Text)
`;
  const fs = await scanOf('hs-r8-litsan', { 'p.cabal': cabal(''), 'src/Main.hs': src });
  assert.ok(live(fs, 'CWE-78').length >= 1, show(fs));
});

// ── 6. a containment guard that dominates a callee's return is a guard on the value the caller receives ──
const RESOLVE = (check) => `{-# LANGUAGE DataKinds, OverloadedStrings, TypeOperators #-}
module Api (app) where

import Control.Monad.IO.Class (liftIO)
import qualified Data.ByteString.Lazy.Char8 as BL
import Data.List (isPrefixOf)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.IO as TIO
import Servant
import System.Directory (canonicalizePath)
import System.FilePath (addTrailingPathSeparator, (</>))

type API = "logs" :> QueryParam "file" Text :> Get '[PlainText] Text

logRoot :: FilePath
logRoot = "/var/log/app"

resolveLog :: Text -> IO (Either String FilePath)
resolveLog name = do
  base <- addTrailingPathSeparator <$> canonicalizePath logRoot
  full <- canonicalizePath (logRoot </> T.unpack name)
  pure (if ${check} then Right full else Left "outside the log directory")

logHandler :: Maybe Text -> Handler Text
logHandler Nothing = throwError err400 { errBody = "file parameter required" }
logHandler (Just name) = do
  resolved <- liftIO (resolveLog name)
  case resolved of
    Left reason -> throwError err403 { errBody = BL.pack reason }
    Right file -> liftIO (TIO.readFile file)

app :: Application
app = serve (Proxy :: Proxy API) logHandler
`;

test('a canonicalised prefix check that decides which branch of a callee returns the path guards the read in the caller; a check of something else does not', async () => {
  const guarded = await scanOf('hs-r8-retguard', { 'p.cabal': lib, 'src/Api.hs': RESOLVE('base `isPrefixOf` full') });
  assert.equal(live(guarded, 'CWE-22').length, 0, show(guarded));
  const unguarded = await scanOf('hs-r8-retguard', { 'p.cabal': lib, 'src/Api.hs': RESOLVE('not (T.null name)') });
  assert.ok(live(unguarded, 'CWE-22').length >= 1, show(unguarded));
});

test('the same guard written as a where-bound predicate helper (`inside root file`) is read as its body', async () => {
  const src = RESOLVE('inside base full').replace('pure (if inside base full then Right full else Left "outside the log directory")',
    'pure (if inside base full then Right full else Left "outside the log directory")\n  where\n    inside root file = root `isPrefixOf` file');
  const fs = await scanOf('hs-r8-retguard-helper', { 'p.cabal': lib, 'src/Api.hs': src });
  assert.equal(live(fs, 'CWE-22').length, 0, show(fs));
});

// ── 7. a WAI response's content type given through a project constant ──
const WAI_JSON = (headers) => `{-# LANGUAGE OverloadedStrings #-}
module Main (main) where

import qualified Data.Aeson as J
import Data.Aeson ((.=))
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Network.HTTP.Types
import Network.Wai
import Network.Wai.Handler.Warp (run)

main :: IO ()
main = run 8080 app

apiHeaders :: [Header]
apiHeaders = ${headers}

jsonResponse :: Status -> J.Value -> Response
jsonResponse st = responseLBS st apiHeaders . J.encode

app :: Application
app req respond = do
  let who = T.intercalate "/" (pathInfo req)
  respond (jsonResponse status200 (J.object ["who" .= who]))
`;

test('a WAI response whose headers are a project constant naming a JSON content type is not an HTML injection; a constant naming text/html keeps it', async () => {
  const json = await scanOf('hs-r8-waijson', { 'p.cabal': cabal(''), 'src/Main.hs': WAI_JSON('[(hContentType, "application/json; charset=utf-8"), (hCacheControl, "no-store")]') });
  assert.equal(live(json, 'CWE-79').length, 0, show(json));
  const html = await scanOf('hs-r8-waijson', { 'p.cabal': cabal(''), 'src/Main.hs': WAI_JSON('[(hContentType, "text/html; charset=utf-8")]') });
  assert.ok(live(html, 'CWE-79').length >= 1, show(html));
});
