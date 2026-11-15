// Round 10 of the Haskell work: the real-code shapes rounds 8 and 9 left (docs/superpowers/plans/2026-11-14-haskell-real-code-precision.md).
//   1. The clock rule follows a clock reading into a project helper: `now <- getCurrentTime; bearer <- signedApiToken api now` in a token-named
//      function is an expiry computation when the helper uses its parameter only in time arithmetic, comparisons, or as a timestamp claim handed
//      to a signing call; the reading that is itself the token (`show now` returned, a seed) is still reported.
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

const BEARER = (signer) => `{-# LANGUAGE OverloadedStrings #-}
module Main (main) where

import Control.Concurrent.STM
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as B
import Data.Int (Int64)
import Data.Time.Clock (UTCTime, addUTCTime, getCurrentTime)
import Data.Time.Clock.POSIX (utcTimeToPOSIXSeconds)
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import Crypto.Hash.Algorithms (SHA256(..))

data Api = Api { apiKey :: ECDSA.PrivateKey, apiToken :: TVar (Maybe (ByteString, UTCTime)) }

main :: IO ()
main = pure ()

bearerToken :: Api -> IO ByteString
bearerToken api = do
  now <- getCurrentTime
  cached <- readTVarIO (apiToken api)
  case cached of
    Just (bearer, validUntil) | now < validUntil -> pure bearer
    _ -> do
      bearer <- signedApiToken api now
      atomically (writeTVar (apiToken api) (Just (bearer, addUTCTime 1500 now)))
      pure bearer

signedApiToken :: Api -> UTCTime -> IO ByteString
signedApiToken api now = do
${signer}
`;

test('a clock handed to a helper that only dates a signed claim is an expiry computation, not the token; a helper that makes the token from the clock is still reported', async () => {
  const claim = await scanOf('hs-r10-clock', { 'p.cabal': exe, 'src/Main.hs': BEARER('  let issuedAt = floor (utcTimeToPOSIXSeconds now) :: Int64\n      claims = B.pack ("{\\"iat\\":" ++ show issuedAt ++ ",\\"exp\\":" ++ show (issuedAt + 1800) ++ "}")\n  sig <- ECDSA.sign (apiKey api) SHA256 claims\n  pure (claims <> "." <> B.pack (show sig))') });
  assert.equal(live(claim, 'CWE-338').length, 0, show(claim));
  const clockToken = await scanOf('hs-r10-clock', { 'p.cabal': exe, 'src/Main.hs': BEARER('  pure (B.pack (show (utcTimeToPOSIXSeconds now)))') });
  assert.ok(live(clockToken, 'CWE-338').length >= 1, show(clockToken));
});

// ── 2. a tuple keeps its fields through a comprehension and a `for_` loop ──
//   `for_ [ (field, unpack (fileName fi), fileContent fi) | (field, fi) <- fs ] $ \(_, fnam, fpath) -> ..`: `fpath` is the framework's temporary
//   file (`fileContent` under scotty's `filesOpts`, a path only there) and `fnam` the client's file name. The write under `fnam` is path traversal;
//   the read of `fpath` is the framework's own file and is lowered. Before, the loop's element was one tainted value with both roots.
test('a tuple built by a comprehension and taken apart by a for_ lambda keeps each field: the client name stays a flaw, the temp-file read is lowered', async () => {
  const src = `{-# LANGUAGE OverloadedStrings, ScopedTypeVariables #-}
module Main (main) where

import Control.Exception (SomeException, catch)
import Control.Monad.IO.Class (liftIO)
import Data.Foldable (for_)
import qualified Data.ByteString.Char8 as BS
import qualified Data.ByteString.Lazy as B
import Network.Wai.Parse (fileContent, fileName, defaultParseRequestBodyOptions)
import System.FilePath ((</>))
import Web.Scotty

main :: IO ()
main = scotty 8080 $
  post "/upload" $ do
    filesOpts defaultParseRequestBodyOptions $ \\_ fs -> do
      let fs' = [ (fieldName, BS.unpack (fileName fi), fileContent fi) | (fieldName, fi) <- fs ]
      for_ fs' $ \\(_, fnam, fpath) -> do
        liftIO (do
          fc <- B.readFile fpath
          B.writeFile ("uploads" </> fnam) fc) \`catch\` (\\(e :: SomeException) -> liftIO (print e))
      text "ok"
`;
  const fs = await scanOf('hs-r10-tuple', { 'p.cabal': exe, 'src/Main.hs': src });
  const path = fs.filter((f) => f.parser === 'IR-TAINT' && f.cwe === 'CWE-22');
  assert.ok(path.some((f) => f.line === 21 && f.severity !== 'info'), `the write under the client name: ${show(path)}`);
  assert.ok(path.every((f) => f.line !== 20 || f.severity === 'info'), `the temp-file read: ${show(path.map((f) => ({ ...f, vuln: `${f.vuln} ${f.trustBoundary && f.trustBoundary.verdict} ${JSON.stringify((f.trustBoundary || {}).roots || []).slice(0, 120)}` })))}`);
});

// ── 3. the parameters of a callback handed to a SOURCE api receive the source ──
//   `filesOpts opts $ \_ fs -> ..`: scotty hands the uploaded parts to the callback; `fs` is the request body. Before, only the call's
//   return value was a source and the callback's parameter was clean, so a field NAME (`(fieldName, fi) <- fs`) written into a page was missed.
test('a callback parameter of a source api is the source: an uploaded field name written into the page is reported', async () => {
  const src = `{-# LANGUAGE OverloadedStrings #-}
module Main (main) where

import qualified Data.Text.Lazy as TL
import Network.Wai.Parse (defaultParseRequestBodyOptions)
import Web.Scotty

main :: IO ()
main = scotty 8080 $
  post "/upload" $
    filesOpts defaultParseRequestBodyOptions $ \\_ fs -> do
      let names = [ fieldName | (fieldName, _) <- fs ]
      html (mconcat (map TL.fromStrict names))
`;
  const fs = await scanOf('hs-r10-callback', { 'p.cabal': exe, 'src/Main.hs': src });
  const xss = live(fs, 'CWE-79').filter((f) => f.parser === 'IR-TAINT');
  assert.ok(xss.some((f) => f.line === 13), show(fs));
});

// ── 4. a record with partly tainted fields passed as an ARGUMENT keeps its fields apart ──
//   `env <- mkEnv req; runAction env` where `mkEnv` builds `Env req responseCell` positionally: the callee reads `envResponse env`, a clean
//   field, and hands it to the response assembly. Before, a record with one tainted field was a tainted argument whole, so the framework's own
//   response plumbing was reported as the injection (scotty's `mkResponse`, every response of every application).
test('a record argument with one tainted field: the callee reading another field is clean, reading the tainted field is not', async () => {
  const mk = (read) => `{-# LANGUAGE OverloadedStrings #-}
module Main (main) where

import qualified Data.ByteString.Lazy as BL
import Data.ByteString.Builder (lazyByteString)
import Network.HTTP.Types (status200)
import Network.Wai

data ActionEnv = Env { envPath :: BL.ByteString, envBody :: BL.ByteString }

main :: IO ()
main = pure ()

app :: Application
app req respond = do
  env <- mkEnv req
  res <- runAction env
  respond res

mkEnv :: Request -> IO ActionEnv
mkEnv req = do
  let greeting = "<p>hello</p>"
  return (Env (BL.fromStrict (rawPathInfo req)) greeting)

runAction :: ActionEnv -> IO Response
runAction env = do
  let body = ${read}
  return (responseBuilder status200 [("Content-Type", "text/html")] (lazyByteString body))
`;
  const clean = await scanOf('hs-r10-recarg', { 'p.cabal': exe, 'src/Main.hs': mk('envBody env') });
  assert.equal(live(clean, 'CWE-79').filter((f) => f.parser === 'IR-TAINT').length, 0, show(clean));
  const tainted = await scanOf('hs-r10-recarg', { 'p.cabal': exe, 'src/Main.hs': mk('envPath env') });
  assert.ok(live(tainted, 'CWE-79').some((f) => f.parser === 'IR-TAINT' && f.line === 28), show(tainted));
});

// ── 5. a response whose headers are assembled from a constant list through a case ──
//   `corsText mOrigin body = responseLBS status200 headers body where baseHeaders = [(hContentType, "text/plain")]; headers = case mOrigin of
//   Nothing -> baseHeaders; Just o -> (cors, o) : baseHeaders`: every branch is the constant list plus a header, so the response is text,
//   not HTML. Before, the header judgement followed one local binding and stopped at the identifier inside the case's branches.
test('a header list assembled by a case over a constant text/plain list is not an HTML response', async () => {
  const src = `{-# LANGUAGE OverloadedStrings #-}
module Main (main) where

import qualified Data.ByteString.Char8 as BS8
import qualified Data.ByteString.Lazy as BL
import Network.HTTP.Types (hContentType, status200)
import Network.Wai
import Network.Wai.Handler.Warp (run)

main :: IO ()
main = run 8080 app

app :: Application
app req respond = respond (corsText (lookup "Origin" (requestHeaders req)) (rawPathInfo req))

corsText :: Maybe BS8.ByteString -> BS8.ByteString -> Response
corsText mOrigin body =
    responseLBS status200 headers (BL.fromStrict body)
  where
    baseHeaders = [(hContentType, "text/plain")]
    headers =
        case mOrigin of
            Nothing     -> baseHeaders
            Just origin -> ("Access-Control-Allow-Origin", origin) : baseHeaders
`;
  const fs = await scanOf('hs-r10-corstext', { 'p.cabal': exe, 'src/Main.hs': src });
  assert.equal(live(fs, 'CWE-79').filter((f) => f.parser === 'IR-TAINT').length, 0, show(fs));
});

// ── unseen-v7 (a development set from here on; its USE-LOG records the reading) ──
// 6. Spock's `html` is the page sink; `param'` is already a source.
test('spock: a request parameter concatenated into the page handed to html is reported', async () => {
  const src = `{-# LANGUAGE OverloadedStrings #-}
module Catalog.Search (searchRoutes) where

import Data.Text (Text)
import qualified Data.Text as T
import Web.Spock

searchRoutes :: SpockM () () () ()
searchRoutes =
  get "parts" $ do
    q <- param' "q"
    html (renderResults q)

renderResults :: Text -> Text
renderResults q = T.concat [ "<h1>Results for ", q, "</h1>" ]
`;
  const fs = await scanOf('hs-r10-spock-html', { 'p.cabal': exe, 'src/Catalog/Search.hs': src });
  assert.ok(live(fs, 'CWE-79').some((f) => f.parser === 'IR-TAINT'), show(fs));
});

// 7. Spock's route captures (`get ("invoices" <//> var <//> "pdf") $ \number -> ..`) are the handler lambda's parameters.
test('spock: a route capture bound by the handler lambda is request input: a file read under it is reported', async () => {
  const src = `{-# LANGUAGE OverloadedStrings #-}
module Invoices.Documents (documentRoutes) where

import Control.Monad.IO.Class (liftIO)
import qualified Data.ByteString.Lazy as BL
import System.FilePath ((</>))
import Web.Spock

invoiceStore :: FilePath
invoiceStore = "/srv/invoices/rendered"

documentRoutes :: SpockM () () () ()
documentRoutes =
  get ("invoices" <//> var <//> "pdf") $ \\number -> do
    pdf <- liftIO (loadRendered number)
    lazyBytes pdf

loadRendered :: String -> IO BL.ByteString
loadRendered number = BL.readFile (invoiceStore </> number ++ ".pdf")
`;
  const fs = await scanOf('hs-r10-spock-var', { 'p.cabal': exe, 'src/Invoices/Documents.hs': src });
  assert.ok(live(fs, 'CWE-22').some((f) => f.parser === 'IR-TAINT'), show(fs));
});

// 8. req: `useHttpsURI`/`useHttpURI` turn a parsed URI into the request target.
test('req: a websocket message parsed into a URI and handed to useHttpsURI is a request to a caller-chosen host', async () => {
  const src = `{-# LANGUAGE DataKinds, OverloadedStrings #-}
module Main (main) where

import qualified Data.ByteString.Lazy as BL
import Data.Text (Text)
import qualified Data.Text as T
import Network.HTTP.Req
import qualified Network.WebSockets as WS
import Text.URI (mkURI)

main :: IO ()
main = WS.runServer "0.0.0.0" 9160 relay

relay :: WS.ServerApp
relay pending = do
  conn <- WS.acceptRequest pending
  msg <- WS.receiveData conn :: IO Text
  body <- fetchFeed (T.strip msg)
  WS.sendBinaryData conn body

fetchFeed :: Text -> IO BL.ByteString
fetchFeed target = do
  uri <- mkURI target
  case useHttpsURI uri of
    Nothing -> pure "feed address must be https"
    Just (url, opts) -> runReq defaultHttpConfig $ do
      r <- req GET url NoReqBody lbsResponse opts
      pure (responseBody r)
`;
  const fs = await scanOf('hs-r10-req', { 'p.cabal': exe, 'src/Main.hs': src });
  assert.ok(live(fs, 'CWE-918').some((f) => f.parser === 'IR-TAINT'), show(fs));
});

// 9. An existence probe whose answer is only tested is part of validating the path, not an access of it.
test('an existence probe whose answer is only tested is lowered; the read it guards is judged on its own', async () => {
  const src = `{-# LANGUAGE OverloadedStrings #-}
module Exports.Download (downloadHandler) where

import Control.Monad.IO.Class (liftIO)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BC
import Data.List (isPrefixOf)
import Snap.Core
import System.Directory (canonicalizePath, doesFileExist)
import System.FilePath ((</>), addTrailingPathSeparator)

exportRoot :: FilePath
exportRoot = "/srv/exports"

downloadHandler :: Snap ()
downloadHandler = do
  mname <- getParam "name"
  case mname of
    Nothing -> writeBS "no such export"
    Just raw -> do
      resolved <- liftIO (resolveExport (BC.unpack raw))
      case resolved of
        Nothing -> writeBS "no such export"
        Just path -> liftIO (BS.readFile path) >>= writeBS

resolveExport :: String -> IO (Maybe FilePath)
resolveExport name = do
  root <- addTrailingPathSeparator <$> canonicalizePath exportRoot
  full <- canonicalizePath (exportRoot </> name)
  exists <- doesFileExist full
  pure (if root \`isPrefixOf\` full && exists then Just full else Nothing)
`;
  const fs = await scanOf('hs-r10-probe', { 'p.cabal': exe, 'src/Exports/Download.hs': src });
  assert.equal(live(fs, 'CWE-22').length, 0, show(fs));
});

// 10. A URI handed back only when its host is a member of a constant set (`Set.member (uriRegName auth) allowedHosts`) is allow-listed.
test('a predicate that returns the URI only when its host is in a constant set is a host allow-list', async () => {
  const src = `{-# LANGUAGE OverloadedStrings #-}
module Preview.Routes (previewRoutes) where

import Control.Lens ((^.))
import Control.Monad.IO.Class (liftIO)
import qualified Data.Set as Set
import qualified Data.Text.Lazy as TL
import Network.URI (URI(..), URIAuth(..), parseURI)
import Network.Wreq (get, responseBody)
import Web.Scotty

allowedHosts :: Set.Set String
allowedHosts = Set.fromList ["cdn.ticketing.example", "images.ticketing.example"]

permitted :: String -> Maybe URI
permitted raw = do
  uri <- parseURI raw
  auth <- uriAuthority uri
  if uriScheme uri == "https:" && Set.member (uriRegName auth) allowedHosts
    then Just uri
    else Nothing

previewRoutes :: ScottyM ()
previewRoutes =
  get "/preview" $ do
    target <- param "url"
    case permitted (TL.unpack target) of
      Nothing -> text "preview host not permitted"
      Just uri -> do
        r <- liftIO (get (show uri))
        raw (r ^. responseBody)
`;
  const fs = await scanOf('hs-r10-allowlist', { 'p.cabal': exe, 'src/Preview/Routes.hs': src });
  assert.equal(live(fs, 'CWE-918').length, 0, show(fs));
});
