// QA-001 UNSEEN shapes, version unseen-v3.
//
// WHY A THIRD SET. unseen-v2 (now templates-shapedev2.mjs, split shape-dev-2) was used to change the engine (the 0.158.0 detection fixes), so it
// stopped measuring generalisation. v3 answers the same question again with code shapes that appear in no other split.
//
// HOW IT WAS WRITTEN. From the vulnerability classes and from what a developer plausibly writes for the vulnerable and the safe variant of each
// family, using library and NixOS option knowledge only. The engine's rule and model files were NOT read while writing it, so the set cannot
// have been shaped to what the engine already handles. Each family has three vulnerable and three safe shapes (the safe ones include
// near-misses: a safe form that shares surface text with the vulnerable one). Recently fixed areas got extra variety: HTTP-client SSRF across
// libraries and call shapes, request-body reading with and without a limit, inline route authentication (including a check that comes too
// late), nested process calls, firewall port ranges and option-expression forms (let, with, optionals, mkMerge), secrets in Nix.
//
// RULES OF USE (what makes this set worth anything):
//   * Nothing in scanner/src may be tuned against these shapes. They are measured ONCE per promotion (bench/language-support/measure.mjs
//     --split unseen), the result is stored, and a miss is a finding about the engine, not an invitation to fit it. If a shape is used to
//     change the engine, it joins a shape-dev set and a NEW unseen set (v4) must be written.
//   * Each shape has ONE flaw (vulnerable) or none (safe). Names say what the value is.
//   * The label is the property the code has, stated by its author; it is not a regex reviewer's verdict.
//   * Nothing here is read by scanner/src.

import { HS_NOUNS, NIX_NOUNS } from './templates.mjs';
import { sha256 } from './lib.mjs';

export const UNSEEN_VERSION = 'unseen-v3';
export { HS_NOUNS as UNSEEN_HS_NOUNS, NIX_NOUNS as UNSEEN_NIX_NOUNS };

const hash64 = (s) => Buffer.from(sha256(s), 'hex').toString('base64');   // a real-looking digest, never the all-A fake-hash placeholder

const hs = (n, j, imports, body) => `module ${n.N}Svc where

${imports.join('\n')}

${body}

endpointPath :: String
endpointPath = "/${n.tbl}/v${j}"
`;

const nix = (n, j, lines, lets = '') => `{ config, lib, pkgs, ... }:
let
  cfg = config.services.${n.tbl};
${lets}in
{
  networking.hostName = "${n.tbl}-y${j}";
${lines.map((l) => `  ${l}`).join('\n')}
}
`;
const nixFull = (expr) => `{ config, lib, pkgs, ... }:\n${expr}\n`;

const SCOTTY = ['import Web.Scotty', 'import Control.Monad.IO.Class (liftIO)', 'import Database.SQLite.Simple', 'import Network.HTTP.Types.Status (status401, status403)', 'import Data.Maybe (isNothing)', 'import Control.Monad (when, unless)', 'import qualified Data.Text.Lazy as TL', 'import System.Environment (getEnv)'];
const WAI_APP = (n) => `app :: Application
app request respond = case (requestMethod request, pathInfo request) of
  ("POST", ["admin", "reindex"]) -> do
    conn <- open "${n.tbl}.db"
    execute_ conn "DELETE FROM ${n.tbl}_index"
    respond (responseLBS status200 [] (BL.pack "reindexed"))
  _ -> respond (responseLBS status404 [] BL.empty)`;
const WAI_IMPORTS = ['import Network.Wai', 'import Network.Wai.Handler.Warp (run)', 'import Network.HTTP.Types (status200, status404)', 'import Database.SQLite.Simple', 'import qualified Data.ByteString.Lazy.Char8 as BL', 'import qualified Data.ByteString.Char8 as BC', 'import System.Environment (getEnv)'];
const SERVANT_IMPORTS = ['import Servant', 'import Servant.Server.Experimental.Auth (AuthServerData)', 'import Control.Monad.IO.Class (liftIO)', 'import Database.SQLite.Simple'];
const SERVANT_ACCOUNT = `data Account = Account { accountId :: Int }

type instance AuthServerData (AuthProtect "jwt") = Account`;

// ── Haskell ──────────────────────────────────────────────────────────────────
export const HS_UNSEEN = {
  'sql-injection': {
    vuln: [
      (n, j) => hs(n, j, ['import Database.Persist.Sql', 'import qualified Data.Text as T'],
        `findByName :: T.Text -> SqlPersistT IO [Single T.Text]
findByName who = rawSql (T.concat ["SELECT ${n.col} FROM ${n.tbl} WHERE ${n.col} = '", who, "'"]) []`),
      (n, j) => hs(n, j, ['import Database.MySQL.Simple', 'import Data.String (fromString)', 'import Text.Printf (printf)'],
        `searchBy :: Connection -> String -> IO [Only String]
searchBy conn term = query_ conn (fromString (printf "SELECT ${n.col} FROM ${n.tbl} WHERE ${n.col} LIKE '%%%s%%'" term))`),
      (n, j) => hs(n, j, ['import Database.HDBC'],
        `lookupRows :: IConnection conn => conn -> String -> IO [[SqlValue]]
lookupRows conn who = quickQuery' conn ("SELECT ${n.col} FROM ${n.tbl} WHERE ${n.col} = '" ++ who ++ "'") []`),
    ],
    safe: [
      [(n, j) => hs(n, j, ['import Database.HDBC'],
        `lookupRows :: IConnection conn => conn -> String -> IO [[SqlValue]]
lookupRows conn who = quickQuery' conn "SELECT ${n.col} FROM ${n.tbl} WHERE ${n.col} = ?" [toSql who]`), 'parameterized'],
      [(n, j) => hs(n, j, ['import Database.PostgreSQL.Simple', 'import Data.String (fromString)'],
        `tableName :: String
tableName = "${n.tbl}"

countFor :: Connection -> String -> IO [Only Int]
countFor conn who = query conn (fromString ("SELECT count(*) FROM " ++ tableName ++ " WHERE ${n.col} = ?")) (Only who)`), 'constant-concat'],
      [(n, j) => hs(n, j, ['import Database.Persist.Sql', 'import qualified Data.Text as T'],
        `findByName :: T.Text -> SqlPersistT IO [Single T.Text]
findByName who = rawSql "SELECT ${n.col} FROM ${n.tbl} WHERE ${n.col} = ?" [toPersistValue who]`), 'parameterized'],
    ],
  },
  'command-injection': {
    vuln: [
      (n, j) => hs(n, j, ['import System.Process.Typed'],
        `unpack :: String -> IO ()
unpack archive = runProcess_ (shell ("tar xzf " ++ archive ++ " -C /srv/${n.tbl}"))`),
      (n, j) => hs(n, j, ['import System.Process', 'import System.Exit (ExitCode)'],
        `thumbnail :: String -> IO ExitCode
thumbnail file = do
  (code, _, _) <- readProcessWithExitCode "sh" ["-c", "convert " ++ file ++ " -resize 64x64 thumb.png"] ""
  pure code`),
      (n, j) => hs(n, j, ['import System.Process'],
        `runShell :: String -> IO ()
runShell cmd = callCommand cmd

compress :: String -> IO ()
compress target = runShell ("gzip -9 " ++ target)`),
    ],
    safe: [
      [(n, j) => hs(n, j, ['import System.Process.Typed'],
        `unpack :: String -> IO ()
unpack archive = runProcess_ (proc "tar" ["xzf", archive, "-C", "/srv/${n.tbl}"])`), 'argv-separator'],
      [(n, j) => hs(n, j, ['import System.Process', 'import System.Exit (ExitCode)'],
        `thumbnail :: String -> IO ExitCode
thumbnail file = do
  (code, _, _) <- readProcessWithExitCode "convert" [file, "-resize", "64x64", "thumb.png"] ""
  pure code`), 'argv-separator'],
      [(n, j) => hs(n, j, ['import System.Process'],
        `compress :: String -> IO ()
compress target = callProcess "sh" ["-c", "gzip -9 -- \\"$1\\"", "sh", target]`), 'positional-args'],
    ],
  },
  'path-traversal': {
    vuln: [
      (n, j) => hs(n, j, ['import System.Directory (listDirectory)', 'import System.FilePath ((</>))'],
        `entries :: String -> IO [FilePath]
entries sub = listDirectory ("/srv/${n.tbl}/files" </> sub)`),
      (n, j) => hs(n, j, ['import System.IO'],
        `saveUpload :: String -> String -> IO ()
saveUpload name content = withFile name WriteMode (\\h -> hPutStr h content)`),
      (n, j) => hs(n, j, ['import Web.Scotty'],
        `main :: IO ()
main = scotty 3000 $ get "/download/:name" $ do
  name <- param "name"
  file ("/srv/${n.tbl}/exports/" ++ name)`),
    ],
    safe: [
      [(n, j) => hs(n, j, ['import System.Directory (canonicalizePath)', 'import System.FilePath ((</>))', 'import Data.List (isPrefixOf)'],
        `readInside :: String -> IO String
readInside name = do
  root <- canonicalizePath "/srv/${n.tbl}/files"
  full <- canonicalizePath (root </> name)
  if (root ++ "/") \`isPrefixOf\` full then readFile full else ioError (userError "outside root")`), 'guard'],
      [(n, j) => hs(n, j, ['import Web.Scotty', 'import qualified Data.Map.Strict as Map'],
        `catalogue :: Map.Map String FilePath
catalogue = Map.fromList [("manual", "/srv/${n.tbl}/manual.pdf"), ("terms", "/srv/${n.tbl}/terms.pdf")]

main :: IO ()
main = scotty 3000 $ get "/download/:name" $ do
  name <- param "name"
  case Map.lookup name catalogue of
    Just known -> file known
    Nothing -> next`), 'constant-table'],
      [(n, j) => hs(n, j, [],
        `saveLatest :: String -> IO ()
saveLatest content = writeFile "/var/lib/${n.tbl}/latest.txt" content`), 'fixed-path'],
    ],
  },
  ssrf: {
    vuln: [
      (n, j) => hs(n, j, ['import Network.HTTP.Req', 'import Text.URI (mkURI)', 'import qualified Data.Text as T'],
        `fetchRemote :: T.Text -> IO ()
fetchRemote raw = do
  uri <- mkURI raw
  case useURI uri of
    Just (Left (u, o)) -> runReq defaultHttpConfig (req GET u NoReqBody ignoreResponse o) >> pure ()
    Just (Right (u, o)) -> runReq defaultHttpConfig (req GET u NoReqBody ignoreResponse o) >> pure ()
    Nothing -> pure ()`),
      (n, j) => hs(n, j, ['import Network.HTTP.Simple', 'import qualified Data.ByteString.Char8 as BC'],
        `probe :: String -> IO Int
probe hostName = do
  let request = setRequestSecure True (setRequestPort 443 (setRequestHost (BC.pack hostName) defaultRequest))
  resp <- httpLBS request
  pure (getResponseStatusCode resp)`),
      (n, j) => hs(n, j, ['import Network.HTTP.Client', 'import Network.HTTP.Client.TLS (getGlobalManager)', 'import Network.URI (parseURI)'],
        `relay :: String -> IO ()
relay target = do
  mgr <- getGlobalManager
  case parseURI target >>= requestFromURI of
    Just req -> httpNoBody req mgr >> pure ()
    Nothing -> pure ()`),
    ],
    safe: [
      [(n, j) => hs(n, j, ['import qualified Network.Wreq as W', 'import Control.Lens ((^.))'],
        `fetch :: Int -> IO Int
fetch itemId = do
  r <- W.get ("https://api.${n.tbl}.example.com/v2/items/" ++ show itemId)
  pure (r ^. W.responseStatus . W.statusCode)`), 'fixed-host'],
      [(n, j) => hs(n, j, ['import Network.HTTP.Client', 'import Network.HTTP.Client.TLS (tlsManagerSettings)', 'import qualified Data.ByteString.Char8 as BC'],
        `allowedHosts :: [BC.ByteString]
allowedHosts = [BC.pack "hooks.${n.tbl}.example.com", BC.pack "status.${n.tbl}.example.com"]

fetch :: String -> IO ()
fetch url = do
  req <- parseRequest url
  if host req \`elem\` allowedHosts && secure req
    then newManager tlsManagerSettings >>= httpNoBody req >> pure ()
    else ioError (userError "host not allowed")`), 'allowlist'],
      [(n, j) => hs(n, j, ['import Network.HTTP.Req', 'import qualified Data.Text as T'],
        `fetchDoc :: T.Text -> IO ()
fetchDoc docId = runReq defaultHttpConfig $ do
  _ <- req GET (https "docs.${n.tbl}.example.com" /: "v1" /: docId) NoReqBody ignoreResponse mempty
  pure ()`), 'fixed-host'],
    ],
  },
  'html-injection': {
    vuln: [
      (n, j) => hs(n, j, ['import Web.Scotty', 'import qualified Data.Text as T', 'import qualified Data.Text.Lazy as TL'],
        `main :: IO ()
main = scotty 3000 $ get "/greet/:who" $ do
  who <- param "who"
  html (TL.fromStrict ("<h1>Welcome, " <> who <> "</h1>"))`),
      (n, j) => hs(n, j, ['import qualified Text.Blaze.Html5 as H', 'import Text.Blaze (preEscapedText)', 'import qualified Data.Text as T'],
        `notice :: T.Text -> H.Html
notice msg = H.div (preEscapedText msg)`),
      (n, j) => hs(n, j, ['import Yesod', 'import qualified Data.Text as T'],
        `renderComment :: T.Text -> Widget
renderComment comment = toWidget (preEscapedToMarkup comment)`),
    ],
    safe: [
      [(n, j) => hs(n, j, ['import Web.Scotty', 'import qualified Data.Text as T', 'import qualified Data.Text.Lazy as TL'],
        `escapeHtml :: T.Text -> T.Text
escapeHtml = T.concatMap esc
  where
    esc '<' = "&lt;"
    esc '>' = "&gt;"
    esc '&' = "&amp;"
    esc '"' = "&quot;"
    esc '\\'' = "&#39;"
    esc c = T.singleton c

main :: IO ()
main = scotty 3000 $ get "/greet/:who" $ do
  who <- param "who"
  html (TL.fromStrict ("<h1>Welcome, " <> escapeHtml who <> "</h1>"))`), 'escaper'],
      [(n, j) => hs(n, j, ['import qualified Text.Blaze.Html5 as H', 'import qualified Data.Text as T'],
        `notice :: T.Text -> H.Html
notice msg = H.div (H.text msg)`), 'escaper'],
      [(n, j) => hs(n, j, ['import Web.Scotty', 'import qualified Lucid as L', 'import qualified Data.Text as T'],
        `main :: IO ()
main = scotty 3000 $ get "/greet/:who" $ do
  who <- param "who"
  html (L.renderText (L.h1_ (L.toHtml (T.append "Welcome, " who))))`), 'escaper'],
    ],
  },
  'weak-password-hash': {
    vuln: [
      (n, j) => hs(n, j, ['import Crypto.Hash (hash, Digest, MD5)', 'import qualified Data.ByteString.Char8 as BC'],
        `hashPassword :: String -> Digest MD5
hashPassword password = hash (BC.pack password)`),
      (n, j) => hs(n, j, ['import Data.Digest.Pure.SHA (sha1, showDigest)', 'import qualified Data.ByteString.Lazy.Char8 as BL'],
        `storeCredential :: String -> String
storeCredential password = showDigest (sha1 (BL.pack password))`),
      (n, j) => hs(n, j, ['import Crypto.Hash (hashWith, SHA512 (..))', 'import Data.ByteArray.Encoding (convertToBase, Base (Base16))', 'import qualified Data.ByteString.Char8 as BC'],
        `passwordDigest :: String -> BC.ByteString
passwordDigest password = convertToBase Base16 (hashWith SHA512 (BC.pack password))`),
    ],
    safe: [
      [(n, j) => hs(n, j, ['import Crypto.KDF.BCrypt (bcrypt)', 'import qualified Data.ByteString.Char8 as BC'],
        `hashPassword :: BC.ByteString -> String -> BC.ByteString
hashPassword salt password = bcrypt 12 salt (BC.pack password)`), 'kdf'],
      [(n, j) => hs(n, j, ['import Crypto.KDF.Scrypt (generate, Parameters (..))', 'import qualified Data.ByteString.Char8 as BC'],
        `storeCredential :: BC.ByteString -> String -> BC.ByteString
storeCredential salt password = generate (Parameters { n = 16384, r = 8, p = 1, outputLength = 64 }) (BC.pack password) salt`), 'kdf'],
      [(n, j) => hs(n, j, ['import Crypto.Hash (hashWith, SHA256 (..))', 'import qualified Data.ByteString as BS'],
        `contentEtag :: BS.ByteString -> String
contentEtag body = show (hashWith SHA256 body)`), 'not-a-password'],
    ],
  },
  'weak-randomness': {
    vuln: [
      (n, j) => hs(n, j, ['import System.Random', 'import Data.Time.Clock.POSIX (getPOSIXTime)'],
        `generateApiKey :: IO String
generateApiKey = do
  now <- getPOSIXTime
  pure (take 32 (randomRs ('a', 'z') (mkStdGen (floor now))))`),
      (n, j) => hs(n, j, ['import System.Random (randomIO)', 'import Data.Word (Word64)'],
        `newCsrfToken :: IO Word64
newCsrfToken = randomIO`),
      (n, j) => hs(n, j, ['import System.Random (randomRIO)', 'import Control.Monad (replicateM)'],
        `temporaryPassword :: IO String
temporaryPassword = replicateM 12 (randomRIO ('a', 'z'))`),
    ],
    safe: [
      [(n, j) => hs(n, j, ['import Crypto.Random (drgNew, randomBytesGenerate)', 'import qualified Data.ByteString as BS'],
        `newCsrfToken :: IO BS.ByteString
newCsrfToken = fmap (fst . randomBytesGenerate 32) drgNew`), 'csprng'],
      [(n, j) => hs(n, j, ['import Crypto.Random (getRandomBytes)', 'import Data.ByteArray.Encoding (convertToBase, Base (Base64URLUnpadded))', 'import qualified Data.ByteString as BS'],
        `newSessionId :: IO BS.ByteString
newSessionId = do
  raw <- getRandomBytes 24 :: IO BS.ByteString
  pure (convertToBase Base64URLUnpadded raw)`), 'csprng'],
      [(n, j) => hs(n, j, ['import System.Random (randomRIO)', 'import Control.Concurrent (threadDelay)'],
        `retryJitter :: IO ()
retryJitter = randomRIO (50, 250) >>= \\ms -> threadDelay (ms * 1000)`), 'not-a-secret'],
    ],
  },
  'resource-limits': {
    vuln: [
      (n, j) => hs(n, j, ['import Web.Scotty', 'import qualified Data.ByteString.Lazy as BL', 'import Control.Monad.IO.Class (liftIO)'],
        `main :: IO ()
main = scotty 3000 $ post "/${n.tbl}/ingest" $ do
  payload <- body
  liftIO (BL.writeFile "/var/spool/${n.tbl}/inbox.dat" payload)
  text "queued"`),
      (n, j) => hs(n, j, ['import Network.Wai (Request)', 'import Network.Wai.Conduit (sourceRequestBody)', 'import Data.Conduit (runConduit, (.|))', 'import Data.Conduit.Binary (sinkLbs)', 'import qualified Data.ByteString.Lazy as BL'],
        `collect :: Request -> IO BL.ByteString
collect request = runConduit (sourceRequestBody request .| sinkLbs)`),
      (n, j) => hs(n, j, ['import Network.Socket (Socket)', 'import Network.Socket.ByteString (recv)', 'import qualified Data.ByteString as BS'],
        `readAll :: Socket -> IO BS.ByteString
readAll sock = loop []
  where
    loop acc = do
      chunk <- recv sock 4096
      if BS.null chunk then pure (BS.concat (reverse acc)) else loop (chunk : acc)`),
    ],
    safe: [
      [(n, j) => hs(n, j, ['import Network.Wai (Request, RequestBodyLength (..), requestBodyLength, strictRequestBody)', 'import qualified Data.ByteString.Lazy as BL'],
        `collect :: Request -> IO BL.ByteString
collect request = case requestBodyLength request of
  KnownLength size | size <= 65536 -> strictRequestBody request
  _ -> pure BL.empty`), 'bound'],
      [(n, j) => hs(n, j, ['import Network.Wai (Request)', 'import Network.Wai.Conduit (sourceRequestBody)', 'import Data.Conduit (runConduit, (.|))', 'import Data.Conduit.Binary (sinkLbs, isolate)', 'import qualified Data.ByteString.Lazy as BL'],
        `collect :: Request -> IO BL.ByteString
collect request = runConduit (sourceRequestBody request .| isolate 65536 .| sinkLbs)`), 'bound'],
      [(n, j) => hs(n, j, ['import Network.Socket (Socket)', 'import Network.Socket.ByteString (recv)', 'import qualified Data.ByteString as BS'],
        `readCapped :: Socket -> IO BS.ByteString
readCapped sock = loop 0 []
  where
    limit = 65536 :: Int
    loop total acc
      | total >= limit = pure (BS.concat (reverse acc))
      | otherwise = do
          chunk <- recv sock 4096
          if BS.null chunk then pure (BS.concat (reverse acc)) else loop (total + BS.length chunk) (chunk : acc)`), 'bound'],
    ],
  },
  'parser-safety': {
    vuln: [
      (n, j) => hs(n, j, [],
        `peak :: [Int] -> Int
peak xs = maximum xs`),
      (n, j) => hs(n, j, ['import qualified Data.Map as M'],
        `price :: M.Map String Int -> String -> Int
price table sku = table M.! sku`),
      (n, j) => hs(n, j, [],
        `lastToken :: String -> String
lastToken line = last (words line)`),
    ],
    safe: [
      [(n, j) => hs(n, j, ['import Data.List.NonEmpty (nonEmpty)'],
        `peak :: [Int] -> Int
peak xs = maybe 0 maximum (nonEmpty xs)`), 'total-parser'],
      [(n, j) => hs(n, j, ['import qualified Data.Map as M'],
        `price :: M.Map String Int -> String -> Int
price table sku = M.findWithDefault 0 sku table`), 'total-parser'],
      [(n, j) => hs(n, j, [],
        `lastToken :: String -> String
lastToken line
  | null ws = ""
  | otherwise = last ws
  where
    ws = words line`), 'guarded-partial'],
    ],
  },
  'sensitive-logging': {
    vuln: [
      (n, j) => hs(n, j, ['import System.Log.Logger (infoM)'],
        `onIssue :: String -> String -> IO ()
onIssue user password = infoM "${n.tbl}.auth" ("issued password " ++ password ++ " to " ++ user)`),
      (n, j) => hs(n, j, ['import Katip', 'import qualified Data.Text as T'],
        `rotate :: Katip m => T.Text -> m ()
rotate refreshToken = logFM InfoS (ls ("refresh token " <> refreshToken))`),
      (n, j) => hs(n, j, ['import Text.Printf (printf)'],
        `debugSession :: String -> String -> IO ()
debugSession sid apiSecret = printf "session %s secret %s\\n" sid apiSecret`),
    ],
    safe: [
      [(n, j) => hs(n, j, ['import System.Log.Logger (infoM)'],
        `onIssue :: String -> String -> IO ()
onIssue user _ = infoM "${n.tbl}.auth" ("issued password to " ++ user)`), 'redaction'],
      [(n, j) => hs(n, j, ['import Katip', 'import qualified Data.Text as T'],
        `rotate :: Katip m => T.Text -> m ()
rotate user = logFM InfoS (ls ("refresh token rotated for " <> user))`), 'not-sensitive'],
      [(n, j) => hs(n, j, ['import Text.Printf (printf)'],
        `mask :: String -> String
mask s = replicate (length s) '*'

debugSession :: String -> String -> IO ()
debugSession sid apiSecret = printf "session %s secret %s\\n" sid (mask apiSecret)`), 'redaction'],
    ],
  },
  'route-authentication': {
    vuln: [
      (n, j) => hs(n, j, SCOTTY,
        `main :: IO ()
main = scotty 3000 $
  delete "/${n.tbl}/all" $ do
    conn <- liftIO (open "${n.tbl}.db")
    liftIO (execute_ conn "DELETE FROM ${n.tbl}")
    token <- header "Authorization"
    when (isNothing token) (status status401 >> finish)
    text "cleared"`),
      (n, j) => hs(n, j, WAI_IMPORTS,
        `${WAI_APP(n)}

main :: IO ()
main = run 8080 app`),
      (n, j) => hs(n, j, ['import Yesod', 'import Database.Persist.Sql (rawExecute)'],
        `postPurgeR :: Handler Text
postPurgeR = do
  runDB (rawExecute "DELETE FROM ${n.tbl}" [])
  return "purged"`),
    ],
    safe: [
      [(n, j) => hs(n, j, SCOTTY,
        `main :: IO ()
main = scotty 3000 $
  delete "/${n.tbl}/all" $ do
    mAuth <- header "Authorization"
    expected <- liftIO (getEnv "ADMIN_TOKEN")
    case mAuth of
      Just a | a == TL.pack ("Bearer " ++ expected) -> do
        conn <- liftIO (open "${n.tbl}.db")
        liftIO (execute_ conn "DELETE FROM ${n.tbl}")
        text "cleared"
      _ -> status status401 >> finish`), 'auth-guard'],
      [(n, j) => hs(n, j, SERVANT_IMPORTS.filter((i) => !/Experimental/.test(i)),
        `data Admin = Admin

type API = BasicAuth "admin" Admin :> "purge" :> Delete '[JSON] NoContent

server :: Server API
server _admin = do
  conn <- liftIO (open "${n.tbl}.db")
  liftIO (execute_ conn "DELETE FROM ${n.tbl}")
  pure NoContent`), 'auth-guard'],
      [(n, j) => hs(n, j, [...WAI_IMPORTS, 'import Network.Wai.Middleware.HttpAuth (basicAuth)'],
        `${WAI_APP(n)}

main :: IO ()
main = do
  pass <- getEnv "ADMIN_PASSWORD"
  run 8080 (basicAuth (\\u p -> pure (u == BC.pack "admin" && p == BC.pack pass)) "admin area" app)`), 'auth-guard'],
    ],
  },
  'object-authorization': {
    vuln: [
      (n, j) => hs(n, j, ['import Yesod'],
        `getInvoiceR :: InvoiceId -> Handler Value
getInvoiceR invoiceId = do
  _ <- requireAuthId
  invoice <- runDB (get404 invoiceId)
  returnJson invoice`),
      (n, j) => hs(n, j, SERVANT_IMPORTS,
        `${SERVANT_ACCOUNT}

type API = AuthProtect "jwt" :> "${n.tbl}" :> Capture "id" Int :> Get '[JSON] [String]

server :: Server API
server _account rowId = do
  conn <- liftIO (open "${n.tbl}.db")
  rows <- liftIO (query conn "SELECT ${n.col} FROM ${n.tbl} WHERE id = ?" (Only rowId))
  pure (map fromOnly rows)`),
      (n, j) => hs(n, j, SCOTTY,
        `requireLogin :: ActionM Int
requireLogin = do
  h <- header "Authorization"
  case h of
    Nothing -> status status401 >> finish
    Just _ -> pure 7

main :: IO ()
main = scotty 3000 $
  put "/${n.tbl}/:id" $ do
    _ <- requireLogin
    oid <- param "id"
    owner <- param "owner"
    body <- param "body"
    conn <- liftIO (open "${n.tbl}.db")
    liftIO (execute conn "UPDATE ${n.tbl} SET ${n.col} = ? WHERE id = ? AND owner_id = ?" (body :: String, oid :: Int, owner :: Int))
    text "saved"`),
    ],
    safe: [
      [(n, j) => hs(n, j, ['import Yesod', 'import Control.Monad (when)'],
        `getInvoiceR :: InvoiceId -> Handler Value
getInvoiceR invoiceId = do
  uid <- requireAuthId
  invoice <- runDB (get404 invoiceId)
  when (invoiceOwner invoice /= uid) notFound
  returnJson invoice`), 'owner-scope'],
      [(n, j) => hs(n, j, SERVANT_IMPORTS,
        `${SERVANT_ACCOUNT}

type API = AuthProtect "jwt" :> "${n.tbl}" :> Capture "id" Int :> Get '[JSON] [String]

server :: Server API
server account rowId = do
  conn <- liftIO (open "${n.tbl}.db")
  rows <- liftIO (query conn "SELECT ${n.col}, owner_id FROM ${n.tbl} WHERE id = ?" (Only rowId))
  case (rows :: [(String, Int)]) of
    [(value, ownerId)] | ownerId == accountId account -> pure [value]
    _ -> throwError err403`), 'owner-scope'],
      [(n, j) => hs(n, j, ['import Yesod'],
        `getInvoiceR :: InvoiceId -> Handler Value
getInvoiceR invoiceId = do
  uid <- requireAuthId
  found <- runDB (selectFirst [InvoiceId ==. invoiceId, InvoiceOwner ==. uid] [])
  maybe notFound returnJson found`), 'owner-scope'],
    ],
  },
  'session-cookie': {
    vuln: [
      (n, j) => hs(n, j, ['import Web.Scotty', 'import Web.Scotty.Cookie (setSimpleCookie)', 'import qualified Data.Text as T'],
        `login :: T.Text -> ActionM ()
login sid = do
  setSimpleCookie "session_id" sid
  text "welcome"`),
      (n, j) => hs(n, j, ['import Network.Wai', 'import Network.HTTP.Types (status200)', 'import Network.HTTP.Types.Header (hSetCookie)', 'import qualified Data.ByteString.Char8 as BC', 'import qualified Data.ByteString.Lazy.Char8 as BL'],
        `loginResponse :: BC.ByteString -> Response
loginResponse sid = responseLBS status200 [(hSetCookie, BC.pack "session_id=" <> sid <> BC.pack "; Path=/")] (BL.pack "ok")`),
      (n, j) => hs(n, j, ['import Servant.Auth.Server'],
        `sessionCookieSettings :: CookieSettings
sessionCookieSettings = defaultCookieSettings { cookieIsSecure = NotSecure }`),
    ],
    safe: [
      [(n, j) => hs(n, j, ['import Servant.Auth.Server'],
        `sessionCookieSettings :: CookieSettings
sessionCookieSettings = defaultCookieSettings { cookieIsSecure = Secure, cookieSameSite = SameSiteStrict }`), 'hardened-attrs'],
      [(n, j) => hs(n, j, ['import Network.Wai', 'import Network.HTTP.Types (status200)', 'import Network.HTTP.Types.Header (hSetCookie)', 'import qualified Data.ByteString.Char8 as BC', 'import qualified Data.ByteString.Lazy.Char8 as BL'],
        `loginResponse :: BC.ByteString -> Response
loginResponse sid = responseLBS status200 [(hSetCookie, BC.pack "session_id=" <> sid <> BC.pack "; Path=/; Secure; HttpOnly; SameSite=Strict")] (BL.pack "ok")`), 'hardened-attrs'],
      [(n, j) => hs(n, j, ['import Web.Scotty', 'import Web.Scotty.Cookie (setSimpleCookie)', 'import qualified Data.Text as T'],
        `rememberLanguage :: T.Text -> ActionM ()
rememberLanguage lang = do
  setSimpleCookie "language" lang
  text "saved"`), 'not-a-session'],
    ],
  },
};

// ── Nix ──────────────────────────────────────────────────────────────────────
export const NIX_UNSEEN = {
  'script-interpolation': {
    vuln: [
      (n, j) => nix(n, j, [`systemd.services.${n.tbl}-backup.script = ''`, `  \${pkgs.rsync}/bin/rsync -a \${cfg.source} \${cfg.destination}`, "'';"]),
      (n, j) => nix(n, j, ['environment.systemPackages = [ (pkgs.writeShellApplication {', `  name = "${n.tbl}-ping";`, '  runtimeInputs = [ pkgs.curl ];', "  text = ''curl -fsS ${cfg.endpoint}/health'';", '}) ];']),
      (n, j) => nix(n, j, [`systemd.services.${n.tbl}.preStart = ''`, `  mkdir -p \${cfg.stateDir} && chmod 750 \${cfg.stateDir}`, "'';"]),
    ],
    safe: [
      [(n, j) => nix(n, j, [`systemd.services.${n.tbl}-backup.script = ''`, '  ${pkgs.rsync}/bin/rsync ${lib.escapeShellArgs [ "-a" cfg.source cfg.destination ]}', "'';"]), 'escaper'],
      [(n, j) => nix(n, j, ['environment.systemPackages = [ (pkgs.writeShellApplication {', `  name = "${n.tbl}-ping";`, '  runtimeInputs = [ pkgs.curl ];', "  text = ''curl -fsS ${lib.escapeShellArg cfg.endpoint}/health'';", '}) ];']), 'escaper'],
      [(n, j) => nix(n, j, [`systemd.services.${n.tbl}-backup.script = ''`, `  \${pkgs.rsync}/bin/rsync -a /srv/${n.tbl}/ /backup/${n.tbl}/`, '  ${pkgs.coreutils}/bin/sync', "'';"]), 'store-path-only'],
    ],
  },
  'secret-in-store': {
    vuln: [
      (n, j) => nix(n, j, [`networking.wireless.networks."${n.tbl}-office".psk = "Tr0ub4dor&3-${n.tbl}";`]),
      (n, j) => nix(n, j, [`systemd.services.${n.tbl}.environment.DATABASE_PASSWORD = "p@ssw0rd-${n.tbl}-prod";`]),
      (n, j) => nix(n, j, [`services.${n.tbl}.passwordFile = pkgs.writeText "${n.tbl}-pass" "swordfish-${n.tbl}";`]),
    ],
    safe: [
      [(n, j) => nix(n, j, [`services.${n.tbl}.passwordFile = config.sops.secrets."${n.tbl}/db-password".path;`]), 'runtime-path'],
      [(n, j) => nix(n, j, ['networking.wireless.secretsFile = "/run/secrets/wireless.env";', `networking.wireless.networks."${n.tbl}-office".pskRaw = "ext:${n.tbl}_office_psk";`]), 'runtime-path'],
      [(n, j) => nix(n, j, [`services.${n.tbl}.settings.passwordMinLength = 12;`]), 'not-a-secret'],
    ],
  },
  'unpinned-source': {
    vuln: [
      (n, j) => nix(n, j, [`environment.etc."${n.tbl}.src".source = builtins.fetchGit { url = "https://example.org/${n.tbl}.git"; ref = "main"; };`]),
      (n, j) => nix(n, j, [`environment.etc."${n.tbl}.tar".source = builtins.fetchTarball "https://example.org/${n.tbl}-v${j}.tar.gz";`]),
      (n, j) => nix(n, j, ['environment.systemPackages = [ unstable.hello ];'], '  unstable = import (builtins.fetchTarball "https://github.com/NixOS/nixpkgs/archive/nixos-unstable.tar.gz") { };\n'),
    ],
    safe: [
      [(n, j) => nix(n, j, [`environment.etc."${n.tbl}.src".source = builtins.fetchGit { url = "https://example.org/${n.tbl}.git"; rev = "0123456789abcdef0123456789abcdef01234567"; };`]), 'content-pin'],
      [(n, j) => nix(n, j, [`environment.etc."${n.tbl}.tar".source = builtins.fetchTarball { url = "https://example.org/${n.tbl}-v${j}.tar.gz"; sha256 = "sha256-${hash64(n.tbl + "tar" + j)}"; };`]), 'content-pin'],
      [(n, j) => nix(n, j, [`environment.etc."${n.tbl}.zip".source = pkgs.fetchzip { url = "https://example.org/${n.tbl}-v${j}.zip"; hash = "sha256-${hash64(n.tbl + "zip" + j)}"; };`]), 'content-pin'],
    ],
  },
  'binary-cache-trust': {
    vuln: [
      (n, j) => nix(n, j, [`nix.settings.extra-substituters = [ "http://cache.${n.tbl}.example.org" ];`]),
      (n, j) => nix(n, j, [`nix.binaryCaches = [ "http://cache.${n.tbl}.example.org" ];`]),
      (n, j) => nix(n, j, ["nix.extraOptions = ''", '  require-sigs = false', "'';"]),
    ],
    safe: [
      [(n, j) => nix(n, j, [`nix.settings.extra-substituters = [ "https://cache.${n.tbl}.example.org" ];`, `nix.settings.extra-trusted-public-keys = [ "cache.${n.tbl}.example.org-1:${hash64(n.tbl + 'key')}" ];`]), 'tls-cache'],
      [(n, j) => nix(n, j, ['nix.binaryCaches = [ "https://cache.nixos.org" ];']), 'tls-cache'],
      [(n, j) => nix(n, j, ["nix.extraOptions = ''", '  require-sigs = true', "'';"]), 'hardened-setting'],
    ],
  },
  'trusted-users': {
    vuln: [
      (n, j) => nix(n, j, ['nix.trustedUsers = [ "root" "@wheel" ];']),
      (n, j) => nix(n, j, ["nix.extraOptions = ''", '  trusted-users = root @wheel', "'';"]),
      (n, j) => nix(n, j, ['nix.settings.trusted-users = [ "root" ] ++ admins;'], '  admins = [ "@wheel" "@admin" ];\n'),
    ],
    safe: [
      [(n, j) => nix(n, j, ['nix.trustedUsers = [ "root" ];']), 'scoped-users'],
      [(n, j) => nix(n, j, ['nix.settings.allowed-users = [ "@wheel" ];']), 'unrelated-setting'],
      [(n, j) => nix(n, j, ["nix.extraOptions = ''", '  trusted-users = root', "'';"]), 'scoped-users'],
    ],
  },
  'native-eval': {
    vuln: [
      (n, j) => nix(n, j, ["nix.extraOptions = ''", '  allow-unsafe-native-code-during-evaluation = true', "'';"]),
      (n, j) => nix(n, j, [`nix.settings.extra-plugin-files = [ "/opt/${n.tbl}/hook-v${j}.so" ];`]),
      (n, j) => nix(n, j, ['nix.settings = { allow-unsafe-native-code-during-evaluation = true; keep-going = true; };']),
    ],
    safe: [
      [(n, j) => nix(n, j, ['nix.settings = { allow-unsafe-native-code-during-evaluation = false; sandbox = true; };']), 'hardened-setting'],
      [(n, j) => nix(n, j, ['nix.settings.extra-plugin-files = [ ];']), 'empty-list'],
      [(n, j) => nix(n, j, ["nix.extraOptions = ''", '  allow-unsafe-native-code-during-evaluation = false', "'';"]), 'hardened-setting'],
    ],
  },
  'sandbox-trust': {
    vuln: [
      (n, j) => nix(n, j, ['nix.settings = { sandbox = false; cores = 4; };']),
      (n, j) => nix(n, j, ['nix.useSandbox = false;']),
      (n, j) => nix(n, j, ["nix.extraOptions = ''", '  sandbox = false', "'';"]),
    ],
    safe: [
      [(n, j) => nix(n, j, ['nix.useSandbox = true;']), 'hardened-setting'],
      [(n, j) => nix(n, j, ['nix.settings = { sandbox = true; cores = 4; };']), 'hardened-setting'],
      [(n, j) => nix(n, j, ['nix.settings.extra-sandbox-paths = [ "/bin/sh=${pkgs.busybox}/bin/sh" ];']), 'unrelated-setting'],
    ],
  },
  'ssh-access': {
    vuln: [
      (n, j) => nix(n, j, ['services.openssh.enable = true;', 'services.openssh.passwordAuthentication = false;', 'services.openssh.permitRootLogin = "yes";']),
      (n, j) => nix(n, j, ['services.openssh.enable = true;', 'services.openssh.settings.PermitRootLogin = "no";', 'services.openssh.settings.PasswordAuthentication = lib.mkForce true;']),
      (n, j) => nix(n, j, ['services.openssh.enable = true;', 'services.openssh.settings.PermitRootLogin = "no";', 'services.openssh.settings.PasswordAuthentication = false;', 'services.openssh.settings.PermitEmptyPasswords = "yes";']),
    ],
    safe: [
      [(n, j) => nix(n, j, ['services.openssh.enable = true;', 'services.openssh.passwordAuthentication = false;', 'services.openssh.permitRootLogin = "no";']), 'hardened-setting'],
      [(n, j) => nixFull(`with lib;\n{\n  services.openssh.enable = true;\n  services.openssh.settings = { PasswordAuthentication = mkForce false; PermitRootLogin = mkDefault "no"; };\n}`), 'hardened-setting'],
      [(n, j) => nix(n, j, ['services.openssh.enable = false;', 'services.openssh.settings.PermitRootLogin = "yes";']), 'service-disabled'],
    ],
  },
  'service-privilege': {
    vuln: [
      (n, j) => nix(n, j, [`systemd.services.${n.tbl}.serviceConfig = { ExecStart = "\${pkgs.hello}/bin/hello"; Restart = "always"; };`]),
      (n, j) => nix(n, j, [`systemd.services.${n.tbl}.serviceConfig = { ExecStart = "\${pkgs.hello}/bin/hello"; User = lib.mkForce "root"; };`]),
      (n, j) => nix(n, j, [`systemd.services.${n.tbl}.serviceConfig = { ExecStart = "\${pkgs.hello}/bin/hello"; User = "${n.tbl}-svc"; AmbientCapabilities = "CAP_SYS_ADMIN"; };`]),
    ],
    safe: [
      [(n, j) => nix(n, j, [`systemd.services.${n.tbl}.serviceConfig = { ExecStart = "\${pkgs.hello}/bin/hello"; DynamicUser = true; ProtectHome = true; };`]), 'scoped-service'],
      [(n, j) => nix(n, j, [`systemd.services.${n.tbl}.serviceConfig = { ExecStart = "\${pkgs.hello}/bin/hello"; User = "${n.tbl}-svc"; Group = "${n.tbl}-svc"; };`]), 'scoped-service'],
      [(n, j) => nix(n, j, [`systemd.services.${n.tbl}.serviceConfig = { ExecStart = "\${pkgs.hello}/bin/hello"; User = "${n.tbl}-svc"; AmbientCapabilities = [ "CAP_NET_BIND_SERVICE" ]; };`]), 'low-risk-capability'],
    ],
  },
  'firewall-exposure': {
    vuln: [
      (n, j) => nix(n, j, ['networking.firewall.enable = true;', 'networking.firewall.allowedTCPPortRanges = [ everything ];'], '  everything = { from = 1; to = 65535; };\n'),
      (n, j) => nixFull('with lib;\n{\n  virtualisation.docker.enable = true;\n  networking.firewall.enable = true;\n  networking.firewall.allowedTCPPorts = mkForce [ 22 2375 ];\n}'),
      (n, j) => nix(n, j, ['networking.firewall = { enable = false; allowPing = true; };']),
    ],
    safe: [
      [(n, j) => nix(n, j, ['networking.firewall.enable = true;', 'networking.firewall.allowedTCPPortRanges = [ { from = 8000; to = 8010; } ];', 'networking.firewall.allowedUDPPortRanges = [ { from = 60000; to = 60010; } ];']), 'narrow-range'],
      [(n, j) => nix(n, j, ['networking.firewall.enable = true;', 'networking.firewall.allowedTCPPorts = [ 443 ] ++ lib.optionals cfg.enableHttp [ 80 ];']), 'hardened-setting'],
      [(n, j) => nixFull('lib.mkMerge [\n  { networking.firewall.enable = true; }\n  { networking.firewall.interfaces."lo".allowedTCPPortRanges = [ { from = 1024; to = 65535; } ]; }\n]'), 'interface-scoped'],
    ],
  },
  'privilege-escalation-policy': {
    vuln: [
      (n, j) => nix(n, j, ['security.sudo.extraRules = [ { groups = [ "wheel" ]; commands = [ { command = "ALL"; options = [ "NOPASSWD" "SETENV" ]; } ]; } ];']),
      (n, j) => nix(n, j, ['security.doas.enable = true;', 'security.doas.extraRules = [ { groups = [ "wheel" ]; noPass = true; } ];']),
      (n, j) => nix(n, j, ["security.sudo.extraConfig = ''", '  Defaults !authenticate', "'';"]),
    ],
    safe: [
      [(n, j) => nix(n, j, [`security.sudo.extraRules = [ { users = [ "${n.tbl}" ]; commands = [ { command = "/run/current-system/sw/bin/systemctl restart ${n.tbl}.service"; options = [ "NOPASSWD" ]; } ]; } ];`]), 'scoped-command'],
      [(n, j) => nix(n, j, ['security.doas.enable = true;', 'security.doas.extraRules = [ { groups = [ "wheel" ]; persist = true; } ];']), 'hardened-setting'],
      [(n, j) => nix(n, j, ["security.sudo.extraConfig = ''", '  Defaults timestamp_timeout=5', '  Defaults lecture=always', "'';"]), 'hardened-setting'],
    ],
  },
  'tls-secret-runtime': {
    vuln: [
      (n, j) => nix(n, j, ['services.nginx.enable = true;', `services.nginx.virtualHosts."${n.tbl}.example.org".sslCertificateKey = pkgs.writeText "${n.tbl}.key" (builtins.readFile ./${n.tbl}.key);`]),
      (n, j) => nix(n, j, ['services.nginx.enable = true;', `services.nginx.virtualHosts."${n.tbl}.example.org".sslCertificateKey = ./${n.tbl}-key.pem;`]),
      (n, j) => nix(n, j, ['services.postfix.enable = true;', `services.postfix.sslKey = ./${n.tbl}-mail.key;`]),
    ],
    safe: [
      [(n, j) => nix(n, j, ['services.nginx.enable = true;', `services.nginx.virtualHosts."${n.tbl}.example.org".sslCertificateKey = "/var/lib/acme/${n.tbl}.example.org/key.pem";`]), 'runtime-path'],
      [(n, j) => nix(n, j, ['services.nginx.enable = true;', `services.nginx.virtualHosts."${n.tbl}.example.org".sslCertificateKey = config.sops.secrets."${n.tbl}-tls".path;`]), 'runtime-path'],
      [(n, j) => nix(n, j, ['services.nginx.enable = true;', `services.nginx.virtualHosts."${n.tbl}.example.org" = { useACMEHost = "${n.tbl}.example.org"; forceSSL = true; };`]), 'hardened-setting'],
    ],
  },
};
