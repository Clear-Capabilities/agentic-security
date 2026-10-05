// QA-001 UNSEEN shapes, version unseen-v2.
//
// WHY A SECOND SET. unseen-v1 (now templates-shapedev.mjs) was used to change the engine, so it stopped measuring generalisation; v2 was
// written AFTER those fixes, from the vulnerability classes and not from the engine's rules, to answer the same question again.
//
// RULES OF USE (what makes this set worth anything):
//   * Nothing in scanner/src may be tuned against these shapes. They are measured ONCE per promotion (bench/language-support/measure.mjs
//     --split unseen), the result is stored, and a miss is a finding about the engine, not an invitation to fit it. If a shape is used to
//     change the engine, it joins the shape-dev set and a NEW unseen set (v3) must be written.
//   * Each shape has ONE flaw (vulnerable) or none (safe). The v1 set taught us what happens otherwise: a shape that carries a second,
//     real flaw makes a correct extra finding score as a false positive, and a name the code does not tie to its purpose (a cookie called
//     "usersses") makes the label depend on the author's intent, not on the code. Names here say what the value is.
//   * The label is the property the code has, stated by its author; it is not a regex reviewer's verdict.
//   * Nothing here is read by scanner/src.

import { HS_NOUNS, NIX_NOUNS } from './templates.mjs';
import { sha256 } from './lib.mjs';

export const UNSEEN_VERSION = 'unseen-v2';
export { HS_NOUNS as UNSEEN_HS_NOUNS, NIX_NOUNS as UNSEEN_NIX_NOUNS };

const hash64 = (s) => Buffer.from(sha256(s), 'hex').toString('base64');   // a real-looking digest, never the all-A fake-hash placeholder

const hs = (n, j, imports, body) => `module ${n.N}Svc where

${imports.join('\n')}

${body}

endpointPath :: String
endpointPath = "/${n.tbl}/v${j}"
`;

const nix = (n, j, lines) => `{ config, lib, pkgs, ... }:
let
  cfg = config.services.${n.tbl};
in
{
  networking.hostName = "${n.tbl}-v${j}";
${lines.map((l) => `  ${l}`).join('\n')}
}
`;

const SCOTTY = ['import Web.Scotty', 'import Control.Monad.IO.Class (liftIO)', 'import Database.SQLite.Simple', 'import Network.HTTP.Types.Status (status401, status403)', 'import Data.Maybe (isNothing)', 'import Control.Monad (when, unless)'];
const AUTHED = `requireLogin :: ActionM Int
requireLogin = do
  h <- header "Authorization"
  case h of
    Nothing -> status status401 >> finish
    Just _ -> pure 7`;

// ── Haskell ──────────────────────────────────────────────────────────────────
export const HS_UNSEEN = {
  'sql-injection': {
    vuln: [
      (n, j) => hs(n, j, ['import Database.PostgreSQL.Simple', 'import Database.PostgreSQL.Simple.Types (Query (..))', 'import qualified Data.ByteString.Char8 as BC'],
        `lookupBy :: Connection -> String -> IO [Only String]
lookupBy conn who = query_ conn (Query (BC.pack ("SELECT ${n.col} FROM ${n.tbl} WHERE ${n.col} = '" ++ who ++ "'")))`),
      (n, j) => hs(n, j, ['import Database.SQLite.Simple', 'import Data.String (fromString)', 'import Data.List (intercalate)'],
        `search :: Connection -> String -> IO [Only String]
search conn term = query_ conn (fromString (intercalate " " ["SELECT", "${n.col}", "FROM", "${n.tbl}", "WHERE", "${n.col}", "LIKE", "'%" ++ term ++ "%'"]))`),
      (n, j) => hs(n, j, ['import Database.Persist.Sql', 'import qualified Data.Text as T'],
        `purge :: String -> SqlPersistT IO ()
purge who = rawExecute (T.pack ("DELETE FROM ${n.tbl} WHERE ${n.col} = '" ++ who ++ "'")) []`),
    ],
    safe: [
      [(n, j) => hs(n, j, ['import Database.SQLite.Simple'],
        `lookupBy :: Connection -> String -> IO [Only String]
lookupBy conn who = queryNamed conn "SELECT ${n.col} FROM ${n.tbl} WHERE ${n.col} = :who" [":who" := who]`), 'parameterized'],
      [(n, j) => hs(n, j, ['import Database.PostgreSQL.Simple'],
        `record :: Connection -> String -> IO ()
record conn who = do
  _ <- execute conn "INSERT INTO ${n.tbl} (${n.col}) VALUES (?)" (Only who)
  pure ()`), 'parameterized'],
      [(n, j) => hs(n, j, ['import Database.Persist.Sql', 'import qualified Data.Text as T'],
        `purge :: T.Text -> SqlPersistT IO ()
purge who = rawExecute "DELETE FROM ${n.tbl} WHERE ${n.col} = ?" [PersistText who]`), 'parameterized'],
    ],
  },
  'command-injection': {
    vuln: [
      (n, j) => hs(n, j, ['import System.Process', 'import Text.Printf (printf)'],
        `listing :: String -> IO ()
listing dir = callCommand (printf "ls -la %s" dir)`),
      (n, j) => hs(n, j, ['import System.Process'],
        `searchLog :: String -> IO String
searchLog pat = readCreateProcess (shell ("grep " ++ pat ++ " /var/log/${n.tbl}.log")) ""`),
      (n, j) => hs(n, j, ['import System.Process'],
        `announce :: String -> IO ()
announce msg = do
  _ <- spawnCommand ("echo " ++ msg)
  pure ()`),
    ],
    safe: [
      [(n, j) => hs(n, j, ['import System.Process'],
        `listing :: String -> IO ()
listing dir = callProcess "ls" ["-la", "--", dir]`), 'argv-separator'],
      [(n, j) => hs(n, j, ['import System.Process'],
        `searchLog :: String -> IO String
searchLog pat = readProcess "grep" ["-F", "-e", pat, "/var/log/${n.tbl}.log"] ""`), 'argv-separator'],
      [(n, j) => hs(n, j, ['import System.Process'],
        `announce :: String -> IO ()
announce msg = if msg \`elem\` ["start", "stop", "status"] then callCommand ("echo " ++ msg) else pure ()`), 'allowlist'],
    ],
  },
  'path-traversal': {
    vuln: [
      (n, j) => hs(n, j, ['import qualified Data.Text as T', 'import qualified Data.Text.IO as TIO'],
        `load :: T.Text -> IO T.Text
load name = TIO.readFile (T.unpack name)`),
      (n, j) => hs(n, j, ['import System.Directory (copyFile)'],
        `stash :: String -> IO ()
stash name = copyFile name "/srv/${n.tbl}/backup"`),
      (n, j) => hs(n, j, ['import System.Directory (removeFile)'],
        `drop' :: String -> IO ()
drop' name = removeFile ("/srv/${n.tbl}/" ++ name)`),
    ],
    safe: [
      [(n, j) => hs(n, j, ['import qualified Data.ByteString as BS', 'import System.FilePath (takeBaseName)'],
        `load :: String -> IO BS.ByteString
load name = BS.readFile ("/srv/${n.tbl}/" ++ takeBaseName name ++ ".dat")`), 'sanitizer'],
      [(n, j) => hs(n, j, ['import System.Directory (copyFile)', 'import System.FilePath (splitDirectories)', 'import Control.Monad (when)'],
        `stash :: String -> IO ()
stash name = do
  when (".." \`elem\` splitDirectories name) (ioError (userError "bad path"))
  copyFile ("/srv/${n.tbl}/" ++ name) "/srv/${n.tbl}/backup"`), 'guard'],
      [(n, j) => hs(n, j, ['import System.Directory (removeFile)', 'import System.FilePath (takeFileName)'],
        `drop' :: String -> IO ()
drop' name = removeFile ("/srv/${n.tbl}/" ++ takeFileName name)`), 'sanitizer'],
    ],
  },
  ssrf: {
    vuln: [
      (n, j) => hs(n, j, ['import Network.HTTP.Client', 'import Network.HTTP.Client.TLS (tlsManagerSettings)'],
        `fetch :: String -> IO ()
fetch url = do
  mgr <- newManager tlsManagerSettings
  req <- parseRequest url
  _ <- httpLbs req mgr
  pure ()`),
      (n, j) => hs(n, j, ['import qualified Network.Wreq as W', 'import Control.Lens ((&), (.~))'],
        `fetch :: String -> IO ()
fetch url = do
  r <- W.getWith (W.defaults & W.checkResponse .~ Nothing) url
  print (r W.^. W.responseStatus)`),
      (n, j) => hs(n, j, ['import Network.HTTP.Conduit'],
        `ping :: String -> IO ()
ping url = parseUrlThrow url >>= \\req -> newManager tlsManagerSettings >>= httpNoBody req >> pure ()`),
    ],
    safe: [
      [(n, j) => hs(n, j, ['import Network.HTTP.Conduit (simpleHttp)'],
        `fetch :: String -> IO ()
fetch url = if url \`elem\` ["https://status.${n.tbl}.example.com/health", "https://status.${n.tbl}.example.com/ready"] then simpleHttp url >>= print else pure ()`), 'allowlist'],
      [(n, j) => hs(n, j, ['import Network.HTTP.Simple'],
        `fetch :: Int -> IO ()
fetch itemId = do
  req <- parseRequest ("https://api.${n.tbl}.example.com/items/" ++ show itemId)
  resp <- httpBS req
  print (getResponseStatusCode resp)`), 'fixed-host'],
      [(n, j) => hs(n, j, ['import Network.HTTP.Conduit (simpleHttp)', 'import Data.List (isPrefixOf)'],
        `ping :: String -> IO ()
ping url
  | "https://hooks.${n.tbl}.example.com/" \`isPrefixOf\` url = simpleHttp url >>= print
  | otherwise = ioError (userError "host not allowed")`), 'allowlist'],
    ],
  },
  'html-injection': {
    vuln: [
      (n, j) => hs(n, j, ['import Web.Scotty', 'import qualified Data.Text.Lazy as TL'],
        `main :: IO ()
main = scotty 3000 $ get "/hello/:who" $ do
  who <- param "who"
  html (TL.pack ("<h1>Hello " ++ who ++ "</h1>"))`),
      (n, j) => hs(n, j, ['import qualified Text.Blaze.Html as H', 'import Text.Blaze.Html5 (preEscapedToHtml)'],
        `banner :: String -> H.Html
banner msg = preEscapedToHtml msg`),
      (n, j) => hs(n, j, ['import qualified Lucid as L', 'import qualified Data.Text as T'],
        `note :: T.Text -> L.Html ()
note body = L.div_ [] (L.toHtmlRaw body)`),
    ],
    safe: [
      [(n, j) => hs(n, j, ['import Web.Scotty', 'import qualified Data.Text.Lazy as TL'],
        `main :: IO ()
main = scotty 3000 $ get "/hello/:who" $ do
  who <- param "who"
  text (TL.pack ("Hello " ++ who))`), 'plain-text'],
      [(n, j) => hs(n, j, ['import qualified Text.Blaze.Html as H', 'import Text.Blaze.Html5 (toHtml)'],
        `banner :: String -> H.Html
banner msg = H.p (toHtml msg)`), 'escaper'],
      [(n, j) => hs(n, j, ['import qualified Lucid as L', 'import qualified Data.Text as T'],
        `note :: T.Text -> L.Html ()
note body = L.div_ [] (L.toHtml body)`), 'escaper'],
    ],
  },
  'weak-password-hash': {
    vuln: [
      (n, j) => hs(n, j, ['import qualified Crypto.Hash.MD5 as MD5', 'import qualified Data.ByteString.Lazy.Char8 as BL'],
        `storePassword :: String -> BL.ByteString
storePassword password = BL.fromStrict (MD5.hashlazy (BL.pack password))`),
      (n, j) => hs(n, j, ['import qualified Crypto.Hash.SHA256 as SHA256', 'import qualified Data.ByteString.Char8 as BC'],
        `digestPassword :: String -> BC.ByteString
digestPassword password = SHA256.hash (BC.pack password)`),
      (n, j) => hs(n, j, ['import qualified Crypto.Hash.SHA1 as SHA1', 'import qualified Data.ByteString.Char8 as BC'],
        `legacyHash :: String -> String -> BC.ByteString
legacyHash salt pwd = SHA1.hash (BC.pack (salt ++ pwd))`),
    ],
    safe: [
      [(n, j) => hs(n, j, ['import qualified Crypto.KDF.PBKDF2 as PBKDF2', 'import Crypto.Hash.Algorithms (SHA256 (..))', 'import qualified Data.ByteString.Char8 as BC'],
        `storePassword :: BC.ByteString -> String -> BC.ByteString
storePassword salt password = PBKDF2.fastPBKDF2_SHA256 (PBKDF2.Parameters { PBKDF2.iterCounts = 600000, PBKDF2.outputLength = 32 }) (BC.pack password) salt`), 'kdf'],
      [(n, j) => hs(n, j, ['import Crypto.BCrypt', 'import qualified Data.ByteString.Char8 as BC'],
        `digestPassword :: String -> IO (Maybe BC.ByteString)
digestPassword password = hashPasswordUsingPolicy fastBcryptHashingPolicy (BC.pack password)`), 'kdf'],
      [(n, j) => hs(n, j, ['import qualified Crypto.Hash.SHA256 as SHA256', 'import qualified Data.ByteString.Char8 as BC'],
        `checksum :: BC.ByteString -> BC.ByteString
checksum payload = SHA256.hash payload`), 'not-a-password'],
    ],
  },
  'weak-randomness': {
    vuln: [
      (n, j) => hs(n, j, ['import System.Random'],
        `newSessionToken :: IO String
newSessionToken = do
  sessionToken <- fmap (take 24 . randomRs ('a', 'z')) newStdGen
  pure sessionToken`),
      (n, j) => hs(n, j, ['import System.CPUTime (getCPUTime)'],
        `makeNonce :: IO Integer
makeNonce = getCPUTime`),
      (n, j) => hs(n, j, ['import System.Random'],
        `resetCode :: IO Int
resetCode = randomRIO (100000, 999999)`),
    ],
    safe: [
      [(n, j) => hs(n, j, ['import Crypto.Random (getRandomBytes)', 'import qualified Data.ByteString as BS'],
        `newSessionToken :: IO BS.ByteString
newSessionToken = getRandomBytes 24`), 'csprng'],
      [(n, j) => hs(n, j, ['import System.Entropy (getEntropy)', 'import qualified Data.ByteString as BS'],
        `makeNonce :: IO BS.ByteString
makeNonce = getEntropy 12`), 'csprng'],
      [(n, j) => hs(n, j, ['import System.Random'],
        `shuffleSeed :: IO Int
shuffleSeed = randomRIO (1, 6)`), 'not-a-secret'],
    ],
  },
  'resource-limits': {
    vuln: [
      (n, j) => hs(n, j, ['import qualified Data.ByteString.Lazy as BL', 'import System.IO (stdin)'],
        `slurp :: IO BL.ByteString
slurp = BL.hGetContents stdin`),
      (n, j) => hs(n, j, ['import Network.Wai (Request, strictRequestBody)', 'import qualified Data.ByteString.Lazy as BL'],
        `receive :: Request -> IO BL.ByteString
receive req = strictRequestBody req`),
      (n, j) => hs(n, j, ['import qualified Data.Text.IO as TIO', 'import qualified Data.Text as T'],
        `slurpText :: IO T.Text
slurpText = TIO.getContents`),
    ],
    safe: [
      [(n, j) => hs(n, j, ['import qualified Data.ByteString.Lazy as BL', 'import System.IO (stdin)'],
        `slurp :: IO BL.ByteString
slurp = fmap (BL.take 65536) (BL.hGetContents stdin)`), 'bound'],
      [(n, j) => hs(n, j, ['import qualified Data.ByteString as BS', 'import System.IO (stdin)'],
        `receive :: IO BS.ByteString
receive = BS.hGet stdin 4096`), 'bound'],
      [(n, j) => hs(n, j, ['import qualified Data.Text.IO as TIO', 'import qualified Data.Text as T'],
        `slurpText :: IO T.Text
slurpText = fmap (T.take 8192) TIO.getContents`), 'bound'],
    ],
  },
  'parser-safety': {
    vuln: [
      (n, j) => hs(n, j, [],
        `firstWord :: [String] -> String
firstWord ws = head ws`),
      (n, j) => hs(n, j, ['import Data.Maybe (fromJust)'],
        `setting :: String -> [(String, String)] -> String
setting key table = fromJust (lookup key table)`),
      (n, j) => hs(n, j, [],
        `parseCount :: String -> Int
parseCount s = read s`),
    ],
    safe: [
      [(n, j) => hs(n, j, [],
        `firstWord :: [String] -> String
firstWord ws = case ws of
  (w : _) -> w
  [] -> ""`), 'total-parser'],
      [(n, j) => hs(n, j, [],
        `setting :: String -> [(String, String)] -> String
setting key table = maybe "" id (lookup key table)`), 'total-parser'],
      [(n, j) => hs(n, j, ['import Text.Read (readMaybe)', 'import Data.Maybe (fromMaybe)'],
        `parseCount :: String -> Int
parseCount s = fromMaybe 0 (readMaybe s)`), 'total-parser'],
    ],
  },
  'sensitive-logging': {
    vuln: [
      (n, j) => hs(n, j, ['import Control.Monad.Logger', 'import qualified Data.Text as T'],
        `onLogin :: T.Text -> T.Text -> LoggingT IO ()
onLogin user password = logInfoN ("login " <> user <> " password=" <> password)`),
      (n, j) => hs(n, j, ['import Debug.Trace (trace)'],
        `checkSecret :: String -> Bool
checkSecret secret = trace ("secret was " ++ secret) (length secret > 8)`),
      (n, j) => hs(n, j, ['import System.IO'],
        `dumpCredentials :: String -> IO ()
dumpCredentials token = hPrint stderr token`),
    ],
    safe: [
      [(n, j) => hs(n, j, ['import Control.Monad.Logger', 'import qualified Data.Text as T'],
        `onLogin :: T.Text -> T.Text -> LoggingT IO ()
onLogin user _ = logInfoN ("login " <> user)`), 'redaction'],
      [(n, j) => hs(n, j, ['import Debug.Trace (trace)'],
        `checkSecret :: String -> Bool
checkSecret secret = trace ("secret length " ++ show (length secret)) (length secret > 8)`), 'redaction'],
      [(n, j) => hs(n, j, ['import System.IO'],
        `dumpCredentials :: String -> IO ()
dumpCredentials user = hPutStrLn stderr ("lookup for " ++ user)`), 'not-sensitive'],
    ],
  },
  'route-authentication': {
    vuln: [
      (n, j) => hs(n, j, SCOTTY,
        `main :: IO ()
main = scotty 3000 $
  put "/${n.tbl}/:id" $ do
    rid <- param "id"
    body <- param "body"
    conn <- liftIO (open "${n.tbl}.db")
    liftIO (execute conn "UPDATE ${n.tbl} SET ${n.col} = ? WHERE id = ?" (body :: String, rid :: Int))
    text "saved"`),
      (n, j) => hs(n, j, SCOTTY,
        `main :: IO ()
main = scotty 3000 $
  post "/${n.tbl}/import" $ do
    rows <- jsonData
    conn <- liftIO (open "${n.tbl}.db")
    liftIO (mapM_ (\\r -> execute conn "INSERT INTO ${n.tbl} (${n.col}) VALUES (?)" (Only (r :: String))) rows)
    text "imported"`),
      (n, j) => hs(n, j, SCOTTY,
        `main :: IO ()
main = scotty 3000 $
  delete "/${n.tbl}/all" $ do
    conn <- liftIO (open "${n.tbl}.db")
    liftIO (execute_ conn "DELETE FROM ${n.tbl}")
    text "cleared"`),
    ],
    safe: [
      [(n, j) => hs(n, j, SCOTTY,
        `main :: IO ()
main = scotty 3000 $
  put "/${n.tbl}/:id" $ do
    h <- header "Authorization"
    when (isNothing h) (status status401 >> finish)
    rid <- param "id"
    body <- param "body"
    conn <- liftIO (open "${n.tbl}.db")
    liftIO (execute conn "UPDATE ${n.tbl} SET ${n.col} = ? WHERE id = ?" (body :: String, rid :: Int))
    text "saved"`), 'auth-guard'],
      [(n, j) => hs(n, j, SCOTTY,
        `${AUTHED}

main :: IO ()
main = scotty 3000 $
  post "/${n.tbl}/import" $ do
    _ <- requireLogin
    rows <- jsonData
    conn <- liftIO (open "${n.tbl}.db")
    liftIO (mapM_ (\\r -> execute conn "INSERT INTO ${n.tbl} (${n.col}) VALUES (?)" (Only (r :: String))) rows)
    text "imported"`), 'auth-guard'],
      [(n, j) => hs(n, j, SCOTTY,
        `main :: IO ()
main = scotty 3000 $
  delete "/${n.tbl}/all" $ do
    mk <- header "X-Api-Key"
    case mk of
      Nothing -> status status403 >> finish
      Just _ -> do
        conn <- liftIO (open "${n.tbl}.db")
        liftIO (execute_ conn "DELETE FROM ${n.tbl}")
        text "cleared"`), 'auth-guard'],
    ],
  },
  'object-authorization': {
    vuln: [
      (n, j) => hs(n, j, SCOTTY,
        `${AUTHED}

main :: IO ()
main = scotty 3000 $
  get "/${n.tbl}/:id" $ do
    _ <- requireLogin
    oid <- param "id"
    conn <- liftIO (open "${n.tbl}.db")
    rows <- liftIO (query conn "SELECT ${n.col} FROM ${n.tbl} WHERE id = ?" (Only (oid :: Int)))
    json (rows :: [Only String])`),
      (n, j) => hs(n, j, SCOTTY,
        `${AUTHED}

main :: IO ()
main = scotty 3000 $
  put "/${n.tbl}/:id" $ do
    _ <- requireLogin
    oid <- param "id"
    body <- param "body"
    conn <- liftIO (open "${n.tbl}.db")
    liftIO (execute conn "UPDATE ${n.tbl} SET ${n.col} = ? WHERE id = ?" (body :: String, oid :: Int))
    text "saved"`),
      (n, j) => hs(n, j, SCOTTY,
        `${AUTHED}

main :: IO ()
main = scotty 3000 $
  delete "/${n.tbl}/:id" $ do
    _ <- requireLogin
    oid <- param "id"
    conn <- liftIO (open "${n.tbl}.db")
    liftIO (execute conn "DELETE FROM ${n.tbl} WHERE id = ?" (Only (oid :: Int)))
    text "gone"`),
    ],
    safe: [
      [(n, j) => hs(n, j, SCOTTY,
        `${AUTHED}

main :: IO ()
main = scotty 3000 $
  get "/${n.tbl}/:id" $ do
    uid <- requireLogin
    oid <- param "id"
    conn <- liftIO (open "${n.tbl}.db")
    rows <- liftIO (query conn "SELECT ${n.col} FROM ${n.tbl} WHERE id = ? AND owner_id = ?" (oid :: Int, uid))
    json (rows :: [Only String])`), 'owner-scope'],
      [(n, j) => hs(n, j, SCOTTY,
        `${AUTHED}

main :: IO ()
main = scotty 3000 $
  put "/${n.tbl}/:id" $ do
    uid <- requireLogin
    oid <- param "id"
    body <- param "body"
    conn <- liftIO (open "${n.tbl}.db")
    liftIO (execute conn "UPDATE ${n.tbl} SET ${n.col} = ? WHERE id = ? AND owner_id = ?" (body :: String, oid :: Int, uid))
    text "saved"`), 'owner-scope'],
      [(n, j) => hs(n, j, SCOTTY,
        `${AUTHED}

main :: IO ()
main = scotty 3000 $
  delete "/${n.tbl}/:id" $ do
    uid <- requireLogin
    oid <- param "id"
    conn <- liftIO (open "${n.tbl}.db")
    liftIO (execute conn "DELETE FROM ${n.tbl} WHERE id = ? AND owner_id = ?" (oid :: Int, uid))
    text "gone"`), 'owner-scope'],
    ],
  },
  'session-cookie': {
    vuln: [
      (n, j) => hs(n, j, ['import Web.Cookie'],
        `sessionCookie :: SetCookie
sessionCookie = defaultSetCookie { setCookieName = "sessionid" }`),
      (n, j) => hs(n, j, ['import Web.Cookie'],
        `authTokenCookie :: SetCookie
authTokenCookie = defaultSetCookie { setCookieName = "auth_token", setCookieSecure = False, setCookieHttpOnly = True }`),
      (n, j) => hs(n, j, ['import Web.Cookie'],
        `loginCookie :: SetCookie
loginCookie = defaultSetCookie { setCookieName = "login_token", setCookieSecure = True, setCookieHttpOnly = False }`),
    ],
    safe: [
      [(n, j) => hs(n, j, ['import Web.Cookie'],
        `sessionCookie :: SetCookie
sessionCookie = defaultSetCookie { setCookieName = "sessionid", setCookieHttpOnly = True, setCookieSecure = True, setCookieSameSite = Just sameSiteLax }`), 'hardened-attrs'],
      [(n, j) => hs(n, j, ['import Web.Cookie'],
        `authTokenCookie :: SetCookie
authTokenCookie = defaultSetCookie { setCookieSecure = True, setCookieName = "auth_token", setCookieHttpOnly = True }`), 'hardened-attrs'],
      [(n, j) => hs(n, j, ['import Web.Cookie'],
        `themeCookie :: SetCookie
themeCookie = defaultSetCookie { setCookieName = "theme_preference" }`), 'not-a-session'],
    ],
  },
};

// ── Nix ──────────────────────────────────────────────────────────────────────
export const NIX_UNSEEN = {
  'script-interpolation': {
    vuln: [
      (n, j) => nix(n, j, [`systemd.services.${n.tbl}-fetch.script = "\${pkgs.curl}/bin/curl -fsS \${cfg.url} -o /var/lib/${n.tbl}/data";`]),
      (n, j) => nix(n, j, [`systemd.services.${n.tbl}-run.serviceConfig.ExecStart = pkgs.writeShellScript "${n.tbl}-run" "echo \${cfg.message}";`]),
      (n, j) => nix(n, j, [`environment.etc."${n.tbl}-cleanup.sh".text = "#!/bin/sh\\nrm -rf \${cfg.stateDir}";`]),
    ],
    safe: [
      [(n, j) => nix(n, j, [`systemd.services.${n.tbl}-fetch.script = "\${pkgs.curl}/bin/curl -fsS \${lib.escapeShellArg cfg.url} -o /var/lib/${n.tbl}/data";`]), 'escaper'],
      [(n, j) => nix(n, j, [`systemd.services.${n.tbl}-run.serviceConfig.ExecStart = pkgs.writeShellScript "${n.tbl}-run" "echo \${lib.escapeShellArg cfg.message}";`]), 'escaper'],
      [(n, j) => nix(n, j, [`systemd.services.${n.tbl}-run.environment.TARGET_DIR = cfg.stateDir;`, `systemd.services.${n.tbl}-run.script = ''rm -rf "$TARGET_DIR"'';`]), 'env-passing'],
    ],
  },
  'secret-in-store': {
    vuln: [
      (n, j) => nix(n, j, [`services.${n.tbl}.settings.adminPassword = "correct-horse-${n.tbl}-v${j}";`]),
      (n, j) => nix(n, j, [`users.users.${n.tbl}-svc.password = "correct-horse-${n.tbl}-v${j}";`]),
      (n, j) => nix(n, j, [`environment.variables.${n.tbl.toUpperCase()}_API_KEY = "correct-horse-${n.tbl}-v${j}";`]),
    ],
    safe: [
      [(n, j) => nix(n, j, [`services.${n.tbl}.settings.adminPasswordFile = "/run/secrets/${n.tbl}-admin";`]), 'runtime-path'],
      [(n, j) => nix(n, j, [`users.users.${n.tbl}-svc.hashedPasswordFile = "/run/secrets/${n.tbl}-svc.hash";`]), 'runtime-path'],
      [(n, j) => nix(n, j, [`systemd.services.${n.tbl}.serviceConfig.EnvironmentFile = "/run/secrets/${n.tbl}.env";`]), 'runtime-path'],
    ],
  },
  'unpinned-source': {
    vuln: [
      (n, j) => nix(n, j, [`environment.etc."${n.tbl}.src".source = pkgs.fetchFromGitHub { owner = "example"; repo = "${n.tbl}"; rev = "main"; };`]),
      (n, j) => nix(n, j, [`environment.etc."${n.tbl}.json".source = builtins.fetchurl "https://example.org/${n.tbl}-v${j}.json";`]),
      (n, j) => nix(n, j, [`environment.etc."${n.tbl}.conf".source = pkgs.fetchurl { url = "https://example.org/${n.tbl}-v${j}.conf"; };`]),
    ],
    safe: [
      [(n, j) => nix(n, j, [`environment.etc."${n.tbl}.src".source = pkgs.fetchFromGitHub { owner = "example"; repo = "${n.tbl}"; rev = "0123456789abcdef0123456789abcdef01234567"; hash = "sha256-${hash64(n.tbl + "gh" + j)}"; };`]), 'content-pin'],
      [(n, j) => nix(n, j, [`environment.etc."${n.tbl}.json".source = builtins.fetchurl { url = "https://example.org/${n.tbl}-v${j}.json"; sha256 = "sha256-${hash64(n.tbl + "json" + j)}"; };`]), 'content-pin'],
      [(n, j) => nix(n, j, [`environment.etc."${n.tbl}.conf".source = pkgs.fetchurl { url = "https://example.org/${n.tbl}-v${j}.conf"; hash = "sha256-${hash64(n.tbl + "conf" + j)}"; };`]), 'content-pin'],
    ],
  },
  'binary-cache-trust': {
    vuln: [
      (n, j) => nix(n, j, ['nix.settings.substituters = lib.mkForce [ "http://mirror.example.org/cache" ];']),
      (n, j) => nix(n, j, ['nix.settings.require-sigs = false;']),
      (n, j) => nix(n, j, ['nix.settings."require-sigs" = false;']),
    ],
    safe: [
      [(n, j) => nix(n, j, ['nix.settings.substituters = lib.mkForce [ "https://mirror.example.org/cache" ];']), 'tls-cache'],
      [(n, j) => nix(n, j, ['nix.settings.require-sigs = true;']), 'hardened-setting'],
      [(n, j) => nix(n, j, ['nix.settings."require-sigs" = true;']), 'hardened-setting'],
    ],
  },
  'trusted-users': {
    vuln: [
      (n, j) => nix(n, j, ['nix.settings.trusted-users = [ "root" "@wheel" ];']),
      (n, j) => nix(n, j, ['nix.settings.trusted-users = [ "@users" ];']),
      (n, j) => nix(n, j, ['nix.settings = { trusted-users = [ "*" ]; };']),
    ],
    safe: [
      [(n, j) => nix(n, j, ['nix.settings.trusted-users = [ "root" ];']), 'scoped-users'],
      [(n, j) => nix(n, j, ['nix.settings.trusted-users = lib.mkDefault [ "root" ];']), 'scoped-users'],
      [(n, j) => nix(n, j, ['nix.settings = { trusted-users = [ ]; };']), 'scoped-users'],
    ],
  },
  'native-eval': {
    vuln: [
      (n, j) => nix(n, j, ['nix.settings."allow-unsafe-native-code-during-evaluation" = true;']),
      (n, j) => nix(n, j, ["nix.extraOptions = ''", `  plugin-files = /opt/${n.tbl}/v${j}.so`, "'';"]),
      (n, j) => nix(n, j, [`nix.settings.plugin-files = [ "/opt/${n.tbl}/hook-v${j}.so" ];`]),
    ],
    safe: [
      [(n, j) => nix(n, j, ['nix.settings."allow-unsafe-native-code-during-evaluation" = false;']), 'hardened-setting'],
      [(n, j) => nix(n, j, ["nix.extraOptions = ''", '  keep-going = true', "'';"]), 'unrelated-setting'],
      [(n, j) => nix(n, j, ['nix.settings.plugin-files = [ ];']), 'empty-list'],
    ],
  },
  'sandbox-trust': {
    vuln: [
      (n, j) => nix(n, j, ['nix.settings.sandbox = lib.mkForce false;']),
      (n, j) => nix(n, j, ["nix.extraOptions = ''", '  sandbox = relaxed', "'';"]),
      (n, j) => nix(n, j, ['nix.settings."sandbox" = false;']),
    ],
    safe: [
      [(n, j) => nix(n, j, ['nix.settings.sandbox = lib.mkForce true;']), 'hardened-setting'],
      [(n, j) => nix(n, j, ["nix.extraOptions = ''", '  sandbox = true', "'';"]), 'hardened-setting'],
      [(n, j) => nix(n, j, ['nix.settings."sandbox" = true;']), 'hardened-setting'],
    ],
  },
  'ssh-access': {
    vuln: [
      (n, j) => nix(n, j, ['services.openssh.enable = true;', 'services.openssh.settings.PasswordAuthentication = false;', 'services.openssh.settings.PermitRootLogin = "yes";']),
      (n, j) => nix(n, j, ['services.openssh.enable = true;', 'services.openssh.settings.PermitRootLogin = "no";', 'services.openssh.settings.PasswordAuthentication = true;']),
      (n, j) => nix(n, j, ['services.openssh = {', '  enable = true;', '  settings = { PermitRootLogin = "no"; PasswordAuthentication = false; PermitEmptyPasswords = true; };', '};']),
    ],
    safe: [
      [(n, j) => nix(n, j, ['services.openssh.enable = true;', 'services.openssh.settings.PasswordAuthentication = false;', 'services.openssh.settings.PermitRootLogin = "no";']), 'hardened-setting'],
      [(n, j) => nix(n, j, ['services.openssh = {', '  enable = true;', '  settings = { PermitRootLogin = "prohibit-password"; PasswordAuthentication = false; };', '};']), 'hardened-setting'],
      [(n, j) => nix(n, j, ['services.openssh.enable = true;', 'services.openssh.settings = { PasswordAuthentication = false; PermitRootLogin = "no"; PermitEmptyPasswords = false; };']), 'hardened-setting'],
    ],
  },
  'service-privilege': {
    vuln: [
      (n, j) => nix(n, j, [`systemd.services.${n.tbl}.serviceConfig = { ExecStart = "\${pkgs.hello}/bin/hello"; User = "root"; NoNewPrivileges = true; };`]),
      (n, j) => nix(n, j, [`systemd.services.${n.tbl}.serviceConfig = { ExecStart = "\${pkgs.hello}/bin/hello"; User = "${n.tbl}-svc"; NoNewPrivileges = true; CapabilityBoundingSet = [ "CAP_SYS_ADMIN" ]; };`]),
      (n, j) => nix(n, j, [`systemd.services.${n.tbl}.serviceConfig = { ExecStart = "\${pkgs.hello}/bin/hello"; User = "${n.tbl}-svc"; NoNewPrivileges = false; };`]),
    ],
    safe: [
      [(n, j) => nix(n, j, [`systemd.services.${n.tbl}.serviceConfig = { ExecStart = "\${pkgs.hello}/bin/hello"; DynamicUser = true; NoNewPrivileges = true; };`]), 'scoped-service'],
      [(n, j) => nix(n, j, [`systemd.services.${n.tbl}.serviceConfig = { ExecStart = "\${pkgs.hello}/bin/hello"; User = "${n.tbl}-svc"; NoNewPrivileges = true; CapabilityBoundingSet = [ "" ]; };`]), 'scoped-service'],
      [(n, j) => nix(n, j, [`systemd.services.${n.tbl}.serviceConfig = { ExecStart = "\${pkgs.hello}/bin/hello"; User = "${n.tbl}-svc"; NoNewPrivileges = true; ProtectSystem = "strict"; };`]), 'scoped-service'],
    ],
  },
  'firewall-exposure': {
    vuln: [
      (n, j) => nix(n, j, ['networking.firewall.enable = lib.mkForce false;']),
      (n, j) => nix(n, j, ['networking.firewall.enable = true;', 'networking.firewall.allowedTCPPortRanges = [ { from = 1; to = 65535; } ];']),
      (n, j) => nix(n, j, ['networking.firewall.enable = true;', 'services.mysql.enable = true;', 'networking.firewall.allowedTCPPorts = [ 3306 ];']),
    ],
    safe: [
      [(n, j) => nix(n, j, ['networking.firewall.enable = lib.mkForce true;']), 'hardened-setting'],
      [(n, j) => nix(n, j, ['networking.firewall.enable = true;', 'networking.firewall.allowedTCPPorts = [ 80 443 ];']), 'hardened-setting'],
      [(n, j) => nix(n, j, ['networking.firewall.enable = true;', 'services.mysql.enable = true;', 'networking.firewall.interfaces."lo".allowedTCPPorts = [ 3306 ];']), 'hardened-setting'],
    ],
  },
  'privilege-escalation-policy': {
    vuln: [
      (n, j) => nix(n, j, ['security.sudo.extraConfig = "%wheel ALL=(ALL) NOPASSWD: ALL";']),
      (n, j) => nix(n, j, ['security.doas.enable = true;', 'security.doas.extraConfig = "permit nopass :wheel";']),
      (n, j) => nix(n, j, ['security.sudo.wheelNeedsPassword = lib.mkForce false;']),
    ],
    safe: [
      [(n, j) => nix(n, j, ['security.sudo.extraConfig = "Defaults timestamp_timeout=5";']), 'hardened-setting'],
      [(n, j) => nix(n, j, ['security.doas.enable = true;', 'security.doas.extraConfig = "permit persist :wheel";']), 'hardened-setting'],
      [(n, j) => nix(n, j, ['security.sudo.wheelNeedsPassword = true;']), 'hardened-setting'],
    ],
  },
  'tls-secret-runtime': {
    vuln: [
      (n, j) => nix(n, j, ['services.nginx.enable = true;', `services.nginx.virtualHosts."${n.tbl}.example.org".sslCertificateKey = builtins.toFile "${n.tbl}-v${j}.key" "placeholder";`]),
      (n, j) => nix(n, j, ['services.nginx.enable = true;', `services.nginx.virtualHosts."${n.tbl}.example.org".sslCertificateKey = "\${./${n.tbl}-v${j}.pem}";`]),
      (n, j) => nix(n, j, ['services.nginx.enable = true;', `services.nginx.virtualHosts."${n.tbl}.example.org".forceSSL = false;`]),
    ],
    safe: [
      [(n, j) => nix(n, j, ['services.nginx.enable = true;', `services.nginx.virtualHosts."${n.tbl}.example.org".sslCertificateKey = "/run/credentials/nginx.service/${n.tbl}-v${j}.key";`]), 'runtime-path'],
      [(n, j) => nix(n, j, ['services.nginx.enable = true;', `services.nginx.virtualHosts."${n.tbl}.example.org".forceSSL = true;`]), 'hardened-setting'],
      [(n, j) => nix(n, j, ['services.nginx.enable = true;', `services.nginx.virtualHosts."${n.tbl}.example.org" = { enableACME = true; forceSSL = true; };`]), 'hardened-setting'],
    ],
  },
};
