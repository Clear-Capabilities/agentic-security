// QA-001 UNSEEN shapes (premortem remediation: generalisation beyond the template family).
//
// The development, validation and holdout splits all draw on the SAME two vulnerable and two safe code shapes per family (templates.mjs):
// they differ only in the nouns. A score on them measures robustness to renaming, not generalisation. These are three further
// vulnerable and three further safe shapes per family, written as different code forms (other APIs, other idioms, a helper in a `where`
// clause, a point-free style, attribute-set versus dotted options, the legacy spelling of an option).
//
// RULES OF USE (they are what makes this split worth anything):
//   * Nothing in scanner/src may be tuned against these shapes. They are measured ONCE per promotion (bench/language-support/measure.mjs
//     --split unseen), the result is stored, and a failure is a finding about the engine, not an invitation to fit it. If a shape is
//     used to change the engine it stops being unseen and a NEW set must be written (bump UNSEEN_VERSION).
//   * They are labelled by their author with the reason stated in the comment above each family, not by the regex reviewer that checks
//     the other splits (that reviewer only knows the old shapes). The label is the property the code has, not what the engine says.
//   * Nothing here is read by scanner/src.

import { HS_NOUNS, NIX_NOUNS } from './templates.mjs';
import { sha256 } from './lib.mjs';

const hash64 = (s) => Buffer.from(sha256(s), 'hex').toString('base64');   // a real-looking digest, never the all-A fake-hash placeholder
export const UNSEEN_VERSION = 'unseen-v1';
export { HS_NOUNS as UNSEEN_HS_NOUNS, NIX_NOUNS as UNSEEN_NIX_NOUNS };

const hs = (n, j, imports, body) => `module ${n.N}Svc where

${imports.join('\n')}

${body}

endpointPath :: String
endpointPath = "/${n.tbl}/u${j}"
`;

const nix = (n, j, lines, extraLet = '') => `{ config, lib, pkgs, ... }:
let
  cfg = config.services.${n.tbl};${extraLet}
in
{
  networking.hostName = "${n.tbl}-u${j}";
${lines.map((l) => `  ${l}`).join('\n')}
}
`;

const SCOTTY = ['import Web.Scotty', 'import Control.Monad.IO.Class (liftIO)', 'import Database.SQLite.Simple', 'import Network.HTTP.Types.Status (status401, status403)'];

// ── Haskell ──────────────────────────────────────────────────────────────────
export const HS_UNSEEN = {
  // vulnerable: the query text is built from the caller's value by formatting, a where-bound helper, or list concatenation, then run.
  // safe: the value is a bound parameter (single, two-parameter, batch) and the statement text is a literal.
  'sql-injection': {
    vuln: [
      (n, j) => hs(n, j, ['import Database.SQLite.Simple', 'import Data.String (fromString)', 'import Text.Printf (printf)'],
        `findBy :: Connection -> String -> IO [Only String]
findBy conn val = query_ conn (fromString (printf "SELECT ${n.col} FROM ${n.tbl} WHERE ${n.col} = '%s'" val))`),
      (n, j) => hs(n, j, ['import Database.SQLite.Simple', 'import Data.String (fromString)'],
        `countIn :: Connection -> String -> IO [Only Int]
countIn conn table = query_ conn q
  where
    q = fromString ("SELECT count(*) FROM " ++ table)`),
      (n, j) => hs(n, j, ['import Database.SQLite.Simple', 'import Data.String (fromString)'],
        `wipe :: Connection -> String -> IO ()
wipe conn who = execute_ conn . fromString $ concat ["DELETE FROM ${n.tbl} WHERE ${n.col} = '", who, "'"]`),
    ],
    safe: [
      [(n, j) => hs(n, j, ['import Database.SQLite.Simple'],
        `findBy :: Connection -> String -> IO [Only String]
findBy conn val = query conn "SELECT ${n.col} FROM ${n.tbl} WHERE ${n.col} = ?" (Only val)`), 'parameterized'],
      [(n, j) => hs(n, j, ['import Database.SQLite.Simple'],
        `page :: Connection -> String -> Int -> IO [Only String]
page conn val lim = query conn "SELECT ${n.col} FROM ${n.tbl} WHERE ${n.col} = ? LIMIT ?" (val, lim)`), 'parameterized'],
      [(n, j) => hs(n, j, ['import Database.SQLite.Simple'],
        `wipeAll :: Connection -> [String] -> IO ()
wipeAll conn whos = executeMany conn "DELETE FROM ${n.tbl} WHERE ${n.col} = ?" (map Only whos)`), 'parameterized'],
    ],
  },
  'command-injection': {
    vuln: [
      (n, j) => hs(n, j, ['import System.Process'],
        `probe :: String -> IO ()
probe host = system ("ping -c1 " ++ host) >> pure ()`),
      (n, j) => hs(n, j, ['import System.Process'],
        `squash :: String -> IO String
squash cmd = readProcess "sh" ["-c", unwords ["gzip", "-c", cmd]] ""`),
      (n, j) => hs(n, j, ['import System.Process'],
        `archive :: String -> IO ()
archive file = callCommand $ unwords ["tar", "czf", "${n.tbl}.tgz", file]`),
    ],
    safe: [
      [(n, j) => hs(n, j, ['import System.Process'],
        `probe :: String -> IO ()
probe host = callProcess "ping" ["-c1", "--", host]`), 'argv-separator'],
      [(n, j) => hs(n, j, ['import System.Process'],
        `squash :: String -> IO String
squash file = readProcess "gzip" ["-c", "--", file] ""`), 'argv-separator'],
      [(n, j) => hs(n, j, ['import System.Process', 'import Data.Maybe (fromMaybe)'],
        `tools :: [(String, String)]
tools = [("zip", "zip"), ("tar", "tar")]

archive :: String -> IO ()
archive choice = case lookup choice tools of
  Just prog -> callProcess prog ["--version"]
  Nothing -> pure ()`), 'guard'],
    ],
  },
  'path-traversal': {
    vuln: [
      (n, j) => hs(n, j, ['import System.IO'],
        `store :: String -> String -> IO ()
store name body = writeFile ("/srv/${n.tbl}/" ++ name) body`),
      (n, j) => hs(n, j, ['import System.IO', 'import System.FilePath (joinPath)'],
        `slurp :: String -> IO String
slurp name = withFile (joinPath ["/srv/${n.tbl}", name]) ReadMode hGetContents'`),
      (n, j) => hs(n, j, ['import System.Directory', 'import System.FilePath'],
        `readIfThere :: String -> IO (Maybe String)
readIfThere name = do
  let p = "/srv/${n.tbl}" </> name
  ok <- doesFileExist p
  if ok then Just <$> readFile p else pure Nothing`),
    ],
    safe: [
      [(n, j) => hs(n, j, ['import System.IO', 'import System.FilePath (takeFileName)'],
        `store :: String -> String -> IO ()
store name body = writeFile ("/srv/${n.tbl}/" ++ takeFileName name) body`), 'sanitizer'],
      [(n, j) => hs(n, j, ['import System.IO', 'import System.FilePath (takeFileName, joinPath)'],
        `slurp :: String -> IO String
slurp name = withFile (joinPath ["/srv/${n.tbl}", takeFileName name]) ReadMode hGetContents'`), 'sanitizer'],
      [(n, j) => hs(n, j, ['import System.Directory', 'import System.FilePath'],
        `readIfThere :: String -> IO (Maybe String)
readIfThere name
  | ".." \`elem\` splitDirectories name = pure Nothing
  | otherwise = do
      let p = "/srv/${n.tbl}" </> name
      ok <- doesFileExist p
      if ok then Just <$> readFile p else pure Nothing`), 'guard'],
    ],
  },
  ssrf: {
    vuln: [
      (n, j) => hs(n, j, ['import Network.HTTP.Conduit (simpleHttp)'],
        `grab :: String -> IO ()
grab url = simpleHttp url >>= print`),
      (n, j) => hs(n, j, ['import Network.HTTP.Simple'],
        `ping :: String -> IO ()
ping url = do
  req <- parseRequest url
  resp <- httpBS req
  print (getResponseStatusCode resp)`),
      (n, j) => hs(n, j, ['import qualified Network.Wreq as W'],
        `pull :: String -> IO ()
pull url = W.get url >>= \\r -> print (r W.^. W.responseStatus)`),
    ],
    safe: [
      [(n, j) => hs(n, j, ['import Network.HTTP.Conduit (simpleHttp)', 'import Data.List (isPrefixOf)'],
        `grab :: String -> IO ()
grab url
  | "https://assets.${n.tbl}.example.com/" \`isPrefixOf\` url = simpleHttp url >>= print
  | otherwise = pure ()`), 'allowlist'],
      [(n, j) => hs(n, j, ['import Network.HTTP.Simple', 'import Network.URI'],
        `ping :: String -> IO ()
ping url = case parseURI url >>= uriAuthority of
  Just a | uriRegName a \`elem\` ["status.${n.tbl}.example.com"] -> do
    req <- parseRequest url
    resp <- httpBS req
    print (getResponseStatusCode resp)
  _ -> pure ()`), 'allowlist'],
      [(n, j) => hs(n, j, ['import qualified Network.Wreq as W'],
        `pull :: String -> IO ()
pull item = W.get ("https://api.${n.tbl}.example.com/items/" ++ show (length item)) >>= \\r -> print (r W.^. W.responseStatus)`), 'allowlist'],
    ],
  },
  'html-injection': {
    vuln: [
      (n, j) => hs(n, j, ['import qualified Lucid as L'],
        `badge :: String -> L.Html ()
badge name = L.p_ (L.toHtmlRaw ("hello " ++ name))`),
      (n, j) => hs(n, j, ['import Text.Blaze.Html (preEscapedToHtml)', 'import Text.Blaze.Html.Renderer.String (renderHtml)'],
        `render :: String -> String
render note = renderHtml (preEscapedToHtml (note ++ "<hr>"))`),
      (n, j) => hs(n, j, [],
        `snippet :: String -> String
snippet who = "<div class=\\"${n.tbl}\\">" <> who <> "</div>"

emit :: String -> IO ()
emit = putStrLn . snippet`),
    ],
    safe: [
      [(n, j) => hs(n, j, ['import qualified Lucid as L'],
        `badge :: String -> L.Html ()
badge name = L.p_ (L.toHtml ("hello " ++ name))`), 'escaper'],
      [(n, j) => hs(n, j, ['import Text.Blaze.Html (toHtml)', 'import Text.Blaze.Html.Renderer.String (renderHtml)'],
        `render :: String -> String
render note = renderHtml (toHtml (note ++ " - ${n.tbl}"))`), 'escaper'],
      [(n, j) => hs(n, j, ['import qualified Text.Blaze.Html5 as H'],
        `snippet :: String -> H.Html
snippet who = H.div (H.toHtml who)`), 'escaper'],
    ],
  },
  'weak-password-hash': {
    vuln: [
      (n, j) => hs(n, j, ['import qualified Crypto.Hash.MD5 as MD5', 'import qualified Data.ByteString.Char8 as BC'],
        `store :: String -> BC.ByteString
store pw = MD5.hash (BC.pack pw)`),
      (n, j) => hs(n, j, ['import qualified Crypto.Hash.SHA1 as SHA1', 'import qualified Data.ByteString.Char8 as BC'],
        `digest :: String -> BC.ByteString
digest pw = SHA1.hash (BC.pack (pw ++ "${n.tbl}"))`),
      (n, j) => hs(n, j, ['import Crypto.Hash (hashWith, SHA1 (..))', 'import qualified Data.ByteString.Char8 as BC'],
        `fingerprint :: String -> String
fingerprint pw = show (hashWith SHA1 (BC.pack pw))`),
    ],
    safe: [
      [(n, j) => hs(n, j, ['import Crypto.BCrypt', 'import qualified Data.ByteString.Char8 as BC'],
        `store :: String -> IO (Maybe BC.ByteString)
store pw = hashPasswordUsingPolicy slowerBcryptHashingPolicy (BC.pack pw)`), 'kdf'],
      [(n, j) => hs(n, j, ['import Crypto.Scrypt', 'import qualified Data.ByteString.Char8 as BC'],
        `digest :: String -> IO EncryptedPass
digest pw = encryptPassIO' defaultParams (Pass (BC.pack pw))`), 'kdf'],
      [(n, j) => hs(n, j, ['import qualified Crypto.KDF.Argon2 as Argon2', 'import qualified Data.ByteString.Char8 as BC'],
        `fingerprint :: BC.ByteString -> String -> Either String BC.ByteString
fingerprint salt pw = Argon2.hash Argon2.defaultOptions (BC.pack pw) salt 32`), 'kdf'],
    ],
  },
  'weak-randomness': {
    vuln: [
      (n, j) => hs(n, j, ['import System.Random'],
        `pin :: IO Int
pin = randomRIO (100000, 999999)`),
      (n, j) => hs(n, j, ['import System.Random'],
        `secret :: IO String
secret = getStdGen >>= \\g -> pure (take 12 (randomRs ('a', 'z') g))`),
      (n, j) => hs(n, j, ['import System.Random', 'import Data.Word (Word64)'],
        `session :: IO Word64
session = do
  g <- newStdGen
  pure (fst (random g))`),
    ],
    safe: [
      [(n, j) => hs(n, j, ['import System.Entropy (getEntropy)', 'import qualified Data.ByteString as BS'],
        `pin :: IO BS.ByteString
pin = getEntropy 8`), 'csprng'],
      [(n, j) => hs(n, j, ['import Crypto.Random (getRandomBytes)', 'import qualified Data.ByteString as BS'],
        `secret :: IO BS.ByteString
secret = getRandomBytes 24`), 'csprng'],
      [(n, j) => hs(n, j, ['import Crypto.Random', 'import qualified Data.ByteString as BS'],
        `session :: IO BS.ByteString
session = do
  drg <- getSystemDRG
  pure (fst (randomBytesGenerate 16 drg))`), 'csprng'],
    ],
  },
  'resource-limits': {
    vuln: [
      (n, j) => hs(n, j, ['import System.IO'],
        `slurpAll :: IO String
slurpAll = hGetContents stdin`),
      (n, j) => hs(n, j, ['import qualified Data.ByteString as BS', 'import System.IO (stdin)'],
        `slurpBytes :: IO BS.ByteString
slurpBytes = BS.hGetContents stdin`),
      (n, j) => hs(n, j, ['import Control.Monad (replicateM)'],
        `readLines :: String -> IO [String]
readLines count = replicateM (read count) getLine`),
    ],
    safe: [
      [(n, j) => hs(n, j, ['import qualified Data.ByteString as BS', 'import System.IO (stdin)'],
        `slurpAll :: IO BS.ByteString
slurpAll = BS.hGet stdin 65536`), 'bound'],
      [(n, j) => hs(n, j, [],
        `slurpBytes :: IO String
slurpBytes = fmap (take 4096) getContents`), 'bound'],
      [(n, j) => hs(n, j, ['import Control.Monad (replicateM)'],
        `readLines :: String -> IO [String]
readLines count = replicateM (min 100 (read count)) getLine`), 'bound'],
    ],
  },
  'parser-safety': {
    vuln: [
      (n, j) => hs(n, j, ['import Data.Maybe (fromJust)'],
        `lookupKey :: String -> [(String, String)] -> String
lookupKey k env = fromJust (lookup k env)`),
      (n, j) => hs(n, j, [],
        `toPort :: String -> Int
toPort raw = read raw + 1`),
      (n, j) => hs(n, j, [],
        `firstArg :: [String] -> String
firstArg args = args !! 0`),
    ],
    safe: [
      [(n, j) => hs(n, j, [],
        `lookupKey :: String -> [(String, String)] -> String
lookupKey k env = maybe "" id (lookup k env)`), 'total-parser'],
      [(n, j) => hs(n, j, ['import Text.Read (readMaybe)'],
        `toPort :: String -> Maybe Int
toPort raw = fmap (+ 1) (readMaybe raw)`), 'total-parser'],
      [(n, j) => hs(n, j, ['import Data.Maybe (listToMaybe)'],
        `firstArg :: [String] -> Maybe String
firstArg = listToMaybe`), 'total-parser'],
    ],
  },
  'sensitive-logging': {
    vuln: [
      (n, j) => hs(n, j, ['import System.IO'],
        `trace :: String -> IO ()
trace tok = hPutStrLn stderr ("token=" ++ tok)`),
      (n, j) => hs(n, j, [],
        `dump :: String -> String -> IO ()
dump user password = print (user, password)`),
      (n, j) => hs(n, j, [],
        `journal :: String -> IO ()
journal secret = appendFile "${n.tbl}-journal.log" ("secret: " ++ secret ++ "\\n")`),
    ],
    safe: [
      [(n, j) => hs(n, j, ['import System.IO'],
        `trace :: String -> IO ()
trace tok = hPutStrLn stderr ("token length=" ++ show (length tok))`), 'redaction'],
      [(n, j) => hs(n, j, [],
        `dump :: String -> String -> IO ()
dump user _ = print (user, "[redacted]" :: String)`), 'redaction'],
      [(n, j) => hs(n, j, [],
        `redact :: String -> String
redact = const "***"

journal :: String -> IO ()
journal secret = appendFile "${n.tbl}-journal.log" ("secret: " ++ redact secret ++ "\\n")`), 'redaction'],
    ],
  },
  // vulnerable: a state-changing route with no credential check. safe: the same route behind a credential check written three ways.
  'route-authentication': {
    vuln: [
      (n, j) => hs(n, j, SCOTTY,
        `main :: IO ()
main = scotty 3000 $ do
  delete "/${n.tbl}/:id" $ do
    rid <- param "id"
    conn <- liftIO (open "${n.tbl}.db")
    liftIO (execute conn "DELETE FROM ${n.tbl} WHERE id = ?" (Only (rid :: Int)))
    text "gone"`),
      (n, j) => hs(n, j, SCOTTY,
        `main :: IO ()
main = scotty 3000 $ do
  post "/${n.tbl}/note" $ do
    body <- param "body"
    liftIO (appendFile "${n.tbl}.log" (body :: String))
    text "ok"`),
      (n, j) => hs(n, j, SCOTTY,
        `main :: IO ()
main = scotty 3000 $ do
  patch "/${n.tbl}/flag" $ do
    conn <- liftIO (open "${n.tbl}.db")
    liftIO (execute_ conn "UPDATE ${n.tbl}_settings SET enabled = 0")
    text "off"`),
    ],
    safe: [
      [(n, j) => hs(n, j, SCOTTY,
        `requireAuth :: ActionM ()
requireAuth = do
  h <- header "Authorization"
  case h of
    Nothing -> status status401 >> finish
    Just _ -> pure ()

main :: IO ()
main = scotty 3000 $ do
  delete "/${n.tbl}/:id" $ do
    requireAuth
    rid <- param "id"
    conn <- liftIO (open "${n.tbl}.db")
    liftIO (execute conn "DELETE FROM ${n.tbl} WHERE id = ?" (Only (rid :: Int)))
    text "gone"`), 'auth-guard'],
      [(n, j) => hs(n, j, [...SCOTTY, 'import Control.Monad (when)'],
        `requireToken :: ActionM ()
requireToken = do
  k <- header "Authorization"
  when (k == Nothing) (status status401 >> finish)

main :: IO ()
main = scotty 3000 $ do
  post "/${n.tbl}/note" $ do
    requireToken
    body <- param "body"
    liftIO (appendFile "${n.tbl}.log" (body :: String))
    text "ok"`), 'auth-guard'],
      [(n, j) => hs(n, j, SCOTTY,
        `guarded :: ActionM () -> ActionM ()
guarded act = do
  h <- header "Authorization"
  case h of
    Nothing -> status status401 >> finish
    Just _ -> act

main :: IO ()
main = scotty 3000 $ do
  patch "/${n.tbl}/flag" $ guarded $ do
    conn <- liftIO (open "${n.tbl}.db")
    liftIO (execute_ conn "UPDATE ${n.tbl}_settings SET enabled = 0")
    text "off"`), 'auth-guard'],
    ],
  },
  // vulnerable: authenticated, but the object is chosen by a client-supplied id with no ownership condition.
  'object-authorization': {
    vuln: [
      (n, j) => hs(n, j, SCOTTY,
        `requireAuth :: ActionM ()
requireAuth = do
  h <- header "Authorization"
  case h of
    Nothing -> status status401 >> finish
    Just _ -> pure ()

main :: IO ()
main = scotty 3000 $ do
  delete "/${n.tbl}/:id" $ do
    requireAuth
    oid <- param "id"
    conn <- liftIO (open "${n.tbl}.db")
    liftIO (execute conn "DELETE FROM ${n.tbl} WHERE id = ?" (Only (oid :: Int)))
    text "gone"`),
      (n, j) => hs(n, j, SCOTTY,
        `requireAuth :: ActionM ()
requireAuth = do
  h <- header "Authorization"
  case h of
    Nothing -> status status401 >> finish
    Just _ -> pure ()

main :: IO ()
main = scotty 3000 $ do
  get "/${n.tbl}/:id/export" $ do
    requireAuth
    oid <- param "id"
    conn <- liftIO (open "${n.tbl}.db")
    rows <- liftIO (query conn "SELECT ${n.col} FROM ${n.tbl} WHERE id = ?" (Only (oid :: Int)))
    json (rows :: [Only String])`),
      (n, j) => hs(n, j, SCOTTY,
        `requireAuth :: ActionM ()
requireAuth = do
  h <- header "Authorization"
  case h of
    Nothing -> status status401 >> finish
    Just _ -> pure ()

main :: IO ()
main = scotty 3000 $ do
  post "/${n.tbl}/:id/archive" $ do
    requireAuth
    oid <- param "id"
    conn <- liftIO (open "${n.tbl}.db")
    liftIO (execute conn "UPDATE ${n.tbl} SET archived = 1 WHERE id = ?" (Only (oid :: Int)))
    text "archived"`),
    ],
    safe: [
      [(n, j) => hs(n, j, SCOTTY,
        `requireUser :: ActionM Int
requireUser = do
  h <- header "Authorization"
  case h of
    Nothing -> status status401 >> finish
    Just _ -> pure 1

main :: IO ()
main = scotty 3000 $ do
  delete "/${n.tbl}/:id" $ do
    uid <- requireUser
    oid <- param "id"
    conn <- liftIO (open "${n.tbl}.db")
    liftIO (execute conn "DELETE FROM ${n.tbl} WHERE id = ? AND owner = ?" (oid :: Int, uid))
    text "gone"`), 'owner-scope'],
      [(n, j) => hs(n, j, SCOTTY,
        `requireUser :: ActionM Int
requireUser = do
  h <- header "Authorization"
  case h of
    Nothing -> status status401 >> finish
    Just _ -> pure 1

main :: IO ()
main = scotty 3000 $ do
  get "/${n.tbl}/:id/export" $ do
    uid <- requireUser
    oid <- param "id"
    conn <- liftIO (open "${n.tbl}.db")
    rows <- liftIO (query conn "SELECT ${n.col} FROM ${n.tbl} WHERE id = ? AND owner = ?" (oid :: Int, uid))
    json (rows :: [Only String])`), 'owner-scope'],
      [(n, j) => hs(n, j, SCOTTY,
        `requireUser :: ActionM Int
requireUser = do
  h <- header "Authorization"
  case h of
    Nothing -> status status401 >> finish
    Just _ -> pure 1

main :: IO ()
main = scotty 3000 $ do
  post "/${n.tbl}/:id/archive" $ do
    uid <- requireUser
    oid <- param "id"
    conn <- liftIO (open "${n.tbl}.db")
    liftIO (execute conn "UPDATE ${n.tbl} SET archived = 1 WHERE id = ? AND owner = ?" (oid :: Int, uid))
    text "archived"`), 'owner-scope'],
    ],
  },
  'session-cookie': {
    vuln: [
      (n, j) => hs(n, j, ['import Web.Cookie'],
        `cookie :: SetCookie
cookie = defaultSetCookie { setCookieName = "${n.tbl}sid", setCookieHttpOnly = False }`),
      (n, j) => hs(n, j, ['import Web.Cookie'],
        `cookie :: SetCookie
cookie = defaultSetCookie { setCookieName = "${n.tbl}tok", setCookieSameSite = Just sameSiteNone }`),
      (n, j) => hs(n, j, ['import Web.Cookie'],
        `cookie :: SetCookie
cookie = defaultSetCookie
  { setCookieName = "${n.tbl}ses"
  , setCookiePath = Just "/"
  }`),
    ],
    safe: [
      [(n, j) => hs(n, j, ['import Web.Cookie'],
        `cookie :: SetCookie
cookie = defaultSetCookie
  { setCookieName = "${n.tbl}sid"
  , setCookieHttpOnly = True
  , setCookieSecure = True
  , setCookieSameSite = Just sameSiteStrict
  }`), 'hardened-attrs'],
      [(n, j) => hs(n, j, ['import Web.Cookie'],
        `cookie :: SetCookie
cookie = defaultSetCookie { setCookieName = "${n.tbl}tok", setCookieSecure = True, setCookieHttpOnly = True, setCookieSameSite = Just sameSiteLax }`), 'hardened-attrs'],
      [(n, j) => hs(n, j, ['import Web.Cookie'],
        `cookie :: SetCookie
cookie = defaultSetCookie { setCookiePath = Just "/", setCookieHttpOnly = True, setCookieName = "${n.tbl}ses", setCookieSecure = True, setCookieSameSite = Just sameSiteStrict }`), 'hardened-attrs'],
    ],
  },
};

// ── Nix ──────────────────────────────────────────────────────────────────────
export const NIX_UNSEEN = {
  // vulnerable: a module option value reaches a shell command by interpolation into a script body (preStart, script, activation text).
  // safe: the value is quoted with escapeShellArg(s) or reaches the process only through the environment.
  'script-interpolation': {
    vuln: [
      (n, j) => nix(n, j, [`systemd.services.${n.tbl}-clean.preStart = ''rm -rf \${cfg.workDir}'';`]),
      (n, j) => nix(n, j, [`systemd.services.${n.tbl}-sync.script = ''\${pkgs.coreutils}/bin/cp \${cfg.source} /var/lib/${n.tbl}'';`]),
      (n, j) => nix(n, j, [`system.activationScripts.${n.tbl}.text = "chown \${cfg.owner} /var/lib/${n.tbl}";`]),
    ],
    safe: [
      [(n, j) => nix(n, j, [`systemd.services.${n.tbl}-clean.preStart = ''rm -rf \${lib.escapeShellArg cfg.workDir}'';`]), 'escaper'],
      [(n, j) => nix(n, j, [`systemd.services.${n.tbl}-sync.script = ''\${pkgs.coreutils}/bin/cp \${lib.escapeShellArg cfg.source} /var/lib/${n.tbl}'';`]), 'escaper'],
      [(n, j) => nix(n, j, [`system.activationScripts.${n.tbl}.text = "chown \${lib.escapeShellArgs [ cfg.owner ]} /var/lib/${n.tbl}";`]), 'escaper'],
    ],
  },
  'secret-in-store': {
    vuln: [
      (n, j) => nix(n, j, [`services.${n.tbl}.settings.password = "example-placeholder-${n.tbl}-u${j}";`]),
      (n, j) => nix(n, j, [`networking.wireless.networks."${n.tbl}-net".psk = "example-placeholder-${n.tbl}-u${j}";`]),
      (n, j) => nix(n, j, [`services.${n.tbl}.apiToken = "example-placeholder-${n.tbl}-u${j}";`]),
    ],
    safe: [
      [(n, j) => nix(n, j, [`services.${n.tbl}.settings.passwordFile = "/run/secrets/${n.tbl}-u${j}";`]), 'runtime-path'],
      [(n, j) => nix(n, j, [`networking.wireless.networks."${n.tbl}-net".pskRaw = "ext:${n.tbl}_psk";`, `networking.wireless.environmentFile = "/run/secrets/wireless-u${j}.env";`]), 'runtime-path'],
      [(n, j) => nix(n, j, [`services.${n.tbl}.apiTokenFile = "/run/credentials/${n.tbl}-u${j}.token";`]), 'runtime-path'],
    ],
  },
  'unpinned-source': {
    vuln: [
      (n, j) => nix(n, j, [`environment.etc."${n.tbl}.tar".source = builtins.fetchTarball "https://example.org/${n.tbl}-u${j}.tar.gz";`]),
      (n, j) => nix(n, j, [`environment.etc."${n.tbl}.git".source = builtins.fetchGit { url = "https://example.org/${n.tbl}.git"; ref = "master"; };`]),
      (n, j) => nix(n, j, [`environment.etc."${n.tbl}.zip".source = pkgs.fetchzip { url = "https://example.org/${n.tbl}-u${j}.zip"; };`]),
    ],
    safe: [
      [(n, j) => nix(n, j, [`environment.etc."${n.tbl}.tar".source = builtins.fetchTarball { url = "https://example.org/${n.tbl}-u${j}.tar.gz"; sha256 = "sha256-${hash64(n.tbl + "tar" + j)}"; };`]), 'content-pin'],
      [(n, j) => nix(n, j, [`environment.etc."${n.tbl}.git".source = pkgs.fetchgit { url = "https://example.org/${n.tbl}.git"; rev = "0123456789abcdef0123456789abcdef01234567"; hash = "sha256-${hash64(n.tbl + "git" + j)}"; };`]), 'content-pin'],
      [(n, j) => nix(n, j, [`environment.etc."${n.tbl}.zip".source = pkgs.fetchzip { url = "https://example.org/${n.tbl}-u${j}.zip"; hash = "sha256-${hash64(n.tbl + "zip" + j)}"; };`]), 'content-pin'],
    ],
  },
  'binary-cache-trust': {
    vuln: [
      (n, j) => nix(n, j, ['nix.settings.substituters = [ "https://cache.nixos.org" "http://cache.internal.example.org" ];']),
      (n, j) => nix(n, j, ['nix.extraOptions = "require-sigs = false";']),
      (n, j) => nix(n, j, ['nix.settings = { require-sigs = false; };']),
    ],
    safe: [
      [(n, j) => nix(n, j, ['nix.settings.substituters = [ "https://cache.nixos.org" "https://cache.internal.example.org" ];']), 'tls-cache'],
      [(n, j) => nix(n, j, ['nix.settings.require-sigs = true;']), 'hardened-setting'],
      [(n, j) => nix(n, j, ['nix.settings = { require-sigs = lib.mkForce true; };']), 'mkForce'],
    ],
  },
  'trusted-users': {
    vuln: [
      (n, j) => nix(n, j, ['nix.settings.trusted-users = [ "@wheel" ];']),
      (n, j) => nix(n, j, ['nix.settings.trusted-users = [ "*" ];']),
      (n, j) => nix(n, j, ['nix.extraOptions = "trusted-users = root *";']),
    ],
    safe: [
      [(n, j) => nix(n, j, ['nix.settings.trusted-users = [ "root" ];']), 'scoped-users'],
      [(n, j) => nix(n, j, ['nix.settings.trusted-users = [ ];']), 'scoped-users'],
      [(n, j) => nix(n, j, ['nix.settings = { trusted-users = lib.mkForce [ "root" ]; };']), 'mkForce'],
    ],
  },
  'native-eval': {
    vuln: [
      (n, j) => nix(n, j, ['nix.extraOptions = "allow-unsafe-native-code-during-evaluation = true";']),
      (n, j) => nix(n, j, [`nix.settings.plugin-files = [ "/opt/${n.tbl}/u${j}.so" ];`]),
      (n, j) => nix(n, j, ['nix.settings = { allow-unsafe-native-code-during-evaluation = true; };']),
    ],
    safe: [
      [(n, j) => nix(n, j, ['nix.extraOptions = "allow-unsafe-native-code-during-evaluation = false";']), 'hardened-setting'],
      [(n, j) => nix(n, j, ['nix.settings.plugin-files = [ ];']), 'empty-list'],
      [(n, j) => nix(n, j, ['nix.settings = { allow-unsafe-native-code-during-evaluation = lib.mkForce false; };']), 'mkForce'],
    ],
  },
  'sandbox-trust': {
    vuln: [
      (n, j) => nix(n, j, ['nix.settings.sandbox = "relaxed";']),
      (n, j) => nix(n, j, ['nix.extraOptions = "sandbox = false";']),
      (n, j) => nix(n, j, ['nix.settings = { sandbox = false; };']),
    ],
    safe: [
      [(n, j) => nix(n, j, ['nix.settings.sandbox = true;']), 'hardened-setting'],
      [(n, j) => nix(n, j, ['nix.extraOptions = "sandbox = true";']), 'hardened-setting'],
      [(n, j) => nix(n, j, ['nix.settings = { sandbox = lib.mkForce true; };']), 'mkForce'],
    ],
  },
  'ssh-access': {
    vuln: [
      (n, j) => nix(n, j, ['services.openssh = { enable = true; settings = { PermitRootLogin = "yes"; }; };']),
      (n, j) => nix(n, j, ['services.openssh.enable = true;', 'services.openssh.settings.PermitEmptyPasswords = true;']),
      (n, j) => nix(n, j, ['services.openssh = {', '  enable = true;', '  settings.PasswordAuthentication = true;', '};']),
    ],
    safe: [
      [(n, j) => nix(n, j, ['services.openssh = { enable = true; settings = { PermitRootLogin = "no"; PasswordAuthentication = false; }; };']), 'hardened-setting'],
      [(n, j) => nix(n, j, ['services.openssh.enable = true;', 'services.openssh.settings.PermitEmptyPasswords = false;', 'services.openssh.settings.PasswordAuthentication = false;']), 'hardened-setting'],
      [(n, j) => nix(n, j, ['services.openssh = {', '  enable = true;', '  settings.PasswordAuthentication = lib.mkForce false;', '};']), 'mkForce'],
    ],
  },
  'service-privilege': {
    vuln: [
      (n, j) => nix(n, j, [`systemd.services.${n.tbl} = { wantedBy = [ "multi-user.target" ]; serviceConfig = { ExecStart = "\${pkgs.hello}/bin/hello"; User = "root"; }; };`]),
      (n, j) => nix(n, j, [`systemd.services.${n.tbl}.serviceConfig.ExecStart = "\${pkgs.hello}/bin/hello";`, `systemd.services.${n.tbl}.serviceConfig.AmbientCapabilities = [ "CAP_SYS_ADMIN" ];`]),
      (n, j) => nix(n, j, [`systemd.services.${n.tbl}.serviceConfig.ExecStart = "\${pkgs.hello}/bin/hello";`, `systemd.services.${n.tbl}.serviceConfig.NoNewPrivileges = false;`]),
    ],
    safe: [
      [(n, j) => nix(n, j, [`systemd.services.${n.tbl} = { wantedBy = [ "multi-user.target" ]; serviceConfig = { ExecStart = "\${pkgs.hello}/bin/hello"; DynamicUser = true; }; };`]), 'scoped-service'],
      [(n, j) => nix(n, j, [`systemd.services.${n.tbl}.serviceConfig.ExecStart = "\${pkgs.hello}/bin/hello";`, `systemd.services.${n.tbl}.serviceConfig.User = "${n.tbl}-svc";`, `systemd.services.${n.tbl}.serviceConfig.CapabilityBoundingSet = [ "" ];`]), 'scoped-service'],
      [(n, j) => nix(n, j, [`systemd.services.${n.tbl}.serviceConfig.ExecStart = "\${pkgs.hello}/bin/hello";`, `systemd.services.${n.tbl}.serviceConfig.NoNewPrivileges = true;`, `systemd.services.${n.tbl}.serviceConfig.DynamicUser = true;`]), 'scoped-service'],
    ],
  },
  'firewall-exposure': {
    vuln: [
      (n, j) => nix(n, j, ['networking.firewall = { enable = false; };']),
      (n, j) => nix(n, j, ['services.postgresql.enable = true;', 'services.postgresql.authentication = "host all all 0.0.0.0/0 trust";']),
      (n, j) => nix(n, j, ['services.postgresql.enable = true;', 'services.postgresql.settings.listen_addresses = "0.0.0.0";']),
    ],
    safe: [
      [(n, j) => nix(n, j, ['networking.firewall = { enable = true; allowedTCPPorts = [ 443 ]; };']), 'hardened-setting'],
      [(n, j) => nix(n, j, ['services.postgresql.enable = true;', 'services.postgresql.authentication = "local all all peer";']), 'hardened-setting'],
      [(n, j) => nix(n, j, ['services.postgresql.enable = true;', 'services.postgresql.settings.listen_addresses = "127.0.0.1";']), 'hardened-setting'],
    ],
  },
  'privilege-escalation-policy': {
    vuln: [
      (n, j) => nix(n, j, ['security.sudo = { wheelNeedsPassword = false; };']),
      (n, j) => nix(n, j, ['security.sudo.extraRules = [ { users = [ "' + 'ops" ]; commands = [ { command = "ALL"; options = [ "NOPASSWD" ]; } ]; } ];']),
      (n, j) => nix(n, j, ['security.doas.enable = true;', 'security.doas.extraRules = [ { groups = [ "wheel" ]; noPass = true; } ];']),
    ],
    safe: [
      [(n, j) => nix(n, j, ['security.sudo = { wheelNeedsPassword = true; };']), 'hardened-setting'],
      [(n, j) => nix(n, j, ['security.sudo.extraRules = [ { users = [ "ops" ]; commands = [ { command = "/run/current-system/sw/bin/systemctl restart ' + n.tbl + '"; } ]; } ];']), 'scoped-command'],
      [(n, j) => nix(n, j, ['security.doas.enable = true;', 'security.doas.extraRules = [ { groups = [ "wheel" ]; command = "/run/current-system/sw/bin/switch-to-configuration"; } ];']), 'scoped-command'],
    ],
  },
  'tls-secret-runtime': {
    vuln: [
      (n, j) => nix(n, j, ['services.nginx.enable = true;', `services.nginx.virtualHosts."${n.tbl}.example.org".sslCertificateKey = pkgs.writeText "${n.tbl}-u${j}.key" "placeholder";`]),
      (n, j) => nix(n, j, ['services.nginx.enable = true;', `services.nginx.virtualHosts."${n.tbl}.example.org" = { forceSSL = false; enableACME = false; };`]),
      (n, j) => nix(n, j, ['services.nginx.enable = true;', `services.nginx.virtualHosts."${n.tbl}.example.org".sslCertificateKey = ./${n.tbl}-u${j}.pem;`]),
    ],
    safe: [
      [(n, j) => nix(n, j, ['services.nginx.enable = true;', `services.nginx.virtualHosts."${n.tbl}.example.org".sslCertificateKey = "/run/credentials/${n.tbl}-u${j}.key";`]), 'runtime-path'],
      [(n, j) => nix(n, j, ['services.nginx.enable = true;', `services.nginx.virtualHosts."${n.tbl}.example.org" = { forceSSL = true; enableACME = true; };`]), 'hardened-setting'],
      [(n, j) => nix(n, j, ['services.nginx.enable = true;', `services.nginx.virtualHosts."${n.tbl}.example.org".sslCertificateKey = "/run/secrets/${n.tbl}-u${j}.pem";`]), 'runtime-path'],
    ],
  },
};
