// QA-001 controlled fixtures: per-family source templates for both ecosystems.
//
// Each family has two vulnerable shapes and two safe shapes. Shape "A" of the
// vulnerable and safe label are a minimal edit of each other (that edit is the
// semantics-changing mutation). Shape "B" uses a different API surface.
// `near` tags the safe shapes that are deliberate near misses.
//
// Nothing here is read by scanner/src.

import { sha256 } from './lib.mjs';

export const HS_NOUNS = [
  { N: 'Users', tbl: 'users', col: 'email' },
  { N: 'Orders', tbl: 'orders', col: 'ref' },
  { N: 'Invoices', tbl: 'invoices', col: 'number' },
  { N: 'Tickets', tbl: 'tickets', col: 'title' },
  { N: 'Devices', tbl: 'devices', col: 'serial' },
  { N: 'Spare', tbl: 'spares', col: 'code' },
];
export const NIX_NOUNS = [
  { N: 'crm', tbl: 'crm', port: 8081 },
  { N: 'billing', tbl: 'billing', port: 8082 },
  { N: 'wiki', tbl: 'wiki', port: 8083 },
  { N: 'mailer', tbl: 'mailer', port: 8084 },
  { N: 'tracker', tbl: 'tracker', port: 8085 },
  { N: 'spare', tbl: 'spare', port: 8086 },
];

const hs = (n, j, imports, body) => `module ${n.N}Svc where

${imports.join('\n')}

${body}

endpointPath :: String
endpointPath = "/${n.tbl}/v${j}"
`;

const nix = (n, j, lines, extraLet = '') => `{ config, lib, pkgs, ... }:
let
  appName = "${n.N}${j}";
  appPort = ${n.port + j * 100};${extraLet}
in
{
  systemd.services.\${appName}.description = "${n.N} service ${j}";
  networking.hostName = appName;
${lines.map((l) => `  ${l}`).join('\n')}
}
`;

const hash64 = (s) => Buffer.from(sha256(s), 'hex').toString('base64');

// ── Haskell ──────────────────────────────────────────────────────────────────
export const HS = {
  'sql-injection': {
    vuln: [
      (n, j) => hs(n, j, ['import Database.SQLite.Simple', 'import Data.String (fromString)'],
        `handleLookup :: Connection -> String -> IO [Only String]
handleLookup conn val = query_ conn (fromString ("SELECT ${n.col} FROM ${n.tbl} WHERE ${n.col} = '" ++ val ++ "'"))`),
      (n, j) => hs(n, j, ['import Database.SQLite.Simple', 'import Data.String (fromString)'],
        `handleRemove :: Connection -> String -> IO ()
handleRemove conn ident = execute_ conn (fromString ("DELETE FROM ${n.tbl} WHERE id = " ++ ident))`),
    ],
    safe: [
      [(n, j) => hs(n, j, ['import Database.SQLite.Simple', 'import Data.String (fromString)'],
        `handleLookup :: Connection -> String -> IO [Only String]
handleLookup conn val = query conn "SELECT ${n.col} FROM ${n.tbl} WHERE ${n.col} = ?" (Only val)`), 'parameterized'],
      [(n, j) => hs(n, j, ['import Database.SQLite.Simple', 'import Data.String (fromString)', 'import Data.Char (isDigit)'],
        `handleRemove :: Connection -> String -> IO ()
handleRemove conn ident =
  if all isDigit ident
    then execute_ conn (fromString ("DELETE FROM ${n.tbl} WHERE id = " ++ ident))
    else pure ()`), 'guard'],
    ],
  },
  'command-injection': {
    vuln: [
      (n, j) => hs(n, j, ['import System.Process'],
        `handleConvert :: String -> IO ()
handleConvert name = callCommand ("convert " ++ name ++ " ${n.tbl}.png")`),
      (n, j) => hs(n, j, ['import System.Process'],
        `handleUnpack :: String -> IO ()
handleUnpack name = callProcess "sh" ["-c", "tar xf " ++ name ++ " -C /srv/${n.tbl}"]`),
    ],
    safe: [
      [(n, j) => hs(n, j, ['import System.Process'],
        `handleConvert :: String -> IO ()
handleConvert name = callProcess "convert" ["--", name, "${n.tbl}.png"]`), 'argv-separator'],
      [(n, j) => hs(n, j, ['import System.Process', 'import Data.Char (isAlphaNum)'],
        `handleUnpack :: String -> IO ()
handleUnpack name =
  if all isAlphaNum name
    then callCommand ("tar xf " ++ name ++ " -C /srv/${n.tbl}")
    else pure ()`), 'guard'],
    ],
  },
  'path-traversal': {
    vuln: [
      (n, j) => hs(n, j, ['import System.IO'],
        `handleDownload :: String -> IO String
handleDownload name = readFile ("/srv/${n.tbl}/" ++ name)`),
      (n, j) => hs(n, j, ['import System.Directory', 'import System.FilePath'],
        `handlePurge :: String -> IO ()
handlePurge name = removeFile ("/srv/${n.tbl}" </> name)`),
    ],
    safe: [
      [(n, j) => hs(n, j, ['import System.IO', 'import System.FilePath (takeFileName)'],
        `handleDownload :: String -> IO String
handleDownload name = readFile ("/srv/${n.tbl}/" ++ takeFileName name)`), 'sanitizer'],
      [(n, j) => hs(n, j, ['import System.Directory', 'import System.FilePath'],
        `handlePurge :: String -> IO ()
handlePurge name =
  if ".." \`elem\` splitDirectories name
    then pure ()
    else removeFile ("/srv/${n.tbl}" </> name)`), 'guard'],
    ],
  },
  ssrf: {
    vuln: [
      (n, j) => hs(n, j, ['import Network.HTTP.Client'],
        `handleFetch :: String -> IO ()
handleFetch target = do
  req <- parseRequest target
  mgr <- newManager defaultManagerSettings
  resp <- httpLbs req mgr
  print (responseStatus resp)`),
      (n, j) => hs(n, j, ['import Network.HTTP.Client'],
        `handleProbe :: String -> IO ()
handleProbe target = do
  req <- parseUrlThrow target
  mgr <- newManager defaultManagerSettings
  body <- httpLbs req mgr
  print (responseBody body)`),
    ],
    safe: [
      [(n, j) => hs(n, j, ['import Network.HTTP.Client', 'import Data.List (isPrefixOf)'],
        `handleFetch :: String -> IO ()
handleFetch target =
  if "https://api.${n.tbl}.example.com/" \`isPrefixOf\` target
    then do
      req <- parseRequest target
      mgr <- newManager defaultManagerSettings
      resp <- httpLbs req mgr
      print (responseStatus resp)
    else pure ()`), 'allowlist'],
      [(n, j) => hs(n, j, ['import Network.HTTP.Client'],
        `allowedHosts :: [String]
allowedHosts = ["https://hooks.${n.tbl}.example.com/ping"]

handleProbe :: String -> IO ()
handleProbe target =
  if target \`elem\` allowedHosts
    then do
      req <- parseUrlThrow target
      mgr <- newManager defaultManagerSettings
      body <- httpLbs req mgr
      print (responseBody body)
    else pure ()`), 'allowlist'],
    ],
  },
  'html-injection': {
    vuln: [
      (n, j) => hs(n, j, ['import qualified Text.Blaze.Html5 as H', 'import Text.Blaze.Html (preEscapedToHtml)'],
        `handlePage :: String -> H.Html
handlePage name = H.h1 (preEscapedToHtml ("hello " ++ name))`),
      (n, j) => hs(n, j, [],
        `handleBanner :: String -> IO ()
handleBanner url = putStrLn ("<a href='" ++ url ++ "'>${n.tbl}</a>")`),
    ],
    safe: [
      [(n, j) => hs(n, j, ['import qualified Text.Blaze.Html5 as H'],
        `handlePage :: String -> H.Html
handlePage name = H.h1 (H.toHtml ("hello " ++ name))`), 'escaper'],
      [(n, j) => hs(n, j, ['import qualified Text.Blaze.Html5 as H', 'import qualified Text.Blaze.Html5.Attributes as A'],
        `handleBanner :: String -> H.Html
handleBanner url = H.a H.! A.href (H.toValue url) $ H.toHtml "${n.tbl}"`), 'escaper'],
    ],
  },
  'weak-password-hash': {
    vuln: [
      (n, j) => hs(n, j, ['import Crypto.Hash', 'import qualified Data.ByteString.Char8 as BC'],
        `handleStore :: String -> String
handleStore pw = show (hash (BC.pack pw) :: Digest MD5)`),
      (n, j) => hs(n, j, ['import Crypto.Hash', 'import qualified Data.ByteString.Char8 as BC'],
        `handleDigest :: String -> String
handleDigest pw = show (hash (BC.pack (pw ++ "${n.tbl}")) :: Digest SHA1)`),
    ],
    safe: [
      [(n, j) => hs(n, j, ['import qualified Crypto.KDF.Argon2 as Argon2', 'import qualified Data.ByteString.Char8 as BC'],
        `handleStore :: BC.ByteString -> String -> Either String BC.ByteString
handleStore salt pw = Argon2.hash Argon2.defaultOptions (BC.pack pw) salt 32`), 'kdf'],
      [(n, j) => hs(n, j, ['import Crypto.KDF.PBKDF2', 'import qualified Data.ByteString.Char8 as BC'],
        `handleDigest :: BC.ByteString -> String -> BC.ByteString
handleDigest salt pw = fastPBKDF2_SHA256 (Parameters 310000 32) (BC.pack pw) salt`), 'kdf'],
    ],
  },
  'weak-randomness': {
    vuln: [
      (n, j) => hs(n, j, ['import System.Random'],
        `handleToken :: Int -> String
handleToken seed = show (fst (randomR (100000, 999999 :: Int) (mkStdGen seed)))`),
      (n, j) => hs(n, j, ['import Data.Time.Clock.POSIX'],
        `handleNonce :: IO String
handleNonce = fmap show getPOSIXTime`),
    ],
    safe: [
      [(n, j) => hs(n, j, ['import Crypto.Random (getRandomBytes)', 'import qualified Data.ByteString as BS'],
        `handleToken :: IO BS.ByteString
handleToken = getRandomBytes 16`), 'csprng'],
      [(n, j) => hs(n, j, ['import Crypto.Random', 'import qualified Data.ByteString as BS'],
        `handleNonce :: IO BS.ByteString
handleNonce = do
  drg <- getSystemDRG
  pure (fst (randomBytesGenerate 32 drg))`), 'csprng'],
    ],
  },
  'resource-limits': {
    vuln: [
      (n, j) => hs(n, j, ['import qualified Data.ByteString.Lazy as BL'],
        `handleUpload :: IO BL.ByteString
handleUpload = BL.getContents`),
      (n, j) => hs(n, j, [],
        `handleAllocate :: String -> String
handleAllocate raw = replicate (read raw :: Int) 'x'`),
    ],
    safe: [
      [(n, j) => hs(n, j, ['import qualified Data.ByteString.Lazy as BL'],
        `handleUpload :: IO BL.ByteString
handleUpload = fmap (BL.take 65536) BL.getContents`), 'bound'],
      [(n, j) => hs(n, j, [],
        `handleAllocate :: String -> String
handleAllocate raw = replicate (min 4096 (read raw :: Int)) 'x'`), 'bound'],
    ],
  },
  'parser-safety': {
    vuln: [
      (n, j) => hs(n, j, [],
        `handleParse :: String -> IO ()
handleParse raw = print (read raw :: Int)`),
      (n, j) => hs(n, j, [],
        `handleFirst :: String -> String
handleFirst raw = head (words raw)`),
    ],
    safe: [
      [(n, j) => hs(n, j, ['import Text.Read (readMaybe)'],
        `handleParse :: String -> IO ()
handleParse raw = print (readMaybe raw :: Maybe Int)`), 'total-parser'],
      [(n, j) => hs(n, j, ['import Data.Maybe (listToMaybe)'],
        `handleFirst :: String -> Maybe String
handleFirst raw = listToMaybe (words raw)`), 'total-parser'],
    ],
  },
  'sensitive-logging': {
    vuln: [
      (n, j) => hs(n, j, [],
        `handleLogin :: String -> String -> IO ()
handleLogin user pw = putStrLn ("login " ++ user ++ " password=" ++ pw)`),
      (n, j) => hs(n, j, [],
        `handleAudit :: String -> IO ()
handleAudit token = appendFile "${n.tbl}-audit.log" token`),
    ],
    safe: [
      [(n, j) => hs(n, j, [],
        `handleLogin :: String -> String -> IO ()
handleLogin user pw = putStrLn ("login " ++ user ++ " password length=" ++ show (length pw))`), 'redaction'],
      [(n, j) => hs(n, j, [],
        `redact :: String -> String
redact _ = "***"

handleAudit :: String -> IO ()
handleAudit token = appendFile "${n.tbl}-audit.log" (redact token)`), 'redaction'],
    ],
  },
  // v2 (see provenance.json "revisions"): handlers perform a real state change, and the guard is a real credential check.
  'route-authentication': {
    vuln: [
      (n, j) => hs(n, j, ['import Web.Scotty', 'import Control.Monad.IO.Class (liftIO)', 'import Database.SQLite.Simple'],
        `main :: IO ()
main = scotty 3000 $ do
  post "/${n.tbl}/purge" $ do
    conn <- liftIO (open "${n.tbl}.db")
    liftIO (execute_ conn "DELETE FROM ${n.tbl}_cache")
    text "purged"`),
      (n, j) => hs(n, j, ['import Web.Scotty', 'import Control.Monad.IO.Class (liftIO)', 'import Database.SQLite.Simple'],
        `main :: IO ()
main = scotty 3000 $ do
  put "/${n.tbl}/settings" $ do
    conn <- liftIO (open "${n.tbl}.db")
    label <- param "label"
    liftIO (execute conn "UPDATE ${n.tbl}_settings SET ${n.col} = ?" (Only (label :: String)))
    text "saved"`),
    ],
    safe: [
      [(n, j) => hs(n, j, ['import Web.Scotty', 'import Control.Monad.IO.Class (liftIO)', 'import Database.SQLite.Simple', 'import Network.HTTP.Types.Status (status401)'],
        `requireAuth :: ActionM ()
requireAuth = do
  h <- header "Authorization"
  case h of
    Nothing -> status status401 >> finish
    Just _ -> pure ()

main :: IO ()
main = scotty 3000 $ do
  post "/${n.tbl}/purge" $ do
    requireAuth
    conn <- liftIO (open "${n.tbl}.db")
    liftIO (execute_ conn "DELETE FROM ${n.tbl}_cache")
    text "purged"`), 'auth-guard'],
      [(n, j) => hs(n, j, ['import Web.Scotty', 'import Control.Monad.IO.Class (liftIO)', 'import Database.SQLite.Simple', 'import Network.HTTP.Types.Status (status401)'],
        `requireAuth :: ActionM ()
requireAuth = do
  h <- header "Authorization"
  case h of
    Nothing -> status status401 >> finish
    Just _ -> pure ()

main :: IO ()
main = scotty 3000 $ do
  put "/${n.tbl}/settings" $ do
    requireAuth
    conn <- liftIO (open "${n.tbl}.db")
    label <- param "label"
    liftIO (execute conn "UPDATE ${n.tbl}_settings SET ${n.col} = ?" (Only (label :: String)))
    text "saved"`), 'auth-guard'],
    ],
  },
  'object-authorization': {
    vuln: [
      (n, j) => hs(n, j, ['import Web.Scotty', 'import Control.Monad.IO.Class (liftIO)', 'import Database.SQLite.Simple', 'import Network.HTTP.Types.Status (status401)'],
        `requireAuth :: ActionM ()
requireAuth = do
  h <- header "Authorization"
  case h of
    Nothing -> status status401 >> finish
    Just _ -> pure ()

main :: IO ()
main = scotty 3000 $ do
  get "/${n.tbl}/:id" $ do
    requireAuth
    oid <- param "id"
    conn <- liftIO (open "${n.tbl}.db")
    rows <- liftIO (query conn "SELECT ${n.col} FROM ${n.tbl} WHERE id = ?" (Only (oid :: Int)))
    json (rows :: [Only String])`),
      (n, j) => hs(n, j, ['import Web.Scotty', 'import Control.Monad.IO.Class (liftIO)', 'import Database.SQLite.Simple', 'import Network.HTTP.Types.Status (status401)'],
        `requireAuth :: ActionM ()
requireAuth = do
  h <- header "Authorization"
  case h of
    Nothing -> status status401 >> finish
    Just _ -> pure ()

main :: IO ()
main = scotty 3000 $ do
  put "/${n.tbl}/:id" $ do
    requireAuth
    rid <- param "id"
    body <- param "body"
    conn <- liftIO (open "${n.tbl}.db")
    liftIO (execute conn "UPDATE ${n.tbl} SET ${n.col} = ? WHERE id = ?" (body :: String, rid :: Int))
    text "saved"`),
    ],
    safe: [
      [(n, j) => hs(n, j, ['import Web.Scotty', 'import Control.Monad.IO.Class (liftIO)', 'import Database.SQLite.Simple', 'import Network.HTTP.Types.Status (status401)'],
        `requireUser :: ActionM Int
requireUser = do
  h <- header "Authorization"
  case h of
    Nothing -> status status401 >> finish
    Just _ -> pure 1

main :: IO ()
main = scotty 3000 $ do
  get "/${n.tbl}/:id" $ do
    uid <- requireUser
    oid <- param "id"
    conn <- liftIO (open "${n.tbl}.db")
    rows <- liftIO (query conn "SELECT ${n.col} FROM ${n.tbl} WHERE id = ? AND owner = ?" (oid :: Int, uid))
    json (rows :: [Only String])`), 'owner-scope'],
      [(n, j) => hs(n, j, ['import Web.Scotty', 'import Control.Monad.IO.Class (liftIO)', 'import Database.SQLite.Simple', 'import Network.HTTP.Types.Status (status401)'],
        `requireUser :: ActionM Int
requireUser = do
  h <- header "Authorization"
  case h of
    Nothing -> status status401 >> finish
    Just _ -> pure 1

main :: IO ()
main = scotty 3000 $ do
  put "/${n.tbl}/:id" $ do
    uid <- requireUser
    rid <- param "id"
    body <- param "body"
    conn <- liftIO (open "${n.tbl}.db")
    liftIO (execute conn "UPDATE ${n.tbl} SET ${n.col} = ? WHERE id = ? AND owner = ?" (body :: String, rid :: Int, uid))
    text "saved"`), 'owner-scope'],
    ],
  },
  'session-cookie': {
    vuln: [
      (n, j) => hs(n, j, ['import Web.Cookie'],
        `cookie :: SetCookie
cookie = defaultSetCookie { setCookieName = "${n.tbl}sid" }`),
      (n, j) => hs(n, j, ['import Web.Cookie'],
        `cookie :: SetCookie
cookie = defaultSetCookie { setCookieName = "${n.tbl}tok", setCookieSecure = False }`),
    ],
    safe: [
      [(n, j) => hs(n, j, ['import Web.Cookie'],
        `cookie :: SetCookie
cookie = defaultSetCookie { setCookieName = "${n.tbl}sid", setCookieHttpOnly = True, setCookieSecure = True, setCookieSameSite = Just sameSiteStrict }`), 'hardened-attrs'],
      [(n, j) => hs(n, j, ['import Web.Cookie'],
        `cookie :: SetCookie
cookie = defaultSetCookie { setCookieName = "${n.tbl}tok", setCookieHttpOnly = True, setCookieSecure = True, setCookieSameSite = Just sameSiteLax }`), 'hardened-attrs'],
    ],
  },
};

// Unknown/unmodeled constructs inserted into an otherwise realistic vulnerable shape.
export const HS_UNKNOWN = [
  (n) => `#if MIN_VERSION_base(4,18,0)\nimport Data.List (singleton)\n#endif`,
  (n) => `{-# LANGUAGE TemplateHaskell #-}\n$(deriveJSON defaultOptions ''${n.N})`,
  (n) => `foreign import ccall unsafe "string.h strlen" c_strlen_${n.tbl} :: Ptr CChar -> IO CSize`,
  (n) => `class Sink a where\n  emit${n.N} :: a -> IO ()`,
  (n) => `import qualified Vendor.${n.N}.Guard as G`,
  (n) => `import Legacy.${n.N}.Compat`,
  (n) => `import Internal.${n.N}.Policy`,
  (n) => `{-# LANGUAGE TemplateHaskell #-}\n$(makeLenses ''${n.N}Config)`,
];

// ── Nix ──────────────────────────────────────────────────────────────────────
export const NIX = {
  'script-interpolation': {
    vuln: [
      (n, j) => nix(n, j, [`systemd.services.\"\${appName}-job\".script = "backup \${config.services.${n.tbl}.target}";`]),
      (n, j) => nix(n, j, [`environment.etc."${n.tbl}-run.sh".text = "echo \${config.services.${n.tbl}.message}";`]),
    ],
    safe: [
      [(n, j) => nix(n, j, [`systemd.services.\"\${appName}-job\".script = "backup \${lib.escapeShellArg config.services.${n.tbl}.target}";`]), 'escaper'],
      [(n, j) => nix(n, j, [`environment.etc."${n.tbl}-run.sh".text = "echo \${lib.escapeShellArg config.services.${n.tbl}.message}";`]), 'escaper'],
    ],
  },
  'secret-in-store': {
    vuln: [
      (n, j) => nix(n, j, [`services.${n.tbl}.password = "example-placeholder-${n.tbl}-${j}";`]),
      (n, j) => nix(n, j, [`environment.variables.API_KEY = "example-placeholder-${n.tbl}-${j}";`]),
    ],
    safe: [
      [(n, j) => nix(n, j, [`services.${n.tbl}.passwordFile = "/run/secrets/${n.tbl}_password_${j}";`]), 'runtime-path'],
      [(n, j) => nix(n, j, [`systemd.services.\"\${appName}-env\".serviceConfig.EnvironmentFile = "/run/secrets/${n.tbl}-${j}.env";`]), 'runtime-path'],
    ],
  },
  'unpinned-source': {
    vuln: [
      (n, j) => nix(n, j, [`environment.etc."${n.tbl}.src".source = pkgs.fetchurl { url = "https://example.org/${n.tbl}-${j}.tar.gz"; };`]),
      (n, j) => nix(n, j, [`environment.etc."${n.tbl}.git".source = pkgs.fetchFromGitHub { owner = "example"; repo = "${n.tbl}"; rev = "main"; };`]),
    ],
    safe: [
      [(n, j) => nix(n, j, [`environment.etc."${n.tbl}.src".source = pkgs.fetchurl { url = "https://example.org/${n.tbl}-${j}.tar.gz"; hash = "sha256-${hash64(n.tbl + j)}"; };`]), 'content-pin'],
      [(n, j) => nix(n, j, [`environment.etc."${n.tbl}.git".source = pkgs.fetchFromGitHub { owner = "example"; repo = "${n.tbl}"; rev = "${sha256(n.tbl + 'rev' + j).slice(0, 40)}"; hash = "sha256-${hash64(n.tbl + 'g' + j)}"; };`]), 'content-pin'],
    ],
  },
  'binary-cache-trust': {
    vuln: [
      (n, j) => nix(n, j, ['nix.settings.require-sigs = false;']),
      (n, j) => nix(n, j, [`nix.settings.substituters = [ "http://cache.${n.tbl}.example.org" ];`]),
    ],
    safe: [
      [(n, j) => nix(n, j, ['nix.settings.require-sigs = lib.mkForce true;']), 'mkForce'],
      [(n, j) => nix(n, j, [`nix.settings.substituters = [ "https://cache.${n.tbl}.example.org" ];`]), 'tls-cache'],
    ],
  },
  'trusted-users': {
    vuln: [
      (n, j) => nix(n, j, [`nix.settings.trusted-users = [ "root" "@wheel" "${n.tbl}" ];`]),
      (n, j) => nix(n, j, [`nix.settings.trusted-users = [ "*" "${n.tbl}${j}" ];`]),
    ],
    safe: [
      [(n, j) => nix(n, j, ['nix.settings.trusted-users = lib.mkForce [ "root" ];']), 'mkForce'],
      [(n, j) => nix(n, j, ['nix.settings.allowed-users = [ "@wheel" ];', 'nix.settings.trusted-users = [ ];']), 'scoped-users'],
    ],
  },
  'native-eval': {
    vuln: [
      (n, j) => nix(n, j, ['nix.settings.allow-unsafe-native-code-during-evaluation = true;']),
      (n, j) => nix(n, j, [`nix.settings.plugin-files = [ "/opt/${n.tbl}/plugin${j}.so" ];`]),
    ],
    safe: [
      [(n, j) => nix(n, j, ['nix.settings.allow-unsafe-native-code-during-evaluation = lib.mkForce false;']), 'mkForce'],
      [(n, j) => nix(n, j, ['nix.settings.plugin-files = [ ];']), 'empty-list'],
    ],
  },
  'sandbox-trust': {
    vuln: [
      (n, j) => nix(n, j, ['nix.settings.sandbox = false;']),
      (n, j) => nix(n, j, [`nix.settings.extra-sandbox-paths = [ "/home/${n.tbl}" ];`, 'nix.settings.sandbox = "relaxed";']),
    ],
    safe: [
      [(n, j) => nix(n, j, ['nix.settings.sandbox = lib.mkForce true;']), 'mkForce'],
      [(n, j) => nix(n, j, ['nix.settings.sandbox = true;', `nix.settings.extra-sandbox-paths = [ "/etc/${n.tbl}-ca" ];`]), 'scoped-path'],
    ],
  },
  'ssh-access': {
    vuln: [
      (n, j) => nix(n, j, ['services.openssh.enable = true;', 'services.openssh.settings.PasswordAuthentication = false;', 'services.openssh.settings.PermitRootLogin = "yes";']),
      (n, j) => nix(n, j, ['services.openssh.enable = true;', 'services.openssh.settings.PasswordAuthentication = true;']),
    ],
    safe: [
      [(n, j) => nix(n, j, ['services.openssh.enable = true;', 'services.openssh.settings.PermitRootLogin = lib.mkForce "no";', 'services.openssh.settings.PasswordAuthentication = false;']), 'mkForce'],
      [(n, j) => nix(n, j, ['services.openssh.enable = true;', 'services.openssh.settings.PasswordAuthentication = false;']), 'hardened-setting'],
    ],
  },
  'service-privilege': {
    vuln: [
      (n, j) => nix(n, j, [`systemd.services.${n.tbl}.wantedBy = [ "multi-user.target" ];`, `systemd.services.${n.tbl}.serviceConfig.ExecStart = "\${pkgs.hello}/bin/hello";`, `systemd.services.${n.tbl}.serviceConfig.User = "root";`]),
      (n, j) => nix(n, j, [`systemd.services.${n.tbl}.wantedBy = [ "multi-user.target" ];`, `systemd.services.${n.tbl}.serviceConfig.ExecStart = "\${pkgs.hello}/bin/hello";`, `systemd.services.${n.tbl}.serviceConfig.User = "${n.tbl}-svc";`, `systemd.services.${n.tbl}.serviceConfig.AmbientCapabilities = [ "CAP_SYS_ADMIN" ];`]),
    ],
    safe: [
      [(n, j) => nix(n, j, [`systemd.services.${n.tbl}.wantedBy = [ "multi-user.target" ];`, `systemd.services.${n.tbl}.serviceConfig.ExecStart = "\${pkgs.hello}/bin/hello";`, `systemd.services.${n.tbl}.serviceConfig.DynamicUser = true;`]), 'dynamic-user'],
      [(n, j) => nix(n, j, [`systemd.services.${n.tbl}.wantedBy = [ "multi-user.target" ];`, `systemd.services.${n.tbl}.serviceConfig.ExecStart = "\${pkgs.hello}/bin/hello";`, `systemd.services.${n.tbl}.serviceConfig.User = "${n.tbl}-svc";`, `systemd.services.${n.tbl}.serviceConfig.AmbientCapabilities = [ "CAP_NET_BIND_SERVICE" ];`]), 'least-capability'],
    ],
  },
  'firewall-exposure': {
    vuln: [
      (n, j) => nix(n, j, ['networking.firewall.enable = false;']),
      (n, j) => nix(n, j, ['services.postgresql.enable = true;', 'services.postgresql.settings.listen_addresses = lib.mkForce "*";']),
    ],
    safe: [
      [(n, j) => nix(n, j, ['networking.firewall.enable = true;']), 'hardened-setting'],
      [(n, j) => nix(n, j, ['services.postgresql.enable = true;', 'services.postgresql.settings.listen_addresses = lib.mkForce "localhost";']), 'mkForce'],
    ],
  },
  'privilege-escalation-policy': {
    vuln: [
      (n, j) => nix(n, j, ['security.sudo.wheelNeedsPassword = false;']),
      (n, j) => nix(n, j, ['security.doas.enable = true;', `security.doas.extraRules = [ { users = [ "${n.tbl}" ]; noPass = true; } ];`]),
    ],
    safe: [
      [(n, j) => nix(n, j, ['security.sudo.wheelNeedsPassword = lib.mkForce true;']), 'mkForce'],
      [(n, j) => nix(n, j, ['security.doas.enable = true;', `security.doas.extraRules = [ { users = [ "${n.tbl}" ]; command = "/run/current-system/sw/bin/switch-to-configuration"; } ];`]), 'scoped-command'],
    ],
  },
  'tls-secret-runtime': {
    vuln: [
      (n, j) => nix(n, j, ['services.nginx.enable = true;', `services.nginx.virtualHosts."${n.tbl}.example.org".sslCertificateKey = ./${n.tbl}${j}.key;`]),
      (n, j) => nix(n, j, ['services.nginx.enable = true;', `services.nginx.virtualHosts."${n.tbl}.example.org".forceSSL = false;`]),
    ],
    safe: [
      [(n, j) => nix(n, j, ['services.nginx.enable = true;', `services.nginx.virtualHosts."${n.tbl}.example.org".sslCertificateKey = "/run/credentials/${n.tbl}${j}.key";`]), 'runtime-path'],
      [(n, j) => nix(n, j, ['services.nginx.enable = true;', `services.nginx.virtualHosts."${n.tbl}.example.org".forceSSL = true;`]), 'hardened-setting'],
    ],
  },
};

// Conditional / unresolved constructs. Each is a realistic NixOS idiom whose
// effective value cannot be decided without evaluating the module system.
export const NIX_UNKNOWN = [
  (n) => `networking.domain = lib.mkDefault "${n.tbl}.example.org";`,
  (n) => `boot.kernelModules = lib.mkIf config.virtualisation.docker.enable [ "br_netfilter" ];`,
  (n) => `environment.variables = lib.optionalAttrs config.services.xserver.enable { ${n.N.toUpperCase()}_UI = "1"; };`,
  (n) => `programs.bash.shellInit = lib.mkMerge [ "echo ${n.tbl}" ];`,
  (n) => `time.timeZone = lib.mkOverride 900 "UTC";`,
  (n) => `environment.etc."${n.tbl}.extra".source = import ./extra-${n.tbl}.nix;`,
  (n) => `networking.search = lib.mkOptionDefault [ "${n.tbl}.internal" ];`,
  (n) => `users.motd = lib.mkIf (config.networking.hostName != "") "${n.tbl}";`,
];

export const insertHs = (text, extra) => {
  // top-level construct goes right after the import block
  const lines = text.split('\n');
  const lastImport = lines.map((l, i) => (/^import\s/.test(l) ? i : -1)).filter((i) => i >= 0).pop();
  const at = (lastImport ?? 2) + 1;
  lines.splice(at, 0, extra);
  return lines.join('\n');
};
export const insertNix = (text, extra) => text.replace(/\n}\n$/, `\n  ${extra}\n}\n`);
