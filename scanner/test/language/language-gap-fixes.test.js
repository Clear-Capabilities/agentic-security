// Engine gaps found by the unseen-shape measurement and fixed in the same release. Every fix is pinned in BOTH directions: the shape that
// used to be missed (or wrongly reported) is now right, and its neighbour that must NOT change still does not. A fix that only moves a
// verdict one way is a pattern added to make a number better; these tests are what stop that.
//
// The engine reads no label and no fixture name. The shapes here are written for the test.

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { analyzeHaskellRules } from '../../src/language/haskell-security-rules.js';
import { runScan } from '../../src/runScan.js';

const hs = (imports, body) => `module M where\n\n${imports.join('\n')}\n\n${body}\n`;
const rules = (src) => analyzeHaskellRules({ 'M.hs': src }).findings.map((f) => f.rule);
const has = (src, rule) => rules(src).includes(rule);

async function scan(file, text) {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'gapfix-')));
  try {
    fs.writeFileSync(path.join(dir, 'package.json'), '{}');
    fs.writeFileSync(path.join(dir, file), text);
    const r = await runScan(dir, { deep: true });
    return [...(r.scan.findings || []), ...(r.scan.secrets || [])].filter((f) => f.severity !== 'info' && !(f.proof && /^proven-/.test(f.proof.verdict)) && !f._provenUnreachable && !(f.controls || []).some((c) => c.kind === 'dominating-guard'));
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}
const cwes = (fs_) => fs_.map((f) => f.cwe);

// ── Haskell: structural rules ────────────────────────────────────────────────

test('randomness: a function named for a PIN is a security value; a die roll and a look-alike name are not', () => {
  assert.ok(has(hs(['import System.Random'], 'pin :: IO Int\npin = randomRIO (100000, 999999)'), 'hs-predictable-random'));
  assert.ok(has(hs(['import System.Random'], 'newPassword :: IO Int\nnewPassword = randomRIO (1, 99999999)'), 'hs-predictable-random'));
  assert.ok(!has(hs(['import System.Random'], 'diceRoll :: IO Int\ndiceRoll = randomRIO (1, 6)'), 'hs-predictable-random'));
  assert.ok(!has(hs(['import System.Random'], 'spinWheel :: IO Int\nspinWheel = randomRIO (1, 36)'), 'hs-predictable-random'), '"spin" contains "pin" but is not the word');
  assert.ok(!has(hs(['import System.Random'], 'mapping :: IO Int\nmapping = randomRIO (1, 9)'), 'hs-predictable-random'));
});

test('allocation: replicateM sized by parsed caller text is unbounded; clamped, and sized by a number, it is not', () => {
  const imp = ['import Control.Monad (replicateM)'];
  assert.ok(has(hs(imp, 'readLines :: String -> IO [String]\nreadLines n = replicateM (read n) getLine'), 'hs-unbounded-allocation'));
  assert.ok(!has(hs(imp, 'readLines :: String -> IO [String]\nreadLines n = replicateM (min 100 (read n)) getLine'), 'hs-unbounded-allocation'));
  assert.ok(!has(hs(imp, 'readLines :: IO [String]\nreadLines = replicateM 3 getLine'), 'hs-unbounded-allocation'));
});

test('partial functions: `!!` on a caller-supplied list is flagged as head is; a total lookup and a local list are not', () => {
  assert.ok(has(hs([], 'firstArg :: [String] -> String\nfirstArg args = args !! 0'), 'hs-partial-function-on-input'));
  assert.ok(has(hs([], 'firstArg :: [String] -> String\nfirstArg args = head args'), 'hs-partial-function-on-input'));
  assert.ok(!has(hs(['import Data.Maybe (listToMaybe)'], 'firstArg :: [String] -> Maybe String\nfirstArg = listToMaybe'), 'hs-partial-function-on-input'));
  assert.ok(!has(hs([], 'third :: Int\nthird = [1, 2, 3, 4 :: Int] !! 2'), 'hs-partial-function-on-input'), 'a literal list is not caller input');
});

test('partial functions: `fromJust (lookup key table)` fails when the CALLER\'s key is missing, so the key is seen even though taint ignores it', () => {
  const imp = ['import Data.Maybe (fromJust)'];
  assert.ok(has(hs(imp, 'setting :: String -> [(String, String)] -> String\nsetting key table = fromJust (lookup key table)'), 'hs-partial-function-on-input'));
  assert.ok(!has(hs(imp, 'setting :: String -> [(String, String)] -> String\nsetting key table = maybe "" id (lookup key table)'), 'hs-partial-function-on-input'));
});

test('logging: a label that names a credential marks the value after it; redaction and an innocent label do not', () => {
  const imp = ['import System.IO'];
  assert.ok(has(hs(imp, 'trace :: String -> IO ()\ntrace tok = hPutStrLn stderr ("token=" ++ tok)'), 'hs-sensitive-logging'));
  assert.ok(has(hs(imp, 'trace :: String -> IO ()\ntrace v = hPutStrLn stderr ("password: " ++ v)'), 'hs-sensitive-logging'));
  assert.ok(!has(hs(imp, 'trace :: String -> IO ()\ntrace tok = hPutStrLn stderr ("token length=" ++ show (length tok))'), 'hs-sensitive-logging'), 'a length is redaction');
  assert.ok(!has(hs(imp, 'trace :: String -> IO ()\ntrace v = hPutStrLn stderr ("user: " ++ v)'), 'hs-sensitive-logging'));
  assert.ok(!has(hs(imp, 'trace :: String -> IO ()\ntrace v = hPutStrLn stderr ("password policy loaded for " ++ v)'), 'hs-sensitive-logging'), 'the label must END in = or :');
});

// ── Haskell: route authentication ────────────────────────────────────────────

const SCOTTY = ['import Web.Scotty', 'import Control.Monad.IO.Class (liftIO)', 'import Database.SQLite.Simple', 'import Network.HTTP.Types.Status (status401)'];
const GUARDED = `guarded :: ActionM () -> ActionM ()
guarded act = do
  h <- header "Authorization"
  case h of
    Nothing -> status status401 >> finish
    Just _ -> act
`;

test('route auth: a wrapper guard that encloses the handler dominates it; a guard that runs after the write is still late', async () => {
  const wrapped = hs(SCOTTY, `${GUARDED}
main :: IO ()
main = scotty 3000 $ do
  patch "/flag" $ guarded $ do
    conn <- liftIO (open "x.db")
    liftIO (execute_ conn "UPDATE s SET e = 0")
    text "off"`);
  assert.ok(!cwes(await scan('M.hs', wrapped)).includes('CWE-306'), 'the wrapped handler is authenticated');
  const none = hs(SCOTTY, `main :: IO ()
main = scotty 3000 $ do
  patch "/flag" $ do
    conn <- liftIO (open "x.db")
    liftIO (execute_ conn "UPDATE s SET e = 0")
    text "off"`);
  assert.ok(cwes(await scan('M.hs', none)).includes('CWE-306'), 'no guard is still reported');
  const late = hs(SCOTTY, `${GUARDED}
main :: IO ()
main = scotty 3000 $ do
  patch "/flag" $ do
    conn <- liftIO (open "x.db")
    liftIO (execute_ conn "UPDATE s SET e = 0")
    guarded (text "off")`);
  assert.ok(cwes(await scan('M.hs', late)).includes('CWE-306'), 'a guard AFTER the write must still be reported (source order, not node order)');
});

// ── Haskell: taint ───────────────────────────────────────────────────────────

test('taint: lookup selects from a table, so a constant table gives a constant result; a tainted table does not', async () => {
  const PROC = ['import System.Process'];
  const constant = hs(PROC, `tools :: [(String, String)]
tools = [("zip", "zip"), ("tar", "tar")]

run :: String -> IO ()
run choice = case lookup choice tools of
  Just prog -> callProcess prog ["--version"]
  Nothing -> pure ()`);
  assert.ok(!(await scan('M.hs', constant)).some((f) => /CWE-(?:78|88)/.test(f.cwe)), 'the key only chooses among constants');
  const tainted = hs(PROC, `run :: String -> IO ()
run cmd = case lookup "a" [("a", cmd)] of
  Just prog -> callProcess prog ["--version"]
  Nothing -> pure ()`);
  assert.ok((await scan('M.hs', tainted)).some((f) => /CWE-(?:78|88)/.test(f.cwe)), 'a tainted VALUE in the table still reaches the sink');
});

test('taint: a number derived from caller text carries no text; the text itself still does', async () => {
  const HTTP = ['import Network.HTTP.Simple'];
  const numeric = hs(HTTP, `fetch :: String -> IO ()
fetch item = do
  req <- parseRequest ("https://api.example.com/items/" ++ show (length item))
  _ <- httpBS req
  pure ()`);
  assert.ok(!cwes(await scan('M.hs', numeric)).includes('CWE-918'));
  const textual = hs(HTTP, `fetch :: String -> IO ()
fetch item = do
  req <- parseRequest ("https://api.example.com/items/" ++ item)
  _ <- httpBS req
  pure ()`);
  assert.ok(cwes(await scan('M.hs', textual)).includes('CWE-918'), 'the path text is still caller-controlled');
});

test('taint: a host allow-list on the parsed URL guards it; parsing alone, or a non-host allow-list, does not', async () => {
  const IMPORTS = ['import Network.HTTP.Simple', 'import Network.URI'];
  const guarded = hs(IMPORTS, `ping :: String -> IO ()
ping url = case parseURI url >>= uriAuthority of
  Just a | uriRegName a \`elem\` ["status.example.com"] -> do
    req <- parseRequest url
    _ <- httpBS req
    pure ()
  _ -> pure ()`);
  assert.ok(!cwes(await scan('M.hs', guarded)).includes('CWE-918'));
  const unchecked = hs(IMPORTS, `ping :: String -> IO ()
ping url = case parseURI url >>= uriAuthority of
  Just _ -> do
    req <- parseRequest url
    _ <- httpBS req
    pure ()
  _ -> pure ()`);
  assert.ok(cwes(await scan('M.hs', unchecked)).includes('CWE-918'), 'parsing the URL is not a check');
});

// ── Nix ──────────────────────────────────────────────────────────────────────

const nixCfg = (lines) => `{ config, lib, pkgs, ... }:\n{\n${lines.map((l) => `  ${l}`).join('\n')}\n}\n`;
const families = async (lines) => (await scan('configuration.nix', nixCfg(lines))).map((f) => f.family);

test('sudo extraRules: NOPASSWD for ALL is a finding; NOPASSWD for one named command, and a password-required rule, are not', async () => {
  assert.ok((await families(['security.sudo.extraRules = [ { users = [ "ops" ]; commands = [ { command = "ALL"; options = [ "NOPASSWD" ]; } ]; } ];'])).includes('privilege-escalation'));
  assert.ok(!(await families(['security.sudo.extraRules = [ { users = [ "ops" ]; commands = [ { command = "/run/current-system/sw/bin/systemctl restart app"; options = [ "NOPASSWD" ]; } ]; } ];'])).includes('privilege-escalation'));
  assert.ok(!(await families(['security.sudo.extraRules = [ { users = [ "ops" ]; commands = [ { command = "ALL"; } ]; } ];'])).includes('privilege-escalation'), 'ALL with a password is the default');
});

test('TLS key: a key written into the store by writeText is a finding; a runtime credential path is not', async () => {
  assert.ok((await families(['services.nginx.enable = true;', 'services.nginx.virtualHosts."a.example.org".sslCertificateKey = pkgs.writeText "a.key" "placeholder";'])).includes('tls-runtime'));
  assert.ok(!(await families(['services.nginx.enable = true;', 'services.nginx.virtualHosts."a.example.org".sslCertificateKey = "/run/credentials/nginx.service/a.key";'])).includes('tls-runtime'));
});

test('wireless secret: ext:NAME is a reference to a runtime variable; a literal pre-shared key is still a secret', async () => {
  assert.ok(!(await families(['networking.wireless.networks."home".pskRaw = "ext:home_psk";', 'networking.wireless.environmentFile = "/run/secrets/wireless.env";'])).includes('hardcoded-secret'));
  assert.ok((await families(['networking.wireless.networks."home".psk = "kT9vQ2mXpL7wRz4Nb";'])).includes('hardcoded-secret'));
});
