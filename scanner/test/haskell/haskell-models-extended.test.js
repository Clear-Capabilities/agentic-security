// Haskell model coverage added after the first release (HS-003 extension): legacy System.Cmd, Turtle, Shelly, hint, HDBC, direct-sqlite, libpq, persistent
// backends, Req, HTTP, open redirect across five web frameworks, and more path/file readers and web sources.
//
// These are DEVELOPMENT cases, written next to the models with real library APIs: they prove the entries are wired and that the identity, guard and
// near-miss rules hold. They are not an accuracy measurement. The frozen holdout and the unseen-shapes split were not read or run to write them.
//
// Each case is one project directory holding one module, scanned once together through the public CLI. A finding counts when it is live (not refuted
// by a guard: `proof.verdict` that starts with "proven-"), in that case's directory, with the case's CWE.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { writeFileSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkTestTmp } from '../helpers/tmp.js';

const BIN = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'bin', 'agentic-security.js');
const CASES = [
 {
  "id": "ctl-callcommand",
  "cwe": "CWE-78",
  "vuln": true,
  "marker": "callCommand",
  "src": "{-# LANGUAGE OverloadedStrings #-}\nmodule Main where\nimport System.Process (callCommand)\nimport System.Environment (getArgs)\n\nmain :: IO ()\nmain = do\n  args <- getArgs\n  callCommand (\"ls \" ++ head args)\n"
 },
 {
  "id": "ctl-readfile",
  "cwe": "CWE-22",
  "vuln": true,
  "marker": "readFile",
  "src": "{-# LANGUAGE OverloadedStrings #-}\nmodule Main where\nimport System.Environment (getArgs)\n\nmain :: IO ()\nmain = do\n  args <- getArgs\n  c <- readFile (head args)\n  putStr c\n"
 },
 {
  "id": "ctl-scotty-param",
  "cwe": "CWE-78",
  "vuln": true,
  "marker": "callCommand",
  "src": "{-# LANGUAGE OverloadedStrings #-}\nmodule Main where\nimport Web.Scotty\nimport System.Process (callCommand)\n\nmain :: IO ()\nmain = scotty 3000 $\n  get \"/r\" $ do\n    c <- queryParam \"c\" :: ActionM String\n    liftIO (callCommand c)\n"
 },
 {
  "id": "cmd-system",
  "cwe": "CWE-78",
  "vuln": true,
  "marker": "system (",
  "src": "{-# LANGUAGE OverloadedStrings #-}\nmodule Main where\nimport System.Cmd (system)\nimport System.Environment (getArgs)\n\nmain :: IO ()\nmain = do\n  args <- getArgs\n  _ <- system (\"ls \" ++ head args)\n  return ()\n"
 },
 {
  "id": "cmd-system-safe",
  "cwe": "CWE-78",
  "vuln": false,
  "marker": "system (",
  "src": "{-# LANGUAGE OverloadedStrings #-}\nmodule Main where\nimport System.Cmd (system)\n\nmain :: IO ()\nmain = do\n  _ <- system (\"ls \" ++ \"/tmp\")\n  return ()\n"
 },
 {
  "id": "turtle-shell",
  "cwe": "CWE-78",
  "vuln": true,
  "marker": "shell (",
  "src": "{-# LANGUAGE OverloadedStrings #-}\nmodule Main where\nimport Turtle\nimport System.Environment (getArgs)\nimport qualified Data.Text as T\n\nmain :: IO ()\nmain = do\n  args <- getArgs\n  _ <- shell (T.pack (\"ls \" ++ head args)) empty\n  return ()\n"
 },
 {
  "id": "turtle-shell-safe",
  "cwe": "CWE-78",
  "vuln": false,
  "marker": "shell (",
  "src": "{-# LANGUAGE OverloadedStrings #-}\nmodule Main where\nimport Turtle\n\nmain :: IO ()\nmain = do\n  _ <- shell (\"ls /tmp\") empty\n  return ()\n"
 },
 {
  "id": "shelly-run",
  "cwe": "CWE-78",
  "vuln": true,
  "marker": "run_ ",
  "src": "{-# LANGUAGE OverloadedStrings #-}\nmodule Main where\nimport Shelly\nimport System.Environment (getArgs)\nimport qualified Data.Text as T\n\nmain :: IO ()\nmain = do\n  args <- getArgs\n  shelly $ run_ (fromText (T.pack (head args))) []\n"
 },
 {
  "id": "shelly-run-safe",
  "cwe": "CWE-78",
  "vuln": false,
  "marker": "run_ ",
  "src": "{-# LANGUAGE OverloadedStrings #-}\nmodule Main where\nimport Shelly\n\nmain :: IO ()\nmain = shelly $ run_ \"ls\" [\"-l\"]\n"
 },
 {
  "id": "hint-interpret",
  "cwe": "CWE-94",
  "vuln": true,
  "marker": "interpret ",
  "src": "{-# LANGUAGE OverloadedStrings #-}\nmodule Main where\nimport Language.Haskell.Interpreter\nimport System.Environment (getArgs)\n\nmain :: IO ()\nmain = do\n  args <- getArgs\n  r <- runInterpreter $ do\n    setImports [\"Prelude\"]\n    interpret (head args) (as :: Int)\n  print r\n"
 },
 {
  "id": "hint-interpret-safe",
  "cwe": "CWE-94",
  "vuln": false,
  "marker": "interpret ",
  "src": "{-# LANGUAGE OverloadedStrings #-}\nmodule Main where\nimport Language.Haskell.Interpreter\n\nmain :: IO ()\nmain = do\n  r <- runInterpreter $ do\n    setImports [\"Prelude\"]\n    interpret \"1 + 2\" (as :: Int)\n  print r\n"
 },
 {
  "id": "hdbc-quick",
  "cwe": "CWE-89",
  "vuln": true,
  "marker": "quickQuery",
  "src": "{-# LANGUAGE OverloadedStrings #-}\nmodule Main where\nimport Database.HDBC\nimport System.Environment (getArgs)\n\nlook :: IConnection c => c -> IO [[SqlValue]]\nlook conn = do\n  args <- getArgs\n  quickQuery' conn (\"SELECT * FROM users WHERE name = '\" ++ head args ++ \"'\") []\n"
 },
 {
  "id": "hdbc-quick-safe",
  "cwe": "CWE-89",
  "vuln": false,
  "marker": "quickQuery",
  "src": "{-# LANGUAGE OverloadedStrings #-}\nmodule Main where\nimport Database.HDBC\nimport System.Environment (getArgs)\n\nlook :: IConnection c => c -> IO [[SqlValue]]\nlook conn = do\n  args <- getArgs\n  quickQuery' conn \"SELECT * FROM users WHERE name = ?\" [toSql (head args)]\n"
 },
 {
  "id": "req-host",
  "cwe": "CWE-918",
  "vuln": true,
  "marker": "https (",
  "src": "{-# LANGUAGE OverloadedStrings #-}\nmodule Main where\nimport Network.HTTP.Req\nimport System.Environment (getArgs)\nimport qualified Data.Text as T\n\nmain :: IO ()\nmain = do\n  args <- getArgs\n  r <- runReq defaultHttpConfig $ req GET (https (T.pack (head args)) /: \"x\") NoReqBody ignoreResponse mempty\n  print (responseStatusCode r)\n"
 },
 {
  "id": "req-host-safe",
  "cwe": "CWE-918",
  "vuln": false,
  "marker": "https (",
  "src": "{-# LANGUAGE OverloadedStrings #-}\nmodule Main where\nimport Network.HTTP.Req\n\nmain :: IO ()\nmain = do\n  r <- runReq defaultHttpConfig $ req GET (https \"example.com\" /: \"x\") NoReqBody ignoreResponse mempty\n  print (responseStatusCode r)\n"
 },
 {
  "id": "http-simple",
  "cwe": "CWE-918",
  "vuln": true,
  "marker": "getRequest",
  "src": "{-# LANGUAGE OverloadedStrings #-}\nmodule Main where\nimport Network.HTTP (simpleHTTP, getRequest, getResponseBody)\nimport System.Environment (getArgs)\n\nmain :: IO ()\nmain = do\n  args <- getArgs\n  r <- simpleHTTP (getRequest (head args))\n  body <- getResponseBody r\n  putStrLn body\n"
 },
 {
  "id": "http-simple-safe",
  "cwe": "CWE-918",
  "vuln": false,
  "marker": "getRequest",
  "src": "{-# LANGUAGE OverloadedStrings #-}\nmodule Main where\nimport Network.HTTP (simpleHTTP, getRequest, getResponseBody)\n\nmain :: IO ()\nmain = do\n  r <- simpleHTTP (getRequest \"http://example.com/\")\n  body <- getResponseBody r\n  putStrLn body\n"
 },
 {
  "id": "scotty-redirect",
  "cwe": "CWE-601",
  "vuln": true,
  "marker": "redirect ",
  "src": "{-# LANGUAGE OverloadedStrings #-}\nmodule Main where\nimport Web.Scotty\nimport qualified Data.Text.Lazy as TL\n\nmain :: IO ()\nmain = scotty 3000 $\n  get \"/go\" $ do\n    target <- queryParam \"to\" :: ActionM TL.Text\n    redirect target\n"
 },
 {
  "id": "scotty-redirect-safe",
  "cwe": "CWE-601",
  "vuln": false,
  "marker": "redirect ",
  "src": "{-# LANGUAGE OverloadedStrings #-}\nmodule Main where\nimport Web.Scotty\n\nmain :: IO ()\nmain = scotty 3000 $\n  get \"/go\" $ do\n    redirect \"/home\"\n"
 },
 {
  "id": "yesod-redirect",
  "cwe": "CWE-601",
  "vuln": true,
  "marker": "redirect ",
  "src": "{-# LANGUAGE OverloadedStrings #-}\nmodule Main where\nimport Yesod.Core\nimport qualified Data.Text as T\n\ngetGoR :: Handler ()\ngetGoR = do\n  mto <- lookupGetParam \"to\"\n  case mto of\n    Just to -> redirect to\n    Nothing -> return ()\n"
 },
 {
  "id": "bs8-readfile",
  "cwe": "CWE-22",
  "vuln": true,
  "marker": "readFile ",
  "src": "{-# LANGUAGE OverloadedStrings #-}\nmodule Main where\nimport qualified Data.ByteString.Char8 as B\nimport Web.Scotty\nimport qualified Data.Text.Lazy as TL\n\nmain :: IO ()\nmain = scotty 3000 $\n  get \"/f\" $ do\n    p <- queryParam \"p\" :: ActionM String\n    c <- liftIO (B.readFile p)\n    raw c\n"
 },
 {
  "id": "tl-readfile",
  "cwe": "CWE-22",
  "vuln": true,
  "marker": "readFile ",
  "src": "{-# LANGUAGE OverloadedStrings #-}\nmodule Main where\nimport qualified Data.Text.Lazy.IO as TLIO\nimport System.Environment (getArgs)\n\nmain :: IO ()\nmain = do\n  args <- getArgs\n  c <- TLIO.readFile (head args)\n  TLIO.putStr c\n"
 },
 {
  "id": "bs8-readfile-safe",
  "cwe": "CWE-22",
  "vuln": false,
  "marker": "readFile ",
  "src": "{-# LANGUAGE OverloadedStrings #-}\nmodule Main where\nimport qualified Data.ByteString.Char8 as B\n\nmain :: IO ()\nmain = do\n  c <- B.readFile \"/etc/hostname\"\n  B.putStr c\n"
 },
 {
  "id": "snap-param",
  "cwe": "CWE-78",
  "vuln": true,
  "marker": "callCommand",
  "src": "{-# LANGUAGE OverloadedStrings #-}\nmodule Main where\nimport Snap.Core\nimport System.Process (callCommand)\nimport qualified Data.ByteString.Char8 as B\n\nhandler :: Snap ()\nhandler = do\n  mp <- getParam \"cmd\"\n  case mp of\n    Just c -> liftIO (callCommand (B.unpack c))\n    Nothing -> return ()\n"
 },
 {
  "id": "spock-param",
  "cwe": "CWE-78",
  "vuln": true,
  "marker": "callCommand",
  "src": "{-# LANGUAGE OverloadedStrings #-}\nmodule Main where\nimport Web.Spock\nimport System.Process (callCommand)\nimport qualified Data.Text as T\n\nhandler :: ActionM ()\nhandler = do\n  c <- param' \"cmd\"\n  liftIO (callCommand (T.unpack c))\n"
 },
 {
  "id": "yesod-getrequest",
  "cwe": "CWE-78",
  "vuln": true,
  "marker": "callCommand",
  "src": "{-# LANGUAGE OverloadedStrings #-}\nmodule Main where\nimport Yesod.Core\nimport System.Process (callCommand)\nimport qualified Data.Text as T\n\ngetRunR :: Handler ()\ngetRunR = do\n  req <- getRequest\n  case lookup \"cmd\" (reqGetParams req) of\n    Just c -> liftIO (callCommand (T.unpack c))\n    Nothing -> return ()\n"
 },
 {
  "id": "own-run-fn",
  "cwe": "CWE-78",
  "vuln": false,
  "marker": "run (",
  "src": "{-# LANGUAGE OverloadedStrings #-}\nmodule Main where\nimport System.Environment (getArgs)\n\nrun :: String -> IO ()\nrun s = putStrLn s\n\nmain :: IO ()\nmain = do\n  args <- getArgs\n  run (head args)\n"
 },
 {
  "id": "own-redirect-fn",
  "cwe": "CWE-601",
  "vuln": false,
  "marker": "redirect (",
  "src": "{-# LANGUAGE OverloadedStrings #-}\nmodule Main where\nimport System.Environment (getArgs)\n\nredirect :: String -> IO ()\nredirect s = putStrLn (\"moved \" ++ s)\n\nmain :: IO ()\nmain = do\n  args <- getArgs\n  redirect (head args)\n"
 },
 {
  "id": "scotty-redirect-allowlist",
  "cwe": "CWE-601",
  "vuln": false,
  "marker": "redirect ",
  "src": "{-# LANGUAGE OverloadedStrings #-}\nmodule Main where\nimport Web.Scotty\nimport qualified Data.Text.Lazy as TL\n\nmain :: IO ()\nmain = scotty 3000 $\n  get \"/go\" $ do\n    target <- queryParam \"to\" :: ActionM TL.Text\n    if target `elem` [\"/home\", \"/about\"] then redirect target else raise \"bad target\"\n"
 },
 {
  "id": "cmd-system-renamed",
  "cwe": "CWE-78",
  "vuln": true,
  "marker": "system (",
  "src": "{-# LANGUAGE OverloadedStrings #-}\nmodule Main where\nimport System.Cmd (system)\nimport System.Environment (getArgs)\n\nmain :: IO ()\nmain = do\n  userWords <- getArgs\n  _exit <- system (\"echo \" ++ concat userWords)\n  return ()\n"
 },
 {
  "id": "hdbc-renamed",
  "cwe": "CWE-89",
  "vuln": true,
  "marker": "run ",
  "src": "{-# LANGUAGE OverloadedStrings #-}\nmodule Main where\nimport Database.HDBC\nimport System.Environment (getArgs)\n\ndel :: IConnection c => c -> IO Integer\ndel db = do\n  who <- fmap head getArgs\n  run db (\"DELETE FROM sessions WHERE owner = '\" ++ who ++ \"'\") []\n"
 },
 {
  "id": "hdbc-run-safe",
  "cwe": "CWE-89",
  "vuln": false,
  "marker": "run ",
  "src": "{-# LANGUAGE OverloadedStrings #-}\nmodule Main where\nimport Database.HDBC\nimport System.Environment (getArgs)\n\ndel :: IConnection c => c -> IO Integer\ndel db = do\n  who <- fmap head getArgs\n  run db \"DELETE FROM sessions WHERE owner = ?\" [toSql who]\n"
 },
 {
  "id": "readfile-allowlist",
  "cwe": "CWE-22",
  "vuln": false,
  "marker": "readFile ",
  "src": "{-# LANGUAGE OverloadedStrings #-}\nmodule Main where\nimport qualified Data.ByteString.Char8 as B\nimport System.Environment (getArgs)\n\nmain :: IO ()\nmain = do\n  args <- getArgs\n  let name = head args\n  if name `elem` [\"a.txt\", \"b.txt\"] then do { c <- B.readFile (\"/srv/public/\" ++ name); B.putStr c } else putStrLn \"no\"\n"
 }
];

let findings;
function scanAll() {
  if (findings) return findings;
  const dir = mkTestTmp('hs-models-ext-');
  for (const c of CASES) { mkdirSync(join(dir, c.id), { recursive: true }); writeFileSync(join(dir, c.id, 'Main.hs'), c.src); }
  const env = { ...process.env }; delete env.NODE_TEST_CONTEXT;
  const p = spawnSync(process.execPath, [BIN, 'scan', dir, '--format', 'json'], { encoding: 'utf8', timeout: 600000, env, maxBuffer: 1 << 28 });
  findings = JSON.parse(p.stdout).findings;
  return findings;
}
const liveFor = (id, cwe) => scanAll().filter((f) => String(f.file || '').startsWith(id + '/') && f.cwe === cwe && !(f.proof && /^proven-/.test(f.proof.verdict)));

for (const c of CASES) {
  test(`${c.vuln ? 'FOUND' : 'SILENT'}: ${c.id} (${c.cwe})`, () => {
    const hits = liveFor(c.id, c.cwe);
    const ls = c.src.split('\n'); const line = ls.map((l, i) => (l.includes(c.marker) ? i + 1 : 0)).filter(Boolean).pop();   // the call site is the last line holding the marker, not the import
    if (c.vuln) { assert.ok(hits.length >= 1, 'a live finding at the sink'); assert.ok(hits.some((h) => h.line === line), `at line ${line}, got ${hits.map((h) => h.line)}`); }
    else assert.equal(hits.length, 0, JSON.stringify(hits.map((h) => ({ line: h.line, vuln: h.vuln }))));
  });
}
