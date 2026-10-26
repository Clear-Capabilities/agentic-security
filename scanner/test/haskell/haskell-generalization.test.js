// Haskell SAST and taint generalisation (the unseen-v3 failures, which became a DEVELOPMENT set). Every change made for them is pinned here in BOTH
// directions: the vulnerable form is found and a near-miss that shares its surface is not. The sources are written for this file in the idioms of
// real Haskell services (handlers with `where` helpers, guards, case alternatives, qualified imports); none is copied from a corpus case.
//
// Groups: 1 rules (cookies, unbounded reads, randomness, partial functions, printf logging), 2 web (convention-named Yesod handlers, function-form
// Servant handlers, Scotty rejection in a case branch, ownership by `when`), 3 taint (new file/URL sinks, guard and escaper recognition, positional
// shell parameters), 4 the source label of an exported function's parameter, 5 the idioms the IR lowers (monadic binds that ignore the result,
// `maybe` / `either`, `\case`, folds and zips, tuple selectors, numeric annotations, character-class filters, let-bound lambdas, branches used as
// statements, function-form Servant endpoints, record fields).

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { analyzeHaskellRules } from '../../src/language/haskell-security-rules.js';
import { analyzeHaskellWeb } from '../../src/language/haskell-web.js';
import { runScan } from '../../src/runScan.js';
import { computeStableId } from '../../src/posture/stable-id.js';
import { mkTestTmp } from '../helpers/tmp.js';

const rules = (src, name = 'Svc.hs') => analyzeHaskellRules({ [name]: src }).findings;
const ruleIds = (src) => rules(src).map((f) => f.rule);
const has = (src, rule) => ruleIds(src).includes(rule);
const mod = (imports, body, header = 'module Svc where') => `${header}\n\n${imports.join('\n')}\n\n${body}\n`;

async function scan(files) {
  const dir = mkTestTmp('hs-gen-');
  writeFileSync(join(dir, 'package.json'), '{}');
  for (const [f, text] of Object.entries(files)) { mkdirSync(dirname(join(dir, f)), { recursive: true }); writeFileSync(join(dir, f), text); }
  const r = await runScan(dir, { deep: true });
  return [...(r.scan.findings || [])].filter((f) => f.severity !== 'info');
}
const live = (fs, cwe) => fs.filter((f) => f.parser === 'IR-TAINT' && f.cwe === cwe && !(f.proof && /^proven-/.test(f.proof.verdict)));

// ── 1. rules ─────────────────────────────────────────────────────────────────

test('cookies: scotty-cookie helper, a hand-written Set-Cookie header and servant-auth NotSecure are session cookies without the flags', () => {
  const scotty = (name) => mod(['import Web.Scotty', 'import Web.Scotty.Cookie (setSimpleCookie)', 'import qualified Data.Text as T'], `login :: T.Text -> ActionM ()\nlogin sid = do\n  setSimpleCookie "${name}" sid\n  text "ok"`);
  assert.ok(has(scotty('session_id'), 'hs-insecure-cookie'));
  assert.ok(!has(scotty('theme'), 'hs-insecure-cookie'), 'a cookie that is not a session or credential cookie');
  const wai = (attrs) => mod(['import Network.Wai', 'import Network.HTTP.Types (status200)', 'import Network.HTTP.Types.Header (hSetCookie)', 'import qualified Data.ByteString.Char8 as BC', 'import qualified Data.ByteString.Lazy.Char8 as BL'],
    `reply :: BC.ByteString -> Response\nreply sid = responseLBS status200 [(hSetCookie, BC.pack "auth_token=" <> sid <> BC.pack "${attrs}")] (BL.pack "ok")`);
  assert.ok(has(wai('; Path=/'), 'hs-insecure-cookie'));
  assert.ok(has(wai('; Path=/; Secure'), 'hs-insecure-cookie'), 'HttpOnly is still missing');
  assert.ok(!has(wai('; Path=/; Secure; HttpOnly'), 'hs-insecure-cookie'));
  const servant = (v) => mod(['import Servant.Auth.Server'], `settings :: CookieSettings\nsettings = defaultCookieSettings { cookieIsSecure = ${v} }`);
  assert.ok(has(servant('NotSecure'), 'hs-insecure-cookie'));
  assert.ok(!has(servant('Secure'), 'hs-insecure-cookie'));
});

test('unbounded reads: a conduit body drained without a limit, a recv loop with no cap, a body read with no length test', () => {
  const conduit = (pipe) => mod(['import Network.Wai (Request)', 'import Network.Wai.Conduit (sourceRequestBody)', 'import Data.Conduit (runConduit, (.|))', 'import Data.Conduit.Binary (sinkLbs, isolate)', 'import qualified Data.ByteString.Lazy as BL'],
    `slurp :: Request -> IO BL.ByteString\nslurp r = runConduit (sourceRequestBody r ${pipe})`);
  assert.ok(has(conduit('.| sinkLbs'), 'hs-unbounded-request-body'));
  assert.ok(!has(conduit('.| isolate 1048576 .| sinkLbs'), 'hs-unbounded-request-body'));
  const loop = (step) => mod(['import Network.Socket (Socket)', 'import Network.Socket.ByteString (recv)', 'import qualified Data.ByteString as BS'],
    `drain :: Socket -> IO BS.ByteString\ndrain s = go 0 []\n  where\n    go n acc = do\n      c <- recv s 1024\n      ${step}`);
  assert.ok(has(loop('if BS.null c then pure (BS.concat acc) else go (n + 1) (c : acc)'), 'hs-unbounded-input-read'));
  assert.ok(!has(loop('if BS.null c || n * 1024 >= 65536 then pure (BS.concat acc) else go (n + 1 :: Int) (c : acc)'), 'hs-unbounded-input-read'), 'the loop compares the amount read with a limit');
  const strict = (check) => mod(['import Network.Wai', 'import qualified Data.ByteString.Lazy as BL'],
    `readBody :: Request -> IO BL.ByteString\nreadBody req = ${check}`);
  assert.ok(has(strict('strictRequestBody req'), 'hs-unbounded-request-body'));
  assert.ok(!has(strict('case requestBodyLength req of\n  KnownLength n | n <= 4096 -> strictRequestBody req\n  _ -> pure BL.empty'), 'hs-unbounded-request-body'));
  // requestBodyLength read but never compared: the body is still unbounded
  assert.ok(has(strict('case requestBodyLength req of\n  KnownLength _ -> strictRequestBody req\n  _ -> pure BL.empty'), 'hs-unbounded-request-body'));
});

test('weak randomness: a generator named as the whole value of a token function, one finding per function, not for a jitter', () => {
  const tok = (name) => mod(['import System.Random (randomIO)', 'import Data.Word (Word64)'], `${name} :: IO Word64\n${name} = randomIO`);
  assert.ok(has(tok('newCsrfToken'), 'hs-predictable-random'));
  assert.ok(!has(tok('retryJitter'), 'hs-predictable-random'));
  const seeded = mod(['import System.Random', 'import Data.Time.Clock.POSIX (getPOSIXTime)'], `apiKey :: IO String\napiKey = do\n  now <- getPOSIXTime\n  pure (take 32 (randomRs ('a', 'z') (mkStdGen (floor now))))`);
  assert.equal(rules(seeded).filter((f) => f.rule === 'hs-predictable-random').length, 1, 'a clock-seeded generator is one flaw, not two');
});

test('partial functions: maximum / head / Map.! on a parameter the caller supplies, unless the function tests it first', () => {
  const plain = (b) => mod([], b, 'module Svc (peak, firstOf) where');
  assert.ok(has(plain('peak :: [Int] -> Int\npeak xs = maximum xs'), 'hs-partial-function-on-input'));
  assert.ok(has(plain('firstOf :: [String] -> String\nfirstOf xs = head xs'), 'hs-partial-function-on-input'));
  assert.ok(!has(plain('peak :: [Int] -> Int\npeak xs = if null xs then 0 else maximum xs'), 'hs-partial-function-on-input'), 'tested for emptiness');
  assert.ok(!has(plain('peak :: [Int] -> Int\npeak xs\n  | null xs = 0\n  | otherwise = maximum xs'), 'hs-partial-function-on-input'), 'a guard');
  assert.ok(!has(plain('peak :: [Int] -> Int\npeak xs = maybe 0 maximum (nonEmpty xs)'), 'hs-partial-function-on-input'), 'total');
  const map = (b) => mod(['import qualified Data.Map as M'], b, 'module Svc (price) where');
  assert.ok(has(map('price :: M.Map String Int -> String -> Int\nprice t k = t M.! k'), 'hs-partial-function-on-input'));
  assert.ok(!has(map('price :: M.Map String Int -> String -> Int\nprice t k = M.findWithDefault 0 k t'), 'hs-partial-function-on-input'));
  assert.ok(!has(map('price :: M.Map String Int -> String -> Int\nprice t k\n  | M.member k t = t M.! k\n  | otherwise = 0'), 'hs-partial-function-on-input'), 'membership tested');
  // not exported: its caller is in this module, not outside
  assert.ok(!has(mod([], 'peak :: [Int] -> Int\npeak xs = maximum xs\n\nmain :: IO ()\nmain = print (peak [1, 2])', 'module Svc (main) where'), 'hs-partial-function-on-input'));
  // a helper that is not exported and not called is judged like any other not-exported function
  const where = plain('firstOf :: String -> String\nfirstOf line\n  | null ws = ""\n  | otherwise = last ws\n  where\n    ws = words line');
  assert.ok(!has(where, 'hs-partial-function-on-input'), 'the guard tests a value the partial call is built from');
});

test('sensitive logging: printf values are judged one by one, so one masked value never hides a secret beside it', () => {
  const pf = (args) => mod(['import Text.Printf (printf)'], `mask :: String -> String\nmask s = replicate (length s) '*'\n\nreport :: String -> String -> IO ()\nreport who apiSecret = printf "user %s key %s\\n" ${args}`);
  assert.ok(has(pf('who apiSecret'), 'hs-sensitive-logging'));
  assert.ok(!has(pf('who (mask apiSecret)'), 'hs-sensitive-logging'));
  assert.ok(has(pf('(mask who) apiSecret'), 'hs-sensitive-logging'), 'the redaction applies to the other value');
  const hp = mod(['import Text.Printf (hPrintf)', 'import System.IO (stderr)'], `trace :: String -> String -> IO ()\ntrace who authToken = hPrintf stderr "%s %s\\n" who authToken`);
  assert.ok(has(hp, 'hs-sensitive-logging'));
});

// ── 2. web ───────────────────────────────────────────────────────────────────

const webRoutes = (files) => analyzeHaskellWeb(files);
const ruleOf = (r, id) => r.findings.filter((f) => f.rule === id);

test('Yesod handlers named by convention are routes even when the route table is in another file', () => {
  const handler = (body) => ({ 'Handler.hs': mod(['import Yesod', 'import Database.Persist.Sql (rawExecute)'], `postWipeR :: Handler Text\npostWipeR = do\n${body}\n  return "done"`) });
  const open = webRoutes(handler('  runDB (rawExecute "DELETE FROM sessions" [])'));
  assert.equal(open.routes.length, 1);
  assert.equal(open.routes[0].method, 'POST');
  assert.equal(ruleOf(open, 'hs-route-missing-auth').length, 1);
  const guarded = webRoutes(handler('  _ <- requireAuthId\n  runDB (rawExecute "DELETE FROM sessions" [])'));
  assert.equal(ruleOf(guarded, 'hs-route-missing-auth').length, 0);
  assert.equal(guarded.routes[0].auth.status, 'authenticated');
  // a function with a handler-looking name and a non-Handler type is not a route
  const notRoute = webRoutes({ 'H.hs': mod(['import Yesod'], 'getValueR :: Int -> Int\ngetValueR n = n + 1') });
  assert.equal(notRoute.routes.length, 0);
});

test('ownership: an id from the route reaches a lookup, and `when (owner /= principal) notFound` is the check that closes it', () => {
  const get = (check) => ({ 'Inv.hs': mod(['import Yesod', 'import Control.Monad (when)'], `getInvoiceR :: InvoiceId -> Handler Value\ngetInvoiceR invoiceId = do\n  uid <- requireAuthId\n  invoice <- runDB (get404 invoiceId)\n${check}  returnJson invoice`) });
  assert.equal(ruleOf(webRoutes(get('')), 'hs-route-bola').length, 1);
  assert.equal(ruleOf(webRoutes(get('  when (invoiceOwner invoice /= uid) notFound\n')), 'hs-route-bola').length, 0);
  assert.equal(ruleOf(webRoutes(get('  unless (invoiceOwner invoice == uid) notFound\n')), 'hs-route-bola').length, 0);
});

test('Servant: an endpoint written as a function takes its auth and capture values from its own parameters', () => {
  const server = (params, query) => ({ 'Api.hs': mod(['import Servant', 'import Servant.Server.Experimental.Auth (AuthServerData)', 'import Control.Monad.IO.Class (liftIO)', 'import Database.SQLite.Simple'],
    `data Account = Account { accountId :: Int }\n\ntype instance AuthServerData (AuthProtect "jwt") = Account\n\ntype API = AuthProtect "jwt" :> "docs" :> Capture "id" Int :> Get '[JSON] [String]\n\nserver :: Server API\nserver ${params} = do\n  conn <- liftIO (open "docs.db")\n  rows <- liftIO (query conn "${query}" ${query.includes('owner') ? '(rowId, accountId acct)' : '(Only rowId)'})\n  pure (map fromOnly rows)`) });
  assert.equal(ruleOf(webRoutes(server('_acct rowId', 'SELECT t FROM docs WHERE id = ?')), 'hs-route-bola').length, 1);
  assert.equal(ruleOf(webRoutes(server('acct rowId', 'SELECT t FROM docs WHERE id = ? AND owner = ?')), 'hs-route-bola').length, 0, 'the query is scoped by the principal');
});

test('Scotty: a rejection in the LAST case alternative still guards the success branch listed first', () => {
  const handler = (alts) => ({ 'S.hs': mod(['import Web.Scotty', 'import Control.Monad.IO.Class (liftIO)', 'import Database.SQLite.Simple', 'import Network.HTTP.Types.Status (status401)', 'import qualified Data.Text.Lazy as TL', 'import System.Environment (getEnv)'],
    `main :: IO ()\nmain = scotty 3000 $\n  delete "/all" $ do\n    mAuth <- header "Authorization"\n    expected <- liftIO (getEnv "TOKEN")\n    case mAuth of\n${alts}`) });
  const ok = 'Just a | a == TL.pack expected -> do\n        conn <- liftIO (open "x.db")\n        liftIO (execute_ conn "DELETE FROM t")\n        text "ok"\n      _ -> status status401 >> finish';
  const wrapped = (s) => s.split('\n').map((l, i) => (i === 0 ? `      ${l}` : l)).join('\n');
  const r = webRoutes(handler(wrapped(ok)));
  assert.equal(r.routes[0].auth.status, 'authenticated', JSON.stringify(r.routes[0].auth));
  // the same shape where the "rejection" only sets the status and never halts: the delete is open
  const noHalt = webRoutes(handler(wrapped(ok.replace(' >> finish', ''))));
  assert.notEqual(noHalt.routes[0].auth.status, 'authenticated');
  // the success branch also taken when no credential was matched: nothing rejects
  const open = webRoutes(handler(wrapped('Just _ -> do\n        conn <- liftIO (open "x.db")\n        liftIO (execute_ conn "DELETE FROM t")\n        text "ok"\n      Nothing -> text "anon"')));
  assert.notEqual(open.routes[0].auth.status, 'authenticated');
});

test('a numeric annotation on the id does not hide it from the ownership analysis', () => {
  const route = (use) => ({ 'S.hs': mod(['import Web.Scotty', 'import Control.Monad.IO.Class (liftIO)', 'import Database.SQLite.Simple', 'import Network.HTTP.Types.Status (status401)'],
    `requireLogin :: ActionM Int\nrequireLogin = do\n  h <- header "Authorization"\n  case h of\n    Nothing -> status status401 >> finish\n    Just _ -> pure 7\n\nmain :: IO ()\nmain = scotty 3000 $\n  get "/u/:id" $ do\n    _ <- requireLogin\n    oid <- param "id"\n    conn <- liftIO (open "u.db")\n    rows <- liftIO (query conn "SELECT e FROM u WHERE id = ?" (Only ${use}))\n    json (rows :: [Only String])`) });
  assert.equal(ruleOf(webRoutes(route('(oid :: Int)')), 'hs-route-bola').length, 1);
  assert.equal(ruleOf(webRoutes(route('oid')), 'hs-route-bola').length, 1);
  assert.equal(ruleOf(webRoutes(route('(7 :: Int)')), 'hs-route-bola').length, 0, 'a constant is not the request id');
});

// ── 3. taint ─────────────────────────────────────────────────────────────────

test('file-serving sinks: a request-chosen name reaches `file`, a name looked up in a fixed table does not', async () => {
  const scotty = (body) => ({ 'src/Svc.hs': mod(['import Web.Scotty', 'import qualified Data.Map.Strict as Map'], `catalogue :: Map.Map String FilePath\ncatalogue = Map.fromList [("manual", "/srv/manual.pdf")]\n\nmain :: IO ()\nmain = scotty 3000 $ get "/dl/:name" $ do\n  name <- param "name"\n${body}`) });
  assert.equal(live(await scan(scotty('  file ("/srv/exports/" ++ name)')), 'CWE-22').length, 1);
  assert.equal(live(await scan(scotty('  case Map.lookup name catalogue of\n    Just known -> file known\n    Nothing -> next')), 'CWE-22').length, 0);
});

test('Req: a URI parsed from caller text reaches the request target; a fixed host with a tainted path segment does not', async () => {
  const req = (body) => ({ 'src/Svc.hs': mod(['import Network.HTTP.Req', 'import Text.URI (mkURI)', 'import qualified Data.Text as T'], body, 'module Svc (fetchRemote, fetchDoc) where') });
  const vuln = req('fetchRemote :: T.Text -> IO ()\nfetchRemote raw = do\n  uri <- mkURI raw\n  case useURI uri of\n    Just (Left (u, o)) -> runReq defaultHttpConfig (req GET u NoReqBody ignoreResponse o) >> pure ()\n    Just (Right (u, o)) -> runReq defaultHttpConfig (req GET u NoReqBody ignoreResponse o) >> pure ()\n    Nothing -> pure ()');
  assert.equal(live(await scan(vuln), 'CWE-918').length, 1, 'one request target, one finding');
  const safe = req('fetchDoc :: T.Text -> IO ()\nfetchDoc docId = runReq defaultHttpConfig $ do\n  _ <- req GET (https "docs.example.com" /: "v1" /: docId) NoReqBody ignoreResponse mempty\n  pure ()');
  assert.equal(live(await scan(safe), 'CWE-918').length, 0);
});

test('http-client: a host allow-list checked AFTER parseRequest dominates the send; without it the send is a finding', async () => {
  const fetchWith = (check) => ({ 'src/Svc.hs': mod(['import Network.HTTP.Client', 'import Network.HTTP.Client.TLS (tlsManagerSettings)', 'import qualified Data.ByteString.Char8 as BC'],
    `allowed :: [BC.ByteString]\nallowed = [BC.pack "hooks.example.com"]\n\nfetch :: String -> IO ()\nfetch url = do\n  r <- parseRequest url\n${check}`, 'module Svc (fetch) where') });
  const send = 'newManager tlsManagerSettings >>= httpNoBody r >> pure ()';
  assert.equal(live(await scan(fetchWith(`  ${send}`)), 'CWE-918').length, 1);
  assert.equal(live(await scan(fetchWith(`  if host r \`elem\` allowed && secure r\n    then ${send}\n    else ioError (userError "no")`)), 'CWE-918').length, 0, 'a named allow-list and `&&` in the condition');
  assert.equal(live(await scan(fetchWith(`  if host r \`elem\` allowed\n    then ioError (userError "no")\n    else ${send}`)), 'CWE-918').length, 1, 'the send is on the branch where the host is NOT allowed');
});

test('a hand-written HTML escaper (recognised by the entities it produces) neutralises XSS; escaping only part of the value does not', async () => {
  const page = (expr) => ({ 'src/Svc.hs': mod(['import Web.Scotty', 'import qualified Data.Text as T', 'import qualified Data.Text.Lazy as TL'],
    `esc :: T.Text -> T.Text\nesc = T.concatMap f\n  where\n    f '<' = "&lt;"\n    f '>' = "&gt;"\n    f '&' = "&amp;"\n    f c = T.singleton c\n\nmain :: IO ()\nmain = scotty 3000 $ get "/g/:w" $ do\n  w <- param "w"\n  html (TL.fromStrict (${expr}))`) });
  assert.equal(live(await scan(page('"<p>" <> w <> "</p>"')), 'CWE-79').length, 1);
  assert.equal(live(await scan(page('"<p>" <> esc w <> "</p>"')), 'CWE-79').length, 0);
  assert.equal(live(await scan(page('"<p>" <> esc w <> w <> "</p>"')), 'CWE-79').length, 1, 'one use of the value is unescaped');
  // a function that merely has the word in its name is not an escaper
  const named = { 'src/Svc.hs': mod(['import Web.Scotty', 'import qualified Data.Text as T', 'import qualified Data.Text.Lazy as TL'], `escapeHtml :: T.Text -> T.Text\nescapeHtml = id\n\nmain :: IO ()\nmain = scotty 3000 $ get "/g/:w" $ do\n  w <- param "w"\n  html (TL.fromStrict ("<p>" <> escapeHtml w))`) };
  assert.equal(live(await scan(named), 'CWE-79').length, 1);
});

test('sh -c: the script is what the shell parses; a tainted positional parameter is data only inside double quotes after "--"', async () => {
  const run = (script, tail) => ({ 'src/Svc.hs': mod(['import System.Process'], `pack :: String -> IO ()\npack target = callProcess "sh" ["-c", ${script}, "sh"${tail}]`, 'module Svc (pack) where') });
  const live78 = (fs) => fs.filter((f) => f.parser === 'IR-TAINT' && (f.cwe === 'CWE-78' || f.cwe === 'CWE-88'));
  assert.equal(live78(await scan(run('"gzip -9 -- \\"$1\\""', ', target'))).length, 0, 'quoted after --');
  assert.ok(live78(await scan(run('"gzip -9 -- $1"', ', target'))).length >= 1, 'unquoted expansion');
  assert.ok(live78(await scan(run('"gzip -9 \\"$1\\""', ', target'))).length >= 1, 'quoted but no -- (option injection)');
  const injected = live78(await scan(run('("gzip -9 " ++ target)', '')));
  assert.ok(injected.some((f) => f.cwe === 'CWE-78'), 'the script itself is built from the value');
});

// ── 4. the label of an exported parameter ────────────────────────────────────

test('an exported function\'s text parameter is a request value only when the function returns a web-framework handler; otherwise the weaker label', async () => {
  const sourceOf = async (imports, sig, body) => {
    const fs = live(await scan({ 'src/Svc.hs': mod(imports, `${sig}\n${body}`) }), 'CWE-22');
    assert.equal(fs.length, 1, JSON.stringify(fs.map((f) => f.id)));
    return fs[0].source && fs[0].source.label;
  };
  const scotty = await sourceOf(['import Web.Scotty', 'import qualified Data.Text as T'], 'download :: String -> ActionM ()', 'download name = file ("/srv/" ++ name)');
  assert.match(scotty, /Scotty action \(request input\)/);
  const yesod = await sourceOf(['import Yesod'], 'showFile :: String -> Handler ()', 'showFile name = sendFile "text/plain" ("/srv/" ++ name)');
  assert.match(yesod, /Yesod handler \(request input\)/);
  const lib = await sourceOf(['import System.IO'], 'load :: String -> IO String', 'load name = readFile ("/srv/" ++ name)');
  assert.match(lib, /exported function \(caller-controlled\)/);
  // a framework module whose function returns plain text: still a library export
  const helper = await sourceOf(['import Web.Scotty'], 'slurp :: String -> IO String', 'slurp name = readFile ("/srv/" ++ name)');
  assert.match(helper, /caller-controlled/);
});

test('naming a parameter source does not change the finding\'s stable id', async () => {
  const fs = live(await scan({ 'src/Svc.hs': mod(['import System.IO'], 'load :: String -> IO String\nload name = readFile ("/srv/" ++ name)') }), 'CWE-22');
  assert.equal(fs.length, 1);
  assert.equal(fs[0].source.kind, 'parameter');
  assert.equal(computeStableId(fs[0]), computeStableId({ ...fs[0], source: undefined }), 'the source label of a parameter is not part of the identity');
  // a source read by a call still is (unchanged behaviour)
  const read = live(await scan({ 'src/Svc.hs': mod(['import System.IO'], 'main :: IO ()\nmain = getLine >>= readFile >>= putStr', 'module Svc (main) where') }), 'CWE-22');
  assert.equal(read.length, 1);
  assert.notEqual(read[0].source.kind, 'parameter');
  assert.notEqual(computeStableId(read[0]), computeStableId({ ...read[0], source: undefined }));
});

test('request accessors a framework handler really uses are sources (Maybe/Either forms, cookies, JSON bodies)', async () => {
  const flow = async (imports, body) => live(await scan({ 'src/Svc.hs': mod(imports, body, 'module Svc (main) where') }), 'CWE-22').length;
  assert.equal(await flow(['import Web.Scotty'], 'main :: IO ()\nmain = scotty 3000 $ get "/a" $ do\n  mn <- queryParamMaybe "n"\n  case mn of\n    Just n -> file n\n    Nothing -> next'), 1);
  assert.equal(await flow(['import Web.Scotty', 'import Web.Scotty.Cookie (getCookie)'], 'main :: IO ()\nmain = scotty 3000 $ get "/a" $ do\n  mc <- getCookie "theme"\n  case mc of\n    Just c -> file (show c)\n    Nothing -> next'), 1);
  assert.equal(await flow(['import Web.Scotty'], 'main :: IO ()\nmain = scotty 3000 $ get "/a" $ do\n  file "/srv/fixed.txt"'), 0, 'a constant path');
});

// ── 5. idioms the IR lowers ──────────────────────────────────────────────────

const cmdFlow = async (body, imports = []) => live(await scan({ 'src/Svc.hs': mod(['import System.Process', ...imports], body, 'module Svc (main, run) where') }), 'CWE-78').length;

test('a bind that ignores the result still runs the action, and a branch used as a statement is a sink site', async () => {
  assert.equal(await cmdFlow('main :: IO ()\nmain = getLine >>= \\c -> callCommand c >>= \\_ -> putStrLn "ok"'), 1);
  assert.equal(await cmdFlow('main :: IO ()\nmain = do\n  c <- getLine\n  if null c then putStrLn "empty" else callCommand c\n  putStrLn "done"'), 1, 'not the last statement');
  assert.equal(await cmdFlow('main :: IO ()\nmain = do\n  c <- getLine\n  case words c of\n    [] -> putStrLn "empty"\n    (w:_) -> callCommand w\n  putStrLn "done"'), 1);
  assert.equal(await cmdFlow('main :: IO ()\nmain = do\n  _ <- getLine\n  if True then putStrLn "a" else callCommand "ls"'), 0, 'nothing tainted reaches the command');
});

test('maybe, either and \\case apply their function to the value inside', async () => {
  assert.equal(await cmdFlow('main :: IO ()\nmain = do\n  mc <- fmap Just getLine\n  maybe (pure ()) callCommand mc'), 1);
  assert.equal(await cmdFlow('main :: IO ()\nmain = do\n  r <- fmap Right getLine :: IO (Either String String)\n  either putStrLn callCommand r'), 1);
  assert.equal(await cmdFlow('main :: IO ()\nmain = getLine >>= \\case\n  "" -> pure ()\n  c -> callCommand c'), 1);
  assert.equal(await cmdFlow('main :: IO ()\nmain = do\n  _ <- getLine\n  maybe (pure ()) callCommand (Just "ls")'), 0, 'a constant inside');
});

test('folds, zips and traversals over the words of a tainted line reach the command; tuple selectors keep the clean side clean', async () => {
  const imp = ['import Control.Monad', 'import Data.Foldable (traverse_)'];
  assert.equal(await cmdFlow('main :: IO ()\nmain = do\n  ws <- words <$> getLine\n  forM_ ws $ \\w -> callCommand ("ls " ++ w)', imp), 1);
  assert.equal(await cmdFlow('main :: IO ()\nmain = do\n  ws <- words <$> getLine\n  foldM (\\_ w -> callCommand w) () ws', imp), 1);
  assert.equal(await cmdFlow('main :: IO ()\nmain = do\n  ws <- words <$> getLine\n  zipWithM_ (\\i w -> callCommand (show i ++ w)) [1 :: Int ..] ws', imp), 1);
  assert.equal(await cmdFlow('main :: IO ()\nmain = do\n  ws <- words <$> getLine\n  traverse_ callCommand ws', imp), 1);
  assert.equal(await cmdFlow('main :: IO ()\nmain = do\n  a <- getLine\n  b <- getLine\n  uncurry (\\x y -> callCommand (x ++ y)) (a, b)'), 1);
  assert.equal(await cmdFlow('main :: IO ()\nmain = do\n  a <- getLine\n  callCommand (fst ("ls", a))'), 0, 'the first component is the constant');
  assert.equal(await cmdFlow('main :: IO ()\nmain = do\n  a <- getLine\n  callCommand (const "ls" a)'), 0);
});

test('a number or a letters-and-numbers filter cannot carry a command; a filter that only drops some characters can', async () => {
  const cmd = (expr) => `main :: IO ()\nmain = do\n  s <- getLine\n  callCommand ("echo " ++ ${expr})`;
  assert.equal(await cmdFlow(cmd('s')), 1);
  assert.equal(await cmdFlow(cmd('show (read s :: Int)')), 0, 'a number');
  assert.equal(await cmdFlow('main :: IO ()\nmain = do\n  s <- getLine\n  case readMaybe s :: Maybe Int of\n    Just n -> callCommand ("kill " ++ show n)\n    Nothing -> pure ()', ['import Text.Read (readMaybe)']), 0);
  assert.equal(await cmdFlow(cmd('filter isAlphaNum s'), ['import Data.Char (isAlphaNum)']), 0, 'only letters and numbers');
  assert.equal(await cmdFlow(cmd('filter (/= \';\') s')), 1, 'dropping one character is not a defence');
  assert.equal(await cmdFlow(cmd('read s :: String')), 1, 'an annotation that is text');
});

test('a let-bound lambda and a where-bound helper are functions of what they are given', async () => {
  assert.equal(await cmdFlow('main :: IO ()\nmain = do\n  c <- getLine\n  let go = \\x -> callCommand x\n  go c'), 1);
  assert.equal(await cmdFlow('main :: IO ()\nmain = do\n  c <- getLine\n  let go = \\x -> callCommand "ls" >> putStrLn x\n  go c'), 0);
  assert.equal(await cmdFlow('main :: IO ()\nmain = getLine >>= go\n  where\n    go l = callCommand l'), 1);
});

test('Servant: the parameters of a single-endpoint function are the request values the API type takes, and only text ones are sources', async () => {
  const api = (type, params, call) => ({ 'src/Svc.hs': mod(['import Servant', 'import System.Process', 'import Control.Monad.IO.Class (liftIO)'], `type API = ${type}\n\nserver :: Server API\nserver ${params} = liftIO (${call}) >> pure "ok"`, 'module Svc (server) where') });
  assert.equal(live(await scan(api('"run" :> Capture "cmd" String :> Get \'[JSON] String', 'cmd', 'callCommand cmd')), 'CWE-78').length, 1);
  assert.equal(live(await scan(api('"run" :> QueryParam "cmd" String :> Get \'[JSON] String', '(Just cmd)', 'callCommand cmd')), 'CWE-78').length, 1);
  assert.equal(live(await scan(api('"run" :> ReqBody \'[JSON] String :> Post \'[JSON] String', 'body', 'callCommand body')), 'CWE-78').length, 1);
  assert.equal(live(await scan(api('"run" :> Capture "n" Int :> Get \'[JSON] String', 'n', 'callCommand (show n)')), 'CWE-78').length, 0, 'a number');
  // the principal an auth combinator hands over is not request text
  assert.equal(live(await scan(api('AuthProtect "jwt" :> "run" :> Get \'[JSON] String', 'who', 'callCommand who')), 'CWE-78').length, 0);
});

test('record fields: a field of a record built from request values carries it, and a clean sibling does not', async () => {
  const scotty = (body) => ({ 'src/Svc.hs': mod(['import Web.Scotty', 'import System.Process', 'import Control.Monad.IO.Class (liftIO)'], `data Req = Req { reqCmd :: String, reqNote :: String }\n\nmain :: IO ()\nmain = scotty 3000 $ post "/r" $ do\n${body}`, 'module Svc (main) where') });
  assert.equal(live(await scan(scotty('  r <- Req <$> param "c" <*> param "n"\n  liftIO (callCommand (reqCmd r))')), 'CWE-78').length, 1);
  assert.equal(live(await scan(scotty('  n <- param "n"\n  let r = Req { reqCmd = "ls", reqNote = n }\n  liftIO (callCommand (reqCmd r))')), 'CWE-78').length, 0);
});
