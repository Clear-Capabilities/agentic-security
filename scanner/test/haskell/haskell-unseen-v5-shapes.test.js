// Shapes read from the unseen-v5 split on 2026-11-01, when it became a development set (see its USE-LOG.md), each pinned in both
// directions: the shape that was missed or wrongly reported, and the nearest shape whose verdict must not move with it.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { analyzeHaskellRules } from '../../src/language/haskell-security-rules.js';
import { analyzeHaskellWeb } from '../../src/language/haskell-web.js';
import { runScan } from '../../src/runScan.js';
import { mkTestTmp } from '../helpers/tmp.js';

const mod = (imports, body, header = 'module Svc where') => `${header}\n\n${imports.join('\n')}\n\n${body}\n`;
const rules = (src) => analyzeHaskellRules({ 'Svc.hs': src }).findings;
const ruleHits = (src, id) => rules(src).filter((f) => f.rule === id);
async function scan(files) {
  const dir = mkTestTmp('hs-v5-');
  writeFileSync(join(dir, 'package.json'), '{}');
  for (const [f, text] of Object.entries(files)) { mkdirSync(dirname(join(dir, f)), { recursive: true }); writeFileSync(join(dir, f), text); }
  const r = await runScan(dir, { deep: true });
  return [...(r.scan.findings || [])];
}
// a finding a default scan would act on: not lowered to information and not proven clean or infeasible
const live = (fs, cwe) => fs.filter((f) => f.cwe === cwe && f.severity !== 'info' && !(f.proof && /^proven-/.test(f.proof.verdict)));

test('Servant: a handler with closure parameters before the endpoint values pairs the API reads from the END', async () => {
  const api = (sig, body) => mod(['import Control.Monad.IO.Class (liftIO)', 'import Data.String (fromString)', 'import Data.Text (Text)', 'import qualified Data.Text as T', 'import Database.SQLite.Simple', 'import Servant'],
    `type OrderApi = "orders" :> QueryParam' '[Required] "ref" Text :> Get '[JSON] [Text]\n\n${sig}\n${body}\n\nordersByReference :: Connection -> Text -> IO [Text]\nordersByReference conn ref = do\n  let statement = "SELECT sku FROM order_lines WHERE reference = '" <> T.unpack ref <> "'"\n  rows <- query_ conn (fromString statement) :: IO [Only Text]\n  pure (map fromOnly rows)`, '{-# LANGUAGE DataKinds, TypeOperators, OverloadedStrings #-}\nmodule Svc (OrderApi, orderServer) where');
  const closure = await scan({ 'src/Svc.hs': api('orderServer :: Connection -> Server OrderApi', 'orderServer conn ref = liftIO (ordersByReference conn ref)') });
  assert.equal(live(closure, 'CWE-89').length, 1, 'the query parameter is the LAST handler parameter, `conn` comes from the closure');
  // a handler with fewer parameters than the API names is not paired at all (nothing is guessed)
  const short = await scan({ 'src/Svc.hs': api('orderServer :: Server OrderApi', 'orderServer = \\ref -> liftIO (ordersByReference undefined ref)') });
  assert.ok(Array.isArray(short));
});

test('cookie: a Set-Cookie header handed to the framework setter is judged like a hand-written tuple', () => {
  const imports = ['import qualified Data.Text.Lazy as TL', 'import Web.Scotty'];
  const route = (hdr) => mod(imports, `data Session = Session { sessionToken :: TL.Text }\n\nsignIn :: ScottyM ()\nsignIn = post "/sign-in" $ do\n  session <- pure (Session "s_1")\n  ${hdr}\n  redirect "/dashboard"`);
  assert.equal(ruleHits(route('setHeader "Set-Cookie" ("session=" <> sessionToken session <> "; Path=/; Max-Age=86400")'), 'hs-insecure-cookie').length, 1);
  assert.equal(ruleHits(route('setHeader "Set-Cookie" ("session=" <> sessionToken session <> "; Path=/; Secure; HttpOnly")'), 'hs-insecure-cookie').length, 0);
  assert.equal(ruleHits(route('setHeader "Cache-Control" ("private, max-age=" <> sessionToken session)'), 'hs-insecure-cookie').length, 0, 'another header');
});

test('inlined helper: a fast password hash or a credential log in a helper is reported once, in the helper, not again at the call', () => {
  const hashSrc = mod(['import Crypto.Hash (SHA1 (..), hashWith)', 'import qualified Data.ByteArray.Encoding as BA', 'import qualified Data.ByteString as BS', 'import Data.Text (Text)', 'import qualified Data.Text.Encoding as TE'],
    'check :: BS.ByteString -> Text -> Bool\ncheck stored pw = stored == digestFor pw\n\ndigestFor :: Text -> BS.ByteString\ndigestFor pw = BA.convertToBase BA.Base16 (hashWith SHA1 (TE.encodeUtf8 pw))');
  const hashes = ruleHits(hashSrc, 'hs-fast-password-hash');
  assert.equal(hashes.length, 1, JSON.stringify(hashes.map((f) => f.line)));
  assert.equal(hashes[0].line, 13, 'in the helper');
  const logSrc = mod(['import Data.Text (Text)', 'import qualified Data.Text as T', 'import System.Log.FastLogger (LoggerSet, pushLogStrLn, toLogStr)'],
    'trace :: LoggerSet -> Text -> IO ()\ntrace logger authorization = logRequest logger "GET /x" authorization\n\nlogRequest :: LoggerSet -> Text -> Text -> IO ()\nlogRequest logger route authorization = pushLogStrLn logger (toLogStr (T.concat ["route=", route, " authorization=", authorization]))');
  const logs = ruleHits(logSrc, 'hs-sensitive-logging');
  assert.equal(logs.length, 1, JSON.stringify(logs.map((f) => f.line)));
  assert.equal(logs[0].line, 11, 'fast-logger is a log sink, reported in the helper');
  // the call site is kept when only the CALL names the credential (the helper's own parameter does not)
  const onlyCaller = mod(['import qualified Data.Text as T', 'import System.IO (hPutStrLn, stderr)'], 'audit :: T.Text -> IO ()\naudit password = emitLine password\n\nemitLine :: T.Text -> IO ()\nemitLine s = hPutStrLn stderr (T.unpack s)');
  assert.ok(ruleHits(onlyCaller, 'hs-sensitive-logging').length >= 1);
});

test('randomness: mwc-random is a statistical generator; a function that makes a key is security-shaped; `code` is a one-time code where the function talks about a reset', () => {
  const mwc = mod(['import Control.Monad (replicateM)', 'import Data.Text (Text)', 'import qualified Data.Text as T', 'import System.Random.MWC (createSystemRandom, uniformR)'],
    'alphabet :: String\nalphabet = [\'a\'..\'z\']\n\nnewKey :: IO Text\nnewKey = do\n  gen <- createSystemRandom\n  picks <- replicateM 40 (uniformR (0, length alphabet - 1) gen)\n  pure (T.pack (map (alphabet !!) picks))');
  assert.equal(ruleHits(mwc, 'hs-predictable-random').length, 1);
  const entropy = mod(['import Data.Text (Text)', 'import qualified Data.Text as T', 'import System.Entropy (getEntropy)', 'import qualified Data.ByteString.Base64.URL as B64', 'import qualified Data.Text.Encoding as TE'],
    'newKey :: IO Text\nnewKey = do\n  bytes <- getEntropy 32\n  pure (TE.decodeUtf8 (B64.encode bytes))');
  assert.equal(ruleHits(entropy, 'hs-predictable-random').length, 0, 'the OS entropy source');
  const reset = (sql) => mod(['import Control.Monad (replicateM)', 'import qualified Data.Text as T', 'import Database.PostgreSQL.Simple', 'import System.Random (randomRIO)'],
    `issue :: Connection -> T.Text -> IO ()\nissue conn email = do\n  code <- replicateM 6 (randomRIO ('0', '9'))\n  _ <- execute conn "${sql}" (email, code)\n  pure ()`);
  assert.equal(ruleHits(reset('INSERT INTO reset_codes (email, code) VALUES (?, ?)'), 'hs-predictable-random').length, 1, 'a reset code');
  assert.equal(ruleHits(reset('INSERT INTO promo_codes (email, code) VALUES (?, ?)'), 'hs-predictable-random').length, 0, 'a promotion code is not a security value by that name');
});

test('routes: an authentication endpoint is public by construction; a credential header the project names itself guards the handler, and an object read behind it without ownership is reported', () => {
  const yesod = analyzeHaskellWeb({ 'src/Login.hs': mod(['import Yesod', 'import Foundation', 'import Model'], 'postMemberLoginR :: Handler Html\npostMemberLoginR = do\n  creds <- runInputPost credentialsForm\n  runDB (insert_ (LoginEvent (credEmail creds)))\n  redirect HomeR', '{-# LANGUAGE OverloadedStrings, TypeFamilies #-}\nmodule Login (postMemberLoginR) where') });
  assert.equal(yesod.findings.filter((f) => f.rule === 'hs-route-missing-auth').length, 0, 'a login POST carries no session yet');
  const scotty = (path) => mod(['import Control.Monad.IO.Class (liftIO)', 'import qualified Data.Text.Lazy as TL', 'import Database.PostgreSQL.Simple', 'import Network.HTTP.Types.Status (status401, status404)', 'import Web.Scotty'],
    `currentUser :: Connection -> ActionM Int\ncurrentUser conn = do\n  token <- header "X-Session"\n  rows <- maybe (pure []) (\\t -> liftIO (query conn "SELECT user_id FROM sessions WHERE token = ?" (Only (TL.toStrict t)))) token\n  case rows of\n    (Only uid : _) -> pure uid\n    []             -> status status401 >> text "sign in first" >> finish\n\nroutes :: Connection -> ScottyM ()\nroutes conn =\n  get "${path}" $ do\n    _ <- currentUser conn\n    invoiceId <- param "id"\n    rows <- liftIO (query conn "SELECT number FROM invoices WHERE id = ?" (Only (invoiceId :: Int))) :: ActionM [Only TL.Text]\n    case rows of\n      (Only n : _) -> text n\n      []           -> status status404 >> text "no such invoice"`, '{-# LANGUAGE OverloadedStrings #-}\nmodule Invoices (routes) where');
  const r = analyzeHaskellWeb({ 'src/Invoices.hs': scotty('/invoices/:id') });
  assert.equal(r.routes[0].auth.status, 'authenticated', JSON.stringify(r.routes[0].auth));
  assert.equal(r.findings.filter((f) => f.rule === 'hs-route-bola').length, 1);
  const owned = analyzeHaskellWeb({ 'src/Invoices.hs': scotty('/invoices/:id').replace('_ <- currentUser conn', 'uid <- currentUser conn').replace('WHERE id = ?" (Only (invoiceId :: Int))', 'WHERE id = ? AND owner_id = ?" (invoiceId :: Int, uid)') });
  assert.equal(owned.findings.filter((f) => f.rule === 'hs-route-bola').length, 0, 'the lookup names the owner');
  const nonCredential = analyzeHaskellWeb({ 'src/Invoices.hs': scotty('/invoices/:id').replace('header "X-Session"', 'header "X-Request-Id"') });
  assert.notEqual(nonCredential.routes[0].auth.status, 'authenticated', 'a request id is not a credential');
});

test('ssrf: a URL that starts from a literal naming the host, or a request built over a fixed base, lets the client choose only the path or query', async () => {
  const scotty = (url) => mod(['import Control.Monad.IO.Class (liftIO)', 'import qualified Data.ByteString.Lazy as BL', 'import qualified Data.Text.Lazy as TL', 'import Network.HTTP.Client', 'import Network.HTTP.Client.TLS (tlsManagerSettings)', 'import Web.Scotty'],
    `deliveryBase :: String\ndeliveryBase = "https://hooks.example.internal/deliveries/"\n\nroutes :: ScottyM ()\nroutes = do\n  manager <- liftIO (newManager tlsManagerSettings)\n  post "/replay" $ do\n    deliveryId <- param "delivery"\n    request <- liftIO (parseRequest (${url}))\n    response <- liftIO (httpLbs request { method = "POST" } manager)\n    raw (BL.take 2048 (responseBody response))`, '{-# LANGUAGE OverloadedStrings #-}\nmodule Replay (routes) where');
  const anchored = await scan({ 'src/Replay.hs': scotty('deliveryBase <> TL.unpack deliveryId') });
  assert.equal(live(anchored, 'CWE-918').length, 0, JSON.stringify(anchored.filter((f) => f.cwe === 'CWE-918').map((f) => [f.line, f.severity, f.guardNote])));
  assert.ok(anchored.some((f) => f.cwe === 'CWE-918' && f.severity === 'info' && f.guardNote && f.guardNote.kind === 'fixed-host-request'), 'kept as information with the reason');
  const whole = await scan({ 'src/Replay.hs': scotty('TL.unpack deliveryId') });
  assert.equal(live(whole, 'CWE-918').length, 1, 'the client names the whole URL');
  const noSlash = await scan({ 'src/Replay.hs': scotty('"https://hooks" <> TL.unpack deliveryId') });
  assert.equal(live(noSlash, 'CWE-918').length, 1, 'a literal that stops inside the host lets the client finish the host name');
  const spock = (req) => mod(['import Control.Monad.IO.Class (liftIO)', 'import qualified Data.ByteString.Lazy as BL', 'import Data.Text (Text)', 'import qualified Data.Text.Encoding as TE', 'import Network.HTTP.Simple', 'import Web.Spock'],
    `catalogRequest :: Request\ncatalogRequest = "https://catalog.example.internal/feeds/search"\n\nsearchFeeds :: Text -> IO BL.ByteString\nsearchFeeds term = do\n  let request = ${req}\n  response <- httpLBS request\n  pure (getResponseBody response)\n\napp :: SpockM () () () ()\napp = get "feeds/search" $ do\n  term <- param' "q"\n  found <- liftIO (searchFeeds term)\n  lazyBytes found`, '{-# LANGUAGE OverloadedStrings #-}\nmodule Feeds (app) where');
  const query = await scan({ 'src/Feeds.hs': spock('setRequestQueryString [("q", Just (TE.encodeUtf8 term))] catalogRequest') });
  assert.equal(live(query, 'CWE-918').length, 0, 'a query string on a fixed request');
  const host = await scan({ 'src/Feeds.hs': spock('setRequestHost (TE.encodeUtf8 term) catalogRequest') });
  assert.equal(live(host, 'CWE-918').length, 1, 'the host set from the client is the forgery');
});

test('path: a canonicalise-and-prefix guard in the HELPER that holds the sink refutes the flow found from its caller', async () => {
  const happstack = (guard) => mod(['import Control.Monad.IO.Class (liftIO)', 'import Data.List (isPrefixOf)', 'import qualified Data.Text as T', 'import qualified Data.Text.IO as TIO', 'import Happstack.Server', 'import System.Directory (canonicalizePath)', 'import System.FilePath ((</>), (<.>), addTrailingPathSeparator)'],
    `data Draft = Draft { draftTitle :: T.Text, draftBody :: T.Text }\n\nsaveDraft :: ServerPart Response\nsaveDraft = do\n  method POST\n  title <- T.pack <$> look "title"\n  body  <- T.pack <$> look "body"\n  stored <- liftIO (persistDraft (Draft title body))\n  ok (toResponse (if stored then "saved" else "rejected" :: T.Text))\n\npersistDraft :: Draft -> IO Bool\npersistDraft d = do\n  base <- addTrailingPathSeparator <$> canonicalizePath "drafts"\n  full <- canonicalizePath ("drafts" </> T.unpack (draftTitle d) <.> "md")\n  ${guard}`, '{-# LANGUAGE OverloadedStrings #-}\nmodule Drafts (saveDraft) where');
  const guarded = await scan({ 'src/Drafts.hs': happstack('if base `isPrefixOf` full\n    then TIO.writeFile full (draftBody d) >> pure True\n    else pure False') });
  assert.equal(live(guarded, 'CWE-22').length, 0, JSON.stringify(guarded.filter((f) => f.cwe === 'CWE-22').map((f) => [f.line, f.severity, f.proof && f.proof.verdict])));
  const unguarded = await scan({ 'src/Drafts.hs': happstack('TIO.writeFile full (draftBody d) >> pure True') });
  assert.equal(live(unguarded, 'CWE-22').length, 1);
});

test('xss: a blaze helper that escapes its parameter is an escaper for the caller\'s sink; one that renders it pre-escaped is not', async () => {
  const page = (helperBody) => mod(['import qualified Data.Text.Lazy as TL', 'import Text.Blaze.Html.Renderer.Text (renderHtml)', 'import Text.Blaze.Html5 (Html, toHtml, preEscapedToHtml)', 'import qualified Text.Blaze.Html5 as H', 'import Web.Scotty'],
    `pageShell :: Html -> Html\npageShell inner = H.docTypeHtml $ do\n  H.head (H.title "Site")\n  H.body inner\n\nroutes :: ScottyM ()\nroutes =\n  get "/welcome" $ do\n    name <- param "name" \`rescue\` (\\_ -> pure ("there" :: TL.Text))\n    html (renderHtml (pageShell (greeting name)))\n\ngreeting :: TL.Text -> Html\ngreeting name = do\n  ${helperBody}\n  H.p "Your dashboard is ready."`, '{-# LANGUAGE OverloadedStrings #-}\nmodule Welcome (routes) where');
  const escaped = await scan({ 'src/Welcome.hs': page('H.h1 ("Welcome back, " <> toHtml name)') });
  assert.equal(live(escaped, 'CWE-79').length, 0, JSON.stringify(escaped.filter((f) => f.cwe === 'CWE-79').map((f) => [f.line, f.severity, f.proof && f.proof.verdict])));
  const raw = await scan({ 'src/Welcome.hs': page('H.h1 ("Welcome back, " <> preEscapedToHtml name)') });
  assert.equal(live(raw, 'CWE-79').length, 1, 'the pre-escaped combinator keeps the markup');
});

test('sensitive logging: a record built from a credential logged through another field, a yes/no answer about it, and a masked card number are not the secret', () => {
  const imports = ['import qualified Data.Text as T', 'import System.IO (hPutStrLn, stderr)'];
  const attempt = (logged) => mod(imports, `data Attempt = Attempt { attemptUser :: T.Text, attemptPassword :: T.Text }\n\ncheckCredentials :: Attempt -> IO Bool\ncheckCredentials a = pure (attemptUser a == "demo" && attemptPassword a == "demo-pass")\n\nlogin :: T.Text -> T.Text -> IO ()\nlogin user password = do\n  let attempt = Attempt user password\n  accepted <- checkCredentials attempt\n  hPutStrLn stderr (${logged})`);
  assert.equal(ruleHits(attempt('"login attempt user=" <> T.unpack (attemptUser attempt) <> " accepted=" <> show accepted'), 'hs-sensitive-logging').length, 0);
  assert.equal(ruleHits(attempt('"login attempt " <> T.unpack (attemptPassword attempt)'), 'hs-sensitive-logging').length, 1, 'the credential field itself');
  assert.equal(ruleHits(attempt('"login attempt " <> show attempt'), 'hs-sensitive-logging').length, 1, 'the whole record');
  const card = (shown) => mod(['import Data.Text (Text)', 'import qualified Data.Text as T', 'import Katip'], `data CardPayment = CardPayment { cardNumber :: Text, orderRef :: Text }\n\nlastFour :: Text -> Text\nlastFour = T.takeEnd 4\n\ncharge :: KatipContext m => CardPayment -> m ()\ncharge payment = logFM InfoS (ls ("charging " <> orderRef payment <> " card " <> ${shown}))`);
  assert.equal(ruleHits(card('lastFour (cardNumber payment)'), 'hs-sensitive-logging').length, 0, 'a masking helper by name');
  assert.equal(ruleHits(card('cardNumber payment'), 'hs-sensitive-logging').length, 1);
});
