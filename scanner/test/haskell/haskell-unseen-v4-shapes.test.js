// Haskell shapes the unseen-v4 split missed (it became a DEVELOPMENT set on 2026-11-01; unseen-v5 is the generalisation measure). Every change
// made for them is pinned here in BOTH directions: the vulnerable form is found and a near-miss that shares its surface is not. The sources are
// written for this file; none is copied from a corpus case.
//
// Groups: 1 rules (request reads as caller text for the partial-function and allocation rules, a presence test that does not cover a split, a
// relational test on a count, randomness reaching a token function's result, a sensitive record logged whole, wai-extra's size check), 2 web
// (Servant closure arguments before the endpoint's values, a Map lookup as the object selection, owner evidence from a column or a record field,
// a handler typed by the framework but registered elsewhere, a Yesod isAuthorized clause with a rejection path, a state-changing route whose
// handler calls something the engine cannot see into, `Auth '[JWT] Admin`), 3 taint (an uploaded file's name, a raw WAI response that says
// text/html, an escaper reached through two local bindings, a hamlet interpolation).

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { analyzeHaskellRules } from '../../src/language/haskell-security-rules.js';
import { analyzeHaskellWeb } from '../../src/language/haskell-web.js';
import { hamletInterpolations, preprocessForSyntax } from '../../src/language/haskell-parser.js';
import { runScan } from '../../src/runScan.js';
import { mkTestTmp } from '../helpers/tmp.js';

const rules = (src, name = 'Svc.hs') => analyzeHaskellRules({ [name]: src }).findings;
const ruleIds = (src) => rules(src).map((f) => f.rule);
const has = (src, rule) => ruleIds(src).includes(rule);
const mod = (imports, body, header = 'module Svc where') => `${header}\n\n${imports.join('\n')}\n\n${body}\n`;
const web = (files) => analyzeHaskellWeb(files).findings;
const ruleOf = (fs, rule) => fs.filter((f) => f.rule === rule);

async function scan(files) {
  const dir = mkTestTmp('hs-v4-');
  writeFileSync(join(dir, 'package.json'), '{}');
  for (const [f, text] of Object.entries(files)) { mkdirSync(dirname(join(dir, f)), { recursive: true }); writeFileSync(join(dir, f), text); }
  const r = await runScan(dir, { deep: true });
  return [...(r.scan.findings || [])];
}
const live = (fs, cwe) => fs.filter((f) => f.parser === 'IR-TAINT' && f.cwe === cwe && f.severity !== 'info' && !f._provenUnreachable && !(f.proof && /^proven-/.test(f.proof.verdict)));

// ── 1. rules ─────────────────────────────────────────────────────────────────

test('a value read from the request inside the handler is caller text for the partial-function rule, whatever the parameters are', () => {
  const page = (expr) => mod(['import Web.Scotty', 'import qualified Data.Text.Lazy as TL', 'import Text.Read (readMaybe)', 'import Data.Maybe (fromMaybe)'], `listPage :: ActionM ()\nlistPage = do\n  raw <- param "page"\n  let page = ${expr} :: Int\n  json [page * 20 .. page * 20 + 19]`);
  assert.ok(has(page('read (TL.unpack raw)'), 'hs-partial-function-on-input'), '`read` of a request parameter');
  assert.ok(!has(page('fromMaybe 1 (readMaybe (TL.unpack raw))'), 'hs-partial-function-on-input'), 'the total parser with a default');
  const body = (expr) => mod(['import Data.Aeson', 'import Data.Maybe (fromJust)', 'import Network.Wai', 'import qualified Data.ByteString.Lazy as BL'], `data Item = Item { name :: String }\ninstance FromJSON Item where\n  parseJSON = withObject "Item" $ \\o -> Item <$> o .: "name"\n\ncreateItem :: Request -> IO Item\ncreateItem req = do\n  body <- strictRequestBody req\n  ${expr}`);
  assert.ok(has(body('pure (fromJust (decode body))'), 'hs-partial-function-on-input'), '`fromJust` of a decoded request body');
  assert.ok(!has(body('if isJust (decode body) then pure (fromJust (decode body)) else fail "bad"'), 'hs-partial-function-on-input'), 'the same decode of the same value was tested');
  assert.ok(!has(body('maybe (fail "bad") pure (decode body)'), 'hs-partial-function-on-input'));
});

test('a presence test on a header does not cover `!!` on its words; a test of the split value does', () => {
  const hdr = (body) => mod(['import Network.Wai', 'import Network.HTTP.Types.Header (hAuthorization)', 'import qualified Data.ByteString.Char8 as B'], `bearerToken :: Request -> B.ByteString\nbearerToken req = ${body}\n  where\n    auth = maybe B.empty id (lookup hAuthorization (requestHeaders req))`, 'module Svc (bearerToken) where');
  assert.ok(has(hdr('B.words auth !! 1'), 'hs-partial-function-on-input'), 'a header with one word raises');
  assert.ok(!has(hdr('case B.words auth of\n    (_ : t : _) -> t\n    _ -> B.empty'), 'hs-partial-function-on-input'), 'a total match');
  const ws = mod(['import Network.Wai', 'import Network.HTTP.Types.Header (hAuthorization)', 'import qualified Data.ByteString.Char8 as B'], `bearerToken :: Request -> B.ByteString\nbearerToken req = if length ws < 2 then B.empty else ws !! 1\n  where\n    auth = maybe B.empty id (lookup hAuthorization (requestHeaders req))\n    ws = B.words auth`, 'module Svc (bearerToken) where');
  assert.ok(!has(ws, 'hs-partial-function-on-input'), 'the length of the split value was tested');
});

test('a count the framework parsed from the request sizes an allocation; a relational test on it or a clamp bounds it', () => {
  const bulk = (body) => mod(['import Web.Scotty', 'import Network.HTTP.Types.Status (status400)', 'import Control.Monad (replicateM_)', 'import Control.Monad.IO.Class (liftIO)', 'import Data.IORef'], `maxBatch :: Int\nmaxBatch = 100\n\nbulkCreate :: IORef Int -> ActionM ()\nbulkCreate counter = do\n  n <- param "count" :: ActionM Int\n${body}`);
  assert.ok(has(bulk('  replicateM_ n (liftIO (modifyIORef\' counter (+1)))\n  text "ok"'), 'hs-unbounded-allocation'));
  assert.ok(!has(bulk('  if n < 0 || n > maxBatch\n    then status status400 >> text "count out of range"\n    else do\n      replicateM_ n (liftIO (modifyIORef\' counter (+1)))\n      text "ok"'), 'hs-unbounded-allocation'), 'a relational test on the count');
  assert.ok(!has(bulk('  replicateM_ (min maxBatch n) (liftIO (modifyIORef\' counter (+1)))\n  text "ok"'), 'hs-unbounded-allocation'), 'a clamp');
});

test('a System.Random value that reaches the result of a token-shaped function is predictable randomness; a shuffle in an ordinary function is not', () => {
  const key = mod(['import System.Random (newStdGen, randoms)', 'import Numeric (showHex)', 'import Data.Word (Word8)'], `generateApiKey :: IO String\ngenerateApiKey = do\n  g <- newStdGen\n  let bytes = take 16 (randoms g) :: [Word8]\n  pure (concatMap (\`showHex\` "") bytes)`, 'module Svc (generateApiKey) where');
  assert.ok(has(key, 'hs-predictable-random'));
  const strong = mod(['import Crypto.Random (getRandomBytes)', 'import qualified Data.ByteString as B', 'import Numeric (showHex)'], `generateApiKey :: IO String\ngenerateApiKey = do\n  bytes <- getRandomBytes 16 :: IO B.ByteString\n  pure (concatMap (\`showHex\` "") (B.unpack bytes))`, 'module Svc (generateApiKey) where');
  assert.ok(!has(strong, 'hs-predictable-random'));
  const shuffle = mod(['import System.Random (newStdGen, randomRs)'], `featuredOrder :: [Int] -> IO [Int]\nfeaturedOrder ids = do\n  g <- newStdGen\n  let ks = take (length ids) (randomRs (0, 1000) g) :: [Int]\n  pure (map snd (zip ks ids))`, 'module Svc (featuredOrder) where');
  assert.ok(!has(shuffle, 'hs-predictable-random'), 'not a security-shaped function');
});

test('a record with a card or credential field written to a log whole is sensitive logging; the same record through a masking helper is not', () => {
  const pay = (expr) => mod(['import System.IO'], `data Card = Card { cardNumber :: String, cardCvv :: String, cardHolder :: String } deriving Show\n\nmasked :: Card -> String\nmasked c = replicate 12 '*' ++ drop 12 (cardNumber c)\n\ncharge :: Card -> Int -> IO ()\ncharge card cents = do\n  hPutStrLn stderr ("charging " ++ show cents ++ " cents to " ++ ${expr})\n  pure ()`, 'module Svc (charge) where');
  assert.ok(has(pay('show card'), 'hs-sensitive-logging'), '`show` of the whole record');
  assert.ok(!has(pay('masked card'), 'hs-sensitive-logging'), 'a masking helper by name');
  assert.ok(!has(pay('cardHolder card'), 'hs-sensitive-logging'), 'a field that is not sensitive');
  const plain = mod(['import System.IO'], `data Order = Order { orderId :: Int, orderTotal :: Int } deriving Show\n\nship :: Order -> IO ()\nship o = hPutStrLn stderr ("shipping " ++ show o)`, 'module Svc (ship) where');
  assert.ok(!has(plain, 'hs-sensitive-logging'), 'a record with no sensitive field');
});

test('wai-extra requestSizeCheck bounds the body read that follows it', () => {
  const rd = (body) => mod(['import Network.Wai', 'import Network.Wai.Request (requestSizeCheck)', 'import qualified Data.ByteString.Lazy as BL'], `readBody :: Request -> IO BL.ByteString\nreadBody req = do\n${body}`, 'module Svc (readBody) where');
  assert.ok(has(rd('  strictRequestBody req'), 'hs-unbounded-request-body'));
  assert.ok(!has(rd('  checked <- requestSizeCheck (Just 65536) req\n  strictRequestBody checked'), 'hs-unbounded-request-body'));
});

// ── 2. web ───────────────────────────────────────────────────────────────────

test('Servant: closure arguments before the endpoint values are paired from the end; a Map lookup by the capture is the object selection', () => {
  const inv = (sel) => ({ 'Invoices.hs': mod(['import Servant', 'import qualified Data.Map.Strict as M', 'import Control.Monad.IO.Class (liftIO)', 'import Data.IORef'],
    `data Invoice = Invoice { invOwner :: Int, invTotal :: Int }\n\ntype InvoiceAPI = Capture "invoiceId" Int :> Get '[JSON] Int\n\ninvoiceById :: IORef (M.Map Int Invoice) -> Int -> Server InvoiceAPI\ninvoiceById store currentUser invoiceId = do\n  m <- liftIO (readIORef store)\n  case M.lookup invoiceId m of\n${sel}\n    _ -> throwError err404`, 'module Invoices (invoiceById) where') });
  assert.equal(ruleOf(web(inv('    Just inv -> pure (invTotal inv)')), 'hs-route-bola').length, 1, 'the owner field is never read');
  assert.equal(ruleOf(web(inv('    Just inv | invOwner inv == currentUser -> pure (invTotal inv)')), 'hs-route-bola').length, 0, 'the owner field decides');
});

test('a Scotty handler typed by the framework but registered elsewhere is judged for ownership by the statement it runs', () => {
  const doc = (sql, args) => ({ 'Documents.hs': mod(['import Web.Scotty', 'import Network.HTTP.Types.Status (status404)', 'import Database.SQLite.Simple', 'import qualified Data.Text as T', 'import qualified Data.Text.Lazy as TL'],
    `data Doc = Doc Int Int T.Text\ninstance FromRow Doc where\n  fromRow = Doc <$> field <*> field <*> field\n\ngetDocument :: Connection -> Int -> ActionM ()\ngetDocument conn currentUser = do\n  docId <- param "id" :: ActionM Int\n  docs <- liftAndCatchIO (query conn "${sql}" ${args} :: IO [Doc])\n  case docs of\n    (Doc _ _ body : _) -> text (TL.fromStrict body)\n    [] -> status status404 >> text "not found"`, 'module Documents (getDocument) where') });
  const fs = web(doc('SELECT id, owner_id, body FROM documents WHERE id = ?', '(Only docId)'));
  assert.equal(ruleOf(fs, 'hs-route-bola').length, 1, 'the statement names owner_id and its WHERE clause does not use it');
  assert.equal(ruleOf(fs, 'hs-route-missing-auth').length, 0, 'no method is known, so no authentication finding');
  assert.equal(ruleOf(web(doc('SELECT id, owner_id, body FROM documents WHERE id = ? AND owner_id = ?', '(docId, currentUser)')), 'hs-route-bola').length, 0, 'the owner column is in the WHERE clause');
  assert.equal(ruleOf(web(doc('SELECT id, title FROM articles WHERE id = ?', '(Only docId)')), 'hs-route-bola').length, 0, 'nothing says the object has an owner');
});

test('an unauthenticated write to an object the client selected is both a missing authentication and an object authorization finding', () => {
  const yes = (pre) => ({ 'Profiles.hs': mod(['import Yesod', 'import Database.Persist.Sql', 'import qualified Data.Text as T'],
    `data App = App\nmkYesod "App" [parseRoutes| /profile/#Int64 ProfileR PUT |]\ninstance Yesod App\n\nputProfileR :: Int64 -> Handler Value\nputProfileR pid = do\n${pre}  newBio <- requireJsonBody :: Handler T.Text\n  runDB (update (toSqlKey pid) [ProfileBio =. newBio])\n  returnJson ("updated" :: T.Text)`, '{-# LANGUAGE QuasiQuotes, TemplateHaskell, TypeFamilies, OverloadedStrings #-}\nmodule Profiles (putProfileR) where') });
  const fs = web(yes(''));
  assert.equal(ruleOf(fs, 'hs-route-missing-auth').length, 1);
  assert.equal(ruleOf(fs, 'hs-route-bola').length, 1);
  const owned = web(yes('  uid <- requireAuthId\n  mProfile <- runDB (get (toSqlKey pid))\n  case mProfile of\n    Just p | profileUser p == uid -> pure ()\n    _ -> permissionDenied "not your profile"\n'));
  assert.equal(ruleOf(owned, 'hs-route-missing-auth').length, 0);
  assert.equal(ruleOf(owned, 'hs-route-bola').length, 0);
});

test('Yesod isAuthorized: a clause that can answer AuthenticationRequired guards the route; a clause that only answers Authorized is public', () => {
  const site = (authz) => ({ 'Settings.hs': mod(['import Yesod', 'import Database.Persist.Sql', 'import qualified Data.Text as T'],
    `data App = App\nmkYesod "App" [parseRoutes|\n/settings/reset-all ResetR POST\n|]\n\ninstance Yesod App${authz}\n\npostResetR :: Handler Html\npostResetR = do\n  runDB (deleteWhere ([] :: [Filter Setting]))\n  redirect ResetR`, '{-# LANGUAGE QuasiQuotes, TemplateHaskell, TypeFamilies, OverloadedStrings #-}\nmodule Settings (postResetR) where') });
  assert.equal(ruleOf(web(site('')), 'hs-route-missing-auth').length, 1, 'a POST route with no guard that deletes rows');
  assert.equal(ruleOf(web(site(' where\n  isAuthorized ResetR _ = do\n    mu <- lookupSession "user"\n    pure (maybe AuthenticationRequired (const Authorized) mu)')), 'hs-route-missing-auth').length, 0, 'the clause can refuse');
  assert.equal(ruleOf(web(site(' where\n  isAuthorized ResetR _ = pure Authorized')), 'hs-route-missing-auth').length, 1, 'the clause can only allow');
});

test('a privileged route whose handler calls into unseen code is reported at a lower severity; a plain write with no visible operation is not', () => {
  const api = (pathSeg, handler) => ({ 'Export.hs': mod(['import Servant', 'import Control.Monad.IO.Class (liftIO)'],
    `type ExportAPI = "${pathSeg}" :> "export" :> "customers" :> Post '[PlainText] String\n\nexportApi :: IO [String] -> Server ExportAPI\nexportApi loadAll = ${handler}`, 'module Export (exportApi) where') });
  const unseen = ruleOf(web(api('internal', 'liftIO (unlines <$> loadAll)')), 'hs-route-missing-auth');
  assert.equal(unseen.length, 1, 'a privileged path whose handler calls a parameter');
  assert.equal(unseen[0].severity, 'medium');
  assert.match(unseen[0].description, /no database, file or process operation is visible/);
  assert.equal(ruleOf(web(api('internal', 'pure "ok"')), 'hs-route-missing-auth').length, 0, 'nothing but a response');
  assert.equal(ruleOf(web(api('public', 'liftIO (unlines <$> loadAll)')), 'hs-route-missing-auth').length, 0, 'a POST on an ordinary path with no visible operation: an echo, an upload demo or a health check on real projects');
});

test('Servant `Auth \'[JWT] Admin` names the role: an authenticated privileged route with it has no function-authorization finding', () => {
  const api = (auth, pats) => ({ 'Export.hs': mod(['import Servant', 'import Servant.Auth.Server', 'import Control.Monad.IO.Class (liftIO)'],
    `data Admin = Admin\ndata Member = Member\n\ntype ExportAPI = ${auth} :> "internal" :> "export" :> "customers" :> Get '[PlainText] String\n\nexportApi :: IO [String] -> Server ExportAPI\nexportApi loadAll ${pats} = liftIO (unlines <$> loadAll)\nexportApi _ _ = throwAll err401`, 'module Export (exportApi) where') });
  assert.equal(ruleOf(web(api("Auth '[JWT] Admin", '(Authenticated _)')), 'hs-route-bfla').length, 0);
  assert.equal(ruleOf(web(api("Auth '[JWT] Member", '(Authenticated _)')), 'hs-route-bfla').length, 1, 'authenticated as any member, on an internal path');
});

// ── 3. taint ─────────────────────────────────────────────────────────────────

test('the name of an uploaded file is request input: spliced into a path it is a traversal; reduced to a file name it is not', async () => {
  const up = (target) => ({ 'src/Uploads.hs': mod(['import Network.Wai.Parse (FileInfo(..))', 'import System.FilePath (takeFileName)', 'import qualified Data.ByteString.Char8 as B', 'import qualified Data.ByteString.Lazy as BL'], `saveUpload :: FileInfo BL.ByteString -> IO ()\nsaveUpload fi = do\n  let target = ${target}\n  BL.writeFile target (fileContent fi)`, 'module Uploads (saveUpload) where') });
  assert.equal(live(await scan(up('"/srv/uploads/" ++ B.unpack (fileName fi)')), 'CWE-22').length, 1);
  assert.equal(live(await scan(up('"/srv/uploads/" ++ takeFileName (B.unpack (fileName fi))')), 'CWE-22').length, 0);
});

test('a raw WAI response is an HTML context only when its headers say text/html; a hand-written escaper behind two bindings neutralises it', async () => {
  const page = (ctype, pathExpr) => ({ 'src/ErrorPage.hs': mod(['import Network.Wai', 'import Network.HTTP.Types', 'import qualified Data.ByteString.Char8 as B', 'import qualified Data.ByteString.Lazy.Char8 as BL'],
    `escape :: String -> String\nescape = concatMap f\n  where\n    f '<' = "&lt;"\n    f '>' = "&gt;"\n    f '&' = "&amp;"\n    f c = [c]\n\nnotFoundPage :: Request -> Response\nnotFoundPage req =\n  responseLBS status404 [(hContentType, B.pack "${ctype}")] page\n  where\n    path = ${pathExpr}\n    page = BL.pack ("<html><body><p>No such page: " ++ path ++ "</p></body></html>")`, 'module ErrorPage (notFoundPage) where') });
  assert.equal(live(await scan(page('text/html', 'B.unpack (rawPathInfo req)')), 'CWE-79').length, 1);
  assert.equal(live(await scan(page('text/plain', 'B.unpack (rawPathInfo req)')), 'CWE-79').length, 0, 'the body is not served as HTML');
  assert.equal(live(await scan(page('text/html', 'escape (B.unpack (rawPathInfo req))')), 'CWE-79').length, 0, 'escaped, through `path` and `page`');
});

test('hamlet: a pre-escaped interpolation of a request value is XSS; a plain interpolation is escaped by hamlet; a borrowed quoter name stays opaque', async () => {
  const yes = (interp, imports = ['import Yesod', 'import Text.Blaze.Html (preEscapedToHtml)', 'import qualified Data.Text as T']) => ({ 'src/Comments.hs': mod(imports,
    `data Site = Site\nmkYesod "Site" [parseRoutes| /comment/#T.Text CommentR GET |]\ninstance Yesod Site\n\ngetCommentR :: T.Text -> Handler Html\ngetCommentR body = defaultLayout $ do\n  setTitle "Comment"\n  [whamlet|\n    <div .comment>\n      <p>${interp}\n  |]`, '{-# LANGUAGE QuasiQuotes, TemplateHaskell, TypeFamilies, OverloadedStrings #-}\nmodule Comments (getCommentR) where') });
  assert.equal(live(await scan(yes('#{preEscapedToHtml body}')), 'CWE-79').length, 1, 'the raw combinator inside the interpolation');
  assert.equal(live(await scan(yes('#{body}')), 'CWE-79').length, 0, 'hamlet escapes a plain interpolation');
  assert.equal(live(await scan(yes('#{preEscapedToHtml (T.toUpper body)}')), 'CWE-79').length, 1, 'parentheses inside the braces');
});

test('hamletInterpolations and the in-place rewrite: same length, same newlines, expressions at their offsets', () => {
  const seg = '[whamlet|\n    <p title=#{t}>#{preEscapedToHtml (f "}" x)}\n    ^{widget}\n  |]';
  const its = hamletInterpolations(seg, seg.indexOf('|') + 1, seg.length - 2);
  assert.deepEqual(its.map((i) => seg.slice(i.exprStart, i.close)), ['t', 'preEscapedToHtml (f "}" x)', 'widget']);
  const src = `{-# LANGUAGE QuasiQuotes #-}\nmodule M where\n\nimport Yesod\n\nw :: Int -> Widget\nw x = do\n  ${seg.replace(/\n/g, '\n  ')}\n`;
  const out = preprocessForSyntax(src);
  assert.equal(out.length, src.length);
  assert.equal(out.split('\n').length, src.split('\n').length);
  assert.match(out, /\(hamletQ/);
  assert.match(out, /\(preEscapedToHtml \(f "\}" x\)\)/);
  assert.ok(!/<p title=/.test(out), 'the template text is gone');
  const custom = src.replace('import Yesod', 'import My.Quoters (whamlet)');
  assert.equal(preprocessForSyntax(custom), custom, 'a quoter that is not Shakespeare\'s is left as written');
});
