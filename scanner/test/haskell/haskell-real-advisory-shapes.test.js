// Shapes found on the real code behind published Haskell advisories (bench/cve-replay/real-haskell-advisories.md), each pinned both ways.
// keter HSEC-2024-0001 (a Host header echoed into HTML) was invisible for four unrelated reasons: a record pattern written with a space
// before its brace dropped the clause; a guard inside a `case` inside a list read as a comprehension; a sink built inside a tuple and a
// constructor in a `return` was not a sink site; and the page builder was a function held in a record field filled at run time.
// hledger-web's handlers were dropped by a Template Haskell splice in expression position and by a Hamlet replacement that lost its
// closing parenthesis. None of these is keyed to the advisory's file: each is a general parser or IR rule, pinned here on synthetic code.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { writeFileSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkTestTmp } from '../helpers/tmp.js';
import { parseSyntax } from '../../src/language/haskell-syntax.js';
import { buildHaskellIR } from '../../src/language/haskell-ir.js';
import { preprocessForSyntaxInfo } from '../../src/language/haskell-parser.js';

const BIN = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'bin', 'agentic-security.js');

function scan(files) {
  const dir = mkTestTmp('hs-advisory-');
  for (const [name, src] of Object.entries(files)) { mkdirSync(dirname(join(dir, name)), { recursive: true }); writeFileSync(join(dir, name), src); }
  const env = { ...process.env, AGENTIC_SECURITY_DEEP: '1', AGENTIC_SECURITY_DEEP_IN_CI: '1' }; delete env.NODE_TEST_CONTEXT;
  const p = spawnSync(process.execPath, [BIN, 'scan', dir, '--format', 'json'], { encoding: 'utf8', timeout: 180000, env, maxBuffer: 64 * 1024 * 1024 });
  return JSON.parse(p.stdout).findings.filter((f) => f.parser === 'IR-TAINT');
}
const live = (fs) => fs.filter((f) => f.severity !== 'info' && !(f.proof && /^proven-/.test(f.proof.verdict)));
const clauseNames = (src) => parseSyntax(src).decls.filter((d) => d.t === 'clause').map((d) => d.name);

// ── parser ──────────────────────────────────────────────────────────────────

test('a record pattern with a space before the brace keeps its clause (keter: `withClient isSecure MkProxySettings {..}`)', () => {
  const src = `module M where
data S = S { f :: Int, g :: Int }
withClient :: Bool -> S -> Int
withClient isSecure S {..} = f + g
tight isSecure S{..} = f
asPat x@S {g = y} = y
`;
  const r = parseSyntax(src);
  assert.deepEqual(r.errors, []);
  const names = clauseNames(src);
  assert.ok(names.includes('withClient') && names.includes('tight') && names.includes('asPat'), String(names));
  const wc = r.decls.find((d) => d.t === 'clause' && d.name === 'withClient');
  assert.equal(wc.clause.pats.length, 2);
  assert.equal(wc.clause.pats[1].t, 'pcon');
  assert.ok(wc.clause.pats[1].fields.some((x) => x.wildcard));
});

test('a multi-line record pattern spanning the clause head keeps its clause (hackage-server: readmeSection)', () => {
  const src = `module M where
data R = R { rendReadme :: Maybe (Int, Int, Int, String), rendPkgId :: Int }
readmeSection :: R -> Maybe String -> [String]
readmeSection R { rendReadme = Just (_, _etag, _, filename), rendPkgId = pkgid }
              (Just content) = [filename, content]
readmeSection _ _ = []
`;
  const r = parseSyntax(src);
  assert.deepEqual(r.errors, []);
  assert.equal(r.decls.filter((d) => d.t === 'clause' && d.name === 'readmeSection').length, 2);
});

test('a guard inside a case inside a list literal is not a comprehension bar (keter: mkUrl)', () => {
  const src = `module M where
mkUrl isSecure host mport req = concat
    [ if isSecure then "https://" else "http://"
    , host
    , case mport of
        Nothing -> ""
        Just port
            | isSecure && port == 443 -> ""
            | otherwise -> ':' : show port
    , req
    ]
comp xs = [ x | x <- xs, x > 0 ]
`;
  const r = parseSyntax(src);
  assert.deepEqual(r.errors, []);
  const mk = r.decls.find((d) => d.t === 'clause' && d.name === 'mkUrl');
  const body = mk.clause.rhs.body;
  const list = body.t === 'app' ? body.args[0] : body;
  assert.equal(list.t, 'list', JSON.stringify(body).slice(0, 200));
  assert.equal(list.items.length, 4);
  assert.equal(list.items[2].t, 'case');
  const comp = r.decls.find((d) => d.t === 'clause' && d.name === 'comp');
  assert.equal(comp.clause.rhs.body.t, 'listcomp');
});

test('a Template Haskell splice in expression position is an opaque atom, and the surrounding expression parses (hledger-web)', () => {
  const src = `{-# LANGUAGE TemplateHaskell #-}
module M where
addForm j today = do
  x <- action j
  pure (validate x today, $(widgetFile "add-form"))
other = f $(mkName "x") 1
plain = g $ (h 1)
`;
  const r = parseSyntax(src);
  assert.deepEqual(r.errors, []);
  const add = r.decls.find((d) => d.t === 'clause' && d.name === 'addForm');
  const last = add.clause.rhs.body.stmts[1].e;
  assert.equal(last.t, 'app');
  assert.equal(last.args[0].t, 'tuple');
  assert.equal(last.args[0].items[1].t, 'splice');
  const plain = r.decls.find((d) => d.t === 'clause' && d.name === 'plain');
  assert.equal(plain.clause.rhs.body.t, 'op');   // `$` stays the operator when nothing says TemplateHaskell is on
  const off = parseSyntax(src.replace('{-# LANGUAGE TemplateHaskell #-}', ''));
  assert.ok(off.errors.length > 0, 'without the extension `$(` is not a splice and the tuple does not parse');
});

test('a Hamlet quasi-quote whose last interpolation ends its line keeps the enclosing function (hledger-web: addModal)', () => {
  const src = `{-# LANGUAGE QuasiQuotes #-}
module M where
import Yesod
import System.Process (callCommand)
addModal addR j today = do
  (addView, addEnctype) <- generateFormPost (addForm j today)
  [whamlet|
<div .modal>
  <form action=@{addR} enctype=#{addEnctype}>
    ^{addView}
|]
  callCommand "true"
`;
  const pp = preprocessForSyntaxInfo(src, { file: 'M.hs' });
  const r = parseSyntax(pp.text);
  assert.deepEqual(r.errors, []);
  const ir = buildHaskellIR({ 'M.hs': src });
  const fn = Object.values(ir.perFile)[0].functions.find((f) => f.name.endsWith('addModal'));
  assert.ok(fn, 'addModal lowered');
  assert.ok(Object.values(fn.cfg.nodes).some((n) => JSON.stringify(n).includes('callCommand')), 'the call after the quasi-quote is kept');
});

test('an as-pattern binding in a where block is a pattern binding, not a function named by its variable (keter: newHooks@ServerHooks{..})', () => {
  const src = `module M where
import qualified Net as TLS
data H = H { onA :: Int, onB :: Int }
f s = onA + onB
  where
    hooks@TLS.H{..} = TLS.mk s
`;
  const r = parseSyntax(src);
  assert.deepEqual(r.errors, []);
  const f = r.decls.find((d) => d.t === 'clause' && d.name === 'f');
  const w = f.clause.rhs.where;
  assert.equal(w.length, 1);
  assert.equal(w[0].t, 'patbind');
  assert.equal(w[0].pat.t, 'pas');
});

// ── taint ───────────────────────────────────────────────────────────────────

const WAI_HEAD = `{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
module Main where
import Network.Wai
import Network.Wai.Handler.Warp (run)
import Network.HTTP.Types (status200)
import Data.ByteString (ByteString)
import qualified Data.ByteString as S
import Blaze.ByteString.Builder (copyByteString)
`;
const RESPONSES = `
page :: ByteString -> ByteString
page host = "<html><body><p>The hostname <code>" <> host <> "</code> is not recognized.</p></body></html>"

respond' :: ByteString -> ByteString -> Response
respond' host body = responseBuilder status200 [("Content-Type", "text/html; charset=utf-8"), ("X-Forwarded-Host", host)] (copyByteString body)
`;

test('a sink built inside a tuple and a constructor in a return is a sink site (keter: WPRResponse inside the callback tuple)', () => {
  const files = { 'Main.hs': `${WAI_HEAD}
data Wrapped = WPR Response

main :: IO ()
main = run 8080 app

app :: Application
app req k = do
  (_, WPR resp) <- getDest req
  k resp
  where
    getDest :: Request -> IO (Int, Wrapped)
    getDest r = case requestHeaderHost r of
      Nothing -> return (1, WPR (respond' "none" "<p>none</p>"))
      Just host -> return (1, WPR $ respond' host (page host))
${RESPONSES}` };
  const fs = live(scan(files));
  assert.equal(fs.filter((f) => f.cwe === 'CWE-79').length, 1, JSON.stringify(fs.map((f) => [f.line, f.vuln])));
  const safe = live(scan({ 'Main.hs': files['Main.hs'].replace('respond\' host (page host)', 'respond\' host (page "fixed")') }));
  assert.equal(safe.filter((f) => f.cwe === 'CWE-79').length, 0);
});

test('a function held in a record field filled at run time resolves to the functions the project stores there (keter: psUnkownHost)', () => {
  const build = (bodyFn) => `${WAI_HEAD}
data Settings = MkSettings { unknownHost :: ByteString -> ByteString, missing :: ByteString }

makeSettings :: Maybe FilePath -> IO Settings
makeSettings custom = do
    let missing = "<p>missing</p>"
    unknownHost <- case custom of
      Nothing -> pure ${bodyFn}
      Just x -> const <$> S.readFile x
    pure MkSettings{..}

main :: IO ()
main = do
  s <- makeSettings Nothing
  run 8080 (proxy s)

proxy :: Settings -> Application
proxy MkSettings {..} req k =
  case requestHeaderHost req of
    Nothing -> k (respond' "none" missing)
    Just host -> k (respond' host (unknownHost host))
${RESPONSES}
pageSafe :: ByteString -> ByteString
pageSafe _ = "<p>static</p>"
`;
  const vuln = live(scan({ 'Main.hs': build('page') }));
  assert.equal(vuln.filter((f) => f.cwe === 'CWE-79').length, 1, JSON.stringify(vuln.map((f) => [f.line, f.vuln])));
  // `const "<p>static</p>"` is a function that ignores its argument (an `ignores` candidate), like the `const <$> readFile` branch: no taint
  // reaches the body. (A resolved project call with a tainted argument stays tainted for the engine whatever the callee does with it, so
  // a named safe function is not the clean form here; that is the engine's standing k=1 rule, not this resolution's.)
  const safe = live(scan({ 'Main.hs': build('(const "<p>static</p>")') }));
  assert.equal(safe.filter((f) => f.cwe === 'CWE-79').length, 0, 'the field holds only functions that ignore the host');
  // A construction the index cannot classify (a lambda with a captured local) leaves the call unresolved: still reported, still tainted.
  const opaque = live(scan({ 'Main.hs': build('page').replace('Just x -> const <$> S.readFile x', 'Just x -> pure (\\h -> S.append h (S.pack [1]))') }));
  assert.equal(opaque.filter((f) => f.cwe === 'CWE-79').length, 1);
});

test("blaze-builder's HTML escapers sanitize, through a point-free composition alias (keter's fix)", () => {
  const src = `${WAI_HEAD}
import Blaze.ByteString.Builder (toByteString)
import Blaze.ByteString.Builder.Html.Word (fromHtmlEscapedByteString)

main :: IO ()
main = run 8080 app

app :: Application
app req k = case requestHeaderHost req of
  Nothing -> k (respond' "none" "<p>none</p>")
  Just host -> k (respond' host (page host))

escapeHtml :: ByteString -> ByteString
escapeHtml = toByteString . fromHtmlEscapedByteString

page :: ByteString -> ByteString
page host = "<html><body><p>The hostname <code>" <> escapeHtml host <> "</code> is not recognized.</p></body></html>"

respond' :: ByteString -> ByteString -> Response
respond' host body = responseBuilder status200 [("Content-Type", "text/html; charset=utf-8"), ("X-Forwarded-Host", host)] (copyByteString body)
`;
  const fs = scan({ 'Main.hs': src }).filter((f) => f.cwe === 'CWE-79');
  assert.equal(fs.length, 1);
  assert.ok(fs[0].proof && /^proven-/.test(fs[0].proof.verdict), JSON.stringify(fs[0].proof));
  assert.ok(JSON.stringify(fs[0].proof).includes('fromHtmlEscapedByteString'));
});

test('a WAI response with a Location header and no content type is a redirect body, lowered to info with the reason', () => {
  const src = `${WAI_HEAD}
import Network.HTTP.Types (status301)

main :: IO ()
main = run 8080 app

app :: Application
app req k = k (responseBuilder status301 [("Location", url)] (copyByteString url))
  where url = "https://example.test" <> rawPathInfo req
`;
  const fs = scan({ 'Main.hs': src }).filter((f) => f.cwe === 'CWE-79');
  assert.equal(fs.length, 1);
  assert.equal(fs[0].severity, 'info');
  assert.equal(fs[0].guardNote && fs[0].guardNote.kind, 'redirect-response-body');
  const html = scan({ 'Main.hs': src.replace('[("Location", url)]', '[("Content-Type", "text/html")]') }).filter((f) => f.cwe === 'CWE-79');
  assert.equal(html.length, 1);
  assert.notEqual(html[0].severity, 'info');
});
