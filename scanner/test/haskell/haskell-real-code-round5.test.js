// Round 5 of the real-code work (docs/superpowers/plans/2026-11-14-haskell-real-code-precision.md): the second discovery batch (postgrest, yesod,
// snap-server, keter, Spock, spacecookie; bench/dag/discovery-haskell, batch 2). Five mechanisms, each from a labelled false positive:
//   1. `posture/api-contract.js`: a contract file under a directory a `test-suite` stanza lists is a test fixture, not the project's API (PostgREST's
//      `test/spec/fixtures/openapi.json` declared four admin routes undeclared); a code route whose path is not a path (`" ++ toS k ++ "`, the text
//      between two string literals) is not compared with any contract.
//   2. `hs-partial-function-on-input`: `last`/`head` on the result of a splitter that returns a non-empty list for every input (`Data.Text.split`,
//      `Data.Text.splitOn`, `Data.List.Split.splitOn`, `inits`, `tails`) is total; the ByteString `split`, which returns `[]` for an empty input, is not.
//   3. `hs-unbounded-input-read`: a socket read repeated by a recursive loop is unbounded only when the loop carries what it read (an accumulator
//      argument built from the read); a loop that answers each message and recurses with the socket alone holds one chunk at a time (keter's REPL).
//   4. A text parameter of a Yesod `Handler`/`HandlerFor` function is request input only when the function is one the routes DSL dispatches to
//      (`getFooR`, `postFooR`, `handleFooR`); a helper returning a handler value takes its parameters from its caller (yesod's
//      `addStaticContentExternal minify hash staticDir toRoute ext'`). The function is still a Yesod entry handler for reachability.
//   6. `hs-partial-function-on-input`: a partial name the module DEFINES (a where-bound `fromJust = error ..`, yesod-core's TypeCache) is that
//      definition, not the library partial; only a call the IR resolved to a library or builtin name is the partial function.
//   5. An entry role is decided along the call PATH from `main`: a function reached only through modules that import no server library is `cli`,
//      even when another branch of the same program serves (yesod-bin's `add-handler` beside `devel`). A function on a path through a server
//      module is `service`, as before.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { mkTestTmp } from '../helpers/tmp.js';
import { analyzeHaskellRules } from '../../src/language/haskell-security-rules.js';
import { buildHaskellIR } from '../../src/language/haskell-ir.js';
import { runApiContractScan } from '../../src/posture/api-contract.js';
import { testComponentIndex } from '../../src/language/haskell-manifests.js';

process.env.AGENTIC_SECURITY_DEEP = '1';
delete process.env.CI;

async function scanOf(prefix, files) {
  const { runScan } = await import('../../src/runScan.js');
  const dir = mkdtempSync(join(mkTestTmp(prefix), 'p-'));
  for (const [k, v] of Object.entries(files)) { mkdirSync(dirname(join(dir, k)), { recursive: true }); writeFileSync(join(dir, k), v); }
  const { scan } = await runScan(dir, { deep: true });
  return { dir, findings: scan.findings.filter((f) => /\.hs$/.test(f.file)) };
}
const flagged = (fs, cwe) => fs.filter((f) => f.parser === 'IR-TAINT' && f.cwe === cwe && f.severity !== 'info' && !(f.proof && /^proven-/.test(f.proof.verdict)));
const lowered = (fs, cwe) => fs.filter((f) => f.parser === 'IR-TAINT' && f.cwe === cwe && f.severity === 'info' && f.trustBoundary);

// ── 1. api-contract: a fixture under a test component, and a route that is not a path ────────────────────────────────────────────────────
const CABAL_WITH_SPEC = 'cabal-version: 2.4\nname: p\nversion: 0.1\n\nlibrary\n    exposed-modules: Admin\n    hs-source-dirs: src\n    build-depends: base\n\ntest-suite spec\n    type: exitcode-stdio-1.0\n    main-is: Spec.hs\n    hs-source-dirs: test/spec\n    build-depends: base\n';
const OPENAPI = JSON.stringify({ openapi: '3.0.0', info: { title: 'p', version: '1' }, paths: { '/users': { get: { responses: { 200: { description: 'ok' } } } } } });

test('api-contract: an OpenAPI file under a test-suite directory is a fixture, not the API the code must declare', () => {
  const dir = mkdtempSync(join(mkTestTmp('hs-round5-contract'), 'p-'));
  for (const [k, v] of Object.entries({ 'p.cabal': CABAL_WITH_SPEC, 'test/spec/fixtures/openapi.json': OPENAPI, 'src/Admin.hs': 'module Admin where\n' })) { mkdirSync(dirname(join(dir, k)), { recursive: true }); writeFileSync(join(dir, k), v); }
  const routes = [{ method: 'ANY', path: '/live', file: 'src/Admin.hs', line: 5 }];
  const idx = testComponentIndex({ 'p.cabal': CABAL_WITH_SPEC });
  assert.ok(idx.dirOwnerOf('test/spec/fixtures/openapi.json'), 'the index names the test suite that owns the fixture directory');
  assert.equal(idx.dirOwnerOf('src/openapi.json'), null);
  const scoped = runApiContractScan(dir, routes, { isTestFile: (rel) => !!idx.dirOwnerOf(rel) });
  assert.equal(scoped.filter((f) => f.subfamily === 'undocumented-endpoint').length, 0, JSON.stringify(scoped));
  // the same tree with no component knowledge still compares the route with the file (the mechanism is the manifest, not the path)
  const unscoped = runApiContractScan(dir, routes, {});
  assert.equal(unscoped.filter((f) => f.subfamily === 'undocumented-endpoint').length, 1, JSON.stringify(unscoped));
});

test('api-contract: a code route whose path is not a path is never an undocumented endpoint', () => {
  const dir = mkdtempSync(join(mkTestTmp('hs-round5-contract'), 'p-'));
  writeFileSync(join(dir, 'openapi.json'), OPENAPI);
  const routes = [
    { method: 'GET', path: ' ++ toS k ++ ', file: 'src/QueryParams.hs', line: 289 },   // the text between two string literals on one line
    { method: 'ANY', path: '/live', file: 'src/Admin.hs', line: 5 },
  ];
  const out = runApiContractScan(dir, routes, {}).filter((f) => f.subfamily === 'undocumented-endpoint');
  assert.deepEqual(out.map((f) => f.line), [5], JSON.stringify(out.map((f) => f.vuln)));
});

// ── 2. a partial function on a splitter that never returns an empty list ───────────────────────────────────────────────────────────────────
const partial = (body) => analyzeHaskellRules({ 'Lib.hs': `module Lib (p) where\nimport qualified Data.Text as T\nimport qualified Data.List as L\nimport qualified Data.List.Split as LS\nimport qualified Data.ByteString.Char8 as B\n\n${body}` }).findings.filter((f) => f.rule === 'hs-partial-function-on-input');

test('partial: last/head on Data.Text.split, Data.Text.splitOn or Data.List.Split.splitOn is total (each returns at least one piece)', () => {
  assert.equal(partial('p :: T.Text -> Bool\np key = L.last (T.split (== \'.\') key) == "x"\n').length, 0, 'last (T.split ..)');
  assert.equal(partial('p :: T.Text -> Bool\np key = L.head (T.splitOn "." key) == "x"\n').length, 0, 'head (T.splitOn ..)');
  assert.equal(partial('p :: String -> Bool\np key = L.last (LS.splitOn "." key) == "x"\n').length, 0, 'last (splitOn ..)');
  assert.equal(partial('p :: String -> Bool\np key = L.last (L.tails key) == ""\n').length, 0, 'last (tails ..)');
  // PostgREST's shape: the qualifier `T` names BOTH Data.Text and Data.Text.Encoding, so the IR cannot resolve `T.split` to one module; every
  // candidate is under Data.Text, and Data.Text.split is in the set
  const shared = analyzeHaskellRules({ 'Lib.hs': 'module Lib (p) where\nimport qualified Data.Text as T\nimport qualified Data.Text.Encoding as T\nimport qualified Data.List as L\n\np :: T.Text -> Bool\np key = L.last (T.split (== \'.\') key) == "x"\n' }).findings.filter((f) => f.rule === 'hs-partial-function-on-input');
  assert.equal(shared.length, 0, 'last (T.split ..) under a shared qualifier');
  // a shared qualifier whose candidates are NOT one family stays reported
  const mixed = analyzeHaskellRules({ 'Lib.hs': 'module Lib (p) where\nimport qualified Data.Text as T\nimport qualified Data.ByteString.Char8 as T\nimport qualified Data.List as L\n\np :: T.Text -> Bool\np key = L.last (T.split (== \'.\') key) == "x"\n' }).findings.filter((f) => f.rule === 'hs-partial-function-on-input');
  assert.equal(mixed.length, 1, 'last (T.split ..) where T may be the ByteString module');
});

test('partial: the ByteString split returns [] for an empty input, so last on it is still reported; so is last on words', () => {
  assert.equal(partial('p :: B.ByteString -> Bool\np key = L.last (B.split \'.\' key) == "x"\n').length, 1, 'last (B.split ..)');
  assert.equal(partial('p :: String -> Bool\np key = L.last (words key) == "x"\n').length, 1, 'last (words ..)');
});

// ── 3. a recursive socket read that holds one chunk at a time ──────────────────────────────────────────────────────────────────────────────
const SOCK = (body) => analyzeHaskellRules({ 'Svc.hs': `module Svc (talk, slurp) where\nimport Network.Socket (Socket)\nimport Network.Socket.ByteString (recv, sendAll)\nimport qualified Data.ByteString as S\nimport Control.Monad (unless)\n\n${body}` }).findings.filter((f) => f.rule === 'hs-unbounded-input-read');

test('unbounded read: a loop that answers each chunk and recurses with the socket alone is bounded by the read size; an accumulating loop is not', () => {
  const talk = 'talk :: Socket -> IO ()\ntalk conn = do\n  msg <- recv conn 1024\n  unless (S.null msg) $ do\n    sendAll conn msg\n    talk conn\n';
  const slurp = 'slurp :: Socket -> S.ByteString -> IO S.ByteString\nslurp conn acc = do\n  chunk <- recv conn 1024\n  if S.null chunk then pure acc else slurp conn (acc <> chunk)\n';
  assert.equal(SOCK(talk).length, 0, JSON.stringify(SOCK(talk).map((f) => [f.line, f.description])));
  const acc = SOCK(slurp);
  assert.equal(acc.length, 1, JSON.stringify(acc.map((f) => [f.line, f.description])));
  assert.equal(acc[0].line, 9);
});

// ── 4. Yesod: request input only on a dispatch-named handler ────────────────────────────────────────────────────────────────────────────────
const CABAL_STATIC = 'cabal-version: 2.4\nname: p\nversion: 0.1\nlibrary\n    exposed-modules: Handler.Static\n    hs-source-dirs: src\n    build-depends: base\n';
const STATIC = `{-# LANGUAGE OverloadedStrings #-}
module Handler.Static (addStaticContentExternal, getStaticR) where

import Yesod.Core
import qualified Data.Text as T
import System.Directory (doesFileExist)
import Control.Monad.IO.Class (liftIO)

addStaticContentExternal :: T.Text -> HandlerFor site Bool
addStaticContentExternal ext = liftIO (doesFileExist ("static/tmp/" ++ T.unpack ext))

getStaticR :: T.Text -> HandlerFor site Bool
getStaticR name = liftIO (doesFileExist ("static/" ++ T.unpack name))
`;

test('Yesod: getStaticR takes a route piece (attacker-reachable); a HandlerFor helper takes its caller\'s value, and both are entry handlers', async () => {
  const { findings } = await scanOf('hs-round5-yesod', { 'p.cabal': CABAL_STATIC, 'src/Handler/Static.hs': STATIC });
  const paths = findings.filter((f) => f.cwe === 'CWE-22');
  const handler = paths.find((f) => f.line === 13); const helper = paths.find((f) => f.line === 10);
  assert.ok(handler, JSON.stringify(paths.map((f) => [f.line, f.severity, f.trustBoundary && f.trustBoundary.verdict])));
  assert.equal(handler.trustBoundary.verdict, 'attacker-reachable');
  if (helper) {
    assert.notEqual(helper.trustBoundary.verdict, 'attacker-reachable', JSON.stringify(helper.trustBoundary));
    assert.ok(!helper.trustBoundary.roots.some((r) => r.provenance === 'url-param'), 'no request provenance was invented for the helper\'s parameter');
  }
  const fns = Object.values(buildHaskellIR({ 'src/Handler/Static.hs': STATIC }).perFile)[0].functions;
  assert.equal(fns.find((f) => /\.addStaticContentExternal$/.test(f.name)).hs.entryHandler, 'yesod', 'reachability still treats the handler-typed helper as a root');
  assert.equal(fns.find((f) => /\.getStaticR$/.test(f.name)).hs.entryHandler, 'yesod');
});

// ── 5. entry roles along the call path ──────────────────────────────────────────────────────────────────────────────────────────────────────
const TWO_FACED = {
  'package.json': '{}',
  'app/Main.hs': 'module Main (main) where\n\nimport Scaffold (addHandler)\nimport Serve (serve)\nimport System.Environment (getArgs)\n\nmain :: IO ()\nmain = do\n  args <- getArgs\n  case args of\n    ["add"] -> addHandler\n    _ -> serve\n',
  'src/Scaffold.hs': 'module Scaffold (addHandler) where\n\nimport System.IO\n\naddHandler :: IO ()\naddHandler = do\n  name <- getLine\n  readFile ("src/Handler/" ++ name ++ ".hs") >>= putStr\n',
  'src/Serve.hs': 'module Serve (serve) where\n\nimport Web.Scotty\nimport Control.Monad.IO.Class (liftIO)\nimport qualified Data.Text.Lazy as TL\n\nserve :: IO ()\nserve = do\n  name <- getLine\n  scotty 3000 $ get "/dump" $ do\n    c <- liftIO (readFile name)\n    text (TL.pack c)\n',
};

test('roles: the scaffolding branch of a program whose other branch serves is a command-line program; the serving branch is a service', async () => {
  const { findings } = await scanOf('hs-round5-roles', TWO_FACED);
  const scaffold = findings.filter((f) => f.file === 'src/Scaffold.hs' && f.cwe === 'CWE-22');
  const serve = findings.filter((f) => f.file === 'src/Serve.hs' && f.cwe === 'CWE-22');
  assert.equal(flagged(scaffold, 'CWE-22').length, 0, JSON.stringify(scaffold.map((f) => [f.line, f.severity, f.trustBoundary])));
  const low = lowered(scaffold, 'CWE-22')[0];
  assert.ok(low, 'the scaffolding read is still reported as information');
  assert.equal(low.trustBoundary.verdict, 'operator-controlled');
  assert.equal(low.trustBoundary.role, 'cli');
  assert.equal(flagged(serve, 'CWE-22').length, 1, JSON.stringify(serve.map((f) => [f.line, f.severity, f.trustBoundary])));
  assert.equal(flagged(serve, 'CWE-22')[0].trustBoundary.role, 'service');
});

// ── 6. a partial name the module defines itself ─────────────────────────────────────────────────────────────────────────────────────────────
test('partial: a where-bound definition named fromJust is that definition, not Data.Maybe.fromJust; the imported one is still reported', () => {
  // yesod-core's TypeCache shape: the local `fromJust` is evaluated only for its type, under `typeOf`, in a key built from the caller's text
  const local = partial('p :: String -> [(String, Int)] -> Maybe Int\np key c = res\n  where\n    res = lookup (typeOf $ fromJust res, key) c >>= fromDynamic\n    fromJust :: Maybe a -> a\n    fromJust = error "never evaluated"\n');
  assert.equal(local.length, 0, JSON.stringify(local.map((f) => [f.line, f.description])));
  const imported = analyzeHaskellRules({ 'Lib.hs': 'module Lib (p) where\nimport Data.Maybe (fromJust)\n\np :: String -> Int\np key = fromJust (lookup key [("a", 1)])\n' }).findings.filter((f) => f.rule === 'hs-partial-function-on-input');
  assert.equal(imported.length, 1);
});
