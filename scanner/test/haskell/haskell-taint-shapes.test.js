// Taint shapes added on 2026-11-02, each pinned in both directions (the shape that was missed, and the nearest shape whose verdict must not
// move with it). They were found by probing self-written idioms against the engine, not by reading any frozen split; the in-tree framework
// shape is the one that lost four real true positives on the fresh set (bench/dag/dev-haskell/README.md), fixed from the code shape alone.
//
//   1. a project that DEFINES a module the model registry models (the project is the framework): the registry's meaning applies to the call
//   2. a mutable cell (IORef, MVar, TVar) written and read in one function carries what was written
//   3. a class method applied to a constructor dispatches to that type's instance
//   4. a function held in a record field of a top-level constant is the function applied
//   5. request text handed to a project helper is caller text in the helper (rules), including an index into a list
//   6. scotty's setMaxRequestBodySize bounds the body reads of the application it is set in (rules)
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { runScan } from '../../src/runScan.js';
import { analyzeHaskellRules } from '../../src/language/haskell-security-rules.js';
import { buildHaskellIR } from '../../src/language/haskell-ir.js';
import { mkTestTmp } from '../helpers/tmp.js';

async function scan(files) {
  const dir = mkTestTmp('hs-taint-shapes-');
  writeFileSync(join(dir, 'package.json'), '{}');
  for (const [f, text] of Object.entries(files)) { mkdirSync(dirname(join(dir, f)), { recursive: true }); writeFileSync(join(dir, f), text); }
  const r = await runScan(dir, { deep: true });
  return [...(r.scan.findings || [])];
}
// a finding a default scan would act on: not lowered to information and not proven clean or infeasible
const live = (fs, cwe) => fs.filter((f) => f.cwe === cwe && f.severity !== 'info' && !(f.proof && /^proven-/.test(f.proof.verdict)));

const HEAD = [
  '{-# LANGUAGE OverloadedStrings #-}',
  'module Svc (app) where',
  '',
  'import Control.Concurrent.MVar',
  'import Control.Concurrent.STM',
  'import Control.Monad.IO.Class (liftIO)',
  'import Data.IORef',
  'import qualified Data.Text.Lazy as TL',
  'import System.Process (callCommand)',
  'import Web.Scotty',
  '',
].join('\n');
const route = (body, decls = '') => `${HEAD}${decls}app :: ScottyM ()\napp = get "/ping" $ do\n${body}\n`;

// ── 1. the project defines a modelled module ─────────────────────────────────────────────────────────────────────────────────────
const FRAMEWORK = `{-# LANGUAGE ImplicitParams #-}
module IHP.Controller.Param (param) where

import Data.Text (Text)
import qualified Data.Text as T
import Network.Wai (Request, queryString)

param :: (?request :: Request) => Text -> Text
param name = maybe "" (T.pack . show) (lookup (T.unpack name) (map (\\(k, v) -> (show k, v)) (queryString ?request)))
`;
const CONTROLLER = (call) => `{-# LANGUAGE ImplicitParams, OverloadedStrings #-}
module IHP.IDE.Logs.Controller (openEditorAction) where

import Data.Text (Text)
import qualified Data.Text as T
import IHP.Controller.Param (param)
import Network.Wai (Request)
import qualified System.Process as Process

openEditorAction :: (?request :: Request) => IO ()
openEditorAction = do
    let path = param "path"
    ${call}

openEditor :: Text -> IO ()
openEditor path = do
    let command = "code " <> path
    _ <- Process.system (T.unpack command)
    pure ()
`;

test('in-tree framework: a project definition of a modelled request read keeps the registry meaning, and the definition is still referenced', async () => {
  const hit = await scan({ 'IHP/Controller/Param.hs': FRAMEWORK, 'IHP/IDE/Logs/Controller.hs': CONTROLLER('openEditor path') });
  const shell = live(hit, 'CWE-78');
  assert.equal(shell.length, 1, JSON.stringify(hit.map((f) => [f.cwe, f.file, f.line, f.severity])));
  assert.equal(shell[0].file, 'IHP/IDE/Logs/Controller.hs');
  assert.equal(shell[0].trustBoundary && shell[0].trustBoundary.verdict, 'attacker-reachable', 'the request read says who supplied the path');
  const quiet = await scan({ 'IHP/Controller/Param.hs': FRAMEWORK, 'IHP/IDE/Logs/Controller.hs': CONTROLLER('openEditor "README.md"') });
  assert.equal(live(quiet, 'CWE-78').length, 0, 'a constant path');
  // the call graph: the definition is referenced (never an uncalled entry point whose parameters are caller-controlled), and the call is the library call
  const ir = buildHaskellIR({ 'IHP/Controller/Param.hs': FRAMEWORK, 'IHP/IDE/Logs/Controller.hs': CONTROLLER('openEditor path') });
  const action = ir.callGraph.functions.get([...ir.callGraph.functions.keys()].find((q) => /openEditorAction@\d+$/.test(q)));
  assert.ok(action.hs.refs.some((r) => r.via === 'modelled-definition' && /Param\.param@\d+$/.test(r.target)), JSON.stringify(action.hs.refs));
  const def = ir.callGraph.functions.get([...ir.callGraph.functions.keys()].find((q) => /IHP\.Controller\.Param\.param@\d+$/.test(q)));
  assert.ok(def && def.hs.reached, 'the project definition is reached through the modelled call');
});

// ── 2. mutable cells ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
test('mutable cells: a value written to an IORef, MVar or TVar and read back in the same function reaches the sink; a constant write does not', async () => {
  const ioref = await scan({ 'src/Svc.hs': route('  host <- param "host"\n  ref <- liftIO (newIORef "")\n  liftIO (writeIORef ref (TL.unpack host))\n  v <- liftIO (readIORef ref)\n  liftIO (callCommand ("ping " ++ v))') });
  assert.equal(live(ioref, 'CWE-78').length, 1, 'writeIORef then readIORef');
  const modify = await scan({ 'src/Svc.hs': route('  host <- param "host"\n  ref <- liftIO (newIORef "ping")\n  liftIO (modifyIORef ref (\\c -> c ++ " " ++ TL.unpack host))\n  v <- liftIO (readIORef ref)\n  liftIO (callCommand v)') });
  assert.equal(live(modify, 'CWE-78').length, 1, 'modifyIORef applies the function to the cell');
  const mvar = await scan({ 'src/Svc.hs': route('  host <- param "host"\n  box <- liftIO newEmptyMVar\n  liftIO (putMVar box (TL.unpack host))\n  v <- liftIO (takeMVar box)\n  liftIO (callCommand ("ping " ++ v))') });
  assert.equal(live(mvar, 'CWE-78').length, 1, 'putMVar then takeMVar');
  const tvar = await scan({ 'src/Svc.hs': route('  host <- param "host"\n  cell <- liftIO (newTVarIO "")\n  liftIO (atomically (writeTVar cell (TL.unpack host)))\n  v <- liftIO (readTVarIO cell)\n  liftIO (callCommand ("ping " ++ v))') });
  assert.equal(live(tvar, 'CWE-78').length, 1, 'writeTVar under atomically, then readTVarIO');
  const constant = await scan({ 'src/Svc.hs': route('  _ <- param "host"\n  ref <- liftIO (newIORef "")\n  liftIO (writeIORef ref "localhost")\n  v <- liftIO (readIORef ref)\n  liftIO (callCommand ("ping " ++ v))') });
  assert.equal(live(constant, 'CWE-78').length, 0, 'a cell holding a constant');
  // the limit, stated: a cell written in one function and read in another is not followed
  const crossFn = await scan({ 'src/Svc.hs': route('  host <- param "host"\n  ref <- liftIO (newIORef "")\n  liftIO (store ref (TL.unpack host))\n  liftIO (run ref)', 'store :: IORef String -> String -> IO ()\nstore ref v = writeIORef ref v\n\nrun :: IORef String -> IO ()\nrun ref = readIORef ref >>= \\v -> callCommand ("ping " ++ v)\n\n') });
  assert.ok(Array.isArray(crossFn));
});

// ── 3. class method dispatch on a constructor ────────────────────────────────────────────────────────────────────────────────────
test('typeclass: a method applied to a constructor is the call of that type\'s instance; another type\'s instance is not charged', async () => {
  const decls = (shellBody, logBody) => `data Shell = Shell\ndata Logger = Logger\n\nclass Runner a where\n  run :: a -> String -> IO ()\n\ninstance Runner Shell where\n  run _ x = ${shellBody}\n\ninstance Runner Logger where\n  run _ x = ${logBody}\n\n`;
  const shell = await scan({ 'src/Svc.hs': route('  host <- param "host"\n  liftIO (run Shell (TL.unpack host))', decls('callCommand ("ping " ++ x)', 'putStrLn x')) });
  assert.equal(live(shell, 'CWE-78').length, 1, 'the Shell instance runs a shell');
  const logger = await scan({ 'src/Svc.hs': route('  host <- param "host"\n  liftIO (run Logger (TL.unpack host))', decls('callCommand ("ping " ++ x)', 'putStrLn x')) });
  assert.equal(live(logger, 'CWE-78').length, 0, 'the Logger instance only prints');
  // an argument of unknown type keeps the candidates (no instance is chosen, nothing is reported for it)
  const ir = buildHaskellIR({ 'src/Svc.hs': route('  host <- param "host"\n  liftIO (run undefined (TL.unpack host))', decls('callCommand ("ping " ++ x)', 'putStrLn x')) });
  const app = ir.callGraph.functions.get([...ir.callGraph.functions.keys()].find((q) => /Svc\.app@\d+$/.test(q)));
  const call = app.calls.find((c) => c.hs && c.hs.cls === 'Runner');
  assert.ok(call && call.hs.status === 'typeclass' && call.hs.candidates.length === 2, JSON.stringify(call && call.hs));
});

// ── 4. a function held in a record field ─────────────────────────────────────────────────────────────────────────────────────────
test('record of functions: `exec ops x` applies the function the constant record holds; a record built at run time stays indirect', async () => {
  const lambda = await scan({ 'src/Svc.hs': route('  host <- param "host"\n  liftIO (exec ops (TL.unpack host))', 'data Ops = Ops { exec :: String -> IO (), name :: String }\n\nops :: Ops\nops = Ops { exec = \\x -> callCommand ("ping " ++ x), name = "shell" }\n\n') });
  assert.equal(live(lambda, 'CWE-78').length, 1, 'a lambda in the field');
  const named = await scan({ 'src/Svc.hs': route('  host <- param "host"\n  liftIO (exec ops (TL.unpack host))', 'data Ops = Ops { exec :: String -> IO (), name :: String }\n\npingHost :: String -> IO ()\npingHost x = callCommand ("ping " ++ x)\n\nops :: Ops\nops = Ops { exec = pingHost, name = "shell" }\n\n') });
  assert.equal(live(named, 'CWE-78').length, 1, 'a named function in the field');
  const safe = await scan({ 'src/Svc.hs': route('  host <- param "host"\n  liftIO (exec ops (TL.unpack host))', 'data Ops = Ops { exec :: String -> IO (), name :: String }\n\nops :: Ops\nops = Ops { exec = putStrLn, name = "log" }\n\n') });
  assert.equal(live(safe, 'CWE-78').length, 0, 'the held function only prints');
  const runtime = await scan({ 'src/Svc.hs': route('  host <- param "host"\n  let ops = Ops { exec = \\x -> callCommand ("ping " ++ x), name = "shell" }\n  liftIO (exec ops (TL.unpack host))', 'data Ops = Ops { exec :: String -> IO (), name :: String }\n\n') });
  assert.ok(Array.isArray(runtime), 'a record built in the handler is not a top-level constant (its field is an indirect call, a stated limit)');
});

// ── 5. request text handed to a helper (rules) ───────────────────────────────────────────────────────────────────────────────────
const ENUMS = (arg, helper) => `{-# LANGUAGE ImplicitParams, OverloadedStrings #-}
module IHP.IDE.SchemaDesigner.Controller.Enums (deleteEnumAction) where

import Data.Text (Text)
import qualified Data.Text as T
import IHP.Controller.Param (param)
import Network.Wai (Request)

deleteEnumAction :: (?request :: Request) => [Text] -> IO [Text]
deleteEnumAction statements = do
    let tableId = length (T.unpack (param "tableId"))
    pure (deleteEnum ${arg} statements)

${helper}
`;
const INLINED = 'deleteEnum :: Int -> [Text] -> [Text]\ndeleteEnum tableId list = filter (/= (list !! tableId)) list';
const NOT_INLINED = 'deleteEnum :: Int -> [Text] -> [Text]\ndeleteEnum tableId list = filter (/= picked) list\n  where\n    picked = list !! tableId';
const GUARDED = 'deleteEnum :: Int -> [Text] -> [Text]\ndeleteEnum tableId list = if tableId < length list then filter (/= (list !! tableId)) list else list';
test('helper parameters: request text passed to a project helper is caller text there; an index from it is a partial function; a bounds test covers it', () => {
  const hits = (src) => analyzeHaskellRules({ 'IHP/Controller/Param.hs': FRAMEWORK, 'Enums.hs': src }).findings.filter((f) => f.rule === 'hs-partial-function-on-input' && /!!/.test(f.description));
  const inlined = hits(ENUMS('tableId', INLINED));
  assert.deepEqual(inlined.map((f) => f.line), [15], 'reported once, in the helper (the inlined call-site copy is dropped)');
  assert.match(inlined[0].description, /caller-supplied index/);
  assert.deepEqual(hits(ENUMS('tableId', NOT_INLINED)).map((f) => f.line), [17], 'a helper the IR does not inline (a where clause) is reached through the call edge');
  assert.equal(hits(ENUMS('tableId', GUARDED)).length, 0, 'a relational test on the index in the helper');
  assert.equal(hits(ENUMS('0', INLINED)).length, 0, 'a constant index');
});

// ── 6. scotty's application-wide body limit (rules) ──────────────────────────────────────────────────────────────────────────────
const SCOTTY_HEAD = '{-# LANGUAGE OverloadedStrings #-}\nmodule Main (main) where\n\nimport Web.Scotty\nimport Data.Text.Lazy.Encoding (decodeUtf8)\n\n';
test('scotty body limit: setMaxRequestBodySize in the block that holds or names the handler bounds the read; in another file it is an unverified control', () => {
  const bodies = (files) => { const r = analyzeHaskellRules(files); return { f: r.findings.filter((x) => x.rule === 'hs-unbounded-request-body'), c: (r.controls || []).filter((x) => x.kind === 'scotty-body-limit') }; };
  const none = bodies({ 'Main.hs': SCOTTY_HEAD + 'main :: IO ()\nmain = scotty 3000 $ do\n    post "/readbody" $ do\n        b <- body\n        text (decodeUtf8 b)\n' });
  assert.equal(none.f.length, 1); assert.equal(none.f[0].severity, 'medium');
  const same = bodies({ 'Main.hs': SCOTTY_HEAD + 'main :: IO ()\nmain = scotty 3000 $ do\n    setMaxRequestBodySize 1024\n    post "/readbody" $ do\n        b <- body\n        text (decodeUtf8 b)\n' });
  assert.equal(same.f.length, 0); assert.equal(same.c.length, 1); assert.equal(same.c[0].verified, true);
  const named = bodies({ 'Main.hs': SCOTTY_HEAD + 'main :: IO ()\nmain = scotty 3000 $ do\n    setMaxRequestBodySize 1024\n    post "/readbody" readBody\n\nreadBody :: ActionM ()\nreadBody = do\n    b <- body\n    text (decodeUtf8 b)\n' });
  assert.equal(named.f.length, 0, 'the block names the handler');
  const other = bodies({ 'Main.hs': SCOTTY_HEAD + 'import Handlers (readBody)\n\nmain :: IO ()\nmain = scotty 3000 $ do\n    setMaxRequestBodySize 1024\n    post "/other" (text "x")\n', 'Handlers.hs': SCOTTY_HEAD.replace('module Main (main)', 'module Handlers (readBody)') + 'readBody :: ActionM ()\nreadBody = do\n    b <- body\n    text (decodeUtf8 b)\n' });
  assert.equal(other.f.length, 1); assert.equal(other.f[0].severity, 'low'); assert.ok(other.f[0].uncertainty, 'the block is in another file: the limit exists, its reach is not verified');
  assert.equal(other.c[0].verified, false);
});
