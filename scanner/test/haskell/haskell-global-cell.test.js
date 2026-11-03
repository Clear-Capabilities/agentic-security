// A module-level mutable cell (`{-# NOINLINE ref #-} ref = unsafePerformIO (newIORef ..)`) written in one function and read in another:
// the IR names it `$cell:<qid>` for the whole project (haskell-ir.js cellBodyOf, lowerCellOp) and the taint engine seeds every Haskell
// function's entry with a cell any writer stored tainted data in (dataflow/engine.js _cellSeeds). A point-free writer
// (`remember = writeIORef ref`) is an alias of the library function with its cell fixed. Probe recorded 2026-11-02: 0 of 1 found before.
// Pinned both ways: the request value reaches the sink through the cell; a cell written only with a literal is silent.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { writeFileSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkTestTmp } from '../helpers/tmp.js';

const BIN = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'bin', 'agentic-security.js');
function scan(files) {
  const dir = mkTestTmp('hs-cell-');
  for (const [name, src] of Object.entries(files)) { mkdirSync(dirname(join(dir, name)), { recursive: true }); writeFileSync(join(dir, name), src); }
  const env = { ...process.env, AGENTIC_SECURITY_DEEP: '1', AGENTIC_SECURITY_DEEP_IN_CI: '1' }; delete env.NODE_TEST_CONTEXT;
  const p = spawnSync(process.execPath, [BIN, 'scan', dir, '--format', 'json'], { encoding: 'utf8', timeout: 180000, env, maxBuffer: 64 * 1024 * 1024 });
  return JSON.parse(p.stdout).findings.filter((f) => f.parser === 'IR-TAINT');
}
const cmd = (fs) => fs.filter((f) => f.cwe === 'CWE-78' && f.severity !== 'info');

const CELL = `{-# LANGUAGE OverloadedStrings #-}
module Main where
import Web.Scotty
import Data.IORef
import System.IO.Unsafe (unsafePerformIO)
import System.Process (callCommand)
import Control.Monad.IO.Class (liftIO)
import qualified Data.Text.Lazy as TL

{-# NOINLINE lastName #-}
lastName :: IORef String
lastName = unsafePerformIO (newIORef "")

remember :: String -> IO ()
remember = writeIORef lastName

runLast :: IO ()
runLast = do
  cur <- readIORef lastName
  callCommand ("label " ++ cur)
`;

test('a global cell written by one function with request text is read tainted by another', () => {
  const fs = scan({ 'Main.hs': `${CELL}
main :: IO ()
main = scotty 3000 $ do
  post "/name" $ do
    n <- formParam "name"
    liftIO (remember (TL.unpack n))
    text "ok"
  get "/run" $ liftIO runLast >> text "done"
` });
  assert.equal(cmd(fs).length, 1, JSON.stringify(fs.map((f) => [f.line, f.vuln])));
  assert.equal(cmd(fs)[0].line, 20);
});

test('a global cell written only with a literal, or modified with a pure function of itself, stays silent', () => {
  const lit = scan({ 'Main.hs': `${CELL}
main :: IO ()
main = scotty 3000 $ do
  post "/name" $ do
    liftIO (remember "fixed")
    text "ok"
  get "/run" $ liftIO runLast >> text "done"
` });
  assert.equal(cmd(lit).length, 0);
  const mod = scan({ 'Main.hs': `${CELL}
main :: IO ()
main = scotty 3000 $ do
  post "/name" $ do
    liftIO (modifyIORef lastName (++ "!"))
    text "ok"
  get "/run" $ liftIO runLast >> text "done"
` });
  assert.equal(cmd(mod).length, 0);
});

test('the cell is one variable across modules: a writer in another file reaches the reader', () => {
  const fs = scan({
    'Store.hs': `module Store (lastName, remember) where
import Data.IORef
import System.IO.Unsafe (unsafePerformIO)

{-# NOINLINE lastName #-}
lastName :: IORef String
lastName = unsafePerformIO (newIORef "")

remember :: String -> IO ()
remember v = writeIORef lastName v
`,
    'Main.hs': `{-# LANGUAGE OverloadedStrings #-}
module Main where
import Web.Scotty
import Data.IORef
import Store
import System.Process (callCommand)
import Control.Monad.IO.Class (liftIO)
import qualified Data.Text.Lazy as TL

main :: IO ()
main = scotty 3000 $ do
  post "/name" $ do
    n <- formParam "name"
    liftIO (remember (TL.unpack n))
    text "ok"
  get "/run" $ do
    cur <- liftIO (readIORef lastName)
    liftIO (callCommand ("label " ++ cur))
    text "done"
`,
  });
  assert.equal(cmd(fs).length, 1, JSON.stringify(fs.map((f) => [f.file, f.line, f.vuln])));
});
