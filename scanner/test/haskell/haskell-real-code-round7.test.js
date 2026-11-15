// Round 7 of the real-code work (docs/superpowers/plans/2026-11-14-haskell-real-code-precision.md).
//   1. Field-sensitive return records (`dataflow/engine.js`, `summaries.js`): a function that returns a record whose fields differ in taint
//      (`VD { j = journalPath, q = queryParam }`, hledger-web's `getViewData`) hands each field its own taint to the caller: the caller's
//      `VD{j, q} <- getViewData` (member reads of the result) leaves `j` clean and `q` tainted, so a file operation on `j` is not a request
//      flow while a sink on `q` still is. A record returned whole-tainted, or read whole, is unchanged. Language neutral (the JavaScript twin
//      is in test/dataflow-field-return.test.js).
//   2. A credential-shaped NAME bound from a producer that yields a path (`pwd <- getCurrentDirectory`, `System.Directory`'s directory
//      readers, `PATH_PRODUCERS` in haskell-security-rules.js) holds a path, not a password: the sensitive-logging rule neither seeds a
//      binding from it nor reports it at a log sink (purescript's six `ppeRelativeDirectory = pwd` sites, every one `hs-sensitive-logging`
//      at high). The same name bound from anything else (`pwd <- getLine`) is still a credential by name.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { mkTestTmp } from '../helpers/tmp.js';

process.env.AGENTIC_SECURITY_DEEP = '1';
process.env.AGENTIC_SECURITY_DEEP_IN_CI = '1';
delete process.env.CI;

async function scanOf(prefix, files) {
  const { runScan } = await import('../../src/runScan.js');
  const dir = mkdtempSync(join(mkTestTmp(prefix), 'p-'));
  for (const [k, v] of Object.entries(files)) { mkdirSync(dirname(join(dir, k)), { recursive: true }); writeFileSync(join(dir, k), v); }
  const { scan } = await runScan(dir, { deep: true });
  return scan.findings.filter((f) => /\.hs$/.test(f.file));
}
const taint = (fs, cwe) => fs.filter((f) => f.parser === 'IR-TAINT' && f.cwe === cwe);

const VIEW = (sinkOn) => `{-# LANGUAGE OverloadedStrings #-}
module Handler.View (getViewR) where

import Yesod.Core
import qualified Data.Text as T
import System.Directory (doesFileExist)
import System.Process (callCommand)
import Control.Monad.IO.Class (liftIO)

data VD = VD { j :: FilePath, q :: T.Text }

getViewData :: HandlerFor site VD
getViewData = do
  mq <- lookupGetParam "q"
  let jf = "/var/lib/app/journal.ledger"
  pure VD { j = jf, q = maybe "" id mq }

getViewR :: HandlerFor site Bool
getViewR = do
  VD{j, q} <- getViewData
  ${sinkOn}
`;

test('a record returned with one tainted field: the clean field read from it is not a request flow, the tainted field still is', async () => {
  const cabal = 'cabal-version: 2.4\nname: p\nversion: 0.1\nlibrary\n    exposed-modules: Handler.View\n    hs-source-dirs: src\n    build-depends: base\n';
  const onPath = await scanOf('hs-round7-record', { 'p.cabal': cabal, 'src/Handler/View.hs': VIEW('liftIO (doesFileExist j)') });
  const paths = taint(onPath, 'CWE-22');
  assert.equal(paths.filter((f) => f.severity !== 'info').length, 0, JSON.stringify(paths.map((f) => [f.line, f.severity, f.trustBoundary && f.trustBoundary.verdict, (f.trustBoundary || {}).roots])));
  const onQuery = await scanOf('hs-round7-record', { 'p.cabal': cabal, 'src/Handler/View.hs': VIEW('liftIO (callCommand ("echo " ++ T.unpack q)) >> pure True') });
  const cmds = taint(onQuery, 'CWE-78');
  assert.ok(cmds.some((f) => f.severity !== 'info'), JSON.stringify(cmds.map((f) => [f.line, f.severity])));
});

const PWD = (bind) => `module Main (main) where

import System.Directory (getCurrentDirectory)
import System.IO (hPutStrLn, stderr)

data Opts = Opts { optFull :: Bool, optRelativeDirectory :: FilePath }

render :: Opts -> [String] -> String
render o es = unlines (map (\\e -> optRelativeDirectory o ++ ": " ++ e) es)

main :: IO ()
main = do
  ${bind}
  let opts = Opts { optFull = True, optRelativeDirectory = pwd }
  hPutStrLn stderr (render opts ["boom"])
  putStrLn (render Opts { optFull = False, optRelativeDirectory = pwd } ["x"])
`;
const logging = (fs) => fs.filter((f) => f.id === 'hs-sensitive-logging' || /hs-sensitive-logging/.test(f.id));

test('a credential-shaped name bound from a path producer is a path: not sensitive logging; bound from anything else it still is', async () => {
  const cabal = 'cabal-version: 2.4\nname: p\nversion: 0.1\nexecutable p\n    main-is: Main.hs\n    hs-source-dirs: app\n    build-depends: base, directory\n';
  const fromDir = await scanOf('hs-round7-pwd', { 'p.cabal': cabal, 'app/Main.hs': PWD('pwd <- getCurrentDirectory') });
  assert.equal(logging(fromDir).length, 0, JSON.stringify(logging(fromDir).map((f) => [f.line, f.severity, f.description])));
  const fromInput = await scanOf('hs-round7-pwd', { 'p.cabal': cabal, 'app/Main.hs': PWD('pwd <- getLine') });
  assert.ok(logging(fromInput).length >= 1, JSON.stringify(fromInput.map((f) => [f.id, f.line])));
});
