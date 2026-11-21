// Haskell taint, round 11: the three mechanisms the unseen-v8 development reading motivated. Each positive case has a refusing twin.
//   1. a shell interpreter reached through a callee (`mapM_ moveRobot ...` merging the callee's `run_ "sh" ["-c", cmd]`) is command injection, not
//      argument injection; Shelly's runners are in the process set
//   2. a let-bound Bool stands for its definition in a guard, and `liftIO (canonicalizePath p)` is a canonical path
//   3. a character-class predicate may be a lambda or a one-expression helper admitting letters, digits and a dash or underscore; `Data.Text.all` counts
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { mkTestTmp } from '../helpers/tmp.js';

async function scanOf(prefix, files) {
  const { runScan } = await import('../../src/runScan.js');
  const dir = mkdtempSync(join(mkTestTmp(prefix), 'p-'));
  for (const [k, v] of Object.entries(files)) { mkdirSync(dirname(join(dir, k)), { recursive: true }); writeFileSync(join(dir, k), v); }
  const { scan } = await runScan(dir, { deep: true });
  return scan.findings.filter((f) => f.parser === 'IR-TAINT');
}
const live = (fs, cwe) => fs.filter((f) => f.cwe === cwe && f.severity !== 'info' && !f._provenUnreachable && !(f.proof && /^proven-/.test(f.proof.verdict)));
const show = (fs) => JSON.stringify(fs.map((f) => [f.cwe, f.line, f.severity, f._provenUnreachable ? 'dominated' : '', f.vuln && f.vuln.slice(0, 40)]));

const DISPATCH = (sink) => `{-# LANGUAGE OverloadedStrings #-}
module Warehouse.RobotDispatch (consumeDispatches) where
import Control.Monad (void)
import qualified Data.ByteString.Lazy as BL
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Text.Encoding.Error (lenientDecode)
import Network.AMQP
import Shelly
data Dispatch = Dispatch { robot :: Text, bay :: Text }
parseDispatch :: BL.ByteString -> Maybe Dispatch
parseDispatch raw =
  case T.splitOn "|" (TE.decodeUtf8With lenientDecode (BL.toStrict raw)) of
    [r, b] -> Just (Dispatch r b)
    _ -> Nothing
consumeDispatches :: Channel -> IO ()
consumeDispatches chan =
  void $ consumeMsgs chan "robot.dispatch" Ack $ \\(msg, env) -> do
    mapM_ moveRobot (parseDispatch (msgBody msg))
    ackEnv env
moveRobot :: Dispatch -> IO ()
moveRobot d = shelly $ silently $
  ${sink}
`;

test('a message-queue value reaching `run_ "sh" ["-c", cmd]` through a callee is OS command injection (critical), not argument injection', async () => {
  const fs = await scanOf('hs-r11-a-', { 'src/Warehouse/RobotDispatch.hs': DISPATCH('run_ "sh" ["-c", "robotctl --robot " <> robot d <> " goto " <> bay d]') });
  assert.equal(live(fs, 'CWE-78').length, 1, show(fs));
  assert.equal(live(fs, 'CWE-88').length, 0, show(fs));
  assert.equal(live(fs, 'CWE-78')[0].severity, 'critical');
  assert.equal(live(fs, 'CWE-78')[0].shellInterpreter, 'sh');
});
test('REFUSES: the same value as a plain argument of a fixed program stays argument injection', async () => {
  const fs = await scanOf('hs-r11-b-', { 'src/Warehouse/RobotDispatch.hs': DISPATCH('run_ "robotctl" ["--robot", robot d, "goto", bay d]') });
  assert.equal(live(fs, 'CWE-78').length, 0, show(fs));
  assert.equal(live(fs, 'CWE-88').length, 1, show(fs));
});

const PARTS = (requested, cond) => `{-# LANGUAGE DataKinds #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeOperators #-}
module Orchestra.PartsDownload (PartsAPI, partsServer) where
import Control.Monad.IO.Class (liftIO)
import qualified Data.ByteString.Lazy as BL
import Data.List (isPrefixOf)
import Data.Text (Text)
import qualified Data.Text as T
import Servant
import System.Directory (canonicalizePath, doesFileExist)
import System.FilePath (addTrailingPathSeparator, (</>))
type PartsAPI = "parts" :> Capture "concert" Text :> Capture "file" Text :> Get '[OctetStream] BL.ByteString
partsRoot :: FilePath
partsRoot = "/srv/orchestra/parts"
partsServer :: Server PartsAPI
partsServer concert file = do
  root <- liftIO (canonicalizePath partsRoot)
  ${requested}
  let inside = addTrailingPathSeparator root \`isPrefixOf\` requested
  exists <- liftIO (doesFileExist requested)
  if ${cond}
    then liftIO (BL.readFile requested)
    else throwError err404
`;
test('a let-bound containment Bool in a conjunction dominates the read when the path was canonicalised under liftIO', async () => {
  const fs = await scanOf('hs-r11-c-', { 'src/Orchestra/PartsDownload.hs': PARTS('requested <- liftIO (canonicalizePath (partsRoot </> T.unpack concert </> T.unpack file))', 'inside && exists') });
  assert.equal(live(fs, 'CWE-22').length, 0, show(fs));
  assert.ok(fs.some((f) => f.cwe === 'CWE-22' && f._provenUnreachable), 'the read is reported as dominated by the guard, not dropped: ' + show(fs));
});
test('REFUSES: the same check on a path that was not canonicalised is only a weak guard', async () => {
  const fs = await scanOf('hs-r11-d-', { 'src/Orchestra/PartsDownload.hs': PARTS('let requested = partsRoot </> T.unpack concert </> T.unpack file', 'inside && exists') });
  assert.equal(live(fs, 'CWE-22').length, 1, show(fs));
});
test('REFUSES: a disjunction with the containment check does not dominate', async () => {
  const fs = await scanOf('hs-r11-e-', { 'src/Orchestra/PartsDownload.hs': PARTS('requested <- liftIO (canonicalizePath (partsRoot </> T.unpack concert </> T.unpack file))', 'inside || exists') });
  assert.equal(live(fs, 'CWE-22').length, 1, show(fs));
});

const PHOTOS = (pred) => `{-# LANGUAGE OverloadedStrings #-}
module Apiary.Photos (photoRoutes) where
import Control.Monad.IO.Class (liftIO)
import qualified Data.ByteString as BS
import Data.Char (isAlphaNum)
import Data.Text (Text)
import qualified Data.Text as T
import Network.HTTP.Types (status400)
import Web.Spock
photoDir :: FilePath
photoDir = "/srv/apiary/photos/"
hiveNameOk :: Text -> Bool
hiveNameOk n = not (T.null n) && T.length n <= 32 && ${pred}
photoRoutes :: SpockM () () () ()
photoRoutes =
  get ("hives" <//> var <//> "photo") $ \\hive ->
    if hiveNameOk hive
      then do
        img <- liftIO (BS.readFile (photoDir ++ T.unpack hive ++ ".jpg"))
        setHeader "Content-Type" "image/jpeg"
        bytes img
      else do
        setStatus status400
        text "hive names are letters, digits and dashes"
`;
test('a top-level predicate whose lambda admits letters, digits and a dash is a character class (Data.Text.all)', async () => {
  const fs = await scanOf('hs-r11-f-', { 'src/Apiary/Photos.hs': PHOTOS("T.all (\\c -> isAlphaNum c || c == '-') n") });
  assert.equal(live(fs, 'CWE-22').length, 0, show(fs));
});
test('... and so is `elem c "-_"` beside the class check', async () => {
  const fs = await scanOf('hs-r11-g-', { 'src/Apiary/Photos.hs': PHOTOS("T.all (\\c -> isAlphaNum c || c `elem` (\"-_\" :: String)) n") });
  assert.equal(live(fs, 'CWE-22').length, 0, show(fs));
});
test('REFUSES: a lambda that also admits a dot or a slash is not a character class for a path', async () => {
  const dot = await scanOf('hs-r11-h-', { 'src/Apiary/Photos.hs': PHOTOS("T.all (\\c -> isAlphaNum c || c == '.') n") });
  const slash = await scanOf('hs-r11-i-', { 'src/Apiary/Photos.hs': PHOTOS("T.all (\\c -> isAlphaNum c || c == '/') n") });
  assert.equal(live(dot, 'CWE-22').length, 1, show(dot));
  assert.equal(live(slash, 'CWE-22').length, 1, show(slash));
});
