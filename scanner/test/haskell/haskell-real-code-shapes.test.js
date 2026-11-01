// Shapes the real-code precision sets (bench/dag/dev-haskell, bench/haskell-precision) showed as false positives in 0.195.8, each pinned in
// both directions: the shape that was wrong is quiet, and the nearest shape that is a real finding still fires.
//
// The two trust-boundary shapes (a path parameter handed on whole; a file name from a command-line program's standard input) are pinned in
// haskell-trust-boundary.test.js. This file holds the two rule shapes.
import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeHaskellRules } from '../../src/language/haskell-security-rules.js';

const mod = (imports, body, header = 'module Svc where') => `${header}\n\n${imports.join('\n')}\n\n${body}\n`;
const rules = (src) => analyzeHaskellRules({ 'Svc.hs': src }).findings;
const has = (src, id) => rules(src).some((f) => f.id === id || f.rule === id);

test('cookie helper: a scotty cookie helper whose NAME is its own parameter is decided by the caller; a session name passed to it is still reported', () => {
  const imports = ['import Web.Scotty', 'import Web.Scotty.Cookie', 'import Data.Text (Text)', 'import qualified Data.Text as T'];
  // scotty's own `setSimpleCookie n v = setCookie $ makeSimpleCookie n v` and `deleteCookie c = setCookie $ (makeSimpleCookie c "") {..}`
  assert.ok(!has(mod(imports, 'setNamed :: Text -> Text -> ActionM ()\nsetNamed n v = setSimpleCookie n v'), 'hs-insecure-cookie'), 'the name is a parameter: the helper is generic');
  assert.ok(!has(mod(imports, 'forget :: Text -> ActionM ()\nforget c = setCookie $ (makeSimpleCookie c "") { setCookiePath = Just "/" }'), 'hs-insecure-cookie'));
  // the site that passes a session name
  assert.ok(has(mod(imports, 'login :: Text -> ActionM ()\nlogin v = setSimpleCookie "session_id" v'), 'hs-insecure-cookie'));
  // a name computed in the function (not a parameter, not a literal) is still unknown and still reported
  assert.ok(has(mod(imports, 'remember :: Text -> ActionM ()\nremember v = do\n  let n = T.toLower "SESSION"\n  setSimpleCookie n v'), 'hs-insecure-cookie'));
});

test('sensitive logging: a value whose name says it is the HASH of a credential is the stored form, not the secret; the plain value is still reported', () => {
  const imports = ['import qualified Data.Text as T', 'import qualified Data.Text.IO as Text', 'import qualified IHP.AuthSupport.Authentication as Auth'];
  const tool = (out) => mod(imports, `main :: IO ()\nmain = do\n  plaintextPassword <- Text.getLine\n  hashedPassword <- Auth.hashPassword plaintextPassword\n  ${out}`, 'module Main (main) where');
  assert.ok(!has(tool('Text.putStrLn hashedPassword'), 'hs-sensitive-logging'), 'a hashing tool prints the hash it made');
  assert.ok(has(tool('Text.putStrLn plaintextPassword'), 'hs-sensitive-logging'), 'the plain password written out is still a finding');
  assert.ok(!has(mod(imports, 'audit :: T.Text -> IO ()\naudit tokenDigest = Text.putStrLn tokenDigest'), 'hs-sensitive-logging'));
  assert.ok(has(mod(imports, 'audit :: T.Text -> IO ()\naudit token = Text.putStrLn token'), 'hs-sensitive-logging'));
});
