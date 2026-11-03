// `hs-predictable-random` by FLOW: a System.Random value that becomes the value of a cookie is reported whatever the function and the variables
// are called. Pinned in both directions; sources are written for this file.

import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeHaskellRules } from '../../src/language/haskell-security-rules.js';

const rules = (src) => analyzeHaskellRules({ 'Svc.hs': src }).findings.filter((f) => f.rule === 'hs-predictable-random' || f.id === 'hs-predictable-random');
const mod = (imports, body) => `module Svc where\n\n${imports.join('\n')}\n\n${body}\n`;

test('random-flow: a generator value that becomes a scotty-cookie value is reported under a neutral function name', () => {
  const f = rules(mod(['import Web.Scotty', 'import Web.Scotty.Cookie', 'import System.Random', 'import qualified Data.Text as T', 'import Control.Monad.IO.Class'],
    `greet :: ActionM ()
greet = do
  g <- liftIO newStdGen
  let v = T.pack (take 16 (randomRs ('a', 'z') g))
  setSimpleCookie "sid" v
  text "hi"`));
  assert.equal(f.length, 1, JSON.stringify(f));
  assert.match(JSON.stringify(f[0]), /cookie/i);
});

test('random-flow: a generator value written into a hand-built Set-Cookie header is reported', () => {
  const f = rules(mod(['import Network.HTTP.Types.Header', 'import System.Random', 'import qualified Data.ByteString.Char8 as B', 'import Control.Monad.IO.Class'],
    `cookieHeader :: IO (HeaderName, B.ByteString)
cookieHeader = do
  n <- randomRIO (1 :: Int, 1000000)
  pure (hSetCookie, B.pack ("sid=" ++ show n))`));
  assert.equal(f.length, 1, JSON.stringify(f));
});

test('random-flow: a generator value in the setCookieValue field of a web-cookie record is reported', () => {
  const f = rules(mod(['import Web.Cookie', 'import System.Random', 'import qualified Data.ByteString.Char8 as B'],
    `mk :: IO SetCookie
mk = do
  n <- randomIO :: IO Int
  pure (defaultSetCookie { setCookieName = B.pack "sid", setCookieValue = B.pack (show n) })`));
  assert.equal(f.length, 1, JSON.stringify(f));
});

test('random-flow negatives: a constant or entropy cookie value, and a random value that never reaches a cookie, are silent', () => {
  assert.equal(rules(mod(['import Web.Scotty', 'import Web.Scotty.Cookie', 'import System.Entropy', 'import qualified Data.Text as T', 'import qualified Data.ByteString as BS', 'import Control.Monad.IO.Class'],
    `greet :: ActionM ()
greet = do
  b <- liftIO (getEntropy 16)
  setSimpleCookie "sid" (T.pack (show (BS.unpack b)))
  text "hi"`)).length, 0);
  assert.equal(rules(mod(['import Web.Scotty', 'import Web.Scotty.Cookie', 'import System.Random', 'import qualified Data.Text as T', 'import Control.Monad.IO.Class'],
    `greet :: ActionM ()
greet = do
  setSimpleCookie "theme" "dark"
  n <- liftIO (randomRIO (1 :: Int, 6))
  text (T.pack (show n))`)).length, 0);
  // a random value used only in a different header
  assert.equal(rules(mod(['import Network.HTTP.Types.Header', 'import System.Random', 'import qualified Data.ByteString.Char8 as B'],
    `hdr :: IO (HeaderName, B.ByteString)
hdr = do
  n <- randomRIO (1 :: Int, 9)
  pure (hRetryAfter, B.pack (show n))`)).length, 0);
});
