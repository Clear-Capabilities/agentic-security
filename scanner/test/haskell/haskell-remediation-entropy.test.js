// hs-random-os-entropy, the three shapes of real true positives that had no fix (bench/dag/dev-haskell: scotty's session id,
// gitit's session key, hackage-server's digest nonce): a character range under replicateM, an integer-literal range, and randomRs under
// newStdGen. System.Entropy is imported when missing (the patch is then a MITIGATION: `entropy` must be declared by the component). Each
// patch is type-checked under GHC against a declared stub of the documented `getEntropy :: Int -> IO ByteString`, and the effective check
// proves the edited line reads the stated number of bytes and no longer calls System.Random.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { planHaskellFix, validateHaskellFix } from '../../src/language/haskell-fix.js';

process.env.GHC_ENVIRONMENT = '-';
const GHC = !spawnSync('ghc', ['--numeric-version'], { encoding: 'utf8' }).error;
const STUB_ENTROPY = `module System.Entropy (getEntropy) where
import qualified Data.ByteString as B
-- documented: getEntropy :: Int -> IO ByteString
getEntropy :: Int -> IO B.ByteString
getEntropy n = B.take n <$> B.readFile "entropy.bin"
`;
const STUB_RANDOM = `module System.Random (randomRIO, randomRs, newStdGen, StdGen) where
data StdGen = StdGen
randomRIO :: (a, a) -> IO a
randomRIO (lo, _) = pure lo
randomRs :: (Int, Int) -> StdGen -> [Int]
randomRs (lo, _) _ = repeat lo
newStdGen :: IO StdGen
newStdGen = pure StdGen
`;
const finding = (file, line) => ({ cwe: 'CWE-338', rule: 'hs-predictable-random', file, line, severity: 'high', vuln: 'Predictable random value' });

async function verified(files, file, line) {
  const plan = planHaskellFix(finding(file, line), files);
  assert.equal(plan.ok, true, JSON.stringify(plan));
  const v = await validateHaskellFix(finding(file, line), { files, compile: true });
  assert.equal(v.gates.syntax.ok, true, JSON.stringify(v.gates.syntax));
  assert.equal(v.gates.effective.ok, true, JSON.stringify(v.gates.effective));
  if (GHC) { assert.equal(v.gates.compile.ran, true, 'ghc ran'); assert.equal(v.gates.compile.ok, true, JSON.stringify(v.gates.compile)); assert.equal(v.status, 'verified', v.reason); }
  return plan;
}

test('scotty: replicateM 32 (randomRIO (a, z)) becomes 32 entropy bytes mapped into the range', async () => {
  const files = {
    'Web/Session.hs': `module Web.Session (createSession) where
import Control.Monad (replicateM)
import qualified Data.Text as T
import System.Random (randomRIO)

createSession :: IO T.Text
createSession = do
    sId <- T.pack <$> replicateM 32 (randomRIO ('a', 'z'))
    return sId
`,
    'System/Entropy.hs': STUB_ENTROPY, 'System/Random.hs': STUB_RANDOM,
  };
  const plan = await verified(files, 'Web/Session.hs', 8);
  assert.equal(plan.label, 'MITIGATION');
  assert.match(plan.after, /sId <- T\.pack <\$> \(map \(\\b -> toEnum \(fromEnum 'a' \+ fromIntegral b `mod` \(fromEnum 'z' - fromEnum 'a' \+ 1\)\)\) \. AgenticBS\.unpack <\$> getEntropy 32\)/);
  assert.match(plan.after, /^import System\.Entropy \(getEntropy\)$/m);
  assert.doesNotMatch(plan.after, /^import System\.Random/m, 'the unused System.Random import is dropped');
  assert.ok(plan.consequences.some((c) => /add `entropy` to build-depends/.test(c)));
});

test('gitit: randomRIO (0, 1000000000) becomes 8 entropy bytes reduced into the range', async () => {
  const files = {
    'State.hs': `module State (newSession) where
import System.Random (randomRIO)

newtype SessionKey = SessionKey Int

newSession :: IO SessionKey
newSession = do
  key <- SessionKey <$> randomRIO (0, 1000000000)
  return key
`,
    'System/Entropy.hs': STUB_ENTROPY, 'System/Random.hs': STUB_RANDOM,
  };
  const plan = await verified(files, 'State.hs', 8);
  assert.match(plan.after, /key <- SessionKey <\$> \(\(\\w -> 0 \+ fromIntegral \(w `mod` 1000000001\)\) \. AgenticBS\.foldl' \(\\acc b -> acc \* 256 \+ fromIntegral b\) \(0 :: Integer\) <\$> getEntropy 8\)/);
});

test('hackage-server: (take 32 . map intToDigit . randomRs (0, 15)) under newStdGen becomes 32 entropy bytes', async () => {
  const files = {
    'Auth.hs': `module Auth (generateNonce, generateNonce2) where
import Data.Char (intToDigit)
import System.Random (randomRs, newStdGen)

generateNonce :: IO String
generateNonce = fmap (take 32 . map intToDigit . randomRs (0, 15)) newStdGen

generateNonce2 :: IO String
generateNonce2 = (take 16 . map intToDigit . randomRs (0, 15)) <$> newStdGen
`,
    'System/Entropy.hs': STUB_ENTROPY, 'System/Random.hs': STUB_RANDOM,
  };
  const plan = await verified(files, 'Auth.hs', 6);
  assert.match(plan.after, /generateNonce = \(map \(intToDigit \. \(\\b -> 0 \+ fromIntegral b `mod` 16\)\) \. AgenticBS\.unpack <\$> getEntropy 32\)/);
  assert.match(plan.after, /^import System\.Random \(randomRs, newStdGen\)$/m, 'the second generator still uses both names, so the import stays');
  const plan2 = planHaskellFix(finding('Auth.hs', 9), files);
  assert.equal(plan2.ok, true);
  assert.match(plan2.after, /getEntropy 16\)/);
});

test('shapes that stay refused: a non-literal range, and a file that already names the ByteString alias', () => {
  const nonLiteral = { 'S.hs': 'module S (f) where\nimport System.Random (randomRIO)\nf :: Int -> IO Int\nf n = randomRIO (0, n)\n' };
  assert.equal(planHaskellFix(finding('S.hs', 4), nonLiteral).ok, false);
  const taken = { 'S.hs': 'module S (f) where\nimport qualified Data.ByteString as AgenticBS\nimport System.Random (randomRIO)\nf :: IO Int\nf = randomRIO (0, 9)\n' };
  assert.equal(planHaskellFix(finding('S.hs', 5), taken).ok, false);
});
