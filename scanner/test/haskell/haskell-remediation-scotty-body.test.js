// The scotty request-body limit fixer (CWE-770, `hs-scotty-body-limit`) and the rule knowledge it relies on.
//
// scotty's `body` reads the whole request body; the bound the library offers is application-wide (`setMaxRequestBodySize :: Kilobytes ->
// ScottyM ()`, scotty 0.12 and later, a 413 before any handler runs). The fixer adds one call as the first statement of the ScottyM block
// that contains the read or names the handler, with a declared default the operator must review. The rule then treats every body read of
// that block (and of the handlers it names) as bounded, so the rescan goes quiet for the right reason; a limit in ANOTHER file keeps the
// finding at low with its reach stated as unverified, and the fixer refuses to edit that other file.
//
// Every verified case goes through the REAL scanner and `validateHaskellFix` with the compile gate requested. scotty is not installed where
// this runs, so `Web.Scotty` is a declared STUB of the documented API shape (the names, `setMaxRequestBodySize :: Int -> ScottyM ()`); a
// type-check against it proves the patch is coherent with that shape, not that it builds against the real package.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { runScan } from '../../src/runScan.js';
import { planHaskellFix, validateHaskellFix, haskellEffectiveCheck, TIERS, SUPPORTED_FIX_IDS, SCOTTY_LIMIT_DEF, SCOTTY_LIMIT_KB } from '../../src/language/haskell-fix.js';
import { mkTestTmp } from '../helpers/tmp.js';

// The stub and the patch need only boot packages; a host's GHC package environment file can hide them (see haskell-remediation-kdf.test.js).
process.env.GHC_ENVIRONMENT = '-';
const GHC = !spawnSync('ghc', ['--numeric-version'], { encoding: 'utf8' }).error;

async function scan(files) {
  const dir = mkTestTmp('hs-fix-scotty-body-');
  writeFileSync(join(dir, 'package.json'), '{}');
  for (const [f, text] of Object.entries(files)) { mkdirSync(dirname(join(dir, f)), { recursive: true }); writeFileSync(join(dir, f), text); }
  const r = await runScan(dir, { deep: true });
  return [...(r.scan.findings || [])].filter((f) => !(f.proof && /^proven-/.test(f.proof.verdict)));
}
const bodyFindings = (fs) => fs.filter((x) => x.rule === 'hs-unbounded-request-body' && x.severity !== 'info');

const STUB_SCOTTY = `module Web.Scotty (scotty, get, post, body, text, setMaxRequestBodySize, ScottyM, ActionM) where
import qualified Data.ByteString.Lazy as BL
import qualified Data.Text.Lazy as TL
-- documented: setMaxRequestBodySize :: Kilobytes -> ScottyM (), type Kilobytes = Int; body :: ActionM ByteString (lazy)
type ScottyM = IO
type ActionM = IO
scotty :: Int -> ScottyM () -> IO ()
scotty _ m = m
get :: String -> ActionM () -> ScottyM ()
get _ a = a
post :: String -> ActionM () -> ScottyM ()
post _ a = a
body :: ActionM BL.ByteString
body = pure BL.empty
text :: TL.Text -> ActionM ()
text _ = pure ()
setMaxRequestBodySize :: Int -> ScottyM ()
setMaxRequestBodySize kb = if kb > 0 then pure () else error "the limit must be positive"
`;
const INLINE = `{-# LANGUAGE OverloadedStrings #-}
module Main (main) where

import Web.Scotty
import Data.Text.Lazy.Encoding (decodeUtf8)

main :: IO ()
main = scotty 3000 $ do
    post "/readbody" $ do
        b <- body
        text (decodeUtf8 b)
`;
const NAMED = `{-# LANGUAGE OverloadedStrings #-}
module Main (main) where

import Web.Scotty
import Data.Text.Lazy.Encoding (decodeUtf8)

main :: IO ()
main = do
    putStrLn "starting"
    scotty 3000 $ do
        post "/readbody" readBody

readBody :: ActionM ()
readBody = do
    b <- body
    text (decodeUtf8 b)
`;
const CABAL = (bound) => `cabal-version: 2.4\nname: app\nversion: 0.1\n\nexecutable app\n  main-is: Main.hs\n  build-depends: base, scotty ${bound}, text\n  default-language: Haskell2010\n`;

async function verified(files, line) {
  const before = await scan(files);
  const finding = bodyFindings(before).find((f) => f.file === 'src/Main.hs' && f.line === line);
  assert.ok(finding, `the body read is reported at line ${line}: ${JSON.stringify(bodyFindings(before).map((f) => [f.file, f.line]))}`);
  const plan = planHaskellFix(finding, files);
  assert.equal(plan.ok, true, plan.reason);
  assert.equal(plan.ruleId, 'hs-scotty-body-limit');
  assert.equal(plan.label, 'MITIGATION');
  assert.equal(plan.tier, TIERS.edit);
  assert.ok(plan.after.includes(SCOTTY_LIMIT_DEF), 'the declared constant is defined in the file');
  assert.ok(plan.after.includes('import qualified Web.Scotty as AgenticScotty'));
  assert.ok(plan.consequences.some((c) => c.includes('413')) && plan.consequences.some((c) => /scotty 0\.12 or later/.test(c)), JSON.stringify(plan.consequences));
  const patched = { ...files, 'src/Main.hs': plan.after };
  const after = await scan(patched);
  assert.equal(bodyFindings(after).filter((f) => f.file === 'src/Main.hs').length, 0, 'the rescan is quiet because the block that holds or names the handler sets the limit');
  const eff = haskellEffectiveCheck(plan, patched);
  assert.equal(eff.ok, true, eff.detail);
  const v = await validateHaskellFix(finding, { files, compile: true });
  assert.equal(v.status, 'verified', JSON.stringify(v.gates));
  assert.equal(v.gates.rescan.originalGone, true);
  assert.equal(v.gates.effective.ok, true);
  if (GHC) assert.equal(v.gates.compile.ok, true, JSON.stringify(v.gates.compile));
  else assert.equal(v.gates.compile.ran, false, 'without GHC the compile gate must say it did not run');
  return plan;
}

test('inline route: the limit becomes the first statement of the scotty block that contains the read', async () => {
  const plan = await verified({ 'src/Main.hs': INLINE, 'Web/Scotty.hs': STUB_SCOTTY }, 10);
  const ls = plan.after.split('\n');
  const at = ls.findIndex((l) => /scotty 3000 \$ do$/.test(l));
  assert.equal(ls[at + 1], '    AgenticScotty.setMaxRequestBodySize agenticRequestBodyLimitKb');
  assert.equal(plan.behavior.kb, SCOTTY_LIMIT_KB);
});

test('named handler: the block that registers the handler gets the limit, with a cabal bound that admits scotty 0.12', async () => {
  const plan = await verified({ 'src/Main.hs': NAMED, 'app.cabal': CABAL('>= 0.11 && < 0.31'), 'Web/Scotty.hs': STUB_SCOTTY }, 15);
  const ls = plan.after.split('\n');
  const at = ls.findIndex((l) => /scotty 3000 \$ do$/.test(l));
  assert.equal(ls[at + 1], '        AgenticScotty.setMaxRequestBodySize agenticRequestBodyLimitKb', 'indented like the block\'s first statement');
  assert.ok(plan.consequences.some((c) => /app\.cabal/.test(c)));
});

test('effective check: a patch that adds the limit elsewhere, or touches a body read, fails it', async () => {
  const files = { 'src/Main.hs': INLINE, 'Web/Scotty.hs': STUB_SCOTTY };
  const finding = bodyFindings(await scan(files)).find((f) => f.line === 10);
  const plan = planHaskellFix(finding, files);
  assert.equal(plan.ok, true);
  const moved = plan.after.replace('    AgenticScotty.setMaxRequestBodySize agenticRequestBodyLimitKb\n', '').replace(/\n$/, '\n\nlimit :: ScottyM ()\nlimit = AgenticScotty.setMaxRequestBodySize agenticRequestBodyLimitKb\n');
  assert.equal(haskellEffectiveCheck(plan, { ...files, 'src/Main.hs': moved }).ok, false, 'the limit is not where the plan put it');
  const twice = plan.after.replace('b <- body', 'b <- body\n        c <- body');
  assert.equal(haskellEffectiveCheck(plan, { ...files, 'src/Main.hs': twice }).ok, false, 'a body read changed');
  assert.equal(haskellEffectiveCheck(plan, { ...files, 'src/Main.hs': plan.after.replace(`agenticRequestBodyLimitKb = ${SCOTTY_LIMIT_KB}`, 'agenticRequestBodyLimitKb = 0') }).ok, false, 'the constant is not the declared one');
});

test('refusals: the block in another file, a cabal bound that excludes scotty 0.12, a taken name, and a non-scotty body read', async () => {
  const handlers = `{-# LANGUAGE OverloadedStrings #-}\nmodule Handlers (readBody) where\n\nimport Web.Scotty\nimport Data.Text.Lazy.Encoding (decodeUtf8)\n\nreadBody :: ActionM ()\nreadBody = do\n    b <- body\n    text (decodeUtf8 b)\n`;
  const main = `{-# LANGUAGE OverloadedStrings #-}\nmodule Main (main) where\n\nimport Web.Scotty\nimport Handlers (readBody)\n\nmain :: IO ()\nmain = scotty 3000 $ do\n    post "/readbody" readBody\n`;
  const split = { 'src/Main.hs': main, 'src/Handlers.hs': handlers };
  const f1 = bodyFindings(await scan(split)).find((f) => f.file === 'src/Handlers.hs');
  assert.ok(f1);
  const p1 = planHaskellFix(f1, split);
  assert.equal(p1.ok, false);
  assert.equal(p1.tier, TIERS.guidance);
  assert.match(p1.reason, /refused when the block is in another file/);
  const bounded = { 'src/Main.hs': INLINE, 'app.cabal': CABAL('< 0.12') };
  const f2 = bodyFindings(await scan(bounded)).find((f) => f.line === 10);
  assert.ok(f2);
  assert.equal(planHaskellFix(f2, bounded).ok, false, 'the declared bound excludes every version with the limit');
  const taken = { 'src/Main.hs': INLINE.replace(/\n$/, '\n\nagenticRequestBodyLimitKb :: Int\nagenticRequestBodyLimitKb = 7\n') };
  const f3 = bodyFindings(await scan(taken)).find((f) => f.line === 10);
  assert.ok(f3);
  assert.equal(planHaskellFix(f3, taken).ok, false, 'a name of ours is taken');
  assert.ok(SUPPORTED_FIX_IDS.includes('hs-scotty-body-limit'));
});
