// The HTML-from-text fixer (CWE-79, `hs-html-escape-text`): scotty's `html` of concatenated text.
//
// On the real-code sets every scotty XSS true positive is `html $ mconcat ["<h1>", v, "</h1>"]` (the framework's own examples), a shape the
// blaze rewrite (`preEscapedToHtml` to `toHtml`) cannot touch because nothing is blaze. The fixer applies an escaper DEFINED IN THE FILE to
// every non-literal part of the concatenation (or to a whole argument that is one expression with no literal in it); the rescan recognises the
// escaper by the entities it spells out, not by its name. Verified cases go through the REAL scanner and `validateHaskellFix` with the compile
// gate requested against a declared STUB of scotty's documented API shape (scotty is not installed where this runs), and the escaper is RUN
// under GHC on hostile input. Where GHC is absent the compile assertions are skipped LOUDLY and the gate is asserted to say it did not run.

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { runScan } from '../../src/runScan.js';
import { planHaskellFix, validateHaskellFix, haskellEffectiveCheck, defaultRescan, HTML_TEXT_HELPER, TIERS } from '../../src/language/haskell-fix.js';
import { mkTestTmp } from '../helpers/tmp.js';

// the stub and the patch need only boot packages (base, text): a host's GHC package environment file must not hide them (see the 0190 suite)
process.env.GHC_ENVIRONMENT = '-';
const GHC = !spawnSync('ghc', ['--numeric-version'], { encoding: 'utf8' }).error;
const skipNoGhc = GHC ? false : 'GHC is not installed: compile verification could not run (this is a skip, not a pass)';

async function scan(files) {
  const dir = mkTestTmp('hs-fix-html-');
  writeFileSync(join(dir, 'package.json'), '{}');
  for (const [f, text] of Object.entries(files)) { mkdirSync(dirname(join(dir, f)), { recursive: true }); writeFileSync(join(dir, f), text); }
  const r = await runScan(dir, { deep: true });
  return [...(r.scan.findings || [])].filter((f) => !(f.proof && /^proven-/.test(f.proof.verdict)));
}
const xss = (fs) => fs.filter((x) => x.cwe === 'CWE-79' && x.severity !== 'info' && /^src\/[A-Z]/.test(x.file));

// documented subset of Web.Scotty: scotty :: Int -> ScottyM () -> IO (); get :: RoutePattern -> ActionM () -> ScottyM (); pathParam :: Parsable a => Text -> ActionM a;
// html :: Text -> ActionM (); text :: Text -> ActionM (). The monads are IO in this stub and the route pattern is a String.
const STUB_SCOTTY = `module Web.Scotty (scotty, get, pathParam, html, text, ScottyM, ActionM) where
import qualified Data.Text.Lazy as TL
type ScottyM = IO
type ActionM = IO
scotty :: Int -> ScottyM () -> IO ()
scotty _ m = m
get :: String -> ActionM () -> ScottyM ()
get _ a = a
pathParam :: TL.Text -> ActionM TL.Text
pathParam = pure
html :: TL.Text -> ActionM ()
html _ = pure ()
text :: TL.Text -> ActionM ()
text _ = pure ()
`;
const APP = `{-# LANGUAGE OverloadedStrings #-}
module App (app) where

import Web.Scotty
import qualified Data.Text.Lazy as TL

app :: IO ()
app = scotty 3000 $ do
  get "/hello/:name" $ do
    v <- pathParam "name"
    html $ mconcat ["<h1>", v, "</h1>"]
  get "/shout/:name" $ do
    v <- pathParam "name"
    html (TL.toUpper v)
  get "/plain/:name" $ do
    v <- pathParam "name"
    text v
`;
const FILES = { 'src/App.hs': APP, 'Web/Scotty.hs': STUB_SCOTTY };
// The stub is for the COMPILER only: a project module named Web.Scotty would shadow the catalog's scotty source and sink in a scan (the
// scanner would analyse the stub's `html _ = pure ()` instead of the registry entry), so every scan and rescan sees the tree without it.
const noStub = (fs) => Object.fromEntries(Object.entries(fs).filter(([k]) => !k.startsWith('Web/')));
const rescan = (fs) => defaultRescan(noStub(fs));

const MAIN_RUN = `module Main (main) where
import App
import qualified Data.Text.Lazy as TL
main :: IO ()
main = do
  putStrLn (TL.unpack (agenticEscapeHtml (TL.pack "<script>alert('x')</script>&\\"")))
  putStrLn (TL.unpack (agenticEscapeHtml (TL.pack "plain text 123")))
`;

test('concatenation: every non-literal part of `html $ mconcat [...]` passes through the file-defined escaper; rescan, effective check and compile (against a stub of scotty) pass', async () => {
  const fs = await scan(noStub(FILES));
  const f = xss(fs).find((x) => x.line === 11);
  assert.ok(f, JSON.stringify(xss(fs).map((x) => [x.line, x.vuln])));
  const v = await validateHaskellFix(f, { files: FILES, compile: GHC, rescan });
  assert.equal(v.status, 'verified', JSON.stringify({ reason: v.reason, gates: v.gates }));
  assert.equal(v.plan.ruleId, 'hs-html-escape-text');
  assert.equal(v.label, 'MITIGATION');
  assert.equal(v.tier, TIERS.edit);
  assert.equal(v.gates.rescan.originalGone, true);
  assert.equal(v.gates.effective.ok, true, v.gates.effective.detail);
  if (GHC) assert.deepEqual([v.gates.compile.ran, v.gates.compile.ok], [true, true], v.gates.compile.detail);
  else assert.deepEqual([v.gates.compile.ran, v.gates.compile.ok], [false, null]);
  assert.match(v.plan.after, /^    html \$ mconcat \["<h1>", agenticEscapeHtml v, "<\/h1>"\]$/m);
  assert.match(v.plan.after, /^    html \(TL\.toUpper v\)$/m, 'the other html call is untouched (its own finding gets its own fix)');
  assert.ok(v.plan.after.includes(HTML_TEXT_HELPER) && v.plan.after.includes('import qualified Data.Text.Lazy as AgenticTL'));
  assert.ok(v.consequences.some((c) => /<script>/.test(c)), 'the limit of the escaping is stated');
  // the other finding stays reported after this patch and is fixed by the whole-argument form, reusing the one helper
  const after = { ...FILES, 'src/App.hs': v.plan.after };
  const rest = xss(await scan(noStub(after)));
  assert.equal(rest.length, 1, JSON.stringify(rest.map((x) => [x.line, x.vuln])));
  const v2 = await validateHaskellFix(rest[0], { files: after, compile: GHC, rescan });
  assert.equal(v2.status, 'verified', JSON.stringify({ reason: v2.reason, gates: v2.gates }));
  assert.match(v2.plan.after, /^    html \(agenticEscapeHtml \(TL\.toUpper v\)\)$/m);
  assert.equal((v2.plan.after.match(/agenticEscapeHtml :: /g) || []).length, 1, 'one helper for the file');
  assert.equal(xss(await scan({ 'src/App.hs': v2.plan.after })).length, 0);
});

test('the escaper is RUN under GHC: hostile markup becomes entities, plain text is unchanged', { skip: skipNoGhc }, () => {
  const plan = planHaskellFix({ cwe: 'CWE-79', file: 'src/App.hs', line: 11 }, { ...FILES, 'src/App.hs': APP.replace('module App (app) where', 'module App where') });
  assert.equal(plan.ok, true, plan.reason);
  const dir = mkTestTmp('hs-html-run-');
  for (const [f, t] of Object.entries({ ...FILES, 'src/App.hs': plan.after, 'Main.hs': MAIN_RUN })) { mkdirSync(dirname(join(dir, f)), { recursive: true }); writeFileSync(join(dir, f), t); }
  const r = spawnSync('runghc', ['-isrc', '-i.', 'Main.hs'], { cwd: dir, encoding: 'utf8', timeout: 180000 });
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(r.stdout.split('\n').filter(Boolean), ['&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;&amp;&quot;', 'plain text 123']);
});

test('effective check: the finding going quiet is not enough; the escaper must be defined and applied the planned number of times', () => {
  const plan = planHaskellFix({ cwe: 'CWE-79', file: 'src/App.hs', line: 11 }, FILES);
  assert.equal(plan.ok, true, plan.reason);
  assert.equal(haskellEffectiveCheck(plan, { 'src/App.hs': plan.after }).ok, true);
  const noHelper = plan.after.replace(HTML_TEXT_HELPER, 'agenticEscapeHtml :: AgenticTL.Text -> AgenticTL.Text\nagenticEscapeHtml = id\n');
  const e1 = haskellEffectiveCheck(plan, { 'src/App.hs': noHelper });
  assert.equal(e1.ok, false); assert.match(e1.detail, /escaper is not defined/);
  const unwrapped = plan.after.replace('html $ mconcat ["<h1>", agenticEscapeHtml v, "</h1>"]', 'html $ mconcat ["<h1>", "", "</h1>"]');
  const e2 = haskellEffectiveCheck(plan, { 'src/App.hs': unwrapped });
  assert.equal(e2.ok, false); assert.match(e2.detail, /not in the patched file as planned/);
});

test('refusals: no scotty import, no Data.Text.Lazy import, a nested construction, a renderer, an argument that is a literal, a taken name; and the blaze fixer still owns preEscapedToHtml', () => {
  const at = (src, line = 11, extra = {}) => planHaskellFix({ cwe: 'CWE-79', file: 'src/App.hs', line }, { 'src/App.hs': src, 'Web/Scotty.hs': STUB_SCOTTY, ...extra });
  const refused = (r, why) => { assert.equal(r.ok, false, why); assert.equal(r.tier, TIERS.guidance); assert.match(r.reason, /only blaze-html's preEscapedToHtml and scotty's html of concatenated text are rewritten/); };
  refused(at(APP.replace('import Web.Scotty', 'import Web.Spock')), 'not scotty');
  refused(at(APP.replace('import qualified Data.Text.Lazy as TL', 'import qualified Data.Text as TL')), 'text is not shown to be declared');
  refused(at(APP.replace('html $ mconcat ["<h1>", v, "</h1>"]', 'html $ mconcat ["<h1>", mconcat ["<b>", v, "</b>"], "</h1>"]')), 'a nested construction');
  refused(at(APP.replace('html $ mconcat ["<h1>", v, "</h1>"]', 'html $ mconcat ["<h1>", renderName v, "</h1>"]')), 'a renderer');
  refused(at(APP.replace('html $ mconcat ["<h1>", v, "</h1>"]', 'html "<h1>static</h1>"')), 'a literal alone');
  refused(at(APP.replace('html $ mconcat ["<h1>", v, "</h1>"]', 'html $ mconcat [v, v]')), 'no markup to be concatenated into');
  refused(at(`${APP}\nagenticEscapeHtml :: Int\nagenticEscapeHtml = 1\n`), 'the helper name is taken');
  const blaze = planHaskellFix({ cwe: 'CWE-79', file: 'src/B.hs', line: 5 }, { 'src/B.hs': 'module B (page) where\nimport Text.Blaze.Html (Html, preEscapedToHtml)\n\npage :: String -> Html\npage s = preEscapedToHtml s\n' });
  assert.equal(blaze.ok, true); assert.equal(blaze.ruleId, 'hs-html-escape');
});
