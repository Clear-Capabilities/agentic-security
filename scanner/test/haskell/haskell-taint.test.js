// HS-005: Haskell field-sensitive interprocedural taint.
// Suite "haskell-taint" (HASKELL_NIXOS_FULL_CAPABILITY_PRD.md).
//
// All flows are real Haskell scanned through the public CLI. Expected spans are located by a marker in the
// source text, so the labels cannot drift from the code they describe.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { scoreLayer, scoreAllLayers, prf, LAYERS } from '../../src/language/accuracy.js';

const BIN = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'bin', 'agentic-security.js');

function scan(files) {
  const dir = mkdtempSync(join(tmpdir(), 'hs-taint-'));
  for (const [f, text] of Object.entries(files)) { mkdirSync(dirname(join(dir, f)), { recursive: true }); writeFileSync(join(dir, f), text); }
  const env = { ...process.env }; delete env.NODE_TEST_CONTEXT;
  const p = spawnSync(process.execPath, [BIN, 'scan', dir, '--format', 'json'], { encoding: 'utf8', timeout: 180000, env, maxBuffer: 64 * 1024 * 1024 });
  return JSON.parse(p.stdout).findings;
}
const lineOf = (src, marker, nth = 1) => { let n = 0; const ls = src.split('\n'); for (let i = 0; i < ls.length; i++) if (ls[i].includes(marker) && ++n === nth) return i + 1; throw new Error(`marker not found: ${marker}`); };
const taint = (fs) => fs.filter((f) => f.parser === 'IR-TAINT');
const live = (fs) => taint(fs).filter((f) => !(f.proof && /^proven-/.test(f.proof.verdict)));
const at = (fs, file, line) => taint(fs).filter((f) => f.file === file && f.line === line);

const UTIL = `module Util (Cfg(..), mkCfg, runCmd, passthrough, wrapUp, readIt) where
import System.Process (callCommand)
data Cfg = Cfg { cmd :: String, label :: String }
mkCfg :: String -> Cfg
mkCfg s = Cfg { cmd = s, label = "fixed" }
runCmd :: String -> IO ()
runCmd s = callCommand s
readIt :: String -> IO String
readIt p = readFile p
passthrough :: String -> String
passthrough = id
wrapUp :: String -> String
wrapUp s = "x " ++ s
`;
const MAIN = `module Main where
import Util
import System.Process (callCommand)
import System.FilePath (takeFileName)

crossFile :: IO ()
crossFile = do
  l <- getLine
  runCmd (wrapUp (passthrough l))

fieldTainted :: IO ()
fieldTainted = do
  l <- getLine
  let c = mkCfg l
  callCommand (cmd c)

fieldClean :: IO ()
fieldClean = do
  l <- getLine
  let c = mkCfg l
  callCommand (label c)

updated :: IO ()
updated = do
  l <- getLine
  let c = mkCfg l
  let c2 = c { label = "other" }
  callCommand (cmd c2)

contexts :: IO ()
contexts = do
  l <- getLine
  runCmd "ls"
  runCmd l

onlyClean :: IO ()
onlyClean = runCmd "ls -l"

composed :: IO ()
composed = callCommand . reverse =<< getLine

viaMap :: IO ()
viaMap = do
  ls <- fmap lines getContents
  mapM_ runCmd ls

sanitizedSibling :: Bool -> IO String
sanitizedSibling b = do
  l <- getLine
  if b then readIt (takeFileName l) else readIt l
`;

const corpus = scan({ 'src/Util.hs': UTIL, 'src/Main.hs': MAIN });
const MAINF = 'src/Main.hs';

// ---- AC01 ------------------------------------------------------------------

test('[HS-005.AC01] multi-hop flows through helpers and returns reach the correct sink at the call site, with ordered spans', () => {
  const sink = lineOf(MAIN, 'runCmd (wrapUp (passthrough l))');
  const f = at(corpus, MAINF, sink);
  assert.equal(f.length, 1);
  assert.equal(f[0].cwe, 'CWE-78');
  assert.equal(f[0].chain[0].line, lineOf(MAIN, 'l <- getLine', 1), 'the source span is the read on the line before');
  assert.ok(f[0].chain[0].line < f[0].line, 'source precedes sink');
  assert.equal(f[0].snippet, 'runCmd (wrapUp (passthrough l))');
  assert.equal(f[0].file, MAINF, 'reported where the program calls it, in the right file');
});

test('[HS-005.AC01] bind/do, composition, record fields and collection traversal reach their sinks', () => {
  assert.equal(at(corpus, MAINF, lineOf(MAIN, 'callCommand . reverse =<< getLine')).length, 1, 'composition with =<<');
  const comp = at(corpus, MAINF, lineOf(MAIN, 'callCommand . reverse =<< getLine'))[0];
  assert.equal(comp.chain[0].line, comp.line, 'the read and the use are on one line: a single span');
  assert.equal(at(corpus, MAINF, lineOf(MAIN, 'callCommand (cmd c)', 1)).length, 1, 'a tainted record field reaches the sink');
  assert.equal(at(corpus, MAINF, lineOf(MAIN, 'mapM_ runCmd ls')).length, 1, 'taint through fmap and mapM_');
});

test('[HS-005.AC01] a clean sibling record field stays clean, in both orders and after a record update', () => {
  assert.equal(at(corpus, MAINF, lineOf(MAIN, 'callCommand (label c)')).length, 0, 'label is built from a literal');
  assert.equal(at(corpus, MAINF, lineOf(MAIN, 'callCommand (cmd c2)')).length, 1, 'a record update keeps the tainted base field');
  const rev = scan({ 'src/R.hs': `module R where
import System.Process (callCommand)
data P = P { safe :: String, risky :: String }
build :: String -> P
build s = P { safe = "const", risky = s }
a :: IO ()
a = do
  l <- getLine
  let p = build l
  callCommand (safe p)
b :: IO ()
b = do
  l <- getLine
  let p = build l
  callCommand (risky p)
` });
  assert.equal(taint(rev).length, 1);
  assert.equal(taint(rev)[0].snippet, 'callCommand (risky p)');
});

test('[HS-005.AC01] a record built from request input keeps request-derived and constant fields apart', () => {
  const fs = scan({ 'src/Q.hs': `module Q where
import Web.Scotty
import System.Process (callCommand)
import qualified Data.Text.Lazy as TL
data Job = Job { target :: String, tag :: String }
handler :: ActionM ()
handler = do
  t <- param "t"
  let j = Job { target = TL.unpack t, tag = "nightly" }
  liftIO (callCommand (tag j))
  liftIO (callCommand (target j))
` });
  const f = taint(fs);
  assert.equal(f.length, 1);
  assert.equal(f[0].snippet, 'liftIO (callCommand (target j))');
  assert.equal(f[0].chain[0].provenance, 'url-param');
});

// ---- AC02 ------------------------------------------------------------------

test('[HS-005.AC02] a helper called with clean and tainted inputs is analysed per call context', () => {
  const clean = at(corpus, MAINF, lineOf(MAIN, 'runCmd "ls"'));
  const dirty = at(corpus, MAINF, lineOf(MAIN, 'runCmd l', 1));
  assert.equal(clean.length, 0, 'the clean call is not flagged');
  assert.equal(dirty.length, 1, 'the tainted call is');
  assert.equal(at(corpus, MAINF, lineOf(MAIN, 'runCmd "ls -l"')).length, 0, 'a function only ever called with constants has no finding');
  assert.equal(taint(corpus).filter((f) => f.file === 'src/Util.hs').length <= 1, true);
});

test('[HS-005.AC02] one sanitized branch cannot suppress an unprotected sibling branch', () => {
  const san = at(corpus, MAINF, lineOf(MAIN, 'if b then readIt (takeFileName l) else readIt l'));
  assert.equal(san.length, 2, 'both branches are sinks');
  const verdicts = san.map((f) => f.proof.verdict).sort();
  assert.deepEqual(verdicts, ['feasible', 'proven-clean'], 'the sanitized branch is discharged and its sibling is not');
  assert.equal(san.find((f) => f.proof.verdict === 'feasible').stableId !== san.find((f) => f.proof.verdict === 'proven-clean').stableId, true);
});

test('[HS-005.AC02] the same helper reached with different taint keeps independent verdicts across files', () => {
  const fs = scan({
    'src/H.hs': 'module H (go) where\nimport System.Process (callCommand)\ngo :: String -> IO ()\ngo s = callCommand s\n',
    'src/A.hs': 'module A where\nimport H\na :: IO ()\na = go "ls"\n',
    'src/B.hs': 'module B where\nimport H\nb :: IO ()\nb = do\n  x <- getLine\n  go x\n',
  });
  assert.equal(taint(fs).filter((f) => f.file === 'src/A.hs').length, 0);
  assert.equal(taint(fs).filter((f) => f.file === 'src/B.hs').length, 1);
});

// ---- AC03 ------------------------------------------------------------------

test('[HS-005.AC03] taint is widened across an unresolved call, and the finding discloses it', () => {
  const fs = scan({ 'src/U.hs': `module U where
import System.Process (callCommand)
run :: IO ()
run = do
  l <- getLine
  let r = mystery l
  callCommand r
` });
  const f = taint(fs);
  assert.equal(f.length, 1, 'the flow is kept, not dropped and not called safe');
  assert.equal(f[0].resolutionStatus, 'partial');
  assert.ok(f[0].uncertainty.some((u) => u.kind === 'unresolved-target' && /mystery/.test(u.detail)));
});

test('[HS-005.AC03] a higher-order parameter and a typeclass method with no instance are disclosed by reason', () => {
  const fs = scan({ 'src/HO.hs': `module HO where
import System.Process (callCommand)
class Shape a where area :: a -> String
viaParam :: (String -> String) -> IO ()
viaParam f = do
  l <- getLine
  callCommand (f l)
viaClass :: Shape a => a -> IO ()
viaClass x = do
  l <- getLine
  callCommand (area x ++ l)
` });
  const f = taint(fs);
  assert.equal(f.length, 2);
  const reasons = f.flatMap((x) => (x.uncertainty || []).map((u) => u.detail)).join(' | ');
  assert.match(reasons, /higher-order parameter/);
  assert.match(reasons, /typeclass method with no visible instance/);
});

test('[HS-005.AC03] a foreign function is an opaque boundary: taint crosses it and the finding says the code is not analysed', () => {
  const fs = scan({ 'src/F.hs': `module F where
import System.Process (callCommand)
foreign import ccall unsafe "string.h transform" c_transform :: String -> IO String
run :: IO ()
run = do
  l <- getLine
  r <- c_transform l
  callCommand r
` });
  const f = taint(fs);
  assert.equal(f.length, 1);
  const u = f[0].uncertainty.find((x) => x.kind === 'foreign-boundary');
  assert.ok(u, 'foreign boundary disclosed');
  assert.match(u.detail, /foreign function, the code behind it is not analysed/);
  assert.equal(f[0].resolutionStatus, 'partial');
});

test('[HS-005.AC03] a fully resolved flow carries no unresolved-target disclosure', () => {
  const f = at(corpus, MAINF, lineOf(MAIN, 'callCommand (cmd c)', 1))[0];
  assert.ok(!(f.uncertainty || []).some((u) => ['unresolved-target', 'foreign-boundary'].includes(u.kind)));
  assert.notEqual(f.resolutionStatus, 'partial');
});

// ---- AC04 ------------------------------------------------------------------

test('[HS-005.AC04] security-taint accuracy is computed by one-to-one matching and recorded separately from structural SAST', () => {
  const cases = [
    { id: 'crossFile', file: MAINF, expect: [{ cwe: 'CWE-78', line: lineOf(MAIN, 'runCmd (wrapUp (passthrough l))') }] },
    { id: 'fieldTainted', file: MAINF, expect: [{ cwe: 'CWE-78', line: lineOf(MAIN, 'callCommand (cmd c)', 1) }] },
    { id: 'composed', file: MAINF, expect: [{ cwe: 'CWE-78', line: lineOf(MAIN, 'callCommand . reverse =<< getLine') }] },
    { id: 'viaMap', file: MAINF, expect: [{ cwe: 'CWE-78', line: lineOf(MAIN, 'mapM_ runCmd ls') }] },
    { id: 'contexts', file: MAINF, expect: [{ cwe: 'CWE-78', line: lineOf(MAIN, 'runCmd l', 1) }] },
    { id: 'updated', file: MAINF, expect: [{ cwe: 'CWE-78', line: lineOf(MAIN, 'callCommand (cmd c2)') }] },
    { id: 'unprotectedSibling', file: MAINF, expect: [{ cwe: 'CWE-22', line: lineOf(MAIN, 'if b then readIt (takeFileName l) else readIt l') }] },
  ];
  // a project that ALSO has structural-SAST findings, which must not be counted as taint
  const mixed = scan({ 'src/Util.hs': UTIL, 'src/Main.hs': MAIN, 'src/Crypto.hs': 'module Crypto where\nimport Crypto.Hash.MD5 as MD5\nimport qualified Data.ByteString.Char8 as B\nh = MD5.hash (B.pack "x")\n' });
  const layers = scoreAllLayers(cases, mixed, ['security-taint', 'structural-sast', 'privacy-lineage']);
  const t = layers['security-taint'];
  assert.equal(t.fn, 0, JSON.stringify(t.misses));
  assert.equal(t.fp, 0, JSON.stringify(t.strays));
  assert.equal(t.tp, 7);
  assert.equal(t.precision, 1); assert.equal(t.recall, 1); assert.equal(t.f1, 1); assert.equal(t.measured, true);
  assert.ok(t.families['CWE-78'].tp >= 6 && t.families['CWE-22'].tp === 1, 'per-family counts');
  // the structural finding exists but is scored in its own layer, not here
  assert.ok(mixed.some((f) => f.parser === 'HS-RULES'));
  assert.equal(layers['structural-sast'].cases, cases.length, 'layers are scored independently over the same cases');
  assert.notEqual(layers['structural-sast'].tp, t.tp);
  // privacy lineage has no Haskell adapter yet: it is NOT MEASURED, never 100% and never borrowed from taint
  assert.equal(layers['privacy-lineage'].measured, false);
  assert.equal(layers['privacy-lineage'].precision, null);
  assert.equal(Object.keys(layers).includes('combined'), false, 'no combined headline number exists');
});

test('[HS-005.AC04] scoring rules: duplicates are not inflated, misses and strays count, empty denominators are not measured', () => {
  const f = (o) => ({ parser: 'IR-TAINT', file: 'a.hs', cwe: 'CWE-78', line: 3, ...o });
  const dup = scoreLayer([{ id: 'x', file: 'a.hs', expect: [{ cwe: 'CWE-78', line: 3 }] }], [f(), f()], { layer: 'security-taint' });
  assert.deepEqual([dup.tp, dup.fp, dup.fn], [1, 1, 0], 'the same vulnerability reported twice is one TP and one FP');
  const miss = scoreLayer([{ id: 'x', file: 'a.hs', expect: [{ cwe: 'CWE-78', line: 3 }] }], [], { layer: 'security-taint' });
  assert.deepEqual([miss.tp, miss.fp, miss.fn], [0, 0, 1], 'a missing detection is a false negative, not an exclusion');
  const wrongLine = scoreLayer([{ id: 'x', file: 'a.hs', expect: [{ cwe: 'CWE-78', line: 3 }] }], [f({ line: 9 })], { layer: 'security-taint' });
  assert.deepEqual([wrongLine.tp, wrongLine.fp, wrongLine.fn], [0, 1, 1]);
  const discharged = scoreLayer([{ id: 'x', file: 'a.hs', expect: [] }], [f({ proof: { verdict: 'proven-clean' } })], { layer: 'security-taint' });
  assert.equal(discharged.fp, 0, 'a flow the proof gate discharged is not a live detection');
  assert.equal(prf(0, 0, 0).precision, null); assert.equal(prf(0, 0, 0).measured, false);
  assert.equal(prf(0, 0, 3).recall, 0); assert.equal(prf(2, 0, 0).f1, 1);
  assert.deepEqual(Object.keys(LAYERS).sort(), ['config-sast', 'privacy-lineage', 'security-taint', 'structural-sast']);
  assert.throws(() => scoreLayer([], [], { layer: 'nope' }), /unknown layer/);
});

test('[HS-005.AC04] every live taint finding in the corpus is attributed to exactly one layer', () => {
  const all = live(corpus);
  assert.ok(all.length >= 7);
  for (const f of all) assert.equal(Object.values(LAYERS).filter((p) => p(f)).length, 1, `${f.file}:${f.line}`);
});
