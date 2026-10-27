// Comment invariance. A verdict about Haskell code must come from the code, never from what a comment says about it. This suite scans the
// Haskell example projects and a spread of corpus-shaped sources three ways and requires the findings to be IDENTICAL:
//   1. the source as written,
//   2. every comment blanked out (same length, same line breaks, so locations do not move),
//   3. every comment replaced by text that lies: "safe, sanitized" on the code that is vulnerable, "vulnerable" on the code that is safe, plus a
//      trailing comment of the same kind appended to every code line.
// A finding is compared by file, line, parser, rule, CWE, family, vulnerability text, severity, trust verdict, proof verdict, snippet and stable id. If the engine ever varies with a
// comment, this test fails and the engine is wrong.

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '../../src/runScan.js';
import { mkTestTmp } from '../helpers/tmp.js';
import { findComments, stripComments, lieAboutComments } from '../helpers/haskell-comments.js';
import { codeOfLine } from '../../src/language/haskell-comments.js';
import { annotateHaskellFindings } from '../../src/language/haskell-findings.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, '..', '..', '..');
function haskellFilesOf(dir) {
  const out = [];
  for (const e of readdirSync(dir)) {
    const p = join(dir, e);
    const st = statSync(p);
    if (st.isDirectory()) { if (e !== '.agentic-security' && e !== 'dist-newstyle') out.push(...haskellFilesOf(p)); } else if (/\.(hs|cabal|yaml|project)$/.test(e)) out.push(p);
  }
  return out;
}

async function scanFiles(files) {
  const dir = mkTestTmp('hs-cmt-');
  writeFileSync(join(dir, 'package.json'), '{}');
  for (const [f, text] of Object.entries(files)) { mkdirSync(dirname(join(dir, f)), { recursive: true }); writeFileSync(join(dir, f), text); }
  const r = await runScan(dir, { deep: true });
  return [...(r.scan.findings || [])]
    .filter((f) => /\.(hs|lhs)$/.test(f.file || ''))
    .map((f) => [f.file, f.line, f.parser, f.rule || '', f.cwe || '', f.family || '', f.vuln || '', f.severity, f.trustBoundary ? f.trustBoundary.verdict : '', (f.proof && f.proof.verdict) || '', f.snippet || '', f.stableId || ''].join('|'))
    .sort();
}

const exampleDirs = ['examples/haskell-app/vulnerable', 'examples/haskell-app/fixed', 'examples/haskell-app/partial', 'examples/haskell-on-nix/vulnerable'];

for (const ex of exampleDirs) {
  test(`comment invariance: ${ex}`, async () => {
    const root = join(REPO, ex);
    const files = {};
    for (const p of haskellFilesOf(root)) files[relative(root, p)] = readFileSync(p, 'utf8');
    const hs = Object.keys(files).filter((f) => /\.hs$/.test(f));
    assert.ok(hs.length > 0);
    const mapAll = (fn) => Object.fromEntries(Object.entries(files).map(([f, t]) => [f, /\.hs$/.test(f) ? fn(t) : t]));
    const asWritten = await scanFiles(files);
    const stripped = await scanFiles(mapAll(stripComments));
    const saysSafe = await scanFiles(mapAll((t) => lieAboutComments(t, 'safe, sanitized')));
    const saysVulnerable = await scanFiles(mapAll((t) => lieAboutComments(t, 'vulnerable')));
    assert.deepEqual(stripped, asWritten, 'blanking the comments changed the findings');
    assert.deepEqual(saysSafe, asWritten, 'comments that claim the code is safe changed the findings');
    assert.deepEqual(saysVulnerable, asWritten, 'comments that claim the code is vulnerable changed the findings');
  });
}

test('comment invariance: corpus-shaped sources, one vulnerable and one safe case of every family (each scanned as its own project)', async () => {
  const dataDir = join(REPO, 'scanner', 'test', 'language', 'corpora', 'data');
  const labels = JSON.parse(readFileSync(join(dataDir, 'labels', 'cases.json'), 'utf8')).filter((c) => c.ecosystem === 'haskell' && c.split === 'train' && c.label !== 'unknown');
  // the first train case of every (family, label) in file order: a deterministic spread that covers each rule family both ways
  const seen = new Set();
  const picked = [];
  for (const c of labels) { const k = `${c.family}|${c.label}`; if (!seen.has(k)) { seen.add(k); picked.push(c); } }
  assert.ok(picked.length >= 20, `only ${picked.length} cases picked`);
  let withFindings = 0;
  for (const c of picked) {
    const dir = join(dataDir, 'sources', 'haskell', c.id);
    const files = {};
    for (const p of haskellFilesOf(dir)) files[relative(dir, p)] = readFileSync(p, 'utf8');
    const mapAll = (fn) => Object.fromEntries(Object.entries(files).map(([f, t]) => [f, /\.hs$/.test(f) ? fn(t) : t]));
    const asWritten = await scanFiles(files);
    if (asWritten.length) withFindings++;
    assert.deepEqual(await scanFiles(mapAll(stripComments)), asWritten, `${c.family}/${c.label}: blanking the comments changed the findings`);
    assert.deepEqual(await scanFiles(mapAll((t) => lieAboutComments(t, 'safe, sanitized'))), asWritten, `${c.family}/${c.label}: comments claiming the code is safe changed the findings`);
    assert.deepEqual(await scanFiles(mapAll((t) => lieAboutComments(t, 'vulnerable'))), asWritten, `${c.family}/${c.label}: comments claiming the code is vulnerable changed the findings`);
  }
  assert.ok(withFindings >= 10, `the picked cases should produce findings (only ${withFindings} did)`);
});

const MIXED = `{-# LANGUAGE OverloadedStrings #-}
module Main (main) where

import Control.Monad.IO.Class (liftIO)
import System.FilePath (takeFileName)
import System.Process (callCommand)
import Web.Scotty

-- | SAFE: the name is validated and sanitized before it reaches the shell. (It is not.)
convert :: String -> IO ()
convert name = callCommand ("convert " ++ name ++ " out.png") -- sanitized, safe, reviewed

{- VULNERABLE path traversal: the file name is used directly. (It is not: takeFileName strips every directory.) -}
serve :: String -> IO String
serve name = readFile ("/srv/files/" ++ takeFileName name) -- vulnerable! path traversal!

main :: IO ()
main = scotty 3000 $ do
  get "/convert/:n" $ do
    n <- param "n"   -- trusted input, safe
    liftIO (convert n)
    text "ok"
  get "/file/:n" $ do
    n <- param "n"   -- user input, vulnerable
    body <- liftIO (serve n)
    text (fromString body)
`;

test('comments that lie in both directions do not move a verdict: the command injection is reported whatever its comment says, the sanitized path is not', async () => {
  const run = async (t) => (await scanFiles({ 'src/Main.hs': t }));
  const asWritten = await run(MIXED);
  const cmd = asWritten.filter((x) => x.includes('|CWE-78|'));
  const path = asWritten.filter((x) => x.includes('|CWE-22|') && !/\|proven-/.test(x));
  assert.ok(cmd.length >= 1, `the command injection must be found: ${JSON.stringify(asWritten)}`);
  assert.equal(path.length, 0, 'takeFileName is a real sanitizer; the comment calling it vulnerable changes nothing');
  assert.deepEqual(await run(stripComments(MIXED)), asWritten);
  assert.deepEqual(await run(lieAboutComments(MIXED, 'safe, sanitized')), asWritten);
  assert.deepEqual(await run(lieAboutComments(MIXED, 'vulnerable')), asWritten);
});

test('a finding snippet is the code of its line, never a comment on it (so its identity and its clone shape cannot depend on one)', () => {
  assert.equal(codeOfLine('  callCommand cmd -- safe, sanitized'), 'callCommand cmd');
  assert.equal(codeOfLine('x = "a -- b" ++ y   -- vulnerable'), 'x = "a -- b" ++ y');
  assert.equal(codeOfLine('  -- only a comment'), '');
  const f = { parser: 'IR-TAINT', file: 'A.hs', line: 2, cwe: 'CWE-78' };
  annotateHaskellFindings([f], { 'A.hs': 'module A where\nrun c = callCommand c -- sanitized upstream\n' });
  assert.equal(f.snippet, 'run c = callCommand c');
});

test('the comment finder: strings, character literals, pragmas and operators are not comments; block comments nest', () => {
  const src = '{-# LANGUAGE OverloadedStrings #-}\nx = "a -- b" ++ \'-\' -- real\ny = a --> b\nz = 1 {- one {- two -} still -} + 2\n';
  const cs = findComments(src).map((c) => src.slice(c.start, c.end));
  assert.deepEqual(cs, ['-- real', '{- one {- two -} still -}']);
  assert.equal(stripComments(src).length, src.length);
  assert.equal(stripComments(src).split('\n').length, src.split('\n').length);
});
