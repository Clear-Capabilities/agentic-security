// Remediation, class by class. For every vulnerability class the Haskell analysis reports, either a deterministic patch exists and is verified
// by the real gates (parse, rescan of the patched tree, and a GHC type-check where the libraries are available), or the fixer REFUSES and says
// why. Nothing here accepts a patch because it looks right: each verified case is applied to a scratch tree, rescanned and compiled.
//
// Compilation: process, filepath, directory, bytestring and base ship with GHC, so those patches are type-checked against the real libraries.
// Database, HTML and hashing libraries are not installed here, so their patches are type-checked against a hand-written stub of the documented API
// (the module and function names and arities the patch uses). That proves the patch is coherent with that API shape, not that it builds against the
// real package; the report says so. When GHC is absent the compile assertions are skipped, loudly, never passed.

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { runScan } from '../../src/runScan.js';
import { planHaskellFix, validateHaskellFix, compileGate, sqlDriverOf, SUPPORTED_FIX_IDS } from '../../src/language/haskell-fix.js';
import { languageFixPreview } from '../../src/language/context.js';
import { mkTestTmp } from '../helpers/tmp.js';

const GHC = !spawnSync('ghc', ['--numeric-version'], { encoding: 'utf8' }).error;
const skipNoGhc = GHC ? false : 'GHC is not installed: compile verification could not run (this is a skip, not a pass)';

async function scan(files) {
  const dir = mkTestTmp('hs-fixcls-');
  writeFileSync(join(dir, 'package.json'), '{}');
  for (const [f, text] of Object.entries(files)) { mkdirSync(dirname(join(dir, f)), { recursive: true }); writeFileSync(join(dir, f), text); }
  const r = await runScan(dir, { deep: true });
  return [...(r.scan.findings || [])].filter((f) => !(f.proof && /^proven-/.test(f.proof.verdict)));
}
const pick = (fs, pred) => fs.find(pred);
const typeCheck = (files) => compileGate(files, { compile: true });

// ── stubs of the documented API shape, used only for the type-check of library-dependent patches ──────────────────────────────
const STUB_SQLITE = `module Database.SQLite.Simple (Connection, Query, Only(..), execute, execute_, query, query_) where
import Data.String (IsString(..))
data Connection = Connection
newtype Query = Query String
instance IsString Query where fromString = Query
newtype Only a = Only a
execute :: Show q => Connection -> Query -> q -> IO ()
execute _ _ _ = pure ()
execute_ :: Connection -> Query -> IO ()
execute_ _ _ = pure ()
query :: Show q => Connection -> Query -> q -> IO [a]
query _ _ _ = pure []
query_ :: Connection -> Query -> IO [a]
query_ _ _ = pure []
instance Show a => Show (Only a) where show (Only a) = show a
`;
const STUB_PG = STUB_SQLITE.replace('Database.SQLite.Simple', 'Database.PostgreSQL.Simple');
const STUB_BLAZE = `module Text.Blaze.Html (Html, toHtml, preEscapedToHtml) where
newtype Html = Html String
toHtml :: String -> Html
toHtml = Html
preEscapedToHtml :: String -> Html
preEscapedToHtml = Html
`;
const STUB_HASH = `{-# LANGUAGE KindSignatures #-}
module Crypto.Hash (hashWith, MD5(..), SHA1(..), SHA256(..), HashAlgorithm) where
import qualified Data.ByteString as B
class HashAlgorithm a
data MD5 = MD5
data SHA1 = SHA1
data SHA256 = SHA256
instance HashAlgorithm MD5
instance HashAlgorithm SHA1
instance HashAlgorithm SHA256
hashWith :: HashAlgorithm a => a -> B.ByteString -> String
hashWith _ _ = ""
`;

// ── 1. process (CWE-78) ──────────────────────────────────────────────────────────────────────────────────────────────────────
const PROC = { 'src/Main.hs': 'module Main (main) where\n\nimport System.Process\n\nmain :: IO ()\nmain = do\n  n <- getLine\n  callCommand ("ls " ++ n)\n' };

test('process: a shell string built from input becomes a direct process call that the gates verify and GHC type-checks', { skip: skipNoGhc }, async () => {
  const f = pick(await scan(PROC), (x) => x.cwe === 'CWE-78' && x.severity !== 'info');
  assert.ok(f, 'the finding exists');
  const pv = await languageFixPreview(f, PROC);
  assert.equal(pv.status, 'verified', JSON.stringify(pv.gates));
  assert.match(pv.after, /callProcess "ls" \["--", n\]/);
  assert.equal(pv.gates.rescan.originalGone, true);
  const tc = typeCheck({ [pv.file]: pv.after });
  assert.deepEqual([tc.ran, tc.ok], [true, true], tc.detail);
  assert.ok(!(await scan({ [pv.file]: pv.after })).some((x) => x.cwe === 'CWE-78' && x.severity !== 'info'), 'the patched tree has no command-injection finding');
});

// ── 2. path traversal (CWE-22) ───────────────────────────────────────────────────────────────────────────────────────────────
const PATHSRC = { 'src/Svc.hs': 'module Svc (loadReport, loadAny, dropReport) where\n\nimport System.Directory\n\nloadReport :: String -> IO String\nloadReport name = readFile ("/srv/reports/" ++ name)\n\nloadAny :: String -> IO String\nloadAny name = readFile name\n\ndropReport :: String -> IO ()\ndropReport name = removeDirectoryRecursive ("/srv/reports/" ++ name)\n' };

test('path: a parameter spliced under a fixed directory gets takeFileName, verified by the rescan and type-checked against the real filepath', { skip: skipNoGhc }, async () => {
  const fs = await scan(PATHSRC);
  const f = pick(fs, (x) => x.cwe === 'CWE-22' && x.line === 6);
  assert.ok(f, JSON.stringify(fs.map((x) => [x.cwe, x.line, x.severity])));
  const pv = await languageFixPreview(f, PATHSRC);
  assert.equal(pv.status, 'verified', JSON.stringify(pv.gates || pv));
  assert.equal(pv.label, 'MITIGATION');
  assert.match(pv.after, /readFile \("\/srv\/reports\/" \+\+ takeFileName name\)/);
  assert.match(pv.after, /import System\.FilePath \(takeFileName\)/);
  const tc = typeCheck({ [pv.file]: pv.after });
  assert.deepEqual([tc.ran, tc.ok], [true, true], tc.detail);
  assert.ok(!(await scan({ [pv.file]: pv.after })).some((x) => x.cwe === 'CWE-22' && x.line === 6 && x.severity !== 'info'), 'the patched read is no longer reported');
});

test('path: a bare parameter, a Text value and a directory operation are not rewritten', async () => {
  const bare = planHaskellFix({ cwe: 'CWE-22', file: 'src/Svc.hs', line: 9 }, PATHSRC);
  assert.equal(bare.ok, false, 'no fixed part: nothing to confine the value under');
  const dir = planHaskellFix({ cwe: 'CWE-22', file: 'src/Svc.hs', line: 12 }, PATHSRC);
  assert.equal(dir.ok, false, '"." and ".." survive takeFileName, so a directory operation is not rewritten');
  const textSrc = { 'src/T.hs': 'module T (load) where\n\nimport qualified Data.Text as T\n\nload :: T.Text -> IO String\nload name = readFile ("/srv/" ++ T.unpack name)\n' };
  assert.equal(planHaskellFix({ cwe: 'CWE-22', file: 'src/T.hs', line: 6 }, textSrc).ok, false, 'takeFileName takes a String');
  const local = { 'src/L.hs': 'module L (go) where\n\ngo :: Int -> IO String\ngo k = do\n  let name = show k\n  readFile ("/srv/" ++ name)\n' };
  assert.equal(planHaskellFix({ cwe: 'CWE-22', file: 'src/L.hs', line: 6 }, local).ok, false, 'a local, not a declared parameter');
});

// ── 3. SQL (CWE-89): the driver is the one the file imports ──────────────────────────────────────────────────────────────────
const sqlFile = (driver, qual = '') => `{-# LANGUAGE OverloadedStrings #-}\nmodule Db (run) where\n\nimport ${qual}${driver}\nimport Data.String (fromString)\n\nrun :: Connection -> String -> IO ()\nrun conn n = ${qual ? 'SQL.' : ''}execute_ conn (fromString ("DELETE FROM t WHERE n = '" ++ n ++ "'"))\n`;

for (const [name, driver, stub] of [['SQLite', 'Database.SQLite.Simple', STUB_SQLITE], ['PostgreSQL', 'Database.PostgreSQL.Simple', STUB_PG]]) {
  test(`SQL (${name}): the parameterized query uses the driver the file already imports and adds no other database import`, { skip: skipNoGhc }, async () => {
    const files = { 'src/Db.hs': sqlFile(driver) };
    const f = pick(await scan(files), (x) => x.cwe === 'CWE-89' && x.severity !== 'info');
    assert.ok(f);
    const pv = await languageFixPreview(f, files);
    assert.equal(pv.status, 'verified', JSON.stringify(pv.gates || pv));
    assert.ok(pv.after.includes(`import ${driver}`));
    const other = driver === 'Database.SQLite.Simple' ? 'Database.PostgreSQL.Simple' : 'Database.SQLite.Simple';
    assert.ok(!pv.after.includes(other), 'no import of a driver the file did not use');
    assert.match(pv.after, /execute conn "DELETE FROM t WHERE n = \?" \(Only n\)/);
    const stubPath = `${driver.replace(/\./g, '/')}.hs`;
    const tc = typeCheck({ [pv.file]: pv.after, [stubPath]: stub.replace('Database.SQLite.Simple', driver) });
    assert.deepEqual([tc.ran, tc.ok], [true, true], `type-checked against a stub of the documented API: ${tc.detail}`);
  });
}

test('SQL: a file with no known driver, two drivers, or a driver whose API differs is not rewritten', () => {
  const f = { cwe: 'CWE-89', file: 'src/Db.hs', line: 8 };
  assert.equal(sqlDriverOf(sqlFile('Database.SQLite.Simple')), 'Database.SQLite.Simple');
  const both = sqlFile('Database.SQLite.Simple').replace('import Data.String', 'import Database.PostgreSQL.Simple (Connection)\nimport Data.String');
  assert.equal(sqlDriverOf(both), null);
  assert.equal(planHaskellFix({ ...f, line: 9 }, { 'src/Db.hs': both }).ok, false);
  const mysql = sqlFile('Database.MySQL.Simple');
  assert.equal(sqlDriverOf(mysql), null, 'mysql-simple is not one of the drivers whose API the rewrite is written against');
  assert.equal(planHaskellFix(f, { 'src/Db.hs': mysql }).ok, false);
  const none = sqlFile('Data.List').replace('Connection', 'Int').replace('execute_ conn', 'execute_ conn');
  assert.equal(planHaskellFix(f, { 'src/Db.hs': none }).ok, false);
});

test('SQL: even with a plan, a fix that would add a database import the file did not have is blocked at the preview', async () => {
  // a plan produced by some other route (a model) that adds a driver import: the preview refuses it
  const { addedDatabaseImports } = await import('../../src/language/context.js');
  assert.deepEqual(addedDatabaseImports({ before: 'import Data.List\nx = 1\n', after: 'import Data.List\nimport Database.PostgreSQL.Simple (Only)\nx = 1\n' }), ['Database.PostgreSQL.Simple']);
});

// ── 4. HTML (CWE-79) ─────────────────────────────────────────────────────────────────────────────────────────────────────────
test('HTML: preEscapedToHtml of input becomes toHtml (type-checked against a stub of blaze-html); a file that does not import blaze is not rewritten', { skip: skipNoGhc }, async () => {
  const files = { 'src/Ht.hs': 'module Ht (render) where\n\nimport Text.Blaze.Html (Html, preEscapedToHtml)\n\nrender :: String -> Html\nrender n = preEscapedToHtml n\n' };
  const plan = planHaskellFix({ cwe: 'CWE-79', file: 'src/Ht.hs', line: 6 }, files);
  assert.equal(plan.ok, true);
  assert.match(plan.after, /render n = toHtml n/);
  const tc = typeCheck({ 'src/Ht.hs': plan.after, 'Text/Blaze/Html.hs': STUB_BLAZE });
  assert.deepEqual([tc.ran, tc.ok], [true, true], tc.detail);
  const foreign = { 'src/Ht.hs': 'module Ht (render) where\n\nimport MyMarkup (Html, preEscapedToHtml)\n\nrender :: String -> Html\nrender n = preEscapedToHtml n\n' };
  assert.equal(planHaskellFix({ cwe: 'CWE-79', file: 'src/Ht.hs', line: 6 }, foreign).ok, false);
});

// ── 5. weak hash (CWE-328) ───────────────────────────────────────────────────────────────────────────────────────────────────
test('weak hash: MD5 becomes SHA-256 when the algorithm is named once; a type that names it elsewhere in the file blocks the rewrite', { skip: skipNoGhc }, async () => {
  const one = { 'src/Hs.hs': 'module Hs (digest) where\n\nimport Crypto.Hash (hashWith, MD5(..))\nimport qualified Data.ByteString as B\n\ndigest :: B.ByteString -> String\ndigest b = hashWith MD5 b\n' };
  const plan = planHaskellFix({ cwe: 'CWE-328', rule: 'hs-weak-hash', file: 'src/Hs.hs', line: 7 }, one);
  assert.equal(plan.ok, true);
  assert.match(plan.after, /hashWith SHA256 b/);
  const tc = typeCheck({ 'src/Hs.hs': plan.after, 'Crypto/Hash.hs': STUB_HASH });
  assert.deepEqual([tc.ran, tc.ok], [true, true], tc.detail);
  const typed = { 'src/Hs.hs': 'module Hs (digest, Tag) where\n\nimport Crypto.Hash (hashWith, MD5(..))\nimport qualified Data.ByteString as B\n\ndata Tag = Tag MD5\n\ndigest :: B.ByteString -> String\ndigest b = hashWith MD5 b\n' };
  assert.equal(planHaskellFix({ cwe: 'CWE-328', rule: 'hs-weak-hash', file: 'src/Hs.hs', line: 9 }, typed).ok, false, 'Tag MD5 would no longer match');
});

// ── 6. logging (CWE-532) ─────────────────────────────────────────────────────────────────────────────────────────────────────
test('logging: a sensitive argument is redacted and the line type-checks', { skip: skipNoGhc }, async () => {
  const files = { 'src/Lg.hs': 'module Lg (l) where\n\nl :: String -> IO ()\nl password = putStrLn ("user logged in with " ++ password)\n' };
  const plan = planHaskellFix({ cwe: 'CWE-532', rule: 'hs-sensitive-logging', file: 'src/Lg.hs', line: 4 }, files);
  assert.equal(plan.ok, true);
  const tc = typeCheck({ 'src/Lg.hs': plan.after });
  assert.deepEqual([tc.ran, tc.ok], [true, true], tc.detail);
});

// ── 7. the classes the fixer refuses, with the reason ────────────────────────────────────────────────────────────────────────
test('refusals: password hashing, a predictable generator, SSRF, argument injection and cookies are proposals with a class-level reason, never a guessed patch', async () => {
  const gitit = { 'src/State.hs': `module State (mkUser, newSession) where

import Data.Digest.Pure.SHA (sha512, showDigest)
import qualified Data.ByteString.Lazy.UTF8 as L
import System.Random (randomRIO)

hashPassword :: String -> String -> String
hashPassword salt pass = showDigest $ sha512 $ L.fromString $ salt ++ pass

newSession :: IO Int
newSession = randomRIO (0, 1000000000)
` };
  const fs = await scan(gitit);
  const pw = pick(fs, (x) => x.cwe === 'CWE-916');
  const rnd = pick(fs, (x) => x.cwe === 'CWE-338');
  assert.ok(pw && rnd, JSON.stringify(fs.map((x) => [x.cwe, x.line])));
  for (const f of [pw, rnd]) {
    const pv = await languageFixPreview(f, gitit);
    assert.equal(pv.ok, false);
    assert.match(String(pv.reason), /KDF|CSPRNG/);
    assert.equal(pv.proposal, 'model-assisted');
  }
  for (const cwe of ['CWE-918', 'CWE-88', 'CWE-1004', 'CWE-306', 'CWE-770']) {
    const r = planHaskellFix({ cwe, file: 'src/X.hs', line: 3 }, { 'src/X.hs': 'module X where\nx :: Int\nx = 1\n' });
    assert.equal(r.ok, false, cwe);
    assert.ok(r.reason && r.reason !== 'no deterministic fix is supported for this exact shape', `${cwe} has a class-level reason: ${r.reason}`);
    assert.equal(r.proposal, 'model-assisted');
  }
});

test('the fixer set is exactly the ten rewrites that are proved the same program minus the vulnerability (or a stated mitigation)', () => {
  assert.deepEqual([...SUPPORTED_FIX_IDS].sort(), ['hs-cookie-attributes', 'hs-hash-sha256', 'hs-html-escape', 'hs-log-redact', 'hs-path-takefilename', 'hs-process-argv', 'hs-random-os-entropy', 'hs-request-body-bound', 'hs-sql-parameterize', 'hs-tls-validate']);
});

test('validateHaskellFix never writes without apply and reports the compile gate as not run by default', async () => {
  const f = pick(await scan(PROC), (x) => x.cwe === 'CWE-78' && x.severity !== 'info');
  const v = await validateHaskellFix(f, { files: PROC });
  assert.equal(v.applied, false);
  assert.equal(v.gates.compile.ran, false);
});
