// Round 3 of the real-code precision work (docs/superpowers/plans/2026-11-14-haskell-real-code-precision.md): three mechanisms from the labelled sets.
//   1. Base64 `encode` of a digest is formatting, not signing: the weak-hash rule read it as "passed to a verifying or signing call" (wai-app-static's
//      ETag digests, two discovery-set false positives). `encodeSigned` (a JWT signature) still is.
//   2. A file read whose path is a PROJECT CONSTANT (`fp <- decodeUtf Paths.schemaFilePath; readFile fp`) is a fixed-location read like a literal path,
//      and environment roots beside it are the operator's: the content is the deployment's own file, so the finding is `low`, kept (IHP's schema compiler,
//      three fresh-set false positives at `high`). A path from a request or a caller stays as reported.
//   3. SCA import reachability knows the packages the Haskell advisory database names (module lists read from each package's Hackage cabal file,
//      versions in the table), with exact matching where a prefix would claim another package's modules (`System.Process.Typed` is typed-process).
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { mkTestTmp } from '../helpers/tmp.js';
import { analyzeHaskellRules } from '../../src/language/haskell-security-rules.js';
import { reachability, PACKAGE_MODULES } from '../../src/language/haskell-sca.js';

process.env.AGENTIC_SECURITY_DEEP = '1';
delete process.env.CI;

async function scanOf(files) {
  const { runScan } = await import('../../src/runScan.js');
  const dir = mkdtempSync(join(mkTestTmp('hs-round3'), 'p-'));
  for (const [k, v] of Object.entries(files)) { mkdirSync(dirname(join(dir, k)), { recursive: true }); writeFileSync(join(dir, k), v); }
  const { scan } = await runScan(dir);
  return scan.findings.filter((f) => /\.hs$/.test(f.file));
}

// ── 1. a digest handed to a Base64 encoder ───────────────────────────────────────────────────────────────────────────────────────
const ETAG = (use) => `module Static (fileHash) where
import qualified Crypto.Hash.MD5 as MD5
import qualified Data.ByteString as BS
import Data.ByteString.Base64 (encode)
import Web.JWT (encodeSigned, hmacSecret)

fileHash :: BS.ByteString -> BS.ByteString
fileHash bs = ${use}
`;
test('weak hash: a digest passed to a Base64 encoder is a cache validator at info; one passed to a JWT signer is reported', () => {
  const hashes = (src) => analyzeHaskellRules({ 'Static.hs': src }).findings.filter((f) => f.rule === 'hs-weak-hash').map((f) => [f.line, f.severity, f.description.replace(/^[^:]*: /, '')]);
  const etag = hashes(ETAG('encode (MD5.hash bs)'));
  assert.equal(etag.length, 1, JSON.stringify(etag));
  assert.equal(etag[0][1], 'info', JSON.stringify(etag));
  assert.doesNotMatch(etag[0][2], /verifying or signing/);
  const signed = hashes(ETAG('encodeSigned (hmacSecret "k") mempty (MD5.hash bs)'));
  assert.equal(signed.length, 1, JSON.stringify(signed));
  assert.equal(signed[0][1], 'medium');
  assert.match(signed[0][2], /verifying or signing/);
});

// ── 2. a read of a project-constant path ─────────────────────────────────────────────────────────────────────────────────────────
const CABAL = 'cabal-version: 2.4\nname: p\nversion: 0.1\nlibrary\n    exposed-modules: Compile, Paths\n    hs-source-dirs: src\n    build-depends: base, text\n';
const PATHS = 'module Paths where\n\nschemaFilePath :: FilePath\nschemaFilePath = "Application/Schema.sql"\n';
const COMPILE = `module Compile (compile, compileRequested) where
import qualified Paths
import qualified Data.Text as T
import qualified Data.Text.IO as TextIO
import System.Environment (lookupEnv)
import System.FilePath ((</>))

compile :: IO ()
compile = do
    relationSupport <- lookupEnv "IHP_RELATION_SUPPORT"
    let fp = Paths.schemaFilePath
    sql <- TextIO.readFile fp
    let out = "build" </> (if relationSupport == Just "0" then "plain" else T.unpack (T.take 8 sql))
    TextIO.writeFile out sql

compileRequested :: String -> IO ()
compileRequested requested = do
    sql <- TextIO.readFile requested
    TextIO.writeFile ("build" </> T.unpack (T.take 8 sql)) sql
`;
test('path: a write whose name comes from the content of a project-constant file and an environment setting is low and kept; one from a caller-named file is not lowered', async () => {
  const fs = await scanOf({ 'p.cabal': CABAL, 'src/Paths.hs': PATHS, 'src/Compile.hs': COMPILE });
  const paths = fs.filter((f) => f.file === 'src/Compile.hs' && f.cwe === 'CWE-22');
  const fixed = paths.find((f) => f.line === 14); const named = paths.find((f) => f.line === 19);
  assert.ok(fixed && named, JSON.stringify(paths.map((f) => [f.line, f.severity, f.trustBoundary && f.trustBoundary.verdict])));
  assert.equal(fixed.severity, 'low', JSON.stringify(fixed.trustBoundary));
  assert.equal(fixed.originalSeverity, 'high');
  assert.ok((fixed.controls || []).some((c) => c.kind === 'fixed-file-source'), JSON.stringify(fixed.controls));
  assert.match(fixed.guardNote.reason, /program text fixes/);
  assert.notEqual(named.severity, 'low'); assert.notEqual(named.severity, 'info');
});

// ── 3. SCA import reachability for the advisory-named packages ───────────────────────────────────────────────────────────────────
test('sca: every package the Haskell advisory database names that ships Haskell modules has a module mapping, with exact matching where a prefix would claim another package', () => {
  for (const pkg of ['jwt', 'tls-extra', 'x509-validation', 'x509-store', 'crypton-x509-store', 'biscuit-haskell', 'process', 'scientific', 'toml-reader', 'warp', 'bzlib', 'bz2', 'bzlib-conduit', 'libarchive', 'xmonad-contrib', 'keter', 'spacecookie', 'hledger-web']) {
    assert.ok(PACKAGE_MODULES[pkg], `${pkg} has a module mapping`);
  }
  const imp = (...ms) => ms.map((module) => ({ module }));
  assert.equal(reachability('jwt', imp('Web.JWT')).import, 'imported');
  assert.equal(reachability('warp', imp('Network.Wai.Handler.Warp.Internal')).import, 'imported');
  assert.equal(reachability('warp', imp('Network.Wai')).import, 'not-imported', 'wai is not warp');
  assert.equal(reachability('process', imp('System.Process')).import, 'imported');
  assert.equal(reachability('process', imp('System.Process.Typed')).import, 'not-imported', 'typed-process is another package');
  assert.equal(reachability('xmonad-contrib', imp('XMonad.Hooks.ManageDocks')).import, 'imported');
  assert.equal(reachability('xmonad-contrib', imp('XMonad')).import, 'not-imported', 'the core XMonad module is the xmonad package');
  assert.equal(reachability('x509-validation', imp('Data.X509.Validation')).import, 'imported');
  assert.equal(reachability('x509-validation', imp('Data.X509')).import, 'not-imported', 'Data.X509 is the x509 package');
  assert.equal(reachability('scientific', imp('Data.Scientific')).import, 'imported');
  assert.equal(reachability('toml-reader', imp('TOML')).import, 'imported');
  assert.equal(reachability('bz2', imp('Codec.Compression.BZip')).import, 'imported');
  assert.equal(reachability('nonexistent-package', imp('Foo')).import, 'unknown', 'absence from the table is unknown, never unreachable');
});
