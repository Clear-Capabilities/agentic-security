// A point-free alias (`tidy = takeFileName`) IS the function it names: applying it must resolve to that function, in the
// sanitizer direction AND the sink direction, for top-level, let and where bindings, and must never be applied where it could be
// captured by a local binding. Found by bench/mutation (hs-san-path-where-helper): the alias was an unresolved call, so a
// sanitizer reached through it lost its identity and the flow stayed "unsanitized".
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkTestTmp } from '../helpers/tmp.js';

const BIN = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'bin', 'agentic-security.js');

function scan(src) {
  const dir = mkTestTmp('hs-alias-');
  writeFileSync(join(dir, 'Main.hs'), src);
  const env = { ...process.env }; delete env.NODE_TEST_CONTEXT;
  const p = spawnSync(process.execPath, [BIN, 'scan', dir, '--format', 'json'], { encoding: 'utf8', timeout: 180000, env, maxBuffer: 64 * 1024 * 1024 });
  return JSON.parse(p.stdout).findings.filter((f) => f.parser === 'IR-TAINT');
}
const path22 = (fs) => fs.filter((f) => f.cwe === 'CWE-22');
// The CLI report carries a sanitized flow as a refuted finding (proof.verdict `proven-*`), not as a `sanitized` field.
const sanitized = (fs) => path22(fs).some((f) => f.proof && /^proven-/.test(f.proof.verdict));

const READ = `  name <- getLine
  body <- readFile (tidy name)
  putStr body
`;

test('a top-level point-free alias of a sanitizer sanitizes', () => {
  const fs = scan(`module Main where\nimport System.FilePath (takeFileName)\n\ntidy :: FilePath -> FilePath\ntidy = takeFileName\n\nmain :: IO ()\nmain = do\n${READ}`);
  assert.equal(path22(fs).length, 1);
  assert.equal(sanitized(fs), true);
});

test('a let-bound and a where-bound alias of a sanitizer sanitize', () => {
  const inLet = scan(`module Main where\nimport System.FilePath (takeFileName)\n\nmain :: IO ()\nmain = do\n  let tidy = takeFileName\n${READ}`);
  assert.equal(sanitized(inLet), true);
  const inWhere = scan(`module Main where\nimport System.FilePath (takeFileName)\n\nmain :: IO ()\nmain = do\n${READ}  where\n    tidy = takeFileName\n`);
  assert.equal(sanitized(inWhere), true);
});

test('an alias that composes the sanitizer sanitizes', () => {
  const fs = scan(`module Main where\nimport System.FilePath (takeFileName)\n\ntidy :: FilePath -> FilePath\ntidy = id . takeFileName\n\nmain :: IO ()\nmain = do\n${READ}`);
  assert.equal(sanitized(fs), true);
});

test('an alias of a function that is not a sanitizer does not sanitize', () => {
  const ident = scan(`module Main where\n\ntidy :: FilePath -> FilePath\ntidy = id\n\nmain :: IO ()\nmain = do\n${READ}`);
  assert.equal(path22(ident).length, 1);
  assert.equal(sanitized(ident), false);
  const wrong = scan(`module Main where\nimport System.FilePath (takeExtension)\n\ntidy :: FilePath -> FilePath\ntidy = takeDirectoryLike\n  where takeDirectoryLike = takeExtension\n\nmain :: IO ()\nmain = do\n${READ}`);
  assert.equal(sanitized(wrong), false);
});

test('an own function that merely shares the sanitizer name is not the sanitizer, even through an alias', () => {
  const fs = scan(`module Main where\n\ntakeFileName :: FilePath -> FilePath\ntakeFileName p = p\n\ntidy :: FilePath -> FilePath\ntidy = takeFileName\n\nmain :: IO ()\nmain = do\n${READ}`);
  assert.equal(path22(fs).length, 1);
  assert.equal(sanitized(fs), false);
});

test('a local binding that would capture the alias target leaves the call unresolved (conservative: stays unsanitized)', () => {
  // Inside `go`, `takeFileName` is a parameter, so re-resolving the alias there would pick the wrong binding. The alias is not applied.
  const fs = scan(`module Main where\nimport System.FilePath (takeFileName)\n\nmain :: IO ()\nmain = do\n  name <- getLine\n  body <- readFile (go name)\n  putStr body\n  where\n    tidy = takeFileName\n    go takeFileName = tidy takeFileName\n`);
  assert.equal(path22(fs).length, 1);
  assert.equal(sanitized(fs), false);
});

test('an alias of a sink is the sink: tainted input fires, a constant does not', () => {
  const hit = scan(`module Main where\nimport System.Process (callCommand)\n\nrun :: String -> IO ()\nrun = callCommand\n\nmain :: IO ()\nmain = do\n  host <- getLine\n  run ("ping -c1 " ++ host)\n`);
  assert.equal(hit.filter((f) => f.cwe === 'CWE-78').length, 1);
  const miss = scan(`module Main where\nimport System.Process (callCommand)\n\nrun :: String -> IO ()\nrun = callCommand\n\nmain :: IO ()\nmain = do\n  _ <- getLine\n  run "ping -c1 127.0.0.1"\n`);
  assert.equal(miss.filter((f) => f.cwe === 'CWE-78').length, 0);
});

test('a self-referential binding does not loop or become an alias', () => {
  const fs = scan(`module Main where\n\ntidy :: FilePath -> FilePath\ntidy = tidy\n\nmain :: IO ()\nmain = do\n${READ}`);
  assert.equal(path22(fs).length, 1);
  assert.equal(sanitized(fs), false);
});
