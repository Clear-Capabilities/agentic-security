// String-interpolating quasi-quoters (`[i|..#{e}..|]`, `[st|..|]`, `[text|..$name..|]`, `[fmt|..{e}..|]`) are read as the concatenation of
// their interpolated expressions (haskell-parser.js INTERP_QUOTERS, haskell-ir.js `iQ`). Before this, every one was an opaque boundary and a
// sink fed through one reported nothing: a self-written probe of the five forms below found 0 findings, 0 of 5 (recorded 2026-11-02).
// Pinned both ways: the vulnerable form fires, a literal-only body stays silent, an unimported quoter stays opaque, and a sanitizer inside
// the interpolation is still seen.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkTestTmp } from '../helpers/tmp.js';
import { parseHaskell, preprocessForSyntaxInfo, interpolationsOf } from '../../src/language/haskell-parser.js';

const BIN = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'bin', 'agentic-security.js');
function scan(src) {
  const dir = mkTestTmp('hs-qq-');
  writeFileSync(join(dir, 'Main.hs'), src);
  const env = { ...process.env, AGENTIC_SECURITY_DEEP: '1', AGENTIC_SECURITY_DEEP_IN_CI: '1' }; delete env.NODE_TEST_CONTEXT;
  const p = spawnSync(process.execPath, [BIN, 'scan', dir, '--format', 'json'], { encoding: 'utf8', timeout: 180000, env, maxBuffer: 64 * 1024 * 1024 });
  return JSON.parse(p.stdout).findings.filter((f) => f.parser === 'IR-TAINT');
}
const cmd = (fs) => fs.filter((f) => f.cwe === 'CWE-78' && f.severity !== 'info');
const HEAD = '{-# LANGUAGE QuasiQuotes, OverloadedStrings #-}\nmodule Main where\nimport System.Process (callCommand)\n';

test('string-interpolate: #{e} inside [i|..|] reaches a command sink; a literal-only body is silent', () => {
  const vuln = scan(`${HEAD}import Data.String.Interpolate (i)\n\nmain :: IO ()\nmain = do\n  name <- getLine\n  callCommand [i|ls #{name}|]\n`);
  assert.equal(cmd(vuln).length, 1, JSON.stringify(vuln.map((f) => [f.line, f.vuln])));
  const safe = scan(`${HEAD}import Data.String.Interpolate (i)\n\nmain :: IO ()\nmain = do\n  name <- getLine\n  callCommand [i|ls -la|]\n  putStrLn name\n`);
  assert.equal(cmd(safe).length, 0);
});

test('shakespeare-text [st|..|], neat-interpolation $name and ${e}, PyF {e} and {e:spec} are followed', () => {
  const st = scan(`${HEAD}import Text.Shakespeare.Text (st)\nimport qualified Data.Text as T\n\nmain :: IO ()\nmain = do\n  name <- getLine\n  callCommand (T.unpack [st|ls #{name}|])\n`);
  assert.equal(cmd(st).length, 1, 'shakespeare-text');
  const neat = scan(`${HEAD}import NeatInterpolation (text)\nimport qualified Data.Text as T\n\nmain :: IO ()\nmain = do\n  name <- T.pack <$> getLine\n  callCommand (T.unpack [text|ls $name|])\n  callCommand (T.unpack [text|ls \${T.toUpper name}|])\n`);
  assert.equal(cmd(neat).length, 2, 'neat-interpolation');
  const pyf = scan(`${HEAD}import PyF (fmt)\n\nmain :: IO ()\nmain = do\n  name <- getLine\n  callCommand [fmt|ls {name}|]\n  callCommand [fmt|ls {name:>10}|]\n`);
  assert.equal(cmd(pyf).length, 2, 'PyF');
});

test('a quoter whose module is not imported stays an opaque boundary, and the module import alone does not accept an unknown quoter', () => {
  const src = `${HEAD}import Data.String.Interpolate (i)\n\nmain :: IO ()\nmain = do\n  name <- getLine\n  callCommand [sql|ls #{name}|]\n`;
  const r = parseHaskell(src, { file: 'Main.hs' });
  assert.ok(r.boundaries.some((b) => b.kind === 'quasiquote' && b.quoter === 'sql'), JSON.stringify(r.boundaries.map((b) => b.kind)));
  assert.equal(preprocessForSyntaxInfo(src, { file: 'Main.hs' }).opaque, true);
  const noImport = `${HEAD}\nmain :: IO ()\nmain = do\n  name <- getLine\n  callCommand [i|ls #{name}|]\n`;
  assert.ok(parseHaskell(noImport, { file: 'Main.hs' }).boundaries.some((b) => b.kind === 'quasiquote' && b.quoter === 'i'));
  assert.equal(cmd(scan(noImport)).length, 0);
});

test('a sanitizer applied inside the interpolation is seen on the path', () => {
  const src = `{-# LANGUAGE QuasiQuotes, OverloadedStrings #-}\nmodule Main where\nimport Data.String.Interpolate (i)\nimport System.FilePath (takeFileName)\n\nmain :: IO ()\nmain = do\n  name <- getLine\n  body <- readFile [i|/srv/files/#{takeFileName name}|]\n  putStr body\n`;
  const fs = scan(src).filter((f) => f.cwe === 'CWE-22');
  assert.equal(fs.length, 1);
  assert.ok(fs[0].proof && /^proven-/.test(fs[0].proof.verdict), JSON.stringify(fs[0].proof));
});

test('interpolationsOf reads each syntax, with escapes and specs', () => {
  const h = interpolationsOf('[i|a #{x} b #{f (y)} c|]', 3, 22, 'hash');
  assert.deepEqual(h.map((it) => [it.exprStart, it.exprEnd]), [[7, 8], [14, 19]]);
  const d = interpolationsOf('[text|$$ $a ${g b} c|]', 6, 19, 'dollar');
  assert.deepEqual(d.map((it) => [it.bare, it.exprStart, it.exprEnd]), [[true, 10, 11], [false, 14, 17]]);
  const b = interpolationsOf('[fmt|{{ {x} {y:>10}|]', 5, 19, 'brace');
  assert.deepEqual(b.map((it) => [it.exprStart, it.exprEnd, it.close]), [[9, 10, 10], [13, 14, 18]]);
});
