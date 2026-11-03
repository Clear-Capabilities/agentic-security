// Syntax the parser dropped (a self-written probe, 2026-11-02, before any change): `\cases` and `mdo` failed the enclosing expression, a GADT
// `data T where` declared no constructors, and `pattern P = ..` was read as a function named `pattern`. Also, a function written in lambda
// form at the top level (`dispatch = \case ..`) returned a closure value no call applied, so a sink inside it was never reached (the `let`
// case already rewrote `let run = \x -> ..`; `lambdaBodied` now does it for top-level, `let` and `where`, for `\x ->`, `\case` and `\cases`).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkTestTmp } from '../helpers/tmp.js';
import { parseSyntax } from '../../src/language/haskell-syntax.js';

const BIN = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'bin', 'agentic-security.js');
function scan(src) {
  const dir = mkTestTmp('hs-syn-');
  writeFileSync(join(dir, 'Main.hs'), src);
  const env = { ...process.env, AGENTIC_SECURITY_DEEP: '1', AGENTIC_SECURITY_DEEP_IN_CI: '1' }; delete env.NODE_TEST_CONTEXT;
  const p = spawnSync(process.execPath, [BIN, 'scan', dir, '--format', 'json'], { encoding: 'utf8', timeout: 180000, env, maxBuffer: 64 * 1024 * 1024 });
  return JSON.parse(p.stdout).findings.filter((f) => f.parser === 'IR-TAINT' && f.cwe === 'CWE-78' && f.severity !== 'info');
}

test('\\cases, mdo, GADT constructors and pattern synonyms parse', () => {
  const lc = parseSyntax('{-# LANGUAGE LambdaCase #-}\nmodule M where\nf = \\cases\n  0 y -> g y\n  x y -> h x y\n');
  assert.deepEqual(lc.errors, []);
  assert.equal(lc.decls[0].clause.rhs.body.t, 'lamcases');
  assert.deepEqual(lc.decls[0].clause.rhs.body.alts.map((a) => a.pats.length), [2, 2]);
  const md = parseSyntax('{-# LANGUAGE RecursiveDo #-}\nmodule M where\nf x = mdo\n  a <- g x\n  pure a\n');
  assert.deepEqual(md.errors, []);
  assert.equal(md.decls[0].clause.rhs.body.t, 'do');
  const plain = parseSyntax('module M where\nf x = mdo x\n');   // without the extension `mdo` is an ordinary name
  assert.equal(plain.decls[0].clause.rhs.body.t, 'app');
  const gadt = parseSyntax('{-# LANGUAGE GADTs #-}\nmodule M where\ndata T where\n  A :: Int -> T\n  B :: { fld :: String } -> T\n  C, D :: T\n');
  assert.deepEqual(gadt.data[0].constructors.map((c) => [c.name, c.arity, c.fields]), [['A', 1, null], ['B', 1, ['fld']], ['C', 0, null], ['D', 0, null]]);
  const ps = parseSyntax('{-# LANGUAGE PatternSynonyms #-}\nmodule M where\npattern Zero :: Int\npattern Zero = 0\nf Zero = g 1\nf n = h n\n');
  assert.deepEqual(ps.errors, []);
  assert.deepEqual(ps.decls.filter((d) => d.t === 'clause').map((d) => d.name), ['f', 'f']);
  assert.equal(ps.decls.filter((d) => d.t === 'patsyn').length, 2);
});

test('a GADT record constructor matched by a \\case function, a \\cases function and an mdo block carry input to the sink', () => {
  const fs = scan(`{-# LANGUAGE LambdaCase, GADTs, RecursiveDo #-}
module Main where
import System.Process (callCommand)

data Cmd where
  Run :: { target :: String } -> Cmd
  Stop :: Cmd

dispatch :: Cmd -> IO ()
dispatch = \\case
  Run t -> callCommand ("deploy " ++ t)
  Stop -> pure ()

pair :: String -> String -> IO ()
pair = \\cases
  "" _ -> pure ()
  a b -> callCommand ("link " ++ a ++ " " ++ b)

main :: IO ()
main = mdo
  x <- getLine
  dispatch (Run x)
  pair x "y"
`);
  assert.deepEqual(fs.map((f) => f.line).sort(), [11, 17], JSON.stringify(fs.map((f) => [f.line, f.vuln])));
  const safe = scan(`{-# LANGUAGE LambdaCase #-}
module Main where
import System.Process (callCommand)

pair :: String -> String -> IO ()
pair = \\cases
  "" _ -> pure ()
  a _ -> callCommand ("link " ++ a)

main :: IO ()
main = do
  x <- getLine
  pair "fixed" x
`);
  assert.equal(safe.length, 0, 'the second parameter does not reach the sink');
});
