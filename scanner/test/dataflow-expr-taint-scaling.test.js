// Scaling guard for the taint engine's expression walk.
//
// A call's argument taint used to be computed twice (once for "are the arguments tainted", once more while building the
// callee's entry state), and each computation re-walked the whole argument subtree, so the work doubled at every level of
// call nesting: N nested calls cost 2^N visits and a deep-mode scan of a large Haskell project did not finish. This test counts
// expression visits (a work counter, not a clock) on a generated project at two nesting depths and requires the growth to be
// close to linear. It also pins that the verdict is unchanged: the nested flow is still reported, and a constant input is not.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildHaskellIR } from '../src/language/haskell-ir.js';
import { runDeepAnalysis } from '../src/dataflow/index.js';
import { _perf } from '../src/dataflow/engine.js';

// `wrap` has a guard, so the IR keeps each use as a call to a project function (a small single-clause body would be inlined away).
// main = callCommand (wrap (wrap (... (wrap getLine) ...)))   -- `depth` nested calls of a project function that has a parameter
function project(depth, input) {
  let expr = input;
  for (let i = 0; i < depth; i++) expr = `(wrap ${expr})`;
  return `module Main where
import System.Process (callCommand)

wrap :: String -> String
wrap s
  | null s = ""
  | otherwise = "x " ++ s

main :: IO ()
main = do
  line <- getLine
  callCommand ${expr}
`;
}

function analyse(depth, input) {
  const file = 'src/Main.hs';
  const ir = buildHaskellIR({ [file]: project(depth, input) });
  _perf.exprTaintCalls = 0;
  const findings = runDeepAnalysis(ir.perFile, ir.callGraph, { fnLimit: 5000, scanRoot: null, fileContents: { [file]: project(depth, input) } });
  return { visits: _perf.exprTaintCalls, findings };
}

test('taint engine: expression visits grow roughly linearly with call nesting depth', () => {
  const small = analyse(8, 'line');
  const large = analyse(16, 'line');
  assert.ok(small.visits > 0, 'the counter must observe the walk');
  // Exponential doubling would make depth 16 about 256 times the depth 8 cost; linear is about 2 times.
  assert.ok(large.visits <= small.visits * 4, `depth 8 -> 16 visits grew ${small.visits} -> ${large.visits}`);
  // And the absolute work stays small for a depth the old walk could not finish.
  const deep = analyse(40, 'line');
  assert.ok(deep.visits < 40 * 400, `depth 40 took ${deep.visits} visits`);
});

test('taint engine: the nested flow is still reported and a constant input is still clean', () => {
  const tainted = analyse(6, 'line');
  const sinks = tainted.findings.filter((f) => /command|CWE-78/i.test(`${f.vuln} ${f.cwe}`));
  assert.ok(sinks.length >= 1, `expected the command-injection flow to be reported, got ${JSON.stringify(tainted.findings.map((f) => f.vuln))}`);
  const clean = analyse(6, '"ls"');
  assert.equal(clean.findings.filter((f) => /command|CWE-78/i.test(`${f.vuln} ${f.cwe}`)).length, 0);
});
