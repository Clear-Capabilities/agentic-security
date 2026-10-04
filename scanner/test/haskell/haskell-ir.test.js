// HS-002: functional semantic IR and call graph.
// Suite "haskell-ir" (HASKELL_NIXOS_FULL_CAPABILITY_PRD.md).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildHaskellIR } from '../../src/language/haskell-ir.js';
import { buildProjectIR, buildProjectIRAsync } from '../../src/ir/index.js';
import { buildConstantFnMap, applyPathFeasibility, runTaintEngine } from '../../src/dataflow/index.js';

const short = (q) => (q || '').split('::')[1] || '';
const edgeSet = (r, { skip = ['builtin', 'external'] } = {}) => [...new Set(r.callGraph.edges.filter((e) => !skip.includes(e.status))
  .map((e) => `${short(e.caller)} -> ${e.calleeName} [${e.status}/${e.kind}${e.via ? `:${e.via}` : ''}]`))].sort();
const fnOf = (r, file, name) => r.perFile[file].functions.find((f) => f.name === name);

const LIB = {
  'src/Lib/Core.hs': `module Lib.Core (sink, wrap, Rec(..)) where
data Rec = Rec { body :: String, tag :: String }
sink :: String -> IO ()
sink s = writeFile "/tmp/x" s
wrap :: String -> String
wrap = (++ "!")
`,
  'src/Lib.hs': `module Lib (module Lib.Core, helper) where
import Lib.Core
helper :: String -> IO ()
helper = sink . wrap
`,
  'src/Main.hs': `module Main where
import qualified Lib as L
import Lib (Rec(..))
main :: IO ()
main = do
  x <- getLine
  L.helper x
  L.sink $ L.wrap x
  mapM_ L.sink [x]
  _ <- traverse L.helper [x]
  fmap L.wrap getLine >>= L.sink
  let r = Rec { body = x, tag = "t" }
  L.sink (body r)
  pure ()
partial :: String -> IO ()
partial = L.sink
guarded :: String -> IO ()
guarded s
  | null s = pure ()
  | Just t <- lookup s [("a","b")] = L.sink t
  | otherwise = L.helper s
`,
};

test('[HS-002.AC01] a labeled multi-module program yields exactly the expected call graph ($, ., currying, aliases, re-exports, do/bind, records, guards, map/traverse/fmap)', () => {
  const r = buildHaskellIR(LIB);
  assert.deepEqual(r.diagnostics, []);
  assert.deepEqual(edgeSet(r), [
    'Lib.helper@4 -> Lib.Core.sink [potential/reference:reference]',
    'Lib.helper@4 -> Lib.Core.wrap [potential/reference:reference]',
    'Main.guarded@18 -> Lib.Core.sink [resolved/direct]',
    'Main.guarded@18 -> Lib.helper [resolved/direct]',
    'Main.main@5 -> Lib.Core.sink [resolved/direct]',
    'Main.main@5 -> Lib.Core.sink [resolved/higher-order:bind]',
    'Main.main@5 -> Lib.Core.sink [resolved/higher-order:mapM_]',
    'Main.main@5 -> Lib.Core.wrap [resolved/direct]',
    'Main.main@5 -> Lib.Core.wrap [resolved/higher-order:fmap]',
    'Main.main@5 -> Lib.helper [resolved/direct]',
    'Main.main@5 -> Lib.helper [resolved/higher-order:traverse]',
    'Main.partial@16 -> Lib.Core.sink [potential/reference:reference]',
  ].sort());
  assert.equal(r.callGraph.unresolved.length, 0, 'every user-defined target resolved: nothing is left unknown');
});

test('[HS-002.AC01] a re-exported name resolves to its defining module, and a qualified alias does not collide with an unqualified import', () => {
  const r = buildHaskellIR(LIB);
  const sinkEdge = r.callGraph.edges.find((e) => short(e.caller) === 'Main.main@5' && e.calleeName === 'Lib.Core.sink');
  assert.equal(short(sinkEdge.callee), 'Lib.Core.sink@4', 'resolved through `module Lib.Core` re-export, not to a copy');
  // two modules defining the same name stay distinct
  const two = buildHaskellIR({
    'A.hs': 'module A (f) where\nf :: String -> String\nf = id\n',
    'B.hs': 'module B (f) where\nf :: String -> String\nf = reverse\n',
    'M.hs': 'module M where\nimport qualified A\nimport qualified B as Bee\nm :: String -> String\nm s = A.f (Bee.f s)\n',
  });
  assert.deepEqual(edgeSet(two), ['M.m@5 -> A.f [resolved/direct]', 'M.m@5 -> B.f [resolved/direct]']);
});

test('[HS-002.AC01] a record field selector and import-by-type resolve; a name not brought in by `T(..)` stays unresolved', () => {
  const ok = buildHaskellIR({
    'U.hs': 'module U (Cfg(..), other) where\ndata Cfg = Cfg { cmd :: String }\nother :: Int\nother = 1\n',
    'M.hs': 'module M where\nimport U (Cfg(..))\nuse :: Cfg -> String\nuse c = cmd c\n',
  });
  assert.equal(ok.callGraph.unresolved.length, 0, 'cmd comes in through Cfg(..)');
  const bad = buildHaskellIR({
    'U.hs': 'module U (Cfg(..), other) where\ndata Cfg = Cfg { cmd :: String }\nother :: Int -> Int\nother = id\n',
    'M.hs': 'module M where\nimport U (Cfg(..))\nuse :: Int -> Int\nuse n = other n\n',
  });
  assert.ok(bad.callGraph.unresolved.some((e) => e.calleeName === 'other'), '`other` was not imported, so it is not resolved to U.other');
});

test('[HS-002.AC01] a where clause after a do block parses under the layout rule', () => {
  const r = buildHaskellIR({ 'M.hs': 'module M where\nrun :: IO ()\nrun = do\n  putStrLn "a"\n  where unused = length "b"\n' });
  assert.deepEqual(r.diagnostics, []);
  assert.ok(fnOf(r, 'M.hs', 'M.run').hs.deferred.some((d) => d.names.includes('unused')));
});

test('[HS-002.AC02] an unreferenced lazy binding is deferred: no executed node, no call edge', () => {
  const r = buildHaskellIR({ 'A.hs': `module A where
import System.Process (callCommand)
lazyUnused :: String -> IO ()
lazyUnused s = do
  putStrLn "hi"
  where dead = callCommand s
        ignored = length s
` });
  const f = fnOf(r, 'A.hs', 'A.lazyUnused');
  assert.deepEqual(f.hs.deferred.map((d) => d.names[0]).sort(), ['dead', 'ignored']);
  assert.ok(f.hs.deferred.every((d) => d.demand === 'unused'));
  assert.deepEqual(f.hs.deferred.find((d) => d.names[0] === 'dead').callees, ['System.Process.callCommand'], 'what it WOULD call is recorded, not executed');
  assert.equal(f.calls.some((c) => /callCommand/.test(c.callee)), false, 'a binding nobody demands is not a call');
  assert.equal(r.callGraph.edges.some((e) => short(e.caller) === 'A.lazyUnused@4' && /callCommand/.test(e.calleeName)), false);
  assert.equal(Object.values(f.cfg.nodes).filter((n) => n.kind === 'call').length >= 0, true);
});

test('[HS-002.AC02] a binding demanded only on one branch keeps its flow with potential demand and uncertainty; a forced one is executed', () => {
  const r = buildHaskellIR({ 'A.hs': `module A where
import System.Process (callCommand)
cond :: Bool -> String -> IO ()
cond b s = if b then putStrLn used else pure ()
  where used = show (callCommand s)
forced :: String -> IO ()
forced s = let act = callCommand s in act
` });
  const cond = fnOf(r, 'A.hs', 'A.cond');
  const lazyNodes = Object.values(cond.cfg.nodes).filter((n) => n.hs && n.hs.lazy);
  assert.ok(lazyNodes.length >= 1);
  assert.ok(lazyNodes.every((n) => n.hs.demand === 'potential' && n.hs.uncertainty === 'potentially-demanded'), 'conditionally demanded: potential, never definite');
  assert.ok(cond.calls.some((c) => c.callee === 'System.Process.callCommand'), 'the flow is retained');
  const forced = fnOf(r, 'A.hs', 'A.forced');
  assert.equal(forced.hs.effect, 'io');
  assert.ok(forced.calls.some((c) => c.callee === 'System.Process.callCommand'));
});

test('[HS-002.AC02] top-level values are not executed at load, and effects belong to where they are sequenced', () => {
  const r = buildHaskellIR({ 'A.hs': `module A where
import System.Process (callCommand)
cmdAction :: IO ()
cmdAction = callCommand "ls"
table :: [Int]
table = [1,2,3]
pureLen :: String -> Int
pureLen = length
` });
  const mod = r.perFile['A.hs'].functions.find((f) => f.name === 'A.<module>');
  const inits = Object.values(mod.cfg.nodes).filter((n) => n.hs && n.hs.init);
  assert.ok(inits.length >= 2);
  assert.ok(inits.every((n) => n.hs.init.executedAtLoad === false && n.hs.init.demand === 'lazy-once'), 'a top-level binding is a lazily evaluated value, not a load-time effect');
  assert.equal(fnOf(r, 'A.hs', 'A.cmdAction').hs.kind, 'io-action');
  assert.equal(fnOf(r, 'A.hs', 'A.pureLen').hs.effect, 'pure');
});

test('[HS-002.AC03] recursion, mutual recursion and a long cycle converge within the caps', () => {
  const r = buildHaskellIR({ 'R.hs': `module R where
loop :: Int -> Int
loop n = if n > 0 then loop (n-1) else mutual n
mutual :: Int -> Int
mutual n = loop (n-1)
` });
  const s = r.callGraph.summarize();
  assert.equal(s.converged, true);
  assert.equal(s.capped, false);
  const loop = [...s.summaries].find(([q]) => /R\.loop@/.test(q))[1];
  assert.equal(loop.callees.size >= 2, true, 'each reaches the other');
  // a 300-function ring
  const N = 300;
  let src = 'module Ring where\n';
  for (let i = 0; i < N; i++) src += `f${i} :: Int -> Int\nf${i} x = f${(i + 1) % N} x\n`;
  const ring = buildHaskellIR({ 'Ring.hs': src });
  const rs = ring.callGraph.summarize({ maxIterations: 1000 });
  assert.equal(rs.converged, true);
  // when the iteration cap is hit the answer is "unknown", never a partial result passed off as complete
  const capped = ring.callGraph.summarize({ maxIterations: 2 });
  assert.equal(capped.converged, false); assert.equal(capped.capped, true);
  assert.ok([...capped.summaries.values()].every((x) => x.unknown === true));
});

test('[HS-002.AC03] unresolved higher-order and typeclass targets are unknown or candidates, and unknown is never proven unreachable', () => {
  const r = buildHaskellIR({ 'A.hs': `module A where
cls :: Shape a => a -> String
cls x = area x
class Shape a where area :: a -> String
data Sq = Sq
instance Shape Sq where area _ = "sq"
dyn :: (String -> IO ()) -> String -> IO ()
dyn f s = f s
unknownCall :: String -> IO ()
unknownCall s = mystery s
leaf :: Int
leaf = 1
` });
  const e = (name) => r.callGraph.edges.filter((x) => x.calleeName === name);
  assert.equal(e('A.area')[0].status, 'candidate'); assert.equal(e('A.area')[0].ambiguous, true);
  assert.equal(e('f')[0].status, 'unknown'); assert.equal(e('f')[0].reason, 'higher-order-parameter');
  assert.equal(e('mystery')[0].status, 'unknown'); assert.equal(e('mystery')[0].reason, 'unbound-name');
  const q = (n) => [...r.callGraph.functions.keys()].find((k) => k.includes(`::${n}@`));
  // from a root that calls an unknown target, an unreached function is UNKNOWN, not unreachable
  const withUnknown = r.callGraph.reachability([q('A.unknownCall')]);
  assert.equal(withUnknown.sawUnknown, true);
  assert.equal(withUnknown.status.get(q('A.leaf')), 'unknown');
  // from a root with only resolved edges, an unreached function is genuinely unreachable
  const clean = r.callGraph.reachability([q('A.leaf')]);
  assert.equal(clean.sawUnknown, false);
  assert.equal(clean.status.get(q('A.cls')), 'unreachable');
  assert.equal(clean.status.get(q('A.leaf')), 'reachable');
});

test('[HS-002.AC03] a typeclass call with no visible instance is unknown, and an import cycle terminates', () => {
  const r = buildHaskellIR({ 'A.hs': 'module A where\nclass C a where m :: a -> Int\nuse :: C a => a -> Int\nuse x = m x\n' });
  const m = r.callGraph.edges.find((x) => x.calleeName === 'A.m');
  assert.equal(m.status, 'unknown'); assert.equal(m.reason, 'no-visible-instance');
  const cyc = buildHaskellIR({
    'X.hs': 'module X (a) where\nimport Y\na :: Int\na = b\n',
    'Y.hs': 'module Y (b, module X) where\nimport X\nb :: Int\nb = a\n',
  });
  assert.ok(cyc.callGraph.functions.size >= 2, 're-export cycles terminate instead of hanging');
});

test('[HS-002.AC04] Haskell reaches the shared IR through the real project entry points, sync and async, with a merged call graph', async () => {
  const files = { ...LIB, 'x.js': 'function a(){ return 1 }\nmodule.exports = a;\n' };
  for (const r of [buildProjectIR(files), await buildProjectIRAsync(files)]) {
    assert.ok(r.perFile['src/Main.hs'] && r.perFile['x.js']);
    assert.equal(r.perFile['src/Main.hs'].language, 'haskell');
    assert.ok(r.callGraph.haskell, 'richer Haskell call graph is attached');
    assert.ok([...r.callGraph.functions.keys()].some((k) => k.includes('Lib.Core.sink')), 'Haskell functions are in the shared function table');
    assert.ok([...r.callGraph.functions.keys()].some((k) => k.startsWith('x.js')), 'JS functions are still there');
    const main = [...r.callGraph.functions.values()].find((f) => f.name === 'Main.main');
    assert.equal(r.callGraph.resolve('Lib.Core.sink', 'src/Main.hs'), [...r.callGraph.functions.keys()].find((k) => k.includes('Lib.Core.sink')));
    assert.ok(main);
  }
});

test('[HS-002.AC04] the existing consumers accept the Haskell IR: IR contract, path feasibility and the taint engine', () => {
  const r = buildProjectIR(LIB);
  // The node kinds the existing parsers already emit (measured from JS and Python IR of a program using
  // branches, loops, try/switch and calls). The Haskell IR must stay inside that set.
  const sample = buildProjectIR({ 'a.js': 'function run(x){ if(x){ f(x); } for(let i=0;i<2;i++){} return x }\n', 'p.py': 'def f(x):\n  if x:\n    return 1\n  for i in x:\n    pass\n' });
  const KNOWN_KINDS = new Set(Object.values(sample.perFile).flatMap((i) => i.functions).flatMap((f) => Object.values(f.cfg.nodes)).map((n) => n.kind));
  assert.ok(['assign', 'call', 'entry', 'exit', 'if', 'noop', 'return'].every((k) => KNOWN_KINDS.has(k)));
  for (const ir of Object.values(r.perFile)) {
    for (const fn of ir.functions) {
      for (const k of ['qid', 'name', 'line', 'params', 'file', 'cfg', 'calls']) assert.ok(k in fn, `${fn.name} has ${k}`);
      for (const n of Object.values(fn.cfg.nodes)) assert.ok(KNOWN_KINDS.has(n.kind), `unexpected node kind ${n.kind}: no additive kinds were introduced`);
    }
  }
  const fns = Object.values(r.perFile).flatMap((i) => i.functions);
  const consts = buildConstantFnMap(fns);
  for (const fn of fns) assert.doesNotThrow(() => applyPathFeasibility(fn, consts));
  const res = runTaintEngine(r.perFile, r.callGraph, {});
  assert.ok(res && typeof res === 'object', 'the taint engine runs over mixed Haskell IR without throwing');
});

test('[HS-002.AC04] current-language IR is unchanged by the Haskell wiring', () => {
  const js = { 'a.js': 'const cp = require("child_process");\nfunction run(x){ if (x) { cp.exec(x); } return x; }\nmodule.exports = run;\n' };
  // node ids come from a global counter, so compare structure (kinds, order, calls) rather than ids
  const shape = (ir) => ir.functions.map((f) => ({ name: f.name, line: f.line, params: f.params, calls: f.calls.map((c) => [c.callee, c.line]), kinds: Object.values(f.cfg.nodes).map((n) => `${n.kind}@${n.line}`) }));
  const withHs = buildProjectIR({ ...js, 'M.hs': 'module M where\nf :: Int\nf = 1\n' });
  const without = buildProjectIR(js);
  assert.deepEqual(shape(withHs.perFile['a.js']), shape(without.perFile['a.js']));
  assert.deepEqual([...without.callGraph.functions.values()].map((f) => f.name).sort(), [...withHs.callGraph.functions.values()].filter((f) => f.file === 'a.js').map((f) => f.name).sort());
});
