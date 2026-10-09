// Scaling guard for the Haskell IR builder.
//
// Lowering a function used to walk every module of the project for each constructor it met, each record type it needed
// (rebuilt per function) and each definition it looked up by id, so a project of M modules and F functions cost F x M.
// Pandoc and cabal-install (hundreds of modules, thousands of functions) did not finish a scan. The lookups are now
// indexes built once. This test does not time anything: it counts how often the module table is iterated while the IR of
// a generated project is built, at two project sizes. Iterating the table once per use shows up as growth with the size;
// an index shows up as a small constant.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildHaskellIR, _internals } from '../../src/language/haskell-ir.js';

// M modules. Module i imports module i+1 and uses its constructor, its record field and a function of it, so every
// function lowering needs the cross-module lookups.
function project(m) {
  const files = {};
  for (let i = 0; i < m; i++) {
    const next = i + 1 < m ? `Mod${i + 1}` : null;
    files[`src/Mod${i}.hs`] = `module Mod${i} where
${next ? `import ${next}\n` : ''}
data Rec${i} = Rec${i} { fld${i} :: String, tag${i} :: String }

mk${i} :: String -> Rec${i}
mk${i} s = Rec${i} { fld${i} = s, tag${i} = "t" }

use${i} :: String -> String
use${i} s
  | null s = ""
  | otherwise = ${next ? `fld${i + 1} (mk${i + 1} s) ++ ` : ''}fld${i} (mk${i} s)

other${i} :: Rec${i} -> String
other${i} (Rec${i} a b) = a ++ b ++ ${next ? `use${i + 1} a` : '"end"'}
`;
  }
  return files;
}

function moduleTableIterations(m) {
  const files = project(m);
  const names = Array.from({ length: m }, (_, i) => `Mod${i}`);
  const proto = Map.prototype;
  const originals = { values: proto.values, entries: proto.entries, keys: proto.keys, forEach: proto.forEach, iter: proto[Symbol.iterator] };
  let count = 0;
  const isModuleTable = (map) => map.size >= Math.min(m, 3) && names.slice(0, 3).every((n) => originals.values && map.has(n));
  const wrap = (orig) => function (...args) { if (isModuleTable(this)) count++; return orig.apply(this, args); };
  proto.values = wrap(originals.values); proto.entries = wrap(originals.entries); proto.keys = wrap(originals.keys);
  proto.forEach = wrap(originals.forEach); proto[Symbol.iterator] = wrap(originals.iter);
  let ir;
  try { ir = buildHaskellIR(files); } finally {
    proto.values = originals.values; proto.entries = originals.entries; proto.keys = originals.keys;
    proto.forEach = originals.forEach; proto[Symbol.iterator] = originals.iter;
  }
  return { count, ir };
}

test('Haskell IR: the module table is not iterated once per function or per use', () => {
  const small = moduleTableIterations(24);
  const large = moduleTableIterations(48);
  assert.equal(small.ir.diagnostics.filter((d) => d.kind === 'ir-lowering-failure').length, 0, 'the generated project must lower cleanly');
  assert.ok(Object.keys(small.ir.perFile).length === 24 && Object.keys(large.ir.perFile).length === 48);
  // Per-use iteration would give ~(functions x modules): doubling the project would quadruple the count or more.
  assert.ok(large.count <= small.count + 6, `iterations of the module table grew with the project: ${small.count} -> ${large.count}`);
  assert.ok(large.count < 60, `the module table is iterated a bounded number of times, got ${large.count}`);
});

test('Haskell IR: a top-level name resolution is computed once and answers identically each time', () => {
  const files = project(4);
  const ir = buildHaskellIR(files);
  const mod = ir.modules.get('Mod0');
  const a = _internals.resolveGlobal(ir.project, mod, 'fld1', null);
  const b = _internals.resolveGlobal(ir.project, mod, 'fld1', null);
  assert.equal(a, b, 'the same resolution must be returned, not recomputed');
  assert.equal(a.kind, 'def');
  assert.equal(a.mod, 'Mod1');
  // different names and qualifiers do not share an answer
  const c = _internals.resolveGlobal(ir.project, mod, 'fld0', null);
  assert.equal(c.mod, 'Mod0');
  const d = _internals.resolveGlobal(ir.project, mod, 'fld1', 'Nope');
  assert.notEqual(d, a);
  assert.equal(d.kind, 'unknown');
  const e = _internals.resolveGlobal(ir.project, mod, 'noSuchName', null);
  assert.equal(e.kind, 'unknown');
});

test('Haskell IR: record parameters, constructors and definitions found through the project indexes', () => {
  const files = {
    'src/A.hs': 'module A where\ndata Cfg = Cfg { cmd :: String }\n',
    'src/B.hs': 'module B where\nimport A\nrunIt :: Cfg -> String\nrunIt c = cmd c\n\nbuild :: String -> Cfg\nbuild s = Cfg s\n',
  };
  const ir = buildHaskellIR(files);
  const fn = [...ir.callGraph.functions.values()].find((f) => f.name === 'B.runIt');
  assert.ok(fn, 'B.runIt is lowered');
  assert.deepEqual(fn.hs.recordParams.map((r) => ({ name: r.name, type: r.type, fields: r.fields })), [{ name: 'c', type: 'Cfg', fields: ['cmd'] }]);
  assert.equal(ir.project.findCon('Cfg').type, 'Cfg');
  assert.equal(ir.project.findCon('Nope'), null);
  assert.equal(ir.project.defByQid(fn.qid).name, 'runIt');
  assert.equal(ir.project.defByQid('no-such-qid'), null);
});
