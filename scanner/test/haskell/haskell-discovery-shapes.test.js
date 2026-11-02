// Shapes found by reading the discovery set (bench/dag/discovery-haskell): two layout rules that dropped hoogle's whole request handler.
// Both parsers (haskell-syntax.js, which the IR uses, and haskell-parser.js, HS-001) are pinned, in both directions.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseSyntax } from '../../src/language/haskell-syntax.js';
import { parseHaskell } from '../../src/language/haskell-parser.js';

const names = (r) => r.decls.filter((d) => d.t === 'clause').map((d) => d.name);
const hs001 = (src) => { const p = parseHaskell(src, { file: 'M.hs' }); return { errors: (p.errors || []).map((e) => e.kind), calls: p.calls.map((c) => c.callee) }; };

test('a where at the case alternatives\' column closes the alternatives and belongs to the clause (hoogle: replyServer)', () => {
  const src = `module A where
reply input = case input of
    [] -> pure "none"
    xs -> pure body
    where
        body = unwords input
`;
  const r = parseSyntax(src);
  assert.deepEqual(r.errors, []);
  const reply = r.decls.find((d) => d.t === 'clause' && d.name === 'reply');
  assert.equal(reply.clause.rhs.body.t, 'case');
  assert.equal(reply.clause.rhs.body.alts.length, 2);
  assert.equal(reply.clause.rhs.where.length, 1);
  const p = hs001(src);
  assert.deepEqual(p.errors, []);
  assert.ok(p.calls.includes('unwords'), String(p.calls));
});

test('semicolon-separated statements on one line of a nested do stay in that do (hoogle: General.Web)', () => {
  const src = `module B where
run act pay = handle h $ do
    s <- act pay; n <- evaluate (length s); pure (Right (s, n))
`;
  const r = parseSyntax(src);
  assert.deepEqual(r.errors, []);
  assert.deepEqual(names(r), ['run']);
  const p = hs001(src);
  assert.deepEqual(p.errors, []);
  assert.deepEqual(p.calls, ['handle', 'act', 'evaluate', 'length', 'pure']);
});

test('a semicolon after a nested block opened on the same line belongs to the nested block (hoogle: a where item with a do)', () => {
  const src = `module A where
f xs = mconcat ys
    where
        remod t = do (a,_) <- g t; pure (a, t)
        ys = map remod xs
`;
  const r = parseSyntax(src);
  assert.deepEqual(r.errors, []);
  const f = r.decls.find((d) => d.t === 'clause' && d.name === 'f');
  assert.equal(f.clause.rhs.where.length, 2);
  assert.equal(f.clause.rhs.where[0].clause.rhs.body.stmts.length, 2);
  assert.deepEqual(hs001(src).errors, []);
});

test('semicolons at the block\'s own level still separate items: top level, let, case and do one-liners', () => {
  const r = parseSyntax(`module B where
f = g 1; h = k 2
m x = let a = g x; b = h a in k a b
n x = case x of 1 -> g x; _ -> h x
o = do a <- g 1; h a
`);
  assert.deepEqual(r.errors, []);
  assert.deepEqual(names(r), ['f', 'h', 'm', 'n', 'o']);
  const body = (n) => r.decls.find((d) => d.t === 'clause' && d.name === n).clause.rhs.body;
  assert.equal(body('m').decls.length, 2);
  assert.equal(body('n').alts.length, 2);
  assert.equal(body('o').stmts.length, 2);
  assert.deepEqual(hs001(`module B where\nf = g 1; h = k 2\n`).calls, ['g', 'k']);
});
