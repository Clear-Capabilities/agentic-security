// A REAL ReDoS, found via this repo's own self-scan gate after parser-rust.js
// merged (SARD_80_F1_SCANNER_PRD.md work), confirmed by direct timing, not
// the self-scan heuristic alone: the original `_FN_RE` chained three
// separately-quantified constructs before `fn` — an attribute-skip star, an
// optional `pub`, and a qualifier-skip star. Each one timed as linear in
// isolation (the file's own now-superseded comment recorded exactly that
// measurement for the sibling attribute-skip shape in `_parseParams`), but a
// backtracking regex engine does not know the alternatives inside a
// `(?:A|B|C)*` are mutually exclusive on real input — on eventual
// overall-match failure (no `fn` ever reached, the ordinary shape of a file
// this parser scans that simply isn't a function declaration) it explores
// every way the star could have divided its iterations among A/B/C, which is
// exponential regardless of how unambiguous the alternation looks to a human
// reader. Merging the three constructs into one alternation-based star (the
// first fix attempted) was STILL exponential. The real fix (see
// parser-rust.js's own `_FN_RE`/`_skipFnQualifiersBackward` comments)
// replaced the whole prefix-matching machinery with a bare `\bfn\s+(name)`
// match plus a separate, backtracking-free backward scan for anything that
// needs the preceding attribute/qualifier text.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseRustFile } from '../src/ir/parser-rust.js';

function timeIt(fn) {
  const t0 = Date.now();
  fn();
  return Date.now() - t0;
}

test('parser-rust ReDoS regression: many attributes with no trailing fn resolves in linear time', () => {
  const src = '#[a] '.repeat(2000) + 'xxx\n';
  const ms = timeIt(() => parseRustFile('a.rs', src));
  assert.ok(ms < 2000, `expected sub-2s parse, got ${ms}ms — a real regression in _FN_RE's linearity`);
});

test('parser-rust ReDoS regression: many qualifier keywords with no trailing fn resolves in linear time', () => {
  const src = 'pub const async unsafe default '.repeat(2000) + 'xxx\n';
  const ms = timeIt(() => parseRustFile('a.rs', src));
  assert.ok(ms < 2000, `expected sub-2s parse, got ${ms}ms — a real regression in _FN_RE's linearity`);
});

test('parser-rust ReDoS regression: attributes AND qualifiers combined with no trailing fn resolves in linear time (the actual bug shape)', () => {
  const src = '#[a] '.repeat(2000) + 'pub const async unsafe '.repeat(2000) + 'xxx\n';
  const ms = timeIt(() => parseRustFile('a.rs', src));
  assert.ok(ms < 2000, `expected sub-2s parse, got ${ms}ms — this exact combined shape is what hung for 50+ seconds at n=1000 before the fix`);
});

test('parser-rust: a route attribute separated from fn by an async qualifier is still recognized (the fix must not silently drop route detection)', () => {
  const src = `
use axum::extract::Query;
#[get("/users")]
async fn get_users(Query(q): Query<Params>) -> String {
    q.name
}
`;
  const ir = parseRustFile('a.rs', src);
  assert.ok(ir, 'expected a parsed IR');
  const fn = ir.functions.find(f => f.name === 'get_users');
  assert.ok(fn, `expected get_users, got: ${ir.functions.map(f => f.name).join(', ')}`);
  // The route attribute must still mark the extractor param as a source —
  // this is the exact behavior _skipFnQualifiersBackward exists to preserve
  // once _FN_RE stopped capturing qualifier text as part of its own match.
  assert.ok(Array.isArray(fn.paramAnnotations) && fn.paramAnnotations.length > 0,
    `expected paramAnnotations from the route-attributed extractor param, got: ${JSON.stringify(fn.paramAnnotations)}`);
});

test('parser-rust: an unqualified plain fn preceded by an attribute on the same line is still recognized', () => {
  const src = `#[inline] fn helper(x: i32) -> i32 { x + 1 }\n`;
  const ir = parseRustFile('a.rs', src);
  assert.ok(ir, 'expected a parsed IR');
  assert.ok(ir.functions.some(f => f.name === 'helper'), `expected helper, got: ${ir.functions.map(f => f.name).join(', ')}`);
});
