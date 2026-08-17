// Stage 3 correctness audit (detection depth, per-language-IR): a shared
// regex bug across the 4 hand-rolled parsers (parser-cs.js, parser-go.js,
// parser-php.js, parser-rb.js). Every call-matching pattern was
// `/^(calleeRe)\s*\((.*)\)\s*$/s` — `(.*)` matches GREEDILY against the
// LAST `)` in the string, not the one that actually balances the FIRST
// `(`. For a chained call (`Sanitize(x).Trim()`), that swallows the
// chain's own parens into the argument text ("x).Trim("), which fails to
// parse as any recognized expression and falls through to
// `{kind:'unknown'}` — silently losing whatever taint-relevant identifier
// was inside the real argument list. `matchBalancedCall` (balanced-call.js)
// fixes this once, shared by all 4 parsers, with a real balanced-paren scan.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { matchBalancedCall } from '../src/ir/balanced-call.js';
import { parseCSharpFile } from '../src/ir/parser-cs.js';
import { parseGoFile } from '../src/ir/parser-go.js';
import { parsePhpFile } from '../src/ir/parser-php.js';
import { parseRubyFile } from '../src/ir/parser-rb.js';

test('matchBalancedCall: a chained call after the balancing paren does not corrupt the argument text', () => {
  const m = matchBalancedCall('Sanitize(x).Trim()', /^([\w.]+)/);
  assert.ok(m, 'expected a match');
  assert.equal(m.callee, 'Sanitize');
  assert.equal(m.argsText, 'x');
});

test('matchBalancedCall: a nested call in the argument list still balances correctly', () => {
  const m = matchBalancedCall('Foo(Bar(x), y)', /^([\w.]+)/);
  assert.equal(m.callee, 'Foo');
  assert.equal(m.argsText, 'Bar(x), y');
});

test('matchBalancedCall: an unbalanced string is refused, not guessed', () => {
  assert.equal(matchBalancedCall('Foo(x', /^([\w.]+)/), null);
});

test('matchBalancedCall: a non-call string does not match', () => {
  assert.equal(matchBalancedCall('not a call at all', /^([\w.]+)/), null);
});

// Taint-recall PRD (80%): these now assert the OUTER call's NAME (not the
// inner one) with args from EVERY level, outermost-first — a deliberate
// behavior change, not a regression. Leaving the chain "unconsumed" (the
// original fix's choice, preserved by these tests until now) avoided
// corruption, but it also meant the OUTER call — the one most likely to
// carry a real sink's tainted argument in practice
// (`new DataTable().Compute(expr)`, `template.New(...).Parse(userTemplate)`,
// `$xp->query($expr)` reached through a chain) — was silently absent from
// the CFG entirely. Confirmed via multiple real corpus fixtures across all
// three languages. Each level's name is dot-joined into one callee string
// so both bare-name and receiver-pattern catalog matching keep working.
// Args are unioned rather than keeping only the outermost — a first version
// of this fix kept only the outer call's args, which broke a real chain
// shape (`xp.compile(taintedExpr).evaluate(doc, NODESET)`) where the
// tainted value sits on an INNER call and the outer call's own args don't
// carry it at all; see the fourth test below. Ruby's sibling test is
// untouched because its example (`.strip`, no parens) was never affected —
// the continuation check requires an actual call, not a bare property/
// no-arg method reference.

test('C#: a chained call after a method call resolves to the OUTER call name, keeping the INNER call\'s own argument (statement form)', () => {
  const ir = parseCSharpFile('App.cs', `
    public string Handle(string id) {
      Sanitize(id).Trim();
      return id;
    }
  `);
  const fn = ir.functions.find(f => f.name === 'Handle');
  const callNode = Object.values(fn.cfg.nodes).find(n => n.kind === 'call');
  assert.ok(callNode, 'expected a call node');
  assert.equal(callNode.callee, 'Sanitize.Trim');
  assert.deepEqual(callNode.args, [{ kind: 'ident', name: 'id' }]);
});

test('Go: a chained call after a function call resolves to the OUTER call name, keeping the INNER call\'s own argument', () => {
  const ir = parseGoFile('app.go', `
    func handle(id string) {
      Sanitize(id).Trim()
    }
  `);
  const fn = ir.functions.find(f => f.name === 'handle');
  const callNode = Object.values(fn.cfg.nodes).find(n => n.kind === 'call');
  assert.ok(callNode, 'expected a call node');
  assert.equal(callNode.callee, 'Sanitize.Trim');
  assert.deepEqual(callNode.args, [{ kind: 'ident', name: 'id' }]);
});

test('PHP: a chained method call after a function call resolves to the OUTER call name, keeping the INNER call\'s own argument', () => {
  const ir = parsePhpFile('app.php', `
    function handle($id) {
      sanitize($id)->trim();
    }
  `);
  const fn = ir.functions.find(f => f.name === 'handle');
  const callNode = Object.values(fn.cfg.nodes).find(n => n.kind === 'call');
  assert.ok(callNode, 'expected a call node');
  assert.equal(callNode.callee, 'sanitize.trim');
  assert.deepEqual(callNode.args, [{ kind: 'ident', name: '$id' }]);
});

test('C#: a chained call with a tainted argument on the OUTER call is not lost, and stays FIRST (argIndex 0 compatibility)', () => {
  const ir = parseCSharpFile('App.cs', `
    public string Handle(string id) {
      Sanitize("x").Trim(id);
      return id;
    }
  `);
  const fn = ir.functions.find(f => f.name === 'Handle');
  const callNode = Object.values(fn.cfg.nodes).find(n => n.kind === 'call');
  assert.ok(callNode, 'expected a call node');
  assert.equal(callNode.callee, 'Sanitize.Trim');
  // Outer (Trim)'s own arg comes first, then Sanitize's — an argIndex: 0
  // catalog entry keyed to the outermost call still finds the right value
  // regardless of how many args any inner call in the chain has.
  assert.deepEqual(callNode.args, [{ kind: 'ident', name: 'id' }, { kind: 'literal', value: '"x"' }]);
});

test('C#: a tainted argument on an INNER call (not the outermost) is still present in the combined args', () => {
  const ir = parseCSharpFile('App.cs', `
    public string Handle(string id) {
      Sanitize(id).Trim();
      return id;
    }
  `);
  const fn = ir.functions.find(f => f.name === 'Handle');
  const callNode = Object.values(fn.cfg.nodes).find(n => n.kind === 'call');
  assert.ok(callNode.args.some(a => a.kind === 'ident' && a.name === 'id'),
    `expected the inner call's own argument to survive, got: ${JSON.stringify(callNode.args)}`);
});

test('Ruby: a chained call after a method call does not corrupt its argument', () => {
  const ir = parseRubyFile('app.rb', `
def handle(id)
  sanitize(id).strip
end
`);
  const fn = ir.functions.find(f => f.name === 'handle');
  const callNode = Object.values(fn.cfg.nodes).find(n => n.kind === 'call');
  assert.ok(callNode, 'expected a call node');
  assert.equal(callNode.callee, 'sanitize');
  assert.deepEqual(callNode.args, [{ kind: 'ident', name: 'id' }]);
});
