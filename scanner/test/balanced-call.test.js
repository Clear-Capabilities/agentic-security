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

test('C#: a chained call after a method call does not corrupt its argument (statement form)', () => {
  const ir = parseCSharpFile('App.cs', `
    public string Handle(string id) {
      Sanitize(id).Trim();
      return id;
    }
  `);
  const fn = ir.functions.find(f => f.name === 'Handle');
  const callNode = Object.values(fn.cfg.nodes).find(n => n.kind === 'call');
  assert.ok(callNode, 'expected a call node');
  assert.equal(callNode.callee, 'Sanitize');
  assert.deepEqual(callNode.args, [{ kind: 'ident', name: 'id' }]);
});

test('Go: a chained call after a function call does not corrupt its argument', () => {
  const ir = parseGoFile('app.go', `
    func handle(id string) {
      Sanitize(id).Trim()
    }
  `);
  const fn = ir.functions.find(f => f.name === 'handle');
  const callNode = Object.values(fn.cfg.nodes).find(n => n.kind === 'call');
  assert.ok(callNode, 'expected a call node');
  assert.equal(callNode.callee, 'Sanitize');
  assert.deepEqual(callNode.args, [{ kind: 'ident', name: 'id' }]);
});

test('PHP: a chained method call after a function call does not corrupt its argument', () => {
  const ir = parsePhpFile('app.php', `
    function handle($id) {
      sanitize($id)->trim();
    }
  `);
  const fn = ir.functions.find(f => f.name === 'handle');
  const callNode = Object.values(fn.cfg.nodes).find(n => n.kind === 'call');
  assert.ok(callNode, 'expected a call node');
  assert.equal(callNode.callee, 'sanitize');
  assert.deepEqual(callNode.args, [{ kind: 'ident', name: '$id' }]);
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
