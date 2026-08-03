// Decorator syntax must PARSE — regression guard.
//
// Decorators are syntax the scanner has to accept, never transform. When the
// parser is not told to accept them it rejects the ENTIRE file, so every
// finding in that file silently ceases to exist. This is the worst shape of
// bug this project can have: no error, no warning, just absent findings.
//
// It was real, not hypothetical. Measured on a live third-party target: 201
// JavaScript files unparseable, every one of them decorator-using framework
// code — roughly 6% of that project invisible to the scanner.
//
// If someone removes the `parserOpts` decorator plugins from parser-js.js or
// engine.js, these tests fail. That is the entire point of them.
import { test, describe } from 'node:test';
import assert from 'node:assert';
import { parseJsFile } from '../src/ir/index.js';

function parses(src, file = '/x/a.js') {
  return parseJsFile(file, src) !== null;
}

describe('decorator syntax parses', () => {
  test('framework-style class decorators on fields and methods', () => {
    const src = `
import Component from '@glimmer/component';
export default class Box extends Component {
  @tracked ratio = 1;
  @service router;
  @action resize(e) { this.ratio = e.target.value; }
}`;
    assert.equal(parses(src), true, 'decorator-using framework code must parse');
  });

  test('TypeScript parameter decorators', () => {
    // The modern 'decorators' plugin variant CANNOT parse this shape, which is
    // why the legacy variant is the one configured. Swapping to modern would
    // trade one blind spot for another rather than removing it.
    assert.equal(parses('class S { constructor(@Inject(X) private y: Y) {} }', '/x/a.ts'), true);
  });

  test('modern auto-accessor fields', () => {
    assert.equal(parses('class C { @logged accessor x = 1; }'), true);
  });

  test('a decorated method still yields functions in the IR, not just a parse', () => {
    // Parsing is necessary but not sufficient — the IR has to contain the
    // decorated method, or taint analysis still cannot see inside it.
    const ir = parseJsFile('/x/h.js', `
export default class H {
  @action run(req) { const c = req.query.cmd; exec(c); }
}`);
    assert.notEqual(ir, null);
    assert.ok((ir.functions || []).length > 0, 'the decorated method must appear in the IR');
  });

  test('undecorated code is unaffected', () => {
    assert.equal(parses('class P { go() { return 1; } }'), true);
    assert.equal(parses('const C = () => <div onClick={() => go(u)} />;', '/x/a.jsx'), true);
  });
});
