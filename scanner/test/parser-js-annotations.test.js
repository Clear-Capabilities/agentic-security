import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { parseJsFile } from '../src/ir/parser-js.js';
import { runScan } from '../src/runScan.js';

test('parseJsFile: a NestJS @Query() decorator on a parameter populates fn.paramAnnotations', () => {
  const code = `
class UserController {
  show(@Query() q) {
    return q;
  }
}
`;
  const ir = parseJsFile('user.controller.ts', code);
  assert.ok(ir);
  const fn = ir.functions.find(f => f.name.includes('show'));
  assert.ok(fn);
  assert.deepEqual(fn.params, ['q'], 'fn.params must stay plain strings, unaffected by this change');
  assert.ok(fn.paramAnnotations, 'expected paramAnnotations to be populated');
  assert.deepEqual(fn.paramAnnotations, [{ index: 0, name: 'q', decorator: 'Query' }]);
});

test('parseJsFile: an undecorated parameter gets no paramAnnotations entry', () => {
  const code = `
class Helper {
  show(q) {
    return q;
  }
}
`;
  const ir = parseJsFile('helper.ts', code);
  assert.ok(ir);
  const fn = ir.functions.find(f => f.name.includes('show'));
  assert.ok(fn);
  assert.deepEqual(fn.params, ['q']);
  assert.ok(!fn.paramAnnotations || fn.paramAnnotations.length === 0);
});

test('parseJsFile: multiple parameters, only decorated ones are recorded', () => {
  const code = `
class UserController {
  show(@Query() q, @Body() body, extra) {
    return q;
  }
}
`;
  const ir = parseJsFile('user.controller.ts', code);
  assert.ok(ir);
  const fn = ir.functions.find(f => f.name.includes('show'));
  assert.deepEqual(fn.params, ['q', 'body', 'extra']);
  assert.deepEqual(fn.paramAnnotations, [
    { index: 0, name: 'q', decorator: 'Query' },
    { index: 1, name: 'body', decorator: 'Body' },
  ]);
});

test('parseJsFile: stacked decorators on one parameter are ALL captured, not just the first', () => {
  // Task 3 (the C# equivalent of this task) initially only captured the FIRST
  // attribute on a stacked-attribute parameter, silently dropping the
  // source-relevant decorator when multiple were stacked. Babel's
  // `p.decorators` is a real array, so this loop must walk all of it.
  const code = `
class UserController {
  show(@Query() @SomeOtherDecorator() q) {
    return q;
  }
}
`;
  const ir = parseJsFile('user.controller.ts', code);
  assert.ok(ir);
  const fn = ir.functions.find(f => f.name.includes('show'));
  assert.ok(fn);
  assert.deepEqual(fn.params, ['q']);
  assert.ok(fn.paramAnnotations, 'expected paramAnnotations to be populated');
  assert.deepEqual(fn.paramAnnotations, [
    { index: 0, name: 'q', decorator: 'Query' },
    { index: 0, name: 'q', decorator: 'SomeOtherDecorator' },
  ]);
});

test('parseJsFile: a bare (non-call) decorator is also recorded', () => {
  const code = `
class UserController {
  show(@Query q) {
    return q;
  }
}
`;
  const ir = parseJsFile('user.controller.ts', code);
  assert.ok(ir);
  const fn = ir.functions.find(f => f.name.includes('show'));
  assert.ok(fn);
  assert.deepEqual(fn.params, ['q']);
  assert.deepEqual(fn.paramAnnotations, [{ index: 0, name: 'q', decorator: 'Query' }]);
});

test('parseJsFile: a decorated parameter with a default value keeps its decorator (fix round 1)', () => {
  // @Query() page = 1 is a common NestJS idiom. Babel represents this param
  // as an AssignmentPattern with the decorator on `p.left`, not `p` — a
  // guard that unconditionally checked the outer `p.type === 'Identifier'`
  // rejected it even though the decorator-node fallback had already found
  // it. Regression guard for that gap.
  const code = `
class UserController {
  show(@Query() page = 1) {
    return page;
  }
}
`;
  const ir = parseJsFile('user.controller.ts', code);
  assert.ok(ir);
  const fn = ir.functions.find(f => f.name.includes('show'));
  assert.ok(fn);
  assert.deepEqual(fn.params, ['page'], 'fn.params must stay plain strings, unaffected by this change');
  assert.ok(fn.paramAnnotations, 'expected paramAnnotations to be populated');
  assert.deepEqual(fn.paramAnnotations, [{ index: 0, name: 'page', decorator: 'Query' }]);
});

test('R14(a) end-to-end: NestJS @Query() flowing to a code-injection sink is detected', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-r14a-nest-'));
  fs.writeFileSync(path.join(dir, 'app.controller.ts'), `
class AppController {
  ping(@Query() cmd) {
    eval(cmd);
  }
}
`);
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const irFindings = (scan.findings || []).filter(f => f.parser === 'IR-TAINT');
  assert.ok(irFindings.length >= 1, `expected an annotation-sourced finding, got: ${JSON.stringify((scan.findings || []).map(f => f.parser))}`);
});
