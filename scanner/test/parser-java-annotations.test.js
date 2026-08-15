import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseJavaFile } from '../src/ir/parser-java.js';
import { runScan } from '../src/runScan.js';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

test('parseJavaFile: real parameter names are now extracted (was [] before this task)', async () => {
  const code = `
public class UserController {
    public String show(String q, int id) {
        return q;
    }
}
`;
  const ir = await parseJavaFile('UserController.java', code);
  assert.ok(ir);
  const fn = ir.functions.find(f => f.name.includes('show'));
  assert.ok(fn);
  assert.deepEqual(fn.params, ['q', 'id']);
});

test('parseJavaFile: @RequestParam and @PathVariable populate fn.paramAnnotations', async () => {
  const code = `
public class UserController {
    public String show(@RequestParam String q, @PathVariable("id") int id) {
        return q;
    }
}
`;
  const ir = await parseJavaFile('UserController.java', code);
  assert.ok(ir);
  const fn = ir.functions.find(f => f.name.includes('show'));
  assert.ok(fn);
  assert.deepEqual(fn.params, ['q', 'id']);
  assert.ok(fn.paramAnnotations);
  assert.deepEqual(fn.paramAnnotations, [
    { index: 0, name: 'q', decorator: 'RequestParam' },
    { index: 1, name: 'id', decorator: 'PathVariable' },
  ]);
});

test('parseJavaFile: a method with no annotated parameters gets no paramAnnotations entry', async () => {
  const code = `
public class Helper {
    public String show(String q) {
        return q;
    }
}
`;
  const ir = await parseJavaFile('Helper.java', code);
  assert.ok(ir);
  const fn = ir.functions.find(f => f.name.includes('show'));
  assert.deepEqual(fn.params, ['q']);
  assert.ok(!fn.paramAnnotations || fn.paramAnnotations.length === 0);
});

test('parseJavaFile: an unrelated annotation (e.g. @Deprecated-style, non-source-shaped) is still recorded in paramAnnotations — catalog filtering, not parser filtering, decides relevance', async () => {
  const code = `
public class UserController {
    public String show(@Nullable String q) {
        return q;
    }
}
`;
  const ir = await parseJavaFile('UserController.java', code);
  assert.ok(ir);
  const fn = ir.functions.find(f => f.name.includes('show'));
  assert.deepEqual(fn.paramAnnotations, [{ index: 0, name: 'q', decorator: 'Nullable' }]);
});

// Task 3 (C#) and Task 4 (JS/TS) each needed a fix round for a "not all
// decorators/attributes captured" edge case. Java syntax allows MULTIPLE
// annotations stacked on one parameter — confirm the CST walk here loops
// over every `variableModifier` entry rather than only reading the first.
test('parseJavaFile: multiple stacked annotations on one parameter are ALL captured', async () => {
  const code = `
public class UserController {
    public String show(@NotNull @RequestParam String q) {
        return q;
    }
}
`;
  const ir = await parseJavaFile('UserController.java', code);
  assert.ok(ir);
  const fn = ir.functions.find(f => f.name.includes('show'));
  assert.ok(fn);
  assert.deepEqual(fn.params, ['q']);
  assert.ok(fn.paramAnnotations);
  assert.deepEqual(fn.paramAnnotations, [
    { index: 0, name: 'q', decorator: 'NotNull' },
    { index: 0, name: 'q', decorator: 'RequestParam' },
  ]);
});

// Fix round 1: a fully-qualified annotation's `typeName.Identifier` is an
// array of ALL dot-separated segments, not just the simple name — taking
// the first entry previously recorded the package root ("org") as the
// decorator instead of the actual annotation name.
test('parseJavaFile: a fully-qualified annotation records the simple name, not the package root', async () => {
  const code = `
public class UserController {
    public String show(@org.springframework.web.bind.annotation.RequestParam String q) {
        return q;
    }
}
`;
  const ir = await parseJavaFile('UserController.java', code);
  assert.ok(ir);
  const fn = ir.functions.find(f => f.name.includes('show'));
  assert.ok(fn);
  assert.deepEqual(fn.params, ['q']);
  assert.deepEqual(fn.paramAnnotations, [{ index: 0, name: 'q', decorator: 'RequestParam' }]);
});

// Java parameter shapes that the CST handles differently from a plain
// `Type name` parameter. Not exhaustive coverage of every shape — just
// confirming extraction doesn't silently corrupt or crash on them.
test('parseJavaFile: varargs parameter does not crash or corrupt other params', async () => {
  const code = `
public class Helper {
    public String show(String first, String... rest) {
        return first;
    }
}
`;
  const ir = await parseJavaFile('Helper.java', code);
  assert.ok(ir);
  const fn = ir.functions.find(f => f.name.includes('show'));
  assert.ok(fn);
  // java-parser puts varargs under a distinct `variableArityParameter` node
  // (not `variableParaRegularParameter`), so it isn't cleanly extracted by
  // this walk; the important thing is graceful degradation — no crash, and
  // the regular leading parameter is still extracted correctly.
  assert.ok(fn.params.includes('first'));
});

test('parseJavaFile: array-typed parameter is extracted cleanly (name unaffected by [])', async () => {
  const code = `
public class Helper {
    public String show(@RequestParam String[] items) {
        return items[0];
    }
}
`;
  const ir = await parseJavaFile('Helper.java', code);
  assert.ok(ir);
  const fn = ir.functions.find(f => f.name.includes('show'));
  assert.ok(fn);
  assert.deepEqual(fn.params, ['items']);
  assert.deepEqual(fn.paramAnnotations, [{ index: 0, name: 'items', decorator: 'RequestParam' }]);
});

test('R14(a) end-to-end: Spring @RequestParam flowing to a JDBC sink is detected', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-r14a-spring-'));
  fs.writeFileSync(path.join(dir, 'UserController.java'), `
public class UserController {
    public String show(@RequestParam String q) throws Exception {
        java.sql.Statement stmt = null;
        stmt.executeQuery(q);
        return q;
    }
}
`);
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const irFindings = (scan.findings || []).filter(f => f.parser === 'IR-TAINT');
  assert.ok(irFindings.length >= 1, `expected an annotation-sourced finding, got: ${JSON.stringify((scan.findings || []).map(f => f.parser))}`);
});
