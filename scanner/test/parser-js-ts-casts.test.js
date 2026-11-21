// TypeScript wrappers carry no value of their own. `req.query.name as string`, `x!`, `<T>x`, `x satisfies T` lowered
// to `unknown`, so a cast on a request value, the ordinary way a typed handler reads one, cut every flow at the cast.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseJsFile } from '../src/ir/parser-js.js';
import { buildProjectIRAsync } from '../src/ir/index.js';
import { runDeepAnalysis } from '../src/dataflow/index.js';

async function sqli(files) {
  const ir = await buildProjectIRAsync(files);
  const r = runDeepAnalysis(ir.perFile, ir.callGraph, { fileContents: files });
  return [...new Set((Array.isArray(r) ? r : (r.findings || [])).filter((f) => f.cwe === 'CWE-89').map((f) => `${f.file}:${f.line}`))];
}
const app = (read, file = 'app.ts') => ({ [file]: `import express from "express";\nconst app = express();\napp.get("/x", (req, res) => {\n  const name = ${read};\n  db.query("SELECT * FROM t WHERE n = '" + name + "'");\n});\n` });

test('as, non-null, satisfies and a parenthesised cast keep the flow', async () => {
  for (const read of ['req.query.name as string', 'req.query.name!', 'req.query.name satisfies string', '(req.query as any).name']) {
    assert.deepEqual(await sqli(app(read)), ['app.ts:5'], read);
  }
});
test('an angle-bracket cast in a .ts file is a type assertion, not JSX', async () => {
  assert.deepEqual(await sqli(app('<string>req.query.name')), ['app.ts:5']);
  const ir = parseJsFile('g.ts', 'const id = <T,>(x: T) => x;\nexport function f(a: string) { return id(a); }\n');
  assert.ok(ir && ir.functions.length >= 1, 'a generic arrow in a .ts file still parses');
});
test('JSX in .tsx and .jsx still parses', async () => {
  assert.deepEqual(await sqli(app('req.query.name as string', 'app.tsx')), ['app.tsx:5']);
  const ir = parseJsFile('c.jsx', 'export function C(p) { return <div>{p.x}</div>; }\n');
  assert.ok(ir && ir.functions.some((f) => f.name === 'C'), 'the component parsed');
});
test('a cast on an assignment target is the same path', async () => {
  const files = { 'app.ts': `import express from "express";\nconst app = express();\napp.get("/x", (req, res) => {\n  const o: any = {};\n  (o as any).k = req.query.name;\n  db.query("SELECT * FROM t WHERE n = '" + o.k + "'");\n});\n` };
  assert.deepEqual(await sqli(files), ['app.ts:6']);
});
test('REFUSES: a cast does not create taint; a constant stays clean', async () => {
  assert.deepEqual(await sqli(app('"fixed" as string')), []);
});
