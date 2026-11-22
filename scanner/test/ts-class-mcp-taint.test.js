// TypeScript taint through classes and MCP tool handlers: a constructor parameter property, a typed field, a field built with `new` in the
// constructor, a typed local, `this.helper(...)`, and a destructured handler parameter of `server.tool(...)` / `server.registerTool(...)`.
// Each positive case has a refusing twin.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildProjectIRAsync } from '../src/ir/index.js';
import { runDeepAnalysis } from '../src/dataflow/index.js';

const SINK = (v) => `db.query("SELECT * FROM t WHERE n = '" + ${v} + "'");`;
const SVC = `export class ItemService {\n  find(name: string) {\n    ${SINK('name')}\n    return 1;\n  }\n  other(name: string, n: number) { return 2; }\n}\n`;
async function sqli(files) {
  const ir = await buildProjectIRAsync(files);
  const r = runDeepAnalysis(ir.perFile, ir.callGraph, { fileContents: files });
  return [...new Set((Array.isArray(r) ? r : (r.findings || [])).filter((f) => f.cwe === 'CWE-89').map((f) => `${f.file}:${f.line}`))];
}
const ctl = (members, body) => `import { Query } from "@nestjs/common";\nimport { ItemService } from "./service";\nexport class Ctl {\n${members}\n  get(@Query("name") name: string) { ${body} }\n}\n`;

test('a NestJS constructor parameter property types the field: this.svc.find(name) reaches the service', async () => {
  assert.deepEqual(await sqli({ 'ctl.ts': ctl('  constructor(private readonly svc: ItemService) {}', 'return this.svc.find(name);'), 'service.ts': SVC }), ['service.ts:3']);
});
test('... a typed field assigned in the constructor, and a field built with new', async () => {
  assert.deepEqual(await sqli({ 'ctl.ts': ctl('  private svc: ItemService;\n  constructor(svc: ItemService) { this.svc = svc; }', 'return this.svc.find(name);'), 'service.ts': SVC }), ['service.ts:3']);
  assert.deepEqual(await sqli({ 'ctl.ts': ctl('  svc;\n  constructor() { this.svc = new ItemService(); }', 'return this.svc.find(name);'), 'service.ts': SVC }), ['service.ts:3']);
});
test('... a typed or constructed local, and this.helper(name) in the own class', async () => {
  assert.deepEqual(await sqli({ 'ctl.ts': `import { ItemService } from "./service";\nexport function get(@Query("name") name: string) { const s = new ItemService(); return s.find(name); }\n`, 'service.ts': SVC }), ['service.ts:3']);
  assert.deepEqual(await sqli({ 'ctl.ts': `import { ItemService } from "./service";\nexport function get(@Query("name") name: string) { const s: ItemService = make(); return s.find(name); }\n`, 'service.ts': SVC }), ['service.ts:3']);
  assert.deepEqual(await sqli({ 'ctl.ts': `export class Ctl {\n  helper(name: string) { ${SINK('name')} }\n  get(@Query("name") name: string) { return this.helper(name); }\n}\n` }), ['ctl.ts:2']);
});
test('REFUSES: a clean method of the typed service, and a library type that no project class matches', async () => {
  assert.deepEqual(await sqli({ 'ctl.ts': ctl('  constructor(private readonly svc: ItemService) {}', 'return this.svc.other(name, 1);'), 'service.ts': SVC }), []);
  assert.deepEqual(await sqli({ 'ctl.ts': `import { HttpService } from "@nestjs/axios";\nexport class Ctl {\n  constructor(private readonly http: HttpService) {}\n  get(@Query("name") name: string) { return this.http.find(name); }\n}\n` }), []);
});
test('the IR states the facts: class records with field types, parameter types, declared and constructed locals, destructured parameter bindings', async () => {
  const ir = await buildProjectIRAsync({ 'c.ts': `class Svc {}\nexport class Ctl {\n  private readonly other: Svc;\n  made: Svc;\n  constructor(private readonly svc: Svc, plain: Svc) { this.made = new Svc(); this.p = plain; }\n  run(q: Svc, r?: string) { const a: Svc = mk(); const b = new Svc(); return a; }\n}\nserver.tool("t", {}, async ({ city, units: u, ...rest }) => city);\n` });
  const pf = ir.perFile['c.ts'];
  assert.deepEqual(pf.classes.map((c) => c.name), ['Svc', 'Ctl']);
  assert.deepEqual(pf.classes[1].fieldTypes, { other: 'Svc', made: 'Svc', svc: 'Svc', p: 'Svc' });
  const run = pf.functions.find((f) => f.name === 'run');
  assert.deepEqual(run.paramTypes, { q: 'Svc' });
  const decl = Object.values(run.cfg.nodes).filter((n) => n.kind === 'assign' && n.declaredType).map((n) => `${n.target}:${n.declaredType}`);
  assert.deepEqual(decl.sort(), ['a:Svc', 'b:Svc']);
  const handler = pf.functions.find((f) => f.paramAnnotations && f.paramAnnotations.some((a) => a.decorator === 'js:mcp-tool-handler'));
  assert.ok(handler, 'the tool handler is marked');
  const binds = Object.values(handler.cfg.nodes).filter((n) => n.kind === 'assign').map((n) => `${n.target}<-${n.source.kind === 'member' ? n.source.object.name + '.' + n.source.prop : n.source.name}`);
  assert.deepEqual(binds, ['city<-<obj>.city', 'u<-<obj>.units', 'rest<-<obj>']);
});
test('MCP tool handler arguments are a source: destructured, renamed, or a named object; the two-argument form and an unrelated callback are not', async () => {
  const sdk = 'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\nimport { z } from "zod";\nconst server = new McpServer({ name: "x", version: "1" });\n';
  assert.deepEqual(await sqli({ 'mcp.ts': sdk + `server.tool("find", { name: z.string() }, async ({ name }) => {\n  ${SINK('name')}\n  return { content: [] };\n});\n` }), ['mcp.ts:5']);
  assert.deepEqual(await sqli({ 'mcp.ts': sdk + `server.tool("find", "finds", { name: z.string() }, async ({ name: n }, extra) => {\n  ${SINK('n')}\n});\n` }), ['mcp.ts:5']);
  assert.deepEqual(await sqli({ 'mcp.ts': sdk + `server.registerTool("find", { inputSchema: {} }, async (args) => {\n  ${SINK('args.name')}\n  return { content: [] };\n});\n` }), ['mcp.ts:5']);
  assert.deepEqual(await sqli({ 'mcp.ts': sdk + `server.tool("ping", async (extra) => {\n  ${SINK('extra.sessionId')}\n});\n` }), [], 'no schema, no arguments');
  assert.deepEqual(await sqli({ 'app.ts': `thing.on("event", ({ name }) => { ${SINK('name')} });\n` }), [], 'an unrelated callback is not a tool handler');
});

// An object literal argument enters the callee by field: a tainted field taints that field of the destructured (or plain) parameter and no
// sibling. Found on this repository's own code, where `record({ root, decision: tainted })` made the clean `root` a path-traversal source.
const REC = (params, use) => `import express from "express";\nfunction rec(${params}) { ${SINK(use)} }\nexport function h(req, res) { BODY }\n`;
const withBody = (src, body) => src.replace('BODY', body);
test('an object literal argument taints only the field that is tainted: the destructured sibling stays clean', async () => {
  const src = REC('{ root, decision }', 'root');
  assert.deepEqual(await sqli({ 'a.js': withBody(src, 'rec({ root: "fixed", decision: req.query.d });') }), []);
  assert.deepEqual(await sqli({ 'a.js': withBody(src, 'rec({ root: req.query.p, decision: 1 });') }), ['a.js:2']);
  assert.deepEqual(await sqli({ 'a.js': withBody(src, 'const root = "fixed"; rec({ root, decision: req.query.d });') }), []);
});
test('... the same for a plain parameter read by field, and for a literal nested one level down', async () => {
  const plain = REC('o', 'o.root');
  assert.deepEqual(await sqli({ 'a.js': withBody(plain, 'rec({ root: "fixed", decision: req.query.d });') }), []);
  assert.deepEqual(await sqli({ 'a.js': withBody(plain, 'rec({ root: req.query.p });') }), ['a.js:2']);
  const nested = REC('{ opts }', 'opts.path');
  assert.deepEqual(await sqli({ 'a.js': withBody(nested, 'rec({ opts: { path: req.query.p } });') }), ['a.js:2']);
  assert.deepEqual(await sqli({ 'a.js': withBody(nested, 'rec({ opts: { path: "fixed" }, other: req.query.p });') }), []);
});
test('STILL WIDENS: a tainted object passed whole, a spread of one, and a value whose shape is unknown', async () => {
  const src = REC('{ root, decision }', 'root');
  assert.deepEqual(await sqli({ 'a.js': withBody(src, 'rec(req.body);') }), ['a.js:2']);
  assert.deepEqual(await sqli({ 'a.js': withBody(src, 'rec({ ...req.body });') }), ['a.js:2']);
  assert.deepEqual(await sqli({ 'a.js': withBody(src, 'const o = req.body; rec(o);') }), ['a.js:2']);
});

// tRPC procedures, TypeORM's query builder and mongoose's `$where` operator.
const EX = (imports, body) => ({ 'a.ts': `import express from "express";\n${imports}\nconst app = express();\napp.get("/r", async (req, res) => {\n${body}\n});\n` });
async function cwe(files, c) {
  const ir = await buildProjectIRAsync(files);
  const r = runDeepAnalysis(ir.perFile, ir.callGraph, { fileContents: files });
  return [...new Set((Array.isArray(r) ? r : (r.findings || [])).filter((f) => f.cwe === c).map((f) => `${f.file}:${f.line}`))];
}
test('tRPC: the resolver after .input(schema) receives client input as `input`, destructured or on a named options object; ctx is not input', async () => {
  const T = (res) => ({ 'a.ts': `import { z } from "zod";\nimport { router, publicProcedure } from "./trpc";\nexport const r = router({ g: publicProcedure.input(z.object({ n: z.string() })).query(${res}) });\n` });
  const Q = (v) => `ctx.prisma.$queryRawUnsafe("SELECT * FROM t WHERE n = '" + ${v} + "'")`;
  assert.deepEqual(await cwe(T(`async ({ input, ctx }) => ${Q('input.n')}`), 'CWE-89'), ['a.ts:3']);
  assert.deepEqual(await cwe(T(`async (opts) => opts.${Q('opts.input.n')}`), 'CWE-89'), ['a.ts:3']);
  assert.deepEqual(await cwe(T(`async ({ input, ctx }) => ${Q('ctx.user.id')}`), 'CWE-89'), []);
  assert.deepEqual(await cwe({ 'a.ts': `import { router, publicProcedure } from "./trpc";\nexport const r = router({ g: publicProcedure.query(async (opts) => opts.ctx.prisma.$queryRawUnsafe("SELECT * FROM t WHERE n = '" + opts.input + "'")) });\n` }, 'CWE-89'), []);
});
test('TypeORM query builder: a concatenated fragment in .where/.andWhere is SQL injection; a parameter placeholder and a knex .where are not', async () => {
  assert.deepEqual(await cwe(EX('import { repo } from "./ds";', `  res.json(await repo.createQueryBuilder("t").where("t.n = '" + req.query.n + "'").getMany());`), 'CWE-89'), ['a.ts:5']);
  assert.deepEqual(await cwe(EX('import { repo } from "./ds";', `  res.json(await repo.createQueryBuilder("t").where("t.a = 1").andWhere("t.n = '" + req.query.n + "'").getMany());`), 'CWE-89'), ['a.ts:5']);
  assert.deepEqual(await cwe(EX('import { repo } from "./ds";', `  res.json(await repo.createQueryBuilder("t").where("t.n = :n", { n: req.query.n }).getMany());`), 'CWE-89'), []);
  assert.deepEqual(await cwe(EX('import { knex } from "./ds";', `  res.json(await knex("t").where("n", req.query.n));`), 'CWE-89'), []);
});
test('mongoose: a tainted $where value in the filter document is NoSQL injection; an ordinary field filter and a literal $where are not', async () => {
  assert.deepEqual(await cwe(EX('import { Item } from "./m";', `  res.json(await Item.find({ $where: "this.n == '" + req.query.n + "'" }));`), 'CWE-943'), ['a.ts:5']);
  assert.deepEqual(await cwe(EX('import { Item } from "./m";', `  res.json(await Item.find({ name: req.query.n }));`), 'CWE-943'), []);
  assert.deepEqual(await cwe(EX('import { Item } from "./m";', `  res.json(await Item.find({ $where: "this.n == 1" }));`), 'CWE-943'), []);
});
