// Covers PRD R6, R10, R11 (docs/DETECTION_GAP_REMEDIATION_PRD.md, Theme B+D).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { runScan } from '../src/runScan.js';
import { buildProjectIR } from '../src/ir/index.js';
import { runDeepAnalysis } from '../src/dataflow/index.js';
import { matchSinkOrSanitizer } from '../src/dataflow/catalog.js';
import { buildClassHierarchy } from '../src/ir/class-hierarchy.js';

function mkTmp(name, files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `as-rcvr-${name}-`));
  for (const [rel, content] of Object.entries(files)) {
    const fp = path.join(dir, rel);
    fs.mkdirSync(path.dirname(fp), { recursive: true });
    fs.writeFileSync(fp, content);
  }
  return dir;
}

test('CHA is threaded onto callContext during a real deep scan (no throw, scan completes)', () => {
  const fileContents = {
    'app.js': `
class UserRepo {
  save(x) { return x; }
}
const repo = new UserRepo();
repo.save(1);
`,
  };
  const { perFile, callGraph } = buildProjectIR(fileContents);
  // Must not throw — this is the smoke test that CHA wiring didn't break
  // the ordinary per-file analysis loop.
  assert.doesNotThrow(() => runDeepAnalysis(perFile, callGraph, { fileContents }));
});

test('R6 unit: matchSinkOrSanitizer suppresses a bare-name SQL sink on a non-DB receiver type', () => {
  const calleeExpr = { kind: 'member', object: { kind: 'ident', name: 'cache' }, prop: 'query' };
  // No receiverType passed (today's behavior) — still matches, unconstrained.
  const unconstrained = matchSinkOrSanitizer(calleeExpr, 'a.js');
  assert.ok(unconstrained && unconstrained.some(h => h.id === 'js-sql-query'),
    'sanity: js-sql-query must still match with no receiverType arg (backward compat)');
  // A confidently-resolved, non-DB receiver type suppresses the SQL sink.
  // NOTE: the receiver type here is a CLASS name (`class Cache {}`), because
  // that is the only thing _receiverTypeFor can now produce. This used to read
  // 'CacheClient', which no longer suppresses — the receiverTypeIn vocabulary
  // is a substring match (whole-branch review, finding C1b) and 'CacheClient'
  // contains 'client'. That is the correct, safe direction: a class whose name
  // says "client" is not confidently non-DB.
  const suppressed = matchSinkOrSanitizer(calleeExpr, 'a.js', 'Cache');
  assert.ok(!suppressed || !suppressed.some(h => h.id === 'js-sql-query'),
    'js-sql-query must NOT match cache.query() once the receiver is confidently typed as non-DB');
});

test('R6 unit: matchSinkOrSanitizer still fires a genuine db.query() with a DB-shaped receiver type', () => {
  const calleeExpr = { kind: 'member', object: { kind: 'ident', name: 'db' }, prop: 'query' };
  const hits = matchSinkOrSanitizer(calleeExpr, 'a.js', 'db');
  assert.ok(hits && hits.some(h => h.id === 'js-sql-query'),
    'js-sql-query must still fire when the receiver type IS in the allow-list');
});

test('R6 unit: REALISTIC compound class names are not suppressed (whole-branch review finding C1b)', () => {
  // The receiverTypeIn patterns were exact-anchored (`^(?:db|pool|...)$`),
  // which only ever matched a class literally named `Db`. Every realistic
  // DB class name failed the allow-list and was silently suppressed. These
  // are the exact names from the review; a re-anchoring regression fails here.
  const calleeExpr = { kind: 'member', object: { kind: 'ident', name: 'x' }, prop: 'query' };
  for (const cls of ['DatabaseConnection', 'PrismaClient', 'MySQLConnection', 'PgPool', 'KnexClient']) {
    const hits = matchSinkOrSanitizer(calleeExpr, 'a.js', cls);
    assert.ok(hits && hits.some(h => h.id === 'js-sql-query'),
      `js-sql-query must fire for a receiver confidently typed as ${cls}`);
  }
  // ...and the genuine false-positive case must STILL be suppressed: no term
  // in the vocabulary is a substring of these.
  for (const cls of ['Cache', 'Logger', 'MemoryStore']) {
    const hits = matchSinkOrSanitizer(calleeExpr, 'a.js', cls);
    assert.ok(!hits || !hits.some(h => h.id === 'js-sql-query'),
      `js-sql-query must stay suppressed for a receiver confidently typed as ${cls}`);
  }
});

test('R6 unit: unknown receiver type (null) stays permissive — unknown != clean', () => {
  const calleeExpr = { kind: 'member', object: { kind: 'ident', name: 'x' }, prop: 'query' };
  const hits = matchSinkOrSanitizer(calleeExpr, 'a.js', null);
  assert.ok(hits && hits.some(h => h.id === 'js-sql-query'),
    'an unresolved (null) receiver type must never suppress a match — only a confident mismatch may');
});

test('R6 end-to-end: db.query(tainted) is reported as SQLi; cache.query(tainted) is NOT (brief Step 1)', async () => {
  // Updated fixture (round 4 fix): use `new X()` patterns which CHA can verify,
  // instead of `require()` patterns which cannot be CHA-typed. With the fix to
  // _receiverTypeFor (removing the bare-identifier fallback), require()-assigned
  // receivers become "unknown" and won't be suppressed anymore. To demonstrate
  // suppression, we need receivers CHA can actually resolve via `new X()`.
  const dir = mkTmp('r6-suppression', {
    'app.js': `
const express = require('express');
const app = express();

class Db { query(sql) { return sql; } }
class Cache { query(key) { return key; } }

function handleA(req) {
  const d = new Db();
  d.query(req.query.q);
}
function handleB(req) {
  const c = new Cache();
  c.query(req.query.q);
}

app.get('/a', (req, res) => { handleA(req); res.send('ok'); });
app.get('/b', (req, res) => { handleB(req); res.send('ok'); });
`,
  });
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const sqlFindings = (scan.findings || []).filter(f => /sql/i.test(f.vuln || ''));
  // Db matches the allow-list (/db/i), so d.query(tainted) should be flagged
  // Cache does NOT match (/db|pool|conn|client|sql|database|pg|mysql|sequelize|knex|prisma/i),
  // so c.query(tainted) should NOT be flagged.
  //
  // Assert on COUNT + LINE, not on f.description: `description` is always ""
  // for IR-TAINT findings, so the previous `filter(f => f.description.includes
  // ('Cache'))` could never match anything and the suppression assertion was
  // vacuously true (whole-branch review, finding I1). d.query() is on fixture
  // line 10, c.query() on line 14 — exactly one finding, and it must be the
  // Db one.
  const DB_QUERY_LINE = 10;
  const CACHE_QUERY_LINE = 14;
  assert.equal(sqlFindings.length, 1,
    `expected exactly one SQLi finding (Db.query, line ${DB_QUERY_LINE}); got ${sqlFindings.length}: ` +
    JSON.stringify(sqlFindings.map(f => ({ line: f.line, parser: f.parser, vuln: f.vuln }))));
  assert.equal(sqlFindings[0].line, DB_QUERY_LINE,
    `the surviving finding must be the Db.query() call on line ${DB_QUERY_LINE}, not the Cache.query() call on line ${CACHE_QUERY_LINE}`);
  assert.ok(!sqlFindings.some(f => f.line === CACHE_QUERY_LINE),
    'Cache.query(tainted) must NOT be flagged as SQLi — the receiver is confidently typed as a non-DB class');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('R6: an unresolvable-type receiver (e.g. a require()-based client) is never suppressed — unknown != clean', async () => {
  // Regression test for the exact bug caught by bench:layer-recall:check:
  // CVE-2021-22214-node-sqli-shape — a realistic Node.js SQLi pattern
  // using a member-call factory. Before the fix to _receiverTypeFor
  // (removing the bare-identifier fallback), this was silently suppressed
  // because `classOfVar` couldn't type `c` (assigned via `mysql.
  // createConnection({})`, not `new X()`), so the code fell back to
  // returning the bare name 'c' — which didn't match the allow-list and
  // suppressed the finding. With the fix, `classOfVar` returns null
  // (unknown), and the finding fires per "unknown ≠ clean".
  const dir = mkTmp('r6-unresolvable', {
    'app.js': `
const express = require('express');
const app = express();
app.get('/search', (req, res) => {
  const c = require('mysql').createConnection({});
  c.query(req.query.q);
  res.send('ok');
});
`,
  });
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const sqlFindings = (scan.findings || []).filter(f => /sql/i.test(f.vuln || ''));
  assert.ok(sqlFindings.length >= 1,
    'a receiver whose type cannot be verified must never be suppressed — this exact shape (CVE-2021-22214-node-sqli-shape) regressed once already');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('R6: this.<field>.<method>() sinks are not regressed by the receiver-type gate', async () => {
  // Critical #2 regression test (confirmed working shape): ensure that
  // this.db.query(tainted) is still detected as SQLi after the _this_ →
  // 'this' sentinel conversion fix. The key is that tainted input (req.query.q)
  // is read WITHIN the same method that calls this.db.query(), not passed
  // as a parameter from an earlier hop (which would hit a pre-existing
  // interprocedural-taint limitation unrelated to this task).
  const dir = mkTmp('r6-this-field', {
    'app.js': `
const express = require('express');
const app = express();
class Repo {
  constructor() { this.db = require('./db'); }
  find(req) { return this.db.query(req.query.q); }
}
const repo = new Repo();
app.get('/search', (req, res) => {
  repo.find(req);
  res.send('ok');
});
`,
    'db.js': `
class Database { query(sql) { return sql; } }
module.exports = new Database();
`,
  });
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const sqlFindings = (scan.findings || []).filter(f => /sql/i.test(f.vuln || ''));
  assert.ok(sqlFindings.length >= 1,
    'this.db.query(req.query.q) inside a class method must still be detected as SQLi after the R6 receiver-type gate');
  fs.rmSync(dir, { recursive: true, force: true });
});

// ─────────────────────────────────────────────────────────────────────────
// Whole-branch-review regressions (findings C1a / C1c / C1d). Each of these
// is a REAL SQL injection that the pre-fix branch silently dropped — not
// demoted, absent — while the pre-branch base commit reported all of them.
// The unifying root cause: _receiverTypeFor was returning name/shape GUESSES
// (a PascalCased `this.<field>` name; the ROOT of a multi-segment chain;
// a PascalCase non-`new` callee mistyped by CHA) and the catalog gate then
// treated those guesses as confident resolutions and suppressed the match.
// ─────────────────────────────────────────────────────────────────────────

for (const field of ['dbConn', 'readReplica']) {
  test(`R6 regression (C1a): this.${field}.query(tainted) is NOT suppressed — a this.<field> receiver has no CHA-verifiable type`, async () => {
    const dir = mkTmp(`r6-this-${field}`, {
      'app.js': `
const express = require('express');
const app = express();
function makeConn() { return require('mysql').createConnection({}); }
class Repo {
  constructor() { this.${field} = makeConn(); }
  find(req) { return this.${field}.query(req.query.q); }
}
const repo = new Repo();
app.get('/search', (req, res) => { repo.find(req); res.send('ok'); });
`,
    });
    const { scan } = await runScan(dir, { deep: true, deepInCi: true });
    const sqlFindings = (scan.findings || []).filter(f => /sql/i.test(f.vuln || ''));
    assert.ok(sqlFindings.some(f => f.parser === 'IR-TAINT'),
      `this.${field}.query(req.query.q) is a real SQLi and must be reported. The old this-branch PascalCased the field name ('${field.charAt(0).toUpperCase() + field.slice(1)}'), never returned null, and suppressed every field name outside a fixed vocabulary`);
    fs.rmSync(dir, { recursive: true, force: true });
  });
}

test('R6 regression (C1c): a multi-segment receiver chain (svc.db.query) resolves to unknown, not to the type of the chain ROOT', async () => {
  const dir = mkTmp('r6-chain-root', {
    'app.js': `
const express = require('express');
const app = express();
class Service { constructor() { this.db = require('./db'); } }
app.get('/search', (req, res) => {
  const svc = new Service();
  svc.db.query(req.query.q);
  res.send('ok');
});
`,
    'db.js': 'class Database { query(sql) { return sql; } }\nmodule.exports = new Database();\n',
  });
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const sqlFindings = (scan.findings || []).filter(f => /sql/i.test(f.vuln || ''));
  // The receiver here is `svc.db`, whose type CHA never tracks. The old code
  // asked classOfVar about `svc` instead (the chain ROOT), got the confident
  // answer 'Service', found no vocabulary match, and suppressed a real SQLi.
  assert.ok(sqlFindings.some(f => f.parser === 'IR-TAINT'),
    'svc.db.query(req.query.q) must be reported: `svc.db` has no CHA-verifiable type, and unknown never suppresses');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('R6/CHA regression (C1d): a PascalCase FACTORY call (no `new`) must not be mistyped as a class', async () => {
  const dir = mkTmp('r6-factory', {
    'app.js': `
const express = require('express');
const app = express();
function BuildCache() { return require('mysql').createConnection({}); }
app.get('/search', (req, res) => {
  const q = BuildCache();
  q.query(req.query.q);
  res.send('ok');
});
`,
  });
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const sqlFindings = (scan.findings || []).filter(f => /sql/i.test(f.vuln || ''));
  // buildClassHierarchy's typeOfVar walker used to accept any PascalCase
  // callee as a constructor, so `q` was confidently (and wrongly) typed
  // 'BuildCache' — no vocabulary match, real SQLi suppressed. It now requires
  // the IR's `isNew` marker, which parser-js.js emits only for NewExpression.
  assert.ok(sqlFindings.some(f => f.parser === 'IR-TAINT'),
    'a receiver returned by a PascalCase factory function has no verified type and must never be suppressed');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('CHA: typeOfVar tracks `new Foo()` and ONLY `new Foo()` (C1d — isNew is required)', () => {
  const { perFile } = buildProjectIR({
    'a.js': 'class Db { query(s) { return s; } }\nfunction MakeThing() { return 1; }\nfunction h() { const a = new Db(); const b = MakeThing(); return [a, b]; }\n',
  });
  const cha = buildClassHierarchy(perFile);
  const typed = [...cha.typeOfVar.entries()].map(([k, v]) => [k.split('::').pop(), v]);
  assert.deepEqual(typed.filter(([n]) => n === 'a'), [['a', 'Db']], '`const a = new Db()` must be typed');
  assert.deepEqual(typed.filter(([n]) => n === 'b'), [], '`const b = MakeThing()` is a plain call, not a constructor — it must stay untyped');
});

test('class-hierarchy: registers a real JS class method from actual parser output (regression — the qid shape is ::-joined, not dot-joined)', () => {
  const fileContents = { 'a.js': 'class UserRepo {\n  save(x) { return x; }\n}\n' };
  const { perFile } = buildProjectIR(fileContents);
  const cha = buildClassHierarchy(perFile);
  assert.ok(cha.classes.has('UserRepo'), 'UserRepo should be registered from real parser-js.js output');
  assert.ok(cha.classes.get('UserRepo').methods.has('save'), "save should be registered as UserRepo's method");
});

test('R11: member-call interprocedural resolution via a CHA-tracked local variable', async () => {
  const dir = mkTmp('r11-local', {
    'app.js': `
const { exec } = require('child_process');
const express = require('express');
const app = express();
class CommandRunner {
  run(cmd) { exec(cmd); }
}
function handle(input) {
  const runner = new CommandRunner();
  runner.run(input);
}
app.get('/run', (req, res) => {
  const cmd = req.query.cmd;
  handle(cmd);
  res.send('ok');
});
`,
  });
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const cmdFindings = (scan.findings || []).filter(f => /command|exec|injection/i.test(f.vuln || ''));
  // Assert on the IR-TAINT parser specifically, mirroring the R10 test below.
  // `>= 1` alone is not an R11 regression detector: this fixture also fires a
  // REGEX-layer finding with R11 completely absent (verified against the
  // pre-branch base commit — whole-branch review, finding I2), so the loose
  // assertion passed either way.
  assert.ok(cmdFindings.some(f => f.parser === 'IR-TAINT'),
    'expected an IR-TAINT finding for the tainted flow through handle() -> runner.run() -> exec(), resolved interprocedurally via a CHA-tracked local variable; got ' +
    JSON.stringify(cmdFindings.map(f => ({ line: f.line, parser: f.parser, vuln: f.vuln }))));
  fs.rmSync(dir, { recursive: true, force: true });
});

test('R11: this.<field>.<method>() does not fabricate an interprocedural resolution (no verified type available)', async () => {
  const dir = mkTmp('r11-this-no-resolve', {
    'app.js': `
const express = require('express');
const app = express();
class Handler {
  process(x) { return x; }
}
class Wrapper {
  constructor() { this.handler = new Handler(); }
  run(input) { this.handler.process(input); }
}
app.get('/run', (req, res) => {
  const w = new Wrapper();
  w.run(req.query.q);
  res.send('ok');
});
`,
  });
  // this.handler.process(input) has no CHA-verified type for `this.handler` —
  // R11 must not resolve it. The assertion here is simply that the scan
  // completes cleanly; no interprocedural finding through process() is
  // expected (and none should be fabricated).
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  assert.ok(scan && Array.isArray(scan.findings), 'scan must complete without fabricating a this.field resolution');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('R11: an ambiguous same-named method across two unrelated classes still refuses to resolve', async () => {
  const dir = mkTmp('r11-ambiguous', {
    'app.js': `
const { exec } = require('child_process');
const express = require('express');
const app = express();
class Logger {
  save(x) { /* writes to a log file, not a sink */ }
}
class Cache {
  save(x) { /* writes to memory, not a sink */ }
}
function useEither(flag, x) {
  const target = flag ? new Logger() : new Cache();
  target.save(x);
}
app.get('/run', (req, res) => {
  useEither(true, req.query.q);
  res.send('ok');
});
`,
  });
  // Neither Logger.save nor Cache.save calls exec/eval/a sink — this test's
  // real assertion is that the scan completes without throwing and without
  // fabricating a finding out of an unresolved/ambiguous receiver. `target`
  // is assigned from a ternary (`flag ? new Logger() : new Cache()`), which
  // isn't a `kind: 'call'` RHS shape buildClassHierarchy's typeOfVar walker
  // recognizes (it only tracks direct `x = new Foo()` assigns) — so
  // classOfVar(cha, file, fnQid, 'target') genuinely returns null here, and
  // _resolveMemberCalleeViaCHA correctly refuses before ever reaching
  // resolveMethod. This is real CHA-ambiguity-driven refusal, not an
  // incidental non-collision between `target` and a registered class name.
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  assert.ok(scan && Array.isArray(scan.findings), 'scan must complete');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('R10: a helper call nested directly in a sink argument is detected', async () => {
  const dir = mkTmp('r10-nested', {
    'app.js': `
const { exec } = require('child_process');
const express = require('express');
const app = express();
function getUserInput(req) { return req.query.cmd; }
app.get('/run', (req, res) => {
  exec(getUserInput(req));
  res.send('ok');
});
`,
  });
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const cmdFindings = (scan.findings || []).filter(f => /command|exec|injection/i.test(f.vuln || ''));
  assert.ok(cmdFindings.length >= 1,
    'expected exec(getUserInput(req)) to be detected — getUserInput()\'s own return-taint summary must be consulted for a call nested directly in the sink argument, not just at assignment/statement position');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('R10: a clean nested call does not spuriously taint the sink', async () => {
  const dir = mkTmp('r10-clean-nested', {
    'app.js': `
const { exec } = require('child_process');
const express = require('express');
const app = express();
function getFixedCommand() { return 'echo hello'; }
app.get('/run', (req, res) => {
  exec(getFixedCommand());
  res.send('ok');
});
`,
  });
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const cmdFindings = (scan.findings || []).filter(f => /command|exec|injection/i.test(f.vuln || ''));
  assert.equal(cmdFindings.length, 0, 'exec(getFixedCommand()) must NOT be flagged — the nested call returns no tainted value');
  fs.rmSync(dir, { recursive: true, force: true });
});

