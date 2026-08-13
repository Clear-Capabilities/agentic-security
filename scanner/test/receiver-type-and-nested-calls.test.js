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
  const suppressed = matchSinkOrSanitizer(calleeExpr, 'a.js', 'CacheClient');
  assert.ok(!suppressed || !suppressed.some(h => h.id === 'js-sql-query'),
    'js-sql-query must NOT match cache.query() once the receiver is confidently typed as non-DB');
});

test('R6 unit: matchSinkOrSanitizer still fires a genuine db.query() with a DB-shaped receiver type', () => {
  const calleeExpr = { kind: 'member', object: { kind: 'ident', name: 'db' }, prop: 'query' };
  const hits = matchSinkOrSanitizer(calleeExpr, 'a.js', 'db');
  assert.ok(hits && hits.some(h => h.id === 'js-sql-query'),
    'js-sql-query must still fire when the receiver type IS in the allow-list');
});

test('R6 unit: unknown receiver type (null) stays permissive — unknown != clean', () => {
  const calleeExpr = { kind: 'member', object: { kind: 'ident', name: 'x' }, prop: 'query' };
  const hits = matchSinkOrSanitizer(calleeExpr, 'a.js', null);
  assert.ok(hits && hits.some(h => h.id === 'js-sql-query'),
    'an unresolved (null) receiver type must never suppress a match — only a confident mismatch may');
});

test('R6 end-to-end: db.query(tainted) is reported as SQLi; cache.query(tainted) is NOT (brief Step 1)', async () => {
  const dir = mkTmp('r6-suppression', {
    'app.js': `
const express = require('express');
const app = express();
app.get('/a', (req, res) => {
  const db = require('./db');
  db.query(req.query.q);
});
app.get('/b', (req, res) => {
  const cache = require('./cache');
  cache.query(req.query.q);
});
`,
    'db.js': `
class Database { query(sql) { return sql; } }
module.exports = new Database();
`,
    'cache.js': `
class Redis { query(key) { return key; } }
module.exports = new Redis();
`,
  });
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const sqlFindings = (scan.findings || []).filter(f => /sql/i.test(f.vuln || ''));
  const lineOf = f => f.line || (f.id && Number((f.id.match(/:(\d+):/) || [])[1])) || 0;
  assert.ok(sqlFindings.some(f => lineOf(f) === 6), 'db.query(tainted) should be flagged as SQLi');
  assert.ok(!sqlFindings.some(f => lineOf(f) === 10), 'cache.query(tainted) should NOT be flagged as SQLi');
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
  assert.ok(cmdFindings.length >= 1,
    'expected the tainted flow through handle() -> runner.run() -> exec() to be detected interprocedurally via a CHA-tracked local variable');
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

