// DAG precision: the general rules behind the false-positive reductions measured by bench/dag.
// Each rule is exercised as a pair: the construct that is safe BY SEMANTICS stays quiet, and the near-miss that changes the
// semantics (a different prefix, a different property, an options object without `root`) keeps the verdict. Engine-level
// metamorphic pairs live in bench/mutation/cases.mjs (DAG_PRECISION_CASES); these are the unit-level tables.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { redirectArgumentPinsOrigin, redirectTargetPinsOriginAt, prefixPinsOrigin, leadingLiteral } from '../src/sast/redirect-target.js';
import { reflectsRawRequestInput, stripHtmlEscaperCalls, responseReflectsRequestInputAt } from '../src/sast/reflected-input.js';
import { sendFileConfinedToRootAt } from '../src/sast/send-file-root.js';
import { insideFunctionBody } from '../src/sast/init-scope.js';
import { isListenCallbackParam } from '../src/sast/listen-bind-address.js';
import { callArguments } from '../src/sast/_call-args.js';
import { backfillFindingDefaults } from '../src/posture/finding-defaults.js';
import { scanSensitiveDataLogging } from '../src/sast/sensitive-data-logging.js';

test('redirect target: a literal that fixes the origin pins it, one that does not does not', () => {
  const pinned = [
    "'/user/' + id", '`/user/${id}`', "'/a'", "'/user/' + a + b", "'https://app.example.com/' + p",
    "'http://example.com:3000/' + req.vhost[0]", "'/x?next=' + q",
  ];
  const open = [
    "'/' + next", "'//' + next", "'/\\\\' + next", "'https://app.example.com' + next", "'https://app.example.com.' + next",
    'next', "'' + next", "next + '/path'", "'//evil.example/' + p", 'req.query.next || "/"', "'https://' + host + '/x'",
  ];
  for (const a of pinned) assert.equal(redirectArgumentPinsOrigin(a), true, a);
  for (const a of open) assert.equal(redirectArgumentPinsOrigin(a), false, a);
});

test('redirect target: leading literal parsing is quote- and template-aware', () => {
  assert.deepEqual(leadingLiteral("'a' + 'b/' + x"), { literal: 'ab/', dynamic: true, closed: true });
  assert.equal(leadingLiteral('`/u/${x}`').literal, '/u/');
  assert.equal(leadingLiteral('`/u/${x}`').dynamic, true);
  assert.equal(leadingLiteral("'/u/'").dynamic, false);
  assert.equal(leadingLiteral("'unterminated").closed, false);
  assert.equal(prefixPinsOrigin('/'), false);
  assert.equal(prefixPinsOrigin('/x'), true);
});

test('redirect target: reads the call at the given line, skipping a status code, and has no opinion without a call', () => {
  assert.equal(redirectTargetPinsOriginAt(["res.redirect(302, '/a/' + x);"], 1), true);
  assert.equal(redirectTargetPinsOriginAt(["res.redirect(302, '/' + x);"], 1), false);
  assert.equal(redirectTargetPinsOriginAt(['res.redirect(', "  '/a/' + x", ');'], 1), true);
  assert.equal(redirectTargetPinsOriginAt(['res.send(x);'], 1), null);
  assert.equal(redirectTargetPinsOriginAt([], 1), null);
});

test('reflected input: only request-input properties count, and not inside an HTML escaper', () => {
  const raw = ["'x' + req.query.q", "req.body.name", "'a' + req.params.id", "req.get('Referer')", "'x' + escapeHtml(req.query.a) + req.query.b", "req['query']"];
  const notRaw = ["'x' + req.session.count", "'x' + req.user.name", "'x' + req.app.locals.title", "'x' + req.pet.id", "'x' + escapeHtml(req.query.q)", "'x' + escapeHtml(req.params.a) + escapeHtml(req.params.b)", "'static'"];
  for (const e of raw) assert.equal(reflectsRawRequestInput(e), true, e);
  for (const e of notRaw) assert.equal(reflectsRawRequestInput(e), false, e);
  assert.ok(!/req/.test(stripHtmlEscaperCalls('x + escapeHtml(f(req.query.q)) + y')));
  assert.equal(responseReflectsRequestInputAt(["res.send('hi ' + req.query.n);"], 1), true);
  assert.equal(responseReflectsRequestInputAt(["res.send('hi ' + req.session.n);"], 1), false);
  assert.equal(responseReflectsRequestInputAt(['foo();'], 1), null);
});

test('file serving: an inline root option confines the path; anything else does not', () => {
  assert.equal(sendFileConfinedToRootAt(["res.sendFile(req.query.f, { root: DIR });"], 1), true);
  assert.equal(sendFileConfinedToRootAt(["res.download(req.query.f, 'n', { root: DIR });"], 1), true);
  assert.equal(sendFileConfinedToRootAt(["res.sendFile(req.query.f, { dotfiles: 'deny' });"], 1), false);
  assert.equal(sendFileConfinedToRootAt(["res.sendFile(req.query.f);"], 1), false);
  assert.equal(sendFileConfinedToRootAt(["res.sendFile(req.query.f, opts);"], 1), false);
  assert.equal(sendFileConfinedToRootAt(["res.sendFile(req.query.f, { ...o });"], 1), false);
  assert.equal(sendFileConfinedToRootAt(['foo();'], 1), null);
  assert.equal(sendFileConfinedToRootAt(["res.download(req.params.f.join('/'), { root: D }, function (err) {"], 1), true);
});

test('initialisation scope: braces of control blocks and literals are not function bodies', () => {
  const at = (src) => insideFunctionBody(src, src.indexOf('READ'));
  assert.equal(at('const a = f({ https: { key: fs.READ(p) } })'), false);
  assert.equal(at('if (x) { fs.READ(p) }'), false);
  assert.equal(at('try { fs.READ(p) } catch (e) {}'), false);
  assert.equal(at('const c = { k: fs.READ(p) }'), false);
  assert.equal(at('app.get("/", (req,res) => { fs.READ(p) })'), true);
  assert.equal(at('app.get("/", function (req,res) { fs.READ(p) })'), true);
  assert.equal(at('class A { m(x) { fs.READ(p) } }'), true);
  assert.equal(at('function boot(){ if (x) { fs.READ(p) } }'), true);
  assert.equal(at('const f = async (a) => { fs.READ(p) }'), true);
  assert.equal(at('const load = (p) => fs.READ(p)'), true, 'an expression-bodied arrow runs when it is called');
  assert.equal(at('app.get("/", (req, res) => res.send(fs.READ(p)))'), true);
  assert.equal(at('const r = [1, 2].map((x) => x + 1, fs.READ(p))'), false, 'after the arrow body ended at the comma');
  assert.equal(at('const a = (x) => x + 1;\nconst k = fs.READ(p);'), false, 'after the arrow body ended at the semicolon');
  assert.equal(at('class Svc { cache = fs.READ(p); }'), true, 'a class field initialiser runs per instance');
  assert.equal(at("export function resolve(a, { d = path.join(os.homedir(), ' ', ' ') } = {}) { try { fs.READ(d) } catch {} }"), true, 'a parameter list nested three deep is still a function head');
  assert.equal(at('async function f(): Promise<void> { fs.READ(p) }'), true, 'a return type annotation does not hide the head');
  assert.equal(at('if (a) { if (b) { fs.READ(p) } } else { fs.READ(p) }'), false);
  assert.equal(at('switch (k) { case 1: { fs.READ(p) } }'), false);
});

test('listen callbacks: the address parameter is the bound socket address; other bindings of the name are unaffected', () => {
  const a = 'server.listen({ port: 1 }, (err, address) => {\n  console.log(address);\n});';
  assert.equal(isListenCallbackParam(a, a.indexOf('address'), 'address'), true);
  const b = 'server.listen(1, function (err, address) { log(address); });';
  assert.equal(isListenCallbackParam(b, b.indexOf('address'), 'address'), true);
  const c = 'const address = req.body.address;\nconsole.log(address);';
  assert.equal(isListenCallbackParam(c, c.indexOf('address'), 'address'), false);
  const d = 'server.listen(1);\nfunction h(address) { log(address); }';
  assert.equal(isListenCallbackParam(d, d.indexOf('address'), 'address'), false);
});

test('call arguments: splits at top-level commas only and reports a window that ends inside the call as partial', () => {
  assert.deepEqual(callArguments("a, f(b, c), {d: 1, e: 2}, 'x,y')"), ['a', ' f(b, c)', ' {d: 1, e: 2}', " 'x,y'"]);
  const p = callArguments('a, b, function (e) {');
  assert.equal(p.partial, true);
  assert.deepEqual([...p], ['a', ' b']);
  assert.equal(callArguments('unterminated'), null);
});

test('finding line: a flow finding that only carries sink.line gets it; a detector-set line is never overwritten', () => {
  const fs1 = [{ sink: { line: 12 }, source: { line: 3 } }, { line: 7, sink: { line: 9 } }, { source: { line: 4 } }, { sink: { line: 0 } }, {}];
  backfillFindingDefaults(fs1);
  assert.equal(fs1[0].line, 12);
  assert.equal(fs1[1].line, 7);
  assert.equal(fs1[2].line, 4);
  assert.equal(fs1[3].line, undefined);
  assert.equal(fs1[4].line, undefined);
});

test('sensitive-data logging: a PII word in message prose is not a logged value; the variable is', () => {
  const scan = (code) => scanSensitiveDataLogging('a.js', code);
  assert.equal(scan("console.log('please enter your email');").length, 0);
  assert.equal(scan('console.log(email);').length, 1);
  assert.equal(scan('console.log(`user ${email} signed in`);').length, 1);
  assert.equal(scan('console.log(`email is required`);').length, 0);
  const py = (code) => scanSensitiveDataLogging('a.py', code);
  assert.equal(py("logger.info(f'login {email}')").length, 1);
  assert.equal(py("logger.info('login email required')").length, 0);
});

test('a source variable is only a read in an argument when it appears as a variable', async () => {
  // `user` appears twice below as TEXT (a string literal and a property name). Neither reads the variable `user`
  // assigned in another function, so no flow from req.params.id may be reported at the response.
  const { runScan } = await import('../src/runScan.js');
  const { disableStateWrites } = await import('../../bench/_lib/tree-integrity.mjs');
  await disableStateWrites();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dag-usedvars-'));
  const verdict = async (code) => {
    fs.writeFileSync(path.join(dir, 'app.js'), code);
    const { scan } = await runScan(dir);
    return (scan.findings || []).filter((f) => f.parser === 'REGEX' && /CWE-79/.test(f.cwe || '')).length;
  };
  try {
    const head = `function loadUser(req, res, next) {\n  var user = users[req.params.id];\n  next();\n}\n`;
    assert.equal(await verdict(`${head}app.get('/u', loadUser, function (req, res) {\n  res.send('Viewing user ' + req.session.label);\n});\n`), 0);
    assert.equal(await verdict(`${head}app.get('/u', loadUser, function (req, res) {\n  res.send('Viewing ' + req.user.name);\n});\n`), 0);
    assert.ok(await verdict(`${head}app.get('/u', loadUser, function (req, res) {\n  var user = users[req.params.id];\n  res.send('Viewing ' + user);\n});\n`) > 0, 'a real read of the variable keeps the finding');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
