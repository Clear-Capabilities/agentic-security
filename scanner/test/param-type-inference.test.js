// Next-gen taint capability #4 — a narrow, call-site-scoped slice of
// "Andersen-style points-to" (not the full thing): cross-call-site PARAMETER
// type inference from the argument a caller actually passes, for JS/TS.
//
// `class-hierarchy.js`'s `typeOfVar` already infers a local variable's type
// from `const x = new Foo()` (assignment-time) and, for Java/C# only, from a
// declared parameter type (`fn.paramTypes`) — but JS/TS has no declared-type
// mechanism at all, so Juliet's own dominant "driver constructs the concrete
// instance and passes it as a parameter to a helper that invokes the virtual
// method" idiom had no JS/TS path: `function wrapper(h, req) { return
// h.getValue(req); }`, called only as `const h = new Helper(); wrapper(h,
// req);`, left `h` permanently untyped inside wrapper's own body, so
// `h.getValue()` could never resolve via CHA. Confirmed via a direct
// reproduction during this session: BOTH a cold scan and a warm
// incremental-cache scan missed the exact same finding identically (ruling
// out a caching-specific cause before attributing this to CHA/type
// inference).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { runScan } from '../src/runScan.js';
import { buildProjectIR } from '../src/ir/index.js';
import { buildClassHierarchy, classOfVar } from '../src/ir/class-hierarchy.js';
import { buildCallGraph } from '../src/ir/callgraph.js';

function mkTmp(name, files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `as-param-type-${name}-`));
  for (const [rel, content] of Object.entries(files)) {
    const fp = path.join(dir, rel);
    fs.mkdirSync(path.dirname(fp), { recursive: true });
    fs.writeFileSync(fp, content);
  }
  return dir;
}

const taintOnly = (findings) => findings.filter((f) => f.parser === 'IR-TAINT');

test('unit: a parameter passed a variable typed via `new Foo()` at the call site is inferred', () => {
  const { perFile } = buildProjectIR({
    'a.js': 'class Helper { getValue(req) { return req; } }\nfunction wrapper(h, req) { return h.getValue(req); }\nfunction top(req) { const h = new Helper(); return wrapper(h, req); }\n',
  });
  const callGraph = buildCallGraph(perFile);
  const cha = buildClassHierarchy(perFile, callGraph);
  const wrapperQid = [...callGraph.functions.keys()].find((q) => q.includes('::wrapper@'));
  assert.ok(wrapperQid, 'sanity: wrapper must be a real function in the built call graph');
  assert.equal(classOfVar(cha, 'a.js', wrapperQid, 'h'), 'Helper',
    "wrapper's own parameter `h` must be inferred as Helper from the call site's argument");
});

test('unit: a literal `new Foo()` passed directly as the argument is also inferred', () => {
  const { perFile } = buildProjectIR({
    'a.js': 'class Helper { getValue(req) { return req; } }\nfunction wrapper(h, req) { return h.getValue(req); }\nfunction top(req) { return wrapper(new Helper(), req); }\n',
  });
  const callGraph = buildCallGraph(perFile);
  const cha = buildClassHierarchy(perFile, callGraph);
  const wrapperQid = [...callGraph.functions.keys()].find((q) => q.includes('::wrapper@'));
  assert.equal(classOfVar(cha, 'a.js', wrapperQid, 'h'), 'Helper');
});

test('unit: two call sites disagreeing on the class for the same parameter refuse to resolve (never guess)', () => {
  const { perFile } = buildProjectIR({
    'a.js': `
class Safe { getValue(req) { return req; } }
class Other { getValue(req) { return req; } }
function wrapper(h, req) { return h.getValue(req); }
function top1(req) { const h = new Safe(); return wrapper(h, req); }
function top2(req) { const h = new Other(); return wrapper(h, req); }
`,
  });
  const callGraph = buildCallGraph(perFile);
  const cha = buildClassHierarchy(perFile, callGraph);
  const wrapperQid = [...callGraph.functions.keys()].find((q) => q.includes('::wrapper@'));
  assert.equal(classOfVar(cha, 'a.js', wrapperQid, 'h'), null,
    'a wrong "confidently resolved" type is worse than staying unknown -- ambiguous call sites must refuse, not pick a side');
});

test('unit: backward compatible -- omitting callGraph entirely skips this pass with no crash', () => {
  const { perFile } = buildProjectIR({
    'a.js': 'class Helper { getValue(req) { return req; } }\nfunction wrapper(h, req) { return h.getValue(req); }\nfunction top(req) { const h = new Helper(); return wrapper(h, req); }\n',
  });
  assert.doesNotThrow(() => buildClassHierarchy(perFile));
  const cha = buildClassHierarchy(perFile);
  // No callGraph means no cross-call-site inference at all. `top`'s OWN
  // local `const h = new Helper()` is still typed by the pre-existing,
  // unrelated assignment-based pass (correct, not this capability's
  // concern) -- the thing that must specifically stay untyped without a
  // callGraph is WRAPPER's own parameter `h`, keyed under wrapper's qid.
  const wrapperKeys = [...cha.typeOfVar.keys()].filter((k) => k.includes('::wrapper@') && k.endsWith('::h'));
  assert.deepEqual(wrapperKeys, [], "without a callGraph, wrapper's own parameter must stay untyped, not fabricated");
});

test('end-to-end: the real cross-file finding this capability closes now fires', async () => {
  const dir = mkTmp('e2e-fire', {
    'src/c.js': 'class Helper {\n  getValue(req) { return req.query.cmd; }\n}\nmodule.exports = { Helper };\n',
    'src/b.js': 'function wrapper(h, req) {\n  return h.getValue(req);\n}\nmodule.exports = { wrapper };\n',
    'src/a.js': `const { exec } = require('child_process');
const { Helper } = require('./c.js');
const { wrapper } = require('./b.js');
module.exports = (req, res) => {
  const h = new Helper();
  exec(wrapper(h, req));
};
`,
  });
  process.env.AGENTIC_SECURITY_DEEP = '1';
  const prevCi = process.env.AGENTIC_SECURITY_DEEP_IN_CI;
  process.env.AGENTIC_SECURITY_DEEP_IN_CI = '1';
  try {
    const { scan } = await runScan(dir);
    const t = taintOnly(scan.findings || []);
    assert.ok(t.some((f) => /Command Injection/i.test(f.vuln)),
      `a parameter-typed receiver (h: Helper, established only via the call site's own argument) must resolve h.getValue(req) via CHA and detect the flow. IR-TAINT findings: ${JSON.stringify(t.map((f) => f.vuln))}`);
  } finally {
    delete process.env.AGENTIC_SECURITY_DEEP;
    if (prevCi === undefined) delete process.env.AGENTIC_SECURITY_DEEP_IN_CI;
    else process.env.AGENTIC_SECURITY_DEEP_IN_CI = prevCi;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('end-to-end precision: two call sites disagreeing on the class refuse to resolve, and never conflate the two classes', async () => {
  const dir = mkTmp('e2e-ambiguous', {
    'src/classes.js': `class Safe {
  getValue(req) { return 'hardcoded-literal'; }
}
class Bad {
  getValue(req) { return req.query.cmd; }
}
module.exports = { Safe, Bad };
`,
    'src/b.js': 'function wrapper(h, req) {\n  return h.getValue(req);\n}\nmodule.exports = { wrapper };\n',
    'src/a.js': `const { exec } = require('child_process');
const { Safe, Bad } = require('./classes.js');
const { wrapper } = require('./b.js');
module.exports = (req, res) => {
  const safe = new Safe();
  exec(wrapper(safe, req));
  const bad = new Bad();
  exec(wrapper(bad, req));
};
`,
  });
  process.env.AGENTIC_SECURITY_DEEP = '1';
  const prevCi = process.env.AGENTIC_SECURITY_DEEP_IN_CI;
  process.env.AGENTIC_SECURITY_DEEP_IN_CI = '1';
  try {
    const { scan } = await runScan(dir);
    const t = taintOnly(scan.findings || []);
    // Ambiguity refusal means CHA-based resolution of `h.getValue(req)`
    // inside wrapper no longer fires for EITHER call site once wrapper is
    // called with two different classes -- this is the documented, accepted
    // cost of "never guess" (matching this file's own established
    // convention elsewhere), not a regression this test is trying to lift.
    // The property genuinely worth guarding is the failure DIRECTION: it
    // must never conflate the two classes and confidently resolve to the
    // WRONG one (e.g. reporting Safe's call site as tainted, or silently
    // treating both calls as identical).
    assert.equal(t.filter((f) => /Command Injection/i.test(f.vuln)).length, 0,
      `ambiguous call sites must refuse CHA resolution entirely, not guess -- IR-TAINT findings: ${JSON.stringify(t.map((f) => f.vuln))}`);
  } finally {
    delete process.env.AGENTIC_SECURITY_DEEP;
    if (prevCi === undefined) delete process.env.AGENTIC_SECURITY_DEEP_IN_CI;
    else process.env.AGENTIC_SECURITY_DEEP_IN_CI = prevCi;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// Next-gen taint capability #4b — the sibling gap this file's own
// `class-hierarchy.js` header comment names and explicitly marks
// unimplemented: "`function buildFoo(): Foo { ... }` typed-return
// inference -- NOT implemented. `const x = buildFoo()` is untyped
// (correctly: it is a plain call, not a `new`)". Confirmed still real via a
// direct reproduction: `function makeHelper() { return new Helper(); }
// const h = makeHelper(); h.getValue(req);` missed the vulnerability
// entirely, the identical failure shape 4a closes for the parameter case.

test('unit: a local assigned from a factory function (return new Foo()) is inferred', () => {
  const { perFile } = buildProjectIR({
    'a.js': 'class Helper { getValue(req) { return req; } }\nfunction makeHelper() { return new Helper(); }\nfunction top(req) { const h = makeHelper(); return h.getValue(req); }\n',
  });
  const callGraph = buildCallGraph(perFile);
  const cha = buildClassHierarchy(perFile, callGraph);
  const topQid = [...callGraph.functions.keys()].find((q) => q.includes('::top@'));
  assert.ok(topQid, 'sanity: top must be a real function in the built call graph');
  assert.equal(classOfVar(cha, 'a.js', topQid, 'h'), 'Helper',
    "top's own local `h` must be inferred as Helper from makeHelper()'s consistent return shape");
});

test('unit: a factory with a non-constructor return on ANY path infers nothing (never guesses)', () => {
  const { perFile } = buildProjectIR({
    'a.js': `
class Helper { getValue(req) { return req; } }
function maybeMakeHelper(flag) {
  if (flag) { return new Helper(); }
  return null;
}
function top(req, flag) { const h = maybeMakeHelper(flag); return h.getValue(req); }
`,
  });
  const callGraph = buildCallGraph(perFile);
  const cha = buildClassHierarchy(perFile, callGraph);
  const topQid = [...callGraph.functions.keys()].find((q) => q.includes('::top@'));
  assert.equal(classOfVar(cha, 'a.js', topQid, 'h'), null,
    'a factory that can also return null (or anything non-constructor) on some path must stay untyped, not confidently guess');
});

test('unit: a factory whose returns disagree on class infers nothing (never guesses)', () => {
  const { perFile } = buildProjectIR({
    'a.js': `
class Safe { getValue(req) { return req; } }
class Other { getValue(req) { return req; } }
function pick(flag) {
  if (flag) { return new Safe(); }
  return new Other();
}
function top(req, flag) { const h = pick(flag); return h.getValue(req); }
`,
  });
  const callGraph = buildCallGraph(perFile);
  const cha = buildClassHierarchy(perFile, callGraph);
  const topQid = [...callGraph.functions.keys()].find((q) => q.includes('::top@'));
  assert.equal(classOfVar(cha, 'a.js', topQid, 'h'), null,
    'disagreeing constructor returns across branches must refuse to resolve, not pick one arbitrarily');
});

test('unit: a real `new Foo()` assignment is unaffected by this pass (no double-processing regression)', () => {
  const { perFile } = buildProjectIR({
    'a.js': 'class Helper { getValue(req) { return req; } }\nfunction top(req) { const h = new Helper(); return h.getValue(req); }\n',
  });
  const callGraph = buildCallGraph(perFile);
  const cha = buildClassHierarchy(perFile, callGraph);
  const topQid = [...callGraph.functions.keys()].find((q) => q.includes('::top@'));
  assert.equal(classOfVar(cha, 'a.js', topQid, 'h'), 'Helper');
});

test('end-to-end: the real cross-file finding this sub-capability closes now fires', async () => {
  const dir = mkTmp('e2e-4b-fire', {
    'src/app.js': `const { exec } = require('child_process');
class Helper {
  getValue(req) { return req.query.cmd; }
}
function makeHelper() {
  return new Helper();
}
module.exports = (req, res) => {
  const h = makeHelper();
  exec(h.getValue(req));
};
`,
  });
  process.env.AGENTIC_SECURITY_DEEP = '1';
  const prevCi = process.env.AGENTIC_SECURITY_DEEP_IN_CI;
  process.env.AGENTIC_SECURITY_DEEP_IN_CI = '1';
  try {
    const { scan } = await runScan(dir);
    const t = taintOnly(scan.findings || []);
    assert.ok(t.some((f) => /Command Injection/i.test(f.vuln)),
      `a local typed only via a factory function's consistent return shape must resolve h.getValue(req) via CHA. IR-TAINT findings: ${JSON.stringify(t.map((f) => f.vuln))}`);
  } finally {
    delete process.env.AGENTIC_SECURITY_DEEP;
    if (prevCi === undefined) delete process.env.AGENTIC_SECURITY_DEEP_IN_CI;
    else process.env.AGENTIC_SECURITY_DEEP_IN_CI = prevCi;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('end-to-end precision: a PascalCase factory that does NOT return new X() must not be mistyped (regression guard)', async () => {
  const dir = mkTmp('e2e-4b-precision', {
    'src/app.js': `const express = require('express');
const app = express();
function BuildCache() { return require('mysql').createConnection({}); }
app.get('/search', (req, res) => {
  const q = BuildCache();
  q.query(req.query.q);
  res.send('ok');
});
`,
  });
  process.env.AGENTIC_SECURITY_DEEP = '1';
  const prevCi = process.env.AGENTIC_SECURITY_DEEP_IN_CI;
  process.env.AGENTIC_SECURITY_DEEP_IN_CI = '1';
  try {
    const { scan } = await runScan(dir);
    const sqlFindings = (scan.findings || []).filter((f) => /sql/i.test(f.vuln || ''));
    assert.ok(sqlFindings.some((f) => f.parser === 'IR-TAINT'),
      'a factory returning a non-constructor value (a real DB connection factory) must never be mistyped as a class -- the real SQLi must still fire, unsuppressed');
  } finally {
    delete process.env.AGENTIC_SECURITY_DEEP;
    if (prevCi === undefined) delete process.env.AGENTIC_SECURITY_DEEP_IN_CI;
    else process.env.AGENTIC_SECURITY_DEEP_IN_CI = prevCi;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
