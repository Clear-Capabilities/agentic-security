// PRD T3.3 — container / collection-element taint.
//
// `docs/WORLD_CLASS_DETECTION_PRD.md` §Theme 3 lists this as "Not started", and
// `access-paths.js`'s own header has carried the note "Index sensitivity is a
// follow-on (P3 work)" since it was written.
//
// Measured first rather than assumed. A probe over ten container shapes found
// the JS ARRAY cases already work — `push`/index-write/`concat`/`join` all
// propagate (the R4 array-element rule in `dataflow/engine.js`), and
// `arr.map(cb)` propagates through the higher-order path. Three gaps were real:
//
//   1. A computed WRITE with a non-literal key. `parser-js.js` lowers
//      `bag[k] = v` to prop `'*'`, so taint lands at access path `bag.*` —
//      which does NOT cover a later read of `bag.anything`, because the
//      lattice only propagates DOWN from a prefix, never up. An unknown key
//      could be any key, so the container itself is what must be tainted.
//   2. Keyed collections. `Map.set` / `Set.add` are mutating writes exactly
//      like `Array.push`, but were not in the mutator list.
//   3. Non-JS containers. The mutator rule required `callee.kind === 'member'`,
//      a shape only `parser-js.js` (Babel) produces. The seven hand-rolled
//      parsers emit a flat dot-joined STRING callee, so Python's
//      `items.append(tainted)` never matched — the same frontend duality
//      `_calleeReceiverTainted` already documents and handles.
//
// Each test asserts `parser === 'IR-TAINT'` specifically. A pattern detector
// firing on the same line would otherwise mask a taint-layer miss — which is
// exactly what the probe found for Python, where PY-SAST caught the sink and
// the taint engine saw nothing.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { runScan } from '../src/runScan.js';

async function scanSource(name, body) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-container-taint-'));
  fs.mkdirSync(path.join(dir, 'src'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'src', name), body);
  process.env.AGENTIC_SECURITY_DEEP = '1';
  const prevCi = process.env.AGENTIC_SECURITY_DEEP_IN_CI;
  process.env.AGENTIC_SECURITY_DEEP_IN_CI = '1';
  try {
    const { scan } = await runScan(dir);
    return scan.findings || [];
  } finally {
    delete process.env.AGENTIC_SECURITY_DEEP;
    if (prevCi === undefined) delete process.env.AGENTIC_SECURITY_DEEP_IN_CI;
    else process.env.AGENTIC_SECURITY_DEEP_IN_CI = prevCi;
  }
}

const taintOnly = (findings) => findings.filter((f) => f.parser === 'IR-TAINT');

test('a computed write with an unknown key taints the container itself', async () => {
  const findings = await scanSource('bag.js', `const { exec } = require('child_process');
module.exports = (req, res) => {
  const bag = {};
  bag[req.query.key] = req.query.cmd;
  exec(bag.anything);
};`);
  const t = taintOnly(findings);
  assert.ok(t.some((f) => /Command Injection/i.test(f.vuln)),
    `bag[<unknown>] = tainted must taint \`bag\`, since the key could be any key. IR-TAINT findings: ${JSON.stringify(t.map((f) => f.vuln))}`);
});

test('Map.set with a tainted value taints the map', async () => {
  const findings = await scanSource('map.js', `const { exec } = require('child_process');
module.exports = (req, res) => {
  const m = new Map();
  m.set('k', req.query.cmd);
  exec(m.get('k'));
};`);
  const t = taintOnly(findings);
  assert.ok(t.some((f) => /Command Injection/i.test(f.vuln)),
    `Map.set is a mutating write exactly like Array.push. IR-TAINT findings: ${JSON.stringify(t.map((f) => f.vuln))}`);
});

test('Set.add with a tainted value taints the set', async () => {
  const findings = await scanSource('set.js', `const { exec } = require('child_process');
module.exports = (req, res) => {
  const s = new Set();
  s.add(req.query.cmd);
  exec(Array.from(s).join(' '));
};`);
  const t = taintOnly(findings);
  assert.ok(t.some((f) => /Command Injection/i.test(f.vuln)),
    `Set.add must taint the set. IR-TAINT findings: ${JSON.stringify(t.map((f) => f.vuln))}`);
});

test('python list.append propagates taint through the container (flat-string callee)', async () => {
  const findings = await scanSource('app.py', `import os
from flask import request

def handler():
    items = []
    items.append(request.args['cmd'])
    os.system(items[0])`);
  const t = taintOnly(findings);
  assert.ok(t.some((f) => /Command Injection/i.test(f.vuln)),
    `python's parser emits a flat dot-joined callee ("items.append"), which the member-shaped mutator check never matched. IR-TAINT findings: ${JSON.stringify(t.map((f) => f.vuln))}`);
});

test('python dict subscript assignment propagates taint through the container', async () => {
  // `parser-py.js` lowers `bag["k"] = v` to a CALL node with the flat callee
  // `bag.__setitem__`, not to an assign node with a member target — so this is
  // the same mutator path as `list.append`, keyed on a dunder rather than a
  // method name. The matching read `bag["k"]` lowers to access path `bag.[]`,
  // which the tainted receiver prefix already covers.
  const findings = await scanSource('bag.py', `import os
from flask import request

def handler():
    bag = {}
    bag['k'] = request.args['cmd']
    os.system(bag['k'])`);
  const t = taintOnly(findings);
  assert.ok(t.some((f) => /Command Injection/i.test(f.vuln)),
    `dict subscript writes lower to __setitem__ and must taint the dict. IR-TAINT findings: ${JSON.stringify(t.map((f) => f.vuln))}`);
});

// ── precision: widening the mutator rule must not make every container tainted
test('a clean value written into a container does not taint it', async () => {
  const findings = await scanSource('clean.js', `const { exec } = require('child_process');
module.exports = (req, res) => {
  const bag = {};
  const m = new Map();
  bag['fixed'] = 'literal-value';
  m.set('k', 'another-literal');
  exec(bag.fixed);
  exec(m.get('k'));
};`);
  const t = taintOnly(findings);
  assert.deepEqual(t.map((f) => f.vuln), [],
    `nothing here is attacker-controlled; a container written with literals must stay clean`);
});

test('a tainted KEY with a clean value does not taint the container contents', async () => {
  // Only the value written matters for the contents. Tainting the container on
  // a tainted KEY would report the wrong thing — the values are all literals.
  const findings = await scanSource('key.js', `const { exec } = require('child_process');
module.exports = (req, res) => {
  const bag = {};
  bag[req.query.key] = 'safe-literal';
  exec(bag.anything);
};`);
  const t = taintOnly(findings);
  assert.deepEqual(t.map((f) => f.vuln), [],
    `the VALUE written is a literal; a tainted key alone must not make the contents tainted`);
});

// ── PRD F2.2 — the last open shape, and what it actually was ───────────────
//
// The PRD recorded Python COMPREHENSIONS as the remaining gap, citing
// `[x for x in request.args.getlist(...)]`. Comprehensions already flowed: the
// IR lowers them as a loop-var assignment plus an array of the element, and the
// same shape over `request.args.get()` tracks end to end.
//
// The example failed on its SOURCE. `getlist` — the standard Flask/Werkzeug and
// Django QueryDict accessor for a repeated parameter — was not in the catalog
// at all, so every repeated-parameter flow was invisible. Modelling
// comprehensions would have changed nothing while looking like a fix.
import { CATALOG as _CATALOG } from '../src/dataflow/catalog.js';

test('F2.2: the multi-value request accessors are sources', () => {
  const ids = _CATALOG.filter((e) => e.kind === 'source').map((e) => e.id);
  assert.ok(ids.includes('py-flask-args-getlist'),
    'request.args.getlist() is the standard repeated-parameter API and was unmodelled');
  assert.ok(ids.includes('py-flask-args-getall'), 'multidict getall() likewise');
});

test('F2.2: a comprehension over a multi-value source reaches a sink via TAINT', async () => {
  // Asserts parser === IR-TAINT specifically. A pattern rule already matched
  // this shape, which is exactly how the gap stayed hidden — the finding
  // appeared, so nothing looked broken.
  const fsx = await import('node:fs');
  const osx = await import('node:os');
  const pathx = await import('node:path');

  const prevDeep = process.env.AGENTIC_SECURITY_DEEP;
  const prevCi = process.env.AGENTIC_SECURITY_DEEP_IN_CI;
  process.env.AGENTIC_SECURITY_DEEP = '1';
  process.env.AGENTIC_SECURITY_DEEP_IN_CI = '1';

  const d = fsx.mkdtempSync(pathx.join(osx.tmpdir(), 'f22-'));
  try {
    fsx.writeFileSync(pathx.join(d, 'app.py'), [
      'import subprocess',
      'from flask import request, Flask',
      'app = Flask(__name__)',
      "@app.route('/r')",
      'def r():',
      "    hosts = [h for h in request.args.getlist('host')]",
      "    subprocess.run('ping ' + hosts[0], shell=True)",
      "    return 'ok'",
    ].join('\n'));
    const { runScan } = await import('../src/runScan.js');
    const { scan } = await runScan(d);
    const cmdi = (scan.findings || []).filter((f) => String(f.cwe) === 'CWE-78');
    assert.ok(cmdi.some((f) => f.parser === 'IR-TAINT'),
      'the flow must be found by the TAINT engine, not only by a pattern rule');
  } finally {
    fsx.rmSync(d, { recursive: true, force: true });
    if (prevDeep === undefined) delete process.env.AGENTIC_SECURITY_DEEP; else process.env.AGENTIC_SECURITY_DEEP = prevDeep;
    if (prevCi === undefined) delete process.env.AGENTIC_SECURITY_DEEP_IN_CI; else process.env.AGENTIC_SECURITY_DEEP_IN_CI = prevCi;
  }
});
