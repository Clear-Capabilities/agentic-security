// Next-gen taint capability #3 — object-instance field taint via method
// calls (JS/TS).
//
// `classTaintedFields` (dataflow/engine.js) already tracks class-wide
// static-field taint (W5.47-51), but that mechanism is a deliberate, CLASS-
// WIDE over-approximation: the moment ANY method of a class taints a field,
// every reader of that field on ANY instance is seeded as tainted. That is
// correct for a genuinely shared static field, but was ALSO the only
// mechanism available for an ordinary INSTANCE field reached via a mutator
// method call on a local receiver (`bad.setData(tainted)`) — and that shape
// wasn't modeled at all: `_mutatedParamsOut` (v0.66) only ever tracks a
// callee's DECLARED parameters, never the implicit `this` receiver, so
// `this.data = v` inside `setData` was invisible to `bad.setData(x)`'s own
// caller. Fixed by treating `this` as an implicit mutable parameter
// (mirroring `_mutatedParamsOut` for the receiver) plus a narrow, structural
// single-field-getter recognizer for the read side. Because the effect
// lands on the RECEIVER'S OWN access path (`bad.data`), two different local
// variables holding instances of the SAME class stay genuinely distinct —
// real object-instance sensitivity, without a full allocation-site-keyed
// heap model.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { runScan } from '../src/runScan.js';
import { mkTestTmp } from './helpers/tmp.js';

async function scanSource(name, body) {
  const dir = mkTestTmp('as-objsens-');
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

test('a setter call taints the field on ITS OWN receiver, seen through a getter call', async () => {
  const findings = await scanSource('single.js', `const { exec } = require('child_process');
class Holder {
  setData(v) { this.data = v; }
  getData() { return this.data; }
}
module.exports = (req, res) => {
  const bad = new Holder();
  bad.setData(req.query.cmd);
  exec(bad.getData());
};`);
  const t = taintOnly(findings);
  assert.ok(t.some((f) => /Command Injection/i.test(f.vuln)),
    `bad.setData(tainted) must taint bad's own data field, visible through bad.getData(). IR-TAINT findings: ${JSON.stringify(t.map((f) => f.vuln))}`);
});

test('a DIFFERENT instance of the same class is NOT tainted — real object-instance sensitivity', async () => {
  const findings = await scanSource('two-instances.js', `const { exec } = require('child_process');
class Holder {
  setData(v) { this.data = v; }
  getData() { return this.data; }
}
module.exports = (req, res) => {
  const bad = new Holder();
  bad.setData(req.query.cmd);
  bad.getData();

  const safe = new Holder();
  safe.setData('literal-only');
  exec(safe.getData());
};`);
  const t = taintOnly(findings);
  assert.ok(!t.some((f) => /Command Injection/i.test(f.vuln)),
    `safe's own data field was only ever set to a literal -- tainting bad must not leak onto a DIFFERENT instance. IR-TAINT findings: ${JSON.stringify(t.map((f) => f.vuln))}`);
});

test('a direct field read (no getter) also sees the receiver-specific taint', async () => {
  const findings = await scanSource('direct-read.js', `const { exec } = require('child_process');
class Holder {
  setData(v) { this.data = v; }
}
module.exports = (req, res) => {
  const bad = new Holder();
  bad.setData(req.query.cmd);
  exec(bad.data);
};`);
  const t = taintOnly(findings);
  assert.ok(t.some((f) => /Command Injection/i.test(f.vuln)),
    `bad.data itself must be tainted after bad.setData(tainted), independent of any getter. IR-TAINT findings: ${JSON.stringify(t.map((f) => f.vuln))}`);
});

test('a setter call with a clean (literal) argument does not taint the receiver', async () => {
  const findings = await scanSource('clean-setter.js', `const { exec } = require('child_process');
class Holder {
  setData(v) { this.data = v; }
  getData() { return this.data; }
}
module.exports = (req, res) => {
  const safe = new Holder();
  safe.setData('literal-only');
  exec(safe.getData());
};`);
  const t = taintOnly(findings);
  assert.ok(!t.some((f) => /Command Injection/i.test(f.vuln)),
    `setData called with a literal must not taint the receiver. IR-TAINT findings: ${JSON.stringify(t.map((f) => f.vuln))}`);
});

test('a multi-field getter (returns different this.<field> on different paths) is NOT treated as a single-field getter', async () => {
  const findings = await scanSource('ambiguous-getter.js', `const { exec } = require('child_process');
class Holder {
  setData(v) { this.data = v; }
  get(flag) { if (flag) { return this.data; } return this.other; }
}
module.exports = (req, res) => {
  const bad = new Holder();
  bad.setData(req.query.cmd);
  bad.other = 'literal';
  exec(bad.get(false));
};`);
  const t = taintOnly(findings);
  assert.ok(!t.some((f) => /Command Injection/i.test(f.vuln)),
    `an ambiguous multi-field getter must bail out (return null) rather than guess the wrong field. IR-TAINT findings: ${JSON.stringify(t.map((f) => f.vuln))}`);
});
