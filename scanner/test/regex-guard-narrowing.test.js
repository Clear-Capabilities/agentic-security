// Next-gen taint capability #2 — regex-validation guard narrowing (JS/TS).
//
// `GUARD_PREDICATES`/`_guardNarrowsVar` (SARD_80_F1 W3.2) already narrows
// taint on the TRUE branch of a named predicate (`is_numeric`, `TryParse`,
// …), but its own header comment names a regex-based guard
// (`preg_match('/^\d+$/', $x)`) as an explicit, deliberately unimplemented
// follow-up: "the PATTERN itself" needs validating as fully-anchored and
// metacharacter-free, "not attempted here". `isSafeValidationPattern`
// (string-domain.js) is that pattern validator; `_regexTestGuardNarrowsVar`
// (engine.js) wires it into the same TRUE-branch-only narrowing mechanism
// for JS/TS's own idiom, `<regex-literal>.test(x)`.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { runScan } from '../src/runScan.js';
import { mkTestTmp } from './helpers/tmp.js';

async function scanSource(name, body) {
  const dir = mkTestTmp('as-regex-guard-');
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

test('a safe anchored regex guard narrows taint and suppresses the finding', async () => {
  const findings = await scanSource('safe.js', `const { exec } = require('child_process');
module.exports = (req, res) => {
  const id = req.query.id;
  if (/^[a-zA-Z0-9]+$/.test(id)) {
    exec('lookup ' + id);
  }
};`);
  const t = taintOnly(findings);
  assert.ok(!t.some((f) => /Command Injection/i.test(f.vuln)),
    `a fully-anchored alphanumeric-only guard proves \`id\` is metacharacter-free on the true branch. IR-TAINT findings: ${JSON.stringify(t.map((f) => f.vuln))}`);
});

test('the wildcard-everything pattern does NOT narrow — finding still fires', async () => {
  const findings = await scanSource('wildcard.js', `const { exec } = require('child_process');
module.exports = (req, res) => {
  const id = req.query.id;
  if (/^.*$/.test(id)) {
    exec('lookup ' + id);
  }
};`);
  const t = taintOnly(findings);
  assert.ok(t.some((f) => /Command Injection/i.test(f.vuln)),
    `/^.*$/ matches everything and must not be treated as a safety proof. IR-TAINT findings: ${JSON.stringify(t.map((f) => f.vuln))}`);
});

test('a negated shorthand class guard (\\D) does NOT narrow — finding still fires', async () => {
  const findings = await scanSource('negated.js', `const { exec } = require('child_process');
module.exports = (req, res) => {
  const id = req.query.id;
  if (/^\\D+$/.test(id)) {
    exec('lookup ' + id);
  }
};`);
  const t = taintOnly(findings);
  assert.ok(t.some((f) => /Command Injection/i.test(f.vuln)),
    `\\D (negated digit) permits almost anything and must not narrow. IR-TAINT findings: ${JSON.stringify(t.map((f) => f.vuln))}`);
});

test('a safe guard on the FALSE branch (no else) does not suppress the sink after the if', async () => {
  const findings = await scanSource('falsebranch.js', `const { exec } = require('child_process');
module.exports = (req, res) => {
  const id = req.query.id;
  if (/^[a-zA-Z0-9]+$/.test(id)) {
    // no-op: the guard only proves safety on ITS OWN true branch
  }
  exec('lookup ' + id);
};`);
  const t = taintOnly(findings);
  assert.ok(t.some((f) => /Command Injection/i.test(f.vuln)),
    `code after the if (or on a false branch) must keep seeing the original tainted state. IR-TAINT findings: ${JSON.stringify(t.map((f) => f.vuln))}`);
});

test('a non-regex condition is unaffected by this guard (ordinary if still analyzed normally)', async () => {
  const findings = await scanSource('plain.js', `const { exec } = require('child_process');
module.exports = (req, res) => {
  const id = req.query.id;
  if (req.query.flag) {
    exec('lookup ' + id);
  }
};`);
  const t = taintOnly(findings);
  assert.ok(t.some((f) => /Command Injection/i.test(f.vuln)),
    `an unrelated condition must not be mistaken for a validation guard. IR-TAINT findings: ${JSON.stringify(t.map((f) => f.vuln))}`);
});
