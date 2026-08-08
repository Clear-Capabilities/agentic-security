// Coverage reduction must be visible where the RESULTS are.
//
// `disable:` in rules.yml removes findings from the report. A removed finding
// is indistinguishable from clean code unless the removal is stated — and the
// only statement used to be a stderr line, which nobody keeps alongside a JSON
// artifact. That is what made a forged signature so damaging: it produced a
// clean-looking report with no trace in the report itself.
//
// An AUTHORISED suppression is reported too. A signature proves who asked for
// the suppression; it does not make the hidden findings stop existing.
import test from 'node:test';
import assert from 'node:assert/strict';

import {
  applyOverrides, suppressionReport, renderSuppressionSummary, _resetSuppressionsForTests,
} from '../src/posture/rule-overrides.js';

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { signLastScan } from '../src/posture/integrity.js';

function project(rules, { sign = true } = {}) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'supp-'));
  fs.writeFileSync(path.join(d, 'package.json'), '{"name":"t","version":"1.0.0"}');
  const sd = path.join(d, '.agentic-security');
  fs.mkdirSync(sd, { recursive: true });
  fs.writeFileSync(path.join(sd, 'rules.yml'), rules);
  if (sign) fs.writeFileSync(path.join(sd, 'rules.yml.sig'), signLastScan(rules));
  return d;
}

const findings = () => ([
  { id: 'a', vuln: 'Command Injection', severity: 'critical', file: 'app.js', line: 2 },
  { id: 'b', vuln: 'Command Injection', severity: 'high', file: 'other.js', line: 9 },
  { id: 'c', vuln: 'Weak Hash', severity: 'low', file: 'h.js', line: 1 },
]);

test('an authorised suppression is recorded, not silently applied', () => {
  _resetSuppressionsForTests();
  const d = project('disable:\n  - Command Injection\n');
  try {
    const kept = applyOverrides(findings(), d);
    assert.equal(kept.length, 1, 'the disable must still take effect');

    const rep = suppressionReport(d);
    assert.ok(rep, 'an effective disable must produce a suppression report');
    assert.equal(rep.total, 2);
    assert.equal(rep.authority, 'signed');
    assert.equal(rep.rules[0].rule, 'Command Injection');
    assert.equal(rep.rules[0].count, 2);
    assert.deepEqual(rep.rules[0].severities, { critical: 1, high: 1 });
    assert.ok(rep.rules[0].examples.includes('app.js:2'), 'the report must say WHAT was removed');
    assert.match(rep.note, /not absent because the code is clean/);
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});

test('the summary says these are removed results, not clean code', () => {
  _resetSuppressionsForTests();
  const d = project('disable:\n  - Command Injection\n');
  try {
    applyOverrides(findings(), d);
    const line = renderSuppressionSummary(suppressionReport(d));
    assert.match(line, /2 finding\(s\) SUPPRESSED/);
    assert.match(line, /authority: signed/);
    assert.match(line, /removed results, not clean code/);
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});

test('no suppression means no report — not an empty one', () => {
  _resetSuppressionsForTests();
  const d = project('disable:\n  - Nothing That Matches\n');
  try {
    const kept = applyOverrides(findings(), d);
    assert.equal(kept.length, 3);
    assert.equal(suppressionReport(d), null);
    assert.equal(renderSuppressionSummary(null), null);
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});

test('an UNSIGNED disable suppresses nothing, and reports nothing', () => {
  // The gate refuses it, so there is no coverage reduction to report.
  _resetSuppressionsForTests();
  const d = project('disable:\n  - Command Injection\n', { sign: false });
  const saved = process.env.AGENTIC_SECURITY_RULES_UNSIGNED;
  try {
    delete process.env.AGENTIC_SECURITY_RULES_UNSIGNED;
    const kept = applyOverrides(findings(), d);
    assert.equal(kept.length, 3, 'an unsigned disable must not take effect');
    assert.equal(suppressionReport(d), null);
  } finally {
    if (saved !== undefined) process.env.AGENTIC_SECURITY_RULES_UNSIGNED = saved;
    fs.rmSync(d, { recursive: true, force: true });
  }
});

test('an env-var opt-out is reported with that authority, not as "signed"', () => {
  // AGENTIC_SECURITY_RULES_UNSIGNED=1 is a developer escape hatch. When it is
  // what authorised a suppression, the artifact must say so — that is a
  // materially weaker claim than a signature.
  _resetSuppressionsForTests();
  const d = project('disable:\n  - Command Injection\n', { sign: false });
  const saved = process.env.AGENTIC_SECURITY_RULES_UNSIGNED;
  try {
    process.env.AGENTIC_SECURITY_RULES_UNSIGNED = '1';
    applyOverrides(findings(), d);
    const rep = suppressionReport(d);
    assert.ok(rep);
    assert.equal(rep.authority, 'unsigned-opt-in');
    assert.match(renderSuppressionSummary(rep), /authority: unsigned-opt-in/);
  } finally {
    if (saved === undefined) delete process.env.AGENTIC_SECURITY_RULES_UNSIGNED;
    else process.env.AGENTIC_SECURITY_RULES_UNSIGNED = saved;
    fs.rmSync(d, { recursive: true, force: true });
  }
});
