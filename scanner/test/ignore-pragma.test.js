// The inline suppression pragma — `// agentic-security-ignore: <rule-id>`.
//
// This was documented in the root CLAUDE.md and advertised to reviewers by
// `pr-comment.js` ("Fix or suppress with …") while NOTHING implemented it. A
// dead suppression mechanism is worse than an absent one: the developer writes
// the pragma, sees the finding again, and concludes the scanner is noisy.
//
// Every test here carries a positive control — the same file without the
// pragma must still produce the finding. Otherwise "0 findings" proves the
// suppression works and equally proves the detector stopped firing.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { runScan } from '../src/runScan.js';
import { normalizeFindings } from '../src/report/index.js';

const VULN_LINE = "  exec('ping ' + req.query.host, (e, o) => res.send(o));";

const file = (suffix = '') => [
  "const { exec } = require('child_process');",
  'module.exports = function h(req, res) {',
  VULN_LINE + suffix,
  '};',
].join('\n');

async function scanOne(name, content) {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'pragma-')));
  try {
    fs.writeFileSync(path.join(dir, name), content);
    const { scan } = await runScan(dir);
    return { findings: normalizeFindings(scan), suppressions: scan.suppressions || [] };
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

test('an inline pragma suppresses the finding on that line', async () => {
  const control = await scanOne('a.js', file());
  assert.ok(control.findings.length > 0, 'positive control: the detector must fire without the pragma');

  const r = await scanOne('a.js', file(' // agentic-security-ignore: command-injection'));
  assert.equal(r.findings.length, 0);
});

test('the suppression is LOGGED, not silent', async () => {
  // A suppression nobody can see is indistinguishable from a finding that
  // never fired, and `--include-suppressed` would show nothing.
  const r = await scanOne('a.js', file(' // agentic-security-ignore: command-injection'));
  const logged = r.suppressions.filter((s) => /pragma/.test(s.reason || ''));
  assert.equal(logged.length, 1);
  assert.equal(logged[0].line, 3);
  assert.match(logged[0].reason, /command-injection/);
});

test('a bare pragma suppresses any rule on that line', async () => {
  const r = await scanOne('a.js', file(' // agentic-security-ignore'));
  assert.equal(r.findings.length, 0);
});

test('a pragma naming a DIFFERENT rule does not suppress', async () => {
  // The one that keeps the mechanism honest: a line-scoped opt-out must not
  // become a line-scoped blanket by accident.
  const r = await scanOne('a.js', file(' // agentic-security-ignore: sql-injection'));
  assert.ok(r.findings.length > 0, 'an unrelated rule id must leave the finding in place');
});

test('a pragma on a NEIGHBOURING line does not suppress', async () => {
  const content = [
    "const { exec } = require('child_process');",
    '// agentic-security-ignore: command-injection',
    'module.exports = function h(req, res) {',
    VULN_LINE,
    '};',
  ].join('\n');
  const r = await scanOne('a.js', content);
  assert.ok(r.findings.length > 0, 'the pragma is line-scoped; a file-wide opt-out is how a module leaves coverage');
});

test('the CWE is an acceptable rule id too', async () => {
  const r = await scanOne('a.js', file(' // agentic-security-ignore: CWE-78'));
  assert.equal(r.findings.length, 0);
});

test('a `#` comment works for languages that use it', async () => {
  const py = [
    'import os',
    'def h(host):',
    '    os.system("ping " + host)  # agentic-security-ignore: command-injection',
  ].join('\n');
  const control = await scanOne('a.py', py.replace(/\s*# agentic-security-ignore.*/, ''));
  assert.ok(control.findings.length > 0, 'positive control: the Python detector must fire');
  const r = await scanOne('a.py', py);
  assert.equal(r.findings.length, 0);
});

// --- deep mode -------------------------------------------------------------
//
// The pragma pass ran ONCE, after the cross-file passes — but deep-mode IR
// findings are appended hundreds of lines later, so no `ir-taint` finding was
// ever suppressed. Deep mode is what the CLI uses outside CI, and taint
// findings are the ones users most want to silence, so the documented feature
// did nothing in the case that mattered most. Nothing in this file exercised
// deep mode, so the suite could not catch it. A second pass now runs after the
// deep append; these tests pin it.
//
// The bug was one of ORDERING, so a direct unit test of the matcher would have
// passed even before the fix. Both tests below drive the real engine end to end.

async function scanDeep(name, content) {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'pragma-deep-')));
  const prevDeep = process.env.AGENTIC_SECURITY_DEEP;
  const prevCi = process.env.AGENTIC_SECURITY_DEEP_IN_CI;
  process.env.AGENTIC_SECURITY_DEEP = '1';
  process.env.AGENTIC_SECURITY_DEEP_IN_CI = '1';
  try {
    fs.writeFileSync(path.join(dir, name), content);
    const { scan } = await runScan(dir);
    return normalizeFindings(scan);
  } finally {
    if (prevDeep === undefined) delete process.env.AGENTIC_SECURITY_DEEP;
    else process.env.AGENTIC_SECURITY_DEEP = prevDeep;
    if (prevCi === undefined) delete process.env.AGENTIC_SECURITY_DEEP_IN_CI;
    else process.env.AGENTIC_SECURITY_DEEP_IN_CI = prevCi;
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

// A flow the IR taint engine reports and the pattern detectors do not, so the
// finding under test provably comes from the deep pass. Verified by hand: this
// yields exactly `ir-taint:d.js:2:js-fetch` (CWE-918) with `parser: 'IR-TAINT'`.
// An earlier attempt at this fixture used a command-injection shape and
// produced only REGEX findings, which would have made the test pass for the
// wrong reason — hence the explicit parser assertion below.
const deepFile = (suffix = '') => [
  'export async function call(prompt) {',
  `  const res = await fetch(process.env.MY_ENDPOINT, { method: 'POST', body: prompt });${suffix}`,
  '  return res.json();',
  '}',
].join('\n');

const isTaint = f => f.parser === 'IR-TAINT' || /^ir-taint/.test(f.id || '');

test('deep mode: an ir-taint finding IS suppressed by a pragma on its line', async () => {
  const control = await scanDeep('d.js', deepFile());
  assert.ok(control.some(isTaint),
    'positive control: deep mode must produce an IR-TAINT finding without the pragma');

  const suppressed = await scanDeep('d.js', deepFile(' // agentic-security-ignore: CWE-918'));
  assert.equal(suppressed.filter(isTaint).length, 0,
    'the pragma must suppress the deep-mode IR finding — this is the regression: ' +
    'the pragma pass ran once, before deep findings were appended, so it was inert');
});

test('deep mode: a pragma naming a DIFFERENT rule does not suppress the finding', async () => {
  // The other direction. Without this, a fix that simply deleted all deep
  // findings would pass the test above.
  const findings = await scanDeep('d.js', deepFile(' // agentic-security-ignore: sql-injection'));
  assert.ok(findings.some(isTaint),
    'a pragma for an unrelated rule must leave the IR finding in place');
});

// NOT TESTED, deliberately, and recorded here so the gap is visible rather than
// forgotten: a finding with no integer `line` can never be suppressed, because
// a line-scoped pragma has nothing to match. `struct:` detectors emit exactly
// such findings (the line survives only inside the id string). The limitation is
// documented at `_applyIgnorePragmas` in engine.js along with the reason a
// file-scoped fallback was rejected.
//
// It is untested because a struct finding could not be reproduced from a
// standalone temp-directory fixture — that detector needs whole-project context,
// and the two attempts made here produced no findings at all, which would have
// been a test that passed while proving nothing. Pinning it needs a fixture
// built the way the bench harnesses build theirs; that belongs with the larger
// change that gives struct findings a `line` in the first place.
