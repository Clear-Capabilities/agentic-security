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
