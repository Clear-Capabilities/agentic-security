// PRD F12.1 — the local gate must not disagree with hosted CI.
//
// WHAT HAPPENED. On 2026-08-19 eight assertions in `py-annotation-sources.test.js`
// passed locally, passed the pre-push gate, and failed in hosted CI. Nothing was
// wrong with the detection logic. The engine auto-disables deep mode under CI
// unless a SECOND opt-in is set:
//
//     _deepEnabled = _deepRequested && (!_inCi || _deepInCiAllowed)
//
// and when it skips, it emits an informational finding that is itself tagged
// `parser: 'IR-TAINT'` — "deep mode skipped in CI environment". Every assertion
// in that file filtered on exactly that parser, so the notice was counted AS a
// taint finding: negative controls expecting `[]` received one element, and the
// positive case's `f[0].vuln` was the notice text rather than the injection.
//
// Neither the local gate nor the pre-push hook sets CI=1, so nothing local could
// see it. That is the gap this file closes, statically and cheaply.
//
// WHY A STATIC INVARIANT RATHER THAN ONLY RUNNING THE SUITE TWICE. Running the
// whole suite a second time under CI env costs roughly as much as the entire
// rest of the gate. The empirical half of F12.1 is `npm run test:ci-parity`,
// which runs only the env-sensitive subset (measured: 102 tests, 35 s) and IS
// wired into the pre-push gate. This file is the other half: it makes the rule
// itself checkable, so a NEW test file that forgets the opt-in fails here
// immediately rather than in someone else's CI run.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));

// A file needs the opt-in when it BOTH turns deep mode on via the env var AND
// actually runs a scan. Two shapes are deliberately exempt and both are
// verified below rather than hardcoded as names:
//   - a file that only mentions the variable as data (an env-fingerprint test)
//   - a file that enables deep through the `{deep:true}` OPTION, which does not
//     go through the env gate at all
const ASSIGNS_DEEP = /process\.env\.AGENTIC_SECURITY_DEEP\s*=\s*['"]1['"]/;
const CALLS_SCAN = /\brunScan\s*\(/;
// Must be an ASSIGNMENT of '1', not a mention. The first draft of this rule
// searched for the bare identifier and was proven useless by its own red check:
// deleting the two lines that SET the opt-in left the `finally` block's restore
// lines behind, the identifier was still present, and the rule reported no
// offender while the file was in exactly the broken state it exists to catch.
const HAS_OPT_IN = /process\.env\.AGENTIC_SECURITY_DEEP_IN_CI\s*=\s*['"]1['"]/;
// A file whose SUBJECT is the skip path itself must be able to omit the opt-in.
// That exemption is a marker in the source carrying a reason, not a name list
// in this file: a hardcoded list rots silently the moment a file is renamed,
// and it hides WHY each entry is there. This file is currently the only user.
const EXEMPT = /ci-parity-exempt:\s*\S/;

function testFiles() {
  return fs.readdirSync(TEST_DIR)
    .filter((f) => f.endsWith('.test.js'))
    .map((f) => ({ name: f, src: fs.readFileSync(path.join(TEST_DIR, f), 'utf8') }));
}

test('every test that enables deep mode via env AND scans also opts into deep-in-CI', () => {
  const offenders = testFiles()
    .filter(({ src }) => ASSIGNS_DEEP.test(src) && CALLS_SCAN.test(src))
    .filter(({ src }) => !HAS_OPT_IN.test(src) && !EXEMPT.test(src))
    .map(({ name }) => name);

  assert.deepEqual(offenders, [],
    'These files set AGENTIC_SECURITY_DEEP=1 and run a scan, but never set '
    + 'AGENTIC_SECURITY_DEEP_IN_CI=1. Under CI the engine silently disables deep '
    + 'mode and emits a notice finding tagged parser:"IR-TAINT", which any '
    + 'IR-TAINT filter will count as a real finding. Add the opt-in (and restore '
    + `the previous value in the finally block):\n  ${offenders.join('\n  ')}`);
});

// Guards the guard. If the engine ever stops emitting the CI-skip notice under
// this parser, the invariant above is still worth keeping, but the REASON in its
// message would be wrong — and a stale reason is how a control gets deleted by
// someone who cannot reproduce what it protects against.
// ci-parity-exempt: this test's SUBJECT is the skip path, so it must enable deep
// mode WITHOUT the in-CI opt-in in order to observe the notice at all.
test('the CI-skip notice is still emitted under the IR-TAINT parser (the reason this rule exists)', async () => {
  const os = await import('node:os');
  const { runScan } = await import('../src/runScan.js');
  const { setStateWritesEnabled } = await import('../src/posture/state-dir.js');

  setStateWritesEnabled(false);
  const prevCi = process.env.CI;
  const prevGha = process.env.GITHUB_ACTIONS;
  const prevDeep = process.env.AGENTIC_SECURITY_DEEP;
  const prevInCi = process.env.AGENTIC_SECURITY_DEEP_IN_CI;
  process.env.CI = 'true';
  process.env.GITHUB_ACTIONS = 'true';
  process.env.AGENTIC_SECURITY_DEEP = '1';
  delete process.env.AGENTIC_SECURITY_DEEP_IN_CI; // the condition under test

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ci-parity-'));
  try {
    fs.writeFileSync(path.join(dir, 'package.json'), '{"name":"t","version":"1.0.0"}');
    fs.writeFileSync(path.join(dir, 'app.py'),
      'import subprocess\ndef h(name):\n    return subprocess.run("x " + name, shell=True)\n');
    const { scan } = await runScan(dir);
    const notices = (scan.findings || []).filter(
      (f) => f.parser === 'IR-TAINT' && /deep mode skipped/i.test(String(f.vuln || '')));
    assert.equal(notices.length, 1,
      'expected exactly one CI-skip notice carrying parser:"IR-TAINT" — if this '
      + 'changed, update the rationale in this file and in the invariant message above');
  } finally {
    if (prevCi === undefined) delete process.env.CI; else process.env.CI = prevCi;
    if (prevGha === undefined) delete process.env.GITHUB_ACTIONS; else process.env.GITHUB_ACTIONS = prevGha;
    if (prevDeep === undefined) delete process.env.AGENTIC_SECURITY_DEEP; else process.env.AGENTIC_SECURITY_DEEP = prevDeep;
    if (prevInCi === undefined) delete process.env.AGENTIC_SECURITY_DEEP_IN_CI; else process.env.AGENTIC_SECURITY_DEEP_IN_CI = prevInCi;
    setStateWritesEnabled(true);
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
