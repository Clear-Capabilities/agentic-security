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

// A file needs the opt-in when it turns deep mode on (via EITHER the env var
// or the `{deep:true}` OPTION — see the second invariant below) AND actually
// runs a scan. This comment used to claim the OPTION shape "does not go
// through the env gate at all" and was therefore exempt — that was WRONG,
// confirmed the hard way: `_deepEnabled = _deepRequested && (!_inCi ||
// _deepInCiAllowed)` requires `_deepInCiAllowed` regardless of how
// `_deepRequested` became true, so `{deep:true}` alone is JUST as CI-downgraded
// as the env var. `privacy-ir-adapter.test.js` had already found and fixed
// this for itself (see its own `ci-parity-exempt` comments), but this
// checker's own detection never grew the matching second invariant — six
// more files (multi-sink-taint-chain.test.js, parser-php-{backtick,
// cond-assign,array-field-taint,include}.test.js, php-include-merge.test.js)
// silently produced ONLY the CI-skip notice on the first-ever real hosted CI
// run of the SARD 80% F1 push's full backlog (never caught locally, since
// `_inCi` is always false outside real CI) before being found and fixed.
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
// The second, OPTION-based shape: `runScan(dir, {deep:true, ...})` or a
// direct `runFullScan({..., deep:true})` call (multi-sink-taint-chain.test.js
// bypasses runScan entirely). Deliberately loose (matches inside a comment or
// string too, same tolerance ASSIGNS_DEEP/CALLS_SCAN already have) — a false
// offender here just means double-checking a harmless file, where a false
// negative means shipping the exact bug this file exists to catch.
const OPTION_DEEP_TRUE = /\bdeep\s*:\s*true\b/;
const CALLS_SCAN_OR_FULLSCAN = /\brun(?:Full)?Scan\s*\(/;
const HAS_DEEP_IN_CI_OPTION = /\bdeepInCi\s*:\s*true\b/;

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

test('every test that enables deep mode via the {deep:true} OPTION and scans also passes {deepInCi:true}', () => {
  const offenders = testFiles()
    .filter(({ src }) => OPTION_DEEP_TRUE.test(src) && CALLS_SCAN_OR_FULLSCAN.test(src))
    .filter(({ src }) => !HAS_DEEP_IN_CI_OPTION.test(src) && !HAS_OPT_IN.test(src) && !EXEMPT.test(src))
    .map(({ name }) => name);

  assert.deepEqual(offenders, [],
    'These files pass {deep:true} to runScan/runFullScan and scan, but never '
    + 'also pass {deepInCi:true} (or set AGENTIC_SECURITY_DEEP_IN_CI=1). The '
    + '{deep:true} OPTION does NOT bypass the CI downgrade — engine.js\'s '
    + '_deepEnabled still requires _deepInCiAllowed. Under CI the engine '
    + 'silently disables deep mode and emits a notice finding tagged '
    + 'parser:"IR-TAINT". Add deepInCi:true to the call:\n  '
    + offenders.join('\n  '));
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
