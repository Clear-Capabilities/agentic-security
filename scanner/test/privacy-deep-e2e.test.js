// FR-403 step 3 (assurance-hardening PRD, D-0047): real end-to-end proof
// that the privacy-deep walker (dataflow/privacy-deep-walker.js) is wired
// into a REAL scan through the REAL parser — not just the hand-built-IR
// unit tests in test/privacy-deep-walker.test.js. Mirrors
// test/deep-taint.test.js's own established withDeepMode() pattern exactly.
//
// The fixture (test/fixtures/privacy-deep/direct-flow/app.js) declares
// `socialSecurityNumber` (classifies as PII by declaration name alone, per
// D-0041 step 2) assigned from an UNCLASSIFIED RHS (`req.body.ssnValue` —
// "ssnValue" does NOT match the taxonomy's `\bssn\b` word-boundary pattern),
// then logs it — proving the declaration-name source path specifically, not
// an RHS-classified coincidence. A sibling function logs an ordinary
// `count` value, which must never fire.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '../src/runScan.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIX = path.join(__dirname, 'fixtures', 'privacy-deep', 'direct-flow');
const INTERPROC_FIX = path.join(__dirname, 'fixtures', 'privacy-deep', 'interprocedural');
const CROSS_FILE_FIX = path.join(__dirname, 'fixtures', 'privacy-deep', 'cross-file');
const ALIASING_FIX = path.join(__dirname, 'fixtures', 'privacy-deep', 'aliasing');
const SAFE_TRANSFORM_FIX = path.join(__dirname, 'fixtures', 'privacy-deep', 'safe-transform');

async function scanWith(envOverrides, dir = FIX) {
  const prev = {};
  for (const k of Object.keys(envOverrides)) prev[k] = process.env[k];
  Object.assign(process.env, envOverrides);
  try {
    const { scan } = await runScan(dir, { network: false });
    return scan.findings || [];
  } finally {
    for (const k of Object.keys(envOverrides)) {
      if (prev[k] === undefined) delete process.env[k];
      else process.env[k] = prev[k];
    }
  }
}

test('AGENTIC_SECURITY_PRIVACY_DEEP=1: a real scan finds the declaration-classified privacy leak through the real parser', async () => {
  const findings = await scanWith({ AGENTIC_SECURITY_DEEP: '1', AGENTIC_SECURITY_DEEP_IN_CI: '1', AGENTIC_SECURITY_PRIVACY_DEEP: '1' });
  const hit = findings.find((f) => f.parser === 'IR-PRIVACY-TAINT');
  assert.ok(hit, `expected an IR-PRIVACY-TAINT finding, got parsers: ${[...new Set(findings.map(f => f.parser))].join(', ')}`);
  assert.equal(hit.cwe, 'CWE-359');
  assert.equal(hit.family, 'pii-exposure');
});

test('AGENTIC_SECURITY_PRIVACY_DEEP=1: the ordinary count value never fires (no false positive through the real parser)', async () => {
  const findings = await scanWith({ AGENTIC_SECURITY_DEEP: '1', AGENTIC_SECURITY_DEEP_IN_CI: '1', AGENTIC_SECURITY_PRIVACY_DEEP: '1' });
  const privacyFindings = findings.filter((f) => f.parser === 'IR-PRIVACY-TAINT');
  assert.ok(privacyFindings.every((f) => f.line !== 8), `logRequestCount's console.log(count) must not fire, got: ${JSON.stringify(privacyFindings)}`);
});

test('deep mode ON but AGENTIC_SECURITY_PRIVACY_DEEP unset: zero IR-PRIVACY-TAINT findings — the capability is genuinely opt-in, not just off by coincidence', async () => {
  const findings = await scanWith({ AGENTIC_SECURITY_DEEP: '1', AGENTIC_SECURITY_DEEP_IN_CI: '1' });
  const hit = findings.find((f) => f.parser === 'IR-PRIVACY-TAINT');
  assert.equal(hit, undefined, `expected zero IR-PRIVACY-TAINT findings with the flag unset, got: ${JSON.stringify(hit)}`);
});

test('deep mode entirely off: zero IR-PRIVACY-TAINT findings regardless of the privacy flag (privacy-deep only runs inside runDeepAnalysis)', async () => {
  const findings = await scanWith({ AGENTIC_SECURITY_PRIVACY_DEEP: '1' });
  const hit = findings.find((f) => f.parser === 'IR-PRIVACY-TAINT');
  assert.equal(hit, undefined, `expected zero IR-PRIVACY-TAINT findings with deep mode off, got: ${JSON.stringify(hit)}`);
});

// FR-403 step 3, item (a): simple same-function aliasing, through the REAL
// parser. test/privacy-deep-walker.test.js's hand-built-fn unit tests prove
// the mechanism in isolation; this proves the real parser (parser-js.js)
// actually lowers `a.value = ssn` into the flat dotted-string assignment
// TARGET shape (`"a.value"`) the walker's alias-aware member-write
// propagation assumes -- an assumption drawn from catalog.js's own
// documented `lhsPath` behavior, not independently re-verified until now.

test('AGENTIC_SECURITY_PRIVACY_DEEP=1: a member write through an alias reaches a sink read through the original name, through the real parser', async () => {
  const findings = await scanWith({ AGENTIC_SECURITY_DEEP: '1', AGENTIC_SECURITY_DEEP_IN_CI: '1', AGENTIC_SECURITY_PRIVACY_DEEP: '1' }, ALIASING_FIX);
  const hit = findings.find((f) => f.parser === 'IR-PRIVACY-TAINT' && f.file === 'app.js' && f.line === 6);
  assert.ok(hit, `expected logViaAlias's console.log(record.value) to fire via alias-aware member-write propagation, got: ${JSON.stringify(findings.filter(f => f.parser === 'IR-PRIVACY-TAINT'))}`);
});

test('AGENTIC_SECURITY_PRIVACY_DEEP=1: an alias write of a non-PII value does NOT fire (no false positive from alias propagation)', async () => {
  const findings = await scanWith({ AGENTIC_SECURITY_DEEP: '1', AGENTIC_SECURITY_DEEP_IN_CI: '1', AGENTIC_SECURITY_PRIVACY_DEEP: '1' }, ALIASING_FIX);
  const privacyFindings = findings.filter((f) => f.parser === 'IR-PRIVACY-TAINT');
  assert.ok(privacyFindings.every((f) => !(f.file === 'app.js' && f.line === 14)),
    `logCleanViaAlias's console.log(record2.value) must not fire, got: ${JSON.stringify(privacyFindings)}`);
});

// FR-403 step 3, item (b): interprocedural flow, through the REAL parser
// and REAL callGraph (test/privacy-deep-walker.test.js's hand-built-fn unit
// tests cannot exercise callGraph.resolveKnownCallee() at all, since that
// method is only attached by the real ir/callgraph.js#buildCallGraph -- a
// hand-built fake callGraph would need its own stubbed resolution logic,
// itself a source of test-design risk this file avoids by using real
// source end to end instead, mirroring this file's own established
// pattern).
//
// test/fixtures/privacy-deep/interprocedural/app.js: getSSN(rawInput)'s OWN
// body classifies a LOCAL declaration ("ssn") as PII, independent of what
// the caller passed in -- this isolates interprocedural resolution from the
// pre-existing "this call's own arguments are tainted" check (which alone
// would already make ANY call with a PII-shaped argument read as tainted,
// masking whether the NEW mechanism fired at all). The call-site argument
// ("count"/"other") is deliberately never itself PII-shaped.

test('AGENTIC_SECURITY_PRIVACY_DEEP=1: a privacy-tainted value produced INSIDE a called helper (independent of the caller-supplied argument) reaches the sink through the real callGraph', async () => {
  const findings = await scanWith({ AGENTIC_SECURITY_DEEP: '1', AGENTIC_SECURITY_DEEP_IN_CI: '1', AGENTIC_SECURITY_PRIVACY_DEEP: '1' }, INTERPROC_FIX);
  const hit = findings.find((f) => f.parser === 'IR-PRIVACY-TAINT' && f.line === 17);
  assert.ok(hit, `expected logViaHelper's console.log(getSSN(count)) to fire via interprocedural resolution, got: ${JSON.stringify(findings.filter(f => f.parser === 'IR-PRIVACY-TAINT'))}`);
});

test('AGENTIC_SECURITY_PRIVACY_DEEP=1: a genuinely clean helper (no PII anywhere in its own body) does NOT fire, even called with the same shape (no false positive from interprocedural resolution)', async () => {
  const findings = await scanWith({ AGENTIC_SECURITY_DEEP: '1', AGENTIC_SECURITY_DEEP_IN_CI: '1', AGENTIC_SECURITY_PRIVACY_DEEP: '1' }, INTERPROC_FIX);
  const privacyFindings = findings.filter((f) => f.parser === 'IR-PRIVACY-TAINT');
  assert.ok(privacyFindings.every((f) => f.line !== 22), `logCleanViaHelper's console.log(getCount(other)) must not fire, got: ${JSON.stringify(privacyFindings)}`);
});

// FR-403 step 3, item (c): cross-file flow. This came essentially FREE from
// item (b)'s implementation: _nestedCallReturnPrivacyTainted resolves via
// callGraph.resolveKnownCallee(), and the REAL callGraph (ir/callgraph.js's
// buildCallGraph) is built ONCE for the whole scan across every file, not
// per-file -- nothing in the interprocedural resolution code restricts it
// to the caller's own file. test/fixtures/privacy-deep/cross-file/ has
// helper.js's getSSN/getCount required by app.js's two callers, mirroring
// item (b)'s exact isolation shape (a neutral, non-PII call-site argument;
// the callee's own body is what determines whether its return taints).

test('AGENTIC_SECURITY_PRIVACY_DEEP=1: a privacy-tainted value produced inside a helper DEFINED IN A DIFFERENT FILE reaches the sink through the real cross-file callGraph', async () => {
  const findings = await scanWith({ AGENTIC_SECURITY_DEEP: '1', AGENTIC_SECURITY_DEEP_IN_CI: '1', AGENTIC_SECURITY_PRIVACY_DEEP: '1' }, CROSS_FILE_FIX);
  const hit = findings.find((f) => f.parser === 'IR-PRIVACY-TAINT' && f.file === 'app.js' && f.line === 5);
  assert.ok(hit, `expected logViaHelper's console.log(getSSN(count)) to fire via cross-file interprocedural resolution (getSSN is defined in helper.js), got: ${JSON.stringify(findings.filter(f => f.parser === 'IR-PRIVACY-TAINT'))}`);
});

test('AGENTIC_SECURITY_PRIVACY_DEEP=1: a genuinely clean helper defined in a DIFFERENT FILE does NOT fire (no false positive from cross-file resolution)', async () => {
  const findings = await scanWith({ AGENTIC_SECURITY_DEEP: '1', AGENTIC_SECURITY_DEEP_IN_CI: '1', AGENTIC_SECURITY_PRIVACY_DEEP: '1' }, CROSS_FILE_FIX);
  const privacyFindings = findings.filter((f) => f.parser === 'IR-PRIVACY-TAINT');
  assert.ok(privacyFindings.every((f) => !(f.file === 'app.js' && f.line === 10)),
    `logCleanViaHelper's console.log(getCount(other)) must not fire, got: ${JSON.stringify(privacyFindings)}`);
});

// FR-403 step 3, "safe transformations" (the last named item in the
// acceptance criterion): through the REAL parser + REAL downstream
// pipeline. Note the pipeline RECALIBRATES confidence/confidenceTier on
// every finding (this codebase's own shared calibration step, applied to
// every detector family alike, not specific to this walker) -- so this
// test deliberately does NOT assert the raw 0.6/0.18 values
// test/privacy-deep-walker.test.js's unit tests see directly from
// runPrivacyTaintEngine(). It asserts the two properties that DO survive
// calibration and are what the acceptance criterion actually cares about:
// (1) both flows still fire -- recall-preserving, never suppressed; (2)
// the transformed flow's confidence is strictly lower than the raw flow's,
// and only the transformed one carries _privacyTransformsOnPath.

test('AGENTIC_SECURITY_PRIVACY_DEEP=1: a hashed value still fires (recall-preserving) but at demoted confidence relative to the same value logged raw, through the real parser and pipeline', async () => {
  const findings = await scanWith({ AGENTIC_SECURITY_DEEP: '1', AGENTIC_SECURITY_DEEP_IN_CI: '1', AGENTIC_SECURITY_PRIVACY_DEEP: '1' }, SAFE_TRANSFORM_FIX);
  const privacyFindings = findings.filter((f) => f.parser === 'IR-PRIVACY-TAINT' && f.file === 'app.js');
  const hashedHit = privacyFindings.find((f) => f.line === 6);
  const rawHit = privacyFindings.find((f) => f.line === 11);
  assert.ok(hashedHit, `expected logHashed's console.log(hashed) to still fire, got: ${JSON.stringify(privacyFindings)}`);
  assert.ok(rawHit, `expected logRaw's console.log(email) to fire, got: ${JSON.stringify(privacyFindings)}`);
  assert.ok(Array.isArray(hashedHit._privacyTransformsOnPath) && hashedHit._privacyTransformsOnPath.length > 0,
    `expected the hashed finding to record _privacyTransformsOnPath, got: ${JSON.stringify(hashedHit)}`);
  assert.equal(rawHit._privacyTransformsOnPath, undefined, 'the raw (untransformed) finding must not carry a transform record');
  assert.ok(hashedHit.confidence < rawHit.confidence,
    `expected the hashed finding's confidence (${hashedHit.confidence}) to be lower than the raw finding's (${rawHit.confidence}) even after pipeline calibration`);
});
