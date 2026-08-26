// FR-404 (assurance-hardening PRD): emit a privacy finding when regulated
// data reaches a PROHIBITED sink UNDER POLICY, and confirm that emission
// actually prevents the related NIST Privacy Framework control from reading
// satisfied.
//
// Two things are proven here, matching the two halves of the acceptance
// criterion:
//   1. "email from request input to logging produces a mapped privacy
//      finding and prevents related control satisfaction" — the DEFAULT
//      case, with no policy configured. This chain (privacy-taint.js's
//      pii-exposure finding -> auditor-walkthrough.js's family:pii-exposure
//      resolution -> privacy-framework.js's bucketOf) already existed before
//      this requirement; these tests pin it end-to-end rather than assuming
//      it from a unit test of one piece alone.
//   2. "under policy" — the genuinely new piece: an operator can mark a
//      specific (data class, sink) pair as permitted via
//      .agentic-security/privacy-policy.json, which suppresses the finding
//      (visibly — via policyExemptions / the DPIA artifact's own section —
//      never silently) without touching source.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fsp from 'node:fs/promises';
import * as path from 'node:path';
import * as os from 'node:os';

import { loadPrivacySinkPolicy, isSinkPermitted, permittingRules } from '../src/dataflow/privacy-sink-policy.js';
import { annotatePrivacyTaint, emitDpiaArtifact } from '../src/dataflow/privacy-taint.js';
import { assessPrivacyFramework } from '../src/posture/privacy-framework.js';

async function tmpProject() {
  const d = await fsp.mkdtemp(path.join(os.tmpdir(), 'privacy-sink-policy-'));
  await fsp.writeFile(path.join(d, 'package.json'), '{"name":"t"}');
  return d;
}

async function writeSinkPolicy(dir, obj) {
  await fsp.mkdir(path.join(dir, '.agentic-security'), { recursive: true });
  await fsp.writeFile(path.join(dir, '.agentic-security', 'privacy-policy.json'), JSON.stringify(obj, null, 2));
}

function emailToLogIR(varName = 'email') {
  const m = new Map();
  m.set('a.js', {
    _content: `const ${varName} = req.body.${varName};\nconsole.log(${varName});\n`,
    decls: [{ name: varName, line: 1 }],
    calls: [{ callee: 'log', receiver: 'console', fullPath: 'console.log', args: [{ text: varName }], line: 2 }],
  });
  return m;
}

// ── privacy-sink-policy.js unit tests ───────────────────────────────────

test('loadPrivacySinkPolicy with no scanRoot or no config file returns the empty policy (everything prohibited)', async () => {
  assert.deepEqual(loadPrivacySinkPolicy(null), { allow: [] });
  const dir = await tmpProject();
  try {
    assert.deepEqual(loadPrivacySinkPolicy(dir), { allow: [] });
  } finally { await fsp.rm(dir, { recursive: true, force: true }); }
});

test('loadPrivacySinkPolicy degrades to the empty policy on malformed JSON, without throwing', async () => {
  const dir = await tmpProject();
  try {
    await fsp.mkdir(path.join(dir, '.agentic-security'), { recursive: true });
    await fsp.writeFile(path.join(dir, '.agentic-security', 'privacy-policy.json'), 'not json{{{');
    assert.deepEqual(loadPrivacySinkPolicy(dir), { allow: [] });
  } finally { await fsp.rm(dir, { recursive: true, force: true }); }
});

test('isSinkPermitted: empty policy never permits anything', () => {
  assert.equal(isSinkPermitted(['PII'], 'log', { allow: [] }), false);
});

test('isSinkPermitted: a class-specific allow rule permits only that class for that sink', () => {
  const policy = { allow: [{ sink: 'emailSend', class: 'PII' }] };
  assert.equal(isSinkPermitted(['PII'], 'emailSend', policy), true);
  assert.equal(isSinkPermitted(['PII'], 'log', policy), false, 'different sink, same class — must not leak');
  assert.equal(isSinkPermitted(['PHI'], 'emailSend', policy), false, 'different class, same sink — must not leak');
});

test('isSinkPermitted: a sink-wide allow rule (no class) permits every class for that sink', () => {
  const policy = { allow: [{ sink: 'response' }] };
  assert.equal(isSinkPermitted(['PII'], 'response', policy), true);
  assert.equal(isSinkPermitted(['CREDENTIALS'], 'response', policy), true);
  assert.equal(isSinkPermitted(['PII'], 'log', policy), false);
});

test('isSinkPermitted: a finding combining a permitted class with an unpermitted one is NOT exempted (no partial bypass)', () => {
  const policy = { allow: [{ sink: 'log', class: 'PII' }] };
  assert.equal(isSinkPermitted(['PII', 'CREDENTIALS'], 'log', policy), false, 'CREDENTIALS was never permitted for log — the whole finding must still fire');
});

test('permittingRules surfaces the reason string for disclosure', () => {
  const policy = { allow: [{ sink: 'emailSend', class: 'PII', reason: 'password reset emails' }] };
  const rules = permittingRules(['PII'], 'emailSend', policy);
  assert.equal(rules.length, 1);
  assert.equal(rules[0].reason, 'password reset emails');
});

// ── end-to-end: annotatePrivacyTaint with a real policy ─────────────────

test('FR-404 default case (no policy): email flowing to console.log produces a mapped pii-exposure finding', async () => {
  const dir = await tmpProject();
  try {
    const r = annotatePrivacyTaint(emailToLogIR(), { scanRoot: dir });
    assert.equal(r.findings.length, 1);
    assert.equal(r.findings[0].family, 'pii-exposure');
    assert.equal(r.findings[0].sinkKind, 'log');
    assert.deepEqual(r.policyExemptions, []);
  } finally { await fsp.rm(dir, { recursive: true, force: true }); }
});

test('FR-404 under policy: a permitted (class, sink) pair produces NO finding, but the flow is recorded as a visible exemption', async () => {
  const dir = await tmpProject();
  try {
    await writeSinkPolicy(dir, { allow: [{ sink: 'log', class: 'PII', reason: 'internal audit log, access-controlled' }] });
    const r = annotatePrivacyTaint(emailToLogIR(), { scanRoot: dir });
    assert.equal(r.findings.length, 0, 'the permitted flow must not produce a finding');
    assert.equal(r.policyExemptions.length, 1, 'but it must not vanish silently either');
    assert.deepEqual(r.policyExemptions[0].classes, ['PII']);
    assert.equal(r.policyExemptions[0].sinkKind, 'log');
    assert.equal(r.policyExemptions[0].rules[0].reason, 'internal audit log, access-controlled');
  } finally { await fsp.rm(dir, { recursive: true, force: true }); }
});

test('FR-404 under policy: an unrelated sink is unaffected by an allow rule for a different sink', async () => {
  const dir = await tmpProject();
  try {
    await writeSinkPolicy(dir, { allow: [{ sink: 'emailSend', class: 'PII' }] });
    // Same email variable, but flowing to console.log, not emailSend.
    const r = annotatePrivacyTaint(emailToLogIR(), { scanRoot: dir });
    assert.equal(r.findings.length, 1, 'log was never permitted — must still fire');
    assert.equal(r.policyExemptions.length, 0);
  } finally { await fsp.rm(dir, { recursive: true, force: true }); }
});

test('annotatePrivacyTaint with no scanRoot/sinkPolicy still fires unconditionally (backward compatible default)', () => {
  const r = annotatePrivacyTaint(emailToLogIR());
  assert.equal(r.findings.length, 1);
  assert.deepEqual(r.policyExemptions, []);
});

// ── DPIA artifact visibility ──────────────────────────────────────────

test('emitDpiaArtifact renders a "Policy-permitted flows" section only when exemptions exist', () => {
  const piiFields = [{ file: 'a.js', line: 1, name: 'email', classes: ['PII'], declaredType: 'string' }];
  const noExemptions = emitDpiaArtifact(piiFields, []);
  assert.doesNotMatch(noExemptions, /Policy-permitted flows/);

  const withExemptions = emitDpiaArtifact(piiFields, [], {
    policyExemptions: [{ file: 'a.js', line: 2, classes: ['PII'], sinkKind: 'log', rules: [{ reason: 'internal audit log' }] }],
  });
  assert.match(withExemptions, /Policy-permitted flows/);
  assert.match(withExemptions, /internal audit log/);
  assert.match(withExemptions, /a\.js:2/);
});

// ── end-to-end: FR-404's literal acceptance-criteria example, through the
// full privacy-framework pipeline ──────────────────────────────────────

test('FR-404 acceptance criterion, end to end: the pii-exposure finding prevents CT.DP-P1 from reading satisfied; a fully policy-permitted flow does not', async () => {
  const dir = await tmpProject();
  try {
    // Default: no policy configured — the flow produces a finding, which
    // must flip the mapped control to gap, not satisfied.
    const withFinding = annotatePrivacyTaint(emailToLogIR(), { scanRoot: dir });
    const scanGap = { findings: withFinding.findings, components: [], filesScanned: 5, privacyIrBacked: true };
    const rGap = assessPrivacyFramework(dir, scanGap);
    const ctDp1Gap = rGap.controls.find(c => c.id === 'CT.DP-P1');
    assert.ok(ctDp1Gap, 'expected CT.DP-P1 (mapped to family:pii-exposure) in the control set');
    assert.equal(ctDp1Gap.bucket, 'gap', 'an open pii-exposure finding must prevent CT.DP-P1 from reading satisfied');

    // Now the SAME flow, fully permitted by policy — no finding at all, so
    // nothing should flip the control away from satisfied on this basis.
    await writeSinkPolicy(dir, { allow: [{ sink: 'log', class: 'PII', reason: 'test' }] });
    const withPolicy = annotatePrivacyTaint(emailToLogIR(), { scanRoot: dir });
    assert.equal(withPolicy.findings.length, 0);
    const scanClean = { findings: withPolicy.findings, components: [], filesScanned: 5, privacyIrBacked: true };
    const rClean = assessPrivacyFramework(dir, scanClean);
    const ctDp1Clean = rClean.controls.find(c => c.id === 'CT.DP-P1');
    assert.equal(ctDp1Clean.bucket, 'satisfied', 'with the finding policy-suppressed, the control must read satisfied again');
  } finally { await fsp.rm(dir, { recursive: true, force: true }); }
});

// ── FR-408: environment- and destination-specific policy decisions ─────
//
// Extends the same (class, sink) allow-rule shape FR-404 built with two
// additional, OPTIONAL axes: `environment` (this scan's deployment
// environment) and `destination` (a regex against the actual sink
// expression, e.g. "stripe.track" — not just its broader category label).
// Both fail closed: a rule naming an axis the caller never supplied context
// for does not match, and every FR-404 rule (with neither field) keeps
// working exactly as before this extension — proven above by the full
// pre-existing FR-404 suite passing unchanged.

function thirdPartySdkIR(destCallee, varName = 'email') {
  const m = new Map();
  m.set('a.js', {
    _content: `const ${varName} = req.body.${varName};\n${destCallee}(${varName});\n`,
    decls: [{ name: varName, line: 1 }],
    calls: [{ callee: destCallee.split('.').pop(), fullPath: destCallee, args: [{ text: varName }], line: 2 }],
  });
  return m;
}

test('FR-408: an environment-scoped rule permits the flow only when the CURRENT environment matches', async () => {
  const dir = await tmpProject();
  try {
    await writeSinkPolicy(dir, { allow: [{ sink: 'log', class: 'PII', environment: 'staging', reason: 'staging debug logs are access-controlled' }] });
    const inStaging = annotatePrivacyTaint(emailToLogIR(), { scanRoot: dir, environment: 'staging' });
    assert.equal(inStaging.findings.length, 0, 'staging matches the rule — no finding');
    assert.equal(inStaging.policyExemptions.length, 1);

    const inProd = annotatePrivacyTaint(emailToLogIR(), { scanRoot: dir, environment: 'production' });
    assert.equal(inProd.findings.length, 1, 'production does not match a staging-only rule — must still fire');
  } finally { await fsp.rm(dir, { recursive: true, force: true }); }
});

test('FR-408: an environment-scoped rule does NOT match when the current environment is unknown (fail closed)', async () => {
  const dir = await tmpProject();
  const hadEnvVar = Object.prototype.hasOwnProperty.call(process.env, 'AGENTIC_SECURITY_ENVIRONMENT');
  const savedEnvVar = process.env.AGENTIC_SECURITY_ENVIRONMENT;
  try {
    await writeSinkPolicy(dir, { allow: [{ sink: 'log', class: 'PII', environment: 'staging' }] });
    // Neither opts.environment nor AGENTIC_SECURITY_ENVIRONMENT set — the
    // rule must not silently apply. Explicitly unset the env var (saved
    // above) rather than assuming it was already unset, since this file
    // runs combined with the rest of the suite in one process.
    delete process.env.AGENTIC_SECURITY_ENVIRONMENT;
    const r = annotatePrivacyTaint(emailToLogIR(), { scanRoot: dir });
    assert.equal(r.findings.length, 1, 'an unknown environment must not satisfy an environment-scoped rule');
  } finally {
    if (hadEnvVar) process.env.AGENTIC_SECURITY_ENVIRONMENT = savedEnvVar; else delete process.env.AGENTIC_SECURITY_ENVIRONMENT;
    await fsp.rm(dir, { recursive: true, force: true });
  }
});

test('FR-408: environment can be an array — the rule matches if the current environment is any listed one', async () => {
  const dir = await tmpProject();
  try {
    await writeSinkPolicy(dir, { allow: [{ sink: 'log', class: 'PII', environment: ['staging', 'development'] }] });
    assert.equal(annotatePrivacyTaint(emailToLogIR(), { scanRoot: dir, environment: 'development' }).findings.length, 0);
    assert.equal(annotatePrivacyTaint(emailToLogIR(), { scanRoot: dir, environment: 'staging' }).findings.length, 0);
    assert.equal(annotatePrivacyTaint(emailToLogIR(), { scanRoot: dir, environment: 'production' }).findings.length, 1);
  } finally { await fsp.rm(dir, { recursive: true, force: true }); }
});

test('FR-408: environment matching is case-insensitive', async () => {
  const dir = await tmpProject();
  try {
    await writeSinkPolicy(dir, { allow: [{ sink: 'log', class: 'PII', environment: 'Staging' }] });
    assert.equal(annotatePrivacyTaint(emailToLogIR(), { scanRoot: dir, environment: 'STAGING' }).findings.length, 0);
  } finally { await fsp.rm(dir, { recursive: true, force: true }); }
});

test('FR-408: a destination-scoped rule permits only the matching destination, not the whole sink category', async () => {
  const dir = await tmpProject();
  try {
    await writeSinkPolicy(dir, { allow: [{ sink: 'thirdPartySdk', class: 'PII', destination: '^stripe\\.', reason: 'stripe needs email for receipts' }] });
    const toStripe = annotatePrivacyTaint(thirdPartySdkIR('stripe.track'), { scanRoot: dir });
    assert.equal(toStripe.findings.length, 0, 'stripe.track matches the destination pattern');
    assert.equal(toStripe.policyExemptions.length, 1);

    const toSentry = annotatePrivacyTaint(thirdPartySdkIR('sentry.track'), { scanRoot: dir });
    assert.equal(toSentry.findings.length, 1, 'sentry.track is the SAME sink category but a different destination — must still fire');
  } finally { await fsp.rm(dir, { recursive: true, force: true }); }
});

test('FR-408: an invalid operator-supplied destination regex never silently matches everything (fails closed, not open)', async () => {
  const dir = await tmpProject();
  try {
    await writeSinkPolicy(dir, { allow: [{ sink: 'thirdPartySdk', class: 'PII', destination: '(unclosed' }] });
    const r = annotatePrivacyTaint(thirdPartySdkIR('stripe.track'), { scanRoot: dir });
    assert.equal(r.findings.length, 1, 'a broken pattern must not accidentally exempt everything');
  } finally { await fsp.rm(dir, { recursive: true, force: true }); }
});

test('FR-408: environment AND destination can be combined on the same rule — both must match', async () => {
  const dir = await tmpProject();
  try {
    await writeSinkPolicy(dir, { allow: [{ sink: 'thirdPartySdk', class: 'PII', environment: 'production', destination: '^stripe\\.' }] });
    assert.equal(
      annotatePrivacyTaint(thirdPartySdkIR('stripe.track'), { scanRoot: dir, environment: 'production' }).findings.length, 0,
      'both axes match',
    );
    assert.equal(
      annotatePrivacyTaint(thirdPartySdkIR('stripe.track'), { scanRoot: dir, environment: 'staging' }).findings.length, 1,
      'destination matches but environment does not — must still fire',
    );
    assert.equal(
      annotatePrivacyTaint(thirdPartySdkIR('sentry.track'), { scanRoot: dir, environment: 'production' }).findings.length, 1,
      'environment matches but destination does not — must still fire',
    );
  } finally { await fsp.rm(dir, { recursive: true, force: true }); }
});

test('FR-408: a rule with neither environment nor destination behaves exactly as an FR-404 rule always did (backward compatible)', async () => {
  const dir = await tmpProject();
  try {
    await writeSinkPolicy(dir, { allow: [{ sink: 'log', class: 'PII' }] });
    assert.equal(annotatePrivacyTaint(emailToLogIR(), { scanRoot: dir, environment: 'production' }).findings.length, 0);
    assert.equal(annotatePrivacyTaint(emailToLogIR(), { scanRoot: dir }).findings.length, 0, 'no environment supplied at all — unconstrained rule still applies');
  } finally { await fsp.rm(dir, { recursive: true, force: true }); }
});

test('FR-408: isSinkPermitted/permittingRules default ctx to {} — direct callers with no 4th argument see FR-404-only behavior', () => {
  const policy = { allow: [{ sink: 'log', class: 'PII', environment: 'staging' }] };
  assert.equal(isSinkPermitted(['PII'], 'log', policy), false, 'environment-scoped rule with no ctx at all must not match');
  assert.deepEqual(permittingRules(['PII'], 'log', policy), []);

  const unconstrained = { allow: [{ sink: 'log', class: 'PII' }] };
  assert.equal(isSinkPermitted(['PII'], 'log', unconstrained), true, 'unconstrained rule matches with no ctx, same as FR-404');
});
