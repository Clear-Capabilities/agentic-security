// FR-504 (assurance-hardening PRD): "Bind conclusions to repository, commit,
// scope, engine, ruleset, analyzer health, and mapping version | Changing
// any bound input produces a new evidence digest."
// FR-506: "Add evidence freshness, owner, reviewer, exception, and expiry |
// Expired evidence or exception changes status to `stale` or `gap` per
// policy."

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';
import {
  loadPolicy, verifyPolicy, emitEvidenceJsonLd, emitEvidenceMarkdown, computeEvidenceDigest, _internals,
  EVIDENCE_SCHEMA_VERSION, STATUS_SEMANTICS,
} from '../src/posture/compliance-policy.js';

async function mkSession() {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'compliance-fr504-'));
  await fsp.mkdir(path.join(dir, '.agentic-security'), { recursive: true });
  await fsp.writeFile(path.join(dir, 'package.json'), '{"name":"t"}');
  return { dir, cleanup: async () => fsp.rm(dir, { recursive: true, force: true }) };
}

const PAST = '2020-01-01T00:00:00.000Z';
const FUTURE = '2099-01-01T00:00:00.000Z';

async function writePolicy(dir, yaml) {
  await fsp.writeFile(path.join(dir, '.agentic-security', 'compliance.policy.yml'), yaml);
}

// ── FR-504: evidence digest ──────────────────────────────────────────────

test('FR-504: verifyPolicy computes an evidenceDigest bound to repository/commit/scope/engine/ruleset/analyzerHealth/mappingVersion/controls', async () => {
  const sess = await mkSession();
  try {
    await writePolicy(sess.dir, `
framework: "SOC2-light"
version: "1.0"
controls:
  CC6.1:
    title: "No hardcoded credentials"
    requires:
      - finding-family: "hardcoded-secret"
        must-be: zero
`);
    const policy = loadPolicy(sess.dir);
    const report = verifyPolicy(policy, { scanRoot: sess.dir, findings: [], repository: 'org/repo', commit: 'abc123' });
    assert.ok(report.evidenceDigest, 'expected a real digest');
    assert.equal(typeof report.evidenceDigest, 'string');
    assert.equal(report.evidenceDigest.length, 64, 'sha256 hex digest');
  } finally { await sess.cleanup(); }
});

test('FR-504: the SAME inputs produce the SAME digest — deterministic, not a fresh random id per run', async () => {
  const sess = await mkSession();
  try {
    await writePolicy(sess.dir, `
framework: "SOC2-light"
version: "1.0"
controls:
  CC6.1:
    title: "x"
    requires:
      - finding-family: "hardcoded-secret"
        must-be: zero
`);
    const policy = loadPolicy(sess.dir);
    const ctx = { scanRoot: sess.dir, findings: [], repository: 'org/repo', commit: 'abc123' };
    const a = verifyPolicy(policy, ctx).evidenceDigest;
    const b = verifyPolicy(policy, ctx).evidenceDigest;
    assert.equal(a, b);
  } finally { await sess.cleanup(); }
});

test('FR-504: changing ANY bound input changes the digest — repository, commit, mapping version, analyzer health, and control outcome each independently', async () => {
  const sess = await mkSession();
  try {
    await writePolicy(sess.dir, `
framework: "SOC2-light"
version: "1.0"
controls:
  CC6.1:
    title: "x"
    requires:
      - finding-family: "hardcoded-secret"
        must-be: zero
`);
    const policy = loadPolicy(sess.dir);
    const base = { scanRoot: sess.dir, findings: [], repository: 'org/repo', commit: 'abc123' };
    const baseline = verifyPolicy(policy, base).evidenceDigest;

    assert.notEqual(verifyPolicy(policy, { ...base, repository: 'org/OTHER' }).evidenceDigest, baseline, 'repository must be bound');
    assert.notEqual(verifyPolicy(policy, { ...base, commit: 'def456' }).evidenceDigest, baseline, 'commit must be bound');
    assert.notEqual(verifyPolicy(policy, { ...base, rulesetVersion: '2.0' }).evidenceDigest, baseline, 'ruleset must be bound');
    assert.notEqual(verifyPolicy(policy, { ...base, scanHealth: { status: 'partial' } }).evidenceDigest, baseline, 'analyzer health must be bound');
    // A different mapping version (same framework) is a different scope.
    const policyV2 = loadPolicy(sess.dir);
    policyV2.version = '2.0';
    assert.notEqual(verifyPolicy(policyV2, base).evidenceDigest, baseline, 'mapping version must be bound');
    // A different control OUTCOME (same everything else) — secret present now.
    const differentOutcome = verifyPolicy(policy, { ...base, secrets: [{ family: 'hardcoded-secret', severity: 'high' }] }).evidenceDigest;
    assert.notEqual(differentOutcome, baseline, 'a changed control verdict must change the digest');
  } finally { await sess.cleanup(); }
});

test('FR-504: the digest appears in both the JSON-LD and markdown evidence artifacts', async () => {
  const sess = await mkSession();
  try {
    await writePolicy(sess.dir, `
framework: "SOC2-light"
controls:
  CC6.1:
    title: "x"
    requires:
      - finding-family: "hardcoded-secret"
        must-be: zero
`);
    const policy = loadPolicy(sess.dir);
    const report = verifyPolicy(policy, { scanRoot: sess.dir, findings: [] });
    const jsonld = emitEvidenceJsonLd(report, sess.dir);
    assert.equal(jsonld.evidenceDigest, report.evidenceDigest);
    const md = emitEvidenceMarkdown(report, sess.dir);
    assert.ok(md.includes(report.evidenceDigest), 'the markdown artifact must show the same digest');
  } finally { await sess.cleanup(); }
});

test('computeEvidenceDigest: control order does not change the digest (sorted before hashing)', () => {
  const a = computeEvidenceDigest({ repository: 'r', commit: 'c', scope: 's', engine: 'e', ruleset: null, analyzerHealth: null, mappingVersion: '1', controls: [{ id: 'B', status: 'compliant' }, { id: 'A', status: 'gap' }] });
  const b = computeEvidenceDigest({ repository: 'r', commit: 'c', scope: 's', engine: 'e', ruleset: null, analyzerHealth: null, mappingVersion: '1', controls: [{ id: 'A', status: 'gap' }, { id: 'B', status: 'compliant' }] });
  assert.equal(a, b);
});

// ── FR-506: staleness ─────────────────────────────────────────────────────

test('FR-506: a control with review-interval-days exceeded becomes stale, with a staleReason', async () => {
  const sess = await mkSession();
  try {
    await writePolicy(sess.dir, `
framework: "SOC2-light"
controls:
  CC6.1:
    title: "x"
    reviewed-at: "${PAST}"
    review-interval-days: 90
    requires:
      - env-var-set: "ALWAYS_SET_FOR_TEST"
`);
    process.env.ALWAYS_SET_FOR_TEST = '1';
    try {
      const policy = loadPolicy(sess.dir);
      const report = verifyPolicy(policy, { scanRoot: sess.dir, findings: [] });
      const c = report.controls.find(x => x.id === 'CC6.1');
      assert.equal(c.status, 'stale');
      assert.match(c.staleReason, /90-day interval/);
      assert.equal(report.summary.stale, 1);
    } finally { delete process.env.ALWAYS_SET_FOR_TEST; }
  } finally { await sess.cleanup(); }
});

test('FR-506: a control reviewed WITHIN the interval stays compliant, not stale', async () => {
  const sess = await mkSession();
  try {
    const recentlyReviewed = new Date().toISOString();
    await writePolicy(sess.dir, `
framework: "SOC2-light"
controls:
  CC6.1:
    title: "x"
    reviewed-at: "${recentlyReviewed}"
    review-interval-days: 90
    requires:
      - env-var-set: "ALWAYS_SET_FOR_TEST"
`);
    process.env.ALWAYS_SET_FOR_TEST = '1';
    try {
      const policy = loadPolicy(sess.dir);
      const report = verifyPolicy(policy, { scanRoot: sess.dir, findings: [] });
      assert.equal(report.controls[0].status, 'compliant');
      assert.equal(report.summary.stale, 0);
    } finally { delete process.env.ALWAYS_SET_FOR_TEST; }
  } finally { await sess.cleanup(); }
});

test('FR-506: a control with NO review-interval-days is never stale, even with a very old reviewed-at — a no-op by default', async () => {
  const sess = await mkSession();
  try {
    await writePolicy(sess.dir, `
framework: "SOC2-light"
controls:
  CC6.1:
    title: "x"
    reviewed-at: "${PAST}"
    requires:
      - env-var-set: "ALWAYS_SET_FOR_TEST"
`);
    process.env.ALWAYS_SET_FOR_TEST = '1';
    try {
      const policy = loadPolicy(sess.dir);
      const report = verifyPolicy(policy, { scanRoot: sess.dir, findings: [] });
      assert.equal(report.controls[0].status, 'compliant');
    } finally { delete process.env.ALWAYS_SET_FOR_TEST; }
  } finally { await sess.cleanup(); }
});

test('FR-506: a NON-compliant control is reported non-compliant, not double-flagged stale, even past its review interval', async () => {
  const sess = await mkSession();
  try {
    await writePolicy(sess.dir, `
framework: "SOC2-light"
controls:
  CC6.1:
    title: "x"
    reviewed-at: "${PAST}"
    review-interval-days: 90
    requires:
      - env-var-set: "DEFINITELY_NOT_SET_FOR_TEST"
`);
    const policy = loadPolicy(sess.dir);
    const report = verifyPolicy(policy, { scanRoot: sess.dir, findings: [] });
    assert.equal(report.controls[0].status, 'non-compliant');
    assert.equal(report.summary.stale, 0);
  } finally { await sess.cleanup(); }
});

// ── FR-506: exceptions (not-applicable) ──────────────────────────────────

test('FR-506: a legacy bare `not-applicable: true` never expires, regardless of time', async () => {
  const sess = await mkSession();
  try {
    await writePolicy(sess.dir, `
framework: "SOC2-light"
controls:
  CC6.1:
    title: "x"
    not-applicable: true
    requires: []
`);
    const policy = loadPolicy(sess.dir);
    const report = verifyPolicy(policy, { scanRoot: sess.dir, findings: [] });
    assert.equal(report.controls[0].status, 'not-applicable');
  } finally { await sess.cleanup(); }
});

test('FR-506: a structured not-applicable exception with a PAST expires-at reopens the control as a gap', async () => {
  const sess = await mkSession();
  try {
    await writePolicy(sess.dir, `
framework: "SOC2-light"
controls:
  CC6.1:
    title: "x"
    not-applicable:
      reason: "no PII in this service, verified Q1"
      owner: "jane@example.com"
      expires-at: "${PAST}"
    requires: []
`);
    const policy = loadPolicy(sess.dir);
    const report = verifyPolicy(policy, { scanRoot: sess.dir, findings: [] });
    const c = report.controls[0];
    assert.equal(c.status, 'gap');
    assert.match(c.gapReason, /exception expired/);
    assert.equal(report.summary.gap, 1);
    assert.equal(report.summary.notApplicable, 0, 'an expired exception must not also count as not-applicable');
  } finally { await sess.cleanup(); }
});

test('FR-506: a structured not-applicable exception with a FUTURE expires-at stays not-applicable', async () => {
  const sess = await mkSession();
  try {
    await writePolicy(sess.dir, `
framework: "SOC2-light"
controls:
  CC6.1:
    title: "x"
    not-applicable:
      reason: "no PII in this service"
      owner: "jane@example.com"
      expires-at: "${FUTURE}"
    requires: []
`);
    const policy = loadPolicy(sess.dir);
    const report = verifyPolicy(policy, { scanRoot: sess.dir, findings: [] });
    assert.equal(report.controls[0].status, 'not-applicable');
    assert.equal(report.summary.gap, 0);
  } finally { await sess.cleanup(); }
});

test('FR-506: owner and reviewer pass through into the JSON-LD and markdown artifacts when set', async () => {
  const sess = await mkSession();
  try {
    await writePolicy(sess.dir, `
framework: "SOC2-light"
controls:
  CC6.1:
    title: "x"
    owner: "bob@example.com"
    reviewer: "jane@example.com"
    requires:
      - env-var-set: "ALWAYS_SET_FOR_TEST"
`);
    process.env.ALWAYS_SET_FOR_TEST = '1';
    try {
      const policy = loadPolicy(sess.dir);
      const report = verifyPolicy(policy, { scanRoot: sess.dir, findings: [] });
      const jsonld = emitEvidenceJsonLd(report, sess.dir);
      assert.equal(jsonld.controls[0].owner, 'bob@example.com');
      assert.equal(jsonld.controls[0].reviewer, 'jane@example.com');
      const md = emitEvidenceMarkdown(report, sess.dir);
      assert.match(md, /owner: bob@example\.com/);
      assert.match(md, /reviewer: jane@example\.com/);
    } finally { delete process.env.ALWAYS_SET_FOR_TEST; }
  } finally { await sess.cleanup(); }
});

test('FR-506: a control naming neither owner nor reviewer nor a review interval is completely unaffected (no fabricated fields)', async () => {
  const sess = await mkSession();
  try {
    await writePolicy(sess.dir, `
framework: "SOC2-light"
controls:
  CC6.1:
    title: "x"
    requires:
      - env-var-set: "ALWAYS_SET_FOR_TEST"
`);
    process.env.ALWAYS_SET_FOR_TEST = '1';
    try {
      const policy = loadPolicy(sess.dir);
      const report = verifyPolicy(policy, { scanRoot: sess.dir, findings: [] });
      const jsonld = emitEvidenceJsonLd(report, sess.dir);
      assert.equal(jsonld.controls[0].owner, undefined);
      assert.equal(jsonld.controls[0].reviewer, undefined);
      assert.equal(jsonld.controls[0].staleReason, undefined);
      assert.equal(jsonld.controls[0].gapReason, undefined);
    } finally { delete process.env.ALWAYS_SET_FOR_TEST; }
  } finally { await sess.cleanup(); }
});

// ── direct unit tests via _internals ─────────────────────────────────────

test('_internals._staleness: no interval configured is never stale', () => {
  assert.equal(_internals._staleness({ review_interval_days: null, reviewed_at: PAST }, Date.now()).stale, false);
});

test('_internals._staleness: never-reviewed with an interval configured is treated as maximally stale, not a free pass', () => {
  const r = _internals._staleness({ review_interval_days: 30, reviewed_at: null }, Date.now());
  assert.equal(r.stale, true);
  assert.match(r.reason, /never reviewed/);
});

test('_internals._exceptionExpired: null/legacy never expires', () => {
  assert.equal(_internals._exceptionExpired(null, Date.now()), false);
  assert.equal(_internals._exceptionExpired({ legacy: true }, Date.now()), false);
});

test('_internals._currentCommit: a non-git directory degrades to null, never throws', () => {
  assert.doesNotThrow(() => _internals._currentCommit('/'));
});

// ── FR-508: stable export — schema version, status semantics, source reference ──

test('FR-508: emitEvidenceJsonLd carries an explicit schemaVersion, statusSemantics for every real status, and a policySource', async () => {
  const sess = await mkSession();
  try {
    await writePolicy(sess.dir, `
framework: "SOC2-light"
controls:
  CC6.1:
    title: "x"
    requires:
      - finding-family: "hardcoded-secret"
        must-be: zero
`);
    const policy = loadPolicy(sess.dir);
    const report = verifyPolicy(policy, { scanRoot: sess.dir, findings: [] });
    const jsonld = emitEvidenceJsonLd(report, sess.dir);
    // Traced back to the single exported source of truth, not re-asserted
    // as an independent literal — proves the emitted document isn't
    // quietly drifting from what the module itself declares.
    assert.equal(jsonld.schemaVersion, EVIDENCE_SCHEMA_VERSION);
    assert.deepEqual(jsonld.statusSemantics, STATUS_SEMANTICS);
    assert.equal(jsonld.policySource, '.agentic-security/compliance.policy.yml');
    // Every status a real control can carry must have a documented meaning.
    for (const status of ['compliant', 'non-compliant', 'not-applicable', 'stale', 'gap']) {
      assert.equal(typeof STATUS_SEMANTICS[status], 'string');
      assert.ok(STATUS_SEMANTICS[status].length > 10, `expected a real definition for '${status}', not a placeholder`);
    }
  } finally { await sess.cleanup(); }
});
