// drift-policy.test.js — M4 FR-503 §14 sub-project 8b, Task 2: a
// before/after drift-policy DSL evaluated against a real GraphDiff.
//
// Reuses graph-diff.test.js's own real-graph/real-git-history fixture
// pattern (`_mkGitRepo`/`_advanceCommit`, `persistGraphSnapshot`,
// `buildGraphWithCoverage`) — real parsed code -> real graph -> real
// snapshot -> real diff -> real policy evaluation, never a hand-built
// GraphDiff fake.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { execFileSync } from 'node:child_process';

import { persistGraphSnapshot } from '../../src/lineage/graph-snapshot.js';
import { computeGraphDiff } from '../../src/lineage/graph-diff.js';
import { buildGraphWithCoverage } from '../../src/lineage/coverage.js';
import { parseJsFile } from '../../src/ir/parser-js.js';
import { buildCallGraph } from '../../src/ir/callgraph.js';
import { loadDriftPolicies, evaluateDriftPolicies } from '../../src/lineage/drift-policy.js';

function _mkGitRepo() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'drift-policy-'));
  execFileSync('git', ['init', '-q'], { cwd: dir });
  execFileSync('git', ['config', 'user.email', 'test@test.com'], { cwd: dir });
  execFileSync('git', ['config', 'user.name', 'Test'], { cwd: dir });
  fs.writeFileSync(path.join(dir, 'README.md'), 'x');
  execFileSync('git', ['add', '.'], { cwd: dir });
  execFileSync('git', ['commit', '-q', '-m', 'init'], { cwd: dir });
  return dir;
}

function _advanceCommit(dir, marker) {
  fs.writeFileSync(path.join(dir, 'marker.txt'), marker);
  execFileSync('git', ['add', '.'], { cwd: dir });
  execFileSync('git', ['commit', '-q', '-m', marker], { cwd: dir });
}

function _realGraph(source, opts = {}) {
  const perFile = { 'source.js': parseJsFile('source.js', source) };
  const callGraph = buildCallGraph(perFile);
  return buildGraphWithCoverage(callGraph, { repository: 'r', generatedAt: '1970-01-01T00:00:00.000Z', ...opts }).graph;
}

function _realGraphFromCallGraph(callGraph, opts = {}) {
  return buildGraphWithCoverage(callGraph, { repository: 'r', generatedAt: '1970-01-01T00:00:00.000Z', ...opts }).graph;
}

// ── AC-27-style worked example: new PHI -> external (AI provider) ──────

const PHI_TO_AI_SOURCE = `function summarizePatient(anthropic, params) {
  const patientRecord = params.arguments.patient_record;
  anthropic.messages.create({
    model: 'claude-3',
    messages: [{ role: 'user', content: patientRecord }],
  });
}
`;

const AI_SINK_NO_PHI_SOURCE = `function summarizePatient(anthropic, params) {
  anthropic.messages.create({
    model: 'claude-3',
    messages: [{ role: 'user', content: 'static-content' }],
  });
}
`;

test('evaluateDriftPolicies: a new PHI -> ai-model-provider policy fires a violation naming the real flow/dataElement/sink', () => {
  const dir = _mkGitRepo();
  try {
    const graphBefore = _realGraph(AI_SINK_NO_PHI_SOURCE);
    const before = persistGraphSnapshot(graphBefore, dir, { capturedAt: '2020-01-01T00:00:00.000Z' });
    _advanceCommit(dir, 'second');
    const graphAfter = _realGraph(PHI_TO_AI_SOURCE);
    const after = persistGraphSnapshot(graphAfter, dir, { capturedAt: '2020-01-02T00:00:00.000Z' });

    const diff = computeGraphDiff(before, after);
    assert.ok(diff.added.flows.length >= 1, 'fixture assumption: a new flow must appear');

    const realFlow = graphAfter.flows.find((f) => f.id === diff.added.flows[0].id);
    const sinkNode = graphAfter.nodes.find((n) => n.id === realFlow.sink);
    assert.ok(sinkNode.subtype, 'fixture assumption: the AI sink must carry a real subtype category');

    const policies = { policies: [{ trigger: 'new_flow', dataClass: 'PHI', sinkCategory: sinkNode.subtype, reason: 'PHI must never reach an AI provider' }] };
    const { violations } = evaluateDriftPolicies(diff, policies, graphAfter);

    assert.equal(violations.length, 1);
    const v = violations[0];
    assert.equal(v.flowId, realFlow.id);
    assert.equal(v.trigger, 'new_flow');
    assert.ok(v.dataElementNames.length >= 1);
    assert.equal(v.sinkCategory, sinkNode.subtype);
    assert.equal(v.sinkNodeId, sinkNode.id);
    assert.equal(typeof v.reason, 'string');
    assert.ok(v.reason.length > 0, 'must be a human-readable reason string, never a bare boolean');
    assert.match(v.reason, /PHI must never reach an AI provider/);
    assert.deepEqual(v.rule, policies.policies[0]);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('evaluateDriftPolicies: a new_flow rule with a non-matching dataClass does not fire', () => {
  const dir = _mkGitRepo();
  try {
    const graphBefore = _realGraph(AI_SINK_NO_PHI_SOURCE);
    const before = persistGraphSnapshot(graphBefore, dir, { capturedAt: '2020-01-01T00:00:00.000Z' });
    _advanceCommit(dir, 'second');
    const graphAfter = _realGraph(PHI_TO_AI_SOURCE);
    const after = persistGraphSnapshot(graphAfter, dir, { capturedAt: '2020-01-02T00:00:00.000Z' });

    const diff = computeGraphDiff(before, after);
    const policies = { policies: [{ trigger: 'new_flow', dataClass: 'PCI', reason: 'irrelevant' }] };
    const { violations } = evaluateDriftPolicies(diff, policies, graphAfter);
    assert.deepEqual(violations, []);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ── protected -> unknown/unprotected on a real changed.flows entry ─────

test('evaluateDriftPolicies: a protected -> unprotected policy fires on a real protectionSummary regression, not on the reverse (an upgrade)', () => {
  // Same parsed source (same callGraph, reused for both builds, exactly
  // like the policyVerdict test above keeps flow identity stable across
  // a pure config change) — an https:// external-api call whose
  // edge.protection.transit verdict is forced via opts.resolveTransitProtection
  // (the real B2 hook, transit-protection.test.js's own precedent),
  // giving a genuine flow.protectionSummary transition
  // (protected -> unprotected, via aggregateVerdicts' own risk
  // precedence) on the SAME flow id — NOT the encrypt-vs-bare shape,
  // which was tried first and found to mint a genuinely different flow
  // id (flowId's own discriminator includes the flow's transformationIds/
  // shape/grade, all of which differ once a transform is added or
  // removed from the path).
  const SOURCE = `
    function h(req) {
      const cardNumber = req.body.card_number;
      fetch('https://payments.example/charge', { method: 'POST', body: cardNumber });
    }
  `;
  const perFile = { 'source.js': parseJsFile('source.js', SOURCE) };
  const callGraph = buildCallGraph(perFile);

  const graphBefore = _realGraphFromCallGraph(callGraph, {
    resolveTransitProtection: () => ({ verdict: 'protected', evidenceGrade: 'code' }),
  });
  const graphAfter = _realGraphFromCallGraph(callGraph, {
    resolveTransitProtection: () => ({ verdict: 'unprotected', evidenceGrade: 'code' }),
  });

  const dir = _mkGitRepo();
  try {
    const before = persistGraphSnapshot(graphBefore, dir, { capturedAt: '2020-01-01T00:00:00.000Z' });
    _advanceCommit(dir, 'second');
    const after = persistGraphSnapshot(graphAfter, dir, { capturedAt: '2020-01-02T00:00:00.000Z' });

    assert.equal(graphBefore.flows.length, 1);
    assert.equal(graphAfter.flows.length, 1);
    assert.equal(graphBefore.flows[0].id, graphAfter.flows[0].id, 'fixture assumption: flow identity must be stable across this change');
    assert.equal(graphBefore.flows[0].protectionSummary, 'protected');
    assert.notEqual(graphAfter.flows[0].protectionSummary, 'protected');

    const diff = computeGraphDiff(before, after);
    assert.equal(diff.changed.flows.length, 1);

    const regressionPolicy = { policies: [{ trigger: 'changed_flow', fromProtectionSummary: 'protected', reason: 'a protected flow must never regress' }] };
    const regressionResult = evaluateDriftPolicies(diff, regressionPolicy, graphAfter);
    assert.equal(regressionResult.violations.length, 1);
    assert.equal(regressionResult.violations[0].flowId, graphAfter.flows[0].id);
    assert.match(regressionResult.violations[0].reason, /protectionSummary/);

    // The reverse direction (an upgrade, toProtectionSummary: 'protected')
    // must NOT fire against this same real transition.
    const upgradePolicy = { policies: [{ trigger: 'changed_flow', toProtectionSummary: 'protected', reason: 'irrelevant' }] };
    const upgradeResult = evaluateDriftPolicies(diff, upgradePolicy, graphAfter);
    assert.deepEqual(upgradeResult.violations, []);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ── fail-closed axis matching, mirrored from privacy-sink-policy's own
// _matchesEnvironment/_matchesDestination precedent ─────────────────────

test('evaluateDriftPolicies: an unset rule field is unconstrained (matches anything)', () => {
  const source = `
    function track(req, analytics) {
      const email = req.body.email;
      analytics.track('signup', { email });
    }
  `;
  const perFile = { 'source.js': parseJsFile('source.js', source) };
  const callGraph = buildCallGraph(perFile);
  const graphBefore = _realGraphFromCallGraph(callGraph);
  const policy = { allow: [{ sink: 'analytics', class: 'PII', environment: 'production', reason: 'test' }] };
  const graphAfter = _realGraphFromCallGraph(callGraph, { privacySinkPolicy: policy, environment: 'production' });

  assert.equal(graphBefore.flows[0].id, graphAfter.flows[0].id);
  assert.equal(graphBefore.flows[0].policyVerdict, 'not_evaluated');
  assert.equal(graphAfter.flows[0].policyVerdict, 'permitted');

  const dir = _mkGitRepo();
  try {
    const before = persistGraphSnapshot(graphBefore, dir, { capturedAt: '2020-01-01T00:00:00.000Z' });
    _advanceCommit(dir, 'second');
    const after = persistGraphSnapshot(graphAfter, dir, { capturedAt: '2020-01-02T00:00:00.000Z' });
    const diff = computeGraphDiff(before, after);
    assert.equal(diff.changed.flows.length, 1);

    // A changed_flow rule with NO fromPolicyVerdict/toPolicyVerdict/
    // fromProtectionSummary/toProtectionSummary/dataClass/sinkCategory set
    // at all — every field unconstrained — must still fire against any
    // real changed.flows entry.
    const wideOpen = { policies: [{ trigger: 'changed_flow', reason: 'any change to any flow' }] };
    const { violations } = evaluateDriftPolicies(diff, wideOpen, graphAfter);
    assert.equal(violations.length, 1);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('evaluateDriftPolicies: a set field with no comparable diff-entry value does NOT match (fails closed)', () => {
  const source = `
    function track(req, analytics) {
      const email = req.body.email;
      analytics.track('signup', { email });
    }
  `;
  const perFile = { 'source.js': parseJsFile('source.js', source) };
  const callGraph = buildCallGraph(perFile);
  const graphBefore = _realGraphFromCallGraph(callGraph);
  const policy = { allow: [{ sink: 'analytics', class: 'PII', environment: 'production', reason: 'test' }] };
  const graphAfter = _realGraphFromCallGraph(callGraph, { privacySinkPolicy: policy, environment: 'production' });

  const dir = _mkGitRepo();
  try {
    const before = persistGraphSnapshot(graphBefore, dir, { capturedAt: '2020-01-01T00:00:00.000Z' });
    _advanceCommit(dir, 'second');
    const after = persistGraphSnapshot(graphAfter, dir, { capturedAt: '2020-01-02T00:00:00.000Z' });
    const diff = computeGraphDiff(before, after);
    assert.equal(diff.changed.flows.length, 1);
    // This real transition changes policyVerdict only — it never touches
    // protectionSummary. A rule that constrains fromProtectionSummary must
    // NOT match a changed.flows entry with no protectionSummary change
    // recorded at all (fail closed: a set field the diff entry has no
    // comparable value for does not match).
    const policyOnProtection = { policies: [{ trigger: 'changed_flow', fromProtectionSummary: 'protected', reason: 'irrelevant' }] };
    const { violations } = evaluateDriftPolicies(diff, policyOnProtection, graphAfter);
    assert.deepEqual(violations, []);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('evaluateDriftPolicies: a new_flow rule with a sinkCategory the added flow does not resolve to does NOT match', () => {
  const dir = _mkGitRepo();
  try {
    const graphBefore = _realGraph(AI_SINK_NO_PHI_SOURCE);
    const before = persistGraphSnapshot(graphBefore, dir, { capturedAt: '2020-01-01T00:00:00.000Z' });
    _advanceCommit(dir, 'second');
    const graphAfter = _realGraph(PHI_TO_AI_SOURCE);
    const after = persistGraphSnapshot(graphAfter, dir, { capturedAt: '2020-01-02T00:00:00.000Z' });
    const diff = computeGraphDiff(before, after);

    const policies = { policies: [{ trigger: 'new_flow', sinkCategory: 'does-not-exist-as-a-category', reason: 'irrelevant' }] };
    const { violations } = evaluateDriftPolicies(diff, policies, graphAfter);
    assert.deepEqual(violations, []);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('evaluateDriftPolicies: no policies configured produces no violations', () => {
  const dir = _mkGitRepo();
  try {
    const graphBefore = _realGraph(AI_SINK_NO_PHI_SOURCE);
    const before = persistGraphSnapshot(graphBefore, dir, { capturedAt: '2020-01-01T00:00:00.000Z' });
    _advanceCommit(dir, 'second');
    const graphAfter = _realGraph(PHI_TO_AI_SOURCE);
    const after = persistGraphSnapshot(graphAfter, dir, { capturedAt: '2020-01-02T00:00:00.000Z' });
    const diff = computeGraphDiff(before, after);

    assert.deepEqual(evaluateDriftPolicies(diff, { policies: [] }, graphAfter), { violations: [] });
    assert.deepEqual(evaluateDriftPolicies(diff, undefined, graphAfter), { violations: [] });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ── loadDriftPolicies ────────────────────────────────────────────────

test('loadDriftPolicies: a missing file is "no policies configured" — never throws', () => {
  assert.deepEqual(loadDriftPolicies(null), { policies: [] });
  assert.deepEqual(loadDriftPolicies(path.join(os.tmpdir(), 'definitely-does-not-exist-drift-policy.json')), { policies: [] });
});

test('loadDriftPolicies: malformed JSON degrades to no policies, without throwing', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'drift-policy-load-'));
  try {
    const fp = path.join(dir, 'drift-policy.json');
    fs.writeFileSync(fp, 'not json{{{');
    assert.deepEqual(loadDriftPolicies(fp), { policies: [] });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('loadDriftPolicies: a malformed rule entry is skipped (with a warning), not a crash', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'drift-policy-load-'));
  const originalError = console.error;
  const warnings = [];
  console.error = (...args) => warnings.push(args.join(' '));
  try {
    const fp = path.join(dir, 'drift-policy.json');
    fs.writeFileSync(fp, JSON.stringify({
      policies: [
        { trigger: 'new_flow', dataClass: 'PHI', reason: 'ok' },
        { dataClass: 'PHI' }, // missing trigger — malformed
        'not even an object',
        { trigger: 'not_a_real_trigger' },
      ],
    }));
    const loaded = loadDriftPolicies(fp);
    assert.equal(loaded.policies.length, 1);
    assert.equal(loaded.policies[0].dataClass, 'PHI');
    assert.ok(warnings.length > 0, 'a malformed entry must produce a visible warning, not silent loss');
  } finally {
    console.error = originalError;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('loadDriftPolicies: a well-formed policy file round-trips exactly', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'drift-policy-load-'));
  try {
    const fp = path.join(dir, 'drift-policy.json');
    const rule = { trigger: 'new_flow', dataClass: 'PHI', sinkCategory: 'ai-model-provider', reason: 'PHI must never reach an AI provider' };
    fs.writeFileSync(fp, JSON.stringify({ policies: [rule] }));
    assert.deepEqual(loadDriftPolicies(fp), { policies: [rule] });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
