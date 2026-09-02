// dataflow-diff.test.js — M4 FR-503 §14 sub-project 8b, Task 3: CLI wiring
// for `agentic-security dataflow diff`.
//
// Mirrors test/cli/lineage-snapshot-persist.test.js's own real-git-fixture,
// real-subprocess pattern: `spawnSync(process.execPath, [BIN, 'scan', dir,
// '--format', 'json'], {env: {...process.env, AGENTIC_SECURITY_LINEAGE_DEEP:
// '1'}, encoding: 'utf8'})`, asserting `run.error === undefined && run.status
// < 4` (scan's own exit code is severity-based, never a pass/fail signal),
// never a hardcoded exit code for `scan` itself.
//
// The fixture reuses drift-policy.test.js's own real, already-proven
// "new PHI -> ai-model-provider" shape verbatim (a bare function taking
// `(anthropic, params)`, `params.arguments.patient_record` matching the
// `js-mcp-call-args` source and `anthropic.messages.create(...)` matching
// `js-anthropic-messages-create` — both real dataflow/catalog.js entries),
// since it is the one already proven, in this exact sub-project, to
// produce a real detectable new flow across two commits.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync, execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as path from 'node:path';
import * as os from 'node:os';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCANNER = path.resolve(HERE, '..', '..');
const BIN = path.join(SCANNER, 'bin', 'agentic-security.js');

const AI_SINK_NO_PHI_SOURCE = `function summarizePatient(anthropic, params) {
  anthropic.messages.create({
    model: 'claude-3',
    messages: [{ role: 'user', content: 'static-content' }],
  });
}
`;

const PHI_TO_AI_SOURCE = `function summarizePatient(anthropic, params) {
  const patientRecord = params.arguments.patient_record;
  anthropic.messages.create({
    model: 'claude-3',
    messages: [{ role: 'user', content: patientRecord }],
  });
}
`;

function mkGitFixture(initialSource) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dataflow-diff-cli-'));
  execFileSync('git', ['init', '-q'], { cwd: dir });
  execFileSync('git', ['config', 'user.email', 'test@test.com'], { cwd: dir });
  execFileSync('git', ['config', 'user.name', 'Test'], { cwd: dir });
  fs.writeFileSync(path.join(dir, 'package.json'), '{"name":"t","version":"1.0.0"}');
  fs.writeFileSync(path.join(dir, 'app.js'), initialSource);
  execFileSync('git', ['add', '.'], { cwd: dir });
  execFileSync('git', ['commit', '-q', '-m', 'init'], { cwd: dir });
  return dir;
}

function advanceCommit(dir, nextSource, marker) {
  fs.writeFileSync(path.join(dir, 'app.js'), nextSource);
  execFileSync('git', ['add', '.'], { cwd: dir });
  execFileSync('git', ['commit', '-q', '-m', marker], { cwd: dir });
}

function runScan(dir) {
  const run = spawnSync(process.execPath, [BIN, 'scan', dir, '--format', 'json'], {
    env: { ...process.env, AGENTIC_SECURITY_LINEAGE_DEEP: '1' },
    encoding: 'utf8',
  });
  assert.equal(run.error, undefined, `scan failed to spawn: ${run.error?.message}`);
  assert.ok(run.status < 4, `scan reported an engine error (exit ${run.status}): stderr=${run.stderr}`);
  return run;
}

function runDiff(args) {
  return spawnSync(process.execPath, [BIN, 'dataflow', 'diff', ...args], { encoding: 'utf8' });
}

test('cli/dataflow-diff-1: two real scans at two commits, dataflow diff (default --against) produces a JSON report naming the real added flow', async () => {
  const dir = mkGitFixture(AI_SINK_NO_PHI_SOURCE);
  try {
    runScan(dir);
    advanceCommit(dir, PHI_TO_AI_SOURCE, 'add PHI to AI flow');
    runScan(dir);

    const outFile = path.join(dir, 'diff.json');
    const run = runDiff([dir, '--output', outFile, '--format', 'json']);
    assert.equal(run.error, undefined, `dataflow diff failed to spawn: ${run.error?.message}`);
    assert.equal(run.status, 0, `expected exit 0: stdout=${run.stdout} stderr=${run.stderr}`);
    assert.ok(fs.existsSync(outFile), 'must write the --output file');

    const report = JSON.parse(fs.readFileSync(outFile, 'utf8'));
    assert.ok(report.id?.startsWith('diff:'), 'must be a real GraphDiff record');
    assert.ok(report.added?.flows?.length >= 1, 'fixture assumption: a new flow must appear');
    assert.ok(Array.isArray(report.violations), 'violations field must be present (empty array when no --drift-policy)');
    assert.deepEqual(report.violations, []);
  } finally {
    await fsp.rm(dir, { recursive: true, force: true });
  }
});

test('cli/dataflow-diff-2: no prior snapshot to compare against -> a clear exit-2 error, not a crash', async () => {
  const dir = mkGitFixture(AI_SINK_NO_PHI_SOURCE);
  try {
    runScan(dir);

    const outFile = path.join(dir, 'diff.json');
    const run = runDiff([dir, '--output', outFile, '--format', 'json']);
    assert.equal(run.error, undefined, `dataflow diff failed to spawn: ${run.error?.message}`);
    assert.equal(run.status, 2, `expected exit 2: stdout=${run.stdout} stderr=${run.stderr}`);
    assert.match(run.stderr, /dataflow diff/i);
    assert.ok(!fs.existsSync(outFile), 'must not write an output file on a usage error');
  } finally {
    await fsp.rm(dir, { recursive: true, force: true });
  }
});

test('cli/dataflow-diff-3: no snapshot at all (never scanned) -> a clear exit-2 error', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dataflow-diff-cli-empty-'));
  try {
    fs.writeFileSync(path.join(dir, 'package.json'), '{"name":"t","version":"1.0.0"}');
    const outFile = path.join(dir, 'diff.json');
    const run = runDiff([dir, '--output', outFile, '--format', 'json']);
    assert.equal(run.status, 2, `expected exit 2: stdout=${run.stdout} stderr=${run.stderr}`);
    assert.ok(!fs.existsSync(outFile));
  } finally {
    await fsp.rm(dir, { recursive: true, force: true });
  }
});

test('cli/dataflow-diff-4: --output is required -> exit 2', async () => {
  const dir = mkGitFixture(AI_SINK_NO_PHI_SOURCE);
  try {
    runScan(dir);
    const run = runDiff([dir, '--format', 'json']);
    assert.equal(run.status, 2);
    assert.match(run.stderr, /--output/);
  } finally {
    await fsp.rm(dir, { recursive: true, force: true });
  }
});

test('cli/dataflow-diff-5: missing/invalid --format -> exit 2', async () => {
  const dir = mkGitFixture(AI_SINK_NO_PHI_SOURCE);
  try {
    runScan(dir);
    advanceCommit(dir, PHI_TO_AI_SOURCE, 'second');
    runScan(dir);
    const outFile = path.join(dir, 'diff.json');

    const missing = runDiff([dir, '--output', outFile]);
    assert.equal(missing.status, 2, `stdout=${missing.stdout} stderr=${missing.stderr}`);
    assert.match(missing.stderr, /--format/);

    const invalid = runDiff([dir, '--output', outFile, '--format', 'yaml']);
    assert.equal(invalid.status, 2);
    assert.match(invalid.stderr, /--format/);

    assert.ok(!fs.existsSync(outFile));
  } finally {
    await fsp.rm(dir, { recursive: true, force: true });
  }
});

test('cli/dataflow-diff-6: --against <commit> resolves an explicit prior snapshot; an unknown commit is a clear exit-2 error', async () => {
  const dir = mkGitFixture(AI_SINK_NO_PHI_SOURCE);
  try {
    const firstHead = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: dir, encoding: 'utf8' }).trim();
    runScan(dir);
    advanceCommit(dir, PHI_TO_AI_SOURCE, 'second');
    runScan(dir);

    const outFile = path.join(dir, 'diff.json');
    const ok = runDiff([dir, '--output', outFile, '--format', 'json', '--against', firstHead]);
    assert.equal(ok.status, 0, `stdout=${ok.stdout} stderr=${ok.stderr}`);
    const report = JSON.parse(fs.readFileSync(outFile, 'utf8'));
    assert.ok(report.added.flows.length >= 1);

    const bad = runDiff([dir, '--output', outFile, '--format', 'json', '--against', 'deadbeef0000']);
    assert.equal(bad.status, 2, `stdout=${bad.stdout} stderr=${bad.stderr}`);
    assert.match(bad.stderr, /deadbeef0000/);
  } finally {
    await fsp.rm(dir, { recursive: true, force: true });
  }
});

test('cli/dataflow-diff-7: --drift-policy with a real "new PHI -> AI" rule surfaces the violation; --fail-on-drift makes it exit 1, its absence exits 0', async () => {
  const dir = mkGitFixture(AI_SINK_NO_PHI_SOURCE);
  try {
    runScan(dir);
    advanceCommit(dir, PHI_TO_AI_SOURCE, 'add PHI to AI flow');
    runScan(dir);

    const policyFile = path.join(dir, 'drift-policy.json');
    fs.writeFileSync(policyFile, JSON.stringify({
      policies: [{ trigger: 'new_flow', dataClass: 'PHI', reason: 'PHI must never reach an AI provider' }],
    }));

    const outFile = path.join(dir, 'diff.json');
    const noGate = runDiff([dir, '--output', outFile, '--format', 'json', '--drift-policy', policyFile]);
    assert.equal(noGate.status, 0, `stdout=${noGate.stdout} stderr=${noGate.stderr}`);
    const report = JSON.parse(fs.readFileSync(outFile, 'utf8'));
    assert.equal(report.violations.length, 1);
    assert.match(report.violations[0].reason, /PHI must never reach an AI provider/);

    const gated = runDiff([dir, '--output', outFile, '--format', 'json', '--drift-policy', policyFile, '--fail-on-drift']);
    assert.equal(gated.status, 1, `stdout=${gated.stdout} stderr=${gated.stderr}`);
    assert.ok(fs.existsSync(outFile), 'the report must still be written even when the gate exit is non-zero');
  } finally {
    await fsp.rm(dir, { recursive: true, force: true });
  }
});

test('cli/dataflow-diff-8: a malformed --drift-policy file is a clear exit-2 error', async () => {
  const dir = mkGitFixture(AI_SINK_NO_PHI_SOURCE);
  try {
    runScan(dir);
    advanceCommit(dir, PHI_TO_AI_SOURCE, 'second');
    runScan(dir);

    const policyFile = path.join(dir, 'bad-drift-policy.json');
    fs.writeFileSync(policyFile, '{ not valid json');

    const outFile = path.join(dir, 'diff.json');
    const run = runDiff([dir, '--output', outFile, '--format', 'json', '--drift-policy', policyFile]);
    assert.equal(run.status, 2, `stdout=${run.stdout} stderr=${run.stderr}`);
    assert.match(run.stderr, /drift-policy/);
    assert.ok(!fs.existsSync(outFile));
  } finally {
    await fsp.rm(dir, { recursive: true, force: true });
  }
});

test('cli/dataflow-diff-9: --format json round-trips through JSON.parse and matches computeGraphDiff\'s own real shape', async () => {
  const dir = mkGitFixture(AI_SINK_NO_PHI_SOURCE);
  try {
    runScan(dir);
    advanceCommit(dir, PHI_TO_AI_SOURCE, 'second');
    runScan(dir);

    const outFile = path.join(dir, 'diff.json');
    const run = runDiff([dir, '--output', outFile, '--format', 'json']);
    assert.equal(run.status, 0, `stdout=${run.stdout} stderr=${run.stderr}`);
    const report = JSON.parse(fs.readFileSync(outFile, 'utf8'));

    const { loadSnapshots, mostRecentPriorSnapshot } = await import('../../src/lineage/graph-snapshot.js');
    const { computeGraphDiff } = await import('../../src/lineage/graph-diff.js');
    const snapshots = loadSnapshots(dir);
    const after = snapshots[0];
    const before = mostRecentPriorSnapshot(dir, after.commit);
    const directDiff = computeGraphDiff(before, after, { generatedAt: report.generatedAt });

    assert.equal(report.id, directDiff.id);
    assert.equal(report.beforeSnapshotId, directDiff.beforeSnapshotId);
    assert.equal(report.afterSnapshotId, directDiff.afterSnapshotId);
    assert.deepEqual(report.comparability, directDiff.comparability);
    assert.deepEqual(report.added, directDiff.added);
    assert.deepEqual(report.removed, directDiff.removed);
    assert.deepEqual(report.changed, directDiff.changed);
  } finally {
    await fsp.rm(dir, { recursive: true, force: true });
  }
});

test('cli/dataflow-diff-11: a --drift-policy file with the wrong top-level shape is a clear exit-2 error, not a silent zero-rules pass', async () => {
  const dir = mkGitFixture(AI_SINK_NO_PHI_SOURCE);
  try {
    runScan(dir);
    advanceCommit(dir, PHI_TO_AI_SOURCE, 'second');
    runScan(dir);

    const outFile = path.join(dir, 'diff.json');

    // A bare JSON array — syntactically valid JSON, structurally wrong.
    const arrayPolicyFile = path.join(dir, 'array-drift-policy.json');
    fs.writeFileSync(arrayPolicyFile, JSON.stringify([{ trigger: 'new_flow' }]));
    const arrayRun = runDiff([dir, '--output', outFile, '--format', 'json', '--drift-policy', arrayPolicyFile, '--fail-on-drift']);
    assert.equal(arrayRun.status, 2, `expected exit 2, not a silent pass: stdout=${arrayRun.stdout} stderr=${arrayRun.stderr}`);
    assert.match(arrayRun.stderr, /drift-policy/i);
    assert.ok(!fs.existsSync(outFile), 'must not write an output file on a usage error');

    // {"rules": [...]} instead of {"policies": [...]} — a typo'd key.
    const rulesPolicyFile = path.join(dir, 'rules-drift-policy.json');
    fs.writeFileSync(rulesPolicyFile, JSON.stringify({ rules: [{ trigger: 'new_flow' }] }));
    const rulesRun = runDiff([dir, '--output', outFile, '--format', 'json', '--drift-policy', rulesPolicyFile, '--fail-on-drift']);
    assert.equal(rulesRun.status, 2, `expected exit 2, not a silent pass: stdout=${rulesRun.stdout} stderr=${rulesRun.stderr}`);
    assert.match(rulesRun.stderr, /drift-policy/i);
    assert.ok(!fs.existsSync(outFile));
  } finally {
    await fsp.rm(dir, { recursive: true, force: true });
  }
});

test('cli/dataflow-diff-12: --against the exact current (AFTER) commit refuses a self-diff, exit 2, even with --fail-on-drift', async () => {
  const dir = mkGitFixture(AI_SINK_NO_PHI_SOURCE);
  try {
    runScan(dir);
    advanceCommit(dir, PHI_TO_AI_SOURCE, 'second');
    runScan(dir);
    const head = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: dir, encoding: 'utf8' }).trim();

    const outFile = path.join(dir, 'diff.json');
    const run = runDiff([dir, '--output', outFile, '--format', 'json', '--against', head, '--fail-on-drift']);
    assert.equal(run.status, 2, `expected exit 2, not a silent pass: stdout=${run.stdout} stderr=${run.stderr}`);
    assert.match(run.stderr, /self-diff/i);
    assert.ok(!fs.existsSync(outFile), 'must not write an output file on a usage error');
  } finally {
    await fsp.rm(dir, { recursive: true, force: true });
  }
});

test('cli/dataflow-diff-10: --format markdown renders a real human-readable report with a prominent drift-policy violations section', async () => {
  const dir = mkGitFixture(AI_SINK_NO_PHI_SOURCE);
  try {
    runScan(dir);
    advanceCommit(dir, PHI_TO_AI_SOURCE, 'second');
    runScan(dir);

    const policyFile = path.join(dir, 'drift-policy.json');
    fs.writeFileSync(policyFile, JSON.stringify({
      policies: [{ trigger: 'new_flow', dataClass: 'PHI', reason: 'PHI must never reach an AI provider' }],
    }));

    const outFile = path.join(dir, 'diff.md');
    const run = runDiff([dir, '--output', outFile, '--format', 'markdown', '--drift-policy', policyFile]);
    assert.equal(run.status, 0, `stdout=${run.stdout} stderr=${run.stderr}`);
    const md = fs.readFileSync(outFile, 'utf8');

    assert.match(md, /^# /m, 'must be a real Markdown document with a heading');
    assert.match(md, /Drift Policy Violations/i);
    assert.match(md, /PHI must never reach an AI provider/);
    assert.match(md, /Added/i);
  } finally {
    await fsp.rm(dir, { recursive: true, force: true });
  }
});
