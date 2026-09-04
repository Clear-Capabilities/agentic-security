// dataflow-watch.test.js — M4 deliverable #9 (watch-mode graph delta
// updates), Task 2: CLI wiring for `agentic-security dataflow watch`.
//
// This command is unlike every other CLI command tested in this
// directory: it does not exit on its own (it blocks on a live `fs.watch`
// async iterator inside `watchProject` until Ctrl-C/SIGTERM — see
// `bin/agentic-security.js`'s own `case 'dataflow': ... else if (sub ===
// 'watch')` dispatch comment for why it is deliberately NOT wrapped in
// `process.exit(await cmdDataflowWatch(args))` the way every other
// subcommand is). A `spawnSync`-and-wait test (this directory's usual
// pattern, e.g. `dataflow-diff.test.js`) would simply hang forever on the
// success path. Real tests below use ASYNC `spawn` instead: start the
// subprocess, poll its buffered stdout/stderr for the exact text a real
// rescan produces (never a fixed `setTimeout` guess), write a real file
// change, poll again for the delta status line, then kill the subprocess.
//
// `DEBOUNCE_MS` (350) is hardcoded here, NOT imported — confirmed
// (2026-09-02) that `src/posture/watch-mode.js`'s own `DEBOUNCE_MS`
// constant is not exported (only `_isScanable`/`SCAN_EXT_RE`/
// `IGNORE_DIR_RE` are, via `_internals`); this is the plan's own
// documented fallback for exactly this case.
//
// The fixture shapes below (AI_SINK_NO_PHI_SOURCE / PHI_TO_AI_SOURCE) are
// reused VERBATIM from test/cli/dataflow-diff.test.js — the one already
// proven, in this exact sub-project family, to produce a real detectable
// new flow (`params.arguments.patient_record` -> PHI ->
// `anthropic.messages.create(...)`) via the real dataflow/catalog.js
// entries `js-mcp-call-args` / `js-anthropic-messages-create`.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync, execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as path from 'node:path';
import * as os from 'node:os';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCANNER = path.resolve(HERE, '..', '..');
const BIN = path.join(SCANNER, 'bin', 'agentic-security.js');

const DEBOUNCE_MS = 350; // src/posture/watch-mode.js's own DEBOUNCE_MS, not exported — see header.

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
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dataflow-watch-cli-'));
  execFileSync('git', ['init', '-q'], { cwd: dir });
  execFileSync('git', ['config', 'user.email', 'test@test.com'], { cwd: dir });
  execFileSync('git', ['config', 'user.name', 'Test'], { cwd: dir });
  fs.writeFileSync(path.join(dir, 'package.json'), '{"name":"t","version":"1.0.0"}');
  fs.writeFileSync(path.join(dir, 'app.js'), initialSource);
  execFileSync('git', ['add', '.'], { cwd: dir });
  execFileSync('git', ['commit', '-q', '-m', 'init'], { cwd: dir });
  return dir;
}

// 30000 (the original budget) had ~20x local headroom (these waits complete
// in ~1.4s on a normal machine) but still timed out on the v0.147.2 release
// run's GitHub Actions draw — this repo's watch mode uses Node's native
// `fs.watch(..., { recursive: true })` (src/posture/watch-mode.js), which is
// documented as slower/less reliable specifically under Linux CI runners'
// inotify handling than on a normal dev machine. 90000 gives real headroom
// against that CI-specific variance without weakening what the test proves
// (it still fails loudly, with the real buffered output, on an actual hang).
const WAIT_TIMEOUT_MS = 90000;

// Polls `getBuffer()` until `re` matches or `timeoutMs` elapses. Never a
// fixed sleep — this repo's own convention (an `until <cond>; do sleep;
// done` shape) translated to JS. Rejects with the buffered text on
// timeout so a real regression fails loudly with the actual output, not a
// bare "timed out".
async function waitForMatch(getBuffer, re, timeoutMs, label) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const buf = getBuffer();
    if (re.test(buf)) return buf;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`waitForMatch(${label}) timed out after ${timeoutMs}ms waiting for ${re}. Buffer so far:\n${getBuffer()}`);
}

function spawnWatch(args, env) {
  const child = spawn(process.execPath, [BIN, 'dataflow', 'watch', ...args], {
    env: { ...process.env, ...env },
  });
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', (c) => { stdout += c; });
  child.stderr.on('data', (c) => { stderr += c; });
  return { child, getStdout: () => stdout, getStderr: () => stderr, getCombined: () => stdout + stderr };
}

async function killAndWait(child) {
  if (child.exitCode !== null || child.killed) return;
  child.kill('SIGTERM');
  await new Promise((resolve) => {
    const t = setTimeout(resolve, 3000); // don't hang the test if teardown itself misbehaves
    child.once('exit', () => { clearTimeout(t); resolve(); });
  });
}

test('cli/dataflow-watch-1: real subprocess — startup banner, then a real debounced rescan reports a real added flow in the live stderr stream', async () => {
  const dir = mkGitFixture(AI_SINK_NO_PHI_SOURCE);
  const { child, getCombined } = spawnWatch([dir], {});
  try {
    // Proves the seed scan completed and the watcher is live.
    await waitForMatch(getCombined, /Ctrl-C to stop/, WAIT_TIMEOUT_MS, 'startup banner');
    assert.match(getCombined(), /does NOT refresh .*lineage-graph\.json/, 'startup banner must disclose the no-live-refresh scope boundary');

    // A real code change: same PHI -> AI-provider shape dataflow-diff.test.js
    // already proved produces a real new flow.
    await fsp.writeFile(path.join(dir, 'app.js'), PHI_TO_AI_SOURCE);

    // Wait at least DEBOUNCE_MS plus real rescan time, polling — never a
    // fixed sleep guess.
    const out = await waitForMatch(getCombined, /\[watch-dataflow\] \+\d+\/-\d+ flows/, WAIT_TIMEOUT_MS, 'delta status line');
    assert.match(out, /\+1\/-0 flows/, 'exactly one new flow must be reported');
  } finally {
    await killAndWait(child);
    await fsp.rm(dir, { recursive: true, force: true });
  }
}, { timeout: WAIT_TIMEOUT_MS * 2 + 30000 });

test('cli/dataflow-watch-2: --drift-policy with a real "new PHI -> AI" rule surfaces the violation in the live stderr stream', async () => {
  const dir = mkGitFixture(AI_SINK_NO_PHI_SOURCE);
  const policyFile = path.join(dir, 'drift-policy.json');
  fs.writeFileSync(policyFile, JSON.stringify({
    policies: [{ trigger: 'new_flow', dataClass: 'PHI', reason: 'PHI must never reach an AI provider' }],
  }));

  const { child, getCombined } = spawnWatch([dir, '--drift-policy', policyFile, '--fail-on-drift'], {});
  try {
    await waitForMatch(getCombined, /Ctrl-C to stop/, WAIT_TIMEOUT_MS, 'startup banner');

    await fsp.writeFile(path.join(dir, 'app.js'), PHI_TO_AI_SOURCE);

    const out = await waitForMatch(getCombined, /DRIFT POLICY VIOLATION/, WAIT_TIMEOUT_MS, 'drift violation block');
    assert.match(out, /new_flow: flow /, 'violation block must name the real triggering flow');
    assert.match(out, /PHI must never reach an AI provider/, 'violation block must carry the rule\'s own reason text');
  } finally {
    await killAndWait(child);
    await fsp.rm(dir, { recursive: true, force: true });
  }
}, { timeout: WAIT_TIMEOUT_MS * 2 + 30000 });

test('cli/dataflow-watch-3: a malformed --drift-policy file is a clear exit-2 error BEFORE the watcher ever starts', () => {
  const dir = mkGitFixture(AI_SINK_NO_PHI_SOURCE);
  try {
    const policyFile = path.join(dir, 'bad-drift-policy.json');
    fs.writeFileSync(policyFile, '{ not valid json');

    // Fails fast and exits on its own — safe to use spawnSync here (per
    // the task brief's own testing-strategy note).
    const run = spawnSync(process.execPath, [BIN, 'dataflow', 'watch', dir, '--drift-policy', policyFile], {
      encoding: 'utf8', timeout: 20000,
    });
    assert.equal(run.status, 2, `expected exit 2; got ${run.status}. stderr=${run.stderr}`);
    assert.match(run.stderr, /drift-policy/i);
    assert.doesNotMatch(run.stderr, /Ctrl-C to stop/, 'must fail before ever printing the startup banner / entering the watch loop');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('cli/dataflow-watch-4: a --drift-policy file with the wrong top-level shape is a clear exit-2 error, not a silent zero-rules pass', () => {
  const dir = mkGitFixture(AI_SINK_NO_PHI_SOURCE);
  try {
    const rulesPolicyFile = path.join(dir, 'rules-drift-policy.json');
    fs.writeFileSync(rulesPolicyFile, JSON.stringify({ rules: [{ trigger: 'new_flow' }] }));
    const run = spawnSync(process.execPath, [BIN, 'dataflow', 'watch', dir, '--drift-policy', rulesPolicyFile], {
      encoding: 'utf8', timeout: 20000,
    });
    assert.equal(run.status, 2, `expected exit 2; got ${run.status}. stderr=${run.stderr}`);
    assert.match(run.stderr, /drift-policy/i);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('cli/dataflow-watch-5: no lineage build possible (seed scan produces no scan.lineageGraph) is a clear exit-1 error, not a crash, and never enters the watch loop', () => {
  // A real, externally-triggered "buildLineageGraph produced nothing" is
  // not practically reachable through any real filesystem target this
  // suite could construct — confirmed empirically (2026-09-02): an empty
  // directory, a nonexistent directory, a broken symlink, and an
  // unreadable file all still produce a valid (possibly empty)
  // scan.lineageGraph, because src/lineage/index.js's own
  // buildLineageGraph and the per-file IR build are both deliberately
  // resilient (the ONLY way scan.lineageGraph stays null in production is
  // a genuine internal engine fault, which test/lineage-fault-injection.
  // test.js already covers by mocking buildCallGraph in-process). This
  // test reaches the same real, shipped exit-1 code path from a REAL
  // subprocess instead, by using Node's own `module.register()` loader
  // hook (node:module, stable since Node 20.6+, well within this repo's
  // Node >= 24 floor) to substitute a `buildLineageGraph` that reports
  // `status: 'failed'` for `src/lineage/index.js` specifically — no
  // production code is touched or mocked in-process; `cmdDataflowWatch`
  // still runs as the real, unmodified CLI code against a real subprocess.
  const dir = mkGitFixture(AI_SINK_NO_PHI_SOURCE);
  const loaderDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dataflow-watch-loader-'));
  try {
    const hooksPath = path.join(loaderDir, 'hooks.mjs');
    fs.writeFileSync(hooksPath, `
export async function load(url, context, nextLoad) {
  if (url.endsWith('/src/lineage/index.js')) {
    return {
      format: 'module',
      shortCircuit: true,
      source: "export function buildLineageGraph() { return { status: 'failed', graph: null, transitEvidence: new Map(), failure: 'TEST-INJECTED lineage failure', elapsedMs: 0 }; }",
    };
  }
  return nextLoad(url, context);
}
`);
    const bootstrapPath = path.join(loaderDir, 'bootstrap.mjs');
    fs.writeFileSync(bootstrapPath, `
import { register } from 'node:module';
register(${JSON.stringify(hooksPath)}, import.meta.url);
`);

    const run = spawnSync(process.execPath, ['--import', bootstrapPath, BIN, 'dataflow', 'watch', dir], {
      encoding: 'utf8', timeout: 30000,
    });
    assert.equal(run.status, 1, `expected exit 1; got ${run.status}. stdout=${run.stdout} stderr=${run.stderr}`);
    assert.match(run.stderr, /seed scan produced no data-flow graph/);
    assert.match(run.stderr, /TEST-INJECTED lineage failure/, 'the real lineageStatus.failure reason must be surfaced, not swallowed');
    assert.doesNotMatch(run.stderr, /\[watch-dataflow\] \+\d+\/-\d+ flows/, 'must never enter the watch/rescan loop');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
    fs.rmSync(loaderDir, { recursive: true, force: true });
  }
}, { timeout: 40000 });

test('cli/dataflow-watch-6: `agentic-security dataflow <unknown>` names all real subcommands, including "watch", "scenario", "impact", "observations", and "twin"', () => {
  const run = spawnSync(process.execPath, [BIN, 'dataflow', 'bogus'], { encoding: 'utf8', timeout: 20000 });
  assert.equal(run.status, 2);
  assert.match(run.stderr, /"export", "diff", "watch", "scenario", "impact", "observations", and "twin"/);
});
