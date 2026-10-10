#!/usr/bin/env node
// Release closure (REL-001): the new assurance suites and the existing controller,
// smoke, build/bundle-source, documentation, scorecard and compatibility checks,
// run against ONE exact commit, with a record that binds every suite version and
// log to that commit.
//
// Three rules, each enforced in code and pinned by a test:
//   1. A record is evidence about a commit, not about a directory. It names the
//      commit and tree it ran against. A dirty tree, a different commit, a suite
//      whose test files or script changed after it ran, a step the plan has but the
//      record lacks, or a step the record has but the plan lacks all invalidate it.
//   2. A step whose prerequisite is not available here is `unsupported`, never
//      `pass`. A step that can only be satisfied by hosted CI (a toolchain or a
//      host this machine does not have) is a REMOTE prerequisite: it is listed as
//      pending, it is never counted as a passing local gate, and the record is not
//      publishable until a matching-commit attestation for that step is supplied.
//   3. A skipped or todo test, a zero-test run, or a non-zero exit is not a pass.
//
// The record is written outside the tracked tree (default .agentic-security/release-
// closure/), so running the gate never dirties the tree it is measuring.
//
//   node scripts/release-closure.mjs --static               # cheap plan integrity checks (pre-push)
//   node scripts/release-closure.mjs --run [--out <dir>] [--only id,id]
//   node scripts/release-closure.mjs --verify <record.json>
//   node scripts/release-closure.mjs --list
// Exit: 0 local gate holds / 1 it does not / 2 bad arguments.

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { digestOf } from '../scanner/src/posture/assurance/identity.js';
import { SCOPES as UNIT_TEST_SCOPES } from './run-unit-tests.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..');

export const CLOSURE_SCHEMA = 'agentic-security/release-closure@1';
export const DEFAULT_OUT = path.join('.agentic-security', 'release-closure');
const LOG_TAIL_NOTE_BYTES = 64 * 1024 * 1024;

// The areas REL-001.AC01 and AC03 name. The static check fails when any has no step.
export const REQUIRED_AREAS = Object.freeze([
  'new-suites', 'controller', 'smoke', 'build', 'bundle-source', 'documentation', 'scorecard',
  'compat-haskell-nix', 'compat-core-language',
]);

// Files the foundation suite runs; kept equal to scripts/assurance-differentiation/test/foundation.test.js by a test.
export const FOUNDATION_FILES = Object.freeze([
  'test/posture/assurance-config.test.js', 'test/posture/assurance-contracts.test.js', 'test/posture/assurance-baseline.test.js',
  'test/evidence-issuer.test.js', 'test/trust-boundary.test.js',
]);

const npm = (script, extra = {}) => ({ run: { type: 'npm', script, expectTests: script.startsWith('test:') }, ...extra });

/**
 * The plan. `area` ties a step to a REL-001 requirement; `covers` names the PRD
 * requirements a new suite closes. `needs` is what the step cannot run without;
 * `remote: { job }` marks a prerequisite only hosted CI can satisfy, naming the CI job that does.
 */
export const CLOSURE_STEPS = Object.freeze([
  { id: 'foundation', title: 'Foundation: baseline, contracts, trust boundary, issuer, configuration', area: 'new-suites', covers: ['CORE-001', 'CORE-002', 'CORE-003', 'CORE-004'], run: { type: 'node-test', files: FOUNDATION_FILES, expectTests: true }, timeoutSec: 600 },
  { id: 'evaluation', title: 'Real-code evaluation suite', area: 'new-suites', covers: ['QA-001', 'QA-008'], ...npm('test:evaluation'), timeoutSec: 1800 },
  { id: 'verification', title: 'Verification and oracles suite', area: 'new-suites', covers: ['X-201', 'X-208'], ...npm('test:verification'), timeoutSec: 900 },
  { id: 'deployment', title: 'Deployment-aware boundaries suite', area: 'new-suites', covers: ['X-301', 'X-308'], ...npm('test:deployment'), timeoutSec: 900 },
  { id: 'invariants', title: 'Business invariants suite', area: 'new-suites', covers: ['X-401', 'X-408'], ...npm('test:invariants'), timeoutSec: 900 },
  { id: 'capabilities', title: 'Agent capability enforcement suite', area: 'new-suites', covers: ['X-501', 'X-508'], ...npm('test:capabilities'), timeoutSec: 900 },
  { id: 'routing', title: 'Calibrated model routing suite', area: 'new-suites', covers: ['X-601', 'X-608'], ...npm('test:routing'), timeoutSec: 900 },
  { id: 'portfolio', title: 'Portfolio and release assurance suite', area: 'new-suites', covers: ['X-701', 'X-708'], ...npm('test:portfolio'), timeoutSec: 900 },
  { id: 'documentation-suite', title: 'Documentation suite', area: 'new-suites', covers: ['DOC-001', 'DOC-003'], ...npm('test:documentation'), timeoutSec: 600 },
  { id: 'release-closure-suite', title: 'Release closure and rollout suite', area: 'new-suites', covers: ['REL-001', 'REL-002'], ...npm('test:release-closure'), timeoutSec: 600 },
  // test:loop is deliberately outside `npm test` (scripts/run-unit-tests.mjs excludes it), so the closure is where the full test run meets it.
  { id: 'controller', title: 'Implementation controller suite', area: 'controller', covers: ['LOOP-001', 'LOOP-004'], ...npm('test:loop'), timeoutSec: 1800, outsideTestSuite: true },
  { id: 'smoke', title: 'Smoke tests', area: 'smoke', covers: [], ...npm('test:smoke'), timeoutSec: 600 },
  { id: 'bundle-source', title: 'Committed bundle equals a fresh build of the source (runs the build)', area: 'bundle-source', covers: [], ...npm('check:bundle-source'), timeoutSec: 1200 },
  { id: 'doc-drift', title: 'Documentation drift and links', area: 'documentation', covers: [], ...npm('check-doc-drift'), timeoutSec: 600 },
  { id: 'doc-language', title: 'Generated language documentation is current', area: 'documentation', covers: [], ...npm('docs:check-language'), timeoutSec: 600 },
  { id: 'scorecard', title: 'Committed scorecard describes this version', area: 'scorecard', covers: [], ...npm('scorecard:check'), timeoutSec: 300 },
  { id: 'compat-haskell', title: 'Haskell behaviour unchanged', area: 'compat-haskell-nix', covers: [], ...npm('test:haskell'), timeoutSec: 900 },
  { id: 'compat-nix', title: 'Nix and NixOS behaviour unchanged', area: 'compat-haskell-nix', covers: [], ...npm('test:nix'), timeoutSec: 900 },
  { id: 'compat-language', title: 'Language registry, ledger and contracts unchanged', area: 'compat-haskell-nix', covers: [], ...npm('test:language'), timeoutSec: 900 },
  { id: 'compat-language-support', title: 'Haskell/Nix support registry matches the stored measurement', area: 'compat-haskell-nix', covers: [], ...npm('bench:language-support:check'), timeoutSec: 300 },
  { id: 'compat-corpus', title: 'CVE-replay corpus across the advertised languages holds', area: 'compat-core-language', covers: [], ...npm('bench:cve-replay:check'), timeoutSec: 900 },
  { id: 'compat-layer-recall', title: 'Per-layer, per-language recall holds for every first-class language', area: 'compat-core-language', covers: [], ...npm('bench:layer-recall:check'), timeoutSec: 600 },
  // Remote prerequisites. They need a toolchain or a host this machine may not have; hosted CI has them. Locally they are
  // `unsupported` and are NEVER counted as passing.
  { id: 'remote-haskell-toolchain', title: 'Haskell tests that need a real GHC toolchain', area: 'compat-haskell-nix', covers: [], ...npm('test:language-tools'), timeoutSec: 900, needs: { tools: ['ghc'], haskellModules: ['Web.Scotty', 'Network.Wai', 'Servant', 'Yesod'] }, remote: { job: 'language-tools-ghc' } },
  { id: 'remote-nixos-host', title: 'NixOS host runtime suite (needs a real NixOS host)', area: 'compat-haskell-nix', covers: [], ...npm('test:nixos-host'), timeoutSec: 900, needs: { paths: ['/etc/NIXOS'] }, remote: { job: 'nixos-runtime' } },
]);

// ---------------------------------------------------------------- pure helpers

const sha256 = (b) => crypto.createHash('sha256').update(b).digest('hex');
const FILE_TOKEN = /(?:\.\.\/)?(?:test|scripts|bench)\/[\w.\-/]+\.(?:m?js|py)/g;

/** Files a step reads, relative to scanner/: the test files or helper scripts its command names. */
export function stepFiles(step, pkg) {
  if (step.run.type === 'node-test') return [...step.run.files];
  const text = pkg?.scripts?.[step.run.script] ?? '';
  return [...new Set(text.match(FILE_TOKEN) || [])];
}

/**
 * The version of one suite: the exact script text plus the digest of every file the
 * script names. A change to either changes the version, so a record cannot be reused
 * across an edited suite. A file that cannot be read is recorded as missing, not skipped.
 */
export function suiteVersionOf(step, { pkg, repoRoot = REPO, readFile = (p) => fs.readFileSync(p) } = {}) {
  const scriptText = step.run.type === 'npm' ? (pkg?.scripts?.[step.run.script] ?? null) : `node --test ${step.run.files.join(' ')}`;
  const files = stepFiles(step, pkg).sort().map((f) => {
    let digest = 'missing';
    try { digest = sha256(readFile(path.resolve(repoRoot, 'scanner', f))); } catch { /* recorded as missing */ }
    return { path: f, sha256: digest };
  });
  return digestOf({ script: step.run.type === 'npm' ? step.run.script : 'node-test', scriptText, files });
}

/** What the plan is, independent of any run: ids, areas, commands and needs. */
export function planDigest(steps = CLOSURE_STEPS) {
  return digestOf(steps.map((s) => ({ id: s.id, area: s.area, run: s.run, needs: s.needs ?? null, remote: s.remote ?? null, outsideTestSuite: s.outsideTestSuite ?? false })));
}

/** { applicable } or { applicable: false, reason }. Pure given `env`. */
export function applicability(step, env) {
  const needs = step.needs || {};
  if (needs.platforms && !needs.platforms.includes(env.platform)) return { applicable: false, reason: `needs platform ${needs.platforms.join('/')}, this is ${env.platform}` };
  for (const t of needs.tools || []) if (!env.hasTool(t)) return { applicable: false, reason: `needs the tool '${t}', which is not available here` };
  for (const p of needs.paths || []) if (!env.exists(p)) return { applicable: false, reason: `needs ${p}, which is not present here` };
  for (const m of needs.haskellModules || []) if (!env.canImportHaskell?.(m)) return { applicable: false, reason: `needs the Haskell module '${m}' importable by ghc, which it is not here` };
  return { applicable: true };
}

/** Counts from the node test runner's default reporter ("ℹ tests 12"). null when absent. */
export function parseCounts(text) {
  const grab = (k) => { const m = new RegExp(`^ℹ ${k} (\\d+)\\s*$`, 'm').exec(text); return m ? Number(m[1]) : null; };
  const c = { tests: grab('tests'), pass: grab('pass'), fail: grab('fail'), skipped: grab('skipped'), todo: grab('todo') };
  return c.tests === null ? null : c;
}

/** The state a finished step earns. Fail closed: only a clean, complete run is `pass`. */
export function stepState({ exitCode, signal, timedOut, counts, expectTests }) {
  if (timedOut) return { state: 'fail', reason: 'timed out and was killed' };
  if (signal) return { state: 'fail', reason: `ended by ${signal}` };
  if (exitCode !== 0) return { state: 'fail', reason: `exit ${exitCode}` };
  if (expectTests) {
    if (!counts || counts.tests === 0) return { state: 'fail', reason: 'exited 0 but ran zero tests' };
    if ((counts.fail ?? 0) > 0) return { state: 'fail', reason: `${counts.fail} failing test(s) despite exit 0` };
    if ((counts.skipped ?? 0) > 0 || (counts.todo ?? 0) > 0) return { state: 'incomplete', reason: `${counts.skipped ?? 0} skipped and ${counts.todo ?? 0} todo test(s); a skip is a gap, not a pass` };
  }
  return { state: 'pass', reason: null };
}

/**
 * Judge a record against the current checkout.
 *   current: { commit, tree, dirtyPaths }
 *   opts:    { steps, pkg, repoRoot, readFile, readLog(stepRecord) -> Buffer|null, attestations: [{ stepId, commit, conclusion, source }], requireLogs }
 * -> { localOk, publishable, reasons[], remotePending[] }
 * `reasons` block even the local gate; `remotePending` only blocks publishable evidence.
 */
export function evaluateClosureRecord(record, current, opts = {}) {
  const { steps = CLOSURE_STEPS, pkg = null, repoRoot = REPO, readFile, readLog = null, attestations = [], requireLogs = true } = opts;
  const reasons = [];
  const remotePending = [];
  if (!record || typeof record !== 'object' || record.schema !== CLOSURE_SCHEMA) {
    return { localOk: false, publishable: false, reasons: [`not a ${CLOSURE_SCHEMA} record`], remotePending };
  }
  if (!current || !current.commit) reasons.push('the current commit cannot be determined, so the record cannot be bound to anything');
  else if (record.commit !== current.commit) reasons.push(`the record is bound to commit ${String(record.commit).slice(0, 12)}, not the current ${current.commit.slice(0, 12)}`);
  if (current?.tree && record.tree !== current.tree) reasons.push('the record is bound to a different tree than the current one');
  if ((current?.dirtyPaths || []).length) reasons.push(`the working tree is dirty (${current.dirtyPaths.length} path(s)); dirty inputs invalidate publishable release evidence`);
  if (record.treeClean !== true) reasons.push('the record was produced on a dirty or unverifiable tree');
  if (record.stable !== true) reasons.push('the tree or commit changed while the closure ran');
  if (record.planDigest !== planDigest(steps)) reasons.push('the closure plan changed since the record was produced');
  const byId = new Map((record.steps || []).map((s) => [s.id, s]));
  for (const id of byId.keys()) if (!steps.some((s) => s.id === id)) reasons.push(`the record names step '${id}', which is not in the plan (unrecorded input)`);

  for (const step of steps) {
    const rec = byId.get(step.id);
    if (!rec) { reasons.push(`step '${step.id}' is in the plan but has no recorded result`); continue; }
    const nowVersion = suiteVersionOf(step, { pkg, repoRoot, readFile });
    if (rec.suiteVersion !== nowVersion) { reasons.push(`step '${step.id}': its suite changed since it ran (recorded ${String(rec.suiteVersion).slice(0, 19)}..., now ${nowVersion.slice(0, 19)}...)`); continue; }
    if (rec.state === 'pass') {
      if (!/^[0-9a-f]{64}$/.test(rec.log?.sha256 || '')) { reasons.push(`step '${step.id}': passed but has no recorded log digest`); continue; }
      if (readLog) {
        const bytes = readLog(rec);
        if (bytes == null) { if (requireLogs) reasons.push(`step '${step.id}': its log is not retained, so the result cannot be re-checked`); }
        else if (sha256(bytes) !== rec.log.sha256) reasons.push(`step '${step.id}': its log no longer matches the recorded digest`);
      }
      continue;
    }
    if (step.remote && rec.state === 'unsupported') {
      const att = attestations.find((a) => a.stepId === step.id && a.commit === record.commit && a.conclusion === 'success');
      if (!att) remotePending.push({ id: step.id, job: step.remote.job, state: rec.state, reason: rec.reason });
      continue;
    }
    reasons.push(`step '${step.id}' is ${rec.state}${rec.reason ? `: ${rec.reason}` : ''}`);
  }
  const localOk = reasons.length === 0;
  return { localOk, publishable: localOk && remotePending.length === 0, reasons, remotePending };
}

// ---------------------------------------------------------------- static plan checks

/** Cheap integrity checks on the plan itself. Returns an array of problems; empty means sound. */
export function checkClosurePlan({ steps = CLOSURE_STEPS, pkg, repoRoot = REPO, scopes = UNIT_TEST_SCOPES, releaseGroups = null, ciJobs = null } = {}) {
  const problems = [];
  const ids = steps.map((s) => s.id);
  for (const id of ids) if (ids.filter((x) => x === id).length > 1) problems.push(`duplicate step id '${id}'`);
  for (const area of REQUIRED_AREAS) {
    if (area === 'build') { if (!steps.some((s) => s.area === 'bundle-source')) problems.push("no step covers the build (the bundle-source step runs it)"); continue; }
    if (!steps.some((s) => s.area === area)) problems.push(`no step covers required area '${area}'`);
  }
  for (const s of steps) {
    if (s.run.type === 'npm') {
      if (typeof pkg?.scripts?.[s.run.script] !== 'string') problems.push(`step '${s.id}': scanner/package.json has no script '${s.run.script}'`);
      const m = /^test:(.+)$/.exec(s.run.script);
      if (m && !s.remote && !s.outsideTestSuite && /node --test/.test(pkg?.scripts?.[s.run.script] || '') && !scopes.includes(m[1])) problems.push(`step '${s.id}': test:${m[1]} is not in SCOPES, so the full test suite would not run it`);
    } else {
      for (const f of s.run.files) if (!fs.existsSync(path.join(repoRoot, 'scanner', f))) problems.push(`step '${s.id}': missing test file scanner/${f}`);
    }
    for (const f of stepFiles(s, pkg)) if (!fs.existsSync(path.join(repoRoot, 'scanner', f))) problems.push(`step '${s.id}': names ${f}, which does not exist`);
    if (s.remote && (!s.needs || !(s.needs.tools?.length || s.needs.paths?.length || s.needs.platforms?.length || s.needs.haskellModules?.length))) problems.push(`remote step '${s.id}' declares no local prerequisite, so it could never be reported unsupported`);
    if (s.remote && ciJobs && !ciJobs.includes(s.remote.job)) problems.push(`remote step '${s.id}': hosted CI job '${s.remote.job}' does not exist in .github/workflows/ci.yml`);
  }
  if (releaseGroups) {
    const named = Object.values(releaseGroups).flat();
    if (!named.includes('release-closure-gate')) problems.push("release-closure-gate is not in any named RELEASE_GROUPS entry (it would run only in `rest`, serially behind the cheap checks)");
  }
  return problems;
}

// ---------------------------------------------------------------- running

// Every command runs inside its own process group, killed as a whole on timeout and again when the command ends, so a hung step cannot leave
// a process tree behind (a plain timeout kills only the direct child: an orphaned test runner outlived its step by 25 minutes this way).
const GROUP_RUNNER = `
import { spawn, spawnSync } from 'node:child_process';
const [ms, cmd, ...args] = process.argv.slice(1);
const c = spawn(cmd, args, { stdio: 'inherit', detached: true });
let timedOut = false;
const killGroup = () => { try { process.kill(-c.pid, 'SIGKILL'); } catch { /* the group is already gone */ } };
const NL = String.fromCharCode(10);
// Before a timed-out group is killed, say what is in it and (on macOS) what each process is blocked in, so a hang that cannot be reproduced
// leaves its evidence in the step log instead of only a timeout.
const snapshot = () => {
  try {
    const ps = spawnSync('ps', ['-axo', 'pid,ppid,pgid,etime,state,pcpu,command'], { encoding: 'utf8' });
    const rows = (ps.stdout || '').split(NL).filter((l) => l.trim().split(/\\s+/)[2] === String(c.pid));
    console.error(NL + '--- closure runner: the step timed out; processes in its group ---' + NL + rows.join(NL));
    if (process.platform === 'darwin') {
      for (const l of rows.slice(0, 8)) {
        const pid = l.trim().split(/\\s+/)[0];
        if (!pid) continue;
        const sm = spawnSync('sample', [pid, '1', '-mayDie'], { encoding: 'utf8', timeout: 20000 });
        console.error('--- sample of ' + pid + ' ---' + NL + (sm.stdout || '').split(NL).slice(0, 70).join(NL));
      }
    }
  } catch { /* diagnostics must never change the outcome */ }
};
const t = setTimeout(() => { timedOut = true; snapshot(); killGroup(); }, Number(ms));
c.on('error', (e) => { console.error('could not start: ' + e.message); process.exit(127); });
c.on('exit', (code, sig) => { clearTimeout(t); killGroup(); process.exit(timedOut ? 124 : (code ?? (sig ? 128 : 1))); });
`;

export function defaultExec(cmd, args, { cwd, timeoutMs, env }) {
  const r = spawnSync(process.execPath, ['--input-type=module', '-e', GROUP_RUNNER, String(timeoutMs), cmd, ...args],
    { cwd, encoding: 'buffer', timeout: timeoutMs + 15_000, maxBuffer: 512 * 1024 * 1024, killSignal: 'SIGKILL', env });
  const timedOut = r.status === 124 || r.error?.code === 'ETIMEDOUT';
  return { status: timedOut ? null : r.status, signal: r.signal, timedOut, error: r.error && r.error.code !== 'ETIMEDOUT' ? String(r.error.message) : null, stdout: r.stdout || Buffer.alloc(0), stderr: r.stderr || Buffer.alloc(0) };
}

/** Tracked files the bench runners append to; modified copies of exactly these do not count as a dirty tree. */
export const GENERATED_OUTPUTS = Object.freeze(['bench/memory/history.jsonl', 'bench/provenance/history.jsonl', 'bench/ttff/history.jsonl']);

export function gitFacts(repoRoot, exec = defaultExec) {
  const g = (args) => { const r = exec('git', args, { cwd: repoRoot, timeoutMs: 60_000, env: process.env }); return r.status === 0 ? r.stdout.toString('utf8') : null; };
  const commit = g(['rev-parse', 'HEAD'])?.trim() || null;
  const tree = g(['rev-parse', 'HEAD^{tree}'])?.trim() || null;
  const porcelain = g(['status', '--porcelain']);
  const entries = porcelain === null ? null : porcelain.split('\n').filter(Boolean).map((l) => ({ code: l.slice(0, 2), path: l.slice(3) }));
  // The bench runners append to these tracked files on every run. They are outputs, never inputs to any step, so a modified (not deleted,
  // not replaced) one does not make the tree dirty; they are listed in the record so nothing is hidden.
  const isGenerated = (e) => GENERATED_OUTPUTS.includes(e.path) && e.code.trim() === 'M';
  const dirtyPaths = entries === null ? ['(git status failed)'] : entries.filter((e) => !isGenerated(e)).map((e) => e.path);
  const ignoredGeneratedOutputs = entries === null ? [] : entries.filter(isGenerated).map((e) => e.path);
  return { commit, tree, dirtyPaths, ignoredGeneratedOutputs };
}

function defaultEnv(repoRoot, exec = defaultExec) {
  return {
    platform: process.platform,
    hasTool: (t) => exec(process.platform === 'win32' ? 'where' : 'which', [t], { cwd: repoRoot, timeoutMs: 10_000, env: process.env }).status === 0,
    exists: (p) => fs.existsSync(p),
    canImportHaskell: (m) => exec('ghc', ['-e', `import ${m}`], { cwd: repoRoot, timeoutMs: 60_000, env: process.env }).status === 0,
  };
}

/**
 * Run the plan against the current commit. Writes one log per step and the record under `outDir`.
 * Returns the record (also written). Nothing here edits the tracked tree.
 */
export function runClosure({ repoRoot = REPO, steps = CLOSURE_STEPS, outDir, only = null, exec = defaultExec, env = null, now = () => new Date().toISOString(), log = () => {} } = {}) {
  const pkg = JSON.parse(fs.readFileSync(path.join(repoRoot, 'scanner', 'package.json'), 'utf8'));
  const e = env || defaultEnv(repoRoot, exec);
  const before = gitFacts(repoRoot, exec);
  const base = outDir || path.join(repoRoot, DEFAULT_OUT);
  const logDir = path.join(base, (before.commit || 'unknown').slice(0, 12));
  fs.mkdirSync(logDir, { recursive: true });
  const selected = only ? steps.filter((s) => only.includes(s.id)) : steps;
  const results = [];
  for (const step of selected) {
    const version = suiteVersionOf(step, { pkg, repoRoot });
    const app = applicability(step, e);
    const entry = { id: step.id, area: step.area, remote: step.remote ? { job: step.remote.job } : null, suiteVersion: version, startedAt: now() };
    if (!app.applicable) {
      results.push({ ...entry, state: 'unsupported', reason: app.reason, command: null, exitCode: null, counts: null, log: null, endedAt: now() });
      log(`UNSUPPORTED ${step.id}: ${app.reason}${step.remote ? ` (only hosted CI job '${step.remote.job}' can satisfy this; not counted as passing)` : ''}\n`);
      continue;
    }
    const argv = step.run.type === 'npm' ? ['npm', ['run', step.run.script]] : [process.execPath, ['--test', ...step.run.files]];
    log(`RUN         ${step.id}\n`);
    const r = exec(argv[0], argv[1], { cwd: path.join(repoRoot, 'scanner'), timeoutMs: step.timeoutSec * 1000, env: { ...process.env, NO_COLOR: '1', FORCE_COLOR: '0' } });
    const out = Buffer.concat([r.stdout, r.stderr.length ? Buffer.from(`\n--- stderr ---\n`) : Buffer.alloc(0), r.stderr]);
    const logPath = path.join(logDir, `${step.id}.log`);
    fs.writeFileSync(logPath, out);
    const counts = parseCounts(out.toString('utf8'));
    const verdict = r.error ? { state: 'fail', reason: `could not start: ${r.error}` } : stepState({ exitCode: r.status, signal: r.signal, timedOut: r.timedOut, counts, expectTests: step.run.expectTests === true });
    results.push({
      ...entry, state: verdict.state, reason: verdict.reason, command: step.run.type === 'npm' ? `npm run ${step.run.script}` : `node --test ${step.run.files.join(' ')}`,
      exitCode: r.status, counts, log: { path: path.relative(base, logPath), sha256: sha256(out), bytes: out.length, note: out.length > LOG_TAIL_NOTE_BYTES ? 'very large' : undefined }, endedAt: now(),
    });
    log(`${verdict.state.toUpperCase().padEnd(11)} ${step.id}${verdict.reason ? `: ${verdict.reason}` : ''}\n`);
    if (verdict.state !== 'pass') {
      // The step's own log stays on the runner; without its tail a hosted failure reads as a bare "exit 1".
      const text = out.toString('utf8').split('\n').filter((l) => l.trim());
      const failing = text.filter((l) => /^\s*(✖|not ok)\s/.test(l)).slice(0, 12);
      log(`  --- ${step.id}: ${failing.length ? `first ${failing.length} failing test line(s)` : 'last lines of its output'} ---\n${(failing.length ? failing : text.slice(-25)).map((l) => `  | ${l.slice(0, 220)}`).join('\n')}\n`);
    }
  }
  const after = gitFacts(repoRoot, exec);
  const record = {
    schema: CLOSURE_SCHEMA,
    commit: before.commit, tree: before.tree,
    treeClean: before.commit !== null && before.dirtyPaths.length === 0,
    dirtyPaths: before.dirtyPaths,
    ignoredGeneratedOutputs: before.ignoredGeneratedOutputs,
    stable: before.commit === after.commit && before.tree === after.tree && JSON.stringify(before.dirtyPaths) === JSON.stringify(after.dirtyPaths),
    planDigest: planDigest(steps),
    partial: Boolean(only) && selected.length !== steps.length,
    environment: { node: process.version, platform: process.platform, arch: process.arch },
    steps: results,
  };
  fs.writeFileSync(path.join(base, `${(before.commit || 'unknown').slice(0, 12)}.json`), `${JSON.stringify(record, null, 2)}\n`);
  return { record, base };
}

export function readLogFor(base) {
  return (rec) => { try { return fs.readFileSync(path.join(base, rec.log.path)); } catch { return null; } };
}

// ---------------------------------------------------------------- CLI

function ciJobNames(repoRoot) {
  try { return [...fs.readFileSync(path.join(repoRoot, '.github', 'workflows', 'ci.yml'), 'utf8').matchAll(/^ {2}([a-z0-9-]+):\s*$/gm)].map((m) => m[1]); } catch { return null; }
}

export async function main(argv, { out = process.stderr } = {}) {
  const has = (f) => argv.includes(f);
  const val = (f) => { const i = argv.indexOf(f); return i === -1 ? null : argv[i + 1]; };
  const pkg = JSON.parse(fs.readFileSync(path.join(REPO, 'scanner', 'package.json'), 'utf8'));
  if (has('--list')) { for (const s of CLOSURE_STEPS) out.write(`${s.id.padEnd(26)} ${s.area.padEnd(22)} ${s.remote ? `remote(${s.remote.job})` : 'local'}\n`); return 0; }
  if (has('--static')) {
    const { RELEASE_GROUPS } = await import('./release-check.mjs');
    const problems = checkClosurePlan({ pkg, releaseGroups: RELEASE_GROUPS, ciJobs: ciJobNames(REPO) });
    if (problems.length) { out.write(`release closure plan is unsound:\n${problems.map((p) => `  - ${p}`).join('\n')}\n`); return 1; }
    out.write(`release closure plan is sound (${CLOSURE_STEPS.length} steps, ${REQUIRED_AREAS.length} required areas covered)\n`);
    return 0;
  }
  if (has('--verify')) {
    const file = val('--verify');
    if (!file) { out.write('--verify needs a record path\n'); return 2; }
    let record;
    try { record = JSON.parse(fs.readFileSync(file, 'utf8')); } catch (e) { out.write(`cannot read ${file}: ${e.message}\n`); return 1; }
    const v = evaluateClosureRecord(record, gitFacts(REPO), { pkg, readLog: readLogFor(path.dirname(file)) });
    return report(v, out);
  }
  if (has('--run')) {
    const only = val('--only') ? val('--only').split(',').map((x) => x.trim()).filter(Boolean) : null;
    const outDir = val('--out') ? path.resolve(val('--out')) : null;
    const { record, base } = runClosure({ outDir, only, log: (m) => out.write(`  ${m}`) });
    if (record.partial) { out.write('PARTIAL closure (--only): never publishable and never the release gate.\n'); }
    const v = evaluateClosureRecord(record, gitFacts(REPO), { pkg, readLog: readLogFor(base) });
    out.write(`record: ${path.join(base, `${record.commit.slice(0, 12)}.json`)}\n`);
    return record.partial ? 1 : report(v, out);
  }
  out.write('usage: release-closure.mjs --static | --run [--out dir] [--only ids] | --verify <record> | --list\n');
  return 2;
}

function report(v, out) {
  for (const r of v.reasons) out.write(`  FAIL ${r}\n`);
  for (const p of v.remotePending) out.write(`  NOT COUNTED (remote prerequisite) ${p.id}: ${p.state}${p.reason ? ` (${p.reason})` : ''}; satisfied only by hosted CI job '${p.job}' for this commit\n`);
  out.write(v.localOk
    ? `local release closure holds${v.publishable ? '; publishable' : '; NOT publishable until the remote prerequisites above are attested for this commit'}\n`
    : 'local release closure does NOT hold\n');
  return v.localOk ? 0 : 1;
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) main(process.argv.slice(2)).then((c) => process.exit(c));
