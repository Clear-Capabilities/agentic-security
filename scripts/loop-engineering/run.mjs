#!/usr/bin/env node
// Supervised-loop CLI. Every subcommand parses its options strictly: an unknown
// flag is an error, never ignored. See docs/guides/loop-engineering.md.
import { spawn } from 'node:child_process';
import { execBoundedSync, configureBounds } from './lib/bounds.mjs';
import { openSync, closeSync, mkdirSync, statfsSync, existsSync, writeFileSync, unlinkSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import net from 'node:net';
import { parseArgs, UsageError } from './lib/args.mjs';
import {
  layout, ensureBase, newRunId, currentRunId, setCurrentRun, judgeLease, appendEvent, readEvents,
  acquireRunLock, releaseRunLock, evidenceKey, HEARTBEAT_MS, readStateFile,
} from './lib/state.mjs';
import { atomicWriteJson, readJson, nowIso, sleep, redact } from './lib/util.mjs';
import { loadProfile, validateProfile, ProfileError, insideRepo, suiteLaunchBlockers } from './lib/profile.mjs';
import { createManifest, writeManifest, loadManifest, checkPrdFresh } from './lib/manifest.mjs';
import { ImportError } from './lib/prd-import.mjs';
import { TreeIndex } from './lib/tree.mjs';
import { assessAll, computeProgress } from './lib/progress.mjs';
import { verifyRequirement, toolAvailable } from './lib/verifier.mjs';
import { buildStatus, commandsFor, isTerminal } from './lib/status.mjs';
import { captureFrozenInputs } from './lib/drift.mjs';
import { buildCompletionReport } from './lib/report.mjs';
import { initialState, startController } from './lib/controller.mjs';
import { runGuardian } from './lib/guardian.mjs';
import { runBounded, reapOwned } from './lib/proc.mjs';
import { identityMatches, signalIdentity, startTimeOf } from './lib/procscan.mjs';
import { registerOpLease, MAX_LEASE_SECONDS } from './lib/oplease.mjs';
import { resolveBinary, detectClaude, authStatus, buildWorkerArgs } from './lib/claude.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const RUN_MJS = fileURLToPath(import.meta.url);
const REPO_ROOT = resolve(process.env.LOOP_ENGINEERING_REPO || resolve(HERE, '..', '..'));
const DEFAULT_PROFILE = 'scripts/loop-engineering/profiles/haskell-nix.json';

const USAGE = `usage: node scripts/loop-engineering/run.mjs <command> [options]

  init --prd <path> --profile <path>     freeze the manifest, capture baseline, create the run record
  preflight                              validate runtime, auth, permissions, budgets, tools, disk, port (never logs in)
  start --background [--serve host:port] detach an OS-owned controller (returns within 5s)
  start --foreground [--serve host:port] run the same controller attached, for debugging
  status [--json] [--run <id>]           liveness-checked status (returns within 2s)
  verify --requirement <id>              run that requirement's registered suite and issue evidence
  verify --all --final                   re-verify every criterion + release gates against one stable tree
  pause | resume                         checkpoint / continue (resume also restarts a dead controller)
  retry --requirement <id>               skip a backoff or re-evaluate an external blocker (caps are not bypassed)
  stop --run <id>                        stop this controller's owned processes, checkpoint, close the dashboard
  report [--json] [--write]              completion report: unmet criteria, blockers, budget stops, evidence paths, next commands
  plan --next                            print the next dependency-ready requirement without starting a worker
  exec --deadline <s> [--label x] -- <cmd...>   run a command under a registered, bounded operation lease
`;

// Loading the profile in force also configures the controller's own subprocess and network bounds from its limits.
function loadProfileBounded(path) { const r = loadProfile(path); configureBounds(r.profile.limits); return r; }

const out = (s = '') => process.stdout.write(s + '\n');
const err = (s) => process.stderr.write(s + '\n');

function gitInfo(root) {
  const g = (...a) => { try { return execBoundedSync('git', a, { cwd: root, wallSeconds: 15 }).trim(); } catch { return null; } };
  const status = g('status', '--porcelain') || '';
  return { head: g('rev-parse', 'HEAD'), branch: g('rev-parse', '--abbrev-ref', 'HEAD'), dirtyFiles: status.split('\n').filter(Boolean).map((l) => l.slice(3)), dirtyCount: status ? status.split('\n').filter(Boolean).length : 0 };
}

function toolVersions() {
  const v = {};
  v.node = process.version;
  for (const [name, args] of [['npm', ['--version']], ['git', ['--version']], ['python3', ['--version']], ['claude', ['--version']], ['nix', ['--version']], ['ghc', ['--version']], ['cabal', ['--version']], ['stack', ['--version']]]) {
    try { v[name] = execBoundedSync(name, args, { wallSeconds: 8 }).trim().split('\n')[0]; } catch { v[name] = null; }
  }
  return v;
}

function loadRunContext(repoRoot, runIdArg = null) {
  const runId = runIdArg || currentRunId(repoRoot);
  if (!runId) throw new UsageError('no run exists yet: run `init` first');
  const L = layout(repoRoot, runId);
  const state = readStateFile(L).state;
  if (!state) throw new UsageError(`run ${runId} has no state file`);
  return { runId, L, state };
}

function nextControlSeq(L) { return (readJson(L.controlFile, { seq: 0 }).seq || 0) + 1; }

async function sendControl(L, command, extra = {}, waitMs = 8000) {
  const seq = nextControlSeq(L);
  atomicWriteJson(L.controlFile, { seq, command, ...extra, requestedAt: nowIso() });
  const end = Date.now() + waitMs;
  while (Date.now() < end) {
    const s = readJson(L.stateFile, null);
    if (s?.control?.ack && s.control.ack.seq >= seq) return s.control.ack;
    const lease = judgeLease(L.leaseFile);
    if (lease.state !== 'live') return { seq, command, result: `no live controller (${lease.state})` };
    await sleep(150);
  }
  return { seq, command, result: 'no acknowledgement within the wait window' };
}

// ---------------------------------------------------------------- init
async function cmdInit(argv) {
  const a = parseArgs(argv, { flags: { prd: { type: 'string', required: true }, profile: { type: 'string', required: true }, 'skip-baseline-gates': { type: 'boolean' }, 'allow-scope-shrink': { type: 'boolean' } } });
  if (a['allow-scope-shrink']) throw new UsageError('--allow-scope-shrink is not supported: the denominator may only grow');
  const root = REPO_ROOT;
  if (!insideRepo(root, a.prd) || !insideRepo(root, a.profile)) throw new UsageError('--prd and --profile must be relative paths inside the repository');
  ensureBase(root);
  const cur = currentRunId(root);
  if (cur) {
    const L0 = layout(root, cur); const st = readJson(L0.stateFile, null);
    const lease = judgeLease(L0.leaseFile);
    if (st && lease.state === 'live' && !isTerminal(st.status)) throw new UsageError(`run ${cur} is active; stop it before re-initialising`);
  }
  const { profile, sha256: psha } = loadProfileBounded(resolve(root, a.profile));
  validateProfile(profile, root);
  const checkout = gitInfo(root);
  const tools = toolVersions();
  const baselineGates = [];
  if (!a['skip-baseline-gates']) {
    out(`recording baseline gate results (${profile.baselineGates.length} gates, each bounded)...`);
    for (const g of profile.baselineGates) {
      if (g.costUsd !== undefined || g.costUnknown) {
        baselineGates.push({ id: g.id, argv: [g.executable, ...g.args], exitCode: null, outcome: 'skipped-paid', ok: false, recordedAt: nowIso(), note: 'a paid step is metered against the provider envelope by the controller, which is not running yet; it was not run at init' });
        out(`  ${g.id}: skipped (paid step)`);
        continue;
      }
      const r = await runBounded({ argv: [g.executable, ...g.args], cwd: resolve(root, g.cwd), wallMs: g.timeoutSeconds * 1000, graceMs: 5000, label: `baseline:${g.id}`, env: { ...process.env, NO_COLOR: '1' } });
      baselineGates.push({ id: g.id, argv: [g.executable, ...g.args], exitCode: r.exitCode, outcome: r.outcome, durationMs: r.durationMs, ok: r.outcome === 'exited' && r.exitCode === 0, recordedAt: nowIso(), note: 'baseline result before any loop work; a failure here is pre-existing, not a regression' });
      out(`  ${g.id}: ${r.outcome === 'exited' ? `exit ${r.exitCode}` : r.outcome}`);
    }
  } else {
    for (const g of profile.baselineGates) baselineGates.push({ id: g.id, argv: [g.executable, ...g.args], exitCode: null, outcome: 'skipped', ok: false, recordedAt: nowIso(), note: 'skipped by --skip-baseline-gates; no baseline was recorded' });
  }
  const { manifest, diff, unchanged } = createManifest({ repoRoot: root, prdPath: a.prd, profile, profileSha: psha, checkout, tools, baselineGates });
  if (unchanged) {
    const existing = loadManifest(root);
    out(`manifest v${existing.version} already matches the PRD and profile; nothing changed.`);
  } else {
    const file = writeManifest(root, manifest);
    out(`manifest v${manifest.manifestVersion} written: ${file}`);
    out(`  ${manifest.totals.requirements} requirements, ${manifest.totals.criteria} criteria, ${manifest.totals.weight} weight points; acceptance hash ${manifest.acceptanceHash.slice(0, 16)}`);
    if (diff) out(`  denominator change vs v${manifest.supersedes}: ${JSON.stringify(diff.denominator.before)} -> ${JSON.stringify(diff.denominator.after)}${diff.added.length ? `; added ${diff.added.join(', ')}` : ''}`);
  }
  // Create the run record (or keep the resumable one) so evidence has a home.
  let runId = currentRunId(root);
  const st = runId ? readJson(layout(root, runId).stateFile, null) : null;
  if (!st || st.status === 'completed') {
    runId = newRunId();
    const L = layout(root, runId);
    mkdirSync(L.dir, { recursive: true, mode: 0o700 });
    const m = loadManifest(root).manifest;
    const state = initialState({ runId, manifest: m, profilePath: a.profile, profileSha: psha, repoRoot: root });
    state.status = 'initialized'; state.statusReason = 'created by init; not started';
    state.frozen = captureFrozenInputs({ repoRoot: root, prdPath: a.prd, profile });
    atomicWriteJson(L.stateFile, state);
    setCurrentRun(root, runId);
    appendEvent(L, 'init', { manifestVersion: m.manifestVersion });
  } else {
    const L = layout(root, runId);
    // An explicit re-initialisation is the ONLY way frozen inputs change. It re-freezes them and clears a recorded drift stop.
    const refrozen = captureFrozenInputs({ repoRoot: root, prdPath: a.prd, profile });
    const changed = st.frozen && (st.frozen.prdSha256 !== refrozen.prdSha256 || st.frozen.profileSha256 !== refrozen.profileSha256);
    st.profilePath = a.profile; st.profileSha = psha; st.frozen = refrozen; delete st.drift;
    st.runBlockers = (st.runBlockers || []).filter((b) => b.type !== 'drift');
    if (st.status === 'blocked' && /^drift:/.test(st.statusReason || '')) { st.status = 'initialized'; st.statusReason = 'drift cleared by explicit re-initialisation'; }
    atomicWriteJson(L.stateFile, st);
    if (changed) out('inputs changed since the previous init: evidence bound to the old PRD or acceptance definition is stale and will be re-verified');
    appendEvent(L, 'reinit', { manifestVersion: loadManifest(root).version });
  }
  out(`run record: ${runId} (status ${readJson(layout(root, runId).stateFile).status})`);
  return 0;
}

// ---------------------------------------------------------------- preflight
function portFree(host, port) {
  return new Promise((r) => { const s = net.createServer(); s.once('error', () => r(false)); s.listen(port, host, () => s.close(() => r(true))); });
}

async function cmdPreflight(argv) {
  parseArgs(argv, { flags: { json: { type: 'boolean' } } });
  const json = argv.includes('--json');
  const root = REPO_ROOT;
  const checks = [];
  const add = (check, status, detail) => checks.push({ check, status, detail });
  if (Number(process.versions.node.split('.')[0]) >= 24) add('node', 'pass', process.version); else add('node', 'fail', `${process.version}; Node >= 24 is required`);
  add('platform', ['darwin', 'linux'].includes(process.platform) ? 'pass' : 'fail', `${process.platform} (Windows is unsupported until a Job Object/WSL implementation is tested)`);
  const m = loadManifest(root);
  if (!m.ok) add('manifest', 'fail', m.error); else {
    add('manifest', 'pass', `v${m.version}, ${m.manifest.totals.requirements} requirements, ${m.manifest.totals.criteria} criteria, ${m.manifest.totals.weight} weight`);
    const prd = checkPrdFresh(root, m.manifest);
    add('prd-frozen', prd.ok ? 'pass' : 'fail', prd.ok ? 'PRD hash matches the frozen manifest' : prd.error);
  }
  const runId = currentRunId(root);
  let profile = null;
  const st = runId ? readJson(layout(root, runId).stateFile, null) : null;
  try {
    const p = loadProfileBounded(resolve(root, st?.profilePath || DEFAULT_PROFILE));
    profile = p.profile; validateProfile(profile, root);
    add('profile', 'pass', `${profile.name}; finite budgets: ${profile.limits.runWallSeconds}s wall, ${profile.limits.runMaxAttempts} attempts, $${profile.limits.claudeBudgetUsd}; one worker`);
    add('permissions', 'pass', `scoped allow list (${profile.worker.allowedTools.length} entries), deny list (${profile.worker.disallowedTools.length}), mode ${profile.worker.permissionMode}; no bypass`);
    for (const l of profile.worker.honestLimits || []) add('permission-limit', 'warn', l);
  } catch (e) { add('profile', 'fail', e.message); }
  // process isolation self-test: spawn a child that spawns a detached grandchild, confirm both die
  try {
    const r = await runBounded({ argv: [process.execPath, '-e', "const {spawn}=require('node:child_process');spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{detached:true,stdio:'ignore'}).unref();setInterval(()=>{},1000)"], wallMs: 1500, graceMs: 500, label: 'preflight-isolation' });
    add('process-isolation', r.outcome === 'timeout-wall' && r.orphansKilled.length >= 1 ? 'pass' : 'fail', `owned process-tree cleanup self-test: outcome ${r.outcome}, reclaimed ${r.orphansKilled.length} detached descendant(s)`);
  } catch (e) { add('process-isolation', 'fail', e.message); }
  if (profile) {
    // Claude CLI
    const bin = resolveBinary(profile.worker.command);
    if (!bin) add('claude-cli', 'fail', `\`${profile.worker.command}\` not found on PATH (a shell alias is not an executable)`);
    else {
      const f = await detectClaude(bin);
      if (!f.ok) add('claude-cli', 'fail', 'could not run `claude --version`/`--help`');
      else {
        add('claude-cli', f.missingRequired.length ? 'fail' : 'pass', `${f.version}${f.missingRequired.length ? `; missing required flag(s): ${f.missingRequired.join(', ')}` : ''}`);
        add('claude-permission-prompts', f.has('--permission-prompts') ? 'pass' : 'warn', f.has('--permission-prompts') ? '--permission-prompts none is available; prompts are denied, never awaited' : 'flag not supported by this CLI; `dontAsk` mode denies instead of prompting');
        add('claude-budget-limit', f.has('--max-budget-usd') ? 'pass' : 'fail', f.has('--max-budget-usd') ? `--max-budget-usd enforces the per-attempt ceiling (run total tracked by the controller)` : 'no supported financial limit in this CLI: supply another finite provider/account limit in the profile before running');
        add('claude-turn-limit', f.has('--max-turns') ? 'pass' : 'warn', f.has('--max-turns') ? '--max-turns available' : `no --max-turns flag; the ${profile.limits.claudeMaxTurns}-turn cap is enforced externally by counting stream turns`);
        const auth = await authStatus(bin);
        add('claude-auth', auth.loggedIn ? 'pass' : (auth.known ? 'fail' : 'warn'), auth.loggedIn ? `logged in via ${auth.method} (${auth.provider})` : (auth.known ? 'not logged in: log in interactively; preflight never initiates a login' : `auth state unknown: ${auth.detail}`));
        const args = buildWorkerArgs({ profile, features: f.flags, budgetUsd: profile.limits.perAttemptBudgetUsd });
        const bad = args.filter((x) => /^--(dangerously|allow-dangerously)/.test(x) || x === 'bypassPermissions');
        add('worker-argv', bad.length ? 'fail' : 'pass', bad.length ? `unsafe flag(s) in worker argv: ${bad.join(' ')}` : `${args.filter((x) => x.startsWith('--')).join(' ')}`);
      }
    }
    // tools for verification commands
    const exes = new Set(); const needs = new Set();
    for (const s of Object.values(profile.suites)) { exes.add(s.executable); (s.requiresTools || []).forEach((t) => needs.add(t)); }
    for (const g of [...profile.finalGates, ...profile.baselineGates]) exes.add(g.executable);
    const missing = [...exes].filter((e) => !toolAvailable(e));
    add('verification-executables', missing.length ? 'fail' : 'pass', missing.length ? `not found on PATH: ${missing.join(', ')}; install it, or remove it from approvedExecutables and the suites or gates that use it` : `${[...exes].join(', ')} resolvable`);
    const blocked = suiteLaunchBlockers(profile, root);
    add('suites-runnable', blocked.length ? 'fail' : 'pass', blocked.length ? `${blocked.length} suite(s) cannot run yet: ${blocked.map((b) => `${b.suite} (${b.reason})`).join('; ')}` : 'every registered suite has its executable wrapper in place');
    const optMissing = [...needs].filter((t) => !toolAvailable(t));
    add('optional-tools', optMissing.length ? 'warn' : 'pass', optMissing.length ? `${optMissing.join(', ')} unavailable: requirements needing them will be recorded as typed blockers, not skipped` : 'all suite tool requirements present');
    const hostTools = ['ghc', 'cabal', 'stack', 'nix'].filter((t) => !toolAvailable(t));
    if (hostTools.length) add('host-toolchain', 'warn', `${hostTools.join(', ')} not installed on this host: controlled compile/VM checks that need them cannot run here`);
    // disk
    try {
      const fs = statfsSync(root); const freeGiB = (fs.bavail * fs.bsize) / 2 ** 30;
      add('disk-space', freeGiB >= profile.limits.resource.minFreeDiskGiB ? 'pass' : 'fail', `${freeGiB.toFixed(1)} GiB free (need ${profile.limits.resource.minFreeDiskGiB})`);
    } catch (e) { add('disk-space', 'fail', `cannot read free space: ${e.code || e.message}`); }
    const host = profile.serve.host, port = profile.serve.port;
    const free = await portFree(host, port);
    add('status-port', free ? 'pass' : 'warn', free ? `${host}:${port} is free` : `${host}:${port} is in use; the dashboard will fall back to an ephemeral port and report it`);
  }
  // evidence key + state dir writable
  try { ensureBase(root); evidenceKey(root); add('state-dir', 'pass', `${layout(root).base} writable`); } catch (e) { add('state-dir', 'fail', e.message); }
  const lock = readJson(layout(root).lockFile, null);
  if (lock && identityMatches(lock.pid, lock.start)) add('run-lock', 'warn', `run ${lock.runId} is already active (pid ${lock.pid})`);
  const fails = checks.filter((c) => c.status === 'fail');
  if (json) out(JSON.stringify({ ok: !fails.length, checks }, null, 2));
  else {
    for (const c of checks) out(`${c.status === 'pass' ? 'PASS' : c.status === 'warn' ? 'WARN' : 'FAIL'}  ${c.check}: ${c.detail}`);
    out(fails.length ? `\npreflight FAILED (${fails.length} blocking)` : `\npreflight passed (${checks.filter((c) => c.status === 'warn').length} warnings)`);
  }
  return fails.length ? 1 : 0;
}

// ---------------------------------------------------------------- start / resume
function printStarted(root, runId, info) {
  const st = buildStatus(root, runId);
  out(`run ID:        ${runId}`);
  out(`controller PID: ${info.pid}`);
  out(`dashboard:     ${st.serve?.url || info.serveUrl || '(not serving)'}${st.serve?.portConflict ? `  (port ${st.serve.requestedPort} was busy; using ${st.serve.port})` : ''}`);
  out(`verified completion: ${st.verifiedPercent}%  (${st.verifiedWeight}/${st.totalWeight} weight, ${st.verifiedRequirements}/${st.totalRequirements} requirements, ${st.passedCriteria}/${st.totalCriteria} criteria; manifest v${st.manifest?.version})`);
  const c = commandsFor(runId);
  out('commands:');
  out(`  status: ${c.status}`);
  out(`  pause:  ${c.pause}`);
  out(`  resume: ${c.resume}`);
  out(`  stop:   ${c.stop}`);
}

async function launchController(root, runId, serveSpec, { foreground }) {
  const L = layout(root, runId);
  mkdirSync(L.dir, { recursive: true });
  const profilePath = (readStateFile(L).state || {}).profilePath || DEFAULT_PROFILE;
  if (foreground) {
    return startController({ repoRoot: root, runId, profilePath, serveSpec });
  }
  const outFd = openSync(join(L.dir, 'controller.out'), 'a', 0o600);
  const args = [RUN_MJS, '_controller', '--run', runId];
  if (serveSpec) args.push('--serve', serveSpec);
  // detached => its own session/process group, reparented to the init process:
  // it survives this terminal and this invoking Claude worker exiting.
  const child = spawn(process.execPath, args, { cwd: root, detached: true, stdio: ['ignore', outFd, outFd], env: { ...process.env, LOOP_ENGINEERING_ROLE: 'controller' } });
  child.unref(); closeSync(outFd);
  // The product's contract is a start that returns within five seconds. A test on a starved machine can legitimately need longer to launch a
  // Node process, so the harness (and only the harness) gets a longer wait; the elapsed time is still measured by the tests that assert it.
  const readyMs = process.env.LOOP_ENGINEERING_TEST_HARNESS === '1' ? 30000 : 4500;
  const deadline = Date.now() + readyMs;
  let ready = false;
  while (Date.now() < deadline) {
    const l = judgeLease(L.leaseFile);
    const g = judgeLease(L.guardianLeaseFile);
    const s = readJson(L.stateFile, {});
    if (l.state === 'live' && l.lease.pid === child.pid && (!serveSpec || g.state === 'live')) { ready = true; break; }
    if (['failed', 'blocked'].includes(s.status) && s.controller?.pid !== child.pid && !identityMatches(child.pid, startTimeOf(child.pid))) break;
    if (!identityMatches(child.pid, startTimeOf(child.pid)) && Date.now() - (deadline - readyMs) > 800) break;
    await sleep(100);
  }
  if (!ready) {
    const s = readJson(L.stateFile, {});
    err(`controller did not become ready: ${s.statusReason || 'see ' + join(L.dir, 'controller.out')}`);
    return { failed: true, pid: child.pid };
  }
  return { pid: child.pid, serveUrl: null };
}

async function cmdStart(argv) {
  const a = parseArgs(argv, { flags: { background: { type: 'boolean' }, foreground: { type: 'boolean' }, serve: { type: 'string' } } });
  if (!!a.background === !!a.foreground) throw new UsageError('start requires exactly one of --background or --foreground');
  if (a.serve && !/^127\.0\.0\.1:\d{1,5}$/.test(a.serve)) throw new UsageError('--serve must be 127.0.0.1:<port> (loopback only)');
  const root = REPO_ROOT;
  const m = loadManifest(root);
  if (!m.ok) throw new UsageError(m.error);
  const prd = checkPrdFresh(root, m.manifest);
  if (!prd.ok) throw new UsageError(prd.error);
  const { runId, state } = loadRunContext(root);
  if (state.status === 'completed') throw new UsageError(`run ${runId} is already completed; run init to create a new run`);
  try {
    const { profile } = loadProfileBounded(resolve(root, state.profilePath || DEFAULT_PROFILE));
    validateProfile(profile, root);
    const blocked = suiteLaunchBlockers(profile, root);
    if (blocked.length) throw new UsageError(`refusing to launch: ${blocked.length} suite(s) cannot run yet: ${blocked.map((x) => `${x.suite} (${x.reason})`).join('; ')}`);
  } catch (e) { if (e instanceof ProfileError) throw new UsageError(`refusing to launch: ${e.message}`); throw e; }
  const lock = readJson(layout(root).lockFile, null);
  if (lock && identityMatches(lock.pid, lock.start)) throw new UsageError(`run ${lock.runId} already has an active controller (pid ${lock.pid}); a second launch cannot mutate this checkout`);
  const r = await launchController(root, runId, a.serve || null, { foreground: !!a.foreground });
  if (a.foreground) return r;
  if (r.failed) return 1;
  printStarted(root, runId, r);
  return 0;
}

async function cmdResume(argv) {
  parseArgs(argv, { flags: {} });
  const root = REPO_ROOT;
  const { runId, L, state } = loadRunContext(root);
  if (state.status === 'completed') throw new UsageError('run is completed; nothing to resume');
  const lease = judgeLease(L.leaseFile);
  if (lease.state === 'live' && !lease.lease.exited && !isTerminal(state.status)) {
    const ack = await sendControl(L, 'resume');
    out(`resume: ${ack.result}`);
    return ack.result === 'ok' ? 0 : 1;
  }
  // No live controller: this is a restart. The new process re-checks the
  // checkout, manifest and evidence freshness before scheduling anything.
  if (state.status === 'completed') throw new UsageError('run is completed; nothing to resume');
  const m = loadManifest(root);
  if (!m.ok) throw new UsageError(m.error);
  const prd = checkPrdFresh(root, m.manifest);
  if (!prd.ok) throw new UsageError(prd.error);
  const serveSpec = (judgeLease(L.guardianLeaseFile).lease?.serve?.url || '').replace('http://', '') || null;
  const r = await launchController(root, runId, serveSpec, { foreground: false });
  if (r.failed) return 1;
  out(`resumed run ${runId} with a new controller process (restart #${(state.restarts || 0) + 1}); stale evidence will be re-verified before new work`);
  printStarted(root, runId, r);
  return 0;
}

// ---------------------------------------------------------------- status / plan
async function cmdStatus(argv) {
  const a = parseArgs(argv, { flags: { json: { type: 'boolean' }, run: { type: 'string' } } });
  const st = buildStatus(REPO_ROOT, a.run || null);
  if (a.json) { out(JSON.stringify(st, null, 2)); return st.ok ? 0 : 1; }
  if (!st.ok) { out(`status: ${st.status}: ${st.error || ''}`); return 1; }
  out(`run ${st.runId}: ${st.status}${st.statusReason ? ` (${st.statusReason})` : ''}`);
  out(`verified completion: ${st.verifiedPercent}%  (${st.verifiedWeight}/${st.totalWeight} weight; ${st.verifiedRequirements}/${st.totalRequirements} requirements; ${st.passedCriteria}/${st.totalCriteria} criteria; manifest v${st.manifest?.version})`);
  out(`controller: ${st.controller.liveness} pid ${st.controller.pid}; guardian: ${st.guardian.liveness}; dashboard: ${st.serve?.url || 'none'}`);
  out(`states: ${Object.entries(st.counts).filter(([, n]) => n).map(([k, n]) => `${k} ${n}`).join(', ')}`);
  if (st.current) out(`current: ${st.current.requirement} (${st.current.phase}${st.current.attempt ? ` attempt ${st.current.attempt}` : ''})`);
  if (st.blockers?.length) for (const b of st.blockers) out(`run blocker: ${b.type}: ${b.detail}`);
  if (st.final?.required) out(`final verification: ${st.final.ok ? 'passed on the current tree' : `not satisfied (${st.final.reasons.join('; ')})`}`);
  if (st.drift) out(`DRIFT: ${st.drift.reasons.map((d) => `${d.input}${d.path ? ' ' + d.path : ''}: ${d.detail}`).join('; ')}`);
  for (const l of st.summary.lines) out(l);
  const unmet = st.requirements.filter((r) => r.state !== 'verified');
  out(`remaining (${unmet.length}): ${unmet.slice(0, 12).map((r) => `${r.id}:${r.state}`).join(' ')}${unmet.length > 12 ? ' ...' : ''}`);
  return 0;
}

async function cmdReport(argv) {
  const a = parseArgs(argv, { flags: { json: { type: 'boolean' }, write: { type: 'boolean' } } });
  const { runId, L } = loadRunContext(REPO_ROOT);
  const rep = buildCompletionReport(buildStatus(REPO_ROOT, runId));
  if (a.write) atomicWriteJson(L.completionReport, rep);
  if (a.json) { out(JSON.stringify(rep, null, 2)); return 0; }
  out(`run ${rep.runId}: ${rep.runStatus}${rep.statusReason ? ` (${rep.statusReason})` : ''}; verdict ${rep.verdict}`);
  out(rep.claim);
  out(`progress: ${rep.progress.verifiedPercent}% (${rep.progress.verifiedWeight}/${rep.progress.totalWeight} weight)`);
  out(`unmet criteria (${rep.unmetCriteria.length}): ${rep.unmetCriteria.slice(0, 20).map((c) => c.criterion).join(' ')}${rep.unmetCriteria.length > 20 ? ' ...' : ''}`);
  for (const b of rep.blockers) out(`blocker: ${b.scope}${b.requirement ? ' ' + b.requirement : ''} ${b.type}: ${b.detail}`);
  for (const b of rep.budgetStops) out(`budget stop: ${b.kind}${b.requirement ? ' ' + b.requirement : ''}: ${b.detail}`);
  out(`implemented and verified: ${rep.implemented.length}`);
  for (const c of rep.nextCommands) out(`next: ${c.command}  (${c.bound})`);
  return 0;
}

async function cmdPlan(argv) {
  parseArgs(argv, { flags: { next: { type: 'boolean', required: true } } });
  const root = REPO_ROOT;
  const m = loadManifest(root);
  if (!m.ok) throw new UsageError(m.error);
  const { runId, L, state } = loadRunContext(root);
  const tree = new TreeIndex(root, join(layout(root).cacheDir, 'tree-cache.json')).build();
  const key = evidenceKey(root);
  const assess = assessAll({ L, manifest: m.manifest, tree, key });
  const progress = computeProgress(m.manifest, assess, state.requirements || {});
  const next = progress.requirements.find((r) => ['ready', 'stale', 'retry-wait'].includes(r.state) && r.dependenciesVerified);
  if (!next) {
    const blocked = progress.requirements.filter((r) => r.state !== 'verified');
    out(JSON.stringify({ next: null, reason: blocked.length ? 'no dependency-ready requirement' : 'every requirement is verified', remaining: blocked.map((r) => ({ id: r.id, state: r.state, waitingOn: r.dependencies.filter((d) => !progress.requirements.find((x) => x.id === d && x.state === 'verified')) })) }, null, 2));
    return 0;
  }
  const req = m.manifest.requirements.find((r) => r.id === next.id);
  out(JSON.stringify({ next: next.id, title: next.title, state: next.state, weight: next.weight, dependencies: next.dependencies, blockingCriteria: next.unmetCriteria.map((id) => ({ id, text: req.criteria.find((c) => c.id === id)?.text })), suite: req.suite }, null, 2));
  return 0;
}

// ---------------------------------------------------------------- verify
async function cmdVerify(argv) {
  const a = parseArgs(argv, { flags: { requirement: { type: 'string' }, all: { type: 'boolean' }, final: { type: 'boolean' }, 'allow-fail': { type: 'boolean' } } });
  if (a['allow-fail']) throw new UsageError('--allow-fail is not supported: a failing criterion is a failure');
  if (a.all && !a.final) throw new UsageError('verify --all requires --final (the final phase is controller-owned)');
  if (!!a.requirement === !!a.all) throw new UsageError('verify requires exactly one of --requirement <id> or --all --final');
  const root = REPO_ROOT;
  const m = loadManifest(root);
  if (!m.ok) throw new UsageError(m.error);
  const { runId, L } = loadRunContext(root);
  if (a.all) {
    // The final phase is owned by the controller (never recursive). From the CLI
    // it is a request to the controller, or a refusal if none is live.
    const lease = judgeLease(L.leaseFile);
    if (lease.state === 'live') { out('the controller owns the final phase and runs it automatically once every other requirement is verified; use `status` to follow it.'); return 0; }
    throw new UsageError('no live controller: `verify --all --final` is executed by the controller. Run `start` or `resume`; it enters the final phase when every other requirement is verified.');
  }
  const req = m.manifest.requirements.find((r) => r.id === a.requirement);
  if (!req) throw new UsageError(`unknown requirement ${a.requirement}`);
  if (req.verification.kind === 'controller-final') throw new UsageError(`${req.id} is evaluated by the controller final phase, not by a suite`);
  const tree = new TreeIndex(root, join(layout(root).cacheDir, 'tree-cache.json'));
  const res = await verifyRequirement({ repoRoot: root, L, manifest: m.manifest, tree, key: evidenceKey(root), runId, invoker: process.env.LOOP_ENGINEERING_WORKER ? 'worker-invoked' : 'cli' }, req, { phase: 'requirement' });
  const ev = res.evidence;
  out(`${req.id} ${ev.result.toUpperCase()}  (${ev.criteria.filter((c) => c.state === 'pass').length}/${req.criteria.length} criteria; tests ${ev.counts.tests} pass ${ev.counts.pass} fail ${ev.counts.fail} skipped ${ev.counts.skipped})`);
  if (ev.reason) out(`reason: ${ev.reason}`);
  for (const c of ev.criteria) out(`  ${c.state === 'pass' ? 'pass' : 'FAIL'} ${c.id}${c.reason ? `  - ${c.reason}` : ''}`);
  out(`evidence: ${ev.evidenceId} -> ${res.file}`);
  if (ev.result !== 'pass' && res.tail && process.env.LOOP_ENGINEERING_VERBOSE) out(res.tail);
  return ev.result === 'pass' ? 0 : 1;
}

// ---------------------------------------------------------------- pause / retry / stop
async function cmdPause(argv) {
  parseArgs(argv, { flags: {} });
  const { L } = loadRunContext(REPO_ROOT);
  const ack = await sendControl(L, 'pause');
  out(`pause: ${ack.result}`);
  return ack.result === 'ok' ? 0 : 1;
}
async function cmdRetry(argv) {
  const a = parseArgs(argv, { flags: { requirement: { type: 'string', required: true } } });
  const { L } = loadRunContext(REPO_ROOT);
  const ack = await sendControl(L, 'retry', { requirement: a.requirement });
  out(`retry ${a.requirement}: ${ack.result}`);
  return /^(requeued|backoff-skipped)$/.test(ack.result) ? 0 : 1;
}

async function cmdStop(argv) {
  const a = parseArgs(argv, { flags: { run: { type: 'string', required: true } } });
  const t0 = Date.now();
  const root = REPO_ROOT;
  const { runId, L, state } = loadRunContext(root, a.run);
  if (a.run !== runId) throw new UsageError('run id mismatch');
  const lease = judgeLease(L.leaseFile);
  const g = judgeLease(L.guardianLeaseFile);
  if (lease.state === 'live') {
    atomicWriteJson(L.controlFile, { seq: nextControlSeq(L), command: 'stop', requestedAt: nowIso() });
    const end = t0 + 10000;
    while (Date.now() < end) { if (!identityMatches(lease.lease.pid, lease.lease.start)) break; await sleep(100); }
  }
  // Escalate against OWNED processes only, by (pid, start time) identity.
  const owned = readJson(L.ownedFile, { entries: [] });
  const stillCtl = lease.lease && identityMatches(lease.lease.pid, lease.lease.start);
  if (stillCtl) { signalIdentity(lease.lease, 'SIGTERM'); await sleep(1500); if (identityMatches(lease.lease.pid, lease.lease.start)) signalIdentity(lease.lease, 'SIGKILL'); }
  const killed = await reapOwned(owned.entries || [], runId, 1500);
  writeFileSync(join(L.dir, 'guardian-stop'), nowIso());
  const gEnd = Math.min(t0 + 13500, Date.now() + 3000);
  while (Date.now() < gEnd && g.lease && identityMatches(g.lease.pid, g.lease.start)) await sleep(100);
  if (g.lease && identityMatches(g.lease.pid, g.lease.start)) { signalIdentity(g.lease, 'SIGTERM'); await sleep(300); signalIdentity(g.lease, 'SIGKILL'); }
  const st = readJson(L.stateFile, state);
  if (!['stopped', 'completed'].includes(st.status)) { st.status = 'stopped'; st.statusReason = 'stopped by operator'; st.current = null; st.updatedAt = nowIso(); atomicWriteJson(L.stateFile, st); }
  releaseRunLock(root, lease.lease?.pid);
  try { unlinkSync(join(L.dir, 'guardian-stop')); } catch { /* */ }
  appendEvent(L, 'stopped', { reclaimed: killed.length });
  const status = buildStatus(root, runId);
  out(`stopped run ${runId} in ${Date.now() - t0}ms; checkpoint preserved; verified completion ${status.verifiedPercent}%`);
  out(`resume: node scripts/loop-engineering/run.mjs resume`);
  return 0;
}

// ---------------------------------------------------------------- exec (operation lease)
async function cmdExec(argv) {
  const a = parseArgs(argv, { flags: { deadline: { type: 'number', required: true }, label: { type: 'string' } }, positionals: 1000 });
  const cmd = a._;
  if (!cmd.length) throw new UsageError('exec needs a command after --');
  if (a.deadline <= 0 || a.deadline > MAX_LEASE_SECONDS) throw new UsageError(`--deadline must be 1..${MAX_LEASE_SECONDS} seconds (leases are finite and never renewed)`);
  const root = REPO_ROOT;
  const runId = process.env.LOOP_ENGINEERING_RUN || currentRunId(root);
  const L = runId ? layout(root, runId) : null;
  const lease = L ? registerOpLease(L.leasesDir, { label: a.label || cmd.join(' ').slice(0, 80), deadlineSeconds: a.deadline }) : null;
  try {
    const r = await runBounded({ argv: cmd, cwd: process.cwd(), wallMs: a.deadline * 1000, graceMs: 5000, label: 'exec', onData: (w, c) => (w === 'stderr' ? process.stderr : process.stdout).write(c), maxLogBytes: 0, runId: runId || 'exec' });
    if (r.outcome === 'exited') return r.exitCode ?? 1;
    err(`exec: ${r.outcome}${r.reason ? `: ${r.reason}` : ''}`);
    return r.outcome === 'timeout-wall' ? 124 : 125;
  } finally { lease?.release(); }
}

// ---------------------------------------------------------------- internal
async function cmdController(argv) {
  const a = parseArgs(argv, { flags: { run: { type: 'string', required: true }, serve: { type: 'string' } } });
  const L = layout(REPO_ROOT, a.run);
  const profilePath = (readStateFile(L).state || {}).profilePath || DEFAULT_PROFILE;
  return startController({ repoRoot: REPO_ROOT, runId: a.run, profilePath, serveSpec: a.serve || null });
}
async function cmdGuardian(argv) {
  const a = parseArgs(argv, { flags: { run: { type: 'string', required: true }, serve: { type: 'string' } } });
  const L = layout(REPO_ROOT, a.run);
  const profile = (() => { try { return loadProfileBounded(resolve(REPO_ROOT, (readStateFile(L).state || {}).profilePath || DEFAULT_PROFILE)).profile; } catch { return null; } })();
  return runGuardian({ repoRoot: REPO_ROOT, runId: a.run, serveSpec: a.serve || null, lingerSeconds: profile?.serve?.lingerSeconds ?? 3600 });
}

const COMMANDS = { init: cmdInit, preflight: cmdPreflight, start: cmdStart, status: cmdStatus, verify: cmdVerify, pause: cmdPause, resume: cmdResume, retry: cmdRetry, stop: cmdStop, plan: cmdPlan, exec: cmdExec, report: cmdReport, _controller: cmdController, _guardian: cmdGuardian };

async function main() {
  const [cmd, ...rest] = process.argv.slice(2);
  if (!cmd || cmd === '--help' || cmd === '-h' || cmd === 'help') { out(USAGE); return cmd ? 0 : 2; }
  const fn = COMMANDS[cmd];
  if (!fn) { err(`unknown command "${cmd}"\n${USAGE}`); return 2; }
  try { return await fn(rest); } catch (e) {
    if (e instanceof UsageError) { err(`error: ${e.message}`); return 2; }
    if (e instanceof ImportError || e instanceof ProfileError) { err(e.message); return 1; }
    err(`error: ${redact(String(e.stack || e))}`); return 1;
  }
}

main().then((c) => { process.exitCode = typeof c === 'number' ? c : 0; }, (e) => { err(String(e)); process.exitCode = 1; });
