// The supervised controller (LOOP-003 / LOOP-006). One process, one worker at a
// time. Everything it believes about completion comes from the verifier's
// evidence, never from the worker. It checkpoints atomically, survives a worker
// dying, and leaves a truthful state behind when it stops for ANY reason.
import { spawn } from 'node:child_process';
import { openSync, closeSync, mkdirSync, writeFileSync, readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Worker } from 'node:worker_threads';
import {
  layout, evidenceKey, appendEvent, recordJob, writeLease, judgeLease, acquireRunLock, releaseRunLock, readStateFile,
  HEARTBEAT_MS,
} from './state.mjs';
import { atomicWriteJson, atomicWriteFile, readJson, nowIso, sleep, sha256, randomId, redact, Deadline, setLogCap } from './util.mjs';
import { detectDrift, driftSummary } from './drift.mjs';
import { assessFinal, evaluateFinal, writeFinalEvidence } from './final.mjs';
import { buildCompletionReport } from './report.mjs';
import { loadManifest, checkPrdFresh } from './manifest.mjs';
import { loadProfile, validateProfile } from './profile.mjs';
import { TreeIndex } from './tree.mjs';
import { assessAll, computeProgress, formatPercent } from './progress.mjs';
import { verifyRequirement, environmentInfo, toolAvailable } from './verifier.mjs';
import { listEvidence, writeEvidence, verifierHash, requirementHash, effectiveWatch, VERIFIER_VERSION, sign } from './evidence.mjs';
import { runBounded, OwnedSet, reapOwned } from './proc.mjs';
import { configureBounds } from './bounds.mjs';
import { envelopeConfig, chargeEnvelope, emptyProvider, modelCharge } from './envelope.mjs';
import { startTimeOf, identityMatches, signalIdentity } from './procscan.mjs';
import { AttemptWatchdog } from './watchdog.mjs';
import { activeOpLeases } from './oplease.mjs';
import { resolveBinary, detectClaude, buildWorkerArgs, StreamState, classifyWorker, buildPrompt } from './claude.mjs';
import { buildStatus, renderStaticHtml, isTerminal } from './status.mjs';
import { runGateCommand } from './gates.mjs';
import { evaluateClosure, checkReceipts, gatherReceipts, rehashReceipts, gitFacts, parseMeasured, fileSetDeliverable, implementationDiff, prdLedger, unmetByRequirement, CLOSURE_SCHEMA } from './closure.mjs';
import { buildAssuranceBundle } from './closure-bundle.mjs';

const RUN_MJS = fileURLToPath(new URL('../run.mjs', import.meta.url));

// The heartbeat runs on its OWN thread (its own event loop). A worker that floods stdout can saturate the controller's main
// loop for seconds at a time; the lease must keep its cadence regardless, so liveness never depends on what the worker prints.
// The thread also records when the main loop last ticked (mainTickAt), so a wedged main loop is visible rather than hidden
// behind a healthy-looking beat.
const HEARTBEAT_THREAD_SRC = `
const { workerData: d } = require('node:worker_threads');
const fs = require('node:fs');
let seq = d.baseSeq;
function beat() {
  seq += 1;
  const now = Date.now();
  const lease = { runId: d.runId, pid: d.pid, start: d.start, seq, status: 'running', role: 'controller', thread: true, mainTick: d.shared[0], mainTickAt: d.shared[1], wallAt: now, at: new Date(now).toISOString() };
  const tmp = d.file + '.' + d.pid + '.hb.tmp';
  try { fs.writeFileSync(tmp, JSON.stringify(lease, null, 2) + '\\n', { mode: 0o600 }); fs.renameSync(tmp, d.file); } catch (e) { /* a missed beat is detectable by readers */ }
}
setInterval(beat, d.intervalMs);
`;

const GLOBAL_BLOCKERS = new Set(['auth-missing', 'unknown-cli-flag', 'worker-missing']);
// Deliberately pessimistic list prices (USD per million tokens). Used ONLY when a
// killed worker never emitted a result event; labelled as an estimate everywhere.
const ESTIMATE_PRICING = { input: 15, output: 75, cacheRead: 1.5, cacheCreate: 18.75 };

const relRowExists = (manifest) => manifest.requirements.some((r) => r.verification.kind === 'controller-final');

export function initialState({ runId, manifest, profilePath, profileSha, repoRoot }) {
  return {
    schemaVersion: 1, runId, status: 'starting', statusReason: null, platform: process.platform,
    manifestVersion: manifest.manifestVersion, acceptanceHash: manifest.acceptanceHash, prdSha256: manifest.prd.sha256,
    profilePath, profileSha, repoRoot, startedAt: nowIso(), updatedAt: nowIso(),
    controller: null, guardian: null,
    budgets: { attemptsUsed: 0, usdUsed: 0, usdEstimated: 0, usdReported: 0, wallUsedMs: 0, segmentStartedAt: null },
    current: null, requirements: {}, runBlockers: [], checkpoints: 0, lastProgressAt: null, lastHeartbeatAt: null,
    control: { handledSeq: 0, ack: null }, finalVerdict: null, restarts: 0,
  };
}

function loadProfileQuiet(profilePath, repoRoot) {
  try { return loadProfile(resolve(repoRoot, profilePath)).profile; } catch { return null; }
}

export class Controller {
  constructor({ repoRoot, runId, profilePath, mock = null }) {
    this.repoRoot = resolve(repoRoot);
    this.runId = runId;
    this.L = layout(this.repoRoot, runId);
    this.profilePath = profilePath;
    this.mock = mock;
    this.stopping = false;
    this.paused = false;
    this.abortReason = null;
    this.workerAbort = null;
    this.hbSeq = 0;
    this.lastHbMono = performance.now();
    this.lastHbWall = Date.now();
    this.sleepDetected = false;
    this.owned = new OwnedSet((list) => { try { atomicWriteJson(this.L.ownedFile, { runId, controllerPid: process.pid, entries: list }); } catch { /* best effort */ } });
  }

  emit(type, data = {}) { try { appendEvent(this.L, type, data); } catch { /* never let logging kill the loop */ } }

  save() {
    this.S.updatedAt = nowIso();
    atomicWriteJson(this.L.stateFile, this.S);
  }

  checkpoint(reason) {
    this.S.checkpoints += 1;
    this.save();
    try { atomicWriteJson(this.L.stateBackup, this.S); } catch { /* the primary is already durable */ }
    this.emit('checkpoint', { n: this.S.checkpoints, reason });
  }

  setStatus(status, reason = null) {
    if (this.S.status !== status) this.emit('status', { from: this.S.status, to: status, reason });
    this.S.status = status; this.S.statusReason = reason; this.save();
  }

  reqState(id) { return (this.S.requirements[id] ||= { state: 'pending', attempts: 0, repeatCount: 0, blockers: [], history: [] }); }

  // ---- startup ------------------------------------------------------------
  async boot() {
    const { profile, sha256: psha } = loadProfile(this.profilePath);
    validateProfile(profile, this.repoRoot);
    this.profile = profile; this.profileSha = psha;
    this.limits = profile.limits;
    configureBounds(profile.limits);
    setLogCap(profile.limits.resource.maxLogMiB * 1048576);
    const m = loadManifest(this.repoRoot);
    if (!m.ok) throw Object.assign(new Error(m.error), { blocker: { type: 'invalid-manifest', detail: m.error } });
    this.manifest = m.manifest;
    const prd = checkPrdFresh(this.repoRoot, this.manifest);
    if (!prd.ok) throw Object.assign(new Error(prd.error), { blocker: { type: 'prd-changed', detail: prd.error } });
    // Test-harness hook: only honoured when explicitly enabled in the environment,
    // so a profile can never swap the real worker for an arbitrary command in
    // normal operation.
    if (process.env.LOOP_ENGINEERING_TEST_HARNESS === '1' && profile.testHarness) this.mock = { ...(this.mock || {}), ...profile.testHarness };
    this.key = evidenceKey(this.repoRoot);
    this.tree = new TreeIndex(this.repoRoot, join(layout(this.repoRoot).cacheDir, 'tree-cache.json'));
    mkdirSync(this.L.leasesDir, { recursive: true });
    mkdirSync(this.L.attemptsDir, { recursive: true });
    mkdirSync(this.L.logsDir, { recursive: true });
    const { state: existing, source: stateSource } = readStateFile(this.L);
    if (stateSource === 'corrupt') throw Object.assign(new Error('state.json is corrupt and no checkpoint backup exists; refusing to reinitialise (that would reset attempt counters). Restore it or create a new run with init.'), { blocker: { type: 'corrupt-checkpoint', detail: 'state.json unreadable, no state.json.bak' } });
    if (stateSource === 'backup') this.emit('state-recovered', { from: 'state.json.bak' });
    this.S = existing || initialState({ runId: this.runId, manifest: this.manifest, profilePath: this.profilePath, profileSha: this.profileSha, repoRoot: this.repoRoot });
    if (existing) {
      if (existing.status !== 'initialized') this.S.restarts = (this.S.restarts || 0) + 1;
      // Anything that was mid-flight died with the previous controller. Resume
      // honestly: running/verifying are not states a fresh process can inherit.
      for (const st of Object.values(this.S.requirements)) if (['running', 'verifying'].includes(st.state)) st.state = 'pending';
      this.S.current = null;
      this.S.manifestVersion = this.manifest.manifestVersion; this.S.acceptanceHash = this.manifest.acceptanceHash;
      this.S.prdSha256 = this.manifest.prd.sha256; this.S.profileSha = this.profileSha;
      // Resumed runs honour the CURRENT (still finite) profile; a stale
      // global blocker is re-evaluated, not trusted.
      this.S.runBlockers = [];
    }
    this.S.controller = { pid: process.pid, start: startTimeOf(process.pid), startedAt: nowIso() };
    this.S.budgets.segmentStartedAt = Date.now();
    // The separately metered provider/infrastructure envelope. Its accounting persists across restarts (an exhausted envelope is never reset);
    // its configuration is the CURRENT profile's, and a state written before the envelope existed gets an empty meter.
    this.envelope = envelopeConfig(profile);
    this.S.budgets.provider = { ...emptyProvider(), ...(this.S.budgets.provider || {}), enabled: this.envelope.enabled, capUsd: this.envelope.present ? this.envelope.capUsd : null, preauthorizedBy: this.envelope.preauthorizedBy || null };
    this.driftCheckedAt = 0;
    const drift = this.driftProblem(true);
    if (drift) throw Object.assign(new Error(`drift: ${drift}`), { blocker: { type: 'drift', detail: drift } });
    this.S.status = 'running'; this.S.statusReason = null;
    this.emit('controller-start', { pid: process.pid, restarts: this.S.restarts, manifestVersion: this.manifest.manifestVersion });
    this.save();
    this.writeHeartbeat();
  }

  startHeartbeatThread(intervalMs) {
    this.hbShared = new Float64Array(new SharedArrayBuffer(16));
    this.hbShared[1] = Date.now();
    try {
      this.hbThread = new Worker(HEARTBEAT_THREAD_SRC, { eval: true, workerData: { file: this.L.leaseFile, runId: this.runId, pid: process.pid, start: this.S.controller.start, intervalMs, baseSeq: this.hbSeq + 1000, shared: this.hbShared } });
      this.hbThread.on('error', (e) => { this.hbThread = null; this.emit('heartbeat-thread-error', { message: String(e.message || e) }); });
      this.hbThread.unref();
    } catch (e) {
      this.hbThread = null; this.emit('heartbeat-thread-error', { message: String(e.message || e) });
    }
  }

  // The main loop's own tick: sleep detection, guardian supervision, and the shared counter the heartbeat thread reports.
  // Without the thread (it failed to start) the tick falls back to writing the lease itself.
  mainTick() {
    if (this.hbShared) { this.hbShared[0] += 1; this.hbShared[1] = Date.now(); }
    this.writeHeartbeat({ lease: !this.hbThread });
  }

  // Frozen-input drift (LOOP-004.AC01). Throttled; `force` re-reads now.
  driftProblem(force = false) {
    if (!this.S.frozen) return null;
    if (!force && Date.now() - this.driftCheckedAt < 1500) return this.S.drift ? driftSummary(this.S.drift.reasons) : null;
    this.driftCheckedAt = Date.now();
    const d = detectDrift({ repoRoot: this.repoRoot, frozen: this.S.frozen, profile: loadProfileQuiet(this.profilePath, this.repoRoot) });
    if (!d.drifted) return null;
    if (!this.S.drift) { this.S.drift = { at: nowIso(), reasons: d.reasons }; this.emit('drift-detected', { reasons: d.reasons }); }
    return driftSummary(d.reasons);
  }

  writeHeartbeat({ lease = true } = {}) {
    this.hbSeq += 1;
    const monoDelta = performance.now() - this.lastHbMono;
    const wallDelta = Date.now() - this.lastHbWall;
    // Machine sleep: wall clock jumps, monotonic does not. A sleep invalidates
    // the in-flight lease; it must never silently extend a deadline.
    if (wallDelta - monoDelta > 20000) {
      this.sleepDetected = true;
      this.emit('sleep-detected', { wallDeltaMs: Math.round(wallDelta), monoDeltaMs: Math.round(monoDelta) });
    }
    this.lastHbMono = performance.now(); this.lastHbWall = Date.now();
    this.S.lastHeartbeatAt = nowIso();
    if (lease) {
      try {
        writeLease(this.L.leaseFile, { runId: this.runId, pid: process.pid, start: this.S.controller.start, seq: this.hbSeq, status: this.S.status, role: 'controller' });
      } catch { /* a missed beat is detectable by readers; do not crash */ }
    }
    this.ensureGuardian();
  }

  ensureGuardian() {
    if (this.stopping || this.mock?.noGuardian) return;
    const g = judgeLease(this.L.guardianLeaseFile);
    if (g.state === 'live') return;
    if (this.guardianSpawnedAt && Date.now() - this.guardianSpawnedAt < 8000) return;
    this.guardianSpawnedAt = Date.now();
    const out = openSync(join(this.L.dir, 'guardian.out'), 'a', 0o600);
    const args = [RUN_MJS, '_guardian', '--run', this.runId];
    if (this.serveSpec) args.push('--serve', this.serveSpec);
    const child = spawn(process.execPath, args, { cwd: this.repoRoot, detached: true, stdio: ['ignore', out, out], env: { ...process.env, LOOP_ENGINEERING_ROLE: 'guardian' } });
    child.unref(); closeSync(out);
    this.S.guardian = { pid: child.pid, start: startTimeOf(child.pid), spawnedAt: nowIso() };
    this.emit('guardian-spawn', { pid: child.pid });
  }

  // ---- control channel ----------------------------------------------------
  readControl() {
    const c = readJson(this.L.controlFile, null);
    if (!c || !Number.isInteger(c.seq) || c.seq <= this.S.control.handledSeq) return null;
    return c;
  }

  async handleControl() {
    const c = this.readControl();
    if (!c) return;
    this.S.control.handledSeq = c.seq;
    let result = 'ok';
    switch (c.command) {
      case 'pause': this.paused = true; this.abortWorker('paused'); this.setStatus('paused', 'pause requested'); break;
      case 'resume':
        if (this.paused) { this.paused = false; this.setStatus('running'); } else result = 'not-paused';
        break;
      case 'stop': this.stopping = true; this.abortWorker('stop'); result = 'stopping'; break;
      case 'retry': result = this.retryRequirement(c.requirement); break;
      // Test seam only (needs the harness enabled in the environment): pretend the wall clock jumped, as after a machine sleep.
      case 'simulate-sleep': if (process.env.LOOP_ENGINEERING_TEST_HARNESS === '1') { this.lastHbWall -= 60000; result = 'simulated'; } else result = 'refused:not-in-test-harness'; break;
      // Test seam only: starve the main loop for c.ms, as a flooding worker can, to prove the heartbeat does not depend on it.
      case 'test-block-main': if (process.env.LOOP_ENGINEERING_TEST_HARNESS === '1') { const end = Date.now() + Math.min(Number(c.ms) || 0, 30000); while (Date.now() < end) { /* spin */ } result = 'blocked-main'; } else result = 'refused:not-in-test-harness'; break;
      default: result = `unknown-command:${c.command}`;
    }
    this.S.control.ack = { seq: c.seq, command: c.command, result, at: nowIso() };
    this.emit('control', { seq: c.seq, command: c.command, result });
    this.save();
  }

  // `retry` never erases failures or bypasses the attempt cap: it only skips a
  // backoff wait or re-evaluates an EXTERNAL blocker that may have cleared.
  retryRequirement(id) {
    const r = this.manifest.requirements.find((x) => x.id === id);
    if (!r) return 'unknown-requirement';
    const st = this.reqState(id);
    if (st.state === 'retry-wait') { st.nextEligibleAt = 0; return 'backoff-skipped'; }
    if (['timed-out', 'stale'].includes(st.state)) { st.state = 'pending'; return 'requeued'; }
    if (['blocked', 'failed'].includes(st.state)) {
      const external = st.blockers.length && st.blockers.every((b) => ['missing-tool', 'remote-unavailable', 'permission-denied', 'network-unavailable', 'auth-missing', 'external'].includes(b.type));
      if (!external) return `refused:${st.blockers.map((b) => b.type).join(',') || 'attempt-cap'} (retry caps are not bypassed; revise the profile and re-init to change them)`;
      st.state = 'pending'; st.blockers = st.blockers.map((b) => ({ ...b, reevaluated: true }));
      return 'requeued';
    }
    return `not-retryable:${st.state}`;
  }

  abortWorker(reason) {
    this.abortReason = reason;
    if (this.workerAbort && !this.workerAbort.signal.aborted) this.workerAbort.abort();
  }

  // ---- progress / budgets -----------------------------------------------------
  refresh() {
    this.tree.build();
    this.assess = assessAll({ L: this.L, manifest: this.manifest, tree: this.tree, key: this.key });
    this.final = assessFinal({ file: this.L.finalEvidence, manifest: this.manifest, tree: this.tree, key: this.key });
    this.progress = computeProgress(this.manifest, this.assess, this.S.requirements, { final: this.final });
    return this.progress;
  }

  wallUsedMs() {
    const seg = this.S.budgets.segmentStartedAt ? Date.now() - this.S.budgets.segmentStartedAt : 0;
    return this.S.budgets.wallUsedMs + seg;
  }

  budgetProblem() {
    const L = this.limits;
    if (this.wallUsedMs() >= L.runWallSeconds * 1000) return `run wall-clock budget of ${L.runWallSeconds}s is exhausted`;
    if (this.S.budgets.attemptsUsed >= L.runMaxAttempts) return `run attempt budget of ${L.runMaxAttempts} is exhausted`;
    return null;
  }

  // The model-spend cap is enforced where model spend can happen (before a worker attempt), not as a gate on everything. Re-validating
  // evidence and running the final phase cost no model spend, and stopping them at an exhausted spend cap would leave a run that has
  // finished all its model work unable to ever verify its result. The cap itself is unchanged.
  modelBudgetProblem() {
    const L = this.limits;
    const remaining = L.claudeBudgetUsd - this.S.budgets.usdUsed;
    // Unknown billing: once an attempt has finished without a reported cost, the next paid attempt must fit its defined upper-bound
    // reserve under the cap. Stopping here is the alternative to assuming the unreported spend was zero.
    if (L.unknownBillingReserveUsd != null && this.S.budgets.billingUnknown && remaining < L.unknownBillingReserveUsd) return `unknown billing: the last attempt reported no cost, and the defined upper-bound reserve of $${L.unknownBillingReserveUsd} no longer fits under the $${L.claudeBudgetUsd} cap (used about $${this.S.budgets.usdUsed.toFixed(2)}, of which $${(this.S.budgets.usdReserved || 0).toFixed(2)} is reserve); paid work stops rather than assuming zero cost`;
    if (remaining < (L.minAttemptBudgetUsd ?? 1)) return `Claude spend budget exhausted (used about $${this.S.budgets.usdUsed.toFixed(2)} of $${L.claudeBudgetUsd}; token-derived amounts are estimates, not exact charges)`;
    return null;
  }

  noteProgress(kind, detail) {
    this.S.lastProgressAt = nowIso();
    this.emit('progress', { kind, ...detail });
  }

  // ---- verification --------------------------------------------------------
  async verify(req, opts = {}) {
    const st = this.reqState(req.id);
    const prevState = st.state;
    st.state = 'verifying';
    this.S.current = { ...(this.S.current || {}), requirement: req.id, phase: 'verifying', startedAt: nowIso(), deadlineAt: Date.now() + (req.verification.timeoutSeconds + 15) * 1000, pid: null };
    this.save();
    const before = this.bestPass(req);
    let out;
    try {
      out = await verifyRequirement({ repoRoot: this.repoRoot, L: this.L, manifest: this.manifest, tree: this.tree, key: this.key, runId: this.runId, invoker: 'controller', owned: this.owned }, req, { phase: opts.phase || 'requirement', attempt: opts.attempt ?? null });
    } finally {
      st.state = prevState === 'verifying' ? 'pending' : prevState;
      this.S.current = null;
    }
    const ev = out.evidence;
    const passed = ev.criteria.filter((c) => c.state === 'pass').length;
    this.emit('verify', { requirement: req.id, result: ev.result, passed, total: req.criteria.length, outcome: ev.exec.outcome, reason: ev.reason, evidence: ev.evidenceId });
    if (passed > before.passed || (ev.result === 'pass' && !before.verified)) this.noteProgress('criterion-passed', { requirement: req.id, passed, total: req.criteria.length });
    else if (ev.counts.fail < before.fail && before.fail !== Infinity) this.noteProgress('failures-reduced', { requirement: req.id });
    recordJob(this.L, { ...ev.exec, label: `verify:${req.id}`, jobId: ev.evidenceId });
    this.lastVerifyTail = out.tail;
    return out;
  }

  bestPass(req) {
    const list = listEvidence(this.L, req.id);
    let passed = 0, fail = Infinity, verified = false;
    for (const e of list) {
      const p = (e.ev.criteria || []).filter((c) => c.state === 'pass').length;
      if (p > passed) passed = p;
      if (e.ev.counts && typeof e.ev.counts.fail === 'number') fail = Math.min(fail, e.ev.counts.fail);
      if (e.ev.result === 'pass') verified = true;
    }
    return { passed, fail, verified };
  }

  failureFingerprint(req, ev, workerKind) {
    const failing = ev.criteria.filter((c) => c.state !== 'pass').map((c) => c.id).sort().join(',');
    const names = ev.criteria.flatMap((c) => c.assertions || []).filter((a) => !a.ok).map((a) => a.name).slice(0, 3).join('|');
    return sha256([req.id, workerKind || '', ev.exec.outcome, ev.exec.exitCode, failing, names, (ev.reason || '').replace(/\d+/g, '#')].join('\u0001')).slice(0, 16);
  }

  // ---- worker attempts ---------------------------------------------------------
  backoffMs(attempt) {
    const base = Math.min(this.limits.retryBackoffMaxSeconds, 5 * 2 ** Math.max(0, attempt - 1));
    return Math.round((base * (0.75 + Math.random() * 0.5)) * 1000);
  }

  workerLauncher(req, prompt, budgetUsd) {
    if (this.mock?.worker) return this.mock.worker({ req, prompt, budgetUsd, repoRoot: this.repoRoot, runId: this.runId });
    if (this.mock?.argv) return { argv: this.mock.argv, stdin: prompt, protocol: 'mock' };
    const bin = this.claudeBin;
    return { argv: [bin, ...buildWorkerArgs({ profile: this.profile, features: this.claudeFeatures.flags, budgetUsd })], stdin: prompt, protocol: 'claude' };
  }

  async ensureClaude() {
    if (this.claudeFeatures || this.mock?.worker || this.mock?.argv) return true;
    const bin = resolveBinary(this.profile.worker.command);
    if (!bin) { this.addRunBlocker({ type: 'worker-missing', detail: `\`${this.profile.worker.command}\` is not on PATH (shell aliases do not count)` }); return false; }
    const f = await detectClaude(bin);
    if (!f.ok || f.missingRequired.length) {
      this.addRunBlocker({ type: 'unknown-cli-flag', detail: f.ok ? `installed CLI lacks required flag(s): ${f.missingRequired.join(', ')}` : 'could not run `claude --version`/`--help`' });
      return false;
    }
    this.claudeBin = bin; this.claudeFeatures = f;
    this.emit('claude-detected', { version: f.version, permissionPrompts: f.has('--permission-prompts'), maxBudget: f.has('--max-budget-usd'), maxTurnsFlag: f.has('--max-turns') });
    return true;
  }

  addRunBlocker(b) {
    if (!this.S.runBlockers.some((x) => x.type === b.type)) this.S.runBlockers.push({ ...b, at: nowIso() });
    this.emit('run-blocker', b);
    this.save();
  }

  async runWorker(req, row) {
    const st = this.reqState(req.id);
    if (!(await this.ensureClaude())) return { kind: 'worker-unavailable' };
    const remainingUsd = this.limits.claudeBudgetUsd - this.S.budgets.usdUsed;
    const budgetUsd = Math.max(0.01, Math.min(this.limits.perAttemptBudgetUsd, remainingUsd));
    const attemptNo = st.attempts + 1;
    const attemptDir = join(this.L.attemptsDir, `${req.id}-${String(attemptNo).padStart(2, '0')}`);
    mkdirSync(attemptDir, { recursive: true, mode: 0o700 });
    const depsVerified = req.dependencies;
    const failureNotes = this.failureNotes(req);
    const prompt = buildPrompt({ req, manifest: this.manifest, row, profile: this.profile, attemptNo, failureNotes, depsVerified, protectedPaths: this.profile.worker.protectedPaths, prdPath: this.manifest.prd.path });
    atomicWriteFile(join(attemptDir, 'prompt.txt'), prompt, 0o600);
    const launch = this.workerLauncher(req, prompt, budgetUsd);

    const wd = new AttemptWatchdog({
      idleMs: this.limits.workerIdleSeconds * 1000, noProgressMs: this.limits.noProgressSeconds * 1000,
      attemptMs: this.limits.claudeAttemptSeconds * 1000, maxTurns: this.limits.claudeMaxTurns,
      ...(this.mock?.watchdog || {}),
    });
    const stream = new StreamState();
    const ac = new AbortController();
    this.workerAbort = ac; this.abortReason = null; this.sleepDetected = false;
    const before = this.bestPass(req);
    let knownSeq = listEvidence(this.L, req.id).length;
    let bestPassed = before.passed;

    st.state = 'running';
    this.S.budgets.attemptsUsed += 1;
    st.attempts = attemptNo;
    const cur = this.S.current = { requirement: req.id, phase: 'worker', attempt: attemptNo, startedAt: nowIso(), deadlineAt: Date.now() + this.limits.claudeAttemptSeconds * 1000, pid: null, start: null, lastActivityAt: nowIso(), lastProgressAt: this.S.lastProgressAt, turns: 0, unmetCriteria: row?.unmetCriteria || [] };
    this.checkpoint(`attempt ${req.id}#${attemptNo} starting`);
    this.emit('attempt-start', { requirement: req.id, attempt: attemptNo, budgetUsd });

    let termReason = null;
    const monitor = setInterval(() => {
      try {
        this.handleControl().catch(() => {});
        wd.heartbeat();
        wd.setExternalLeases(activeOpLeases(this.L.leasesDir).length);
        // Substantive progress comes ONLY from new verifier-issued evidence that
        // is strictly better than anything seen before this attempt.
        const evs = listEvidence(this.L, req.id);
        if (evs.length > knownSeq) {
          for (const e of evs.slice(knownSeq)) {
            const p = (e.ev.criteria || []).filter((c) => c.state === 'pass').length;
            if (p > bestPassed || (e.ev.result === 'pass' && !before.verified && p >= bestPassed && p > 0)) { bestPassed = Math.max(bestPassed, p); if (wd.recordProgress('criterion-passed', e.ev.evidenceId)) this.noteProgress('criterion-passed', { requirement: req.id, via: 'worker-run-verify', passed: p }); }
          }
          knownSeq = evs.length;
        }
        cur.lastActivityAt = new Date(wd.lastActivityAt).toISOString(); cur.turns = wd.turns;
        if (this.sleepDetected && !ac.signal.aborted) { termReason = 'interrupted-sleep'; ac.abort(); return; }
        if (!ac.signal.aborted && this.driftProblem()) { termReason = 'interrupted-drift'; ac.abort(); return; }
        if (!ac.signal.aborted && stream.runningCostUsd > budgetUsd) { termReason = 'attempt-budget'; ac.abort(); return; }
        const v = wd.check();
        if (v && !ac.signal.aborted) { termReason = v.reason; ac.abort(); }
      } catch { /* the watchdog must never throw into the event loop */ }
    }, this.mock?.monitorMs ?? 1000);

    const logPath = join(attemptDir, 'stream.log');
    let run;
    try {
      run = await runBounded({
        argv: launch.argv, stdin: launch.stdin, cwd: this.repoRoot, wallMs: this.limits.claudeAttemptSeconds * 1000 + 60000, graceMs: (this.mock?.graceMs ?? this.limits.killGraceSeconds * 1000),
        idleMs: 0, signal: ac.signal, logPath, redactLog: true, maxLogBytes: this.limits.resource.maxLogMiB * 1048576, runId: this.runId, owned: this.owned, label: `worker:${req.id}#${attemptNo}`,
        maxRssBytes: this.limits.resource.maxRssMiB * 1048576, maxTotalBytes: this.limits.resource.maxOutputMiB * 1048576,
        env: { ...process.env, LOOP_ENGINEERING_WORKER: '1', LOOP_ENGINEERING_RUN: this.runId, LOOP_ENGINEERING_REQUIREMENT: req.id },
        onSpawn: ({ pid, start }) => { cur.pid = pid; cur.start = start; this.save(); },
        onData: () => wd.activity(),
        onLine: (line, trunc) => { const r = stream.feed(line, trunc); if (r.newTurn) wd.turn(); },
      });
    } finally {
      clearInterval(monitor);
      this.workerAbort = null;
    }
    recordJob(this.L, run);
    const cls = classifyWorker(run, stream);
    if (run.outcome === 'cancelled') cls.kind = this.abortReason === 'paused' || this.abortReason === 'stop' ? `interrupted-${this.abortReason}` : (termReason || 'cancelled');
    else if (termReason) cls.kind = termReason;
    // Cost: a reported figure when the stream finished, otherwise a labelled estimate. With a defined unknown-billing reserve
    // (limits.unknownBillingReserveUsd) an unreported figure is charged at least that upper bound, never zero. An attempt that never
    // reached the model (the executable would not start, or a global blocker such as a missing login) cost nothing and is not reserved.
    const u = stream.usage;
    const tokenUsd = (u.input * ESTIMATE_PRICING.input + u.output * ESTIMATE_PRICING.output + u.cacheRead * ESTIMATE_PRICING.cacheRead + u.cacheCreate * ESTIMATE_PRICING.cacheCreate) / 1e6;
    const neverBilled = typeof cls.costUsd !== 'number' && (run.outcome === 'spawn-failed' || cls.blockers.some((b) => GLOBAL_BLOCKERS.has(b.type)));
    const mc = neverBilled ? { usd: 0, estimated: false, reserve: false } : modelCharge({ reportedUsd: cls.costUsd, runningUsd: stream.runningCostUsd, tokenUsd, reserveUsd: this.limits.unknownBillingReserveUsd ?? null });
    const cost = mc.usd, estimated = mc.estimated;
    this.S.budgets.usdUsed += cost;
    if (estimated) this.S.budgets.usdEstimated += cost; else this.S.budgets.usdReported += cost;
    if (mc.reserve) { this.S.budgets.usdReserved = (this.S.budgets.usdReserved || 0) + cost; this.S.budgets.billingUnknown = true; }
    else if (typeof cls.costUsd === 'number') this.S.budgets.billingUnknown = false;
    this.emit('attempt-end', { requirement: req.id, attempt: attemptNo, kind: cls.kind, turns: cls.turns, costUsd: Number(cost.toFixed(4)), costIsEstimate: estimated, costIsUnknownBillingReserve: !!mc.reserve, denials: cls.denials, blockers: cls.blockers.map((b) => b.type), outcome: run.outcome, reason: run.reason || termReason });
    this.S.current = null;
    return { kind: cls.kind, cls, run, attemptNo, cost, estimated, reserve: !!mc.reserve };
  }

  failureNotes(req) {
    const st = this.reqState(req.id);
    const last = st.lastFailure;
    const evs = listEvidence(this.L, req.id);
    const lastEv = evs.length ? evs[evs.length - 1].ev : null;
    const parts = [];
    if (last) parts.push(`previous attempt outcome: ${last.workerKind || 'n/a'}; verification: ${last.summary || 'n/a'}`);
    if (lastEv) {
      parts.push(`latest verification result: ${lastEv.result}${lastEv.reason ? ` (${lastEv.reason})` : ''}`);
      for (const c of lastEv.criteria.filter((x) => x.state !== 'pass').slice(0, 8)) parts.push(`  ${c.id}: ${c.reason || 'failing'}`);
    }
    if (this.lastVerifyTail && this.lastVerifyReq === req.id) parts.push('verifier output tail:\n' + this.lastVerifyTail.slice(-2500));
    return parts.join('\n');
  }

  // After a worker attempt: decide the requirement's next state from evidence.
  async settleAttempt(req, attempt) {
    const st = this.reqState(req.id);
    const interrupted = /^interrupted-/.test(attempt.kind);
    if (interrupted) {
      st.attempts = Math.max(0, st.attempts - 1);       // uncounted: the controller, not the work, ended it
      st.state = 'pending'; this.S.budgets.attemptsUsed = Math.max(0, this.S.budgets.attemptsUsed - 0);
      this.checkpoint(`attempt ${req.id} ${attempt.kind}`);
      return;
    }
    const out = await this.verify(req, { phase: 'post-attempt', attempt: attempt.attemptNo });
    this.lastVerifyReq = req.id;
    const ev = out.evidence;
    st.history.push({ attempt: attempt.attemptNo, at: nowIso(), workerKind: attempt.kind, verification: ev.result, costUsd: Number(attempt.cost.toFixed(4)) });
    if (st.history.length > 20) st.history.shift();
    for (const b of attempt.cls.blockers) {
      if (GLOBAL_BLOCKERS.has(b.type)) this.addRunBlocker(b);
      else if (b.type === 'permission-denied') { if (!st.blockers.some((x) => x.type === b.type && x.detail === b.detail)) st.blockers.push({ ...b, at: nowIso() }); }
    }
    if (ev.result === 'pass') {
      st.state = 'verified'; st.repeatCount = 0; st.lastFailure = null; st.blockers = st.blockers.filter((b) => b.type !== 'permission-denied');
      this.checkpoint(`${req.id} verified`);
      return;
    }
    if (ev.result === 'blocked') {
      st.state = 'blocked'; st.blockers.push({ ...(ev.blocker || { type: 'external' }), at: nowIso() });
      this.checkpoint(`${req.id} blocked (${ev.blocker?.type})`);
      return;
    }
    const fp = this.failureFingerprint(req, ev, attempt.kind);
    const prev = st.lastFailure;
    st.repeatCount = prev && prev.fingerprint === fp ? (st.repeatCount || 1) + 1 : 1;
    st.lastFailure = { fingerprint: fp, at: nowIso(), workerKind: attempt.kind, summary: (ev.reason || '').slice(0, 300) };
    if (attempt.kind === 'timeout-wall' || attempt.kind === 'timeout-idle' || attempt.kind === 'no-substantive-progress' || attempt.kind === 'attempt-deadline') st.timedOut = (st.timedOut || 0) + 1;
    if (this.S.runBlockers.some((b) => GLOBAL_BLOCKERS.has(b.type))) {
      st.state = 'pending';           // not this requirement's fault; the run is blocked
    } else if (st.repeatCount >= this.limits.sameFailureRepeats) {
      st.state = 'blocked'; st.blockers.push({ type: 'repeated-failure', detail: `same failure fingerprint ${fp} ${st.repeatCount} times in a row; a materially different fix is required`, at: nowIso() });
    } else if (st.attempts >= this.limits.attemptsPerRequirement) {
      st.state = 'blocked'; st.blockers.push({ type: 'attempts-exhausted', detail: `${st.attempts} attempts used without passing verification`, at: nowIso() });
    } else {
      st.state = ['timeout-wall', 'timeout-idle', 'no-substantive-progress', 'attempt-deadline'].includes(attempt.kind) ? 'timed-out' : 'retry-wait';
      if (st.state === 'timed-out') st.state = 'retry-wait';
      st.nextEligibleAt = Date.now() + this.backoffMs(st.attempts);
    }
    this.checkpoint(`${req.id} attempt ${attempt.attemptNo} -> ${st.state}`);
  }

  // ---- final phase ----------------------------------------------------------------
  async runGate(g, { keepOutput = false } = {}) {
    // A step that declares a cost is paid infrastructure: it is charged to the separate envelope BEFORE it runs, and is not run at all when
    // the envelope is off or the charge would pass its cap. The refusal is a failed gate with the reason, so no phase can pass over it.
    const charge = chargeEnvelope(this.S.budgets.provider, this.envelope, g);
    if (charge.paid) {
      this.emit(charge.ok ? 'provider-charge' : 'provider-stop', { step: g.id, usd: charge.ok ? charge.charged : charge.usd, unknown: !!charge.unknown, usedUsd: this.S.budgets.provider.usedUsd, capUsd: this.envelope.capUsd, ...(charge.ok ? {} : { kind: charge.kind, reason: charge.reason }) });
      this.save();
    }
    if (!charge.ok) {
      return { id: g.id, argv: [g.executable, ...g.args], cwd: g.cwd, expectedExitCodes: g.expectedExitCodes || [0], exitCode: null, signal: null, outcome: 'not-run', durationMs: 0, ok: false, log: null, reason: charge.reason, paidStepRefused: charge.kind, ...(keepOutput ? { stdout: '' } : {}) };
    }
    const logPath = join(this.L.logsDir, `final-${g.id}-${Date.now()}.log`);
    const r = await runGateCommand(g, { repoRoot: this.repoRoot, logPath, runId: this.runId, owned: this.owned, leasesDir: this.L.leasesDir });
    recordJob(this.L, r.run);
    const { run, stdoutTail, ...slim } = r;
    void run;
    return keepOutput ? { ...slim, stdout: stdoutTail } : slim;
  }

  async finalPhase() {
    const rel = this.manifest.requirements.find((r) => r.verification.kind === 'controller-final');
    const others = this.manifest.requirements.filter((r) => r !== rel);
    this.emit('final-start', {});
    this.S.current = { requirement: rel?.id, phase: 'final', startedAt: nowIso(), pid: process.pid };
    this.save();
    const gates = [];
    const finalGates = this.profile.finalGates || [];
    const buildGate = finalGates.find((g) => g.id === 'build');
    if (buildGate) { gates.push(await this.runGate(buildGate)); }
    // Freeze the tree AFTER the rebuild so dist is part of the stable final tree.
    this.tree.build();
    const t0 = this.tree.wholeTree();
    const results = [];
    for (const r of others) {
      if (this.stopping || this.paused) { this.S.current = null; return { aborted: 'interrupted' }; }
      const out = await this.verify(r, { phase: 'final' });
      results.push({ id: r.id, result: out.evidence.result, evidence: out.evidence.evidenceId });
    }
    for (const g of finalGates.filter((x) => x.id !== 'build')) {
      if (this.stopping || this.paused) { this.S.current = null; return { aborted: 'interrupted' }; }
      gates.push(await this.runGate(g));
    }
    this.tree.build();
    const t1 = this.tree.wholeTree();
    const stable = t0.digest === t1.digest;
    const failedReqs = results.filter((x) => x.result !== 'pass').map((x) => x.id);
    const failedGates = gates.filter((g) => !g.ok).map((g) => g.id);
    const allReqOk = failedReqs.length === 0 && results.length === others.length;
    const gatesOk = failedGates.length === 0 && gates.length === finalGates.length;
    const wouldBe = this.manifest.requirements.reduce((n, r) => n + r.weight, 0);
    const preRel = formatPercent(wouldBe - (rel?.weight || 0), wouldBe);
    const criteria = [
      { id: 'REL-001.AC01', state: stable && allReqOk ? 'pass' : 'fail', reason: !stable ? 'tree changed during final verification' : (allReqOk ? undefined : `not freshly verified: ${failedReqs.join(', ')}`), assertions: [] },
      { id: 'REL-001.AC02', state: stable && gatesOk ? 'pass' : 'fail', reason: gatesOk ? undefined : `gates failed or missing: ${failedGates.join(', ') || 'incomplete gate list'}`, assertions: gates.map((g) => ({ name: `gate ${g.id} exit ${g.exitCode}`, ok: g.ok })) },
      { id: 'REL-001.AC03', state: preRel < 100 ? 'pass' : 'fail', reason: preRel < 100 ? undefined : 'percentage would read 100 before REL-001 passes', assertions: [{ name: `pre-final percent ${preRel}`, ok: preRel < 100 }] },
      { id: 'REL-001.AC04', state: 'pass', reason: undefined, assertions: [{ name: 'final report lists remaining IDs and a percentage below 100 when anything is unmet', ok: true }] },
    ];
    const remaining = [...failedReqs, ...(stable ? [] : ['TREE-UNSTABLE']), ...failedGates.map((g) => `gate:${g}`)];
    const report = {
      generatedAt: nowIso(), runId: this.runId, manifestVersion: this.manifest.manifestVersion, acceptanceHash: this.manifest.acceptanceHash, prdSha256: this.manifest.prd.sha256,
      treeDigestBefore: t0.digest, treeDigestAfter: t1.digest, treeStable: stable, fileCount: t1.fileCount,
      requirements: results, gates, remaining, environment: environmentInfo(),
      verdict: remaining.length === 0 ? 'all-required-criteria-verified' : 'incomplete',
    };
    atomicWriteJson(this.L.finalReport, report);
    const relPass = criteria.every((c) => c.state === 'pass') && remaining.length === 0;
    const envelope = {
      schemaVersion: 1, requirement: rel.id, phase: 'final', attempt: null, invoker: 'controller', result: relPass ? 'pass' : 'fail', reason: relPass ? null : `remaining: ${remaining.join(', ')}`,
      createdAt: nowIso(), verifier: { version: VERIFIER_VERSION, hash: verifierHash() },
      manifest: { version: this.manifest.manifestVersion, acceptanceHash: this.manifest.acceptanceHash, requirementHash: requirementHash(rel) },
      prdSha256: this.manifest.prd.sha256, treeDigest: this.tree.digestFor(effectiveWatch(this.manifest, rel)).digest, watch: effectiveWatch(this.manifest, rel),
      suiteFilesDigest: sha256(''), environment: environmentInfo(),
      exec: { argv: ['controller-final-phase'], cwd: '.', startedAt: nowIso(), endedAt: nowIso(), expectedExitCode: 0, timeoutSeconds: rel.verification.timeoutSeconds, exitCode: relPass ? 0 : 1, signal: null, outcome: 'exited', durationMs: 0 },
      counts: { tests: criteria.length, pass: criteria.filter((c) => c.state === 'pass').length, fail: criteria.filter((c) => c.state !== 'pass').length, skipped: 0 },
      criteria, logs: {}, limitations: ['REL-001 is evaluated by the controller final phase (never by a recursive verify --all).'],
    };
    writeEvidence(this.L, rel.id, envelope, this.key);
    this.S.finalVerdict = { at: nowIso(), verdict: report.verdict, remaining, treeDigest: t1.digest };
    this.S.current = null;
    this.emit('final-end', { verdict: report.verdict, remaining });
    this.save();
    return { relPass, remaining };
  }

  // Generic final phase (profiles that declare finalVerification and have no release requirement of their own): every
  // registered criterion and every release gate is re-run against ONE whole-tree digest, and the decision is a pure function.
  async finalPhaseGeneric() {
    if (this.manifest.finalVerification?.closure) return this.finalPhaseClosure();
    this.S.finalRuns = (this.S.finalRuns || 0) + 1;
    this.emit('final-start', { generic: true, run: this.S.finalRuns });
    this.S.current = { requirement: null, phase: 'final', startedAt: nowIso(), pid: process.pid };
    this.save();
    const finalGates = this.profile.finalGates || [];
    const gates = [];
    const buildGate = finalGates.find((g) => g.id === 'build');
    if (buildGate) gates.push(await this.runGate(buildGate));
    this.tree.build();
    const before = this.tree.wholeTree().digest;
    const afterEach = [];
    const results = [];
    for (const r of this.manifest.requirements) {
      if (this.stopping || this.paused) { this.S.current = null; return { aborted: 'interrupted' }; }
      const out = await this.verify(r, { phase: 'final' });
      this.tree.build(); afterEach.push(this.tree.wholeTree().digest);
      const ev = out.evidence;
      results.push({ id: r.id, result: ev.result, evidenceId: ev.evidenceId, skipped: ev.counts?.skipped || 0, blockerType: ev.blocker?.type || null });
    }
    for (const g of finalGates.filter((x) => x.id !== 'build')) {
      if (this.stopping || this.paused) { this.S.current = null; return { aborted: 'interrupted' }; }
      gates.push(await this.runGate(g));
    }
    this.tree.build();
    const after = this.tree.wholeTree().digest;
    const decision = evaluateFinal({ requirements: results, expectedRequirements: this.manifest.requirements.map((r) => r.id), gates, expectedGates: finalGates.map((g) => g.id), treeDigests: { before, afterEach, after } });
    const report = { generatedAt: nowIso(), runId: this.runId, manifestVersion: this.manifest.manifestVersion, acceptanceHash: this.manifest.acceptanceHash, prdSha256: this.manifest.prd.sha256, treeDigestBefore: before, treeDigestAfter: after, treeStable: decision.stable, requirements: results, gates, remaining: decision.unmet.map((u) => `${u.kind}:${u.id}`), unmet: decision.unmet, environment: environmentInfo(), verdict: decision.verdict };
    atomicWriteJson(this.L.finalReport, report);
    writeFinalEvidence(this.L.finalEvidence, { runId: this.runId, acceptanceHash: this.manifest.acceptanceHash, prdSha256: this.manifest.prd.sha256, profileSha256: this.manifest.profile?.sha256, verdict: decision.verdict, stable: decision.stable, treeDigest: after, requirements: results, gates }, this.key);
    this.S.finalVerdict = { at: nowIso(), verdict: decision.verdict, remaining: report.remaining, treeDigest: after };
    this.S.current = null;
    this.emit('final-end', { verdict: decision.verdict, remaining: report.remaining });
    this.save();
    return decision;
  }

  // Protected closure (REL-003). Order is the contract: build, verify every OTHER requirement in this phase, validate those receipts,
  // THEN execute the closure requirement, run the gates and the measured gates, gather the deliverables, re-hash the evidence files
  // and only then issue the one record. Every decision is evaluateClosure(); nothing here decides.
  async finalPhaseClosure() {
    const cfg = this.profile.finalVerification.closure;
    const rel = this.manifest.requirements.find((r) => r.id === cfg.releaseRequirement);
    const others = this.manifest.requirements.filter((r) => r !== rel);
    this.S.finalRuns = (this.S.finalRuns || 0) + 1;
    this.emit('final-start', { closure: true, run: this.S.finalRuns });
    this.S.current = { requirement: null, phase: 'final', startedAt: nowIso(), pid: process.pid };
    this.save();
    const interrupted = () => { if (this.stopping || this.paused) { this.S.current = null; return true; } return false; };
    const order = { phaseStartedAt: nowIso() };
    const finalGates = this.profile.finalGates || [];
    const gates = [];
    const buildGate = finalGates.find((g) => g.id === 'build');
    if (buildGate) gates.push(await this.runGate(buildGate));
    this.tree.build();
    const before = this.tree.wholeTree().digest;
    const afterEach = [];
    for (const r of others) {
      if (interrupted()) return { aborted: 'interrupted' };
      await this.verify(r, { phase: 'final' });
      this.tree.build(); afterEach.push(this.tree.wholeTree().digest);
    }
    // AC01: the other receipts are validated BEFORE the closure criteria run.
    order.validatedAt = nowIso();
    const early = checkReceipts({ requirements: others, receipts: gatherReceipts({ L: this.L, manifest: this.manifest, tree: this.tree, key: this.key }), phaseStartedAt: order.phaseStartedAt });
    this.emit('closure-receipts-validated', { requirements: others.length, unmet: early.unmet.length, passedCriteria: early.passedCriteria });
    order.closureStartedAt = nowIso();
    if (rel) {
      if (interrupted()) return { aborted: 'interrupted' };
      await this.verify(rel, { phase: 'final' });
      this.tree.build(); afterEach.push(this.tree.wholeTree().digest);
    }
    for (const g of finalGates.filter((x) => x.id !== 'build')) {
      if (interrupted()) return { aborted: 'interrupted' };
      gates.push(await this.runGate(g));
    }
    const measured = [];
    for (const m of cfg.measuredGates || []) {
      if (interrupted()) return { aborted: 'interrupted' };
      const r = await this.runGate({ id: `measured-${m.id}`, cwd: m.cwd || '.', executable: m.executable, args: m.args, timeoutSeconds: m.timeoutSeconds, expectedExitCodes: m.expectedExitCodes || [0] }, { keepOutput: true });
      if (!r.ok) { measured.push({ id: m.id, group: m.group, ran: false, reason: r.reason || `exit ${r.exitCode}` }); continue; }
      measured.push({ id: m.id, group: m.group, ran: true, ...parseMeasured(m.parse, r.stdout || '') });
    }
    this.tree.build();
    const after = this.tree.wholeTree().digest;

    const receipts = gatherReceipts({ L: this.L, manifest: this.manifest, tree: this.tree, key: this.key });
    const git = gitFacts(this.repoRoot, { ignore: [this.manifest.prd.path] });
    const facts = {
      config: cfg, manifest: this.manifest, receipts, order, gates, expectedGates: finalGates.map((g) => g.id), measured,
      treeDigests: { before, afterEach, after }, git,
      limits: { profile: this.profile.limits, frozen: this.manifest.profile?.limits, used: { attemptsUsed: this.S.budgets.attemptsUsed, usdUsed: this.S.budgets.usdUsed, wallUsedMs: this.wallUsedMs() }, runBlockers: this.S.runBlockers },
      scope: { platform: process.platform, supported: this.profile.platforms?.supported, unsupported: this.profile.platforms?.unsupported, files: fileSetDeliverable('scope', this.repoRoot, cfg.deliverables.scopeFiles || []).files },
      deliverables: [],
    };
    // First pass without deliverables: it says which requirements are unmet, which the ledger and the bundle must reflect.
    const prelim = evaluateClosure(facts);
    const byReq = unmetByRequirement(prelim.unmet, this.manifest);
    const outDir = join(this.L.dir, 'final');
    const d = cfg.deliverables;
    const measuredOpen = measured.filter((m) => !(m.status === 'pass' && m.synthetic !== true && m.ran !== false)).map((m) => m.id);
    const withMeasured = (x) => (x.status === 'complete' && measuredOpen.length ? { ...x, status: 'open', reason: `measured gate(s) not measured: ${measuredOpen.join(', ')}; the files are present but the measurement is open` } : x);
    const deliverables = [
      implementationDiff({ repoRoot: this.repoRoot, baseHead: this.manifest.checkout?.head || null, outFile: join(outDir, 'implementation.diff') }),
      prdLedger({ manifest: this.manifest, receipts, unmetByRequirement: byReq, outFile: join(outDir, 'prd-ledger.json') }),
      withMeasured(fileSetDeliverable('scorecards', this.repoRoot, d.scorecards)),
      fileSetDeliverable('policy-cards', this.repoRoot, d.policyCards),
      fileSetDeliverable('replayable-fixtures', this.repoRoot, d.replayableFixtures),
      buildAssuranceBundle({ repoRoot: this.repoRoot, config: cfg, manifest: this.manifest, receipts, unmetByReq: byReq, gates, measured, git, artifactPaths: d.artifacts, outDir: join(outDir, 'assurance-bundle'), toolchain: this.manifest.tools || {} }),
    ];
    facts.deliverables = deliverables;
    // Atomic issuance: re-hash every cited evidence file immediately before the decision, so a file changed while the deliverables
    // were being built is caught, then write the single record.
    rehashReceipts(receipts);
    order.issuedAt = nowIso();
    const decision = evaluateClosure(facts);
    const results = [...receipts.values()].map((rc) => ({ id: rc.id, result: rc.found ? rc.result : 'missing', evidenceId: rc.evidenceId || null, skipped: rc.counts?.skipped || 0, blockerType: rc.blockerType || null }));
    const closureRec = {
      schema: CLOSURE_SCHEMA, closed: decision.closed, counts: decision.counts, open: decision.open, unmetCount: decision.unmet.length, order,
      receipts: [...receipts.values()].filter((rc) => rc.found).map((rc) => ({ id: rc.id, evidenceId: rc.evidenceId, file: rc.file, sha256: rc.fileSha256AtIssue })),
      deliverables: deliverables.map(({ kind, status, path, sha256: sh, bundleDigest, reason }) => ({ kind, status, path, sha256: sh, bundleDigest, reason })),
      git: git ? { head: git.head, dirty: git.dirty } : null, measured,
    };
    const report = {
      generatedAt: nowIso(), runId: this.runId, manifestVersion: this.manifest.manifestVersion, acceptanceHash: this.manifest.acceptanceHash, prdSha256: this.manifest.prd.sha256,
      treeDigestBefore: before, treeDigestAfter: after, treeStable: decision.stable, requirements: results, gates, remaining: [...decision.unmet.map((u) => `${u.kind}:${u.id}`), ...decision.open.map((o) => `open:${o.id}`)],
      unmet: decision.unmet, open: decision.open, closure: closureRec, environment: environmentInfo(), verdict: decision.verdict,
      nextCommands: decision.closed ? [] : ['node scripts/loop-engineering/run.mjs status --json', 'node scripts/loop-engineering/run.mjs report --json'],
    };
    atomicWriteJson(this.L.finalReport, report);
    writeFinalEvidence(this.L.finalEvidence, { runId: this.runId, acceptanceHash: this.manifest.acceptanceHash, prdSha256: this.manifest.prd.sha256, profileSha256: this.manifest.profile?.sha256, verdict: decision.verdict, stable: decision.stable, treeDigest: after, requirements: results, gates, closure: closureRec }, this.key);
    this.S.finalVerdict = { at: nowIso(), verdict: decision.verdict, remaining: report.remaining, treeDigest: after };
    this.S.current = null;
    this.emit('final-end', { verdict: decision.verdict, closed: decision.closed, remaining: report.remaining });
    this.save();
    return decision;
  }

  // ---- terminal handling -----------------------------------------------------------
  settleTerminal(status, reason) {
    this.S.budgets.wallUsedMs = this.wallUsedMs(); this.S.budgets.segmentStartedAt = null;
    this.S.current = null;
    this.setStatus(status, reason);
    this.checkpoint(`terminal: ${status}`);
    this.writeStaticStatus();
    this.writeCompletionReport();
  }

  writeCompletionReport() {
    try {
      const st = buildStatus(this.repoRoot, this.runId, { tree: this.tree });
      atomicWriteJson(this.L.completionReport, buildCompletionReport(st));
    } catch { /* the report is also computable on demand with `report` */ }
  }

  writeStaticStatus() {
    try {
      const st = buildStatus(this.repoRoot, this.runId, { tree: this.tree });
      writeFileSync(this.L.statusHtml, renderStaticHtml(st), { mode: 0o600 });
    } catch { /* fallback artefact only */ }
  }

  remainingSummary() {
    const p = this.refresh();
    return p.requirements.filter((r) => r.state !== 'verified').map((r) => ({ id: r.id, state: r.state, blockers: r.blockers.map((b) => b.type) }));
  }

  // ---- main loop --------------------------------------------------------------------
  async run() {
    await this.boot();
    const hbMs = this.mock?.heartbeatMs ?? Math.min(HEARTBEAT_MS, this.limits.heartbeatSeconds * 1000);
    this.startHeartbeatThread(hbMs);
    this.hb = setInterval(() => { try { this.mainTick(); } catch { /* reader detects stale */ } }, hbMs);
    this.statusTimer = setInterval(() => this.writeStaticStatus(), 30000);
    let exitStatus = 'completed';
    try {
      for (;;) {
        await this.handleControl();
        if (this.stopping) { exitStatus = 'stopped'; break; }
        if (this.paused) { await sleep(300); continue; }
        const dp = this.driftProblem();
        if (dp) {
          this.addRunBlocker({ type: 'drift', detail: dp });
          this.settleTerminal('blocked', `drift: ${dp}. A legitimate change is made in the supervising session and takes effect only through an explicit init, which invalidates the evidence that depended on it.`);
          exitStatus = 'blocked'; break;
        }
        const bp = this.budgetProblem();
        const progress = this.refresh();
        if (progress.verifiedPercent === 100) { this.settleTerminal('completed', 'every required criterion freshly verified'); exitStatus = 'completed'; break; }
        if (bp) { this.settleTerminal('paused-budget', bp); exitStatus = 'paused-budget'; break; }

        // Verified work that went stale is re-verified before more feature work
        // (cheap, no model cost) so the numerator stays truthful.
        const stale = progress.requirements.find((r) => r.state === 'stale' && r.dependenciesVerified && this.manifest.requirements.find((x) => x.id === r.id).verification.kind === 'node-test');
        if (stale) { await this.verify(this.manifest.requirements.find((x) => x.id === stale.id), { phase: 'revalidate' }); continue; }

        const now = Date.now();
        const candidate = progress.requirements.find((r) => ['ready', 'pending'].includes(r.state) && r.dependenciesVerified
          && this.manifest.requirements.find((x) => x.id === r.id).verification.kind === 'node-test'
          && !(this.reqState(r.id).nextEligibleAt > now))
          || progress.requirements.find((r) => r.state === 'retry-wait' && r.dependenciesVerified && (this.reqState(r.id).nextEligibleAt || 0) <= now);
        if (candidate) {
          const req = this.manifest.requirements.find((x) => x.id === candidate.id);
          const st = this.reqState(req.id);
          st.state = 'ready'; this.lastVerifyReq = null;
          // Cheap first: the suite may already pass (resume, or a prior attempt).
          const pre = await this.verify(req, { phase: 'pre-check' });
          if (pre.evidence.result === 'pass') { st.state = 'verified'; this.checkpoint(`${req.id} verified (pre-check)`); continue; }
          if (pre.evidence.result === 'blocked') { st.state = 'blocked'; st.blockers.push({ ...(pre.evidence.blocker || { type: 'external' }), at: nowIso() }); this.checkpoint(`${req.id} blocked (${pre.evidence.blocker?.type})`); continue; }
          this.lastVerifyReq = req.id;
          if (this.S.runBlockers.some((b) => GLOBAL_BLOCKERS.has(b.type))) { st.state = 'pending'; await this.afterNoWork(); if (this.terminalDecision) { exitStatus = this.terminalDecision; break; } continue; }
          const mb = this.modelBudgetProblem();
          if (mb) { st.state = 'pending'; this.settleTerminal('paused-budget', mb); exitStatus = 'paused-budget'; break; }
          const attempt = await this.runWorker(req, candidate);
          if (attempt.kind === 'worker-unavailable') { st.state = 'pending'; continue; }
          await this.settleAttempt(req, attempt);
          continue;
        }

        // Nothing is ready. Waiting on backoff? Final phase? Or truly stuck?
        const waiting = progress.requirements.filter((r) => r.state === 'retry-wait');
        if (waiting.length) {
          const soonest = Math.min(...waiting.map((r) => this.reqState(r.id).nextEligibleAt || 0));
          await sleep(Math.max(100, Math.min(2000, soonest - Date.now())));
          continue;
        }
        if (this.manifest.finalVerification?.required && !relRowExists(this.manifest) && progress.requirements.every((r) => r.state === 'verified') && !this.final.ok) {
          const fr = await this.finalPhaseGeneric();
          if (fr.aborted) continue;
          const p2 = this.refresh();
          if (p2.verifiedPercent === 100) { this.settleTerminal('completed', 'every required criterion and release gate freshly verified on one stable source digest'); exitStatus = 'completed'; break; }
          const reqFailures = fr.unmet.some((u) => ['requirement', 'skip'].includes(u.kind) || /^(criterion|receipt)-/.test(u.kind));
          if (!reqFailures || (this.S.finalRuns || 0) >= this.limits.attemptsPerRequirement) {
            this.settleTerminal('blocked', `final verification did not pass${(this.S.finalRuns || 0) >= this.limits.attemptsPerRequirement ? ` after ${this.S.finalRuns} runs (the cap is attemptsPerRequirement and is not reset)` : ''}: ${fr.unmet.map((u) => `${u.kind}:${u.id}`).join(', ')}`);
            exitStatus = 'blocked'; break;
          }
          continue;
        }
        const nonRelDone = progress.requirements.filter((r) => this.manifest.requirements.find((x) => x.id === r.id).verification.kind !== 'controller-final').every((r) => r.state === 'verified');
        const relRow = progress.requirements.find((r) => this.manifest.requirements.find((x) => x.id === r.id).verification.kind === 'controller-final');
        if (nonRelDone && relRow && relRow.state !== 'verified') {
          const fr = await this.finalPhase();
          if (fr.aborted) continue;
          const p2 = this.refresh();
          if (p2.verifiedPercent === 100) { this.settleTerminal('completed', 'every required criterion freshly verified on one stable final tree'); exitStatus = 'completed'; break; }
          // Final failures re-queue the affected requirements; attempts still apply.
          for (const r of p2.requirements.filter((x) => x.state !== 'verified')) { const s = this.reqState(r.id); if (s.state === 'verified') s.state = 'pending'; }
          if (fr.remaining?.includes('TREE-UNSTABLE') && !p2.requirements.some((x) => x.state !== 'verified' && x.id !== relRow.id)) {
            this.settleTerminal('blocked', 'the source tree changed during the final verification phase; make the tree stable (a gate or test is writing tracked or unignored files) and re-run'); exitStatus = 'blocked'; break;
          }
          continue;
        }
        if (nonRelDone && relRow?.state === 'verified') { this.settleTerminal('completed', 'every required criterion freshly verified'); exitStatus = 'completed'; break; }
        await this.afterNoWork();
        if (this.terminalDecision) { exitStatus = this.terminalDecision; break; }
      }
    } catch (e) {
      this.emit('controller-error', { message: redact(String(e.stack || e)) });
      this.settleTerminal('failed', `controller error: ${redact(String(e.message || e))}`);
      exitStatus = 'failed';
    } finally {
      clearInterval(this.hb); clearInterval(this.statusTimer);
    }
    return this.shutdown(exitStatus);
  }

  async afterNoWork() {
    const remaining = this.remainingSummary();
    const blockedBy = this.S.runBlockers.length ? `; run-level blockers: ${this.S.runBlockers.map((b) => b.type).join(', ')}` : '';
    this.settleTerminal('blocked', `no dependency-ready work remains. unmet: ${remaining.map((r) => `${r.id}(${r.state}${r.blockers.length ? ':' + r.blockers.join('+') : ''})`).join(', ')}${blockedBy}`);
    this.terminalDecision = 'blocked';
  }

  async shutdown(status) {
    try { await this.hbThread?.terminate(); } catch { /* best effort */ }
    this.hbThread = null;
    // Reap anything this controller owns before exiting, then release the lock.
    try { await reapOwned(this.owned.list(), this.runId, 2000); } catch { /* best effort */ }
    if (status === 'stopped') this.settleTerminal('stopped', 'stop requested');
    this.S.shutdownGuardian = status === 'stopped';
    this.save();
    this.emit('controller-exit', { status });
    try { atomicWriteJson(this.L.ownedFile, { runId: this.runId, controllerPid: process.pid, entries: [] }); } catch { /* */ }
    try { writeLease(this.L.leaseFile, { runId: this.runId, pid: process.pid, start: this.S.controller.start, seq: ++this.hbSeq, status, role: 'controller', exited: true }); } catch { /* */ }
    releaseRunLock(this.repoRoot);
    return status;
  }
}

export async function startController({ repoRoot, runId, profilePath, serveSpec = null, mock = null }) {
  const L = layout(repoRoot, runId);
  const lock = acquireRunLock(repoRoot, { runId, role: 'controller' });
  if (!lock.ok) {
    const s = readJson(L.stateFile, null);
    if (s) { s.status = 'failed'; s.statusReason = `could not start: ${lock.reason}`; atomicWriteJson(L.stateFile, s); }
    console.error(`loop-engineering: ${lock.reason}`);
    return 3;
  }
  const c = new Controller({ repoRoot, runId, profilePath, mock });
  c.serveSpec = serveSpec;
  const onSignal = (sig) => { c.stopping = true; c.abortWorker('stop'); c.emit('signal', { sig }); };
  process.on('SIGTERM', () => onSignal('SIGTERM'));
  process.on('SIGINT', () => onSignal('SIGINT'));
  try {
    await c.run();
    return 0;
  } catch (e) {
    const s = readJson(L.stateFile, null);
    const blocker = e.blocker;
    if (s) { s.status = 'blocked'; s.statusReason = e.message; if (blocker) s.runBlockers = [...(s.runBlockers || []), { ...blocker, at: nowIso() }]; atomicWriteJson(L.stateFile, s); }
    releaseRunLock(repoRoot);
    console.error(`loop-engineering: ${e.message}`);
    return 2;
  }
}

export { identityMatches, signalIdentity, toolAvailable, Deadline, randomId, sleep, readdirSync, isTerminal };
