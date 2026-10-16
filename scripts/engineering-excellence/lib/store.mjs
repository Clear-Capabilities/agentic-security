// Durable status store for the Engineering Excellence program.
//
// Guarantees (each one has a test in scanner/test/engineering-excellence/):
//   * every write is a read-modify-write under a file lock whose owner is checked for liveness (a dead owner's lock is recovered,
//     a live owner's is never stolen), then an atomic write-then-rename, so two writers cannot lose an update and a reader never
//     sees a half-written file;
//   * a malformed or schema-violating status.json is a hard, explicit failure (StatusCorruptError), never silently reset; the previous
//     good copy is kept as status.json.bak and `restoreBackup` is the only way back;
//   * a task becomes `done` or `already_satisfied` only through `completeTask` / `satisfyTask`, which build the evidence from commands
//     the runner actually executed and logged (exit code, log file, log hash) and refuse when there is none.
import { execFileSync } from 'node:child_process';
import { copyFileSync, existsSync, mkdirSync, readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, isAbsolute, join, normalize, relative, resolve } from 'node:path';
import { appendJsonl, atomicWriteJson, nowIso, withFileLock } from '../../loop-engineering/lib/util.mjs';
import { isAlive } from '../../loop-engineering/lib/procscan.mjs';
import { EE_DIR, MAX_COMMAND_RECORDS, REPO_ROOT, STALE_HEARTBEAT_MS, TRANSITIONS, VERIFIED_STATES, validateStatus } from './model.mjs';

export class StatusCorruptError extends Error {
  constructor(message, problems = []) { super(message); this.name = 'StatusCorruptError'; this.problems = problems; }
}
export class TransitionError extends Error {
  constructor(message) { super(message); this.name = 'TransitionError'; }
}

export function paths(root = REPO_ROOT) {
  const dir = root === REPO_ROOT ? EE_DIR : join(root, 'scripts', 'engineering-excellence');
  return {
    root, dir,
    tasks: join(dir, 'tasks.json'),
    status: join(dir, 'status.json'),
    backup: join(dir, 'status.json.bak'),
    events: join(dir, 'events.jsonl'),
    lock: join(dir, 'status.lock'),
    logs: join(dir, 'logs'),
  };
}

const sha256File = (p) => createHash('sha256').update(readFileSync(p)).digest('hex');

/** Commit, branch and whether the worktree has uncommitted changes. Every field is null when git cannot answer. */
export function checkoutInfo(root = REPO_ROOT) {
  const git = (args) => { try { return execFileSync('git', args, { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 15000 }).trim(); } catch { return null; } };
  const commit = git(['rev-parse', 'HEAD']);
  const branch = git(['rev-parse', '--abbrev-ref', 'HEAD']);
  const porcelain = git(['status', '--porcelain']);
  return { commit, branch, dirty: porcelain === null ? null : porcelain.length > 0, capturedAt: nowIso() };
}

export function loadManifest(root = REPO_ROOT) {
  const p = paths(root).tasks;
  if (!existsSync(p)) throw new Error(`no task manifest at ${p}; run init.mjs`);
  let doc;
  try { doc = JSON.parse(readFileSync(p, 'utf8')); } catch (e) { throw new Error(`task manifest ${p} is not valid JSON: ${e.message}`); }
  if (!doc || !Array.isArray(doc.tasks) || doc.schemaVersion !== 1) throw new Error(`task manifest ${p} has an unsupported shape`);
  return doc;
}

export function readStatus(root = REPO_ROOT) {
  const p = paths(root).status;
  if (!existsSync(p)) return null;
  let doc;
  try { doc = JSON.parse(readFileSync(p, 'utf8')); } catch (e) {
    throw new StatusCorruptError(`status.json is not valid JSON (${e.message}); it was not modified. Inspect status.json.bak or run: node scripts/engineering-excellence/status.mjs --restore-backup`, ['invalid-json']);
  }
  const problems = validateStatus(doc);
  if (problems.length) throw new StatusCorruptError(`status.json violates its schema (${problems.slice(0, 3).join('; ')}); it was not modified`, problems);
  return doc;
}

/** Replace a corrupt status.json with the last good backup. Refuses when the backup is itself unusable. */
export function restoreBackup(root = REPO_ROOT) {
  const P = paths(root);
  if (!existsSync(P.backup)) throw new Error('there is no status.json.bak to restore from');
  let doc;
  try { doc = JSON.parse(readFileSync(P.backup, 'utf8')); } catch { throw new Error('status.json.bak is not valid JSON; nothing was restored'); }
  const problems = validateStatus(doc);
  if (problems.length) throw new Error(`status.json.bak violates the schema (${problems[0]}); nothing was restored`);
  withFileLock(P.lock, () => { atomicWriteJson(P.status, doc); appendJsonl(P.events, { at: nowIso(), type: 'restored_from_backup', revision: doc.revision }); }, { hardMs: 30000 });
  return doc;
}

function newTask() { return { state: 'pending', attempts: 0, startedAt: null, completedAt: null, heartbeatAt: null, activeProcess: null, exitCode: null, commit: null, blocker: null, failure: null, commands: [], evidence: null, notes: [] }; }

/**
 * Create status.json, or bring an existing one up to date with the manifest. Existing task entries (state, evidence, history) are
 * never touched; tasks new to the manifest are added as pending. A task in status.json that the manifest no longer lists is an error:
 * silently dropping recorded evidence is the failure this whole structure exists to prevent.
 */
export function initStatus(root = REPO_ROOT, manifest = loadManifest(root)) {
  const P = paths(root);
  mkdirSync(P.dir, { recursive: true });
  return withFileLock(P.lock, () => {
    let doc = readStatus(root);
    const created = !doc;
    const now = nowIso();
    if (!doc) doc = { schemaVersion: 1, program: manifest.program, createdAt: now, updatedAt: now, revision: 0, checkout: checkoutInfo(root), tasks: {} };
    const known = new Set(manifest.tasks.map((t) => t.id));
    const stray = Object.keys(doc.tasks).filter((id) => !known.has(id));
    if (stray.length) throw new StatusCorruptError(`status.json records task(s) the manifest does not define: ${stray.join(', ')}; refusing to drop their evidence`, stray);
    let added = 0;
    for (const t of manifest.tasks) if (!doc.tasks[t.id]) { doc.tasks[t.id] = newTask(); added++; }
    if (created || added) {
      doc.updatedAt = now; doc.revision++; doc.checkout = checkoutInfo(root);
      persist(P, doc, { at: now, type: created ? 'initialised' : 'tasks_added', added });
    }
    return { doc, created, added };
  }, { hardMs: 30000 });
}

function persist(P, doc, event) {
  const problems = validateStatus(doc);
  if (problems.length) throw new StatusCorruptError(`refusing to write a status document that violates the schema: ${problems[0]}`, problems);
  if (existsSync(P.status)) { try { copyFileSync(P.status, P.backup); } catch { /* the backup is a convenience; the write below is the point */ } }
  atomicWriteJson(P.status, doc);
  if (event) appendJsonl(P.events, event);
}

/** Read-modify-write under the lock. `fn(doc, manifest)` mutates the document and returns an event (or undefined). */
export function mutate(root, fn) {
  const P = paths(root);
  const manifest = loadManifest(root);
  return withFileLock(P.lock, () => {
    const doc = readStatus(root);
    if (!doc) throw new Error('status.json does not exist; run init.mjs');
    const event = fn(doc, manifest);
    const now = nowIso();
    doc.updatedAt = now; doc.revision++;
    persist(P, doc, event ? { at: now, revision: doc.revision, ...event } : null);
    return doc;
  }, { hardMs: 30000 });
}

export const isVerified = (task) => !!task && VERIFIED_STATES.includes(task.state);

function requireTask(doc, manifest, id) {
  const def = manifest.tasks.find((t) => t.id === id);
  if (!def) throw new TransitionError(`unknown task ${id}`);
  const st = doc.tasks[id];
  if (!st) throw new TransitionError(`task ${id} has no status entry; run init.mjs`);
  return { def, st };
}

function move(st, id, to) {
  if (!TRANSITIONS[st.state]?.includes(to)) throw new TransitionError(`${id}: ${st.state} -> ${to} is not an allowed transition`);
  st.state = to;
}

export function startTask(root, id) {
  return mutate(root, (doc, manifest) => {
    const { def, st } = requireTask(doc, manifest, id);
    const open = def.requires.filter((r) => !isVerified(doc.tasks[r]));
    if (open.length) throw new TransitionError(`${id} cannot start: not yet verified: ${open.join(', ')}`);
    move(st, id, 'in_progress');
    doc.checkout = checkoutInfo(root);
    const now = nowIso();
    st.attempts++; st.startedAt = now; st.completedAt = null; st.heartbeatAt = now;
    st.blocker = null; st.failure = null; st.exitCode = null; st.evidence = null;
    return { type: 'task_started', task: id, attempt: st.attempts };
  });
}

export function heartbeat(root, id, { note } = {}) {
  return mutate(root, (doc, manifest) => {
    const { st } = requireTask(doc, manifest, id);
    if (st.state !== 'in_progress') throw new TransitionError(`${id} is ${st.state}, not in_progress`);
    st.heartbeatAt = nowIso();
    if (note) st.notes = [...st.notes, String(note).slice(0, 300)].slice(-20);
    return null;
  });
}

export function blockTask(root, id, { reason, nextAction = '', kind = 'external' }) {
  if (!reason) throw new TransitionError('a blocked task needs a reason');
  return mutate(root, (doc, manifest) => {
    const { st } = requireTask(doc, manifest, id);
    move(st, id, 'blocked');
    st.blocker = { reason: String(reason).slice(0, 600), nextAction: String(nextAction).slice(0, 600), at: nowIso(), kind };
    st.activeProcess = null;
    return { type: 'task_blocked', task: id, kind, reason: st.blocker.reason };
  });
}

export function failTask(root, id, { reason }) {
  if (!reason) throw new TransitionError('a failed task needs a reason');
  return mutate(root, (doc, manifest) => {
    const { st } = requireTask(doc, manifest, id);
    move(st, id, 'failed');
    st.failure = { reason: String(reason).slice(0, 600), at: nowIso() };
    st.activeProcess = null;
    return { type: 'task_failed', task: id, reason: st.failure.reason };
  });
}

export function resetToPending(root, id, reason) {
  return mutate(root, (doc, manifest) => {
    const { st } = requireTask(doc, manifest, id);
    move(st, id, 'pending');
    st.activeProcess = null;
    return { type: 'task_returned_to_pending', task: id, reason };
  });
}

// ---- commands the runner executed -------------------------------------------------------------------------------------

export function recordCommandStart(root, id, rec, { allowClosed = false } = {}) {
  return mutate(root, (doc, manifest) => {
    const { st } = requireTask(doc, manifest, id);
    if (st.state !== 'in_progress' && !(allowClosed && isVerified(st))) throw new TransitionError(`${id} is ${st.state}; start it before running commands for it`);
    const { pid, ...stored } = rec;
    st.commands = [...st.commands, stored].slice(-MAX_COMMAND_RECORDS);
    st.activeProcess = { pid: pid ?? process.pid, command: rec.argv.join(' ').slice(0, 300), startedAt: rec.startedAt, timeoutMs: rec.timeoutMs };
    st.heartbeatAt = nowIso();
    return { type: 'command_started', task: id, command: rec.id, argv0: rec.argv[0] };
  });
}

export function recordCommandHeartbeat(root, id, commandId) {
  return mutate(root, (doc, manifest) => {
    const { st } = requireTask(doc, manifest, id);
    if (st.state === 'in_progress') st.heartbeatAt = nowIso();
    void commandId;
    return null;
  });
}

export function recordCommandEnd(root, id, commandId, patch) {
  return mutate(root, (doc, manifest) => {
    const { st } = requireTask(doc, manifest, id);
    const rec = st.commands.find((c) => c.id === commandId);
    if (!rec) throw new TransitionError(`${id} has no command ${commandId}`);
    Object.assign(rec, patch);
    st.activeProcess = null; st.exitCode = patch.exitCode ?? null;
    if (st.state === 'in_progress') st.heartbeatAt = nowIso();
    return { type: 'command_finished', task: id, command: commandId, outcome: patch.outcome, exitCode: patch.exitCode ?? null };
  });
}

// ---- closing a task: evidence must be real -----------------------------------------------------------------------------

const TEST_FILE_RE = /(?:\.test\.(?:m?js|cjs|ts)|_test\.py|(?:^|\/)test_[^/]+\.py|_test\.go)$/;

function inRepo(root, rel) {
  if (typeof rel !== 'string' || !rel || isAbsolute(rel)) return null;
  const n = normalize(rel);
  if (n.startsWith('..')) return null;
  return resolve(root, n);
}

/** Test files named in a command's argv that exist under the repository. */
export function testFilesOf(root, argv, cwd) {
  const out = [];
  for (const a of argv.slice(1)) {
    if (!TEST_FILE_RE.test(a)) continue;
    for (const base of [cwd, root]) {
      const p = isAbsolute(a) ? a : resolve(base || root, a);
      if (existsSync(p)) { out.push(relative(root, p)); break; }
    }
  }
  return [...new Set(out)];
}

/**
 * The passing, logged test commands for the current attempt, or a list of reasons there are none. A distinct test command whose
 * LATEST run failed blocks completion: a green run earlier does not outvote a red run after it.
 */
export function collectTestEvidence(root, st) {
  const reasons = [];
  const since = st.startedAt || '';
  const latest = new Map();
  for (const c of st.commands) {
    if (c.kind !== 'test' || (c.startedAt || '') < since) continue;
    latest.set(c.argv.join('\u0000'), c);
  }
  const passing = [];
  for (const c of latest.values()) {
    if (c.outcome !== 'exited' || c.exitCode !== 0) { reasons.push(`the latest run of \`${c.argv.join(' ').slice(0, 120)}\` did not pass (${c.outcome}${c.exitCode == null ? '' : `, exit ${c.exitCode}`})`); continue; }
    if (!c.log || !c.logSha256) { reasons.push(`the run of \`${c.argv.join(' ').slice(0, 120)}\` has no log`); continue; }
    const lp = inRepo(root, c.log);
    if (!lp || !existsSync(lp)) { reasons.push(`log ${c.log} is missing`); continue; }
    if (sha256File(lp) !== c.logSha256) { reasons.push(`log ${c.log} changed after the run`); continue; }
    const files = testFilesOf(root, c.argv, c.cwd);
    if (!files.length) { reasons.push(`\`${c.argv.join(' ').slice(0, 120)}\` names no existing test file, so it does not exercise the task`); continue; }
    passing.push({ command: c.argv.join(' '), cwd: c.cwd, exitCode: 0, log: c.log, logSha256: c.logSha256, testFiles: files, durationMs: c.durationMs ?? null });
  }
  if (!passing.length && !reasons.length) reasons.push('no test command was run for this attempt (use runner.mjs --kind test)');
  return { passing, reasons };
}

function validateClosing(root, def, st, input, { alreadySatisfied }) {
  const problems = [];
  const t = collectTestEvidence(root, st);
  if (!t.passing.length || t.reasons.length) problems.push(...t.reasons);
  const acceptance = Array.isArray(input.acceptanceEvidence) ? input.acceptanceEvidence.filter((x) => typeof x === 'string' && x.trim()) : [];
  if (!acceptance.length) problems.push('acceptanceEvidence must name at least one artifact or section that shows the acceptance criterion is met');
  const changed = Array.isArray(input.changedPaths) ? input.changedPaths : [];
  for (const p of changed) { const abs = inRepo(root, p); if (!abs || !existsSync(abs)) problems.push(`changed path ${p} does not exist under the repository`); }
  if (!alreadySatisfied && !changed.length) problems.push('changedPaths is empty; a task that changed nothing is `already_satisfied`, with code references');
  const refs = Array.isArray(input.codeRefs) ? input.codeRefs : [];
  if (alreadySatisfied) {
    if (!refs.length) problems.push('already_satisfied needs codeRefs: the existing files that implement the requirement');
    for (const p of refs) { const abs = inRepo(root, String(p).split('#')[0]); if (!abs || !existsSync(abs)) problems.push(`code reference ${p} does not exist`); }
  }
  if (!Array.isArray(input.benchmarkComparisons)) problems.push('benchmarkComparisons must be present (use a one-item list with the unmeasured reason when there is no benchmark)');
  if (!Array.isArray(input.knownLimitations)) problems.push('knownLimitations must be present (an empty list is allowed)');
  return { problems, tests: t.passing, acceptance, changed, refs };
}

function close(root, id, input, to) {
  return mutate(root, (doc, manifest) => {
    const { def, st } = requireTask(doc, manifest, id);
    if (st.state !== 'in_progress') throw new TransitionError(`${id} is ${st.state}; only an in_progress task can be closed`);
    const v = validateClosing(root, def, st, input, { alreadySatisfied: to === 'already_satisfied' });
    if (v.problems.length) throw new TransitionError(`${id} cannot be ${to}: ${v.problems.join('; ')}`);
    const info = checkoutInfo(root);
    doc.checkout = info;
    move(st, id, to);
    const now = nowIso();
    st.completedAt = now; st.commit = info.commit; st.activeProcess = null; st.exitCode = 0;
    st.evidence = {
      taskId: id, status: to, sourceCommit: info.commit, worktreeDirty: info.dirty,
      changedPaths: v.changed, codeRefs: v.refs.length ? v.refs : undefined,
      testCommands: v.tests.map((t) => ({ command: t.command, exitCode: t.exitCode, log: t.log, logSha256: t.logSha256, testFiles: t.testFiles })),
      acceptanceEvidence: v.acceptance,
      benchmarkComparisons: input.benchmarkComparisons,
      knownLimitations: input.knownLimitations,
      closedAt: now,
    };
    return { type: `task_${to}`, task: id, commit: info.commit, tests: v.tests.length };
  });
}

export const completeTask = (root, id, input) => close(root, id, input, 'done');
export const satisfyTask = (root, id, input) => close(root, id, input, 'already_satisfied');

/**
 * Check every closed task's evidence still holds on disk: logs present and unchanged, changed paths and test files present. A task whose
 * evidence no longer holds returns to in_progress (PRD 14.2). Returns the ids moved.
 */
export function revalidateEvidence(root = REPO_ROOT) {
  const moved = [];
  mutate(root, (doc) => {
    for (const [id, st] of Object.entries(doc.tasks)) {
      if (!isVerified(st) || !st.evidence) continue;
      const bad = [];
      for (const tc of st.evidence.testCommands || []) {
        const lp = inRepo(root, tc.log);
        if (!lp || !existsSync(lp)) bad.push(`log ${tc.log} is gone`);
        else if (sha256File(lp) !== tc.logSha256) bad.push(`log ${tc.log} changed`);
        for (const f of tc.testFiles || []) if (!existsSync(resolve(root, f))) bad.push(`test file ${f} is gone`);
      }
      for (const p of st.evidence.changedPaths || []) if (!existsSync(resolve(root, p))) bad.push(`changed path ${p} is gone`);
      if (bad.length) {
        st.state = 'in_progress'; st.completedAt = null; st.evidence = null; st.heartbeatAt = nowIso(); st.attempts++; st.startedAt = nowIso();
        st.notes = [...st.notes, `evidence invalidated: ${bad[0]}`].slice(-20);
        moved.push({ id, reason: bad[0] });
      }
    }
    return moved.length ? { type: 'evidence_invalidated', tasks: moved } : null;
  });
  return moved;
}

/**
 * After a crash or an abandoned session: a task whose recorded process is gone, or whose heartbeat is stale with no live process, was
 * interrupted. It returns to pending (or to blocked after repeated interruptions) and an `interrupted` event is appended.
 * `force` treats every in_progress task as interrupted (a new session starting cold).
 */
export function recoverInterrupted(root = REPO_ROOT, { now = Date.now(), pidAlive = isAlive, force = false, maxInterruptions = 3 } = {}) {
  const recovered = [];
  mutate(root, (doc) => {
    for (const [id, st] of Object.entries(doc.tasks)) {
      if (st.state !== 'in_progress') continue;
      const hb = st.heartbeatAt ? Date.parse(st.heartbeatAt) : 0;
      const procAlive = st.activeProcess ? pidAlive(st.activeProcess.pid) : false;
      const stale = now - hb > STALE_HEARTBEAT_MS;
      const dead = st.activeProcess && !procAlive;
      if (!(force || dead || (stale && !procAlive))) continue;
      for (const c of st.commands) if (c.outcome === 'running') { c.outcome = 'cancelled'; c.endedAt = nowIso(); }
      st.activeProcess = null;
      const interruptions = st.notes.filter((n) => n.startsWith('interrupted')).length + 1;
      st.notes = [...st.notes, `interrupted (attempt ${st.attempts})`].slice(-20);
      if (interruptions >= maxInterruptions) {
        st.state = 'blocked';
        st.blocker = { reason: `interrupted ${interruptions} times`, nextAction: 'inspect the logs for what kills the work, then retry', at: nowIso(), kind: 'interrupted' };
      } else st.state = 'pending';
      recovered.push({ id, to: st.state });
    }
    return recovered.length ? { type: 'interrupted', tasks: recovered } : null;
  });
  return recovered;
}

// ---- derived views -----------------------------------------------------------------------------------------------------

export function readyTasks(manifest, doc) {
  return manifest.tasks.filter((t) => {
    const st = doc.tasks[t.id];
    return st && st.state === 'pending' && t.requires.every((r) => isVerified(doc.tasks[r]));
  });
}

const PRI = { P0: 0, P1: 1, P2: 2 };
/** Highest priority first, then document order. */
export function nextTasks(manifest, doc, limit = 3) {
  const order = new Map(manifest.tasks.map((t, i) => [t.id, i]));
  return readyTasks(manifest, doc).sort((a, b) => (PRI[a.priority] - PRI[b.priority]) || (order.get(a.id) - order.get(b.id))).slice(0, limit);
}

export function summarize(manifest, doc, { now = Date.now() } = {}) {
  const counts = { pending: 0, in_progress: 0, done: 0, already_satisfied: 0, blocked: 0, failed: 0 };
  let verifiedWeight = 0; let totalWeight = 0;
  const epics = manifest.epics.map((e) => ({ id: e.id, title: e.title, total: 0, verified: 0, weight: 0, verifiedWeight: 0 }));
  const epicOf = new Map(epics.map((e) => [e.id, e]));
  for (const t of manifest.tasks) {
    const st = doc.tasks[t.id] || newTask();
    counts[st.state]++;
    totalWeight += t.weight;
    const ep = epicOf.get(t.epic);
    ep.total++; ep.weight += t.weight;
    if (isVerified(st)) { verifiedWeight += t.weight; ep.verified++; ep.verifiedWeight += t.weight; }
  }
  const active = manifest.tasks.filter((t) => doc.tasks[t.id]?.state === 'in_progress').map((t) => {
    const st = doc.tasks[t.id];
    const hb = st.heartbeatAt ? Date.parse(st.heartbeatAt) : 0;
    return { id: t.id, title: t.title, startedAt: st.startedAt, elapsedMs: st.startedAt ? now - Date.parse(st.startedAt) : null, heartbeatAgeMs: hb ? now - hb : null, stale: hb ? now - hb > STALE_HEARTBEAT_MS : true, command: st.activeProcess?.command || null };
  });
  const blocked = manifest.tasks.filter((t) => doc.tasks[t.id]?.state === 'blocked').map((t) => ({ id: t.id, title: t.title, ...doc.tasks[t.id].blocker }));
  const failed = manifest.tasks.filter((t) => doc.tasks[t.id]?.state === 'failed').map((t) => ({ id: t.id, title: t.title, ...doc.tasks[t.id].failure }));
  const closed = manifest.tasks.filter((t) => isVerified(doc.tasks[t.id]) && doc.tasks[t.id].completedAt).sort((a, b) => doc.tasks[b.id].completedAt.localeCompare(doc.tasks[a.id].completedAt));
  return {
    total: manifest.tasks.length, counts,
    verified: counts.done + counts.already_satisfied,
    weightedPercent: totalWeight ? Math.round((verifiedWeight / totalWeight) * 1000) / 10 : 0,
    epics: epics.map((e) => ({ ...e, percent: e.weight ? Math.round((e.verifiedWeight / e.weight) * 100) : 0 })),
    active, blocked, failed,
    lastVerified: closed[0] ? { id: closed[0].id, title: closed[0].title, at: doc.tasks[closed[0].id].completedAt } : null,
    next: nextTasks(manifest, doc, 3).map((t) => t.id),
    // an ETA is shown only if one was measured; nothing in this program measures one
    eta: 'unknown',
  };
}

/** Relative log path for a new command log: logs/<task>/<timestamp>-<id>.log, under the program directory. */
export function logPathFor(root, taskId, commandId, at = new Date()) {
  const stamp = at.toISOString().replace(/[:.]/g, '-');
  const abs = join(paths(root).logs, taskId, `${stamp}-${commandId}.log`);
  mkdirSync(dirname(abs), { recursive: true });
  return { abs, rel: relative(root, abs) };
}

export function fileSha256(root, rel) {
  const p = inRepo(root, rel);
  if (!p || !existsSync(p)) return null;
  return sha256File(p);
}

