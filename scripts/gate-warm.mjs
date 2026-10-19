#!/usr/bin/env node
// Background gate warm-up: run the pre-push gate against the commit you just made, while you keep working, so that `git push`
// finds every verdict already cached and takes seconds instead of the 15 to 35 minutes the checks cost.
//
//   node scripts/gate-warm.mjs --start         start (or restart) the background run for HEAD; returns at once. The post-commit hook does this.
//   node scripts/gate-warm.mjs --status        one-screen state for HEAD (exit 0 passed, 1 failed, 2 running, 3 nothing recorded / stale)
//   node scripts/gate-warm.mjs --wait          block until the run for HEAD is no longer running, then behave like --status
//   node scripts/gate-warm.mjs --json          machine-readable status (with --status or --wait)
//
// WHAT THIS IS NOT. It is not a second gate and it never marks anything green by itself. It runs the SAME gate (`pre-push-gate.mjs --force`)
// with the SAME verdict cache, so a pass here is recorded exactly as a pass at push time would be, keyed by the commit, the tree, the
// bundle, the toolchain and the environment. If anything differs when you push (an amend, a rebase, an edit, another Node) the key differs,
// the cached verdicts are not used, and the gate runs in full as before. Nothing about `git push` is bypassed.
//
// The state lives in `.agentic-security/gate-warm/` (git-ignored): status.json (what is running or last finished, for which commit and
// tree) and gate.log (the gate's output). A run for an older commit is stopped when a newer commit starts one.
//
// Off with AGENTIC_SECURITY_NO_GATE_WARM=1, in CI, and during a rebase, merge, cherry-pick or bisect (a commit made by those is rarely the one
// you will push, and each would otherwise start a fresh multi-minute run).
import { spawn, spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_DEFAULT = path.resolve(HERE, '..');
export const EXIT = Object.freeze({ passed: 0, failed: 1, running: 2, none: 3 });

const GIT_ENV_KEYS = ['GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'GIT_OBJECT_DIRECTORY', 'GIT_ALTERNATE_OBJECT_DIRECTORIES', 'GIT_PREFIX', 'GIT_COMMON_DIR'];
/** The environment for any git or gate child: a hook's own GIT_* variables must not leak into a run that reads the repository. */
export function cleanEnv(env = process.env) {
  const out = { ...env };
  for (const k of GIT_ENV_KEYS) delete out[k];
  return out;
}

const stateDir = (repo) => path.join(repo, '.agentic-security', 'gate-warm');
const statusPath = (repo) => path.join(stateDir(repo), 'status.json');
const logPath = (repo) => path.join(stateDir(repo), 'gate.log');

function git(repo, args) {
  const r = spawnSync('git', args, { cwd: repo, encoding: 'utf8', shell: false, env: cleanEnv() });
  return r.status === 0 ? r.stdout.trim() : null;
}

export function readStatus(repo = REPO_DEFAULT) {
  try { return JSON.parse(fs.readFileSync(statusPath(repo), 'utf8')); } catch { return null; }
}

function writeStatus(repo, status) {
  fs.mkdirSync(stateDir(repo), { recursive: true });
  const tmp = `${statusPath(repo)}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, `${JSON.stringify(status, null, 2)}\n`);
  fs.renameSync(tmp, statusPath(repo));
}

export function pidAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try { process.kill(pid, 0); return true; } catch (e) { return e && e.code === 'EPERM'; }
}

/**
 * What the recorded status says about the commit and tree you are about to push. A pure function so it can be tested.
 *   passed  the gate passed for exactly this commit and tree
 *   failed  it failed for exactly this commit and tree (names in `failed`)
 *   running a live run for exactly this commit and tree
 *   none    nothing recorded, a different commit or tree, or a run whose process died without finishing
 */
export function decide({ status, commit, tree, alive = pidAlive }) {
  if (!status || status.commit !== commit || status.tree !== tree) return { state: 'none', why: status ? 'the recorded run is for a different commit or tree' : 'no background run recorded' };
  if (status.state === 'passed') return { state: 'passed', why: 'the gate passed for this exact commit and tree' };
  if (status.state === 'failed') return { state: 'failed', why: 'the gate failed for this exact commit and tree', failed: status.failed || [] };
  if (status.state === 'running') {
    if (alive(status.pid)) return { state: 'running', why: 'a background run for this commit is still going' };
    return { state: 'none', why: 'the background run stopped without recording a result' };
  }
  return { state: 'none', why: `unrecognised state "${status.state}"` };
}

/** Why a warm-up must not start here, or null. */
export function skipReason({ env = process.env, repo = REPO_DEFAULT } = {}) {
  if (env.AGENTIC_SECURITY_NO_GATE_WARM === '1') return 'AGENTIC_SECURITY_NO_GATE_WARM=1';
  if (env.CI === 'true' || env.GITHUB_ACTIONS === 'true') return 'running in CI';
  for (const marker of ['rebase-merge', 'rebase-apply', 'MERGE_HEAD', 'CHERRY_PICK_HEAD', 'BISECT_LOG']) {
    const p = git(repo, ['rev-parse', '--git-path', marker]);
    if (p && fs.statSync(path.resolve(repo, p), { throwIfNoEntry: false })) return `a ${marker} is in progress`;
  }
  return null;
}

/** The failed check names from the gate's output: it prints one `FAIL  <check>` line per failed check. */
export function parseFailed(text) {
  return [...new Set(String(text).split('\n').filter((l) => /^FAIL\s/.test(l)).map((l) => l.replace(/^FAIL\s+/, '').trim()))];
}

function head(repo) {
  const commit = git(repo, ['rev-parse', 'HEAD']);
  const tree = git(repo, ['rev-parse', 'HEAD^{tree}']);
  return commit && tree ? { commit, tree } : null;
}

/** Start (or restart) the background run for HEAD. Returns a one-line description; never throws into a commit. */
export function start({ repo = REPO_DEFAULT, env = process.env, spawnFn = spawn, now = () => new Date() } = {}) {
  const why = skipReason({ env, repo });
  if (why) return { started: false, reason: why };
  const h = head(repo);
  if (!h) return { started: false, reason: 'could not read HEAD' };
  const prev = readStatus(repo);
  if (prev && prev.commit === h.commit && prev.tree === h.tree && (prev.state === 'passed' || (prev.state === 'running' && pidAlive(prev.pid)))) {
    return { started: false, reason: `already ${prev.state} for this commit` };
  }
  if (prev && prev.state === 'running' && pidAlive(prev.pid)) {
    try { process.kill(-prev.pid, 'SIGTERM'); } catch { try { process.kill(prev.pid, 'SIGTERM'); } catch { /* already gone */ } }
  }
  fs.mkdirSync(stateDir(repo), { recursive: true });
  const out = fs.openSync(logPath(repo), 'w');
  const child = spawnFn(process.execPath, [path.join(HERE, 'gate-warm.mjs'), '--child', h.commit, h.tree], {
    cwd: repo, detached: true, stdio: ['ignore', out, out], env: cleanEnv(env),
  });
  child.unref();
  writeStatus(repo, { state: 'running', commit: h.commit, tree: h.tree, pid: child.pid, startedAt: now().toISOString(), log: path.relative(repo, logPath(repo)) });
  return { started: true, pid: child.pid, commit: h.commit };
}

/** The detached worker: run the gate, record the verdict. It lowers its own priority so the editor and the tests you run stay responsive. */
async function runChild(repo, commit, tree) {
  try { os.setPriority(0, 15); } catch { /* not permitted: run at normal priority */ }
  const started = Date.now();
  const r = spawnSync(process.execPath, [path.join(HERE, 'pre-push-gate.mjs'), '--force'], {
    cwd: repo, encoding: 'utf8', shell: false, env: cleanEnv(), maxBuffer: 512 * 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'],
  });
  const text = `${r.stdout || ''}\n${r.stderr || ''}`;
  fs.appendFileSync(logPath(repo), text);
  const now = head(repo);
  const state = r.status === 0 ? 'passed' : 'failed';
  // A run only counts for the commit and tree it started on; if HEAD moved meanwhile the next commit's own run supersedes this one.
  const cur = readStatus(repo);
  if (cur && cur.commit === commit && cur.tree === tree) {
    writeStatus(repo, { ...cur, state, endedAt: new Date().toISOString(), seconds: Math.round((Date.now() - started) / 1000), failed: state === 'failed' ? parseFailed(text) : [], exit: r.status, headAtEnd: now ? now.commit : null });
  }
  return 0;
}

export function describe(d, status) {
  const lines = [];
  const where = status ? `commit ${String(status.commit).slice(0, 8)}` : 'no recorded run';
  if (d.state === 'passed') lines.push(`gate-warm: PASSED for HEAD (${where}${status && status.seconds ? `, ${status.seconds}s` : ''}). \`git push\` will reuse the cached verdicts.`);
  else if (d.state === 'running') lines.push(`gate-warm: RUNNING for HEAD (${where}, since ${status.startedAt}). Log: ${status.log}`);
  else if (d.state === 'failed') lines.push(`gate-warm: FAILED for HEAD (${where}). Failed checks: ${(d.failed || []).join('; ') || '(none named, see the log)'}. Log: ${status && status.log}`);
  else lines.push(`gate-warm: nothing usable for HEAD (${d.why}). A push will run the gate in full.`);
  return lines;
}

export async function waitUntilDone({ repo = REPO_DEFAULT, timeoutMs = 90 * 60 * 1000, intervalMs = 5000, sleep = (ms) => new Promise((r) => setTimeout(r, ms)), now = Date.now } = {}) {
  const t0 = now();
  for (;;) {
    const h = head(repo);
    const d = decide({ status: readStatus(repo), commit: h && h.commit, tree: h && h.tree });
    if (d.state !== 'running' || now() - t0 > timeoutMs) return d;
    await sleep(intervalMs);
  }
}

export async function main(argv) {
  const repo = REPO_DEFAULT;
  const json = argv.includes('--json');
  if (argv[0] === '--child') return runChild(repo, argv[1], argv[2]);
  if (argv.includes('--start')) {
    const r = start({ repo });
    if (!argv.includes('--quiet')) process.stderr.write(`gate-warm: ${r.started ? `background gate started for ${r.commit.slice(0, 8)} (pid ${r.pid}); \`npm run gate:status\` shows progress` : `not started (${r.reason})`}\n`);
    return 0;
  }
  if (argv.includes('--status') || argv.includes('--wait')) {
    const h = head(repo);
    const d = argv.includes('--wait') ? await waitUntilDone({ repo }) : decide({ status: readStatus(repo), commit: h && h.commit, tree: h && h.tree });
    const status = readStatus(repo);
    if (json) process.stdout.write(`${JSON.stringify({ ...d, commit: h && h.commit, tree: h && h.tree })}\n`);
    else for (const l of describe(d, status)) process.stdout.write(`${l}\n`);
    return EXIT[d.state];
  }
  process.stderr.write('usage: gate-warm.mjs --start | --status [--json] | --wait [--json]\n');
  return 64;
}

if (process.argv[1] && fs.realpathSync(process.argv[1]) === fs.realpathSync(fileURLToPath(import.meta.url))) {
  process.exit(await main(process.argv.slice(2)));
}
