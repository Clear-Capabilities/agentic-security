#!/usr/bin/env node
// Ship the current branch: push, pull request, blocking checks, merge, verify, tag, hosted release, npm. One command, no idle gaps.
//
//   node scripts/ship.mjs                    ship the current branch end to end
//   node scripts/ship.mjs --dry-run          everything up to (not including) the merge
//   node scripts/ship.mjs --resume           continue a run that stopped (a closed laptop, a crash): finished phases are not repeated
//   node scripts/ship.mjs --status           print the last run's phases and exit
//   node scripts/ship.mjs --tmpdir <dir>     TMPDIR for the release gate (a fresh directory keeps leftover temp files from slowing the suite)
//
// Progress is written to .agentic-security/ship/state.json (git-ignored) for a dashboard, and every long command's full output goes to
// .agentic-security/ship/logs/<phase>.log. See scripts/ship/lib.mjs for what it will and will not do (it never bypasses a gate).

import { spawnSync } from 'node:child_process';
import { readFileSync, mkdirSync, openSync, closeSync, appendFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ShipState, PHASES } from './ship/lib.mjs';
import { runShip } from './ship/run.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DIR = path.join(ROOT, '.agentic-security', 'ship');
const argv = process.argv.slice(2);
const flag = (n) => argv.includes(`--${n}`);
const opt = (n) => { const i = argv.indexOf(`--${n}`); return i >= 0 ? argv[i + 1] : undefined; };

// One log directory, and a file name that can only be a phase name: nothing derived from input ever reaches a path.
const LOG_DIR = path.join(DIR, 'logs');
const SHIP_LOG = path.join(LOG_DIR, 'ship.log');
const phaseLog = (name) => path.join(LOG_DIR, PHASES.includes(name) ? `${name}.log` : 'run.log');
mkdirSync(LOG_DIR, { recursive: true });
const state = ShipState.load(path.join(DIR, 'state.json'));

if (flag('status')) { process.stdout.write(`${state.summary()}\n${state.data.failed ? `FAILED in ${state.data.failed.phase}: ${state.data.failed.message}\n` : ''}`); process.exit(0); }
if (!flag('resume')) { state.data = { phases: {}, started: Date.now(), events: [] }; state.save(); }

const stamp = () => new Date().toISOString().slice(11, 19);
const ctx = {
  state,
  now: () => Date.now(),
  sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
  log: (line) => { const l = `[${stamp()}] ${line}`; process.stdout.write(`${l}\n`); try { appendFileSync(SHIP_LOG, `${l}\n`); } catch { /* logging is best effort */ } },
  readFile: (p) => readFileSync(path.join(ROOT, p), 'utf8'),
  fetchJson: async (url) => { const r = await fetch(url, { signal: AbortSignal.timeout(15000) }); if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); },
  sh(cmd, args, { timeoutMs = 120000, stream = false, env = {} } = {}) {
    // A long command (the pre-push gate, the release gate) writes straight to its own log file, so its output is readable while it runs.
    let fd = null;
    let logPath = null;
    if (stream) { logPath = phaseLog(state.data.current); fd = openSync(logPath, 'a'); }
    const r = spawnSync(cmd, args, { cwd: ROOT, encoding: 'utf8', timeout: timeoutMs, maxBuffer: 64 << 20, env: { ...process.env, ...env }, stdio: stream ? ['ignore', fd, fd] : ['ignore', 'pipe', 'pipe'] });
    if (fd !== null) closeSync(fd);
    // A streamed command's output went to its log, so a failure's message is read back from the END of that log (the verdict is always last).
    let tail = '';
    if (logPath) { try { const b = readFileSync(logPath, 'utf8'); tail = b.slice(-6000); } catch { tail = ''; } }
    return { code: r.status ?? 1, out: r.stdout || tail, err: r.stderr || tail || (r.error ? String(r.error.message) : '') };
  },
};

const result = await runShip(ctx, { dryRun: flag('dry-run'), resume: flag('resume'), tmpdir: opt('tmpdir'), branch: opt('branch') });
const total = Math.round((Date.now() - state.data.started) / 1000);
process.stdout.write(`\n${state.summary()}\n${result.ok ? `\nshipped in ${Math.floor(total / 60)} min ${total % 60} s` : `\nSTOPPED in ${result.phase}: ${result.message}\nfull logs: ${path.relative(ROOT, LOG_DIR)}/ ; resume with: node scripts/ship.mjs --resume\n`}`);
process.exit(result.ok ? 0 : 1);
