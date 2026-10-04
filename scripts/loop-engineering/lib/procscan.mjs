// Process-table helpers. Identity is (pid, start time), never a pid alone: a
// recycled pid has a different start time, so it is never mistaken for ours.
// We never match processes by name.
import { execFileSync } from 'node:child_process';
import { readdirSync, readFileSync } from 'node:fs';

const ROW = /^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\w{3}\s+\w{3}\s+\d+\s+\d\d:\d\d:\d\d\s+\d{4})\s+(.*)$/;
const PS_ENV = { ...process.env, LC_ALL: 'C', LANG: 'C' };

export function listProcesses() {
  let out;
  try {
    out = execFileSync('ps', ['-axww', '-o', 'pid=,ppid=,pgid=,rss=,lstart=,command='], { encoding: 'utf8', env: PS_ENV, maxBuffer: 64 * 1024 * 1024, timeout: 5000 });
  } catch { return []; }
  const rows = [];
  for (const line of out.split('\n')) {
    const m = ROW.exec(line);
    if (m) rows.push({ pid: +m[1], ppid: +m[2], pgid: +m[3], rssKb: +m[4], start: m[5].replace(/\s+/g, ' '), command: m[6] });
  }
  return rows;
}

export function startTimeOf(pid) {
  try {
    const out = execFileSync('ps', ['-o', 'lstart=', '-p', String(pid)], { encoding: 'utf8', env: PS_ENV, timeout: 3000 }).trim();
    return out ? out.replace(/\s+/g, ' ') : null;
  } catch { return null; }
}

export function isAlive(pid) {
  try { process.kill(pid, 0); return true; } catch (e) { return e.code === 'EPERM'; }
}

// Is the process with this pid still the one we recorded?
//  - strict (used before SIGNALLING anything): requires a positive start-time
//    match; if `ps` cannot answer, we do NOT act.
//  - lenient (used to judge LIVENESS): a transient `ps` failure under load must
//    never turn a live process into a "dead" one, so an unanswerable start-time
//    check counts as alive. Only a definite mismatch (pid reuse) or ESRCH is dead.
export function identityMatches(pid, start, { strict = false } = {}) {
  if (!pid || !start || !isAlive(pid)) return false;
  let cur = startTimeOf(pid);
  if (cur === null) cur = startTimeOf(pid);           // one retry
  if (cur === null) return !strict;
  return cur === start.replace(/\s+/g, ' ');
}

export function descendantsOf(rootPid, rows) {
  const kids = new Map();
  for (const r of rows) { if (!kids.has(r.ppid)) kids.set(r.ppid, []); kids.get(r.ppid).push(r); }
  const out = [];
  const stack = [rootPid];
  const seen = new Set([rootPid]);
  while (stack.length) {
    const p = stack.pop();
    for (const c of kids.get(p) || []) { if (!seen.has(c.pid)) { seen.add(c.pid); out.push(c); stack.push(c.pid); } }
  }
  return out;
}

// Find processes carrying an environment marker, which survives reparenting
// and setsid()/double-fork escapes that a parent-pid walk cannot follow.
// `prefix` matches `NAME=<prefix>...`. Returns [{pid, start}] (excluding `exclude`).
export function scanEnvMarker(name, prefix, exclude = []) {
  const needle = `${name}=${prefix}`;
  const skip = new Set([process.pid, ...exclude]);
  const hits = [];
  if (process.platform === 'linux') {
    let pids = [];
    try { pids = readdirSync('/proc').filter((d) => /^\d+$/.test(d)).map(Number); } catch { /* no /proc */ }
    for (const pid of pids) {
      if (skip.has(pid)) continue;
      try {
        const env = readFileSync(`/proc/${pid}/environ`, 'latin1');
        if (env.split('\0').some((kv) => kv.startsWith(needle))) hits.push({ pid, start: startTimeOf(pid) });
      } catch { /* exited or not ours */ }
    }
    return hits.filter((h) => h.start);
  }
  // macOS/BSD: `ps -E` appends the environment to the command column.
  let out;
  try {
    out = execFileSync('ps', ['-axwwE', '-o', 'pid=,command='], { encoding: 'utf8', env: PS_ENV, maxBuffer: 256 * 1024 * 1024, timeout: 8000 });
  } catch { return []; }
  for (const line of out.split('\n')) {
    if (!line.includes(needle)) continue;
    const pid = parseInt(line, 10);
    if (!Number.isInteger(pid) || skip.has(pid)) continue;
    const start = startTimeOf(pid);
    if (start) hits.push({ pid, start });
  }
  return hits;
}

// Signal one process only if it is still the process we recorded.
export function signalIdentity({ pid, start }, signal) {
  if (!identityMatches(pid, start)) return false;
  try { process.kill(pid, signal); return true; } catch { return false; }
}
