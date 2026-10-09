// Active probes for every control the boundary relies on (CORE-003.AC02).
//
// A control is "proved" only when a probe ATTACKED it through the real
// backend and the attack observably failed, AND a paired positive control
// showed the same probe succeeds when the control is off (so a probe that can
// never succeed cannot pass for a working control). An executable existing, a
// flag being passed or an earlier run succeeding proves nothing here.
//
// States:
//   proved       attack failed, positive control succeeded, both observed
//   not-proved   the probe ran and the control did not hold, or the probe could
//                not establish its own positive control
//   unsupported  this backend does not implement the control at all
//   unavailable  no confinement backend works on this host
//   unverified   deliberately not probed; the reason says why (never a pass)
//
// The probes are generic, so on a Linux host they run against the namespace
// backend for real. Nothing in this file asserts a Linux outcome in advance.
import crypto from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { detectBackend } from './capabilities.js';
import { runConfined } from './index.js';
import { runConfinedSupervised } from './supervise.js';

export const CONTROLS = Object.freeze([
  'write-confinement', 'read-denial', 'env-scrub', 'network',
  'tree-termination', 'file-size-limit', 'process-cap',
]);

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const alive = (pid) => { try { process.kill(pid, 0); return true; } catch (e) { return e.code === 'EPERM'; } };
const NODE = process.execPath;

function mk(prefix) { return fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), prefix))); }
function rm(p) { try { fs.rmSync(p, { recursive: true, force: true }); } catch { /* best effort */ } }
const proved = (evidence) => ({ state: 'proved', evidence });
const notProved = (reason) => ({ state: 'not-proved', reason });

function probeWrite() {
  const root = mk('agsec-probe-w-'); const outside = mk('agsec-probe-wo-');
  try {
    const good = runConfined(['/bin/sh', '-c', 'echo x > "$ROOT/in.txt"'], { root });
    const inOk = fs.existsSync(path.join(root, 'in.txt'));
    runConfined(['/bin/sh', '-c', `echo x > '${outside}/escape.txt'; true`], { root });
    const escaped = fs.existsSync(path.join(outside, 'escape.txt'));
    if (!inOk) return notProved(`positive control failed: in-root write did not happen (${good.status})`);
    if (escaped) return notProved('an out-of-root write succeeded');
    return proved('in-root write succeeded; out-of-root write created no file');
  } finally { rm(root); rm(outside); }
}

function probeReadDenial(backend) {
  if (backend !== 'userspace') return { state: 'unsupported', reason: `read denial of host paths is not implemented on the ${backend} backend` };
  const root = mk('agsec-probe-r-'); const secretDir = mk('agsec-probe-rs-');
  try {
    const secret = path.join(secretDir, 'sealed.txt');
    const token = `SEALED-${crypto.randomBytes(8).toString('hex')}`;
    fs.writeFileSync(secret, token);
    const cmd = ['/bin/sh', '-c', `cat '${secret}' 2>&1; true`];
    const open = runConfined(cmd, { root });
    if (!open.stdout.includes(token)) return notProved('positive control failed: the probe could not read the canary even without denial');
    const closed = runConfined(cmd, { root, denyReadPaths: [secretDir] });
    if (closed.stdout.includes(token)) return notProved('a denied path was still readable');
    return proved('canary readable without denial, unreadable with denyReadPaths');
  } finally { rm(root); rm(secretDir); }
}

function probeEnv() {
  const root = mk('agsec-probe-e-');
  const name = 'AGSEC_PROBE_PARENT_CANARY';
  const prev = process.env[name];
  process.env[name] = 'parent-env-canary-value';
  try {
    const r = runConfined(['/usr/bin/env'], { root, env: { AGSEC_PROBE_EXPLICIT: 'explicit-ok' } });
    if (!r.stdout.includes('AGSEC_PROBE_EXPLICIT=explicit-ok')) return notProved(`positive control failed: explicit env not visible (${r.status})`);
    if (r.stdout.includes(name) || r.stdout.includes('parent-env-canary-value')) return notProved('the parent environment leaked into the target');
    return proved('explicit variable visible, parent canary variable absent');
  } finally {
    if (prev === undefined) delete process.env[name]; else process.env[name] = prev;
    rm(root);
  }
}

async function probeNetwork() {
  const root = mk('agsec-probe-n-');
  let hits = 0;
  const server = net.createServer((s) => { hits++; s.destroy(); });
  try {
    await new Promise((res, rej) => { server.once('error', rej); server.listen(0, '127.0.0.1', res); });
    const port = server.address().port;
    const script = `require('net').connect(${port},'127.0.0.1').on('error',()=>process.exit(0)).on('connect',()=>process.exit(0));setTimeout(()=>process.exit(0),1500)`;
    runConfined([NODE, '-e', script], { root, timeoutMs: 6000, allowNetwork: true });
    await sleep(200);
    const open = hits;
    if (open < 1) return notProved('positive control failed: loopback listener saw no connection with network allowed');
    runConfined([NODE, '-e', script], { root, timeoutMs: 6000, allowNetwork: false });
    await sleep(200);
    if (hits > open) return notProved('a connection reached a loopback listener with network denied');
    return proved('connection seen with network allowed, none with network denied');
  } finally { server.close(); rm(root); }
}

async function probeTree() {
  const root = mk('agsec-probe-t-');
  try {
    // Three tree shapes: a plain background child, a grandchild, and one that
    // ignores SIGTERM and so needs the SIGKILL escalation.
    const script = [
      'sleep 300 & echo $! > "$ROOT/p1"',
      '(sleep 300 & echo $! > "$ROOT/p2"; wait) &',
      `(trap '' TERM; sleep 300 & echo $! > "$ROOT/p3"; while :; do sleep 1; done) &`,
      'wait',
    ].join('\n');
    const r = await runConfinedSupervised(['/bin/sh', '-c', script], { root, timeoutMs: 1500, graceMs: 300 });
    if (r.backend !== 'userspace' || !r.supervised) {
      return { state: 'unsupported', reason: `supervised tree termination is not implemented on the ${r.backend} backend (${r.status})` };
    }
    const pids = ['p1', 'p2', 'p3'].map((f) => { try { return Number(fs.readFileSync(path.join(root, f), 'utf8')); } catch { return NaN; } });
    if (pids.some((p) => !Number.isFinite(p))) return notProved('positive control failed: the probe tree did not start');
    await sleep(100);
    const live = pids.filter(alive);
    for (const p of live) { try { process.kill(p, 'SIGKILL'); } catch { /* probe cleanup */ } }
    if (live.length) return notProved(`processes survived the timeout: ${live.join(',')}`);
    return proved('timeout ended a three-process tree including a SIGTERM-ignoring member');
  } finally { rm(root); }
}

function probeFileSize() {
  const root = mk('agsec-probe-f-');
  try {
    const cmd = ['/bin/sh', '-c', 'dd if=/dev/zero of="$ROOT/big" bs=1024 count=400 2>&1; true'];
    runConfined(cmd, { root, limits: { maxFileSizeKb: 65536 } });
    const full = fs.existsSync(path.join(root, 'big')) ? fs.statSync(path.join(root, 'big')).size : 0;
    if (full < 400 * 1024) return notProved('positive control failed: the unrestricted write did not complete');
    fs.rmSync(path.join(root, 'big'));
    runConfined(cmd, { root, limits: { maxFileSizeKb: 16 } });
    const capped = fs.existsSync(path.join(root, 'big')) ? fs.statSync(path.join(root, 'big')).size : 0;
    if (capped >= 400 * 1024) return notProved('the file size limit did not stop a large write');
    return proved(`400 KiB write completed unrestricted and stopped at ${capped} bytes under a 16 KiB limit`);
  } finally { rm(root); }
}

const UNPROBED_PROCESS_CAP = {
  state: 'unverified',
  reason: 'a process-count cap is per-uid and system-wide on macOS (a soft brake, not a wall) and did not refuse on the hosted Linux runner in the last release; no enforcement is claimed on any backend',
};

const _cache = new Map();
export function resetProbeCache() { _cache.clear(); }

/**
 * Probe every control on the active backend.
 * @param {object} [o]
 * @param {string} [o.force]   backend override (same meaning as runConfined's)
 * @param {object} [o.probes]  per-control probe overrides (test seam). A probe
 *                             may only make the report MORE restrictive in
 *                             practice, since the boundary consults the report
 *                             before any run; it cannot make a run unconfined.
 */
export async function probeControls({ force, probes = {} } = {}) {
  const backend = detectBackend({ force });
  const key = `${backend}:${Object.keys(probes).sort().join(',')}`;
  if (!Object.keys(probes).length && _cache.has(backend)) return _cache.get(backend);

  const controls = {};
  if (backend === 'disabled') {
    for (const c of CONTROLS) controls[c] = { state: 'unavailable', reason: 'no confinement backend works on this host' };
  } else {
    const run = async (name, fn) => {
      if (probes[name]) { controls[name] = await probes[name](); return; }
      try { controls[name] = await fn(); } catch (e) { controls[name] = notProved(`probe threw: ${e.message}`); }
    };
    await run('write-confinement', probeWrite);
    await run('read-denial', () => probeReadDenial(backend));
    await run('env-scrub', probeEnv);
    await run('network', probeNetwork);
    await run('tree-termination', probeTree);
    await run('file-size-limit', probeFileSize);
    controls['process-cap'] = probes['process-cap'] ? await probes['process-cap']() : UNPROBED_PROCESS_CAP;
  }
  const report = { platform: process.platform, backend, controls };
  if (!Object.keys(probes).length) _cache.set(backend, report);
  void key;
  return report;
}

/** Controls from `required` that are not proved, with the reason for each. */
export function unmetControls(report, required) {
  const out = [];
  for (const c of required) {
    const v = report?.controls?.[c];
    if (!v || v.state !== 'proved') out.push({ control: c, state: v?.state ?? 'not-probed', reason: v?.reason ?? 'no probe result' });
  }
  return out;
}

/**
 * Human-readable capability matrix. States what each control is on this host
 * and carries the standing disclosure that Linux enforcement is only evidenced
 * where the hosted `sandbox-linux` job actually ran.
 */
export function capabilityReport(report) {
  return {
    ...report,
    advertisedIsolationBackends: ['userspace (macOS family)', 'namespace (Linux family)'],
    notes: [
      'A state of proved was established by an active probe on THIS host in THIS process; it is not inherited from another platform.',
      'Linux enforcement cannot be exercised on a macOS host. It is evidenced only where the sandbox-linux CI job ran this same probe set.',
      'Process-count caps are not claimed enforced on any backend.',
    ],
  };
}
