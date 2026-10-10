// Active probes specific to the Linux namespace backend (X-502, X-503, CORE-003).
//
// These are the controls that are only true because of what the kernel does
// with namespaces, each established the way `control-probes.js` establishes the
// others: an ATTACK that must fail, paired with a POSITIVE CONTROL showing the
// same probe succeeds when the control is off, so a probe that can never
// succeed cannot pass for a working control.
//
//   pid-namespace              the payload is pid 1 and cannot see host pids
//   init-kill-reaps-detached   killing the namespace's supervisor (or its init)
//                              ends a double-forked, setsid member that no
//                              process-group or sweep logic could find
//   protected-canary-masked    a protected file and directory under a DECLARED
//                              read root are unreadable (masked), and readable
//                              when not protected
//   capability-network         in capability mode a loopback listener is
//                              reachable only when network is allowed
//
// Each takes a `run` seam so a test can hand it a runner that is deliberately
// wrong and see the probe say so. Nothing here asserts a result in advance: a
// probe that cannot establish its own positive control reports `not-proved`.
import { spawn, spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { runConfined } from './index.js';
import { buildNamespaceInvocation } from './backend-namespace.js';
import { heartbeatShell } from './control-probes.js';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const NODE = process.execPath;
const proved = (evidence) => ({ state: 'proved', evidence });
const notProved = (reason) => ({ state: 'not-proved', reason });

function mk(prefix) { return fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), prefix))); }
function rm(p) { try { fs.rmSync(p, { recursive: true, force: true }); } catch { /* best effort */ } }
const token = (p) => `${p}-${crypto.randomBytes(8).toString('hex')}`;

/** The payload is pid 1 of its own PID namespace and sees no host process. */
export async function probePidNamespace({ run = runConfined } = {}) {
  const root = mk('agsec-lp-pid-');
  try {
    // A host process that certainly exists and is not in the payload's tree.
    const r = run(['/bin/sh', '-c', 'echo PID=$$; ls /proc'], { root, timeoutMs: 8000 });
    const out = String(r.stdout || '');
    const m = /PID=(\d+)/.exec(out);
    if (!m) return notProved(`positive control failed: the probe payload did not report (${r.status})`);
    if (m[1] !== '1') return notProved(`the payload is pid ${m[1]}, not pid 1 of a new PID namespace`);
    const visible = out.split('\n').map((l) => l.trim()).filter((l) => /^\d+$/.test(l));
    if (!visible.length) return notProved('positive control failed: /proc listed no processes, so host visibility could not be judged');
    if (visible.includes(String(process.pid)) || visible.includes(String(process.ppid))) {
      return notProved('the payload can see host processes in /proc');
    }
    return proved(`the payload is pid 1; /proc lists ${visible.length} process(es) and none of the host's`);
  } finally { rm(root); }
}

function childrenOf(pid) {
  const r = spawnSync('ps', ['-o', 'pid=', '--ppid', String(pid)], { encoding: 'utf8', timeout: 3000 });
  return String(r.stdout || '').split('\n').map((x) => Number(x.trim())).filter(Number.isFinite).filter(Boolean);
}

/**
 * Start a namespace-confined tree that includes a double-forked, setsid member,
 * then kill ONE process from the host: the supervisor (`unshare`) or the
 * namespace's init (its child). Either way the kernel must take every member
 * of the namespace with it.
 *
 * @param {'supervisor'|'init'} victim
 */
export async function probeInitKillReapsDetached({ victim = 'supervisor', settleMs = 700, deps } = {}) {
  const root = mk('agsec-lp-init-');
  let inv = null; let child = null;
  try {
    const script = [
      `( ${heartbeatShell(1)} ) &`,
      `( setsid /bin/sh -c '${heartbeatShell(2)}' >/dev/null 2>&1 & ) &`,
      `( trap '' TERM; ${heartbeatShell(3)} ) &`,
      'wait',
    ].join('\n');
    inv = buildNamespaceInvocation(['/bin/sh', '-c', script], { root }, deps);
    if (inv.error) return { state: 'unsupported', reason: String(inv.error.stderr || '').split('\n')[0] };
    if (!inv.treeKill) return { state: 'unsupported', reason: 'this host cannot make the kernel kill the namespace with its supervisor' };
    child = spawn(inv.bin, inv.args, { cwd: inv.cwd, env: inv.env, stdio: 'ignore' });
    const lines = (n) => { try { return fs.readFileSync(path.join(root, `hb${n}`), 'utf8').split('\n').filter(Boolean).length; } catch { return 0; } };
    const names = [1, 2, 3];
    const deadline = Date.now() + 8000;
    while (Date.now() < deadline && !names.every((n) => lines(n) >= 3)) await sleep(100);
    if (!names.every((n) => lines(n) >= 3)) return notProved('positive control failed: the tree did not start and heartbeat before the kill');

    let targets = [child.pid];
    if (victim === 'init') {
      // The namespace's init is the supervisor's direct child (unshare forks
      // it). Kill every direct child, never the supervisor itself.
      targets = childrenOf(child.pid);
      if (!targets.length) return notProved('positive control failed: no namespace init found under the supervisor');
    }
    for (const t of targets) { try { process.kill(t, 'SIGKILL'); } catch { /* already gone */ } }
    await sleep(settleMs);
    const mid = names.map(lines);
    await sleep(settleMs);
    const late = names.map(lines);
    const alive = names.filter((n, i) => late[i] > mid[i]);
    if (alive.length) return notProved(`members of the namespace outlived the kill of its ${victim} (heartbeat ${alive.join(',')})`);
    return proved(`SIGKILL of the namespace ${victim} ended a plain member, a double-forked setsid member and a SIGTERM-ignoring member`);
  } finally {
    try { if (child) child.kill('SIGKILL'); } catch { /* gone */ }
    if (inv && !inv.error) { try { inv.finish('', { hadError: true }); } catch { /* best effort */ } }
    rm(root);
  }
}

/** A protected file and directory under a declared read root are unreadable, and readable when unprotected. */
export async function probeProtectedCanaryMasked({ run = runConfined } = {}) {
  const root = mk('agsec-lp-prot-'); const base = mk('agsec-lp-pbase-');
  try {
    const dirTok = token('SEALEDDIR'); const fileTok = token('SEALEDFILE'); const pubTok = token('PUBLIC');
    fs.mkdirSync(path.join(base, 'sealed'));
    fs.writeFileSync(path.join(base, 'sealed', 'k.txt'), dirTok);
    fs.writeFileSync(path.join(base, 'sealed-file.txt'), fileTok);
    fs.writeFileSync(path.join(base, 'public.txt'), pubTok);
    const cmd = ['/bin/sh', '-c', `cat '${base}/public.txt' '${base}/sealed/k.txt' '${base}/sealed-file.txt' 2>&1; true`];
    const open = run(cmd, { root, readRoots: [base], timeoutMs: 8000 });
    const o = String(open.stdout || '');
    if (!(o.includes(pubTok) && o.includes(dirTok) && o.includes(fileTok))) {
      return notProved(`positive control failed: the files were not readable without protection (${open.status})`);
    }
    const closed = run(cmd, { root, readRoots: [base], denyReadPaths: [path.join(base, 'sealed'), path.join(base, 'sealed-file.txt')], timeoutMs: 8000 });
    const c = String(closed.stdout || '');
    if (!c.includes(pubTok)) return notProved(`positive control failed: the unprotected file stopped being readable (${closed.status})`);
    if (c.includes(dirTok)) return notProved('a protected directory under a declared root was readable');
    if (c.includes(fileTok)) return notProved('a protected file under a declared root was readable');
    return proved('a protected directory and file under a declared read root were unreadable; the unprotected file and both canaries were readable without protection');
  } finally { rm(root); rm(base); }
}

/** In capability mode a loopback listener is reachable with network allowed and unreachable otherwise. */
export async function probeCapabilityNetwork({ run = runConfined } = {}) {
  const root = mk('agsec-lp-net-');
  let hits = 0;
  const server = net.createServer((s) => { hits += 1; s.destroy(); });
  try {
    await new Promise((res, rej) => { server.once('error', rej); server.listen(0, '127.0.0.1', res); });
    const port = server.address().port;
    const script = `require('net').connect(${port},'127.0.0.1').on('error',()=>process.exit(0)).on('connect',()=>process.exit(0));setTimeout(()=>process.exit(0),1500)`;
    const exeReal = fs.realpathSync(NODE);
    run([NODE, '-e', script], { root, readRoots: [exeReal], allowNetwork: true, timeoutMs: 8000 });
    await sleep(200);
    const open = hits;
    if (open < 1) return notProved('positive control failed: the loopback listener saw no connection with network allowed');
    const denied = run([NODE, '-e', script], { root, readRoots: [exeReal], allowNetwork: false, timeoutMs: 8000 });
    await sleep(200);
    if (hits > open) return notProved('a connection reached a loopback listener with network denied');
    void denied;
    return proved('a connection was seen with network allowed and none with network denied (capability mode)');
  } finally { server.close(); rm(root); }
}

/** Every Linux-specific probe, in a fixed order. */
export async function runLinuxProbes() {
  const out = {};
  const step = async (name, fn) => {
    try { out[name] = await fn(); } catch (e) { out[name] = notProved(`probe threw: ${String(e.message).split('\n')[0]}`); }
  };
  await step('pid-namespace', () => probePidNamespace());
  await step('init-kill-reaps-detached:supervisor', () => probeInitKillReapsDetached({ victim: 'supervisor' }));
  await step('init-kill-reaps-detached:init', () => probeInitKillReapsDetached({ victim: 'init' }));
  await step('protected-canary-masked:default', () => probeProtectedCanaryMasked({ run: (a, o) => runConfined(a, { ...o, readRoots: undefined }) }));
  await step('protected-canary-masked:capability', () => probeProtectedCanaryMasked());
  await step('capability-network', () => probeCapabilityNetwork());
  return out;
}
