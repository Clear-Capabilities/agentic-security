// X-502 / X-503 / X-504 / CORE-003: the Linux half of capability enforcement.
//
// Two kinds of test live here, and the split is the point.
//
//   CONSTRUCTION tests run on every host. They build the Linux mount plan, the
//   setup script and the spawn invocation with stand-in tools, and run the
//   setup script with logging stand-ins for the mount tools, so the ORDER and
//   the ARGUMENTS of what would reach the kernel are checked anywhere. They say
//   nothing about what the kernel then does.
//
//   EXECUTION tests need the real namespace backend. They run the active
//   probes (attack plus positive control) against the kernel, and each also
//   runs the probe against a runner that is DELIBERATELY WRONG (a root left
//   writable, a read root left too wide, a leaky tree) and requires the probe to
//   say so: a probe that cannot fail proves nothing. They SKIP, loudly, on a host
//   without the backend ("SKIPPED, NOT PASSED"), and they RUN on the
//   `sandbox-linux` CI job, whose runner script fails when they skip.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { detectBackend } from '../../src/sandbox/capabilities.js';
import { buildNamespaceInvocation } from '../../src/sandbox/backend-namespace.js';
import { runConfinedSupervised } from '../../src/sandbox/supervise.js';
import { probeControls } from '../../src/sandbox/control-probes.js';
import { probeTreeHeartbeat } from '../../src/sandbox/control-probes.js';
import {
  buildRootPlan, serializePlan, PIVOT_SETUP_SCRIPT, FINAL_SCRIPT, BASELINE_DIRS, MARK_SETUP_FAILED,
} from '../../src/sandbox/linux-rootfs.js';
import {
  probePidNamespace, probeInitKillReapsDetached, probeProtectedCanaryMasked, probeCapabilityNetwork,
} from '../../src/sandbox/linux-probes.js';
import { probeCapabilityControls, probeFsRead, probeMultiWrite, resetCapabilityProbeCache } from '../../src/capabilities/probes.js';
import { mkTestTmp } from '../helpers/tmp.js';

const BACKEND = detectBackend();
const CAN_RUN = BACKEND === 'namespace';
const SKIP = CAN_RUN ? false
  : `SKIPPED, NOT PASSED: execution tests need the Linux namespace backend (selected '${BACKEND}'); UNVERIFIED here`;

const tmp = (p) => fs.realpathSync(mkTestTmp(p));

// ---------------------------------------------------------------------------
// Construction (every host)
// ---------------------------------------------------------------------------

describe('[X-502.AC01] the Linux mount plan makes visible only the baseline and the declared roots', () => {
  const real = (p) => p; // no symlink resolution: the plan is judged on the text given

  test('positive control: declared read and write roots appear with the right access', () => {
    const plan = buildRootPlan({ root: '/work/root', readRoots: ['/data/in'], writeRoots: ['/data/out'], realpath: real });
    assert.equal(plan.ok, true);
    const by = Object.fromEntries(plan.entries.map((e) => [e.path, e.mode]));
    assert.equal(by['/data/in'], 'ro');
    assert.equal(by['/data/out'], 'rw');
    assert.equal(by['/work/root'], 'rw');
    for (const b of ['/usr', '/bin']) assert.equal(by[b], 'ro', `${b} must be read-only baseline`);
  });

  test('an undeclared path is not in the plan, and nothing outside baseline plus roots is', () => {
    const plan = buildRootPlan({ root: '/work/root', readRoots: ['/data/in'], writeRoots: ['/data/out'], realpath: real });
    const allowed = new Set([...BASELINE_DIRS, '/etc/ld.so.cache', '/etc/ld.so.conf', '/etc/localtime', '/etc/nsswitch.conf', '/etc/passwd', '/etc/group', '/work/root', '/data/in', '/data/out']);
    for (const e of plan.entries) assert.ok(allowed.has(e.path), `unexpected path made visible: ${e.path}`);
    assert.ok(!plan.entries.some((e) => e.path === '/data' || e.path === '/home' || e.path === '/root' || e.path === '/tmp'));
  });

  test('a root declared read-only AND write is read-write; an entry covered by a bound ancestor is dropped', () => {
    const plan = buildRootPlan({ root: '/w', readRoots: ['/d', '/usr/bin/cat'], writeRoots: ['/d'], realpath: real });
    const by = Object.fromEntries(plan.entries.map((e) => [e.path, e.mode]));
    assert.equal(by['/d'], 'rw', 'rw must win over ro for the same path');
    assert.equal(by['/usr/bin/cat'], undefined, 'a file under a bound read-only baseline directory must not be re-bound');
  });

  test('a read-write child of a read-only parent is kept (the narrowing is by access, not path)', () => {
    const plan = buildRootPlan({ root: '/w', readRoots: ['/d'], writeRoots: ['/d/out'], realpath: real });
    const by = Object.fromEntries(plan.entries.map((e) => [e.path, e.mode]));
    assert.equal(by['/d'], 'ro'); assert.equal(by['/d/out'], 'rw');
    const order = plan.entries.map((e) => e.path);
    assert.ok(order.indexOf('/d') < order.indexOf('/d/out'), 'a parent must be bound before its child');
  });

  test('the filesystem root, paths the format cannot carry, and an outside working directory are refused', () => {
    assert.equal(buildRootPlan({ root: '/w', readRoots: ['/'], realpath: real }).ok, false);
    assert.equal(buildRootPlan({ root: '/w', readRoots: ['/a\tb'], realpath: real }).ok, false);
    assert.equal(buildRootPlan({ root: '/w', readRoots: ['/a\nb'], realpath: real }).ok, false);
    assert.equal(buildRootPlan({ root: '/w', readRoots: ['relative'], realpath: () => 'relative' }).ok, false);
    assert.equal(buildRootPlan({ root: '/w', cwd: '/elsewhere', realpath: real }).ok, false);
    assert.equal(buildRootPlan({ root: '/w', cwd: '/w/sub', realpath: real }).ok, true);
  });

  test('a protected path becomes a mask; one containing a bound root is refused rather than guessed', () => {
    const ok = buildRootPlan({ root: '/w', readRoots: ['/d'], denyReadPaths: ['/d/sealed'], realpath: real });
    assert.deepEqual(ok.masks, ['/d/sealed']);
    assert.match(serializePlan(ok), /^M\t-\t\/d\/sealed$/m);
    const hides = buildRootPlan({ root: '/w', readRoots: ['/d'], denyReadPaths: ['/d'], realpath: real });
    assert.equal(hides.ok, false);
  });
});

function stubTools(dir) {
  const log = path.join(dir, 'calls.log');
  const mk = (name, body) => { const p = path.join(dir, name); fs.writeFileSync(p, `#!/bin/sh\n${body}\n`, { mode: 0o755 }); return p; };
  return {
    log,
    SBX_MOUNT: mk('mount', `echo "mount $*" >> "${log}"`),
    SBX_UMOUNT: mk('umount', `echo "umount $*" >> "${log}"`),
    SBX_PIVOT: mk('pivot_root', `echo "pivot_root $*" >> "${log}"`),
    SBX_PRIVDROP: mk('setpriv', `echo "setpriv $*" >> "${log}"\nwhile [ $# -gt 0 ]; do case "$1" in --*) shift;; *) break;; esac; done\nexec "$@"`),
  };
}

function runSetup(plan, { final = FINAL_SCRIPT, canaryWritable = false } = {}) {
  const dir = tmp('x502-stub-');
  const root = path.join(dir, 'root'); fs.mkdirSync(root);
  const nr = path.join(dir, 'newroot'); fs.mkdirSync(nr);
  for (const m of plan.masks) fs.mkdirSync(path.join(nr, m), { recursive: true }); // stands in for the bound content
  const t = stubTools(dir);
  const canary = canaryWritable ? path.join(dir, 'canary') : path.join(dir, 'no-such-dir', 'canary');
  const r = spawnSync('/bin/sh', ['-c', PIVOT_SETUP_SCRIPT, '_sbx', '/bin/sh', '-c', 'echo ran > "$ROOT/payload.out"'], {
    encoding: 'utf8', timeout: 20000,
    env: {
      PATH: '/usr/bin:/bin', ROOT: root, SBX_NEWROOT: nr, SBX_PLAN: serializePlan(plan), SBX_FINAL: final,
      SBX_CANARY: canary, SBX_CWD: root, SBX_MOUNT: t.SBX_MOUNT, SBX_UMOUNT: t.SBX_UMOUNT, SBX_PIVOT: t.SBX_PIVOT, SBX_PRIVDROP: t.SBX_PRIVDROP,
    },
  });
  const calls = fs.existsSync(t.log) ? fs.readFileSync(t.log, 'utf8').split('\n').filter(Boolean) : [];
  return { r, calls, root, nr, ranPayload: fs.existsSync(path.join(root, 'payload.out')) };
}

describe('[X-502.AC01] the setup script asks the kernel for the right mounts, in the right order', () => {
  const root0 = tmp('x502-plan-');
  const ro = path.join(root0, 'ro'); const rw = path.join(root0, 'rw'); const sealed = path.join(ro, 'sealed');
  fs.mkdirSync(sealed, { recursive: true }); fs.mkdirSync(rw);
  const planFor = () => buildRootPlan({ root: path.join(root0, 'root'), readRoots: [ro], writeRoots: [rw], denyReadPaths: [sealed] });
  fs.mkdirSync(path.join(root0, 'root'));

  test('every read-only path is bound then remounted read-only; read-write paths are not; the root is sealed last, then pivoted', () => {
    const plan = planFor(); assert.equal(plan.ok, true, plan.error);
    const { r, calls, ranPayload, nr } = runSetup(plan);
    assert.equal(r.status, 0, `${r.stderr}\n${calls.join('\n')}`);
    assert.equal(ranPayload, true, 'the stand-in run should reach the payload');
    const idx = (pred) => calls.findIndex(pred);
    assert.match(calls[0], /^mount --make-rprivate \/$/, 'propagation must be made private first');
    assert.match(calls[1], /^mount -t tmpfs .* tmpfs /, 'the new root must be a fresh tmpfs');
    for (const e of plan.entries) {
      const bind = idx((c) => c === `mount --bind ${e.path} ${nr}${e.path}`);
      if (!fs.existsSync(e.path)) continue; // baseline entries absent on this host
      if (fs.lstatSync(e.path).isSymbolicLink()) continue;
      assert.ok(bind >= 0, `no bind for ${e.path}`);
      const rem = idx((c) => c === `mount -o remount,bind,ro ${nr}${e.path}`);
      if (e.mode === 'ro') assert.ok(rem > bind, `${e.path} was not remounted read-only after it was bound`);
      else assert.equal(rem, -1, `${e.path} is a write root and must not be remounted read-only`);
    }
    const maskCall = idx((c) => c.startsWith('mount -t tmpfs -o size=4k,mode=000 tmpfs ') && c.endsWith(`${nr}${sealed}`));
    assert.ok(maskCall > idx((c) => c === `mount --bind ${ro} ${nr}${ro}`), 'the protected directory must be masked after its root is bound');
    const seal = idx((c) => c === `mount -o remount,bind,ro ${nr}`);
    const pivot = idx((c) => c.startsWith('pivot_root '));
    const umount = idx((c) => c === 'umount -l /.old');
    assert.ok(seal > maskCall && pivot > seal && umount > pivot, `bad order: seal=${seal} pivot=${pivot} umount=${umount}`);
    assert.equal(pivot, calls.findIndex((c) => c === `pivot_root ${nr} ${nr}/.old`));
    assert.ok(calls.some((c) => c.startsWith('setpriv --no-new-privs')), 'privileges must be dropped before the payload');
  });

  test('DELIBERATE BREAKAGE: a plan that leaves a read root writable is visible in the call log', () => {
    const plan = planFor();
    const broken = { ...plan, entries: plan.entries.map((e) => (e.path === ro ? { ...e, mode: 'rw' } : e)) };
    const { calls, nr } = runSetup(broken);
    assert.equal(calls.some((c) => c === `mount -o remount,bind,ro ${nr}${ro}`), false,
      'the broken plan must not read-only remount the root, which is exactly what the good-plan test requires');
  });

  test('a mount that fails stops the setup before the payload runs (fail closed)', () => {
    const dir = tmp('x502-fail-');
    const plan = planFor();
    const root = path.join(dir, 'root'); fs.mkdirSync(root);
    const nr = path.join(dir, 'newroot'); fs.mkdirSync(nr);
    const t = stubTools(dir);
    fs.writeFileSync(t.SBX_PIVOT, '#!/bin/sh\nexit 1\n', { mode: 0o755 });
    const r = spawnSync('/bin/sh', ['-c', PIVOT_SETUP_SCRIPT, '_sbx', '/bin/sh', '-c', 'echo ran > "$ROOT/payload.out"'], {
      encoding: 'utf8', timeout: 20000,
      env: { PATH: '/usr/bin:/bin', ROOT: root, SBX_NEWROOT: nr, SBX_PLAN: serializePlan(plan), SBX_FINAL: FINAL_SCRIPT, SBX_CANARY: path.join(dir, 'x', 'c'), SBX_CWD: root, ...t },
    });
    assert.equal(r.status, 91);
    assert.ok(r.stderr.includes(MARK_SETUP_FAILED));
    assert.equal(fs.existsSync(path.join(root, 'payload.out')), false, 'the payload must not run when pivot_root failed');
  });
});

describe('[X-502.AC01] the second stage refuses to run the command unless confinement holds, in both directions', () => {
  const run = (env) => {
    const dir = tmp('x502-final-');
    const root = path.join(dir, 'root'); fs.mkdirSync(root);
    const r = spawnSync('/bin/sh', ['-c', FINAL_SCRIPT, '_sbx', '/bin/sh', '-c', 'echo ran > "$ROOT/payload.out"'], {
      encoding: 'utf8', env: { PATH: '/usr/bin:/bin', ROOT: root, ...env(dir) },
    });
    return { r, ran: fs.existsSync(path.join(root, 'payload.out')), root };
  };
  test('positive control: an unwritable canary and a writable root run the command', () => {
    const { r, ran } = run((dir) => ({ SBX_CANARY: path.join(dir, 'nope', 'c') }));
    assert.equal(r.status, 0, r.stderr); assert.equal(ran, true);
  });
  test('a writable canary means confinement is not in force: the command does not run', () => {
    const { r, ran } = run((dir) => ({ SBX_CANARY: path.join(dir, 'c') }));
    assert.equal(r.status, 91); assert.equal(ran, false);
    assert.ok(r.stderr.includes('out-of-root write is still possible'));
  });
  test('the internal setup variables are not handed to the command', () => {
    const dir = tmp('x502-env-');
    const root = path.join(dir, 'root'); fs.mkdirSync(root);
    const r = spawnSync('/bin/sh', ['-c', FINAL_SCRIPT, '_sbx', '/usr/bin/env'], {
      encoding: 'utf8', env: { PATH: '/usr/bin:/bin', ROOT: root, SBX_CANARY: path.join(dir, 'n', 'c'), SBX_PLAN: 'B\tro\t/secret-plan-text', SBX_MOUNT: '/x' },
    });
    assert.equal(r.status, 0, r.stderr);
    assert.ok(!/SBX_|secret-plan-text/.test(r.stdout), r.stdout);
  });
});

describe('[X-502.AC03] the invocation builder fails closed instead of running with less', () => {
  const tools = {
    nsBin: () => '/x/unshare', mountBin: () => '/x/mount', privDropBin: () => '/x/setpriv', pivotBin: () => '/x/pivot_root', umountBin: () => '/x/umount',
    nsArgs: (bin, net) => ['--user', '--map-root-user', '--mount', '--pid', '--ipc', '--uts', '--fork', '--kill-child', ...(net ? [] : ['--net'])],
  };
  const root = tmp('x502-inv-');
  const base = { root, limits: { maxProcs: 1000 } };

  test('capability mode builds a pivot invocation carrying every confinement flag', () => {
    const inv = buildNamespaceInvocation(['/bin/true'], { ...base, readRoots: [] }, tools);
    assert.equal(inv.error, undefined, JSON.stringify(inv.error));
    try {
      assert.equal(inv.mode, 'capability'); assert.equal(inv.treeKill, true);
      for (const f of ['--mount', '--pid', '--net', '--kill-child', '--fork']) assert.ok(inv.args.includes(f), f);
      assert.equal(inv.env.SBX_STRICT, '1'); assert.ok(inv.env.SBX_NEWROOT);
      assert.ok(inv.args.join(' ').includes('pivot_root'));
    } finally { inv.dispose(); }
  });

  test('default mode keeps the legacy setup and does not pivot', () => {
    const inv = buildNamespaceInvocation(['/bin/true'], base, tools);
    try {
      assert.equal(inv.mode, 'default'); assert.equal(inv.env.SBX_STRICT, undefined);
      assert.ok(!inv.args.join(' ').includes('pivot_root'));
    } finally { inv.dispose(); }
  });

  test('mediated network is refused, never silently allowed', () => {
    const inv = buildNamespaceInvocation(['/bin/true'], { ...base, readRoots: [], networkProxyPort: 8080 }, tools);
    assert.equal(inv.error.status, 'error'); assert.match(inv.error.stderr, /mediated network/);
  });

  test('a missing pivot or unmount tool refuses capability mode but not default mode', () => {
    const noPivot = buildNamespaceInvocation(['/bin/true'], { ...base, readRoots: [] }, { ...tools, pivotBin: () => null });
    assert.equal(noPivot.error.status, 'error');
    const legacy = buildNamespaceInvocation(['/bin/true'], base, { ...tools, pivotBin: () => null });
    assert.equal(legacy.error, undefined); legacy.dispose();
  });

  test('a denied path that contains the sandbox root is refused', () => {
    const inv = buildNamespaceInvocation(['/bin/true'], { ...base, denyReadPaths: [path.dirname(root)] }, tools);
    assert.equal(inv.error.status, 'error'); assert.match(inv.error.stderr, /overlaps/);
  });

  test('without the unshare tree-kill flag the supervised run is refused (no sweep-only claim)', async () => {
    const noKill = { ...tools, nsArgs: (b, net) => tools.nsArgs(b, net).filter((a) => a !== '--kill-child') };
    const inv = buildNamespaceInvocation(['/bin/true'], base, noKill);
    try { assert.equal(inv.treeKill, false); } finally { inv.dispose(); }
  });
});

// ---------------------------------------------------------------------------
// Execution (needs the real backend)
// ---------------------------------------------------------------------------

describe('[CORE-003.AC02] the base controls are proved on the Linux namespace backend', { skip: SKIP }, () => {
  test('write-confinement, read-denial, env-scrub, network, tree-termination and file-size-limit are all proved', async () => {
    const report = await probeControls({});
    const states = Object.fromEntries(Object.entries(report.controls).map(([k, v]) => [k, `${v.state}${v.reason ? `: ${v.reason}` : ''}`]));
    for (const c of ['write-confinement', 'read-denial', 'env-scrub', 'network', 'tree-termination', 'file-size-limit']) {
      assert.match(states[c], /^proved/, `${c} -> ${states[c]}`);
    }
    assert.equal(report.controls['process-cap'].state, 'unverified', 'a process-count cap must stay unasserted');
  });

  test('the heartbeat tree probe cannot pass against a runner that leaks a detached member (probe sensitivity)', async () => {
    const leaky = async (argv, o) => {
      const child = spawn('/bin/sh', ['-c', argv[2]], { env: { PATH: '/usr/bin:/bin', ROOT: o.root }, detached: true, stdio: 'ignore' });
      await new Promise((r) => setTimeout(r, 1800));
      try { process.kill(-child.pid, 'SIGKILL'); } catch { /* gone */ }
      return { supervised: true, backend: 'leaky', status: 'timeout' };
    };
    const r = await probeTreeHeartbeat({ run: leaky });
    assert.notEqual(r.state, 'proved', JSON.stringify(r));
    if (process.platform === 'linux') assert.match(r.reason, /still running/, 'the detached heartbeat must be seen surviving');
  });
});

describe('[X-502.AC01] reads and writes outside the allowed roots are blocked on the Linux namespace backend', { skip: SKIP }, () => {
  test('read confinement: direct, symlink, traversal and descendant reads are refused; the declared root is readable', async () => {
    const r = await probeFsRead('namespace');
    assert.equal(r.state, 'proved', JSON.stringify(r));
  });

  test('multi-root write: both write roots writable, the read-only root and an undeclared directory are not', async () => {
    const r = await probeMultiWrite('namespace');
    assert.equal(r.state, 'proved', JSON.stringify(r));
  });

  test('FAULT INJECTION: a runner that leaves the read-only root writable is caught by the write probe', async () => {
    const wide = (argv, o) => runConfinedSupervised(argv, { ...o, writeRoots: [...(o.writeRoots || []), ...(o.readRoots || [])] });
    const r = await probeMultiWrite('namespace', wide);
    assert.equal(r.state, 'not-proved', JSON.stringify(r));
    assert.match(r.reason, /read-only was writable/);
  });

  test('FAULT INJECTION: a runner that declares the whole temp directory readable is caught by the read probe', async () => {
    const wide = (argv, o) => runConfinedSupervised(argv, { ...o, readRoots: [...(o.readRoots || []), os.tmpdir()] });
    const r = await probeFsRead('namespace', wide);
    assert.equal(r.state, 'not-proved', JSON.stringify(r));
    assert.match(r.reason, /readable/);
  });

  test('the pivoted root is read-only, the old root is gone, and a host path outside the roots has no name', async () => {
    const root = tmp('x502-live-'); const outside = tmp('x502-live-out-');
    fs.writeFileSync(path.join(outside, 'c.txt'), 'host-canary');
    const r = await runConfinedSupervised(['/bin/sh', '-c',
      `( : > /rootwrite ) 2>&1; ls / 2>&1; cat '${outside}/c.txt' 2>&1; echo LISTING; ls -A '${path.dirname(outside)}' 2>&1; true`], { root, readRoots: [] });
    assert.equal(r.supervised, true, JSON.stringify(r));
    assert.ok(!r.stdout.includes('host-canary'), r.stdout);
    // The error message of the failed read names the path; the directory
    // listing is what must not.
    const listing = r.stdout.split('LISTING\n')[1] ?? '';
    assert.ok(listing.includes(path.basename(root)), `positive control: the declared root should be listed (${listing})`);
    assert.ok(!listing.includes(path.basename(outside)), 'a sibling of an undeclared directory must not be listed');
    assert.ok(!fs.existsSync('/rootwrite'));
  });
});

describe('[X-503.AC02] descendants are terminated by the kernel, including ones no sweep can find', { skip: SKIP }, () => {
  test('killing the namespace supervisor ends a plain, a SIGTERM-ignoring and a double-forked setsid member', async () => {
    const r = await probeInitKillReapsDetached({ victim: 'supervisor' });
    assert.equal(r.state, 'proved', JSON.stringify(r));
  });
  test('killing the namespace init directly ends the same three members', async () => {
    const r = await probeInitKillReapsDetached({ victim: 'init' });
    assert.equal(r.state, 'proved', JSON.stringify(r));
  });
  test('the payload is pid 1 of its own PID namespace and cannot see host processes', async () => {
    const r = await probePidNamespace();
    assert.equal(r.state, 'proved', JSON.stringify(r));
  });
});

describe('[CORE-003.AC01] protected paths are unreadable on the Linux namespace backend', { skip: SKIP }, () => {
  test('a protected file and directory under a declared root are masked in capability mode', async () => {
    const r = await probeProtectedCanaryMasked();
    assert.equal(r.state, 'proved', JSON.stringify(r));
  });
  test('and in the default mode', async () => {
    const { runConfined } = await import('../../src/sandbox/index.js');
    const r = await probeProtectedCanaryMasked({ run: (a, o) => runConfined(a, { ...o, readRoots: undefined }) });
    assert.equal(r.state, 'proved', JSON.stringify(r));
  });
  test('FAULT INJECTION: a runner that forgets the protected paths is caught', async () => {
    const { runConfined } = await import('../../src/sandbox/index.js');
    const forgetful = (a, o) => runConfined(a, { ...o, denyReadPaths: [] });
    const r = await probeProtectedCanaryMasked({ run: forgetful });
    assert.equal(r.state, 'not-proved', JSON.stringify(r));
    assert.match(r.reason, /was readable/);
  });
});

describe('[X-504.AC03] a direct socket cannot bypass the policy on the Linux namespace backend', { skip: SKIP }, () => {
  test('in capability mode a loopback listener is reachable only when network is allowed', async () => {
    const r = await probeCapabilityNetwork();
    assert.equal(r.state, 'proved', JSON.stringify(r));
  });
  test('FAULT INJECTION: a runner that always allows network is caught', async () => {
    const { runConfined } = await import('../../src/sandbox/index.js');
    const open = (a, o) => runConfined(a, { ...o, allowNetwork: true });
    const r = await probeCapabilityNetwork({ run: open });
    assert.equal(r.state, 'not-proved', JSON.stringify(r));
    assert.match(r.reason, /network denied/);
  });
  test('mediated network is unsupported here, so a task that declares a destination is blocked, never allowed', async () => {
    resetCapabilityProbeCache();
    const controls = (await probeCapabilityControls({})).controls;
    assert.equal(controls['network-mediation'].state, 'unsupported');
    assert.equal(controls['fs-read-confinement'].state, 'proved', JSON.stringify(controls['fs-read-confinement']));
    assert.equal(controls['fs-multi-root-write'].state, 'proved', JSON.stringify(controls['fs-multi-root-write']));
  });
});
