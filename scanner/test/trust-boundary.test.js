// CORE-003.AC01 and AC02: the trust boundary is ATTACKED, not inspected.
//
// A skip here is NOT a pass. The enforced-boundary attacks need a backend whose
// controls were proved by active probe on this host. Where that is not the
// case (Linux: read denial and supervised tree termination are not implemented
// on the namespace backend; hosts with no backend), the test asserts the
// opposite, equally important property: the boundary is BLOCKED and the target
// never ran. Nothing below asserts a Linux outcome that has not been executed.
import { test, describe, before } from 'node:test';
import assert from 'node:assert';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { detectBackend } from '../src/sandbox/capabilities.js';
import { runInBoundary, DEFAULT_REQUIRED_CONTROLS } from '../src/sandbox/trust-boundary.js';
import { probeControls, capabilityReport, unmetControls, CONTROLS } from '../src/sandbox/control-probes.js';
import { runConfinedSupervised, superviseSpawn } from '../src/sandbox/supervise.js';
import {
  DOMAINS, RESOURCES, mayDo, protectedReadPaths, keyDirectory, settleVerification,
  assertNoSecretMaterial, scrubEnv, classifyRun,
} from '../src/sandbox/trust-domains.js';
import { mkTestTmp } from './helpers/tmp.js';

const BACKEND = detectBackend();
const ENFORCED = BACKEND === 'userspace';
const why = `SKIPPED, NOT PASSED: the enforced-boundary attacks need a probed userspace backend (selected '${BACKEND}'); UNVERIFIED here`;
const skipUnlessEnforced = ENFORCED ? false : why;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const alive = (pid) => { try { process.kill(pid, 0); return true; } catch (e) { return e.code === 'EPERM'; } };

function psHas(needle) {
  const r = spawnSync('ps', ['-A', '-o', 'command='], { encoding: 'utf8' });
  return String(r.stdout).split('\n').filter((l) => l.includes(needle)).length;
}

// ---- trust domains ----------------------------------------------------------

describe('[CORE-003.AC01] trust domains are an explicit default-deny policy', () => {
  test('target and worker may touch only their workspace', () => {
    for (const d of [DOMAINS.TARGET, DOMAINS.WORKER]) {
      assert.equal(mayDo(d, RESOURCES.WORKSPACE, 'write'), true);
      for (const r of [RESOURCES.SIGNING_KEY, RESOURCES.HMAC_KEY, RESOURCES.SEALED_LABELS,
        RESOURCES.AUTHORITATIVE_EVIDENCE, RESOURCES.VERIFICATION_STATUS, RESOURCES.HOST_CREDENTIALS]) {
        assert.equal(mayDo(d, r, 'read'), false, `${d} read ${r}`);
        assert.equal(mayDo(d, r, 'write'), false, `${d} write ${r}`);
      }
    }
  });
  test('only the signer reads the signing key; only the verifier writes evidence and status', () => {
    assert.equal(mayDo(DOMAINS.SIGNER, RESOURCES.SIGNING_KEY, 'read'), true);
    assert.equal(mayDo(DOMAINS.VERIFIER, RESOURCES.SIGNING_KEY, 'read'), false);
    assert.equal(mayDo(DOMAINS.VERIFIER, RESOURCES.AUTHORITATIVE_EVIDENCE, 'write'), true);
    assert.equal(mayDo(DOMAINS.SIGNER, RESOURCES.AUTHORITATIVE_EVIDENCE, 'write'), false);
    assert.equal(mayDo(DOMAINS.VERIFIER, RESOURCES.VERIFICATION_STATUS, 'write'), true);
    assert.equal(mayDo('nonsense', RESOURCES.WORKSPACE, 'read'), false);
  });
  test('the default protected set always contains the key directory used by the signer', async () => {
    const tmp = mkTestTmp('tb-xdg-');
    const { keyPaths } = await import('../src/posture/evidence-bundle.js');
    const prev = process.env.XDG_CONFIG_HOME;
    process.env.XDG_CONFIG_HOME = tmp;
    try {
      assert.ok(protectedReadPaths().includes(keyDirectory()));
      assert.equal(path.dirname(keyPaths().privateKey), keyDirectory(),
        'evidence-bundle and the boundary must agree on where the key lives');
    } finally { if (prev === undefined) delete process.env.XDG_CONFIG_HOME; else process.env.XDG_CONFIG_HOME = prev; }
  });
  test('secret-looking environment entries are detected and scrubbed, never forwarded', () => {
    const env = { PATH: '/bin', AGENTIC_SECURITY_HMAC_KEY: 'ab', GITHUB_TOKEN: 'x', FOO: '-----BEGIN PRIVATE KEY-----\nzz', OK: '1' };
    assert.deepEqual(assertNoSecretMaterial(env).offenders.sort(), ['AGENTIC_SECURITY_HMAC_KEY', 'FOO', 'GITHUB_TOKEN']);
    assert.deepEqual(Object.keys(scrubEnv(env)).sort(), ['OK', 'PATH']);
    assert.equal(assertNoSecretMaterial({ PATH: '/bin', HOME: '/h' }).ok, true);
  });
});

// ---- blocked, never a pass ---------------------------------------------------

describe('[CORE-003.AC01] insufficient isolation yields blocked and the target never runs', () => {
  test('a disabled backend blocks without executing', async () => {
    const root = mkTestTmp('tb-root-');
    const r = await runInBoundary(['/bin/sh', '-c', `echo ran > "$ROOT/marker"`], { root, force: 'disabled' });
    assert.equal(r.status, 'blocked');
    assert.equal(r.blocked, true);
    assert.equal(r.executed, false);
    assert.equal(r.verificationStatus, 'not-run');
    assert.equal(fs.existsSync(path.join(root, 'marker')), false);
  });

  test('an unproved required control blocks, with the control named, and nothing runs', async () => {
    const root = mkTestTmp('tb-root-');
    const r = await runInBoundary(['/bin/sh', '-c', `echo ran > "$ROOT/marker"`], {
      root,
      controlProbes: { 'read-denial': () => ({ state: 'unsupported', reason: 'stand-in: no read denial here' }) },
    });
    if (BACKEND === 'disabled') { assert.equal(r.blocked, true); return; }
    assert.equal(r.status, 'blocked');
    assert.ok(r.reasons.some((x) => x.includes("'read-denial'") && x.includes('unsupported')), r.reasons.join('|'));
    assert.equal(fs.existsSync(path.join(root, 'marker')), false, 'the target must not run when a control is unproved');
  });

  test('a probe that cannot prove its own positive control is not-proved, never proved', async () => {
    const report = await probeControls({
      probes: { network: () => ({ state: 'not-proved', reason: 'positive control failed' }) },
    });
    if (BACKEND === 'disabled') return;
    assert.equal(report.controls.network.state, 'not-proved');
    assert.equal(unmetControls(report, ['network']).length, 1);
  });

  test('secret material bound for the target is refused before anything runs', async () => {
    const root = mkTestTmp('tb-root-');
    const r = await runInBoundary(['/bin/sh', '-c', `echo ran > "$ROOT/marker"`], {
      root, env: { AGENTIC_SECURITY_HMAC_KEY: 'deadbeef' },
    });
    if (BACKEND === 'disabled') { assert.equal(r.blocked, true); return; }
    assert.equal(r.blocked, true);
    assert.match(r.reasons.join(' '), /AGENTIC_SECURITY_HMAC_KEY/);
    assert.equal(fs.existsSync(path.join(root, 'marker')), false);
  });

  test('a workspace that contains a protected path is refused', async () => {
    const parent = mkTestTmp('tb-parent-');
    const labels = path.join(parent, 'labels');
    fs.mkdirSync(labels);
    const r = await runInBoundary(['/bin/sh', '-c', 'true'], { root: parent, labelDirs: [labels] });
    assert.equal(r.blocked, true);
    if (BACKEND !== 'disabled') assert.match(r.reasons.join(' '), /overlaps protected/);
  });

  test('on any backend: either every required control is proved, or the result is blocked and unexecuted', async () => {
    const root = mkTestTmp('tb-root-');
    const r = await runInBoundary(['/bin/sh', '-c', `echo ran > "$ROOT/marker"`], { root });
    if (r.blocked) {
      assert.equal(r.executed, false);
      assert.equal(fs.existsSync(path.join(root, 'marker')), false);
    } else {
      for (const c of DEFAULT_REQUIRED_CONTROLS) assert.equal(r.controls[c].state, 'proved', c);
      assert.equal(r.executed, true);
    }
  });
});

// ---- the attack fixture ------------------------------------------------------

describe('[CORE-003.AC01] a malicious target cannot cross the boundary', { skip: skipUnlessEnforced }, () => {
  let root, keyDir, labels, evidence, fakeHome, secrets, run;

  before(async () => {
    root = mkTestTmp('tb-atk-root-');
    const base = mkTestTmp('tb-atk-host-');
    keyDir = path.join(base, 'xdg', 'agentic-security');
    labels = path.join(base, 'labels');
    evidence = path.join(base, 'evidence');
    fakeHome = path.join(base, 'home');
    for (const d of [keyDir, labels, evidence, path.join(fakeHome, '.ssh')]) fs.mkdirSync(d, { recursive: true });
    secrets = {
      key: 'ED25519-PRIVATE-KEY-CANARY-7f3a',
      hmac: 'HMAC-SCAN-KEY-CANARY-91bc',
      label: 'SEALED-LABEL-CANARY-ec02',
      ssh: 'SSH-PRIVATE-CANARY-55d1',
      env: 'ENV-HMAC-CANARY-0a9e',
    };
    fs.writeFileSync(path.join(keyDir, 'attest-key.pem'), secrets.key);
    fs.writeFileSync(path.join(keyDir, 'scan-key'), secrets.hmac);
    fs.writeFileSync(path.join(labels, 'labels.jsonl'), secrets.label);
    fs.writeFileSync(path.join(fakeHome, '.ssh', 'id_ed25519'), secrets.ssh);
    fs.writeFileSync(path.join(evidence, 'verdict.json'), '{"status":"refuted"}');

    // The hostile target: tries every forbidden action and prints forged status.
    const attack = [
      `cat '${keyDir}/attest-key.pem' 2>&1`,
      `cat '${keyDir}/scan-key' 2>&1`,
      `cat '${labels}/labels.jsonl' 2>&1`,
      `cat '${fakeHome}/.ssh/id_ed25519' 2>&1`,
      `echo "env:$AGENTIC_SECURITY_HMAC_KEY" 2>&1`,
      `printf '{"status":"confirmed"}' > '${evidence}/verdict.json' 2>&1`,
      `printf forged > '${evidence}/forged.json' 2>&1`,
      `rm -f '${evidence}/verdict.json' 2>&1`,
      `echo '{"verificationStatus":"confirmed"}'`,
      `echo 'VERIFIED: status=confirmed execution-proven'`,
      'true',
    ].join('\n');
    const prev = process.env.AGENTIC_SECURITY_HMAC_KEY;
    process.env.AGENTIC_SECURITY_HMAC_KEY = secrets.env;
    try {
      run = await runInBoundary(['/bin/sh', '-c', attack], {
        root, home: fakeHome, labelDirs: [labels], evidenceDirs: [evidence], denyReadPaths: [keyDir],
      });
    } finally { if (prev === undefined) delete process.env.AGENTIC_SECURITY_HMAC_KEY; else process.env.AGENTIC_SECURITY_HMAC_KEY = prev; }
  });

  test('the attack actually ran inside the boundary (not blocked, not skipped)', () => {
    assert.equal(run.blocked, false, run.reasons.join('|'));
    assert.equal(run.executed, true);
  });

  test('verifier keys and the install HMAC key are unreadable', () => {
    const out = run.targetOutput.stdout + run.targetOutput.stderr;
    assert.ok(!out.includes(secrets.key), 'signing key leaked');
    assert.ok(!out.includes(secrets.hmac), 'install HMAC key leaked');
    assert.ok(!out.includes(secrets.env), 'the parent HMAC environment variable leaked');
  });

  test('sealed labels are unreadable', () => {
    assert.ok(!(run.targetOutput.stdout + run.targetOutput.stderr).includes(secrets.label));
  });

  test('unrelated host credential paths are unreadable', () => {
    assert.ok(!(run.targetOutput.stdout + run.targetOutput.stderr).includes(secrets.ssh));
  });

  test('authoritative evidence is unchanged: not overwritten, not deleted, nothing added', () => {
    assert.equal(fs.readFileSync(path.join(evidence, 'verdict.json'), 'utf8'), '{"status":"refuted"}');
    assert.equal(fs.existsSync(path.join(evidence, 'forged.json')), false);
  });

  test('forged status in target output does not set the verification status', () => {
    assert.ok(run.targetOutput.stdout.includes('VERIFIED'), 'the forgery was printed');
    assert.ok(run.targetOutput.statusLikeLines >= 2);
    assert.equal(run.verificationStatus, 'inconclusive');
    assert.notEqual(run.verificationStatus, 'confirmed');
    assert.equal(run.targetOutput.trust, 'untrusted');
  });

  test('only verifier-observed evidence can confirm; worker or target claims cannot', () => {
    assert.equal(settleVerification(run, { observedBy: DOMAINS.TARGET, satisfied: true }), 'inconclusive');
    assert.equal(settleVerification(run, { observedBy: DOMAINS.WORKER, satisfied: true }), 'inconclusive');
    assert.equal(settleVerification(run, { satisfied: true }), 'inconclusive');
    assert.equal(settleVerification(run, { observedBy: DOMAINS.VERIFIER, satisfied: true }), 'confirmed');
    // a refutation needs the oracle to say its preconditions held
    assert.equal(settleVerification(run, { observedBy: DOMAINS.VERIFIER, satisfied: false }), 'inconclusive');
    assert.equal(settleVerification(run, { observedBy: DOMAINS.VERIFIER, satisfied: false, preconditionsHeld: true }), 'refuted');
    // a run that never executed can never be confirmed, whatever evidence is offered
    assert.equal(settleVerification({ executed: false }, { observedBy: DOMAINS.VERIFIER, satisfied: true }), 'not-run');
    assert.equal(classifyRun(null), 'not-run');
  });

  test('GOOD: legitimate in-workspace work still runs and is observed', async () => {
    const r = await runInBoundary(['/bin/sh', '-c', 'echo fine > "$ROOT/out.txt"; cat "$ROOT/out.txt"'], { root });
    assert.equal(r.status, 'ok', r.targetOutput?.stderr);
    assert.match(r.targetOutput.stdout, /fine/);
  });
});

// ---- AC02: process trees, probes, resources ----------------------------------

describe('[CORE-003.AC02] controls are proved by active probes on the advertised backend', { skip: skipUnlessEnforced }, () => {
  test('every control reports a state with evidence, and the matrix is honest', async () => {
    const rep = capabilityReport(await probeControls());
    assert.equal(rep.backend, 'userspace');
    for (const c of CONTROLS) assert.ok(rep.controls[c], c);
    for (const c of ['write-confinement', 'read-denial', 'env-scrub', 'network', 'tree-termination', 'file-size-limit']) {
      assert.equal(rep.controls[c].state, 'proved', `${c}: ${JSON.stringify(rep.controls[c])}`);
      assert.ok(rep.controls[c].evidence, `${c} has no evidence`);
    }
    // never claimed: a process-count cap
    assert.notEqual(rep.controls['process-cap'].state, 'proved');
    assert.match(rep.controls['process-cap'].reason, /no enforcement is claimed/);
    assert.ok(rep.notes.some((n) => /Linux enforcement cannot be exercised on a macOS host/.test(n)));
  });
});

describe('[CORE-003.AC02] every process in the tree ends on timeout, cancel and exit', { skip: skipUnlessEnforced }, () => {
  async function pidsFrom(root, names) {
    await sleep(150);
    return names.map((n) => Number(fs.readFileSync(path.join(root, n), 'utf8')));
  }

  test('timeout kills the child, grandchildren and a SIGTERM-ignoring member; ps shows no orphan', async () => {
    const root = mkTestTmp('tb-tree-');
    const script = [
      'sleep 7311 & echo $! > "$ROOT/a"',
      '(sleep 7312 & echo $! > "$ROOT/b"; wait) &',
      `(trap '' TERM; sleep 7313 & echo $! > "$ROOT/c"; while :; do sleep 1; done) &`,
      'wait',
    ].join('\n');
    const t0 = Date.now();
    const r = await runConfinedSupervised(['/bin/sh', '-c', script], { root, timeoutMs: 1200, graceMs: 300 });
    const elapsed = Date.now() - t0;
    assert.equal(r.status, 'timeout');
    assert.equal(r.timedOut, true);
    assert.deepEqual(r.termination.survivors, []);
    assert.ok(elapsed < 4000, `took ${elapsed} ms`);
    const pids = await pidsFrom(root, ['a', 'b', 'c']);
    for (const p of pids) assert.equal(alive(p), false, `pid ${p} survived`);
    for (const n of ['7311', '7312', '7313']) assert.equal(psHas(`sleep ${n}`), 0, `sleep ${n} is an orphan`);
    assert.equal(r.termination.signalled, 'SIGKILL', 'a TERM-ignoring member must force the SIGKILL escalation');
  });

  test('cancel (AbortSignal) ends the whole tree promptly', async () => {
    const root = mkTestTmp('tb-cancel-');
    const ac = new AbortController();
    setTimeout(() => ac.abort(), 500);
    const p = runConfinedSupervised(['/bin/sh', '-c', '(sleep 7321 & echo $! > "$ROOT/a"; wait) & wait'], {
      root, timeoutMs: 20000, graceMs: 300, signal: ac.signal,
    });
    const r = await p;
    assert.equal(r.status, 'cancelled');
    assert.equal(r.cancelled, true);
    const [pid] = await pidsFrom(root, ['a']);
    assert.equal(alive(pid), false);
    assert.equal(psHas('sleep 7321'), 0);
  });

  test('a backgrounded grandchild cannot outlive a run that exited cleanly', async () => {
    const root = mkTestTmp('tb-exit-');
    const r = await runConfinedSupervised(['/bin/sh', '-c', 'sleep 7331 & echo $! > "$ROOT/a"; exit 0'], { root, timeoutMs: 5000, graceMs: 300 });
    assert.equal(r.status, 'ok');
    const [pid] = await pidsFrom(root, ['a']);
    assert.equal(alive(pid), false, 'leftover descendant survived a clean exit');
    assert.equal(psHas('sleep 7331'), 0);
  });

  test('an output flood is capped and the tree is terminated', async () => {
    const root = mkTestTmp('tb-flood-');
    const r = await runConfinedSupervised(['/bin/sh', '-c', 'sleep 7341 & while :; do echo flood-flood-flood-flood; done'], {
      root, timeoutMs: 20000, graceMs: 300, maxOutputBytes: 20000,
    });
    assert.equal(r.outputCapped, true);
    assert.equal(r.status, 'error');
    assert.ok(r.stdout.length <= 20000);
    await sleep(100);
    assert.equal(psHas('sleep 7341'), 0);
  });

  test('POSITIVE control: an unsupervised spawn leaves a descendant, so the survivor checks above are meaningful', async () => {
    // Without this, "nothing survived" could simply mean the sleepers never started.
    const root = mkTestTmp('tb-sens-');
    const r = spawnSync('/bin/sh', ['-c', `sleep 7351 & echo $! > '${root}/a'`], { timeout: 2000 });
    assert.equal(r.status, 0);
    await sleep(100);
    const pid = Number(fs.readFileSync(path.join(root, 'a'), 'utf8'));
    assert.equal(alive(pid), true, 'unsupervised spawn leaves the descendant, so the probe can fail');
    process.kill(pid, 'SIGKILL');
    await sleep(100);
    assert.equal(psHas('sleep 7351'), 0);
  });
});

describe('[CORE-003.AC02] backends where termination or read denial is not proved refuse to run', () => {
  test('a namespace backend that cannot be established refuses supervised execution instead of running unsupervised', async (t) => {
    // On a host where the namespace backend works this exact request RUNS (tree
    // termination is then proved by linux-probes.js on the sandbox-linux job),
    // so it is only a refusal test where the backend cannot be established.
    const { detectBackend } = await import('../src/sandbox/capabilities.js');
    if (detectBackend() === 'namespace') {
      t.skip('SKIPPED, NOT PASSED: the namespace backend works on this host, so this refusal path cannot be exercised here');
      return;
    }
    const root = mkTestTmp('tb-ns-');
    const r = await runConfinedSupervised(['/bin/sh', '-c', `echo ran > "$ROOT/marker"`], { root, force: 'namespace' });
    assert.equal(r.status, 'error');
    assert.match(r.stderr, /no kernel-namespace binary|could not be created|refusing to execute|not implemented or verified/);
    assert.equal(fs.existsSync(path.join(root, 'marker')), false);
  });

  test('the namespace backend refuses mediated network instead of silently ignoring it', async () => {
    const { runNamespace } = await import('../src/sandbox/backend-namespace.js');
    const root = mkTestTmp('tb-ns2-');
    const r = runNamespace(['/bin/sh', '-c', `echo ran > "$ROOT/marker"`], { root, networkProxyPort: 8080 });
    assert.equal(r.status, 'error');
    assert.match(r.stderr, /mediated network .* not implemented/);
    assert.equal(fs.existsSync(path.join(root, 'marker')), false);
  });

  test('a disabled backend never executes supervised work', async () => {
    const root = mkTestTmp('tb-dis-');
    const r = await runConfinedSupervised(['/bin/sh', '-c', `echo ran > "$ROOT/marker"`], { root, force: 'disabled' });
    assert.equal(r.status, 'disabled');
    assert.equal(fs.existsSync(path.join(root, 'marker')), false);
  });

  test('superviseSpawn reports a spawn failure instead of throwing or hanging', async () => {
    const r = await superviseSpawn('/nonexistent/binary-xyz', [], { timeoutMs: 2000 });
    assert.ok(r.spawnError);
    assert.equal(r.exitCode, null);
  });
});
