// X-502: filesystem access is enforced at execution, below the hooks.
//
// The attacks run through the real runner and the real operating-system
// boundary on this host. They assert on side effects (a file that must not exist
// does not; a canary that must not be read is not in the output), never on a
// status word alone. Execution tests skip, loudly, where no probed backend
// exists: a skip is a declared gap, not a pass.
//
// IMPORTANT, and tested below: macOS is not an advertised enforced backend. What
// these tests prove on this host is `host-proved` confinement, and the runner says
// `enforced: false` for it. Nothing here asserts a Linux outcome.
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { decide } from '../../src/capabilities/decide.js';
import { advise, toCapabilityDecisionRecord } from '../../src/capabilities/records.js';
import { isAdvertisedBackend, platformStatements, requiredControlsFor } from '../../src/capabilities/probes.js';
import { runCapabilityTask } from '../../src/capabilities/runner.js';
import { resolveAssuranceConfig } from '../../src/posture/assurance/config.js';
import { unmetControls } from '../../src/sandbox/control-probes.js';
import { digestOf } from '../../src/posture/assurance/identity.js';
import { BACKEND, SKIP, CONFIG_ON, bind, ctxFor, run, tmp, manifest, assertOsRefused, assertLevelHonest } from './helpers.js';

const CAT = { executable: '/bin/cat', args: { mode: 'prefix', values: [] } };
const TOUCH = { executable: '/usr/bin/touch', args: { mode: 'prefix', values: [] } };
const LS = { executable: '/bin/ls', args: { mode: 'prefix', values: [] } };

describe('[X-502.AC01] reads and writes outside allowed roots are blocked at the operating-system boundary', { skip: SKIP }, () => {
  let dir; let bound; let canary;
  before(() => {
    dir = tmp('x502-');
    canary = `CANARY-FS-${process.pid}-${Date.now()}`;
    for (const d of ['ro', 'work', 'outside']) fs.mkdirSync(path.join(dir, d));
    fs.writeFileSync(path.join(dir, 'ro/a.txt'), 'readable-in-root');
    fs.writeFileSync(path.join(dir, 'outside/secret.txt'), canary);
    fs.symlinkSync(path.join(dir, 'outside/secret.txt'), path.join(dir, 'ro/link'));
    fs.symlinkSync(path.join(dir, 'outside'), path.join(dir, 'ro/dirlink'));
    fs.symlinkSync(path.join(dir, 'outside'), path.join(dir, 'work/outdir'));
    bound = bind({
      filesystem: { read: [path.join(dir, 'ro')], write: [path.join(dir, 'work')] },
      commands: [CAT, TOUCH, LS],
    });
  });
  const exec = (executable, args) => run(bound, { executable, args });

  test('a read and a write inside the declared roots succeed (the positive control)', async () => {
    const r = await exec('/bin/cat', [path.join(dir, 'ro/a.txt')]);
    assert.equal(r.status, 'ok', JSON.stringify({ s: r.status, c: r.code, m: r.reason }));
    assert.equal(r.output.stdout, 'readable-in-root');
    const w = await exec('/usr/bin/touch', [path.join(dir, 'work/created-in-root')]);
    assert.equal(w.status, 'ok');
    assert.ok(fs.existsSync(path.join(dir, 'work/created-in-root')));
  });

  test('a read outside every root is refused by the operating system, not by the policy', async () => {
    const outside = path.join(dir, 'outside/secret.txt');
    // The command policy accepts these arguments (prefix mode, any tail): only the OS can stop the read.
    assert.equal(decide(bound, { kind: 'command', executable: '/bin/cat', args: [outside] }, ctxFor(bound)).decision, 'allow');
    const r = await exec('/bin/cat', [outside]);
    assert.equal(r.executed, true);
    assert.ok(!JSON.stringify(r).includes(canary), 'the canary is nowhere in the result');
    assertOsRefused(assert, r, 'a read outside every root');
  });

  test('a write outside the roots, and into a read-only root, creates nothing', async () => {
    const targets = [path.join(dir, 'outside/forged'), path.join(dir, 'ro/forged')];
    for (const t of targets) {
      const r = await exec('/usr/bin/touch', [t]);
      assert.equal(r.executed, true);
      assert.ok(!fs.existsSync(t), `${t} must not exist`);
      assertOsRefused(assert, r, `a write to ${path.basename(path.dirname(t))}`);
    }
  });

  test('a symbolic link cannot carry a read or a write across the boundary', async () => {
    for (const p of [path.join(dir, 'ro/link'), path.join(dir, 'ro/dirlink/secret.txt')]) {
      const r = await exec('/bin/cat', [p]);
      assert.ok(!JSON.stringify(r).includes(canary), `reading through ${path.basename(p)} must not leak`);
      assertOsRefused(assert, r, `reading through ${path.basename(p)}`);
    }
    const w = await exec('/usr/bin/touch', [path.join(dir, 'work/outdir/pwned')]);
    assert.ok(!fs.existsSync(path.join(dir, 'outside/pwned')), 'a write through a link inside a write root must not land outside it');
    assertOsRefused(assert, w, 'a write through a link');
    // The policy layer agrees that the path is not inside the roots, and says why.
    assert.equal(decide(bound, { kind: 'filesystem-read', path: path.join(dir, 'ro/link') }, ctxFor(bound)).code, 'symlink-escape');
    assert.equal(decide(bound, { kind: 'filesystem-write', path: path.join(dir, 'work/outdir/pwned') }, ctxFor(bound)).code, 'symlink-escape');
  });

  test('a parent-directory traversal cannot leave the roots', async () => {
    const sneaky = `${path.join(dir, 'ro')}/../outside/secret.txt`;
    const r = await exec('/bin/cat', [sneaky]);
    assert.ok(!JSON.stringify(r).includes(canary));
    assertOsRefused(assert, r, 'a parent-directory traversal');
    assert.equal(decide(bound, { kind: 'filesystem-read', path: sneaky }, ctxFor(bound)).code, 'path-traversal');
    const inside = `${path.join(dir, 'ro')}/sub/../a.txt`;
    assert.equal(decide(bound, { kind: 'filesystem-read', path: inside }, ctxFor(bound)).code, 'path-traversal', 'even a harmless .. is refused: the kernel and the lexical form can disagree');
  });

  test('paths outside the roots cannot even be listed, so their contents cannot be probed', async () => {
    const r = await exec('/bin/ls', [path.join(dir, 'outside')]);
    assert.ok(!r.output.stdout.includes('secret.txt'));
    assertOsRefused(assert, r, 'listing an undeclared directory');
  });

  test('the run is honest about what it is: host-proved on macOS, enforced on Linux only because every control was proved', async () => {
    const r = await exec('/bin/cat', [path.join(dir, 'ro/a.txt')]);
    assertLevelHonest(assert, r);
    const fsRead = r.report.capabilities.find((c) => c.kind === 'filesystem-read');
    assert.equal(fsRead.checked['fs-read-confinement'], 'proved');
    assert.ok(r.capabilityDecisions.length > 0 && r.capabilityDecisions.every((d) => d.enforced === (BACKEND === 'namespace')));
  });
});

describe('[X-502.AC02] verifier labels, receipts, credentials and signing material are unreachable by a worker, interpreter or child', { skip: SKIP }, () => {
  let dir; let home; let labels; let evidence; let xdg; let canaries; let savedXdg;
  before(() => {
    dir = tmp('x502b-');
    home = path.join(dir, 'home'); labels = path.join(dir, 'labels'); evidence = path.join(dir, 'evidence'); xdg = path.join(dir, 'xdg');
    const ro = path.join(dir, 'ro');
    for (const d of [path.join(home, '.ssh'), labels, evidence, path.join(xdg, 'agentic-security'), ro, path.join(dir, 'work')]) fs.mkdirSync(d, { recursive: true });
    canaries = {
      ssh: `CANARY-SSH-${process.pid}`, labels: `CANARY-LABELS-${process.pid}`, evidence: `CANARY-RECEIPT-${process.pid}`, key: `CANARY-SIGNING-KEY-${process.pid}`,
    };
    fs.writeFileSync(path.join(home, '.ssh/id_ed25519'), canaries.ssh);
    fs.writeFileSync(path.join(labels, 'labels.json'), canaries.labels);
    fs.writeFileSync(path.join(evidence, 'receipt.json'), canaries.evidence);
    fs.writeFileSync(path.join(xdg, 'agentic-security/scan-key'), canaries.key);
    fs.writeFileSync(path.join(ro, 'ok.txt'), 'still-readable');
    savedXdg = process.env.XDG_CONFIG_HOME;
    process.env.XDG_CONFIG_HOME = xdg;
  });
  after(() => { if (savedXdg === undefined) delete process.env.XDG_CONFIG_HOME; else process.env.XDG_CONFIG_HOME = savedXdg; });

  const targets = () => [path.join(home, '.ssh/id_ed25519'), path.join(labels, 'labels.json'), path.join(evidence, 'receipt.json'), path.join(xdg, 'agentic-security/scan-key')];

  test('a scoped node interpreter, and a child it spawns, cannot read any protected path, and can still read its own root', async () => {
    const script = `
const fs=require('fs'),cp=require('child_process');
const out={};
for (const p of ${JSON.stringify(targets())}) {
  try { out[p]='READ:'+fs.readFileSync(p,'utf8'); } catch(e) { out[p]=e.code; }
  try { out[p+'#child']='READ:'+cp.execFileSync('/bin/cat',[p],{encoding:'utf8',stdio:['ignore','pipe','pipe']}); } catch(e) { out[p+'#child']='DENIED'; }
}
try { fs.writeFileSync(${JSON.stringify(path.join(evidence, 'forged.json'))},'x'); out.forge='WROTE'; } catch(e) { out.forge=e.code; }
try { out.own=fs.readFileSync(${JSON.stringify(path.join(dir, 'ro/ok.txt'))},'utf8'); } catch(e) { out.own=e.code; }
console.log(JSON.stringify(out));`;
    const bound = bind({
      filesystem: { read: [path.join(dir, 'ro')], write: [path.join(dir, 'work')] },
      commands: [{ executable: process.execPath, interpreter: 'scoped', args: { mode: 'exact', values: ['-e', script] } }],
    });
    const r = await run(bound, { executable: process.execPath, args: ['-e', script] }, { home, labelDirs: [labels], evidenceDirs: [evidence] });
    assert.equal(r.executed, true, JSON.stringify({ s: r.status, c: r.code, m: r.reason }));
    for (const c of Object.values(canaries)) assert.ok(!JSON.stringify(r).includes(c), 'no canary anywhere in the result');
    const seen = JSON.parse(r.output.stdout.trim());
    for (const p of targets()) {
      assert.ok(!String(seen[p]).startsWith('READ:'), `${p} must not be readable`);
      assert.equal(seen[`${p}#child`], 'DENIED', 'the child process is confined too');
    }
    assert.notEqual(seen.forge, 'WROTE');
    assert.ok(!fs.existsSync(path.join(evidence, 'forged.json')), 'the worker cannot write authoritative evidence');
    assert.equal(seen.own, 'still-readable', 'the declared root stays readable');
  });

  test('a scoped shell and its nested shell cannot read them either', async () => {
    const script = `${targets().map((p) => `cat '${p}'`).join('; ')}; sh -c "cat '${targets()[1]}'"; (cat '${targets()[3]}') 2>&1; true`;
    const bound = bind({
      filesystem: { read: [path.join(dir, 'ro')] },
      commands: [{ executable: '/bin/sh', interpreter: 'scoped', args: { mode: 'exact', values: ['-c', script] } }],
    });
    const r = await run(bound, { executable: '/bin/sh', args: ['-c', script] }, { home, labelDirs: [labels], evidenceDirs: [evidence] });
    assert.equal(r.executed, true, JSON.stringify({ s: r.status, c: r.code, m: r.reason }));
    for (const c of Object.values(canaries)) assert.ok(!JSON.stringify(r).includes(c));
    // `cat` of a protected file fails (the script ends with `true`, so the exit code is 0): the refusal shows in stderr.
    if (BACKEND === 'namespace') assert.match(String(r.output.stderr), /No such file or directory|Permission denied/, 'the protected paths have no name inside the namespace');
    else assert.equal(r.denied, true);
  });

  test('a manifest root that contains protected material is blocked before anything runs', async () => {
    for (const root of [dir, home, path.join(dir)]) {
      const bound = bind({ filesystem: { read: [root] }, commands: [CAT] });
      const r = await run(bound, { executable: '/bin/cat', args: [path.join(labels, 'labels.json')] }, { home, labelDirs: [labels], evidenceDirs: [evidence] });
      assert.equal(r.status, 'blocked');
      assert.equal(r.policyCode, 'protected-path');
      assert.equal(r.executed, false);
      assert.ok(!JSON.stringify(r).includes(canaries.labels));
    }
  });

  test('the policy layer also refuses a protected path that sits inside a granted root', () => {
    const bound = bind({ filesystem: { read: [home] } });
    const ctx = ctxFor(bound, { protectedPaths: [path.join(home, '.ssh')] });
    assert.equal(decide(bound, { kind: 'filesystem-read', path: path.join(home, '.ssh/id_ed25519') }, ctx).code, 'protected-path');
    assert.equal(decide(bound, { kind: 'filesystem-read', path: path.join(home, 'notes.txt') }, ctx).decision, 'allow', 'the rest of the root is unaffected');
  });
});

describe('[X-502.AC03] a platform without equivalent enforcement is explicitly unsupported; hooks and allowlists never establish enforcement', () => {
  const REQ = { executable: '/usr/bin/touch' };
  const mkBound = (dir) => bind({ filesystem: { write: [dir] }, commands: [TOUCH] });

  test('an isolation-required task on a non-advertised backend is unsupported, and the target never runs', async () => {
    const dir = tmp('x502c-');
    const marker = path.join(dir, 'ran');
    const bound = mkBound(dir);
    const r = await runCapabilityTask(bound, { ...REQ, args: [marker] }, { binding: bound.binding, config: CONFIG_ON });
    if (BACKEND === 'namespace') {
      // The Linux namespace backend IS the advertised one. Where the active probes prove every control the task
      // depends on (the sandbox-linux job shows they do) it runs, labelled enforced; where any is not proved it is
      // blocked and the target never runs. Both outcomes are asserted, neither is assumed.
      if (r.executed) {
        assert.equal(r.enforced, true); assert.equal(r.level, 'enforced'); assert.ok(fs.existsSync(marker));
      } else {
        assert.equal(r.status, 'blocked'); assert.ok(!fs.existsSync(marker));
      }
      return;
    }
    assert.equal(r.executed, false);
    assert.ok(!fs.existsSync(marker), 'the command did not run');
    if (process.platform === 'darwin') {
      assert.equal(r.status, 'unsupported');
      assert.equal(r.code, 'platform-unsupported');
    } else {
      assert.ok(['unsupported', 'blocked'].includes(r.status), `status ${r.status}`);
    }
  });

  test('the backend gate holds on its own, even when the feature table is satisfied', async () => {
    // A config that claims the platform is supported must not be enough: the runner
    // checks the backend it actually detected against the advertised set.
    const cfg = resolveAssuranceConfig({ env: { AGENTIC_SECURITY_ASSURANCE_CAPABILITY_ENFORCEMENT: '1' }, platform: 'linux' });
    const dir = tmp('x502h-');
    const marker = path.join(dir, 'ran');
    const bound = mkBound(dir);
    const r = await runCapabilityTask(bound, { ...REQ, args: [marker] }, { binding: bound.binding, config: cfg });
    if (BACKEND === 'namespace') {
      // Advertised backend: the gate lets it through, and it is only `enforced` if every probe proved.
      assert.equal(r.executed ? r.enforced : r.status === 'blocked', true, JSON.stringify({ s: r.status, e: r.executed }));
      return;
    }
    assert.equal(r.executed, false);
    assert.ok(!fs.existsSync(marker));
    if (BACKEND === 'userspace') {
      assert.equal(r.status, 'unsupported');
      assert.equal(r.code, 'platform-unsupported');
    }
  });

  test('the platform table says what is advertised and what is unverified', () => {
    assert.equal(isAdvertisedBackend('namespace', 'linux'), true);
    assert.equal(isAdvertisedBackend('userspace', 'darwin'), false, 'macOS can supervise but is not an advertised enforced backend');
    assert.equal(isAdvertisedBackend('namespace', 'darwin'), false);
    assert.equal(isAdvertisedBackend('userspace', 'win32'), false);
    const p = platformStatements();
    assert.equal(p.linux.status, 'partially-verified', 'Linux is advertised and verified only for the controls the sandbox-linux job proved');
    assert.ok(p.linux.verifiedControls.includes('fs-read-confinement'));
    assert.ok(!p.linux.verifiedControls.includes('network-mediation') && !p.linux.verifiedControls.includes('process-cap'), 'unsupported and unasserted controls are never listed as verified');
    assert.equal(p.darwin.status, 'host-proved-not-advertised');
    assert.equal(p.win32.status, 'unsupported');
    assert.match(p.linux.note, /never claimed|not claimed|Process-count caps are never claimed/);
  });

  test('a backend with incomplete controls blocks: it is never a warning or a quiet fallback', async () => {
    const dir = tmp('x502d-');
    const marker = path.join(dir, 'ran');
    const bound = mkBound(dir);
    const notImplemented = (c) => ({ [c]: async () => ({ state: 'unsupported', reason: `${c} is not implemented on this backend` }) });
    for (const control of ['fs-read-confinement', 'read-denial', 'tree-termination', 'write-confinement']) {
      const r = await runCapabilityTask(bound, { ...REQ, args: [marker] }, {
        binding: bound.binding, config: CONFIG_ON, allowUnadvertisedBackend: true, controlProbes: notImplemented(control),
      });
      if (BACKEND === 'disabled') { assert.equal(r.status, 'blocked'); continue; }
      assert.equal(r.status, 'blocked', `${control}: ${r.status}`);
      assert.equal(r.code, 'missing-execution-backend');
      assert.equal(r.executed, false);
      assert.ok(r.unmet.some((u) => u.control === control), `${control} is named`);
      assert.ok(!fs.existsSync(marker));
    }
  });

  test('a simulated Linux report with the controls the namespace backend lacks would block', () => {
    const bound = mkBound('/work/x');
    const report = {
      controls: {
        'write-confinement': { state: 'proved' }, 'env-scrub': { state: 'proved' }, network: { state: 'proved' }, 'file-size-limit': { state: 'proved' },
        'read-denial': { state: 'unsupported', reason: 'not implemented on the namespace backend' },
        'tree-termination': { state: 'unsupported', reason: 'not implemented on the namespace backend' },
        'fs-read-confinement': { state: 'unsupported', reason: 'not implemented on the namespace backend' },
        'fs-multi-root-write': { state: 'unsupported', reason: 'not implemented on the namespace backend' },
      },
    };
    const unmet = unmetControls(report, requiredControlsFor(bound.manifest)).map((u) => u.control).sort();
    assert.deepEqual(unmet, ['fs-multi-root-write', 'fs-read-confinement', 'read-denial', 'tree-termination']);
  });

  test('without a disabled-by-default feature, an operator switch and no project-file override, nothing runs', async () => {
    const dir = tmp('x502e-');
    const marker = path.join(dir, 'ran');
    const bound = mkBound(dir);
    const base = { binding: bound.binding, allowUnadvertisedBackend: true };
    const off = await runCapabilityTask(bound, { ...REQ, args: [marker] }, { ...base, config: resolveAssuranceConfig({ env: {} }) });
    assert.equal(off.status, 'disabled');
    const killed = await runCapabilityTask(bound, { ...REQ, args: [marker] }, {
      ...base, config: resolveAssuranceConfig({ env: { AGENTIC_SECURITY_ASSURANCE_CAPABILITY_ENFORCEMENT: '1', AGENTIC_SECURITY_NO_CAPABILITY_ENFORCEMENT: '1' } }),
    });
    assert.equal(killed.status, 'blocked');
    assert.equal(killed.code, 'kill-switch');
    // A project file lives in the scanned repository, which is hostile input: it cannot switch this on.
    const scanRoot = tmp('x502f-');
    fs.mkdirSync(path.join(scanRoot, '.agentic-security'), { recursive: true });
    fs.writeFileSync(path.join(scanRoot, '.agentic-security/assurance.yml'), 'features:\n  capability-enforcement:\n    enabled: true\n');
    const cfg = resolveAssuranceConfig({ scanRoot, env: {} });
    const fromFile = await runCapabilityTask(bound, { ...REQ, args: [marker] }, { ...base, config: cfg });
    assert.equal(fromFile.status, 'disabled');
    assert.ok(!fs.existsSync(marker));
  });

  test('a hook response is advice: it never carries an enforced record', () => {
    const bound = bind({ filesystem: { read: ['/work/x'] }, commands: [CAT] });
    const ctx = ctxFor(bound);
    const adv = advise(bound, { kind: 'filesystem-read', path: '/work/x/a' }, ctx);
    assert.equal(adv.advisory, true);
    assert.equal(adv.enforced, false);
    assert.equal(adv.decision, 'allow');
    assert.equal(adv.record.mediation, 'hook-advisory');
    assert.equal(adv.record.enforced, false);
    const shell = advise(bound, { kind: 'command', command: 'cat /work/x/a | sh' }, ctx);
    assert.equal(shell.decision, 'unsupported', 'a shell string is not an action the policy can parse');
    assert.equal(shell.enforced, false);
    // The record schema itself refuses a hook that claims enforcement.
    const d = decide(bound, { kind: 'filesystem-read', path: '/work/x/a' }, ctx);
    const probeDigest = digestOf({ probe: 1 });
    assert.equal(toCapabilityDecisionRecord(d, { mediation: 'hook-advisory', enforced: true, backend: 'userspace', probeDigest }).ok, false);
    assert.equal(toCapabilityDecisionRecord(d, { mediation: 'in-process-policy', enforced: true, backend: 'userspace', probeDigest }).ok, false);
    assert.equal(toCapabilityDecisionRecord(d, { mediation: 'runner', enforced: true, backend: 'namespace', probeDigest: null }).ok, false, 'enforcement needs a probe digest');
    assert.equal(toCapabilityDecisionRecord(d, { mediation: 'runner', enforced: true, backend: null, probeDigest }).ok, false, 'enforcement needs a named backend');
    assert.equal(toCapabilityDecisionRecord(d, { mediation: 'runner', enforced: true, backend: 'namespace', probeDigest }).ok, true, 'runner mediation with a backend and a probe digest may claim it');
  });

  test('a command allowlist alone does not make a run enforced', { skip: SKIP }, async () => {
    const dir = tmp('x502g-');
    const bound = mkBound(dir);
    assert.equal(decide(bound, { kind: 'command', executable: '/usr/bin/touch', args: [path.join(dir, 'x')] }, ctxFor(bound)).decision, 'allow');
    const r = await run(bound, { ...REQ, args: [path.join(dir, 'x')] });
    assert.equal(r.executed, true);
    // The allowlist said "allow" in both cases. What differs is whether the BACKEND is an advertised one.
    assertLevelHonest(assert, r);
    // The other direction: take one proved control away and the same allowlisted command is refused outright.
    const weakened = await runCapabilityTask(bound, { ...REQ, args: [path.join(dir, 'y')] }, {
      binding: bound.binding, config: CONFIG_ON, allowUnadvertisedBackend: true,
      controlProbes: { 'write-confinement': async () => ({ state: 'not-proved', reason: 'fault injection' }) },
    });
    assert.equal(weakened.executed, false, 'an allowlisted command does not run on a backend whose control is not proved');
    assert.ok(!fs.existsSync(path.join(dir, 'y')));
  });
});

void manifest;
