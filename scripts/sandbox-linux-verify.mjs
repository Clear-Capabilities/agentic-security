#!/usr/bin/env node
// Linux sandbox verification runner.
//
// WHY THIS EXISTS. The kernel-namespace backend's escape tests SKIP whenever
// the host cannot create the namespaces, and a skipped suite scrolling past in
// a green job is indistinguishable from a suite that passed. That is exactly
// the misread this repository has paid for before, so the verdict is made
// explicit here: this runner prints which backend was selected, prints RAN or
// SKIPPED for every test individually, and EXITS NON-ZERO unless the
// kernel-namespace suites actually ran. A job that cannot exercise the backend
// fails loudly rather than reporting success it did not earn.
//
// It weakens nothing: it does not pass flags to the tests, does not relax any
// assertion, and does not select a backend. It runs the existing suites, runs
// the capability-mode execution suite (which contains the fault-injection
// tests: probes that must FAIL against a runner that is deliberately wrong),
// then runs the active probes once more as a table, writes that table to
// `$RUNNER_TEMP/sandbox-linux-evidence.json`, and refuses to call anything verified that a
// probe did not prove.
//
// The process-count cap is a REQUIRED proved control here. It is applied by
// `prlimit` to the payload alone (the shell used for the resource prelude is dash on
// the hosted image, whose `ulimit` has no `-u`), and the probe attacks it and pairs
// it with a positive control. A diagnostic at the end prints what the kernel did
// with an unprivileged `ulimit -u` and with the namespace cap, as context only.
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SCANNER = path.join(ROOT, 'scanner');

// Suites whose skip is not allowed to be mistaken for a pass. Matched against
// the TAP test name.
const REQUIRED_SUITE = 'kernel-namespace confinement — escape attempts';
const REQUIRED_CAPABILITY_SUITES = [
  '[CORE-003.AC02] the base controls are proved on the Linux namespace backend',
  '[X-503.AC03] the process-count cap binds inside the user namespace, in both directions',
  '[X-502.AC01] reads and writes outside the allowed roots are blocked on the Linux namespace backend',
  '[X-503.AC02] descendants are terminated by the kernel, including ones no sweep can find',
  '[CORE-003.AC01] protected paths are unreadable on the Linux namespace backend',
  '[X-504.AC03] a direct socket cannot bypass the policy on the Linux namespace backend',
];
// Controls that must be `proved` for the Linux backend to be called verified.
const REQUIRED_PROVED = [
  'write-confinement', 'read-denial', 'env-scrub', 'network', 'tree-termination', 'file-size-limit',
  'fs-read-confinement', 'fs-multi-root-write', 'process-cap',
];
// Controls that must stay NOT proved on this backend (honesty checks).
const MUST_NOT_BE_PROVED = ['network-mediation'];

function line(s = '') { process.stdout.write(`${s}\n`); }

function parseTap(tap) {
  const results = [];
  for (const l of tap.split('\n')) {
    const m = /^\s*(not ok|ok)\s+\d+\s+-\s+(.*)$/.exec(l);
    if (!m) continue;
    const skipped = /#\s*SKIP/i.test(m[2]);
    const name = m[2].replace(/\s*#\s*(SKIP|TODO).*$/i, '').trim();
    results.push({ name, ok: m[1] === 'ok', skipped });
  }
  return results;
}

function runTests(files) {
  line(`=== running ${files.join(' ')} ===`);
  const run = spawnSync(process.execPath, ['--test', '--test-reporter=tap', ...files],
    { cwd: SCANNER, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  const tap = `${run.stdout || ''}\n${run.stderr || ''}`;
  process.stdout.write(tap);
  return { run, results: parseTap(tap) };
}

// ---------------------------------------------------------------- backend
const { detectBackend } = await import(path.join(SCANNER, 'src', 'sandbox', 'capabilities.js'));
const backend = detectBackend();

line('=== sandbox backend selection ===');
line(`platform: ${process.platform}`);
line(`SELECTED BACKEND: ${backend}`);
line('');
line('Selection is functional: a backend is reported only if a trivial command');
line('just ran through its real code path under real confinement. "disabled"');
line('means confinement does not work here, not that a check was lenient.');
line('');

const problems = [];
if (backend !== 'namespace') {
  problems.push(`the kernel-namespace backend was not selected (got '${backend}'), so its confinement was never exercised`);
}

// ---------------------------------------------------------------- host facts
line('=== host facts (context, not proof) ===');
for (const [label, cmd] of [
  ['kernel', ['uname', ['-a']]],
  ['uid', ['id', []]],
  ['unshare', ['unshare', ['--version']]],
  ['pivot_root', ['sh', ['-c', 'command -v pivot_root setpriv umount mount setsid']]],
]) {
  const r = spawnSync(cmd[0], cmd[1], { encoding: 'utf8' });
  line(`${label}: ${String(r.stdout || r.stderr || '').trim().replace(/\n/g, ' | ')}`);
}
{
  const r = spawnSync('unshare', ['--help'], { encoding: 'utf8' });
  line(`unshare advertises --kill-child: ${/--kill-child/.test(`${r.stdout}${r.stderr}`)}`);
}
line('');

// ---------------------------------------------------------------- smoke
// Before any assertion: run one trivial command through each mode and print
// EVERYTHING, so that when a probe below reports "positive control failed" the
// reason (a setup step that the kernel refused, with its marker) is already in
// the log rather than needing another run to find out.
line('=== smoke: one command per mode, full result (context, not proof) ===');
if (backend === 'namespace') {
  const { runNamespace } = await import(path.join(SCANNER, 'src', 'sandbox', 'backend-namespace.js'));
  const { runConfinedSupervised } = await import(path.join(SCANNER, 'src', 'sandbox', 'supervise.js'));
  const mk = () => fs.mkdtempSync(path.join(process.env.RUNNER_TEMP || os.tmpdir(), 'agsec-smoke-'));
  const show = (label, r) => line(`${label}: ${JSON.stringify({ status: r.status, exitCode: r.exitCode, denied: r.denied, supervised: r.supervised, stdout: String(r.stdout).slice(0, 1500), stderr: String(r.stderr).slice(0, 1500) })}`);
  const d1 = mk();
  show('default mode', runNamespace(['/bin/sh', '-c', 'id; echo hi'], { root: d1, timeoutMs: 10000 }));
  const d2 = mk();
  show('capability mode (no read roots)', await runConfinedSupervised(['/bin/sh', '-c', 'id; echo "pid=$$"; ls -la /; echo ---; ls /proc | head -5; echo ---; head -40 /proc/self/mountinfo; echo hi'], { root: d2, readRoots: [], timeoutMs: 10000 }));
  for (const d of [d1, d2]) fs.rmSync(d, { recursive: true, force: true });
} else {
  line('not run: no namespace backend');
}
line('');

// ---------------------------------------------------------------- suites
const base =runTests(['test/sandbox-escape.test.js', 'test/sandbox.test.js']);
const cap = runTests(['test/capabilities/linux-enforcement.test.js']);

line('');
line('=== RAN / SKIPPED, per test ===');
for (const r of [...base.results, ...cap.results]) {
  line(`${r.skipped ? 'SKIPPED' : r.ok ? 'RAN+PASS' : 'RAN+FAIL '} :: ${r.name}`);
}

const required = base.results.find((r) => r.name === REQUIRED_SUITE);
if (!required) problems.push(`the required suite "${REQUIRED_SUITE}" did not appear in the test output at all`);
else if (required.skipped) problems.push(`the required suite "${REQUIRED_SUITE}" SKIPPED: a skip is a declared gap in verification, never a pass`);
else if (!required.ok) problems.push(`the required suite "${REQUIRED_SUITE}" FAILED`);
if (base.run.status !== 0) problems.push(`the sandbox test process exited ${base.run.status}`);

for (const name of REQUIRED_CAPABILITY_SUITES) {
  const r = cap.results.find((x) => x.name === name);
  if (!r) problems.push(`the capability suite "${name}" did not appear in the test output`);
  else if (r.skipped) problems.push(`the capability suite "${name}" SKIPPED: a skip is never a pass`);
  else if (!r.ok) problems.push(`the capability suite "${name}" FAILED`);
}
const capSkipped = cap.results.filter((r) => r.skipped);
if (capSkipped.length) problems.push(`${capSkipped.length} test(s) in linux-enforcement.test.js SKIPPED`);
if (cap.results.filter((r) => r.ok && !r.skipped).length < 50) problems.push('fewer tests ran in linux-enforcement.test.js than expected');
if (cap.run.status !== 0) problems.push(`the linux-enforcement test process exited ${cap.run.status}`);

// ---------------------------------------------------------------- execution suites
// The suites that execute targets through the trust boundary must RUN on this host, not skip. Their file lists are read from the scoped
// scripts in package.json so this cannot drift from what those scripts run. linux-enforcement.test.js is already covered above.
const pkg = JSON.parse(fs.readFileSync(path.join(SCANNER, 'package.json'), 'utf8'));
const EXEC_SCOPES = ['test:capabilities', 'test:verification', 'test:invariants', 'test:documentation'];
const execFiles = [...new Set(EXEC_SCOPES.flatMap((s) => String(pkg.scripts[s] || '').match(/test\/[\w./-]+\.test\.js/g) || []))]
  .filter((f) => f !== 'test/capabilities/linux-enforcement.test.js');
execFiles.push('test/trust-boundary.test.js', 'test/evidence-issuer.test.js');
if (execFiles.length < 30) problems.push(`only ${execFiles.length} execution-suite files were found in package.json; the scope lists were not read`);
line('');
const exe = runTests(execFiles);
line('');
line('=== execution suites: RAN / SKIPPED summary ===');
const exeSkipped = exe.results.filter((r) => r.skipped);
const exeRan = exe.results.filter((r) => r.ok && !r.skipped);
line(`ran and passed: ${exeRan.length}; skipped: ${exeSkipped.length}; failed: ${exe.results.filter((r) => !r.ok).length}`);
for (const r of exeSkipped) line(`SKIPPED :: ${r.name}`);
if (exe.run.status !== 0) problems.push(`the execution-suite test process exited ${exe.run.status}`);
if (exeSkipped.length) problems.push(`${exeSkipped.length} test(s) in the execution suites SKIPPED on a host that has the backend: ${exeSkipped.map((r) => r.name).slice(0, 5).join(' | ')}`);
if (exeRan.length < 300) problems.push(`only ${exeRan.length} execution-suite tests ran; far fewer than expected`);

// ---------------------------------------------------------------- probe table
line('');
line('=== active probes, one more time, as an evidence table ===');
const evidence = { backend, platform: process.platform, generatedAt: new Date().toISOString(), controls: {}, linux: {} };
if (backend === 'namespace') {
  const { probeControls } = await import(path.join(SCANNER, 'src', 'sandbox', 'control-probes.js'));
  const { probeCapabilityControls } = await import(path.join(SCANNER, 'src', 'capabilities', 'probes.js'));
  const { runLinuxProbes } = await import(path.join(SCANNER, 'src', 'sandbox', 'linux-probes.js'));
  const base0 = await probeControls({});
  const cap0 = await probeCapabilityControls({});
  evidence.controls = Object.fromEntries(Object.entries(cap0.controls).map(([k, v]) => [k, { state: v.state, ...(v.evidence ? { evidence: v.evidence } : {}), ...(v.reason ? { reason: v.reason } : {}) }]));
  evidence.baseControls = Object.keys(base0.controls);
  evidence.linux = await runLinuxProbes();
  for (const [k, v] of Object.entries(evidence.controls)) line(`${v.state.padEnd(12)} :: ${k} :: ${v.evidence || v.reason || ''}`);
  for (const [k, v] of Object.entries(evidence.linux)) line(`${v.state.padEnd(12)} :: linux:${k} :: ${v.evidence || v.reason || ''}`);
  for (const c of REQUIRED_PROVED) {
    if (evidence.controls[c]?.state !== 'proved') problems.push(`control '${c}' is ${evidence.controls[c]?.state ?? 'absent'}, not proved`);
  }
  for (const [k, v] of Object.entries(evidence.linux)) {
    if (v.state !== 'proved') problems.push(`linux probe '${k}' is ${v.state}, not proved: ${v.reason || ''}`);
  }
  for (const c of MUST_NOT_BE_PROVED) {
    if (evidence.controls[c]?.state === 'proved') problems.push(`control '${c}' claims proved but is not implemented/asserted on this backend`);
  }
} else {
  line('not run: no namespace backend');
}
try {
  const out = path.join(process.env.RUNNER_TEMP || os.tmpdir(), 'sandbox-linux-evidence.json');
  fs.writeFileSync(out, `${JSON.stringify(evidence, null, 2)}\n`);
  line(`evidence written to ${out}`);
} catch (e) { line(`could not write the evidence file: ${e.message}`); }

// ---------------------------------------------------------------- diagnostic
line('');
line('=== DIAGNOSTIC (context, not a proof; the gated proof is the process-cap probe above): process-count cap on this runner ===');
{
  const un = spawnSync('sh', ['-c', 'ulimit -u 1 2>&1; echo "ulimit -u now: $(ulimit -u)"; (sleep 0.05 &) ; echo "background fork rc=$?"; sleep 0.2'], { encoding: 'utf8', timeout: 8000 });
  line(`unconfined, cap 1: ${String(un.stdout + un.stderr).trim().replace(/\n/g, ' | ')}`);
  if (backend === 'namespace') {
    const { runNamespace } = await import(path.join(SCANNER, 'src', 'sandbox', 'backend-namespace.js'));
    const tmp = fs.mkdtempSync(path.join(process.env.RUNNER_TEMP || '/tmp', 'agsec-diag-'));
    const r = runNamespace(['/bin/sh', '-c', 'ulimit -u; ( /bin/sleep 0.05 & ) ; echo fork-rc=$?'], { root: tmp, timeoutMs: 8000, limits: { maxProcs: 1 } });
    line(`namespace, cap 1: status=${r.status} exit=${r.exitCode} stdout=${JSON.stringify(r.stdout.trim())} stderr=${JSON.stringify(String(r.stderr).trim().slice(0, 300))}`);
    fs.rmSync(tmp, { recursive: true, force: true });
  }
  line('The gated proof of the namespace process cap is the process-cap probe in the evidence table above, not these lines.');
}

// ---------------------------------------------------------------- verdict
line('');
line('=== verdict ===');
if (problems.length === 0) {
  line('VERIFIED: the kernel-namespace suites RAN on this host, every required control was proved by its active probe,');
  line('and every fault-injection test showed its probe failing against a deliberately wrong runner.');
  process.exit(0);
}
line('NOT VERIFIED:');
for (const p of problems) line(`  - ${p}`);
process.exit(1);
