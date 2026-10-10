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
// What it does NOT do: assert anything about process-count caps. A diagnostic
// prints what the runner's kernel did with a cap of 1, clearly labelled as not
// a proof; the control stays unasserted.
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
  '[X-502.AC01] reads and writes outside the allowed roots are blocked on the Linux namespace backend',
  '[X-503.AC02] descendants are terminated by the kernel, including ones no sweep can find',
  '[CORE-003.AC01] protected paths are unreadable on the Linux namespace backend',
  '[X-504.AC03] a direct socket cannot bypass the policy on the Linux namespace backend',
];
// Controls that must be `proved` for the Linux backend to be called verified.
const REQUIRED_PROVED = [
  'write-confinement', 'read-denial', 'env-scrub', 'network', 'tree-termination', 'file-size-limit',
  'fs-read-confinement', 'fs-multi-root-write',
];
// Controls that must stay NOT proved on this backend (honesty checks).
const MUST_NOT_BE_PROVED = ['process-cap', 'network-mediation'];

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

// ---------------------------------------------------------------- suites
const base = runTests(['test/sandbox-escape.test.js', 'test/sandbox.test.js']);
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
if (cap.results.filter((r) => r.ok && !r.skipped).length < 25) problems.push('fewer tests ran in linux-enforcement.test.js than expected');
if (cap.run.status !== 0) problems.push(`the linux-enforcement test process exited ${cap.run.status}`);

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
line('=== DIAGNOSTIC (not a proof, not gated): process-count cap on this runner ===');
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
  line('The process cap stays UNASSERTED on every backend regardless of the above.');
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
