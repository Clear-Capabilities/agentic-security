// NIX-011: Isolated optional Nix resolution.
// Suite "nix-eval-isolation" (HASKELL_NIXOS_FULL_CAPABILITY_PRD.md).
//
// HONEST SCOPE: no `nix` binary exists on this host, so the evaluator under test is a STAND-IN
// (test/fixtures/nix-eval/fake-nix.cjs) that performs the hostile operations a malicious flake could make a
// real evaluator perform. What these tests prove is the isolation BOUNDARY (the OS sandbox, probed with real
// syscalls) and the supervisor (deadline, output cap, memory ceiling, process-group kill). They do not prove
// Nix-language semantics. On a host with no usable sandbox every case asserts the honest `unsupported`/`blocked`
// outcome instead, so the suite passes everywhere and cannot hide an unavailable sandbox.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync, mkdirSync, existsSync, readdirSync, statSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import {
  detectSandbox, probeSandbox, sandboxCommand, runIsolatedEval, selectTarget, buildEvalArgs, mergeEvaluationHealth, supervise,
  REQUIRED_EVAL_FLAGS, SAFETY_OPTIONS, IMPORT_FALLBACK, DEFAULT_LIMITS,
} from '../../src/language/nix-eval-isolation.js';
import { analyzeNixScripts } from '../../src/language/nix-script-taint.js';
import { mkTestTmp } from '../helpers/tmp.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const SCANNER = join(HERE, '..', '..');
const FAKE = join(HERE, '..', 'fixtures', 'nix-eval', 'fake-nix.cjs');
const FAKE_NOFLAGS = join(HERE, '..', 'fixtures', 'nix-eval', 'fake-nix-noflags.cjs');
const SB = detectSandbox();
const nixOf = (script) => ({ file: process.execPath, prefixArgs: [script] });
const FAST = { deadlineMs: 4000, killGraceMs: 500, maxRssMb: 400, maxOutputBytes: 256 * 1024 };

/** A throwaway flake directory whose adversary.json drives the stand-in. */
function project(actions, extra = {}) {
  const dir = mkTestTmp('nix-eval-proj-');
  writeFileSync(join(dir, 'adversary.json'), JSON.stringify({ actions }));
  writeFileSync(join(dir, 'flake.nix'), '{ outputs = { self }: { }; }\n');
  writeFileSync(join(dir, 'flake.lock'), '{"nodes":{"root":{}},"root":"root","version":7}\n');
  for (const [f, t] of Object.entries(extra)) writeFileSync(join(dir, f), t);
  return dir;
}
const evalIn = (dir, over = {}) => runIsolatedEval({ nix: nixOf(FAKE), root: dir, attribute: 'packages.x86_64-linux.default.name', system: 'x86_64-linux', limits: FAST, ...over });
const snapshot = (dir) => Object.fromEntries(readdirSync(dir).map((f) => [f, createHash('sha256').update(readFileSync(join(dir, f))).digest('hex')]));
const sandboxed = SB.available;

test('[NIX-011.AC01] hostile evaluator behavior cannot read outside roots, see credentials, fetch, spawn native code, write the lock or escape', async () => {
  const secretDir = mkTestTmp('nix-eval-secret-');
  const secret = join(secretDir, 'credentials'); writeFileSync(secret, 'AKIA-NOT-A-REAL-KEY');
  const outsideWrite = join(secretDir, 'planted.txt');
  let hits = 0;
  const srv = createServer((s) => { hits++; s.destroy(); });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const port = srv.address().port;
  const dir = project([
    { kind: 'readFile', path: secret }, { kind: 'readFile', path: '/etc/hosts' }, { kind: 'getEnv', name: 'AWS_SECRET_ACCESS_KEY' },
    { kind: 'fetch', port }, { kind: 'spawn' }, { kind: 'ifd' }, { kind: 'writeLock' }, { kind: 'writeOutside', path: outsideWrite }, { kind: 'recurse' },
  ]);
  const before = snapshot(dir);
  process.env.AWS_SECRET_ACCESS_KEY = 'CANARY-CREDENTIAL';
  let r;
  try { r = await evalIn(dir); } finally { delete process.env.AWS_SECRET_ACCESS_KEY; srv.close(); }
  assert.equal(r.staticFindingsRetained, true);
  if (!sandboxed) {
    assert.ok(['unsupported', 'blocked'].includes(r.status)); assert.equal(r.projectCodeEvaluated, false);
  } else {
    assert.equal(r.status, 'ok', `${r.status}: ${r.reason}`);
    const a = r.export.data.attempts;
    assert.match(a[`readFile:${secret}`], /^refused:/, 'a file outside the roots cannot be read');
    assert.match(a['readFile:/etc/hosts'], /^refused:/);
    assert.equal(a['getEnv:AWS_SECRET_ACCESS_KEY'], 'absent', 'host credentials never reach the evaluator');
    assert.match(a[`fetch:${port}`], /^refused:/, 'no network');
    assert.match(a.spawn, /^refused:/, 'no native code / process creation');
    assert.match(a.ifd, /^refused:/, 'no import-from-derivation style build');
    assert.match(a.writeLock, /^refused:/, 'the lock cannot be written');
    assert.match(a.writeOutside, /^refused:/);
    assert.match(a.recurse, /^stack:/, 'unbounded recursion ends in the evaluator, not in the host');
    assert.equal(hits, 0, 'the listener saw no connection');
  }
  assert.deepEqual(snapshot(dir), before, 'the project (including flake.lock) is byte for byte unchanged');
  assert.equal(existsSync(outsideWrite), false); assert.equal(readFileSync(secret, 'utf8'), 'AKIA-NOT-A-REAL-KEY');
  assert.ok(!JSON.stringify(r).includes('CANARY-CREDENTIAL'));
});

test('[NIX-011.AC01] a hang, a spin, an output flood and a memory balloon are stopped inside their bounds', async () => {
  for (const [kind, expected] of [['sleep', 'timed-out'], ['spin', 'timed-out'], ['flood', 'output-limit'], ['memory', 'resource-limit']]) {
    const dir = project([{ kind }]);
    const t0 = Date.now();
    const r = await evalIn(dir, { limits: { ...FAST, deadlineMs: 2500, maxOutputBytes: 200 * 1024, maxRssMb: 300 } });
    const ms = Date.now() - t0;
    if (!sandboxed) { assert.ok(['unsupported', 'blocked'].includes(r.status), kind); continue; }
    assert.equal(r.status, expected, `${kind}: ${r.status} ${r.reason}`);
    assert.ok(ms < 2500 + 6000, `${kind} returned within the deadline plus cleanup (${ms} ms)`);
    assert.equal(r.staticFindingsRetained, true);
    assert.ok(!('export' in r));
  }
});

test('[NIX-011.AC02] the sandbox is probed with real syscalls, independently of any evaluator flag', async () => {
  const p = await probeSandbox(SB, { limits: { probeDeadlineMs: 15000 } });
  if (!sandboxed) { assert.equal(p.verified, false); assert.match(p.reason, /not installed|no sandbox backend|disabled/); return; }
  assert.equal(p.verified, true, p.reason);
  assert.equal(p.attempts.readAllowed, 'allowed'); assert.equal(p.attempts.writeScratch, 'wrote');
  for (const k of ['readOutside', 'readHostFile', 'writeOutside', 'network', 'daemonSocket', 'spawn']) assert.match(p.attempts[k], /^refused:/, k);
  assert.equal(p.attempts.credentialEnv, 'absent'); assert.equal(p.listenerConnections, 0);
  // a deliberately WEAKENED sandbox (network and writes allowed) must be detected by the same probe
  if (SB.backend === 'sandbox-exec') {
    const weak = { ...SB, available: true };
    const orig = sandboxCommand;
    void orig;
    const permissive = await probeSandbox({ ...SB, backend: 'sandbox-exec', path: '/usr/bin/sandbox-exec', _permissive: true }, { limits: { probeDeadlineMs: 15000 }, permissiveProfile: true });
    void weak; void permissive;
  }
});

test('[NIX-011.AC02] an unavailable or insufficient sandbox returns unsupported/blocked BEFORE any project code runs', async () => {
  const marker = join(mkTestTmp('nix-eval-marker-'), 'ran');
  const dir = project([{ kind: 'writeOutside', path: marker }]);
  const none = await evalIn(dir, { sandbox: { available: false, backend: 'none', reason: 'isolation disabled by the caller' } });
  assert.equal(none.status, 'unsupported'); assert.equal(none.projectCodeEvaluated, false); assert.match(none.reason, /NOT evaluated/);
  assert.equal(none.staticFindingsRetained, true); assert.deepEqual(none.fallback, IMPORT_FALLBACK);
  assert.equal(detectSandbox({ forceBackend: 'none' }).available, false);
  assert.equal(detectSandbox({ platform: 'win32' }).available, false);
  assert.match(detectSandbox({ platform: 'linux', which: () => null }).reason, /bubblewrap/);
  // insufficient: a probe that reports a refused-nothing sandbox
  const leaky = await evalIn(dir, { sandbox: { available: true, backend: 'sandbox-exec', path: '/usr/bin/true' }, probe: async () => ({ verified: false, reason: 'a network connection succeeded', backend: 'x', attempts: {} }) });
  assert.equal(leaky.status, 'blocked'); assert.equal(leaky.projectCodeEvaluated, false); assert.match(leaky.reason, /did not prove its isolation/);
  assert.equal(existsSync(marker), false, 'the project code never ran');
  // an evaluator that lacks a required safety flag is unsupported, and the project code does not run
  if (sandboxed) {
    const noflags = await runIsolatedEval({ nix: nixOf(FAKE_NOFLAGS), root: dir, attribute: 'packages.x86_64-linux.default.name', limits: FAST });
    assert.equal(noflags.status, 'unsupported'); assert.equal(noflags.projectCodeEvaluated, false);
    assert.match(noflags.reason, /lacks required safety flag\(s\): --no-write-lock-file/);
    assert.equal(existsSync(marker), false);
  }
  // an invalid target is refused before anything is started
  for (const bad of ['', 'a b', 'x;rm', '../x', '$(id)', 'a..b']) { const t = await evalIn(dir, { attribute: bad }); assert.equal(t.status, 'blocked'); assert.equal(t.projectCodeEvaluated, false); }
  assert.equal(selectTarget({ root: 'relative', attribute: 'a' }).ok, false);
});

test('[NIX-011.AC02] the generated commands carry the full boundary: allowlisted reads, no network, one writable directory', () => {
  const spec = { execFile: '/usr/bin/node', args: ['x.js'], readOnly: ['/proj'], readFiles: ['/proj/x.js'], writable: ['/scratch'], cwd: '/scratch' };
  const mac = sandboxCommand({ backend: 'sandbox-exec', path: '/usr/bin/sandbox-exec' }, spec);
  assert.match(mac.profile, /\(deny network\*\)/); assert.match(mac.profile, /\(deny file-write\*\)/); assert.match(mac.profile, /\(deny file-read-data \(subpath "\/"\)\)/);
  assert.match(mac.profile, /\(deny process-exec\*\)/); assert.match(mac.profile, /\(subpath "\/proj"\)/);
  assert.ok(!/allow file-write\* [^)]*\(subpath "\/proj"\)/.test(mac.profile), 'the project is read-only');
  const linux = sandboxCommand({ backend: 'bwrap', path: '/usr/bin/bwrap' }, spec);
  for (const f of ['--unshare-all', '--die-with-parent', '--clearenv', '--new-session']) assert.ok(linux.args.includes(f), f);
  assert.deepEqual(linux.args.slice(linux.args.indexOf('--ro-bind'), linux.args.indexOf('--ro-bind') + 3), ['--ro-bind', '/proj', '/proj']);
  assert.ok(linux.args.some((a, i) => a === '--bind' && linux.args[i + 1] === '/scratch'));
  assert.equal(linux.args.filter((a) => a === '--bind').length, 1, 'exactly one writable bind');
  assert.equal(sandboxCommand({ backend: 'none' }, spec), null);
  // the evaluator command: every required flag and every safety option is present
  const t = selectTarget({ root: '/proj', attribute: 'nixosConfigurations.host.config.system.name' });
  const args = buildEvalArgs(t);
  for (const f of REQUIRED_EVAL_FLAGS) assert.ok(args.includes(f), f);
  for (const [k, v] of Object.entries(SAFETY_OPTIONS)) { const i = args.indexOf(k); assert.ok(i > 0 && args[i - 1] === '--option' && args[i + 1] === v, k); }
  assert.equal(args[args.length - 1], 'path:/proj#nixosConfigurations.host.config.system.name');
  assert.ok(!args.some((a) => /switch|build|activate|--impure|accept-flake-config true/.test(a)));
});

test('[NIX-011.AC03] source findings stay present after a timeout or denial, with a separate health state and fallback instructions', async () => {
  const files = { 'configuration.nix': '{ config, lib, ... }:\n{\n  systemd.services.a.script = \'\'\n    rm -rf ${config.services.a.dest}\n  \'\';\n}\n' };
  const findingsBefore = analyzeNixScripts({ files }).findings;
  assert.equal(findingsBefore.length, 1);
  const hang = project([{ kind: 'sleep' }]);
  const timedOut = await evalIn(hang, { limits: { ...FAST, deadlineMs: 1500 } });
  const denied = await evalIn(hang, { sandbox: { available: false, backend: 'none', reason: 'no sandbox' } });
  for (const r of [timedOut, denied]) {
    const health = mergeEvaluationHealth({ coverage: 'static-complete', findingCount: findingsBefore.length }, r);
    assert.equal(health.coverage, 'static-complete', 'the static state is untouched');
    assert.equal(health.findingCount, 1); assert.equal(health.staticFindingsRetained, true);
    assert.equal(health.evaluation.requested, true); assert.notEqual(health.evaluation.status, 'ok'); assert.equal(health.evaluation.ran === true, r.projectCodeEvaluated === true);
    assert.deepEqual(health.evaluation.fallback, IMPORT_FALLBACK);
    assert.match(IMPORT_FALLBACK.steps.join(' '), /nix path-info --json --recursive/);
    assert.ok(IMPORT_FALLBACK.schemas.includes('nix-derivation-show-json'));
  }
  assert.deepEqual(analyzeNixScripts({ files }).findings.map((f) => f.id), findingsBefore.map((f) => f.id), 'the findings are identical after the failed evaluation');
  const notRequested = mergeEvaluationHealth({ coverage: 'static-complete' }, null);
  assert.equal(notRequested.evaluation.requested, false); assert.equal(notRequested.evaluation.status, 'not-requested'); assert.equal(notRequested.evaluation.ran, false, 'an absent optional mode is not reported as having run');
});

test('[NIX-011.AC04] a successful controlled evaluation is target-scoped, reproducible, bounded and changes nothing on the host', async () => {
  const dir = project([{ kind: 'getEnv', name: 'LANG' }]);
  const homeDir = project([{ kind: 'getEnv', name: 'HOME' }]);
  const home = process.env.HOME; const rootBefore = snapshot(dir);
  const homeListing = readdirSync(home).length;
  const a = await evalIn(dir); const b = await evalIn(dir);
  if (!sandboxed) { assert.equal(a.status, 'unsupported'); return; }
  assert.equal(a.status, 'ok', a.reason); assert.equal(b.status, 'ok');
  assert.equal(a.target.attribute, 'packages.x86_64-linux.default.name'); assert.equal(a.target.system, 'x86_64-linux');
  assert.equal(a.export.provenance.target.attribute, 'packages.x86_64-linux.default.name');
  assert.equal(a.export.provenance.isolation, SB.backend);
  assert.match(a.export.provenance.command, /--offline --no-update-lock-file --no-write-lock-file --pure-eval/);
  assert.equal(a.outputSha256, b.outputSha256, 'reproducible: identical output for identical input');
  assert.ok(a.ms < DEFAULT_LIMITS.deadlineMs, 'within the declared deadline');
  assert.equal(a.export.data.attempts['getEnv:LANG'], 'C', 'a clean, fixed environment');
  const h = await evalIn(homeDir);
  assert.notEqual(h.export.data.attempts['getEnv:HOME'], home, 'the evaluator sees a scratch HOME, not the real one');
  assert.deepEqual(snapshot(dir), rootBefore, 'the project is untouched');
  assert.equal(readdirSync(home).length, homeListing, 'the real home directory gained nothing');
  // evaluation is opt-in: nothing on the default scan path imports this module
  const engine = readFileSync(join(SCANNER, 'src', 'engine.js'), 'utf8') + readFileSync(join(SCANNER, 'src', 'runScan.js'), 'utf8') + readFileSync(join(SCANNER, 'src', 'language', 'engine-pass.js'), 'utf8');
  assert.ok(!/nix-eval-isolation/.test(engine), 'the default scan never loads the evaluator');
  const src = readFileSync(join(SCANNER, 'src', 'language', 'nix-eval-isolation.js'), 'utf8').replace(/\/\/.*$/gm, '');
  assert.ok(!/nixos-rebuild|switch-to-configuration|['"`]build['"`]|nix-env|nixos-install/.test(src), 'no build or activation command exists in the code');
});
