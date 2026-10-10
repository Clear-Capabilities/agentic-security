// Independent acceptance verifier (LOOP-005). The worker never judges its own
// work: this module runs the registered suite itself, parses per-test results,
// and maps them to PRD criteria through [<criterion-id>] tags in test names.
//
// A criterion passes only when at least one test carries its tag, every tagged
// test passed, none was skipped/todo, and the suite as a whole exited with the
// expected code having actually run tests. Missing tests, empty selection,
// skipped tests and swallowed non-zero exits all fail closed.
import { resolve, join } from 'node:path';
import { existsSync } from 'node:fs';
import os from 'node:os';
import { execBoundedSync } from './bounds.mjs';
import { runBounded } from './proc.mjs';
import { runLeasedChildren, mergeTap } from './child-leases.mjs';
import { parseTap } from './tap.mjs';
import { sha256, readJson, nowIso } from './util.mjs';
import { writeEvidence, verifierHash, requirementHash, effectiveWatch, VERIFIER_VERSION } from './evidence.mjs';
import { registerOpLease } from './oplease.mjs';
import { runRemote } from './remote.mjs';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';

export function toolAvailable(name) {
  if (name === 'node') return true;
  try { execBoundedSync(process.platform === 'win32' ? 'where' : 'which', [name], { wallSeconds: 10 }); return true; } catch { return false; }
}

export function environmentInfo() {
  return { node: process.version, platform: process.platform, arch: process.arch, os: os.release(), cpus: os.cpus().length, memGiB: Math.round(os.totalmem() / 2 ** 30) };
}

function failAll(req, reason) {
  return req.criteria.map((c) => ({ id: c.id, state: 'fail', reason, assertions: [] }));
}

export function evaluateCriteria(req, tap, suiteOk) {
  return req.criteria.map((c) => {
    const tag = `[${c.id}]`;
    const hits = tap.tests.filter((t) => t.name.includes(tag));
    if (!hits.length) return { id: c.id, state: 'fail', reason: `no test is tagged ${tag}`, assertions: [] };
    const bad = hits.filter((t) => !t.ok || t.skip || t.todo);
    const assertions = hits.map((t) => ({ name: t.name, ok: t.ok && !t.skip && !t.todo, skipped: t.skip || t.todo }));
    if (bad.length) return { id: c.id, state: 'fail', reason: bad.some((t) => t.skip || t.todo) ? 'a tagged test was skipped/todo (counts as failed)' : 'a tagged test failed', assertions };
    void suiteOk;
    return { id: c.id, state: 'pass', assertions };
  });
}

/**
 * ctx: { repoRoot, L, manifest, tree, key, runId?, invoker, owned? }
 * Returns { evidence, file }.
 */
export async function verifyRequirement(ctx, req, opts = {}) {
  const { repoRoot, L, manifest, tree, key } = ctx;
  const v = req.verification;
  if (v.kind !== 'node-test') throw new Error(`verifyRequirement cannot run kind=${v.kind}; use the controller final phase`);
  tree.build();
  const watch = effectiveWatch(manifest, req);
  const before = tree.digestFor(watch).digest;
  const cwdAbs = resolve(repoRoot, v.cwd);
  const argv = [v.executable === 'node' ? process.execPath : v.executable, ...v.args.slice(0, 1), '--test-reporter=tap', ...v.args.slice(1)];
  const startedAt = nowIso();
  const limitations = [];
  let criteria, counts = { tests: 0, pass: 0, fail: 0, skipped: 0 };
  let run = null, result = 'fail', blocker = null, reason = null;
  let remoteRecord = null, remoteFiles = [];
  const logPath = join(L.evidenceDir, req.id, `${String(Date.now())}.log`);

  const missingFiles = v.files.filter((f) => !existsSync(resolve(cwdAbs, f)));
  const missingTools = (v.requiresTools || []).filter((t) => !toolAvailable(t));
  if (missingFiles.length) {
    reason = `suite file(s) do not exist yet: ${missingFiles.join(', ')}`;
    criteria = failAll(req, reason);
  } else if (missingTools.length && v.remote && !opts.noRemote && process.env.LOOP_REMOTE_VERIFY !== '0') {
    // The tool is not here but a declared hosted-CI executor has it: run the suite there, bound to this exact commit and tree.
    const rr = await runRemote({
      repoRoot, evidenceDir: join(L.evidenceDir, req.id), req, watch, watchDigest: before, remoteCfg: v.remote, evaluateCriteria,
      logger: opts.logger,
    });
    criteria = rr.criteria; counts = rr.counts; remoteRecord = rr.remote || null; remoteFiles = rr.files || [];
    limitations.push(...(rr.limitations || []));
    if (rr.status === 'ok') result = 'pass';
    else if (rr.status === 'unavailable') { result = 'blocked'; blocker = { type: 'remote-unavailable', tools: missingTools }; reason = rr.reason; limitations.push(`required tool(s) unavailable here (${missingTools.join(', ')}) and ${rr.reason}`); }
    else { result = 'fail'; reason = rr.reason; }
  } else if (missingTools.length) {
    result = 'blocked'; blocker = { type: 'missing-tool', tools: missingTools };
    reason = `required tool(s) unavailable: ${missingTools.join(', ')}`;
    criteria = failAll(req, reason);
    limitations.push(reason);
  } else {
    mkdirSync(join(L.evidenceDir, req.id), { recursive: true, mode: 0o700 });
    const lease = registerOpLease(L.leasesDir, { label: `verify ${req.id}`, deadlineSeconds: v.timeoutSeconds + 15 });
    try {
      const env = { ...process.env, LOOP_ENGINEERING_VERIFY: '1', NO_COLOR: '1', FORCE_COLOR: '0' };
      if (v.childLeaseSeconds && v.files.length > 1) {
        // A suite of several files runs each as a child with its own finite lease, all inside the suite class's ceiling (LOOP-002).
        run = await runLeasedSuite({ v, argv, cwdAbs, env, logPath, opts, ctx, reqId: req.id });
      } else run = await runBounded({
        argv, cwd: cwdAbs, wallMs: v.timeoutSeconds * 1000, graceMs: opts.graceMs ?? 5000, logPath,
        maxLogBytes: opts.maxLogBytes ?? 5 * 1024 * 1024, tailBytes: 8 * 1024 * 1024, runId: ctx.runId, owned: ctx.owned, label: `verify:${req.id}`,
        env,
        maxRssBytes: opts.maxRssBytes ?? 0,
      });
    } finally { lease.release(); }
    const tap = parseTap(run.stdoutTail);
    const top = tap.tests;
    counts = {
      tests: tap.summary.tests ?? top.length,
      pass: tap.summary.pass ?? top.filter((t) => t.ok).length,
      fail: tap.summary.fail ?? top.filter((t) => !t.ok).length,
      skipped: (tap.summary.skipped ?? 0) + (tap.summary.todo ?? 0),
    };
    criteria = evaluateCriteria(req, tap, true);
    if (run.outcome !== 'exited') reason = `${run.outcome}${run.reason ? `: ${run.reason}` : ''}`;
    else if (run.exitCode !== v.expectedExitCode) reason = `exit code ${run.exitCode}, expected ${v.expectedExitCode}`;
    else if (counts.tests <= 0 || !top.length) reason = 'suite ran zero tests (empty selection fails)';
    else if (counts.skipped > 0) reason = `${counts.skipped} test(s) skipped/todo; skipped required tests count as failed`;
    if (run.logTruncated) limitations.push('log truncated at the configured cap');
    const allPass = criteria.every((c) => c.state === 'pass');
    result = !reason && allPass ? 'pass' : 'fail';
    if (!reason && !allPass) reason = `criteria not passing: ${criteria.filter((c) => c.state !== 'pass').map((c) => c.id).join(', ')}`;
  }

  tree.build();
  const after = tree.digestFor(watch).digest;
  if (after !== before) {
    result = 'fail';
    reason = 'source tree changed while the suite was running; the result cannot be bound to a tree';
    criteria = criteria.map((c) => ({ ...c, state: 'fail', reason }));
  }

  const logSha = run && existsSync(logPath) ? sha256(readFileSync(logPath)) : null;
  const envelope = {
    schemaVersion: 1, requirement: req.id, phase: opts.phase || 'requirement', attempt: opts.attempt ?? null,
    invoker: remoteRecord ? 'controller+hosted-ci' : (ctx.invoker || 'controller'), result, reason,
    createdAt: nowIso(),
    verifier: { version: VERIFIER_VERSION, hash: verifierHash() },
    manifest: { version: manifest.manifestVersion, acceptanceHash: manifest.acceptanceHash, requirementHash: requirementHash(req) },
    prdSha256: manifest.prd.sha256,
    treeDigest: after,
    watch,
    suiteFilesDigest: sha256(v.files.map((f) => { try { return sha256(readFileSync(resolve(cwdAbs, f))); } catch { return 'missing'; } }).join('')),
    environment: environmentInfo(),
    exec: {
      argv: remoteRecord ? ['hosted-ci', v.remote.workflow, String(remoteRecord.runId)] : [v.executable, ...argv.slice(1)], cwd: v.cwd, startedAt, endedAt: nowIso(), expectedExitCode: v.expectedExitCode, timeoutSeconds: v.timeoutSeconds,
      exitCode: run?.exitCode ?? (remoteRecord ? (result === 'pass' ? 0 : 1) : null), signal: run?.signal ?? null, outcome: run ? run.outcome : (remoteRecord ? 'hosted-ci' : (blocker ? 'blocked' : 'not-run')), durationMs: run?.durationMs ?? 0,
      orphansKilled: run?.orphansKilled?.length ?? 0, peakRssKb: run?.peakRssKb ?? 0,
      ...(run?.children ? { children: run.children, hungFiles: run.hung } : {}),
    },
    counts, criteria,
    ...(blocker ? { blocker } : {}),
    logs: run ? { combined: { path: logPath, sha256: logSha, bytes: run.bytes.stdout + run.bytes.stderr } } : Object.fromEntries(remoteFiles.map((f, i) => [`remote${i}`, f])),
    ...(remoteRecord ? { remote: remoteRecord } : {}),
    limitations,
  };
  const out = writeEvidence(L, req.id, envelope, key);
  return { evidence: out.evidence, file: out.file, tail: run ? (run.stdoutTail.slice(-4000) + '\n' + run.stderrTail.slice(-2000)) : '' };
}

// Leased execution of a multi-file suite, shaped like one runBounded result so everything downstream (TAP parsing, evidence) is unchanged.
async function runLeasedSuite({ v, argv, cwdAbs, env, logPath, opts, ctx, reqId }) {
  const [exe] = argv;
  const t0 = Date.now();
  const lr = await runLeasedChildren({
    files: v.files, argvFor: (f) => [exe, '--test', '--test-reporter=tap', f], cwd: cwdAbs, env, ceilingSeconds: v.timeoutSeconds, childLeaseSeconds: v.childLeaseSeconds,
    graceMs: opts.graceMs ?? 5000, concurrency: 2, label: `verify:${reqId}`, runId: ctx.runId, owned: ctx.owned, extra: { maxRssBytes: opts.maxRssBytes ?? 0 },
  });
  const cap = opts.maxLogBytes ?? 5 * 1024 * 1024;
  const log = lr.children.map((c) => `### ${c.file} (${c.outcome}${c.reason ? `: ${c.reason}` : ''})\n${c.stdoutTail}${c.stderrTail ? `\n[err] ${c.stderrTail}` : ''}\n`).join('\n');
  const buf = Buffer.from(log, 'utf8');
  writeFileSync(logPath, buf.length > cap ? buf.subarray(0, cap) : buf, { mode: 0o600 });
  const outcome = lr.outcome === 'exited' ? 'exited' : (['lease-expired', 'ceiling-expired', 'not-run'].includes(lr.outcome) ? 'timeout-wall' : lr.outcome);
  return {
    outcome, reason: lr.reason, exitCode: lr.exitCode, signal: null, stdoutTail: mergeTap(lr.children), stderrTail: '',
    bytes: { stdout: lr.children.reduce((n, c) => n + (c.bytes?.stdout || 0), 0), stderr: lr.children.reduce((n, c) => n + (c.bytes?.stderr || 0), 0) },
    logTruncated: buf.length > cap, durationMs: Date.now() - t0, orphansKilled: new Array(lr.children.reduce((n, c) => n + (c.orphansKilled || 0), 0)), peakRssKb: Math.max(0, ...lr.children.map((c) => c.peakRssKb || 0)),
    children: lr.children.map((c) => ({ file: c.file, outcome: c.outcome, exitCode: c.exitCode, leaseSeconds: c.leaseSeconds, durationMs: c.durationMs })), hung: lr.hung,
  };
}

export function loadJsonSafe(p) { return readJson(p, null); }
