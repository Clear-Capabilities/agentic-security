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
import { execFileSync } from 'node:child_process';
import { runBounded } from './proc.mjs';
import { parseTap } from './tap.mjs';
import { sha256, readJson, nowIso } from './util.mjs';
import { writeEvidence, verifierHash, requirementHash, effectiveWatch, VERIFIER_VERSION } from './evidence.mjs';
import { registerOpLease } from './oplease.mjs';
import { mkdirSync, readFileSync } from 'node:fs';

export function toolAvailable(name) {
  if (name === 'node') return true;
  try { execFileSync(process.platform === 'win32' ? 'where' : 'which', [name], { stdio: 'ignore' }); return true; } catch { return false; }
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
  const logPath = join(L.evidenceDir, req.id, `${String(Date.now())}.log`);

  const missingFiles = v.files.filter((f) => !existsSync(resolve(cwdAbs, f)));
  const missingTools = (v.requiresTools || []).filter((t) => !toolAvailable(t));
  if (missingFiles.length) {
    reason = `suite file(s) do not exist yet: ${missingFiles.join(', ')}`;
    criteria = failAll(req, reason);
  } else if (missingTools.length) {
    result = 'blocked'; blocker = { type: 'missing-tool', tools: missingTools };
    reason = `required tool(s) unavailable: ${missingTools.join(', ')}`;
    criteria = failAll(req, reason);
    limitations.push(reason);
  } else {
    mkdirSync(join(L.evidenceDir, req.id), { recursive: true, mode: 0o700 });
    const lease = registerOpLease(L.leasesDir, { label: `verify ${req.id}`, deadlineSeconds: v.timeoutSeconds + 15 });
    try {
      run = await runBounded({
        argv, cwd: cwdAbs, wallMs: v.timeoutSeconds * 1000, graceMs: opts.graceMs ?? 5000, logPath,
        maxLogBytes: opts.maxLogBytes ?? 5 * 1024 * 1024, tailBytes: 8 * 1024 * 1024, runId: ctx.runId, owned: ctx.owned, label: `verify:${req.id}`,
        env: { ...process.env, LOOP_ENGINEERING_VERIFY: '1', NO_COLOR: '1', FORCE_COLOR: '0' },
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
    invoker: ctx.invoker || 'controller', result, reason,
    createdAt: nowIso(),
    verifier: { version: VERIFIER_VERSION, hash: verifierHash() },
    manifest: { version: manifest.manifestVersion, acceptanceHash: manifest.acceptanceHash, requirementHash: requirementHash(req) },
    prdSha256: manifest.prd.sha256,
    treeDigest: after,
    watch,
    suiteFilesDigest: sha256(v.files.map((f) => { try { return sha256(readFileSync(resolve(cwdAbs, f))); } catch { return 'missing'; } }).join('')),
    environment: environmentInfo(),
    exec: {
      argv: [v.executable, ...argv.slice(1)], cwd: v.cwd, startedAt, endedAt: nowIso(), expectedExitCode: v.expectedExitCode, timeoutSeconds: v.timeoutSeconds,
      exitCode: run?.exitCode ?? null, signal: run?.signal ?? null, outcome: run ? run.outcome : (blocker ? 'blocked' : 'not-run'), durationMs: run?.durationMs ?? 0,
      orphansKilled: run?.orphansKilled?.length ?? 0, peakRssKb: run?.peakRssKb ?? 0,
    },
    counts, criteria,
    ...(blocker ? { blocker } : {}),
    logs: run ? { combined: { path: logPath, sha256: logSha, bytes: run.bytes.stdout + run.bytes.stderr } } : {},
    limitations,
  };
  const out = writeEvidence(L, req.id, envelope, key);
  return { evidence: out.evidence, file: out.file, tail: run ? (run.stdoutTail.slice(-4000) + '\n' + run.stderrTail.slice(-2000)) : '' };
}

export function loadJsonSafe(p) { return readJson(p, null); }
