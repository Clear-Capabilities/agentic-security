// Scanner invocation for the proof corpus.
//
// Deliberately invokes the COMMITTED BUNDLE as a subprocess rather than
// importing runScan from src/, which is what bench/cve-replay/runner.mjs does.
// The bundle is what users actually run; a bench that passes against src/ while
// the bundle is stale is exactly the false-confidence failure the project's
// verification rules exist to prevent. Do not "simplify" this to a src/ import.

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { spawn, execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const _HERE = path.dirname(fileURLToPath(import.meta.url));
const _SCANNER_DIR = path.resolve(_HERE, '..', '..', '..', 'scanner');

export function bundlePath() {
  return path.join(_SCANNER_DIR, 'dist', 'agentic-security.mjs');
}

export function verifyBundle() {
  const bundle = bundlePath();
  let buf;
  try {
    buf = fs.readFileSync(bundle);
  } catch {
    return { ok: false, reason: `bundle missing at ${bundle} — run "npm run build"`, sha: null };
  }
  const sha = crypto.createHash('sha256').update(buf).digest('hex');
  let sidecar;
  try {
    sidecar = fs.readFileSync(bundle + '.sha256', 'utf8').trim().split(/\s+/)[0];
  } catch {
    return { ok: false, reason: 'sha256 sidecar missing — run "npm run build"', sha };
  }
  if (sidecar !== sha) {
    return { ok: false, reason: 'bundle does not match its sha256 sidecar — run "npm run build"', sha };
  }
  return { ok: true, reason: null, sha };
}

// Poll the child's RSS. process.resourceUsage() only covers this process, and
// spawnSync gives no peak figure, so sampling `ps` is the portable option.
function _sampleRssKb(pid) {
  try {
    const out = execFileSync('ps', ['-o', 'rss=', '-p', String(pid)], {
      encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 5000,
    }).trim();
    const kb = parseInt(out, 10);
    return Number.isFinite(kb) ? kb : null;
  } catch {
    return null;
  }
}

export function runRepoScan(opts) {
  const {
    dir,
    statsPath = null,
    sarifPath = null,
    timeoutMs = 1_800_000,
    extraEnv = {},
  } = opts || {};

  return new Promise((resolve) => {
    // Two CLI facts this depends on, both verified against bin/agentic-security.js:
    //
    // 1. There is no `--sarif <path>` flag. SARIF comes from `--format sarif`
    //    on stdout, so we capture stdout to the file ourselves.
    // 2. We deliberately do NOT pass `--deterministic`. That flag calls
    //    verifyLockfile(), which returns {ok:false, mismatches:['no lockfile
    //    present']} and makes the CLI exit 4 WITHOUT SCANNING on any tree that
    //    has no committed .agentic-security rules lockfile — which is every
    //    third-party target. Setting the same two env vars the flag sets gives
    //    identical deterministic behaviour without the lockfile coupling.
    const args = ['scan', dir, '--format', 'sarif'];

    const env = {
      ...process.env,
      AGENTIC_SECURITY_DETERMINISTIC: '1',
      AGENTIC_SECURITY_OFFLINE: '1',
      ...extraEnv,
    };
    if (statsPath) env.AGENTIC_SECURITY_IR_STATS = statsPath;

    // Scan state accumulates inside the scanned tree and can mask results on a
    // re-run — CLAUDE.md's "wipe scan state before benchmarking" rule. The
    // determinism check scans the same tree twice, so this is not optional.
    try {
      fs.rmSync(path.join(dir, '.agentic-security'), { recursive: true, force: true });
    } catch { /* nothing to clear */ }

    const started = Date.now();
    const sarifStream = sarifPath ? fs.createWriteStream(sarifPath) : null;
    const child = spawn(process.execPath, [bundlePath(), ...args], {
      cwd: dir,
      env,
      stdio: ['ignore', sarifStream ? 'pipe' : 'ignore', 'pipe'],
    });
    if (sarifStream) child.stdout.pipe(sarifStream);

    let peakRssKb = null;
    const poll = setInterval(() => {
      const kb = _sampleRssKb(child.pid);
      if (kb !== null && (peakRssKb === null || kb > peakRssKb)) peakRssKb = kb;
    }, 500);

    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGKILL');
    }, timeoutMs);

    let stderr = '';
    child.stderr.on('data', (d) => {
      stderr += d.toString();
      if (stderr.length > 64_000) stderr = stderr.slice(-64_000);
    });

    child.on('close', (code) => {
      clearInterval(poll);
      clearTimeout(timer);
      const finish = () => resolve({
        exitCode: code,
        wallMs: Date.now() - started,
        timedOut,
        peakRssKb,
        stderrTail: stderr.slice(-4000),
      });
      // Wait for the SARIF write to flush, or the determinism hash reads a
      // truncated file and reports a spurious mismatch.
      if (sarifStream) sarifStream.end(finish); else finish();
    });

    child.on('error', (err) => {
      clearInterval(poll);
      clearTimeout(timer);
      resolve({
        exitCode: null,
        wallMs: Date.now() - started,
        timedOut,
        peakRssKb,
        stderrTail: String(err && err.message),
      });
    });
  });
}
