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

// Pure comparison, factored out of verifyBundle() so it can be pointed at a
// temp-dir copy in tests without touching the committed bundle. verifyBundle()
// itself keeps its fixed-path, no-argument public signature.
export function _verifyBundleAt(bundle) {
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

export function verifyBundle() {
  return _verifyBundleAt(bundlePath());
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

    // The two determinism vars are defaults set here rather than via the CLI's
    // `--deterministic` flag, which calls verifyLockfile() and exits 4 WITHOUT
    // SCANNING on any tree without a committed rules lockfile — every
    // third-party target. `...process.env` is spread first, so a stray ambient
    // shell variable can never override these two defaults. `...extraEnv` is
    // spread last and deliberately CAN override them: a later caller in this
    // series re-enables network access (unsets AGENTIC_SECURITY_OFFLINE) to run
    // supply-chain analysis against the same targets, and needs this as the
    // escape hatch. Do not reorder the spreads.
    const env = {
      ...process.env,
      AGENTIC_SECURITY_DETERMINISTIC: '1',
      AGENTIC_SECURITY_OFFLINE: '1',
      ...extraEnv,
    };
    if (statsPath) env.AGENTIC_SECURITY_IR_STATS = statsPath;
    // Determinism run B passes statsPath=null deliberately (no need to re-measure
    // coverage twice). Without this, an ambient AGENTIC_SECURITY_IR_STATS the
    // operator happened to have set in their shell would still be inherited via
    // the `...process.env` spread above, silently writing a sidecar to whatever
    // path they left set — not the deterministic-only run this is supposed to be.
    else delete env.AGENTIC_SECURITY_IR_STATS;

    // Scan state accumulates inside the scanned tree and can mask results on a
    // re-run — CLAUDE.md's "wipe scan state before benchmarking" rule. The
    // determinism check scans the same tree twice, so this is not optional.
    try {
      fs.rmSync(path.join(dir, '.agentic-security'), { recursive: true, force: true });
    } catch { /* nothing to clear */ }

    const started = Date.now();
    // SARIF capture goes to a FILE DESCRIPTOR, not a pipe.
    //
    // The CLI ends every command with `process.exit(code)`. Writes to a pipe
    // are asynchronous, so `process.exit` discards whatever has not yet
    // drained — the OS pipe buffer is 64 KiB, which is exactly the size both
    // of Godot's captured SARIFs came out as (65,536 bytes, truncated
    // mid-token). Because the runner then sha256'd two identically truncated
    // prefixes, the determinism check reported `identical: true` from a gate
    // that could not fail. Reproduced and fixed in this session: a child that
    // writes 1,000,001 bytes then exits yields 65,536 bytes through a pipe
    // and 1,000,001 through an fd.
    //
    // Writes to a regular file are synchronous in Node, so handing the child
    // an fd for stdout makes `process.exit` flush-safe without changing the
    // CLI. Do not "simplify" this back to a pipe + createWriteStream.
    const sarifFd = sarifPath ? fs.openSync(sarifPath, 'w') : null;
    const child = spawn(process.execPath, [bundlePath(), ...args], {
      cwd: dir,
      env,
      stdio: ['ignore', sarifFd !== null ? sarifFd : 'ignore', 'pipe'],
    });

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

    // Close the SARIF fd on every exit path — both the close and error paths
    // route through this so a future third exit path can't leak the
    // descriptor. The child owns its own dup of the fd, so the bytes are on
    // disk by the time it exits; this close is the parent's copy.
    let settled = false;
    const settle = (result) => {
      if (settled) return;
      settled = true;
      clearInterval(poll);
      clearTimeout(timer);
      if (sarifFd !== null) { try { fs.closeSync(sarifFd); } catch { /* already closed */ } }
      resolve(result);
    };

    child.on('close', (code) => {
      settle({
        exitCode: code,
        wallMs: Date.now() - started,
        timedOut,
        peakRssKb,
        stderrTail: stderr.slice(-4000),
      });
    });

    child.on('error', (err) => {
      settle({
        exitCode: null,
        wallMs: Date.now() - started,
        timedOut,
        peakRssKb,
        stderrTail: String(err && err.message),
      });
    });
  });
}
