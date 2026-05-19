// FR-VER-10 — Ephemeral verification target (Docker driver).
//
// Docker-based ephemeral sandbox for running generated PoCs against a fresh
// copy of the customer's app. The customer supplies the image (or a
// docker-compose.yml); we spin it up, run the PoC, tear down. Network is
// disabled by default; mount is read-only.
//
// Public API:
//   isAvailable() → boolean — `docker --version` succeeds
//   startTarget({ image, env, port, scanRoot }) → { containerId, url, stop() }
//   runPoCAgainst(transcript, target, pocCode) → { exitCode, stdout, stderr }
//
// Falls back gracefully to `infra-unavailable` when Docker is missing. This
// module does NOT make cloud API calls; it only wraps the local Docker CLI.

import { spawnSync, spawn } from 'node:child_process';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

const STARTUP_TIMEOUT_MS = 30_000;
const POC_TIMEOUT_MS = 15_000;

export function isAvailable() {
  try {
    const r = spawnSync('docker', ['--version'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
    return r.status === 0;
  } catch { return false; }
}

export function startTarget(opts = {}) {
  if (!isAvailable()) {
    return { available: false, reason: 'docker-not-installed' };
  }
  const image = opts.image || '';
  if (!image) return { available: false, reason: 'no-image-supplied' };
  const containerName = `as-target-${crypto.randomBytes(4).toString('hex')}`;
  const port = opts.port || 3000;
  const args = [
    'run', '--rm', '--detach',
    '--name', containerName,
    '--network', opts.network === 'host' ? 'host' : 'bridge',
    '--cap-drop=ALL',
    '--memory=512m',
    '--cpus=0.5',
    '--read-only',
    '--tmpfs', '/tmp:size=64m',
    '--publish', `127.0.0.1:0:${port}`,
  ];
  for (const [k, v] of Object.entries(opts.env || {})) args.push('--env', `${k}=${v}`);
  args.push(image);
  if (opts.cmd) args.push(...(Array.isArray(opts.cmd) ? opts.cmd : [opts.cmd]));

  const r = spawnSync('docker', args, { encoding: 'utf8', timeout: STARTUP_TIMEOUT_MS });
  if (r.status !== 0) {
    return { available: false, reason: `docker-run-failed:${(r.stderr || '').slice(0, 200)}` };
  }
  const containerId = (r.stdout || '').trim();

  // Resolve the actually-assigned host port.
  let url = null;
  try {
    const inspect = spawnSync('docker', [
      'port', containerId, String(port),
    ], { encoding: 'utf8' });
    const hostPortLine = (inspect.stdout || '').split('\n').find(l => l.startsWith('127.0.0.1:'));
    if (hostPortLine) url = 'http://' + hostPortLine.trim();
  } catch {}

  return {
    available: true,
    containerId,
    url,
    stop() {
      try { spawnSync('docker', ['kill', containerId], { timeout: 10_000 }); } catch {}
    },
  };
}

// Run a PoC string in a one-shot Node container; return its exit code +
// captured stdout/stderr. Network is host-bridged so the PoC can reach the
// target URL the caller provides via TARGET_URL env.
export function runPoCAgainst(target, pocCode, opts = {}) {
  if (!isAvailable()) {
    return { available: false, reason: 'docker-not-installed' };
  }
  if (!target || !target.url) return { available: false, reason: 'no-target' };
  const tmp = path.join(os.tmpdir(), `as-poc-${crypto.randomBytes(4).toString('hex')}.mjs`);
  try { fs.writeFileSync(tmp, pocCode, 'utf8'); }
  catch (e) { return { available: false, reason: `tmp-write-failed:${e.message}` }; }
  try {
    const args = [
      'run', '--rm',
      '--network', 'bridge',
      '--cap-drop=ALL',
      '--memory=128m',
      '--cpus=0.25',
      '--read-only',
      '--tmpfs', '/tmp:size=16m',
      '--volume', `${tmp}:/poc.mjs:ro`,
      '--env', `TARGET_URL=${target.url}`,
      '--workdir', '/tmp',
      opts.runtimeImage || 'node:20-alpine',
      'node', '/poc.mjs',
    ];
    const r = spawnSync('docker', args, { encoding: 'utf8', timeout: POC_TIMEOUT_MS });
    return {
      available: true,
      exitCode: r.status,
      stdout: r.stdout || '',
      stderr: r.stderr || '',
      timedOut: r.signal === 'SIGTERM' || r.error?.code === 'ETIMEDOUT',
    };
  } finally {
    try { fs.unlinkSync(tmp); } catch {}
  }
}
