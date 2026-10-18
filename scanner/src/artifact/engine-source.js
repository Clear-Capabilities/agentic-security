// Read an image from a LOCAL container engine (`docker save` / `podman save`), for `image scan --engine <name>` (PRD 5, requirement 1:
// "local image"). The engine produces a docker-archive tar, which then goes through the same hardened parser as any other archive.
//
// Nothing here runs the image: `save` only exports it. The engine is a process like any other in this codebase, so it has what the
// shared contract asks of one: a timeout, cancellation, process-group cleanup, and a byte cap on what it may produce. The cap
// matters because the output is streamed to a temporary file and counted as it arrives: an engine (or a mislabelled "engine") that
// writes without end is stopped at the cap instead of filling the disk. The temporary file is removed on every exit path.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';

export class EngineError extends Error {
  constructor(message, code) { super(message); this.name = 'EngineError'; this.code = code; }
}

export const ENGINE_LIMITS = Object.freeze({ timeoutMs: 5 * 60_000, maxBytes: 2 * 1024 * 1024 * 1024 });
const RUNTIMES = Object.freeze(['docker', 'podman']);
// a reference, never an option: it must start with a letter or digit, so it can never be read as a flag
const REF_RE = /^[A-Za-z0-9][A-Za-z0-9._\/:@+-]{0,254}$/;

function findTool(name, pathEnv = process.env.PATH || '') {
  for (const dir of pathEnv.split(path.delimiter)) {
    if (!dir) continue;
    const p = path.join(dir, name);
    try { fs.accessSync(p, fs.constants.X_OK); if (fs.statSync(p).isFile()) return fs.realpathSync(p); } catch { /* next */ }
  }
  return null;
}

export function saveFromEngine(ref, { runtime = 'docker', limits = ENGINE_LIMITS, signal = null, pathEnv = process.env.PATH } = {}) {
  const L = { ...ENGINE_LIMITS, ...limits };
  if (!RUNTIMES.includes(runtime)) return Promise.reject(new EngineError(`the container engine must be one of ${RUNTIMES.join(', ')}`, 'bad_runtime'));
  if (!REF_RE.test(String(ref ?? '')) || String(ref).includes('..')) return Promise.reject(new EngineError('not a valid image reference', 'bad_reference'));
  const bin = findTool(runtime, pathEnv);
  if (!bin) return Promise.reject(new EngineError(`${runtime} is not installed or not on PATH; nothing was read`, 'engine_unavailable'));
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'engine-save-'));
  const file = path.join(dir, 'image.tar');
  const cleanup = () => { try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ } };
  return new Promise((resolve, reject) => {
    const out = fs.createWriteStream(file, { mode: 0o600 });
    out.on('error', (e) => fail(new EngineError(`could not write the export: ${e.code ?? e.message}`, 'engine_error')));
    const child = spawn(bin, ['save', ref], { detached: true, stdio: ['ignore', 'pipe', 'pipe'] });
    let bytes = 0; let stderr = ''; let settled = false; let reason = null;
    const kill = () => { try { process.kill(-child.pid, 'SIGKILL'); } catch { try { child.kill('SIGKILL'); } catch { /* gone */ } } };
    const fail = (e) => { if (settled) return; settled = true; clearTimeout(timer); signal?.removeEventListener('abort', onAbort); kill(); out.destroy(); cleanup(); reject(e); };
    const timer = setTimeout(() => { reason = 'timeout'; fail(new EngineError(`${runtime} save did not finish within ${Math.round(L.timeoutMs / 1000)}s`, 'timeout')); }, L.timeoutMs);
    const onAbort = () => fail(new EngineError('cancelled', 'cancelled'));
    if (signal) { if (signal.aborted) { onAbort(); return; } signal.addEventListener('abort', onAbort, { once: true }); }
    child.stdout.on('data', (d) => {
      if (settled) return;
      bytes += d.length;
      if (bytes > L.maxBytes) { fail(new EngineError(`the image export is larger than ${L.maxBytes} bytes`, 'too_large')); return; }
      out.write(d);
    });
    child.stderr.on('data', (d) => { if (stderr.length < 4096) stderr += d; });
    child.on('error', (e) => fail(new EngineError(`could not start ${runtime}: ${e.code ?? e.message}`, 'engine_unavailable')));
    child.on('close', (code) => {
      if (settled) return;
      out.end(() => {
        if (settled) return;
        if (code !== 0) return fail(new EngineError(`${runtime} save failed: ${stderr.trim().split('\n').pop()?.slice(0, 200) || `exit ${code}`}`, /no such image|not found|unable to find/i.test(stderr) ? 'not_found' : 'engine_error'));
        try {
          const buf = fs.readFileSync(file);
          settled = true; clearTimeout(timer); signal?.removeEventListener('abort', onAbort); cleanup();
          resolve({ tar: buf, source: { kind: 'engine', runtime, reference: ref, bytes: buf.length } });
        } catch (e) { fail(new EngineError(`could not read the exported image: ${e.code ?? e.message}`, 'engine_error')); }
      });
    });
    void reason;
  });
}
