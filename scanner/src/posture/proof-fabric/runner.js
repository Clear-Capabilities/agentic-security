// Hermetic execution of one reproducer attempt.
//
// Isolation preference: container (when a working runtime and a pre-pulled image exist) > local confined sandbox >
// unavailable. The local mode is LOWER assurance and says so in every result; it is never silently substituted for a
// container where a policy requires one (`requireContainer`). Nothing here ever executes target code unconfined.
//
// Defaults: outbound network denied; only a runner-controlled loopback callback listener may be reachable, and only when
// the reproducer asks for it; no privileged containers; bounded CPU, memory, disk, process count and wall time.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { randomBytes, createHash } from 'node:crypto';
import { runInBoundary } from '../../sandbox/trust-boundary.js';
import { detectBackend } from '../../sandbox/index.js';
import { evaluateOracle } from './oracles.js';
import { validateReproducer, substitute } from './reproducer.js';
import { runInContainer, CONTAINER_ROOT, CONTAINER_TOOLS } from './container.js';

export const DEFAULT_LIMITS = Object.freeze({
  timeoutMs: 20_000, buildTimeoutMs: 60_000, graceMs: 1000, maxOutputBytes: 256 * 1024,
  cpus: 1, memoryMb: 512, pids: 128, diskMb: 64,
});

const CONTAINER_IMAGES = Object.freeze({
  javascript: 'node:24-slim', typescript: 'node:24-slim', python: 'python:3-slim', java: 'eclipse-temurin:21',
  c: 'gcc:latest', cpp: 'gcc:latest', csharp: 'mcr.microsoft.com/dotnet/sdk:8.0', haskell: 'haskell:9',
});

const SIGNALS = { 134: 'SIGABRT', 135: 'SIGBUS', 136: 'SIGFPE', 132: 'SIGILL', 139: 'SIGSEGV' };

// only language toolchains are probed; the container engine has its own, richer health check (`container.js`)
const PROBED_TOOLS = new Set(['java', 'javac', 'python3', 'cc', 'gcc', 'dotnet', 'ghc', 'runghc']);
const probeCache = new Map();
/** A launcher that exists is not a toolchain that works: macOS ships /usr/bin/java and /usr/bin/python3 as stubs that only prompt for an
 * install. A tool counts only if it answers its version flag, within a short timeout, with exit 0. */
function toolWorks(file, name) {
  if (probeCache.has(file)) return probeCache.get(file);
  const args = name === 'java' || name === 'javac' ? ['-version'] : ['--version'];
  let ok = false;
  try { const r = spawnSync(file, args, { stdio: 'ignore', timeout: 8000 }); ok = r.status === 0; } catch { ok = false; }
  probeCache.set(file, ok);
  return ok;
}

function findTool(name, pathEnv = process.env.PATH || '') {
  const dirs = pathEnv.split(path.delimiter);
  // a configured JDK wins over whatever stub sits on PATH
  if ((name === 'java' || name === 'javac') && process.env.JAVA_HOME) dirs.unshift(path.join(process.env.JAVA_HOME, 'bin'));
  for (const dir of dirs) {
    if (!dir) continue;
    const p = path.join(dir, name);
    try {
      fs.accessSync(p, fs.constants.X_OK);
      if (!fs.statSync(p).isFile()) continue;
      const real = fs.realpathSync(p);
      if (!PROBED_TOOLS.has(name) || toolWorks(real, name)) return real;
    } catch { /* next */ }
  }
  return null;
}

export function hostTools() {
  return { node: process.execPath, python: findTool('python3'), java: findTool('java'), javac: findTool('javac'), cc: findTool('cc') || findTool('gcc'), dotnet: findTool('dotnet'), ghc: findTool('ghc'), runghc: findTool('runghc') };
}

/** Language -> tools it needs. Missing tools make the language `unsupported` with a typed reason, never a pass. */
export function languageSupport(lang, tools = hostTools()) {
  const need = { javascript: ['node'], typescript: ['node'], python: ['python'], java: ['java', 'javac'], c: ['cc'], cpp: ['cc'], csharp: ['dotnet'], haskell: ['ghc', 'runghc'] }[lang];
  if (!need) return { supported: false, reason: `unsupported language: ${lang}` };
  const missing = need.filter((t) => !tools[t]);
  return missing.length ? { supported: false, reason: `missing toolchain: ${missing.join(', ')}` } : { supported: true, reason: null };
}

/**
 * Pick the execution environment. `docker` is injectable for tests. A container needs a responsive daemon AND the image
 * already present: nothing is ever pulled (no network during proof).
 */
export function selectEnvironment({ lang, preferContainer = true, requireContainer = false, docker = null, tools = hostTools(), force } = {}) {
  const dockerBin = docker?.bin ?? findTool('docker');
  if (preferContainer && dockerBin) {
    const image = docker?.images?.[lang] ?? CONTAINER_IMAGES[lang];
    const probe = (docker?.probe ?? defaultDockerProbe)(dockerBin, image);
    if (probe.ok) return { mode: 'container', assurance: 'high', runtime: dockerBin, image, imageId: probe.imageId ?? null, reason: null };
    if (requireContainer) return { mode: 'unavailable', assurance: 'none', reason: `container required but unavailable: ${probe.reason}` };
    const local = localEnv(force);
    return { ...local, containerSkipped: probe.reason };
  }
  if (requireContainer) return { mode: 'unavailable', assurance: 'none', reason: 'container required but no container runtime found' };
  return localEnv(force);
}

function localEnv(force) {
  const backend = detectBackend({ force });
  if (backend === 'disabled') return { mode: 'unavailable', assurance: 'none', reason: 'no confinement backend works on this host; refusing to execute' };
  return { mode: 'local-confined', assurance: 'lower', backend, reason: null, note: 'lower-assurance local confinement: not a container boundary' };
}

function defaultDockerProbe(bin, image) {
  // a daemon that is busy (a runner just finished pulling images) can take longer than a few seconds to answer; one slow
  // answer must not read as "no daemon", so the first probe is patient and a failed one is tried once more
  const ask = () => spawnSync(bin, ['info', '--format', '{{.ServerVersion}}'], { encoding: 'utf8', timeout: 15000, killSignal: 'SIGKILL' });
  let info = ask();
  if (info.status !== 0) info = ask();
  if (info.status !== 0) return { ok: false, reason: 'container daemon not responding' };
  const img = spawnSync(bin, ['image', 'inspect', '--format', '{{.Id}}', image], { encoding: 'utf8', timeout: 5000, killSignal: 'SIGKILL' });
  // the image id is the environment's identity: two proofs with the same id ran on the same base
  return img.status === 0 ? { ok: true, imageId: /^(?:sha256:)?[0-9a-f]{12,64}$/i.test(String(img.stdout).trim()) ? String(img.stdout).trim() : null } : { ok: false, reason: `image ${image} is not present locally (proofs never pull)` };
}

// ---------------------------------------------------------------------------------------------------------------

const digestFile = (p) => { try { return createHash('sha256').update(fs.readFileSync(p)).digest('hex'); } catch { return null; } };

const LISTENER_SRC = `
const http = require('node:http'); const fs = require('node:fs');
const out = process.argv[1];
const s = http.createServer((req, res) => {
  const m = /^\\/([A-Za-z0-9_-]{8,64})/.exec(req.url || '');
  if (m) fs.appendFileSync(out, JSON.stringify({ nonce: m[1] }) + '\\n');
  req.resume(); res.end('ok');
});
s.on('error', () => process.exit(2));
s.listen(0, '127.0.0.1', () => { process.stdout.write(String(s.address().port) + '\\n'); });
setTimeout(() => process.exit(0), 120000).unref();
`;

async function startListener(dir) {
  const hits = path.join(dir, 'hits.jsonl');
  fs.writeFileSync(hits, '');
  const child = spawn(process.execPath, ['-e', LISTENER_SRC, hits], { stdio: ['ignore', 'pipe', 'ignore'], detached: false });
  const port = await new Promise((resolve) => {
    let buf = '';
    const t = setTimeout(() => resolve(null), 3000);
    child.stdout.on('data', (d) => { buf += d; const n = Number(buf.trim()); if (n > 0) { clearTimeout(t); resolve(n); } });
    child.on('exit', () => { clearTimeout(t); resolve(null); });
  });
  return {
    port, child,
    hits: () => { try { return fs.readFileSync(hits, 'utf8').split('\n').filter(Boolean).map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean); } catch { return []; } },
    stop: () => { try { child.kill('SIGKILL'); } catch { /* gone */ } },
  };
}

function trimOut(s, max) { s = String(s ?? ''); return s.length > max ? `${s.slice(0, max)}\n[truncated]` : s; }

/**
 * Run one attempt. Never throws. Result:
 *   { status, executed, environment, observation, oracle, durationMs, reasons[], degraded[], nonceDigest }
 * status: 'completed' | 'build-failed' | 'blocked' | 'unsupported' | 'invalid' | 'error'
 * Only `completed` carries an oracle verdict; everything else is incomplete evidence.
 */
export async function runAttempt(reproducer, opts = {}) {
  const started = Date.now();
  const limits = { ...DEFAULT_LIMITS, ...(opts.limits || {}) };
  const done = (o) => ({ executed: false, observation: null, oracle: null, degraded: [], reasons: [], ...o, durationMs: Date.now() - started });

  const errs = validateReproducer(reproducer);
  if (errs.length) return done({ status: 'invalid', reasons: errs });
  const tools = opts.tools ?? hostTools();
  const sup = languageSupport(reproducer.lang, tools);
  if (!sup.supported) return done({ status: 'unsupported', reasons: [sup.reason] });
  const env = opts.environment ?? selectEnvironment({ lang: reproducer.lang, requireContainer: opts.requireContainer, preferContainer: opts.preferContainer ?? true, force: opts.force });
  if (env.mode === 'unavailable') return done({ status: 'blocked', environment: env, reasons: [env.reason] });
  const inContainer = env.mode === 'container';
  if (inContainer && reproducer.network === 'callback') {
    // the container has no network by design, so it cannot reach the runner's loopback listener
    if (opts.requireContainer) return done({ status: 'blocked', environment: env, reasons: ['this reproducer needs the loopback callback listener, which a container (no network) cannot reach, and a container was required'] });
    return done({ status: 'unsupported', environment: env, reasons: ['a reproducer that needs the loopback callback listener cannot run in a container (no network); run it without a container requirement to use the local confined backend'] });
  }
  if (!inContainer && reproducer.network === 'callback' && env.backend !== 'userspace') {
    return done({ status: 'unsupported', environment: env, reasons: [`loopback callback needs the userspace backend; this host uses ${env.backend}`] });
  }

  const nonce = randomBytes(12).toString('hex');
  const base = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'proof-fabric-')));
  const root = path.join(base, 'root');
  const aux = path.join(base, 'aux');
  fs.mkdirSync(root, { recursive: true });
  fs.mkdirSync(path.join(root, 'canary'));
  fs.mkdirSync(path.join(root, 'tmp'));
  fs.mkdirSync(aux);
  let listener = null;
  try {
    const secrets = {};
    const canaries = {};
    const ctx = {
      nonce, root: inContainer ? CONTAINER_ROOT : root, tools: inContainer ? CONTAINER_TOOLS : tools,
      secret: (n) => (secrets[n] ??= `SECRET-${nonce}-${n}`),
      // the host path is what the oracle reads; inside a container the same file is seen under /work
      canary: (n) => { canaries[n] ??= { path: path.join(root, 'canary', `${nonce}-${n}`) }; return inContainer ? path.posix.join(CONTAINER_ROOT, 'canary', `${nonce}-${n}`) : canaries[n].path; },
    };
    if (reproducer.network === 'callback') {
      listener = await startListener(aux);
      if (!listener.port) return done({ status: 'error', environment: env, reasons: ['could not start the loopback callback listener'] });
      ctx.callbackPort = listener.port;
      ctx.callbackUrl = `http://127.0.0.1:${listener.port}/${nonce}`;
    }
    // Repository sources imported at proof time (so a patch can be overlaid). Read-only, size-bounded, confined to sourceRoot.
    const imported = {};
    if (reproducer.sources) {
      if (!opts.sourceRoot) return done({ status: 'invalid', environment: env, reasons: ['reproducer imports repository sources but no sourceRoot was given'] });
      const realRoot = fs.realpathSync(opts.sourceRoot);
      for (const [dest, src] of Object.entries(reproducer.sources)) {
        let text;
        if (opts.overlay && Object.hasOwn(opts.overlay, src)) text = String(opts.overlay[src]);
        else {
          const abs = path.resolve(realRoot, src);
          let real; try { real = fs.realpathSync(abs); } catch { return done({ status: 'invalid', environment: env, reasons: [`source not found: ${src}`] }); }
          if (real !== realRoot && !real.startsWith(realRoot + path.sep)) return done({ status: 'invalid', environment: env, reasons: [`source escapes the repository: ${src}`] });
          const st = fs.statSync(real);
          if (!st.isFile() || st.size > 256 * 1024) return done({ status: 'invalid', environment: env, reasons: [`source is not a regular file within the size limit: ${src}`] });
          text = fs.readFileSync(real, 'utf8');
        }
        imported[dest] = text;
      }
    }
    for (const [rel, text] of Object.entries({ ...imported, ...reproducer.files })) {
      const dest = path.join(root, rel);
      fs.mkdirSync(path.dirname(dest), { recursive: true });
      fs.writeFileSync(dest, substitute(text, ctx));
    }
    const argv = (a) => a.map((x) => substitute(x, ctx));
    const watch = {};
    for (const [name, rel] of Object.entries(reproducer.watch || {})) {
      const p = path.join(root, rel);
      watch[name] = { path: p, existedBefore: fs.existsSync(p), digestBefore: digestFile(p) };
    }
    const runEnv = inContainer ? { LANG: 'C.UTF-8' } : { PATH: '/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin', HOME: root, TMPDIR: path.join(root, 'tmp'), LANG: 'C.UTF-8', CI: '1' };
    for (const [k, v] of Object.entries(reproducer.env || {})) runEnv[k] = substitute(v, ctx);
    const boundary = { root, timeoutMs: limits.timeoutMs, graceMs: limits.graceMs, maxOutputBytes: limits.maxOutputBytes, env: runEnv, force: opts.force, signal: opts.signal, controlProbes: opts.controlProbes };

    const degraded = [];
    if (env.assurance === 'lower') degraded.push('lower-assurance-local-confinement');

    const execute = (cmd, extra) => (inContainer
      ? runInContainer({ runtime: env.runtime, image: env.image, name: `proof-${nonce}-${extra.stage}`, hostRoot: root, argv: cmd, env: runEnv, limits, timeoutMs: extra.timeoutMs, signal: opts.signal, maxOutputBytes: limits.maxOutputBytes, user: opts.containerUser })
      : runInBoundary(cmd, { ...boundary, ...extra.boundary }));
    if (reproducer.build) {
      const b = await execute(argv(reproducer.build), { stage: 'build', timeoutMs: limits.buildTimeoutMs, boundary: { timeoutMs: limits.buildTimeoutMs, cwd: undefined } });
      if (b.blocked) return done({ status: 'blocked', environment: env, reasons: b.reasons, degraded });
      if (b.timedOut || b.exitCode !== 0) return done({ status: 'build-failed', executed: true, environment: env, reasons: [b.timedOut ? 'build timed out' : `build exited ${b.exitCode}`], degraded, observation: { buildStderr: trimOut(b.targetOutput?.stderr, 2000) } });
    }

    const r = await execute(argv(reproducer.run), { stage: 'run', timeoutMs: limits.timeoutMs, boundary: listener ? { networkProxyPort: listener.port } : {} });
    if (r.blocked) return done({ status: 'blocked', environment: env, reasons: r.reasons, degraded });
    if (!r.executed) return done({ status: 'error', environment: env, reasons: [`target did not execute (${r.status})`], degraded });

    const exitCode = r.exitCode ?? null;
    const observation = {
      exitCode, signal: SIGNALS[exitCode] ?? null, timedOut: !!r.timedOut,
      stdout: trimOut(r.targetOutput?.stdout, limits.maxOutputBytes), stderr: trimOut(r.targetOutput?.stderr, limits.maxOutputBytes),
      nonce, secrets, canaries: {}, callbacks: listener ? listener.hits() : [],
    };
    for (const [n, c] of Object.entries(canaries)) observation.canaries[n] = { exists: fs.existsSync(c.path), existedBefore: false };
    for (const [n, w] of Object.entries(watch)) observation.canaries[n] = { exists: fs.existsSync(w.path), existedBefore: w.existedBefore, digestBefore: w.digestBefore, digestAfter: digestFile(w.path) };
    if (r.outputCapped) degraded.push('output-capped');
    if (r.timedOut) degraded.push('timed-out');
    if (r.termination?.survivors?.length) degraded.push('surviving-processes');

    const oracle = evaluateOracle(reproducer.oracle, observation);
    // Raw secrets/nonce must not leave this function: persisted evidence carries digests only.
    const safeObs = { ...observation, secrets: Object.fromEntries(Object.keys(secrets).map((k) => [k, '[redacted]'])), nonce: '[redacted]', callbacks: observation.callbacks.length };
    safeObs.stdout = scrub(safeObs.stdout, nonce); safeObs.stderr = scrub(safeObs.stderr, nonce);
    return done({
      status: oracle.unsupported ? 'unsupported' : 'completed', executed: true, environment: { ...env, backend: r.backend ?? env.backend },
      observation: safeObs, oracle, degraded, reasons: oracle.unsupported ? [oracle.reason] : [], controls: r.controls,
      nonceDigest: createHash('sha256').update(nonce).digest('hex').slice(0, 16),
    });
  } catch (e) {
    return done({ status: 'error', environment: env, reasons: [`runner error: ${e.message}`] });
  } finally {
    if (listener) listener.stop();
    fs.rmSync(base, { recursive: true, force: true });
  }
}

const scrub = (s, nonce) => String(s).split(nonce).join('[nonce]');
