// Isolated, opt-in Nix evaluation (NIX-011).
//
// Ordinary scanning NEVER evaluates customer Nix: nothing imports this module on the default path. An
// operator who explicitly asks for evaluation gets it only inside an OS sandbox whose isolation this module
// has just proved with a probe, and only through an evaluator whose required safety flags were
// feature-detected. The order is fixed and every step before the last is "before project code runs":
//
//   1. detectSandbox      which backend exists on this host (macOS sandbox-exec, Linux bubblewrap), or none
//   2. probeSandbox       run a probe INSIDE the sandbox that tries to read outside the allowlist, write
//                         outside it, reach the network, reach a daemon socket, spawn a process and see a
//                         credential variable; the sandbox is accepted only if every attempt is refused
//   3. detectEvaluator    run `--version` / `eval --help` and require every safety flag to exist
//   4. runIsolatedEval    run the target-scoped evaluation with a clean environment, a read-only allowlist,
//                         a wall-clock deadline, an output cap and a memory ceiling; kill the whole process group
//
// Anything that fails earlier returns `unsupported` or `blocked` with `projectCodeEvaluated:false`; the
// static findings of the scan are never touched (`staticFindingsRetained:true`) and the result says how to
// import a supplied export instead. Flags are NOT the boundary: the filesystem/network/process boundary is
// the sandbox, and the probe tests it independently of any flag. Nix's own build sandbox and restricted
// evaluation are additional controls, not substitutes. Nothing here runs `nixos-rebuild`, activates a
// configuration, builds anything or edits a host setting.

import { spawn, spawnSync } from 'node:child_process';
import { createServer as netServer } from 'node:net';
import { mkdtempSync, writeFileSync, mkdirSync, rmSync, existsSync, realpathSync } from 'node:fs';
import { tmpdir, platform as osPlatform } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { createHash } from 'node:crypto';

export const NIX_EVAL_VERSION = 'nix-eval-isolation/1';
export const DEFAULT_LIMITS = Object.freeze({ deadlineMs: 20_000, maxOutputBytes: 1 << 20, maxRssMb: 512, killGraceMs: 1500, probeDeadlineMs: 15_000 });
/** Flags the evaluator must support; a missing one means `unsupported`, never "run without it". */
export const REQUIRED_EVAL_FLAGS = Object.freeze(['--offline', '--no-update-lock-file', '--no-write-lock-file', '--pure-eval', '--json', '--option']);
/** `--option name value` settings that are always passed. */
export const SAFETY_OPTIONS = Object.freeze({
  'allow-import-from-derivation': 'false',
  'allow-unsafe-native-code-during-evaluation': 'false',
  'accept-flake-config': 'false',
  'restrict-eval': 'true',
  'allowed-uris': '',
  'substituters': '',
  'max-jobs': '0',
});
const CLEAN_PATH = '/usr/bin:/bin';
const ATTR_RE = /^[A-Za-z0-9_][A-Za-z0-9_.+'-]*(?:\.(?:[A-Za-z0-9_][A-Za-z0-9_+'-]*|"[A-Za-z0-9_.+-]+"))*$/;

// ── 1. sandbox backend ───────────────────────────────────────────────────────
const which = (bin) => { const r = spawnSync('/usr/bin/which', [bin], { encoding: 'utf8', timeout: 5000 }); return r.status === 0 ? r.stdout.trim() : null; };

export function detectSandbox(opts = {}) {
  const plat = opts.platform || osPlatform();
  const find = opts.which || which;
  if (opts.forceBackend === 'none') return { available: false, backend: 'none', platform: plat, reason: 'isolation disabled by the caller' };
  if (plat === 'darwin') {
    const p = find('sandbox-exec');
    return p ? { available: true, backend: 'sandbox-exec', path: p, platform: plat, reason: null } : { available: false, backend: 'none', platform: plat, reason: 'sandbox-exec is not installed' };
  }
  if (plat === 'linux') {
    const p = find('bwrap');
    return p ? { available: true, backend: 'bwrap', path: p, platform: plat, reason: null } : { available: false, backend: 'none', platform: plat, reason: 'bubblewrap (bwrap) is not installed: no tested unprivileged filesystem/network namespace is available' };
  }
  return { available: false, backend: 'none', platform: plat, reason: `no sandbox backend is implemented for ${plat}` };
}

const sbq = (s) => `"${String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
const real = (p) => { try { return realpathSync(p); } catch { return resolve(p); } };

/**
 * The sandboxed command for a backend. Reads are an ALLOWLIST (the listed roots, system library paths and the
 * evaluator); writes are an allowlist of one scratch directory; network and process creation are denied.
 * @param {{backend:string, path?:string}} sb
 * @param {{execFile:string, args:string[], readOnly:string[], readFiles?:string[], writable:string[], cwd:string}} spec
 */
export function sandboxCommand(sb, spec) {
  const ro = [...new Set(spec.readOnly.map(real))];
  const files = [...new Set((spec.readFiles || []).map(real))];
  const rw = [...new Set(spec.writable.map(real))];
  const exec = real(spec.execFile);
  if (sb.backend === 'sandbox-exec') {
    const profile = [
      '(version 1)', '(allow default)', '(deny network*)',
      '(deny file-write*)', `(allow file-write* ${rw.map((p) => `(subpath ${sbq(p)})`).join(' ')} (subpath "/dev"))`,
      '(deny file-read-data (subpath "/"))',
      `(allow file-read-data (literal "/") ${[spec.cwd, ...rw].map((p) => `(literal ${sbq(real(p))})`).join(' ')} (subpath "/usr") (subpath "/System") (subpath "/Library") (subpath "/private/var/db") (subpath "/dev") (subpath "/nix/store") ${ro.map((p) => `(subpath ${sbq(p)})`).join(' ')} ${files.map((p) => `(literal ${sbq(p)})`).join(' ')} ${rw.map((p) => `(subpath ${sbq(p)})`).join(' ')})`,
      '(deny process-exec*)', `(allow process-exec (literal ${sbq(exec)}) (subpath "/nix/store"))`,
    ].join('\n');
    return { file: sb.path, args: ['-p', profile, exec, ...spec.args], profile };
  }
  if (sb.backend === 'bwrap') {
    const a = ['--unshare-all', '--die-with-parent', '--new-session', '--clearenv', '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp'];
    for (const p of ['/usr', '/lib', '/lib64', '/bin', '/etc/ssl', '/nix/store']) a.push('--ro-bind-try', p, p);
    for (const p of ro) a.push('--ro-bind', p, p);
    for (const p of files) a.push('--ro-bind', p, p);
    for (const p of rw) a.push('--bind', p, p);
    a.push('--chdir', spec.cwd, exec, ...spec.args);
    return { file: sb.path, args: a, profile: null };
  }
  return null;
}

// ── process supervisor ───────────────────────────────────────────────────────
function rssOfGroup(pgid) {
  const r = spawnSync('/bin/ps', ['-o', 'rss=', '-g', String(pgid)], { encoding: 'utf8', timeout: 2000 });
  if (r.status !== 0) return 0;
  return r.stdout.split('\n').map((x) => parseInt(x, 10)).filter(Number.isFinite).reduce((a, b) => a + b, 0) / 1024;
}
function killGroup(pid, sig) { try { process.kill(-pid, sig); } catch { try { process.kill(pid, sig); } catch { /* gone */ } } }

/** Run a command to completion under a deadline, an output cap and a memory ceiling. Never throws. */
export function supervise(file, args, { env, cwd, deadlineMs, maxOutputBytes, maxRssMb, killGraceMs = 1500 }) {
  return new Promise((resolveP) => {
    const t0 = Date.now();
    let child;
    try { child = spawn(file, args, { env, cwd, detached: true, stdio: ['ignore', 'pipe', 'pipe'] }); }
    catch (e) { return resolveP({ status: 'failed', reason: `could not start: ${e.message}`, stdout: '', stderr: '', exitCode: null, signal: null, ms: 0 }); }
    let out = ''; let err = ''; let bytes = 0; let state = null; let done = false;
    const finish = (extra = {}) => { if (done) return; done = true; clearInterval(poll); clearTimeout(dl); resolveP({ stdout: out, stderr: err.slice(0, 4000), ms: Date.now() - t0, ...extra }); };
    const stop = (why) => { if (state) return; state = why; killGroup(child.pid, 'SIGTERM'); setTimeout(() => killGroup(child.pid, 'SIGKILL'), killGraceMs).unref(); };
    child.stdout.on('data', (d) => { bytes += d.length; if (bytes > maxOutputBytes) { stop('output-limit'); return; } out += d.toString('utf8'); });
    child.stderr.on('data', (d) => { if (err.length < 8000) err += d.toString('utf8'); });
    const dl = setTimeout(() => stop('timed-out'), deadlineMs);
    const poll = setInterval(() => { if (!state && maxRssMb && rssOfGroup(child.pid) > maxRssMb) stop('resource-limit'); }, 250);
    child.on('error', (e) => finish({ status: 'failed', reason: e.message, exitCode: null, signal: null }));
    child.on('close', (code, signal) => {
      killGroup(child.pid, 'SIGKILL');                                          // reap any descendants
      finish({ status: state || (code === 0 ? 'ok' : 'failed'), exitCode: code, signal, reason: state ? `${state}${state === 'timed-out' ? ` after ${deadlineMs} ms` : ''}` : (code === 0 ? null : `exit ${code}`) });
    });
  });
}

const cleanEnv = (work, extra = {}) => ({ PATH: CLEAN_PATH, HOME: work, TMPDIR: work, LANG: 'C', LC_ALL: 'C', ...extra });

// ── 2. probe ─────────────────────────────────────────────────────────────────
const PROBE_SOURCE = `
const fs=require('fs'),net=require('net'),cp=require('child_process');
const [allowedFile,outsideFile,outsideWrite,okWrite,port,sock]=process.argv.slice(2);
const r={};const t=(k,f)=>{try{r[k]=f()}catch(e){r[k]='refused:'+(e.code||'error')}};
t('readAllowed',()=>fs.readFileSync(allowedFile,'utf8').trim());
t('readOutside',()=>{fs.readFileSync(outsideFile,'utf8');return 'READ'});
t('readHostFile',()=>{fs.readFileSync('/etc/hosts','utf8');return 'READ'});
t('writeOutside',()=>{fs.writeFileSync(outsideWrite,'x');return 'WROTE'});
t('writeScratch',()=>{fs.writeFileSync(okWrite,'x');return 'wrote'});
t('spawn',()=>{cp.execFileSync('/bin/echo',['x']);return 'SPAWNED'});
t('credentialEnv',()=>process.env.PROBE_CREDENTIAL||'absent');
let pending=2;const fin=()=>{if(--pending===0){console.log(JSON.stringify(r));process.exit(0)}};
const tcp=net.connect(Number(port),'127.0.0.1');tcp.on('connect',()=>{r.network='CONNECTED';tcp.destroy();fin()});tcp.on('error',(e)=>{r.network='refused:'+e.code;fin()});
const un=net.connect(sock);un.on('connect',()=>{r.daemonSocket='CONNECTED';un.destroy();fin()});un.on('error',(e)=>{r.daemonSocket='refused:'+e.code;fin()});
setTimeout(()=>{r.timeout=true;console.log(JSON.stringify(r));process.exit(0)},8000);
`;

/**
 * Prove the isolation of a backend with real attempts, independent of any evaluator flag. The result is
 * `verified` only if the one permitted read worked, the scratch write worked and every other attempt was refused.
 */
export async function probeSandbox(sb, opts = {}) {
  if (!sb || !sb.available) return { verified: false, backend: sb ? sb.backend : 'none', reason: (sb && sb.reason) || 'no sandbox', attempts: {} };
  const limits = { ...DEFAULT_LIMITS, ...(opts.limits || {}) };
  const base = mkdtempSync(join(tmpdir(), 'nix-eval-probe-'));
  const allowed = join(base, 'ro'); const scratch = join(base, 'rw'); const outside = join(base, 'outside');
  for (const d of [allowed, scratch, outside]) mkdirSync(d);
  writeFileSync(join(allowed, 'a.txt'), 'allowed'); writeFileSync(join(outside, 'secret.txt'), 'secret');
  const script = join(base, 'probe.cjs'); writeFileSync(script, PROBE_SOURCE);
  const sockPath = join(base, 'daemon.sock');
  let connections = 0;
  const tcp = netServer((s) => { connections++; s.destroy(); });
  const uds = netServer((s) => { connections++; s.destroy(); });
  await new Promise((r) => tcp.listen(0, '127.0.0.1', r));
  await new Promise((r) => uds.listen(sockPath, r));
  const port = tcp.address().port;
  try {
    const exe = opts.nodePath || process.execPath;
    const cmd = sandboxCommand(sb, { execFile: exe, args: [script, join(allowed, 'a.txt'), join(outside, 'secret.txt'), join(outside, 'w.txt'), join(scratch, 'w.txt'), String(port), sockPath], readOnly: [allowed, dirname(dirname(real(exe)))], readFiles: [script], writable: [scratch], cwd: scratch });
    const r = await supervise(cmd.file, cmd.args, { env: cleanEnv(scratch), cwd: scratch, deadlineMs: limits.probeDeadlineMs, maxOutputBytes: 64 * 1024, maxRssMb: limits.maxRssMb, killGraceMs: limits.killGraceMs });
    let attempts = null;
    try { attempts = JSON.parse(r.stdout.trim()); } catch { /* unparseable: not verified */ }
    if (!attempts) return { verified: false, backend: sb.backend, reason: `the probe did not complete inside the sandbox (${r.reason || r.stderr.slice(0, 120) || 'no output'})`, attempts: {} };
    const insufficient = [];
    if (attempts.readAllowed !== 'allowed') insufficient.push('the allowlisted read failed: the sandbox is unusable');
    if (attempts.writeScratch !== 'wrote') insufficient.push('the scratch write failed: the sandbox is unusable');
    if (attempts.readOutside === 'READ') insufficient.push('a file outside the allowlist could be read');
    if (attempts.readHostFile === 'READ') insufficient.push('a host file (/etc/hosts) could be read');
    if (attempts.writeOutside === 'WROTE') insufficient.push('a file outside the scratch directory could be written');
    if (attempts.network === 'CONNECTED') insufficient.push('a network connection succeeded');
    if (attempts.daemonSocket === 'CONNECTED') insufficient.push('a unix daemon socket could be reached');
    if (attempts.spawn === 'SPAWNED') insufficient.push('a native process could be spawned');
    if (attempts.credentialEnv && attempts.credentialEnv !== 'absent') insufficient.push('a credential environment variable was visible');
    if (attempts.timeout) insufficient.push('the probe timed out');
    return { verified: insufficient.length === 0 && connections === 0, backend: sb.backend, reason: insufficient.length ? insufficient.join('; ') : (connections ? 'the probe listeners saw a connection' : null), attempts, listenerConnections: connections, insufficient };
  } finally { tcp.close(); uds.close(); rmSync(base, { recursive: true, force: true }); }
}

// ── 3. evaluator feature detection ───────────────────────────────────────────
/** @param {{file:string, prefixArgs?:string[]}} nix  the evaluator command (a stand-in in tests) */
export async function detectEvaluator(nix, sb, ctx) {
  const run = async (args) => {
    const cmd = sandboxCommand(sb, { execFile: nix.file, args: [...(nix.prefixArgs || []), ...args], readOnly: ctx.readOnly, readFiles: [...(ctx.readFiles || []), ...(nix.prefixArgs || []).filter((a) => !a.startsWith('-'))], writable: [ctx.work], cwd: ctx.work });
    return supervise(cmd.file, cmd.args, { env: cleanEnv(ctx.work), cwd: ctx.work, deadlineMs: 10_000, maxOutputBytes: 64 * 1024, maxRssMb: ctx.limits.maxRssMb, killGraceMs: ctx.limits.killGraceMs });
  };
  const v = await run(['--version']);
  const ver = (/(\d+\.\d+(?:\.\d+)?)/.exec(v.stdout) || [])[1] || null;
  if (v.status !== 'ok' || !ver) return { ok: false, reason: `the evaluator did not report a version (${v.reason || 'no output'})`, version: null, missing: REQUIRED_EVAL_FLAGS.slice() };
  const h = await run(['eval', '--help']);
  const text = `${h.stdout}\n${h.stderr}`;
  const missing = REQUIRED_EVAL_FLAGS.filter((f) => !text.includes(f));
  return { ok: missing.length === 0, version: ver, missing, reason: missing.length ? `the evaluator lacks required safety flag(s): ${missing.join(', ')}` : null };
}

// ── target selection and argv ────────────────────────────────────────────────
/** A flake output attribute, validated. Anything outside a plain attribute path is refused. */
export function selectTarget({ root, attribute, system = null } = {}) {
  if (typeof root !== 'string' || !root.startsWith('/')) return { ok: false, reason: 'the project root must be an absolute path' };
  if (typeof attribute !== 'string' || !ATTR_RE.test(attribute) || attribute.length > 200) return { ok: false, reason: `"${String(attribute).slice(0, 40)}" is not a plain flake attribute path` };
  if (/\.\./.test(attribute)) return { ok: false, reason: 'attribute paths may not contain ..' };
  return { ok: true, installable: `path:${root}#${attribute}`, root, attribute, system };
}
export function buildEvalArgs(target) {
  const opts = Object.entries(SAFETY_OPTIONS).flatMap(([k, v]) => ['--option', k, v]);
  return ['eval', '--offline', '--no-update-lock-file', '--no-write-lock-file', '--pure-eval', '--json', ...opts, target.installable];
}

// ── 4. run ───────────────────────────────────────────────────────────────────
export const IMPORT_FALLBACK = Object.freeze({
  summary: 'Evaluation did not run or did not finish. Static findings are unaffected. To supply the data yourself, generate an export on a trusted machine and pass it in:',
  steps: ['nix path-info --json --recursive <installable>  >  pathinfo.json', 'nix derivation show --recursive <installable>  >  drvshow.json', 'Provide both with a provenance envelope (tool, command, target system and installable, flake.lock sha256, generation time); see docs/guides/nix.md'],
  schemas: ['nix-path-info-json', 'nix-derivation-show-json', 'nix-store-query-text'],
});

/**
 * @param {{nix:{file:string,prefixArgs?:string[]}, root:string, attribute:string, system?:string, limits?:object,
 *          sandbox?:object, extraReadOnly?:string[], probe?:Function, env?:object}} o
 * @returns {Promise<{status:'ok'|'unsupported'|'blocked'|'timed-out'|'output-limit'|'resource-limit'|'failed', projectCodeEvaluated:boolean, ...}>}
 */
export async function runIsolatedEval(o) {
  const limits = { ...DEFAULT_LIMITS, ...(o.limits || {}) };
  const keep = { staticFindingsRetained: true, fallback: IMPORT_FALLBACK, evaluation: 'opt-in' };
  const stopBefore = (status, reason, extra = {}) => ({ status, reason, projectCodeEvaluated: false, ...keep, ...extra });
  const target = selectTarget({ root: o.root, attribute: o.attribute, system: o.system });
  if (!target.ok) return stopBefore('blocked', target.reason);
  const sb = o.sandbox || detectSandbox();
  if (!sb.available) return stopBefore('unsupported', `no isolation is available (${sb.reason}); the project's Nix code was NOT evaluated`, { sandbox: sb });
  const probe = await (o.probe || probeSandbox)(sb, { limits });
  if (!probe.verified) return stopBefore('blocked', `the sandbox did not prove its isolation, so the project's Nix code was NOT evaluated: ${probe.reason}`, { sandbox: sb, probe });
  const work = mkdtempSync(join(tmpdir(), 'nix-eval-work-'));
  try {
    const root = real(o.root);
    const nixFiles = [nix_file(o.nix), ...(o.nix.prefixArgs || []).filter((a) => a && !a.startsWith('-')).map(real)];
    const ctx = { work: real(work), readOnly: [root, dirname(dirname(real(o.nix.file))), ...(o.extraReadOnly || [])], readFiles: nixFiles, limits };
    const feat = await detectEvaluator(o.nix, sb, ctx);
    if (!feat.ok) return stopBefore('unsupported', `${feat.reason}; the project's Nix code was NOT evaluated`, { sandbox: sb, probe: { verified: true }, evaluator: feat });
    const args = [...(o.nix.prefixArgs || []), ...buildEvalArgs(target)];
    const cmd = sandboxCommand(sb, { execFile: o.nix.file, args, readOnly: ctx.readOnly, readFiles: nixFiles, writable: [ctx.work], cwd: ctx.work });
    const r = await supervise(cmd.file, cmd.args, { env: cleanEnv(ctx.work, o.env || {}), cwd: ctx.work, deadlineMs: limits.deadlineMs, maxOutputBytes: limits.maxOutputBytes, maxRssMb: limits.maxRssMb, killGraceMs: limits.killGraceMs });
    const base = { ...keep, projectCodeEvaluated: true, sandbox: { backend: sb.backend }, evaluator: { version: feat.version }, ms: r.ms, target: { attribute: target.attribute, system: target.system, installable: target.installable } };
    if (r.status !== 'ok') return { ...base, status: r.status === 'failed' ? 'failed' : r.status, reason: r.reason || r.stderr.slice(0, 200) };
    let data;
    try { data = JSON.parse(r.stdout); } catch { return { ...base, status: 'failed', reason: 'the evaluator output was not JSON' }; }
    const digest = createHash('sha256').update(r.stdout).digest('hex');
    return { ...base, status: 'ok', reason: null, export: { schema: 'nix-eval-attrs-json', provenance: { tool: 'nix', toolVersion: feat.version, command: `nix ${buildEvalArgs(target).join(' ')}`, target: { system: target.system, installable: target.installable, attribute: target.attribute }, generatedAt: new Date().toISOString(), isolation: sb.backend, outputSha256: digest }, data }, outputSha256: digest };
  } finally { rmSync(work, { recursive: true, force: true }); }
}
const nix_file = (n) => real(n.file);

/** Evaluation health is its OWN state: it never replaces, empties or downgrades the static scan. */
export function mergeEvaluationHealth(scanHealth, result) {
  const h = scanHealth && typeof scanHealth === 'object' ? { ...scanHealth } : {};
  const requested = !!result;
  h.evaluation = requested
    ? { requested: true, status: result.status, ran: result.projectCodeEvaluated === true, reason: result.reason || null, ms: result.ms ?? null, fallback: result.status === 'ok' ? null : result.fallback || IMPORT_FALLBACK }
    : { requested: false, status: 'not-requested', ran: false, reason: 'evaluation is opt-in; the scan is static', fallback: null };
  h.staticFindingsRetained = true;
  return h;
}

export { cleanEnv as _cleanEnv, which as _which };
