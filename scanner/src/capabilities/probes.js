// Active probes for the controls capability enforcement depends on (X-502, X-503,
// X-504), and the platform status that follows from them.
//
// The sandbox already probes write confinement, read denial of named host paths,
// environment scrubbing, the no-network default, tree termination and the
// file-size limit (sandbox/control-probes.js). Capability enforcement needs three
// more, each established the same way: an attack through the real backend that
// must fail, paired with a positive control that must succeed, so a probe that
// cannot succeed cannot pass for a working control.
//
//   fs-read-confinement   a canary outside every declared root is unreadable by
//                         the task, by a descendant, through a symbolic link
//                         planted inside a readable root and through `..`; the
//                         same canary IS readable once its directory is declared
//   fs-multi-root-write   several declared write roots are writable, a read-only
//                         root and an undeclared directory are not
//   network-mediation     a declared destination is reachable through the
//                         mediation proxy, an undeclared one is refused by the
//                         proxy, and a direct socket to either is refused by the
//                         operating system
//
// Nothing here asserts an outcome on a platform it did not run on. On the
// namespace backend (Linux) the new controls are `unsupported`, because that
// backend does not implement them, and the inherited probes run for real where a
// Linux host exists. No state is ever inherited from another platform.
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { detectBackend } from '../sandbox/capabilities.js';
import { runConfinedSupervised } from '../sandbox/supervise.js';
import { probeControls, unmetControls } from '../sandbox/control-probes.js';
import { digestOf } from '../posture/assurance/identity.js';
import { FEATURES } from '../posture/assurance/config.js';
import { bindManifest } from './manifest.js';
import { startMediationProxy } from './proxy.js';

export const CAPABILITY_CONTROLS = Object.freeze(['fs-read-confinement', 'fs-multi-root-write', 'network-mediation']);

const NODE = process.execPath;
const ZERO_REV = '0'.repeat(40);
const proved = (evidence) => ({ state: 'proved', evidence });
const notProved = (reason) => ({ state: 'not-proved', reason });
const unsupported = (reason) => ({ state: 'unsupported', reason });

function mk(prefix) { return fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), prefix))); }
function rm(p) { try { fs.rmSync(p, { recursive: true, force: true }); } catch { /* best effort */ } }
const token = (p) => `${p}-${crypto.randomBytes(8).toString('hex')}`;

// `run` is a seam so a test can hand the probe a runner that is deliberately
// wrong (a read root left too wide, a root left writable) and see the probe say
// so: a probe that cannot fail proves nothing.
export async function probeFsRead(backend, runner = runConfinedSupervised) {
  if (backend !== 'userspace' && backend !== 'namespace') return unsupported(`read confinement to declared roots is not implemented on the ${backend} backend`);
  const root = mk('agsec-cap-r-'); const ro = mk('agsec-cap-ro-'); const outside = mk('agsec-cap-out-');
  try {
    const okTok = token('READABLE'); const secTok = token('SEALED');
    fs.writeFileSync(path.join(ro, 'r.txt'), okTok);
    fs.writeFileSync(path.join(outside, 's.txt'), secTok);
    fs.symlinkSync(path.join(outside, 's.txt'), path.join(ro, 'link'));
    const run = (script, readRoots) => runner(['/bin/sh', '-c', script], { root, readRoots, timeoutMs: 8000, graceMs: 300 });
    const pos = await run(`cat '${ro}/r.txt'`, [ro]);
    if (!pos.stdout.includes(okTok)) return notProved(`positive control failed: a file inside a declared root was not readable (${pos.status})`);
    const open = await run(`cat '${outside}/s.txt'`, [ro, outside]);
    if (!open.stdout.includes(secTok)) return notProved('positive control failed: the canary was not readable even when its directory was declared');
    const attempts = {
      direct: `cat '${outside}/s.txt'`,
      'symbolic link': `cat '${ro}/link'`,
      traversal: `cat '${ro}/../${path.basename(outside)}/s.txt'`,
      descendant: `sh -c "cat '${outside}/s.txt'"; ( cat '${outside}/s.txt' ) 2>&1`,
    };
    for (const [name, script] of Object.entries(attempts)) {
      const r = await run(`${script}; true`, [ro]);
      if (r.stdout.includes(secTok)) return notProved(`the canary outside every declared root was readable (${name})`);
    }
    return proved('declared roots readable; canary unreadable directly, through a link, through .., and from a descendant; readable once declared');
  } finally { rm(root); rm(ro); rm(outside); }
}

export async function probeMultiWrite(backend, runner = runConfinedSupervised) {
  if (backend !== 'userspace' && backend !== 'namespace') return unsupported(`several declared write roots are not implemented on the ${backend} backend`);
  const root = mk('agsec-cap-w-'); const w1 = mk('agsec-cap-w1-'); const w2 = mk('agsec-cap-w2-');
  const ro = mk('agsec-cap-wro-'); const outside = mk('agsec-cap-wout-');
  try {
    const script = [`echo a > '${w1}/f'`, `echo b > '${w2}/f'`, `echo c > '${ro}/f'`, `echo d > '${outside}/f'`, 'true'].join('; ');
    await runner(['/bin/sh', '-c', script], { root, readRoots: [ro], writeRoots: [w1, w2], timeoutMs: 8000, graceMs: 300 });
    if (!fs.existsSync(path.join(w1, 'f')) || !fs.existsSync(path.join(w2, 'f'))) return notProved('positive control failed: a declared write root was not writable');
    if (fs.existsSync(path.join(ro, 'f'))) return notProved('a root declared read-only was writable');
    if (fs.existsSync(path.join(outside, 'f'))) return notProved('an undeclared directory was writable');
    return proved('both declared write roots writable; the read-only root and an undeclared directory were not');
  } finally { rm(root); rm(w1); rm(w2); rm(ro); rm(outside); }
}

function listener(label) {
  const state = { connections: 0 };
  const server = http.createServer((req, res) => { res.writeHead(200, { 'content-type': 'text/plain' }); res.end(label); });
  server.on('connection', () => { state.connections += 1; });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve({ server, state, port: server.address().port }));
  });
}

async function probeNetworkMediation(backend) {
  if (backend !== 'userspace') return unsupported(`mediated network access is not implemented on the ${backend} backend (its network namespace has no path to a proxy)`);
  const root = mk('agsec-cap-n-');
  let a; let b; let proxy;
  try {
    a = await listener('A'); b = await listener('B');
    const built = bindManifest({
      schema: 'agentic-security/capability-manifest', schemaVersion: '1.0.0', taskId: 'probe-network', repository: { revision: ZERO_REV }, policyVersion: 1,
      network: [{ host: '127.0.0.1', port: a.port, schemes: ['http'] }],
    });
    if (!built.ok) return notProved('probe manifest was invalid');
    proxy = await startMediationProxy({ bound: built.bound });
    const script = `
const http=require('http'),net=require('net');
const via=(p)=>new Promise(r=>{const q=http.request({host:'127.0.0.1',port:${proxy.port},method:'GET',path:'http://127.0.0.1:'+p+'/',headers:{host:'127.0.0.1:'+p},agent:false},res=>{let b='';res.on('data',d=>b+=d);res.on('end',()=>r({s:res.statusCode,b}))});q.on('error',e=>r({e:e.code}));q.setTimeout(4000,()=>q.destroy());q.end()});
const direct=(p)=>new Promise(r=>{const s=net.connect(p,'127.0.0.1');s.on('connect',()=>{s.destroy();r({connected:true})});s.on('error',e=>r({e:e.code}));setTimeout(()=>r({e:'TIMEOUT'}),2500)});
(async()=>{console.log(JSON.stringify({pa:await via(${a.port}),pb:await via(${b.port}),da:await direct(${a.port}),db:await direct(${b.port})}))})();`;
    const r = await runConfinedSupervised([NODE, '-e', script], {
      root, readRoots: [NODE], networkProxyPort: proxy.port, timeoutMs: 15000, graceMs: 300,
    });
    let out;
    try { out = JSON.parse(String(r.stdout).trim().split('\n').pop()); } catch { return notProved(`positive control failed: the probe client did not report (${r.status})`); }
    if (!(out.pa && out.pa.s === 200 && out.pa.b === 'A')) return notProved('positive control failed: a declared destination was not reachable through the proxy');
    if (!(out.pb && out.pb.s === 403)) return notProved('an undeclared destination was not refused by the proxy');
    if (out.da?.connected || out.db?.connected) return notProved('a direct socket bypassed the proxy');
    if (b.state.connections !== 0) return notProved('the undeclared listener saw a connection');
    if (a.state.connections !== 1) return notProved(`the declared listener saw ${a.state.connections} connections; only the proxied request should have arrived`);
    return proved('declared destination reachable only through the proxy; undeclared refused by the proxy; direct sockets refused by the operating system');
  } finally {
    if (proxy) await proxy.close();
    for (const l of [a, b]) if (l) await new Promise((res) => l.server.close(() => res()));
    rm(root);
  }
}

const _cache = new Map();
export function resetCapabilityProbeCache() { _cache.clear(); }

async function measure(backend, force) {
  const base = await probeControls({ force });
  const controls = { ...base.controls };
  if (backend === 'disabled') {
    for (const c of CAPABILITY_CONTROLS) controls[c] = { state: 'unavailable', reason: 'no confinement backend works on this host' };
  } else {
    const run = async (name, fn) => {
      try { controls[name] = await fn(); } catch (e) { controls[name] = notProved(`probe threw: ${String(e.message).split('\n')[0]}`); }
    };
    await run('fs-read-confinement', () => probeFsRead(backend));
    await run('fs-multi-root-write', () => probeMultiWrite(backend));
    await run('network-mediation', () => probeNetworkMediation(backend));
  }
  return controls;
}

/**
 * Probe every control capability enforcement uses, on the active backend.
 * @param {object} [o]
 * @param {string} [o.force]   backend override (same meaning as runConfined's)
 * @param {object} [o.probes]  per-control overrides (test seam). An override can only
 *                             be used to make a control LESS proved in a test; a run
 *                             still goes through the real backend.
 */
export async function probeCapabilityControls({ force, probes = {} } = {}) {
  const backend = detectBackend({ force });
  if (!_cache.has(backend)) _cache.set(backend, await measure(backend, force));
  const controls = { ..._cache.get(backend) };
  // Overrides replace one control's result after the real measurement; the run
  // itself still goes through the real backend.
  for (const [name, fn] of Object.entries(probes)) controls[name] = await fn();
  const states = Object.fromEntries(Object.entries(controls).sort().map(([k, v]) => [k, v.state]));
  return {
    platform: process.platform, backend, controls,
    probeDigest: digestOf({ platform: process.platform, backend, states }),
  };
}

/** Controls this manifest actually depends on; a control it never uses cannot block it. */
export function requiredControlsFor(manifest) {
  const req = ['write-confinement', 'read-denial', 'fs-read-confinement', 'fs-multi-root-write', 'env-scrub', 'tree-termination', 'file-size-limit', 'network'];
  if (manifest.network.length) req.push('network-mediation');
  return req;
}

/**
 * Whether this platform and backend are one the product ADVERTISES for enforced
 * mode. Taken from the feature table in the assurance config (Linux only), and
 * the only advertised backend is the kernel-namespace one. The macOS userspace
 * backend can be proved on a host by the probes above, and is still not
 * advertised: it is development-host evidence, not an enforced backend.
 */
export function isAdvertisedBackend(backend, platform = process.platform) {
  return FEATURES['capability-enforcement'].platforms.includes(platform) && backend === 'namespace';
}

/** Standing platform statements. Nothing here is measured; it states what has and has not been evidenced. */
export function platformStatements() {
  return Object.freeze({
    linux: {
      backend: 'namespace', status: 'unverified',
      note: 'advertised for enforced mode, but the control probes in this module have not run on a Linux host from this workspace. Several controls are not implemented on the namespace backend (read confinement to declared roots, several write roots, mediated network, supervised tree termination), so enforced mode is blocked there until they are implemented and the sandbox-linux job shows them proved. Process-count caps are never claimed.',
    },
    darwin: {
      backend: 'userspace', status: 'host-proved-not-advertised',
      note: 'the active probes can prove the controls on a macOS host, and tasks can run there for development only when the caller opts in; macOS is not an advertised enforced backend.',
    },
    win32: { backend: null, status: 'unsupported', note: 'no isolation backend exists on Windows.' },
  });
}

export { unmetControls };
