// Observation preload for e6-07 (`node --import`). Records every process spawn, network connection and filesystem write, and every read outside the
// scanned tree, to the JSONL file named by CONTAINMENT_LOG. It observes and does not block: the test decides what is a violation by comparing a hostile
// repository with a clean one and by checking that hostile-controlled text never reaches a shell, a host or a write path.
import cp from 'node:child_process';
import net from 'node:net';
import dns from 'node:dns';
import http from 'node:http';
import https from 'node:https';
import fs from 'node:fs';
import path from 'node:path';
import { syncBuiltinESMExports } from 'node:module';

const LOG = process.env.CONTAINMENT_LOG;
const ROOTS = process.env.CONTAINMENT_ROOT ? [process.env.CONTAINMENT_ROOT, fs.realpathSync(process.env.CONTAINMENT_ROOT)] : null;
const TMP = fs.realpathSync('/tmp');
const append = fs.appendFileSync.bind(fs);
const rec = (o) => { try { append(LOG, JSON.stringify(o) + '\n'); } catch { /* the log itself must never break the process */ } };

for (const fn of ['spawn', 'spawnSync', 'execFile', 'execFileSync', 'fork']) {
  const orig = cp[fn];
  cp[fn] = function (file, args, opts) {
    const o = Array.isArray(args) ? opts : args;
    rec({ t: 'spawn', via: fn, file: String(file), args: Array.isArray(args) ? args.map(String) : [], shell: !!(o && o.shell), cwd: o && o.cwd ? String(o.cwd) : null });
    return orig.apply(this, arguments);
  };
}
for (const fn of ['exec', 'execSync']) {
  const orig = cp[fn];
  cp[fn] = function (command) { rec({ t: 'spawn', via: fn, file: 'sh', args: [String(command)], shell: true, cwd: null }); return orig.apply(this, arguments); };
}
const origConnect = net.Socket.prototype.connect;
net.Socket.prototype.connect = function (...a) { const o = a[0]; rec({ t: 'net', target: typeof o === 'object' && o ? `${o.host || ''}:${o.port || o.path || ''}` : String(o) }); return origConnect.apply(this, a); };
for (const fn of ['lookup', 'resolve', 'resolve4', 'resolve6']) { const orig = dns[fn]; dns[fn] = function (host) { rec({ t: 'dns', host: String(host) }); return orig.apply(this, arguments); }; }
for (const m of [http, https]) for (const fn of ['request', 'get']) {
  const orig = m[fn];
  m[fn] = function (u) { rec({ t: 'http', url: typeof u === 'string' ? u : (u && (u.href || `${u.hostname || u.host}${u.path || ''}`)) || '' }); return orig.apply(this, arguments); };
}
if (typeof globalThis.fetch === 'function') { const of = globalThis.fetch; globalThis.fetch = function (u) { rec({ t: 'http', url: String(u && u.url ? u.url : u) }); return of.apply(this, arguments); }; }

const WRITES = ['writeFile', 'writeFileSync', 'appendFile', 'appendFileSync', 'mkdir', 'mkdirSync', 'rm', 'rmSync', 'unlink', 'unlinkSync', 'rename', 'renameSync', 'copyFile', 'copyFileSync', 'symlink', 'symlinkSync', 'createWriteStream', 'truncate', 'truncateSync', 'chmod', 'chmodSync'];
for (const fn of WRITES) {
  const orig = fs[fn]; if (typeof orig !== 'function') continue;
  fs[fn] = function (p) { if (p !== LOG) rec({ t: 'write', via: fn, path: path.resolve(String(p && p.href ? p.pathname : p)) }); return orig.apply(this, arguments); };
}
const READS = ['readFile', 'readFileSync', 'createReadStream', 'readdirSync', 'readdir'];
for (const fn of READS) {
  const orig = fs[fn];
  fs[fn] = function (p) {
    try {
      if (ROOTS && typeof p === 'string') {
        const r = path.resolve(p);
        const real = fs.existsSync(r) ? fs.realpathSync(r) : r;
        if (!ROOTS.some((x) => real.startsWith(x) || r.startsWith(x)) && !real.startsWith(TMP) && !real.startsWith(process.cwd()) && !/node_modules|\.agentic-security|\/\.config\/|\/\.claude\/|\/private\/var\/folders/.test(real)) rec({ t: 'read-outside', via: fn, path: r, real });
      }
    } catch { /* ignore */ }
    return orig.apply(this, arguments);
  };
}

// named imports (`import { execFileSync } from 'node:child_process'`) read the module's ESM facade, which is a snapshot until it is re-synced
syncBuiltinESMExports();
