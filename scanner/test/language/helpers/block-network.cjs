// Preload for offline assertions: every attempt to open a socket, resolve a name or call fetch is RECORDED to the file named by
// AGENTIC_SECURITY_NET_LOG and then refused. A scan that completes with an empty log made no network attempt at all.
const fs = require('node:fs');
const net = require('node:net');
const dns = require('node:dns');
const log = process.env.AGENTIC_SECURITY_NET_LOG;
const note = (what, target) => { try { if (log) fs.appendFileSync(log, `${what} ${String(target).slice(0, 200)}\n`); } catch { /* best effort */ } };
const refuse = (what, target) => { note(what, target); const e = new Error(`network blocked by the offline test: ${what} ${target}`); e.code = 'ENETBLOCKED'; throw e; };
const origConnect = net.Socket.prototype.connect;
net.Socket.prototype.connect = function (...a) {
  const o = a[0];
  // a unix-domain socket or a pipe is local IPC, not the network
  if (o && typeof o === 'object' && (o.path || o.fd !== undefined)) return origConnect.apply(this, a);
  if (typeof o === 'string' && !/^\d+$/.test(o)) return origConnect.apply(this, a);
  return refuse('connect', JSON.stringify(a[0]));
};
for (const k of ['lookup', 'resolve', 'resolve4', 'resolve6']) if (typeof dns[k] === 'function') dns[k] = (...a) => refuse(`dns.${k}`, a[0]);
if (typeof globalThis.fetch === 'function') globalThis.fetch = (u) => refuse('fetch', u && u.url ? u.url : u);
