// The mediated network boundary (X-504.AC01, X-504.AC03).
//
// The runner starts one of these per task that declares network destinations and
// opens exactly its loopback port in the sandbox profile. Everything else is
// closed by the operating system: DNS, every other loopback port, every remote
// address, every unix socket. A child, a descendant or an interpreter that
// ignores the proxy settings and opens a socket itself is refused by the kernel,
// not by this file; this file decides what the ONE open door lets through.
//
// Per request:
//   1. the destination is checked against the bound manifest (`decide`, kind
//      'network') before any name is resolved
//   2. the name is resolved ONCE, in this process (the sandbox cannot resolve),
//      the resolved addresses are checked (a declared name that resolves to a
//      loopback, private, link-local or metadata address is refused unless the
//      entry says so; a pinned address set must match), and the connection goes to
//      the address that was checked, so a name that changes between check and
//      connect cannot redirect the connection
//   3. plaintext HTTP is buffered (bounded), filtered with `redactOutbound`, and
//      forwarded; a binary body that cannot be inspected is refused
//   4. HTTPS is an opaque CONNECT tunnel, allowed only to a destination declared
//      for the https scheme. Its payload is NOT inspected and the report says so.
//   5. a redirect is returned to the client unchanged and never followed here, so
//      the next hop arrives as a new request and meets step 1 again
//
// A denial records the destination class, a digest of the host, the port and the
// policy code. It never records a path, header, body or the host name itself.
import dns from 'node:dns';
import http from 'node:http';
import net from 'node:net';
import { decide } from './decide.js';
import { redactOutbound, denialRecord, recordNetworkDenial } from './outbound.js';
import { normalizeHost } from './address.js';

const HOP_BY_HOP = new Set([
  'connection', 'proxy-connection', 'proxy-authorization', 'proxy-authenticate', 'keep-alive', 'te', 'trailer',
  'transfer-encoding', 'upgrade', 'content-length',
]);
const MAX_RECORDS = 1000;

async function defaultResolve(host) {
  const rows = await dns.promises.lookup(host, { all: true });
  return rows.map((r) => r.address);
}

/**
 * @param {object} o
 * @param {{manifest: object, binding: object}} o.bound
 * @param {string[]} [o.canaries]
 * @param {(host:string)=>Promise<string[]>} [o.resolve]   test seam for name resolution
 * @param {number} [o.maxRequestBytes]
 * @param {string} [o.scanRoot]   when set, denials are appended to the egress audit chain
 * @param {number} [o.connectTimeoutMs]
 */
export async function startMediationProxy({
  bound, canaries = [], resolve = defaultResolve, maxRequestBytes = 1024 * 1024, scanRoot = null, connectTimeoutMs = 8000,
}) {
  const records = [];
  const sockets = new Set();
  const stats = { allowed: 0, denied: 0, redactions: 0, bytesForwarded: 0 };
  const ctx = { binding: bound.binding, canaries };

  const note = (outcome, code, host, port, scheme) => {
    const rec = denialRecord({ taskId: bound.binding.taskId, host, port, scheme, code });
    const entry = { ...rec, outcome };
    if (records.length < MAX_RECORDS) records.push(entry);
    if (outcome === 'deny') { stats.denied += 1; recordNetworkDenial(scanRoot, rec); } else stats.allowed += 1;
  };

  // Decide on the declared destination, resolve, decide again on the addresses.
  async function authorize(rawHost, port, scheme) {
    const first = decide(bound, { kind: 'network', host: rawHost, port, scheme }, ctx);
    if (first.decision !== 'allow') return { ok: false, code: first.code };
    const h = normalizeHost(rawHost);
    let addresses;
    if (h.kind === 'name') {
      try { addresses = await resolve(h.host); } catch { addresses = []; }
      if (!Array.isArray(addresses) || !addresses.every((a) => net.isIP(a))) addresses = [];
    } else addresses = [h.host];
    const second = decide(bound, { kind: 'network', host: rawHost, port, scheme, resolvedAddresses: addresses }, ctx);
    if (second.decision !== 'allow') return { ok: false, code: second.code };
    return { ok: true, address: addresses[0], host: h.host };
  }

  function deny(res, code) {
    if (res.headersSent) { res.destroy(); return; }
    const body = JSON.stringify({ blocked: true, code });
    res.writeHead(403, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body), connection: 'close' });
    res.end(body);
  }

  const server = http.createServer((req, res) => {
    handle(req, res).catch(() => deny(res, 'invalid-manifest'));
  });
  server.on('connection', (s) => { sockets.add(s); s.on('close', () => sockets.delete(s)); });
  server.keepAliveTimeout = 1000;

  async function handle(req, res) {
    let target;
    try { target = new URL(req.url); } catch { target = null; }
    if (!target || target.protocol !== 'http:') {
      // An origin-form request is a client talking to the proxy as if it were a
      // server; an https:// absolute URI is a client that skipped CONNECT.
      note('deny', 'destination-not-declared', req.headers.host || '', 0, null);
      return deny(res, 'destination-not-declared');
    }
    const port = target.port ? Number(target.port) : 80;
    const auth = await authorize(target.hostname, port, 'http');
    if (!auth.ok) { note('deny', auth.code, target.hostname, port, 'http'); return deny(res, auth.code); }

    const chunks = []; let size = 0; let tooBig = false;
    await new Promise((done) => {
      req.on('data', (c) => { size += c.length; if (size > maxRequestBytes) { tooBig = true; req.destroy(); done(); } else chunks.push(c); });
      req.on('end', done); req.on('error', done); req.on('close', done);
    });
    if (tooBig) { note('deny', 'payload-too-large', target.hostname, port, 'http'); return deny(res, 'payload-too-large'); }
    const body = chunks.length ? Buffer.concat(chunks) : null;
    const filtered = redactOutbound({ url: req.url, headers: req.headers, body, contentType: req.headers['content-type'] }, { canaries });
    if (filtered.uninspectable) { note('deny', 'payload-uninspectable', target.hostname, port, 'http'); return deny(res, 'payload-uninspectable'); }
    stats.redactions += filtered.redactions;

    const out = {};
    for (const [k, v] of Object.entries(filtered.headers)) if (!HOP_BY_HOP.has(k) && k !== 'host') out[k] = v;
    out.host = target.port ? `${target.hostname}:${target.port}` : target.hostname;
    out.connection = 'close';
    if (filtered.body !== null) out['content-length'] = Buffer.byteLength(filtered.body);
    const fu = new URL(filtered.url);
    const upstream = http.request({
      host: auth.address, port, method: req.method, path: `${fu.pathname}${fu.search}`, headers: out, setHost: false,
      timeout: connectTimeoutMs, agent: false,
    });
    note('allow', 'allowed', target.hostname, port, 'http');
    upstream.on('timeout', () => upstream.destroy(new Error('timeout')));
    upstream.on('error', () => deny(res, 'destination-not-declared'));
    upstream.on('response', (up) => {
      const headers = {};
      for (const [k, v] of Object.entries(up.headers)) if (!HOP_BY_HOP.has(k)) headers[k] = v;
      headers.connection = 'close';
      res.writeHead(up.statusCode || 502, headers);
      up.on('data', (c) => { stats.bytesForwarded += c.length; });
      up.pipe(res);
    });
    if (filtered.body !== null) upstream.write(filtered.body);
    upstream.end();
  }

  server.on('connect', (req, client, head) => {
    sockets.add(client); client.on('close', () => sockets.delete(client));
    client.on('error', () => client.destroy());
    (async () => {
      const m = /^(\[[0-9a-fA-F:.]+\]|[^:\s]+):(\d{1,5})$/.exec(req.url || '');
      if (!m) { note('deny', 'host-invalid', '', 0, 'https'); client.end('HTTP/1.1 403 Forbidden\r\nconnection: close\r\n\r\n'); return; }
      const port = Number(m[2]);
      const auth = await authorize(m[1], port, 'https');
      if (!auth.ok) { note('deny', auth.code, m[1], port, 'https'); client.end('HTTP/1.1 403 Forbidden\r\nconnection: close\r\n\r\n'); return; }
      const upstream = net.connect({ host: auth.address, port, timeout: connectTimeoutMs });
      sockets.add(upstream); upstream.on('close', () => sockets.delete(upstream));
      upstream.on('timeout', () => upstream.destroy());
      upstream.on('error', () => { client.destroy(); });
      client.on('close', () => upstream.destroy());
      upstream.on('connect', () => {
        note('allow', 'allowed', m[1], port, 'https');
        client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        if (head && head.length) upstream.write(head);
        upstream.pipe(client); client.pipe(upstream);
      });
    })().catch(() => client.destroy());
  });

  await new Promise((resolveListen, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolveListen); });
  const port = server.address().port;
  return {
    port,
    url: `http://127.0.0.1:${port}`,
    records,
    stats,
    async close() {
      for (const s of sockets) { try { s.destroy(); } catch { /* ignore */ } }
      await new Promise((r) => server.close(() => r()));
    },
  };
}
