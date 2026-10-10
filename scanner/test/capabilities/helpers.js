// Shared fixtures for the capability suites (X-501 to X-504). Not a test file.
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import { detectBackend } from '../../src/sandbox/capabilities.js';
import { resolveAssuranceConfig } from '../../src/posture/assurance/config.js';
import { bindManifest } from '../../src/capabilities/manifest.js';
import { runCapabilityTask } from '../../src/capabilities/runner.js';
import { mkTestTmp } from '../helpers/tmp.js';

export const REV = 'a'.repeat(40);
export const BACKEND = detectBackend();
export const CAN_RUN = BACKEND === 'userspace';
// A skip is a declared gap, never a pass. Every execution test names why.
export const SKIP = CAN_RUN ? false : `SKIPPED, NOT PASSED: execution tests need a probed userspace backend (selected '${BACKEND}'); UNVERIFIED here`;

export const CONFIG_ON = resolveAssuranceConfig({ env: { AGENTIC_SECURITY_ASSURANCE_CAPABILITY_ENFORCEMENT: '1' } });

export function tmp(prefix = 'cap-') { return fs.realpathSync(mkTestTmp(prefix)); }

export function manifest(over = {}) {
  return {
    schema: 'agentic-security/capability-manifest', schemaVersion: '1.0.0', taskId: 'task-1',
    repository: { revision: REV }, policyVersion: 1, ...over,
  };
}

export function bind(over = {}) {
  const r = bindManifest(manifest(over));
  if (!r.ok) throw new Error(`fixture manifest invalid: ${JSON.stringify(r.errors)}`);
  return r.bound;
}

export const ctxFor = (bound, extra = {}) => ({ binding: bound.binding, ...extra });

/** Run a task on this host: the dev opt-in is explicit because macOS is not an advertised backend. */
export function run(bound, request, opts = {}) {
  return runCapabilityTask(bound, request, { binding: bound.binding, config: CONFIG_ON, allowUnadvertisedBackend: true, ...opts });
}

export const alive = (pid) => { try { process.kill(pid, 0); return true; } catch (e) { return e.code === 'EPERM'; } };
export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** A loopback http server that records what it received. */
export function recordingServer(handler) {
  const seen = { requests: [], connections: 0 };
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      seen.requests.push({ method: req.method, url: req.url, headers: req.headers, body: Buffer.concat(chunks).toString('utf8') });
      if (handler) handler(req, res); else { res.writeHead(200, { 'content-type': 'text/plain' }); res.end('ok'); }
    });
  });
  server.on('connection', () => { seen.connections += 1; });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve({
      server, seen, port: server.address().port,
      close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(() => r()); }),
    }));
  });
}

/** A loopback tcp echo server (for CONNECT tunnels). */
export function echoServer() {
  const seen = { connections: 0 };
  const server = net.createServer((s) => { seen.connections += 1; s.on('data', (d) => s.write(d)); s.on('error', () => {}); });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve({ server, seen, port: server.address().port, close: () => new Promise((r) => server.close(() => r())) }));
  });
}

/** Send a proxy-style request (absolute URI) to a proxy and collect the response. */
export function viaProxy(proxyPort, { url, method = 'GET', headers = {}, body = null }) {
  return new Promise((resolve) => {
    let host = 'unknown';
    try { host = new URL(url).host; } catch { /* a path-only request line */ }
    const req = http.request({
      host: '127.0.0.1', port: proxyPort, method, path: url, headers: { host, ...headers }, agent: false,
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('error', (e) => resolve({ error: e.code || e.message }));
    req.setTimeout(5000, () => req.destroy());
    if (body !== null) req.write(body);
    req.end();
  });
}
