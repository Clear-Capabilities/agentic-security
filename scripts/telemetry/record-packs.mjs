#!/usr/bin/env node
// Records REAL telemetry exports for the runtime-corroboration adapters, so the adapters are tested against what the real tools write
// and not against what a person guessed they write. Each source runs the real tool, captures the file it produces, and writes it
// untouched next to a manifest line naming the tool, its version, the exact command and the digest of the capture.
//
//   node scripts/telemetry/record-packs.mjs --out <dir> [--source otel,envoy,http,k8s]
//
// Needs network (npm, container images, kind) and a container engine for envoy, http and k8s, so it runs in the hosted `telemetry-capture`
// job. A source whose tool is missing FAILS; it is never skipped, because a pack that was not recorded is not evidence.
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as http from 'node:http';
import * as crypto from 'node:crypto';
import { spawnSync, spawn } from 'node:child_process';

const args = process.argv.slice(2);
const flag = (n, d = null) => { const i = args.indexOf(`--${n}`); return i >= 0 ? args[i + 1] : d; };
const OUT = path.resolve(flag('out', 'telemetry-packs'));
const SOURCES = (flag('source', 'otel,envoy,http,k8s')).split(',');
fs.mkdirSync(OUT, { recursive: true });

const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');
const run = (cmd, a, o = {}) => { const r = spawnSync(cmd, a, { encoding: 'utf8', ...o }); if (r.error) throw r.error; return r; };
const must = (cmd, a, o = {}) => { const r = run(cmd, a, o); if (r.status !== 0) throw new Error(`${cmd} ${a.join(' ')} exited ${r.status}\n${r.stderr || r.stdout}`); return r; };
/** Run a child without blocking this process, which is serving the receiver the child posts to. */
const runAsync = (cmd, a, o = {}) => new Promise((resolve, reject) => {
  const c = spawn(cmd, a, { encoding: 'utf8', ...o });
  let err = '';
  c.stderr?.on('data', (d) => { err += d; });
  c.on('error', reject);
  c.on('close', (code) => (code === 0 ? resolve() : reject(new Error(`${cmd} ${a.join(' ')} exited ${code}\n${err}`))));
});
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const manifest = [];

function record(source, file, text, tool, version, command) {
  fs.mkdirSync(path.join(OUT, source), { recursive: true });
  fs.writeFileSync(path.join(OUT, source, file), text);
  manifest.push({ source, file, tool, version, command, sha256: sha(text), bytes: Buffer.byteLength(text), recordedAt: new Date().toISOString(), host: `${os.platform()}-${os.arch()}` });
  console.log(`recorded ${source}/${file} (${Buffer.byteLength(text)} bytes) from ${tool} ${version}`);
}

/** A local HTTP server the recorded tools talk to. `handler(req,res,body)`. */
function server(handler) {
  return new Promise((resolve) => {
    const s = http.createServer((req, res) => {
      const chunks = [];
      req.on('data', (c) => chunks.push(c));
      req.on('end', () => handler(req, res, Buffer.concat(chunks).toString('utf8')));
    });
    s.listen(0, '127.0.0.1', () => resolve({ s, port: s.address().port }));
  });
}

// ---------------------------------------------------------------------------------------------------------------- OpenTelemetry
// The real OpenTelemetry JavaScript SDK and its real OTLP/JSON HTTP exporter produce the document; a local server takes the POST.
async function otel() {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'otel-rec-'));
  const VERSIONS = { '@opentelemetry/api': '1.9.0', '@opentelemetry/sdk-trace-base': '1.30.1', '@opentelemetry/exporter-trace-otlp-http': '0.57.2', '@opentelemetry/resources': '1.30.1', '@opentelemetry/semantic-conventions': '1.28.0' };
  fs.writeFileSync(path.join(work, 'package.json'), JSON.stringify({ name: 'otel-rec', version: '1.0.0', type: 'module', dependencies: VERSIONS }));
  must('npm', ['install', '--no-audit', '--no-fund', '--ignore-scripts'], { cwd: work });
  let body = null;
  const { s, port } = await server((req, res, b) => { if (req.url === '/v1/traces') body = b; res.writeHead(200, { 'content-type': 'application/json' }); res.end('{}'); });
  const prog = `
import { BasicTracerProvider, BatchSpanProcessor } from '@opentelemetry/sdk-trace-base';
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-http';
import { Resource } from '@opentelemetry/resources';
import { SpanKind } from '@opentelemetry/api';
const provider = new BasicTracerProvider({ resource: new Resource({ 'service.name': 'orders-api' }) });
provider.addSpanProcessor(new BatchSpanProcessor(new OTLPTraceExporter({ url: 'http://127.0.0.1:${port}/v1/traces' })));
const tracer = provider.getTracer('recorder');
const calls = [
  { name: 'POST /charge', kind: SpanKind.CLIENT, attributes: { 'server.address': 'api.payments.example', 'server.port': 443, 'url.scheme': 'https', 'network.protocol.name': 'http' } },
  { name: 'SELECT orders', kind: SpanKind.CLIENT, attributes: { 'db.system': 'postgresql', 'db.name': 'orders', 'server.address': 'db.internal', 'server.port': 5432 } },
  { name: 'publish orders', kind: SpanKind.PRODUCER, attributes: { 'messaging.system': 'kafka', 'messaging.destination.name': 'orders-created' } },
];
for (const c of calls) { const sp = tracer.startSpan(c.name, { kind: c.kind, attributes: c.attributes }); sp.end(); }
await provider.forceFlush(); await provider.shutdown();
`;
  fs.writeFileSync(path.join(work, 'rec.mjs'), prog);
  await runAsync('node', ['rec.mjs'], { cwd: work });
  s.close();
  if (!body) throw new Error('the OpenTelemetry exporter posted nothing');
  record('otel', 'traces.otlp.json', body, 'opentelemetry-js', JSON.stringify(VERSIONS), 'BasicTracerProvider + OTLPTraceExporter (OTLP/JSON over HTTP) to a local receiver');
}

// ---------------------------------------------------------------------------------------------------------------------- Envoy
const ENVOY_IMAGE = 'envoyproxy/envoy:v1.31.2';
async function envoy() {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'envoy-rec-'));
  const up = await server((req, res) => { res.writeHead(200); res.end('ok'); });
  const upDeadPort = 9; // nothing listens: Envoy reports an upstream connection failure
  const cfg = `
static_resources:
  listeners:
  - name: l
    address: { socket_address: { address: 127.0.0.1, port_value: 18080 } }
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: ingress
          access_log:
          - name: envoy.access_loggers.file
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.access_loggers.file.v3.FileAccessLog
              path: /dev/stdout
              log_format:
                json_format:
                  start_time: "%START_TIME%"
                  duration: "%DURATION%"
                  protocol: "%PROTOCOL%"
                  response_code: "%RESPONSE_CODE%"
                  response_flags: "%RESPONSE_FLAGS%"
                  upstream_host: "%UPSTREAM_HOST%"
                  upstream_cluster: "%UPSTREAM_CLUSTER%"
          route_config:
            virtual_hosts:
            - name: all
              domains: ["*"]
              routes:
              - match: { prefix: "/ok" }
                route: { cluster: healthy }
              - match: { prefix: "/down" }
                route: { cluster: dead }
          http_filters:
          - name: envoy.filters.http.router
            typed_config: { "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router }
  clusters:
  - name: healthy
    type: STATIC
    load_assignment: { cluster_name: healthy, endpoints: [{ lb_endpoints: [{ endpoint: { address: { socket_address: { address: 127.0.0.1, port_value: ${up.port} } } } }] }] }
  - name: dead
    type: STATIC
    connect_timeout: 1s
    load_assignment: { cluster_name: dead, endpoints: [{ lb_endpoints: [{ endpoint: { address: { socket_address: { address: 127.0.0.1, port_value: ${upDeadPort} } } } }] }] }
`.replace('- name: healthy\n    type: STATIC', '- name: healthy\n    type: STATIC\n    connect_timeout: 1s');
  fs.writeFileSync(path.join(work, 'envoy.yaml'), cfg);
  must('docker', ['rm', '-f', 'telemetry-envoy'], {});
  must('docker', ['run', '-d', '--name', 'telemetry-envoy', '--network', 'host', '-v', `${work}/envoy.yaml:/etc/envoy/envoy.yaml:ro`, ENVOY_IMAGE, '-c', '/etc/envoy/envoy.yaml']);
  let ready = false;
  for (let i = 0; i < 40 && !ready; i++) { await sleep(500); ready = run('curl', ['-s', '-o', '/dev/null', 'http://127.0.0.1:18080/ok']).status === 0; }
  if (!ready) { console.error(run('docker', ['logs', 'telemetry-envoy']).stdout); throw new Error('envoy did not start'); }
  for (let i = 0; i < 3; i++) run('curl', ['-s', '-o', '/dev/null', 'http://127.0.0.1:18080/ok']);
  run('curl', ['-s', '-o', '/dev/null', 'http://127.0.0.1:18080/down']);
  run('curl', ['-s', '-o', '/dev/null', 'http://127.0.0.1:18080/nowhere']);
  // Envoy flushes a file access log on an interval (10 seconds by default), so a graceful stop is what guarantees every line is out
  must('docker', ['stop', '-t', '10', 'telemetry-envoy']);
  const logs = run('docker', ['logs', 'telemetry-envoy']);
  const lines = `${logs.stdout}\n${logs.stderr}`.split('\n').filter((l) => l.startsWith('{') && l.includes('"upstream_cluster"'));
  const version = must('docker', ['run', '--rm', ENVOY_IMAGE, '--version']).stdout.trim().split('\n')[0];
  run('docker', ['rm', '-f', 'telemetry-envoy']);
  up.s.close();
  if (lines.length < 5) { console.error(`${logs.stdout}\n${logs.stderr}`); throw new Error(`envoy wrote ${lines.length} access-log lines, expected 5`); }
  record('envoy', 'access.jsonl', lines.join('\n') + '\n', ENVOY_IMAGE, version, 'envoy json_format access log on stdout; 3 routed, 1 to a closed upstream, 1 with no route');
}

// ---------------------------------------------------------------------------------------------------------------------- nginx
const NGINX_IMAGE = 'nginx:1.27';
async function httpLog() {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'nginx-rec-'));
  const up = await server((req, res) => { res.writeHead(200); res.end('ok'); });
  const conf = `
events {}
http {
  log_format structured escape=json '{"timestamp":"$time_iso8601","host":"$host","upstream":"$upstream_addr","scheme":"$scheme","status":"$status"}';
  access_log /dev/stdout structured;
  server {
    listen 18081;
    location / { proxy_pass http://127.0.0.1:${up.port}; }
  }
}
`;
  fs.writeFileSync(path.join(work, 'nginx.conf'), conf);
  run('docker', ['rm', '-f', 'telemetry-nginx']);
  must('docker', ['run', '-d', '--name', 'telemetry-nginx', '--network', 'host', '-v', `${work}/nginx.conf:/etc/nginx/nginx.conf:ro`, NGINX_IMAGE]);
  let ready = false;
  for (let i = 0; i < 40 && !ready; i++) { await sleep(500); ready = run('curl', ['-s', '-o', '/dev/null', 'http://127.0.0.1:18081/']).status === 0; }
  if (!ready) { console.error(run('docker', ['logs', 'telemetry-nginx']).stderr); throw new Error('nginx did not start'); }
  for (const h of ['shop.example', 'api.example', 'shop.example']) run('curl', ['-s', '-o', '/dev/null', '-H', `Host: ${h}`, 'http://127.0.0.1:18081/items?token=abc']);
  await sleep(1000);
  const logs = run('docker', ['logs', 'telemetry-nginx']);
  const lines = `${logs.stdout}\n${logs.stderr}`.split('\n').filter((l) => l.startsWith('{"timestamp"'));
  const version = must('docker', ['run', '--rm', NGINX_IMAGE, 'nginx', '-v']).stderr.trim();
  run('docker', ['rm', '-f', 'telemetry-nginx']);
  up.s.close();
  if (lines.length < 3) { console.error(`${logs.stdout}\n${logs.stderr}`); throw new Error(`nginx wrote ${lines.length} access-log lines, expected at least 3`); }
  record('http', 'access.jsonl', lines.join('\n') + '\n', NGINX_IMAGE, version, 'nginx log_format with escape=json (host, upstream, scheme, status) on stdout; three proxied requests');
}

// ------------------------------------------------------------------------------------------------------------ Kubernetes audit
const KIND_VERSION = 'v0.25.0';
async function k8s() {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'k8s-rec-'));
  const kind = path.join(work, 'kind');
  const arch = os.arch() === 'arm64' ? 'arm64' : 'amd64';
  must('curl', ['-sSL', '-o', kind, `https://kind.sigs.k8s.io/dl/${KIND_VERSION}/kind-linux-${arch}`]);
  fs.chmodSync(kind, 0o755);
  fs.writeFileSync(path.join(work, 'audit-policy.yaml'), `apiVersion: audit.k8s.io/v1
kind: Policy
omitStages: ["RequestReceived"]
rules:
- level: Metadata
`);
  fs.writeFileSync(path.join(work, 'kind.yaml'), `kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  kubeadmConfigPatches:
  - |
    kind: ClusterConfiguration
    apiServer:
      extraArgs:
        audit-policy-file: /etc/kubernetes/policies/audit-policy.yaml
        audit-log-path: /var/log/kubernetes/audit.log
      extraVolumes:
      - name: policies
        hostPath: /etc/kubernetes/policies
        mountPath: /etc/kubernetes/policies
        readOnly: true
        pathType: DirectoryOrCreate
      - name: logs
        hostPath: /var/log/kubernetes
        mountPath: /var/log/kubernetes
        readOnly: false
        pathType: DirectoryOrCreate
  extraMounts:
  - hostPath: ${path.join(work, 'audit-policy.yaml')}
    containerPath: /etc/kubernetes/policies/audit-policy.yaml
    readOnly: true
`);
  must(kind, ['create', 'cluster', '--name', 'telemetry', '--config', path.join(work, 'kind.yaml'), '--wait', '120s'], { stdio: 'inherit' });
  try {
    const kc = (...a) => run('kubectl', ['--context', 'kind-telemetry', ...a]);
    kc('create', 'namespace', 'payments');
    kc('-n', 'payments', 'create', 'configmap', 'settings', '--from-literal=mode=live');
    kc('-n', 'payments', 'get', 'configmap', 'settings');
    kc('-n', 'payments', 'create', 'secret', 'generic', 'db', '--from-literal=pw=x');
    kc('-n', 'payments', 'get', 'secret', 'db');
    kc('-n', 'payments', 'get', 'pods');
    kc('--as=system:anonymous', '-n', 'payments', 'get', 'secrets'); // forbidden: a 403 in the audit log
    kc('-n', 'payments', 'get', 'configmap', 'does-not-exist'); // not found: a 404
    await sleep(3000);
    const cat = must('docker', ['exec', 'telemetry-control-plane', 'cat', '/var/log/kubernetes/audit.log']).stdout;
    const version = must('kubectl', ['--context', 'kind-telemetry', 'version', '-o', 'json']).stdout;
    const sv = JSON.parse(version).serverVersion?.gitVersion || 'unknown';
    // keep the events that touch the namespace we drove, so the capture is small and about what we did; every line is untouched
    const lines = cat.split('\n').filter((l) => l.startsWith('{') && /"namespace":"payments"|"resource":"namespaces"/.test(l) && l.includes('"stage":"ResponseComplete"'));
    if (lines.length < 5) throw new Error(`the audit log held ${lines.length} matching events, expected at least 5`);
    record('k8s', 'audit.jsonl', lines.join('\n') + '\n', `kind ${KIND_VERSION}`, sv, 'kube-apiserver file audit backend, policy level Metadata; namespace, configmap, secret, forbidden and not-found requests');
  } finally { run(kind, ['delete', 'cluster', '--name', 'telemetry']); }
}

const RUN = { otel, envoy, http: httpLog, k8s };
// Every source is attempted so one run reports on all of them, and the run fails if any did not record: a pack that was not recorded
// is not evidence, and a partial manifest is written only so the sources that did record can be inspected.
const failed = [];
for (const s of SOURCES) {
  if (!RUN[s]) throw new Error(`unknown source: ${s}`);
  console.log(`\n== ${s} ==`);
  try { await RUN[s](); } catch (e) { failed.push(s); console.error(`FAILED ${s}: ${e.message}`); }
}
fs.writeFileSync(path.join(OUT, 'MANIFEST.json'), JSON.stringify({ recorder: 'scripts/telemetry/record-packs.mjs', packs: manifest }, null, 2) + '\n');
console.log(`\nwrote ${manifest.length} pack(s) to ${OUT}`);
if (failed.length) { console.error(`did not record: ${failed.join(', ')}`); process.exit(1); }
