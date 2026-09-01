// Real end-to-end HTTP requests against a real, started `explore` server.
// Node's own http.request — no test-only shortcut — per the plan's own
// requirement that T2/T3 get a LIVE regression guard, not just a unit test
// of the pure security.js functions in isolation.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as http from 'node:http';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createExploreServer, TOKEN_HEADER } from '../../src/server/http-server.js';
import { generateSessionToken } from '../../src/server/security.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURE_PATH = path.join(__dirname, '..', '..', 'src', 'lineage', 'fixtures', 'flagship-graph.json');
const GRAPH = JSON.parse(fs.readFileSync(FIXTURE_PATH, 'utf8'));

/** One real HTTP request. Resolves {status, headers, body(parsed if JSON)}. */
function request(port, { method = 'GET', path: reqPath = '/', headers = {} } = {}, body = null) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { hostname: '127.0.0.1', port, path: reqPath, method, headers },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const raw = Buffer.concat(chunks).toString('utf8');
          let parsed = raw;
          try { parsed = JSON.parse(raw); } catch { /* not JSON, keep raw */ }
          resolve({ status: res.statusCode, headers: res.headers, body: parsed });
        });
      },
    );
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

async function startTestServer(overrides = {}) {
  const sessionToken = generateSessionToken();
  const { server, port } = await createExploreServer({
    graph: GRAPH,
    port: 0,
    sessionToken,
    idleTimeoutMs: 5 * 60 * 1000, // long enough that ordinary tests never hit it
    keepOpen: false,
    ...overrides,
  });
  return { server, port, sessionToken };
}

test('valid token + valid Host -> 200 with real data on every one of the five endpoints', async () => {
  const { server, port, sessionToken } = await startTestServer();
  try {
    const ids = { node: GRAPH.nodes[0].id, edge: GRAPH.edges[0].id, flow: GRAPH.flows[0].id };
    const cases = [
      ['/api/v1/scan', 'scanHealth'],
      ['/api/v1/graph', 'nodes'],
      [`/api/v1/nodes/${encodeURIComponent(ids.node)}`, 'id'],
      [`/api/v1/edges/${encodeURIComponent(ids.edge)}`, 'id'],
      [`/api/v1/flows/${encodeURIComponent(ids.flow)}`, 'id'],
    ];
    for (const [p] of cases) {
      const res = await request(port, {
        path: p,
        headers: { host: `127.0.0.1:${port}`, [TOKEN_HEADER]: sessionToken },
      });
      assert.equal(res.status, 200, `expected 200 for ${p}, got ${res.status}: ${JSON.stringify(res.body)}`);
      assert.equal(typeof res.body, 'object');
      assert.equal(res.body.digest, GRAPH.graphId);
    }
  } finally {
    server.close();
  }
});

test('T2 regression guard: a forged Host header is rejected with 400 on a REAL running server', async () => {
  const { server, port, sessionToken } = await startTestServer();
  try {
    const res = await request(port, {
      path: '/api/v1/scan',
      headers: { host: 'evil.example.com', [TOKEN_HEADER]: sessionToken },
    });
    assert.equal(res.status, 400);
    assert.match(res.body.error, /Host/i);
  } finally {
    server.close();
  }
});

test('T2 regression guard: a Host header naming the right IP but wrong port is rejected', async () => {
  const { server, port, sessionToken } = await startTestServer();
  try {
    const res = await request(port, {
      path: '/api/v1/scan',
      headers: { host: `127.0.0.1:1`, [TOKEN_HEADER]: sessionToken },
    });
    assert.equal(res.status, 400);
  } finally {
    server.close();
  }
});

test('T3 regression guard: a missing session token is rejected with 401 on every one of the five endpoints, on a REAL running server', async () => {
  const { server, port } = await startTestServer();
  try {
    const ids = { node: GRAPH.nodes[0].id, edge: GRAPH.edges[0].id, flow: GRAPH.flows[0].id };
    const paths = [
      '/api/v1/scan',
      '/api/v1/graph',
      `/api/v1/nodes/${encodeURIComponent(ids.node)}`,
      `/api/v1/edges/${encodeURIComponent(ids.edge)}`,
      `/api/v1/flows/${encodeURIComponent(ids.flow)}`,
    ];
    for (const p of paths) {
      const res = await request(port, { path: p, headers: { host: `127.0.0.1:${port}` } });
      assert.equal(res.status, 401, `expected 401 for ${p} with no token, got ${res.status}`);
    }
  } finally {
    server.close();
  }
});

test('T3 regression guard: a WRONG session token is rejected with 401 on every one of the five endpoints', async () => {
  const { server, port } = await startTestServer();
  try {
    const wrongToken = generateSessionToken(); // real shape, wrong value
    const ids = { node: GRAPH.nodes[0].id, edge: GRAPH.edges[0].id, flow: GRAPH.flows[0].id };
    const paths = [
      '/api/v1/scan',
      '/api/v1/graph',
      `/api/v1/nodes/${encodeURIComponent(ids.node)}`,
      `/api/v1/edges/${encodeURIComponent(ids.edge)}`,
      `/api/v1/flows/${encodeURIComponent(ids.flow)}`,
    ];
    for (const p of paths) {
      const res = await request(port, {
        path: p,
        headers: { host: `127.0.0.1:${port}`, [TOKEN_HEADER]: wrongToken },
      });
      assert.equal(res.status, 401, `expected 401 for ${p} with a wrong token, got ${res.status}`);
    }
  } finally {
    server.close();
  }
});

test('response headers include the CSP value and Cache-Control: no-store, and EXCLUDE Access-Control-Allow-Origin — on both a 200 and a rejected request', async () => {
  const { server, port, sessionToken } = await startTestServer();
  try {
    const ok = await request(port, {
      path: '/api/v1/scan',
      headers: { host: `127.0.0.1:${port}`, [TOKEN_HEADER]: sessionToken },
    });
    assert.equal(ok.status, 200);
    assert.match(ok.headers['content-security-policy'] || '', /default-src 'none'/);
    assert.equal(ok.headers['cache-control'], 'no-store');
    assert.equal(ok.headers['access-control-allow-origin'], undefined);

    const rejected = await request(port, {
      path: '/api/v1/scan',
      headers: { host: 'evil.example.com' },
    });
    assert.equal(rejected.status, 400);
    assert.match(rejected.headers['content-security-policy'] || '', /default-src 'none'/);
    assert.equal(rejected.headers['cache-control'], 'no-store');
    assert.equal(rejected.headers['access-control-allow-origin'], undefined);
  } finally {
    server.close();
  }
});

test('an unknown route -> 404', async () => {
  const { server, port, sessionToken } = await startTestServer();
  try {
    const res = await request(port, {
      path: '/api/v1/nope',
      headers: { host: `127.0.0.1:${port}`, [TOKEN_HEADER]: sessionToken },
    });
    assert.equal(res.status, 404);
  } finally {
    server.close();
  }
});

test('an oversized request body is rejected with 413 before being handled', async () => {
  const { server, port, sessionToken } = await startTestServer();
  try {
    const big = 'x'.repeat(70 * 1024); // > MAX_REQUEST_BODY_BYTES (64KB)
    const res = await request(
      port,
      {
        method: 'POST',
        path: '/api/v1/scan',
        headers: {
          host: `127.0.0.1:${port}`,
          [TOKEN_HEADER]: sessionToken,
          'content-type': 'text/plain',
          'content-length': Buffer.byteLength(big),
        },
      },
      big,
    );
    assert.equal(res.status, 413);
  } finally {
    server.close();
  }
});

test('binds only to 127.0.0.1 (server.address().address is the loopback literal)', async () => {
  const { server } = await startTestServer();
  try {
    const addr = server.address();
    assert.equal(addr.address, '127.0.0.1');
  } finally {
    server.close();
  }
});

test('idle-timeout auto-stop: a short-timeout server genuinely closes itself', async () => {
  const sessionToken = generateSessionToken();
  const { server, port } = await createExploreServer({
    graph: GRAPH,
    port: 0,
    sessionToken,
    idleTimeoutMs: 150,
    keepOpen: false,
  });
  assert.equal(server.listening, true);

  // Confirm it's genuinely alive first.
  const alive = await request(port, {
    path: '/api/v1/scan',
    headers: { host: `127.0.0.1:${port}`, [TOKEN_HEADER]: sessionToken },
  });
  assert.equal(alive.status, 200);

  // Wait past the idle timeout with NO further traffic.
  await new Promise((r) => setTimeout(r, 400));

  assert.equal(server.listening, false, 'server must have auto-stopped after the idle timeout');
  await assert.rejects(
    () => request(port, { path: '/api/v1/scan', headers: { host: `127.0.0.1:${port}`, [TOKEN_HEADER]: sessionToken } }),
    /ECONNREFUSED/,
    'a new connection must be refused once the server has genuinely closed',
  );
});

test('--keep-open (keepOpen: true) suppresses idle-timeout auto-stop', async () => {
  const sessionToken = generateSessionToken();
  const { server, port } = await createExploreServer({
    graph: GRAPH,
    port: 0,
    sessionToken,
    idleTimeoutMs: 150,
    keepOpen: true,
  });
  try {
    // Wait well past what would have been the idle timeout.
    await new Promise((r) => setTimeout(r, 400));
    assert.equal(server.listening, true, 'keepOpen:true must prevent auto-stop');
    const res = await request(port, {
      path: '/api/v1/scan',
      headers: { host: `127.0.0.1:${port}`, [TOKEN_HEADER]: sessionToken },
    });
    assert.equal(res.status, 200);
  } finally {
    server.close();
  }
});

test('createExploreServer rejects a missing/short sessionToken rather than starting insecurely', () => {
  // These validation failures are synchronous (thrown before the Promise is
  // ever constructed) — assert.throws, not assert.rejects.
  assert.throws(() => createExploreServer({ graph: GRAPH, sessionToken: 'too-short' }));
  assert.throws(() => createExploreServer({ graph: GRAPH }));
});

test('createExploreServer rejects a missing graph', () => {
  assert.throws(() => createExploreServer({ sessionToken: generateSessionToken() }));
});

// --- Milestone 3, sub-project Wire: static-asset serving ---
// Real, live HTTP requests against a real running server — same discipline
// as the rest of this file — proving the deliberate token-exemption AND the
// allowlist/path-confinement both hold under actual network traffic, not
// just the pure-function unit tests in static-assets.test.js.

test('GET / with NO session token succeeds — the ONE deliberate unauthenticated exception — and serves the real index.html markup', async () => {
  const { server, port } = await startTestServer();
  try {
    const res = await request(port, { path: '/', headers: { host: `127.0.0.1:${port}` } });
    assert.equal(res.status, 200);
    assert.match(String(res.body), /<div id="app-root">/);
    assert.match(String(res.body), /src="\.\/src\/main\.js"/);
  } finally {
    server.close();
  }
});

test('GET /api/v1/graph with NO token still returns 401 — unchanged from S1, the exemption is static-asset-only', async () => {
  const { server, port } = await startTestServer();
  try {
    const res = await request(port, { path: '/api/v1/graph', headers: { host: `127.0.0.1:${port}` } });
    assert.equal(res.status, 401);
  } finally {
    server.close();
  }
});

test('static routes still carry the SEPARATE static CSP (same-origin-permitting), not the JSON API\'s default-src none', async () => {
  const { server, port } = await startTestServer();
  try {
    const res = await request(port, { path: '/', headers: { host: `127.0.0.1:${port}` } });
    assert.equal(res.status, 200);
    assert.match(res.headers['content-security-policy'] || '', /script-src 'self'/);
    assert.doesNotMatch(res.headers['content-security-policy'] || '', /default-src 'none'/);
    assert.equal(res.headers['cache-control'], 'no-store');
    assert.equal(res.headers['access-control-allow-origin'], undefined);
    assert.match(res.headers['content-type'] || '', /text\/html/);
  } finally {
    server.close();
  }
});

test('an allowlisted JS asset is served with the right Content-Type', async () => {
  const { server, port } = await startTestServer();
  try {
    const res = await request(port, { path: '/src/app.js', headers: { host: `127.0.0.1:${port}` } });
    assert.equal(res.status, 200);
    assert.match(res.headers['content-type'] || '', /text\/javascript/);
    assert.match(String(res.body), /bootstrap/);
  } finally {
    server.close();
  }
});

test('T2 regression guard: a forged Host header is STILL rejected on a static route (T2 applies regardless of auth)', async () => {
  const { server, port } = await startTestServer();
  try {
    const res = await request(port, { path: '/', headers: { host: 'evil.example.com' } });
    assert.equal(res.status, 400);
    assert.match(res.body.error, /Host/i);
  } finally {
    server.close();
  }
});

test('T4 regression guard: a `../`-style traversal attempt is rejected with 404 on a REAL running server, no token supplied', async () => {
  const { server, port } = await startTestServer();
  try {
    const attempts = [
      '/../package.json',
      '/src/../../package.json',
      '/%2e%2e/package.json',
    ];
    for (const p of attempts) {
      const res = await request(port, { path: p, headers: { host: `127.0.0.1:${port}` } });
      assert.equal(res.status, 404, `expected 404 for traversal attempt ${p}, got ${res.status}`);
      assert.doesNotMatch(String(res.body), /"name"\s*:\s*"@clear-capabilities/, `${p} must never actually serve package.json's contents`);
    }
  } finally {
    server.close();
  }
});

test('files that exist on disk but are NOT allowlisted (test/, scripts/, package.json, README.md, CLAUDE.md) are rejected 404 on a REAL running server', async () => {
  const { server, port } = await startTestServer();
  try {
    const rejected = ['/test/dom-shim.js', '/scripts/generate-fixture-module.mjs', '/package.json', '/README.md', '/CLAUDE.md', '/.gitignore'];
    for (const p of rejected) {
      const res = await request(port, { path: p, headers: { host: `127.0.0.1:${port}` } });
      assert.equal(res.status, 404, `expected 404 for ${p}, got ${res.status}`);
    }
  } finally {
    server.close();
  }
});

test('a rejected static path returns 404, never 403 (never confirms a path\'s existence to a prober)', async () => {
  const { server, port } = await startTestServer();
  try {
    const res = await request(port, { path: '/README.md', headers: { host: `127.0.0.1:${port}` } });
    assert.equal(res.status, 404);
    assert.notEqual(res.status, 403);
  } finally {
    server.close();
  }
});
