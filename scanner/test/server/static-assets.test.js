// Pure-function unit tests for resolveStaticAsset() — no fs/http access,
// no running server. Proves the ALLOWLIST is doing real work, not merely a
// `../`-traversal guard: several of the rejected paths below are real files
// that genuinely exist on disk under frontend/, and must still be refused.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { resolveStaticAsset, FRONTEND_ROOT, CONTENT_TYPE_MAP, STATIC_CSP_HEADER_VALUE } from '../../src/server/static-assets.js';

test('FRONTEND_ROOT resolves to the real, existing frontend/ directory', () => {
  assert.ok(fs.existsSync(FRONTEND_ROOT), `FRONTEND_ROOT (${FRONTEND_ROOT}) must exist`);
  assert.ok(fs.existsSync(`${FRONTEND_ROOT}/index.html`), 'FRONTEND_ROOT must contain the real index.html');
});

test('/ maps to index.html', () => {
  const r = resolveStaticAsset('/');
  assert.deepEqual(r, { ok: true, relativePath: 'index.html', contentType: CONTENT_TYPE_MAP['.html'] });
});

test('empty string also maps to index.html (defensive)', () => {
  const r = resolveStaticAsset('');
  assert.equal(r.ok, false); // empty string is rejected up front (invalid-path), '/' is the only root form accepted
});

test('every real allowlisted file resolves correctly with the right content type', () => {
  const cases = [
    ['/index.html', 'text/html; charset=utf-8'],
    ['/src/app.js', 'text/javascript; charset=utf-8'],
    ['/src/shell.js', 'text/javascript; charset=utf-8'],
    ['/src/main.js', 'text/javascript; charset=utf-8'],
    ['/src/data/flagship-graph.js', 'text/javascript; charset=utf-8'],
    ['/src/lib/dom.js', 'text/javascript; charset=utf-8'],
    ['/src/lib/api-client.js', 'text/javascript; charset=utf-8'],
    ['/src/views/architecture-view.js', 'text/javascript; charset=utf-8'],
    ['/src/components/evidence-inspector.js', 'text/javascript; charset=utf-8'],
    ['/styles/tokens.css', 'text/css; charset=utf-8'],
    ['/styles/shell.css', 'text/css; charset=utf-8'],
  ];
  for (const [reqPath, contentType] of cases) {
    const r = resolveStaticAsset(reqPath);
    assert.equal(r.ok, true, `expected ${reqPath} to be allowlisted`);
    assert.equal(r.contentType, contentType, `wrong content type for ${reqPath}`);
    assert.equal(r.relativePath, reqPath.slice(1), `wrong relativePath for ${reqPath}`);
    // Every allowlisted path must correspond to a REAL file on disk, so the
    // allowlist and the actual inventory never silently drift apart.
    assert.ok(fs.existsSync(`${FRONTEND_ROOT}/${r.relativePath}`), `${reqPath} allowlisted but missing on disk`);
  }
});

test('a path that is a real file on disk but NOT allowlisted is rejected — the real proof the allowlist is doing work, not just a traversal guard', () => {
  const cases = ['/test/dom-shim.js', '/scripts/generate-fixture-module.mjs', '/package.json', '/README.md', '/CLAUDE.md', '/.gitignore'];
  for (const reqPath of cases) {
    // Confirm these really do exist on disk in frontend/ — the point is
    // that a real, present file still gets refused.
    const relative = reqPath.slice(1);
    assert.ok(fs.existsSync(`${FRONTEND_ROOT}/${relative}`), `test setup: ${reqPath} should exist on disk for this test to be meaningful`);
    const r = resolveStaticAsset(reqPath);
    assert.equal(r.ok, false, `${reqPath} must be rejected even though it exists on disk`);
    assert.equal(r.reason, 'not-allowlisted');
  }
});

test('a `..`-containing path is rejected, several encodings', () => {
  const cases = [
    '/../package.json',
    '/src/../../package.json',
    '/src/../../../package.json',
    '/styles/../package.json',
    '/..',
    '/src/..',
    '/%2e%2e/package.json',
    '/%2e%2e%2fpackage.json',
    '/src/%2e%2e/%2e%2e/package.json',
    '/src/app.js/../../package.json',
  ];
  for (const reqPath of cases) {
    const r = resolveStaticAsset(reqPath);
    assert.equal(r.ok, false, `expected ${reqPath} to be rejected`);
    assert.ok(
      r.reason === 'path-traversal' || r.reason === 'not-allowlisted',
      `expected a traversal-class rejection for ${reqPath}, got reason "${r.reason}"`,
    );
  }
});

test('a null-byte path is rejected, both literal and percent-encoded', () => {
  const r1 = resolveStaticAsset('/index.html\0.js');
  assert.equal(r1.ok, false);
  assert.equal(r1.reason, 'null-byte');

  const r2 = resolveStaticAsset('/index.html%00.js');
  assert.equal(r2.ok, false);
  assert.equal(r2.reason, 'null-byte');
});

test('an absolute-URL-looking input is rejected', () => {
  for (const reqPath of ['http://evil.example.com/x', '//evil.example.com/x', 'https://x', 'javascript:alert(1)']) {
    const r = resolveStaticAsset(reqPath);
    assert.equal(r.ok, false, `expected ${reqPath} to be rejected`);
  }
});

test('a malformed percent-encoding is rejected rather than throwing', () => {
  const r = resolveStaticAsset('/%');
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'malformed-encoding');
});

test('non-string / empty input is rejected', () => {
  assert.equal(resolveStaticAsset(undefined).ok, false);
  assert.equal(resolveStaticAsset(null).ok, false);
  assert.equal(resolveStaticAsset(123).ok, false);
});

test('a nested styles/ path is rejected (no nested subdirectories in the real inventory)', () => {
  const r = resolveStaticAsset('/styles/sub/tokens.css');
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'not-allowlisted');
});

test('an unlisted top-level directory is rejected', () => {
  const r = resolveStaticAsset('/data/flagship-graph.js'); // real file lives at src/data/, not data/
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'not-allowlisted');
});

test('STATIC_CSP_HEADER_VALUE is same-origin-permitting and denies cross-origin sources', () => {
  assert.match(STATIC_CSP_HEADER_VALUE, /script-src 'self'/);
  assert.match(STATIC_CSP_HEADER_VALUE, /style-src 'self'/);
  assert.match(STATIC_CSP_HEADER_VALUE, /connect-src 'self'/);
  assert.doesNotMatch(STATIC_CSP_HEADER_VALUE, /unsafe-inline/);
  assert.doesNotMatch(STATIC_CSP_HEADER_VALUE, /\*/);
});
