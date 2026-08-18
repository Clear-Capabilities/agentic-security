// PRD T4.4 + T4.5 — redirect/header-forwarding and validate-then-resolve
// TOCTOU. 11 of the 96 root-caused real-world misses.
//
// These are the INVERSE of the open-redirect rules already in this codebase:
// there the app emits an attacker-controlled Location; here the app is the
// CLIENT and the danger is what its own request does when redirected.
//
// Each rule names the specific control the real fix added and must go silent
// when it is present — so every test comes in a vulnerable/fixed pair.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanRedirectToctou } from '../src/sast/redirect-toctou.js';

const sub = (f) => f.map(x => x.subfamily);

test('T4.4a: credentials forwarded across a redirect fire; header-stripping silences', () => {
  const vuln = scanRedirectToctou('u.py',
    'import httpx\ndef fetch(url, headers):\n    return httpx.get(url, headers=headers, follow_redirects=True)\n');
  assert.deepEqual(sub(vuln), ['credential-across-redirect']);
  assert.equal(vuln[0].cwe, 'CWE-200');

  const fixed = scanRedirectToctou('u.py',
    'import httpx\ndef fetch(url, headers):\n    def _redirect_headers(req, res):\n        if origin(req.url) != origin(res.url):\n            del headers["Authorization"]\n    return httpx.get(url, headers=headers, follow_redirects=True)\n');
  assert.deepEqual(fixed, []);
});

test('T4.4b: allow-list checked once then redirects followed fires; a per-hop hook silences', () => {
  const vuln = scanRedirectToctou('u.py',
    'import requests\ndef fetch(url):\n    if not is_allowed(url):\n        raise ValueError()\n    return requests.get(url, allow_redirects=True)\n');
  assert.deepEqual(sub(vuln), ['unvalidated-redirect-hop']);
  assert.equal(vuln[0].cwe, 'CWE-918');

  const fixed = scanRedirectToctou('u.py',
    'import requests\ndef fetch(url):\n    if not is_allowed(url):\n        raise ValueError()\n    return requests.get(url, allow_redirects=True, hooks={"response": validate_redirect})\n');
  assert.deepEqual(fixed, []);
});

test('T4.5: resolve-check-then-re-resolve fires; pinning the resolved value silences', () => {
  const vuln = scanRedirectToctou('u.py',
    'import socket\ndef fetch(host):\n    ip = socket.getaddrinfo(host, 443)[0][4][0]\n    if not is_allowed(ip):\n        raise ValueError()\n    return conn(host)\n');
  assert.deepEqual(sub(vuln), ['toctou-resolve']);
  assert.equal(vuln[0].cwe, 'CWE-367');

  const fixed = scanRedirectToctou('u.py',
    'import socket\ndef fetch(host):\n    resolved_ip = socket.getaddrinfo(host, 443)[0][4][0]\n    if not is_allowed(resolved_ip):\n        raise ValueError()\n    return connect_to_ip(resolved_ip)\n');
  assert.deepEqual(fixed, []);
});

test('REFUSES: an ordinary request that does not follow redirects', () => {
  assert.deepEqual(scanRedirectToctou('u.py', 'import requests\ndef fetch(url):\n    return requests.get(url)\n'), []);
});

test('REFUSES: redirect-following with no credentials and no allow-list', () => {
  assert.deepEqual(
    scanRedirectToctou('u.py', 'import requests\ndef fetch(url):\n    return requests.get(url, allow_redirects=True)\n'),
    []);
});

test('every finding records what it looked for (T2.2)', () => {
  const f = scanRedirectToctou('u.py',
    'import httpx\ndef fetch(url, headers):\n    return httpx.get(url, headers=headers, follow_redirects=True)\n');
  assert.ok(f[0].checkedFor);
});

test('non-source files are skipped cheaply', () => {
  assert.deepEqual(scanRedirectToctou('a.go', 'http.Get(url) // redirect'), []);
});
