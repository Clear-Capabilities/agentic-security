// Auth/AuthZ deep-analysis detector — F1 over labelled fixtures.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { evaluateF1 } from './helpers/f1.js';
import { scanAuthZ } from '../src/sast/authz.js';

const LABELS = [
  { file: 'vuln-jwt-alg-none.js',           positive: true,  matcher: /JWT alg:none/i },
  { file: 'vuln-jwt-hardcoded-secret.js',   positive: true,  matcher: /hardcoded JWT secret/i },
  { file: 'vuln-jwt-verify-no-algs.js',     positive: true,  matcher: /jwt\.verify.*algorithms/i },
  { file: 'vuln-oauth-no-pkce.js',          positive: true,  matcher: /OAuth2.*PKCE/i },
  { file: 'vuln-oauth-redirect-from-req.js',positive: true,  matcher: /redirect_uri from request/i },
  { file: 'vuln-session-fixation.js',       positive: true,  matcher: /session.*regenerated|session fixation/i },
  { file: 'vuln-multi-tenant-no-scope.js',  positive: true,  matcher: /tenant.*scoped query missing|tenantId\/orgId/i },
  { file: 'safe-jwt-explicit-algs.js',      positive: false, matcher: /^AuthZ:/i },
  { file: 'safe-oauth-pkce.js',             positive: false, matcher: /^AuthZ:/i },
  { file: 'safe-redirect-allowlist.js',     positive: false, matcher: /^AuthZ:/i },
  { file: 'safe-session-regenerate.js',     positive: false, matcher: /^AuthZ:/i },
  { file: 'safe-multi-tenant-scoped.js',    positive: false, matcher: /^AuthZ:/i },
];

test('AuthZ detector — F1 evaluation', async () => {
  await evaluateF1({
    name: 'AuthZ-detector',
    fixtureDir: 'authz',
    labels: LABELS,
    floors: { f1: 0.85, precision: 0.83, recall: 0.83 },
  });
});

// Stage 1 correctness audit: `!A && !B === false || C` — operator precedence
// makes `!B === false` reduce to `B`, and `C` (val.length >= 4) is always
// true given the capture group's own {4,64} quantifier, so the whole
// "suppress only template/env placeholders" condition was a tautology —
// every match was flagged regardless, including literal env-var
// placeholders the comment explicitly says should be suppressed.
test('hardcoded-JWT-secret does not flag a template/env-var placeholder', () => {
  const src = 'const JWT_SECRET = "${process.env.JWT_SECRET}";\n';
  const findings = scanAuthZ('app.js', src);
  assert.equal(findings.filter(f => /hardcoded JWT secret/i.test(f.vuln)).length, 0,
    `expected no finding for an env-var placeholder, got: ${JSON.stringify(findings)}`);
});

test('hardcoded-JWT-secret still flags a real literal secret', () => {
  const src = 'const JWT_SECRET = "supersecretvalue123";\n';
  const findings = scanAuthZ('app.js', src);
  assert.equal(findings.filter(f => /hardcoded JWT secret/i.test(f.vuln)).length, 1);
});

test('hardcoded-JWT-secret still flags well-known placeholder values (changeme/secret/example)', () => {
  const src = 'const JWT_SECRET = "changeme";\n';
  const findings = scanAuthZ('app.js', src);
  assert.equal(findings.filter(f => /hardcoded JWT secret/i.test(f.vuln)).length, 1,
    'well-known bad placeholders must still be flagged per the module\'s own stated intent');
});
