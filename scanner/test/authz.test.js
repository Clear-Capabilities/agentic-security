// Auth/AuthZ deep-analysis detector — F1 over labelled fixtures.
import { test } from 'node:test';
import { evaluateF1 } from './helpers/f1.js';

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
