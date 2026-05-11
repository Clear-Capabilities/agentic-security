// Authentication / authorization deep-analysis detector.
//
// OWASP A01: Broken Access Control is consistently the #1 source of real
// breaches. The taint-based pipeline already catches IDOR-by-id and SQLi via
// auth-table lookups. This module covers the higher-level patterns that pure
// data-flow misses:
//
//   - JWT alg:none / algorithm confusion
//   - Hardcoded JWT secret
//   - jwt.verify called without an algorithms allow-list
//   - OAuth2 authorization_code flow with no PKCE
//   - OAuth2 redirect_uri taken from the request without allowlist validation
//   - Session not regenerated after authentication (session fixation)
//   - Multi-tenant query missing a tenant scope (cross-tenant read)
//
// F1 strategy:
//   Each pattern fires only when there is concrete signal in source. Negative
//   contexts (allow-list present, tenant filter present, PKCE generation
//   present in the same module) suppress the finding.

const _SCAN_EXT_RE = /\.(?:js|jsx|ts|tsx|mjs|cjs|py)$/i;
const _NONPROD_PATH_RE = /(?:^|\/)(?:tests?|__tests__|spec|fixtures?|examples?|docs?|stories|codefixes|node_modules)\//i;

// --- JWT patterns ---

// jwt.sign or jwt.verify with explicit alg: 'none' / "none"
const JWT_ALG_NONE_RE = /\b(?:jwt|jsonwebtoken)\.(?:sign|verify|decode)\s*\([^)]*?(?:algorithm|alg)\s*:\s*['"]none['"]/i;

// JWT_SECRET / signingKey hardcoded as a literal short string in source
const JWT_HARDCODED_SECRET_RE = /\b(?:JWT_SECRET|jwtSecret|jwt_secret|signingSecret|signing_key|JWT_KEY)\s*[:=]\s*['"]([^'"]{4,64})['"]/;

// jwt.verify called without an `algorithms` option (algorithm confusion attack)
// We require: a `jwt.verify(` call within ~200 chars of a missing `algorithms`
const JWT_VERIFY_RE = /\b(?:jwt|jsonwebtoken)\.verify\s*\(/g;
const JWT_ALGORITHMS_OPT_RE = /\balgorithms\s*:\s*\[/;

// --- OAuth2 / OIDC ---

// authorization_code flow without PKCE: matches `response_type: 'code'` with no
// `code_challenge` in surrounding context.
const OAUTH_AUTHCODE_RE = /\bresponse_type\s*[:=]\s*['"]code['"]/;
const OAUTH_PKCE_RE = /\b(?:code_challenge|codeChallenge|pkce|code_verifier)\b/;

// redirect_uri taken from req without allow-list. We trigger when:
//   redirectUrl/url = req.query.redirect_uri      (or .body / .params)
// and the same module has no constants[*] === url style allow-list.
const OAUTH_REDIRECT_FROM_REQ_RE = /\b(?:redirect|redirectUri|redirect_uri|callback|returnTo|returnUrl|next)\s*[:=]\s*(?:req|request)\.(?:query|body|params)\.[A-Za-z_]\w*/i;
const OAUTH_REDIRECT_ALLOWLIST_RE = /\b(?:ALLOWED_REDIRECTS|REDIRECT_ALLOWLIST|allowedRedirects|allowedHosts|isAllowed(?:Url|Host|Redirect)|VALID_REDIRECTS)\b|\.includes\s*\(\s*(?:redirect|redirectUri|redirect_uri|returnTo|callback|next|url)\s*\)/;

// --- Session fixation ---

// Pattern: an authentication step (req.login, passport.authenticate completion,
// `req.session.userId = ...`) followed by no `session.regenerate(` call.
const SESSION_LOGIN_RE = /\b(?:req\.login\s*\(|req\.session\.(?:userId|user_id|user|uid)\s*=|passport\.authenticate\s*\([^)]*\)\s*\(req|request\.session\['user'\]\s*=)/;
const SESSION_REGENERATE_RE = /\b(?:req\.session\.regenerate\s*\(|session\.regenerate\s*\(|request\.session\.cycle_key\s*\(|sessionStore\.regenerate)/;

// --- Multi-tenant scope ---

// SELECT/find with a where-clause keyed by a non-tenant id (Sequelize, Prisma,
// raw SQL, mongoose). Suppress if the same statement contains tenantId/orgId/
// workspaceId in the where clause.
const MT_QUERY_RE = /\b(?:findOne|findById|findFirst|findUnique|find\(\s*\{)\s*[^;]*?\bwhere\s*:\s*\{[^}]*\bid\s*:\s*(?:req|request)\.(?:params|body|query)\.[A-Za-z_]\w*[^}]*\}/i;
const MT_TENANT_KEY_RE = /\b(?:tenantId|tenant_id|orgId|org_id|workspaceId|workspace_id|accountId|account_id|companyId|company_id)\b/;

// Raw SQL with direct interpolation of a request value into the WHERE-by-id
// clause. We deliberately do NOT match parameterized placeholders (?, $1, :id)
// — those are the safe pattern. Only flag string-concatenation or template-
// literal interpolation that pulls from req/request.
const MT_RAW_SQL_RE = /\b(?:select|update|delete)\b[\s\S]{0,200}?\bwhere\s+(?:[\w_.]*\.)?id\s*=\s*\$?\{?\s*(?:req|request)\.(?:params|body|query)\.[A-Za-z_]\w*/i;

function _emit(fp, line, vuln, severity, cwe, snippet, fix, confidence=0.85) {
  return {
    id: `authz:${fp}:${line}:${vuln.replace(/[^A-Za-z0-9]/g, '_').slice(0, 60)}`,
    kind: 'authz', severity, vuln,
    cwe, stride: 'Elevation of Privilege',
    file: fp, line, snippet: (snippet || '').trim().slice(0, 200),
    fix, confidence,
  };
}

// Strip string-literal contents while preserving line/col so the raw-SQL and
// shape-only patterns below don't self-detect inside fix-message templates or
// other string-embedded examples.
function _stripStrings(code){
  const out = code.split('');
  const n = code.length;
  let i = 0, state = 0; // 0 NORMAL, 1 SQ, 2 DQ, 3 BT
  while (i < n) {
    const c = code[i];
    if (state === 0) {
      if (c === "'") { state = 1; i++; continue; }
      if (c === '"') { state = 2; i++; continue; }
      if (c === '`') { state = 3; i++; continue; }
      i++; continue;
    }
    const quote = state === 1 ? "'" : state === 2 ? '"' : '`';
    if (c === '\\' && i + 1 < n) { if (code[i+1] !== '\n') out[i+1] = ' '; out[i] = ' '; i += 2; continue; }
    if (c === quote) { state = 0; i++; continue; }
    if (state === 3 && c === '$' && code[i+1] === '{') {
      // Preserve template expression content: skip ahead until matching }.
      let depth = 1; out[i]='$'; out[i+1]='{'; i += 2;
      while (i < n && depth > 0) {
        if (code[i] === '{') depth++;
        else if (code[i] === '}') depth--;
        i++;
      }
      continue;
    }
    if (c !== '\n') out[i] = ' ';
    i++;
  }
  return out.join('');
}

export function scanAuthZ(fp, raw) {
  if (!_SCAN_EXT_RE.test(fp)) return [];
  const fpNorm = fp.replace(/\\/g, '/');
  if (_NONPROD_PATH_RE.test(fpNorm)) return [];
  if (!raw || raw.length > 500_000) return [];

  // `rawForShape` is used by detectors that match on code shape (raw SQL, JWT
  // calls). String literals are blanked so fix-message templates and example
  // snippets don't self-detect. Detectors that explicitly read literal content
  // (hardcoded JWT secret) keep using `raw`.
  const rawForShape = _stripStrings(raw);
  const linesShape = rawForShape.split('\n');
  const lines = raw.split('\n');
  const findings = [];
  const seen = new Set();
  const push = (f) => { if (!seen.has(f.id)) { seen.add(f.id); findings.push(f); } };

  // Per-line patterns
  for (let i = 0; i < lines.length; i++) {
    const ln = lines[i];

    // 1. JWT alg:none
    if (JWT_ALG_NONE_RE.test(ln)) {
      push(_emit(fp, i + 1,
        'AuthZ: JWT alg:none accepted (forgery)',
        'critical', 'CWE-347', ln,
        'Setting algorithm to "none" disables signature verification — any token is accepted as valid. Set an explicit `algorithms: ["RS256"]` (or HS256 for symmetric) and reject tokens that present a different alg.'));
    }

    // 2. Hardcoded JWT secret (shortish literal)
    const m2 = ln.match(JWT_HARDCODED_SECRET_RE);
    if (m2) {
      const val = m2[1];
      // Suppress only template/env placeholders
      if (!/process\.env|\$\{|<.*?>|^\s*$/.test(val) && !/\bsecret\b|\bchange.?me\b|^example$/i.test(val) === false || val.length >= 4) {
        // We still flag well-known placeholders ("secret", "changeme") because they
        // are the most common production foot-gun.
        push(_emit(fp, i + 1,
          'AuthZ: hardcoded JWT secret in source',
          'critical', 'CWE-798', ln.replace(val, '<redacted>'),
          'Move the JWT secret to an environment variable or secret store, and rotate the previous value (it must be considered leaked). For asymmetric tokens, prefer RS256 with the private key in a KMS.'));
      }
    }

    // 3. authorization_code flow without PKCE — needs whole-file context.
    if (OAUTH_AUTHCODE_RE.test(ln)) {
      const hasPkceNearby = OAUTH_PKCE_RE.test(raw);
      if (!hasPkceNearby) {
        push(_emit(fp, i + 1,
          'AuthZ: OAuth2 authorization_code without PKCE',
          'high', 'CWE-287', ln,
          'Public OAuth2 clients (SPAs, mobile, native) must use PKCE. Generate a `code_verifier` (43–128 chars), derive a `code_challenge = base64url(sha256(verifier))`, send it on the authorize call, and verify it on the token exchange.'));
      }
    }

    // 4. redirect_uri taken from request — flag if no allow-list anywhere in file
    if (OAUTH_REDIRECT_FROM_REQ_RE.test(ln)) {
      const hasAllowlist = OAUTH_REDIRECT_ALLOWLIST_RE.test(raw);
      if (!hasAllowlist) {
        push(_emit(fp, i + 1,
          'AuthZ: OAuth2 redirect_uri from request without allow-list',
          'high', 'CWE-601', ln,
          'Validate the redirect_uri against a server-side allow-list before redirecting. An attacker can register a malicious client or pass `?redirect=evil.com` and intercept the authorization code or open-redirect to a phishing page.'));
      }
    }
  }

  // 5. jwt.verify without algorithms option
  let vm;
  const verifyRe = new RegExp(JWT_VERIFY_RE.source, 'g');
  while ((vm = verifyRe.exec(raw))) {
    // window is the call-site argument list
    const after = raw.slice(vm.index, Math.min(raw.length, vm.index + 400));
    if (!JWT_ALGORITHMS_OPT_RE.test(after) && !JWT_ALG_NONE_RE.test(after)) {
      const line = raw.substring(0, vm.index).split('\n').length;
      push(_emit(fp, line,
        'AuthZ: jwt.verify called without algorithms allow-list',
        'high', 'CWE-347', lines[line - 1] || '',
        'Pass `{ algorithms: ["RS256"] }` (or HS256) explicitly to `jwt.verify`. Without it, an attacker can forge a token using an unexpected algorithm (alg:none, or HS256-signed with the public key for an RS256 issuer).'));
    }
  }

  // 6. Session fixation: login without regenerate
  if (SESSION_LOGIN_RE.test(raw) && !SESSION_REGENERATE_RE.test(raw)) {
    const m = raw.match(SESSION_LOGIN_RE);
    if (m) {
      const line = raw.substring(0, m.index).split('\n').length;
      push(_emit(fp, line,
        'AuthZ: session not regenerated after authentication (session fixation)',
        'high', 'CWE-384', lines[line - 1] || '',
        'After successful authentication, call `req.session.regenerate(...)` (or your framework equivalent) before storing the user identity in the session. Otherwise an attacker who fixed the pre-auth session id retains access post-login.'));
    }
  }

  // 7. Multi-tenant: where-by-id without tenant scope
  let mm;
  const mtRe = new RegExp(MT_QUERY_RE.source, 'gi');
  while ((mm = mtRe.exec(raw))) {
    const block = mm[0];
    if (!MT_TENANT_KEY_RE.test(block)) {
      const line = raw.substring(0, mm.index).split('\n').length;
      push(_emit(fp, line,
        'AuthZ: tenant-scoped query missing tenantId/orgId filter',
        'high', 'CWE-639', lines[line - 1] || block.slice(0, 120),
        'Multi-tenant queries must include the requesting user\'s tenantId/orgId in the WHERE clause. Otherwise a row id collision (or guessing) reads another tenant\'s data. Add `where: { id, tenantId: req.user.tenantId }`.'));
    }
  }
  let rm;
  const rawSqlRe = new RegExp(MT_RAW_SQL_RE.source, 'gi');
  while ((rm = rawSqlRe.exec(rawForShape))) {
    const block = rm[0];
    if (!MT_TENANT_KEY_RE.test(block)) {
      const line = rawForShape.substring(0, rm.index).split('\n').length;
      push(_emit(fp, line,
        'AuthZ: raw SQL where-by-id without tenant scope',
        'high', 'CWE-639', lines[line - 1] || block.slice(0, 120),
        'The query selects a row by id without scoping to the caller\'s tenant. Append `AND tenant_id = $tenantId` (and pass it from the authenticated session, never the request body).'));
    }
  }

  return findings;
}
