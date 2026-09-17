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

const _SCAN_EXT_RE = /\.(?:js|jsx|ts|tsx|mjs|cjs|py|php)$/i;
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

// --- PHP: missing-authorization / IDOR (CWE-862/639) ---
//
// PHP's own idiom for the identical shape: a raw SQL/XPath query selects a
// row by a request-supplied id with no accompanying check that the row
// belongs to the CURRENT session's user. Unlike the JS pattern above (a
// single ORM call-site expression), PHP's own convention (confirmed against
// the public generator source, stivalet/PHP-Vuln-test-suite-generator,
// pinned 84b4cccf05598c74b052111804954eac19f259b6, construction.xml's
// "right_verification" sample) fixes this by APPENDING the ownership check
// as a SEPARATE, SUBSEQUENT `.=` statement (`$query .= "AND
// course.allowed=$_SESSION[userid]";`) — the check never appears inside the
// same string literal as the WHERE clause, so the suppression window must
// extend forward past the initial query-building statement, not just
// inspect the matched span itself (unlike `MT_RAW_SQL_RE` above, where a
// single ORM call is fully self-contained).
const PHP_IDOR_WHERE_ID_RE = /\bwhere\b[\s\S]{0,80}?\bid\s*=\s*[^$\n]{0,10}\$(\w+)/i;
// A second, structurally distinct sub-family from the SAME generator
// (stivalet/PHP-Vuln-test-suite-generator, construction.xml's "fopen"
// sample): `$var = fopen($tainted, "r")` — opening a FILE by a raw
// request-supplied id/path, with no ownership check, is a separate flaw
// type (`CWE_862_Fopen_IDOR`) from the SQL where-by-id shape above and has
// no "where"/"id=" text at all, so `PHP_IDOR_WHERE_ID_RE` can never match
// it. Confirmed via the generator's own construction.xml: this specific
// suite classifies "read an arbitrary resource by an unauthenticated,
// unverified identifier" as a missing-authorization issue in its own
// right (distinct from, and can legitimately coexist with, a path-
// traversal finding on the same line from `php.js`'s structural rule).
const PHP_FOPEN_IDOR_RE = /\bfopen\s*\(\s*\$(\w+)\s*,/i;
const PHP_SUPERGLOBAL_SOURCE_RE = /\$_(?:GET|POST|REQUEST|COOKIE)\b/;
const PHP_SESSION_CHECK_RE = /\$_SESSION\b/;
// Two more safe paths from the SAME generator (sanitize.xml), both real
// corpus false positives this rule needs to stay silent on: an OWASP ESAPI
// validator call, and an "indirect reference" pattern that resolves the id
// through a $_SESSION-scoped allow-list array built earlier in the request
// (`$course_array = $_SESSION['course_array']; ... $tainted =
// $course_array[$tainted];`) — the $_SESSION reference there can be far
// enough from the WHERE clause that a narrow window around the match misses
// it, so this check is deliberately file-scoped like the superglobal-source
// check above, not windowed like PHP_SESSION_CHECK_RE.
const PHP_ESAPI_VALIDATOR_RE = /\bESAPI\b/;
// The generator's OTHER safe path (construction.xml/sanitize.xml, confirmed
// via real corpus false positives, not reasoning alone — the first version
// of this rule fired on both): the tainted value never reaches a
// session-scoped ownership check at all, because it was constrained to a
// fixed allow-list BEFORE the query — a ternary compare-and-substitute
// (`$tainted = $tainted == 'safe1' ? 'safe1' : 'safe2';`) or an
// `in_array($tainted, $whitelist)` guard. Either makes the value provably
// one of a small known-safe set regardless of what the attacker supplied,
// which is the actual reason it's safe (the generator's own `testSafety`
// treats a safe SANITIZER as equally sufficient to a safe CONSTRUCTION).
function _phpVarIsWhitelisted(raw, varName) {
  const esc = varName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const ternaryRe = new RegExp(`\\$${esc}\\s*==\\s*['"][^'"]*['"]\\s*\\?`);
  const inArrayRe = new RegExp(`\\bin_array\\s*\\(\\s*\\$${esc}\\b`, 'i');
  return ternaryRe.test(raw) || inArrayRe.test(raw);
}

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
      // Suppress only template/env placeholders. We still flag well-known
      // placeholders ("secret", "changeme", "example") because they are the
      // most common production foot-gun.
      const looksLikePlaceholder = /process\.env|\$\{|<.*?>|^\s*$/.test(val);
      const isKnownBadPlaceholder = /\bsecret\b|\bchange.?me\b|^example$/i.test(val);
      if (!looksLikePlaceholder || isKnownBadPlaceholder) {
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

  // 8. PHP: raw SQL where-by-id built from a request superglobal, no
  // $_SESSION-based ownership check anywhere in a window around the query
  // (see PHP_IDOR_WHERE_ID_RE above for why the window must extend forward,
  // not just cover the matched span). Uses `raw`, not `rawForShape`: PHP
  // double-quoted strings interpolate `$var` directly, so blanking string
  // content (as `_stripStrings` does for JS template-literal shape matching)
  // would erase the very `$id`/`$_SESSION` references this pattern needs.
  if (/\.php$/i.test(fp)) {
    let pm;
    const phpIdorRe = new RegExp(PHP_IDOR_WHERE_ID_RE.source, 'gi');
    while ((pm = phpIdorRe.exec(raw))) {
      // File-level co-occurrence, not a traced direct assignment: the public
      // generator's own combinatorics route the same superglobal read through
      // many indirections (a getter method, an array element, an object
      // property set in the constructor — confirmed via input.xml) that a
      // single-line "$var = $_GET[...]" regex can never enumerate. The same
      // looser, file-scoped co-occurrence bar is already how this file's own
      // OAuth/crypto-context checks work elsewhere (see `looksCrypto` in
      // csharp.js for the cross-language precedent).
      if (!PHP_SUPERGLOBAL_SOURCE_RE.test(raw)) continue;
      const windowEnd = Math.min(raw.length, pm.index + 300);
      const window = raw.slice(Math.max(0, pm.index - 100), windowEnd);
      if (PHP_SESSION_CHECK_RE.test(window)) continue;
      if (_phpVarIsWhitelisted(raw, pm[1])) continue;
      if (PHP_ESAPI_VALIDATOR_RE.test(raw)) continue;
      const line = raw.substring(0, pm.index).split('\n').length;
      push(_emit(fp, line,
        'AuthZ: raw SQL where-by-id from request input without an ownership check',
        'high', 'CWE-862', lines[line - 1] || raw.slice(pm.index, pm.index + 120),
        'The query selects a row by an id taken directly from the request with no check that the row belongs to the current session\'s user. Add a filter on the authenticated user\'s identity (e.g. `AND owner_id = $_SESSION[\'userid\']`) so a guessed or enumerated id cannot read another user\'s data.'));
    }

    // 9. PHP: fopen() on a request-derived path/id, no ownership check
    // anywhere in a window around the call. Same file-wide co-occurrence and
    // suppression conventions as the SQL IDOR check above (#8) — see that
    // block's own comments for why each guard exists.
    let fm;
    const phpFopenIdorRe = new RegExp(PHP_FOPEN_IDOR_RE.source, 'gi');
    while ((fm = phpFopenIdorRe.exec(raw))) {
      if (!PHP_SUPERGLOBAL_SOURCE_RE.test(raw)) continue;
      const windowEnd = Math.min(raw.length, fm.index + 300);
      const window = raw.slice(Math.max(0, fm.index - 100), windowEnd);
      if (PHP_SESSION_CHECK_RE.test(window)) continue;
      if (_phpVarIsWhitelisted(raw, fm[1])) continue;
      if (PHP_ESAPI_VALIDATOR_RE.test(raw)) continue;
      const line = raw.substring(0, fm.index).split('\n').length;
      push(_emit(fp, line,
        'AuthZ: fopen() on request-supplied path/id without an ownership check',
        'high', 'CWE-862', lines[line - 1] || raw.slice(fm.index, fm.index + 120),
        'The file is opened using an identifier taken directly from the request with no check that the resource belongs to the current session\'s user. Verify ownership (e.g. against `$_SESSION[\'userid\']`) or resolve through a per-user allow-list before opening the file, so a guessed or enumerated id cannot read another user\'s data.'));
    }
  }

  return findings;
}
