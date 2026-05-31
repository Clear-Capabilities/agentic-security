import { blankComments } from './_comment-strip.js';
// CSRF on state-changing routes.
//
// Heuristic: POST / PUT / PATCH / DELETE routes that don't show evidence of
// CSRF protection in the file or in the project-wide middleware chain.
//
// Evidence of protection (per-file or per-route):
//   - csurf / csrf middleware in scope
//   - express-csrf-token / lusca.csrf / fastify-csrf
//   - Flask-WTF CSRFProtect / django.middleware.csrf.CsrfViewMiddleware
//   - Spring CsrfFilter / @CsrfProtected
//   - SameSite=Strict|Lax cookie config
//   - Origin / Referer check
//   - Authorization: Bearer (token auth is CSRF-safe by construction)
//   - methodNotAllowed: state-changing route guarded by API-only header

const STATE_CHANGE_RE = {
  express: /\b(?:app|router|express\(\))\s*\.\s*(post|put|patch|delete)\s*\(/gi,
  fastify: /\b(?:fastify|server)\s*\.\s*(post|put|patch|delete)\s*\(/gi,
  flask: /@(?:app|bp|blueprint)\s*\.\s*route\s*\([^)]*methods\s*=\s*\[[^\]]*['"](POST|PUT|PATCH|DELETE)['"]/gi,
  django: /\b(?:require_POST|require_http_methods\s*\(\s*\[[^\]]*['"](POST|PUT|PATCH|DELETE)['"])/gi,
  fastapi: /@\w+\s*\.\s*(post|put|patch|delete)\s*\(/gi,
  spring: /@(PostMapping|PutMapping|PatchMapping|DeleteMapping)\b/g,
  // Symfony: reading the POST body bag (`$request->request->get(...)`) is the
  // state-change signal, plus the Route annotation method list.
  symfony: /\$\w+\s*->\s*(?:request|getPayload\s*\(\s*\))\s*->\s*(?:get|getInt|getBoolean|getAlnum|getDigits|all|has)\s*\(|[#@]\[?\s*Route\s*\([^)]*methods\s*[:=]\s*[[{][^\]}]*['"](?:POST|PUT|PATCH|DELETE)['"]/gi,
};

const CSRF_DEFENCE_RE = /\b(?:csurf|csrfProtection|csrf\(\)|express-csrf-token|lusca\.csrf|fastify-csrf|CSRFProtect|csrf_protect|CsrfViewMiddleware|CsrfFilter|@CsrfProtected|isCsrfTokenValid|IsCsrfTokenValid|csrf_token|CsrfToken|sameSite\s*[:=]\s*['"](?:Strict|Lax)['"]|origin\s*===|referer\s*===|Origin\s*===|Referer\s*===)/i;

const TOKEN_AUTH_RE = /\b(?:Authorization\s*:\s*Bearer|\.startsWith\s*\(\s*['"`]Bearer|req\.headers\.authorization|request\.headers\.get\(\s*['"`]authorization|bearer\s+token|x-api-key|verifyJWT|jwt\.verify|jsonwebtoken|lexik_jwt|JWTTokenAuthenticator|headers\s*->\s*get\s*\(\s*['"]Authorization)/i;

const TEST_FILE_RE = /(?:^|\/)(?:tests?|__tests__|specs?|test|fixtures)\//i;

function lineOf(raw, idx) { return raw.substring(0, idx).split('\n').length; }

export function scanCSRF(fp, raw) {
  if (!raw || raw.length > 500_000) return [];
  if (TEST_FILE_RE.test(fp)) return [];
  const ext = (fp.match(/\.([a-z]+)$/i) || [])[1] || '';
  let langSel = null;
  if (/^(?:js|jsx|ts|tsx|mjs|cjs)$/i.test(ext)) langSel = ['express', 'fastify'];
  else if (ext === 'py') langSel = ['flask', 'django', 'fastapi'];
  else if (ext === 'java' || ext === 'kt') langSel = ['spring'];
  else if (ext === 'php' || ext === 'phtml') langSel = ['symfony'];
  if (!langSel) return [];

  const code = blankComments(raw, ext === 'py' ? 'py' : undefined);
  // Project-wide-ish: if the file shows CSRF defence anywhere or only handles
  // token-authenticated routes, we suppress.
  const csrfInScope = CSRF_DEFENCE_RE.test(code);
  const tokenAuthInScope = TOKEN_AUTH_RE.test(code);
  if (csrfInScope || tokenAuthInScope) return [];

  const findings = [];
  const seen = new Set();
  for (const sel of langSel) {
    const re = new RegExp(STATE_CHANGE_RE[sel].source, STATE_CHANGE_RE[sel].flags);
    let m;
    while ((m = re.exec(code))) {
      const line = lineOf(raw, m.index);
      const id = `csrf:${fp}:${line}`;
      if (seen.has(id)) continue;
      seen.add(id);
      // Check ±15 lines for inline defence (one-off route-level guard).
      // Use the comment-blanked text — comments like "// no csurf yet" must
      // not satisfy the defence check.
      const windowLines = code.split('\n').slice(Math.max(0, line - 16), line + 15).join(' ');
      if (CSRF_DEFENCE_RE.test(windowLines) || TOKEN_AUTH_RE.test(windowLines)) continue;
      const method = (m[1] || (sel === 'spring' ? m[1] : '')).toUpperCase();
      findings.push({
        id,
        file: fp, line,
        vuln: `Missing CSRF protection on state-changing route (${method || 'POST/PUT/PATCH/DELETE'})`,
        severity: 'high',
        cwe: 'CWE-352',
        stride: 'Tampering',
        snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
        remediation: 'For session-cookie auth: add the framework\'s CSRF middleware (`csurf` for Express, `Flask-WTF CSRFProtect` for Flask, the built-in `CsrfViewMiddleware` for Django, `CsrfFilter` for Spring) and require a token in every state-changing form. For pure token auth (Authorization: Bearer), set `SameSite=Strict` on the session cookie or drop the cookie entirely. For SPAs: use a double-submit cookie or per-request token from the server.',
        parser: 'CSRF',
        confidence: 0.65,
      });
    }
  }
  return findings;
}
