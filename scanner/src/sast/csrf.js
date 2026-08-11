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
  // Go (gin/echo/fiber/chi/mux): a router POST/PUT/PATCH/DELETE registration,
  // or net/http mux `.Methods("POST")`.
  go: /\b\w+\s*\.\s*(?:POST|PUT|PATCH|DELETE)\s*\(\s*["'`]|\.\s*Methods\s*\(\s*["'](?:POST|PUT|PATCH|DELETE)["']/g,
  // Ruby on Rails: a route declaration `post '/x'` / `patch` / `put` / `delete`
  // (in routes.rb) or `resources :x` (full CRUD incl. state-changing verbs).
  ruby: /^\s*(?:post|put|patch|delete)\s+['":]|\bresources\s+:/gim,
  // C# ASP.NET MVC/Web API: a [HttpPost]/[HttpPut]/[HttpPatch]/[HttpDelete]
  // action attribute.
  csharp: /\[\s*Http(?:Post|Put|Patch|Delete)\b/g,
};

const CSRF_DEFENCE_RE = /\b(?:csurf|csrfProtection|csrf\(\)|express-csrf-token|lusca\.csrf|fastify-csrf|CSRFProtect|csrf_protect|CsrfViewMiddleware|CsrfFilter|@CsrfProtected|isCsrfTokenValid|IsCsrfTokenValid|csrf_token|CsrfToken|ValidateAntiForgeryToken|AutoValidateAntiforgeryToken|IAntiforgery|protect_from_forgery|verify_authenticity_token|form_authenticity_token|gorilla\/csrf|csrf\.Protect|nosurf|sameSite\s*[:=]\s*['"](?:Strict|Lax)['"]|origin\s*===|referer\s*===|Origin\s*===|Referer\s*===)/i;

// Token-auth signals — these auth schemes are CSRF-safe by construction (the
// credential rides in a header the browser never auto-attaches). NOTE: bare
// `[Authorize]` is intentionally NOT here — ASP.NET cookie auth is the default
// and stays CSRF-vulnerable; only an explicit Bearer scheme or [ApiController]
// (which disables antiforgery + implies token auth) exempts.
const TOKEN_AUTH_RE = /\b(?:Authorization\s*:\s*Bearer|\.startsWith\s*\(\s*['"`]Bearer|req\.headers\.authorization|request\.headers\.get\(\s*['"`]authorization|bearer\s+token|x-api-key|verifyJWT|jwt\.verify|jsonwebtoken|lexik_jwt|JWTTokenAuthenticator|headers\s*->\s*get\s*\(\s*['"]Authorization|c\.GetHeader\s*\(\s*["']Authorization|request\.headers\[["']Authorization)|\[\s*ApiController\b|AuthenticationSchemes\s*=\s*["']?Bearer/i;

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
  else if (ext === 'go') langSel = ['go'];
  else if (ext === 'rb') langSel = ['ruby'];
  else if (ext === 'cs') langSel = ['csharp'];
  if (!langSel) return [];

  const code = blankComments(raw, (ext === 'py' || ext === 'rb') ? 'py' : undefined);
  // Per-route defence is checked below (±15-line window around each route).
  // There used to also be a whole-file gate here ("if the file shows CSRF
  // defence ANYWHERE, suppress every route in it") — by regex-substring
  // monotonicity that gate always fires whenever the per-route window would
  // have matched too (the window is a substring of the file), so it made the
  // per-route check provably unreachable: one protected route silently
  // suppressed every OTHER route in the same file, however unprotected.

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
