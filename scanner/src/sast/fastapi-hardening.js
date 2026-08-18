// FastAPI framework hardening.
//
// Coverage:
//   1. app.run(host="0.0.0.0", debug=True) or uvicorn run with debug=True
//   2. CORSMiddleware(allow_origins=["*"]) with allow_credentials=True
//   3. @app.<verb>("...") without Depends(security_dep) on mutating endpoints
//   4. JWT decode without signature verification (jwt.decode(token, options={"verify_signature": False}))
//   5. Pydantic Settings with literal API key default
//   6. HTTPBearer used without auto_error checks
//   7. app.add_middleware(TrustedHostMiddleware, allowed_hosts=["*"])

import { routeAuthEvidence } from './_auth-signals.js';

const _PY_RE = /\.py$/i;

function _line(raw, idx) {
  return raw.slice(0, idx).split('\n').length;
}

function _isFastApi(raw) {
  return /\bfrom\s+fastapi\b/.test(raw) || /\bimport\s+fastapi\b/.test(raw);
}

export function scanFastapiHardening(file, raw) {
  if (!file || !raw || typeof raw !== 'string') return [];
  if (!_PY_RE.test(file)) return [];
  if (!_isFastApi(raw)) return [];
  if (raw.length > 200_000) return [];

  const findings = [];

  // 1. debug=True on app run
  for (const m of raw.matchAll(/\b(?:app\.run|uvicorn\.run)\s*\([^)]*\bdebug\s*=\s*True\b/g)) {
    findings.push({
      id: `fastapi:debug-true:${file}:${_line(raw, m.index)}`,
      file, line: _line(raw, m.index),
      vuln: 'FastAPI / uvicorn run with debug=True',
      severity: 'high',
      family: 'fastapi-debug-enabled',
      cwe: 'CWE-489',
      confidence: 0.95,
      description: 'debug=True enables hot-reload and detailed tracebacks on errors. In a deployed environment this leaks stack traces with line-level file paths and the request body.',
      remediation: 'Remove debug=True from production entry points. Use `uvicorn app:app --reload` only on local dev.',
    });
  }

  // 2. Wildcard CORS with credentials — matches both direct instantiation
  // `CORSMiddleware(...)` and `add_middleware(CORSMiddleware, ...)` shapes.
  for (const m of raw.matchAll(/CORSMiddleware[^)]*\)/g)) {
    const block = m[0];
    const hasWildcard = /allow_origins\s*=\s*\[\s*['"]\*['"]\s*\]/.test(block);
    const hasCreds = /allow_credentials\s*=\s*True\b/.test(block);
    if (hasWildcard && hasCreds) {
      findings.push({
        id: `fastapi:cors-wildcard-credentials:${file}:${_line(raw, m.index)}`,
        file, line: _line(raw, m.index),
        vuln: 'FastAPI CORS allow_origins=["*"] combined with allow_credentials=True',
        severity: 'critical',
        family: 'fastapi-cors-wildcard',
        cwe: 'CWE-942',
        confidence: 0.95,
        description: 'Browsers block this combination — but FastAPI still emits Access-Control-Allow-Origin: * which most reverse-proxies and SDKs interpret as "any origin can read credentialed responses." Some browsers no longer enforce; libraries and middleboxes do not.',
        remediation: 'Use an explicit allow-list: allow_origins=["https://app.example.com"]. Never combine wildcard with credentials.',
      });
    } else if (hasWildcard) {
      findings.push({
        id: `fastapi:cors-wildcard:${file}:${_line(raw, m.index)}`,
        file, line: _line(raw, m.index),
        vuln: 'FastAPI CORS allow_origins=["*"]',
        severity: 'medium',
        family: 'fastapi-cors-wildcard',
        cwe: 'CWE-942',
        confidence: 0.85,
        description: 'Wildcard CORS broadens the API\'s exposure to scraping and CSRF-like abuse.',
        remediation: 'Use an explicit allow-list: allow_origins=["https://app.example.com"].',
      });
    }
  }

  // 3. Mutating endpoint without Depends() injecting security
  //
  // PRD T1.2 — this rule previously keyed on a CLOSED list of blessed
  // dependency names (get_current_user|require_auth|verify_jwt|require_admin|
  // oauth2_scheme) and never looked at the handler BODY at all. Measured
  // consequence (independent-population entry GHSA-3cg5-48j3-v4gv): it
  // asserted that a handler declaring `user=Depends(get_verified_user)` and
  // calling `await check_folders_permission(request, user, db=db)` had no auth
  // dependency. Both halves now go through the shared resolver in
  // _auth-signals.js, which recognises the SHAPE rather than an enumeration.
  const mutatingRouteRe = /@\s*(?:app|router)\.(?:post|put|patch|delete)\s*\(\s*['"][^'"]+['"][^)]*\)\s*(?:async\s+)?def\s+(\w+)\s*\(([^)]*)\)/g;
  for (const m of raw.matchAll(mutatingRouteRe)) {
    const params = m[2];
    // The handler body: from the end of the signature to the next top-level
    // decorator/def, so an authorization call inside THIS handler counts and
    // one in the next handler does not.
    const bodyStart = m.index + m[0].length;
    const rest = raw.slice(bodyStart);
    const nextHandler = rest.search(/\n@\s*(?:app|router)\.|\n(?:async\s+)?def\s+/);
    const body = nextHandler === -1 ? rest : rest.slice(0, nextHandler);

    const evidence = routeAuthEvidence({ params, body });
    if (evidence) continue;

    findings.push({
      id: `fastapi:no-auth-dep:${file}:${_line(raw, m.index)}:${m[1]}`,
      file, line: _line(raw, m.index),
      vuln: `FastAPI mutating endpoint ${m[1]}() has no Security() / Depends() auth dependency`,
      severity: 'high',
      family: 'fastapi-missing-auth',
      cwe: 'CWE-862',
      confidence: 0.7,
      description: 'A POST/PUT/PATCH/DELETE handler is declared without a Security(...) or Depends(get_current_user) parameter, and its body performs no recognisable authorization check. Unless a global middleware enforces auth (rare), this endpoint is callable anonymously.',
      remediation: 'Add: current_user: User = Depends(get_current_user) — or Security(oauth2_scheme, scopes=["admin"]) — as a parameter to the route handler.',
      // T2.2 — an absence-claim must record what it looked for, so a reviewer
      // (or a refutation lens) can falsify it.
      checkedFor: 'Depends()/Security() auth dependency in the signature; authorization call or explicit 401/403 in the body',
    });
  }

  // 4. JWT decode without signature verification
  for (const m of raw.matchAll(/\bjwt\.decode\s*\([^)]*verify_signature\s*['"]?\s*:?\s*False/g)) {
    findings.push({
      id: `fastapi:jwt-no-verify:${file}:${_line(raw, m.index)}`,
      file, line: _line(raw, m.index),
      vuln: 'jwt.decode called with verify_signature=False',
      severity: 'critical',
      family: 'fastapi-jwt-no-verify',
      cwe: 'CWE-347',
      confidence: 0.95,
      description: 'jwt.decode with verify_signature=False reads claims without verifying the token. An attacker can forge any claims (including admin roles) and the token will be accepted.',
      remediation: 'Remove verify_signature=False. Always verify against the public key / shared secret.',
    });
  }

  // 5. Pydantic Settings with literal API-key-shaped default
  for (const m of raw.matchAll(/\b(?:[Aa]pi_?[Kk]ey|secret_key|jwt_secret)\s*:\s*str\s*=\s*['"]([A-Za-z0-9!@#$%^&*_+\-=]{12,})['"]/g)) {
    if (/your[-_]?key|change[-_]?me|placeholder|example|TODO/i.test(m[1])) continue;
    findings.push({
      id: `fastapi:hardcoded-default-secret:${file}:${_line(raw, m.index)}`,
      file, line: _line(raw, m.index),
      vuln: 'Pydantic Settings (or similar) has a hardcoded default secret',
      severity: 'critical',
      family: 'fastapi-hardcoded-credential',
      cwe: 'CWE-798',
      confidence: 0.85,
      description: 'A real secret value is the literal default for a config field. Anyone who reads the source has the key.',
      remediation: 'Set the field with no default (forcing env-var provision) or default to None and raise if missing at startup.',
    });
  }

  // 6. TrustedHostMiddleware with wildcard
  for (const m of raw.matchAll(/TrustedHostMiddleware\s*[^)]*allowed_hosts\s*=\s*\[\s*['"]\*['"]\s*\]/g)) {
    findings.push({
      id: `fastapi:trusted-host-wildcard:${file}:${_line(raw, m.index)}`,
      file, line: _line(raw, m.index),
      vuln: 'TrustedHostMiddleware allowed_hosts=["*"]',
      severity: 'medium',
      family: 'fastapi-trusted-host-wildcard',
      cwe: 'CWE-20',
      confidence: 0.9,
      description: 'Disables Host header validation. Combined with downstream URL generation (password-reset emails, OAuth callbacks), attackers can route victims through their own hostnames.',
      remediation: 'Provide an explicit allow-list of your real hostnames.',
    });
  }

  return findings;
}
