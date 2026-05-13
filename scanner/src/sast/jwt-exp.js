import { blankComments } from './_comment-strip.js';
// JWT expiration and bcrypt cost-factor checks.
//
// JWT-no-exp:
//   jwt.sign(payload, secret)                — no options block at all
//   jwt.sign(payload, secret, { algorithm }) — options without expiresIn
// Safe shapes:
//   - jwt.sign(payload, secret, { expiresIn: '15m' })
//   - jwt.sign(payload, secret, { exp: ... })  (claim in payload)
//   - payload contains `exp:` field           (claim in payload)
//
// Weak-bcrypt:
//   bcrypt.hash(password, n)  where n < 10    — too-fast brute-forceable
//   bcrypt.hashSync(password, n) where n < 10
//   bcryptjs same shape

// We do not flag `decode`/`verify` — those are read paths. Only `sign` is at risk
// of issuing eternal tokens.
const JWT_SIGN_RE = /\b(?:jwt|jsonwebtoken)\s*\.\s*sign\s*\(/g;
const JWT_OPTS_EXPIRESIN_RE = /\bexpiresIn\s*:/;
const JWT_PAYLOAD_EXP_RE = /\bexp\s*:\s*(?:Math\.floor|Date\.now|\d+)/;

const BCRYPT_HASH_RE = /\b(?:bcrypt|bcryptjs)\s*\.\s*(?:hash|hashSync)\s*\(\s*[^,)]+,\s*(\d+)\s*[,)]/g;

function _lineOf(raw, idx) { return raw.substring(0, idx).split('\n').length; }

// Best-effort: extract the full call expression starting at `start` so we can
// scan its argument list for the expiresIn key. Respects nested parens and
// strings.
function _extractCallArgs(code, start) {
  // start is at the '(' character — find its matching ')'
  let depth = 0;
  let inS = null;
  for (let i = start; i < code.length; i++) {
    const c = code[i];
    if (inS) {
      if (c === '\\') { i++; continue; }
      if (c === inS) inS = null;
      continue;
    }
    if (c === "'" || c === '"' || c === '`') { inS = c; continue; }
    if (c === '(') depth++;
    else if (c === ')') { depth--; if (depth === 0) return code.substring(start + 1, i); }
  }
  return null;
}

export function scanJwtExp(fp, raw) {
  if (!/\.(?:js|jsx|ts|tsx|mjs|cjs)$/i.test(fp)) return [];
  if (!raw || raw.length > 500_000) return [];
  const findings = [];
  const seen = new Set();
  const push = (f) => { if (!seen.has(f.id)) { seen.add(f.id); findings.push(f); } };
  // Blank out comments while keeping every character index in sync with raw.
  const code = blankComments(raw);

  // JWT sign without expiresIn / exp
  const re = new RegExp(JWT_SIGN_RE.source, JWT_SIGN_RE.flags);
  let m;
  while ((m = re.exec(code))) {
    const openParen = code.indexOf('(', m.index);
    if (openParen < 0) continue;
    const args = _extractCallArgs(code, openParen);
    if (args == null) continue;
    if (JWT_OPTS_EXPIRESIN_RE.test(args)) continue;
    if (JWT_PAYLOAD_EXP_RE.test(args)) continue;
    const line = _lineOf(raw, m.index);
    push({
      id: `jwt-exp:${fp}:${line}`,
      file: fp, line,
      vuln: 'Eternal Token: JWT issued without expiresIn / exp claim',
      severity: 'high',
      cwe: 'CWE-613',
      stride: 'Spoofing',
      snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
      remediation: 'Always set an `expiresIn` (or an `exp` claim) when signing a JWT. Eternal tokens cannot be revoked except by rotating the signing key for every issued token. Recommended: `jwt.sign(payload, secret, { algorithm: "HS256", expiresIn: "15m" })` and refresh via a separate, server-tracked refresh token.',
      confidence: 0.85,
      parser: 'JWT-EXP',
    });
  }

  // Weak bcrypt cost factor
  const bre = new RegExp(BCRYPT_HASH_RE.source, BCRYPT_HASH_RE.flags);
  let bm;
  while ((bm = bre.exec(code))) {
    const cost = parseInt(bm[1], 10);
    if (!Number.isFinite(cost) || cost >= 10) continue;
    const line = _lineOf(raw, bm.index);
    push({
      id: `bcrypt-cost:${fp}:${line}`,
      file: fp, line,
      vuln: `Weak bcrypt cost factor (${cost}) — too fast for password storage`,
      severity: cost < 8 ? 'high' : 'medium',
      cwe: 'CWE-916',
      stride: 'Information Disclosure',
      snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
      remediation: `bcrypt cost ${cost} is below the modern minimum. Use cost 12+ (about 250 ms per hash on a 2024 server CPU). Cost is logarithmic — each +1 doubles work. If you have legacy hashes at cost ${cost}, rehash transparently on the next successful login.`,
      confidence: 0.95,
      parser: 'BCRYPT-COST',
    });
  }

  return findings;
}
