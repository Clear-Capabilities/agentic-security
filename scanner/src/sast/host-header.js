// Host header attack detection.
//
// req.headers.host / req.host is attacker-controlled (HTTP/1.1 lets clients
// set whatever Host they want; even with allowlisted hostnames, reverse
// proxies often forward whatever they receive). When used to build:
//   - password-reset / email-verification URLs   → Account-takeover via
//                                                    poisoned reset link
//   - server-side redirects (Location header)    → Open redirect / phishing
//   - cache keys                                  → Cache poisoning
// the attacker controls the URL embedded in security-sensitive emails or in
// downstream caches.
//
// Patterns:
//   `https://${req.headers.host}/reset?token=...`
//   `'http://' + req.headers.host + '/verify?token=...'`
//   res.redirect(req.headers.host + ...)
//
// Safe shapes (file-level suppression of a finding):
//   - An ALLOWED_HOSTS/TRUSTED_HOSTS array compared against the header

const HOST_SOURCE_RE = /\b(?:req|request|ctx)\s*\.\s*(?:headers\s*(?:\.|\[\s*['"])\s*host\s*['"]?\s*\]?|host(?![A-Za-z_]))/g;
const HOST_X_FORWARDED_RE = /\b(?:req|request|ctx)\s*\.\s*(?:headers\s*(?:\.|\[\s*['"])\s*x-forwarded-host\s*['"]?\s*\]?)/g;

// Reset / verify URL pattern: hostSource concatenated/interpolated with reset/verify path.
const RESET_URL_TEMPLATE_RE = /`[^`]*\$\{[^}]*\b(?:req|request|ctx)\s*\.\s*(?:headers\s*(?:\.|\[\s*['"])\s*(?:host|x-forwarded-host)\s*['"]?\s*\]?|host(?![A-Za-z_]))[^}]*\}[^`]*(?:reset|verify|confirm|invite|onboard|password|token|auth|magic)[^`]*`/gi;
const RESET_URL_CONCAT_RE = /['"][^'"]*(?:https?:\/\/|^\/|^)['"][^;]{0,80}?(?:req|request|ctx)\s*\.\s*(?:headers\.host|host|headers\[['"]host['"]\])[^;]{0,200}?(?:reset|verify|confirm|invite|password|token|auth|magic)/gi;

// Direct redirect using host header
const HOST_IN_REDIRECT_RE = /\b(?:res|response)\s*\.\s*(?:redirect|location)\s*\([^)]*\b(?:req|request|ctx)\s*\.\s*(?:headers\.host|host|headers\[['"]host['"]\])/g;

const TRUSTED_HOSTS_RE = /\b(?:ALLOWED_HOSTS|TRUSTED_HOSTS|allowedHosts|trustedHosts|hostAllowlist|hostnameAllowlist|validHosts)\b/;

import { blankComments } from './_comment-strip.js';

function _lineOf(raw, idx) { return raw.substring(0, idx).split('\n').length; }

export function scanHostHeader(fp, raw) {
  if (!/\.(?:js|jsx|ts|tsx|mjs|cjs|py)$/i.test(fp)) return [];
  if (!raw || raw.length > 500_000) return [];
  // Blank out comments while preserving character indices.
  const code = /\.py$/i.test(fp) ? blankComments(raw, 'py') : blankComments(raw);
  const findings = [];
  const seen = new Set();
  const push = (f) => { if (!seen.has(f.id)) { seen.add(f.id); findings.push(f); } };
  const hasAllowlist = TRUSTED_HOSTS_RE.test(code);

  // 1. Template literal with host + reset/verify keyword
  const tre = new RegExp(RESET_URL_TEMPLATE_RE.source, RESET_URL_TEMPLATE_RE.flags);
  let m;
  while ((m = tre.exec(code))) {
    if (hasAllowlist) continue;
    const line = _lineOf(raw, m.index);
    push({
      id: `host-header:${fp}:${line}:reset-tpl`,
      file: fp, line,
      vuln: 'Host Header Attack: password-reset / verify URL built from req.headers.host',
      severity: 'high',
      cwe: 'CWE-20',
      stride: 'Spoofing',
      snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
      remediation: 'An attacker can set the Host header to a domain they control; if your reset email then embeds that host, the recipient clicks a link pointing at attacker-controlled infrastructure that captures the token. Use a server-side constant (process.env.PUBLIC_HOST) for any URL that lands in an email, or validate req.headers.host against an explicit allowlist of canonical hostnames.',
      confidence: 0.85,
      parser: 'HOST-HEADER',
    });
  }

  // 2. String concatenation form (looser shape)
  const cre = new RegExp(RESET_URL_CONCAT_RE.source, RESET_URL_CONCAT_RE.flags);
  while ((m = cre.exec(code))) {
    if (hasAllowlist) continue;
    const line = _lineOf(raw, m.index);
    push({
      id: `host-header:${fp}:${line}:reset-concat`,
      file: fp, line,
      vuln: 'Host Header Attack: reset/verify URL concatenates req.headers.host',
      severity: 'high',
      cwe: 'CWE-20',
      stride: 'Spoofing',
      snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
      remediation: 'Replace req.headers.host with process.env.PUBLIC_HOST (or equivalent server-side constant). For multi-tenant apps that legitimately need request-derived hosts, validate against a per-tenant allowlist.',
      confidence: 0.7,
      parser: 'HOST-HEADER',
    });
  }

  // 3. Redirect using host header
  const rre = new RegExp(HOST_IN_REDIRECT_RE.source, HOST_IN_REDIRECT_RE.flags);
  while ((m = rre.exec(code))) {
    if (hasAllowlist) continue;
    const line = _lineOf(raw, m.index);
    push({
      id: `host-header:${fp}:${line}:redirect`,
      file: fp, line,
      vuln: 'Host Header Attack: redirect target uses req.headers.host',
      severity: 'high',
      cwe: 'CWE-601',
      stride: 'Spoofing',
      snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
      remediation: 'A server-side redirect to req.headers.host lets the attacker pick the destination. Use a fixed canonical URL or an explicit per-tenant allowlist.',
      confidence: 0.85,
      parser: 'HOST-HEADER',
    });
  }

  return findings;
}
