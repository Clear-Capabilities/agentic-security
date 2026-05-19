// FR-LOGIC-9 — Counterfactual analysis (reverse blast radius for controls).
//
// For each defensive control found in the code (auth check, sanitizer guard,
// CSRF middleware, rate-limit middleware, type guard), compute the reverse
// blast radius: how many existing findings would become critical or exposed
// if THIS control were removed or bypassed?
//
// The output is a list of `single-point-of-failure` records — controls whose
// removal would expose ≥ 3 findings at high+. These are the controls that
// most deserve hardening attention BEFORE an attacker tests them. The output
// also feeds the trust-boundary diagram.
//
// We deliberately do NOT modify the findings themselves; we emit a separate
// `counterfactualReport` artifact that lives on the scan object.

const CONTROL_PATTERNS = [
  // Each entry: [name, regex, family of finding this control mitigates]
  ['auth-middleware',      /(?:requireAuth|authMiddleware|isAuthenticated|verifyJWT|@login_required|protect|requireLogin|getServerSession)\s*\(/g, ['missing-authz', 'broken-auth', 'idor']],
  ['csrf-middleware',      /(?:csrf|csurf|csrfProtection|CSRFProtect|CsrfFilter)\s*\(/g, ['csrf']],
  ['rate-limiter',         /(?:rateLimit|expressRateLimit|RateLimiter|rateLimiterFlexible)\s*\(/g, ['unbounded-llm', 'broken-auth']],
  ['xss-sanitizer',        /(?:DOMPurify\.sanitize|sanitizeHtml|escape|bleach\.clean|html_safe)\s*\(/g, ['xss']],
  ['sql-param',            /\.(?:prepare|query)\s*\([^)]{0,40}\$\d|\?|placeholder/g, ['sql-injection']],
  ['url-validator',        /(?:validateUrl|isValidUrl|url\.parse|new URL\()/g, ['ssrf', 'open-redirect']],
  ['path-validator',       /(?:path\.normalize|path\.resolve|isPathInside|safe_join)\s*\(/g, ['path-traversal']],
  ['signature-verify',     /(?:hmac|createVerify|timingSafeEqual|verify_signature|stripe\.webhooks\.constructEvent)\s*\(/g, ['webhook-no-signature']],
  ['admin-gate',           /(?:isAdmin|requireAdmin|hasRole\(['"]admin['"])/g, ['idor', 'missing-authz']],
];

function detectControls(fileContents) {
  const controls = [];
  if (!fileContents) return controls;
  for (const [fp, text] of Object.entries(fileContents)) {
    if (!text || typeof text !== 'string') continue;
    for (const [name, re, mitigatesFamilies] of CONTROL_PATTERNS) {
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(text))) {
        const line = text.slice(0, m.index).split('\n').length;
        controls.push({ name, file: fp, line, mitigates: mitigatesFamilies });
      }
    }
  }
  return controls;
}

function familyOfFinding(f) {
  if (f.family) return String(f.family).toLowerCase();
  const v = (f.vuln || '').toLowerCase();
  if (/sql.*injection/.test(v)) return 'sql-injection';
  if (/command.*injection/.test(v)) return 'command-injection';
  if (/xss|cross.site/.test(v)) return 'xss';
  if (/ssrf/.test(v)) return 'ssrf';
  if (/idor/.test(v)) return 'idor';
  if (/missing.auth/.test(v)) return 'missing-authz';
  if (/broken.auth|jwt|session/.test(v)) return 'broken-auth';
  if (/csrf/.test(v)) return 'csrf';
  if (/path.travers/.test(v)) return 'path-traversal';
  if (/open.redirect/.test(v)) return 'open-redirect';
  if (/webhook.*sign/.test(v)) return 'webhook-no-signature';
  if (/max_tokens|unbounded/.test(v)) return 'unbounded-llm';
  return 'unknown';
}

export function runCounterfactual(findings, fileContents) {
  const controls = detectControls(fileContents);
  if (!controls.length) return { spofControls: [], note: 'no-controls-detected' };

  // For each control, count how many findings it currently mitigates and
  // how many would become exposed if it were removed.
  const byMitigates = new Map();
  for (const c of controls) {
    const key = `${c.name}@${c.file}:${c.line}`;
    if (!byMitigates.has(key)) byMitigates.set(key, { control: c, exposedIfRemoved: [] });
  }

  if (Array.isArray(findings)) {
    for (const f of findings) {
      if (!f || typeof f !== 'object') continue;
      const fam = familyOfFinding(f);
      if (fam === 'unknown') continue;
      // A control that's in the same file as the finding (proxy for "this
      // route uses this control") and that lists `fam` in its mitigates set
      // is treated as a current mitigator.
      for (const [key, rec] of byMitigates) {
        if (rec.control.file !== f.file) continue;
        if (!rec.control.mitigates.includes(fam)) continue;
        // Only flag the finding as "exposed if removed" if it currently has
        // severity high+ — small bugs don't deserve a SPOF alarm.
        if (['critical', 'high'].includes(f.severity)) {
          rec.exposedIfRemoved.push({ family: fam, file: f.file, line: f.line, severity: f.severity });
        }
      }
    }
  }

  const spofControls = [];
  for (const [, rec] of byMitigates) {
    if (rec.exposedIfRemoved.length >= 3) {
      spofControls.push({
        control: rec.control.name,
        location: `${rec.control.file}:${rec.control.line}`,
        wouldExpose: rec.exposedIfRemoved.length,
        examples: rec.exposedIfRemoved.slice(0, 5),
        recommendation: `${rec.control.name} at ${rec.control.file}:${rec.control.line} is a single point of failure for ${rec.exposedIfRemoved.length} high+ findings. Consider redundant defense-in-depth.`,
      });
    }
  }
  return { spofControls, controlsDetected: controls.length };
}
