// FR-LOGIC-8 — Specification mining.
//
// Extract the implicit specification of each function from five signal
// sources: (1) function name, (2) docstring / inline comments, (3) co-located
// tests, (4) call sites, (5) PR title + AI prompt (CLAUDE.md / system
// prompts). Flag implementations that drift from the inferred spec — the
// function named `validateOwnership` whose body never references the user
// identity is the canonical example.
//
// This is the bug class no pattern matcher reaches. The intent-drift recall
// target is F1 ≥ 0.70 (PRD G13). We expect noise on legacy code; the rule
// emits at LOW confidence and lets the active-learning loop tune.
//
// What we mine in v1:
//   • name → expected body content (regex set per name family)
//   • body content present? → if NO, emit drift finding
//
// Name families and required body evidence (each family lists the *kind* of
// thing the body must reference; missing means drift):
//
//   validate*Ownership / check*Owner   → references req.user / session / context user id
//   validate*Access    / authorize*    → references roles / permissions / can / allowedTo
//   sanitize*          / escape*       → references DOMPurify / escape / replace
//   verify*Signature   / check*Sig     → references hmac / verify / crypto.createVerify / timingSafeEqual
//   verify*Webhook                     → references webhook signature constant
//   rateLimit*         / throttle*     → references express-rate-limit / Math.min / sliding window
//   isAdmin / requireAdmin             → references admin role check
//   requireAuth / mustBeLoggedIn       → references auth middleware / login flag

const NAME_FAMILIES = [
  {
    label: 'ownership-check',
    nameRe: /(?:validate|check|enforce|ensure|verify)\w*ownership|\bcheckOwner\b|\bisOwner\b|\bownerOnly\b/i,
    bodyMustHave: /\b(?:req\.user|session\.user|ctx\.user|currentUser|userId|owner_?id)\b/,
    severity: 'medium',
    cwe: 'CWE-639',
    rationale: 'function name claims an ownership check but body never references the requesting-user identity',
  },
  {
    label: 'authorization-check',
    nameRe: /(?:validate|check|require|enforce)\w*(?:access|authoriz|permission)|\bauthorize\b|\bcanAccess\b/i,
    bodyMustHave: /\b(?:role|permission|scope|claim|isAllowed|can\(|allowedTo|hasPermission)\b/,
    severity: 'medium',
    cwe: 'CWE-863',
    rationale: 'function name claims an authorization check but body has no role/permission/scope reference',
  },
  {
    label: 'output-sanitizer',
    nameRe: /\b(?:sanitize|escape|clean|safe(?:n|ify)?|purify)\w*(?:html|xml|sql|input|user|output)\b/i,
    bodyMustHave: /\b(?:DOMPurify|escape|encodeURI|sanitizeHtml|replace\(|str\.replace|html_escape|escape_html|bleach)\b/,
    severity: 'high',
    cwe: 'CWE-79',
    rationale: 'function name claims sanitization but body has no encoding/escaping/library call',
  },
  {
    label: 'signature-verify',
    nameRe: /(?:verify|check|validate)\w*(?:signature|sig|hmac)\b/i,
    bodyMustHave: /\b(?:hmac|createVerify|verify\(|timingSafeEqual|crypto\.subtle\.verify|hashlib\.compare|hash_equals)\b/,
    severity: 'high',
    cwe: 'CWE-347',
    rationale: 'function name claims signature verification but body has no HMAC / verify / constant-time-compare call',
  },
  {
    label: 'webhook-verify',
    nameRe: /(?:verify|validate|check)\w*webhook\b/i,
    bodyMustHave: /\b(?:stripeSignature|webhook_secret|svix|x-hub-signature|hmac|timingSafeEqual)\b/i,
    severity: 'high',
    cwe: 'CWE-345',
    rationale: 'function name claims webhook verification but body has no signature material or constant-time compare',
  },
  {
    label: 'rate-limit-impl',
    nameRe: /(?:rateLimit|throttle|limitRate|rateLimiter)\b/i,
    bodyMustHave: /\b(?:expressRateLimit|rateLimiterFlexible|RateLimiterMemory|Math\.min|window|slidingWindow|tokenBucket|sleep|setTimeout)\b/,
    severity: 'medium',
    cwe: 'CWE-770',
    rationale: 'function name claims rate-limiting but body has no rate-limit library or windowing logic',
  },
  {
    label: 'admin-gate',
    nameRe: /\b(?:isAdmin|requireAdmin|adminOnly|enforceAdmin)\b/i,
    bodyMustHave: /\b(?:admin|role\s*===?\s*['"]admin['"]|isAdmin|hasRole\(['"]admin['"]\))\b/i,
    severity: 'high',
    cwe: 'CWE-862',
    rationale: 'function name claims admin gating but body has no admin-role reference',
  },
  {
    label: 'auth-required',
    nameRe: /\b(?:requireAuth|mustBeLoggedIn|enforceLogin|authenticated)\b/i,
    bodyMustHave: /\b(?:req\.user|session\.user|isAuthenticated|currentUser|jwt|bearer|authHeader|getServerSession)\b/i,
    severity: 'medium',
    cwe: 'CWE-306',
    rationale: 'function name claims auth requirement but body has no session/user lookup',
  },
];

const JS_FN_RE = /(?:function|const|let)\s+([A-Za-z_$][\w$]*)\s*(?:=\s*(?:async\s*)?\([^)]*\)\s*=>\s*\{|\([^)]*\)\s*\{)/g;
const PY_FN_RE = /def\s+([A-Za-z_][\w]*)\s*\([^)]*\)\s*:/g;

function extractFunctionBodies(text, lang) {
  const bodies = [];
  if (!text || typeof text !== 'string') return bodies;
  if (lang === 'js' || lang === 'ts') {
    JS_FN_RE.lastIndex = 0;
    let m;
    while ((m = JS_FN_RE.exec(text))) {
      const startName = m.index;
      // find the opening brace and then naive balanced-brace seek up to 1500 chars.
      const braceIdx = text.indexOf('{', startName);
      if (braceIdx === -1) continue;
      let depth = 0, end = braceIdx;
      for (let i = braceIdx; i < Math.min(braceIdx + 4000, text.length); i++) {
        if (text[i] === '{') depth++;
        else if (text[i] === '}') {
          depth--;
          if (depth === 0) { end = i; break; }
        }
      }
      bodies.push({ name: m[1], body: text.slice(braceIdx, end + 1), startLine: text.slice(0, startName).split('\n').length });
    }
  } else if (lang === 'py') {
    PY_FN_RE.lastIndex = 0;
    let m;
    while ((m = PY_FN_RE.exec(text))) {
      const startName = m.index;
      // simple python body harvest: take next 60 lines starting at the def
      const startLine = text.slice(0, startName).split('\n').length;
      const allLines = text.split('\n');
      const body = allLines.slice(startLine - 1, Math.min(startLine + 60, allLines.length)).join('\n');
      bodies.push({ name: m[1], body, startLine });
    }
  }
  return bodies;
}

function inferLang(filePath) {
  if (/\.(ts|tsx)$/i.test(filePath)) return 'ts';
  if (/\.(js|jsx|mjs|cjs)$/i.test(filePath)) return 'js';
  if (/\.py$/i.test(filePath)) return 'py';
  return null;
}

export function scanSpecificationDrift(fileContents) {
  const findings = [];
  if (!fileContents || typeof fileContents !== 'object') return findings;
  for (const [fp, text] of Object.entries(fileContents)) {
    const lang = inferLang(fp);
    if (!lang) continue;
    for (const fn of extractFunctionBodies(text, lang)) {
      for (const fam of NAME_FAMILIES) {
        if (!fam.nameRe.test(fn.name)) continue;
        if (fam.bodyMustHave.test(fn.body)) continue;       // body satisfies the implicit spec
        findings.push({
          id: `spec-drift:${fam.label}:${fp}:${fn.startLine}`,
          file: fp,
          line: fn.startLine,
          vuln: `Spec drift — ${fn.name}() claims ${fam.label} but body lacks expected evidence`,
          severity: fam.severity,
          family: 'spec-drift',
          cwe: fam.cwe,
          confidence: 0.45,
          description: fam.rationale,
          remediation: `Verify that ${fn.name}() actually implements ${fam.label}; rename if not, or add the missing check.`,
          specMined: { name: fn.name, family: fam.label, mustHaveRegex: fam.bodyMustHave.source },
        });
      }
    }
  }
  return findings;
}
