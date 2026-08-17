// Rate limiting & abuse prevention advisor.
//
// Vibecoders forget rate limiting on auth, AI, payment, and form endpoints.
// The consequence is account brute-force, $10k+ AI API bills from a single
// attacker, and credential-stuffing. This module detects handler files that
// define sensitive-category routes without a recognisable rate-limit guard.
//
// Findings:
//   RATE_LIMIT_AUTH      — auth endpoint (login/register/forgot) without rate limiting
//   RATE_LIMIT_AI        — AI generation endpoint without rate limiting
//   RATE_LIMIT_PAYMENT   — payment / checkout endpoint without rate limiting
//   RATE_LIMIT_CONTACT   — contact / submit form endpoint without rate limiting
//   RATE_LIMIT_MISSING   — generic API endpoint without rate limiting when no RL lib imported

const _SCAN_EXT_RE = /\.(?:js|jsx|ts|tsx|mjs|cjs)$/i;
const _NONPROD_RE = /(?:^|\/)(?:tests?|__tests__|spec|fixtures?|examples?|node_modules)\//i;

// Rate-limit library imports / usage signals
const RL_IMPORT_RE = /(?:from|require)\s*\(?\s*['"`](?:express-rate-limit|rate-limiter-flexible|@upstash\/ratelimit|hono-rate-limiter|next-rate-limit|bottleneck|p-throttle|@nestjs\/throttler|fastify-rate-limit|koa-ratelimit|slowDown|express-slow-down)['"`]/i;
const RL_USAGE_RE = /\b(?:rateLimit|rateLimiter|limiter|throttle|throttler|createRateLimiter|upstashRatelimit|slidingWindow|fixedWindow|tokenBucket)\s*\(/;
const REDIS_RL_RE = /\b(?:incr|expire|setex)\s*\([^)]*(?:rate|limit|attempt|count)/i;

// Route definition patterns
const ROUTE_DEF_RE = /(?:app|router|server|Route)\s*\.\s*(?:get|post|put|patch|delete|all)\s*\(\s*['"`]([^'"`]+)['"`]/g;
const NEXT_HANDLER_RE = /export\s+(?:default\s+)?(?:async\s+)?function\s+(?:POST|GET|PUT|PATCH|DELETE|handler)\b/;
const NEXT_ROUTE_FILE_RE = /(?:^|\/)(?:app|pages)\/(?:api\/)?([^/]+(?:\/[^/]+)*)\//;

// Sensitive endpoint categories by URL segment
const AUTH_PATH_RE = /\/(?:auth|login|logout|signin|signout|signup|register|forgot|reset|password|verify|otp|mfa|2fa|token|refresh)\b/i;
const AI_PATH_RE = /\/(?:ai|chat|generate|complete|completion|embed|embedding|gpt|claude|llm|openai|anthropic|inference|predict)\b/i;
const PAYMENT_PATH_RE = /\/(?:pay(?:ment)?|checkout|stripe|order|subscribe|billing|invoice|charge|purchase)\b/i;
const CONTACT_PATH_RE = /\/(?:contact|submit|feedback|form|newsletter|subscribe|waitlist|signup|onboard)\b/i;

function _hasRateLimit(content) {
  return RL_IMPORT_RE.test(content) || RL_USAGE_RE.test(content) || REDIS_RL_RE.test(content);
}

function _categorise(path) {
  if (AUTH_PATH_RE.test(path)) return 'auth';
  if (AI_PATH_RE.test(path)) return 'ai';
  if (PAYMENT_PATH_RE.test(path)) return 'payment';
  if (CONTACT_PATH_RE.test(path)) return 'contact';
  return null;
}

const CATEGORY_META = {
  auth: {
    severity: 'high',
    title: 'Auth endpoint missing rate limiting',
    description: 'Authentication endpoints without rate limiting are trivially brute-forced. An attacker can try thousands of passwords per second at zero cost.',
    remediation: 'Add a rate limiter: max 5 attempts per IP per 15 minutes on login/register. Use express-rate-limit, @upstash/ratelimit, or your platform\'s edge middleware.',
    cwe: 'CWE-307',
  },
  ai: {
    severity: 'high',
    title: 'AI generation endpoint missing rate limiting',
    description: 'AI API call endpoints without rate limiting let a single attacker exhaust your entire monthly OpenAI/Anthropic budget in minutes. This is a direct financial attack vector.',
    remediation: 'Add per-user and per-IP rate limits on AI endpoints. Use @upstash/ratelimit for serverless or express-rate-limit for Node servers. Consider per-request cost caps as well.',
    cwe: 'CWE-400',
  },
  payment: {
    severity: 'high',
    title: 'Payment endpoint missing rate limiting',
    description: 'Payment and checkout endpoints without rate limiting enable card-testing attacks where attackers enumerate stolen card numbers at high speed.',
    remediation: 'Add strict rate limiting (max 3 attempts per IP per hour) on payment endpoints. Stripe also recommends enabling Radar rules in the dashboard.',
    cwe: 'CWE-307',
  },
  contact: {
    severity: 'medium',
    title: 'Contact / form endpoint missing rate limiting',
    description: 'Unprotected form submission endpoints are used for spam campaigns, email flooding, and enumeration of valid email addresses.',
    remediation: 'Add rate limiting (max 3 submissions per IP per hour) and consider adding a honeypot field or CAPTCHA for public-facing forms.',
    cwe: 'CWE-400',
  },
};

function scanRateLimit(file, content) {
  if (!_SCAN_EXT_RE.test(file)) return [];
  if (_NONPROD_RE.test(file)) return [];
  if (_hasRateLimit(content)) return [];
  const findings = [];
  const lines = content.split('\n');

  // Check named route definitions
  let m;
  ROUTE_DEF_RE.lastIndex = 0;
  while ((m = ROUTE_DEF_RE.exec(content)) !== null) {
    const routePath = m[1];
    const cat = _categorise(routePath);
    if (cat) {
      const lineNum = content.slice(0, m.index).split('\n').length;
      const meta = CATEGORY_META[cat];
      findings.push({
        id: `rate-limit:RATE_LIMIT_${cat.toUpperCase()}:${file}:${lineNum}`,
        title: meta.title,
        vuln: meta.title,
        severity: meta.severity,
        file, line: lineNum,
        description: meta.description,
        remediation: meta.remediation,
        cwe: meta.cwe,
      });
    }
  }

  // Next.js route handler: infer category from file path
  if (findings.length === 0 && NEXT_HANDLER_RE.test(content)) {
    const filePathMatch = NEXT_ROUTE_FILE_RE.exec(file);
    const routeSegment = filePathMatch ? '/' + filePathMatch[1] : file;
    const cat = _categorise(routeSegment) || _categorise(file);
    if (cat) {
      const handlerLine = lines.findIndex(l => NEXT_HANDLER_RE.test(l)) + 1;
      const meta = CATEGORY_META[cat];
      findings.push({
        id: `rate-limit:RATE_LIMIT_${cat.toUpperCase()}:${file}:${handlerLine}`,
        title: meta.title,
        vuln: meta.title,
        severity: meta.severity,
        file, line: handlerLine,
        description: meta.description,
        remediation: meta.remediation,
        cwe: meta.cwe,
      });
    }
  }

  return findings;
}

export { scanRateLimit };
