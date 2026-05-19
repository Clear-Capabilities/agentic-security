// FR-PROD-5 — Crown-jewel / business-impact mapping.
//
// Score each file (and, where possible, function) by the loss exposure if it
// is compromised. CVSS knows nothing about your business. A SQL-injection in
// a public health-check is `info`; the same SQLi in a Stripe webhook handler
// is "you just lost the customer's revenue stream + their trust." We map
// files to a 0..1 business-impact score so findings can be ranked by
// proximity to actual crown-jewel paths.
//
// Signals (each pushes the score up, capped at 1.0):
//
//   Path patterns:
//     - /admin/, /internal/, /backoffice/  → 0.30
//     - /billing/, /checkout/, /webhooks/, /payment/, /stripe/ → 0.40
//     - /auth/, /login/, /session/, /tokens/, /password/ → 0.35
//     - /users/, /accounts/, /profiles/  → 0.20
//     - /api/v\d+/  → +0.05 (public API surface)
//
//   File content:
//     - imports stripe / paddle / braintree → +0.30
//     - imports auth0 / clerk / next-auth / @auth0 → +0.25
//     - references DROP TABLE / DELETE FROM / TRUNCATE → +0.15
//     - references private keys / KMS / signing keys → +0.25
//     - schema files (prisma, drizzle, sequelize) → +0.20
//
//   Filename hints:
//     - *.health.* / */health/* / readiness → -0.30 (deliberate downgrade)
//     - *.test.*, */tests/* → -0.50 (test code, no prod blast radius)
//     - */docs/, README → -0.50
//
// The score is ordinal — use it to rank findings, not as a probability.

const PATH_BUMPS = [
  [/\/(?:admin|internal|backoffice|staff)\b/i, 0.30, 'admin-path'],
  [/\/(?:billing|checkout|webhooks?|payment|stripe|paddle|braintree)\b/i, 0.40, 'revenue-path'],
  [/\/(?:auth|login|session|tokens?|password|oauth)\b/i, 0.35, 'auth-path'],
  [/\/(?:users?|accounts?|profiles?|members?)\b/i, 0.20, 'identity-path'],
  [/\/api\/v\d+\b/, 0.05, 'public-api-surface'],
  [/\/(?:secrets?|keys?|kms|vault)\b/i, 0.30, 'secrets-path'],
  [/\/(?:health|healthz|readiness|liveness|ping|status|metrics)\b/i, -0.30, 'health-check'],
  [/(?:\.test\.|\.spec\.|\/tests?\/|__tests__\/|\/fixtures?\/|\/mocks?\/)/i, -0.50, 'test-code'],
  [/(?:\/docs?\/|README|CHANGELOG)/i, -0.50, 'docs-code'],
];

const CONTENT_BUMPS = [
  [/(?:require|import).{0,40}\b(?:stripe|@paddle|braintree|@chargebee|adyen|@lemonsqueezy)\b/i, 0.30, 'imports-payments'],
  [/(?:require|import).{0,40}\b(?:auth0|@clerk\/|next-auth|@auth\/|lucia-auth|workos|@okta\/)\b/i, 0.25, 'imports-auth'],
  [/\b(?:DROP\s+TABLE|DELETE\s+FROM|TRUNCATE\s+TABLE|GRANT\s+ALL)\b/i, 0.15, 'destructive-sql'],
  [/(?:PRIVATE\s+KEY|@aws-crypto|@google-cloud\/kms|@azure\/keyvault|jsonwebtoken|jose|signKey|signingKey)/, 0.25, 'crypto-keys'],
  [/datasource\s+db|generator\s+client|model\s+\w+\s*\{|drizzle\.config|@sequelize/, 0.20, 'schema-file'],
  [/req\.(?:user|account|tenant)\.(?:id|email|role|tier)/, 0.10, 'session-context'],
  [/\b(?:exec|spawn|spawnSync|child_process)\b/, 0.15, 'shell-execution'],
  [/process\.env\.(?:[A-Z_]*_KEY|[A-Z_]*_SECRET|[A-Z_]*_TOKEN)/, 0.10, 'reads-secret-env'],
];

export function scoreFile(filePath, content) {
  let score = 0;
  const factors = [];
  if (filePath) {
    for (const [re, bump, label] of PATH_BUMPS) {
      if (re.test(filePath)) { score += bump; factors.push(label); }
    }
  }
  if (content && typeof content === 'string') {
    const sample = content.length > 32_000 ? content.slice(0, 32_000) : content;
    for (const [re, bump, label] of CONTENT_BUMPS) {
      if (re.test(sample)) { score += bump; factors.push(label); }
    }
  }
  score = Math.max(0, Math.min(1, score));
  let tier;
  if (score >= 0.65) tier = 'crown-jewel';
  else if (score >= 0.40) tier = 'high-value';
  else if (score >= 0.20) tier = 'standard';
  else if (score === 0) tier = 'unknown';
  else tier = 'low-value';
  return { score: Number(score.toFixed(2)), tier, factors };
}

export function mapCrownJewels(fileContents) {
  if (!fileContents || typeof fileContents !== 'object') return {};
  const map = {};
  for (const [fp, content] of Object.entries(fileContents)) {
    const r = scoreFile(fp, content);
    if (r.score > 0 || r.factors.length > 0) map[fp] = r;
  }
  return map;
}

export function annotateCrownJewelScores(findings, fileContents) {
  if (!Array.isArray(findings)) return findings;
  const map = mapCrownJewels(fileContents || {});
  for (const f of findings) {
    if (!f || typeof f !== 'object') continue;
    const fp = f.file;
    if (!fp) continue;
    const r = map[fp];
    if (!r) {
      const fallback = scoreFile(fp, fileContents?.[fp] || '');
      f.crownJewelScore = fallback.score;
      f.crownJewelTier = fallback.tier;
      f.crownJewelFactors = fallback.factors;
    } else {
      f.crownJewelScore = r.score;
      f.crownJewelTier = r.tier;
      f.crownJewelFactors = r.factors;
    }
  }
  return findings;
}
