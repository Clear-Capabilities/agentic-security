// Live-secret validation (#22) — label a detected secret live | dead | unknown.
//
// "This Stripe/GitHub key is LIVE and was committed 40 commits ago" is a P0 the
// vibecoder must rotate now; "you have a high-entropy string" is noise. This
// closes that gap for the providers with a cheap, read-only "whoami" check.
//
// STRICTLY opt-in (a --validate-secrets flag / AGENTIC_SECURITY_VALIDATE_SECRETS)
// and OFFLINE-DEGRADING: any network error, timeout, or unrecognized provider
// yields 'unknown' — never a false 'dead'. No runtime cloud calls by default,
// per the scanner's no-network-by-default convention. The request builder is
// pure (no I/O) so it's testable without hitting a provider.

// Map a detected secret to a read-only validation request, or null when we have
// no safe check for that provider. Only providers whose token is a self-
// contained bearer/token credential (no signing, no extra params) are covered.
function buildLiveCheckRequest(secret) {
  const val = (secret && (secret.match || secret.value || secret.secret || secret.token)) || '';
  if (typeof val !== 'string' || val.length < 8) return null;

  // GitHub PAT / OAuth token → GET /user (200 = live, 401 = dead).
  if (/^gh[posru]_[A-Za-z0-9]{20,}$/.test(val) || /^github_pat_[A-Za-z0-9_]{20,}$/.test(val)) {
    return { provider: 'github', method: 'GET', url: 'https://api.github.com/user',
      headers: { Authorization: `token ${val}`, 'User-Agent': 'agentic-security', Accept: 'application/vnd.github+json' } };
  }
  // Stripe secret key → GET /v1/account (200 = live, 401 = dead).
  if (/^sk_live_[A-Za-z0-9]{16,}$/.test(val) || /^rk_live_[A-Za-z0-9]{16,}$/.test(val)) {
    return { provider: 'stripe', method: 'GET', url: 'https://api.stripe.com/v1/account',
      headers: { Authorization: `Bearer ${val}` } };
  }
  // OpenAI key → GET /v1/models.
  if (/^sk-[A-Za-z0-9]{20,}$/.test(val) && !/^sk_live_/.test(val)) {
    return { provider: 'openai', method: 'GET', url: 'https://api.openai.com/v1/models',
      headers: { Authorization: `Bearer ${val}` } };
  }
  // SendGrid key → GET /v3/scopes.
  if (/^SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}$/.test(val)) {
    return { provider: 'sendgrid', method: 'GET', url: 'https://api.sendgrid.com/v3/scopes',
      headers: { Authorization: `Bearer ${val}` } };
  }
  return null;
}

// Classify an HTTP status into a liveness verdict. 200-2xx = live; 401/403 =
// dead (rejected credential); anything else = unknown (rate-limit, 5xx, etc. —
// we don't know, so don't claim dead).
function classifyStatus(status) {
  if (status >= 200 && status < 300) return 'live';
  if (status === 401 || status === 403) return 'dead';
  return 'unknown';
}

// Perform the validation. Returns { verdict: 'live'|'dead'|'unknown', provider }.
// Offline-degrading: on any error/timeout, verdict is 'unknown'.
export async function checkSecretLive(secret, { timeoutMs = 4000 } = {}) {
  const req = buildLiveCheckRequest(secret);
  if (!req) return { verdict: 'unknown', provider: null };
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const r = await fetch(req.url, { method: req.method, headers: req.headers, signal: ctrl.signal });
    return { verdict: classifyStatus(r.status), provider: req.provider };
  } catch {
    return { verdict: 'unknown', provider: req.provider };
  } finally {
    clearTimeout(t);
  }
}

// Pure surfaces exposed for tests (no network) — kept off the public API so the
// dead-module guard doesn't flag them; `checkSecretLive` is the wired entry.
export const _internal = { buildLiveCheckRequest, classifyStatus };
