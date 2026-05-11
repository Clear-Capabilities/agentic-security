// True positive: API key compared without constant-time
const provided = req.headers['x-api-key'];
if (provided === process.env.API_KEY) {
  authenticated = true;
}

// True positive: hash compared
if (req.body.hash === process.env.WEBHOOK_SECRET) ok();

// True positive: variable named token compared to env
const expectedToken = process.env.AUTH_TOKEN;
if (token === expectedToken) authenticate();

// False positive: feature flag, not a secret
const quiet = process.env.AGENTIC_SECURITY_QUIET === '1';

// False positive: env-vs-literal flag check
if (process.env.NODE_ENV === 'production') enableMetrics();

// False positive: numeric comparison
if (process.env.PORT === '3000') log('default');
