// Two-tenant records service for the threat-model pilot (PRD FR-08.1). Loopback only, synthetic data, no credentials of any value.
//
// GET /records/:id returns a record; GET /health is an unrelated route with the same method. Each variant is an "artifact": its
// identity is the digest of its handler source, so evidence is bound to the code that produced it.
//
//   vulnerable  returns the record to anyone (no credential, a rejected credential, or another tenant's actor)
//   fixed       401 for a missing or rejected credential, 403 for another tenant, 200 for the rightful tenant
//   deny-all    403 to everyone: a "fix" that breaks the legitimate case
//
// The service writes one JSON log line per request with SANITIZED evidence from its own identity and policy decisions: the auth outcome,
// the actor and object tenants, the decision, and an opt-in join key (the request id). The credential value is never written.
// `omitAuthFacts` drops the outcome and tenants, the way a log without trusted identity fields looks (PILOT-08).
import http from 'node:http';
import crypto from 'node:crypto';

const TOKENS = { 'token-tenant-a': 'tenant-a', 'token-tenant-b': 'tenant-b' };

function decide(variant, actorTenant, authOutcome, objectTenant) {
  if (variant === 'vulnerable') return { status: 200, decision: 'allow' };
  if (variant === 'deny-all') return { status: 403, decision: 'deny' };
  if (authOutcome !== 'authenticated') return { status: 401, decision: 'deny' };
  if (actorTenant !== objectTenant) return { status: 403, decision: 'deny' };
  return { status: 200, decision: 'allow' };
}

export const VARIANTS = ['vulnerable', 'fixed', 'deny-all'];
/** The artifact identity of a variant: the digest of the decision code and the variant name. */
export const artifactDigest = (variant) => crypto.createHash('sha256').update(`${variant}\n${decide.toString()}`).digest('hex');

/** Start the service on an ephemeral loopback port. Returns { url, records, logLines, close, artifact }. */
export async function startRecordsService({ variant, omitAuthFacts = false, seed = 'pilot' } = {}) {
  if (!VARIANTS.includes(variant)) throw new Error(`unknown variant ${variant}`);
  const marker = `MARKER-B-${crypto.createHash('sha256').update(seed).digest('hex').slice(0, 12)}`;
  const records = { 'r-b-1': { tenant: 'tenant-b', body: marker } };
  const logLines = [];
  let n = 0;
  const server = http.createServer((req, res) => {
    const requestId = `req-${++n}`;
    const url = new URL(req.url, 'http://127.0.0.1');
    const authz = req.headers.authorization;
    const token = typeof authz === 'string' && authz.startsWith('Bearer ') ? authz.slice(7) : null;
    const actorTenant = token ? TOKENS[token] ?? null : null;
    const authOutcome = actorTenant ? 'authenticated' : 'unauthenticated';
    let status = 404; let body = ''; let objectTenant = null; let decision = null;
    const m = /^\/records\/([A-Za-z0-9-]+)$/.exec(url.pathname);
    if (req.method === 'GET' && url.pathname === '/health') { status = 200; body = 'ok'; }
    else if (req.method === 'GET' && m && records[m[1]]) {
      objectTenant = records[m[1]].tenant;
      ({ status, decision } = decide(variant, actorTenant, authOutcome, objectTenant));
      if (status === 200) body = records[m[1]].body;
    }
    const entry = { '@timestamp': new Date().toISOString(), request_id: requestId, method: req.method, path: url.pathname, status,
      headers: { ...(authz !== undefined ? { authorization: '[redacted]' } : {}), accept: String(req.headers.accept ?? '*/*') } };
    if (!omitAuthFacts) Object.assign(entry, { authenticated: authOutcome === 'authenticated', ...(actorTenant ? { identity: { tenant: actorTenant } } : {}), ...(objectTenant ? { object: { tenant: objectTenant } } : {}), ...(decision ? { authz: { decision } } : {}) });
    logLines.push(JSON.stringify(entry));
    res.writeHead(status, { 'content-type': 'text/plain', 'x-request-id': requestId });
    res.end(body);
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address();
  return {
    url: `http://127.0.0.1:${port}`, marker, records, logLines, artifact: { variant, digest: artifactDigest(variant) },
    close: () => new Promise((r) => server.close(r)),
  };
}

/** The client oracle: it records only whether the protected marker came back, and the join key. Never the body itself. */
export async function observe(svc, path, { token = null } = {}) {
  const headers = token === null ? {} : { authorization: `Bearer ${token}` };
  const r = await fetch(`${svc.url}${path}`, { headers });
  const text = await r.text();
  return { status: r.status, markerDelivered: text.includes(svc.marker), requestId: r.headers.get('x-request-id') };
}
