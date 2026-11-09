// PILOT-12 fixtures (threat-model PRD FR-08.3): one app-to-cloud chain and one bounded database-backed injection proof, loopback and
// synthetic only.
//
// The app-to-cloud chain. An export service runs as workload identity `app` with principal tag tenant=tenant-a and fetches objects from
// a stand-in object store. The store enforces the fixture IAM policy with ITS OWN evaluator, written separately from the scanner's
// (`lineage/deployment/iam-eval.js`), so the observed effect is adjudicated independently of the graph that predicts it. It supports
// exactly: Allow/Deny, exact or trailing-`*` actions and resources, and StringEquals/StringNotEquals on aws:PrincipalTag/tenant;
// anything else is refused as unsupported rather than guessed.
//
// The database proof. A records search builds its query by concatenation (vulnerable) or binds the parameter (fixed), over an
// in-memory SQLite database seeded with one record per tenant. The proof input is a fixed tautology; the oracle records only whether
// another tenant's marker came back. Results are capped at 10 rows and the database is discarded after each run.
import http from 'node:http';
import crypto from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';

export const POLICIES = {
  vulnerable: { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::records/*' }] },
  // the repair scopes the identity to its own tenant's prefix
  fixed: { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::records/tenant-a/*' }] },
  // the same intent as a conditional deny: the store decides it, the graph (no request context for this key) reports it unresolved
  conditional: { Version: '2012-10-17', Statement: [
    { Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::records/*' },
    { Effect: 'Deny', Action: 's3:GetObject', Resource: 'arn:aws:s3:::records/*', Condition: { StringNotEquals: { 'aws:PrincipalTag/tenant': 'tenant-b' } } },
  ] },
};
export const OBJECTS = { 'arn:aws:s3:::records/tenant-a/report.csv': 'MARKER-A-REPORT', 'arn:aws:s3:::records/tenant-b/report.csv': 'MARKER-B-REPORT' };
const digest = (x) => `sha256:${crypto.createHash('sha256').update(typeof x === 'string' ? x : JSON.stringify(x)).digest('hex')}`;
export const policyDigest = (name) => digest(POLICIES[name]);

// the store's own evaluator (independent of the scanner's)
const like = (pat, v) => (pat.endsWith('*') ? v.startsWith(pat.slice(0, -1)) : pat === v);
function storeDecides(policy, { action, resource, tags }) {
  let allowed = false;
  for (const st of policy.Statement) {
    const acts = [].concat(st.Action); const ress = [].concat(st.Resource);
    if (!acts.some((a) => like(a, action)) || !ress.some((r) => like(r, resource))) continue;
    let holds = true;
    for (const [op, block] of Object.entries(st.Condition || {})) {
      for (const [key, val] of Object.entries(block)) {
        if (key !== 'aws:PrincipalTag/tenant' || !['StringEquals', 'StringNotEquals'].includes(op)) return { decision: 'unsupported', reason: `${op} ${key}` };
        const eq = [].concat(val).includes(tags.tenant);
        holds = holds && (op === 'StringEquals' ? eq : !eq);
      }
    }
    if (!holds) continue;
    if (st.Effect === 'Deny') return { decision: 'deny' };
    allowed = true;
  }
  return { decision: allowed ? 'allow' : 'deny' };
}

/** The export service plus its object store. `variant` picks the policy the identity runs under. */
export async function startCloudChain({ policy }) {
  const tags = { tenant: 'tenant-a' };
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    if (url.pathname !== '/export') { res.writeHead(404); return res.end(); }
    // the vulnerable step in the application: the object key comes straight from the request, unvalidated
    const resource = `arn:aws:s3:::records/${url.searchParams.get('key') ?? ''}`;
    const d = storeDecides(POLICIES[policy], { action: 's3:GetObject', resource, tags });
    if (d.decision !== 'allow') { res.writeHead(d.decision === 'unsupported' ? 501 : 403); return res.end(d.decision); }
    const body = OBJECTS[resource];
    res.writeHead(body ? 200 : 404); res.end(body ?? '');
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return { url: `http://127.0.0.1:${server.address().port}`, policyDigest: policyDigest(policy), close: () => new Promise((r) => server.close(r)) };
}

/** The export service's artifact identity: the digest of its handler and its store's evaluator. */
export const cloudArtifactDigest = () => digest(`${startCloudChain.toString()}\n${storeDecides.toString()}`);

export const DB_APPS = {
  vulnerable: (db, tenant, name) => db.prepare(`SELECT marker FROM records WHERE tenant = '${tenant}' AND name = '${name}' LIMIT 10`).all(),
  fixed: (db, tenant, name) => db.prepare('SELECT marker FROM records WHERE tenant = ? AND name = ? LIMIT 10').all(tenant, name),
};
export const dbArtifactDigest = (variant) => digest(DB_APPS[variant].toString());

/** One bounded run of the records search: a fresh seeded database, one query, the database discarded. */
export function runDbSearch(variant, { tenant, name }) {
  const db = new DatabaseSync(':memory:');
  try {
    db.exec("CREATE TABLE records (tenant TEXT, name TEXT, marker TEXT); INSERT INTO records VALUES ('tenant-a', 'invoice', 'MARKER-A-DB'), ('tenant-b', 'invoice', 'MARKER-B-DB');");
    let rows; let error = null;
    try { rows = DB_APPS[variant](db, tenant, name); } catch (e) { rows = []; error = e.code || 'query-error'; }
    const markers = rows.map((r) => r.marker);
    return { rows: rows.length, otherTenantMarker: markers.some((m) => !m.startsWith(`MARKER-${tenant.slice(-1).toUpperCase()}`)), ownMarker: markers.some((m) => m.startsWith(`MARKER-${tenant.slice(-1).toUpperCase()}`)), error };
  } finally { db.close(); }
}
