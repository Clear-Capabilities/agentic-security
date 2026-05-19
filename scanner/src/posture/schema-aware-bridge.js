// Schema-aware cross-language bridges (P4.1).
//
// The existing cross-lang bridges (`cross-lang-openapi.js`, `cross-lang-grpc.js`,
// `cross-lang-graphql.js`) work by NAME-MATCHING: they pair a JS client's
// `fetch('/api/users/:id')` with a Python `@app.get('/api/users/<id>')`.
// That misses real attack paths whenever:
//   - the client and server disagree on the path shape (`:id` vs `<id>` vs `{id}`)
//   - a field is named differently on each side (clientside `user.email`
//     posted as JSON; serverside reads `data['emailAddress']`)
//   - the schema permits extra fields the server silently uses
//
// SCHEMA-AWARE bridging uses the actual schema document (OpenAPI / proto /
// SDL) as the ground truth and propagates taint via STRUCTURAL FIELD
// IDENTITY rather than name string-equality:
//
//   client posts `{ email, password }` to /signup
//     ↓ (schema says /signup accepts { emailAddress: string, password: string })
//     ↓ rename client.email → schema.emailAddress
//   server reads request.body.emailAddress
//     ↓ inherits client-side taint via schema.emailAddress
//   server passes emailAddress into raw_sql query
//     ↓ cross-language SQL-i chain
//
// This module builds the SCHEMA FIELD GRAPH for an OpenAPI / proto / SDL
// document and exposes a `matchEndpoint(schemaDoc, clientCall)` that
// returns the canonical endpoint shape (path-template + body-schema +
// param-schema) — usable by the existing bridges as an upgrade-in-place.

/**
 * Normalize an OpenAPI 3.x path template to a canonical shape.
 *   `/users/{id}/posts/{postId}` → `/users/:_/posts/:_`
 *   `/users/<id>`               → `/users/:_`
 *   `/users/:id`                → `/users/:_`
 */
export function canonicalizePath(p) {
  if (typeof p !== 'string') return '';
  return p
    .replace(/\{[^}]+\}/g, ':_')
    .replace(/<[^>]+>/g, ':_')
    .replace(/:[A-Za-z0-9_]+/g, ':_')
    .replace(/\/+$/g, '')
    .toLowerCase();
}

/** OpenAPI 3.x → flat list of endpoints with normalized shapes. */
export function indexOpenApi(doc) {
  if (!doc || typeof doc !== 'object') return [];
  const paths = doc.paths || {};
  const out = [];
  for (const [rawPath, ops] of Object.entries(paths)) {
    if (!ops || typeof ops !== 'object') continue;
    for (const [method, def] of Object.entries(ops)) {
      if (!/^(get|post|put|patch|delete|head|options)$/i.test(method)) continue;
      if (!def || typeof def !== 'object') continue;
      const bodySchema = resolveBodySchema(def, doc);
      const paramFields = (def.parameters || [])
        .filter(p => p && (p.in === 'query' || p.in === 'path' || p.in === 'header' || p.in === 'cookie'))
        .map(p => ({ name: p.name, in: p.in, schema: p.schema || null }));
      out.push({
        method: method.toUpperCase(),
        pathRaw: rawPath,
        pathCanon: canonicalizePath(rawPath),
        operationId: def.operationId || null,
        bodyFields: flattenSchemaFields(bodySchema, doc),
        paramFields,
      });
    }
  }
  return out;
}

function resolveBodySchema(def, doc) {
  const rb = def.requestBody;
  if (!rb) return null;
  const content = rb.content || {};
  // Prefer application/json.
  const json = content['application/json'] || content['application/x-www-form-urlencoded'] || Object.values(content)[0];
  if (!json) return null;
  return resolveRef(json.schema, doc);
}

function resolveRef(node, doc) {
  if (!node) return null;
  if (node.$ref) {
    const m = /^#\/components\/schemas\/([^/]+)$/.exec(node.$ref);
    if (m) return doc?.components?.schemas?.[m[1]] || null;
  }
  return node;
}

/** Walk a JSON schema and return a flat list of `{ path, type }` field descriptors. */
export function flattenSchemaFields(schema, doc, prefix = '') {
  if (!schema) return [];
  const resolved = resolveRef(schema, doc);
  if (!resolved) return [];
  if (resolved.type === 'object' && resolved.properties) {
    const out = [];
    for (const [name, prop] of Object.entries(resolved.properties)) {
      const next = prefix ? `${prefix}.${name}` : name;
      const childResolved = resolveRef(prop, doc);
      if (childResolved && (childResolved.type === 'object' || childResolved.properties)) {
        out.push(...flattenSchemaFields(childResolved, doc, next));
      } else {
        out.push({ path: next, type: childResolved?.type || 'unknown' });
      }
    }
    return out;
  }
  if (resolved.type === 'array' && resolved.items) {
    return flattenSchemaFields(resolved.items, doc, prefix ? `${prefix}[*]` : '[*]');
  }
  return prefix ? [{ path: prefix, type: resolved.type || 'unknown' }] : [];
}

/**
 * Match a client-side call site `{ method, path, bodyKeys, queryKeys }`
 * against the schema's endpoints. Returns the matched endpoint (or null)
 * + a field-renaming map { clientKey: serverField } when synonyms are
 * detected.
 *
 * Synonym rules (case-insensitive):
 *   email ↔ emailAddress ↔ mail
 *   pwd ↔ password
 *   id ↔ userId ↔ uid
 *   token ↔ accessToken ↔ authToken
 */
const SYNONYMS = [
  ['email', 'emailaddress', 'mail', 'email_address'],
  ['pwd',   'password',     'pass', 'passwd'],
  ['id',    'userid',       'uid',  'user_id'],
  ['token', 'accesstoken',  'authtoken', 'access_token'],
  ['name',  'fullname',     'displayname', 'full_name'],
];
const SYN_INDEX = new Map();
for (const grp of SYNONYMS) for (const w of grp) SYN_INDEX.set(w, grp);

function _norm(s) { return String(s || '').toLowerCase().replace(/[_-]/g, ''); }
function _areSynonyms(a, b) {
  const na = _norm(a), nb = _norm(b);
  if (na === nb) return true;
  const ga = SYN_INDEX.get(na);
  if (!ga) return false;
  return ga.includes(nb);
}

export function matchEndpoint(schemaIndex, clientCall) {
  if (!Array.isArray(schemaIndex) || !clientCall) return null;
  const methodU = (clientCall.method || 'GET').toUpperCase();
  const pathC   = canonicalizePath(clientCall.path || '');
  // Exact (method, path canonical) match first.
  let best = null;
  for (const ep of schemaIndex) {
    if (ep.method !== methodU) continue;
    if (ep.pathCanon !== pathC) continue;
    best = ep; break;
  }
  if (!best) return null;
  // Build the rename map between client-side body keys and server-side fields.
  const rename = {};
  const clientKeys = Array.isArray(clientCall.bodyKeys) ? clientCall.bodyKeys : [];
  const serverFields = best.bodyFields.map(f => f.path);
  for (const ck of clientKeys) {
    if (serverFields.includes(ck)) { rename[ck] = ck; continue; }
    const hit = serverFields.find(sf => _areSynonyms(ck, sf));
    if (hit) rename[ck] = hit;
  }
  return { endpoint: best, rename };
}

/**
 * gRPC proto → endpoint index. Accepts the AST shape produced by a generic
 * proto3 parser (just the field tuples we care about: service + rpc + msg).
 */
export function indexProto(protoAst) {
  if (!protoAst || !Array.isArray(protoAst.services)) return [];
  const messages = new Map();
  for (const m of (protoAst.messages || [])) messages.set(m.name, m.fields || []);
  const out = [];
  for (const svc of protoAst.services) {
    for (const rpc of (svc.rpcs || [])) {
      out.push({
        service: svc.name,
        method:  rpc.name,
        requestType:  rpc.requestType,
        responseType: rpc.responseType,
        requestFields:  messages.get(rpc.requestType)  || [],
        responseFields: messages.get(rpc.responseType) || [],
      });
    }
  }
  return out;
}

/**
 * GraphQL SDL → operation index.
 */
export function indexGraphQL(sdlAst) {
  if (!sdlAst || !Array.isArray(sdlAst.types)) return [];
  const types = new Map();
  for (const t of sdlAst.types) types.set(t.name, t.fields || []);
  const query  = types.get('Query') || [];
  const mutation = types.get('Mutation') || [];
  const out = [];
  for (const f of query)    out.push({ op: 'Query',    name: f.name, args: f.args || [], returns: f.returns });
  for (const f of mutation) out.push({ op: 'Mutation', name: f.name, args: f.args || [], returns: f.returns });
  return out;
}
