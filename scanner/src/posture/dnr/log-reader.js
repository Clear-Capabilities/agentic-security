// Bounded, streaming reader for historical HTTP logs (PRD 7, requirement 4). Logs are hostile input: a file may be huge,
// binary, symlinked, line-less or crafted to blow up a parser. Everything here has a cap and a clock, and every cap that is
// reached is REPORTED (`truncated`, `budgetExhausted`, skipped-file reasons) so the hunt can answer INCONCLUSIVE rather than
// pretend it searched everything.
//
// Production logs stay local: this module reads files and calls a callback. It imports no network module, and a test pins
// that. Understood shapes: Apache/nginx common and combined access logs, JSON lines (including Envoy and generic structured
// loggers). Anything else on a line is a parse failure, counted, never guessed at.
import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline';

export const LIMITS = Object.freeze({ maxFiles: 500, maxDepth: 4, maxFileBytes: 256 * 1024 * 1024, maxTotalBytes: 2 * 1024 * 1024 * 1024, maxLines: 20_000_000, maxLineChars: 32 * 1024, maxParams: 200, budgetMs: 10 * 60 * 1000 });
const TEXT_EXT = /\.(?:log|txt|json|jsonl|ndjson|access|out)$|^[^.]+$/i;
const MONTHS = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };
const CLF = /^(\S+) \S+ (\S+) \[([^\]]+)\] "([A-Z]{3,8}) (\S+)(?: HTTP\/[\d.]+)?" (\d{3}|-) (?:\d+|-)/;

const decode = (s) => { try { return decodeURIComponent(String(s).replace(/\+/g, ' ')); } catch { return String(s); } };

export function parseQuery(qs, cap = LIMITS.maxParams) {
  const out = {};
  let n = 0;
  for (const part of String(qs ?? '').split('&')) {
    if (!part) continue;
    if (++n > cap) break;
    const i = part.indexOf('=');
    const k = decode(i === -1 ? part : part.slice(0, i));
    const v = i === -1 ? '' : decode(part.slice(i + 1));
    if (k.length > 128) continue;
    (out[k] ??= []).push(v);
  }
  return out;
}

function parseTime(v) {
  if (v == null || v === '') return null;
  if (typeof v === 'number' && Number.isFinite(v)) { const ms = v > 1e12 ? v : v * 1000; const d = new Date(ms); return Number.isNaN(d.getTime()) ? null : d.toISOString(); }
  const s = String(v);
  const clf = /^(\d{1,2})\/([A-Za-z]{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-]\d{4})$/.exec(s);
  if (clf && clf[2] in MONTHS) {
    const off = clf[7];
    const sign = off[0] === '-' ? -1 : 1;
    const offMin = sign * (Number(off.slice(1, 3)) * 60 + Number(off.slice(3, 5)));
    return new Date(Date.UTC(Number(clf[3]), MONTHS[clf[2]], Number(clf[1]), Number(clf[4]), Number(clf[5]), Number(clf[6])) - offMin * 60000).toISOString();
  }
  if (/^\d{9,13}(?:\.\d+)?$/.test(s)) return parseTime(Number(s));
  // GA-10 §2 (0.195.31): a timestamp with no zone (`2026-03-14 02:13:44`, `2026-03-14T02:13:44`) used to be read in the host's
  // local time, so the same line placed an event at different instants on different machines. It is ambiguous, not dated:
  // the event is still searched, it is reported through `timeAmbiguous`, and the hunt says the window is not fully known.
  if (ZONELESS.test(s)) return null;
  const d = new Date(s);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}
const ZONELESS = /^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?)?$/;
/** True when a raw timestamp carries a date and time but no zone, so it cannot be placed on the UTC line without a guess. */
export function timeIsAmbiguous(raw) { return raw != null && raw !== '' && typeof raw !== 'number' && ZONELESS.test(String(raw)) && /[T ]\d{2}:\d{2}/.test(String(raw)); }

function flatten(obj, prefix = '', depth = 0, out = {}) {
  for (const [k, v] of Object.entries(obj)) {
    const key = prefix ? `${prefix}.${k}` : k;
    if (v && typeof v === 'object' && !Array.isArray(v) && depth < 3) flatten(v, key, depth + 1, out);
    else out[key.toLowerCase()] = v;
  }
  return out;
}
const pick = (flat, names) => { for (const n of names) if (flat[n] !== undefined && flat[n] !== null && flat[n] !== '') return flat[n]; return undefined; };

function fromRequestTarget(target) {
  const t = String(target);
  const i = t.indexOf('?');
  const p = i === -1 ? t : t.slice(0, i);
  return { path: p.startsWith('http') ? (() => { try { return new URL(p).pathname; } catch { return null; } })() : p, query: i === -1 ? {} : parseQuery(t.slice(i + 1)) };
}

/** One log line -> normalized event, or null when it is not a request record in a shape this reader understands. */
export function parseLine(line) {
  const text = line.trim();
  if (!text) return undefined; // blank: neither parsed nor failed
  if (text[0] === '{') {
    let obj;
    try { obj = JSON.parse(text); } catch { return null; }
    if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return null;
    const f = flatten(obj);
    const method = pick(f, ['method', 'request_method', 'http.request.method', 'http.method', 'req.method', 'request.method', 'httpmethod', 'verb']);
    let target = pick(f, ['path', 'uri', 'url', 'request_uri', ':path', 'url.path', 'request.path', 'req.url', 'http.url', 'request.uri', 'url.original', 'requesturi']);
    const requestLine = pick(f, ['request']); // "GET /x HTTP/1.1" in some structured loggers
    let m = method;
    if (!target && typeof requestLine === 'string') { const rl = /^([A-Z]{3,8}) (\S+)/.exec(requestLine); if (rl) { m = m ?? rl[1]; target = rl[2]; } }
    if (typeof target !== 'string' && typeof m !== 'string') return null;
    // `flatten` dissolves nested objects, so a structured body or query is read from the original object
    const nested = (...chain) => chain.reduce((acc, k) => (acc && typeof acc === 'object' ? acc[k] : undefined), obj);
    const qsField = pick(f, ['query', 'query_string', 'url.query', 'request.query', 'querystring']) ?? nested('query') ?? nested('request', 'query') ?? nested('url', 'query');
    const tgt = typeof target === 'string' ? fromRequestTarget(target) : { path: undefined, query: undefined };
    let query = tgt.query;
    if (typeof qsField === 'string') query = { ...(query ?? {}), ...parseQuery(qsField.replace(/^\?/, '')) };
    else if (qsField && typeof qsField === 'object') query = { ...(query ?? {}), ...Object.fromEntries(Object.entries(qsField).slice(0, LIMITS.maxParams).map(([k, v]) => [k, [].concat(v).map(String)])) };
    const bodyRaw = pick(f, ['body', 'request_body', 'request.body', 'http.request.body.content', 'req.body', 'payload']) ?? nested('body') ?? nested('request', 'body') ?? nested('req', 'body') ?? nested('http', 'request', 'body', 'content') ?? nested('payload');
    let bodyParams = null;
    if (typeof bodyRaw === 'string') {
      try { const j = JSON.parse(bodyRaw); bodyParams = j && typeof j === 'object' && !Array.isArray(j) ? Object.fromEntries(Object.entries(flatten(j)).slice(0, LIMITS.maxParams).map(([k, v]) => [k, [String(v)]])) : { '': [bodyRaw] }; } catch { bodyParams = bodyRaw.includes('=') ? parseQuery(bodyRaw) : { '': [bodyRaw] }; }
    } else if (bodyRaw && typeof bodyRaw === 'object') bodyParams = Object.fromEntries(Object.entries(flatten(bodyRaw)).slice(0, LIMITS.maxParams).map(([k, v]) => [k, [String(v)]]));
    const headers = {};
    let sawHeaders = false;
    for (const [k, v] of Object.entries(f)) {
      const hm = /^(?:request\.)?headers?\.(.+)$/.exec(k) || /^http\.request\.headers\.(.+)$/.exec(k);
      if (hm) { headers[hm[1]] = String(v); sawHeaders = true; }
    }
    const authHeader = headers.authorization ?? pick(f, ['authorization']);
    const authFlag = pick(f, ['authenticated', 'is_authenticated', 'auth.present']);
    // Legacy: one boolean where a header wins over everything. Kept for existing callers; detections read the two facts below.
    const authPresent = authHeader != null ? true : typeof authFlag === 'boolean' ? authFlag : (sawHeaders ? false : null);
    const statusRaw = pick(f, ['status', 'status_code', 'response_code', 'http.response.status_code', 'sc-status', 'response.status', 'res.statuscode']);
    const status = Number.isInteger(Number(statusRaw)) && statusRaw !== undefined ? Number(statusRaw) : null;
    const rawTime = pick(f, ['@timestamp', 'timestamp', 'time', 'ts', 'start_time', 'datetime', 'date']);
    // GA-10 §2 (0.195.31): every parser limit that can DROP a value is reported on the event, so the hunt can say that a payload past
    // the limit would not have been seen; before, a query of 201 parameters or a body nested four deep was cut in silence.
    const truncated = [];
    const countParams = (qs) => String(qs ?? '').split('&').filter(Boolean).length;
    const over = (o) => o && typeof o === 'object' && !Array.isArray(o) && Object.keys(flatten(o)).length > LIMITS.maxParams;
    const deep = (o) => o && typeof o === 'object' && !Array.isArray(o) && Object.values(flatten(o)).some((v) => v && typeof v === 'object' && !Array.isArray(v));
    if (typeof target === 'string' && target.includes('?') && countParams(target.slice(target.indexOf('?') + 1)) > LIMITS.maxParams) truncated.push('query-params');
    if (typeof qsField === 'string' && countParams(qsField.replace(/^\?/, '')) > LIMITS.maxParams) truncated.push('query-params');
    if (qsField && typeof qsField === 'object' && Object.keys(qsField).length > LIMITS.maxParams) truncated.push('query-params');
    let bodyObj = bodyRaw && typeof bodyRaw === 'object' ? bodyRaw : null;
    if (typeof bodyRaw === 'string') { try { bodyObj = JSON.parse(bodyRaw); } catch { bodyObj = null; } }
    if (over(bodyObj)) truncated.push('body-params');
    if (deep(bodyObj)) truncated.push('body-depth');
    return { timeAmbiguous: timeIsAmbiguous(rawTime), truncated: [...new Set(truncated)].length ? [...new Set(truncated)] : null, time: parseTime(rawTime), method: typeof m === 'string' ? m.toUpperCase() : null, path: tgt.path ?? null, query: query ?? null, bodyParams, headers: sawHeaders ? headers : null, status, authPresent, ...authFacts(f, authHeader, sawHeaders) };
  }
  const c = CLF.exec(text);
  if (c) {
    const { path: p, query } = fromRequestTarget(c[5]);
    return { time: parseTime(c[3]), method: c[4], path: p, query, bodyParams: null, headers: null, status: c[6] === '-' ? null : Number(c[6]), authPresent: null, ...UNKNOWN_AUTH };
  }
  return null;
}

// ── authentication and authorization facts (PRD threat-model FR-07.1, FR-07.5) ──────────────────────────────────────────────────────
// Credential PRESENCE and the verified authentication OUTCOME are separate facts. A header only says a credential was sent; an
// authoritative `authenticated: false` (or an auth result of "rejected") says it was refused, and survives a redacted header. Missing or
// conflicting outcome fields leave the outcome `unknown`. Identity and policy fields (actor tenant, object tenant, a cross-tenant grant,
// the authorization decision) are read only from these mapped field names, never from request headers, query or body, which the client
// controls.
const OUTCOME_FIELDS = ['authenticated', 'is_authenticated', 'auth.authenticated', 'auth.outcome', 'auth.result', 'authn.outcome', 'authn.result'];
const ACTOR_TENANT_FIELDS = ['identity.tenant', 'actor.tenant', 'auth.tenant', 'principal.tenant'];
const OBJECT_TENANT_FIELDS = ['object.tenant', 'resource.tenant', 'record.tenant'];
const GRANT_FIELDS = ['authz.cross_tenant_grant', 'authz.delegated', 'authz.crossTenantGrant'];
const DECISION_FIELDS = ['authz.decision', 'authz.result'];
const UNKNOWN_AUTH = Object.freeze({ credentialPresent: null, authOutcome: 'unknown', actorTenant: null, objectTenant: null, crossTenantGrant: null, authzDecision: null });

function outcomeOf(v) {
  if (v === true) return 'authenticated';
  if (v === false) return 'unauthenticated';
  const s = String(v ?? '').trim().toLowerCase();
  if (/^(?:true|success|succeeded|ok|authenticated|allow|allowed|valid)$/.test(s)) return 'authenticated';
  if (/^(?:false|failure|failed|rejected|denied|invalid|unauthenticated|anonymous|none|expired)$/.test(s)) return 'unauthenticated';
  return null;
}
const ident = (v) => (v === undefined || v === null || v === '' ? null : String(v).slice(0, 128));

function authFacts(f, authHeader, sawHeaders) {
  const outcomes = new Set(OUTCOME_FIELDS.map((k) => f[k]).filter((v) => v !== undefined).map(outcomeOf).filter(Boolean));
  const authOutcome = outcomes.size === 1 ? [...outcomes][0] : 'unknown';
  const presentFlag = f['auth.present'];
  const credentialPresent = authHeader != null ? true : typeof presentFlag === 'boolean' ? presentFlag : (sawHeaders ? false : null);
  const grant = GRANT_FIELDS.map((k) => f[k]).find((v) => v !== undefined);
  const decision = DECISION_FIELDS.map((k) => f[k]).find((v) => v !== undefined);
  const d = String(decision ?? '').toLowerCase();
  return {
    credentialPresent,
    authOutcome: outcomes.size > 1 ? 'conflict' : authOutcome,
    actorTenant: ident(pick(f, ACTOR_TENANT_FIELDS)),
    objectTenant: ident(pick(f, OBJECT_TENANT_FIELDS)),
    crossTenantGrant: grant === true || grant === 'true' ? true : grant === false || grant === 'false' ? false : null,
    authzDecision: /^(?:allow|allowed|permit|granted)$/.test(d) ? 'allow' : /^(?:deny|denied|forbidden|refused)$/.test(d) ? 'deny' : null,
  };
}

function collectFiles(root, limits, skipped) {
  const out = [];
  const walk = (p, depth) => {
    let st;
    try { st = fs.lstatSync(p); } catch { skipped.push({ file: path.basename(p), reason: 'unreadable' }); return; }
    if (st.isSymbolicLink()) { skipped.push({ file: path.basename(p), reason: 'symlink' }); return; }
    if (st.isDirectory()) {
      if (depth > limits.maxDepth) { skipped.push({ file: path.basename(p), reason: 'too-deep' }); return; }
      let names = [];
      try { names = fs.readdirSync(p).sort(); } catch { skipped.push({ file: path.basename(p), reason: 'unreadable' }); return; }
      for (const n of names) walk(path.join(p, n), depth + 1);
      return;
    }
    if (!st.isFile()) return;
    if (/\.(?:gz|zip|bz2|xz|zst|tgz)$/i.test(p)) { skipped.push({ file: path.basename(p), reason: 'compressed-unsupported' }); return; }
    if (!TEXT_EXT.test(path.basename(p))) { skipped.push({ file: path.basename(p), reason: 'not-a-log-extension' }); return; }
    if (out.length >= limits.maxFiles) { skipped.push({ file: path.basename(p), reason: 'file-count-limit' }); return; }
    out.push({ file: p, size: st.size });
  };
  walk(root, 0);
  return out;
}

/**
 * Stream every request record under `target` through `onEvent(event)`. Never throws on bad content.
 * @returns stats: files, lines, parsed/failed counts, time window, per-field availability, and every limit that was hit.
 */
export async function readLogs(target, { onEvent, signal, limits: over = {} } = {}) {
  const limits = { ...LIMITS, ...over };
  const stats = { files: [], filesSkipped: [], lines: 0, parsed: 0, failed: 0, oversizeLines: 0, eventsTruncated: 0, ambiguousTime: 0, windowStart: null, windowEnd: null, eventsWithTime: 0, fieldCounts: { method: 0, path: 0, query: 0, body: 0, headers: 0, status: 0, auth: 0, authOutcome: 0, tenant: 0 }, truncated: [], budgetExhausted: false, aborted: false, unreadable: false };
  let st;
  try { st = fs.lstatSync(target); } catch { stats.unreadable = true; return stats; }
  if (st.isSymbolicLink()) { stats.unreadable = true; stats.filesSkipped.push({ file: path.basename(target), reason: 'symlink' }); return stats; }
  const base = st.isDirectory() ? target : path.dirname(target);
  const files = st.isDirectory() ? collectFiles(target, limits, stats.filesSkipped) : collectFiles(target, limits, stats.filesSkipped);
  const deadline = Date.now() + limits.budgetMs;
  let totalBytes = 0;
  for (const { file, size } of files) {
    if (signal?.aborted) { stats.aborted = true; break; }
    if (Date.now() > deadline) { stats.budgetExhausted = true; stats.truncated.push('time-budget'); break; }
    if (size > limits.maxFileBytes) { stats.filesSkipped.push({ file: path.relative(base, file), reason: 'file-too-large' }); stats.truncated.push('file-too-large'); continue; }
    if (totalBytes + size > limits.maxTotalBytes) { stats.filesSkipped.push({ file: path.relative(base, file), reason: 'total-size-limit' }); stats.truncated.push('total-size-limit'); continue; }
    totalBytes += size;
    const fstat = { name: path.relative(base, file) || path.basename(file), bytes: size, lines: 0, parsed: 0, failed: 0 };
    stats.files.push(fstat);
    const stream = fs.createReadStream(file, { encoding: 'utf8', highWaterMark: 1 << 20 });
    const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });
    try {
      for await (const line of rl) {
        if (signal?.aborted) { stats.aborted = true; break; }
        if ((fstat.lines & 0x3ff) === 0 && Date.now() > deadline) { stats.budgetExhausted = true; stats.truncated.push('time-budget'); break; }
        if (stats.lines >= limits.maxLines) { stats.truncated.push('line-limit'); break; }
        stats.lines++; fstat.lines++;
        if (line.length > limits.maxLineChars) { stats.oversizeLines++; stats.failed++; fstat.failed++; continue; }
        const ev = parseLine(line);
        if (ev === undefined) continue;
        if (ev === null) { stats.failed++; fstat.failed++; continue; }
        stats.parsed++; fstat.parsed++;
        if (ev.method) stats.fieldCounts.method++;
        if (ev.path != null) stats.fieldCounts.path++;
        if (ev.query != null) stats.fieldCounts.query++;
        if (ev.bodyParams != null) stats.fieldCounts.body++;
        if (ev.headers != null) stats.fieldCounts.headers++;
        if (ev.status != null) stats.fieldCounts.status++;
        if (ev.authPresent != null) stats.fieldCounts.auth++;
        if (ev.authOutcome === 'authenticated' || ev.authOutcome === 'unauthenticated') stats.fieldCounts.authOutcome++;
        if (ev.actorTenant != null && ev.objectTenant != null) stats.fieldCounts.tenant++;
        if (ev.truncated) stats.eventsTruncated++;
        if (ev.timeAmbiguous) stats.ambiguousTime++;
        if (ev.time) { stats.eventsWithTime++; if (!stats.windowStart || ev.time < stats.windowStart) stats.windowStart = ev.time; if (!stats.windowEnd || ev.time > stats.windowEnd) stats.windowEnd = ev.time; }
        onEvent?.(ev);
      }
    } catch { stats.filesSkipped.push({ file: fstat.name, reason: 'read-error' }); } finally { rl.close(); stream.destroy(); }
    if (stats.aborted || stats.budgetExhausted || stats.truncated.includes('line-limit')) break;
  }
  stats.truncated = [...new Set(stats.truncated)];
  return stats;
}
