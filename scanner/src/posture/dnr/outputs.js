// Renderers for a detection IR (PRD 7, requirement 2): Sigma-compatible logic, a generic HTTP detection, generic WAF
// suggestions, a structured log query and YARA where it is appropriate. The P1 renderers (Splunk SPL, Microsoft Sentinel KQL,
// CloudWatch Logs Insights) are text only; nothing here connects to a SIEM.
//
// Every value interpolated into a rule comes from the IR, and the IR is closed-world (detection-ir.js), so a rule can only
// contain what a proof established. Each renderer escapes for ITS target's quoting rules, because an endpoint path or a
// parameter name is hostile input (it came from a reproducer a model may have written).
import { PAYLOAD_CLASSES } from './payload-classes.js';

export const FORMATS = Object.freeze(['sigma', 'http', 'waf', 'log-query', 'yara', 'spl', 'kql', 'cloudwatch', 'elastic', 'yaral', 'datadog']);

/** One regular expression (source text, case-insensitive) covering a class's indicators. */
export function classRegex(className) {
  const def = PAYLOAD_CLASSES[className];
  if (!def) return null;
  if (def.matcher === 'length') return `.{${def.minLength},}`;
  if (def.matcher === 'behavior') return null;
  return def.indicators.map((re) => `(?:${re.source})`).join('|');
}

const hasTemplate = (p) => /\/(?::[A-Za-z_]\w*|\{[A-Za-z_]\w*\})(?=\/|$)/.test(p);
const escRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
/** A path template as an anchored regular expression. */
function pathRegex(path) {
  return `^${path.split('/').map((seg) => (/^(?::[A-Za-z_]\w*|\{[A-Za-z_]\w*\})$/.test(seg) ? '[^/]+' : escRe(seg))).join('/')}$`;
}

const levelFor = (ir) => (ir.confidence >= 0.8 ? 'high' : ir.confidence >= 0.5 ? 'medium' : 'low');
const title = (ir) => `Exploitation attempt: ${ir.payloadClass} against ${ir.endpoint ? `${ir.endpoint.method} ${ir.endpoint.path}` : 'an application endpoint'}`;
const numericRuleId = (ir) => 9000000 + (parseInt(ir.digest.slice(0, 5), 16) % 999999);
const unavailable = (reason) => ({ applicable: false, reason });
const fpNotes = (ir) => [
  'A legitimate client that sends this payload shape to the same endpoint (a security scanner, a penetration test).',
  ...(ir.payloadClass === 'auth-bypass' ? ['Public endpoints that are intentionally reachable without a credential.'] : []),
];

/** Sigma rule as YAML text. JSON string syntax is used for every scalar; it is valid YAML and cannot be broken out of. */
function sigma(ir) {
  if (!ir.endpoint) return unavailable('no endpoint is known for this finding, so there is no request to describe');
  const q = JSON.stringify;
  const lines = [
    `title: ${q(title(ir))}`,
    `id: ${q(`${ir.digest.slice(0, 8)}-${ir.digest.slice(8, 12)}-${ir.digest.slice(12, 16)}-${ir.digest.slice(16, 20)}-${ir.digest.slice(20, 32)}`)}`,
    'status: experimental',
    `description: ${q(`${ir.attackBehavior}. Generated from finding ${ir.findingId} (${ir.grounding}).`)}`,
    'references:', `  - ${q(`finding:${ir.findingId}`)}`,
    'author: agentic-security',
    'logsource:', '  category: webserver',
    'detection:', '  selection_request:',
    `    cs-method: ${q(ir.endpoint.method)}`,
  ];
  if (hasTemplate(ir.endpoint.path)) lines.push(`    cs-uri-stem|re: ${q(pathRegex(ir.endpoint.path))}`);
  else lines.push(`    cs-uri-stem: ${q(ir.endpoint.path)}`);
  let condition = 'selection_request';
  if (ir.payloadClass === 'auth-bypass') {
    lines.push('  selection_outcome:', '    sc-status|startswith: "2"', '  filter_credential:', '    cs-authorization|exists: true');
    condition = 'selection_request and selection_outcome and not filter_credential';
  } else {
    const field = ir.parameter?.location === 'body' ? 'request-body' : ir.parameter?.location === 'header' ? `cs(${ir.parameter.name})` : ir.parameter?.location === 'cookie' ? 'cs-cookie' : 'cs-uri-query';
    lines.push('  selection_payload:', `    ${field}|re|i: ${q(classRegex(ir.payloadClass))}`);
    condition = 'selection_request and selection_payload';
  }
  lines.push(`  condition: ${condition}`, 'falsepositives:', ...fpNotes(ir).map((n) => `  - ${q(n)}`), `level: ${levelFor(ir)}`,
    'tags:', '  - attack.initial_access', '  - attack.t1190', ...(ir.cwe ? [`  - ${q(String(ir.cwe).toLowerCase().replace('cwe-', 'cwe.'))}`] : []));
  return { applicable: true, format: 'sigma', content: `${lines.join('\n')}\n` };
}

function http(ir) {
  if (!ir.endpoint) return unavailable('no endpoint is known for this finding');
  const def = PAYLOAD_CLASSES[ir.payloadClass];
  const detection = {
    schema: 'agentic-security/http-detection', version: 1, id: ir.id, findingId: ir.findingId, level: levelFor(ir), mode: 'detect',
    request: { method: ir.endpoint.method, pathTemplate: ir.endpoint.path },
    parameter: ir.parameter,
    payload: ir.payloadClass === 'auth-bypass' ? { class: 'auth-bypass', behavior: 'status 2xx with no credential' }
      : { class: ir.payloadClass, matcher: def.matcher, minLength: def.minLength ?? null, regex: classRegex(ir.payloadClass), flags: 'i' },
    limitations: ir.limitations,
  };
  return { applicable: true, format: 'http', content: `${JSON.stringify(detection, null, 2)}\n` };
}

/** ModSecurity-style suggestion. Always detect-only (`pass`): a generated rule must never block traffic on its own. */
function waf(ir) {
  if (!ir.endpoint) return unavailable('no endpoint is known for this finding');
  const id = numericRuleId(ir);
  const msg = `Agentic Security ${ir.id}: ${ir.payloadClass} on ${ir.endpoint.method} ${ir.endpoint.path}`.replace(/['"\\]/g, '');
  const rx = (s) => s.replace(/"/g, '\\x22');
  const pathOp = hasTemplate(ir.endpoint.path) ? `"@rx ${rx(pathRegex(ir.endpoint.path))}"` : `"@streq ${rx(ir.endpoint.path)}"`;
  const out = [
    '# SUGGESTION ONLY. Detect-only (pass). Review, test against your own traffic, then decide whether to enforce.',
    `SecRule REQUEST_METHOD "@streq ${ir.endpoint.method}" "id:${id},phase:2,pass,nolog,chain"`,
    `  SecRule REQUEST_FILENAME ${pathOp} "chain"`,
  ];
  if (ir.payloadClass === 'auth-bypass') {
    out.push(`  SecRule &REQUEST_HEADERS:Authorization "@eq 0" "log,auditlog,msg:'${msg}',severity:'WARNING',tag:'cwe-${(ir.cwe || '').replace(/\D/g, '')}'"`);
  } else {
    const target = ir.parameter?.location === 'body' ? `ARGS_POST${ir.parameter ? `:${ir.parameter.name}` : ''}` : ir.parameter?.location === 'header' ? `REQUEST_HEADERS:${ir.parameter.name}` : ir.parameter?.location === 'cookie' ? `REQUEST_COOKIES:${ir.parameter.name}` : ir.parameter ? `ARGS_GET:${ir.parameter.name}` : 'ARGS';
    out.push(`  SecRule ${target} "@rx ${rx(classRegex(ir.payloadClass))}" "t:urlDecodeUni,log,auditlog,msg:'${msg}',severity:'CRITICAL',tag:'cwe-${(ir.cwe || '').replace(/\D/g, '')}'"`);
  }
  return { applicable: true, format: 'waf', content: `${out.join('\n')}\n`, enforcement: 'detect-only' };
}

function logQuery(ir) {
  if (!ir.endpoint) return unavailable('no endpoint is known for this finding');
  const where = [{ field: 'http.request.method', op: 'eq', value: ir.endpoint.method }, hasTemplate(ir.endpoint.path) ? { field: 'url.path', op: 'regex', value: pathRegex(ir.endpoint.path) } : { field: 'url.path', op: 'eq', value: ir.endpoint.path }];
  if (ir.payloadClass === 'auth-bypass') where.push({ field: 'http.response.status_code', op: 'range', value: [200, 299] }, { field: 'http.request.headers.authorization', op: 'absent' });
  else where.push({ field: ir.parameter?.location === 'body' ? 'http.request.body.content' : ir.parameter?.location === 'query' ? `url.query.${ir.parameter.name}` : 'url.query', op: 'regex', value: classRegex(ir.payloadClass), flags: 'i' });
  return { applicable: true, format: 'log-query', content: `${JSON.stringify({ schema: 'agentic-security/structured-log-query', version: 1, id: ir.id, findingId: ir.findingId, where }, null, 2)}\n` };
}

function yara(ir) {
  if (ir.payloadClass !== 'deserialization') return unavailable(`YARA matches file or memory content; the ${ir.payloadClass} class is request-shaped, so a YARA rule would be misleading`);
  const ident = `as_${ir.digest.slice(0, 12)}`;
  const content = [
    `rule ${ident} {`, '  meta:', `    description = ${JSON.stringify(`serialized object stream (${ir.findingId})`)}`, `    finding = ${JSON.stringify(ir.findingId)}`, '    generated_by = "agentic-security"',
    '  strings:', '    $java_raw = { AC ED 00 05 }', '    $java_b64 = "rO0AB"', '    $pickle_b64 = "gASV"', '    $php = /O:[0-9]{1,4}:"[A-Za-z_\\\\]/',
    '  condition:', '    any of them', '}', '',
  ].join('\n');
  return { applicable: true, format: 'yara', content };
}

const splQ = (s) => `"${s.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
function spl(ir) {
  if (!ir.endpoint) return unavailable('no endpoint is known for this finding');
  const pathPart = hasTemplate(ir.endpoint.path) ? `| regex uri_path=${splQ(pathRegex(ir.endpoint.path))}` : `uri_path=${splQ(ir.endpoint.path)}`;
  const head = `index=* method=${ir.endpoint.method} ${hasTemplate(ir.endpoint.path) ? '' : pathPart}`.trim();
  const rest = [hasTemplate(ir.endpoint.path) ? pathPart : null,
    ir.payloadClass === 'auth-bypass' ? '| where status>=200 AND status<300 AND isnull(http_authorization)' : `| regex ${ir.parameter?.location === 'body' ? 'request_body' : 'uri_query'}=${splQ(`(?i)${classRegex(ir.payloadClass)}`)}`].filter(Boolean);
  return { applicable: true, format: 'spl', content: `${[head, ...rest].join('\n')}\n` };
}
const kqlQ = (s) => `@"${s.replace(/"/g, '""')}"`;
function kql(ir) {
  if (!ir.endpoint) return unavailable('no endpoint is known for this finding');
  if (['body', 'header', 'cookie'].includes(ir.parameter?.location)) return unavailable(`the W3CIISLog table does not record request ${ir.parameter.location}s, so this rule would never see the parameter`);
  const lines = ['W3CIISLog', `| where csMethod == ${JSON.stringify(ir.endpoint.method)}`,
    hasTemplate(ir.endpoint.path) ? `| where csUriStem matches regex ${kqlQ(pathRegex(ir.endpoint.path))}` : `| where csUriStem == ${JSON.stringify(ir.endpoint.path)}`,
    ir.payloadClass === 'auth-bypass' ? '| where scStatus between (200 .. 299) and isempty(csAuthorization)' : `| where csUriQuery matches regex ${kqlQ(`(?i)${classRegex(ir.payloadClass)}`)}`];
  return { applicable: true, format: 'kql', content: `${lines.join('\n')}\n` };
}
function cloudwatch(ir) {
  if (!ir.endpoint) return unavailable('no endpoint is known for this finding');
  if (['body', 'header', 'cookie'].includes(ir.parameter?.location)) return unavailable(`access logs do not record request ${ir.parameter.location}s, so this query would never see the parameter`);
  const re = (s) => `/${s.replace(/\//g, '\\/')}/`;
  const lines = ['fields @timestamp, @message', `| filter @message like ${re(`${ir.endpoint.method} ${hasTemplate(ir.endpoint.path) ? pathRegex(ir.endpoint.path).replace(/^\^|\$$/g, '') : escRe(ir.endpoint.path)}`)}`,
    ir.payloadClass === 'auth-bypass' ? '| filter @message like /" 2[0-9][0-9] /' : `| filter @message like ${re(`(?i)${classRegex(ir.payloadClass)}`)}`, '| sort @timestamp desc'];
  return { applicable: true, format: 'cloudwatch', content: `${lines.join('\n')}\n` };
}

const RENDERERS = { sigma, http, waf, 'log-query': logQuery, yara, spl, kql, cloudwatch };

/** Render one format. An inapplicable format is reported as such with its reason, never as an empty rule. */
export function renderDetection(ir, format) {
  const fn = RENDERERS[format];
  if (!fn) return { applicable: false, reason: `unknown format: ${format}` };
  return { format, ...fn(ir) };
}

export function renderAll(ir) {
  return Object.fromEntries(FORMATS.map((f) => [f, renderDetection(ir, f)]));
}

// ── Elasticsearch / Elastic Security, Google Chronicle (YARA-L) and Datadog Cloud SIEM (P1 adapters) ──────────────────────────────────
// Text only, like every other renderer here: nothing connects to a SIEM. Each target has a different regular-expression dialect or none,
// and a rule that silently means something else is worse than no rule, so a renderer either translates exactly or reports why it cannot.

/**
 * A JavaScript regular-expression source as an Elasticsearch/Lucene `regexp` pattern, or null when some construct has no Lucene
 * equivalent (anchors, word boundaries, look-around, back-references). A lazy quantifier becomes greedy, which is exact for a yes/no match. Lucene matches the WHOLE term, so the caller
 * wraps unanchored patterns in `.*(...).*`; case-insensitivity is the query's `case_insensitive` flag, not an inline flag.
 */
export function luceneRegex(src) {
  const cls = { d: '0-9', w: 'a-zA-Z0-9_', s: ' \\t\\n\\r' };
  const bare = { d: '[0-9]', D: '[^0-9]', w: '[a-zA-Z0-9_]', s: '[ \\t\\n\\r]', S: '[^ \\t\\n\\r]' };
  const RESERVED = new Set(['&', '~', '<', '>', '@', '"', '#']);
  let out = ''; let inClass = false; let prevQuant = false;
  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    if (c === '\\') {
      const n = src[++i];
      if (n === undefined) return null;
      if (inClass) {
        if (cls[n]) out += cls[n]; else if (/[dswDSWbBnrt0-9A-Za-z]/.test(n)) { if (n === 'n') out += '\\n'; else if (n === 'r') out += '\\r'; else if (n === 't') out += '\\t'; else return null; } else out += `\\${n}`;
      } else if (bare[n]) out += bare[n];
      else if (n === 'n') out += '\\n'; else if (n === 'r') out += '\\r'; else if (n === 't') out += '\\t';
      else if (/[A-Za-z0-9]/.test(n)) return null;
      else out += `\\${n}`;
      prevQuant = false; continue;
    }
    if (inClass) { if (c === ']') inClass = false; out += RESERVED.has(c) ? `\\${c}` : c; continue; }
    if (c === '[') { inClass = true; out += c; prevQuant = false; continue; }
    if (c === '(') {
      if (src[i + 1] === '?') { if (src[i + 2] === ':') { out += '('; i += 2; prevQuant = false; continue; } return null; }
      out += '('; prevQuant = false; continue;
    }
    if (c === '^' || c === '$') return null;
    if (c === '?' && prevQuant) { prevQuant = false; continue; } // a lazy quantifier: for a yes/no match the greedy form is equivalent, and Lucene has no lazy form
    if (c === '*' || c === '+' || c === '?') { out += c; prevQuant = true; continue; }
    if (c === '{') { const m = /^\{\d+(?:,\d*)?\}/.exec(src.slice(i)); if (!m) { out += '\\{'; prevQuant = false; continue; } out += m[0]; i += m[0].length - 1; prevQuant = true; continue; }
    if (c === '}') { out += '\\}'; prevQuant = false; continue; }
    out += RESERVED.has(c) ? `\\${c}` : c; prevQuant = false;
  }
  return inClass ? null : out;
}

function elastic(ir) {
  if (!ir.endpoint) return unavailable('no endpoint is known for this finding');
  const loc = ir.parameter?.location;
  const filter = [{ term: { 'http.request.method': ir.endpoint.method } }];
  if (hasTemplate(ir.endpoint.path)) {
    const p = luceneRegex(pathRegex(ir.endpoint.path).replace(/^\^|\$$/g, ''));
    if (p === null) return unavailable('the endpoint path template has no Lucene regular-expression form');
    filter.push({ regexp: { 'url.path': { value: p } } });
  } else filter.push({ term: { 'url.path': ir.endpoint.path } });
  const mustNot = [];
  if (ir.payloadClass === 'auth-bypass') {
    filter.push({ range: { 'http.response.status_code': { gte: 200, lte: 299 } } });
    mustNot.push({ exists: { field: 'http.request.headers.authorization' } });
  } else {
    const re = luceneRegex(classRegex(ir.payloadClass) ?? '');
    if (re === null || !classRegex(ir.payloadClass)) return unavailable(`the ${ir.payloadClass} indicators use regular-expression constructs Lucene cannot express exactly (anchors, word boundaries or look-around), so a rule would not mean what the proof established`);
    const field = loc === 'body' ? 'http.request.body.content' : loc === 'query' ? 'url.query' : loc === 'header' || loc === 'cookie' ? null : 'url.query';
    if (!field) return unavailable(`ECS web logs do not record request ${loc}s by default, so this rule would never see the parameter`);
    filter.push({ regexp: { [field]: { value: `.*(${re}).*`, case_insensitive: true } } });
  }
  const body = { query: { bool: { filter, ...(mustNot.length ? { must_not: mustNot } : {}) } }, _meta: { id: ir.id, findingId: ir.findingId, generatedBy: 'agentic-security', note: 'Lucene regexp matches the whole field value; the pattern is wrapped accordingly.' } };
  return { applicable: true, format: 'elastic', content: `${JSON.stringify(body, null, 2)}\n` };
}

/** True when a regex source uses `^`, `$` or a word boundary outside a character class: its meaning depends on WHERE the value starts and ends. */
const edgeSensitive = (src) => /[\^$]/.test(src.replace(/\\./g, 'x').replace(/\[[^\]]*\]/g, 'x')) || /\\[bB]/.test(src);

function yaral(ir) {
  if (!ir.endpoint) return unavailable('no endpoint is known for this finding');
  if (['body', 'header', 'cookie'].includes(ir.parameter?.location)) return unavailable(`UDM HTTP events carry the URL, not request ${ir.parameter.location}s, so this rule would never see the parameter`);
  if (ir.payloadClass === 'auth-bypass') return unavailable('UDM HTTP events do not carry request headers, so "no credential was sent" cannot be expressed');
  const cr = classRegex(ir.payloadClass);
  if (!cr) return unavailable(`the ${ir.payloadClass} class has no regular-expression indicators`);
  // the indicators are written against a query string or a body; YARA-L sees the whole URL, so a pattern anchored to "the start/end of the value" would mean something else
  if (edgeSensitive(cr)) return unavailable(`the ${ir.payloadClass} indicators are anchored to the start or end of the parameter value, and UDM only exposes the whole URL, so a rule would not mean what the proof established`);
  const pathRe = hasTemplate(ir.endpoint.path) ? pathRegex(ir.endpoint.path).replace(/^\^|\$$/g, '') : escRe(ir.endpoint.path);
  const urlRe = `(?i)^[^?]*${pathRe}(?:\\?.*)?$`;
  const payloadRe = `(?i)${cr}`;
  if (urlRe.includes('`') || payloadRe.includes('`')) return unavailable('the pattern contains a backtick, which cannot appear in a YARA-L raw regular expression');
  const ident = `as_${ir.digest.slice(0, 12)}`;
  const content = [
    `rule ${ident} {`, '  meta:', `    description = ${JSON.stringify(title(ir))}`, `    finding = ${JSON.stringify(ir.findingId)}`, '    author = "agentic-security"', `    severity = ${JSON.stringify(levelFor(ir).toUpperCase())}`,
    '  events:', '    $e.metadata.event_type = "NETWORK_HTTP"', `    $e.network.http.method = ${JSON.stringify(ir.endpoint.method)}`,
    `    re.regex($e.target.url, \`${urlRe}\`)`, `    re.regex($e.target.url, \`${payloadRe}\`)`, '  condition:', '    $e', '}', '',
  ].join('\n');
  return { applicable: true, format: 'yaral', content };
}

function datadog(ir) {
  if (!ir.endpoint) return unavailable('no endpoint is known for this finding');
  if (ir.payloadClass !== 'auth-bypass') return unavailable(`Datadog log search has wildcards but no regular expressions, so the ${ir.payloadClass} indicators cannot be expressed exactly; use the log-query or sigma output`);
  const wild = ir.endpoint.path.replace(/\/(?::[A-Za-z_]\w*|\{[A-Za-z_]\w*\})(?=\/|$)/g, '/*');
  if (/[\s"\\]/.test(wild)) return unavailable('the endpoint path contains characters that cannot be quoted safely in a Datadog query');
  const query = `@http.method:${ir.endpoint.method} @http.url_details.path:${wild} @http.status_code:[200 TO 299] -@http.request.headers.authorization:*`;
  const rule = { name: title(ir), type: 'log_detection', isEnabled: false, message: `${title(ir)}. Finding ${ir.findingId}. Generated by agentic-security; review before enabling.`, tags: ['source:agentic-security'], queries: [{ query, aggregation: 'count', groupByFields: [], distinctFields: [], name: 'a' }], cases: [{ name: 'proven pattern seen', status: levelFor(ir) === 'high' ? 'high' : 'medium', condition: 'a > 0', notifications: [] }], options: { evaluationWindow: 900, keepAlive: 3600, maxSignalDuration: 86400 } };
  return { applicable: true, format: 'datadog', content: `${JSON.stringify(rule, null, 2)}\n` };
}
RENDERERS.elastic = elastic; RENDERERS.yaral = yaral; RENDERERS.datadog = datadog;
