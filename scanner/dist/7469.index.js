export const id = 7469;
export const ids = [7469,5216,5046,2665];
export const modules = {

/***/ 17469:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

// ESM COMPAT FLAG
__webpack_require__.r(__webpack_exports__);

// EXPORTS
__webpack_require__.d(__webpack_exports__, {
  HUNT_EXIT: () => (/* binding */ HUNT_EXIT),
  cmdDnr: () => (/* binding */ cmdDnr)
});

// EXTERNAL MODULE: external "node:fs"
var external_node_fs_ = __webpack_require__(73024);
// EXTERNAL MODULE: external "node:path"
var external_node_path_ = __webpack_require__(76760);
// EXTERNAL MODULE: ./src/posture/proof-fabric/store.js
var store = __webpack_require__(25216);
// EXTERNAL MODULE: ./src/posture/proof-fabric/reproducer.js
var reproducer = __webpack_require__(82034);
// EXTERNAL MODULE: ./src/posture/proof-fabric/states.js
var states = __webpack_require__(58355);
// EXTERNAL MODULE: ./src/posture/dnr/payload-classes.js
var payload_classes = __webpack_require__(75508);
// EXTERNAL MODULE: ./src/posture/dnr/attack-facts.js
var attack_facts = __webpack_require__(59513);
;// CONCATENATED MODULE: ./src/posture/dnr/detection-ir.js
// Detection intermediate representation (PRD 7, requirement 1). One IR per confirmed finding; every rendered rule, every
// hunt and every validation is derived from it, so there is exactly one place where the claim "what the exploit looks like"
// is made.
//
// Evidence grounding (requirement 3) is enforced structurally:
//   * the IR is CLOSED-WORLD: `validateDetectionIR` refuses any key it does not list, and none of them can carry an attacker
//     address, a domain, a file hash or a user agent;
//   * every fact that came from somewhere records where (`facts[field] = {source, ref}`), and a fact with no source is not
//     put in the IR at all (it is `null`, and the limitation is stated);
//   * the confidence is computed from the evidence state, never asserted.





const DETECTION_IR_SCHEMA = 'agentic-security/detection-ir';
const DETECTION_IR_VERSION = 1;

const IR_KEYS = Object.freeze(['schema', 'version', 'id', 'findingId', 'cwe', 'family', 'attackBehavior', 'endpoint', 'parameter', 'payloadClass', 'affectedOperation', 'processEffect', 'networkEffect', 'dbEffect', 'confidence', 'grounding', 'evidence', 'facts', 'limitations', 'digest']);
const GROUNDING = Object.freeze(['exploit-confirmed', 'reproduced', 'static-only']);

/** "POST /api/export" -> {method, path}; anything else -> null. A finding's own route text is a fact source like any other. */
function parseRouteText(text) {
  const m = /^\s*(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\/[A-Za-z0-9/_\-.:{}~%]{0,199})\s*$/.exec(String(text ?? ''));
  return m ? { method: m[1], path: m[2] } : null;
}

function groundingFor(proof) {
  const state = proof?.state ?? null;
  if (state && (0,states/* stateRank */.g3)(state) >= (0,states/* stateRank */.g3)('EXPLOIT_CONFIRMED')) return 'exploit-confirmed';
  if (state && (0,states/* stateRank */.g3)(state) >= (0,states/* stateRank */.g3)('REPRODUCED')) return 'reproduced';
  return 'static-only';
}

/**
 * Build the IR for one finding. Returns {ok:true, ir} or {ok:false, reason}.
 * A finding with no proof is refused unless `allowUnproven` is set, in which case the IR says so (`grounding: static-only`)
 * and carries a lower confidence. A finding with no recognisable payload class is refused: there is nothing to detect.
 */
function buildDetectionIR({ finding, proof = null, allowUnproven = false } = {}) {
  if (!finding || typeof finding !== 'object') return { ok: false, reason: 'no finding' };
  const findingId = String(finding.stableId ?? finding.id ?? '');
  if (!findingId) return { ok: false, reason: 'the finding has no stable id' };
  const grounding = groundingFor(proof);
  if (grounding === 'static-only' && !allowUnproven) {
    return { ok: false, reason: `no exploit proof for ${findingId}: prove it first (triage exploit ${findingId} --prove), or pass --allow-unproven to build a lower-confidence detection from the static finding alone` };
  }
  const attack = proof?.reproducer?.attack ?? null;
  const attackErrs = (0,attack_facts/* validateAttackFacts */.GT)(attack);
  if (attackErrs.length) return { ok: false, reason: `the reproducer's attack facts are invalid: ${attackErrs.join('; ')}` };

  const facts = {};
  const evidence = [];
  const limitations = [];
  if (finding.file) evidence.push({ kind: 'finding', ref: `${finding.file}:${finding.line ?? '?'}`, id: findingId });
  if (proof?.recordDigest) evidence.push({ kind: 'proof', ref: `proof:${proof.recordDigest}`, state: proof.state ?? null, oracle: proof.oracle ?? null });
  if (attack) evidence.push({ kind: 'reproducer', ref: `reproducer:${String(proof?.reproducer ? (0,reproducer/* sha256 */.sc)((0,reproducer/* canonicalize */.dw)(proof.reproducer)) : '').slice(0, 16)}` });

  // payload class: the reproducer's explicit statement wins, then the finding's CWE
  let payloadClass = null;
  if (attack?.payloadClass) { payloadClass = attack.payloadClass; facts.payloadClass = { source: 'reproducer', ref: 'attack.payloadClass' }; }
  else if ((0,payload_classes/* classForCwe */.T6)(finding.cwe)) { payloadClass = (0,payload_classes/* classForCwe */.T6)(finding.cwe); facts.payloadClass = { source: 'finding', ref: `cwe:${finding.cwe}` }; }
  if (!payloadClass) return { ok: false, reason: `no payload class describes ${finding.cwe || 'this finding'}; a detection would have to guess, and a guessed detection is not generated` };
  const def = payload_classes/* PAYLOAD_CLASSES */.oE[payloadClass];

  // endpoint: the reproducer's facts, else the finding's own route text
  let endpoint = null;
  if (attack?.method && attack?.path) { endpoint = { method: attack.method, path: attack.path }; facts.endpoint = { source: 'reproducer', ref: 'attack.method+attack.path' }; }
  else {
    const fromFinding = parseRouteText(finding.route ?? finding.endpoint);
    if (fromFinding) { endpoint = fromFinding; facts.endpoint = { source: 'finding', ref: finding.route ? 'route' : 'endpoint' }; }
  }
  if (!endpoint) limitations.push('no endpoint is known for this finding, so no request-level rule is generated; only the payload class is described');

  let parameter = null;
  if (attack?.parameter) { parameter = { name: attack.parameter, location: attack.location }; facts.parameter = { source: 'reproducer', ref: 'attack.parameter' }; }
  else if (payloadClass !== 'auth-bypass') limitations.push('no vulnerable parameter is known, so the payload test is applied to every query and body value of the endpoint');

  let sink = null;
  if (attack?.sink) { sink = attack.sink; facts.sink = { source: 'reproducer', ref: 'attack.sink' }; }
  const affectedOperation = { sink, file: finding.file ? String(finding.file) : null, line: Number.isInteger(finding.line) ? finding.line : null };

  const confidence = Math.max(0.1, Math.min(0.95,
    (grounding === 'exploit-confirmed' ? 0.9 : grounding === 'reproduced' ? 0.7 : 0.4) - (endpoint ? 0 : 0.2) - (parameter || payloadClass === 'auth-bypass' ? 0 : 0.1)));
  if (grounding !== 'exploit-confirmed') limitations.push(grounding === 'reproduced' ? 'the exploit was reproduced but not independently confirmed' : 'the exploit was not executed; this detection rests on static analysis only');

  const ir = {
    schema: DETECTION_IR_SCHEMA, version: DETECTION_IR_VERSION,
    id: '', findingId,
    cwe: finding.cwe ? String(finding.cwe) : null,
    family: finding.family ? String(finding.family) : payloadClass,
    attackBehavior: def.behavior,
    endpoint, parameter, payloadClass, affectedOperation,
    processEffect: def.effects.process ?? 'none', networkEffect: def.effects.network ?? 'none', dbEffect: def.effects.db ?? 'none',
    confidence: Number(confidence.toFixed(2)), grounding, evidence, facts, limitations, digest: '',
  };
  ir.digest = (0,reproducer/* sha256 */.sc)((0,reproducer/* canonicalize */.dw)({ ...ir, id: '', digest: '' }));
  ir.id = `det-${ir.digest.slice(0, 12)}`;
  return { ok: true, ir };
}

/** Structural validation of an IR read back from disk or supplied by a caller. Returns a list of problems. */
function validateDetectionIR(ir) {
  if (!ir || typeof ir !== 'object' || Array.isArray(ir)) return ['detection IR must be an object'];
  const errs = [];
  for (const k of Object.keys(ir)) if (!IR_KEYS.includes(k)) errs.push(`unknown IR field: ${k}`);
  if (ir.schema !== DETECTION_IR_SCHEMA || ir.version !== DETECTION_IR_VERSION) errs.push('unsupported schema or version');
  if (typeof ir.findingId !== 'string' || !ir.findingId) errs.push('findingId required');
  if (!payload_classes/* PAYLOAD_CLASSES */.oE[ir.payloadClass]) errs.push(`unknown payload class: ${String(ir.payloadClass)}`);
  if (!GROUNDING.includes(ir.grounding)) errs.push('unknown grounding');
  if (ir.endpoint != null) {
    if (!attack_facts/* HTTP_METHODS */.y8.includes(ir.endpoint.method) || typeof ir.endpoint.path !== 'string') errs.push('endpoint must be {method, path}');
    else if ((0,attack_facts/* validateAttackFacts */.GT)({ method: ir.endpoint.method, path: ir.endpoint.path }).length) errs.push('endpoint path is not a plain URL path');
  }
  if (ir.parameter != null) {
    if (!attack_facts/* PARAM_LOCATIONS */.ZC.includes(ir.parameter.location) || typeof ir.parameter.name !== 'string') errs.push('parameter must be {name, location}');
    else if ((0,attack_facts/* validateAttackFacts */.GT)({ parameter: ir.parameter.name, location: ir.parameter.location }).length) errs.push('parameter name is not a plain name');
  }
  if (typeof ir.confidence !== 'number' || ir.confidence < 0 || ir.confidence > 1) errs.push('confidence must be between 0 and 1');
  if (!Array.isArray(ir.evidence) || !Array.isArray(ir.limitations)) errs.push('evidence and limitations must be lists');
  if (ir.digest && ir.digest !== (0,reproducer/* sha256 */.sc)((0,reproducer/* canonicalize */.dw)({ ...ir, id: '', digest: '' }))) errs.push('digest does not match the content');
  return errs;
}

;// CONCATENATED MODULE: ./src/posture/dnr/outputs.js
// Renderers for a detection IR (PRD 7, requirement 2): Sigma-compatible logic, a generic HTTP detection, generic WAF
// suggestions, a structured log query and YARA where it is appropriate. The P1 renderers (Splunk SPL, Microsoft Sentinel KQL,
// CloudWatch Logs Insights) are text only; nothing here connects to a SIEM.
//
// Every value interpolated into a rule comes from the IR, and the IR is closed-world (detection-ir.js), so a rule can only
// contain what a proof established. Each renderer escapes for ITS target's quoting rules, because an endpoint path or a
// parameter name is hostile input (it came from a reproducer a model may have written).


const FORMATS = Object.freeze(['sigma', 'http', 'waf', 'log-query', 'yara', 'spl', 'kql', 'cloudwatch', 'elastic', 'yaral', 'datadog']);

/** One regular expression (source text, case-insensitive) covering a class's indicators. */
function classRegex(className) {
  const def = payload_classes/* PAYLOAD_CLASSES */.oE[className];
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
  const def = payload_classes/* PAYLOAD_CLASSES */.oE[ir.payloadClass];
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
function renderDetection(ir, format) {
  const fn = RENDERERS[format];
  if (!fn) return { applicable: false, reason: `unknown format: ${format}` };
  return { format, ...fn(ir) };
}

function renderAll(ir) {
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
function luceneRegex(src) {
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

;// CONCATENATED MODULE: ./src/posture/dnr/matchers.js
// The one evaluator behind every detection output. Validation (synthetic events), hunting (historical logs) and the
// rendered rules' described behavior all call `evaluateEvent`, so a rule that passes validation is the same rule that
// searches the logs. An event is the NORMALIZED request record produced by log-reader.js or by the validator.
//
//   event = { time, method, path, query: {name: [values]}, bodyParams: {name: [values]} | null, headers: {name: value} | null,
//             status, authPresent: boolean | null }
//
// A missing field is `undefined`/`null`, never an empty string: "the log did not record this" and "the value was empty" are
// different facts, and only the first makes an event undecidable.


const norm = (p) => (p.length > 1 ? p.replace(/\/+$/, '') : p);

/** `/api/users/:id` and `/api/users/{id}` match any single non-empty segment in that position. */
function pathMatches(template, actual) {
  if (typeof actual !== 'string' || !actual.startsWith('/')) return false;
  const t = norm(template).split('/');
  const a = norm(actual.split('?')[0]).split('/');
  if (t.length !== a.length) return false;
  return t.every((seg, i) => (/^(?::[A-Za-z_]\w*|\{[A-Za-z_]\w*\})$/.test(seg) ? a[i].length > 0 : seg === a[i]));
}

/** Fields an event must have for a detection to be able to say "no" about it. */
function requiredFields(ir) {
  const need = new Set();
  if (ir.endpoint) { need.add('method'); need.add('path'); }
  if (ir.payloadClass === 'auth-bypass') { need.add('status'); need.add('auth'); return [...need]; }
  const loc = ir.parameter?.location;
  if (loc === 'body') need.add('body');
  else if (loc === 'header' || loc === 'cookie') need.add('headers');
  else if (loc === 'path') need.add('path');
  else need.add('query');
  if (!ir.endpoint) need.add('path');
  return [...need];
}

function candidateValues(ir, event) {
  const out = [];
  const p = ir.parameter;
  const take = (bag, name) => { for (const v of (bag?.[name] ?? [])) out.push([`${name}`, v]); };
  if (!p) {
    for (const [k, vs] of Object.entries(event.query ?? {})) for (const v of vs) out.push([`query:${k}`, v]);
    for (const [k, vs] of Object.entries(event.bodyParams ?? {})) for (const v of vs) out.push([`body:${k}`, v]);
    return { values: out, decidable: event.query != null };
  }
  if (p.location === 'query') { take(event.query, p.name); return { values: out.map(([k, v]) => [`query:${k}`, v]), decidable: event.query != null }; }
  if (p.location === 'body') { take(event.bodyParams, p.name); return { values: out.map(([k, v]) => [`body:${k}`, v]), decidable: event.bodyParams != null }; }
  if (p.location === 'header' || p.location === 'cookie') {
    const v = event.headers?.[p.name.toLowerCase()];
    return { values: v == null ? [] : [[`${p.location}:${p.name}`, v]], decidable: event.headers != null };
  }
  // path parameter: the segment where the template has the parameter
  if (p.location === 'path' && ir.endpoint) {
    const t = norm(ir.endpoint.path).split('/');
    const a = norm(String(event.path).split('?')[0]).split('/');
    t.forEach((seg, i) => { if (seg === `:${p.name}` || seg === `{${p.name}}`) out.push([`path:${p.name}`, a[i] ?? '']); });
  }
  return { values: out, decidable: typeof event.path === 'string' };
}

/**
 * @returns {{match: boolean, undecidable: boolean, missing: string[], matchedOn: string|null, value: string|null}}
 * `undecidable` means "this event lacks a field the detection needs", which is different from "this event does not match".
 */
function evaluateEvent(ir, event) {
  const res = { match: false, undecidable: false, missing: [], matchedOn: null, value: null };
  if (ir.endpoint) {
    if (!event.method) res.missing.push('method');
    if (typeof event.path !== 'string') res.missing.push('path');
    if (res.missing.length) { res.undecidable = true; return res; }
    if (String(event.method).toUpperCase() !== ir.endpoint.method) return res;
    if (!pathMatches(ir.endpoint.path, event.path)) return res;
  } else if (typeof event.path !== 'string') { res.missing.push('path'); res.undecidable = true; return res; }

  if (ir.payloadClass === 'auth-bypass') {
    if (event.status == null) res.missing.push('status');
    if (event.authPresent == null) res.missing.push('auth');
    if (res.missing.length) { res.undecidable = true; return res; }
    if (event.status >= 200 && event.status < 300 && event.authPresent === false) { res.match = true; res.matchedOn = 'unauthenticated-success'; res.value = `${event.status}`; }
    return res;
  }

  if (!payload_classes/* PAYLOAD_CLASSES */.oE[ir.payloadClass]) { res.undecidable = true; res.missing.push('payload-class'); return res; }
  const { values, decidable } = candidateValues(ir, event);
  for (const [where, v] of values) {
    if ((0,payload_classes/* matchesClass */.Us)(ir.payloadClass, v)) { res.match = true; res.matchedOn = where; res.value = String(v).slice(0, 200); return res; }
  }
  if (!decidable) { res.undecidable = true; res.missing.push(ir.parameter?.location === 'body' ? 'body' : ir.parameter?.location === 'header' || ir.parameter?.location === 'cookie' ? 'headers' : 'query'); }
  return res;
}

;// CONCATENATED MODULE: ./src/posture/dnr/validate.js
// Detection validation (PRD 7, requirement 6): before a detection is allowed to be "enabled", prove it behaves.
//   positive exploit event  -> the detection fires
//   negative lookalike      -> the detection does not fire
// Events are synthesized from the IR's own proven facts (endpoint, parameter, class) and the class's exemplar payloads, then
// pushed through the SAME evaluator the hunt uses, so a rule that validates is the rule that searches the logs. The negatives
// are the point: a rule that fires on everything passes every positive test.




const PROBE = 'probe';

function eventFor(ir, { method, path, values, extraParam = null, status = 200, authPresent = null }) {
  const p = ir.parameter;
  const bag = {};
  const ev = { time: '2024-01-01T00:00:00.000Z', method, path, query: {}, bodyParams: {}, headers: {}, status, authPresent };
  const put = (loc, name, vals) => {
    if (loc === 'query') ev.query[name] = vals;
    else if (loc === 'body') ev.bodyParams[name] = vals;
    else if (loc === 'header' || loc === 'cookie') ev.headers[name.toLowerCase()] = vals[0];
  };
  void bag;
  if (values) {
    if (p?.location === 'path') {
      const t = ir.endpoint.path.split('/').map((seg) => (seg === `:${p.name}` || seg === `{${p.name}}` ? encodeURIComponent(values[0]) : (/^(?::\w+|\{\w+\})$/.test(seg) ? 'x' : seg)));
      if (path === ir.endpoint.path.replace(/(:[A-Za-z_]\w*|\{[A-Za-z_]\w*\})/g, '42')) ev.path = t.join('/');
    } else if (p) put(p.location, extraParam ?? p.name, values);
    else put('query', extraParam ?? PROBE, values);
  }
  // a channel the IR does not use is "present and empty", not "not logged": the event models a log that records everything
  return ev;
}

function validateDetection(ir) {
  const def = payload_classes/* PAYLOAD_CLASSES */.oE[ir.payloadClass];
  const cases = [];
  const render = { regexCompiles: true };
  try { const rx = classRegex(ir.payloadClass); if (rx) new RegExp(rx, 'i'); } catch { render.regexCompiles = false; }
  if (!ir.endpoint) return { schema: 'agentic-security/detection-validation', version: 1, detectionId: ir.id, status: 'NOT_VALIDATED', reason: 'no endpoint is known, so there is no request to synthesize', cases, render, counts: { positives: 0, negatives: 0, passed: 0, failed: 0 } };
  const concretePath = ir.endpoint.path.replace(/(:[A-Za-z_]\w*|\{[A-Za-z_]\w*\})/g, '42');
  const { method } = ir.endpoint;
  const add = (kind, name, ev) => { const r = evaluateEvent(ir, ev); cases.push({ kind, name, expected: kind === 'positive', fired: r.match, undecidable: r.undecidable, ok: kind === 'positive' ? r.match : !r.match }); };

  if (ir.payloadClass === 'auth-bypass') {
    add('positive', 'success with no credential', eventFor(ir, { method, path: concretePath, status: 200, authPresent: false }));
    add('negative', 'success with a credential', eventFor(ir, { method, path: concretePath, status: 200, authPresent: true }));
    add('negative', 'refusal without a credential (401)', eventFor(ir, { method, path: concretePath, status: 401, authPresent: false }));
    add('negative', 'refusal without a credential (403)', eventFor(ir, { method, path: concretePath, status: 403, authPresent: false }));
    add('negative', 'same request on another path', eventFor(ir, { method, path: '/other/unrelated', status: 200, authPresent: false }));
  } else {
    for (const [i, v] of def.exemplars.positive.entries()) add('positive', `exploit payload #${i + 1}`, eventFor(ir, { method, path: concretePath, values: [v] }));
    for (const [i, v] of def.exemplars.benign.entries()) add('negative', `benign value #${i + 1} on the same endpoint`, eventFor(ir, { method, path: concretePath, values: [v] }));
    const exploit = [def.exemplars.positive[0]];
    const otherMethod = method === 'GET' ? 'POST' : 'GET';
    add('negative', `exploit payload with another method (${otherMethod})`, eventFor(ir, { method: otherMethod, path: concretePath, values: exploit }));
    add('negative', 'exploit payload on another path', eventFor(ir, { method, path: '/other/unrelated', values: exploit }));
    add('negative', 'same endpoint, no parameter at all', eventFor(ir, { method, path: concretePath }));
    if (ir.parameter && ir.parameter.location !== 'path') add('negative', 'exploit payload in an unrelated parameter', eventFor(ir, { method, path: concretePath, values: exploit, extraParam: 'unrelated_field' }));
  }
  const positives = cases.filter((c) => c.kind === 'positive'); const negatives = cases.filter((c) => c.kind === 'negative');
  const failed = cases.filter((c) => !c.ok);
  const status = failed.length === 0 && positives.length && negatives.length && render.regexCompiles ? 'VALIDATED' : 'FAILED';
  return { schema: 'agentic-security/detection-validation', version: 1, detectionId: ir.id, status, cases, render, counts: { positives: positives.length, negatives: negatives.length, passed: cases.length - failed.length, failed: failed.length }, failures: failed.map((c) => c.name) };
}

// EXTERNAL MODULE: external "node:readline"
var external_node_readline_ = __webpack_require__(80481);
;// CONCATENATED MODULE: ./src/posture/dnr/log-reader.js
// Bounded, streaming reader for historical HTTP logs (PRD 7, requirement 4). Logs are hostile input: a file may be huge,
// binary, symlinked, line-less or crafted to blow up a parser. Everything here has a cap and a clock, and every cap that is
// reached is REPORTED (`truncated`, `budgetExhausted`, skipped-file reasons) so the hunt can answer INCONCLUSIVE rather than
// pretend it searched everything.
//
// Production logs stay local: this module reads files and calls a callback. It imports no network module, and a test pins
// that. Understood shapes: Apache/nginx common and combined access logs, JSON lines (including Envoy and generic structured
// loggers). Anything else on a line is a parse failure, counted, never guessed at.




const LIMITS = Object.freeze({ maxFiles: 500, maxDepth: 4, maxFileBytes: 256 * 1024 * 1024, maxTotalBytes: 2 * 1024 * 1024 * 1024, maxLines: 20_000_000, maxLineChars: 32 * 1024, maxParams: 200, budgetMs: 10 * 60 * 1000 });
const TEXT_EXT = /\.(?:log|txt|json|jsonl|ndjson|access|out)$|^[^.]+$/i;
const MONTHS = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };
const CLF = /^(\S+) \S+ (\S+) \[([^\]]+)\] "([A-Z]{3,8}) (\S+)(?: HTTP\/[\d.]+)?" (\d{3}|-) (?:\d+|-)/;

const decode = (s) => { try { return decodeURIComponent(String(s).replace(/\+/g, ' ')); } catch { return String(s); } };

function parseQuery(qs, cap = LIMITS.maxParams) {
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
  const d = new Date(s);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

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
function parseLine(line) {
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
    const authPresent = authHeader != null ? true : typeof authFlag === 'boolean' ? authFlag : (sawHeaders ? false : null);
    const statusRaw = pick(f, ['status', 'status_code', 'response_code', 'http.response.status_code', 'sc-status', 'response.status', 'res.statuscode']);
    const status = Number.isInteger(Number(statusRaw)) && statusRaw !== undefined ? Number(statusRaw) : null;
    return { time: parseTime(pick(f, ['@timestamp', 'timestamp', 'time', 'ts', 'start_time', 'datetime', 'date'])), method: typeof m === 'string' ? m.toUpperCase() : null, path: tgt.path ?? null, query: query ?? null, bodyParams, headers: sawHeaders ? headers : null, status, authPresent };
  }
  const c = CLF.exec(text);
  if (c) {
    const { path: p, query } = fromRequestTarget(c[5]);
    return { time: parseTime(c[3]), method: c[4], path: p, query, bodyParams: null, headers: null, status: c[6] === '-' ? null : Number(c[6]), authPresent: null };
  }
  return null;
}

function collectFiles(root, limits, skipped) {
  const out = [];
  const walk = (p, depth) => {
    let st;
    try { st = external_node_fs_.lstatSync(p); } catch { skipped.push({ file: external_node_path_.basename(p), reason: 'unreadable' }); return; }
    if (st.isSymbolicLink()) { skipped.push({ file: external_node_path_.basename(p), reason: 'symlink' }); return; }
    if (st.isDirectory()) {
      if (depth > limits.maxDepth) { skipped.push({ file: external_node_path_.basename(p), reason: 'too-deep' }); return; }
      let names = [];
      try { names = external_node_fs_.readdirSync(p).sort(); } catch { skipped.push({ file: external_node_path_.basename(p), reason: 'unreadable' }); return; }
      for (const n of names) walk(external_node_path_.join(p, n), depth + 1);
      return;
    }
    if (!st.isFile()) return;
    if (/\.(?:gz|zip|bz2|xz|zst|tgz)$/i.test(p)) { skipped.push({ file: external_node_path_.basename(p), reason: 'compressed-unsupported' }); return; }
    if (!TEXT_EXT.test(external_node_path_.basename(p))) { skipped.push({ file: external_node_path_.basename(p), reason: 'not-a-log-extension' }); return; }
    if (out.length >= limits.maxFiles) { skipped.push({ file: external_node_path_.basename(p), reason: 'file-count-limit' }); return; }
    out.push({ file: p, size: st.size });
  };
  walk(root, 0);
  return out;
}

/**
 * Stream every request record under `target` through `onEvent(event)`. Never throws on bad content.
 * @returns stats: files, lines, parsed/failed counts, time window, per-field availability, and every limit that was hit.
 */
async function readLogs(target, { onEvent, signal, limits: over = {} } = {}) {
  const limits = { ...LIMITS, ...over };
  const stats = { files: [], filesSkipped: [], lines: 0, parsed: 0, failed: 0, oversizeLines: 0, windowStart: null, windowEnd: null, eventsWithTime: 0, fieldCounts: { method: 0, path: 0, query: 0, body: 0, headers: 0, status: 0, auth: 0 }, truncated: [], budgetExhausted: false, aborted: false, unreadable: false };
  let st;
  try { st = external_node_fs_.lstatSync(target); } catch { stats.unreadable = true; return stats; }
  if (st.isSymbolicLink()) { stats.unreadable = true; stats.filesSkipped.push({ file: external_node_path_.basename(target), reason: 'symlink' }); return stats; }
  const base = st.isDirectory() ? target : external_node_path_.dirname(target);
  const files = st.isDirectory() ? collectFiles(target, limits, stats.filesSkipped) : collectFiles(target, limits, stats.filesSkipped);
  const deadline = Date.now() + limits.budgetMs;
  let totalBytes = 0;
  for (const { file, size } of files) {
    if (signal?.aborted) { stats.aborted = true; break; }
    if (Date.now() > deadline) { stats.budgetExhausted = true; stats.truncated.push('time-budget'); break; }
    if (size > limits.maxFileBytes) { stats.filesSkipped.push({ file: external_node_path_.relative(base, file), reason: 'file-too-large' }); stats.truncated.push('file-too-large'); continue; }
    if (totalBytes + size > limits.maxTotalBytes) { stats.filesSkipped.push({ file: external_node_path_.relative(base, file), reason: 'total-size-limit' }); stats.truncated.push('total-size-limit'); continue; }
    totalBytes += size;
    const fstat = { name: external_node_path_.relative(base, file) || external_node_path_.basename(file), bytes: size, lines: 0, parsed: 0, failed: 0 };
    stats.files.push(fstat);
    const stream = external_node_fs_.createReadStream(file, { encoding: 'utf8', highWaterMark: 1 << 20 });
    const rl = external_node_readline_.createInterface({ input: stream, crlfDelay: Infinity });
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
        if (ev.time) { stats.eventsWithTime++; if (!stats.windowStart || ev.time < stats.windowStart) stats.windowStart = ev.time; if (!stats.windowEnd || ev.time > stats.windowEnd) stats.windowEnd = ev.time; }
        onEvent?.(ev);
      }
    } catch { stats.filesSkipped.push({ file: fstat.name, reason: 'read-error' }); } finally { rl.close(); stream.destroy(); }
    if (stats.aborted || stats.budgetExhausted || stats.truncated.includes('line-limit')) break;
  }
  stats.truncated = [...new Set(stats.truncated)];
  return stats;
}

// EXTERNAL MODULE: external "node:crypto"
var external_node_crypto_ = __webpack_require__(77598);
;// CONCATENATED MODULE: ./src/posture/dnr/redact.js
// Redaction for anything the loop persists or prints from production logs (PRD 7, privacy requirements). A matched log value
// is evidence that an exploit-shaped request existed; it must never also be a copy of a password, a token or regulated data.
// Layered on the proof fabric's secret scrubber (credentials), with the data classes a request log is likely to carry.



const PATTERNS = [
  [/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, '[REDACTED-EMAIL]'],
  [/\b(?:\d[ -]?){13,19}\b/g, '[REDACTED-NUMBER]'],
  [/\b\d{3}-\d{2}-\d{4}\b/g, '[REDACTED-ID]'],
  [/\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}/gi, '[REDACTED-CREDENTIAL]'],
  [/\b(?:password|passwd|pwd|secret|token|api[_-]?key|authorization|session|sid)=[^&\s"']+/gi, (m) => `${m.split('=')[0]}=[REDACTED]`],
  [/\b[A-Za-z0-9+/_-]{40,}={0,2}/g, '[REDACTED-TOKEN]'],
];

/** Redact a string for storage or display, then bound its length. */
function redactValue(value, max = 120) {
  let t = String(value ?? '');
  for (const [re, rep] of PATTERNS) t = t.replace(re, rep);
  t = (0,store.scrubDeep)(t);
  return t.length > max ? `${t.slice(0, max)}…` : t;
}

/** Stable short fingerprint of the ORIGINAL value, so two sightings of the same payload can be recognised without storing it. */
const fingerprint = (value) => (0,external_node_crypto_.createHash)('sha256').update(String(value ?? '')).digest('hex').slice(0, 16);

;// CONCATENATED MODULE: ./src/posture/dnr/hunt.js
// Historical hunting (PRD 7, requirement 4): search local logs for requests that have the shape of the proven exploit.
//
// Four outcomes, and the rules for reaching each are deliberately asymmetric:
//   OBSERVED              at least one event matches. A match is a lead, not a verdict of compromise.
//   NOT_OBSERVED          nothing matched AND the evidence was good enough to look: logs readable and parsed cleanly, every
//                         field the detection needs present on the events, the read not cut short, timestamps available.
//   INCONCLUSIVE          nothing matched but one of those conditions failed. This is the honest answer, never NOT_OBSERVED.
//   TELEMETRY_UNAVAILABLE no readable request records at all.
//
// NOT_OBSERVED never means NOT_EXPLOITED, and the result says so in a field a consumer can test (`notExploitedClaim: false`)
// and in a sentence a person reads.





const HUNT_VERDICTS = Object.freeze(['OBSERVED', 'NOT_OBSERVED', 'INCONCLUSIVE', 'TELEMETRY_UNAVAILABLE']);
const MAX_SAMPLES = 20;
const MAX_PARSE_FAILURE_RATIO = 0.05;

const STATEMENTS = {
  OBSERVED: (n) => `${n} request(s) have the shape of this exploit. A match is a lead to investigate, not proof of compromise: a scanner or a test could produce the same request.`,
  NOT_OBSERVED: () => 'No matching request was found in the searched logs. This does not establish that the vulnerability was not exploited: exploitation could have used a route, encoding or time these logs do not cover.',
  INCONCLUSIVE: () => 'No matching request was found, but the logs could not support a negative answer. See the caveats; do not read this as "not exploited".',
  TELEMETRY_UNAVAILABLE: () => 'There were no readable request records to search, so nothing can be said about past exploitation.',
};

const FIELD_COUNT_KEY = { method: 'method', path: 'path', query: 'query', body: 'body', headers: 'headers', status: 'status', auth: 'auth' };

async function huntLogs({ ir, logsPath, since = null, until = null, signal, limits } = {}) {
  const base = { schema: 'agentic-security/hunt-result', version: 1, findingId: ir.findingId, detectionId: ir.id, detectionDigest: ir.digest, notExploitedClaim: false, egress: 'none' };
  const sinceMs = since ? Date.parse(since) : null;
  const untilMs = until ? Date.parse(until) : null;
  if ((since && Number.isNaN(sinceMs)) || (until && Number.isNaN(untilMs))) {
    return { ...base, verdict: 'INCONCLUSIVE', caveats: ['the --since/--until value is not a valid date, so nothing was searched'], matches: { count: 0, samples: [] }, statement: STATEMENTS.INCONCLUSIVE() };
  }
  const sampleList = [];
  let matchCount = 0; let firstSeen = null; let lastSeen = null;
  let undecidable = 0; const undecidableFields = new Set();
  let endpointEvents = 0; let outOfWindow = 0; let undated = 0;

  const stats = await readLogs(logsPath, {
    signal, limits,
    onEvent(ev) {
      if (sinceMs != null || untilMs != null) {
        if (!ev.time) { undated++; return; }
        const t = Date.parse(ev.time);
        if ((sinceMs != null && t < sinceMs) || (untilMs != null && t > untilMs)) { outOfWindow++; return; }
      }
      const r = evaluateEvent(ir, ev);
      if (r.undecidable) { undecidable++; r.missing.forEach((m) => undecidableFields.add(m)); return; }
      if (ir.endpoint && ev.method === ir.endpoint.method) endpointEvents++;
      if (!r.match) return;
      matchCount++;
      if (ev.time) { if (!firstSeen || ev.time < firstSeen) firstSeen = ev.time; if (!lastSeen || ev.time > lastSeen) lastSeen = ev.time; }
      if (sampleList.length < MAX_SAMPLES) sampleList.push({ time: ev.time, method: ev.method, path: redactValue(ev.path, 160), matchedOn: r.matchedOn, valueFingerprint: fingerprint(r.value), valuePreview: redactValue(r.value, 80), status: ev.status });
    },
  });

  const logs = { source: external_node_path_.basename(String(logsPath)), files: stats.files.length, filesSkipped: stats.filesSkipped, lines: stats.lines, parsed: stats.parsed, failed: stats.failed, truncated: stats.truncated };
  const window = { start: stats.windowStart, end: stats.windowEnd, datedEvents: stats.eventsWithTime };
  const caveats = [];
  const result = (verdict) => ({ ...base, verdict, logs, window, coverage: { requestedWindow: { since, until }, outOfWindow, undated, endpointEvents, requiredFields: requiredFields(ir), fieldAvailability: Object.fromEntries(Object.entries(FIELD_COUNT_KEY).map(([k, key]) => [k, stats.parsed ? Number((stats.fieldCounts[key] / stats.parsed).toFixed(3)) : 0])) }, matches: { count: matchCount, firstSeen, lastSeen, samples: sampleList }, caveats, statement: STATEMENTS[verdict](matchCount) });

  if (stats.unreadable || stats.parsed === 0) {
    caveats.push(stats.unreadable ? 'the log path could not be read' : stats.lines === 0 ? 'the logs contain no lines' : 'no line was recognised as a request record (supported: common/combined access logs, JSON lines)');
    return result('TELEMETRY_UNAVAILABLE');
  }
  if (matchCount > 0) {
    if (stats.truncated.length || stats.aborted) caveats.push(`the read was cut short (${[...stats.truncated, ...(stats.aborted ? ['aborted'] : [])].join(', ')}); more matches may exist`);
    return result('OBSERVED');
  }
  // nothing matched: decide whether a negative answer is supportable
  const failRatio = stats.lines ? stats.failed / stats.lines : 0;
  if (failRatio > MAX_PARSE_FAILURE_RATIO) caveats.push(`${(failRatio * 100).toFixed(1)}% of lines could not be parsed (limit ${MAX_PARSE_FAILURE_RATIO * 100}%)`);
  if (stats.truncated.length || stats.aborted || stats.budgetExhausted) caveats.push(`the read was cut short (${[...stats.truncated, ...(stats.aborted ? ['aborted'] : [])].join(', ') || 'budget'})`);
  if (undecidable > 0) caveats.push(`${undecidable} event(s) lacked a field this detection needs (${[...undecidableFields].join(', ')}), so they could not be judged`);
  if (!stats.eventsWithTime) caveats.push('no event carries a timestamp, so the searched time window is unknown');
  if (stats.filesSkipped.some((f) => f.reason !== 'not-a-log-extension')) caveats.push(`${stats.filesSkipped.filter((f) => f.reason !== 'not-a-log-extension').length} file(s) were skipped (${[...new Set(stats.filesSkipped.map((f) => f.reason))].join(', ')})`);
  if (undated > 0) caveats.push(`${undated} event(s) had no timestamp and were excluded by the requested window`);
  if (!caveats.length && ir.endpoint && endpointEvents === 0) caveats.push('no request to the endpoint appears in the logs at all (informational: nothing to exploit was seen either)');
  const blocking = caveats.some((c) => !c.startsWith('no request to the endpoint'));
  return result(blocking ? 'INCONCLUSIVE' : 'NOT_OBSERVED');
}

// EXTERNAL MODULE: external "node:child_process"
var external_node_child_process_ = __webpack_require__(31421);
;// CONCATENATED MODULE: ./src/posture/dnr/exposure-window.js
// Vulnerability exposure window (PRD 7, requirement 5): combine WHEN the flaw entered the code, WHEN a build containing it
// first ran, WHEN the fix was committed and deployed, and WHAT telemetry exists, into the span that can actually be hunted.
//
// Every date is sourced (provenance, a deployment record, a git commit, a hunt's own telemetry window). A date that has no
// source is reported as unknown and listed under `unknowns`; the window that depends on it is then `partial`, or
// `unavailable`, and the output never fills a gap with an assumption. Part of the exposure that predates the telemetry is
// reported as `unobservableBefore`: it happened, and nothing here can say whether it was exploited.



const MAX_DEPLOYMENTS = 1000;
const SHA_RE = /^[0-9a-f]{7,64}$/i;
const ts = (v) => { if (v == null) return null; const t = Date.parse(v); return Number.isNaN(t) ? null : t; };
const iso = (t) => (t == null ? null : new Date(t).toISOString());

/**
 * Which source commit each artifact digest was built from, read from artifact provenance graphs (`provenance trace` output, or the
 * graph alone). The commit is whatever the graph's build label declared: a graph whose commit is unknown contributes nothing, and a
 * digest named by two graphs that disagree is listed as a conflict and resolves to neither.
 * Returns { commits: Map<digest, sha>, problems }.
 */
function artifactCommitMap(graphs) {
  const commits = new Map(); const conflicts = new Set(); const problems = [];
  (graphs || []).forEach((doc, i) => {
    const g = doc?.artifactProvenanceGraph ?? doc;
    if (!g || !Array.isArray(g.nodes) || !Array.isArray(g.edges)) { problems.push(`artifact graph ${i}: not an artifact provenance graph`); return; }
    const digest = g.nodes.find((n) => n && n.kind === 'ociDigest' && typeof n.digest === 'string')?.digest;
    const commit = g.nodes.find((n) => n && n.kind === 'gitCommit' && n.known === true && typeof n.sha === 'string' && SHA_RE.test(n.sha))?.sha?.toLowerCase();
    if (!digest) { problems.push(`artifact graph ${i}: no image digest`); return; }
    if (!commit) { problems.push(`artifact graph ${i}: the image declares no source commit, so ${digest.slice(0, 19)} cannot be placed in history`); return; }
    if (commits.has(digest) && commits.get(digest) !== commit) { conflicts.add(digest); return; }
    commits.set(digest, commit);
  });
  for (const d of conflicts) { commits.delete(d); problems.push(`artifact graphs disagree about the source commit of ${d.slice(0, 19)}; it resolves to neither`); }
  return { commits, problems };
}

/**
 * Parse a deployment-history file. Returns {deployments, problems}. Unusable entries are listed, never silently dropped.
 * With `artifactCommits` (from artifactCommitMap), a deployment that names only an artifact digest is placed at the commit the image
 * declares, and one that names both is refused when they disagree: the record cannot be trusted over the build label or the reverse.
 */
function loadDeployments(file, { environment = null, artifactCommits = null } = {}) {
  const problems = [];
  let raw;
  try { raw = JSON.parse(external_node_fs_.readFileSync(file, 'utf8')); } catch (e) { return { deployments: [], problems: [`could not read deployment history: ${e.code || e.message}`] }; }
  const list = Array.isArray(raw) ? raw : Array.isArray(raw?.deployments) ? raw.deployments : null;
  if (!list) return { deployments: [], problems: ['deployment history must be a list, or an object with a "deployments" list'] };
  if (list.length > MAX_DEPLOYMENTS) problems.push(`only the first ${MAX_DEPLOYMENTS} of ${list.length} deployments were read`);
  const deployments = [];
  list.slice(0, MAX_DEPLOYMENTS).forEach((d, i) => {
    if (!d || typeof d !== 'object') { problems.push(`deployment ${i}: not an object`); return; }
    const digest = typeof d.artifactDigest === 'string' ? d.artifactDigest.slice(0, 80) : null;
    const fromGraph = digest && artifactCommits ? artifactCommits.get(digest) ?? null : null;
    let commit = typeof d.commit === 'string' && SHA_RE.test(d.commit) ? d.commit.toLowerCase() : null;
    let commitSource = 'deployment-record';
    if (!commit && d.commit !== undefined && d.commit !== null) { problems.push(`deployment ${i}: commit must be a hex sha`); return; }
    if (commit && fromGraph && !(fromGraph.startsWith(commit) || commit.startsWith(fromGraph))) { problems.push(`deployment ${i}: the record says commit ${commit.slice(0, 12)} but the image ${digest.slice(0, 19)} declares ${fromGraph.slice(0, 12)}; it was not used`); return; }
    if (!commit && fromGraph) { commit = fromGraph; commitSource = 'artifact-provenance-graph'; }
    if (!commit) { problems.push(digest && artifactCommits ? `deployment ${i}: commit must be a hex sha, and image ${digest.slice(0, 19)} is not in the artifact graphs` : `deployment ${i}: commit must be a hex sha`); return; }
    if (ts(d.deployedAt) == null) { problems.push(`deployment ${i}: deployedAt is not a date`); return; }
    if (environment && d.environment !== environment) return;
    deployments.push({ commit, commitSource, deployedAt: iso(ts(d.deployedAt)), environment: typeof d.environment === 'string' ? d.environment.slice(0, 40) : null, artifactDigest: digest });
  });
  return { deployments, problems };
}

function git(repo, args, timeoutMs = 15000) {
  const r = (0,external_node_child_process_.spawnSync)('git', args, { cwd: repo, encoding: 'utf8', timeout: timeoutMs, killSignal: 'SIGKILL', stdio: ['ignore', 'pipe', 'ignore'], maxBuffer: 1 << 20 });
  return r.error || r.status === null ? { ok: false, status: null, out: '' } : { ok: true, status: r.status, out: r.stdout.trim() };
}
/** true / false / null (null: git could not answer, e.g. an unknown commit or a shallow clone). */
function isAncestor(repo, ancestor, descendant) {
  const r = git(repo, ['merge-base', '--is-ancestor', ancestor, descendant]);
  if (!r.ok) return null;
  return r.status === 0 ? true : r.status === 1 ? false : null;
}
function commitDate(repo, sha) {
  const r = git(repo, ['show', '-s', '--format=%cI', sha]);
  return r.ok && r.status === 0 && r.out ? iso(ts(r.out)) : null;
}

/** True only when the NEWEST recorded deployment is one that contains the flaw: a statement about the record, not about today. */
function stillExposed(deployments, vulnerable) {
  if (!deployments.length || !vulnerable.length) return false;
  const newest = [...deployments].sort((a, b) => Date.parse(b.deployedAt) - Date.parse(a.deployedAt))[0];
  return vulnerable.some((d) => d.commit === newest.commit && d.deployedAt === newest.deployedAt);
}

function computeExposureWindow({ finding, repo, deployments: rawDeployments = [], deploymentProblems = [], fixCommit = null, telemetry = null, deps = {} } = {}) {
  // callers may pass records that did not come through loadDeployments; normalise dates so every output is comparable
  const deployments = rawDeployments.filter((d) => d && ts(d.deployedAt) != null).map((d) => ({ ...d, deployedAt: iso(ts(d.deployedAt)) }));
  const anc = deps.isAncestor ?? ((a, d) => isAncestor(repo, a, d));
  const cdate = deps.commitDate ?? ((sha) => commitDate(repo, sha));
  const unknowns = [];
  const origin = finding?.findingProvenance?.findingOrigin ?? null;
  const introCommit = origin?.commit ?? null;
  const introducedAt = iso(ts(origin?.authorDate ?? origin?.committerDate));
  if (!introCommit) unknowns.push('introduction commit (the finding has no resolved origin)');
  else if (!introducedAt) unknowns.push('introduction date');

  const fixAt = fixCommit ? cdate(fixCommit) : null;
  if (!fixCommit) unknowns.push('fix commit (not supplied)');
  else if (!fixAt) unknowns.push('fix commit date (the commit could not be read)');

  const unresolved = [];
  const vulnerable = []; const fixed = [];
  if (!deployments.length) unknowns.push('deployment history (none supplied)');
  for (const d of deployments) {
    if (!introCommit) break;
    const hasBug = anc(introCommit, d.commit);
    if (hasBug === null) { unresolved.push({ commit: d.commit, deployedAt: d.deployedAt, reason: 'ancestry could not be determined' }); continue; }
    const hasFix = fixCommit ? anc(fixCommit, d.commit) : false;
    if (fixCommit && hasFix === null) { unresolved.push({ commit: d.commit, deployedAt: d.deployedAt, reason: 'fix ancestry could not be determined' }); continue; }
    if (hasBug && !hasFix) vulnerable.push(d);
    if (hasFix) fixed.push(d);
  }
  if (unresolved.length) unknowns.push(`${unresolved.length} deployment(s) whose contents could not be resolved against the introduction/fix commits`);
  const byTime = (a, b) => Date.parse(a.deployedAt) - Date.parse(b.deployedAt);
  const firstVulnerable = [...vulnerable].sort(byTime)[0] ?? null;
  const fixDeployedAt = [...fixed].sort(byTime)[0] ?? null;
  if (introCommit && deployments.length && !firstVulnerable && !unresolved.length) unknowns.push('no recorded deployment contains the vulnerable code');
  if (fixCommit && deployments.length && !fixDeployedAt && !unresolved.length) unknowns.push('the fix has not been deployed according to the deployment history');

  const exposureStart = ts(firstVulnerable?.deployedAt);
  const exposureEnd = ts(fixDeployedAt?.deployedAt);
  const telStart = ts(telemetry?.start); const telEnd = ts(telemetry?.end);
  if (telStart == null || telEnd == null) unknowns.push('telemetry window (no dated telemetry)');

  let observable = null; let unobservableBefore = null;
  if (exposureStart != null) {
    const end = exposureEnd ?? telEnd;
    if (telStart != null && telEnd != null && end != null) {
      const s = Math.max(exposureStart, telStart); const e = Math.min(end, telEnd);
      if (s <= e) observable = { start: iso(s), end: iso(e), openEnded: exposureEnd == null };
      if (exposureStart < telStart) unobservableBefore = { start: iso(exposureStart), end: iso(Math.min(telStart, end ?? telStart)) };
    }
  }
  const status = exposureStart == null ? 'unavailable' : (unknowns.length || !observable) ? 'partial' : 'complete';
  return {
    schema: 'agentic-security/exposure-window', version: 1, findingId: finding?.stableId ?? finding?.id ?? null, status,
    vulnerabilityIntroduced: introducedAt ? { at: introducedAt, commit: introCommit, source: 'finding-provenance' } : null,
    firstVulnerableDeployment: firstVulnerable ? { at: firstVulnerable.deployedAt, commit: firstVulnerable.commit, commitSource: firstVulnerable.commitSource ?? 'deployment-record', environment: firstVulnerable.environment, artifactDigest: firstVulnerable.artifactDigest } : null,
    fixCommitted: fixAt ? { at: fixAt, commit: fixCommit } : null,
    fixDeployed: fixDeployedAt ? { at: fixDeployedAt.deployedAt, commit: fixDeployedAt.commit, commitSource: fixDeployedAt.commitSource ?? 'deployment-record', environment: fixDeployedAt.environment, artifactDigest: fixDeployedAt.artifactDigest } : null,
    stillExposed: stillExposed(deployments, vulnerable),
    telemetryWindow: telStart != null && telEnd != null ? { start: iso(telStart), end: iso(telEnd) } : null,
    observableWindow: observable, unobservableBefore, unresolvedDeployments: unresolved, deploymentProblems, unknowns,
    statement: 'The observable window is the part of the exposure that telemetry covers. Exposure outside it is unobserved, which is not the same as unexploited.',
  };
}

function formatExposureWindow(w) {
  const day = (x) => (x ? x.at.slice(0, 10) : 'unknown');
  const lines = [
    `Vulnerability introduced: ${day(w.vulnerabilityIntroduced)}`,
    `First vulnerable deployment: ${day(w.firstVulnerableDeployment)}`,
    `Fix committed: ${day(w.fixCommitted)}`,
    `Fix deployed: ${w.fixDeployed ? day(w.fixDeployed) : w.stillExposed ? 'not deployed (still exposed)' : 'unknown'}`,
    `Telemetry available: ${w.telemetryWindow ? `${w.telemetryWindow.start.slice(0, 10)} to ${w.telemetryWindow.end.slice(0, 10)}` : 'unknown'}`,
    '',
    `Observable exposure window: ${w.observableWindow ? `${w.observableWindow.start.slice(0, 10)} to ${w.observableWindow.openEnded ? 'present (fix not deployed)' : w.observableWindow.end.slice(0, 10)}` : 'cannot be determined'}`,
  ];
  if (w.unobservableBefore) lines.push(`Exposed but not observable: ${w.unobservableBefore.start.slice(0, 10)} to ${w.unobservableBefore.end.slice(0, 10)} (before telemetry began)`);
  if (w.unknowns.length) lines.push('', `Status: ${w.status}. Unknown: ${w.unknowns.join('; ')}`);
  return lines.join('\n');
}

// EXTERNAL MODULE: ./src/posture/dnr/store.js
var dnr_store = __webpack_require__(75046);
// EXTERNAL MODULE: ./src/posture/state-dir.js
var state_dir = __webpack_require__(69259);
;// CONCATENATED MODULE: ./src/posture/dnr/view.js
// The unified finding view (PRD 7, requirement 8): FIND, PROVE, HUNT, FIX, VERIFY, DETECT in one place, assembled only from
// records that exist. A step with no record is shown as missing, not inferred from its neighbours; a tampered record is
// shown as such and not used.






function loadFindingFromLastScan(root, id) {
  try {
    const last = JSON.parse(external_node_fs_.readFileSync((0,state_dir.statePath)(root, 'last-scan.json'), 'utf8'));
    return (last.findings || []).find((f) => f.id === id || f.stableId === id) ?? null;
  } catch { return null; }
}

const days = (w) => (w?.start && w?.end ? Math.max(1, Math.round((Date.parse(w.end) - Date.parse(w.start)) / 86400000)) : null);

function buildLifecycleView(root, findingId) {
  const finding = loadFindingFromLastScan(root, findingId);
  const proofs = (0,store.listProofs)(root, findingId);
  const proofTampered = proofs.some((p) => p.tampered);
  const proof = proofs.find((p) => p.record && !p.tampered)?.record ?? null;
  // An earlier hunt that OBSERVED matches must not be hidden by a later hunt over different logs that did not.
  const hunts = (0,dnr_store.listRecords)(root, findingId, 'hunt').filter((r) => r.record && !r.tampered).map((r) => r.record);
  const hunt = hunts.find((h) => h.verdict === 'OBSERVED') ?? hunts[0] ?? null;
  const otherVerdicts = hunt ? [...new Set(hunts.filter((h) => h !== hunt).map((h) => h.verdict))] : [];
  const fix = (0,dnr_store.latestRecord)(root, findingId, 'fix')?.record ?? null;
  const det = (0,dnr_store.latestRecord)(root, findingId, 'detection')?.record ?? null;
  const tampered = [proofTampered ? 'proof' : null, ...['hunt', 'fix', 'detection'].map((k) => ((0,dnr_store.listRecords)(root, findingId, k).some((r) => r.tampered) ? k : null))].filter(Boolean);

  const confirmed = proof && (0,states/* stateRank */.g3)(proof.state) >= (0,states/* stateRank */.g3)('EXPLOIT_CONFIRMED');
  const steps = {
    FIND: finding ? { status: 'done', text: `${confirmed ? 'Confirmed vulnerability' : 'Candidate finding'}: ${finding.vuln ?? finding.id}${finding.file ? ` (${finding.file}${finding.line ? `:${finding.line}` : ''})` : ''}` } : { status: 'missing', text: 'Finding not found in the last scan' },
    PROVE: proof ? { status: confirmed ? 'done' : 'partial', text: confirmed ? `Exploit reproduced ${proof.attempts?.successes ?? 0}/${proof.attempts?.run ?? 0}, independent replay ${proof.independentReplay?.status ?? 'not run'}` : `Not confirmed (${proof.state})` } : { status: 'missing', text: 'No exploit proof' },
    HUNT: hunt ? { status: hunt.verdict === 'OBSERVED' || hunt.verdict === 'NOT_OBSERVED' ? 'done' : 'partial', text: `${days(hunt.window) ?? 'unknown'} day(s) of telemetry searched, ${hunt.verdict === 'OBSERVED' ? `${hunt.matches?.count ?? 0} matching event(s) observed` : hunt.verdict === 'NOT_OBSERVED' ? 'no matching events (not the same as not exploited)' : `${hunt.verdict.toLowerCase().replace('_', ' ')}`}${otherVerdicts.length ? `; other hunt(s): ${otherVerdicts.join(', ')}` : ''}` } : { status: 'missing', text: 'No historical hunt run' },
    FIX: fix ? { status: fix.verified ? 'done' : 'partial', text: fix.verified ? `${fix.completeness} verified remediation` : `Fix not verified: ${fix.reason ?? fix.incompleteStep ?? 'incomplete'}` } : { status: 'missing', text: 'No verified remediation recorded' },
    VERIFY: fix ? (fix.legs?.postPatch && fix.legs.postPatch.exploitSucceeded === 0 && fix.legs.postPatch.completed === fix.legs.postPatch.attempts ? { status: 'done', text: 'Original exploit blocked' } : { status: 'partial', text: 'Original exploit not shown to be blocked' }) : { status: 'missing', text: 'No post-fix replay recorded' },
    DETECT: det ? (det.validation?.status === 'VALIDATED' ? { status: 'done', text: `Recurrence rule enabled (${det.ir?.id})` } : { status: 'partial', text: `Detection ${det.ir?.id} generated but not validated (${det.validation?.status ?? 'no validation'}); not enabled` }) : { status: 'missing', text: 'No detection generated' },
  };
  return { findingId, steps, tampered, links: { detection: det ? { id: det.ir?.id, recordDigest: det.recordDigest, proofRecordDigest: det.proof?.recordDigest ?? null } : null, proofRecordDigest: proof?.recordDigest ?? null } };
}

function formatLifecycleView(v) {
  const mark = { done: 'x', partial: '~', missing: ' ' };
  const lines = [`Finding ${v.findingId}`, ''];
  for (const [name, s] of Object.entries(v.steps)) lines.push(`[${mark[s.status]}] ${name.padEnd(7)} ${s.text}`);
  if (v.tampered.length) lines.push('', `WARNING: ${v.tampered.join(', ')} record(s) failed their integrity check and were not used.`);
  lines.push('', '[x] done   [~] partial or unconfirmed   [ ] missing');
  return lines.join('\n');
}

;// CONCATENATED MODULE: ./src/posture/dnr/cli.js
// CLI surface for the detection-and-response loop: `dnr generate|validate|hunt|window|show|status`.
// Non-interactive by construction (no command reads stdin), bounded (log reads have size, line and time budgets), and local:
// nothing here contacts a network or a model, so production logs never leave the machine.
//
// Exit codes: 0 completed and clean, 4 usage or precondition, 1 a stored/produced result failed its own check (validation),
// and for `hunt` a distinct code per verdict so automation cannot read an unanswered question as a clean one:
//   0 NOT_OBSERVED   10 OBSERVED   11 INCONCLUSIVE   12 TELEMETRY_UNAVAILABLE











const HUNT_EXIT = Object.freeze({ NOT_OBSERVED: 0, OBSERVED: 10, INCONCLUSIVE: 11, TELEMETRY_UNAVAILABLE: 12 });
const EXT = { sigma: 'yml', http: 'json', waf: 'conf', 'log-query': 'json', yara: 'yar', spl: 'spl', kql: 'kql', cloudwatch: 'txt', elastic: 'json', yaral: 'yaral', datadog: 'json' };

const usage = () => { console.error('usage: dnr generate <finding-id> [--format sigma|http|waf|log-query|yara|spl|kql|cloudwatch|elastic|yaral|datadog|all] [--out dir] [--allow-unproven]\n       dnr validate <finding-id>\n       dnr hunt <finding-id> --logs <file-or-dir> [--since ISO] [--until ISO]\n       dnr window <finding-id> --deployments <file> [--fix-commit sha] [--environment name]\n       dnr show <finding-id>\n       dnr status <finding-id>'); return 4; };

function ensureDetection(root, id, flags) {
  const existing = (0,dnr_store.latestRecord)(root, id, 'detection');
  if (existing && !flags.regenerate) return { ok: true, saved: existing.record };
  const finding = loadFindingFromLastScan(root, id);
  if (!finding) return { ok: false, reason: `Finding ${id} not found in the last scan.` };
  const proofRec = (0,store.latestProof)(root, id);
  const built = buildDetectionIR({ finding, proof: proofRec?.record ?? null, allowUnproven: !!flags['allow-unproven'] });
  if (!built.ok) return { ok: false, reason: built.reason };
  const validation = validateDetection(built.ir);
  const record = { ir: built.ir, validation: { status: validation.status, counts: validation.counts, failures: validation.failures ?? [], reason: validation.reason ?? null }, enabled: validation.status === 'VALIDATED', proof: proofRec?.record ? { recordDigest: proofRec.record.recordDigest ?? null, state: proofRec.record.state ?? null } : null };
  const saved = (0,dnr_store.saveRecord)(root, id, 'detection', record);
  if (!saved.ok) return { ok: false, reason: `could not store the detection: ${saved.reason}` };
  return { ok: true, saved: { ...record, recordDigest: saved.digest }, fresh: true };
}

function writeOut(dir, id, ir, formats) {
  // the id names a file: it must be the digest-derived form, never text that arrived from a record on disk
  if (!/^det-[0-9a-f]{12}$/.test(String(ir.id))) { console.error('refusing to write: the detection id is not in its derived form'); return []; }
  external_node_fs_.mkdirSync(dir, { recursive: true });
  const written = [];
  for (const f of formats) {
    const r = renderDetection(ir, f);
    if (!r.applicable) continue;
    const file = external_node_path_.join(dir, `${ir.id}.${f === 'log-query' ? 'query' : f}.${EXT[f]}`);
    try { if (external_node_fs_.lstatSync(file).isSymbolicLink()) { console.error(`refusing to write through a symlink: ${file}`); continue; } } catch { /* does not exist */ }
    external_node_fs_.writeFileSync(file, r.content);
    written.push(file);
  }
  return written;
}

async function cmdDnr(args, root) {
  const sub = args._[1];
  const id = String(args._[2] ?? '');
  const flags = args.flags || {};
  if (!sub || !id) return usage();

  if (sub === 'generate') {
    const r = ensureDetection(root, id, { ...flags, regenerate: true });
    if (!r.ok) { console.error(r.reason); return 4; }
    const { ir, validation } = r.saved;
    const want = flags.format ? String(flags.format) : null;
    if (want && want !== 'all' && !FORMATS.includes(want)) { console.error(`unknown format "${want}"; choose one of ${FORMATS.join(', ')}, or all`); return 4; }
    if (flags.json) { console.log(JSON.stringify({ ir, validation, outputs: want && want !== 'all' ? { [want]: renderDetection(ir, want) } : renderAll(ir) }, null, 2)); return validation.status === 'VALIDATED' ? 0 : 1; }
    console.log(`Detection ${ir.id} for ${ir.findingId}: ${ir.payloadClass} (${ir.grounding}, confidence ${ir.confidence})`);
    console.log(`Validation: ${validation.status} (${validation.counts.passed}/${validation.counts.positives + validation.counts.negatives} synthetic cases)${validation.status === 'VALIDATED' ? '; recurrence rule enabled' : '; NOT enabled'}`);
    for (const l of ir.limitations) console.log(`  limitation: ${l}`);
    if (flags.out) { const w = writeOut(external_node_path_.resolve(String(flags.out)), id, ir, want && want !== 'all' ? [want] : FORMATS); console.log(`Wrote ${w.length} file(s) to ${external_node_path_.resolve(String(flags.out))}`); }
    else if (want && want !== 'all') { const o = renderDetection(ir, want); console.log(''); console.log(o.applicable ? o.content : `(${want} not applicable: ${o.reason})`); }
    else console.log(`Formats: ${FORMATS.filter((f) => renderDetection(ir, f).applicable).join(', ')} (use --format <name> to print one, --out <dir> to write them)`);
    return validation.status === 'VALIDATED' ? 0 : 1;
  }

  if (sub === 'validate') {
    const rec = (0,dnr_store.latestRecord)(root, id, 'detection');
    if (!rec) { console.error(`No detection for ${id}. Run: dnr generate ${id}`); return 4; }
    const errs = validateDetectionIR(rec.record.ir);
    if (errs.length) { console.error(`The stored detection is invalid: ${errs.join('; ')}`); return 1; }
    const v = validateDetection(rec.record.ir);
    if (flags.json) console.log(JSON.stringify(v, null, 2));
    else { console.log(`Validation: ${v.status} (${v.counts.passed}/${v.cases.length} cases)`); for (const c of v.cases.filter((x) => !x.ok)) console.log(`  FAILED: ${c.kind} "${c.name}" ${c.kind === 'positive' ? 'did not fire' : 'fired'}`); if (v.reason) console.log(`  ${v.reason}`); }
    return v.status === 'VALIDATED' ? 0 : 1;
  }

  if (sub === 'hunt') {
    if (!flags.logs) { console.error('dnr hunt needs --logs <file-or-directory>. Nothing was searched.'); return 4; }
    const det = ensureDetection(root, id, flags);
    if (!det.ok) { console.error(det.reason); return 4; }
    const ac = new AbortController();
    const onSig = () => ac.abort();
    process.once('SIGINT', onSig);
    let result;
    try { result = await huntLogs({ ir: det.saved.ir, logsPath: external_node_path_.resolve(String(flags.logs)), since: flags.since ?? null, until: flags.until ?? null, signal: ac.signal }); } finally { process.off('SIGINT', onSig); }
    const saved = (0,dnr_store.saveRecord)(root, id, 'hunt', result);
    if (flags.json) console.log(JSON.stringify({ ...result, stored: saved.ok ? saved.file : null }, null, 2));
    else {
      console.log(`Hunt: ${result.verdict}`);
      console.log(`Logs: ${result.logs.files} file(s), ${result.logs.parsed}/${result.logs.lines} lines parsed${result.window.start ? `, ${result.window.start.slice(0, 10)} to ${result.window.end.slice(0, 10)}` : ', no timestamps'}`);
      if (result.matches.count) console.log(`Matches: ${result.matches.count}${result.matches.firstSeen ? ` (first ${result.matches.firstSeen}, last ${result.matches.lastSeen})` : ''}`);
      for (const s of result.matches.samples.slice(0, 5)) console.log(`  ${s.time ?? 'undated'} ${s.method} ${s.path} [${s.matchedOn}] ${s.valuePreview}`);
      for (const c of result.caveats) console.log(`Caveat: ${c}`);
      console.log(result.statement);
      if (!saved.ok) console.log(`(result not stored: ${saved.reason})`);
    }
    return HUNT_EXIT[result.verdict] ?? 11;
  }

  if (sub === 'window') {
    if (!flags.deployments) { console.error('dnr window needs --deployments <file> (a JSON list of {commit, deployedAt, environment?}; with --artifact-graph, {artifactDigest, deployedAt} is enough). Nothing was computed.'); return 4; }
    const finding = loadFindingFromLastScan(root, id);
    if (!finding) { console.error(`Finding ${id} not found in the last scan.`); return 4; }
    let artifactCommits = null; const graphProblems = [];
    if (flags['artifact-graph']) {
      const docs = [];
      for (const f of String(flags['artifact-graph']).split(',').filter(Boolean)) {
        try { docs.push(JSON.parse(external_node_fs_.readFileSync(external_node_path_.resolve(f), 'utf8'))); } catch (e) { graphProblems.push(`artifact graph ${f}: could not be read (${e.code || 'not JSON'})`); }
      }
      const map = artifactCommitMap(docs); artifactCommits = map.commits; graphProblems.push(...map.problems);
    }
    const loaded = loadDeployments(external_node_path_.resolve(String(flags.deployments)), { environment: flags.environment ?? null, artifactCommits });
    const deployments = loaded.deployments; const problems = [...loaded.problems, ...graphProblems];
    const hunt = (0,dnr_store.latestRecord)(root, id, 'hunt')?.record ?? null;
    const telemetry = flags['telemetry-start'] && flags['telemetry-end'] ? { start: flags['telemetry-start'], end: flags['telemetry-end'] } : hunt?.window ?? null;
    const w = computeExposureWindow({ finding, repo: root, deployments, deploymentProblems: problems, fixCommit: flags['fix-commit'] ?? null, telemetry });
    (0,dnr_store.saveRecord)(root, id, 'window', w);
    if (flags.json) console.log(JSON.stringify(w, null, 2)); else console.log(`${formatExposureWindow(w)}\n\n${w.statement}`);
    return w.status === 'complete' ? 0 : 1;
  }

  if (sub === 'show') {
    const rec = (0,dnr_store.latestRecord)(root, id, 'detection');
    if (!rec) { console.error(`No detection for ${id}.`); return 4; }
    if ((0,dnr_store.listRecords)(root, id, 'detection').some((r) => r.tampered)) console.error('WARNING: a stored detection record failed its integrity check and was not used.');
    console.log(JSON.stringify(flags.json ? rec.record : { id: rec.record.ir.id, payloadClass: rec.record.ir.payloadClass, grounding: rec.record.ir.grounding, endpoint: rec.record.ir.endpoint, enabled: rec.record.enabled, validation: rec.record.validation.status, proof: rec.record.proof }, null, 2));
    return 0;
  }

  if (sub === 'status') {
    const v = buildLifecycleView(root, id);
    if (flags.json) console.log(JSON.stringify(v, null, 2)); else console.log(formatLifecycleView(v));
    return 0;
  }
  return usage();
}


/***/ }),

/***/ 75046:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   hasTamperedRecords: () => (/* binding */ hasTamperedRecords),
/* harmony export */   latestRecord: () => (/* binding */ latestRecord),
/* harmony export */   listRecords: () => (/* binding */ listRecords),
/* harmony export */   saveRecord: () => (/* binding */ saveRecord)
/* harmony export */ });
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(73024);
/* harmony import */ var node_path__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(76760);
/* harmony import */ var _state_dir_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(69259);
/* harmony import */ var _encryption_provider_js__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(71425);
/* harmony import */ var _proof_fabric_reproducer_js__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(82034);
/* harmony import */ var _proof_fabric_store_js__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(25216);
// Persistence for the detection-and-response loop: `.agentic-security/dnr/<findingKey>/<kind>-<digest>.json`.
// Same machinery and the same guarantees as the proof store, reused rather than copied where it is exported:
// safe state-directory writes (no symlinks, no unsafe dirs), the encryption policy, retention as evidence, legal holds, and
// a recursive secret scrub before anything touches disk. A record that no longer matches its own digest is returned FLAGGED,
// never trusted and never silently dropped.







const DIR = 'dnr';
const MAX_RECORD_BYTES = 1024 * 1024;
const RECORD_KINDS = Object.freeze(['detection', 'hunt', 'window', 'fix']);

const digestOf = (record) => { const { recordDigest: _omit, ...rest } = record; return (0,_proof_fabric_reproducer_js__WEBPACK_IMPORTED_MODULE_4__/* .sha256 */ .sc)((0,_proof_fabric_reproducer_js__WEBPACK_IMPORTED_MODULE_4__/* .canonicalize */ .dw)(rest)); };

function saveRecord(root, findingId, kind, record) {
  if (!RECORD_KINDS.includes(kind)) return { ok: false, reason: `unknown record kind: ${kind}` };
  const safe = (0,_proof_fabric_store_js__WEBPACK_IMPORTED_MODULE_5__.scrubDeep)(record);
  safe.schema = `agentic-security/dnr-${kind}-record`;
  safe.kind = kind;
  safe.findingId = String(findingId);
  safe.savedAt = record.savedAt ?? new Date().toISOString();
  safe.recordDigest = digestOf(safe);
  const text = JSON.stringify(safe, null, 2);
  if (Buffer.byteLength(text) > MAX_RECORD_BYTES) return { ok: false, reason: 'record exceeds the size limit' };
  if (!(0,_state_dir_js__WEBPACK_IMPORTED_MODULE_2__.ensureStateDir)(root)) return { ok: false, reason: 'no safe state directory for this project' };
  const enc = (0,_encryption_provider_js__WEBPACK_IMPORTED_MODULE_3__/* .maybeEncryptForWrite */ .v2)(root, DIR, text);
  if (!enc.ok) return { ok: false, reason: enc.reason };
  const file = (0,_state_dir_js__WEBPACK_IMPORTED_MODULE_2__.statePath)(root, DIR, (0,_proof_fabric_store_js__WEBPACK_IMPORTED_MODULE_5__.findingKey)(findingId), `${kind}-${safe.recordDigest.slice(0, 16)}.json`);
  if (!(0,_state_dir_js__WEBPACK_IMPORTED_MODULE_2__.safeWriteState)(file, enc.content)) return { ok: false, reason: 'state write refused' };
  return { ok: true, file, digest: safe.recordDigest, encrypted: enc.encrypted };
}

/** Newest-first records of one kind for a finding. Tampered records are flagged. */
function listRecords(root, findingId, kind) {
  const dir = (0,_state_dir_js__WEBPACK_IMPORTED_MODULE_2__.statePath)(root, DIR, (0,_proof_fabric_store_js__WEBPACK_IMPORTED_MODULE_5__.findingKey)(findingId));
  let names = [];
  try { names = node_fs__WEBPACK_IMPORTED_MODULE_0__.readdirSync(dir).filter((n) => n.startsWith(`${kind}-`) && n.endsWith('.json')); } catch { return []; }
  const out = [];
  for (const n of names) {
    const file = node_path__WEBPACK_IMPORTED_MODULE_1__.join(dir, n);
    try {
      const rec = JSON.parse((0,_encryption_provider_js__WEBPACK_IMPORTED_MODULE_3__.maybeDecryptForRead)(node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(file, 'utf8')));
      out.push({ file, record: rec, tampered: rec.recordDigest !== digestOf(rec), mtime: node_fs__WEBPACK_IMPORTED_MODULE_0__.statSync(file).mtimeMs });
    } catch { out.push({ file, record: null, tampered: true, mtime: 0 }); }
  }
  return out.sort((a, b) => b.mtime - a.mtime);
}

/** Newest intact record of a kind, or null. A tampered newest record does NOT fall through silently: the caller can see it via listRecords. */
function latestRecord(root, findingId, kind) {
  return listRecords(root, findingId, kind).find((r) => r.record && !r.tampered) ?? null;
}
const hasTamperedRecords = (root, findingId, kind) => listRecords(root, findingId, kind).some((r) => r.tampered);


/***/ }),

/***/ 58355:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   KF: () => (/* binding */ toProofTier),
/* harmony export */   g3: () => (/* binding */ stateRank),
/* harmony export */   jn: () => (/* binding */ fromProofTier),
/* harmony export */   np: () => (/* binding */ advance)
/* harmony export */ });
/* unused harmony exports EVIDENCE_STATES, COMPLETENESS */
// Evidence state ladder for the Universal Exploit Proof Fabric.
//
// Evidence state is SEPARATE from severity and confidence. It extends, never replaces, the vocabulary that already
// exists: `proof-tier.js` (execution-proven / proof-failed / taint-proven / unproven) and the fix-verify legs
// (`verifiedFull`, `degradedLegs`). `toProofTier` / `fromProofTier` are the explicit bridges.
//
// Transitions are guarded: a state can only be reached from the state directly before it (or by dropping back), so no
// caller can jump a finding to EXPLOIT_CONFIRMED without passing REPRODUCED, or to FIX_VERIFIED without
// FIX_REPLAY_BLOCKED. A degraded or incomplete run NEVER advances a state.
const EVIDENCE_STATES = Object.freeze([
  'CANDIDATE',
  'STATICALLY_CORROBORATED',
  'REPRODUCER_GENERATED',
  'REPRODUCED',
  'EXPLOIT_CONFIRMED',
  'FIX_REPLAY_BLOCKED',
  'FIX_VERIFIED',
]);

const stateRank = (s) => EVIDENCE_STATES.indexOf(s);

const REQUIRES_PREDECESSOR = Object.freeze(Object.fromEntries(EVIDENCE_STATES.map((s, i) => [s, i === 0 ? null : EVIDENCE_STATES[i - 1]])));

/**
 * Advance `from` to `to`. Returns { ok, state, reason }. Moving up requires `to` to be exactly the next rung; moving
 * down or staying is always allowed (evidence can be lost, never invented). Unknown states are rejected.
 */
function advance(from, to) {
  if (!EVIDENCE_STATES.includes(from)) return { ok: false, state: 'CANDIDATE', reason: `unknown current state: ${String(from)}` };
  if (!EVIDENCE_STATES.includes(to)) return { ok: false, state: from, reason: `unknown target state: ${String(to)}` };
  if (stateRank(to) <= stateRank(from)) return { ok: true, state: to, reason: null };
  if (REQUIRES_PREDECESSOR[to] !== from) return { ok: false, state: from, reason: `cannot reach ${to} from ${from}: ${REQUIRES_PREDECESSOR[to]} is required first` };
  return { ok: true, state: to, reason: null };
}

// Bridges to the older vocabulary so existing consumers keep working.
function toProofTier(state) {
  const r = stateRank(state);
  if (r >= stateRank('EXPLOIT_CONFIRMED')) return 'execution-proven';
  if (r >= stateRank('STATICALLY_CORROBORATED')) return 'taint-proven';
  return 'unproven';
}

function fromProofTier(tier) {
  if (tier === 'taint-proven') return 'STATICALLY_CORROBORATED';
  // execution-proven under the older single-run marker path is one run, not the 3/3 + independent replay the fabric
  // requires, so it maps to REPRODUCED and never to EXPLOIT_CONFIRMED.
  if (tier === 'execution-proven') return 'REPRODUCED';
  return 'CANDIDATE';
}

// Completeness vocabulary shared with fix-verify: FULL only when nothing was skipped.
const COMPLETENESS = Object.freeze(['FULL', 'DEGRADED', 'INCOMPLETE']);


/***/ }),

/***/ 25216:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   findingKey: () => (/* binding */ findingKey),
/* harmony export */   latestProof: () => (/* binding */ latestProof),
/* harmony export */   listProofs: () => (/* binding */ listProofs),
/* harmony export */   saveProof: () => (/* binding */ saveProof),
/* harmony export */   scrubDeep: () => (/* binding */ scrubDeep)
/* harmony export */ });
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(73024);
/* harmony import */ var node_path__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(76760);
/* harmony import */ var _state_dir_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(69259);
/* harmony import */ var _encryption_provider_js__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(71425);
/* harmony import */ var _llm_validator_redact_js__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(98039);
/* harmony import */ var _reproducer_js__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(82034);
// Proof artifact store: `.agentic-security/proofs/<findingKey>/<recordDigest>.json`.
//
// Reuses the existing state machinery rather than adding another: `safeWriteState` (refuses unsafe dirs and symlinks),
// `maybeEncryptForWrite` / `maybeDecryptForRead` (the `proofs` artifact is registered `confidential`), retention
// (evidence class) and legal holds (a hold on `proofs` blocks purge). Nothing persisted contains a plaintext credential:
// records are passed through a recursive secret filter first, and the runner never returns its per-run nonce or secrets.







const PROOF_RECORD_SCHEMA = 'agentic-security/proof-record';
const PROOFS_DIR = 'proofs';
const MAX_RECORD_BYTES = 512 * 1024;

const findingKey = (id) => `${String(id).replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 80)}-${(0,_reproducer_js__WEBPACK_IMPORTED_MODULE_5__/* .sha256 */ .sc)(String(id)).slice(0, 8)}`;

// The shared redactor catches key=value shapes; bare tokens need their own pass, so persisted evidence cannot carry one.
const BARE_SECRET_RES = [
  /\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}\b/g, /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, /\bsk-[A-Za-z0-9_-]{20,}\b/g,
  /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g, /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g, /\bSECRET-[0-9a-f]{24}-[a-z0-9_-]+\b/g,
];
function scrubString(text) {
  let t = String(text);
  try { t = (0,_llm_validator_redact_js__WEBPACK_IMPORTED_MODULE_4__/* .redactSecrets */ .f)(t).text; } catch { return '[unredactable]'; }
  for (const re of BARE_SECRET_RES) t = t.replace(re, '[REDACTED-SECRET]');
  return t;
}

/** Deep-copy `v` with every string passed through the secret redactor. */
function scrubDeep(v) {
  if (typeof v === 'string') return scrubString(v);
  if (Array.isArray(v)) return v.map(scrubDeep);
  if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, scrubDeep(x)]));
  return v;
}

function recordDigest(record) {
  const { recordDigest: _omit, ...rest } = record;
  return (0,_reproducer_js__WEBPACK_IMPORTED_MODULE_5__/* .sha256 */ .sc)((0,_reproducer_js__WEBPACK_IMPORTED_MODULE_5__/* .canonicalize */ .dw)(rest));
}

function saveProof(scanRoot, record) {
  const safe = scrubDeep(record);
  safe.schema = PROOF_RECORD_SCHEMA;
  safe.recordDigest = recordDigest(safe);
  const text = JSON.stringify(safe, null, 2);
  if (Buffer.byteLength(text) > MAX_RECORD_BYTES) return { ok: false, reason: 'proof record exceeds the size limit' };
  if (!(0,_state_dir_js__WEBPACK_IMPORTED_MODULE_2__.ensureStateDir)(scanRoot)) return { ok: false, reason: 'no safe state directory for this project' };
  const enc = (0,_encryption_provider_js__WEBPACK_IMPORTED_MODULE_3__/* .maybeEncryptForWrite */ .v2)(scanRoot, PROOFS_DIR, text);
  if (!enc.ok) return { ok: false, reason: enc.reason };
  const file = (0,_state_dir_js__WEBPACK_IMPORTED_MODULE_2__.statePath)(scanRoot, PROOFS_DIR, findingKey(record.findingId), `${safe.recordDigest}.json`);
  if (!(0,_state_dir_js__WEBPACK_IMPORTED_MODULE_2__.safeWriteState)(file, enc.content)) return { ok: false, reason: 'state write refused' };
  return { ok: true, file, digest: safe.recordDigest, encrypted: enc.encrypted };
}

function readRecord(file) {
  const text = (0,_encryption_provider_js__WEBPACK_IMPORTED_MODULE_3__.maybeDecryptForRead)(node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(file, 'utf8'));
  const rec = JSON.parse(text);
  // A record whose content no longer matches its own digest was modified after it was written.
  if (rec.recordDigest !== recordDigest(rec)) return { tampered: true, record: rec };
  return { tampered: false, record: rec };
}

/** Newest-first records for a finding. Tampered records are returned flagged, never silently dropped or trusted. */
function listProofs(scanRoot, findingId) {
  const dir = (0,_state_dir_js__WEBPACK_IMPORTED_MODULE_2__.statePath)(scanRoot, PROOFS_DIR, findingKey(findingId));
  let names = [];
  try { names = node_fs__WEBPACK_IMPORTED_MODULE_0__.readdirSync(dir).filter((n) => n.endsWith('.json')); } catch { return []; }
  const out = [];
  for (const n of names) {
    const f = node_path__WEBPACK_IMPORTED_MODULE_1__.join(dir, n);
    try { const { tampered, record } = readRecord(f); out.push({ file: f, tampered, record, mtime: node_fs__WEBPACK_IMPORTED_MODULE_0__.statSync(f).mtimeMs }); } catch { out.push({ file: f, tampered: true, record: null, mtime: 0 }); }
  }
  return out.sort((a, b) => b.mtime - a.mtime);
}

function latestProof(scanRoot, findingId) {
  return listProofs(scanRoot, findingId).find((p) => p.record) ?? null;
}


/***/ })

};
