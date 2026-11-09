// Syntax checks for every rendered detection format (GA-10 §1, 0.195.31). `checkRendered(format, content)` holds a renderer's
// output to the grammar of what it claims to be, for the subset of each language the renderers emit, and says which kind of
// check it is: a vendored schema (JSON shapes this repository owns), a subset grammar written from the target's public
// documentation at a stated version, or an official tool (none here: the hosted job that would run `sigma check`, `yarac` and a
// ModSecurity rule check is not provisioned, and this module never claims it did).
//
// What a subset grammar catches: a field that does not exist in the target's log table, a metadata action on the wrong rule of a
// ModSecurity chain, an escape sequence the target's string syntax does not accept, an undefined selection in a Sigma condition,
// an unbalanced quote or brace, a regular expression delimiter left unescaped. What it does not catch: whether the rule MEANS
// what the proof established (that is `renderer-semantics` for the two formats with an interpreter, and a real product for the
// rest). The constant `FORMAT_ASSURANCE` in outputs.js states the level per format; the contract page mirrors it.
import { load as loadYaml } from '../../util/yaml.js';

/** The target each check is written against. A version is the public document the subset was read from, not a tool that ran. */
export const SYNTAX_TARGETS = Object.freeze({
  sigma: { target: 'Sigma rule specification', version: '2.0.0', check: 'subset-grammar' },
  http: { target: 'agentic-security/http-detection', version: '1', check: 'vendored-schema' },
  waf: { target: 'ModSecurity SecRule language', version: '2.9 / 3.0 (CRS 4 conventions)', check: 'subset-grammar' },
  'log-query': { target: 'agentic-security/structured-log-query', version: '1', check: 'vendored-schema' },
  yara: { target: 'YARA rule language', version: '4.5', check: 'subset-grammar' },
  spl: { target: 'Splunk Search Processing Language', version: '9.x', check: 'subset-grammar' },
  kql: { target: 'Kusto Query Language over the W3CIISLog table', version: 'Azure Monitor Logs, 2024 schema', check: 'subset-grammar' },
  cloudwatch: { target: 'CloudWatch Logs Insights query syntax', version: '2024', check: 'subset-grammar' },
  elastic: { target: 'Elasticsearch Query DSL (bool, term, regexp, range, exists)', version: '8.x', check: 'vendored-schema' },
  yaral: { target: 'YARA-L', version: '2.0', check: 'subset-grammar' },
  datadog: { target: 'Datadog Security Monitoring rule (log_detection)', version: 'API v2, 2024', check: 'vendored-schema' },
});

const ok = () => ({ ok: true, errors: [] });
const fail = (...errors) => ({ ok: false, errors });

// ── Sigma ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
const SIGMA_REQUIRED = ['title', 'id', 'status', 'description', 'logsource', 'detection', 'level'];
const SIGMA_STATUS = new Set(['stable', 'test', 'experimental', 'deprecated', 'unsupported']);
const SIGMA_LEVEL = new Set(['informational', 'low', 'medium', 'high', 'critical']);
const SIGMA_MODIFIERS = new Set(['re', 'i', 'contains', 'startswith', 'endswith', 'exists', 'all']);
// the fields of the `webserver` log source category, as the W3C extended log format names them
const SIGMA_WEBSERVER_FIELDS = new Set(['cs-method', 'cs-uri-stem', 'cs-uri-query', 'cs-uri', 'c-ip', 'cs-host', 'cs-user-agent', 'cs-referer', 'cs-username', 'sc-status', 'sc-bytes', 'cs-bytes', 'cs-version', 'cs-cookie', 'cs-authorization', 'date', 'time', 's-ip', 's-port', 'time-taken']);
export function checkSigma(text) {
  let doc;
  try { doc = loadYaml(String(text)); } catch (e) { return fail(`not YAML: ${e.message}`); }
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) return fail('a Sigma rule is a YAML mapping');
  const errors = [];
  for (const k of SIGMA_REQUIRED) if (!(k in doc)) errors.push(`missing required key: ${k}`);
  if (typeof doc.id !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(doc.id)) errors.push('id must be a UUID');
  if (!SIGMA_STATUS.has(doc.status)) errors.push(`status must be one of ${[...SIGMA_STATUS].join(', ')}`);
  if (!SIGMA_LEVEL.has(doc.level)) errors.push(`level must be one of ${[...SIGMA_LEVEL].join(', ')}`);
  if (doc.date !== undefined && !/^\d{4}[-/]\d{2}[-/]\d{2}$/.test(String(doc.date))) errors.push('date must be YYYY-MM-DD');
  if (!doc.logsource || typeof doc.logsource !== 'object' || !(doc.logsource.category || doc.logsource.product || doc.logsource.service)) errors.push('logsource needs a category, product or service');
  if (Array.isArray(doc.tags)) for (const t of doc.tags) if (!/^[a-z0-9_-]+\.[a-z0-9._-]+$/.test(String(t))) errors.push(`tag ${JSON.stringify(t)} is not namespace.value`);
  const det = doc.detection;
  if (!det || typeof det !== 'object' || typeof det.condition !== 'string') { errors.push('detection needs a string condition'); return errors.length ? fail(...errors) : ok(); }
  const selections = Object.keys(det).filter((k) => k !== 'condition');
  if (!selections.length) errors.push('detection has no selection');
  for (const name of selections) {
    const sel = det[name];
    if (!sel || typeof sel !== 'object') { errors.push(`selection ${name} must be a mapping or a list`); continue; }
    const maps = Array.isArray(sel) ? sel : [sel];
    for (const m of maps) for (const key of Object.keys(m)) {
      const [field, ...mods] = key.split('|');
      if (!field) errors.push(`selection ${name}: empty field name`);
      for (const mod of mods) if (!SIGMA_MODIFIERS.has(mod)) errors.push(`selection ${name}: unknown modifier |${mod}`);
      if (doc.logsource?.category === 'webserver' && !SIGMA_WEBSERVER_FIELDS.has(field)) errors.push(`selection ${name}: ${field} is not a field of the webserver log source`);
      if (mods.includes('re')) { try { new RegExp(String(m[key])); } catch { errors.push(`selection ${name}: ${field}|re is not a regular expression`); } }
    }
  }
  const words = det.condition.replace(/[()]/g, ' ').split(/\s+/).filter(Boolean);
  for (let i = 0; i < words.length; i++) {
    const w = words[i];
    if (['and', 'or', 'not', 'of', 'them', 'all', '1'].includes(w) || /^\d+$/.test(w)) continue;
    if (w.endsWith('*')) { const prefix = w.slice(0, -1); if (!selections.some((s) => s.startsWith(prefix))) errors.push(`condition names ${w}, which matches no selection`); continue; }
    if (!selections.includes(w)) errors.push(`condition names ${w}, which is not a selection`);
  }
  return errors.length ? fail(...errors) : ok();
}

// ── ModSecurity chain ───────────────────────────────────────────────────────────────────────────────────────────────────────────
const MODSEC_DISRUPTIVE = new Set(['allow', 'block', 'deny', 'drop', 'pass', 'proxy', 'redirect']);
const MODSEC_METADATA = new Set(['id', 'msg', 'severity', 'tag', 'log', 'nolog', 'auditlog', 'noauditlog', 'phase', 'rev', 'ver', 'maturity', 'accuracy', 'logdata']);
function splitActions(s) {
  const out = []; let cur = ''; let q = null;
  for (const c of s) {
    if (q) { cur += c; if (c === q) q = null; continue; }
    if (c === "'" || c === '"') { q = c; cur += c; continue; }
    if (c === ',') { if (cur.trim()) out.push(cur.trim()); cur = ''; continue; }
    cur += c;
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}
export function checkModsecChain(text) {
  const rules = String(text).split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#'));
  if (!rules.length) return fail('no SecRule');
  const errors = [];
  const ids = new Set();
  let inChain = false;
  rules.forEach((line, i) => {
    const m = /^SecRule\s+(\S+)\s+"((?:[^"\\]|\\.)*)"\s+"((?:[^"\\]|\\.)*)"$/.exec(line);
    if (!m) { errors.push(`line ${i + 1}: not a SecRule VARIABLES "OPERATOR" "ACTIONS" line`); return; }
    const [, vars, operator, actionText] = m;
    if (!/^@[a-zA-Z]+(?:\s|$)/.test(operator)) errors.push(`line ${i + 1}: operator must start with @name`);
    if (!/^[&!]?[A-Z_]+(?::[^\s"]+)?$/.test(vars)) errors.push(`line ${i + 1}: variable ${vars} is not a ModSecurity collection`);
    const actions = splitActions(actionText).map((a) => a.split(':')[0]);
    const disruptive = actions.filter((a) => MODSEC_DISRUPTIVE.has(a));
    const metadata = actions.filter((a) => MODSEC_METADATA.has(a));
    const starter = !inChain;
    if (starter) {
      const id = splitActions(actionText).find((a) => a.startsWith('id:'));
      if (!id) errors.push(`line ${i + 1}: a chain starter needs id`);
      else { const n = Number(id.slice(3)); if (!(n >= 9000000 && n <= 9999999)) errors.push(`line ${i + 1}: id ${n} is outside the generated range`); if (ids.has(n)) errors.push(`line ${i + 1}: duplicate id ${n}`); ids.add(n); }
      if (!actions.includes('phase')) errors.push(`line ${i + 1}: a chain starter needs phase`);
      if (disruptive.length !== 1) errors.push(`line ${i + 1}: exactly one disruptive action, got ${disruptive.join(',') || 'none'}`);
      else if (disruptive[0] !== 'pass') errors.push(`line ${i + 1}: a generated rule must be pass (detect-only), not ${disruptive[0]}`);
    } else {
      if (disruptive.length) errors.push(`line ${i + 1}: a chained rule may not carry a disruptive action (${disruptive.join(',')})`);
      if (metadata.length) errors.push(`line ${i + 1}: metadata actions belong on the chain starter, not a chained rule (${metadata.join(',')})`);
    }
    inChain = actions.includes('chain');
  });
  if (inChain) errors.push('the last rule still says chain');
  return errors.length ? fail(...errors) : ok();
}

// ── YARA and YARA-L ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
const YARA_STRING = /^"(?:[^"\\\x00-\x1f\x7f-￿]|\\[\\"tn]|\\x[0-9a-fA-F]{2})*"$/;
export function checkYara(text) {
  const lines = String(text).split('\n');
  const errors = [];
  const head = lines.findIndex((l) => /^rule\s+[A-Za-z_][A-Za-z0-9_]*\s*\{$/.test(l.trim()));
  if (head < 0) errors.push('no `rule <identifier> {` header');
  if (!lines.some((l) => l.trim() === '}')) errors.push('unbalanced braces');
  let section = null;
  for (const raw of lines.slice(head + 1)) {
    const l = raw.trim();
    if (!l || l === '}') continue;
    if (/^(meta|strings|condition):$/.test(l)) { section = l.slice(0, -1); continue; }
    if (section === 'meta') { const m = /^[a-z_]+\s*=\s*(.+)$/.exec(l); if (!m || !(YARA_STRING.test(m[1]) || /^-?\d+$/.test(m[1]) || /^(true|false)$/.test(m[1]))) errors.push(`meta: ${l} is not identifier = "string" | integer | boolean (YARA strings accept only \\\\ \\" \\t \\n \\xNN escapes)`); continue; }
    if (section === 'strings') { const m = /^\$[A-Za-z0-9_]*\s*=\s*(.+)$/.exec(l); if (!m) { errors.push(`strings: ${l} is not $name = ...`); continue; } const v = m[1]; if (!(YARA_STRING.test(v) || /^\{\s*(?:[0-9A-Fa-f?]{2}\s*)+\}$/.test(v) || /^\/.+\/[is]*$/.test(v))) errors.push(`strings: ${v} is not a text, hex or regex string`); continue; }
    if (section === 'condition') { if (!/^(any of them|all of them|\$[A-Za-z0-9_]+(?:\s+(?:and|or)\s+\$[A-Za-z0-9_]+)*)$/.test(l)) errors.push(`condition: ${l} is outside the subset grammar`); continue; }
    errors.push(`line outside a section: ${l}`);
  }
  if (section !== 'condition' && !lines.some((l) => l.trim() === 'condition:')) errors.push('no condition section');
  return errors.length ? fail(...errors) : ok();
}
export function checkYaral(text) {
  const lines = String(text).split('\n').map((l) => l.trim());
  const errors = [];
  if (!lines.some((l) => /^rule\s+[A-Za-z_][A-Za-z0-9_]*\s*\{$/.test(l))) errors.push('no `rule <identifier> {` header');
  if (!lines.some((l) => l === '}')) errors.push('unbalanced braces');
  for (const sec of ['meta:', 'events:', 'condition:']) if (!lines.includes(sec)) errors.push(`missing section ${sec}`);
  let section = null;
  for (const l of lines) {
    if (!l || l === '}' || /^rule\s/.test(l)) continue;
    if (/^(meta|events|condition):$/.test(l)) { section = l.slice(0, -1); continue; }
    if (section === 'meta' && !/^[a-z_]+\s*=\s*"(?:[^"\\]|\\.)*"$/.test(l)) errors.push(`meta: ${l} is not identifier = "string"`);
    if (section === 'events' && !(/^\$[a-z]\.[a-z_.]+\s*=\s*"(?:[^"\\]|\\.)*"$/.test(l) || /^re\.regex\(\$[a-z]\.[a-z_.]+,\s*`[^`]+`\)$/.test(l))) errors.push(`events: ${l} is outside the subset grammar`);
    if (section === 'condition' && !/^\$[a-z]$/.test(l)) errors.push(`condition: ${l} must name the event variable`);
  }
  return errors.length ? fail(...errors) : ok();
}

// ── SPL, KQL, CloudWatch ────────────────────────────────────────────────────────────────────────────────────────────────────────
const quoted = (s) => /^"(?:[^"\\]|\\[\\"])*"$/.test(s);
export function checkSpl(text) {
  const lines = String(text).split('\n').map((l) => l.trim()).filter(Boolean);
  const errors = [];
  if (!lines.length) return fail('empty query');
  const head = lines[0].match(/(?:[a-z_]+=(?:"(?:[^"\\]|\\[\\"])*"|\S+))/g) || [];
  if (!/^index=/.test(lines[0]) || head.join(' ') !== lines[0]) errors.push('the first line must be field=value search terms starting with index=');
  for (const l of lines.slice(1)) {
    const rx = /^\| regex ([a-z_]+)=("(?:[^"\\]|\\[\\"])*")$/.exec(l);
    // SPL regexes are PCRE: a leading `(?i)` is the case-insensitivity flag, which JavaScript cannot compile inline
    if (rx) { try { new RegExp(JSON.parse(rx[2]).replace(/^\(\?i\)/, ''), 'i'); } catch { errors.push(`regex: ${rx[2]} is not a regular expression`); } continue; }
    if (/^\| where [a-z_]+[<>=!]+[0-9]+(?: (?:AND|OR) (?:[a-z_]+[<>=!]+[0-9]+|isnull\([a-z_]+\)|isnotnull\([a-z_]+\)))*$/.test(l)) continue;
    errors.push(`${l} is outside the subset grammar`);
  }
  return errors.length ? fail(...errors) : ok();
}
const KQL_TABLES = Object.freeze({ W3CIISLog: ['TimeGenerated', 'csMethod', 'csUriStem', 'csUriQuery', 'scStatus', 'cIP', 'csUserAgent', 'csReferer', 'csHost', 'sIP', 'sPort', 'csUserName', 'scBytes', 'csBytes', 'TimeTaken', 'Computer'] });
export function checkKql(text) {
  const lines = String(text).split('\n').map((l) => l.trim()).filter(Boolean);
  const errors = [];
  const columns = KQL_TABLES[lines[0]];
  if (!columns) return fail(`the query must start with a known table (${Object.keys(KQL_TABLES).join(', ')}), got ${JSON.stringify(lines[0] ?? '')}`);
  for (const l of lines.slice(1)) {
    const m = /^\| where (.+)$/.exec(l);
    if (!m) { errors.push(`${l} is not a | where clause`); continue; }
    for (const clause of m[1].split(/\s+and\s+/)) {
      const c = clause.trim();
      const simple = /^([A-Za-z]+) (==|!=|=~|matches regex|between) (.+)$/.exec(c);
      const fn = /^(isempty|isnotempty)\(([A-Za-z]+)\)$/.exec(c);
      const col = simple ? simple[1] : fn ? fn[2] : null;
      if (!col) { errors.push(`${c} is outside the subset grammar`); continue; }
      if (!columns.includes(col)) errors.push(`${col} is not a column of ${lines[0]}`);
      if (simple && simple[2] === 'matches regex' && !/^@"(?:[^"]|"")*"$/.test(simple[3])) errors.push(`${c}: a regex literal must be a verbatim @"..." string`);
      if (simple && simple[2] === 'between' && !/^\(\d+ \.\. \d+\)$/.test(simple[3])) errors.push(`${c}: between needs (a .. b)`);
      if (simple && ['==', '!=', '=~'].includes(simple[2]) && !quoted(simple[3])) errors.push(`${c}: the right side must be a quoted string`);
    }
  }
  return errors.length ? fail(...errors) : ok();
}
export function checkCloudwatch(text) {
  const lines = String(text).split('\n').map((l) => l.trim()).filter(Boolean);
  const errors = [];
  if (!/^fields (@?[A-Za-z_]+)(, @?[A-Za-z_]+)*$/.test(lines[0] || '')) errors.push('the first line must be `fields ...`');
  for (const l of lines.slice(1)) {
    const f = /^\| filter @message like \/(.+)\/$/.exec(l);
    // Logs Insights regexes are PCRE-like: `(?i)` is the case flag, which JavaScript cannot compile inline
    if (f) { if (/(?<!\\)\//.test(f[1])) errors.push(`filter regex has an unescaped /: ${f[1]}`); try { new RegExp(f[1].replace(/\\\//g, '/').replace(/^\(\?i\)/, ''), 'i'); } catch { errors.push(`filter: ${f[1]} is not a regular expression`); } continue; }
    if (/^\| sort @?[A-Za-z_]+ (asc|desc)$/.test(l)) continue;
    if (/^\| limit \d+$/.test(l)) continue;
    errors.push(`${l} is outside the subset grammar`);
  }
  return errors.length ? fail(...errors) : ok();
}

// ── JSON shapes this repository owns or vendors ─────────────────────────────────────────────────────────────────────────────────
function closed(obj, allowed, where, errors) {
  for (const k of Object.keys(obj)) if (!allowed.includes(k)) errors.push(`${where}: unknown key ${k}`);
}
export function checkJsonShape(format, text) {
  let doc;
  try { doc = JSON.parse(String(text)); } catch (e) { return fail(`not JSON: ${e.message}`); }
  if (!doc || typeof doc !== 'object') return fail('not a JSON object');
  const errors = [];
  if (format === 'http') {
    closed(doc, ['schema', 'version', 'id', 'findingId', 'level', 'mode', 'request', 'parameter', 'payload', 'limitations'], 'http', errors);
    if (doc.schema !== 'agentic-security/http-detection' || doc.version !== 1) errors.push('schema/version');
    if (doc.mode !== 'detect') errors.push('mode must be detect');
    if (!doc.request || typeof doc.request.method !== 'string' || typeof doc.request.pathTemplate !== 'string') errors.push('request needs method and pathTemplate');
    if (doc.payload?.regex !== undefined && doc.payload.regex !== null) { try { new RegExp(doc.payload.regex, doc.payload.flags || ''); } catch { errors.push('payload.regex is not a regular expression'); } }
  } else if (format === 'log-query') {
    closed(doc, ['schema', 'version', 'id', 'findingId', 'where'], 'log-query', errors);
    if (doc.schema !== 'agentic-security/structured-log-query' || doc.version !== 1) errors.push('schema/version');
    if (!Array.isArray(doc.where) || !doc.where.length) errors.push('where must be a non-empty list');
    for (const w of doc.where || []) {
      closed(w, ['field', 'op', 'value', 'flags'], 'where', errors);
      if (!['eq', 'ne', 'ne-field', 'regex', 'range', 'absent'].includes(w.op)) errors.push(`unknown op ${w.op}`);
      if (w.op === 'ne-field' && !(typeof w.value === 'string' && w.value.trim())) errors.push(`${w.field}: ne-field compares with another field, named by a string`);
      if (w.op === 'ne' && (w.value === null || typeof w.value === 'object')) errors.push(`${w.field}: ne compares with a single value`);
      if (w.op === 'regex') { try { new RegExp(w.value, w.flags || ''); } catch { errors.push(`${w.field}: not a regular expression`); } }
      if (w.op === 'range' && !(Array.isArray(w.value) && w.value.length === 2 && w.value.every(Number.isFinite))) errors.push(`${w.field}: range needs [low, high]`);
    }
  } else if (format === 'elastic') {
    closed(doc, ['query', '_meta'], 'elastic', errors);
    const b = doc.query?.bool;
    if (!b || !Array.isArray(b.filter)) errors.push('query.bool.filter is required');
    for (const c of [...(b?.filter || []), ...(b?.must_not || [])]) {
      const kind = Object.keys(c)[0];
      if (!['term', 'regexp', 'range', 'exists'].includes(kind) || Object.keys(c).length !== 1) errors.push(`clause ${JSON.stringify(c)} is outside the subset`);
      if (kind === 'regexp') for (const v of Object.values(c.regexp)) { if (typeof v.value !== 'string' || /\\[dswDSWbB]/.test(v.value)) errors.push('regexp: Lucene has no \\d \\w \\s \\b classes'); }
    }
  } else if (format === 'datadog') {
    closed(doc, ['name', 'type', 'isEnabled', 'message', 'tags', 'queries', 'cases', 'options'], 'datadog', errors);
    if (doc.type !== 'log_detection') errors.push('type must be log_detection');
    if (doc.isEnabled !== false) errors.push('a generated rule must be disabled until reviewed');
    if (!Array.isArray(doc.queries) || !doc.queries.length || doc.queries.some((q) => typeof q.query !== 'string' || !q.query.trim())) errors.push('queries need a query string');
    if (!Array.isArray(doc.cases) || !doc.cases.every((c) => typeof c.condition === 'string')) errors.push('cases need a condition');
  } else errors.push(`no JSON shape for ${format}`);
  return errors.length ? fail(...errors) : ok();
}

const CHECKS = { sigma: checkSigma, waf: checkModsecChain, yara: checkYara, yaral: checkYaral, spl: checkSpl, kql: checkKql, cloudwatch: checkCloudwatch, http: (t) => checkJsonShape('http', t), 'log-query': (t) => checkJsonShape('log-query', t), elastic: (t) => checkJsonShape('elastic', t), datadog: (t) => checkJsonShape('datadog', t) };

/** @returns {{ok:boolean, errors:string[], target:object}} */
export function checkRendered(format, content) {
  const fn = CHECKS[format];
  if (!fn) return { ok: false, errors: [`no syntax check for ${format}`], target: null };
  const r = fn(content);
  return { ...r, target: SYNTAX_TARGETS[format] };
}
