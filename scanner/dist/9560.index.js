export const id = 9560;
export const ids = [9560,8218,9390,8752];
export const modules = {

/***/ 99405:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {


// EXPORTS
__webpack_require__.d(__webpack_exports__, {
  e: () => (/* binding */ createToolGate)
});

// UNUSED EXPORTS: featureEnabledByOperator

// EXTERNAL MODULE: ./src/posture/assurance/config.js
var config = __webpack_require__(90385);
// EXTERNAL MODULE: ./src/mcp/redact.js
var redact = __webpack_require__(83468);
// EXTERNAL MODULE: ./src/llm-validator/redact.js
var llm_validator_redact = __webpack_require__(65388);
;// CONCATENATED MODULE: ./src/capabilities/secrets.js
// One secret scrubber for the capability layer: provider-shaped credentials
// (mcp/redact.js, which is the list the scanner's own detector mirrors), then
// assignment, bearer, connection-string and high-entropy-literal shapes
// (llm-validator/redact.js). Pure. The count is of replacements made, so a
// caller can ask "did this text carry a secret" without keeping the secret.



/**
 * True when the text carries a provider-shaped credential or a quoted credential
 * assignment. The high-entropy-literal heuristic is deliberately NOT used here:
 * an argument list is mostly paths and scripts, and refusing every long quoted
 * path would make the policy unusable. Scrubbing for output and logs (below) is
 * allowed to be broader than refusing an argument.
 */
function detectSecretShapes(text) {
  return typeof text === 'string' && (0,redact/* redactSecretShapes */.Kb)(text).redactions > 0;
}

function secrets_scrubSecretText(text) {
  if (typeof text !== 'string' || !text) return { text: typeof text === 'string' ? text : '', redactions: 0 };
  const a = (0,redact/* redactSecretShapes */.Kb)(text);
  let b;
  try { b = (0,llm_validator_redact/* redactSecrets */.f)(a.text); } catch { return { text: '[unprintable]', redactions: a.redactions + 1 }; }
  return { text: b.text, redactions: a.redactions + b.redactions };
}

;// CONCATENATED MODULE: ./src/capabilities/reasons.js
// Policy reason codes (X-501.AC03). A decision carries a code from this closed
// table and the fixed sentence beside it, never text built from the request. The
// request (a path, an argument, a host) can carry attacker-chosen content, and a
// decision is logged, put in receipts and shown to a worker, so nothing from the
// request may reach the reason. The only request-derived field of a decision is
// `subject`, which is sanitized and length-capped (`sanitizeSubject`).


const REASONS = Object.freeze({
  allowed: 'the action is inside the declared capability scope',
  'no-grant': 'no capability of this kind is declared for the task',
  'binding-mismatch': 'the request is not bound to this task, repository revision and policy version',
  'unknown-action': 'the action kind is not recognized',
  'invalid-manifest': 'the capability manifest is invalid',
  'scope-expansion': 'the request would widen the capability scope granted by the parent task',
  'path-invalid': 'the path is not an absolute, well-formed path',
  'path-traversal': 'the path escapes the declared roots through parent-directory segments',
  'symlink-escape': 'the path resolves outside the declared roots through a symbolic link',
  'outside-roots': 'the path is outside every declared root',
  'protected-path': 'the path is protected from tasks (keys, sealed labels, evidence, credentials)',
  'executable-not-absolute': 'the executable must be an absolute path; names are not resolved through a search path',
  'executable-unresolvable': 'the executable does not exist or is not a regular executable file',
  'executable-in-writable-root': 'the executable lives in a writable root, so the task could replace it',
  'command-not-listed': 'the executable is not a declared command',
  'args-invalid': 'the argument list is not an array of plain strings within the size limits',
  'args-not-permitted': 'the arguments are not permitted for this declared command',
  'secret-in-argument': 'an argument contains secret material; arguments are visible to every process',
  'interpreter-blocked': 'the executable is a shell or language interpreter and is not declared as a scoped interpreter',
  'interpreter-args-unpinned': 'a scoped interpreter must be declared with its exact argument list',
  'host-invalid': 'the destination host is not a well-formed host name or address',
  'port-invalid': 'the destination port is not valid',
  'destination-not-declared': 'the destination is not a declared network destination',
  'port-not-declared': 'the destination host is declared but not on this port',
  'scheme-not-declared': 'the destination is declared but not for this scheme',
  'dns-private-address': 'the host name resolves to a loopback, private, link-local or metadata address that was not declared',
  'dns-changed': 'the host name resolves to addresses outside the pinned set',
  'payload-too-large': 'the outbound payload exceeds the mediated size limit',
  'payload-uninspectable': 'the outbound payload is binary and cannot be filtered for secrets',
  'tool-not-declared': 'the tool is not a declared tool action',
  'delegation-not-allowed': 'the task is not allowed to delegate',
  'delegation-depth': 'the delegation depth limit is reached',
  'resource-limit-exceeded': 'the request exceeds a declared resource limit',
  'tool-unclassified': 'the tool has no declared capability classification, so it cannot be checked and is refused',
  'identity-missing': 'no current task identity is bound to this server, so a mutating or externally communicating tool is refused',
  'identity-spoofed': 'the request names a task identity other than the one this server is bound to',
  'retry-limit': 'the same action was denied the permitted number of times in this policy version and stays blocked',
  'task-halted': 'the task reached its denial budget and is halted until an operator changes the policy',
});

const REASON_CODES = Object.freeze(Object.keys(REASONS));

function reasonText(code) {
  return Object.prototype.hasOwnProperty.call(REASONS, code) ? REASONS[code] : REASONS['unknown-action'];
}

/**
 * The one request-derived field of a decision. Control characters are removed,
 * secret-shaped material is redacted and the length is capped, so the field is
 * safe to log and to show to the worker that made the request.
 */
function reasons_sanitizeSubject(value, max = 160) {
  let s = typeof value === 'string' ? value : JSON.stringify(value) ?? '';
  s = s.replace(/[\u0000-\u001f\u007f]/g, ' ');
  try { s = secrets_scrubSecretText(s).text; } catch { s = '[unprintable]'; }
  if (s.length > max) s = `${s.slice(0, max)}...`;
  return s || '(empty)';
}

;// CONCATENATED MODULE: ./src/capabilities/tool-registry.js
// The capability classification of every registered MCP tool (X-505.AC01).
//
// A tool that writes, runs a project command or reaches the network must say so,
// and the gate (tool-gate.js) checks what it declares before the handler runs. A
// tool that is not in this table is refused when the gate is active
// (`tool-unclassified`), so adding a tool to the MCP registry without classifying
// it fails closed and fails a test (test/capabilities/tools.test.js compares this
// table with the registry in both directions).
//
//   effect    'read'      reads local state only
//             'mutating'  writes project or agent state, or runs project code
//             'external'  reaches, or may reach, the network through a package
//                         manager or another tool the server process runs
//   requires  the capability checks made before the handler:
//               'tool'               the tool is a declared tool action
//               'write:sessionRoot'  the session root is inside a declared write root
//
// What this table does NOT do: it does not route a tool's own file or network
// activity through the capability runner. A tool runs in the MCP server process;
// the decision is made at the tool boundary, so it is policy (`in-process-policy`),
// never enforced isolation, and the report says so.
const read = (note) => Object.freeze({ effect: 'read', requires: Object.freeze(['tool']), note });
const mutating = (note, extra = []) => Object.freeze({ effect: 'mutating', requires: Object.freeze(['tool', 'write:sessionRoot', ...extra]), note });
const external = (note, extra = []) => Object.freeze({ effect: 'external', requires: Object.freeze(['tool', ...extra]), note });

const TOOL_CAPABILITIES = Object.freeze({
  scan_diff: read('scans files in memory'),
  query_taint: read('reads the last verified scan'),
  explain_finding: read('reads the last verified scan'),
  find_rule_module: read('reads scanner source names'),
  read_scratchpad: read('reads the agent scratchpad'),
  read_agents_memory: read('reads the continual-learning file'),
  lookup_cve: read('reads the local advisory caches'),
  query_triage_memory: read('reads past triage decisions'),
  query_findings_memory: read('reads accumulated scan memory'),
  query_cache_telemetry: read('reads the session transcript statistics'),
  synthesize_fix: read('returns a stored patch'),
  dataflow_get_graph: read('reads the signed graph artifact'),
  dataflow_get_node: read('reads the signed graph artifact'),
  dataflow_get_edge: read('reads the signed graph artifact'),
  dataflow_get_flow: read('reads the signed graph artifact'),
  invariant_scenario_export: read('builds a read-only scenario export from a supplied contract, confined to the session root'),
  portfolio_progress: read('builds a read-only progress view from a portfolio store, ledger and optional inputs, confined to the session root'),
  apply_fix: mutating('writes verified patches into the project'),
  verify_fix: mutating('runs the project linter and tests and appends fix metrics'),
  append_scratchpad: mutating('writes under the agent scratchpad'),
  append_agents_memory: mutating('appends to the continual-learning file'),
  synthesize_sca_upgrade: external('runs a package manager dry-run, which may reach a registry'),
  apply_sca_upgrade: external('runs the package manager and the project tests and rewrites manifests', ['write:sessionRoot']),
});

function toolCapabilityFor(name) {
  return typeof name === 'string' && Object.prototype.hasOwnProperty.call(TOOL_CAPABILITIES, name) ? TOOL_CAPABILITIES[name] : null;
}

/** Tools whose effect is not read-only: the ones that must always be checked. */
function isMutatingOrExternal(name) {
  const c = toolCapabilityFor(name);
  return c ? c.effect !== 'read' : true; // an unclassified tool is treated as the riskiest
}

// EXTERNAL MODULE: external "node:crypto"
var external_node_crypto_ = __webpack_require__(77598);
// EXTERNAL MODULE: ./src/posture/evidence-bundle.js
var evidence_bundle = __webpack_require__(98317);
// EXTERNAL MODULE: ./src/sandbox/trust-domains.js
var trust_domains = __webpack_require__(38832);
// EXTERNAL MODULE: ./src/posture/assurance/identity.js
var identity = __webpack_require__(41877);
// EXTERNAL MODULE: external "node:path"
var external_node_path_ = __webpack_require__(76760);
// EXTERNAL MODULE: ./src/posture/assurance/schema-kit.js
var schema_kit = __webpack_require__(53353);
// EXTERNAL MODULE: external "node:fs"
var external_node_fs_ = __webpack_require__(73024);
;// CONCATENATED MODULE: ./src/capabilities/paths.js
// Path handling for capability decisions (X-502). The OS boundary is what
// actually blocks an access; these helpers only let a policy decision and a
// pre-flight check agree with it about what a path names, including `..`
// segments and symbolic links.



const MAX_PATH = 4096;

/**
 * Lexical form of an absolute path: normalized, no trailing separator.
 * `dotdot` reports whether the caller wrote a parent-directory segment, which
 * is kept so a decision can say "traversal" rather than just "outside".
 */
function lexicalPath(p) {
  if (typeof p !== 'string' || p.length === 0 || p.length > MAX_PATH || p.includes('\0')) return { ok: false };
  if (!external_node_path_.isAbsolute(p)) return { ok: false };
  const dotdot = p.split(external_node_path_.sep).includes('..');
  let n = external_node_path_.normalize(p);
  if (n.length > 1 && n.endsWith(external_node_path_.sep)) n = n.slice(0, -1);
  return { ok: true, path: n, dotdot };
}

/**
 * Canonical form: symbolic links resolved for the longest existing prefix, the
 * not-yet-existing remainder appended lexically. This is what a write to a new
 * file is judged by.
 */
function canonicalPath(p) {
  const lex = lexicalPath(p);
  if (!lex.ok) return null;
  let head = lex.path;
  const tail = [];
  for (let i = 0; i < 4096; i++) {
    try {
      const real = external_node_fs_.realpathSync(head);
      return tail.length ? external_node_path_.join(real, ...tail.reverse()) : real;
    } catch (e) {
      if (e.code !== 'ENOENT' && e.code !== 'ENOTDIR') return null;
      const parent = external_node_path_.dirname(head);
      if (parent === head) return null;
      tail.push(external_node_path_.basename(head));
      head = parent;
    }
  }
  return null;
}

/** `child` equals `root` or lies beneath it. Both must already be normalized. */
function isWithin(child, root) {
  return child === root || child.startsWith(root.endsWith(external_node_path_.sep) ? root : root + external_node_path_.sep);
}

/** True when two normalized paths overlap in either direction. */
function overlaps(a, b) {
  return isWithin(a, b) || isWithin(b, a);
}

// EXTERNAL MODULE: external "node:net"
var external_node_net_ = __webpack_require__(77030);
;// CONCATENATED MODULE: ./src/capabilities/address.js
// Host and address helpers for network policy (X-504). Pure.


const LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

/**
 * Canonical host: lower case, one trailing dot removed, IPv6 brackets removed.
 * Returns `{ ok, host, kind }` with kind `ip4`, `ip6` or `name`. Numeric forms
 * that are not a strict dotted quad (`2130706433`, `0x7f.1`, `127.1`) are
 * rejected, because different parsers read them as different addresses and a
 * policy must not be decided on a reading the connecting stack may not share.
 */
function address_normalizeHost(raw) {
  if (typeof raw !== 'string') return { ok: false };
  let h = raw.trim().toLowerCase();
  if (h.startsWith('[') && h.endsWith(']')) h = h.slice(1, -1);
  if (h.endsWith('.') && h.length > 1) h = h.slice(0, -1);
  if (!h || h.length > 253 || /[^\x21-\x7e]/.test(h)) return { ok: false };
  const family = external_node_net_.isIP(h);
  if (family === 4) return { ok: true, host: h, kind: 'ip4' };
  if (family === 6) return { ok: true, host: h, kind: 'ip6' };
  const labels = h.split('.');
  // A top-level label is never numeric; one that is (or starts 0x) is an address in disguise.
  if (/^(?:0x[0-9a-f]*|[0-9]+)$/.test(labels[labels.length - 1])) return { ok: false };
  if (!labels.every((l) => LABEL.test(l))) return { ok: false };
  return { ok: true, host: h, kind: 'name' };
}

function v4Parts(ip) { return ip.split('.').map(Number); }

function classifyV4(ip) {
  const [a, b] = v4Parts(ip);
  if (ip === '169.254.169.254') return 'metadata';
  if (a === 127) return 'loopback';
  if (a === 0) return 'unspecified';
  if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127)) return 'private';
  if (a === 169 && b === 254) return 'link-local';
  if (a >= 224 && a <= 239) return 'multicast';
  if (a >= 240) return 'reserved';
  return 'public';
}

/**
 * Class of an address: loopback, private, link-local, metadata, unspecified,
 * multicast, reserved or public. IPv4-mapped IPv6 is judged as the IPv4
 * address it carries. Anything that is not an address is `invalid`.
 */
function address_classifyAddress(ip) {
  const family = external_node_net_.isIP(ip);
  if (family === 4) return classifyV4(ip);
  if (family !== 6) return 'invalid';
  const l = ip.toLowerCase();
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(l);
  if (mapped) return classifyV4(mapped[1]);
  const hex = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(l);
  if (hex) {
    const hi = parseInt(hex[1], 16); const lo = parseInt(hex[2], 16);
    return classifyV4(`${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`);
  }
  if (l === '::1') return 'loopback';
  if (l === '::') return 'unspecified';
  if (l.startsWith('fd00:ec2::254')) return 'metadata';
  const first = parseInt(l.split(':')[0] || '0', 16);
  if ((first & 0xfe00) === 0xfc00) return 'private';
  if ((first & 0xffc0) === 0xfe80) return 'link-local';
  if ((first & 0xff00) === 0xff00) return 'multicast';
  return 'public';
}

/** Non-public classes a host name must not resolve to unless declared. */
function isNonPublicClass(cls) {
  return cls !== 'public';
}

;// CONCATENATED MODULE: ./src/capabilities/manifest.js
// Task capability manifests (X-501).
//
// A manifest is the complete statement of what one task may do: readable and
// writable roots, structured commands, network destinations, tool actions,
// resource limits and whether it may delegate. It is
//
//   deny-by-default   a section that is absent grants nothing; there is no
//                     wildcard that means "everything", and no field whose
//                     default is more permissive than its absence
//   closed-world      an unknown field, an unknown schema version, a relative
//                     path, a wildcard host with no domain behind it or a value
//                     of the wrong type invalidates the whole manifest; nothing
//                     is carried through, ignored or defaulted open
//   bound             to a task id, an exact repository revision and a policy
//                     version, carried as `binding` with the manifest digest, so
//                     a grant made for one task, revision or policy version
//                     cannot be replayed for another (decide.js checks it)
//   monotonic         `deriveChild` builds a child manifest only from a subset
//                     of the parent's grants; anything wider is `SCOPE_EXPANSION`
//                     and no child manifest is produced
//
// Pure data except for `deriveChild`, which compares canonical (symlink-resolved)
// paths so a link inside a granted root cannot widen a child.







const MANIFEST_SCHEMA = 'agentic-security/capability-manifest';
const MANIFEST_SCHEMA_VERSION = '1.0.0';
const ARG_MODES = Object.freeze(['exact', 'prefix', 'any']);
const NETWORK_SCHEMES = Object.freeze(['http', 'https']);
const MAX_DELEGATION_DEPTH = 8;

const MANIFEST_ALLOWED = [
  'schema', 'schemaVersion', 'taskId', 'parentTaskId', 'repository', 'policyVersion', 'filesystem', 'commands',
  'network', 'tools', 'resources', 'delegation', 'createdAt',
];
const MANIFEST_REQUIRED = ['schema', 'schemaVersion', 'taskId', 'repository', 'policyVersion'];

// Resource limits a manifest can carry. The first three come straight from the
// assurance config (same ranges), the file-size cap is enforced by the sandbox
// prelude, and the last two are CARRIED but never claimed enforced: see
// `RESOURCE_ENFORCEMENT` in runner.js.
const RESOURCE_RANGES = Object.freeze({
  timeoutMs: { min: config/* LIMITS */.b1.timeoutMs.min, max: config/* LIMITS */.b1.timeoutMs.max },
  maxOutputBytes: { min: config/* LIMITS */.b1.maxOutputBytes.min, max: config/* LIMITS */.b1.maxOutputBytes.max },
  maxFileSizeKb: { min: 1, max: 1_048_576 },
  maxProcesses: { min: 1, max: 4096 },
  maxMemoryMiB: { min: config/* LIMITS */.b1.maxMemoryMiB.min, max: config/* LIMITS */.b1.maxMemoryMiB.max },
});

const TOOL_NAME = /^[A-Za-z0-9_.:-]{1,80}$/;
const MAX_LIST = 256;
const MAX_ARGS = 256;
const MAX_ARG_LEN = 8192;

function checkPathList(ctx, where, list) {
  if (list === undefined) return [];
  if (!Array.isArray(list) || list.length > MAX_LIST) { ctx.err('BAD_TYPE', where, `must be an array of at most ${MAX_LIST} absolute paths`); return []; }
  const out = [];
  list.forEach((p, i) => {
    const lex = lexicalPath(p);
    if (!lex.ok) { ctx.err('BAD_PATH', `${where}[${i}]`, 'must be an absolute path without NUL bytes'); return; }
    if (lex.dotdot) { ctx.err('BAD_PATH', `${where}[${i}]`, 'must not contain parent-directory segments'); return; }
    if (lex.path === external_node_path_.sep) { ctx.err('BAD_PATH', `${where}[${i}]`, 'the filesystem root cannot be granted'); return; }
    out.push(lex.path);
  });
  return [...new Set(out)].sort();
}

function checkCommands(ctx, list) {
  if (list === undefined) return [];
  if (!Array.isArray(list) || list.length > MAX_LIST) { ctx.err('BAD_TYPE', 'commands', `must be an array of at most ${MAX_LIST} entries`); return []; }
  const out = [];
  list.forEach((c, i) => {
    const w = `commands[${i}]`;
    if (!(0,schema_kit/* isPlainObject */.Qd)(c)) { ctx.err('BAD_TYPE', w, 'must be an object'); return; }
    for (const k of Object.keys(c)) if (!['executable', 'args', 'interpreter'].includes(k)) ctx.err('UNKNOWN_FIELD', `${w}.${k}`, 'not part of a command entry');
    const lex = lexicalPath(c.executable);
    if (!lex.ok || lex.dotdot) { ctx.err('BAD_PATH', `${w}.executable`, 'must be an absolute path without parent-directory segments'); return; }
    let args = { mode: 'exact', values: [] };
    if (c.args !== undefined) {
      if (!(0,schema_kit/* isPlainObject */.Qd)(c.args)) { ctx.err('BAD_TYPE', `${w}.args`, 'must be an object {mode, values}'); return; }
      for (const k of Object.keys(c.args)) if (!['mode', 'values'].includes(k)) ctx.err('UNKNOWN_FIELD', `${w}.args.${k}`, 'not part of args');
      if (!ARG_MODES.includes(c.args.mode)) { ctx.err('UNKNOWN_ENUM', `${w}.args.mode`, `must be one of: ${ARG_MODES.join(', ')}`); return; }
      const values = c.args.values === undefined ? [] : c.args.values;
      const okValues = Array.isArray(values) && values.length <= MAX_ARGS
        && values.every((v) => typeof v === 'string' && v.length <= MAX_ARG_LEN && !v.includes('\0'));
      if (!okValues) { ctx.err('BAD_TYPE', `${w}.args.values`, 'must be an array of plain strings within the size limits'); return; }
      if (c.args.mode === 'any' && values.length) { ctx.err('RULE_VIOLATION', `${w}.args.values`, `mode 'any' takes no values`); return; }
      args = { mode: c.args.mode, values: [...values] };
    }
    let interpreter = null;
    if (c.interpreter !== undefined && c.interpreter !== null) {
      if (c.interpreter !== 'scoped') { ctx.err('UNKNOWN_ENUM', `${w}.interpreter`, `must be 'scoped' when present`); return; }
      if (args.mode !== 'exact') { ctx.err('RULE_VIOLATION', `${w}.interpreter`, `a scoped interpreter must pin its exact arguments (mode 'exact')`); return; }
      interpreter = 'scoped';
    }
    out.push({ executable: lex.path, args, interpreter });
  });
  const key = (c) => `${c.executable}\0${c.args.mode}\0${JSON.stringify(c.args.values)}\0${c.interpreter}`;
  const seen = new Map(out.map((c) => [key(c), c]));
  return [...seen.values()].sort((a, b) => (key(a) < key(b) ? -1 : 1));
}

function checkNetwork(ctx, list) {
  if (list === undefined) return [];
  if (!Array.isArray(list) || list.length > MAX_LIST) { ctx.err('BAD_TYPE', 'network', `must be an array of at most ${MAX_LIST} entries`); return []; }
  const out = [];
  list.forEach((d, i) => {
    const w = `network[${i}]`;
    if (!(0,schema_kit/* isPlainObject */.Qd)(d)) { ctx.err('BAD_TYPE', w, 'must be an object'); return; }
    for (const k of Object.keys(d)) if (!['host', 'port', 'schemes', 'allowPrivateResolution', 'addresses'].includes(k)) ctx.err('UNKNOWN_FIELD', `${w}.${k}`, 'not part of a network entry');
    if (typeof d.host !== 'string') { ctx.err('BAD_TYPE', `${w}.host`, 'must be a string'); return; }
    let wildcard = false;
    let hostText = d.host;
    if (hostText.startsWith('*.')) { wildcard = true; hostText = hostText.slice(2); }
    const h = address_normalizeHost(hostText);
    if (!h.ok) { ctx.err('BAD_TYPE', `${w}.host`, 'must be a host name, an IP address or a *.domain wildcard'); return; }
    if (wildcard && (h.kind !== 'name' || h.host.split('.').length < 2)) {
      ctx.err('RULE_VIOLATION', `${w}.host`, 'a wildcard needs a registrable domain behind it (*.example.com), never a bare suffix or an address');
      return;
    }
    if (!Number.isInteger(d.port) || d.port < 1 || d.port > 65535) { ctx.err('BAD_TYPE', `${w}.port`, 'must be an integer from 1 to 65535; wildcard ports do not exist'); return; }
    const schemes = d.schemes === undefined ? ['https'] : d.schemes;
    if (!Array.isArray(schemes) || !schemes.length || !schemes.every((s) => NETWORK_SCHEMES.includes(s))) {
      ctx.err('UNKNOWN_ENUM', `${w}.schemes`, `must be a non-empty subset of: ${NETWORK_SCHEMES.join(', ')}`); return;
    }
    if (d.allowPrivateResolution !== undefined && typeof d.allowPrivateResolution !== 'boolean') { ctx.err('BAD_TYPE', `${w}.allowPrivateResolution`, 'must be a boolean'); return; }
    let addresses = null;
    if (d.addresses !== undefined && d.addresses !== null) {
      const ok = Array.isArray(d.addresses) && d.addresses.length > 0 && d.addresses.length <= 32
        && d.addresses.every((a) => { const n = address_normalizeHost(a); return n.ok && n.kind !== 'name'; });
      if (!ok) { ctx.err('BAD_TYPE', `${w}.addresses`, 'must be a non-empty array of IP addresses'); return; }
      addresses = [...new Set(d.addresses.map((a) => address_normalizeHost(a).host))].sort();
    }
    out.push({
      host: `${wildcard ? '*.' : ''}${h.host}`, port: d.port, schemes: [...new Set(schemes)].sort(),
      allowPrivateResolution: d.allowPrivateResolution === true, addresses,
    });
  });
  const key = (n) => JSON.stringify(n);
  const seen = new Map(out.map((n) => [key(n), n]));
  return [...seen.values()].sort((a, b) => (key(a) < key(b) ? -1 : 1));
}

function checkResources(ctx, r) {
  if (r === undefined) return {};
  if (!(0,schema_kit/* isPlainObject */.Qd)(r)) { ctx.err('BAD_TYPE', 'resources', 'must be an object'); return {}; }
  const out = {};
  for (const [k, v] of Object.entries(r)) {
    const range = RESOURCE_RANGES[k];
    if (!range) { ctx.err('UNKNOWN_FIELD', `resources.${k}`, 'not a known resource limit'); continue; }
    if (!Number.isInteger(v) || v < range.min || v > range.max) { ctx.err('BAD_TYPE', `resources.${k}`, `must be an integer from ${range.min} to ${range.max}`); continue; }
    out[k] = v;
  }
  return out;
}

function checkDelegation(ctx, d) {
  if (d === undefined) return { allow: false, maxDepth: 0 };
  if (!(0,schema_kit/* isPlainObject */.Qd)(d)) { ctx.err('BAD_TYPE', 'delegation', 'must be an object'); return { allow: false, maxDepth: 0 }; }
  for (const k of Object.keys(d)) if (!['allow', 'maxDepth'].includes(k)) ctx.err('UNKNOWN_FIELD', `delegation.${k}`, 'not part of delegation');
  if (typeof d.allow !== 'boolean') { ctx.err('BAD_TYPE', 'delegation.allow', 'must be a boolean'); return { allow: false, maxDepth: 0 }; }
  const maxDepth = d.maxDepth === undefined ? (d.allow ? 1 : 0) : d.maxDepth;
  if (!Number.isInteger(maxDepth) || maxDepth < 0 || maxDepth > MAX_DELEGATION_DEPTH) { ctx.err('BAD_TYPE', 'delegation.maxDepth', `must be an integer from 0 to ${MAX_DELEGATION_DEPTH}`); return { allow: false, maxDepth: 0 }; }
  if (!d.allow && maxDepth !== 0) { ctx.err('RULE_VIOLATION', 'delegation.maxDepth', 'a task that may not delegate has depth 0'); return { allow: false, maxDepth: 0 }; }
  if (d.allow && maxDepth === 0) { ctx.err('RULE_VIOLATION', 'delegation.maxDepth', 'a task that may delegate needs a depth of at least 1'); return { allow: false, maxDepth: 0 }; }
  return { allow: d.allow, maxDepth };
}

/**
 * Validate and normalize a manifest. Returns `{ ok, errors, manifest }`;
 * `manifest` is the frozen normalized form and is present only when `ok`.
 * Never throws.
 */
function manifest_validateManifest(m) {
  const g = (0,schema_kit/* guardObject */.NW)(m);
  const ctx = g.ctx;
  if (!g.ok) return { ...(0,schema_kit/* result */.Ke)(ctx), manifest: null };
  if (!(0,schema_kit/* checkHeader */.eb)(ctx, m, MANIFEST_SCHEMA)) return { ...(0,schema_kit/* result */.Ke)(ctx), manifest: null };
  (0,schema_kit/* checkFields */.oA)(ctx, m, MANIFEST_ALLOWED, MANIFEST_REQUIRED);
  (0,schema_kit/* checkString */.Em)(ctx, 'taskId', m.taskId);
  if (m.parentTaskId !== undefined && m.parentTaskId !== null) (0,schema_kit/* checkString */.Em)(ctx, 'parentTaskId', m.parentTaskId);
  if (!(0,schema_kit/* isPlainObject */.Qd)(m.repository)) ctx.err('BAD_TYPE', 'repository', 'must be an object {revision}');
  else {
    for (const k of Object.keys(m.repository)) if (k !== 'revision') ctx.err('UNKNOWN_FIELD', `repository.${k}`, 'not part of repository');
    (0,schema_kit/* checkCommit */.su)(ctx, 'repository.revision', m.repository.revision ?? null, { nullable: false });
  }
  if (!Number.isInteger(m.policyVersion) || m.policyVersion < 1) ctx.err('BAD_TYPE', 'policyVersion', 'must be a positive integer');

  let fsRead = []; let fsWrite = [];
  if (m.filesystem !== undefined) {
    if (!(0,schema_kit/* isPlainObject */.Qd)(m.filesystem)) ctx.err('BAD_TYPE', 'filesystem', 'must be an object {read, write}');
    else {
      for (const k of Object.keys(m.filesystem)) if (!['read', 'write'].includes(k)) ctx.err('UNKNOWN_FIELD', `filesystem.${k}`, 'not part of filesystem');
      fsRead = checkPathList(ctx, 'filesystem.read', m.filesystem.read);
      fsWrite = checkPathList(ctx, 'filesystem.write', m.filesystem.write);
    }
  }
  const commands = checkCommands(ctx, m.commands);
  const network = checkNetwork(ctx, m.network);
  let tools = [];
  if (m.tools !== undefined) {
    if (!Array.isArray(m.tools) || m.tools.length > MAX_LIST || !m.tools.every((t) => typeof t === 'string' && TOOL_NAME.test(t))) {
      ctx.err('BAD_TYPE', 'tools', `must be an array of tool names (${TOOL_NAME})`);
    } else tools = [...new Set(m.tools)].sort();
  }
  const resources = checkResources(ctx, m.resources);
  const delegation = checkDelegation(ctx, m.delegation);
  if (ctx.errors.length) return { ...(0,schema_kit/* result */.Ke)(ctx), manifest: null };

  const manifest = {
    schema: MANIFEST_SCHEMA, schemaVersion: m.schemaVersion, taskId: m.taskId,
    parentTaskId: m.parentTaskId ?? null,
    repository: { revision: m.repository.revision }, policyVersion: m.policyVersion,
    filesystem: { read: fsRead, write: fsWrite }, commands, network, tools, resources, delegation,
  };
  return { ok: true, errors: [], manifest: deepFreeze(manifest) };
}

function deepFreeze(o) {
  if (o && typeof o === 'object' && !Object.isFrozen(o)) {
    Object.freeze(o);
    for (const v of Object.values(o)) deepFreeze(v);
  }
  return o;
}

/** Digest of the normalized manifest: the policy identity a receipt binds to. */
function manifestDigest(manifest) {
  return digestOf(manifest);
}

/**
 * Validate and bind. The returned object is what every decision and the runner
 * consume: the normalized manifest plus the binding it is valid for.
 */
function manifest_bindManifest(m) {
  const v = manifest_validateManifest(m);
  if (!v.ok) return { ok: false, errors: v.errors, bound: null };
  const bound = {
    manifest: v.manifest,
    binding: Object.freeze({
      taskId: v.manifest.taskId, revision: v.manifest.repository.revision,
      policyVersion: v.manifest.policyVersion, digest: manifestDigest(v.manifest),
    }),
  };
  return { ok: true, errors: [], bound: Object.freeze(bound) };
}

// ---------------------------------------------------------------- inheritance

function canon(p) { return canonicalPath(p) ?? p; }

function rootCovered(child, parentRoots) {
  const c = canon(child);
  return parentRoots.some((r) => {
    const pr = canon(r);
    return isWithin(c, pr) && isWithin(child, r);
  });
}

function hostCovered(child, parent) {
  if (child === parent) return true;
  if (!parent.startsWith('*.')) return false;
  const base = parent.slice(2);
  const c = child.startsWith('*.') ? child.slice(2) : child;
  return c !== base && c.endsWith(`.${base}`);
}

function networkCovered(c, p) {
  if (!hostCovered(c.host, p.host) || c.port !== p.port) return false;
  if (!c.schemes.every((s) => p.schemes.includes(s))) return false;
  if (c.allowPrivateResolution && !p.allowPrivateResolution) return false;
  if (p.addresses) { if (!c.addresses || !c.addresses.every((a) => p.addresses.includes(a))) return false; }
  return true;
}

function commandCovered(c, p) {
  if (canon(c.executable) !== canon(p.executable)) return false;
  if (c.interpreter && !p.interpreter) return false;
  const pv = p.args.values; const cv = c.args.values;
  if (p.args.mode === 'any') return true;
  if (p.args.mode === 'exact') return c.args.mode === 'exact' && cv.length === pv.length && cv.every((v, i) => v === pv[i]);
  // parent prefix
  return c.args.mode !== 'any' && cv.length >= pv.length && pv.every((v, i) => v === cv[i]);
}

/**
 * Build a child task's manifest from a request, only if it is a subset of the
 * parent's. Omitted repository, policy version and resource limits are
 * inherited; anything else that is omitted is simply not granted. Returns
 * `{ ok, errors, manifest }`; on any widening `ok` is false with
 * `SCOPE_EXPANSION` errors and NO manifest, so there is no partial grant.
 *
 * @param {object} parent  a normalized manifest (from `validateManifest`/`bindManifest`)
 * @param {object} request manifest-shaped; `taskId` required
 */
function deriveChild(parent, request) {
  const errors = [];
  const pv = manifest_validateManifest(parent);
  if (!pv.ok) return { ok: false, errors: [{ code: 'RULE_VIOLATION', path: 'parent', message: 'the parent manifest is invalid' }], manifest: null };
  const p = pv.manifest;
  if (!(0,schema_kit/* isPlainObject */.Qd)(request)) return { ok: false, errors: [{ code: 'NOT_AN_OBJECT', path: '', message: 'request must be an object' }], manifest: null };

  const merged = { ...request, schema: MANIFEST_SCHEMA, schemaVersion: request.schemaVersion ?? p.schemaVersion };
  merged.parentTaskId = p.taskId;
  if (request.parentTaskId !== undefined && request.parentTaskId !== null && request.parentTaskId !== p.taskId) {
    errors.push({ code: 'SCOPE_EXPANSION', path: 'parentTaskId', message: 'a child names its actual parent' });
  }
  merged.repository = request.repository ?? { revision: p.repository.revision };
  merged.policyVersion = request.policyVersion ?? p.policyVersion;
  if (merged.repository?.revision !== p.repository.revision) errors.push({ code: 'SCOPE_EXPANSION', path: 'repository.revision', message: 'a child is bound to its parent\'s repository revision' });
  if (merged.policyVersion !== p.policyVersion) errors.push({ code: 'SCOPE_EXPANSION', path: 'policyVersion', message: 'a child is bound to its parent\'s policy version' });
  if (request.taskId === p.taskId) errors.push({ code: 'SCOPE_EXPANSION', path: 'taskId', message: 'a child has its own task id' });
  // Inherit limits the parent set; the child may only lower them.
  merged.resources = { ...(p.resources), ...((0,schema_kit/* isPlainObject */.Qd)(request.resources) ? request.resources : {}) };

  const cv = manifest_validateManifest(merged);
  if (!cv.ok) return { ok: false, errors: [...errors, ...cv.errors], manifest: null };
  const c = cv.manifest;

  const parentReadable = [...p.filesystem.read, ...p.filesystem.write];
  c.filesystem.read.forEach((r, i) => { if (!rootCovered(r, parentReadable)) errors.push({ code: 'SCOPE_EXPANSION', path: `filesystem.read[${i}]`, message: 'not inside a root the parent may read' }); });
  c.filesystem.write.forEach((r, i) => { if (!rootCovered(r, p.filesystem.write)) errors.push({ code: 'SCOPE_EXPANSION', path: `filesystem.write[${i}]`, message: 'not inside a root the parent may write' }); });
  c.commands.forEach((cmd, i) => { if (!p.commands.some((pc) => commandCovered(cmd, pc))) errors.push({ code: 'SCOPE_EXPANSION', path: `commands[${i}]`, message: 'not covered by a command the parent may run' }); });
  c.network.forEach((n, i) => { if (!p.network.some((pn) => networkCovered(n, pn))) errors.push({ code: 'SCOPE_EXPANSION', path: `network[${i}]`, message: 'not covered by a destination the parent may reach' }); });
  c.tools.forEach((t, i) => { if (!p.tools.includes(t)) errors.push({ code: 'SCOPE_EXPANSION', path: `tools[${i}]`, message: 'not a tool the parent may use' }); });
  for (const [k, v] of Object.entries(c.resources)) {
    if (p.resources[k] !== undefined && v > p.resources[k]) errors.push({ code: 'SCOPE_EXPANSION', path: `resources.${k}`, message: 'higher than the parent limit' });
  }
  if (c.delegation.allow) {
    if (!p.delegation.allow) errors.push({ code: 'SCOPE_EXPANSION', path: 'delegation.allow', message: 'the parent may not delegate' });
    else if (c.delegation.maxDepth > p.delegation.maxDepth - 1) errors.push({ code: 'SCOPE_EXPANSION', path: 'delegation.maxDepth', message: 'must be lower than the parent depth' });
  }
  if (errors.length) return { ok: false, errors, manifest: null };
  return { ok: true, errors: [], manifest: c };
}

// EXTERNAL MODULE: ./src/posture/assurance/contracts.js
var contracts = __webpack_require__(49928);
;// CONCATENATED MODULE: ./src/capabilities/decide.js
// Deterministic capability decisions (X-501.AC02, X-501.AC03).
//
// `decide(bound, action, ctx)` answers one question: does this task's bound
// manifest permit this one action? The answer is a frozen
// `{ decision, code, reason, kind, subject, taskId, manifestDigest }`:
//
//   - deny-by-default: the answer is `allow` only when a specific declared grant
//     covers the action; every other path, including every error, is `deny`
//   - deterministic: no clock, no randomness, no environment; the same bound
//     manifest, action and context give the same answer (the filesystem is read
//     only to resolve symbolic links and to look at an executable)
//   - sanitized: `code` comes from the closed table in reasons.js and `reason` is
//     the fixed sentence beside it; the one request-derived field, `subject`, is
//     redacted and length-capped
//   - fail-closed: an unknown action kind, a binding that does not match, an
//     argument list that is not plain strings, a path that cannot be resolved,
//     an interpreter that is not declared as one: all `deny`
//
// This is a POLICY decision. Whether the operating system then actually stops the
// task from doing what the decision denied is the runner's job (runner.js), and
// only the runner may claim enforcement. A hook or an in-process check that calls
// this function explains; it does not enforce.










const decide_MAX_ARGS = 256;
const decide_MAX_ARG_LEN = 8192;

// Executables that run code supplied elsewhere (their arguments, a script file,
// standard input): shells, language runtimes, launchers and build drivers. A
// shell allowlist cannot see through any of them, so each is refused unless the
// manifest declares it as a scoped interpreter with its exact argument list.
const INTERPRETER_NAMES = new Set([
  'sh', 'bash', 'zsh', 'dash', 'ksh', 'csh', 'tcsh', 'fish', 'ash', 'busybox', 'env', 'xargs', 'nice', 'nohup',
  'time', 'timeout', 'sudo', 'doas', 'su', 'ssh', 'osascript', 'launchctl', 'script', 'expect', 'tclsh', 'wish',
  'awk', 'gawk', 'mawk', 'nawk', 'java', 'jshell', 'deno', 'bun', 'nodejs', 'swift', 'make', 'gmake',
  'npm', 'npx', 'yarn', 'pnpm', 'pip', 'pip3', 'pipx', 'gem', 'bundle', 'cargo', 'go', 'gradle', 'mvn', 'watch',
]);
const INTERPRETER_FAMILY = /^(?:python|pypy|ruby|perl|php|lua|luajit|node|tclsh)[0-9.]*$/;

/**
 * What kind of executable this is. `interpreter` is true for a known shell or
 * runtime by name, and for any file that starts with a `#!` line (a script,
 * whatever it is called). A name is a hint, the shebang is the file's own word.
 */
function classifyExecutable(realPath) {
  const base = external_node_path_.basename(realPath).toLowerCase();
  if (INTERPRETER_NAMES.has(base) || INTERPRETER_FAMILY.test(base)) return { interpreter: true, via: 'name' };
  let fd;
  try {
    fd = external_node_fs_.openSync(realPath, 'r');
    const buf = Buffer.alloc(2);
    const n = external_node_fs_.readSync(fd, buf, 0, 2, 0);
    if (n === 2 && buf[0] === 0x23 && buf[1] === 0x21) return { interpreter: true, via: 'shebang' };
  } catch { /* unreadable: handled by the caller's stat check */ } finally {
    if (fd !== undefined) { try { external_node_fs_.closeSync(fd); } catch { /* ignore */ } }
  }
  return { interpreter: false, via: null };
}

function result(bound, action, decision, code, subject) {
  return Object.freeze({
    decision, code, reason: reasonText(code), kind: typeof action?.kind === 'string' ? reasons_sanitizeSubject(action.kind, 40) : 'unknown',
    subject: reasons_sanitizeSubject(subject), taskId: bound?.binding?.taskId ?? null, manifestDigest: bound?.binding?.digest ?? null,
  });
}

function argsDigest(args) {
  return external_node_crypto_.createHash('sha256').update(JSON.stringify(args)).digest('hex').slice(0, 12);
}

// ---------------------------------------------------------------- filesystem

function decideFilesystem(bound, action, ctx) {
  const write = action.kind === 'filesystem-write';
  const subject = typeof action.path === 'string' ? action.path : '(not a string)';
  const lex = lexicalPath(action.path);
  if (!lex.ok) return result(bound, action, 'deny', 'path-invalid', subject);
  // Any parent-directory segment is refused outright. Lexical normalization of
  // `link/..` disagrees with what the kernel does when `link` is a symlink, so
  // a path containing one cannot be judged by its normalized form.
  if (lex.dotdot) return result(bound, action, 'deny', 'path-traversal', subject);
  const real = canonicalPath(lex.path);
  if (!real) return result(bound, action, 'deny', 'path-invalid', subject);

  for (const p of ctx.protectedPaths || []) {
    const pl = lexicalPath(p);
    if (!pl.ok) continue;
    const pr = canonicalPath(pl.path) ?? pl.path;
    if (isWithin(real, pr) || isWithin(lex.path, pl.path)) return result(bound, action, 'deny', 'protected-path', subject);
  }
  const fsGrants = bound.manifest.filesystem;
  const roots = write ? fsGrants.write : [...fsGrants.read, ...fsGrants.write];
  if (!roots.length) return result(bound, action, 'deny', 'no-grant', subject);
  const lexicallyIn = roots.some((r) => isWithin(lex.path, r));
  if (!lexicallyIn) return result(bound, action, 'deny', 'outside-roots', subject);
  const really = roots.some((r) => isWithin(real, canonicalPath(r) ?? r));
  if (!really) return result(bound, action, 'deny', 'symlink-escape', subject);
  return result(bound, action, 'allow', 'allowed', subject);
}

// ---------------------------------------------------------------- commands

function decideCommand(bound, action, ctx) {
  const exe = action.executable;
  const args = action.args === undefined ? [] : action.args;
  const subjectBase = typeof exe === 'string' ? exe : '(not a string)';
  const lexExe = lexicalPath(exe);
  if (!lexExe.ok || lexExe.dotdot) return result(bound, action, 'deny', 'executable-not-absolute', subjectBase);
  if (!Array.isArray(args) || args.length > decide_MAX_ARGS || !args.every((a) => typeof a === 'string' && a.length <= decide_MAX_ARG_LEN && !a.includes('\0'))) {
    return result(bound, action, 'deny', 'args-invalid', `${subjectBase} (malformed arguments)`);
  }
  const subject = `${subjectBase} (${args.length} args, args sha256:${argsDigest(args)})`;

  // Arguments are visible to every process on the host and to every descendant.
  // A secret does not belong in one, whatever command it is handed to.
  const canaries = (ctx.canaries || []).filter((c) => typeof c === 'string' && c.length >= 6);
  for (const a of args) {
    let secret = false;
    try { secret = detectSecretShapes(a); } catch { secret = true; }
    if (secret || canaries.some((c) => a.includes(c))) return result(bound, action, 'deny', 'secret-in-argument', subject);
  }

  let real; let st;
  try { real = external_node_fs_.realpathSync(lexExe.path); st = external_node_fs_.statSync(real); } catch { return result(bound, action, 'deny', 'executable-unresolvable', subject); }
  if (!st.isFile()) return result(bound, action, 'deny', 'executable-unresolvable', subject);
  try { external_node_fs_.accessSync(real, external_node_fs_.constants.X_OK); } catch { return result(bound, action, 'deny', 'executable-unresolvable', subject); }

  for (const w of bound.manifest.filesystem.write) {
    if (isWithin(real, canonicalPath(w) ?? w)) return result(bound, action, 'deny', 'executable-in-writable-root', subject);
  }

  const entries = bound.manifest.commands.filter((c) => (canonicalPath(c.executable) ?? c.executable) === real);
  if (!entries.length) return result(bound, action, 'deny', 'command-not-listed', subject);

  const cls = classifyExecutable(real);
  const matches = (e) => {
    const v = e.args.values;
    if (e.args.mode === 'any') return true;
    if (e.args.mode === 'exact') return v.length === args.length && v.every((x, i) => x === args[i]);
    return args.length >= v.length && v.every((x, i) => x === args[i]);
  };
  const argOk = entries.filter(matches);
  if (!argOk.length) {
    // An interpreter whose entries pin different arguments is the unpinned case.
    if (cls.interpreter && !entries.some((e) => e.interpreter)) return result(bound, action, 'deny', 'interpreter-blocked', subject);
    return result(bound, action, 'deny', 'args-not-permitted', subject);
  }
  if (cls.interpreter) {
    const scoped = argOk.find((e) => e.interpreter === 'scoped');
    if (!scoped) return result(bound, action, 'deny', 'interpreter-blocked', subject);
    if (scoped.args.mode !== 'exact') return result(bound, action, 'deny', 'interpreter-args-unpinned', subject);
  }
  return result(bound, action, 'allow', 'allowed', subject);
}

// ---------------------------------------------------------------- network

function hostMatches(entryHost, host) {
  if (entryHost === host) return true;
  if (!entryHost.startsWith('*.')) return false;
  const base = entryHost.slice(2);
  return host !== base && host.endsWith(`.${base}`);
}

function decideNetwork(bound, action) {
  const h = address_normalizeHost(action.host);
  const subject = typeof action.host === 'string' ? `${action.scheme ?? '?'}://${action.host}:${action.port ?? '?'}` : '(not a string)';
  if (!h.ok) return result(bound, action, 'deny', 'host-invalid', subject);
  if (!Number.isInteger(action.port) || action.port < 1 || action.port > 65535) return result(bound, action, 'deny', 'port-invalid', subject);
  const scheme = action.scheme === undefined ? 'https' : action.scheme;
  if (scheme !== 'http' && scheme !== 'https') return result(bound, action, 'deny', 'scheme-not-declared', subject);
  const onHost = bound.manifest.network.filter((d) => hostMatches(d.host, h.host));
  if (!onHost.length) return result(bound, action, 'deny', 'destination-not-declared', subject);
  const onPort = onHost.filter((d) => d.port === action.port);
  if (!onPort.length) return result(bound, action, 'deny', 'port-not-declared', subject);
  const onScheme = onPort.filter((d) => d.schemes.includes(scheme));
  if (!onScheme.length) return result(bound, action, 'deny', 'scheme-not-declared', subject);

  // Address checks apply to a host NAME once it has been resolved. The caller
  // (the proxy) resolves once, passes the addresses here and connects to those
  // same addresses, so what is checked is what is connected to.
  const resolved = Array.isArray(action.resolvedAddresses) ? action.resolvedAddresses : null;
  if (h.kind === 'name' && resolved) {
    if (!resolved.length) return result(bound, action, 'deny', 'dns-private-address', subject);
    const verdicts = onScheme.map((d) => {
      if (d.addresses && !resolved.every((a) => d.addresses.includes(a))) return 'dns-changed';
      if (!d.allowPrivateResolution && resolved.some((a) => address_classifyAddress(a) !== 'public')) return 'dns-private-address';
      return 'ok';
    });
    if (!verdicts.includes('ok')) return result(bound, action, 'deny', verdicts.includes('dns-changed') ? 'dns-changed' : 'dns-private-address', subject);
  }
  return result(bound, action, 'allow', 'allowed', subject);
}

// ---------------------------------------------------------------- tools, delegation

function decideTool(bound, action) {
  const subject = typeof action.tool === 'string' ? action.tool : '(not a string)';
  if (typeof action.tool !== 'string' || !bound.manifest.tools.includes(action.tool)) return result(bound, action, 'deny', 'tool-not-declared', subject);
  return result(bound, action, 'allow', 'allowed', subject);
}

function decideDelegation(bound, action) {
  const d = bound.manifest.delegation;
  const depth = Number.isInteger(action.depth) && action.depth >= 0 ? action.depth : 0;
  const subject = `delegation at depth ${depth}`;
  if (!d.allow) return result(bound, action, 'deny', 'delegation-not-allowed', subject);
  if (depth >= d.maxDepth) return result(bound, action, 'deny', 'delegation-depth', subject);
  if (action.request !== undefined) {
    const child = deriveChild(bound.manifest, action.request);
    if (!child.ok) return result(bound, action, 'deny', 'scope-expansion', subject);
  }
  return result(bound, action, 'allow', 'allowed', subject);
}

/**
 * @param {{manifest: object, binding: object}} bound   from `bindManifest`
 * @param {object} action  `{ kind, ... }`; kind is one of CAPABILITY_KINDS
 * @param {object} ctx
 * @param {{taskId:string, revision:string, policyVersion:number}} ctx.binding  what the caller believes it is acting for
 * @param {string[]} [ctx.protectedPaths]  paths no task may touch, whatever the manifest says
 * @param {string[]} [ctx.canaries]        values that must never appear in an argument
 */
function decide_decide(bound, action, ctx = {}) {
  if (!bound || !bound.manifest || !bound.binding) return result(bound, action, 'deny', 'invalid-manifest', '(no manifest)');
  const b = ctx.binding;
  const bb = bound.binding;
  if (!b || b.taskId !== bb.taskId || b.revision !== bb.revision || b.policyVersion !== bb.policyVersion) {
    return result(bound, action, 'deny', 'binding-mismatch', '(binding)');
  }
  if (!action || typeof action !== 'object' || Array.isArray(action) || !contracts/* CAPABILITY_KINDS */.bq.includes(action.kind)) {
    return result(bound, action, 'deny', 'unknown-action', typeof action?.kind === 'string' ? action.kind : '(no kind)');
  }
  try {
    switch (action.kind) {
      case 'filesystem-read':
      case 'filesystem-write': return decideFilesystem(bound, action, ctx);
      case 'command': return decideCommand(bound, action, ctx);
      case 'network': return decideNetwork(bound, action);
      case 'tool': return decideTool(bound, action);
      case 'delegation': return decideDelegation(bound, action);
      default: return result(bound, action, 'deny', 'unknown-action', action.kind);
    }
  } catch {
    // A decision never throws. An unexpected failure is a denial.
    return result(bound, action, 'deny', 'invalid-manifest', '(decision failed)');
  }
}

// EXTERNAL MODULE: external "node:http"
var external_node_http_ = __webpack_require__(37067);
// EXTERNAL MODULE: external "node:os"
var external_node_os_ = __webpack_require__(48161);
// EXTERNAL MODULE: ./src/sandbox/capabilities.js
var capabilities = __webpack_require__(60450);
// EXTERNAL MODULE: ./src/sandbox/supervise.js
var supervise = __webpack_require__(74676);
// EXTERNAL MODULE: ./src/sandbox/control-probes.js
var control_probes = __webpack_require__(39899);
// EXTERNAL MODULE: external "node:dns"
var external_node_dns_ = __webpack_require__(40610);
// EXTERNAL MODULE: ./src/egress/audit.js
var audit = __webpack_require__(37355);
;// CONCATENATED MODULE: ./src/capabilities/outbound.js
// Outbound payload filtering and denial records (X-504.AC02, X-504.AC03).
//
// `redactOutbound` is the structured counterpart of egress/redact.js: that module
// redacts prompt TEXT bound for a model endpoint, this one redacts a whole
// request (URL, headers, body) bound for a declared network destination. It
// reuses the same secret detector (`redactSecrets`), then adds what a request has
// that prose does not: credentials in URL userinfo, secret-named query
// parameters and header names, and secret-named keys in JSON and form bodies.
// Exact canary values (and their URL-encoded and base64 forms) are removed
// wherever they appear, which is what the canary fixtures assert.
//
// What it cannot do is look inside an encrypted tunnel. A CONNECT tunnel to a
// declared https destination is opaque to the proxy; the control for that path is
// that the task was never handed a secret to put in it (secret-free environment,
// protected paths, no secrets in arguments), and the capability report says
// `payloadFiltering: plaintext-http-only`.






const PLACEHOLDER = '[REDACTED-SECRET]';
const SECRET_NAME = /(?:^|[^a-z])(?:token|secret|passw(?:or)?d|api[-_]?key|apikey|auth(?:orization)?|credential|private[-_]?key|session|cookie|signature|sig|bearer)(?:[^a-z]|$)/i;
const MAX_DEPTH = 32;

function isSecretName(name) {
  return typeof name === 'string' && SECRET_NAME.test(name);
}

/** The forms in which a canary value could travel: raw, URL-encoded, base64 and its URL-safe variant. */
function canaryForms(canaries) {
  const out = new Set();
  for (const c of canaries || []) {
    if (typeof c !== 'string' || c.length < 6) continue;
    out.add(c);
    out.add(encodeURIComponent(c));
    const b64 = Buffer.from(c, 'utf8').toString('base64');
    out.add(b64);
    out.add(b64.replace(/=+$/, ''));
    out.add(b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''));
  }
  return [...out].filter((x) => x.length >= 6);
}

function scrubText(text, forms, stats) {
  let out = String(text);
  for (const f of forms) {
    if (out.includes(f)) { out = out.split(f).join(PLACEHOLDER); stats.canary += 1; }
  }
  const r = scrubSecretText(out);
  if (r.redactions > 0) { stats.secrets += r.redactions; out = r.text; }
  return out;
}

function walk(value, forms, stats, depth = 0) {
  if (depth > MAX_DEPTH) { stats.truncated = true; return PLACEHOLDER; }
  if (typeof value === 'string') return scrubText(value, forms, stats);
  if (Array.isArray(value)) return value.map((v) => walk(v, forms, stats, depth + 1));
  if (value && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      const key = scrubText(k, forms, stats);
      if (isSecretName(k) && (typeof v === 'string' || typeof v === 'number')) { out[key] = PLACEHOLDER; stats.keys += 1; }
      else out[key] = walk(v, forms, stats, depth + 1);
    }
    return out;
  }
  return value;
}

function scrubParams(params, forms, stats) {
  const out = new URLSearchParams();
  for (const [k, v] of params) {
    if (isSecretName(k) && v !== '') { out.append(scrubText(k, forms, stats), PLACEHOLDER); stats.keys += 1; }
    else out.append(scrubText(k, forms, stats), scrubText(v, forms, stats));
  }
  return out;
}

/**
 * Filter a request before it leaves.
 * @param {{url?: string, headers?: object, body?: string|Buffer|object, contentType?: string}} req
 * @param {{canaries?: string[]}} [opts]
 * @returns {{url: string|null, headers: object, body: string|null, redactions: number,
 *            categories: {userinfo:number, secrets:number, keys:number, canary:number}, uninspectable: boolean}}
 *   `uninspectable` is true for a binary body, which is returned untouched and
 *   must not be sent by a caller that requires filtering.
 */
function outbound_redactOutbound(req = {}, opts = {}) {
  const forms = canaryForms(opts.canaries);
  const stats = { secrets: 0, keys: 0, canary: 0, userinfo: 0, truncated: false };
  let url = null;
  if (typeof req.url === 'string') {
    try {
      const u = new URL(req.url);
      if (u.username || u.password) { stats.userinfo += 1; u.username = ''; u.password = ''; }
      u.search = scrubParams(u.searchParams, forms, stats).toString();
      u.pathname = u.pathname.split('/').map((seg) => scrubText(decodeURIComponent(seg), forms, stats)).map(encodeURIComponent).join('/');
      u.hash = '';
      url = u.toString();
    } catch {
      url = scrubText(req.url.replace(/\/\/[^/@\s]*@/, '//'), forms, stats);
    }
  }
  const headers = {};
  for (const [name, raw] of Object.entries(req.headers || {})) {
    const values = Array.isArray(raw) ? raw : [raw];
    const cleaned = values.map((v) => {
      if (isSecretName(name)) { stats.keys += 1; return PLACEHOLDER; }
      return scrubText(String(v), forms, stats);
    });
    headers[name.toLowerCase()] = Array.isArray(raw) ? cleaned : cleaned[0];
  }
  let body = null;
  let uninspectable = false;
  if (req.body !== undefined && req.body !== null) {
    const ct = String(req.contentType || headers['content-type'] || '').toLowerCase();
    if (Buffer.isBuffer(req.body) && req.body.includes(0)) {
      uninspectable = true; body = req.body;
    } else if (typeof req.body === 'object' && !Buffer.isBuffer(req.body)) {
      body = JSON.stringify(walk(req.body, forms, stats));
    } else {
      const text = Buffer.isBuffer(req.body) ? req.body.toString('utf8') : String(req.body);
      if (ct.includes('json')) {
        try { body = JSON.stringify(walk(JSON.parse(text), forms, stats)); } catch { body = scrubText(text, forms, stats); }
      } else if (ct.includes('x-www-form-urlencoded')) {
        body = scrubParams(new URLSearchParams(text), forms, stats).toString();
      } else body = scrubText(text, forms, stats);
    }
  }
  const categories = { userinfo: stats.userinfo, secrets: stats.secrets, keys: stats.keys, canary: stats.canary };
  return {
    url, headers, body, categories, uninspectable,
    redactions: stats.userinfo + stats.secrets + stats.keys + stats.canary,
  };
}

/** Log-safe text: canary values and secret shapes removed. Never used to build a decision reason. */
function sanitizeLogText(text, canaries = []) {
  let out = typeof text === 'string' ? text : JSON.stringify(text) ?? '';
  for (const f of canaryForms(canaries)) out = out.split(f).join(PLACEHOLDER);
  // Provider-shaped credentials only. The high-entropy-literal heuristic is for
  // payloads, where over-redaction is acceptable; here it would rewrite ordinary
  // quoted paths in a task's output.
  return redactSecretShapes(out).text;
}

// ---------------------------------------------------------------- denial records

/** Class of a destination for the audit trail: an address class, or `hostname`. */
function destinationClass(host) {
  const h = normalizeHost(host);
  if (!h.ok) return 'invalid';
  if (h.kind === 'name') return h.host === 'localhost' || h.host.endsWith('.localhost') ? 'loopback' : 'hostname';
  return classifyAddress(h.host);
}

/**
 * What a denied egress leaves behind: the destination CLASS, a short digest of
 * the host (a host name can itself carry data, so it is never stored), the port,
 * the scheme and the policy code. No path, query, header or body, ever.
 */
function outbound_denialRecord({ taskId, host, port, scheme, code }) {
  const h = normalizeHost(host);
  const digest = crypto.createHash('sha256').update(h.ok ? h.host : String(host)).digest('hex').slice(0, 12);
  return Object.freeze({
    taskId: taskId ?? null, outcome: 'deny', code, destinationClass: destinationClass(host),
    hostDigest: digest, port: Number.isInteger(port) ? port : null, scheme: scheme === 'http' || scheme === 'https' ? scheme : null,
  });
}

/**
 * Append a denial to the existing tamper-evident egress audit chain
 * (egress/audit.js). The chain records provider, purpose, outcome and reason, so
 * the destination class is carried as the provider and the policy code as the
 * reason; nothing else is passed in.
 */
function outbound_recordNetworkDenial(scanRoot, record) {
  if (!scanRoot || !record) return;
  recordEgressCall({
    scanRoot,
    decision: {
      allowed: false, decision: 'deny', reason: record.code, provider: record.destinationClass,
      policySource: 'capability-manifest', purpose: 'capability-network',
    },
    ctx: {},
  });
}

;// CONCATENATED MODULE: ./src/capabilities/proxy.js
// The mediated network boundary (X-504.AC01, X-504.AC03).
//
// The runner starts one of these per task that declares network destinations and
// opens exactly its loopback port in the sandbox profile. Everything else is
// closed by the operating system: DNS, every other loopback port, every remote
// address, every unix socket. A child, a descendant or an interpreter that
// ignores the proxy settings and opens a socket itself is refused by the kernel,
// not by this file; this file decides what the ONE open door lets through.
//
// Per request:
//   1. the destination is checked against the bound manifest (`decide`, kind
//      'network') before any name is resolved
//   2. the name is resolved ONCE, in this process (the sandbox cannot resolve),
//      the resolved addresses are checked (a declared name that resolves to a
//      loopback, private, link-local or metadata address is refused unless the
//      entry says so; a pinned address set must match), and the connection goes to
//      the address that was checked, so a name that changes between check and
//      connect cannot redirect the connection
//   3. plaintext HTTP is buffered (bounded), filtered with `redactOutbound`, and
//      forwarded; a binary body that cannot be inspected is refused
//   4. HTTPS is an opaque CONNECT tunnel, allowed only to a destination declared
//      for the https scheme. Its payload is NOT inspected and the report says so.
//   5. a redirect is returned to the client unchanged and never followed here, so
//      the next hop arrives as a new request and meets step 1 again
//
// A denial records the destination class, a digest of the host, the port and the
// policy code. It never records a path, header, body or the host name itself.







const HOP_BY_HOP = new Set([
  'connection', 'proxy-connection', 'proxy-authorization', 'proxy-authenticate', 'keep-alive', 'te', 'trailer',
  'transfer-encoding', 'upgrade', 'content-length',
]);
const MAX_RECORDS = 1000;

async function defaultResolve(host) {
  const rows = await dns.promises.lookup(host, { all: true });
  return rows.map((r) => r.address);
}

/**
 * @param {object} o
 * @param {{manifest: object, binding: object}} o.bound
 * @param {string[]} [o.canaries]
 * @param {(host:string)=>Promise<string[]>} [o.resolve]   test seam for name resolution
 * @param {number} [o.maxRequestBytes]
 * @param {string} [o.scanRoot]   when set, denials are appended to the egress audit chain
 * @param {number} [o.connectTimeoutMs]
 */
async function proxy_startMediationProxy({
  bound, canaries = [], resolve = defaultResolve, maxRequestBytes = 1024 * 1024, scanRoot = null, connectTimeoutMs = 8000,
}) {
  const records = [];
  const sockets = new Set();
  const stats = { allowed: 0, denied: 0, redactions: 0, bytesForwarded: 0 };
  const ctx = { binding: bound.binding, canaries };

  const note = (outcome, code, host, port, scheme) => {
    const rec = denialRecord({ taskId: bound.binding.taskId, host, port, scheme, code });
    const entry = { ...rec, outcome };
    if (records.length < MAX_RECORDS) records.push(entry);
    if (outcome === 'deny') { stats.denied += 1; recordNetworkDenial(scanRoot, rec); } else stats.allowed += 1;
  };

  // Decide on the declared destination, resolve, decide again on the addresses.
  async function authorize(rawHost, port, scheme) {
    const first = decide(bound, { kind: 'network', host: rawHost, port, scheme }, ctx);
    if (first.decision !== 'allow') return { ok: false, code: first.code };
    const h = normalizeHost(rawHost);
    let addresses;
    if (h.kind === 'name') {
      try { addresses = await resolve(h.host); } catch { addresses = []; }
      if (!Array.isArray(addresses) || !addresses.every((a) => net.isIP(a))) addresses = [];
    } else addresses = [h.host];
    const second = decide(bound, { kind: 'network', host: rawHost, port, scheme, resolvedAddresses: addresses }, ctx);
    if (second.decision !== 'allow') return { ok: false, code: second.code };
    return { ok: true, address: addresses[0], host: h.host };
  }

  function deny(res, code) {
    if (res.headersSent) { res.destroy(); return; }
    const body = JSON.stringify({ blocked: true, code });
    res.writeHead(403, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body), connection: 'close' });
    res.end(body);
  }

  const server = http.createServer((req, res) => {
    handle(req, res).catch(() => deny(res, 'invalid-manifest'));
  });
  server.on('connection', (s) => { sockets.add(s); s.on('close', () => sockets.delete(s)); });
  server.keepAliveTimeout = 1000;

  async function handle(req, res) {
    let target;
    try { target = new URL(req.url); } catch { target = null; }
    if (!target || target.protocol !== 'http:') {
      // An origin-form request is a client talking to the proxy as if it were a
      // server; an https:// absolute URI is a client that skipped CONNECT.
      note('deny', 'destination-not-declared', req.headers.host || '', 0, null);
      return deny(res, 'destination-not-declared');
    }
    const port = target.port ? Number(target.port) : 80;
    const auth = await authorize(target.hostname, port, 'http');
    if (!auth.ok) { note('deny', auth.code, target.hostname, port, 'http'); return deny(res, auth.code); }

    const chunks = []; let size = 0; let tooBig = false;
    await new Promise((done) => {
      req.on('data', (c) => { size += c.length; if (size > maxRequestBytes) { tooBig = true; req.destroy(); done(); } else chunks.push(c); });
      req.on('end', done); req.on('error', done); req.on('close', done);
    });
    if (tooBig) { note('deny', 'payload-too-large', target.hostname, port, 'http'); return deny(res, 'payload-too-large'); }
    const body = chunks.length ? Buffer.concat(chunks) : null;
    const filtered = redactOutbound({ url: req.url, headers: req.headers, body, contentType: req.headers['content-type'] }, { canaries });
    if (filtered.uninspectable) { note('deny', 'payload-uninspectable', target.hostname, port, 'http'); return deny(res, 'payload-uninspectable'); }
    stats.redactions += filtered.redactions;

    const out = {};
    for (const [k, v] of Object.entries(filtered.headers)) if (!HOP_BY_HOP.has(k) && k !== 'host') out[k] = v;
    out.host = target.port ? `${target.hostname}:${target.port}` : target.hostname;
    out.connection = 'close';
    if (filtered.body !== null) out['content-length'] = Buffer.byteLength(filtered.body);
    const fu = new URL(filtered.url);
    const upstream = http.request({
      host: auth.address, port, method: req.method, path: `${fu.pathname}${fu.search}`, headers: out, setHost: false,
      timeout: connectTimeoutMs, agent: false,
    });
    note('allow', 'allowed', target.hostname, port, 'http');
    upstream.on('timeout', () => upstream.destroy(new Error('timeout')));
    upstream.on('error', () => deny(res, 'destination-not-declared'));
    upstream.on('response', (up) => {
      const headers = {};
      for (const [k, v] of Object.entries(up.headers)) if (!HOP_BY_HOP.has(k)) headers[k] = v;
      headers.connection = 'close';
      res.writeHead(up.statusCode || 502, headers);
      up.on('data', (c) => { stats.bytesForwarded += c.length; });
      up.pipe(res);
    });
    if (filtered.body !== null) upstream.write(filtered.body);
    upstream.end();
  }

  server.on('connect', (req, client, head) => {
    sockets.add(client); client.on('close', () => sockets.delete(client));
    client.on('error', () => client.destroy());
    (async () => {
      const m = /^(\[[0-9a-fA-F:.]+\]|[^:\s]+):(\d{1,5})$/.exec(req.url || '');
      if (!m) { note('deny', 'host-invalid', '', 0, 'https'); client.end('HTTP/1.1 403 Forbidden\r\nconnection: close\r\n\r\n'); return; }
      const port = Number(m[2]);
      const auth = await authorize(m[1], port, 'https');
      if (!auth.ok) { note('deny', auth.code, m[1], port, 'https'); client.end('HTTP/1.1 403 Forbidden\r\nconnection: close\r\n\r\n'); return; }
      const upstream = net.connect({ host: auth.address, port, timeout: connectTimeoutMs });
      sockets.add(upstream); upstream.on('close', () => sockets.delete(upstream));
      upstream.on('timeout', () => upstream.destroy());
      upstream.on('error', () => { client.destroy(); });
      client.on('close', () => upstream.destroy());
      upstream.on('connect', () => {
        note('allow', 'allowed', m[1], port, 'https');
        client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        if (head && head.length) upstream.write(head);
        upstream.pipe(client); client.pipe(upstream);
      });
    })().catch(() => client.destroy());
  });

  await new Promise((resolveListen, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolveListen); });
  const port = server.address().port;
  return {
    port,
    url: `http://127.0.0.1:${port}`,
    records,
    stats,
    async close() {
      for (const s of sockets) { try { s.destroy(); } catch { /* ignore */ } }
      await new Promise((r) => server.close(() => r()));
    },
  };
}

;// CONCATENATED MODULE: ./src/capabilities/probes.js
// Active probes for the controls capability enforcement depends on (X-502, X-503,
// X-504), and the platform status that follows from them.
//
// The sandbox already probes write confinement, read denial of named host paths,
// environment scrubbing, the no-network default, tree termination and the
// file-size limit (sandbox/control-probes.js). Capability enforcement needs three
// more, each established the same way: an attack through the real backend that
// must fail, paired with a positive control that must succeed, so a probe that
// cannot succeed cannot pass for a working control.
//
//   fs-read-confinement   a canary outside every declared root is unreadable by
//                         the task, by a descendant, through a symbolic link
//                         planted inside a readable root and through `..`; the
//                         same canary IS readable once its directory is declared
//   fs-multi-root-write   several declared write roots are writable, a read-only
//                         root and an undeclared directory are not
//   network-mediation     a declared destination is reachable through the
//                         mediation proxy, an undeclared one is refused by the
//                         proxy, and a direct socket to either is refused by the
//                         operating system
//
// Nothing here asserts an outcome on a platform it did not run on. On the
// namespace backend (Linux) the new controls are `unsupported`, because that
// backend does not implement them, and the inherited probes run for real where a
// Linux host exists. No state is ever inherited from another platform.













const CAPABILITY_CONTROLS = Object.freeze(['fs-read-confinement', 'fs-multi-root-write', 'network-mediation']);

const NODE = process.execPath;
const ZERO_REV = '0'.repeat(40);
const proved = (evidence) => ({ state: 'proved', evidence });
const notProved = (reason) => ({ state: 'not-proved', reason });
const unsupported = (reason) => ({ state: 'unsupported', reason });

function mk(prefix) { return fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), prefix))); }
function rm(p) { try { fs.rmSync(p, { recursive: true, force: true }); } catch { /* best effort */ } }
const token = (p) => `${p}-${crypto.randomBytes(8).toString('hex')}`;

// `run` is a seam so a test can hand the probe a runner that is deliberately
// wrong (a read root left too wide, a root left writable) and see the probe say
// so: a probe that cannot fail proves nothing.
async function probeFsRead(backend, runner = runConfinedSupervised) {
  if (backend !== 'userspace' && backend !== 'namespace') return unsupported(`read confinement to declared roots is not implemented on the ${backend} backend`);
  const root = mk('agsec-cap-r-'); const ro = mk('agsec-cap-ro-'); const outside = mk('agsec-cap-out-');
  try {
    const okTok = token('READABLE'); const secTok = token('SEALED');
    fs.writeFileSync(path.join(ro, 'r.txt'), okTok);
    fs.writeFileSync(path.join(outside, 's.txt'), secTok);
    fs.symlinkSync(path.join(outside, 's.txt'), path.join(ro, 'link'));
    const run = (script, readRoots) => runner(['/bin/sh', '-c', script], { root, readRoots, timeoutMs: 8000, graceMs: 300 });
    const pos = await run(`cat '${ro}/r.txt'`, [ro]);
    if (!pos.stdout.includes(okTok)) return notProved(`positive control failed: a file inside a declared root was not readable (${pos.status})`);
    const open = await run(`cat '${outside}/s.txt'`, [ro, outside]);
    if (!open.stdout.includes(secTok)) return notProved('positive control failed: the canary was not readable even when its directory was declared');
    const attempts = {
      direct: `cat '${outside}/s.txt'`,
      'symbolic link': `cat '${ro}/link'`,
      traversal: `cat '${ro}/../${path.basename(outside)}/s.txt'`,
      descendant: `sh -c "cat '${outside}/s.txt'"; ( cat '${outside}/s.txt' ) 2>&1`,
    };
    for (const [name, script] of Object.entries(attempts)) {
      const r = await run(`${script}; true`, [ro]);
      if (r.stdout.includes(secTok)) return notProved(`the canary outside every declared root was readable (${name})`);
    }
    return proved('declared roots readable; canary unreadable directly, through a link, through .., and from a descendant; readable once declared');
  } finally { rm(root); rm(ro); rm(outside); }
}

async function probeMultiWrite(backend, runner = runConfinedSupervised) {
  if (backend !== 'userspace' && backend !== 'namespace') return unsupported(`several declared write roots are not implemented on the ${backend} backend`);
  const root = mk('agsec-cap-w-'); const w1 = mk('agsec-cap-w1-'); const w2 = mk('agsec-cap-w2-');
  const ro = mk('agsec-cap-wro-'); const outside = mk('agsec-cap-wout-');
  try {
    const script = [`echo a > '${w1}/f'`, `echo b > '${w2}/f'`, `echo c > '${ro}/f'`, `echo d > '${outside}/f'`, 'true'].join('; ');
    await runner(['/bin/sh', '-c', script], { root, readRoots: [ro], writeRoots: [w1, w2], timeoutMs: 8000, graceMs: 300 });
    if (!fs.existsSync(path.join(w1, 'f')) || !fs.existsSync(path.join(w2, 'f'))) return notProved('positive control failed: a declared write root was not writable');
    if (fs.existsSync(path.join(ro, 'f'))) return notProved('a root declared read-only was writable');
    if (fs.existsSync(path.join(outside, 'f'))) return notProved('an undeclared directory was writable');
    return proved('both declared write roots writable; the read-only root and an undeclared directory were not');
  } finally { rm(root); rm(w1); rm(w2); rm(ro); rm(outside); }
}

function listener(label) {
  const state = { connections: 0 };
  const server = http.createServer((req, res) => { res.writeHead(200, { 'content-type': 'text/plain' }); res.end(label); });
  server.on('connection', () => { state.connections += 1; });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve({ server, state, port: server.address().port }));
  });
}

async function probeNetworkMediation(backend) {
  if (backend !== 'userspace') return unsupported(`mediated network access is not implemented on the ${backend} backend (its network namespace has no path to a proxy)`);
  const root = mk('agsec-cap-n-');
  let a; let b; let proxy;
  try {
    a = await listener('A'); b = await listener('B');
    const built = bindManifest({
      schema: 'agentic-security/capability-manifest', schemaVersion: '1.0.0', taskId: 'probe-network', repository: { revision: ZERO_REV }, policyVersion: 1,
      network: [{ host: '127.0.0.1', port: a.port, schemes: ['http'] }],
    });
    if (!built.ok) return notProved('probe manifest was invalid');
    proxy = await startMediationProxy({ bound: built.bound });
    const script = `
const http=require('http'),net=require('net');
const via=(p)=>new Promise(r=>{const q=http.request({host:'127.0.0.1',port:${proxy.port},method:'GET',path:'http://127.0.0.1:'+p+'/',headers:{host:'127.0.0.1:'+p},agent:false},res=>{let b='';res.on('data',d=>b+=d);res.on('end',()=>r({s:res.statusCode,b}))});q.on('error',e=>r({e:e.code}));q.setTimeout(4000,()=>q.destroy());q.end()});
const direct=(p)=>new Promise(r=>{const s=net.connect(p,'127.0.0.1');s.on('connect',()=>{s.destroy();r({connected:true})});s.on('error',e=>r({e:e.code}));setTimeout(()=>r({e:'TIMEOUT'}),2500)});
(async()=>{console.log(JSON.stringify({pa:await via(${a.port}),pb:await via(${b.port}),da:await direct(${a.port}),db:await direct(${b.port})}))})();`;
    const r = await runConfinedSupervised([NODE, '-e', script], {
      root, readRoots: [NODE], networkProxyPort: proxy.port, timeoutMs: 15000, graceMs: 300,
    });
    let out;
    try { out = JSON.parse(String(r.stdout).trim().split('\n').pop()); } catch { return notProved(`positive control failed: the probe client did not report (${r.status})`); }
    if (!(out.pa && out.pa.s === 200 && out.pa.b === 'A')) return notProved('positive control failed: a declared destination was not reachable through the proxy');
    if (!(out.pb && out.pb.s === 403)) return notProved('an undeclared destination was not refused by the proxy');
    if (out.da?.connected || out.db?.connected) return notProved('a direct socket bypassed the proxy');
    if (b.state.connections !== 0) return notProved('the undeclared listener saw a connection');
    if (a.state.connections !== 1) return notProved(`the declared listener saw ${a.state.connections} connections; only the proxied request should have arrived`);
    return proved('declared destination reachable only through the proxy; undeclared refused by the proxy; direct sockets refused by the operating system');
  } finally {
    if (proxy) await proxy.close();
    for (const l of [a, b]) if (l) await new Promise((res) => l.server.close(() => res()));
    rm(root);
  }
}

const _cache = new Map();
function resetCapabilityProbeCache() { _cache.clear(); }

async function measure(backend, force) {
  const base = await probeControls({ force });
  const controls = { ...base.controls };
  if (backend === 'disabled') {
    for (const c of CAPABILITY_CONTROLS) controls[c] = { state: 'unavailable', reason: 'no confinement backend works on this host' };
  } else {
    const run = async (name, fn) => {
      try { controls[name] = await fn(); } catch (e) { controls[name] = notProved(`probe threw: ${String(e.message).split('\n')[0]}`); }
    };
    await run('fs-read-confinement', () => probeFsRead(backend));
    await run('fs-multi-root-write', () => probeMultiWrite(backend));
    await run('network-mediation', () => probeNetworkMediation(backend));
  }
  return controls;
}

/**
 * Probe every control capability enforcement uses, on the active backend.
 * @param {object} [o]
 * @param {string} [o.force]   backend override (same meaning as runConfined's)
 * @param {object} [o.probes]  per-control overrides (test seam). An override can only
 *                             be used to make a control LESS proved in a test; a run
 *                             still goes through the real backend.
 */
async function probes_probeCapabilityControls({ force, probes = {} } = {}) {
  const backend = detectBackend({ force });
  if (!_cache.has(backend)) _cache.set(backend, await measure(backend, force));
  const controls = { ..._cache.get(backend) };
  // Overrides replace one control's result after the real measurement; the run
  // itself still goes through the real backend.
  for (const [name, fn] of Object.entries(probes)) controls[name] = await fn();
  const states = Object.fromEntries(Object.entries(controls).sort().map(([k, v]) => [k, v.state]));
  return {
    platform: process.platform, backend, controls,
    probeDigest: digestOf({ platform: process.platform, backend, states }),
  };
}

/** Controls this manifest actually depends on; a control it never uses cannot block it. */
function probes_requiredControlsFor(manifest) {
  const req = ['write-confinement', 'read-denial', 'fs-read-confinement', 'fs-multi-root-write', 'env-scrub', 'tree-termination', 'file-size-limit', 'network'];
  if (manifest.network.length) req.push('network-mediation');
  return req;
}

/**
 * Whether this platform and backend are one the product ADVERTISES for enforced
 * mode. Taken from the feature table in the assurance config (Linux only), and
 * the only advertised backend is the kernel-namespace one. The macOS userspace
 * backend can be proved on a host by the probes above, and is still not
 * advertised: it is development-host evidence, not an enforced backend.
 */
function isAdvertisedBackend(backend, platform = process.platform) {
  return FEATURES['capability-enforcement'].platforms.includes(platform) && backend === 'namespace';
}

/** Standing platform statements. Nothing here is measured; it states what has and has not been evidenced. */
function platformStatements() {
  return Object.freeze({
    linux: {
      backend: 'namespace', status: 'partially-verified',
      // Evidence is the hosted sandbox-linux CI job (ubuntu-latest, x86_64), whose active probes
      // (attack plus positive control, with fault-injection counterparts) proved these controls.
      // Anything not listed here is not claimed: a verified control is verified on that runner image
      // and kernel, not on every Linux host, which is why the job runs on every push.
      evidence: 'sandbox-linux CI job (hosted ubuntu-latest, x86_64); scripts/sandbox-linux-verify.mjs',
      verifiedControls: Object.freeze([
        'write-confinement', 'read-denial', 'env-scrub', 'network', 'tree-termination', 'file-size-limit',
        'fs-read-confinement', 'fs-multi-root-write',
      ]),
      unsupportedControls: Object.freeze(['network-mediation']),
      unassertedControls: Object.freeze(['process-cap']),
      note: 'advertised for enforced mode. Proved by active probes on the hosted Linux runner (not on every Linux host): write-confinement, read-denial, env-scrub, network, tree-termination, file-size-limit, fs-read-confinement, fs-multi-root-write. Mediated network is NOT implemented on the namespace backend (an empty network namespace has no path to a proxy), so a task that declares a network destination is blocked on Linux, never allowed. Process-count caps are never claimed: the cause of the earlier non-refusal was found (the shell used for the resource prelude has no process-limit option, so the cap was never applied) and no replacement has been proved. The attack corpus is not run in the sandbox-linux job, so corpus coverage stays unverified on Linux.',
    },
    darwin: {
      backend: 'userspace', status: 'host-proved-not-advertised',
      note: 'the active probes can prove the controls on a macOS host, and tasks can run there for development only when the caller opts in; macOS is not an advertised enforced backend.',
    },
    win32: { backend: null, status: 'unsupported', note: 'no isolation backend exists on Windows.' },
  });
}



;// CONCATENATED MODULE: ./src/capabilities/recovery.js
// Explicit policy recovery (X-506).
//
// A denied task does not talk its way out of a denial and does not retry until
// something gives. The only way a denial turns into a permission is a policy
// change that
//
//   is OPERATOR-ONLY   the grant is an Ed25519 signature over the exact change;
//                      the signing key lives in the signer domain, which a worker
//                      cannot read (sandbox/trust-domains.js, the protected key
//                      directory), so a worker cannot mint one and a forged
//                      signature fails verification
//   is BOUND           the signature covers the digest of the manifest it
//                      changes AND the digest of the manifest it produces, the
//                      task and both policy versions, so it is not a blank
//                      cheque and cannot be replayed on another task or version
//   is BOUNDED         a short validity window, a single use (nonce), and a
//                      finite number of changes per task
//   is RECORDED        every applied change is an entry in a hash-chained ledger
//   creates a NEW VERSION  the policy version rises by one. Every earlier binding
//                      is then stale (`binding-mismatch`) and every receipt for
//                      the earlier digest is superseded (receipts.js)
//
// A denial itself returns `blocked`, the missing capability and a proposed
// manifest change for a human to review (`proposeChange`). The proposal is data:
// applying it needs the operator grant above. Repeated denials of one action hit
// a finite limit and stay blocked (`createDenialGuard`); no path in this module
// turns a denial into an allow, falls back to unrestricted execution or loops.












const GRANT_SCHEMA = 'agentic-security/policy-grant';
const LEDGER_SCHEMA = 'agentic-security/policy-ledger';
const DEFAULT_RETRY_LIMIT = 3;
const MAX_RETRY_LIMIT = 10;
const DEFAULT_TASK_DENIAL_BUDGET = 20;
const MAX_TASK_DENIAL_BUDGET = 100;
const MAX_GRANT_TTL_MS = (/* unused pure expression or super */ null && (60 * 60 * 1000));
const DEFAULT_MAX_CHANGES = 5;
const MAX_TRACKED = 1000;
const GENESIS = '0'.repeat(64);

const sha = (v) => external_node_crypto_.createHash('sha256').update(typeof v === 'string' ? v : (0,evidence_bundle/* canonicalJson */.dj)(v)).digest('hex');
const clean = (s) => typeof s === 'string' && !/[\u0000-\u001f\u007f]/.test(s) && !detectSecretShapes(s);

// ---------------------------------------------------------------- proposals

// Codes that name a structural refusal. A proposal for any of these would be an
// invitation to widen the boundary around keys, labels, links and secrets.
const NOT_PROPOSABLE = new Set([
  'binding-mismatch', 'unknown-action', 'invalid-manifest', 'scope-expansion', 'path-invalid', 'path-traversal',
  'symlink-escape', 'protected-path', 'executable-not-absolute', 'executable-unresolvable', 'executable-in-writable-root',
  'args-invalid', 'secret-in-argument', 'host-invalid', 'port-invalid', 'dns-private-address', 'dns-changed',
  'payload-too-large', 'payload-uninspectable', 'resource-limit-exceeded', 'retry-limit', 'task-halted', 'identity-spoofed',
  'identity-missing', 'tool-unclassified', 'allowed', 'delegation-depth',
]);

function unproposable(decision, why) {
  return Object.freeze({
    proposable: false, why, missing: Object.freeze({ capability: decision.kind, code: decision.code, detail: decision.subject }),
    selfGrantable: false, requiresOperatorGrant: true, change: null,
  });
}

/**
 * The missing capability and a reviewable manifest change for one denial. The
 * change is the NARROWEST addition that would allow exactly this action (an exact
 * path, an exact argument array, one host and port). It is a proposal: a worker
 * can read it and cannot apply it.
 */
function proposeChange(bound, action, decision) {
  const base = { kind: decision?.kind ?? 'unknown', code: decision?.code ?? 'unknown-action', subject: decision?.subject ?? '' };
  if (!decision || decision.decision === 'allow') return unproposable({ ...base, code: 'allowed' }, 'the action was allowed; there is nothing to propose');
  if (NOT_PROPOSABLE.has(decision.code)) return unproposable(decision, `${reasonText(decision.code)}; no manifest change is proposed for this refusal`);
  let add = null; let risk = 'scope-addition';
  const a = action || {};
  switch (a.kind) {
    case 'filesystem-read':
    case 'filesystem-write':
      if (typeof a.path === 'string' && clean(a.path)) add = { filesystem: { [a.kind === 'filesystem-write' ? 'write' : 'read']: [a.path] } };
      break;
    case 'command':
      if (typeof a.executable === 'string' && clean(a.executable) && (a.args ?? []).every((x) => typeof x === 'string' && clean(x))) {
        const entry = { executable: a.executable, args: { mode: 'exact', values: [...(a.args ?? [])] } };
        if (decision.code === 'interpreter-blocked' || decision.code === 'interpreter-args-unpinned') { entry.interpreter = 'scoped'; risk = 'interpreter'; }
        add = { commands: [entry] };
      }
      break;
    case 'network':
      // A literal loopback, private, link-local or metadata address is never offered as a destination.
      if (typeof a.host === 'string' && clean(a.host) && Number.isInteger(a.port) && (() => {
        const h = address_normalizeHost(a.host);
        return h.ok && (h.kind === 'name' || address_classifyAddress(h.host) === 'public');
      })()) {
        add = { network: [{ host: a.host, port: a.port, schemes: [a.scheme === 'http' ? 'http' : 'https'] }] };
      }
      break;
    case 'tool':
      // Only a tool this build knows can be proposed; an unknown name is not a capability.
      if (typeof a.tool === 'string' && toolCapabilityFor(a.tool)) add = { tools: [a.tool] };
      break;
    case 'delegation':
      if (decision.code === 'delegation-not-allowed') add = { delegation: { allow: true, maxDepth: 1 } };
      break;
    default: break;
  }
  if (!add) return unproposable(decision, 'the request cannot be turned into a safe manifest addition');
  const change = Object.freeze({ add });
  return Object.freeze({
    proposable: true, why: null, risk,
    missing: Object.freeze({ capability: decision.kind, code: decision.code, detail: decision.subject }),
    selfGrantable: false, requiresOperatorGrant: true,
    nextPolicyVersion: bound.binding.policyVersion + 1,
    change, changeDigest: (0,identity/* digestOf */.ol)(change),
    review: `Add to task ${reasons_sanitizeSubject(bound.binding.taskId, 80)} at policy version ${bound.binding.policyVersion + 1}: ${reasons_sanitizeSubject(JSON.stringify(add), 300)}`,
  });
}

// ---------------------------------------------------------------- denial guard

function actionKey(binding, action) {
  const a = action && typeof action === 'object' ? action : {};
  const material = { kind: a.kind ?? null, path: a.path ?? null, executable: a.executable ?? null, args: Array.isArray(a.args) ? a.args : null, host: a.host ?? null, port: a.port ?? null, scheme: a.scheme ?? null, tool: a.tool ?? null };
  return sha({ taskId: binding?.taskId ?? null, policyVersion: binding?.policyVersion ?? null, material });
}

/**
 * Bounded denial handling. `admit` is asked BEFORE the policy is evaluated; once
 * an action has been denied `retryLimit` times in one policy version, or the task
 * has been denied `taskBudget` times in all, the answer is a fixed refusal and the
 * action is not even evaluated again. A new policy version starts a new count (the
 * operator changed something, so a retry is no longer the same request).
 */
function createDenialGuard({ retryLimit = DEFAULT_RETRY_LIMIT, taskBudget = DEFAULT_TASK_DENIAL_BUDGET } = {}) {
  const rl = Number.isInteger(retryLimit) && retryLimit >= 1 ? Math.min(retryLimit, MAX_RETRY_LIMIT) : DEFAULT_RETRY_LIMIT;
  const tb = Number.isInteger(taskBudget) && taskBudget >= 1 ? Math.min(taskBudget, MAX_TASK_DENIAL_BUDGET) : DEFAULT_TASK_DENIAL_BUDGET;
  const perAction = new Map();
  const perTask = new Map();
  const taskKey = (b) => `${b?.taskId ?? 'unbound'}@${b?.policyVersion ?? 0}`;
  return Object.freeze({
    retryLimit: rl, taskBudget: tb,
    admit(binding, action) {
      const t = perTask.get(taskKey(binding)) ?? 0;
      if (t >= tb || perAction.size >= MAX_TRACKED) return { admit: false, code: 'task-halted' };
      if ((perAction.get(actionKey(binding, action)) ?? 0) >= rl) return { admit: false, code: 'retry-limit' };
      return { admit: true, code: null };
    },
    record(binding, action) {
      const k = actionKey(binding, action);
      const n = (perAction.get(k) ?? 0) + 1;
      perAction.set(k, n);
      perTask.set(taskKey(binding), (perTask.get(taskKey(binding)) ?? 0) + 1);
      return { attempts: n, remaining: Math.max(0, rl - n), exhausted: n >= rl };
    },
    stats(binding) { return { taskDenials: perTask.get(taskKey(binding)) ?? 0, trackedActions: perAction.size }; },
  });
}

/**
 * One mediated decision with recovery semantics. The result is either the policy
 * allowing the action, or `blocked`; there is no third outcome, no retry inside
 * this function and no fallback.
 */
function mediate(bound, action, ctx, { guard } = {}) {
  const binding = ctx?.binding;
  if (guard) {
    const adm = guard.admit(binding, action);
    if (!adm.admit) {
      const decision = Object.freeze({
        decision: 'deny', code: adm.code, reason: reasonText(adm.code), kind: typeof action?.kind === 'string' ? reasons_sanitizeSubject(action.kind, 40) : 'unknown',
        subject: '(action not re-evaluated)', taskId: bound?.binding?.taskId ?? null, manifestDigest: bound?.binding?.digest ?? null,
      });
      return Object.freeze({ status: 'blocked', blocked: true, decision, ...proposalFields(unproposable(decision, reasonText(adm.code))), attemptsRemaining: 0, exhausted: true });
    }
  }
  const decision = decide_decide(bound, action, ctx);
  if (decision.decision === 'allow') return Object.freeze({ status: 'ok', blocked: false, decision, proposal: null, missing: null, attemptsRemaining: null, exhausted: false });
  const counted = guard ? guard.record(binding, action) : null;
  const proposal = counted?.exhausted ? unproposable(decision, `${reasonText('retry-limit')}`) : proposeChange(bound, action, decision);
  return Object.freeze({
    status: 'blocked', blocked: true, decision, ...proposalFields(proposal),
    attemptsRemaining: counted ? counted.remaining : null, exhausted: counted ? counted.exhausted : false,
  });
}

function proposalFields(p) { return { proposal: p, missing: p.missing }; }

// ---------------------------------------------------------------- operator grants

function assertSigner(domain) {
  if (!mayDo(domain, RESOURCES.SIGNING_KEY, 'read')) {
    throw Object.assign(new Error(`the ${String(domain)} domain may not sign a policy grant`), { code: 'domain-denied' });
  }
}

const ADD_KEYS = (/* unused pure expression or super */ null && (['filesystem', 'commands', 'network', 'tools', 'delegation']));

/** Apply an add-only change to a normalized manifest; the result is validated and bound at the next policy version. */
function applyChangeToManifest(manifest, change) {
  if (!change || typeof change !== 'object' || Array.isArray(change) || Object.keys(change).some((k) => k !== 'add')) return { ok: false, code: 'change-invalid', bound: null };
  const add = change.add;
  if (!add || typeof add !== 'object' || Array.isArray(add) || Object.keys(add).length === 0 || Object.keys(add).some((k) => !ADD_KEYS.includes(k))) return { ok: false, code: 'change-invalid', bound: null };
  const next = JSON.parse(JSON.stringify(manifest));
  next.policyVersion = manifest.policyVersion + 1;
  if (add.filesystem) {
    if (typeof add.filesystem !== 'object' || Object.keys(add.filesystem).some((k) => !['read', 'write'].includes(k))) return { ok: false, code: 'change-invalid', bound: null };
    next.filesystem.read = [...next.filesystem.read, ...(add.filesystem.read ?? [])];
    next.filesystem.write = [...next.filesystem.write, ...(add.filesystem.write ?? [])];
  }
  if (add.commands) next.commands = [...next.commands, ...add.commands];
  if (add.network) next.network = [...next.network, ...add.network];
  if (add.tools) next.tools = [...next.tools, ...add.tools];
  if (add.delegation) next.delegation = add.delegation;
  const b = bindManifest(next);
  return b.ok ? { ok: true, code: null, bound: b.bound } : { ok: false, code: 'change-invalid', bound: null, errors: b.errors };
}

/**
 * Operator side. Signs a grant for ONE change to ONE manifest. Refuses unless the
 * caller declares the signer domain; a worker or target cannot sign (and in any
 * case does not hold the key).
 */
function signPolicyGrant({ domain, privateKeyPem, bound, change, operator, reason, now = new Date(), ttlMs = 15 * 60 * 1000, nonce }) {
  assertSigner(domain);
  const applied = applyChangeToManifest(bound.manifest, change);
  if (!applied.ok) throw Object.assign(new Error('the change is not a valid add-only manifest change'), { code: applied.code });
  const ttl = Math.min(Math.max(1, ttlMs), MAX_GRANT_TTL_MS);
  const payload = {
    schema: GRANT_SCHEMA, taskId: bound.binding.taskId,
    fromPolicyVersion: bound.binding.policyVersion, fromDigest: bound.binding.digest,
    toPolicyVersion: applied.bound.binding.policyVersion, toDigest: applied.bound.binding.digest,
    operator: sanitizeSubject(operator, 80), reason: sanitizeSubject(reason, 200),
    issuedAt: now.toISOString(), expiresAt: new Date(now.getTime() + ttl).toISOString(),
    nonce: nonce ?? crypto.randomBytes(12).toString('hex'),
  };
  const publicKeyPem = crypto.createPublicKey(privateKeyPem).export({ type: 'spki', format: 'pem' });
  const issuance = {
    issuer: { id: `local-install:${keyFingerprint(publicKeyPem).slice(0, 16)}`, kind: 'local-install', keyFingerprint: keyFingerprint(publicKeyPem) },
    trustBasis: 'self-issued-local-key', independentlyCertified: false, statement: TRUST_BASES['self-issued-local-key'].statement,
  };
  const sig = crypto.sign(null, Buffer.from(canonicalJson({ payload, issuance }), 'utf8'), privateKeyPem);
  return Object.freeze({ payload, issuance, signature: { algorithm: 'ed25519', value: sig.toString('base64') } });
}

function verifyGrant(grant, publicKeyPem) {
  if (!grant || typeof grant !== 'object' || !grant.payload || !grant.signature || grant.payload.schema !== GRANT_SCHEMA) return { ok: false, code: 'grant-invalid' };
  if (Object.keys(grant).some((k) => !['payload', 'issuance', 'signature'].includes(k))) return { ok: false, code: 'grant-invalid' };
  if (grant.signature.algorithm !== 'ed25519' || typeof grant.signature.value !== 'string') return { ok: false, code: 'grant-invalid' };
  if (!publicKeyPem) return { ok: false, code: 'grant-unsigned' };
  let ok = false;
  try { ok = crypto.verify(null, Buffer.from(canonicalJson({ payload: grant.payload, issuance: grant.issuance }), 'utf8'), publicKeyPem, Buffer.from(grant.signature.value, 'base64')); } catch { ok = false; }
  if (!ok) return { ok: false, code: 'grant-signature-invalid' };
  const iss = grant.issuance;
  if (!iss || !TRUST_BASES[iss.trustBasis] || iss.independentlyCertified !== false || iss.issuer?.keyFingerprint !== keyFingerprint(publicKeyPem)) return { ok: false, code: 'grant-issuer-invalid' };
  return { ok: true, code: null };
}

// ---------------------------------------------------------------- ledger

/** A hash-chained record of every applied policy change. Held by the controller, never by a worker. */
function createPolicyLedger({ maxChanges = DEFAULT_MAX_CHANGES } = {}) {
  const max = Number.isInteger(maxChanges) && maxChanges >= 1 ? Math.min(maxChanges, 50) : DEFAULT_MAX_CHANGES;
  const entries = [];
  const nonces = new Set();
  const current = new Map(); // taskId -> {policyVersion, digest}
  const head = () => (entries.length ? entries[entries.length - 1].hash : GENESIS);
  return {
    maxChanges: max,
    entries: () => entries.map((e) => ({ ...e })),
    changesFor: (taskId) => entries.filter((e) => e.taskId === taskId).length,
    nonceUsed: (n) => nonces.has(n),
    /** Seed the current policy of a task (the first bound manifest). */
    register(bound) { if (!current.has(bound.binding.taskId)) current.set(bound.binding.taskId, { policyVersion: bound.binding.policyVersion, digest: bound.binding.digest }); },
    current: (taskId) => current.get(taskId) ?? null,
    isCurrent: (binding) => { const c = current.get(binding?.taskId); return !!c && c.policyVersion === binding.policyVersion && c.digest === binding.digest; },
    append(entry) {
      const body = { seq: entries.length, prev: head(), ...entry };
      const full = { ...body, hash: sha(body) };
      entries.push(Object.freeze(full));
      nonces.add(entry.nonce);
      current.set(entry.taskId, { policyVersion: entry.toPolicyVersion, digest: entry.toDigest });
      return full;
    },
    verify() { return verifyLedgerEntries(entries); },
  };
}

function verifyLedgerEntries(list) {
  let prev = GENESIS;
  for (let i = 0; i < list.length; i++) {
    const { hash, ...body } = list[i];
    if (body.seq !== i || body.prev !== prev || sha(body) !== hash) return { ok: false, breakAt: i };
    prev = hash;
  }
  return { ok: true, breakAt: null, head: prev };
}

// ---------------------------------------------------------------- applying a grant

/**
 * Apply an operator grant to a task's policy. Returns the NEW bound manifest (a
 * new policy version), the ledger entry and the re-run preflight. On any refusal
 * `ok` is false, `bound` is null and the old policy is untouched.
 *
 * @param {object} o
 * @param {{manifest:object,binding:object}} o.bound   the current policy
 * @param {object} o.change                            the proposed `{add}`
 * @param {object} o.grant                             from `signPolicyGrant`
 * @param {string} o.publicKeyPem                      the operator's public key
 * @param {object} o.ledger                            from `createPolicyLedger`
 * @param {Date}   [o.now]
 * @param {object} [o.deniedAction]                    re-decided under the new policy
 * @param {object} [o.probeReport]                     injected probe report (default: probe this host)
 */
async function applyPolicyChange({ bound, change, grant, publicKeyPem, ledger, now = new Date(), deniedAction, probeReport, ctxExtra = {} }) {
  const refuse = (code) => ({ ok: false, code, reason: `policy change refused: ${code}`, bound: null, entry: null, preflight: null });
  if (!bound?.manifest || !bound?.binding || !ledger) return refuse('invalid-input');
  const v = verifyGrant(grant, publicKeyPem);
  if (!v.ok) return refuse(v.code);
  const p = grant.payload;
  const issued = Date.parse(p.issuedAt); const expires = Date.parse(p.expiresAt);
  if (!Number.isFinite(issued) || !Number.isFinite(expires) || expires - issued > MAX_GRANT_TTL_MS || expires <= issued) return refuse('grant-window-invalid');
  if (now.getTime() < issued) return refuse('grant-not-yet-valid');
  if (now.getTime() >= expires) return refuse('grant-expired');
  const b = bound.binding;
  if (p.taskId !== b.taskId) return refuse('grant-wrong-task');
  if (p.fromPolicyVersion !== b.policyVersion || p.fromDigest !== b.digest) return refuse('grant-stale');
  ledger.register(bound);
  if (!ledger.isCurrent(b)) return refuse('grant-stale');
  if (ledger.nonceUsed(p.nonce)) return refuse('grant-replayed');
  if (ledger.changesFor(b.taskId) >= ledger.maxChanges) return refuse('change-limit');
  const applied = applyChangeToManifest(bound.manifest, change);
  if (!applied.ok) return refuse(applied.code);
  if (applied.bound.binding.digest !== p.toDigest || applied.bound.binding.policyVersion !== p.toPolicyVersion) return refuse('grant-change-mismatch');

  const entry = ledger.append({
    taskId: b.taskId, operator: p.operator, reason: p.reason, nonce: p.nonce,
    fromPolicyVersion: b.policyVersion, fromDigest: b.digest, toPolicyVersion: p.toPolicyVersion, toDigest: p.toDigest,
    changeDigest: digestOf(change), at: now.toISOString(),
  });

  // Rerun what the change can affect: the manifest itself, the controls the new
  // manifest depends on, and the action that was denied.
  const nb = applied.bound;
  const pr = probeReport || await probeCapabilityControls({});
  const required = requiredControlsFor(nb.manifest);
  const unmet = unmetControls(pr, required);
  const valid = validateManifest(nb.manifest).ok;
  const redecision = deniedAction ? decide(nb, deniedAction, { binding: nb.binding, ...ctxExtra }) : null;
  const preflight = {
    manifestValid: valid, requiredControls: required, unmet,
    redecision: redecision ? { decision: redecision.decision, code: redecision.code } : null,
    ready: valid && unmet.length === 0 && (!redecision || redecision.decision === 'allow'),
  };
  return {
    ok: true, code: null, reason: 'policy changed; a new policy version was created', bound: nb, entry, preflight,
    supersedes: { policyVersion: b.policyVersion, digest: b.digest },
  };
}

;// CONCATENATED MODULE: ./src/capabilities/records.js
// Capability decisions as CORE-002 records, and the advisory (hook) view.
//
// A policy decision (decide.js) becomes an `agentic-security/capability-decision`
// record. The record schema already carries the honesty rule this module relies
// on: only runner or proxy mediation, naming a backend and the digest of an
// active probe, may claim `enforced`. `enforced` here is true only when the
// runner says the backend is an advertised one and every required control was
// proved; a development-host run is recorded as a runner-mediated decision with
// `enforced: false`.





/**
 * @param {object} d            a decision from `decide`
 * @param {object} o
 * @param {'runner'|'proxy'|'in-process-policy'|'hook-advisory'|'none'} o.mediation
 * @param {boolean} o.enforced
 * @param {string|null} o.backend
 * @param {string|null} o.probeDigest
 * @returns {{ok: boolean, record: object|null, errors: object[]}}
 */
function toCapabilityDecisionRecord(d, { mediation, enforced, backend = null, probeDigest = null }) {
  const rec = {
    schema: 'agentic-security/capability-decision', schemaVersion: schema_kit/* SCHEMA_VERSION */.f$,
    taskId: d.taskId ?? 'unbound', capability: d.kind, subject: reasons_sanitizeSubject(d.subject, 200),
    decision: d.decision, mediation, enforced: enforced === true, backend,
    ...(probeDigest ? { probeDigest } : {}),
    reason: `${d.code}: ${d.reason}`,
  };
  rec.id = (0,contracts/* capabilityDecisionId */.A9)(rec);
  const v = (0,contracts/* validateCapabilityDecision */.f_)(rec);
  return v.ok ? { ok: true, record: Object.freeze(rec), errors: [] } : { ok: false, record: null, errors: v.errors };
}

/**
 * What a hook may say about an action. The same policy answer, labelled as
 * advice: mediation `hook-advisory` and never enforced, however the manifest
 * reads. A shell command string is not an action the policy can parse, so it is
 * reported as unsupported for enforcement and left to the runner's structured
 * execution.
 */
function advise(bound, action, ctx) {
  if (action && action.kind === 'command' && typeof action.command === 'string') {
    return Object.freeze({
      advisory: true, enforced: false, decision: 'unsupported', code: 'interpreter-blocked',
      note: 'a shell command string cannot be mediated; run it as an executable and an argument array through the capability runner',
      record: null,
    });
  }
  const d = decide(bound, action, ctx);
  const r = toCapabilityDecisionRecord(d, { mediation: 'hook-advisory', enforced: false, backend: null });
  return Object.freeze({
    advisory: true, enforced: false, decision: d.decision, code: d.code,
    note: 'advice only: a hook response explains a decision, it does not enforce one', record: r.ok ? r.record : null,
  });
}

;// CONCATENATED MODULE: ./src/capabilities/tool-gate.js
// The MCP tool gate (X-505.AC01, X-505.AC03).
//
// Every tool call is checked against the SAME decision function the runner and
// the hooks use (`decide`), for the CURRENT task identity, before its handler
// runs. The identity is the one the operator bound to the server; nothing the
// calling agent sends can change it: tool arguments are closed schemas, and an
// identity named in the request metadata is compared with the bound one and
// refused when it differs (`identity-spoofed`).
//
//   no policy, feature off   the gate is inactive: behaviour is exactly what it
//                            was before this module existed
//   feature on, no policy    read tools pass; a mutating or externally
//                            communicating tool is refused (`identity-missing`),
//                            because there is no task to check it for
//   policy bound             every tool is checked: it must be a declared tool
//                            action (deny by default), a mutating one must also
//                            have the session root inside a declared write root,
//                            and a tool missing from the classification table is
//                            refused (`tool-unclassified`)
//
// A denial is synchronous and final for that call: no prompt, no waiting, no
// retry inside the gate. It carries the missing capability and a reviewable
// proposed change (recovery.js); repeated denials hit the finite limit there.
//
// This is POLICY at the tool boundary. The tool then runs in the MCP server
// process, so the decision is recorded as `in-process-policy` and never
// `enforced`; the runner is the only enforcement layer.






const FEATURE = 'capability-enforcement';
const MAX_KEPT = 500;

function synthetic(bound, kind, code, subject) {
  return Object.freeze({
    decision: 'deny', code, reason: reasonText(code), kind, subject: reasons_sanitizeSubject(subject),
    taskId: bound?.binding?.taskId ?? null, manifestDigest: bound?.binding?.digest ?? null,
  });
}

/** Whether the OPERATOR enabled the feature (environment only; a project file can never enable it). */
function featureEnabledByOperator(env = process.env) {
  try { return (0,config.resolveAssuranceConfig)({ env }).features?.[FEATURE]?.enabled === true; } catch { return false; }
}

/**
 * @param {object} o
 * @param {string} o.sessionRoot
 * @param {{bound: object, binding: object}|null} [o.policy]  the task's bound manifest and the identity it acts for
 * @param {object} [o.guard]    denial guard (default: a fresh one with the default limits)
 * @param {object} [o.env]
 */
function createToolGate({ sessionRoot, policy = null, guard, env = process.env } = {}) {
  let current = policy && policy.bound && policy.binding ? { bound: policy.bound, binding: policy.binding } : null;
  const denialGuard = guard || createDenialGuard();
  const kept = [];

  function record(decision) {
    const r = toCapabilityDecisionRecord(decision, { mediation: 'in-process-policy', enforced: false, backend: null });
    if (r.ok) { kept.push(r.record); if (kept.length > MAX_KEPT) kept.shift(); }
    return r.ok ? r.record : null;
  }

  function refused(d) {
    return Object.freeze({
      allowed: false, blocked: true, code: d.code, reason: d.reason, decision: d,
      missing: Object.freeze({ capability: 'tool', code: d.code, detail: d.subject }),
      proposal: null, attemptsRemaining: null, exhausted: false, record: record(d),
    });
  }

  function blockedResult(m, extra = {}) {
    return Object.freeze({
      allowed: false, blocked: true, code: m.decision.code, reason: m.decision.reason, decision: m.decision, missing: m.missing,
      proposal: m.proposal, attemptsRemaining: m.attemptsRemaining, exhausted: m.exhausted, record: record(m.decision), ...extra,
    });
  }

  const self = {
    /** The gate is active when a policy is bound or the operator turned the feature on. */
    active: () => current !== null || featureEnabledByOperator(env),
    hasPolicy: () => current !== null,
    /** Operator-side: replace the bound policy (a new policy version, a different task). Stale bindings are then refused. */
    update(next) { current = next && next.bound && next.binding ? { bound: next.bound, binding: next.binding } : null; },
    decisions: () => kept.slice(),
    guard: denialGuard,

    /**
     * @param {string} name   the tool the agent asked for
     * @param {{claimedTaskId?: string}} [req]   identity claimed in the request, if any
     */
    check(name, { claimedTaskId } = {}) {
      if (!self.active()) return Object.freeze({ allowed: true, skipped: true, decision: null });
      if (!current) {
        if (!isMutatingOrExternal(name)) return Object.freeze({ allowed: true, skipped: true, decision: null });
        return refused(synthetic(null, 'tool', 'identity-missing', String(name)));
      }
      const { bound, binding } = current;
      if (claimedTaskId !== undefined && claimedTaskId !== binding.taskId) {
        return refused(synthetic(bound, 'tool', 'identity-spoofed', `${String(name)} (claimed task ${reasons_sanitizeSubject(claimedTaskId, 60)})`));
      }
      const cap = toolCapabilityFor(name);
      if (!cap) return refused(synthetic(bound, 'tool', 'tool-unclassified', String(name)));
      const ctx = { binding };
      const decisions = [];
      for (const req of cap.requires) {
        const action = req === 'tool' ? { kind: 'tool', tool: name } : { kind: 'filesystem-write', path: sessionRoot };
        const m = mediate(bound, action, ctx, { guard: denialGuard });
        if (m.status !== 'ok') return blockedResult(m, { checked: decisions.length });
        decisions.push(m.decision); record(m.decision);
      }
      return Object.freeze({ allowed: true, skipped: false, decision: decisions[0], decisions });
    },
  };
  return Object.freeze(self);
}


/***/ }),

/***/ 69390:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   auditCall: () => (/* binding */ auditCall)
/* harmony export */ });
/* unused harmony export verifyAuditLog */
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(73024);
/* harmony import */ var node_path__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(76760);
/* harmony import */ var node_crypto__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(77598);
/* harmony import */ var _redact_js__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(83468);
/* harmony import */ var _posture_state_dir_js__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(31174);
// Append-only audit log of MCP tool calls — OWASP MCP08.
//
// Format: one JSON object per line (NDJSON) at
//   <sessionRoot>/.agentic-security/mcp-audit.log
//
// Each entry carries `prev` — the SHA-256 of the previous entry's serialized
// form. The first entry's prev is "GENESIS". Tampering with any line breaks
// the chain from that point forward; a reader can detect partial truncation
// or in-place edits.
//
// REMOTE SINK (post-recommendation #10). The local file alone cannot detect
// a total rewrite — an attacker with FS write can re-author the whole log
// with fresh hashes. Closing that blind spot requires an off-host witness.
// Set $AGENTIC_SECURITY_AUDIT_WEBHOOK to a POST endpoint; every entry is
// fire-and-forget POSTed there in addition to the local append. Failures
// to reach the webhook are best-effort — they NEVER block a tool call,
// because that would let a network outage become a denial of service. They
// DO get recorded as `_remoteSinkErr` on the local entry, so an operator
// reviewing the log later can spot a forging attempt that targeted the
// remote (any gap between local-sequence and remote-sequence is evidence).
//
// Argument blobs are redacted (OWASP MCP01/MCP10) so credentials passed in
// arguments cannot leak via the audit trail OR via the remote sink.







const MAX_ARG_BYTES = 1024;
const GENESIS = 'GENESIS';
const REMOTE_TIMEOUT_MS = 1500;

// Per-process session ID (harness-anatomy #9). Stamped on every audit entry
// so downstream metrics can aggregate by session and surface outliers like
// "200 apply_fix calls in one session." The ID is `<pid>-<short-ts>` — not
// cryptographically unique, but enough to disambiguate concurrent runs on
// the same host. Stable for the lifetime of this Node process.
const SESSION_ID = `${process.pid}-${Date.now().toString(36).slice(-6)}`;

function _summarize(args) {
  let s;
  try { s = JSON.stringify(args); } catch { s = '<unserializable>'; }
  s = (0,_redact_js__WEBPACK_IMPORTED_MODULE_4__/* .redactArgsBlob */ .MC)(s);
  if (s.length > MAX_ARG_BYTES) s = s.slice(0, MAX_ARG_BYTES) + `…(+${s.length - MAX_ARG_BYTES})`;
  return s;
}

function _sha(s) { return node_crypto__WEBPACK_IMPORTED_MODULE_2__.createHash('sha256').update(s).digest('hex'); }

function _readLastEntryHash(logFile) {
  if (!node_fs__WEBPACK_IMPORTED_MODULE_0__.existsSync(logFile)) return GENESIS;
  try {
    const all = node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(logFile, 'utf8');
    const lines = all.split('\n').filter(Boolean);
    if (!lines.length) return GENESIS;
    return _sha(lines[lines.length - 1]);
  } catch { return GENESIS; }
}

// Fire-and-forget POST to the remote sink. Resolves to null on success,
// to a short error string on failure. Never throws; never blocks longer
// than REMOTE_TIMEOUT_MS. The local audit append happens regardless.
async function _postRemote(url, entry) {
  try {
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), REMOTE_TIMEOUT_MS);
    const r = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(entry),
      signal: controller.signal,
    });
    clearTimeout(t);
    if (!r.ok) return `HTTP ${r.status}`;
    return null;
  } catch (e) {
    return String((e && e.message) || e).slice(0, 200);
  }
}

function auditCall({ sessionRoot, tool, args, outcome, reason }) {
  if (!sessionRoot) return;
  try {
    // Safety: only write audit log if sessionRoot looks like a project root
    const MARKERS = ['.git', 'package.json', 'pyproject.toml', 'go.mod', 'Cargo.toml', 'pom.xml', 'composer.json', 'Gemfile'];
    let hasMarker = false;
    for (const m of MARKERS) { try { if (node_fs__WEBPACK_IMPORTED_MODULE_0__.existsSync(node_path__WEBPACK_IMPORTED_MODULE_1__.join(sessionRoot, m))) { hasMarker = true; break; } } catch {} }
    if (!hasMarker) return;
    const dir = (0,_posture_state_dir_js__WEBPACK_IMPORTED_MODULE_3__/* .stateDir */ .Pn)(sessionRoot);
    node_fs__WEBPACK_IMPORTED_MODULE_0__.mkdirSync(dir, { recursive: true });
    const logFile = node_path__WEBPACK_IMPORTED_MODULE_1__.join(dir, 'mcp-audit.log');
    const entry = {
      ts: new Date().toISOString(),
      sessionId: SESSION_ID,
      tool,
      outcome,
      ...(reason ? { reason } : {}),
      args: _summarize(args),
      prev: _readLastEntryHash(logFile),
    };
    node_fs__WEBPACK_IMPORTED_MODULE_0__.appendFileSync(logFile, JSON.stringify(entry) + '\n');
    // Remote sink (post-recommendation #10). Fire-and-forget. We don't await
    // the promise so the tool call returns immediately; the remote POST runs
    // on its own microtask. Failures get logged to a sidecar file so the
    // operator can detect when the sink is unreachable.
    const webhook = process.env.AGENTIC_SECURITY_AUDIT_WEBHOOK;
    if (webhook) {
      _postRemote(webhook, entry).then((err) => {
        if (!err) return;
        try {
          const errFile = node_path__WEBPACK_IMPORTED_MODULE_1__.join(dir, 'mcp-audit.remote-errors.log');
          node_fs__WEBPACK_IMPORTED_MODULE_0__.appendFileSync(errFile, JSON.stringify({
            ts: new Date().toISOString(), entryTs: entry.ts, tool, err,
          }) + '\n');
        } catch { /* nothing else to do */ }
      });
    }
  } catch { /* audit failure must never break a tool call */ }
}

// Verify the chain from start to end. Returns
//   { ok: true, entries: N } if intact
//   { ok: false, brokenAt: <line-index>, expected, got } if any link breaks
// Reader/operator-facing tool.
function verifyAuditLog(logFile) {
  if (!fs.existsSync(logFile)) return { ok: true, entries: 0 };
  const text = fs.readFileSync(logFile, 'utf8');
  const lines = text.split('\n').filter(Boolean);
  let expectedPrev = GENESIS;
  for (let i = 0; i < lines.length; i++) {
    let entry;
    try { entry = JSON.parse(lines[i]); }
    catch { return { ok: false, brokenAt: i, reason: 'not JSON' }; }
    if (entry.prev !== expectedPrev) {
      return { ok: false, brokenAt: i, expected: expectedPrev, got: entry.prev };
    }
    expectedPrev = _sha(lines[i]);
  }
  return { ok: true, entries: lines.length };
}


/***/ }),

/***/ 20095:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   HI: () => (/* binding */ dataflow_get_node),
/* harmony export */   HX: () => (/* binding */ dataflow_get_graph),
/* harmony export */   gC: () => (/* binding */ dataflow_get_edge),
/* harmony export */   ri: () => (/* binding */ dataflow_get_flow)
/* harmony export */ });
/* harmony import */ var _server_graph_loader_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(78218);
/* harmony import */ var _server_routes_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(84268);
/* harmony import */ var _lineage_redact_graph_js__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(10334);
/* harmony import */ var _lineage_export_json_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(40859);
// dataflow-tools.js — Milestone 4, sub-project MCP tools.
//
// Thin, read-only MCP adapter over the DataFlowGraph v1 artifact. Every
// piece of actual graph-loading and graph-query logic here is REUSED,
// unmodified, from scanner/src/server/ (built for the `explore` HTTP
// server, Milestone 3): loadSignedGraph does the signed-artifact
// load+verify, the four handleX functions do the lookups. This module
// adds nothing but MCP tool shape (name/description/inputSchema/handler)
// and MCP-appropriate error handling — no new graph-query logic is
// written here, on purpose (see this sub-project's own scoping doc).






const META = { source: 'agentic-security-mcp', untrusted_excerpts: true };

function _loadOrFailure(sessionRoot) {
  const loaded = (0,_server_graph_loader_js__WEBPACK_IMPORTED_MODULE_0__.loadSignedGraph)(sessionRoot);
  if (loaded.ok) return { graph: loaded.graph };
  return {
    failure: {
      _meta: META,
      hasResult: false,
      reason: loaded.reason,
      message: loaded.message,
    },
  };
}

// Milestone 5, large-graph pagination: an optional `filter` input narrows the
// returned graph via the exact same `validateFilterShape`/`_filterGraph`
// pair the CLI's own `--filter` and the `explore` server's new
// `POST /api/v1/query` endpoint both already use — one real, shared
// primitive, not a third drifting copy. KNOWN, DISCLOSED GAP (still open):
// an OMITTED filter still returns the whole graph inline, with the same
// stdio.js MAX_LINE_BYTES (4MB) risk on a very large, unfiltered scan as
// before this change — this increment adds an opt-in capability for a
// caller that supplies a filter, it does not add a forced fallback/offload
// for a caller that doesn't. That remains a follow-up increment.
// Final whole-branch review finding: `filter: {}` is NOT the same as
// omitting `filter` — `_filterGraph` treats an empty (but well-formed)
// filter object as "narrow to nothing" (empty nodeIds/edgeIds Sets), so
// `filter: {}` returns an EMPTY graph (zero nodes/edges/flows), not the
// whole one. Called out explicitly in this tool's own `description` below
// so an agent reaching for "no restriction" reaches for OMITTING the
// argument, never for `{}`.
const dataflow_get_graph = {
  name: 'dataflow_get_graph',
  description: 'Return the DataFlowGraph v1 artifact from the last signed, verified deep-mode scan: nodes, edges, flows, scope, coverage, and limitations. Requires a prior `AGENTIC_SECURITY_LINEAGE_DEEP=1 agentic-security scan`. Optional `filter: {nodeIds, edgeIds}` narrows the returned nodes/edges/flows/dataElements (same primitive as the CLI\'s `--filter` and the `explore` server\'s `POST /api/v1/query`). IMPORTANT: omit `filter` entirely for the whole graph — passing `filter: {}` returns an EMPTY graph (zero nodes/edges/flows), not the whole one, since an empty filter narrows to nothing rather than meaning "no restriction". KNOWN GAP: an OMITTED filter still returns the whole graph inline with no pagination/offload — may exceed the stdio transport line cap on a very large, unfiltered graph; supply a real, non-empty filter to narrow the response.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      filter: {
        type: 'object',
        additionalProperties: false,
        properties: {
          nodeIds: { type: 'array', items: { type: 'string' } },
          edgeIds: { type: 'array', items: { type: 'string' } },
        },
      },
    },
  },
  async handler(args, ctx) {
    const { graph, failure } = _loadOrFailure(ctx.sessionRoot);
    if (failure) return failure;
    // Milestone 5, large-graph pagination: reuses the exact same
    // validateFilterShape/_filterGraph pair the new POST /api/v1/query
    // server endpoint and the CLI's own --filter both use — one real,
    // shared primitive, not a third drifting copy.
    const filterCheck = (0,_lineage_export_json_js__WEBPACK_IMPORTED_MODULE_2__.validateFilterShape)(args?.filter);
    if (!filterCheck.valid) {
      return { _meta: META, hasResult: false, reason: 'invalid-filter', message: filterCheck.error };
    }
    const { status, body } = (0,_server_routes_js__WEBPACK_IMPORTED_MODULE_1__/* .handleGraph */ .fn)(graph);
    return {
      _meta: META,
      hasResult: true,
      status,
      data: (0,_lineage_redact_graph_js__WEBPACK_IMPORTED_MODULE_3__/* ._redactGraph */ .zl)(args?.filter ? (0,_lineage_export_json_js__WEBPACK_IMPORTED_MODULE_2__/* ._filterGraph */ .e)(body.data, args.filter) : body.data),
      digest: body.digest,
      schemaVersion: body.schemaVersion,
      extensions: body.extensions,
      scope: body.scope,
      coverage: body.coverage,
      limitations: body.limitations,
    };
  },
};

const dataflow_get_node = {
  name: 'dataflow_get_node',
  description: 'Look up one node by canonical id in the DataFlowGraph v1 artifact.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: { id: { type: 'string', minLength: 1, maxLength: 512 } },
    required: ['id'],
  },
  async handler({ id }, ctx) {
    const { graph, failure } = _loadOrFailure(ctx.sessionRoot);
    if (failure) return failure;
    const { status, body } = (0,_server_routes_js__WEBPACK_IMPORTED_MODULE_1__/* .handleNode */ .d5)(graph, id);
    return {
      _meta: META,
      hasResult: true,
      notFound: status === 404,
      data: (0,_lineage_redact_graph_js__WEBPACK_IMPORTED_MODULE_3__/* ._redactNode */ .T2)(body.data),
      canonicalIds: body.canonicalIds,
    };
  },
};

const dataflow_get_edge = {
  name: 'dataflow_get_edge',
  description: 'Look up one edge by canonical id in the DataFlowGraph v1 artifact.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: { id: { type: 'string', minLength: 1, maxLength: 512 } },
    required: ['id'],
  },
  async handler({ id }, ctx) {
    const { graph, failure } = _loadOrFailure(ctx.sessionRoot);
    if (failure) return failure;
    const { status, body } = (0,_server_routes_js__WEBPACK_IMPORTED_MODULE_1__/* .handleEdge */ .Yu)(graph, id);
    return {
      _meta: META,
      hasResult: true,
      notFound: status === 404,
      data: body.data,
      canonicalIds: body.canonicalIds,
    };
  },
};

const dataflow_get_flow = {
  name: 'dataflow_get_flow',
  description: 'Look up one flow by canonical id in the DataFlowGraph v1 artifact, including its contributing node/edge canonical ids.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: { id: { type: 'string', minLength: 1, maxLength: 512 } },
    required: ['id'],
  },
  async handler({ id }, ctx) {
    const { graph, failure } = _loadOrFailure(ctx.sessionRoot);
    if (failure) return failure;
    const { status, body } = (0,_server_routes_js__WEBPACK_IMPORTED_MODULE_1__/* .handleFlow */ .jg)(graph, id);
    return {
      _meta: META,
      hasResult: true,
      notFound: status === 404,
      data: body.data,
      canonicalIds: body.canonicalIds,
    };
  },
};


/***/ }),

/***/ 82407:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   _: () => (/* binding */ makeInvariantTools)
/* harmony export */ });
/* harmony import */ var _posture_invariants_export_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(90145);
/* harmony import */ var _posture_assurance_config_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(90385);
/* harmony import */ var _redact_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(83468);
// invariant-tools.js: the MCP surface for bounded business-logic scenarios (X-407.AC03).
//
// One READ-ONLY tool, `invariant_scenario_export`: build the reproducible scenario package for a reviewer-supplied contract and a
// disposable fixture directory that both live inside the session root. It runs nothing and writes nothing. The same function
// the CLI calls (`posture/invariants/export.js` `exportFromFiles`) does the work, so the two surfaces cannot disagree.
//
// Guarantees, each with a test:
//   - paths are confined to the session root by the server's own `_confine` (passed in; this file never resolves a path itself);
//   - the export carries no tenant secret: scenarios holding secret-looking content are withheld, the fixture source is never
//     included, and the serialized result is checked once more with the server's own secret-shape redactor, which BLOCKS the
//     result rather than editing it (an edited scenario is a different scenario);
//   - it never claims exhaustive correctness: every export carries the bounded-sample statement;
//   - gated behind the `invariant-scenarios` feature (off by default, operator-only): with it off the tool reports it is
//     disabled and builds nothing.
// The factory shape (rather than importing `_confine` from tools.js) avoids a cycle between this file and the registry.




const MAX_RESPONSE_BYTES = 1_500_000;

function makeInvariantTools({ confine, META }) {
  const invariant_scenario_export = {
    name: 'invariant_scenario_export',
    description: 'Export the bounded stateful scenarios for one executable business-logic invariant as a reproducible package: scenario documents with content digests, the pinned fixture digest, replay manifests (when a commit is given), the bounds applied and the scenario families that could not be built. Read-only: runs nothing. The fixture source and any secret-looking content are never included, and the package states that it is a bounded sample, not a proof of correctness. Requires the invariant-scenarios feature (off by default).',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      properties: {
        invariant_file: { type: 'string', minLength: 1, maxLength: 512 },
        fixture_dir: { type: 'string', minLength: 1, maxLength: 512 },
        ledger_file: { type: 'string', minLength: 1, maxLength: 512 },
        commit: { type: 'string', pattern: '^[0-9a-f]{40}([0-9a-f]{24})?$' },
        seed: { type: 'integer', minimum: 0, maximum: 4294967295 },
        bounds: {
          type: 'object', additionalProperties: false,
          properties: {
            actors: { type: 'integer', minimum: 1, maximum: 4 }, depth: { type: 'integer', minimum: 1, maximum: 12 }, requests: { type: 'integer', minimum: 1, maximum: 16 },
            scenarios: { type: 'integer', minimum: 1, maximum: 6 }, timeBudgetMs: { type: 'integer', minimum: 1, maximum: 8000 },
          },
        },
      },
      required: ['invariant_file', 'fixture_dir'],
    },
    async handler(args, ctx) {
      let invariantPath; let fixturePath; let ledgerPath;
      try {
        invariantPath = confine(ctx.sessionRoot, args.invariant_file, 'invariant_file');
        fixturePath = confine(ctx.sessionRoot, args.fixture_dir, 'fixture_dir');
        if (args.ledger_file) ledgerPath = confine(ctx.sessionRoot, args.ledger_file, 'ledger_file');
      } catch (e) {
        return { _meta: META, ok: false, status: 'rejected', reason: `path refused: ${String(e.message).replace(ctx.sessionRoot, '<root>')}` };
      }
      const config = (0,_posture_assurance_config_js__WEBPACK_IMPORTED_MODULE_1__.resolveAssuranceConfig)({ scanRoot: ctx.sessionRoot, env: process.env });
      const r = (0,_posture_invariants_export_js__WEBPACK_IMPORTED_MODULE_0__/* .exportFromFiles */ .iF)({ invariantPath, fixturePath, ledgerPath, commit: args.commit, seed: args.seed, bounds: args.bounds, config });
      if (r.status !== 'ok') return { _meta: META, ok: false, status: r.status, reason: String(r.reason || '').replace(ctx.sessionRoot, '<root>').slice(0, 400), withheld: r.withheld ?? [] };
      const text = JSON.stringify(r.export);
      if ((0,_redact_js__WEBPACK_IMPORTED_MODULE_2__/* .redactSecretShapes */ .Kb)(text).redactions > 0) return { _meta: META, ok: false, status: 'blocked', reason: 'the export contains secret-shaped content and was not returned; an edited scenario would be a different scenario' };
      if (text.length > MAX_RESPONSE_BYTES) return { _meta: META, ok: false, status: 'blocked', reason: 'the export is too large for one response; lower the bounds' };
      return { _meta: META, ok: true, status: 'ok', export: r.export, withheld: r.withheld };
    },
  };
  return { invariant_scenario_export };
}


/***/ }),

/***/ 99027:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   _: () => (/* binding */ makePortfolioTools)
/* harmony export */ });
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(73024);
/* harmony import */ var _posture_assurance_config_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(90385);
/* harmony import */ var _posture_portfolio_work_units_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(90987);
/* harmony import */ var _posture_portfolio_scheduler_js__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(34563);
/* harmony import */ var _posture_portfolio_progress_js__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(67439);
/* harmony import */ var _posture_portfolio_wording_js__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(9886);
/* harmony import */ var _redact_js__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(83468);
// portfolio-tools.js: the MCP surface for portfolio progress and review queues (X-707).
//
// One READ-ONLY tool, `portfolio_progress`: the coverage-aware progress view of a durable portfolio store that lives inside the session
// root. It reads the store (verified; a corrupt store is an error, never a reset), the scheduler ledger beside it, and optionally a
// budgets file and a findings file, and writes nothing. The same function the CLI calls (`posture/portfolio/progress.js`
// `buildProgressView`) does the work, so the two surfaces cannot disagree.
//
// Guarantees, each with a test:
//   - paths are confined to the session root by the server's own `_confine` (passed in; this file never resolves a path itself);
//   - the view separates verified, blocked/failed/stale, coverage, budget and pending review, keeps stale workers visible, and never
//     states that the portfolio passed (a finished controller is reported as finished);
//   - the serialized result is checked with the server's secret-shape redactor and BLOCKED rather than edited if anything would change;
//   - gated behind the `portfolio-assurance` feature (off by default): with it off the tool answers `status: 'disabled'` and reads nothing.
// The factory shape (rather than importing `_confine` from tools.js) avoids a cycle between this file and the registry.








const MAX_RESPONSE_BYTES = 1_500_000;
const MAX_INPUT_BYTES = 8 * 1024 * 1024;

function readJson(file) {
  const st = node_fs__WEBPACK_IMPORTED_MODULE_0__.lstatSync(file);
  if (st.isSymbolicLink() || !st.isFile() || st.size > MAX_INPUT_BYTES) throw new Error('not a regular JSON file within the size limit');
  return JSON.parse(node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(file, 'utf8'));
}

function makePortfolioTools({ confine, META }) {
  const portfolio_progress = {
    name: 'portfolio_progress',
    description: 'Show the progress of a resumable multi-repository portfolio audit as a coverage-aware view: verified units, blocked/failed/stale units, per-repository coverage, remaining budget, pending human review, worker liveness (stale workers stay visible) and, when a findings file is given, aggregate findings deduplicated by stable identity with per-repository/environment evidence and separate affected releases. A finished controller is reported as finished, never as passed. Read-only; paths must be inside the session root. Disabled unless the portfolio-assurance feature is on.',
    inputSchema: {
      type: 'object',
      additionalProperties: false,
      properties: {
        store_file: { type: 'string', minLength: 1, maxLength: 512 },
        budgets_file: { type: 'string', minLength: 1, maxLength: 512 },
        findings_file: { type: 'string', minLength: 1, maxLength: 512 },
        blocking_severity: { type: 'string', enum: ['info', 'low', 'medium', 'high', 'critical'] },
        now: { type: 'integer', minimum: 0 },
      },
      required: ['store_file'],
    },
    async handler(args, ctx) {
      const config = (0,_posture_assurance_config_js__WEBPACK_IMPORTED_MODULE_1__.resolveAssuranceConfig)({ scanRoot: ctx.sessionRoot, env: process.env });
      const gate = (0,_posture_assurance_config_js__WEBPACK_IMPORTED_MODULE_1__/* .featureStatus */ .FX)(config, _posture_portfolio_wording_js__WEBPACK_IMPORTED_MODULE_5__/* .FEATURE_ID */ .DU);
      if (gate.status !== 'ok') return { _meta: META, ok: false, status: gate.status, reason: `portfolio progress is not available: ${gate.reason ?? gate.code}` };
      let storePath; let budgetsPath; let findingsPath;
      try {
        storePath = confine(ctx.sessionRoot, args.store_file, 'store_file');
        if (args.budgets_file) budgetsPath = confine(ctx.sessionRoot, args.budgets_file, 'budgets_file');
        if (args.findings_file) findingsPath = confine(ctx.sessionRoot, args.findings_file, 'findings_file');
      } catch (e) {
        return { _meta: META, ok: false, status: 'rejected', reason: `path refused: ${String(e.message).replace(ctx.sessionRoot, '<root>')}` };
      }
      let store; let ledger; let budgets = null; let findings = null;
      try {
        store = (0,_posture_portfolio_work_units_js__WEBPACK_IMPORTED_MODULE_2__/* .readStore */ .uz)(storePath);
        if (!store) return { _meta: META, ok: false, status: 'rejected', reason: 'no portfolio store at that path' };
        ledger = (0,_posture_portfolio_scheduler_js__WEBPACK_IMPORTED_MODULE_3__/* .readLedger */ .SC)(storePath);
        if (budgetsPath) budgets = readJson(budgetsPath);
        if (findingsPath) findings = readJson(findingsPath);
      } catch (e) {
        return { _meta: META, ok: false, status: 'blocked', reason: `the store or an input failed verification: ${String(e.code ?? e.message).slice(0, 200)}` };
      }
      const r = (0,_posture_portfolio_progress_js__WEBPACK_IMPORTED_MODULE_4__/* .buildProgressView */ .TJ)({ store, ledger, budgets, now: Number.isInteger(args.now) ? args.now : Date.now(), findings, blockingSeverity: args.blocking_severity });
      if (!r.ok) return { _meta: META, ok: false, status: 'rejected', reason: r.errors.map((e) => e.message).join('; ').slice(0, 400) };
      const text = JSON.stringify(r.view);
      if ((0,_redact_js__WEBPACK_IMPORTED_MODULE_6__/* .redactSecretShapes */ .Kb)(text).redactions > 0) return { _meta: META, ok: false, status: 'blocked', reason: 'the view contains secret-shaped content and was not returned' };
      if (text.length > MAX_RESPONSE_BYTES) return { _meta: META, ok: false, status: 'blocked', reason: 'the view is too large for one response' };
      return { _meta: META, ok: true, status: 'ok', view: r.view };
    },
  };
  return { portfolio_progress };
}


/***/ }),

/***/ 27438:
/***/ ((__webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.a(__webpack_module__, async (__webpack_handle_async_dependencies__, __webpack_async_result__) => { try {
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   sA: () => (/* binding */ createServer)
/* harmony export */ });
/* unused harmony exports SERVER_NAME, SERVER_VERSION, PROTOCOL_VERSION, CODE_FINGERPRINT */
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(73024);
/* harmony import */ var node_crypto__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(77598);
/* harmony import */ var node_path__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(76760);
/* harmony import */ var node_url__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(73136);
/* harmony import */ var _tools_js__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(14054);
/* harmony import */ var _validate_js__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(61211);
/* harmony import */ var _audit_js__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(69390);
/* harmony import */ var _capabilities_tool_gate_js__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(99405);
var __webpack_async_dependencies__ = __webpack_handle_async_dependencies__([_tools_js__WEBPACK_IMPORTED_MODULE_4__]);
_tools_js__WEBPACK_IMPORTED_MODULE_4__ = (__webpack_async_dependencies__.then ? (await __webpack_async_dependencies__)() : __webpack_async_dependencies__)[0];
// MCP server core — JSON-RPC 2.0 handler for the Model Context Protocol.
//
// Hardening posture (mapped to OWASP MCP Top 10):
//   - Session root chosen at server boot, no per-call retargeting (MCP02)
//   - Every tools/call argument validated against the tool's inputSchema (MCP02/MCP05)
//   - Every tools/call audited with a hash-chained log (MCP08)
//   - serverInfo.codeFingerprint = SHA-256 of MCP source files (MCP04/MCP09)
//     so a fleet can detect tampered or unauthorized server deployments
//   - AGENTIC_SECURITY_MCP_DISABLED=1 hard-disables all tool calls (MCP09)
//   - Stdio transport caps line/buffer size (./stdio.js) (MCP05 DoS)








// X-505: tool calls are checked against the capability policy before a handler runs.


const PROTOCOL_VERSION = '2025-03-26';
const SERVER_NAME = 'agentic-security';

// Premortem #6: read version from scanner/package.json at module load so the
// MCP `initialize` response can't silently drift from the shipped package
// version. A hardcoded constant rotted from 0.39.2 → wrong for every release
// that followed. Fall back to 'unknown' rather than a stale literal.
const SERVER_VERSION = (() => {
  try {
    const here = node_path__WEBPACK_IMPORTED_MODULE_2__.dirname((0,node_url__WEBPACK_IMPORTED_MODULE_3__.fileURLToPath)(import.meta.url));
    // scanner/src/mcp/ → scanner/package.json
    const pkgPath = node_path__WEBPACK_IMPORTED_MODULE_2__.resolve(here, '..', '..', 'package.json');
    const pkg = JSON.parse(node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(pkgPath, 'utf8'));
    if (typeof pkg.version === 'string' && pkg.version.length) return pkg.version;
  } catch { /* fall through */ }
  return 'unknown';
})();

const TOOLS_BY_NAME = Object.fromEntries(_tools_js__WEBPACK_IMPORTED_MODULE_4__/* .ALL_TOOLS */ .Wi.map(t => [t.name, t]));

// Code fingerprint — SHA-256 of the MCP source files concatenated in a
// stable order. Embedded in `initialize` response so a fleet operator can
// detect when an unapproved build is running (OWASP MCP04/MCP09).
function _codeFingerprint() {
  try {
    const here = node_path__WEBPACK_IMPORTED_MODULE_2__.dirname((0,node_url__WEBPACK_IMPORTED_MODULE_3__.fileURLToPath)(import.meta.url));
    const files = ['server.js', 'tools.js', 'dataflow-tools.js', 'invariant-tools.js', 'portfolio-tools.js', 'stdio.js', 'audit.js', 'validate.js', 'redact.js'];
    const h = node_crypto__WEBPACK_IMPORTED_MODULE_1__.createHash('sha256');
    for (const f of files) {
      try { h.update(f); h.update(node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(node_path__WEBPACK_IMPORTED_MODULE_2__.join(here, f))); } catch {}
    }
    return h.digest('hex');
  } catch { return null; }
}
const CODE_FINGERPRINT = _codeFingerprint();

function _err(id, code, message, data) {
  const out = { jsonrpc: '2.0', id, error: { code, message } };
  if (data !== undefined) out.error.data = data;
  return out;
}

function _ok(id, result) {
  return { jsonrpc: '2.0', id, result };
}

// `capabilityPolicy` is `{ bound, binding }`, supplied by the operator from the
// capability manifest facility. Absent, and with the `capability-enforcement`
// feature off, the gate is inactive and behaviour is unchanged.
function createServer({ sessionRoot = process.cwd(), capabilityPolicy = null } = {}) {
  const ctx = { sessionRoot };
  const gate = (0,_capabilities_tool_gate_js__WEBPACK_IMPORTED_MODULE_6__/* .createToolGate */ .e)({ sessionRoot, policy: capabilityPolicy });

  async function handleRequest(msg) {
    if (!msg || typeof msg !== 'object') return _err(null, -32600, 'Invalid Request');
    if (msg.jsonrpc !== '2.0') return _err(msg.id ?? null, -32600, 'Invalid Request: jsonrpc must be "2.0"');

    const isNotification = msg.id === undefined || msg.id === null;
    const id = msg.id ?? null;
    const disabled = process.env.AGENTIC_SECURITY_MCP_DISABLED === '1';

    switch (msg.method) {
      case 'initialize':
        return _ok(id, {
          protocolVersion: PROTOCOL_VERSION,
          capabilities: { tools: {} },
          serverInfo: {
            name: SERVER_NAME,
            version: SERVER_VERSION,
            codeFingerprint: CODE_FINGERPRINT,
            disabled,
          },
        });

      case 'notifications/initialized':
        return null;

      case 'ping':
        return _ok(id, {});

      case 'tools/list':
        return _ok(id, {
          tools: _tools_js__WEBPACK_IMPORTED_MODULE_4__/* .ALL_TOOLS */ .Wi.map(t => ({
            name: t.name,
            description: t.description,
            inputSchema: t.inputSchema,
          })),
        });

      case 'tools/call': {
        const name = msg.params?.name;
        const args = msg.params?.arguments ?? {};
        if (disabled) {
          (0,_audit_js__WEBPACK_IMPORTED_MODULE_5__.auditCall)({ sessionRoot, tool: name, args, outcome: 'rejected', reason: 'server-disabled' });
          return _ok(id, {
            content: [{ type: 'text', text: 'MCP server is disabled (AGENTIC_SECURITY_MCP_DISABLED=1).' }],
            isError: true,
          });
        }
        const tool = TOOLS_BY_NAME[name];
        if (!tool) {
          (0,_audit_js__WEBPACK_IMPORTED_MODULE_5__.auditCall)({ sessionRoot, tool: name, args, outcome: 'rejected', reason: 'unknown-tool' });
          return _err(id, -32602, `Unknown tool: ${name}`);
        }
        // X-505: the capability check, for the task identity bound to this server.
        // An identity named in the request metadata can only be compared with it.
        const gated = gate.check(name, { claimedTaskId: msg.params?._meta?.taskId });
        if (!gated.allowed) {
          (0,_audit_js__WEBPACK_IMPORTED_MODULE_5__.auditCall)({ sessionRoot, tool: name, args, outcome: 'rejected', reason: `capability-denied: ${gated.code}` });
          const p = gated.proposal;
          return _ok(id, {
            content: [{ type: 'text', text: JSON.stringify({
              blocked: true, code: gated.code, reason: gated.reason, missing: gated.missing,
              proposedChange: p && p.proposable ? { review: p.review, change: p.change, nextPolicyVersion: p.nextPolicyVersion, requiresOperatorGrant: true } : null,
              attemptsRemaining: gated.attemptsRemaining, exhausted: gated.exhausted,
            }, null, 2) }],
            isError: true,
          });
        }
        try { (0,_validate_js__WEBPACK_IMPORTED_MODULE_7__/* .validate */ .t)(tool.inputSchema, args); }
        catch (e) {
          (0,_audit_js__WEBPACK_IMPORTED_MODULE_5__.auditCall)({ sessionRoot, tool: name, args, outcome: 'rejected', reason: `invalid-args: ${e.message}` });
          return _ok(id, {
            content: [{ type: 'text', text: `Invalid arguments: ${e.message}` }],
            isError: true,
          });
        }
        try {
          const result = await tool.handler(args, ctx);
          (0,_audit_js__WEBPACK_IMPORTED_MODULE_5__.auditCall)({ sessionRoot, tool: name, args, outcome: 'ok' });
          return _ok(id, {
            content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
            isError: false,
          });
        } catch (e) {
          (0,_audit_js__WEBPACK_IMPORTED_MODULE_5__.auditCall)({ sessionRoot, tool: name, args, outcome: 'error', reason: e.message });
          return _ok(id, {
            content: [{ type: 'text', text: `Error: ${e.message}` }],
            isError: true,
          });
        }
      }

      default:
        if (isNotification) return null;
        return _err(id, -32601, `Method not found: ${msg.method}`);
    }
  }

  return { handleRequest, sessionRoot, capabilityGate: gate };
}

// NOTE: no default-singleton export. Callers must use createServer({...})
// with an explicit sessionRoot. Removed because the prior default was bound
// to process.cwd() at module-load time — a footgun for any caller that
// imported `handleRequest` directly (OWASP A05).



__webpack_async_result__();
} catch(e) { __webpack_async_result__(e); } });

/***/ }),

/***/ 9560:
/***/ ((__webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.a(__webpack_module__, async (__webpack_handle_async_dependencies__, __webpack_async_result__) => { try {
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   runStdio: () => (/* binding */ runStdio)
/* harmony export */ });
/* harmony import */ var _server_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(27438);
var __webpack_async_dependencies__ = __webpack_handle_async_dependencies__([_server_js__WEBPACK_IMPORTED_MODULE_0__]);
_server_js__WEBPACK_IMPORTED_MODULE_0__ = (__webpack_async_dependencies__.then ? (await __webpack_async_dependencies__)() : __webpack_async_dependencies__)[0];
// Stdio transport for the MCP server — newline-delimited JSON in/out.
//
// MCP's stdio transport is NDJSON: one JSON-RPC message per line on stdin,
// one response per line on stdout. stderr is reserved for logging.
//
// Hardening:
//   - Per-message line cap (MAX_LINE_BYTES). A line over the cap is dropped
//     and the buffer state is reset so a long oversize payload can't peg
//     the parser via `buf += chunk` growth.
//   - Buffer hard cap (MAX_BUFFER_BYTES). Reached if input arrives with no
//     newlines (e.g., a peer streaming a 4GB stream of `a`). On overflow we
//     emit a parse-error response and reset.



const MAX_LINE_BYTES = 4 * 1024 * 1024;        // 4 MB per JSON-RPC message
const MAX_BUFFER_BYTES = 8 * 1024 * 1024;      // 8 MB sliding buffer

function runStdio({
  stdin = process.stdin,
  stdout = process.stdout,
  stderr = process.stderr,
  sessionRoot = process.cwd(),
} = {}) {
  const server = (0,_server_js__WEBPACK_IMPORTED_MODULE_0__/* .createServer */ .sA)({ sessionRoot });
  let buf = '';
  let overflowSkip = false; // true while we are dropping bytes until the next newline

  stdin.setEncoding('utf8');

  stdin.on('data', async (chunk) => {
    if (overflowSkip) {
      const nl = chunk.indexOf('\n');
      if (nl === -1) return;
      // Resume after the next newline.
      chunk = chunk.slice(nl + 1);
      overflowSkip = false;
    }

    buf += chunk;

    // Hard buffer cap — only triggers if a peer is streaming without newlines.
    if (buf.length > MAX_BUFFER_BYTES) {
      stderr.write(`mcp: input buffer exceeded ${MAX_BUFFER_BYTES} bytes — dropping until next newline\n`);
      const errResponse = { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error: input too large' } };
      stdout.write(JSON.stringify(errResponse) + '\n');
      buf = '';
      overflowSkip = true;
      return;
    }

    let nl;
    while ((nl = buf.indexOf('\n')) !== -1) {
      const line = buf.slice(0, nl).trim();
      buf = buf.slice(nl + 1);
      if (!line) continue;
      if (line.length > MAX_LINE_BYTES) {
        stderr.write(`mcp: dropped oversize line (${line.length} > ${MAX_LINE_BYTES} bytes)\n`);
        const errResponse = { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error: line too large' } };
        stdout.write(JSON.stringify(errResponse) + '\n');
        continue;
      }
      let msg;
      try { msg = JSON.parse(line); }
      catch (e) {
        stderr.write(`mcp: failed to parse line as JSON: ${e.message}\n`);
        const errResponse = { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } };
        stdout.write(JSON.stringify(errResponse) + '\n');
        continue;
      }
      try {
        const response = await server.handleRequest(msg);
        if (response !== null) stdout.write(JSON.stringify(response) + '\n');
      } catch (e) {
        stderr.write(`mcp: handler threw: ${e.message}\n`);
        const errResponse = { jsonrpc: '2.0', id: msg.id ?? null, error: { code: -32603, message: 'Internal error', data: e.message } };
        stdout.write(JSON.stringify(errResponse) + '\n');
      }
    }
  });

  stdin.on('end', () => { process.exit(0); });
}

__webpack_async_result__();
} catch(e) { __webpack_async_result__(e); } });

/***/ }),

/***/ 14054:
/***/ ((__webpack_module__, __webpack_exports__, __webpack_require__) => {

__webpack_require__.a(__webpack_module__, async (__webpack_handle_async_dependencies__, __webpack_async_result__) => { try {
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   Wi: () => (/* binding */ ALL_TOOLS)
/* harmony export */ });
/* unused harmony exports _internals, scan_diff, query_taint, explain_finding, apply_fix, verify_fix, synthesize_fix, find_rule_module, append_scratchpad, read_scratchpad, append_agents_memory, read_agents_memory, query_triage_memory, query_findings_memory, lookup_cve, query_cache_telemetry, synthesize_sca_upgrade, apply_sca_upgrade */
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(73024);
/* harmony import */ var node_fs_promises__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(51455);
/* harmony import */ var node_path__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(76760);
/* harmony import */ var node_crypto__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(77598);
/* harmony import */ var _posture_fix_history_js__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(84407);
/* harmony import */ var _fix_apply_fix_service_js__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(97730);
/* harmony import */ var _posture_material_change_js__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(74629);
/* harmony import */ var _fix_approver_registry_js__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(10437);
/* harmony import */ var _posture_deterministic_fix_js__WEBPACK_IMPORTED_MODULE_8__ = __webpack_require__(30413);
/* harmony import */ var _posture_integrity_js__WEBPACK_IMPORTED_MODULE_9__ = __webpack_require__(71130);
/* harmony import */ var _posture_state_dir_js__WEBPACK_IMPORTED_MODULE_10__ = __webpack_require__(31174);
/* harmony import */ var _posture_cache_economics_js__WEBPACK_IMPORTED_MODULE_11__ = __webpack_require__(58752);
/* harmony import */ var _redact_js__WEBPACK_IMPORTED_MODULE_19__ = __webpack_require__(83468);
/* harmony import */ var _report_index_js__WEBPACK_IMPORTED_MODULE_12__ = __webpack_require__(75917);
/* harmony import */ var _posture_verification_projection_js__WEBPACK_IMPORTED_MODULE_13__ = __webpack_require__(51864);
/* harmony import */ var _lineage_deployment_projection_js__WEBPACK_IMPORTED_MODULE_14__ = __webpack_require__(73596);
/* harmony import */ var _posture_provenance_schema_js__WEBPACK_IMPORTED_MODULE_15__ = __webpack_require__(34594);
/* harmony import */ var _dataflow_tools_js__WEBPACK_IMPORTED_MODULE_16__ = __webpack_require__(20095);
/* harmony import */ var _invariant_tools_js__WEBPACK_IMPORTED_MODULE_17__ = __webpack_require__(82407);
/* harmony import */ var _portfolio_tools_js__WEBPACK_IMPORTED_MODULE_18__ = __webpack_require__(99027);
/* harmony import */ var _posture_agents_memory_js__WEBPACK_IMPORTED_MODULE_20__ = __webpack_require__(79907);
/* harmony import */ var _posture_cve_lookup_js__WEBPACK_IMPORTED_MODULE_21__ = __webpack_require__(71364);
var __webpack_async_dependencies__ = __webpack_handle_async_dependencies__([_report_index_js__WEBPACK_IMPORTED_MODULE_12__]);
_report_index_js__WEBPACK_IMPORTED_MODULE_12__ = (__webpack_async_dependencies__.then ? (await __webpack_async_dependencies__)() : __webpack_async_dependencies__)[0];
// MCP tool implementations — PRD Feature 2, hardened against the OWASP MCP
// Top 10 (see ./redact.js, ./audit.js, ./server.js for sibling controls).
//
// Trust model:
//   - Session root fixed at server boot. No per-call retargeting.
//   - Path arguments lstat-checked (symlinks refused, OWASP MCP05) and
//     realpath-confined to session root.
//   - Tool outputs marked _meta.untrusted_excerpts:true (OWASP MCP03/MCP06)
//     because they may contain text from scanned files, which is adversary-
//     controlled in any context where the agent might read malicious code.
//   - Secret-shaped strings redacted on the way out (OWASP MCP01/MCP10).
//   - `apply_fix` requires confirm:true, valid HMAC signature on
//     last-scan.json, non-shadow finding, and confined file path.















// X-206: the one projection of the verification record, shared with the JSON report, the text report and the autopilot response.


// Git-origin provenance (Finding Provenance M0/M1). Distinct from
// `finding.provenance` (AI-authorship) and from an SCA entry's `provenance`
// (Sigstore/SLSA attestation) — see report/index.js's import comment.





// Lazy-loaded: these transitively pull in npm packages (@babel/core and
// friends) that aren't available in the plugin-cache install path
// (no node_modules). Deferring keeps the MCP server bootable everywhere;
// the import only runs when a tool that needs them is actually called.
let _runScan;
async function getRunScan() {
  if (!_runScan) _runScan = (await Promise.resolve(/* import() */).then(__webpack_require__.bind(__webpack_require__, 45950))).runScan;
  return _runScan;
}
let _verifyFixCore;
async function getVerifyFixCore() {
  if (!_verifyFixCore) _verifyFixCore = (await __webpack_require__.e(/* import() */ 7838).then(__webpack_require__.bind(__webpack_require__, 27838))).verifyFix;
  return _verifyFixCore;
}

const MAX_FILES_PER_SCAN = 1024;
const MAX_FILE_BYTES = 500_000;
const MAX_TOTAL_SCAN_BYTES = 50_000_000;
const META = { source: 'agentic-security-mcp', untrusted_excerpts: true };

// OWASP A01 — refuse writes to paths that could subvert the security tool
// itself or the host's source-control / dependency state. A forged finding
// could otherwise tell apply_fix to overwrite our own rules.yml, our audit
// log, a .git/hooks/post-commit payload, a CI workflow, an IaC file, or a
// dependency manifest (premortem #3 expansion).
//
// Two kinds of guard:
//   - DIR-prefix matches anywhere under one of these directories
//   - FILE-suffix matches any path whose basename ends with one of these
const RESERVED_WRITE_PREFIXES = [
  '.git/',
  '.github/',
  '.gitlab/',
  '.circleci/',
  '.buildkite/',
  '.agentic-security/',
  'node_modules/',
  '.terraform/',
  '.aws/',
  'k8s/',
  'kubernetes/',
];
const RESERVED_WRITE_BASENAMES = new Set([
  'Dockerfile',
  'Jenkinsfile',
  '.gitlab-ci.yml',
  '.gitlab-ci.yaml',
  'package.json',
  'package-lock.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'pyproject.toml',
  'Pipfile',
  'Pipfile.lock',
  'poetry.lock',
  'requirements.txt',
  'go.mod',
  'go.sum',
  'Cargo.toml',
  'Cargo.lock',
  'composer.json',
  'composer.lock',
  'Gemfile',
  'Gemfile.lock',
  'pom.xml',
  'build.gradle',
  'build.gradle.kts',
]);
const RESERVED_WRITE_SUFFIXES = [
  '.tf',
  '.tfvars',
  'docker-compose.yml',
  'docker-compose.yaml',
  // _CONFINEMENT rule 3 — backup and lock files. The specific lock BASENAMES
  // above cover the ecosystems we know; this catches the rest (`deps.lock`,
  // `foo.bak`) without needing to enumerate them. Nothing an autofix should
  // ever be rewriting: a `.bak` is someone's safety copy and a `.lock` is
  // generated state.
  '.bak',
  '.lock',
];
// _CONFINEMENT rule 3 — build output. Matched as a PATH SEGMENT at any depth,
// not as a top-level prefix, because build output is routinely nested
// (`packages/web/dist/`, `services/api/target/`) and a top-level-only check
// would refuse the monorepo root and allow every package inside it.
//
// This matters most in THIS repository: `scanner/dist/` holds the shipped
// bundle, which carries its own SHA-256 integrity sidecar precisely because
// what it contains matters. Before this, `apply_fix` would rewrite it and
// report success.
//
// NOTE for a future change, deliberately not made here: the PREFIX list above
// (`node_modules/`, `.git/`, …) is still top-level-only, so a nested
// `packages/a/node_modules/` is not covered by it. That is a separate widening
// with its own blast radius and belongs in its own change with its own tests.
const RESERVED_WRITE_DIR_SEGMENTS = new Set(['dist', 'build', 'target']);
function _isReservedWritePath(sessionRoot, absFile) {
  // Resolve sessionRoot symlinks so the relative path is computed against
  // the same canonical root as `absFile` (which _confine already realpath'd).
  // On macOS /tmp → /private/tmp; without this normalization the relative
  // would contain "../" and the prefix check would miss the reserved path.
  const rootReal = node_fs__WEBPACK_IMPORTED_MODULE_0__.realpathSync(node_path__WEBPACK_IMPORTED_MODULE_2__.resolve(sessionRoot));
  const rel = node_path__WEBPACK_IMPORTED_MODULE_2__.relative(rootReal, absFile).replace(/\\/g, '/');
  if (RESERVED_WRITE_PREFIXES.some(p => rel === p.replace(/\/$/, '') || rel.startsWith(p))) return true;
  const segments = rel.split('/');
  const base = segments[segments.length - 1] || '';
  if (RESERVED_WRITE_BASENAMES.has(base)) return true;
  if (RESERVED_WRITE_SUFFIXES.some(s => base === s || base.endsWith(s))) return true;
  // Any DIRECTORY segment that names build output — checked over
  // `segments.length - 1` so a source file legitimately called `build` or
  // `dist` is not refused for its own name; only living inside such a
  // directory counts.
  if (segments.slice(0, -1).some(seg => RESERVED_WRITE_DIR_SEGMENTS.has(seg))) return true;
  return false;
}

// LangChain harness-anatomy recommendation: the filesystem is the right
// collaboration / scratchpad surface for subagents. We carve out one writable
// directory inside the otherwise-reserved `.agentic-security/` tree —
// `.agentic-security/agent-scratchpad/<agent>/<session>/` — and expose
// `append_scratchpad` / `read_scratchpad` for in-progress agent state.
//
// Confinement rules:
//   - relative path required (no absolute / no `..`)
//   - must start with `agent-scratchpad/<agent>/<session>/`
//   - `<agent>` and `<session>` are restricted to `[A-Za-z0-9_.-]{1,64}`
//     (no slashes — keeps the prefix exactly three components deep)
//   - file basename: same charset rules
//   - max scratchpad bytes per file: SCRATCHPAD_MAX_FILE_BYTES
const SCRATCHPAD_PREFIX = '.agentic-security/agent-scratchpad/';
const SCRATCHPAD_NAME_RE = /^[A-Za-z0-9_.-]{1,64}$/;
const SCRATCHPAD_MAX_FILE_BYTES = 2 * 1024 * 1024;   // 2 MB per file
const SCRATCHPAD_MAX_TOTAL_BYTES = 50 * 1024 * 1024; // 50 MB per scan root

function _validateScratchpadPath(relPath) {
  if (typeof relPath !== 'string' || !relPath.length) {
    return { ok: false, reason: 'path: not a string' };
  }
  if (node_path__WEBPACK_IMPORTED_MODULE_2__.isAbsolute(relPath)) return { ok: false, reason: 'path: must be relative' };
  if (relPath.includes('..')) return { ok: false, reason: 'path: must not contain ..' };
  const normalized = relPath.replace(/\\/g, '/');
  if (!normalized.startsWith(SCRATCHPAD_PREFIX)) {
    return { ok: false, reason: `path: must start with "${SCRATCHPAD_PREFIX}"` };
  }
  const rest = normalized.slice(SCRATCHPAD_PREFIX.length);
  const parts = rest.split('/');
  if (parts.length < 3) {
    return { ok: false, reason: 'path: must be agent-scratchpad/<agent>/<session>/<file>' };
  }
  const [agent, session, ...fileParts] = parts;
  if (!SCRATCHPAD_NAME_RE.test(agent)) return { ok: false, reason: `path: agent name "${agent}" not in [A-Za-z0-9_.-]{1,64}` };
  if (!SCRATCHPAD_NAME_RE.test(session)) return { ok: false, reason: `path: session id "${session}" not in [A-Za-z0-9_.-]{1,64}` };
  for (const p of fileParts) {
    if (!SCRATCHPAD_NAME_RE.test(p)) return { ok: false, reason: `path: file part "${p}" not in [A-Za-z0-9_.-]{1,64}` };
  }
  return { ok: true, agent, session, fileParts };
}

// Routes through the same lstat+realpath confinement every other write/
// path-taking tool uses (OWASP MCP05) — a lexical prefix/charset check
// alone doesn't stop a pre-planted symlink at any path component from
// relocating the write/read outside the session root. Throws on escape;
// callers must catch (see append_scratchpad / read_scratchpad).
function _scratchpadAbs(sessionRoot, relPath) {
  return _confine(sessionRoot, relPath.replace(/\\/g, '/'), 'scratchpad path');
}

function _scratchpadTotalBytes(sessionRoot) {
  const base = (0,_posture_state_dir_js__WEBPACK_IMPORTED_MODULE_10__.statePath)(sessionRoot, 'agent-scratchpad');
  if (!node_fs__WEBPACK_IMPORTED_MODULE_0__.existsSync(base)) return 0;
  let total = 0;
  const walk = (dir) => {
    let entries;
    try { entries = node_fs__WEBPACK_IMPORTED_MODULE_0__.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const fp = node_path__WEBPACK_IMPORTED_MODULE_2__.join(dir, e.name);
      try {
        if (e.isFile()) { total += node_fs__WEBPACK_IMPORTED_MODULE_0__.statSync(fp).size; }
        else if (e.isDirectory()) walk(fp);
      } catch { /* skip */ }
    }
  };
  walk(base);
  return total;
}

// ─── Path confinement ────────────────────────────────────────────────────────
// Lexical check + lstat symlink reject + realpath re-check. OWASP MCP05.
//
// For non-existent paths (apply_fix to a new file is a possible legitimate
// case; in practice we re-check existence at the use-site) we walk up the
// deepest existing ancestor and realpath that, so a parent-symlink can't
// silently relocate writes.
function _confine(sessionRoot, candidate, label) {
  if (typeof candidate !== 'string' || !candidate) throw new Error(`${label}: not a string`);
  const rootReal = node_fs__WEBPACK_IMPORTED_MODULE_0__.realpathSync(node_path__WEBPACK_IMPORTED_MODULE_2__.resolve(sessionRoot));
  const abs = node_path__WEBPACK_IMPORTED_MODULE_2__.isAbsolute(candidate) ? candidate : node_path__WEBPACK_IMPORTED_MODULE_2__.resolve(rootReal, candidate);

  // Lexical pre-check: rejects "../../etc/passwd" before any fs call.
  const relLex = node_path__WEBPACK_IMPORTED_MODULE_2__.relative(rootReal, node_path__WEBPACK_IMPORTED_MODULE_2__.resolve(abs));
  if (relLex === '' || relLex.startsWith('..') || node_path__WEBPACK_IMPORTED_MODULE_2__.isAbsolute(relLex)) {
    throw new Error(`${label}: path "${candidate}" escapes session root`);
  }

  // If the path exists, the leaf must not be a symlink and its realpath
  // must still be under rootReal.
  if (node_fs__WEBPACK_IMPORTED_MODULE_0__.existsSync(abs)) {
    if (node_fs__WEBPACK_IMPORTED_MODULE_0__.lstatSync(abs).isSymbolicLink()) {
      throw new Error(`${label}: path "${candidate}" is a symbolic link (refused)`);
    }
    const real = node_fs__WEBPACK_IMPORTED_MODULE_0__.realpathSync(abs);
    if (node_path__WEBPACK_IMPORTED_MODULE_2__.relative(rootReal, real).startsWith('..')) {
      throw new Error(`${label}: path "${candidate}" resolves outside session root via symlink`);
    }
    return real;
  }

  // Path doesn't exist — walk up to the deepest existing ancestor and
  // realpath that. If a parent dir is a symlink pointing outside rootReal
  // we catch it here.
  let parent = node_path__WEBPACK_IMPORTED_MODULE_2__.dirname(abs);
  while (parent !== node_path__WEBPACK_IMPORTED_MODULE_2__.dirname(parent) && !node_fs__WEBPACK_IMPORTED_MODULE_0__.existsSync(parent)) {
    parent = node_path__WEBPACK_IMPORTED_MODULE_2__.dirname(parent);
  }
  const parentReal = node_fs__WEBPACK_IMPORTED_MODULE_0__.realpathSync(parent);
  if (node_path__WEBPACK_IMPORTED_MODULE_2__.relative(rootReal, parentReal).startsWith('..')) {
    throw new Error(`${label}: path "${candidate}" parent resolves outside session root`);
  }
  const suffix = node_path__WEBPACK_IMPORTED_MODULE_2__.relative(parent, abs);
  return node_path__WEBPACK_IMPORTED_MODULE_2__.resolve(parentReal, suffix);
}

function _readLastScanVerified(sessionRoot, { allowUnsigned = false } = {}) {
  const stateDirPath = (0,_posture_state_dir_js__WEBPACK_IMPORTED_MODULE_10__/* .stateDir */ .Pn)(sessionRoot);
  const scanFile = node_path__WEBPACK_IMPORTED_MODULE_2__.join(stateDirPath, 'last-scan.json');
  const sigFile = scanFile + '.sig';
  if (!node_fs__WEBPACK_IMPORTED_MODULE_0__.existsSync(scanFile)) return { scan: null, status: 'missing' };
  const body = node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(scanFile, 'utf8');
  const ok = (0,_posture_integrity_js__WEBPACK_IMPORTED_MODULE_9__/* .verifyLastScan */ .Ef)(body, sigFile);
  if (ok === false) return { scan: null, status: 'tampered' };
  if (ok === null && !allowUnsigned) return { scan: null, status: 'unsigned' };
  let parsed;
  try { parsed = JSON.parse(body); }
  catch { return { scan: null, status: 'unparseable' }; }
  return { scan: parsed, status: ok ? 'verified' : 'unsigned' };
}

function _findById(scan, id) {
  if (!scan) return null;
  return (scan.findings || []).find(f => f.id === id)
      || (scan.secrets || []).find(f => f.id === id)
      || (scan.supplyChain || []).find(f => f.id === id)
      || (scan.logicVulns || []).find(f => f.id === id)
      || null;
}

// ─── Tool-output offloading (harness-anatomy #1) ────────────────────────────
// LangChain post: "the harness keeps the head and tail tokens of tool outputs
// above a threshold number of tokens and offloads the full output to the
// filesystem." We apply this to any MCP tool response whose findings array
// exceeds OFFLOAD_THRESHOLD entries: write the full list to a scratchpad
// file, return only head[0..3] + tail[-2..] + total + path. The agent can
// call `read_scratchpad(path)` to page through the rest.
//
// Design choices:
//   - Threshold is conservative (10) — anything bigger than a casual UI page
//     gets offloaded. Tunable via $AGENTIC_SECURITY_MCP_OFFLOAD_THRESHOLD.
//   - Offload location is the agent-scratchpad (not a separate dir) so the
//     same cleanup + size caps apply.
//   - File names are deterministic per response (sha256 of JSON.stringify)
//     so two identical responses share the same offload file.
//   - The session id is process.pid + boot timestamp short hash — collides
//     only across restarts within a millisecond, which is fine for cache.
const OFFLOAD_THRESHOLD = (() => {
  const v = parseInt(process.env.AGENTIC_SECURITY_MCP_OFFLOAD_THRESHOLD || '10', 10);
  return Number.isFinite(v) && v >= 1 ? v : 10;
})();
const MCP_SESSION_ID = `${process.pid}-${Date.now().toString(36).slice(-6)}`;

function _maybeOffload(sessionRoot, toolName, items) {
  if (!Array.isArray(items) || items.length <= OFFLOAD_THRESHOLD) {
    return { offloaded: false, items, total: items.length };
  }
  const head = items.slice(0, 3);
  const tail = items.slice(-2);
  const json = JSON.stringify({ tool: toolName, total: items.length, items }, null, 2);
  const hashShort = node_crypto__WEBPACK_IMPORTED_MODULE_3__.createHash('sha256').update(json).digest('hex').slice(0, 10);
  const rel = `.agentic-security/agent-scratchpad/mcp-offload/${MCP_SESSION_ID}/${toolName}-${hashShort}.json`;
  const abs = node_path__WEBPACK_IMPORTED_MODULE_2__.resolve(sessionRoot, rel);
  try {
    node_fs__WEBPACK_IMPORTED_MODULE_0__.mkdirSync(node_path__WEBPACK_IMPORTED_MODULE_2__.dirname(abs), { recursive: true });
    node_fs__WEBPACK_IMPORTED_MODULE_0__.writeFileSync(abs, json);
  } catch (e) {
    // If we can't write to disk for some reason, fall back to returning
    // everything — the alternative would be silently dropping data, which
    // is worse than blowing the context.
    return { offloaded: false, items, total: items.length, offloadError: e.message };
  }
  return {
    offloaded: true,
    head, tail, total: items.length,
    scratchpadPath: rel,
    pagingHint: `call read_scratchpad({ path: "${rel}", offset, limit }) to page through; the file is { tool, total, items: [...] } JSON`,
  };
}

// ─── scan_diff ───────────────────────────────────────────────────────────────
// Test seam for the write boundary (PRD F6.4).
//
// `_confine` and `isReservedWrite` ARE the confinement contract in
// agents/_CONFINEMENT.md. A boundary is only worth what its refusals are worth,
// and refusals cannot be adversarially tested through the public tools without
// also exercising a real scan, a real patch and a real filesystem write — so
// the check would be measuring four things and attributing failure to one.
//
// Exported under the `_internals` convention this codebase already uses
// (see posture/poc-inprocess.js). Not part of the MCP tool surface.
const _internals = { _confine, isReservedWrite: _isReservedWritePath, checkMultiFileTargets: _checkMultiFileTargets, multiFilePlanDigest: _multiFilePlanDigest };

const scan_diff = {
  name: 'scan_diff',
  description: 'Scan a list of files for security findings. Use BEFORE writing a Write/Edit to disk so the agent can self-correct. Returns findings with severity, file:line, title, remediation. Snippets are redacted of obvious secret patterns. Paths confined to the session root; symlinks are refused.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      files: {
        type: 'array', minItems: 1, maxItems: MAX_FILES_PER_SCAN,
        items: { type: 'string', minLength: 1, maxLength: 4096 },
      },
      severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] },
    },
    required: ['files'],
  },
  async handler({ files, severity }, ctx) {
    const sessionRoot = ctx.sessionRoot;
    const abs = files.map(f => _confine(sessionRoot, f, 'files[]'));

    const fileContents = {};
    // `_confine` returns real paths; the session root may itself be a symlink (macOS /tmp, /var), so keys are made
    // relative to the REAL root. A key built from the unresolved root climbs out of the tree and no finding ever
    // matches the file it was asked about.
    const rootReal = node_fs__WEBPACK_IMPORTED_MODULE_0__.realpathSync(node_path__WEBPACK_IMPORTED_MODULE_2__.resolve(sessionRoot));
    let totalBytes = 0;
    for (const a of abs) {
      let stat;
      try { stat = node_fs__WEBPACK_IMPORTED_MODULE_0__.statSync(a); } catch { continue; }
      if (!stat.isFile()) continue;
      if (stat.size > MAX_FILE_BYTES) continue;
      totalBytes += stat.size;
      if (totalBytes > MAX_TOTAL_SCAN_BYTES) {
        throw new Error(`scan_diff: total scan size exceeds ${MAX_TOTAL_SCAN_BYTES} bytes`);
      }
      let content;
      try { content = node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(a, 'utf8'); } catch { continue; }
      const rel = node_path__WEBPACK_IMPORTED_MODULE_2__.relative(rootReal, a).replace(/\\/g, '/');
      fileContents[rel] = content;
    }

    // PRD R1 (docs/DETECTION_GAP_REMEDIATION_PRD.md): deep mode is default-on
    // for the interactive CLI scan but was never requested here, so an
    // agent's pre-write self-correction scan was regex/AST-only — blind to
    // any bug whose source and sink are connected only through a call
    // (`fileContents` scopes the deep engine's IR to exactly the files
    // passed in, same bound this tool already enforces via MAX_FILES_PER_SCAN
    // / MAX_TOTAL_SCAN_BYTES, so this does not turn scan_diff into a
    // full-project deep scan).
    const runScan = await getRunScan();
    // FR-704 (assurance-hardening PRD): this tool's own description promises
    // "runs scan in memory" — without this, runFullScan's own state writers
    // (dpia.md, ropa.md, privacy-framework.json, threat-model.json, and
    // others) fire unconditionally on every call, silently mutating the
    // user's real project on every pre-write self-correction scan. Confirmed
    // by direct execution before this fix (11 state artifacts written by a
    // single scan_diff-shaped call).
    // Haskell and Nix results depend on imported modules and manifests, so the files asked about are scanned together
    // with their import closure (read from disk, bounded). Findings are still reported only for the requested files.
    const wantSet = new Set(Object.keys(fileContents));
    const { withLanguageContext } = await Promise.resolve(/* import() */).then(__webpack_require__.bind(__webpack_require__, 52603));
    const lc = withLanguageContext(sessionRoot, fileContents, {});
    const result = await (0,_posture_state_dir_js__WEBPACK_IMPORTED_MODULE_10__/* .withStateWritesDisabled */ .Ao)(() =>
      runScan(sessionRoot, { network: false, fileContents: lc.fileContents, depFileContents: lc.depFileContents, deep: true, deepInCi: true }));
    const sevRank = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
    const min = sevRank[severity] ?? 0;
    // Stage 6 correctness audit (historical): this used to only read
    // result.scan.findings (the SAST channel) — scan.secrets and
    // scan.logicVulns are separate arrays on the raw runScan() result, and a
    // hand-rolled 3-channel concat here was a second, divergent copy of the
    // merge report/index.js's normalizeFindings() already does (four
    // channels, plus per-channel defaulting and remediation-string
    // resolution the old concat re-implemented separately and could drift
    // from). Assurance-hardening PRD FR-105 ("JSON, SARIF, HTML, CSV, JUnit,
    // and MCP outputs derive from the same validated object"): route through
    // the same canonical merge every other output format uses.
    //
    // This closes the field-mapping/dedup divergence, but does NOT make
    // scan_diff surface SCA/supply-chain findings end to end: this handler
    // never builds a `depFileContents` map (everything a caller passes in
    // `files`, manifests included, lands in `fileContents`), and manifest-
    // based supply-chain detection in engine.js reads only `depFileContents`
    // — so `result.scan.supplyChain` is always empty for this tool today
    // regardless of this fix. That is a separate, real limitation (scan_diff
    // was designed for pre-write code self-correction, not manifest
    // scanning), left as-is rather than silently claimed fixed here.
    const findings = (0,_report_index_js__WEBPACK_IMPORTED_MODULE_12__.normalizeFindings)(result.scan)
      .filter(f => wantSet.has(String(f.file || '').replace(/\\/g, '/')) && (sevRank[f.severity] ?? 0) >= min)
      .map(f => (0,_redact_js__WEBPACK_IMPORTED_MODULE_19__/* .redactFinding */ .lE)({
        id: f.id, severity: f.severity, file: f.file, line: f.line,
        title: f.vuln, cwe: f.cwe,
        description: f.description, remediation: f.remediation,
      }));
    // Harness-anatomy #1: offload when the result exceeds OFFLOAD_THRESHOLD.
    // The agent gets a head+tail preview plus a path it can page through;
    // the full finding list lives on disk. This is the documented fix for
    // "context rot" — large tool outputs eat the model's attention budget.
    const off = _maybeOffload(sessionRoot, 'scan_diff', findings);
    if (off.offloaded) {
      return {
        _meta: META,
        scannedFiles: Object.keys(fileContents).length,
        findingCount: off.total,
        offloaded: true,
        head: off.head, tail: off.tail,
        scratchpadPath: off.scratchpadPath,
        pagingHint: off.pagingHint,
      };
    }
    return {
      _meta: META,
      scannedFiles: Object.keys(fileContents).length,
      findingCount: findings.length,
      findings,
    };
  },
};

// ─── query_taint ─────────────────────────────────────────────────────────────
const query_taint = {
  name: 'query_taint',
  description: 'Query whether the last verified scan found a taint path involving a given source and sink. Paginated — returns up to `limit` matches (default 10, max 50) starting at `offset` (default 0); set `truncated:true` and `totalMatches` tell you when to page.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      source: { type: 'string', minLength: 1, maxLength: 256 },
      sink: { type: 'string', minLength: 1, maxLength: 256 },
      limit: { type: 'integer', minimum: 1, maximum: 50 },
      offset: { type: 'integer', minimum: 0, maximum: 10000 },
    },
    required: ['source', 'sink'],
  },
  async handler({ source, sink, limit, offset }, ctx) {
    const { scan, status } = _readLastScanVerified(ctx.sessionRoot, { allowUnsigned: true });
    if (!scan) {
      return { _meta: META, hasResult: false, status, message: `No usable scan state (${status}).` };
    }
    const lim = Number.isInteger(limit) ? Math.min(50, Math.max(1, limit)) : 10;
    const off = Number.isInteger(offset) ? Math.max(0, offset) : 0;
    const srcL = String(source).toLowerCase();
    const sinkL = String(sink).toLowerCase();
    // Filter first (cheap), then paginate (so totalMatches is accurate).
    // Harness-engineering note (post-derived): "context window != context
    // attention." Returning hundreds of matches to the agent in one shot
    // dilutes its reasoning; the agent receives a bounded slice plus the
    // cursor to fetch the rest if it wants.
    const all = (scan.findings || []).filter(f => {
      const hay = [f.description, f.title, f.vuln, f.snippet, JSON.stringify(f.trace || '')].join(' ').toLowerCase();
      return hay.includes(srcL) && hay.includes(sinkL);
    });
    const page = all.slice(off, off + lim).map(f => (0,_redact_js__WEBPACK_IMPORTED_MODULE_19__/* .redactFinding */ .lE)({
      id: f.id, severity: f.severity, file: f.file, line: f.line,
      title: f.title || f.vuln, description: f.description,
      trace: f.trace || null,
    }));
    return {
      _meta: META,
      hasResult: true,
      integrity: status,
      scanStartedAt: scan.startedAt || scan.meta?.startedAt || null,
      totalMatches: all.length,
      matchCount: page.length,
      offset: off,
      limit: lim,
      truncated: off + page.length < all.length,
      nextOffset: off + page.length < all.length ? off + page.length : null,
      matches: page,
    };
  },
};

// ─── explain_finding ─────────────────────────────────────────────────────────
const explain_finding = {
  name: 'explain_finding',
  description: 'Return full details for a single finding from the last verified scan. Snippet/description redacted of secret patterns.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      finding_id: { type: 'string', minLength: 1, maxLength: 256 },
    },
    required: ['finding_id'],
  },
  async handler({ finding_id }, ctx) {
    const { scan, status } = _readLastScanVerified(ctx.sessionRoot, { allowUnsigned: true });
    if (!scan) throw new Error(`No usable scan state (${status}).`);
    const f = _findById(scan, finding_id);
    if (!f) throw new Error(`Finding not found: ${finding_id}`);
    const redacted = (0,_redact_js__WEBPACK_IMPORTED_MODULE_19__/* .redactFinding */ .lE)({
      id: f.id, severity: f.severity, file: f.file, line: f.line,
      title: f.title || f.vuln, cwe: f.cwe,
      description: f.description, remediation: f.remediation,
      snippet: f.snippet || null,
      trace: f.trace || null,
    });
    // Harness-anatomy #1: explain_finding's trace is the most-likely-large
    // field on a single finding. Offload when it crosses the threshold so
    // the agent gets a head/tail preview, not a 50-step trace dumped into
    // its context.
    let traceTrimmed = redacted.trace;
    let traceMeta = null;
    if (Array.isArray(redacted.trace) && redacted.trace.length > OFFLOAD_THRESHOLD) {
      const off = _maybeOffload(ctx.sessionRoot, 'explain_finding-trace', redacted.trace);
      if (off.offloaded) {
        traceTrimmed = [...off.head, { _gap: `... ${off.total - off.head.length - off.tail.length} more steps elided; read scratchpad ...` }, ...off.tail];
        traceMeta = {
          totalSteps: off.total,
          scratchpadPath: off.scratchpadPath,
          pagingHint: off.pagingHint,
        };
      }
    }
    return {
      _meta: META,
      ...redacted,
      trace: traceTrimmed,
      traceOffload: traceMeta,
      confidence: f.confidence ?? null,
      hasReplacementFix: typeof f.fix?.replacement === 'string',
      integrity: status,
      // Risk-signal passthrough so agents can decide priority without
      // re-reading last-scan.json or re-fetching OSV/KEV/EPSS. compositeRisk
      // is the canonical sort key; the other fields are its provenance.
      compositeRisk: f.compositeRisk ?? null,
      compositeRiskTier: f.compositeRiskTier ?? null,
      compositeRiskFactors: Array.isArray(f.compositeRiskFactors) ? f.compositeRiskFactors : [],
      exploitability: f.exploitability ?? null,
      exploitabilityTier: f.exploitabilityTier ?? null,
      mitigationVerdict: f.mitigationVerdict ?? null,
      kev: !!(f.kev || f.kevListed || f.weaponized),
      epssScore: typeof f.epssScore === 'number' ? f.epssScore : null,
      epssPercentile: typeof f.epssPercentile === 'number' ? f.epssPercentile : null,
      exploitedNow: !!f.exploitedNow,
      // Which commit introduced this finding. `includeEmail` stays at its
      // DEFAULT (false) unconditionally — unlike the JSON report there is no
      // operator-set env escape for it here, because the consumer is an
      // agent that has no business receiving a committer's email address.
      // `pseudonymize`, by contrast, IS read back from the same env var
      // report/index.js's `_normalizedProvenance` reads
      // (AGENTIC_SECURITY_PSEUDONYMIZE_AUTHORS=1 / --pseudonymize-authors) —
      // fix-round item 4: an operator who set that policy was still getting
      // raw committer names (and, via providerEnrichment, raw reviewer
      // logins/CODEOWNERS lines) through this MCP surface because this call
      // passed no options object at all, silently defeating their policy at
      // this one output boundary while report/index.js honoured it.
      findingProvenance: f.findingProvenance ? (0,_posture_provenance_schema_js__WEBPACK_IMPORTED_MODULE_15__/* .redactFindingProvenance */ .As)(f.findingProvenance, {
        pseudonymize: process.env.AGENTIC_SECURITY_PSEUDONYMIZE_AUTHORS === '1',
      }) : null,
      // X-206: the same verification projection the JSON and text reports carry; absent when the finding has no record.
      ...(f.verificationRecord && typeof f.verificationRecord === 'object'
        ? { verificationRecord: f.verificationRecord, ...(0,_posture_verification_projection_js__WEBPACK_IMPORTED_MODULE_13__/* .verificationFields */ .ze)(f.verificationRecord, { replay: f.verificationReplay }) }
        : {}),
      // X-307: the same boundary projection the JSON and text reports carry; absent when the finding has no context.
      ...(f.boundaryContext && typeof f.boundaryContext === 'object'
        ? (0,_lineage_deployment_projection_js__WEBPACK_IMPORTED_MODULE_14__/* .boundaryFields */ .Q)(f.boundaryContext)
        : {}),
    };
  },
};

// FR-307/FR-1002/FR-1003: the high-impact-change approval gate (approval evidence, approver identity, separation of duties),
// shared by the caller-patch branch and the multi-file plan branch so the two cannot drift. Returns a refusal result, or null
// when the change is not high-impact or is properly approved.
function _highImpactApprovalRefusal(ctx, materialClassification, fixMeta) {
  if (!materialClassification.highImpactCategories.length) return null;
  const cats = materialClassification.highImpactCategories.join(', ');
  const approval = fixMeta && typeof fixMeta === 'object' ? fixMeta.approval : null;
  const hasApprovalEvidence = !!(approval && typeof approval === 'object' &&
    typeof approval.approvedBy === 'string' && approval.approvedBy.trim().length > 0 &&
    typeof approval.reason === 'string' && approval.reason.trim().length > 0);
  if (!hasApprovalEvidence) {
    return {
      _meta: META, applied: false,
      reason: `high-impact change (${cats}) requires approval evidence — pass fixMeta.approval: {approvedBy, reason} — before it can be applied`,
      materialClassification,
    };
  }
  const approverRegistry = (0,_fix_approver_registry_js__WEBPACK_IMPORTED_MODULE_7__.loadApproverRegistry)(ctx.sessionRoot);
  const requiredRoles = (0,_fix_approver_registry_js__WEBPACK_IMPORTED_MODULE_7__/* .requiredRolesFor */ .K)(approverRegistry, materialClassification.highImpactCategories);
  const identityCheck = (0,_fix_approver_registry_js__WEBPACK_IMPORTED_MODULE_7__.verifyApprover)(approverRegistry, approval.approvedBy, requiredRoles);
  if (!identityCheck.verified) {
    return { _meta: META, applied: false, reason: `high-impact change (${cats}) approval rejected: ${identityCheck.reason}`, materialClassification };
  }
  // FR-1003: separation-of-duties, same no-op-unless-configured gate as apply-fix-service.js's own copy; see approver-registry.js.
  const sodCheck = (0,_fix_approver_registry_js__WEBPACK_IMPORTED_MODULE_7__.checkSeparationOfDuties)(approverRegistry, fixMeta?.author, approval.approvedBy);
  if (!sodCheck.ok) {
    return { _meta: META, applied: false, reason: `high-impact change (${cats}) approval rejected: ${sodCheck.reason}`, materialClassification };
  }
  return null;
}

// ─── Multi-file plans (apply_fix with plan_digest) ───────────────────────────
// A NixOS option fix can edit several files at once (every definition at the winning priority). apply_fix never accepts file
// contents for this: it RECOMPUTES the plan from the signed finding and the live tree, and writes only if that plan's digest is
// the one synthesize_fix returned. The digest binds the finding, every file path, the exact pre-image and the exact post-image
// of each edit, so a changed tree, a changed finding, or an altered digest all refuse. The write itself is the language
// lifecycle's all-or-nothing writeManyWithBackup (one backup per file, one history group, honest rollback).
const MULTI_FILE_MAX = 8;
const _sha256 = (t) => node_crypto__WEBPACK_IMPORTED_MODULE_3__.createHash('sha256').update(String(t), 'utf8').digest('hex');
function _multiFilePlanDigest(finding, edits) {
  const canon = edits.map((e) => ({ file: String(e.file), before: _sha256(e.before), after: _sha256(e.after) })).sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : 0));
  return _sha256(JSON.stringify({ v: 'mf-plan/1', id: finding.id || null, stableId: finding.stableId || null, edits: canon }));
}
// Every file of a multi-file plan gets the SAME checks a single-file apply_fix target gets: root-relative lexical form,
// confinement (no symlink leaf, no symlinked parent, no escape), reserved-write list, and existence. Returns {ok, reason, abs}.
function _checkMultiFileTargets(sessionRoot, edits) {
  if (!Array.isArray(edits) || edits.length < 2) return { ok: false, reason: 'a multi-file plan needs at least two edits' };
  if (edits.length > MULTI_FILE_MAX) return { ok: false, reason: `a multi-file plan may edit at most ${MULTI_FILE_MAX} files` };
  const rootReal = node_fs__WEBPACK_IMPORTED_MODULE_0__.realpathSync(node_path__WEBPACK_IMPORTED_MODULE_2__.resolve(sessionRoot));
  const seen = new Set();
  const abs = {};
  for (const e of edits) {
    const rel = e && e.file;
    if (typeof rel !== 'string' || !rel || rel.includes('\0') || rel.includes('\\') || node_path__WEBPACK_IMPORTED_MODULE_2__.isAbsolute(rel) || rel.split('/').some((seg) => seg === '..' || seg === '.' || seg === '')) {
      return { ok: false, reason: `path-escape refused: plan file "${node_path__WEBPACK_IMPORTED_MODULE_2__.isAbsolute(String(rel)) ? '(absolute path)' : String(rel).slice(0, 120)}" is not a clean root-relative path` };
    }
    if (seen.has(rel)) return { ok: false, reason: `the same file appears twice in the plan: ${rel}` };
    seen.add(rel);
    let real;
    try { real = _confine(sessionRoot, rel, 'plan file'); }
    catch (err) { return { ok: false, reason: `path-escape refused: ${String(err.message).split(rootReal).join('<root>')}` }; }
    if (node_path__WEBPACK_IMPORTED_MODULE_2__.relative(rootReal, real).split(node_path__WEBPACK_IMPORTED_MODULE_2__.sep).join('/') !== rel) return { ok: false, reason: `path-escape refused: plan file "${rel}" resolves through a symbolic link` };
    if (_isReservedWritePath(sessionRoot, real)) return { ok: false, reason: `reserved path refused: ${rel}` };
    if (!node_fs__WEBPACK_IMPORTED_MODULE_0__.existsSync(real)) return { ok: false, reason: `plan file not found: ${rel}` };
    abs[rel] = real;
  }
  return { ok: true, abs };
}
const _scrubRoot = (sessionRoot, text) => {
  let out = String(text);
  const roots = new Set([node_path__WEBPACK_IMPORTED_MODULE_2__.resolve(sessionRoot)]);
  try { roots.add(node_fs__WEBPACK_IMPORTED_MODULE_0__.realpathSync(node_path__WEBPACK_IMPORTED_MODULE_2__.resolve(sessionRoot))); } catch { /* root vanished: the plain path is still scrubbed */ }
  for (const r of roots) out = out.split(r).join('<root>');
  return (0,_redact_js__WEBPACK_IMPORTED_MODULE_19__/* .redactString */ .rd)(out);
};
const _gateSummary = (g) => (g ? {
  path: g.path ? g.path.ok : undefined, syntax: g.syntax ? g.syntax.ok : undefined,
  rescan: g.rescan ? { ok: g.rescan.ok, originalGone: g.rescan.originalGone, newMediumOrHigher: g.rescan.newMediumOrHigher } : undefined,
  effective: g.effective ? { ok: g.effective.ok, ran: g.effective.ran === true, detail: g.effective.detail } : undefined,
  compile: g.compile ? { ran: g.compile.ran === true, ok: g.compile.ok } : undefined,
} : null);

async function _applyMultiFilePlan({ f, planDigest, dryRun, fixMeta, ctx, status }) {
  const refuse = (reason, extra = {}) => ({ _meta: META, applied: false, multiFile: true, reason, ...extra });
  if (typeof planDigest !== 'string' || !/^[0-9a-f]{64}$/.test(planDigest)) return refuse('plan_digest must be the 64-character hex digest returned by synthesize_fix');
  if (!f.stableId) return refuse('finding has no stableId, so a plan cannot be verified against it');
  const lc = await Promise.resolve(/* import() */).then(__webpack_require__.bind(__webpack_require__, 52603));
  if (lc.languageOfFinding(f) !== 'nix') return refuse('multi-file plans are produced for NixOS findings only');
  const nf = await Promise.resolve(/* import() */).then(__webpack_require__.bind(__webpack_require__, 57820));
  const proj = lc.loadLanguageProject(ctx.sessionRoot);
  const files = proj.files;
  // The plan is derived here, from the signed finding and the live tree. Nothing the caller sends can supply file content.
  const plan = nf.planNixFix(f, files);
  if (!plan || plan.ok === false) return refuse(`no applicable plan: ${_scrubRoot(ctx.sessionRoot, (plan && plan.reason) || 'no deterministic fix')}`);
  if (!Array.isArray(plan.edits) || plan.edits.length < 2) return refuse('this finding has a single-file plan; use apply_fix without plan_digest');
  if (_multiFilePlanDigest(f, plan.edits) !== planDigest) {
    return refuse('plan_digest does not match the plan computed now for this finding: the project files or the finding changed since synthesize_fix, or the digest was altered. Run synthesize_fix again and review the new plan.', { stale: true });
  }
  const targets = _checkMultiFileTargets(ctx.sessionRoot, plan.edits);
  if (!targets.ok) return refuse(targets.reason);
  const classification = (0,_posture_material_change_js__WEBPACK_IMPORTED_MODULE_6__/* .classifyFixMaterialRisk */ .kz)(Object.fromEntries(plan.edits.map((e) => [e.file, { before: e.before, after: e.after }])));
  if (!dryRun) {
    const approvalRefusal = _highImpactApprovalRefusal(ctx, classification, fixMeta);
    if (approvalRefusal) return { ...approvalRefusal, multiFile: true };
  }
  // The verification gates (syntax, rescan with no new finding, effective value changed as intended) run inside the lifecycle,
  // and the pre-write hook re-checks the digest of the VERIFIED edits and the targets immediately before the first byte is written.
  const preWrite = (verifiedPlan) => {
    const vedits = Array.isArray(verifiedPlan.edits) ? verifiedPlan.edits : [];
    if (_multiFilePlanDigest(f, vedits) !== planDigest) return { ok: false, detail: 'the verified plan differs from the previewed plan' };
    const again = _checkMultiFileTargets(ctx.sessionRoot, vedits);
    return again.ok ? { ok: true } : { ok: false, detail: again.reason };
  };
  let res;
  try { res = await nf.validateNixFix(f, { files, apply: !dryRun, root: ctx.sessionRoot, preWrite }); }
  catch (e) { return refuse(`plan verification failed: ${_scrubRoot(ctx.sessionRoot, e.message)}`); }
  const gates = _gateSummary(res.gates);
  const touched = plan.edits.map((e) => e.file);
  if (res.status === 'verified' && dryRun) {
    return { _meta: META, applied: false, dryRun: true, verified: true, multiFile: true, files: touched, planDigest, gates, materialClassification: classification, diff: res.preview };
  }
  if (res.status === 'applied') {
    let acceptance = null;
    try { acceptance = (0,_posture_fix_history_js__WEBPACK_IMPORTED_MODULE_4__/* .fixAcceptanceRate */ .XR)(ctx.sessionRoot); } catch { /* best-effort */ }
    const hist = Array.isArray(res.history) ? res.history : [];
    const allRecorded = hist.length === touched.length && hist.every(Boolean);
    return {
      _meta: META, applied: true, verified: true, multiFile: true, files: touched, planDigest,
      groupId: res.backup && res.backup.id, historyIds: hist.map((h) => (h ? h.id : null)),
      ...(allRecorded ? {} : { warning: 'the files were written and backed up, but the fix history could not record every entry; restore with the group backup under .agentic-security/fix-backups' }),
      gates, integrity: status, acceptance, materialClassification: classification,
    };
  }
  // Blocked or failed: nothing is left changed unless rollbackIncomplete says otherwise.
  const incomplete = res.rolledBack === false;
  return {
    _meta: META, applied: false, multiFile: true, files: touched,
    reason: _scrubRoot(ctx.sessionRoot, res.reason || `plan not applied (${res.status})`),
    gates,
    ...(res.rolledBack !== undefined ? { rolledBack: res.rolledBack === true, rollbackIncomplete: incomplete, ...(incomplete ? { restoreManually: (res.rollbackFailed || []).map(String) } : {}) } : {}),
  };
}

// ─── apply_fix ───────────────────────────────────────────────────────────────
const apply_fix = {
  name: 'apply_fix',
  description: 'Apply a fix for a finding. Two modes: (1) the stored fix.replacement, or (2) a caller-supplied `patch` (a files map) which is RE-VERIFIED inline (rescan-clean + no new ≥medium + lint) before any write — this unblocks findings that ship only a template or description. Refuses if last-scan.json fails its HMAC check, if the finding is shadow-marked, or if a path escapes the session root via lexical traversal OR a symlink. Requires confirm:true. Supports dry_run:true to preview without writing. On success, `verified:true` means verification passed but `verifiedFull:true` is the honest signal that every required leg (lint when configured, tests when a runner exists) genuinely ran — a false `verifiedFull` with `verified:true` means the pass is real but degraded (see `verify.degradedLegs`), not a full verification. MULTI-FILE NixOS FIX: when synthesize_fix returns `languageFix.planDigest` (an option defined in several files, edited together), pass it back as `plan_digest`. apply_fix then RECOMPUTES the plan itself from the signed finding and the live files, refuses unless its digest matches (so a changed tree, a changed finding or an altered digest all refuse; you never send file content), applies the same confinement, reserved-path, shadow and high-impact-approval checks to EVERY file, runs the verification gates (syntax, rescan with no new finding, the option resolves to the intended value on the patched configuration) before writing, and writes all files or none with one backup per file and one history group that `undo` reverts together. A rollback that could not complete is reported as `rollbackIncomplete` with the files to restore. `plan_digest` cannot be combined with `patch`.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      finding_id: { type: 'string', minLength: 1, maxLength: 256 },
      confirm: { type: 'boolean' },
      dry_run: { type: 'boolean' },
      plan_digest: { type: 'string', minLength: 64, maxLength: 64 },
      patch: {
        type: 'object',
        additionalProperties: { type: 'string', maxLength: 500_000 },
        minProperties: 1, maxProperties: 8,
      },
      // Stage 6 correctness audit: same gap and same fix as verify_fix — the
      // honesty gate is reachable but was never wired to any real caller.
      // Here it's stronger than advisory: the inline re-verify below already
      // gates the WRITE on `verdict.ok`, and verifyFixCore's own `ok`
      // formula already folds in `honesty.ok` when fixMeta is supplied — so
      // passing it through here makes a dishonest fixMeta (hand-wave
      // residual, uncited false-positive verdict) block the write itself,
      // not just report a verdict.
      fixMeta: {
        type: 'object',
        additionalProperties: false,
        properties: {
          residual: { type: 'string', maxLength: 2000 },
          verdict: { type: 'string', maxLength: 64 },
          evidence: { type: 'array', items: { type: 'string', maxLength: 500 }, maxItems: 20 },
          signals: {
            type: 'object',
            additionalProperties: false,
            properties: {
              sinkSignatureChanged: { type: 'boolean' },
              allCallersRouted: { type: 'boolean' },
              testDiscriminates: { type: 'boolean' },
              rateLimitOnly: { type: 'boolean' },
              docsOnly: { type: 'boolean' },
              logOnlyNoReject: { type: 'boolean' },
              partialSanitization: { type: 'boolean' },
            },
          },
          // FR-307/FR-1002: this schema had `additionalProperties: false`
          // and never declared `approval` — the property apply-fix-
          // service.js's high-impact-change gate has required since FR-307
          // was built. A real MCP caller supplying fixMeta.approval was
          // rejected by validate.js at the schema layer before the handler
          // ever ran, silently making the approval gate (and FR-1002's
          // identity check layered on it) unreachable from this tool's
          // only real production entry point. See D-0024.
          approval: {
            type: 'object',
            additionalProperties: false,
            properties: {
              approvedBy: { type: 'string', minLength: 1, maxLength: 200 },
              reason: { type: 'string', minLength: 1, maxLength: 1000 },
            },
          },
          // FR-1003: separation-of-duties. Self-reported the same way
          // approvedBy is — this tool has no way to determine who actually
          // wrote a patch, so `author` is a claim, checked against a
          // configurable policy the same way `approval` is.
          author: { type: 'string', minLength: 1, maxLength: 200 },
        },
      },
    },
    required: ['finding_id', 'confirm'],
  },
  async handler({ finding_id, confirm, dry_run = false, patch = null, fixMeta = null, plan_digest = null }, ctx) {
    if (confirm !== true) {
      return { _meta: META, applied: false, reason: 'apply_fix requires confirm: true.' };
    }
    const { scan, status } = _readLastScanVerified(ctx.sessionRoot, { allowUnsigned: false });
    if (!scan) {
      return { _meta: META, applied: false, reason: `last-scan.json failed integrity check: ${status}. Run a fresh scan.` };
    }
    const f = _findById(scan, finding_id);
    if (!f) return { _meta: META, applied: false, reason: `Finding not found: ${finding_id}` };
    if (f._shadow === true) {
      return { _meta: META, applied: false, reason: 'shadow findings cannot be auto-applied' };
    }

    // Multi-file plan (a NixOS option defined in several files). The plan is recomputed here and bound by plan_digest; the
    // caller can never supply file content on this path, and it cannot be combined with `patch`.
    if (plan_digest !== null && plan_digest !== undefined) {
      if (patch && typeof patch === 'object' && Object.keys(patch).length) {
        return { _meta: META, applied: false, reason: 'plan_digest and patch cannot be combined: a multi-file plan is computed by the scanner, not supplied by the caller' };
      }
      return _applyMultiFilePlan({ f, planDigest: plan_digest, dryRun: dry_run === true, fixMeta, ctx, status });
    }

    // #3 — verifier-approved patch path. When the caller supplies `patch` (a
    // files map, same shape as verify_fix), apply_fix re-runs the verifier
    // INLINE and writes only if it passes: the original finding's stableId is
    // gone, no new ≥medium finding was introduced, and lint is clean. This lets
    // a deterministic OR LLM-synthesized patch be applied for the ~100% of
    // findings that ship only a template/description (no stored fix.replacement).
    // Security: all existing gates hold (confirm, last-scan HMAC, reserved
    // paths, confinement, fix-history backup + attempt budget); the write is
    // additionally gated on a FRESH verification, so a stale/forged patch can't
    // slip through — there is no token to replay, the verify runs here and now.
    if (patch && typeof patch === 'object' && Object.keys(patch).length) {
      if (!f.stableId) {
        return { _meta: META, applied: false, reason: 'finding has no stableId — cannot verify a patch against it' };
      }
      const confinedAbs = {};
      for (const [rel, content] of Object.entries(patch)) {
        let abs;
        try { abs = _confine(ctx.sessionRoot, rel, 'patch key'); }
        catch (e) { return { _meta: META, applied: false, reason: `path-escape refused: ${e.message}` }; }
        if (_isReservedWritePath(ctx.sessionRoot, abs)) {
          return { _meta: META, applied: false, reason: `reserved path refused: ${rel}` };
        }
        confinedAbs[rel] = { abs, content: String(content) };
      }
      // Inline re-verify — the load-bearing gate. Must pass to write.
      let verdict;
      try {
        const _files = Object.fromEntries(Object.entries(confinedAbs).map(([rel, v]) => [rel, v.content]));
        if (process.env.AGENTIC_SECURITY_FIX_RUN_TESTS === '1') {
          // Addition #7 — connect the closed-loop verifier: add the project test
          // suite as a fourth verification leg (scan + lint + tests). Opt-in
          // because many repos have no runner and we must not fail-closed by
          // default. Normalized to the scan+lint verdict shape used below.
          const { verifyFixWithTests } = await __webpack_require__.e(/* import() */ 4113).then(__webpack_require__.bind(__webpack_require__, 64113));
          const t = await verifyFixWithTests({ scanRoot: ctx.sessionRoot, originalFindingStableId: f.stableId, files: _files });
          verdict = { ok: t.ok, summary: t.summary, rescan: t.legs?.scan?.detail, lint: t.legs?.lint?.detail, tests: t.legs?.tests, testVerdict: t.verdict, verificationRecord: t.verificationRecord ?? null };
        } else {
          const verifyFixCore = await getVerifyFixCore();
          verdict = await verifyFixCore({
            scanRoot: ctx.sessionRoot,
            originalFindingStableId: f.stableId,
            files: _files,
            fixMeta,
          });
        }
      } catch (e) {
        return { _meta: META, applied: false, reason: `patch verification failed: ${e.message}` };
      }
      if (!verdict.ok) {
        return {
          _meta: META, applied: false,
          reason: `patch rejected by verifier: ${verdict.summary || verdict.rescan?.reason || 'did not verify'}`,
          verify: { rescan: verdict.rescan, lint: { runner: verdict.lint?.runner, ok: verdict.lint?.ok }, honesty: verdict.honesty || null },
          // X-201: the same version-1 verification record every surface emits (additive; null when none could be formed).
          verificationRecord: verdict.verificationRecord ?? null,
          ...(0,_posture_verification_projection_js__WEBPACK_IMPORTED_MODULE_13__/* .verificationFields */ .ze)(verdict.verificationRecord),
        };
      }
      // FR-307/FR-1002/D-0024: this caller-supplied-patch branch writes via
      // applyFixHistory() directly and never called applyVerifiedFix() — so
      // the high-impact-change approval gate (auth/authZ/crypto/PII/schema/
      // infra-privilege/public-API) built for the OTHER apply_fix branch
      // (stored fix.replacement) never ran here at all, for any input. Since
      // this is the branch the tool's own description calls the one that
      // covers "~100% of findings that ship only a template," that gap was
      // the larger of the two found this cycle. Same before/after content
      // shape `apply-fix-service.js` already uses — read-first-in-try/catch
      // (D-0012), never existsSync-then-readFileSync.
      const filesForMaterialClassification = {};
      for (const [rel, v] of Object.entries(confinedAbs)) {
        let before = '';
        try { before = await node_fs_promises__WEBPACK_IMPORTED_MODULE_1__.readFile(v.abs, 'utf8'); } catch { /* new file — before stays '' */ }
        filesForMaterialClassification[rel] = { before, after: v.content };
      }
      const materialClassification = (0,_posture_material_change_js__WEBPACK_IMPORTED_MODULE_6__/* .classifyFixMaterialRisk */ .kz)(filesForMaterialClassification);
      if (dry_run) {
        return { _meta: META, applied: false, dryRun: true, verified: true, files: Object.keys(confinedAbs), summary: verdict.summary, verificationRecord: verdict.verificationRecord ?? null, ...(0,_posture_verification_projection_js__WEBPACK_IMPORTED_MODULE_13__/* .verificationFields */ .ze)(verdict.verificationRecord), materialClassification };
      }
      const approvalRefusal = _highImpactApprovalRefusal(ctx, materialClassification, fixMeta);
      if (approvalRefusal) return approvalRefusal;
      const written = [];
      try {
        for (const [rel, v] of Object.entries(confinedAbs)) {
          const fileExisted = node_fs__WEBPACK_IMPORTED_MODULE_0__.existsSync(v.abs);
          const originalContent = fileExisted ? await node_fs_promises__WEBPACK_IMPORTED_MODULE_1__.readFile(v.abs, 'utf8') : '';
          const entry = await (0,_posture_fix_history_js__WEBPACK_IMPORTED_MODULE_4__/* .applyFix */ .oM)({
            scanRoot: ctx.sessionRoot, file: rel, originalContent, newContent: v.content, fileExisted,
            findingId: f.id, stableId: f.stableId, ruleId: f.ruleId || f.cwe || f.family || null, vuln: f.vuln || f.title || null,
            findingProvenance: f.findingProvenance || null,
          });
          written.push({ file: rel, historyId: entry.id, backupPath: entry.backupPath });
        }
      } catch (e) {
        // FR-306: roll back every file THIS batch already wrote before the
        // failure — applyFixHistory already restored the one file that just
        // failed; this covers the rest, so a multi-file patch never leaves
        // some files patched and others not.
        for (const w of written) {
          try { await (0,_posture_fix_history_js__WEBPACK_IMPORTED_MODULE_4__/* .revertEntryById */ .rJ)(ctx.sessionRoot, w.historyId); } catch { /* best-effort; original error still propagates below */ }
        }
        if (e && e.name === 'FixAttemptBudgetExceededError') {
          return { _meta: META, applied: false, reason: `budget-exceeded: ${e.message}`, budgetExceeded: true, attempts: e.attempts, maxAttempts: e.max, key: e.key };
        }
        throw e;
      }
      let acceptance = null;
      try { acceptance = (0,_posture_fix_history_js__WEBPACK_IMPORTED_MODULE_4__/* .fixAcceptanceRate */ .XR)(ctx.sessionRoot); } catch { /* best-effort */ }
      return { _meta: META, applied: true, verified: true, patched: written, integrity: status, verify: { summary: verdict.summary, verificationRecord: verdict.verificationRecord ?? null, ...(0,_posture_verification_projection_js__WEBPACK_IMPORTED_MODULE_13__/* .verificationFields */ .ze)(verdict.verificationRecord) }, acceptance, materialClassification };
    }

    if (typeof f.fix?.replacement !== 'string') {
      // Premortem #2: templates are patch-shaped text. Same reasoning as
      // the replacement path — do NOT pass through redactString here.
      return {
        _meta: META, applied: false,
        reason: 'No full replacement available — only a template. Apply the template manually.',
        template: f.fix?.code || '',
        file: f.file, line: f.line,
      };
    }
    let absFile;
    try { absFile = _confine(ctx.sessionRoot, f.file, 'finding.file'); }
    catch (e) {
      return { _meta: META, applied: false, reason: `path-escape refused: ${e.message}` };
    }
    if (_isReservedWritePath(ctx.sessionRoot, absFile)) {
      return { _meta: META, applied: false, reason: `reserved path refused: writes to .git/, .agentic-security/, or node_modules/ are not permitted via apply_fix` };
    }
    if (!node_fs__WEBPACK_IMPORTED_MODULE_0__.existsSync(absFile)) {
      return { _meta: META, applied: false, reason: `File not found: ${absFile}` };
    }
    const originalContent = await node_fs_promises__WEBPACK_IMPORTED_MODULE_1__.readFile(absFile, 'utf8');

    if (dry_run) {
      return {
        _meta: META,
        applied: false, dryRun: true,
        file: f.file,
        originalSize: originalContent.length,
        newSize: f.fix.replacement.length,
        diffSummary: `${originalContent.length} → ${f.fix.replacement.length} bytes`,
      };
    }

    // FR-301/A-08 (assurance-hardening PRD): this branch used to write
    // f.fix.replacement straight to disk with NO fresh verification — no
    // rescan, no lint, nothing confirming the stored replacement actually
    // closes the finding it claims to fix. The caller-patch branch above
    // already required this; there is no reason a STORED fix should be
    // trusted more than a caller-supplied one just because it shipped with
    // the finding. Routed through the same applyVerifiedFix() service the
    // CLI's `fix --apply` now also uses (src/fix/apply-fix-service.js) —
    // confinement/reserved-path are re-checked there too (harmless
    // redundancy with the dry_run preview above, kept for that preview's
    // size-diff shape) but the load-bearing addition is the verification
    // gate before the write.
    if (!f.stableId) {
      return { _meta: META, applied: false, reason: 'finding has no stableId — cannot verify a stored fix against it' };
    }
    const result = await (0,_fix_apply_fix_service_js__WEBPACK_IMPORTED_MODULE_5__/* .applyVerifiedFix */ .On)({
      scanRoot: ctx.sessionRoot,
      finding: f,
      files: { [f.file]: f.fix.replacement },
      fixMeta,
    });
    if (!result.ok) {
      if (result.budgetExceeded) {
        return { _meta: META, applied: false, reason: result.reason, budgetExceeded: true, attempts: result.attempts, maxAttempts: result.maxAttempts, key: result.key };
      }
      return { _meta: META, applied: false, reason: result.reason, verify: result.verify || null };
    }
    // R25 (PRD §5): surface the running auto-fix acceptance rate after each
    // applied fix, so the closed loop reports its own success metric.
    let acceptance = null;
    try { acceptance = (0,_posture_fix_history_js__WEBPACK_IMPORTED_MODULE_4__/* .fixAcceptanceRate */ .XR)(ctx.sessionRoot); } catch { /* metric is best-effort */ }
    const entry = result.written[0];
    return {
      // FR-305: verifiedFull distinguishes "every required leg (lint, tests)
      // genuinely ran and passed" from "passed, but a required leg was
      // skipped or unavailable" — verified:true alone conflates them.
      _meta: META, applied: true, verified: true, verifiedFull: result.verifiedFull,
      historyId: entry.historyId, file: entry.file, backupPath: entry.backupPath,
      integrity: status, attemptOrdinal: entry.attemptOrdinal, acceptance,
      verify: result.verify,
    };
  },
};

// ─── verify_fix ──────────────────────────────────────────────────────────────
// Closed-loop verification of a proposed patch BEFORE the agent applies it.
// Re-scans the patched files in-memory (no disk write), confirms the original
// stableId is gone, and runs the project's existing linter on the patched
// files. Returns a structured verdict the agent can use to decide whether to
// proceed with apply_fix.
const verify_fix = {
  name: 'verify_fix',
  description: 'Verify a proposed patch before applying. Re-scans the patched files in memory, runs the project linter, runs the project test suite, checks fix honesty (FULL/MITIGATION/WORKAROUND) when fixMeta is supplied, and re-runs the PoC when one exists. Returns { ok, rescan, lint, tests, honesty, poc, summary, verificationRecord } (verificationRecord is the shared version-1 record: outcome is one of not-run, unsupported, inconclusive, error, refuted, confirmed, and a static re-scan alone is never reported as confirmed; verificationView is the shared projection every interface shows for it, with state, scope, evidence ids, replay prerequisites and what was and was not verified). Does not write to the target project’s own files, but DOES append one record per attempt to .agentic-security/fix-metrics.jsonl for the measured fix-loop.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      stable_id: { type: 'string', minLength: 8, maxLength: 64 },
      files: {
        type: 'object',
        additionalProperties: { type: 'string', maxLength: 500_000 },
        minProperties: 1,
        maxProperties: 8,
      },
      // Stage 6 correctness audit: posture/fix-honesty-gate.js's deterministic
      // honesty checks (vague-assurance residual prose, unbacked false-
      // positive verdicts, tier/residual consistency) were fully built and
      // fix-verify.js already consulted them when given a `fixMeta` — but
      // this schema never had a `fixMeta` property, so no call through the
      // MCP surface could ever supply one. The gate can only run against
      // claims the AGENT self-reports (residual risk, verdict, evidence,
      // completeness signals) — nothing here is server-computable — so
      // fixing this meant exposing the property, not inventing a lookup.
      fixMeta: {
        type: 'object',
        additionalProperties: false,
        properties: {
          residual: { type: 'string', maxLength: 2000 },
          verdict: { type: 'string', maxLength: 64 },
          evidence: { type: 'array', items: { type: 'string', maxLength: 500 }, maxItems: 20 },
          signals: {
            type: 'object',
            additionalProperties: false,
            properties: {
              sinkSignatureChanged: { type: 'boolean' },
              allCallersRouted: { type: 'boolean' },
              testDiscriminates: { type: 'boolean' },
              rateLimitOnly: { type: 'boolean' },
              docsOnly: { type: 'boolean' },
              logOnlyNoReject: { type: 'boolean' },
              partialSanitization: { type: 'boolean' },
            },
          },
        },
      },
    },
    required: ['stable_id', 'files'],
  },
  async handler({ stable_id, files, fixMeta }, ctx) {
    // Confine every file path before passing to the verifier.
    const confined = {};
    for (const [relPath, content] of Object.entries(files || {})) {
      try {
        _confine(ctx.sessionRoot, relPath, 'files key');
      } catch (e) {
        return { _meta: META, ok: false, reason: `path-escape refused: ${e.message}` };
      }
      confined[relPath] = String(content);
    }
    try {
      // The PoC-re-check leg (verifyFixCore's `pocLeg`) needs a `poc` param
      // to do anything — until now nothing supplied one, so it always
      // reported {status:'not-requested'} through this surface (see
      // posture/CLAUDE.md's disclosure). Rather than widening inputSchema
      // to make the CALLER pass PoC data back, look it up server-side: the
      // scan pipeline already attaches an HTTP-shaped f.poc to matching
      // findings by default (engine.js's annotatePocs), and last-scan.json
      // already carries it under the same stableId this handler receives.
      // Best-effort: a missing/unsigned/tampered scan just means no PoC is
      // available to re-check, not a verify_fix failure — the rescan/lint/
      // tests legs below are independent of this and still apply.
      let poc = null;
      try {
        const { scan: lastScan } = _readLastScanVerified(ctx.sessionRoot, { allowUnsigned: true });
        const orig = lastScan && (lastScan.findings || []).find(f => f.stableId === stable_id);
        if (orig && orig.poc && orig.poc.code) poc = { ...orig.poc, finding: orig };
      } catch { /* best-effort lookup; poc stays null */ }

      const verifyFixCore = await getVerifyFixCore();
      const r = await verifyFixCore({
        scanRoot: ctx.sessionRoot,
        originalFindingStableId: stable_id,
        files: confined,
        poc,
        fixMeta,
      });
      return {
        _meta: META,
        ok: r.ok,
        rescan: { ok: r.rescan.ok, reason: r.rescan.reason, introduced: r.rescan.introduced || [] },
        lint: { runner: r.lint.runner, ok: r.lint.ok, skipped: r.lint.skipped || false, output: (0,_redact_js__WEBPACK_IMPORTED_MODULE_19__/* .redactString */ .rd)(r.lint.output || '').slice(0, 1500) },
        // verifyFix computes five legs, not two — tests/honesty/poc were
        // being silently dropped here, leaving an agent with no structured
        // way to see WHY verification failed when the failure was in one
        // of those three (only the free-text summary carried it).
        // test-runner.js's runProjectTests never returns raw stdout/stderr,
        // so no redaction is needed there; honesty.violations are static,
        // code-generated strings; poc.reason is redacted defensively since
        // it can echo proof-harness detail derived from scanned source.
        tests: r.tests,
        honesty: r.honesty,
        poc: r.poc ? { ...r.poc, reason: r.poc.reason ? (0,_redact_js__WEBPACK_IMPORTED_MODULE_19__/* .redactString */ .rd)(r.poc.reason) : r.poc.reason } : r.poc,
        summary: r.summary,
        // X-201: the one version-1 verification record (additive). It states what was actually established, e.g.
        // `not-run` when no exploit oracle executed against the patch, never a bare pass/fail.
        verificationRecord: r.verificationRecord ?? null,
        ...(0,_posture_verification_projection_js__WEBPACK_IMPORTED_MODULE_13__/* .verificationFields */ .ze)(r.verificationRecord),
      };
    } catch (e) {
      return { _meta: META, ok: false, reason: `verify_fix failed: ${e.message}` };
    }
  },
};

// ─── synthesize_fix ──────────────────────────────────────────────────────────
// Return the stored fix replacement + regression-test scaffold for a finding,
// WITHOUT applying anything. The agent can call verify_fix → apply_fix in
// sequence with the returned blob.
const synthesize_fix = {
  name: 'synthesize_fix',
  description: 'Return the stored fix replacement for a finding (replacement text + remediation + plan if the patch is too large). Read-only; never writes to disk. Use verify_fix → apply_fix to deploy. For a NixOS option defined in several files, `languageFix.multiFile` lists every file, `languageFix.edits` gives each file\'s before/after SHA-256 (no file content) and `languageFix.planDigest` is the value to pass to apply_fix as `plan_digest`; the preview is verified but nothing is written.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      finding_id: { type: 'string', minLength: 1, maxLength: 256 },
    },
    required: ['finding_id'],
  },
  async handler({ finding_id }, ctx) {
    const { scan, status } = _readLastScanVerified(ctx.sessionRoot, { allowUnsigned: false });
    if (!scan) {
      return { _meta: META, ok: false, reason: `last-scan.json failed integrity check: ${status}` };
    }
    const f = _findById(scan, finding_id);
    if (!f) return { _meta: META, ok: false, reason: `Finding not found: ${finding_id}` };
    if (f._shadow === true) return { _meta: META, ok: false, reason: 'shadow findings have no synthesized fix' };
    const fix = f.fix || {};
    const hasReplacement = typeof fix.replacement === 'string' && fix.replacement.length > 0;
    // Patch bounds: count files touched + LoC delta.
    let touchedFiles = 1;
    let locDelta = 0;
    if (hasReplacement) {
      let orig = '';
      try {
        const abs = _confine(ctx.sessionRoot, f.file, 'finding.file');
        orig = node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(abs, 'utf8');
      } catch { /* ignore — counts will reflect new-only LoC */ }
      locDelta = Math.abs(fix.replacement.split('\n').length - orig.split('\n').length);
    }
    const oversized = touchedFiles > 3 || locDelta > 100;
    // #1 — deterministic autofix: for classes with a safe context-independent
    // swap (weak hash, TLS verify-off), materialize a full-file patch from the
    // live file. The agent passes `autofix.patch` straight to apply_fix, which
    // re-verifies it (rescan-clean + no new ≥medium + lint) before writing — so
    // even a mis-attributed swap can't land a bad edit. No stored replacement,
    // no per-finding bloat in last-scan.json.
    let autofix = null;
    let languageFix = null;
    if (!hasReplacement) {
      try {
        const abs = _confine(ctx.sessionRoot, f.file, 'finding.file');
        const det = (0,_posture_deterministic_fix_js__WEBPACK_IMPORTED_MODULE_8__/* .synthesizeDeterministicPatch */ .X)(f, node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(abs, 'utf8'));
        if (det) autofix = { deterministic: true, ruleId: det.ruleId, patch: det.patch };
      } catch { /* best-effort — no file / no rule → no autofix */ }
      // Haskell and Nix: a read-only preview from the language fixer, with the verification gates' verdict and the
      // FULL / MITIGATION / WORKAROUND tier. It writes nothing; apply_fix re-verifies before anything lands.
      if (!autofix) {
        try {
          const lc = await Promise.resolve(/* import() */).then(__webpack_require__.bind(__webpack_require__, 52603));
          if (lc.languageOfFinding(f)) {
            const proj = lc.loadLanguageProject(ctx.sessionRoot);
            const prev = await lc.languageFixPreview(f, proj.files);
            languageFix = { status: prev.status, ok: prev.ok, label: prev.label || null, tier: prev.tier || null, reason: prev.reason || null, diff: prev.diff || null, explanation: prev.explanation || null, consequences: prev.consequences || [] };
            // A fix that spans several files is applied with apply_fix + plan_digest (atomic, one history group); see _applyMultiFilePlan.
            if (prev.ok && prev.edits) {
              languageFix.multiFile = prev.edits.map((e) => e.file);
              // The digest binds finding + every file + exact pre/post image. Pass it to apply_fix as plan_digest; apply_fix
              // recomputes the plan itself and refuses on any difference. No file content is ever sent back to apply_fix.
              languageFix.planDigest = _multiFilePlanDigest(f, prev.edits);
              languageFix.edits = prev.edits.map((e) => ({ file: e.file, beforeSha256: _sha256(e.before), afterSha256: _sha256(e.after) }));
              languageFix.applyWith = { finding_id: f.id, confirm: true, plan_digest: languageFix.planDigest };
            }
            else if (prev.ok) autofix = { deterministic: true, ruleId: f.rule || f.family || null, patch: prev.after, file: prev.file, label: prev.label || null, verified: true };
          }
        } catch { /* best-effort: the preview is advisory */ }
      }
    }
    // Premortem #2: `replacement` is a *patch* (the code we'll write to disk),
    // not a finding excerpt. Running it through redactString silently corrupts
    // valid patches whose content happens to match a secret-shape (e.g. a
    // placeholder like `password = "loadFromEnv"`). Patches MUST pass through
    // verbatim. Snippet/description/etc. continue to be redacted in
    // explain_finding / scan_diff — that's the right surface for redaction.
    return {
      _meta: META,
      ok: true,
      stable_id: f.stableId || null,
      file: f.file, line: f.line,
      vuln: f.vuln,
      severity: f.severity,
      hasReplacement,
      replacement: hasReplacement ? fix.replacement : null,
      template: fix.code || null,
      autofix,
      languageFix,
      // #15 — the regression test the scan annotator already generated for this
      // finding (present when a PoC was built). Surfaced here so the fix flow
      // writes the test alongside the patch; fix-verify-loop then runs it, so an
      // applied fix ships with a test that fails pre-fix and passes post-fix.
      regression_test: f.regression_test || null,
      remediation: typeof fix.description === 'string' ? fix.description : (typeof fix === 'string' ? fix : null),
      patchBounds: { touchedFiles, locDelta, oversized },
      // oversized can only be true when hasReplacement is true (locDelta is
      // only computed in that branch, and touchedFiles never varies) — a
      // `!hasReplacement` conjunct here was a structural contradiction that
      // made this permanently false. The correct signal: the stored
      // replacement itself is too big to trust auto-applying, and there's
      // no safer deterministic alternative.
      recommendsFixPlan: oversized && !autofix,
    };
  },
};

// ─── find_rule_module ───────────────────────────────────────────────────────
// Codebase-navigation helper (C.6). Answers "which file under scanner/src/
// implements the detector for CWE-X / family Y" by scanning the SAST and
// posture sources for `cwe:` / `family:` literals. Cheaper and more reliable
// than asking the agent to grep — premortem note: "grep for a common function
// name in a large codebase returns thousands of matches."
//
// Read-only; no findings consumed. Output is a list of file paths + the
// matching literal lines so the agent can verify before editing.
const find_rule_module = {
  name: 'find_rule_module',
  description: 'Find the file(s) under scanner/src/{sast,posture}/ that emit findings for a given CWE id or family name. Use BEFORE editing a rule — answers "where is the SQL-injection detector?" without grepping the whole tree. Returns at most 20 hits; refine the query if too broad.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      cwe: { type: 'string', minLength: 5, maxLength: 16 },
      family: { type: 'string', minLength: 2, maxLength: 64 },
    },
  },
  async handler({ cwe, family }, ctx) {
    if (!cwe && !family) {
      return { _meta: META, ok: false, reason: 'provide cwe (e.g. "CWE-89") or family (e.g. "sql-injection")' };
    }
    // Pattern enforcement — the mini-schema validator doesn't do `pattern`.
    if (cwe && !/^CWE-\d+$/.test(cwe)) {
      return { _meta: META, ok: false, reason: 'cwe must match /^CWE-\\d+$/ (e.g. "CWE-89")' };
    }
    if (family && !/^[a-z][a-z0-9-]+$/.test(family)) {
      return { _meta: META, ok: false, reason: 'family must match /^[a-z][a-z0-9-]+$/ (e.g. "sql-injection")' };
    }
    const sessionRoot = ctx.sessionRoot;
    const roots = [
      node_path__WEBPACK_IMPORTED_MODULE_2__.join(sessionRoot, 'scanner', 'src', 'sast'),
      node_path__WEBPACK_IMPORTED_MODULE_2__.join(sessionRoot, 'scanner', 'src', 'posture'),
    ];
    const hits = [];
    const cweLit = cwe ? new RegExp(`['"\`]${cwe.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}['"\`]`) : null;
    // Family match is broader on purpose: detectors often emit findings
    // without an explicit `family:` field (it's backfilled by
    // posture/finding-defaults.js). We match the family literal anywhere in
    // the file (vuln-name strings, comments, ids) so e.g. searching for "csrf"
    // surfaces sast/csrf.js even though it doesn't tag findings with the field.
    const famLit = family ? new RegExp(`\\b${family.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/-/g, '[-_ ]?')}\\b`, 'i') : null;
    // Also try a filename-stem match when only family is given.
    const famFilename = family ? family.toLowerCase() : null;
    for (const root of roots) {
      if (!node_fs__WEBPACK_IMPORTED_MODULE_0__.existsSync(root)) continue;
      let entries;
      try { entries = node_fs__WEBPACK_IMPORTED_MODULE_0__.readdirSync(root); } catch { continue; }
      for (const entry of entries) {
        if (!entry.endsWith('.js')) continue;
        const abs = node_path__WEBPACK_IMPORTED_MODULE_2__.join(root, entry);
        let stat;
        try { stat = node_fs__WEBPACK_IMPORTED_MODULE_0__.statSync(abs); } catch { continue; }
        if (!stat.isFile() || stat.size > MAX_FILE_BYTES) continue;
        let body;
        try { body = node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(abs, 'utf8'); } catch { continue; }
        const lines = body.split('\n');
        const matches = [];
        const stem = entry.replace(/\.js$/, '').toLowerCase();
        const filenameMatchesFamily = famFilename && (stem === famFilename || stem.includes(famFilename));
        if (filenameMatchesFamily) {
          matches.push({ line: 1, text: `<filename "${entry}" matches family>`, kind: 'filename' });
        }
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          if (cweLit && cweLit.test(line)) matches.push({ line: i + 1, text: line.trim().slice(0, 200), kind: 'cwe' });
          else if (famLit && famLit.test(line)) matches.push({ line: i + 1, text: line.trim().slice(0, 200), kind: 'family' });
          if (matches.length >= 5) break;
        }
        if (matches.length) {
          hits.push({
            file: node_path__WEBPACK_IMPORTED_MODULE_2__.relative(sessionRoot, abs).replace(/\\/g, '/'),
            matchCount: matches.length,
            matches,
          });
          if (hits.length >= 20) break;
        }
      }
      if (hits.length >= 20) break;
    }
    return {
      _meta: META,
      ok: true,
      query: { cwe: cwe || null, family: family || null },
      hitCount: hits.length,
      hits,
      truncated: hits.length >= 20,
    };
  },
};

// ─── append_scratchpad / read_scratchpad ───────────────────────────────────
// LangChain harness-anatomy: the filesystem is the durable agent scratchpad.
// These tools expose a tightly-confined slice of the project tree for
// in-progress agent state: PLAN.md decompositions, offloaded tool outputs,
// session notes that survive context resets.
//
// Confinement (validated in `_validateScratchpadPath`):
//   ALL paths must start with `.agentic-security/agent-scratchpad/<agent>/<session>/`
//   and consist of [A-Za-z0-9_.-]{1,64} path components — no `..`, no
//   absolute paths, no shell metacharacters. This is the ONE place inside
//   the otherwise-reserved `.agentic-security/` tree where agents can write.
// Limits:
//   - 2 MB per file (write attempts beyond this are refused).
//   - 50 MB total across the scratchpad — protects against runaway agents.
// Operators who want to clean up: `rm -rf .agentic-security/agent-scratchpad`.
//
// The post: "Agents can store intermediate outputs and maintain state that
// outlasts a single session." This is that mechanism.

const append_scratchpad = {
  name: 'append_scratchpad',
  description: 'Append text to a file under .agentic-security/agent-scratchpad/<agent>/<session>/. The ONLY writable location for in-progress agent state (PLAN.md, notes, offloaded tool outputs, decision logs). Path must start with that prefix; <agent>/<session>/file parts are restricted to [A-Za-z0-9_.-]{1,64}. Caps: 2 MB per file, 50 MB total across the scratchpad.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      path: { type: 'string', minLength: 1, maxLength: 256 },
      content: { type: 'string', minLength: 1, maxLength: 256 * 1024 },
    },
    required: ['path', 'content'],
  },
  async handler({ path: relPath, content }, ctx) {
    const v = _validateScratchpadPath(relPath);
    if (!v.ok) return { _meta: META, ok: false, reason: v.reason };
    let abs;
    try { abs = _scratchpadAbs(ctx.sessionRoot, relPath); }
    catch (e) { return { _meta: META, ok: false, reason: `path-escape refused: ${e.message}` }; }
    const total = _scratchpadTotalBytes(ctx.sessionRoot);
    if (total + content.length > SCRATCHPAD_MAX_TOTAL_BYTES) {
      return {
        _meta: META, ok: false,
        reason: `scratchpad-total-exceeded: ${total} + ${content.length} > ${SCRATCHPAD_MAX_TOTAL_BYTES}. Clean up via "rm -rf .agentic-security/agent-scratchpad" or rotate sessions.`,
      };
    }
    let existing = 0;
    try { if (node_fs__WEBPACK_IMPORTED_MODULE_0__.existsSync(abs)) existing = node_fs__WEBPACK_IMPORTED_MODULE_0__.statSync(abs).size; } catch {}
    if (existing + content.length > SCRATCHPAD_MAX_FILE_BYTES) {
      return {
        _meta: META, ok: false,
        reason: `scratchpad-file-exceeded: ${existing} + ${content.length} > ${SCRATCHPAD_MAX_FILE_BYTES}. Start a new file.`,
      };
    }
    try {
      node_fs__WEBPACK_IMPORTED_MODULE_0__.mkdirSync(node_path__WEBPACK_IMPORTED_MODULE_2__.dirname(abs), { recursive: true });
      node_fs__WEBPACK_IMPORTED_MODULE_0__.appendFileSync(abs, content);
      return {
        _meta: META, ok: true,
        path: relPath, bytesWritten: content.length, fileSize: existing + content.length,
        scratchpadTotal: total + content.length,
      };
    } catch (e) {
      return { _meta: META, ok: false, reason: `write-failed: ${e.message}` };
    }
  },
};

const read_scratchpad = {
  name: 'read_scratchpad',
  description: 'Read a file under .agentic-security/agent-scratchpad/<agent>/<session>/. Paginated for large files via `offset` (default 0) and `limit` (default 4096 bytes, max 64 KB). Returns bytesRead, truncated, nextOffset for paging.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      path: { type: 'string', minLength: 1, maxLength: 256 },
      offset: { type: 'integer', minimum: 0, maximum: 100 * 1024 * 1024 },
      limit: { type: 'integer', minimum: 1, maximum: 64 * 1024 },
    },
    required: ['path'],
  },
  async handler({ path: relPath, offset, limit }, ctx) {
    const v = _validateScratchpadPath(relPath);
    if (!v.ok) return { _meta: META, ok: false, reason: v.reason };
    let abs;
    try { abs = _scratchpadAbs(ctx.sessionRoot, relPath); }
    catch (e) { return { _meta: META, ok: false, reason: `path-escape refused: ${e.message}` }; }
    if (!node_fs__WEBPACK_IMPORTED_MODULE_0__.existsSync(abs)) return { _meta: META, ok: false, reason: 'not-found' };
    let stat;
    try { stat = node_fs__WEBPACK_IMPORTED_MODULE_0__.statSync(abs); } catch (e) { return { _meta: META, ok: false, reason: `stat-failed: ${e.message}` }; }
    if (!stat.isFile()) return { _meta: META, ok: false, reason: 'not-a-file' };
    const off = Number.isInteger(offset) ? Math.max(0, offset) : 0;
    const lim = Number.isInteger(limit) ? Math.min(64 * 1024, Math.max(1, limit)) : 4096;
    let buf;
    try {
      const fd = node_fs__WEBPACK_IMPORTED_MODULE_0__.openSync(abs, 'r');
      const tmp = Buffer.alloc(lim);
      const read = node_fs__WEBPACK_IMPORTED_MODULE_0__.readSync(fd, tmp, 0, lim, off);
      node_fs__WEBPACK_IMPORTED_MODULE_0__.closeSync(fd);
      buf = tmp.slice(0, read);
    } catch (e) { return { _meta: META, ok: false, reason: `read-failed: ${e.message}` }; }
    const text = buf.toString('utf8');
    return {
      _meta: META, ok: true,
      path: relPath,
      offset: off, limit: lim, bytesRead: buf.length,
      totalSize: stat.size,
      truncated: off + buf.length < stat.size,
      nextOffset: off + buf.length < stat.size ? off + buf.length : null,
      content: text,
    };
  },
};

// ─── append_agents_memory / read_agents_memory ─────────────────────────────
// LangChain harness-anatomy #2: AGENTS.md as continual-learning surface.
// Lazy-import to keep the MCP module dependency-light.




const append_agents_memory = {
  name: 'append_agents_memory',
  description: 'Append a short narrative entry to AGENTS.md — agent-authored continual-learning notes. Use at session end to record "what worked / what didn\'t / what I\'d try differently next time" so the next agent can pick up the lesson. Bounded: 2 KB per entry, 20 KB total before rotation to AGENTS.md.archive. Use sparingly — narrative, not structured data.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      agent: { type: 'string', minLength: 1, maxLength: 64 },
      body: { type: 'string', minLength: 1, maxLength: 4096 },
    },
    required: ['agent', 'body'],
  },
  async handler({ agent, body }, ctx) {
    const r = (0,_posture_agents_memory_js__WEBPACK_IMPORTED_MODULE_20__/* .appendAgentsMemory */ .eu)(ctx.sessionRoot, { agent, body });
    return { _meta: META, ...r };
  },
};

const read_agents_memory = {
  name: 'read_agents_memory',
  description: 'Read the AGENTS.md continual-learning file (and AGENTS.md.archive if needed). Returns the most-recent ~6 KB tail by default; pass `full: true` for everything. The SessionStart hook already surfaces a summary; use this when an agent wants to look up specifics mid-session.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      full: { type: 'boolean' },
    },
  },
  async handler({ full }, ctx) {
    const body = (0,_posture_agents_memory_js__WEBPACK_IMPORTED_MODULE_20__/* .readAgentsMemory */ .ox)(ctx.sessionRoot);
    if (!body) return { _meta: META, present: false };
    if (full) return { _meta: META, present: true, length: body.length, content: body };
    // Tail-only — same logic as summarizeForSession but inlined to avoid a
    // second import surface.
    const limit = 6 * 1024;
    if (body.length <= limit) return { _meta: META, present: true, length: body.length, content: body };
    const tail = body.slice(-limit);
    const firstSection = tail.indexOf('\n## ');
    const slice = firstSection >= 0 ? tail.slice(firstSection) : tail;
    return { _meta: META, present: true, length: body.length, truncated: true, content: slice };
  },
};

// ─── query_triage_memory ───────────────────────────────────────────────────
// Natural-language Q&A over past triage decisions (wont-fix / false-positive
// markings + reasons). Backed by .agentic-security/triage-memory.jsonl, which
// is auto-populated by triage.transition(). Returns at most 10 most-relevant
// past decisions.

const query_triage_memory = {
  name: 'query_triage_memory',
  description: 'Search past triage decisions (wont-fix / false-positive) by natural-language query. Returns up to 10 most-relevant past decisions with their reasons. Use when you see a new finding and want to know "did we already decide on something like this?" — answers in seconds without re-reading the full AGENTS.md narrative.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      query: { type: 'string', description: 'Free-text terms to match against past reasons / vuln text / file paths / family names.' },
    },
  },
  async handler({ query }, ctx) {
    const { queryMemory } = await Promise.resolve(/* import() */).then(__webpack_require__.bind(__webpack_require__, 21905));
    const raw = queryMemory(ctx.sessionRoot, query || '');
    // Stage 6 correctness audit: this returned queryMemory's output
    // verbatim, with no redaction pass — every other tool that echoes
    // scanned-source-derived text redacts it (mcp/CLAUDE.md's "Adding a new
    // tool" step 3). Round-trip through redactString the same way
    // redactFinding already does for its own opaque `.trace` field: results
    // here mix shapes (a triage decision's free-text `reason`, a finding's
    // `vuln`/`family`/file path), so scrubbing the whole serialized
    // structure catches secret-shaped substrings regardless of which field
    // they landed in, rather than hardcoding a field allowlist that could
    // miss one.
    let results;
    try { results = JSON.parse((0,_redact_js__WEBPACK_IMPORTED_MODULE_19__/* .redactString */ .rd)(JSON.stringify(raw))); }
    catch { results = raw; }
    return {
      _meta: META,
      count: results.length,
      results,
    };
  },
};

// ─── query_findings_memory ─────────────────────────────────────────────────
// Natural-language Q&A across the scanner's accumulated institutional
// memory: current findings + past triage decisions + scan history +
// AGENTS.md narrative. Use to answer "have we seen something like this
// before?" without reading multiple files.

const query_findings_memory = {
  name: 'query_findings_memory',
  description: 'Search the scanner accumulated memory (current scan findings + past wont-fix/false-positive decisions + scan history + AGENTS.md narrative) by natural-language terms. Returns top-10 results scored by term-match count and ranked finding > triage > history > AGENTS.md.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      query: { type: 'string', description: 'Natural-language search terms (2+ chars each).' },
    },
    required: ['query'],
  },
  async handler({ query }, ctx) {
    const { queryFindingsMemory } = await __webpack_require__.e(/* import() */ 3839).then(__webpack_require__.bind(__webpack_require__, 23839));
    const raw = queryFindingsMemory(ctx.sessionRoot, query || '');
    // Stage 6 correctness audit — same redaction gap and same fix as
    // query_triage_memory just above: this mixes four differently-shaped
    // result kinds (finding / triage / history / AGENTS.md text), so a
    // whole-structure redactString round-trip is applied rather than a
    // per-field allowlist that could miss one of the four shapes.
    let body;
    try { body = JSON.parse((0,_redact_js__WEBPACK_IMPORTED_MODULE_19__/* .redactString */ .rd)(JSON.stringify(raw))); }
    catch { body = raw; }
    return { _meta: META, ...body };
  },
};

// ─── lookup_cve ────────────────────────────────────────────────────────────
// LangChain harness-anatomy #8: bridge the knowledge-cutoff gap by exposing
// the local OSV / KEV / EPSS cache as a structured tool. Read-only — never
// triggers a network fetch from the MCP path.
const lookup_cve = {
  name: 'lookup_cve',
  description: 'Look up a CVE id in the local OSV / KEV / EPSS caches. Returns staleness-tiered cached data (fresh / recent / stale / very-stale). Read-only — does NOT fetch fresh data; the scan pipeline is the only thing that populates the cache. Use to inform reasoning about an SCA finding without relying on the model\'s training cutoff.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      cve: { type: 'string', minLength: 9, maxLength: 20 },
    },
    required: ['cve'],
  },
  async handler({ cve }, _ctx) {
    const r = (0,_posture_cve_lookup_js__WEBPACK_IMPORTED_MODULE_21__/* .lookupCve */ .x)(cve);
    return { _meta: META, ...r };
  },
};

const query_cache_telemetry = {
  name: 'query_cache_telemetry',
  description: 'Read prompt-cache economics for the current session from the Claude Code transcript: cache-hit %, $ saved by caching, $ wasted on avoidable cache misses (model switches / TTL gaps / prefix changes), and a per-model breakdown. Read-only, no network. Use to reason about token-cost efficiency and whether a model switch is worth the cache rewarm.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      // Optional explicit transcript path; otherwise derived from the session root.
      transcript_path: { type: 'string', minLength: 1, maxLength: 4096 },
    },
    required: [],
  },
  async handler({ transcript_path } = {}, ctx) {
    const result = (0,_posture_cache_economics_js__WEBPACK_IMPORTED_MODULE_11__.analyzeTranscript)({ transcriptPath: transcript_path, projectDir: ctx?.sessionRoot || process.cwd() });
    if (!result.ok) return { _meta: META, ok: false, reason: result.reason };
    return {
      _meta: META,
      ok: true,
      metrics: result.metrics,
      leaks: result.leaks,
      report: (0,_posture_cache_economics_js__WEBPACK_IMPORTED_MODULE_11__.formatCacheReport)(result),
      statusline: (0,_posture_cache_economics_js__WEBPACK_IMPORTED_MODULE_11__.renderCacheStatusLine)(result.metrics),
    };
  },
};

// ─── synthesize_sca_upgrade ───────────────────────────────────────────────
// Phase 3 / Item 5 of the SCA improvement plan. Read-only counterpart to
// apply_sca_upgrade — produces a structured upgrade plan via the
// ecosystem's native --dry-run command. Safe to call any number of times.
let _scaUpgrade;
async function _getScaUpgrade() {
  if (!_scaUpgrade) _scaUpgrade = await __webpack_require__.e(/* import() */ 5333).then(__webpack_require__.bind(__webpack_require__, 35333));
  return _scaUpgrade;
}
const synthesize_sca_upgrade = {
  name: 'synthesize_sca_upgrade',
  description: 'Generate an upgrade plan for a single SCA finding. Runs the ecosystem dry-run (npm install --dry-run, pip install --dry-run, cargo update --dry-run). Returns { ecosystem, package, currentVersion, targetVersion, isBreaking, command, manifestFiles, dryRun, testCommand }. No writes.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      finding_id: { type: 'string', minLength: 1, maxLength: 256 },
    },
    required: ['finding_id'],
  },
  async handler({ finding_id }, ctx) {
    const { scan, status } = _readLastScanVerified(ctx.sessionRoot, { allowUnsigned: true });
    if (!scan) throw new Error(`No usable scan state (${status}).`);
    const f = _findById(scan, finding_id);
    if (!f) throw new Error(`Finding not found: ${finding_id}`);
    if (f.type !== 'vulnerable_dep') {
      return { _meta: META, ok: false, reason: 'finding is not an SCA vulnerable_dep — use synthesize_fix for SAST findings' };
    }
    const { planScaUpgrade } = await _getScaUpgrade();
    const plan = await planScaUpgrade({ scanRoot: ctx.sessionRoot, finding: f });
    return { _meta: META, ...plan };
  },
};

// ─── apply_sca_upgrade ────────────────────────────────────────────────────
// Phase 3 / Item 5 of the SCA improvement plan. The MCP `apply_fix` path
// refuses every package-manager manifest by design. This tool bypasses
// that ONLY for the install pathway — it shells out to the ecosystem's
// native package manager (npm / pip / cargo / go) which is the right
// surface for safely modifying manifests + lockfiles. Backs up affected
// manifests before the install; runs the project's test command (if
// detected); rolls back manifests if tests fail.
const apply_sca_upgrade = {
  name: 'apply_sca_upgrade',
  description: 'Apply a vulnerable_dep upgrade. Backs up manifests, runs the package manager, runs the project test command, restores manifests on test failure. Requires confirm:true. Set run_tests:false to skip the test gate (NOT recommended).',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      finding_id: { type: 'string', minLength: 1, maxLength: 256 },
      confirm: { type: 'boolean' },
      run_tests: { type: 'boolean' },
    },
    required: ['finding_id', 'confirm'],
  },
  async handler({ finding_id, confirm, run_tests = true }, ctx) {
    if (confirm !== true) {
      return { _meta: META, applied: false, reason: 'apply_sca_upgrade requires confirm: true.' };
    }
    const { scan, status } = _readLastScanVerified(ctx.sessionRoot, { allowUnsigned: false });
    if (!scan) {
      return { _meta: META, applied: false, reason: `last-scan.json failed integrity check: ${status}. Run a fresh scan.` };
    }
    const f = _findById(scan, finding_id);
    if (!f) return { _meta: META, applied: false, reason: `Finding not found: ${finding_id}` };
    if (f.type !== 'vulnerable_dep') {
      return { _meta: META, applied: false, reason: 'finding is not an SCA vulnerable_dep — use apply_fix for SAST findings' };
    }
    const { applyScaUpgrade } = await _getScaUpgrade();
    const result = await applyScaUpgrade({ scanRoot: ctx.sessionRoot, finding: f, runTests: run_tests });
    return { _meta: META, ...result };
  },
};

// X-407: read-only scenario export; the factory takes this file's confinement so the two modules do not import each other.
const { invariant_scenario_export } = (0,_invariant_tools_js__WEBPACK_IMPORTED_MODULE_17__/* .makeInvariantTools */ ._)({ confine: _confine, META });
// X-707: read-only portfolio progress view, same factory shape.
const { portfolio_progress } = (0,_portfolio_tools_js__WEBPACK_IMPORTED_MODULE_18__/* .makePortfolioTools */ ._)({ confine: _confine, META });

const ALL_TOOLS = [scan_diff, query_taint, explain_finding, apply_fix, verify_fix, synthesize_fix, find_rule_module, append_scratchpad, read_scratchpad, append_agents_memory, read_agents_memory, lookup_cve, synthesize_sca_upgrade, apply_sca_upgrade, query_triage_memory, query_findings_memory, query_cache_telemetry, _dataflow_tools_js__WEBPACK_IMPORTED_MODULE_16__/* .dataflow_get_graph */ .HX, _dataflow_tools_js__WEBPACK_IMPORTED_MODULE_16__/* .dataflow_get_node */ .HI, _dataflow_tools_js__WEBPACK_IMPORTED_MODULE_16__/* .dataflow_get_edge */ .gC, _dataflow_tools_js__WEBPACK_IMPORTED_MODULE_16__/* .dataflow_get_flow */ .ri, invariant_scenario_export, portfolio_progress];

__webpack_async_result__();
} catch(e) { __webpack_async_result__(e); } });

/***/ }),

/***/ 61211:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   t: () => (/* binding */ validate)
/* harmony export */ });
// Minimal JSON Schema validator — just the subset our tool schemas use.
// No deps. Throws on invalid input with a path-prefixed error message.
//
// Supported keywords: type (object/array/string/boolean/number),
// required, properties, items, enum, minItems, maxItems, maxLength,
// minLength, additionalProperties (only as `false` — strict).

const TYPE_OF = (v) => {
  if (v === null) return 'null';
  if (Array.isArray(v)) return 'array';
  return typeof v;
};

function validate(schema, value, path = 'arguments') {
  if (!schema) return;
  const t = schema.type;
  if (t === 'object') {
    if (TYPE_OF(value) !== 'object') throw new Error(`${path}: expected object, got ${TYPE_OF(value)}`);
    for (const req of schema.required || []) {
      if (!(req in value)) throw new Error(`${path}: missing required property "${req}"`);
    }
    if (schema.additionalProperties === false) {
      const allowed = new Set(Object.keys(schema.properties || {}));
      for (const k of Object.keys(value)) {
        if (!allowed.has(k)) throw new Error(`${path}: unexpected property "${k}"`);
      }
    }
    for (const [k, sub] of Object.entries(schema.properties || {})) {
      if (k in value) validate(sub, value[k], `${path}.${k}`);
    }
  } else if (t === 'array') {
    if (!Array.isArray(value)) throw new Error(`${path}: expected array, got ${TYPE_OF(value)}`);
    if (schema.minItems != null && value.length < schema.minItems) throw new Error(`${path}: minItems=${schema.minItems}, got length=${value.length}`);
    if (schema.maxItems != null && value.length > schema.maxItems) throw new Error(`${path}: maxItems=${schema.maxItems}, got length=${value.length}`);
    if (schema.items) for (let i = 0; i < value.length; i++) validate(schema.items, value[i], `${path}[${i}]`);
  } else if (t === 'string') {
    if (typeof value !== 'string') throw new Error(`${path}: expected string, got ${TYPE_OF(value)}`);
    if (schema.enum && !schema.enum.includes(value)) throw new Error(`${path}: must be one of [${schema.enum.join(', ')}]`);
    if (schema.maxLength != null && value.length > schema.maxLength) throw new Error(`${path}: maxLength=${schema.maxLength}, got length=${value.length}`);
    if (schema.minLength != null && value.length < schema.minLength) throw new Error(`${path}: minLength=${schema.minLength}, got length=${value.length}`);
  } else if (t === 'boolean') {
    if (typeof value !== 'boolean') throw new Error(`${path}: expected boolean, got ${TYPE_OF(value)}`);
  } else if (t === 'number' || t === 'integer') {
    if (typeof value !== 'number') throw new Error(`${path}: expected number, got ${TYPE_OF(value)}`);
    if (t === 'integer' && !Number.isInteger(value)) throw new Error(`${path}: expected integer`);
    if (schema.minimum != null && value < schema.minimum) throw new Error(`${path}: < minimum (${schema.minimum})`);
    if (schema.maximum != null && value > schema.maximum) throw new Error(`${path}: > maximum (${schema.maximum})`);
  }
}


/***/ }),

/***/ 79907:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   eu: () => (/* binding */ appendAgentsMemory),
/* harmony export */   ox: () => (/* binding */ readAgentsMemory)
/* harmony export */ });
/* unused harmony exports summarizeForSession, _internals */
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(73024);
/* harmony import */ var node_path__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(76760);
/* harmony import */ var _state_dir_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(31174);
// AGENTS.md — writable continual-learning memory (harness-anatomy #2).
//
// LangChain post:
//   "Harnesses support memory file standards like AGENTS.md which get
//    injected into context on agent start. As agents add and edit this file,
//    harnesses load the updated file into context. This is a form of
//    continual learning where agents durably store knowledge from one
//    session and inject that knowledge into future sessions."
//
// Distinct from CLAUDE.md:
//   - CLAUDE.md = human-authored project conventions, gotchas, layout.
//   - AGENTS.md = agent-authored notes ("what worked / didn't work / I'd try
//                  differently next time"). Append-only. Bounded.
//
// Lives at `<project>/.agentic-security/AGENTS.md`.
//
// Bounds:
//   - MAX_BYTES (default 20 KB) — past this, the oldest entries rotate to
//     `AGENTS.md.archive` (also bounded; oldest archive entries are dropped).
//   - MAX_ENTRY_BYTES (default 2 KB) — caps a single appendage.
//   - Entries are append-only with an ISO timestamp + section divider, so
//     readers can grep / slice by date without parsing.
//
// We deliberately avoid tying AGENTS.md to a session-id namespace. The post's
// recommendation is FLAT continual learning — the whole project's agents see
// each other's notes. Subagents that want session-scoped scratch use the
// agent-scratchpad surface instead.





const MEMORY_FILE = '.agentic-security/AGENTS.md';
const ARCHIVE_FILE = '.agentic-security/AGENTS.md.archive';
const MAX_BYTES = 20 * 1024;
const MAX_ENTRY_BYTES = 2 * 1024;
const ARCHIVE_MAX_BYTES = 200 * 1024;
const HEADER = '# AGENTS.md\n\nAgent-authored continual-learning notes. Each entry: timestamp + agent name + one short paragraph. New entries appended at the bottom; oldest entries rotate to AGENTS.md.archive when this file exceeds 20 KB.\n\n';

function _resolve(scanRoot) { return (0,_state_dir_js__WEBPACK_IMPORTED_MODULE_2__.statePath)(scanRoot, 'AGENTS.md'); }
function _archivePath(scanRoot) { return (0,_state_dir_js__WEBPACK_IMPORTED_MODULE_2__.statePath)(scanRoot, 'AGENTS.md.archive'); }

function readAgentsMemory(scanRoot) {
  const fp = _resolve(scanRoot);
  if (!node_fs__WEBPACK_IMPORTED_MODULE_0__.existsSync(fp)) return '';
  try { return node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(fp, 'utf8'); } catch { return ''; }
}

function appendAgentsMemory(scanRoot, { agent, body }) {
  if (typeof agent !== 'string' || !agent.length) {
    return { ok: false, reason: 'agent: required string' };
  }
  if (!/^[A-Za-z0-9_.-]{1,64}$/.test(agent)) {
    return { ok: false, reason: 'agent: must match [A-Za-z0-9_.-]{1,64}' };
  }
  if (typeof body !== 'string' || !body.trim().length) {
    return { ok: false, reason: 'body: required non-empty string' };
  }
  let snippet = body.trim();
  // Strip control chars and cap.
  snippet = snippet.replace(/[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f]/g, ' ');
  if (snippet.length > MAX_ENTRY_BYTES) {
    snippet = snippet.slice(0, MAX_ENTRY_BYTES) + '…';
  }
  const ts = new Date().toISOString();
  const entry = `\n## ${ts}  agent: ${agent}\n\n${snippet}\n`;
  try {
    const fp = _resolve(scanRoot);
    if (!(0,_state_dir_js__WEBPACK_IMPORTED_MODULE_2__.stateWritesEnabled)()) return;
  node_fs__WEBPACK_IMPORTED_MODULE_0__.mkdirSync(node_path__WEBPACK_IMPORTED_MODULE_1__.dirname(fp), { recursive: true });
    if (!node_fs__WEBPACK_IMPORTED_MODULE_0__.existsSync(fp)) node_fs__WEBPACK_IMPORTED_MODULE_0__.writeFileSync(fp, HEADER);
    node_fs__WEBPACK_IMPORTED_MODULE_0__.appendFileSync(fp, entry);
    _maybeRotate(scanRoot);
    const stat = node_fs__WEBPACK_IMPORTED_MODULE_0__.statSync(fp);
    return { ok: true, entryBytes: entry.length, fileSize: stat.size };
  } catch (e) {
    return { ok: false, reason: `write-failed: ${e.message}` };
  }
}

function _maybeRotate(scanRoot) {
  const fp = _resolve(scanRoot);
  let body;
  try { body = node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(fp, 'utf8'); } catch { return; }
  if (body.length <= MAX_BYTES) return;
  // Split on the `## ` entry headers. Keep the most-recent N until the head
  // (everything before the cut) drops below MAX_BYTES/2; move the head to
  // the archive.
  const head = HEADER;
  const trailing = body.slice(head.length);
  const sections = trailing.split(/(?=\n## )/g).filter(s => s.length);
  // Walk from the end, accumulating until we have roughly MAX_BYTES/2 of
  // recent entries. Everything else goes to the archive.
  let kept = '', archive = '', accum = 0;
  for (let i = sections.length - 1; i >= 0; i--) {
    if (accum + sections[i].length <= MAX_BYTES / 2) {
      kept = sections[i] + kept;
      accum += sections[i].length;
    } else {
      archive = sections.slice(0, i + 1).join('') + archive;
      break;
    }
  }
  try {
    node_fs__WEBPACK_IMPORTED_MODULE_0__.writeFileSync(fp, head + kept);
    if (archive.length) {
      const arcFp = _archivePath(scanRoot);
      let existing = '';
      try { existing = node_fs__WEBPACK_IMPORTED_MODULE_0__.existsSync(arcFp) ? node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(arcFp, 'utf8') : ''; } catch {}
      let next = existing + archive;
      if (next.length > ARCHIVE_MAX_BYTES) {
        // Drop oldest entries until under cap.
        const oldestSplit = next.split(/(?=\n## )/g).filter(s => s.length);
        while (oldestSplit.length && next.length > ARCHIVE_MAX_BYTES) {
          oldestSplit.shift();
          next = oldestSplit.join('');
        }
      }
      node_fs__WEBPACK_IMPORTED_MODULE_0__.writeFileSync(arcFp, next);
    }
  } catch { /* best-effort rotation */ }
}

// Public summary helper for the SessionStart hook. Returns a tail aligned
// to a section header (no leading partial entry, no leading newline).
function summarizeForSession(scanRoot, { maxBytes = 6 * 1024 } = {}) {
  const body = readAgentsMemory(scanRoot);
  if (!body) return null;
  if (body.length <= maxBytes) return body;
  const tail = body.slice(-maxBytes);
  const firstSection = tail.indexOf('\n## ');
  if (firstSection < 0) return tail;
  // Slice past the leading `\n` so the result starts with `## `.
  return tail.slice(firstSection + 1);
}

const _internals = { MAX_BYTES, MAX_ENTRY_BYTES, MEMORY_FILE, ARCHIVE_FILE };


/***/ }),

/***/ 58752:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   analyzeTranscript: () => (/* binding */ analyzeTranscript),
/* harmony export */   formatCacheReport: () => (/* binding */ formatCacheReport),
/* harmony export */   renderCacheStatusLine: () => (/* binding */ renderCacheStatusLine)
/* harmony export */ });
/* unused harmony export _internal */
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(73024);
/* harmony import */ var node_os__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(48161);
/* harmony import */ var node_path__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(76760);
// Prompt-cache economics — turn Claude Code's own transcript usage into a
// dollarized report: how much prompt caching saved, how much was wasted on
// avoidable cache misses, and what invalidated the cache.
//
// Source of truth: the Claude Code transcript at
//   ~/.claude/projects/<enc>/<session>.jsonl
// where <enc> is CLAUDE_PROJECT_DIR with `/` and `.` replaced by `-`. Each
// assistant turn carries `message.usage` with input/output/cache_read/
// cache_creation token counts (and a 5m/1h write split). We price those against
// per-model rates to compute real economics — no estimates, no network.
//
// Pure compute on parsed records; only `locateTranscript`/`parseTranscriptUsage`
// touch the filesystem. ESM (scanner tree). A trimmed CJS twin lives at
// hooks/lib/transcript.js for the CJS hooks; test/cache-economics.test.js asserts
// the two agree.




// Cents-scale money formatter (fmtUsd in risk-dollars.js targets five-figure
// breach costs and won't round sub-dollar values).
function money(n) {
  const v = Number(n) || 0;
  return Math.abs(v) >= 1 ? `$${v.toFixed(2)}` : `$${v.toFixed(4)}`;
}

// Per-1M-token rates (input / output). Mirror hooks/model-cost-advisor.js MODELS.
const MODEL_RATES = {
  fable:   { label: 'Fable 5',    in: 10, out: 50 },
  opus:    { label: 'Opus 4.8',   in: 5,  out: 25 },
  sonnet5: { label: 'Sonnet 5',   in: 3,  out: 15 },
  sonnet:  { label: 'Sonnet 4.6', in: 3,  out: 15 },
  haiku:   { label: 'Haiku 4.5',  in: 1,  out: 5 },
};
const CACHE_READ_MULT = 0.1;   // cache read ≈ 0.1× input
const CACHE_WRITE_MULT = 1.25; // 5-minute cache write ≈ 1.25× input
const CACHE_WRITE_1H_MULT = 2.0; // 1-hour cache write ≈ 2× input
const TTL_MS = 5 * 60 * 1000;

// Map any model string to a rate family. Returns null for unpriceable models
// (e.g. "<synthetic>" sidechain/compaction turns) so they're skipped.
function rateFor(model) {
  if (typeof model !== 'string') return null;
  const s = model.toLowerCase();
  if (s.includes('fable') || s.includes('mythos')) return MODEL_RATES.fable;
  if (s.includes('haiku')) return MODEL_RATES.haiku;
  if (s.includes('sonnet')) return (s.includes('sonnet-5') || s.includes('sonnet 5')) ? MODEL_RATES.sonnet5 : MODEL_RATES.sonnet;
  if (s.includes('opus')) return MODEL_RATES.opus;
  return null;
}

// ── Transcript discovery + parse ─────────────────────────────────────────────

function encodeProjectDir(dir) {
  return String(dir).replace(/[/.]/g, '-');
}

// Locate the session transcript. Prefer an explicit (hook-provided) path; else
// derive the project's transcript dir and take the most-recently-modified jsonl.
function locateTranscript({ transcriptPath, projectDir } = {}) {
  try {
    if (transcriptPath && node_fs__WEBPACK_IMPORTED_MODULE_0__.existsSync(transcriptPath)) return transcriptPath;
  } catch { /* fall through */ }
  try {
    const dir = node_path__WEBPACK_IMPORTED_MODULE_2__.join(node_os__WEBPACK_IMPORTED_MODULE_1__.homedir(), '.claude', 'projects', encodeProjectDir(projectDir || process.cwd()));
    if (!node_fs__WEBPACK_IMPORTED_MODULE_0__.existsSync(dir)) return null;
    const files = node_fs__WEBPACK_IMPORTED_MODULE_0__.readdirSync(dir)
      .filter(f => f.endsWith('.jsonl'))
      .map(f => ({ f: node_path__WEBPACK_IMPORTED_MODULE_2__.join(dir, f), m: node_fs__WEBPACK_IMPORTED_MODULE_0__.statSync(node_path__WEBPACK_IMPORTED_MODULE_2__.join(dir, f)).mtimeMs }))
      .sort((a, b) => b.m - a.m);
    return files.length ? files[0].f : null;
  } catch { return null; }
}

// Parse a transcript jsonl into per-assistant-turn usage records. Skips lines
// that aren't priceable assistant turns.
function parseTranscriptUsage(jsonlPath) {
  let raw;
  try { raw = node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(jsonlPath, 'utf8'); } catch { return []; }
  const records = [];
  for (const line of raw.split('\n')) {
    const t = line.trim();
    if (!t) continue;
    let o;
    try { o = JSON.parse(t); } catch { continue; }
    if (o.type !== 'assistant') continue;
    const msg = o.message;
    const u = msg && msg.usage;
    if (!u || !msg.model || !rateFor(msg.model)) continue;
    const cc = u.cache_creation || {};
    records.push({
      model: msg.model,
      input: u.input_tokens || 0,
      output: u.output_tokens || 0,
      cacheRead: u.cache_read_input_tokens || 0,
      cacheCreate: u.cache_creation_input_tokens || 0,
      cacheCreate5m: cc.ephemeral_5m_input_tokens || 0,
      cacheCreate1h: cc.ephemeral_1h_input_tokens || 0,
      ts: o.timestamp ? Date.parse(o.timestamp) : null,
    });
  }
  return records;
}

// ── Pure economics ───────────────────────────────────────────────────────────

function writeCostUsd(r, inRate) {
  const m5 = r.cacheCreate5m || 0, m1 = r.cacheCreate1h || 0;
  if (m5 + m1 > 0) return (m5 * CACHE_WRITE_MULT + m1 * CACHE_WRITE_1H_MULT) * inRate;
  return (r.cacheCreate || 0) * CACHE_WRITE_MULT * inRate; // breakdown absent
}

// Aggregate economics over parsed records.
function computeCacheEconomics(records) {
  let turns = 0, inTok = 0, outTok = 0, cacheRead = 0, cacheCreate = 0;
  let actualUsd = 0, uncachedUsd = 0, writePremiumUsd = 0;
  const perModel = {};

  for (const r of records) {
    const rate = rateFor(r.model);
    if (!rate) continue;
    turns++;
    const inRate = rate.in / 1e6, outRate = rate.out / 1e6;

    const readCost = r.cacheRead * inRate * CACHE_READ_MULT;
    const writeCost = writeCostUsd(r, inRate);
    const inCost = r.input * inRate;
    const outCost = r.output * outRate;
    const turnActual = readCost + writeCost + inCost + outCost;
    // What this turn would have cost with NO caching: every input-side token full price.
    const turnUncached = (r.cacheRead + r.cacheCreate + r.input) * inRate + outCost;

    actualUsd += turnActual;
    uncachedUsd += turnUncached;
    writePremiumUsd += writeCost - (r.cacheCreate * inRate); // the >1× premium paid to cache

    inTok += r.input; outTok += r.output; cacheRead += r.cacheRead; cacheCreate += r.cacheCreate;

    const key = rate.label;
    const pm = perModel[key] || (perModel[key] = { turns: 0, actualUsd: 0, cacheRead: 0, inputSide: 0 });
    pm.turns++; pm.actualUsd += turnActual; pm.cacheRead += r.cacheRead;
    pm.inputSide += r.cacheRead + r.cacheCreate + r.input;
  }

  const inputSide = cacheRead + cacheCreate + inTok;
  return {
    turns,
    tokens: { input: inTok, output: outTok, cacheRead, cacheCreate },
    actualUsd,
    uncachedUsd,
    savedUsd: uncachedUsd - actualUsd,         // net $ caching saved (can dip negative early)
    writePremiumUsd,                            // $ invested establishing caches
    cacheHitRatio: inputSide ? cacheRead / inputSide : 0,
    costPerTurnUsd: turns ? actualUsd / turns : 0,
    perModel,
  };
}

// Attribute cache drops: a turn that re-ingests a large prefix cold after a warm
// prior turn. Cause = model-switch | cache-expired | prefix-change.
function detectInvalidators(records) {
  const leaks = [];
  const MIN_WARM = 2000;
  for (let i = 1; i < records.length; i++) {
    const prev = records[i - 1], cur = records[i];
    const prevWarm = prev.cacheRead + prev.input + prev.cacheCreate;
    if (prevWarm < MIN_WARM) continue;
    const curFresh = cur.input + cur.cacheCreate;
    const coldish = cur.cacheRead < prevWarm * 0.25 && curFresh > prevWarm * 0.5;
    if (!coldish) continue;

    let cause;
    if (cur.model !== prev.model) cause = 'model-switch';
    else if (cur.ts && prev.ts && (cur.ts - prev.ts) > TTL_MS) cause = 'cache-expired';
    else cause = 'prefix-change';

    const rate = rateFor(cur.model);
    const inRate = rate ? rate.in / 1e6 : 0;
    // Extra paid vs. having kept the prefix as a cheap cache read.
    const wastedUsd = prevWarm * inRate * (1 - CACHE_READ_MULT);
    leaks.push({ turn: i, cause, wastedUsd, model: cur.model });
  }
  return leaks;
}

// Convenience: locate → parse → compute → detect. Returns { ok:false } when no
// transcript is available.
function analyzeTranscript(opts = {}) {
  const transcript = locateTranscript(opts);
  if (!transcript) return { ok: false, reason: 'no-transcript' };
  const records = parseTranscriptUsage(transcript);
  if (!records.length) return { ok: false, reason: 'no-priceable-turns', transcript };
  return {
    ok: true,
    transcript,
    metrics: computeCacheEconomics(records),
    leaks: detectInvalidators(records),
  };
}

// ── Report formatting ────────────────────────────────────────────────────────

const CAUSE_LABEL = {
  'model-switch': 'model switch (cache is model-scoped)',
  'cache-expired': 'cache expired (gap > 5-min TTL)',
  'prefix-change': 'prefix changed (system prompt / tools / context edit)',
};

// F6 — one-line HUD for a Claude Code statusLine command (mirrors
// watch-mode.js renderStatusLine). Takes the metrics from computeCacheEconomics.
function renderCacheStatusLine(metrics) {
  if (!metrics || !metrics.turns) return 'agentic-security: no session cost yet';
  const hit = Math.round(metrics.cacheHitRatio * 100);
  return `agentic-security: ${money(metrics.actualUsd)} · ${hit}% cached · ${money(metrics.costPerTurnUsd)}/turn`;
}

function formatCacheReport(result) {
  if (!result.ok) {
    return result.reason === 'no-transcript'
      ? 'agentic-security: no Claude Code transcript found for this project yet.'
      : 'agentic-security: transcript has no priceable model turns yet.';
  }
  const m = result.metrics;
  const lines = [];
  lines.push('');
  lines.push('  Prompt-cache economics — this session');
  lines.push(`  ${result.turns ?? m.turns} model turns\n`);
  lines.push(`  cache hit ratio     ${(m.cacheHitRatio * 100).toFixed(1)}%  (input-side tokens served from cache)`);
  lines.push(`  spent               ${money(m.actualUsd)}   (~${money(m.costPerTurnUsd)}/turn)`);
  lines.push(`  ▶ saved by caching  ${money(m.savedUsd)}   vs. ${money(m.uncachedUsd)} with no cache`);
  lines.push(`  invested in caches  ${money(m.writePremiumUsd)}   (write premium over base input)`);
  lines.push('');
  lines.push('  tokens: '
    + `${m.tokens.cacheRead.toLocaleString()} cached-read · `
    + `${m.tokens.cacheCreate.toLocaleString()} cache-write · `
    + `${m.tokens.input.toLocaleString()} fresh-in · `
    + `${m.tokens.output.toLocaleString()} out`);

  const models = Object.keys(m.perModel);
  if (models.length > 1) {
    lines.push('\n  by model:');
    for (const k of models.sort()) {
      const pm = m.perModel[k];
      const hr = pm.inputSide ? (pm.cacheRead / pm.inputSide * 100).toFixed(0) : '0';
      lines.push(`    ${k.padEnd(12)} ${pm.turns} turns · ${money(pm.actualUsd)} · ${hr}% cached`);
    }
  }

  if (result.leaks && result.leaks.length) {
    const wasted = result.leaks.reduce((s, l) => s + l.wastedUsd, 0);
    lines.push(`\n  ⚠ cache leaks (${result.leaks.length}, ~${money(wasted)} wasted re-ingesting context):`);
    const byCause = {};
    for (const l of result.leaks) {
      (byCause[l.cause] || (byCause[l.cause] = { n: 0, usd: 0 })).n++;
      byCause[l.cause].usd += l.wastedUsd;
    }
    for (const c of Object.keys(byCause).sort()) {
      lines.push(`    · ${byCause[c].n}× ${CAUSE_LABEL[c] || c} — ~${money(byCause[c].usd)}`);
    }
    lines.push('    Keep one model + a stable system prompt within a working window to avoid these.');
  } else {
    lines.push('\n  ✓ no cache leaks detected — your context stayed warm.');
  }
  lines.push('');
  return lines.join('\n');
}

// Test surface (underscore export is exempt from the dead-module gate).
const _internal = {
  MODEL_RATES, CACHE_READ_MULT, CACHE_WRITE_MULT, CACHE_WRITE_1H_MULT,
  rateFor, locateTranscript, parseTranscriptUsage, computeCacheEconomics, detectInvalidators,
};


/***/ }),

/***/ 71364:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   x: () => (/* binding */ lookupCve)
/* harmony export */ });
/* unused harmony export _internals */
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(73024);
/* harmony import */ var node_os__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(48161);
/* harmony import */ var node_path__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(76760);
/* harmony import */ var node_crypto__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(77598);
// CVE lookup — read-only against the per-install OSV / KEV / EPSS caches.
//
// LangChain harness-anatomy post:
//   "Knowledge cutoffs mean that models can't directly access new data like
//    updated library versions without the user providing them directly."
//
// The validator and any subagent reasoning about an SCA finding can call
// `lookup_cve(cve_id)` to get the most recently-cached OSV advisory, the
// CISA KEV entry if listed, and the EPSS exploit-prediction percentile, all
// with `staleness` metadata so the caller can decide whether to trust the
// cached value.
//
// This module deliberately NEVER triggers a network fetch — the scan
// pipeline is the only thing that populates the cache. If a CVE isn't
// cached, we return `present: false` for that source rather than blocking
// on a fetch and risking a multi-second MCP timeout.






const CACHE_DIR = node_path__WEBPACK_IMPORTED_MODULE_2__.join(node_os__WEBPACK_IMPORTED_MODULE_1__.homedir(), '.claude', 'agentic-security', 'osv-cache');

function _keyToPath(key) {
  const safe = node_crypto__WEBPACK_IMPORTED_MODULE_3__.createHash('sha256').update(key).digest('hex');
  return node_path__WEBPACK_IMPORTED_MODULE_2__.join(CACHE_DIR, safe + '.json');
}

function _readCache(key) {
  const fp = _keyToPath(key);
  if (!node_fs__WEBPACK_IMPORTED_MODULE_0__.existsSync(fp)) return { present: false };
  let body;
  try { body = node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(fp, 'utf8'); }
  catch { return { present: false, error: 'unreadable' }; }
  let parsed;
  try { parsed = JSON.parse(body); }
  catch { return { present: false, error: 'unparseable' }; }
  let mtime = null;
  try { mtime = node_fs__WEBPACK_IMPORTED_MODULE_0__.statSync(fp).mtimeMs; } catch {}
  return { present: true, data: parsed, cachedAt: mtime, ageMs: mtime ? Date.now() - mtime : null };
}

function _stalenessTier(ageMs) {
  if (ageMs === null || ageMs === undefined) return 'unknown';
  if (ageMs < 24 * 3600 * 1000) return 'fresh';        // <1d
  if (ageMs < 7 * 24 * 3600 * 1000) return 'recent';   // <1w
  if (ageMs < 30 * 24 * 3600 * 1000) return 'stale';   // <1mo
  return 'very-stale';
}

const CVE_RE = /^CVE-\d{4}-\d{1,7}$/i;

function lookupCve(rawId) {
  if (typeof rawId !== 'string' || !CVE_RE.test(rawId)) {
    return { ok: false, reason: 'invalid-cve-id', expected: 'CVE-YYYY-NNNN' };
  }
  const cve = rawId.toUpperCase();

  // KEV catalog — single cached blob keyed at 'kev:catalog'.
  const kevCacheRaw = _readCache('kev:catalog');
  let kev = { present: false };
  if (kevCacheRaw.present) {
    // The blob shape from engine.js: { ts, byCve: { 'CVE-XXX': { ... } } }
    // sessionStorage shim stores the value as the JSON-stringified inner
    // object directly (no extra wrapper).
    const blob = kevCacheRaw.data;
    const byCve = blob?.byCve || null;
    if (byCve && byCve[cve]) {
      kev = {
        present: true,
        ...byCve[cve],
        cachedAt: kevCacheRaw.cachedAt,
        ageMs: kevCacheRaw.ageMs,
        staleness: _stalenessTier(kevCacheRaw.ageMs),
      };
    } else if (byCve) {
      // Catalog is cached but doesn't list this CVE — meaningful negative.
      kev = {
        present: false, listedInCatalog: false,
        cachedAt: kevCacheRaw.cachedAt, ageMs: kevCacheRaw.ageMs,
        staleness: _stalenessTier(kevCacheRaw.ageMs),
      };
    }
  }

  // EPSS — per-CVE cache at 'epss:CVE-XXX'.
  const epssRaw = _readCache('epss:' + cve);
  let epss = { present: false };
  if (epssRaw.present) {
    epss = {
      present: epssRaw.data !== false,   // engine stores `false` for "looked up, no record"
      score: epssRaw.data?.score ?? null,
      percentile: epssRaw.data?.percentile ?? null,
      cachedAt: epssRaw.cachedAt,
      ageMs: epssRaw.ageMs,
      staleness: _stalenessTier(epssRaw.ageMs),
    };
  }

  // OSV — entries are keyed by vuln id (GHSA-... or CVE-...). The engine
  // caches them at 'vuln:<id>'. We do a direct CVE lookup AND a soft probe
  // for any known alias the caller provided implicitly through the KEV
  // hit's vendor/product (no — we keep this simple: direct lookup only).
  const osvRaw = _readCache('vuln:' + cve);
  let osv = { present: false };
  if (osvRaw.present) {
    osv = {
      present: true,
      data: osvRaw.data,
      cachedAt: osvRaw.cachedAt, ageMs: osvRaw.ageMs,
      staleness: _stalenessTier(osvRaw.ageMs),
    };
  }

  return {
    ok: true,
    cve,
    kev,
    epss,
    osv,
    sourcesFound: [kev.present, epss.present, osv.present].filter(Boolean).length,
    note: (kev.present || epss.present || osv.present)
      ? 'cached values only; staleness tier per source. The MCP tool does NOT trigger a network fetch.'
      : 'no cached data for this CVE on the current install. Run a scan against a project that depends on the affected package, or set $AGENTIC_SECURITY_OFFLINE=0 and run a scan to populate the cache.',
  };
}

const _internals = { CACHE_DIR, CVE_RE, _stalenessTier };


/***/ }),

/***/ 30413:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   X: () => (/* binding */ synthesizeDeterministicPatch)
/* harmony export */ });
// Deterministic fix synthesis (#1) — for the narrow set of vulnerability classes
// where a context-INDEPENDENT literal swap is a safe, correct fix, produce a
// full-file replacement from the current file content. No LLM, no guessing, no
// per-finding bloat in last-scan.json (the patch is materialized on demand by
// synthesize_fix from the live file, not stored on every finding).
//
// Safety: every patch this produces is still gated by verify_fix before apply_fix
// writes it (original finding gone + no new ≥medium + lint clean). So a swap that
// a rule mis-attributed simply fails verification instead of landing a bad edit —
// this module widens the deterministic-fix surface without weakening the gate.
//
// Returns { patch: { [relFile]: newContent }, ruleId } or null when no
// deterministic fix applies to the finding.

const JS_EXT = /\.(?:js|jsx|ts|tsx|mjs|cjs)$/i;
const PY_EXT = /\.py$/i;
const JAVA_EXT = /\.java$/i;

// Each rule gates on the finding's cwe/family, then rewrites the whole-file
// content. transform() returns the new content, or null when nothing changed
// (e.g. the vulnerable token isn't literally present — then we don't claim a fix).
const RULES = [
  {
    id: 'weak-hash-sha256',
    // md5 / sha1 → sha256. Every occurrence in the file is a weak hash, so
    // swapping them all is safe; the verifier confirms the weak-hash finding is
    // gone and nothing worse appeared.
    applies: (f) => /CWE-(?:327|328|916)/.test(f.cwe || '') || /weak.?hash/i.test(f.family || ''),
    // SARD_AGENTIC_SECURITY_PRD.md Phase 8 bench work found this rule's
    // `applies()` gate matched Java findings (CWE-327/328) by cwe/family, but
    // `transform()` had no Java branch at all — every Java weak-hash finding
    // silently produced `null` (no fix), a coverage gap invisible from the
    // gate alone. `MessageDigest.getInstance("MD5"|"SHA1"|"SHA-1")` ->
    // `"SHA-256"` is the same class of context-independent literal swap as
    // the existing JS/Python branches (the algorithm name is a string
    // literal, not something requiring surrounding-code understanding).
    transform: (content, file) => {
      let out = content;
      if (JS_EXT.test(file)) {
        out = out.replace(/(\bcreateHash\s*\(\s*['"`])(?:md5|sha1)(['"`])/gi, '$1sha256$2');
      } else if (PY_EXT.test(file)) {
        out = out.replace(/\bhashlib\.(?:md5|sha1)\s*\(/g, 'hashlib.sha256(');
      } else if (JAVA_EXT.test(file)) {
        out = out.replace(/(\bMessageDigest\.getInstance\s*\(\s*")(?:MD5|SHA-?1)(")/gi, '$1SHA-256$2');
      }
      return out !== content ? out : null;
    },
  },
  {
    id: 'tls-verify-on',
    // Disabled TLS verification → enabled. rejectUnauthorized:false → true (JS),
    // verify=False → verify=True (Python requests).
    applies: (f) => /CWE-295/.test(f.cwe || '') || /tls.?no.?verify|cert.?(?:none|verify)/i.test(f.family || ''),
    transform: (content, file) => {
      let out = content;
      if (JS_EXT.test(file)) {
        out = out.replace(/(\brejectUnauthorized\s*:\s*)false\b/g, '$1true');
      } else if (PY_EXT.test(file)) {
        out = out.replace(/(\bverify\s*=\s*)False\b/g, '$1True');
      }
      return out !== content ? out : null;
    },
  },
];

function synthesizeDeterministicPatch(finding, fileContent) {
  if (!finding || typeof fileContent !== 'string' || !finding.file) return null;
  for (const rule of RULES) {
    try {
      if (!rule.applies(finding)) continue;
      const next = rule.transform(fileContent, finding.file);
      if (next && next !== fileContent) return { patch: { [finding.file]: next }, ruleId: rule.id };
    } catch { /* a single rule failing must never break synthesis */ }
  }
  return null;
}


/***/ }),

/***/ 78218:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   loadFreshLineageGraph: () => (/* binding */ loadFreshLineageGraph),
/* harmony export */   loadSignedGraph: () => (/* binding */ loadSignedGraph)
/* harmony export */ });
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(73024);
/* harmony import */ var _posture_state_dir_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(31174);
/* harmony import */ var _posture_integrity_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(71130);
// graph-loader.js — Milestone 3, sub-project Server, increment 1.
//
// Reads and VERIFIES the `.agentic-security/lineage-graph.json` artifact
// before `explore` is allowed to serve a single byte of it. Reuses
// `posture/integrity.js`'s `verifyLastScan` DIRECTLY (per the plan and the
// root CLAUDE.md's own instruction) — this module does not implement any
// signature comparison of its own. `verifyLastScan` already uses
// `crypto.timingSafeEqual` internally.
//
// Loaded ONCE at server startup (see bin/agentic-security.js's cmdExplore)
// and held in memory for the life of the process — this is a read-only,
// single-scan-snapshot server; a change to the graph on disk mid-session is
// out of scope for this increment (threat-model doc's own "P0 is
// read-only" framing).





/**
 * @param {string} scanRoot
 * @returns {{ok:true, graph:object} | {ok:false, reason:'missing'|'unsigned'|'tampered'|'malformed', message:string}}
 *
 * Four, and only four, distinct failure reasons — each with its own clear
 * message so an operator knows exactly what to do next:
 *   - 'missing'  — no lineage-graph.json at all. Run a scan with
 *                  AGENTIC_SECURITY_LINEAGE_DEEP=1 first.
 *   - 'unsigned' — the graph exists but its .sig sibling does not
 *                  (verifyLastScan returns null). Refuse to serve an
 *                  unverifiable graph.
 *   - 'tampered' — the graph exists and has a .sig, but the signature does
 *                  not match the body (verifyLastScan returns false). The
 *                  file was modified after signing, or signed under a
 *                  different install key.
 *   - 'malformed' — the body passed signature verification but is not
 *                  valid JSON. Should not happen from a normal scan; the
 *                  file may be corrupted on disk after signing.
 */
function loadSignedGraph(scanRoot) {
  const graphPath = (0,_posture_state_dir_js__WEBPACK_IMPORTED_MODULE_1__.statePath)(scanRoot, 'lineage-graph.json');
  const sigPath = graphPath + '.sig';

  if (!node_fs__WEBPACK_IMPORTED_MODULE_0__.existsSync(graphPath)) {
    return {
      ok: false,
      reason: 'missing',
      message: `No lineage graph found at ${graphPath}. Run a scan with AGENTIC_SECURITY_LINEAGE_DEEP=1 first (e.g. \`AGENTIC_SECURITY_LINEAGE_DEEP=1 agentic-security scan\`), then re-run \`agentic-security explore\`.`,
    };
  }

  let body;
  try {
    body = node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(graphPath, 'utf8');
  } catch (e) {
    return {
      ok: false,
      reason: 'missing',
      message: `Lineage graph found at ${graphPath} but could not be read: ${e && e.message ? e.message : e}.`,
    };
  }

  const verified = (0,_posture_integrity_js__WEBPACK_IMPORTED_MODULE_2__/* .verifyLastScan */ .Ef)(body, sigPath);
  if (verified === null) {
    return {
      ok: false,
      reason: 'unsigned',
      message: `Lineage graph at ${graphPath} has no signature file (${sigPath} is missing). Refusing to serve an unverifiable graph. Re-run the scan (AGENTIC_SECURITY_LINEAGE_DEEP=1) to regenerate both files together.`,
    };
  }
  if (verified === false) {
    return {
      ok: false,
      reason: 'tampered',
      message: `Lineage graph at ${graphPath} FAILED signature verification — its contents do not match ${sigPath}. The file may have been modified after the scan, or signed under a different install key. Refusing to serve a tampered graph. Re-run the scan to regenerate it.`,
    };
  }

  let graph;
  try {
    graph = JSON.parse(body);
  } catch (e) {
    return {
      ok: false,
      reason: 'malformed',
      message: `Lineage graph at ${graphPath} passed signature verification but is not valid JSON (${e && e.message ? e.message : e}). This should not happen from a normal scan — the file may be corrupted. Re-run the scan to regenerate it.`,
    };
  }

  return { ok: true, graph };
}

/**
 * Load .agentic-security/lineage-graph.json ONLY when it is genuinely
 * fresh for THIS scan — never merely because a file happens to exist on
 * disk. Shared by every caller that signs or narrates a graph:-derived
 * compliance claim (M4 sub-project 6c's final whole-branch review found
 * the identical staleness gap independently reachable from
 * `attest --obligations` AND `compliance --walkthrough`, and required
 * this predicate to live in exactly one place rather than being
 * copy-pasted per caller — a safety check that drifts between two
 * near-identical inline copies is worse than one shared bug).
 *
 * `.agentic-security/lineage-graph.json` is only rewritten when a scan
 * actually finishes building a graph (`if (scan.lineageGraph)` in
 * bin/agentic-security.js's persistence code) — an ordinary non-deep
 * rescan, or a deep scan whose lineage build fails, leaves whatever file
 * was there from an earlier successful deep scan untouched. Loading that
 * stale graph and joining it to the CURRENT scan's other data would let a
 * caller assert a graph-derived fact (e.g. "transit protected") about
 * code that has since changed.
 *
 * `enabled: true` in `scan.scanHealth.lineageAnalysis` does NOT by itself
 * mean the build succeeded — engine.js sets it the moment
 * AGENTIC_SECURITY_LINEAGE_DEEP=1 is read, before the build even starts,
 * and leaves it `true` even when the build later throws (only `failure`
 * gets set in that case). `requested && enabled` alone therefore still
 * accepts a stale graph after a failed rebuild — reproduced live via the
 * scan's own already-shipped fault-injection fixture
 * (test/lineage-fault-injection.test.js) before this `failure === null`
 * check was added.
 *
 * @param {string} scanRoot
 * @param {object} scan - the parsed last-scan.json for the CURRENT scan
 * @returns {{graph:object|null, fresh:boolean, loaded:ReturnType<typeof loadSignedGraph>}}
 *   `fresh` is true only when a signed graph loaded successfully AND this
 *   scan's own scanHealth confirms lineage analysis was requested,
 *   enabled, and did not fail. `graph` is `loaded.graph` when fresh, else
 *   `null` — never the stale file, even when one exists on disk.
 *   `loaded` is the raw `loadSignedGraph` result, so a caller can still
 *   distinguish "no file at all" from "a file exists but isn't fresh" for
 *   its own disclosure message.
 */
function loadFreshLineageGraph(scanRoot, scan) {
  const la = scan?.scanHealth?.lineageAnalysis;
  const requested = la?.requested === true;
  const enabled = la?.enabled === true;
  const failure = la?.failure ?? null;
  const loaded = loadSignedGraph(scanRoot);
  const fresh = loaded.ok && requested && enabled && failure === null;
  return { graph: fresh ? loaded.graph : null, fresh, loaded };
}


/***/ }),

/***/ 84268:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   Yo: () => (/* binding */ handleScan),
/* harmony export */   Yu: () => (/* binding */ handleEdge),
/* harmony export */   d5: () => (/* binding */ handleNode),
/* harmony export */   fn: () => (/* binding */ handleGraph),
/* harmony export */   jg: () => (/* binding */ handleFlow),
/* harmony export */   rR: () => (/* binding */ handleQuery)
/* harmony export */ });
/* unused harmony export wrapResponse */
/* harmony import */ var _lineage_export_json_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(40859);
// routes.js — Milestone 3, sub-project Server, increment 1.
//
// Five pure GET-endpoint handlers, each `(graph, ...) -> {status, body}`.
// No req/res access anywhere in this file — that is what makes these
// handlers unit-testable without an HTTP layer at all. http-server.js is
// the only module that touches node:http and calls into these.
//
// Every response body is wrapped in `wrapResponse`, which adds the exact
// envelope fields PRD line 1326 names (quoted in the implementation plan):
// "base graph/snapshot digest, schema/extension versions, scope, coverage,
// limitations, and contributing canonical IDs."



/**
 * Shared response envelope. Maps PRD line 1326's required fields onto the
 * graph's own real fields:
 *   - digest              -> graph.graphId (the base graph/snapshot digest)
 *   - schemaVersion        -> graph.schemaVersion
 *   - extensions           -> graph.extensions (schema/extension versions —
 *                             today always `{}`; see schema.js)
 *   - scope                -> graph.scope
 *   - coverage              -> graph.coverage
 *   - limitations           -> graph.limitations
 *   - canonicalIds          -> see the design note below
 *
 * "contributing canonical IDs" design decision (disclosed per the plan):
 * for `handleScan`/`handleGraph`, which describe the WHOLE graph rather
 * than one entity, `canonicalIds` is `null` — the response body for
 * `handleGraph` already IS the full nodes/edges/flows arrays, so echoing
 * every id again here would be pure duplication with no informational
 * gain, and for a large graph would materially bloat the response for
 * zero benefit. For `handleNode`/`handleEdge`, `canonicalIds` is the
 * single id the response is about. For `handleFlow`, `canonicalIds` is
 * the flow's own id PLUS the node/edge ids that flow's evidence draws
 * from (source, sink, edgeIds) — a flow is a derived record referencing
 * several underlying entities, and naming all of them here is genuinely
 * useful metadata a client would otherwise have to re-derive from the
 * flow body itself.
 */
function wrapResponse(data, graph, { canonicalIds = null } = {}) {
  return {
    digest: graph?.graphId ?? null,
    schemaVersion: graph?.schemaVersion ?? null,
    extensions: graph?.extensions ?? {},
    scope: graph?.scope ?? null,
    coverage: graph?.coverage ?? null,
    limitations: graph?.limitations ?? [],
    canonicalIds,
    data,
  };
}

function _findById(list, id) {
  if (!Array.isArray(list)) return null;
  return list.find((item) => item && item.id === id) ?? null;
}

/** Scan/graph metadata — NOT the full node/edge arrays. */
function handleScan(graph) {
  const data = {
    schemaVersion: graph?.schemaVersion ?? null,
    graphId: graph?.graphId ?? null,
    generatedAt: graph?.generatedAt ?? null,
    scope: graph?.scope ?? null,
    scanHealth: graph?.scanHealth ?? null,
    coverage: graph?.coverage ?? null,
  };
  return { status: 200, body: wrapResponse(data, graph, { canonicalIds: null }) };
}

/** The full graph document, unfiltered. For a scoped/narrowed projection, use `handleQuery` (`POST /api/v1/query`, Milestone 5) below instead. */
function handleGraph(graph) {
  return { status: 200, body: wrapResponse(graph, graph, { canonicalIds: null }) };
}

/**
 * A deterministic typed projection query — Milestone 5's own
 * `POST /api/v1/query`, the S2 endpoint `handleGraph`'s own header
 * comment named and deferred. `filter` is the exact `{nodeIds, edgeIds}`
 * shape `dataflow export --filter`/`exportGraphJSON` already use — reused
 * via `_filterGraph`, never reimplemented. Final whole-branch review
 * finding: `undefined` (filter omitted entirely) returns the WHOLE graph,
 * identical to `handleGraph` — but `{}` (an empty, well-formed filter
 * object) is NOT the same thing, and does NOT mean "no restriction": both
 * `nodeIds`/`edgeIds` default to empty Sets inside `_filterGraph`, so `{}`
 * narrows the graph down to EMPTY node/edge/flow/dataElement arrays. A
 * caller that wants the whole graph must omit `filter` entirely, never
 * pass `{}` meaning "everything." A malformed filter is a 400, never a
 * thrown exception reaching the caller.
 */
function handleQuery(graph, filter) {
  const check = (0,_lineage_export_json_js__WEBPACK_IMPORTED_MODULE_0__.validateFilterShape)(filter);
  if (!check.valid) {
    return { status: 400, body: { error: check.error } };
  }
  return { status: 200, body: wrapResponse((0,_lineage_export_json_js__WEBPACK_IMPORTED_MODULE_0__/* ._filterGraph */ .e)(graph, filter), graph, { canonicalIds: null }) };
}

/** Look up one node by id. 404 with a clear body if not found. */
function handleNode(graph, id) {
  const node = _findById(graph?.nodes, id);
  if (!node) {
    return { status: 404, body: wrapResponse({ error: `node not found: ${id}` }, graph, { canonicalIds: [] }) };
  }
  return { status: 200, body: wrapResponse(node, graph, { canonicalIds: [id] }) };
}

/** Look up one edge by id. 404 with a clear body if not found. */
function handleEdge(graph, id) {
  const edge = _findById(graph?.edges, id);
  if (!edge) {
    return { status: 404, body: wrapResponse({ error: `edge not found: ${id}` }, graph, { canonicalIds: [] }) };
  }
  return { status: 200, body: wrapResponse(edge, graph, { canonicalIds: [id] }) };
}

/** Look up one flow by id. 404 with a clear body if not found. */
function handleFlow(graph, id) {
  const flow = _findById(graph?.flows, id);
  if (!flow) {
    return { status: 404, body: wrapResponse({ error: `flow not found: ${id}` }, graph, { canonicalIds: [] }) };
  }
  const contributing = new Set([id]);
  if (flow.source) contributing.add(flow.source);
  if (flow.sink) contributing.add(flow.sink);
  for (const eid of (flow.edgeIds || [])) contributing.add(eid);
  return { status: 200, body: wrapResponse(flow, graph, { canonicalIds: [...contributing] }) };
}


/***/ })

};
