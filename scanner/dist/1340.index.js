export const id = 1340;
export const ids = [1340];
export const modules = {

/***/ 1340:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {


// EXPORTS
__webpack_require__.d(__webpack_exports__, {
  renderBoundariesText: () => (/* binding */ renderBoundariesText),
  runBoundaries: () => (/* binding */ runBoundaries)
});

// UNUSED EXPORTS: BINDINGS_FILE, BOUNDARIES_REPORT_SCHEMA, BOUNDARIES_REPORT_VERSION, IDENTITIES_FILE, MAX_FINDINGS, TRACE_FILES, listConfigFiles, readScanFindings

// EXTERNAL MODULE: external "node:fs"
var external_node_fs_ = __webpack_require__(73024);
// EXTERNAL MODULE: external "node:path"
var external_node_path_ = __webpack_require__(76760);
// EXTERNAL MODULE: ./src/posture/assurance/config.js
var assurance_config = __webpack_require__(90385);
// EXTERNAL MODULE: ./src/egress/policy.js
var policy = __webpack_require__(45712);
// EXTERNAL MODULE: ./src/egress/redact.js
var redact = __webpack_require__(11723);
// EXTERNAL MODULE: ./src/egress/audit.js
var audit = __webpack_require__(37355);
;// CONCATENATED MODULE: ./src/posture/assurance/bounded-io.js
// Bounded I/O and the single route for new model/network calls (CORE-004).
//
// There is deliberately NO HTTP client in this module. `guardedModelCall` takes
// the transport as an argument (`call`), so it cannot become a way around the
// existing egress layer: before `call` is ever invoked, the request is
//   1. gated by the feature configuration (disabled, killed, unsupported),
//   2. checked for a configured endpoint (never defaulted, never a cloud fallback),
//   3. evaluated by egress/policy.js evaluateEgress(), BEFORE any payload is built,
//   4. redacted by egress/redact.js redactPayload(), so `call` only ever sees
//      redacted text,
//   5. size-checked against the finite request limit.
// Only then is it run under a deadline with a bounded retry count, and its output
// is capped. Every decision is appended to the existing egress audit chain.
//
// Every limit named here is enforced by a function in this file; limits that this
// layer cannot enforce are disclosed as such by config.js, not claimed.







/** Read a file, refusing anything larger than `maxBytes`. Reads at most maxBytes+1, so a file that grows after the size check cannot exhaust memory. */
function readFileBounded(filePath, maxBytes) {
  if (!Number.isInteger(maxBytes) || maxBytes < 1) return (0,assurance_config/* typed */.nE)('blocked', 'invalid-config', 'maxBytes must be a positive integer');
  let fd;
  try {
    fd = external_node_fs_.openSync(filePath, 'r');
    const st = external_node_fs_.fstatSync(fd);
    if (!st.isFile()) return (0,assurance_config/* typed */.nE)('blocked', 'limit-exceeded', 'not a regular file');
    if (st.size > maxBytes) return (0,assurance_config/* typed */.nE)('blocked', 'limit-exceeded', `file is ${st.size} bytes, over the ${maxBytes} byte limit`, { bytes: st.size });
    const buf = Buffer.alloc(maxBytes + 1);
    const n = external_node_fs_.readSync(fd, buf, 0, maxBytes + 1, 0);
    if (n > maxBytes) return (0,assurance_config/* typed */.nE)('blocked', 'limit-exceeded', `file grew past the ${maxBytes} byte limit while reading`);
    return (0,assurance_config/* typed */.nE)('ok', null, 'read', { text: buf.subarray(0, n).toString('utf8'), bytes: n });
  } catch (e) {
    return (0,assurance_config/* typed */.nE)('blocked', 'missing-dependency', `cannot read ${filePath}: ${e.code || e.message}`);
  } finally {
    if (fd !== undefined) { try { external_node_fs_.closeSync(fd); } catch { /* already closed */ } }
  }
}

/** Cap a string to `maxBytes` of UTF-8 without splitting a character. */
function capOutput(text, maxBytes) {
  const s = typeof text === 'string' ? text : String(text ?? '');
  const bytes = Buffer.byteLength(s, 'utf8');
  if (bytes <= maxBytes) return { text: s, truncated: false, bytes };
  let cut = Buffer.from(s, 'utf8').subarray(0, maxBytes).toString('utf8');
  if (cut.endsWith('�')) cut = cut.slice(0, -1); // a multi-byte character was split at the boundary
  return { text: cut, truncated: true, bytes };
}

/** Run `fn(signal)` under a hard deadline. The timer is always cleared; a timeout aborts the signal and resolves to a typed result. */
async function withDeadline(fn, ms) {
  const ac = new AbortController();
  let timer;
  const timeout = new Promise((resolve) => {
    timer = setTimeout(() => { ac.abort(); resolve(typed('blocked', 'timeout', `no result within ${ms} ms`)); }, ms);
  });
  try {
    const run = Promise.resolve().then(() => fn(ac.signal)).then(
      (value) => ({ ok: true, value }),
      (error) => ({ ok: false, error }),
    );
    const winner = await Promise.race([run, timeout]);
    if (winner && winner.ok === true) return typed('ok', null, 'completed', { value: winner.value });
    if (winner && winner.ok === false) return { status: 'error', error: winner.error };
    return winner;
  } finally { clearTimeout(timer); }
}

/** At most `retries` extra attempts, and only for failures the callee marks `retryable`. */
async function retryBounded(fn, { retries, backoffMs = 0 } = {}) {
  const max = Math.max(0, Math.min(Number.isInteger(retries) ? retries : 0, 10));
  let attempts = 0;
  for (;;) {
    attempts += 1;
    const r = await fn(attempts);
    if (r.status !== 'error' || !r.error?.retryable || attempts > max) return { ...r, attempts };
    if (backoffMs > 0) await new Promise(res => setTimeout(res, Math.min(backoffMs * attempts, 5000)));
  }
}

/**
 * The only way a new feature makes a model or network call.
 *
 * @param {object} p
 * @param {object} p.config      resolveAssuranceConfig() result
 * @param {string} p.featureId
 * @param {string} p.scanRoot
 * @param {string|null} p.endpoint   MUST come from operator configuration; null yields `missing-provider`
 * @param {string} p.purpose
 * @param {string} p.text            the prompt/payload, BEFORE redaction
 * @param {string|null} [p.filePath]
 * @param {string|null} [p.model]
 * @param {Array} [p.requirements]   extra requirements (e.g. a credential), evaluated before any call
 * @param {(req:{endpoint:string,text:string,signal:AbortSignal,timeoutMs:number})=>Promise<string>} p.call  injected transport
 */
async function guardedModelCall({ config, featureId, scanRoot, endpoint, purpose, text, filePath = null, model = null, requirements = [], call }) {
  const gate = featureStatus(config, featureId);
  if (gate.status !== 'ok') return gate;
  const limits = limitValues(config);

  if (!endpoint || typeof endpoint !== 'string') {
    return typed('blocked', 'missing-provider', `${featureId} has no model endpoint configured; there is no default and no cloud fallback`, { feature: featureId });
  }
  const { missingRequired } = evaluateRequirements(requirements);
  if (missingRequired.length) {
    const m = missingRequired[0];
    return typed('blocked', m.code, `${featureId} needs ${m.kind} '${m.name}', which is not available`, { feature: featureId, missing: missingRequired });
  }
  if (typeof call !== 'function') return typed('blocked', 'missing-dependency', 'no transport supplied', { feature: featureId });

  // egress policy BEFORE the prompt is built or any client is touched
  const ctx = { scanRoot, purpose, endpoint, model, path: filePath };
  const decision = evaluateEgress(ctx);
  if (!decision.allowed) {
    recordEgressCall({ scanRoot, decision, ctx });
    return typed('blocked', 'egress-denied', decision.reason || 'egress policy denied the call', { feature: featureId, decision });
  }

  // redaction BEFORE request construction
  const redacted = redactPayload({ text: String(text ?? ''), filePath, scanRoot });
  const metrics = payloadMetrics(redacted.text);
  if (metrics.byteCount > limits.maxRequestBytes) {
    recordEgressCall({ scanRoot, decision: { ...decision, allowed: false, decision: 'deny', reason: 'request over maxRequestBytes' }, ctx });
    return typed('blocked', 'limit-exceeded', `request is ${metrics.byteCount} bytes, over the ${limits.maxRequestBytes} byte limit`, { feature: featureId });
  }
  recordEgressCall({ scanRoot, decision, ctx, metrics });

  const run = await retryBounded(
    () => withDeadline((signal) => call({ endpoint, text: redacted.text, signal, timeoutMs: limits.timeoutMs }), limits.timeoutMs),
    { retries: limits.retries },
  );
  if (run.status === 'error') {
    return typed('blocked', 'missing-dependency', `model call failed: ${String(run.error?.message || run.error)}`, { feature: featureId, attempts: run.attempts });
  }
  if (run.status !== 'ok') return { ...run, feature: featureId, attempts: run.attempts };
  const out = capOutput(run.value, limits.maxOutputBytes);
  const status = out.truncated ? 'degraded' : 'ok';
  return typed(status, out.truncated ? 'limit-exceeded' : null, out.truncated ? `output truncated to ${limits.maxOutputBytes} bytes` : 'completed', {
    feature: featureId, text: out.text, truncated: out.truncated, attempts: run.attempts, redactions: redacted.redactions,
  });
}

// EXTERNAL MODULE: ./src/posture/state-dir.js
var state_dir = __webpack_require__(31174);
// EXTERNAL MODULE: ./src/posture/assurance/identity.js
var identity = __webpack_require__(41877);
// EXTERNAL MODULE: ./src/lineage/deployment/boundary-graph.js
var boundary_graph = __webpack_require__(8283);
// EXTERNAL MODULE: ./src/util/yaml.js + 1 modules
var yaml = __webpack_require__(82340);
;// CONCATENATED MODULE: ./src/lineage/deployment/adapter-kit.js
// adapter-kit.js: shared plumbing for the deployment configuration adapters
// (X-302). Every adapter is a pure function from text to `{ nodes, edges, gaps }`
// built through one context, so that three things hold for every adapter
// without each one remembering them:
//
//  - every edge a static adapter emits is `static-config` provenance and
//    carries the exact file reference, digest, parser name and parser version
//    it came from (X-302.AC03);
//  - environment, tenant and owning repository are stamped uniformly, so two
//    environments never share a node;
//  - a reference that cannot be resolved becomes an unresolved node plus a gap,
//    never a guessed edge to a resolved one.
//
// Nothing here evaluates configuration. YAML is read with the scanner's safe
// loader (unknown tags are refused), JSON with JSON.parse, and policy strings
// are JSON.parse'd, never evaluated.




const ANCHOR_LIMIT = 100;

/**
 * Parse one YAML document, or several separated by `---`. Never throws.
 * Returns `{ docs }` or `{ gap }` where the gap is a typed unsupported or
 * malformed result. YAML merge keys are not expanded by the loader, so a
 * document that uses `<<` is reported by the adapter that needs the key.
 */
function parseYamlDocuments(text, file) {
  const aliasCount = (text.match(/(^|[\s\[{,:-])\*[A-Za-z0-9_-]+/g) || []).length;
  if (aliasCount > ANCHOR_LIMIT) {
    return { gap: { code: 'unsupported-syntax', subject: file, file, message: `YAML uses ${aliasCount} aliases, over the limit of ${ANCHOR_LIMIT}; the file is not read` } };
  }
  const chunks = text.split(/^---[ \t]*$/m);
  const docs = [];
  for (const chunk of chunks) {
    let doc;
    try { doc = (0,yaml/* load */.Hh)(chunk); } catch (e) {
      return { gap: { code: 'malformed-input', subject: file, file, message: `not valid YAML (${String(e.message).split('\n')[0]})` } };
    }
    if (doc !== undefined && doc !== null) docs.push(doc);
  }
  return { docs };
}

function isObject(v) { return v !== null && typeof v === 'object' && !Array.isArray(v); }
function asArray(v) { return Array.isArray(v) ? v : []; }
function str(v) { return typeof v === 'string' && v.length > 0 ? v : null; }

/** True when every entry of `selector` is present with the same value in `labels`. An empty selector selects nothing. */
function selectorMatches(selector, labels) {
  if (!isObject(selector) || !isObject(labels)) return false;
  const entries = Object.entries(selector);
  if (entries.length === 0) return false;
  return entries.every(([k, v]) => Object.hasOwn(labels, k) && String(labels[k]) === String(v));
}

/**
 * @param {object} p
 * @param {string} p.file         path as supplied, relative to the ingest root
 * @param {string} p.digest       sha256 of the text that was parsed
 * @param {string} p.environment  deployment environment these files describe
 * @param {string|null} p.repository
 * @param {string|null} p.revision exact commit, when known
 * @param {string} p.parser
 * @param {string} p.parserVersion
 */
function adapterContext({ file, digest, environment, repository, revision, parser, parserVersion }) {
  const nodes = [];
  const edges = [];
  const gaps = [];
  const ref = { file, digest };
  const source = { file, digest, parser, parserVersion };

  const kit = {
    nodes, edges, gaps, environment, repository, file,

    /** Declare a node this file defines. Adds the structural environment, repository and tenant edges. */
    node(kind, name, o = {}) {
      const tenant = o.tenant ?? null;
      const n = {
        kind, name, environment, tenant, repository: o.resolved === false ? null : repository,
        trustZone: o.trustZone ?? 'unknown', resolved: o.resolved !== false, unresolvedReason: o.unresolvedReason ?? null,
        attrs: o.attrs ?? {}, declaredBy: o.resolved === false ? [] : [ref],
      };
      nodes.push(n);
      if (o.resolved !== false) {
        const env = { kind: 'environment', name: environment, environment, tenant: null, repository: null, trustZone: 'unknown', resolved: true, attrs: {}, declaredBy: [ref] };
        nodes.push(env);
        kit.structural('deployed-in', n, env);
        if (repository) {
          const repo = { kind: 'repository', name: repository, environment: null, tenant: null, repository, trustZone: 'unknown', resolved: true, attrs: {}, declaredBy: [ref] };
          nodes.push(repo);
          kit.structural('defined-in', n, repo);
        }
        if (tenant) {
          const t = { kind: 'tenant', name: tenant, environment, tenant, repository: null, trustZone: 'unknown', resolved: true, attrs: {}, declaredBy: [ref] };
          nodes.push(t);
          kit.structural('scoped-to', n, t);
        }
      }
      return n;
    },

    /** A reference this file makes to something it does not define and cannot resolve. */
    unresolved(kind, name, reason, o = {}) {
      return kit.node(kind, name, { ...o, resolved: false, unresolvedReason: reason });
    },

    structural(relation, from, to) {
      edges.push(kit.baseEdge(relation, from, to, { effect: 'none', confidence: 'high' }));
    },

    baseEdge(relation, from, to, o = {}) {
      return {
        relation, from: idOf(from), to: idOf(to), environment: from.environment ?? to.environment ?? null, tenant: o.tenant ?? null,
        effect: o.effect ?? 'none', provenance: 'static-config', confidence: o.confidence ?? 'medium',
        pathState: o.effect === 'deny' ? 'blocked' : (o.pathState ?? 'possible'),
        observationInterval: null, completeness: null, sourceRevision: revision ?? null, source,
        discriminator: o.discriminator ?? null, crossRepo: null, attrs: o.attrs ?? {},
        _fromNode: from, _toNode: to,
      };
    },

    /** Add a relation between two nodes from this file. */
    edge(relation, from, to, o = {}) {
      edges.push(kit.baseEdge(relation, from, to, o));
    },

    gap(code, subject, message) { gaps.push({ code, subject, file, message }); },

    result() {
      // Drop the private endpoint references now that the ids are computed.
      return { nodes, edges: edges.map(({ _fromNode, _toNode, ...e }) => e), gaps };
    },
  };
  return kit;
}

function idOf(node) {
  return (0,boundary_graph/* nodeIdOf */.$z)({ kind: node.kind, name: node.name, environment: node.kind === 'environment' ? node.name : (node.environment ?? null), tenant: node.kind === 'tenant' ? node.name : (node.tenant ?? null) });
}

;// CONCATENATED MODULE: ./src/lineage/deployment/adapter-kubernetes.js
// adapter-kubernetes.js: Kubernetes manifests, Ingress, Gateway API HTTPRoute,
// RBAC and NetworkPolicy into deployment boundary nodes and edges (X-302).
//
// Reads only the fields that name a topology relation. Container environment
// variables, Secret objects, ConfigMap data and image references are never
// read, so no credential or payload can reach the graph through this adapter.
//
// Two passes: the first indexes every object in the supplied files, the second
// emits nodes and edges, so a Service can be matched to a workload declared
// later in the same bundle. A reference to something not in the supplied
// files (a ServiceAccount, a Role, a backend Service, a selector with no
// matching workload) becomes an unresolved node and a typed gap.



const KUBERNETES_PARSER = 'kubernetes-manifest';
const KUBERNETES_PARSER_VERSION = '1';

const WORKLOAD_KINDS = new Set(['Deployment', 'StatefulSet', 'DaemonSet', 'ReplicaSet', 'Job', 'CronJob', 'Pod']);
const SKIPPED_KINDS = new Set(['Secret', 'ConfigMap']);

function ns(o) { return str(o?.metadata?.namespace) ?? 'default'; }
function nm(o) { return str(o?.metadata?.name); }

function podTemplate(o) {
  if (o.kind === 'Pod') return { spec: o.spec, labels: o.metadata?.labels };
  if (o.kind === 'CronJob') return { spec: o.spec?.jobTemplate?.spec?.template?.spec, labels: o.spec?.jobTemplate?.spec?.template?.metadata?.labels };
  return { spec: o.spec?.template?.spec, labels: o.spec?.template?.metadata?.labels };
}

/**
 * Does a NetworkPolicy podSelector pick this workload? An empty selector picks
 * every workload in the namespace; matchExpressions are not evaluated, so a
 * selector that uses them selects nothing (and the caller reports a gap).
 */
function podSelectorPicks(sel, labels) {
  if (!isObject(sel)) return false;
  const keys = Object.keys(sel);
  if (keys.length === 0) return true;
  if (keys.includes('matchExpressions')) return false;
  const ml = sel.matchLabels;
  if (!isObject(ml) || Object.keys(ml).length === 0) return keys.every(k => k === 'matchLabels');
  return selectorMatches(ml, labels);
}

function tenantOf(...labelMaps) {
  for (const m of labelMaps) if (isObject(m) && typeof m.tenant === 'string' && /^[A-Za-z0-9._-]{1,64}$/.test(m.tenant)) return m.tenant;
  return null;
}

/** @returns {{nodes: object[], edges: object[], gaps: object[]}} */
function parseKubernetes(text, fileCtx) {
  const kit = adapterContext({ ...fileCtx, parser: KUBERNETES_PARSER, parserVersion: KUBERNETES_PARSER_VERSION });
  const parsed = parseYamlDocuments(text, fileCtx.file);
  if (parsed.gap) { kit.gaps.push(parsed.gap); return kit.result(); }

  const objects = [];
  for (const d of parsed.docs) {
    if (!isObject(d) || !str(d.kind) || !str(d.apiVersion)) {
      kit.gap('unsupported-format', fileCtx.file, 'a YAML document without apiVersion and kind is not a Kubernetes object and is skipped');
      continue;
    }
    if (SKIPPED_KINDS.has(d.kind)) continue; // never read secret-bearing kinds
    if (!nm(d)) { kit.gap('malformed-input', `${d.kind}`, `a ${d.kind} without metadata.name is skipped`); continue; }
    objects.push(d);
  }

  // ---- pass 1: index
  const workloads = [];
  const serviceAccounts = new Set();
  const services = new Map();
  const roles = new Map();
  for (const o of objects) {
    if (WORKLOAD_KINDS.has(o.kind)) {
      const t = podTemplate(o);
      workloads.push({ obj: o, namespace: ns(o), name: nm(o), labels: isObject(t.labels) ? t.labels : {}, spec: isObject(t.spec) ? t.spec : {} });
    } else if (o.kind === 'ServiceAccount') serviceAccounts.add(`${ns(o)}/${nm(o)}`);
    else if (o.kind === 'Service') services.set(`${ns(o)}/${nm(o)}`, o);
    else if (o.kind === 'Role') roles.set(`Role:${ns(o)}/${nm(o)}`, o);
    else if (o.kind === 'ClusterRole') roles.set(`ClusterRole:${nm(o)}`, o);
  }

  // NetworkPolicy: which workloads are isolated, and which peers may reach them.
  const policies = objects.filter(o => o.kind === 'NetworkPolicy');
  const isolation = new Map(); // workload key -> 'deny-all' | 'restricted'
  const wkey = (w) => `${w.namespace}/${w.name}`;
  for (const p of policies) {
    const types = asArray(p.spec?.policyTypes);
    const selects = workloads.filter(w => w.namespace === ns(p) && podSelectorPicks(p.spec?.podSelector, w.labels));
    if (selects.length === 0) { kit.gap('unresolved-identity', `NetworkPolicy ${ns(p)}/${nm(p)}`, 'the policy selects no workload in the supplied manifests'); continue; }
    const hasIngress = types.includes('Ingress') || (types.length === 0 && Array.isArray(p.spec?.ingress));
    for (const w of selects) {
      if (!hasIngress) continue;
      const rules = asArray(p.spec?.ingress);
      const prior = isolation.get(wkey(w));
      isolation.set(wkey(w), rules.length === 0 ? (prior ?? 'deny-all') : 'restricted');
    }
  }

  // ---- pass 2: emit
  const wNodes = new Map();
  for (const w of workloads) {
    const tenant = tenantOf(w.labels, w.obj.metadata?.labels);
    const attrs = { workloadKind: w.obj.kind, namespace: w.namespace };
    const iso = isolation.get(wkey(w));
    if (iso) attrs.ingressPolicy = iso;
    if (w.spec.hostNetwork === true) attrs.hostNetwork = true;
    const node = kit.node('service', wkey(w), { tenant, trustZone: 'internal', attrs });
    wNodes.set(wkey(w), node);
    const saName = str(w.spec.serviceAccountName) ?? 'default';
    const saKey = `${w.namespace}/${saName}`;
    let ident;
    if (serviceAccounts.has(saKey) || saName === 'default') {
      ident = kit.node('identity', `sa/${saKey}`, { trustZone: 'internal', attrs: saName === 'default' && !serviceAccounts.has(saKey) ? { implicit: true } : {} });
    } else {
      ident = kit.unresolved('identity', `sa/${saKey}`, 'ServiceAccount is not in the supplied manifests', { trustZone: 'unknown' });
      kit.gap('unresolved-identity', wkey(w), `serviceAccountName '${saName}' is not declared in the supplied manifests`);
    }
    kit.edge('assumes', node, ident, { confidence: 'high' });
  }
  for (const key of serviceAccounts) kit.node('identity', `sa/${key}`, { trustZone: 'internal' });

  // RBAC
  for (const b of objects.filter(o => o.kind === 'RoleBinding' || o.kind === 'ClusterRoleBinding')) {
    const refKind = b.roleRef?.kind, refName = str(b.roleRef?.name);
    if (!refName || (refKind !== 'Role' && refKind !== 'ClusterRole')) { kit.gap('malformed-input', `${b.kind} ${nm(b)}`, 'roleRef is missing or has an unsupported kind'); continue; }
    const cluster = b.kind === 'ClusterRoleBinding';
    const roleKey = refKind === 'ClusterRole' ? `ClusterRole:${refName}` : `Role:${ns(b)}/${refName}`;
    const role = roles.get(roleKey);
    const scope = cluster ? 'cluster' : `ns:${ns(b)}`;
    for (const s of asArray(b.subjects)) {
      let ident;
      if (s?.kind === 'ServiceAccount' && str(s.name)) ident = kit.node('identity', `sa/${str(s.namespace) ?? ns(b)}/${s.name}`, { trustZone: 'internal' });
      else if ((s?.kind === 'User' || s?.kind === 'Group') && str(s.name)) ident = kit.node('identity', `${s.kind.toLowerCase()}/${s.name}`, { trustZone: 'internal' });
      else { kit.gap('malformed-input', `${b.kind} ${nm(b)}`, 'a subject without kind and name is skipped'); continue; }
      if (!role) {
        const target = kit.unresolved('resource', `k8s/${scope}/role:${refName}`, `${refKind} '${refName}' is not in the supplied manifests`, { trustZone: 'unknown' });
        kit.gap('unresolved-identity', `${b.kind} ${nm(b)}`, `${refKind} '${refName}' is not in the supplied manifests, so the permissions it grants are unknown`);
        kit.edge('grants', ident, target, { effect: 'allow', confidence: 'low', discriminator: `role:${refName}` });
        continue;
      }
      for (const rule of asArray(role.rules)) {
        const verbs = asArray(rule?.verbs).filter(v => typeof v === 'string').sort();
        for (const res of asArray(rule?.resources).filter(r => typeof r === 'string')) {
          const target = kit.node('resource', `k8s/${scope}/${res}`, { trustZone: 'internal', attrs: res === '*' ? { wildcard: true } : {} });
          kit.edge('grants', ident, target, { effect: 'allow', confidence: 'high', discriminator: verbs.join(',') || 'none', attrs: { verbs: verbs.join(',') || 'none' } });
        }
      }
    }
  }

  // Services and what they route to
  const svcNodes = new Map();
  const svcNode = (nsName, name) => {
    const key = `${nsName}/${name}`;
    if (svcNodes.has(key)) return svcNodes.get(key);
    const obj = services.get(key);
    let node;
    if (obj) {
      const type = str(obj.spec?.type) ?? 'ClusterIP';
      const internalLb = obj.metadata?.annotations && Object.entries(obj.metadata.annotations).some(([k, v]) => /internal/i.test(k) && String(v) === 'true');
      const zone = type === 'LoadBalancer' ? (internalLb ? 'internal' : 'public') : type === 'NodePort' ? 'edge' : 'internal';
      node = kit.node('route', `svc/${key}`, { tenant: tenantOf(obj.metadata?.labels), trustZone: zone, attrs: { serviceType: type, namespace: nsName } });
      if (type === 'ExternalName' && str(obj.spec?.externalName)) {
        const ext = kit.unresolved('resource', `external/${obj.spec.externalName}`, 'ExternalName target is outside the supplied manifests', { trustZone: 'public' });
        kit.edge('routes-to', node, ext, { confidence: 'low' });
        kit.gap('unresolved-identity', `Service ${key}`, `ExternalName '${obj.spec.externalName}' is not resolved`);
      } else {
        const sel = obj.spec?.selector;
        const matched = workloads.filter(w => w.namespace === nsName && selectorMatches(sel, w.labels));
        for (const w of matched) kit.edge('routes-to', node, wNodes.get(wkey(w)), { confidence: 'medium' });
        if (matched.length === 0) {
          const miss = kit.unresolved('service', `${key}#selector`, 'the Service selector matches no workload in the supplied manifests', { trustZone: 'unknown' });
          kit.edge('routes-to', node, miss, { confidence: 'low' });
          kit.gap('unresolved-identity', `Service ${key}`, 'the selector matches no workload in the supplied manifests');
        }
      }
    } else {
      node = kit.unresolved('route', `svc/${key}`, 'the Service is not in the supplied manifests', { trustZone: 'unknown' });
      kit.gap('unresolved-identity', `Service ${key}`, 'a route targets a Service that is not in the supplied manifests');
    }
    svcNodes.set(key, node);
    return node;
  };
  for (const key of services.keys()) { const [n, ...rest] = key.split('/'); svcNode(n, rest.join('/')); }

  // Ingress
  for (const ing of objects.filter(o => o.kind === 'Ingress')) {
    const cls = String(ing.spec?.ingressClassName ?? ing.metadata?.annotations?.['kubernetes.io/ingress.class'] ?? '');
    const zone = /internal/i.test(cls) ? 'internal' : 'public';
    const tls = asArray(ing.spec?.tls).length > 0;
    const rules = asArray(ing.spec?.rules);
    const targets = [];
    for (const r of rules) {
      for (const p of asArray(r?.http?.paths)) targets.push({ host: str(r.host) ?? '*', path: str(p.path) ?? '/', backend: str(p.backend?.service?.name) });
    }
    const def = str(ing.spec?.defaultBackend?.service?.name);
    if (def) targets.push({ host: '*', path: '/', backend: def });
    if (targets.length === 0) kit.gap('malformed-input', `Ingress ${ns(ing)}/${nm(ing)}`, 'the Ingress has no routable rule');
    for (const t of targets) {
      const route = kit.node('route', `ingress/${ns(ing)}/${nm(ing)}:${t.host}${t.path}`, { tenant: tenantOf(ing.metadata?.labels), trustZone: zone, attrs: { host: t.host, path: t.path, tls } });
      if (!t.backend) { kit.gap('malformed-input', `Ingress ${ns(ing)}/${nm(ing)}`, 'a rule without a backend service is skipped'); continue; }
      kit.edge('routes-to', route, svcNode(ns(ing), t.backend), { confidence: 'high' });
    }
  }

  // Gateway API HTTPRoute
  for (const hr of objects.filter(o => o.kind === 'HTTPRoute')) {
    const hosts = asArray(hr.spec?.hostnames).filter(h => typeof h === 'string');
    const gateways = asArray(hr.spec?.parentRefs).map(p => str(p?.name)).filter(Boolean).sort().join(',');
    for (const rule of asArray(hr.spec?.rules)) {
      const paths = asArray(rule?.matches).map(m => str(m?.path?.value) ?? '/');
      const pathList = paths.length ? paths : ['/'];
      for (const host of hosts.length ? hosts : ['*']) for (const path of pathList) {
        const route = kit.node('route', `httproute/${ns(hr)}/${nm(hr)}:${host}${path}`, { tenant: tenantOf(hr.metadata?.labels), trustZone: 'public', attrs: { host, path, gateways: gateways || 'none' } });
        for (const ref of asArray(rule?.backendRefs)) {
          const b = str(ref?.name);
          if (b) kit.edge('routes-to', route, svcNode(str(ref.namespace) ?? ns(hr), b), { confidence: 'medium' });
        }
      }
    }
  }

  // NetworkPolicy allows
  for (const p of policies) {
    const selected = workloads.filter(w => w.namespace === ns(p) && podSelectorPicks(p.spec?.podSelector, w.labels));
    for (const rule of asArray(p.spec?.ingress)) {
      for (const from of asArray(rule?.from)) {
        const sources = [];
        if (isObject(from.podSelector)) {
          const pods = workloads.filter(w => (from.namespaceSelector ? true : w.namespace === ns(p)) && podSelectorPicks(from.podSelector, w.labels) && Object.keys(from.podSelector).length > 0);
          for (const w of pods) sources.push(wNodes.get(wkey(w)));
          if (pods.length === 0) kit.gap('unresolved-identity', `NetworkPolicy ${ns(p)}/${nm(p)}`, 'a peer selector matches no workload in the supplied manifests');
        } else if (isObject(from.ipBlock) && str(from.ipBlock.cidr)) {
          const cidr = from.ipBlock.cidr;
          sources.push(kit.node('route', `cidr/${cidr}`, { trustZone: /^0\.0\.0\.0\/0$|^::\/0$/.test(cidr) ? 'public' : 'edge', attrs: { cidr } }));
        } else if (isObject(from.namespaceSelector)) {
          kit.gap('unresolved-identity', `NetworkPolicy ${ns(p)}/${nm(p)}`, 'a namespace-only peer selector cannot be resolved to workloads from the supplied manifests');
        }
        for (const src of sources) for (const w of selected) {
          if (src && src !== wNodes.get(wkey(w))) kit.edge('network-allows', src, wNodes.get(wkey(w)), { confidence: 'medium', discriminator: `policy:${nm(p)}` });
        }
      }
    }
  }
  return kit.result();
}

;// CONCATENATED MODULE: ./src/lineage/deployment/adapter-compose.js
// adapter-compose.js: container composition files into deployment boundary
// nodes and edges (X-302).
//
// A service is a node. A published port is an entry route into it, public
// unless it is bound to loopback. `depends_on` and `links` are declared
// dependencies: they are recorded as `depends-on`, never as `calls`, because a
// dependency is a startup ordering or a reachability hint and says nothing
// about a call actually being made. Environment variables, env files, secrets
// and build arguments are never read, so a credential in a compose file cannot
// reach the graph.



const COMPOSE_PARSER = 'compose-file';
const COMPOSE_PARSER_VERSION = '1';

function parsePort(p) {
  if (typeof p === 'number') return { published: String(p), target: String(p), hostIp: null };
  if (typeof p === 'string') {
    let t = p.trim().replace(/\/(tcp|udp|sctp)$/i, '');
    let hostIp = null;
    const v6 = /^\[([^\]]+)\]:(.*)$/.exec(t);
    if (v6) { hostIp = `[${v6[1]}]`; t = v6[2]; }
    const parts = t.split(':');
    const port = /^\d+(-\d+)?$/;
    if (parts.some(x => !port.test(x) && !(parts.length === 3 && x === parts[0] && /^[0-9.]+$/.test(x)))) return null;
    if (parts.length === 1) return { published: null, target: parts[0], hostIp };
    if (parts.length === 2) return { published: parts[0], target: parts[1], hostIp };
    if (parts.length === 3 && !hostIp) return { published: parts[1], target: parts[2], hostIp: parts[0] };
    return null;
  }
  if (isObject(p)) {
    const target = p.target != null ? String(p.target) : null;
    if (!target) return null;
    return { published: p.published != null ? String(p.published) : null, target, hostIp: str(p.host_ip) };
  }
  return null;
}

function parseCompose(text, fileCtx) {
  const kit = adapterContext({ ...fileCtx, parser: COMPOSE_PARSER, parserVersion: COMPOSE_PARSER_VERSION });
  const parsed = parseYamlDocuments(text, fileCtx.file);
  if (parsed.gap) { kit.gaps.push(parsed.gap); return kit.result(); }
  const doc = parsed.docs[0];
  if (!isObject(doc) || !isObject(doc.services)) {
    kit.gap('unsupported-format', fileCtx.file, 'no top-level services mapping; not a compose file');
    return kit.result();
  }
  const declared = new Set(Object.keys(doc.services));
  const nodes = new Map();
  const nodeFor = (name) => nodes.get(name);
  const networks = isObject(doc.networks) ? doc.networks : {};

  for (const [name, svc] of Object.entries(doc.services)) {
    if (!isObject(svc)) { kit.gap('malformed-input', name, 'a service that is not a mapping is skipped'); continue; }
    if (Object.hasOwn(svc, '<<')) kit.gap('unsupported-syntax', name, "YAML merge key '<<' is not expanded; fields inherited through it are not read");
    const tenant = isObject(svc.labels) && typeof svc.labels.tenant === 'string' && /^[A-Za-z0-9._-]{1,64}$/.test(svc.labels.tenant) ? svc.labels.tenant : null;
    const attrs = {};
    const nets = (Array.isArray(svc.networks) ? svc.networks : isObject(svc.networks) ? Object.keys(svc.networks) : []).filter(n => typeof n === 'string').sort();
    if (nets.length) attrs.networks = nets.join(',');
    if (nets.length && nets.every(n => isObject(networks[n]) && networks[n].internal === true)) attrs.networkInternal = true;
    if (svc.network_mode === 'host') attrs.networkMode = 'host';
    nodes.set(name, kit.node('service', name, { tenant, trustZone: 'internal', attrs }));
  }

  for (const [name, svc] of Object.entries(doc.services)) {
    const node = nodeFor(name);
    if (!node) continue;
    for (const raw of asArray(svc.ports)) {
      const port = parsePort(raw);
      if (!port) { kit.gap('malformed-input', name, 'a port mapping that cannot be read is skipped'); continue; }
      if (port.published === null) continue; // container port only, not published to the host
      const loop = port.hostIp !== null && (/^127\./.test(port.hostIp) || port.hostIp === '[::1]');
      const route = kit.node('route', `port/${name}:${port.published}`, { tenant: node.tenant, trustZone: loop ? 'internal' : 'public', attrs: { published: port.published, target: port.target, bind: port.hostIp ?? 'all-interfaces' } });
      kit.edge('routes-to', route, node, { confidence: 'high' });
    }
    const deps = Array.isArray(svc.depends_on) ? svc.depends_on : isObject(svc.depends_on) ? Object.keys(svc.depends_on) : [];
    const links = [...asArray(svc.links), ...asArray(svc.external_links)].map(l => (typeof l === 'string' ? l.split(':')[0] : null));
    for (const d of [...deps, ...links]) {
      if (typeof d !== 'string' || !d) continue;
      if (declared.has(d) && nodeFor(d)) kit.edge('depends-on', node, nodeFor(d), { confidence: 'medium' });
      else {
        const miss = kit.unresolved('service', d, 'the dependency is not defined in this compose file', { trustZone: 'unknown' });
        kit.edge('depends-on', node, miss, { confidence: 'low' });
        kit.gap('unresolved-identity', name, `depends on '${d}', which this compose file does not define`);
      }
    }
  }
  return kit.result();
}

;// CONCATENATED MODULE: ./src/lineage/deployment/adapter-cloud.js
// adapter-cloud.js: Terraform plan JSON and IAM policy documents into
// deployment boundary nodes and edges (X-302).
//
// Input is a plan that someone already produced (`terraform show -json`); this
// adapter never runs terraform, never evaluates HCL and never contacts a
// provider. Values the plan itself marks as unknown after apply are not
// guessed: the relation becomes an unresolved node plus a gap. Policy
// documents are read with JSON.parse; `NotAction` / `NotResource` statements
// and conditions it cannot interpret are reported, not approximated.



const TERRAFORM_PARSER = 'terraform-plan-json';
const TERRAFORM_PARSER_VERSION = '1';
const IAM_PARSER = 'iam-policy-json';
const IAM_PARSER_VERSION = '1';

const MAX_STATEMENTS = 200;
const MAX_RESOURCES_PER_STATEMENT = 50;

function toList(v) { return typeof v === 'string' ? [v] : Array.isArray(v) ? v.filter(x => typeof x === 'string') : []; }

/** Emit grants edges for every statement of a policy document. Returns the number of statements read. */
function applyPolicy(kit, identity, policy, subject) {
  const statements = Array.isArray(policy?.Statement) ? policy.Statement : isObject(policy?.Statement) ? [policy.Statement] : null;
  if (!statements) { kit.gap('malformed-input', subject, 'policy document has no Statement'); return 0; }
  let read = 0;
  for (const st of statements.slice(0, MAX_STATEMENTS)) {
    if (!isObject(st)) { kit.gap('malformed-input', subject, 'a policy statement that is not an object is skipped'); continue; }
    if (st.NotAction !== undefined || st.NotResource !== undefined || st.NotPrincipal !== undefined) {
      kit.gap('unsupported-syntax', subject, 'NotAction, NotResource and NotPrincipal statements are not interpreted; the statement is skipped');
      continue;
    }
    const effect = st.Effect === 'Allow' ? 'allow' : st.Effect === 'Deny' ? 'deny' : null;
    if (!effect) { kit.gap('malformed-input', subject, `statement Effect must be Allow or Deny, got ${JSON.stringify(st.Effect)}`); continue; }
    const actions = toList(st.Action).sort();
    const resources = toList(st.Resource);
    if (actions.length === 0 || resources.length === 0) { kit.gap('malformed-input', subject, 'a statement without Action and Resource is skipped'); continue; }
    const conditioned = isObject(st.Condition) && Object.keys(st.Condition).length > 0;
    read += 1;
    if (resources.length > MAX_RESOURCES_PER_STATEMENT) kit.gap('limit-exceeded', subject, `a statement lists ${resources.length} resources; only the first ${MAX_RESOURCES_PER_STATEMENT} are read`);
    for (const r of resources.slice(0, MAX_RESOURCES_PER_STATEMENT)) {
      const target = kit.node('resource', `aws/${r}`, { trustZone: 'internal', attrs: r === '*' ? { wildcard: true } : {} });
      const attrs = { actions: actions.join(',').slice(0, 250) };
      if (conditioned) attrs.conditioned = true;
      kit.edge('grants', identity, target, {
        effect, confidence: conditioned ? 'low' : 'high', discriminator: `${actions.join(',')}${conditioned ? ';cond' : ''}`.slice(0, 250), attrs,
      });
    }
  }
  if (statements.length > MAX_STATEMENTS) kit.gap('limit-exceeded', subject, `policy has ${statements.length} statements; only the first ${MAX_STATEMENTS} are read`);
  return read;
}

function parseIamPolicy(text, fileCtx) {
  const kit = adapterContext({ ...fileCtx, parser: IAM_PARSER, parserVersion: IAM_PARSER_VERSION });
  let doc;
  try { doc = JSON.parse(text); } catch (e) {
    kit.gap('malformed-input', fileCtx.file, `not valid JSON (${String(e.message).split('\n')[0]})`);
    return kit.result();
  }
  const identityName = str(fileCtx.identity);
  let identity;
  if (identityName) identity = kit.node('identity', `iam/${identityName}`, { trustZone: 'internal' });
  else {
    identity = kit.unresolved('identity', `iam/policy:${fileCtx.file}`, 'the policy document is not attached to a named identity', { trustZone: 'unknown' });
    kit.gap('unresolved-identity', fileCtx.file, 'the policy document is not attached to a named identity; supply the identity it belongs to');
  }
  applyPolicy(kit, identity, doc, fileCtx.file);
  return kit.result();
}

function roleNameFromArn(arn) {
  const m = /^arn:[^:]*:iam::[^:]*:role\/(?:.*\/)?([^/]+)$/.exec(arn ?? '');
  return m ? m[1] : null;
}

function parseTerraformPlan(text, fileCtx) {
  const kit = adapterContext({ ...fileCtx, parser: TERRAFORM_PARSER, parserVersion: TERRAFORM_PARSER_VERSION });
  let plan;
  try { plan = JSON.parse(text); } catch (e) {
    kit.gap('malformed-input', fileCtx.file, `not valid JSON (${String(e.message).split('\n')[0]})`);
    return kit.result();
  }
  if (!isObject(plan) || !str(plan.format_version) || !Array.isArray(plan.resource_changes)) {
    kit.gap('unsupported-format', fileCtx.file, 'not a terraform plan in JSON form (needs format_version and resource_changes)');
    return kit.result();
  }
  const resources = new Map();
  for (const rc of plan.resource_changes) {
    if (!isObject(rc) || !str(rc.address) || !isObject(rc.change)) continue;
    const actions = asArray(rc.change.actions);
    if (actions.includes('delete') && !actions.includes('create')) continue;
    resources.set(rc.address, { type: rc.type, name: rc.name, after: isObject(rc.change.after) ? rc.change.after : {}, unknown: isObject(rc.change.after_unknown) ? rc.change.after_unknown : {} });
  }
  const config = new Map();
  for (const r of asArray(plan.configuration?.root_module?.resources)) {
    if (isObject(r) && str(r.address)) config.set(r.address, isObject(r.expressions) ? r.expressions : {});
  }
  const refTarget = (address, field, wantType) => {
    const refs = asArray(config.get(address)?.[field]?.references);
    for (const ref of refs) {
      const m = /^([a-z0-9_]+\.[A-Za-z0-9_-]+)(?:\.|$)/.exec(ref);
      if (m && resources.get(m[1])?.type === wantType) return m[1];
    }
    return null;
  };

  const identityNodes = new Map();
  const roleNode = (address) => {
    if (identityNodes.has(address)) return identityNodes.get(address);
    const r = resources.get(address);
    const name = str(r?.after?.name);
    let node;
    if (name && r.unknown.name !== true) node = kit.node('identity', `iam-role/${name}`, { trustZone: 'internal' });
    else {
      node = kit.unresolved('identity', `iam-role/${address}`, 'the role name is only known after apply', { trustZone: 'unknown' });
      kit.gap('unresolved-identity', address, 'the role name is only known after apply');
    }
    identityNodes.set(address, node);
    return node;
  };
  const roleByArn = (arn, subject) => {
    const n = roleNameFromArn(arn);
    if (!n) { kit.gap('unresolved-identity', subject, 'the role reference is not a literal role ARN and has no resolvable reference'); return kit.unresolved('identity', `iam-role/${subject}`, 'unresolved role reference', { trustZone: 'unknown' }); }
    return kit.unresolved('identity', `iam-role/${n}`, 'the role is not defined in this plan', { trustZone: 'unknown' });
  };

  const handled = new Set(['aws_iam_role', 'aws_iam_policy', 'aws_iam_role_policy', 'aws_iam_role_policy_attachment', 'aws_lambda_function', 'aws_s3_bucket', 'aws_security_group']);
  const unsupportedTypes = new Set();
  const policies = new Map();
  for (const [address, r] of resources) {
    if (r.type === 'aws_iam_policy' || r.type === 'aws_iam_role_policy') {
      let doc = null;
      if (typeof r.after.policy === 'string' && r.unknown.policy !== true) { try { doc = JSON.parse(r.after.policy); } catch { doc = null; } }
      policies.set(address, doc);
    }
    if (!handled.has(r.type)) unsupportedTypes.add(r.type);
  }

  for (const [address, r] of resources) {
    switch (r.type) {
      case 'aws_iam_role': roleNode(address); break;
      case 'aws_iam_role_policy': {
        const roleAddr = refTarget(address, 'role', 'aws_iam_role');
        const ident = roleAddr ? roleNode(roleAddr) : (str(r.after.role) && r.unknown.role !== true ? kit.node('identity', `iam-role/${r.after.role}`, { trustZone: 'internal' }) : kit.unresolved('identity', `iam-role/${address}`, 'the role is only known after apply', { trustZone: 'unknown' }));
        const doc = policies.get(address);
        if (!doc) kit.gap('unresolved-identity', address, 'the policy document is only known after apply or is not valid JSON; its grants are unknown');
        else applyPolicy(kit, ident, doc, address);
        break;
      }
      case 'aws_iam_role_policy_attachment': {
        const roleAddr = refTarget(address, 'role', 'aws_iam_role');
        const polAddr = refTarget(address, 'policy_arn', 'aws_iam_policy');
        const ident = roleAddr ? roleNode(roleAddr) : (str(r.after.role) && r.unknown.role !== true ? kit.node('identity', `iam-role/${r.after.role}`, { trustZone: 'internal' }) : kit.unresolved('identity', `iam-role/${address}`, 'the role is only known after apply', { trustZone: 'unknown' }));
        if (!polAddr) {
          kit.gap('unresolved-identity', address, `attached policy ${typeof r.after.policy_arn === 'string' ? r.after.policy_arn : '(known after apply)'} is not defined in this plan, so what it grants is unknown`);
          const target = kit.unresolved('resource', `aws/policy:${typeof r.after.policy_arn === 'string' ? r.after.policy_arn : address}`, 'the attached policy is not defined in this plan', { trustZone: 'unknown' });
          kit.edge('grants', ident, target, { effect: 'allow', confidence: 'low', discriminator: 'attached-policy' });
        } else if (!policies.get(polAddr)) {
          kit.gap('unresolved-identity', polAddr, 'the policy document is only known after apply or is not valid JSON; its grants are unknown');
        } else applyPolicy(kit, ident, policies.get(polAddr), address);
        break;
      }
      case 'aws_lambda_function': {
        const name = str(r.after.function_name);
        const node = name && r.unknown.function_name !== true
          ? kit.node('service', `lambda/${name}`, { trustZone: 'internal' })
          : kit.unresolved('service', `lambda/${address}`, 'the function name is only known after apply', { trustZone: 'unknown' });
        const roleAddr = refTarget(address, 'role', 'aws_iam_role');
        const ident = roleAddr ? roleNode(roleAddr) : (typeof r.after.role === 'string' ? roleByArn(r.after.role, address) : roleByArn(null, address));
        kit.edge('assumes', node, ident, { confidence: roleAddr ? 'high' : 'low' });
        break;
      }
      case 'aws_s3_bucket': {
        const b = str(r.after.bucket);
        if (b && r.unknown.bucket !== true) kit.node('resource', `s3/${b}`, { trustZone: r.after.acl === 'public-read' || r.after.acl === 'public-read-write' ? 'public' : 'internal', attrs: { acl: typeof r.after.acl === 'string' ? r.after.acl : 'unspecified' } });
        else kit.unresolved('resource', `s3/${address}`, 'the bucket name is only known after apply', { trustZone: 'unknown' });
        break;
      }
      case 'aws_security_group': {
        const name = str(r.after.name) ?? address;
        const sg = kit.node('resource', `sg/${name}`, { trustZone: 'internal' });
        for (const rule of asArray(r.after.ingress)) {
          const cidrs = asArray(rule?.cidr_blocks).filter(c => typeof c === 'string');
          const ports = `${rule?.protocol ?? '-1'}:${rule?.from_port ?? 0}-${rule?.to_port ?? 0}`;
          for (const cidr of cidrs) {
            const src = kit.node('route', `cidr/${cidr}`, { trustZone: cidr === '0.0.0.0/0' ? 'public' : 'edge', attrs: { cidr } });
            kit.edge('network-allows', src, sg, { confidence: 'high', discriminator: ports, attrs: { ports } });
          }
        }
        break;
      }
      default: break;
    }
  }
  if (unsupportedTypes.size) {
    const list = [...unsupportedTypes].sort();
    kit.gap('unsupported-format', fileCtx.file, `resource types not interpreted by this adapter: ${list.slice(0, 10).join(', ')}${list.length > 10 ? `, and ${list.length - 10} more` : ''}`);
  }
  return kit.result();
}

;// CONCATENATED MODULE: ./src/lineage/deployment/ingest.js
// ingest.js: turn customer-supplied deployment files into a boundary graph
// (X-302), and invalidate it when a source file changes.
//
// What this module will and will not do:
//  - It reads only files the caller names, under one root, as bounded UTF-8
//    text. It follows no symlink out of the root, opens no socket, spawns no
//    process, reads no credential and calls no cloud API. The pure entry point
//    (`ingestDeploymentConfig`) takes text and cannot touch the file system at
//    all; the file entry point (`ingestDeploymentFiles`) is gated by the
//    `deployment-boundaries` feature so it is inert unless an operator turns
//    it on.
//  - It does not execute configuration. Terraform HCL, nginx style
//    configuration and other languages are reported as typed unsupported
//    syntax, with a hint where a supported equivalent exists, and contribute
//    no edges.
//  - An adapter that throws on hostile input is contained: the file becomes a
//    typed gap and the other files are still ingested.
//
// Every edge an adapter emits carries the file, the sha256 of the exact text
// parsed, the parser name and the parser version. `invalidateChangedSources`
// uses those digests to drop what a changed or removed file used to support,
// so a stale relation does not outlive its evidence.











const DEPLOYMENT_FEATURE = 'deployment-boundaries';
const MAX_INGEST_FILES = 200;

const ADAPTERS = Object.freeze({
  kubernetes: { parse: parseKubernetes, parser: KUBERNETES_PARSER, version: KUBERNETES_PARSER_VERSION },
  compose: { parse: parseCompose, parser: COMPOSE_PARSER, version: COMPOSE_PARSER_VERSION },
  'terraform-plan': { parse: parseTerraformPlan, parser: TERRAFORM_PARSER, version: TERRAFORM_PARSER_VERSION },
  'iam-policy': { parse: parseIamPolicy, parser: IAM_PARSER, version: IAM_PARSER_VERSION },
});
const ADAPTER_NAMES = Object.freeze(Object.keys(ADAPTERS));

const UNSUPPORTED_SYNTAX = {
  '.tf': 'Terraform HCL is not interpreted (it would need evaluation); supply the JSON from `terraform show -json <plan>`',
  '.hcl': 'HCL is not interpreted; supply a supported JSON or YAML form',
  '.tfvars': 'Terraform variable files carry values, not topology, and are not read',
  '.conf': 'proxy and server configuration syntax is not supported by any adapter',
  '.toml': 'TOML configuration is not supported by any adapter',
  '.xml': 'XML configuration is not supported by any adapter',
};

/** Decide which adapter reads a file, or why none does. Pure. */
function detectFormat(file, text) {
  const ext = external_node_path_.extname(file).toLowerCase();
  if (UNSUPPORTED_SYNTAX[ext]) return { adapter: null, code: 'unsupported-syntax', reason: UNSUPPORTED_SYNTAX[ext] };
  if (ext === '.json') {
    let doc;
    try { doc = JSON.parse(text); } catch (e) { return { adapter: null, code: 'malformed-input', reason: `not valid JSON (${String(e.message).split('\n')[0]})` }; }
    if (doc && typeof doc === 'object' && !Array.isArray(doc)) {
      if (typeof doc.format_version === 'string' && Array.isArray(doc.resource_changes)) return { adapter: 'terraform-plan' };
      if (Object.hasOwn(doc, 'Statement')) return { adapter: 'iam-policy' };
    }
    return { adapter: null, code: 'unsupported-format', reason: 'JSON that is neither a terraform plan nor an IAM policy document' };
  }
  if (ext === '.yaml' || ext === '.yml') {
    if (/^services:\s*(#.*)?$/m.test(text)) return { adapter: 'compose' };
    if (/^apiVersion:\s*\S/m.test(text) && /^kind:\s*\S/m.test(text)) return { adapter: 'kubernetes' };
    return { adapter: null, code: 'unsupported-format', reason: 'YAML that is neither a compose file nor a Kubernetes manifest' };
  }
  return { adapter: null, code: 'unsupported-format', reason: `no adapter reads '${ext || 'files without an extension'}'` };
}

const NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const REV = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;

/**
 * Ingest already-read files. Pure: no file system, no network, no clock.
 *
 * @param {object} p
 * @param {Array<{path: string, text: string}>} p.files
 * @param {string} p.environment  the deployment environment these files describe
 * @param {string|null} [p.repository]
 * @param {string|null} [p.revision]   exact commit these files were read at, when known
 * @param {Record<string,string>} [p.identities]  file path -> identity a policy document belongs to
 * @returns {{status: 'ok'|'invalid-input'|'invalid-graph', graph: object|null, files: object[], errors: object[]}}
 */
function ingestDeploymentConfig({ files, environment, repository = null, revision = null, identities = {} } = {}) {
  if (typeof environment !== 'string' || !NAME.test(environment)) return { status: 'invalid-input', graph: null, files: [], errors: [{ code: 'BAD_TYPE', path: 'environment', message: 'environment must be a name such as prod or staging' }] };
  if (repository !== null && (typeof repository !== 'string' || !NAME.test(repository))) return { status: 'invalid-input', graph: null, files: [], errors: [{ code: 'BAD_TYPE', path: 'repository', message: 'repository must be null or a name' }] };
  if (revision !== null && !(typeof revision === 'string' && REV.test(revision))) return { status: 'invalid-input', graph: null, files: [], errors: [{ code: 'BAD_TYPE', path: 'revision', message: 'revision must be null or an exact 40/64 hex commit' }] };
  if (!Array.isArray(files)) return { status: 'invalid-input', graph: null, files: [], errors: [{ code: 'BAD_TYPE', path: 'files', message: 'files must be an array' }] };

  const nodes = [], edges = [], gaps = [], sources = [], report = [];
  const sorted = [...files].filter(f => f && typeof f.path === 'string' && typeof f.text === 'string').sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  if (files.length > MAX_INGEST_FILES) gaps.push({ code: 'limit-exceeded', subject: 'files', file: null, message: `${files.length} files supplied; only the first ${MAX_INGEST_FILES} are read` });
  for (const f of sorted.slice(0, MAX_INGEST_FILES)) {
    const bytes = Buffer.from(f.text, 'utf8');
    const digest = (0,identity/* digestOfBytes */.by)(bytes);
    const fmt = detectFormat(f.path, f.text);
    if (!fmt.adapter) {
      gaps.push({ code: fmt.code, subject: f.path, file: f.path, message: fmt.reason });
      report.push({ file: f.path, adapter: null, status: fmt.code });
      continue;
    }
    const a = ADAPTERS[fmt.adapter];
    let out;
    try {
      out = a.parse(f.text, { file: f.path, digest, environment, repository, revision, identity: identities[f.path] ?? null });
    } catch (e) {
      gaps.push({ code: 'malformed-input', subject: f.path, file: f.path, message: `the ${fmt.adapter} adapter could not read this file (${String(e?.message ?? e).split('\n')[0]})` });
      report.push({ file: f.path, adapter: fmt.adapter, status: 'malformed-input' });
      continue;
    }
    nodes.push(...out.nodes); edges.push(...out.edges); gaps.push(...out.gaps);
    sources.push({ file: f.path, digest, parser: a.parser, parserVersion: a.version, bytes: bytes.length });
    report.push({ file: f.path, adapter: fmt.adapter, status: out.nodes.length || out.edges.length ? 'ingested' : (out.gaps[0]?.code ?? 'empty') });
  }
  const built = (0,boundary_graph/* buildBoundaryGraph */.v4)({ repository, revision, nodes, edges, gaps, sources });
  if (!built.ok) return { status: 'invalid-graph', graph: null, files: report, errors: built.errors };
  return { status: 'ok', graph: built.graph, files: report, errors: [] };
}

// ------------------------------------------------------------ file entry point

/** Resolve `rel` under `root`, refusing absolute paths, traversal and symlinks. Returns the real path or null. */
function resolveUnderRoot(root, rel) {
  if (typeof rel !== 'string' || rel === '' || external_node_path_.isAbsolute(rel) || rel.split(/[\\/]/).includes('..')) return null;
  let realRoot;
  try { realRoot = external_node_fs_.realpathSync(root); } catch { return null; }
  const full = external_node_path_.join(realRoot, rel);
  let st;
  try { st = external_node_fs_.lstatSync(full); } catch { return null; }
  if (st.isSymbolicLink() || !st.isFile()) return null;
  let real;
  try { real = external_node_fs_.realpathSync(full); } catch { return null; }
  return real === full && (real === realRoot || real.startsWith(realRoot + external_node_path_.sep)) ? real : null;
}

/**
 * Read named files under `root` and ingest them. Gated by the
 * `deployment-boundaries` feature (off by default; the environment, an explicit
 * option or the operator's config turn it on). Returns a typed result and never
 * throws.
 *
 * @param {object} p
 * @param {object} p.config  resolveAssuranceConfig() result
 * @param {string} p.root
 * @param {string[]} p.paths  relative paths under root
 */
function ingestDeploymentFiles({ config, root, paths, environment, repository = null, revision = null, identities = {} } = {}) {
  const gate = (0,assurance_config/* featureStatus */.FX)(config, DEPLOYMENT_FEATURE);
  if (gate.status !== 'ok') return gate;
  if (!Array.isArray(paths)) return (0,assurance_config/* typed */.nE)('blocked', 'invalid-config', 'paths must be an array', { feature: DEPLOYMENT_FEATURE });
  const maxBytes = (0,assurance_config/* limitValues */.OH)(config).maxFileBytes;
  const files = [];
  const readGaps = [];
  for (const rel of paths.slice(0, MAX_INGEST_FILES)) {
    const real = resolveUnderRoot(root, rel);
    if (!real) { readGaps.push({ code: 'malformed-input', subject: String(rel), file: null, message: 'path is outside the root, is a symlink, or is not a regular file; it is not read' }); continue; }
    const r = readFileBounded(real, maxBytes);
    if (r.status !== 'ok') { readGaps.push({ code: r.code === 'limit-exceeded' ? 'limit-exceeded' : 'malformed-input', subject: String(rel), file: String(rel), message: r.reason }); continue; }
    files.push({ path: rel.split(external_node_path_.sep).join('/'), text: r.text });
  }
  const out = ingestDeploymentConfig({ files, environment, repository, revision, identities });
  if (out.status !== 'ok') return (0,assurance_config/* typed */.nE)('blocked', 'invalid-config', out.errors.map(e => e.message).join('; ') || 'invalid ingest input', { feature: DEPLOYMENT_FEATURE, ...out });
  if (readGaps.length) {
    // Re-build with the read gaps included so the graph tells the whole story.
    const again = (0,boundary_graph/* buildBoundaryGraph */.v4)({ ...out.graph, repository, revision, gaps: [...out.graph.gaps, ...readGaps] });
    if (again.ok) out.graph = again.graph;
  }
  return (0,assurance_config/* typed */.nE)('ok', null, 'ingested', { feature: DEPLOYMENT_FEATURE, ...out });
}

// ------------------------------------------------------------ invalidation

/**
 * Drop what changed or removed source files used to support (X-302.AC03).
 *
 * `currentDigests` maps file -> the sha256 of the file as it is NOW (a missing
 * entry means the file is gone). Static edges sourced from a file whose digest
 * differs are removed; a node that only a stale file declared stops being
 * resolved; nodes nothing references any more are dropped; a gap records each
 * invalidated file. Runtime and inferred edges are untouched because they do
 * not claim a file as evidence. Returns a rebuilt, validated graph.
 */
function invalidateChangedSources(graph, currentDigests) {
  const cur = currentDigests instanceof Map ? currentDigests : new Map(Object.entries(currentDigests ?? {}));
  const stale = new Map(); // file -> 'changed' | 'missing'
  for (const s of graph.sources) {
    const now = cur.get(s.file);
    if (now === undefined) stale.set(s.file, 'missing');
    else if (now !== s.digest) stale.set(s.file, 'changed');
  }
  if (stale.size === 0) return { ok: true, graph, invalidatedEdgeIds: [], staleFiles: [], errors: [] };

  const isStale = (ref) => ref && stale.has(ref.file) && cur.get(ref.file) !== ref.digest;
  const keptEdges = [], invalidated = [];
  for (const e of graph.edges) {
    if (e.source && isStale(e.source)) invalidated.push(e.id); else keptEdges.push(e);
  }
  const referenced = new Set();
  for (const e of keptEdges) { referenced.add(e.from); referenced.add(e.to); }
  const nodes = [];
  for (const n of graph.nodes) {
    const declaredBy = n.declaredBy.filter(d => !isStale(d));
    const lostDeclaration = declaredBy.length < n.declaredBy.length;
    if (declaredBy.length === 0 && !referenced.has(n.id)) continue; // nothing supports it any more
    if (lostDeclaration && declaredBy.length === 0) nodes.push({ ...n, declaredBy, resolved: false, unresolvedReason: 'the file that declared it changed or was removed', repository: null });
    else nodes.push({ ...n, declaredBy });
  }
  const gaps = [...graph.gaps];
  for (const [file, why] of [...stale].sort()) {
    gaps.push({ code: why === 'missing' ? 'source-missing' : 'source-changed', subject: file, file, message: `${file} ${why === 'missing' ? 'is no longer present' : 'has changed since it was ingested'}; the relations it supported were dropped and must be re-ingested` });
  }
  const sources = graph.sources.filter(s => !stale.has(s.file));
  const built = buildBoundaryGraph({ repository: graph.repository, revision: graph.revision, nodes, edges: keptEdges, gaps, sources });
  if (!built.ok) return { ok: false, graph: null, invalidatedEdgeIds: invalidated, staleFiles: [...stale.keys()].sort(), errors: built.errors };
  return { ok: true, graph: built.graph, invalidatedEdgeIds: invalidated.sort(), staleFiles: [...stale.keys()].sort(), errors: [] };
}

// EXTERNAL MODULE: ./src/lineage/runtime-observation.js
var runtime_observation = __webpack_require__(61995);
;// CONCATENATED MODULE: ./src/lineage/deployment/trace-correlation.js
// trace-correlation.js: sanitize runtime traces and correlate them with the
// static deployment boundary graph (X-303).
//
// The import side:
//  - A trace line is a JSON object. Only an allowlist of topology metadata is
//    kept (timestamp, environment, tenant, source and destination service,
//    host and port, request method, route host and path, outcome, sampled
//    flag, repeat count). Every other field is removed, never stored, and only
//    counted, split into credential-shaped, payload-shaped and other. A field
//    name is never kept, so a header or a body cannot reach the artifact even
//    as a key.
//  - Values that are kept are held to an identifier grammar. A request path
//    loses its query string and fragment, and any segment that looks like a
//    number, a uuid, a hash, a token or a long opaque string becomes `:id`.
//    A record whose kept value is not identifier-shaped is rejected whole,
//    never partially kept.
//  - A record for another environment is not relabelled and not stored: the
//    import is for one environment and counts the rest as rejected. A record
//    with no environment cannot be placed and is rejected too.
//  - Storage is bounded: input bytes, line length, line count, distinct
//    observations. Duplicates (same normalized key) merge into one observation
//    with a summed count and a widened interval. Past the observation cap the
//    oldest are evicted and the eviction is reported.
//
// The correlation side matches observations to graph nodes by explicit,
// numbered rules (R1 exact service pair, R2 route, R3 identity, R4 naming
// convention). R1-R3 produce `runtime-observation` edges; R4 produces an
// `inferred` edge because a naming convention is a guess about identity, not
// an observation of it. A static edge is never edited: observed and inferred
// edges are separate edges, so the three kinds of evidence stay separate.
//
// What coverage means here: an observed edge is evidence that the path
// carried traffic during the window. It is never evidence that the window held
// all traffic. `trafficCoverage` is therefore always 'not-established'; sampled,
// stale and missing observations are listed separately; and a static edge with
// no matching observation stays `possible`, never `blocked` (absence in a
// sampled or unknown-completeness trace cannot establish a block).





const OBSERVATION_SET_SCHEMA = 'agentic-security/deployment-observations';
const OBSERVATION_SET_VERSION = '1.0.0';

const TRACE_LIMITS = Object.freeze({
  maxInputBytes: 4 * 1024 * 1024,
  maxLineBytes: 8 * 1024,
  maxLines: 50_000,
  maxObservations: 2_000,
  maxCount: 1_000_000_000,
});
const DEFAULT_STALE_AFTER_MS = 7 * 24 * 3600 * 1000;

const CORRELATION_RULES = Object.freeze({
  R1: 'exact service pair: source and destination service names match service nodes of the same environment and tenant',
  R2: 'route: request host and path fall under a route node reached from the destination service',
  R3: 'identity: the source identity matches the identity the source service is configured to assume',
  R4: 'naming convention: a DNS style host or an unqualified service name resolves to exactly one service (inferred, never observed)',
});

const OUTCOMES = ['ok', 'denied', 'error'];
const METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'];
const TOP_KEYS = ['ts', 'environment', 'tenant', 'source', 'destination', 'route', 'outcome', 'sampled', 'count'];
const SOURCE_KEYS = ['service', 'identity', 'tenant'];
const DEST_KEYS = ['service', 'host', 'port', 'tenant'];
const ROUTE_KEYS = ['method', 'host', 'path'];

const SVC = /^[A-Za-z0-9][A-Za-z0-9._\/-]{0,127}$/;
const HOST = /^[A-Za-z0-9*]([A-Za-z0-9._-]{0,251}[A-Za-z0-9])?$/;
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;
const ENV = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

const CREDENTIAL_KEY = /auth|token|secret|passw|cookie|bearer|credential|session|api[-_]?key|signature|jwt/i;
const PAYLOAD_KEY = /body|payload|request|response|header|query|param|message|data|content|text|input|output|record|prompt/i;

function emptySanitization() {
  return { recordsWithRemovedFields: 0, removedFieldCount: 0, credentialShaped: 0, payloadShaped: 0, other: 0 };
}

function classifyRemoved(key, s) {
  s.removedFieldCount += 1;
  if (CREDENTIAL_KEY.test(key)) s.credentialShaped += 1;
  else if (PAYLOAD_KEY.test(key)) s.payloadShaped += 1;
  else s.other += 1;
}

/** Strip a path to its route shape: no query, no fragment, opaque segments become ':id'. Returns null if nothing usable remains. */
function normalizePath(raw) {
  if (typeof raw !== 'string') return null;
  const cut = raw.split(/[?#]/)[0];
  if (!cut.startsWith('/')) return null;
  const segs = cut.split('/').slice(1, 13);
  // Keep only plain words and versions; numbers, ids, hashes and tokens all carry digits or length.
  const out = segs.map((seg) => {
    if (seg === '') return '';
    if (/^[A-Za-z]+([_-][A-Za-z]+)*$/.test(seg) && seg.length <= 32) return seg;
    if (/^v\d{1,3}$/.test(seg)) return seg;
    return ':id';
  });
  const p = out.join('/');
  const rebuilt = `/${p.startsWith('/') ? p.slice(1) : p}`.replace(/\/{2,}/g, '/');
  return rebuilt.length <= 200 ? rebuilt : null;
}

function sanitizeObject(obj, allowed, stats) {
  const kept = {};
  let removed = 0;
  for (const k of Object.keys(obj)) {
    if (allowed.includes(k)) kept[k] = obj[k]; else { classifyRemoved(k, stats); removed += 1; }
  }
  return { kept, removed };
}

/** Normalize one parsed line. Returns `{ obs }` or `{ reject }`. */
function normalizeRecord(rec, stats) {
  if (rec === null || typeof rec !== 'object' || Array.isArray(rec)) return { reject: 'not-an-object' };
  let removedTotal = 0;
  const top = sanitizeObject(rec, TOP_KEYS, stats); removedTotal += top.removed;
  const r = top.kept;
  const sub = (v, keys) => { if (v === undefined) return {}; if (v === null || typeof v !== 'object' || Array.isArray(v)) return null; const s = sanitizeObject(v, keys, stats); removedTotal += s.removed; return s.kept; };
  const src = sub(r.source, SOURCE_KEYS), dst = sub(r.destination, DEST_KEYS), rt = sub(r.route, ROUTE_KEYS);
  if (removedTotal > 0) stats.recordsWithRemovedFields += 1;
  if (src === null || dst === null || rt === null) return { reject: 'bad-structure' };

  if (typeof r.ts !== 'string' || !ISO.test(r.ts) || !Number.isFinite(Date.parse(r.ts))) return { reject: 'bad-timestamp' };
  if (typeof r.environment !== 'string' || !ENV.test(r.environment)) return { reject: 'missing-environment' };
  if (r.tenant !== undefined && r.tenant !== null && (typeof r.tenant !== 'string' || !ENV.test(r.tenant))) return { reject: 'bad-tenant' };
  for (const t of [src.tenant, dst.tenant]) if (t !== undefined && t !== null && (typeof t !== 'string' || !ENV.test(t))) return { reject: 'bad-tenant' };
  if (src.service !== undefined && (typeof src.service !== 'string' || !SVC.test(src.service))) return { reject: 'bad-source-service' };
  if (src.identity !== undefined && (typeof src.identity !== 'string' || !SVC.test(src.identity))) return { reject: 'bad-identity' };
  if (dst.service !== undefined && (typeof dst.service !== 'string' || !SVC.test(dst.service))) return { reject: 'bad-destination-service' };
  if (dst.host !== undefined && (typeof dst.host !== 'string' || !HOST.test(dst.host))) return { reject: 'bad-destination-host' };
  if (dst.port !== undefined && !(Number.isInteger(dst.port) && dst.port >= 1 && dst.port <= 65535)) return { reject: 'bad-destination-port' };
  if (rt.method !== undefined && !METHODS.includes(rt.method)) return { reject: 'bad-method' };
  if (rt.host !== undefined && (typeof rt.host !== 'string' || !HOST.test(rt.host))) return { reject: 'bad-route-host' };
  let path = null;
  if (rt.path !== undefined) { path = normalizePath(rt.path); if (path === null) return { reject: 'bad-route-path' }; }
  if (r.outcome !== undefined && !OUTCOMES.includes(r.outcome)) return { reject: 'bad-outcome' };
  if (r.sampled !== undefined && typeof r.sampled !== 'boolean') return { reject: 'bad-sampled' };
  if (r.count !== undefined && !(Number.isInteger(r.count) && r.count >= 1 && r.count <= TRACE_LIMITS.maxCount)) return { reject: 'bad-count' };
  if (!src.service && !src.identity && !dst.service && !dst.host && !(rt.host || path)) return { reject: 'no-topology-fields' };

  const o = {
    environment: r.environment,
    tenant: r.tenant ?? null,
    from: { service: src.service ?? null, identity: src.identity ?? null, tenant: src.tenant ?? r.tenant ?? null },
    to: { service: dst.service ?? null, host: dst.host ?? null, port: dst.port ?? null, tenant: dst.tenant ?? r.tenant ?? null },
    route: (rt.method || rt.host || path) ? { method: rt.method ?? null, host: rt.host ?? null, path } : null,
    outcome: r.outcome ?? 'ok',
    sampled: r.sampled === true,
    eventCount: r.count ?? 1,
    firstObservedAt: r.ts,
    lastObservedAt: r.ts,
  };
  o.id = observationIdOf(o);
  return { obs: o };
}

const OBS_ID_FIELDS = ['environment', 'tenant', 'from', 'to', 'route', 'outcome', 'sampled'];
function observationIdOf(o) { return (0,identity/* semanticId */.YN)('bobs', o, OBS_ID_FIELDS); }

function mergeInto(a, b) {
  a.eventCount = Math.min(TRACE_LIMITS.maxCount, a.eventCount + b.eventCount);
  if (Date.parse(b.firstObservedAt) < Date.parse(a.firstObservedAt)) a.firstObservedAt = b.firstObservedAt;
  if (Date.parse(b.lastObservedAt) > Date.parse(a.lastObservedAt)) a.lastObservedAt = b.lastObservedAt;
}

function eventCountBand(n) {
  if (n <= 1) return runtime_observation/* EVENT_COUNT_BANDS */.Ws[0];
  if (n <= 10) return runtime_observation/* EVENT_COUNT_BANDS */.Ws[1];
  if (n <= 100) return runtime_observation/* EVENT_COUNT_BANDS */.Ws[2];
  if (n <= 1000) return runtime_observation/* EVENT_COUNT_BANDS */.Ws[3];
  return runtime_observation/* EVENT_COUNT_BANDS */.Ws[4];
}

function computeSetDigest(set) { return (0,identity/* digestOf */.ol)({ ...set, digest: null }); }

function finalizeSet(environment, byId, stats, sanitization, limits) {
  let list = [...byId.values()];
  let evicted = 0;
  if (list.length > limits.maxObservations) {
    list.sort((a, b) => Date.parse(b.lastObservedAt) - Date.parse(a.lastObservedAt) || (a.id < b.id ? -1 : 1));
    evicted = list.length - limits.maxObservations;
    list = list.slice(0, limits.maxObservations);
  }
  list.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  const times = list.flatMap(o => [Date.parse(o.firstObservedAt), Date.parse(o.lastObservedAt)]);
  const set = {
    schema: OBSERVATION_SET_SCHEMA,
    schemaVersion: OBSERVATION_SET_VERSION,
    environment,
    window: times.length ? { start: new Date(Math.min(...times)).toISOString(), end: new Date(Math.max(...times)).toISOString() } : null,
    observations: list,
    sanitization,
    stats: { ...stats, evicted },
    digest: '',
  };
  set.digest = computeSetDigest(set);
  return set;
}

/**
 * Import runtime trace lines for ONE environment. Never throws, never reads a
 * file, never stores a removed field or a rejected record.
 *
 * @param {string} text  JSON Lines
 * @param {object} p
 * @param {string} p.environment  the only environment this import accepts
 */
function importTraceLines(text, { environment, limits: overrides = {} } = {}) {
  const limits = { ...TRACE_LIMITS, ...overrides };
  if (typeof environment !== 'string' || !ENV.test(environment)) return { status: 'invalid-input', reason: 'environment must be a name such as prod', set: null };
  if (typeof text !== 'string') return { status: 'invalid-input', reason: 'trace input must be text', set: null };
  if (Buffer.byteLength(text, 'utf8') > limits.maxInputBytes) return { status: 'limit-exceeded', reason: `trace input is over the ${limits.maxInputBytes} byte limit; nothing was imported`, set: null };

  const sanitization = emptySanitization();
  const stats = { linesRead: 0, accepted: 0, duplicates: 0, rejected: 0, rejectedEnvironment: 0, truncatedLines: false, rejectReasons: {} };
  const byId = new Map();
  const lines = text.split('\n');
  for (const raw of lines) {
    const line = raw.endsWith('\r') ? raw.slice(0, -1) : raw;
    if (line.trim() === '') continue;
    if (stats.linesRead >= limits.maxLines) { stats.truncatedLines = true; break; }
    stats.linesRead += 1;
    const reject = (why) => { stats.rejected += 1; stats.rejectReasons[why] = (stats.rejectReasons[why] ?? 0) + 1; };
    if (Buffer.byteLength(line, 'utf8') > limits.maxLineBytes) { reject('line-too-long'); continue; }
    let rec;
    try { rec = JSON.parse(line); } catch { reject('not-json'); continue; }
    const n = normalizeRecord(rec, sanitization);
    if (n.reject) { reject(n.reject); continue; }
    if (n.obs.environment !== environment) { stats.rejectedEnvironment += 1; stats.rejected += 1; stats.rejectReasons['other-environment'] = (stats.rejectReasons['other-environment'] ?? 0) + 1; continue; }
    const prev = byId.get(n.obs.id);
    if (prev) { mergeInto(prev, n.obs); stats.duplicates += 1; } else byId.set(n.obs.id, n.obs);
    stats.accepted += 1;
  }
  const set = finalizeSet(environment, byId, stats, sanitization, limits);
  return { status: 'ok', reason: null, set };
}

/**
 * Merge a newer import into stored observations of the SAME environment,
 * bounded. Different environments are refused (never merged). Returns a new set.
 */
function mergeObservationSets(existing, incoming, { maxObservations = TRACE_LIMITS.maxObservations } = {}) {
  if (!existing || !incoming) return { status: 'invalid-input', reason: 'two observation sets are required', set: null };
  if (existing.environment !== incoming.environment) return { status: 'environment-mismatch', reason: `refusing to merge '${incoming.environment}' observations into '${existing.environment}'`, set: null };
  const byId = new Map(existing.observations.map(o => [o.id, { ...o }]));
  let duplicates = 0;
  for (const o of incoming.observations) {
    const prev = byId.get(o.id);
    if (prev) { mergeInto(prev, o); duplicates += 1; } else byId.set(o.id, { ...o });
  }
  const stats = { linesRead: 0, accepted: byId.size, duplicates, rejected: 0, rejectedEnvironment: 0, truncatedLines: false, rejectReasons: {} };
  const sanitization = {
    recordsWithRemovedFields: existing.sanitization.recordsWithRemovedFields + incoming.sanitization.recordsWithRemovedFields,
    removedFieldCount: existing.sanitization.removedFieldCount + incoming.sanitization.removedFieldCount,
    credentialShaped: existing.sanitization.credentialShaped + incoming.sanitization.credentialShaped,
    payloadShaped: existing.sanitization.payloadShaped + incoming.sanitization.payloadShaped,
    other: existing.sanitization.other + incoming.sanitization.other,
  };
  return { status: 'ok', reason: null, set: finalizeSet(existing.environment, byId, stats, sanitization, { maxObservations }) };
}

// ------------------------------------------------------------ persistence

const SET_FIELDS = (/* unused pure expression or super */ null && (['schema', 'schemaVersion', 'environment', 'window', 'observations', 'sanitization', 'stats', 'digest']));
const OBS_FIELDS = (/* unused pure expression or super */ null && (['id', 'environment', 'tenant', 'from', 'to', 'route', 'outcome', 'sampled', 'eventCount', 'firstObservedAt', 'lastObservedAt']));

/** Deterministic text form of an observation set (for the caller to store). */
function exportObservationSet(set) { return `${canonicalize(set)}\n`; }

/**
 * Read a stored observation set back. Closed world, bounded, digest-checked:
 * a set that was edited, padded with extra fields, or grown past the cap is
 * refused, never partially accepted.
 */
function parseObservationSet(text, { maxObservations = TRACE_LIMITS.maxObservations, maxBytes = 2 * TRACE_LIMITS.maxInputBytes } = {}) {
  if (typeof text !== 'string' || Buffer.byteLength(text, 'utf8') > maxBytes) return { status: 'malformed', reason: 'not text, or over the size limit', set: null };
  let set;
  try { set = JSON.parse(text); } catch { return { status: 'malformed', reason: 'not valid JSON', set: null }; }
  const bad = (reason) => ({ status: 'invalid', reason, set: null });
  if (!set || typeof set !== 'object' || Array.isArray(set)) return bad('not an object');
  for (const k of Object.keys(set)) if (!SET_FIELDS.includes(k)) return bad(`unknown field '${k}'`);
  if (set.schema !== OBSERVATION_SET_SCHEMA) return bad('wrong schema');
  if (typeof set.environment !== 'string' || !ENV.test(set.environment)) return bad('bad environment');
  if (!Array.isArray(set.observations) || set.observations.length > maxObservations) return bad(`observations must be an array of at most ${maxObservations}`);
  const ids = new Set();
  for (const o of set.observations) {
    if (!o || typeof o !== 'object' || Array.isArray(o)) return bad('observation is not an object');
    for (const k of Object.keys(o)) if (!OBS_FIELDS.includes(k)) return bad(`observation has unknown field '${k}'`);
    if (o.environment !== set.environment) return bad('observation environment differs from the set environment');
    if (!ISO.test(o.firstObservedAt ?? '') || !ISO.test(o.lastObservedAt ?? '') || Date.parse(o.firstObservedAt) > Date.parse(o.lastObservedAt)) return bad('observation interval is invalid');
    if (!OUTCOMES.includes(o.outcome) || typeof o.sampled !== 'boolean') return bad('observation outcome or sampled flag is invalid');
    if (!Number.isInteger(o.eventCount) || o.eventCount < 1 || o.eventCount > TRACE_LIMITS.maxCount) return bad('observation count is invalid');
    for (const [f, keys] of [['from', SOURCE_KEYS], ['to', DEST_KEYS]]) {
      if (!o[f] || typeof o[f] !== 'object') return bad(`observation.${f} is missing`);
      for (const k of Object.keys(o[f])) if (!keys.includes(k)) return bad(`observation.${f} has unknown field '${k}'`);
    }
    for (const v of [o.from?.service, o.from?.identity, o.to?.service]) if (v !== null && v !== undefined && !SVC.test(v)) return bad('observation has a non identifier-shaped name');
    for (const v of [o.tenant, o.from?.tenant, o.to?.tenant]) if (v !== null && v !== undefined && !ENV.test(v)) return bad('observation has a bad tenant');
    if (o.to.host !== null && o.to.host !== undefined && !HOST.test(o.to.host)) return bad('observation has a bad host');
    if (o.route !== null) {
      if (typeof o.route !== 'object') return bad('observation.route is invalid');
      for (const k of Object.keys(o.route)) if (!ROUTE_KEYS.includes(k)) return bad(`observation.route has unknown field '${k}'`);
      if (o.route.path !== null && o.route.path !== undefined && (typeof o.route.path !== 'string' || !/^\/[A-Za-z0-9._:\/-]*$/.test(o.route.path) || o.route.path.length > 200)) return bad('observation has a bad route path');
    }
    if (observationIdOf(o) !== o.id) return bad('observation id does not match its content');
    if (ids.has(o.id)) return bad('duplicate observation id');
    ids.add(o.id);
  }
  if (set.digest !== computeSetDigest(set)) return bad('digest does not match the content');
  return { status: 'ok', reason: null, set };
}

// ------------------------------------------------------------ correlation

const COMM_RELATIONS = new Set(['calls', 'depends-on', 'network-allows', 'routes-to']);

function serviceIndex(graph, environment) {
  const exact = new Map(), bySuffix = new Map();
  for (const n of graph.nodes) {
    if (n.kind !== 'service' || n.environment !== environment) continue;
    exact.set(`${n.tenant ?? ''}\n${n.name}`, n);
    const base = n.name.includes('/') ? n.name.slice(n.name.lastIndexOf('/') + 1) : n.name;
    const k = `${n.tenant ?? ''}\n${base}`;
    if (!bySuffix.has(k)) bySuffix.set(k, []);
    bySuffix.get(k).push(n);
  }
  return { exact, bySuffix };
}

function dnsToService(host) {
  const m = /^([a-z0-9]([a-z0-9-]*[a-z0-9])?)\.([a-z0-9]([a-z0-9-]*[a-z0-9])?)(\.svc(\.cluster\.local)?)?$/.exec(host ?? '');
  return m ? `${m[3]}/${m[1]}` : null;
}

function resolveService(idx, tenant, name, host) {
  const t = tenant ?? '';
  if (name) {
    const hit = idx.exact.get(`${t}\n${name}`);
    if (hit) return { node: hit, rule: 'R1', basis: 'exact-name' };
    if (!name.includes('/')) {
      const c = idx.bySuffix.get(`${t}\n${name}`) ?? [];
      if (c.length === 1) return { node: c[0], rule: 'R4', basis: 'unqualified-name' };
      if (c.length > 1) return { node: null, reason: 'ambiguous-service-name' };
    }
    return { node: null, reason: 'no-service-node' };
  }
  if (host) {
    const dns = dnsToService(host);
    if (dns) {
      const hit = idx.exact.get(`${t}\n${dns}`);
      if (hit) return { node: hit, rule: 'R4', basis: 'dns-name' };
    }
    const c = idx.bySuffix.get(`${t}\n${host}`) ?? [];
    if (c.length === 1) return { node: c[0], rule: 'R4', basis: 'host-as-service-name' };
    return { node: null, reason: c.length > 1 ? 'ambiguous-service-name' : 'no-service-node' };
  }
  return { node: null, reason: 'no-destination' };
}

function pathUnder(prefix, path) {
  if (typeof prefix !== 'string' || typeof path !== 'string') return false;
  if (prefix === '/') return true;
  return path === prefix || path.startsWith(prefix.endsWith('/') ? prefix : `${prefix}/`);
}

/**
 * Correlate an observation set with a static graph. Pure: the clock is the
 * explicit `now` argument. Returns the correlation record; use
 * `applyCorrelation` to fold its edges into a graph.
 *
 * @param {object} graph  a valid boundary graph
 * @param {object} set    an observation set from importTraceLines
 * @param {object} p
 * @param {string} p.now  ISO timestamp the freshness test uses
 * @param {number} [p.staleAfterMs]
 * @param {boolean} [p.createObservedOnlyNodes]  default true
 */
function correlateObservations(graph, set, { now, staleAfterMs = DEFAULT_STALE_AFTER_MS, createObservedOnlyNodes = true } = {}) {
  if (!graph || !set || set.schema !== OBSERVATION_SET_SCHEMA) return { status: 'invalid-input', reason: 'a boundary graph and an observation set are required' };
  const nowMs = Date.parse(now);
  if (!Number.isFinite(nowMs)) return { status: 'invalid-input', reason: 'now must be an ISO timestamp' };
  const env = set.environment;
  const idx = serviceIndex(graph, env);
  const nodesById = new Map(graph.nodes.map(n => [n.id, n]));
  const outStatic = new Map();
  for (const e of graph.edges) {
    if (e.provenance !== 'static-config') continue;
    if (!outStatic.has(e.from)) outStatic.set(e.from, []);
    outStatic.get(e.from).push(e);
  }
  const staticBetween = (a, b) => graph.edges.filter(e => e.provenance === 'static-config' && e.from === a && e.to === b && COMM_RELATIONS.has(e.relation));

  const newNodes = new Map();
  const unmatched = [];
  const conflicts = [];
  const acc = new Map(); // observed/inferred edge key -> accumulator
  const touchedStatic = new Set();
  const outcomes = { ok: 0, denied: 0, error: 0 };
  const deniedStatic = new Set();

  const observedOnly = (name, tenant) => {
    if (!createObservedOnlyNodes || !name) return null;
    const n = { kind: 'service', name, environment: env, tenant: tenant ?? null, repository: null, trustZone: 'unknown', resolved: false, unresolvedReason: 'observed at runtime, not present in the static configuration', attrs: {}, declaredBy: [] };
    newNodes.set(`${n.tenant ?? ''}\n${n.name}`, n);
    return n;
  };
  const idOf = (n) => n.id ?? (0,boundary_graph/* nodeIdOf */.$z)(n);

  const bump = (key, init, o) => {
    let a = acc.get(key);
    if (!a) { a = { ...init, first: o.firstObservedAt, last: o.lastObservedAt, allSampled: true, count: 0 }; acc.set(key, a); }
    if (Date.parse(o.firstObservedAt) < Date.parse(a.first)) a.first = o.firstObservedAt;
    if (Date.parse(o.lastObservedAt) > Date.parse(a.last)) a.last = o.lastObservedAt;
    a.allSampled = a.allSampled && o.sampled;
    a.count = Math.min(TRACE_LIMITS.maxCount, a.count + o.eventCount);
    return a;
  };

  for (const o of set.observations) {
    outcomes[o.outcome] += 1;
    const srcR = o.from.service ? resolveService(idx, o.from.tenant, o.from.service, null) : { node: null, reason: 'no-source' };
    const dstR = (o.to.service || o.to.host) ? resolveService(idx, o.to.tenant, o.to.service, o.to.host) : { node: null, reason: 'no-destination' };
    let srcNode = srcR.node, dstNode = dstR.node;
    let matchedAny = false;

    // R1/R4: service pair
    if (o.from.service && (o.to.service || o.to.host)) {
      if (!srcNode && srcR.reason === 'no-service-node') srcNode = observedOnly(o.from.service, o.from.tenant);
      if (!dstNode && dstR.reason === 'no-service-node') dstNode = observedOnly(o.to.service ?? o.to.host, o.to.tenant);
      if (srcNode && dstNode) {
        const srcId = idOf(srcNode), dstId = idOf(dstNode);
        const inferred = srcR.rule === 'R4' || dstR.rule === 'R4';
        const stat = staticBetween(srcId, dstId);
        if (o.outcome === 'ok') {
          const basis = inferred ? (srcR.rule === 'R4' ? srcR.basis : dstR.basis) : null;
          const key = `${inferred ? `I:${basis}` : 'O'}\n${srcId}\n${dstId}`;
          const a = bump(key, { kind: inferred ? 'inferred' : 'runtime', relation: 'calls', from: srcId, to: dstId, rule: inferred ? 'R4' : 'R1', basis, corroborates: new Set(), contradicts: new Set() }, o);
          for (const e of stat) { if (e.pathState !== 'blocked') { a.corroborates.add(e.id); touchedStatic.add(e.id); } }
          for (const e of graph.edges.filter(x => x.provenance === 'static-config' && x.from === srcId && x.to === dstId && x.pathState === 'blocked')) { a.contradicts.add(e.id); conflicts.push({ code: 'observed-over-blocked-path', edgeId: e.id, observationId: o.id }); }
        } else {
          for (const e of stat) deniedStatic.add(e.id);
        }
        matchedAny = true;
      }
    }

    // R3: identity
    if (o.from.identity && srcNode && o.outcome === 'ok') {
      const srcId = idOf(srcNode);
      const assumes = (outStatic.get(srcId) ?? []).filter(e => e.relation === 'assumes');
      const named = assumes.find(e => { const n = nodesById.get(e.to); return n && (n.name === o.from.identity || n.name.endsWith(`/${o.from.identity}`)); });
      if (named) {
        const a = bump(`O\n${srcId}\n${named.to}\nassumes`, { kind: 'runtime', relation: 'assumes', from: srcId, to: named.to, rule: 'R3', basis: null, corroborates: new Set(), contradicts: new Set() }, o);
        a.corroborates.add(named.id); touchedStatic.add(named.id);
        matchedAny = true;
      } else if (assumes.length) {
        conflicts.push({ code: 'identity-mismatch', service: srcNode.name, observedIdentity: o.from.identity, configured: assumes.map(e => nodesById.get(e.to)?.name).sort(), observationId: o.id });
        matchedAny = true;
      }
    }

    // R2: route
    if (o.route && (o.route.host || o.route.path) && dstNode && o.outcome === 'ok') {
      const dstId = idOf(dstNode);
      const routes = graph.nodes.filter(n => n.kind === 'route' && n.environment === env && (n.tenant === null || n.tenant === (o.to.tenant ?? null)) && (!o.route.host || n.attrs.host === o.route.host || n.attrs.host === '*') && (o.route.path === null || pathUnder(n.attrs.path, o.route.path)));
      for (const r of routes) {
        const chain = (0,boundary_graph/* findPath */.Hh)(outStatic, r.id, dstId, { accept: (e) => e.relation === 'routes-to' && e.pathState !== 'blocked', maxHops: 4 });
        if (chain) {
          for (const e of chain) {
            const a = bump(`O\n${e.from}\n${e.to}\nroutes-to`, { kind: 'runtime', relation: 'routes-to', from: e.from, to: e.to, rule: 'R2', basis: null, corroborates: new Set(), contradicts: new Set() }, o);
            a.corroborates.add(e.id); touchedStatic.add(e.id);
          }
          matchedAny = true;
        }
      }
    }
    if (!matchedAny) {
      const reason = !o.to.service && !o.to.host && !o.route ? 'no-destination' : (srcR.reason && !srcNode ? srcR.reason : dstR.reason) ?? 'no-rule-matched';
      unmatched.push({ observationId: o.id, reason });
    }
  }

  // Build observed / inferred edges
  const edges = [];
  for (const [key, a] of [...acc.entries()].sort((x, y) => (x[0] < y[0] ? -1 : 1))) {
    const stale = nowMs - Date.parse(a.last) > staleAfterMs;
    const e = {
      relation: a.relation, from: a.from, to: a.to, environment: env, tenant: null, effect: 'none',
      provenance: a.kind === 'runtime' ? 'runtime-observation' : 'inferred',
      confidence: a.kind === 'inferred' ? 'low' : (a.allSampled || stale ? 'medium' : 'high'),
      pathState: 'possible', observationInterval: null, completeness: null, sourceRevision: null, source: null,
      discriminator: a.kind === 'inferred' ? `R4:${a.basis}` : a.rule, crossRepo: null,
      attrs: { rule: a.rule, countBand: eventCountBand(a.count), ...(a.basis ? { basis: a.basis } : {}), ...(a.kind === 'runtime' && stale ? { stale: true } : {}) },
    };
    if (a.kind === 'runtime') {
      e.pathState = 'runtime-supported';
      e.observationInterval = { start: a.first, end: a.last };
      e.completeness = a.allSampled ? 'sampled' : 'unknown'; // never 'complete'
    }
    e.id = (0,boundary_graph/* edgeIdOf */.aI)(e);
    edges.push({ edge: e, acc: a, stale });
  }

  const staticCandidates = graph.edges.filter(e => e.provenance === 'static-config' && e.environment === env && COMM_RELATIONS.has(e.relation) && e.pathState !== 'blocked' && e.effect !== 'deny');
  const missingEdgeIds = staticCandidates.filter(e => !touchedStatic.has(e.id)).map(e => e.id).sort();

  return {
    status: 'ok',
    environment: env,
    rules: CORRELATION_RULES,
    window: set.window,
    evaluatedAt: new Date(nowMs).toISOString(),
    staleAfterMs,
    observedNodes: [...newNodes.values()],
    edges: edges.map(x => x.edge),
    corroboration: Object.fromEntries(edges.map(x => [x.edge.id, { corroborates: [...x.acc.corroborates].sort(), contradicts: [...x.acc.contradicts].sort() }])),
    conflicts,
    unmatched,
    outcomes,
    coverage: {
      // Observation is evidence of traffic, never proof that the window held all traffic.
      trafficCoverage: 'not-established',
      observed: edges.filter(x => x.edge.provenance === 'runtime-observation' && !x.acc.allSampled && !x.stale).map(x => x.edge.id).sort(),
      sampled: edges.filter(x => x.acc.allSampled && x.edge.provenance === 'runtime-observation').map(x => x.edge.id).sort(),
      stale: edges.filter(x => x.stale && x.edge.provenance === 'runtime-observation').map(x => x.edge.id).sort(),
      missingStaticEdgeIds: missingEdgeIds,
      deniedObservedStaticEdgeIds: [...deniedStatic].sort(),
    },
  };
}

/** Fold a correlation into a graph as a new validated graph. Static edges are untouched. */
function applyCorrelation(graph, correlation) {
  if (!correlation || correlation.status !== 'ok') return { ok: false, graph: null, errors: [{ code: 'RULE_VIOLATION', path: '', message: 'correlation is not usable' }] };
  const nodes = [...graph.nodes, ...correlation.observedNodes];
  const edges = [...graph.edges, ...correlation.edges];
  return (0,boundary_graph/* buildBoundaryGraph */.v4)({ repository: graph.repository, revision: graph.revision, nodes, edges, gaps: graph.gaps, sources: graph.sources });
}

// EXTERNAL MODULE: ./src/lineage/deployment/projection.js + 1 modules
var projection = __webpack_require__(73596);
;// CONCATENATED MODULE: ./src/lineage/deployment/boundaries-run.js
// boundaries-run.js: the operator entry point that builds a boundary context for scanned findings (X-308 wiring).
//
// Nothing in the default scan builds a boundary context. This is the one place that does, and it runs only when an operator
// asks for it (`agentic-security boundaries`) AND the `deployment-boundaries` feature is on (off by default). Rules it keeps:
//   - Local files only. It reads the directory it is pointed at, bounded, with no symlink followed, and optionally one scan
//     result file. It opens no socket, spawns no process, reads no credential and executes no configuration.
//   - Read-only with respect to the project. The only write is the report file the operator names with `out`, refused when the
//     target is a symlink.
//   - Off means off. With the feature off nothing is read: the result is a typed `disabled` and no file is opened.
//   - Everything that was not established is carried through: ingest gaps, unsupported syntax, files not read, trace sampling
//     and staleness, findings with no service binding. A result never says safe.
//
// Reserved names inside the directory: `service-bindings.json` (finding path prefix to service), `identities.json` (policy file
// to the identity it belongs to) and `traces.jsonl` / `traces.ndjson` (sanitized runtime trace lines). They are inputs, never
// ingested as configuration.










const BOUNDARIES_REPORT_SCHEMA = 'agentic-security/boundaries-report';
const BOUNDARIES_REPORT_VERSION = '1.0.0';
const BINDINGS_FILE = 'service-bindings.json';
const IDENTITIES_FILE = 'identities.json';
const TRACE_FILES = Object.freeze(['traces.jsonl', 'traces.ndjson']);
const MAX_FINDINGS = 5000;

const RESERVED = new Set([BINDINGS_FILE, IDENTITIES_FILE, ...TRACE_FILES]);
const CONFIG_EXTENSIONS = new Set(['.yaml', '.yml', '.json', '.tf', '.hcl', '.tfvars', '.conf', '.toml', '.xml']);
const SKIP_DIRS = new Set(['.git', 'node_modules', state_dir/* STATE_DIR_NAME */.Ky]);
const MAX_WALK_ENTRIES = 5000;

/** List candidate configuration files under `dir`, relative and sorted. Symlinks are never followed or listed. */
function listConfigFiles(dir) {
  const found = [];
  const skipped = { symlinks: 0, overLimit: false };
  let seen = 0;
  const walk = (d, rel) => {
    let entries;
    try { entries = external_node_fs_.readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of entries.sort((a, b) => a.name.localeCompare(b.name))) {
      if (++seen > MAX_WALK_ENTRIES) { skipped.overLimit = true; return; }
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (e.isSymbolicLink()) { skipped.symlinks += 1; continue; }
      if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name)) walk(external_node_path_.join(d, e.name), r); continue; }
      if (!e.isFile()) continue;
      if (!rel && RESERVED.has(e.name)) continue;
      if (CONFIG_EXTENSIONS.has(external_node_path_.extname(e.name).toLowerCase())) found.push(r);
    }
  };
  walk(dir, '');
  return { files: found.sort(), skipped };
}

function readJsonFile(file, maxBytes, what) {
  const r = readFileBounded(file, maxBytes);
  if (r.status !== 'ok') return { ok: false, reason: `${what}: ${r.reason}` };
  try { return { ok: true, value: JSON.parse(r.text) }; } catch (e) { return { ok: false, reason: `${what} is not valid JSON (${String(e.message).split('\n')[0]})` }; }
}

/**
 * Read the findings of a scan result file. A sibling `.sig` that exists must verify; a result with no signature is read and
 * labelled unverified.
 */
function readScanFindings(file, { maxBytes, verify } = {}) {
  const r = readFileBounded(file, maxBytes);
  if (r.status !== 'ok') return { ok: false, reason: `scan result: ${r.reason}`, findings: [], integrity: 'unreadable' };
  let integrity = 'unsigned';
  if (typeof verify === 'function') {
    const v = verify(r.text, `${file}.sig`);
    if (v === false) return { ok: false, reason: 'the scan result has a signature that does not verify; it is not used', findings: [], integrity: 'signature-mismatch' };
    if (v === true) integrity = 'verified';
  }
  let doc;
  try { doc = JSON.parse(r.text); } catch (e) { return { ok: false, reason: `scan result is not valid JSON (${String(e.message).split('\n')[0]})`, findings: [], integrity }; }
  const list = Array.isArray(doc) ? doc : doc?.findings;
  if (!Array.isArray(list)) return { ok: false, reason: 'scan result has no findings array', findings: [], integrity };
  return { ok: true, reason: null, findings: list.filter((f) => f && typeof f === 'object' && !Array.isArray(f)), integrity };
}

/**
 * Build a boundary graph from a directory of deployment sources and attach a context to each finding.
 *
 * @param {object} o
 * @param {object} o.config        resolveAssuranceConfig() result (the feature gate)
 * @param {string} o.from          directory with configuration, optional traces, bindings and identities
 * @param {string} [o.environment] default 'prod'
 * @param {string|null} [o.repository]
 * @param {string|null} [o.revision]  exact 40/64 hex commit the files were read at
 * @param {string|null} [o.findingsFile]  a scan result (last-scan.json)
 * @param {object[]|null} [o.findings]     findings already in memory (an evaluation passes these instead of a file)
 * @param {Function} [o.verifySignature]  (body, sigFile) => true | false | null
 * @param {string} [o.now]         ISO time used to judge trace staleness; defaults to the current time
 * @returns {object} typed result; `status` is ok | disabled | blocked | unsupported | error. Never throws.
 */
function runBoundaries({ config, from, environment = 'prod', repository = null, revision = null, findingsFile = null, findings: suppliedFindings = null, verifySignature, now } = {}) {
  const gate = (0,assurance_config/* featureStatus */.FX)(config, DEPLOYMENT_FEATURE);
  if (gate.status !== 'ok') return { ...gate, report: null };
  const limits = (0,assurance_config/* limitValues */.OH)(config);
  const fail = (code, reason) => (0,assurance_config/* typed */.nE)('error', code, reason, { feature: DEPLOYMENT_FEATURE, report: null });

  if (typeof from !== 'string' || !from) return fail('invalid-input', '--from names the directory with deployment configuration');
  let root;
  try { root = external_node_fs_.realpathSync(from); if (!external_node_fs_.statSync(root).isDirectory()) throw new Error('not a directory'); } catch { return fail('invalid-input', `--from '${from}' is not a readable directory`); }

  const clock = now ?? new Date().toISOString();
  const notes = [];
  const listing = listConfigFiles(root);
  if (listing.skipped.symlinks) notes.push(`${listing.skipped.symlinks} symbolic link(s) were not followed`);
  if (listing.skipped.overLimit) notes.push(`the directory walk stopped at ${MAX_WALK_ENTRIES} entries; later files were not listed`);
  let paths = listing.files;
  if (paths.length > MAX_INGEST_FILES) { notes.push(`${paths.length - MAX_INGEST_FILES} configuration file(s) beyond the ${MAX_INGEST_FILES} file limit were not read`); paths = paths.slice(0, MAX_INGEST_FILES); }
  if (!paths.length) return fail('invalid-input', `no configuration files (${[...CONFIG_EXTENSIONS].join(', ')}) were found under '${from}'`);

  let identities = {};
  const idFile = external_node_path_.join(root, IDENTITIES_FILE);
  if (external_node_fs_.existsSync(idFile)) {
    const j = readJsonFile(idFile, limits.maxFileBytes, IDENTITIES_FILE);
    if (!j.ok) return fail('invalid-input', j.reason);
    if (!j.value || typeof j.value !== 'object' || Array.isArray(j.value)) return fail('invalid-input', `${IDENTITIES_FILE} must be an object mapping a file path to an identity`);
    identities = Object.fromEntries(Object.entries(j.value).filter(([, v]) => typeof v === 'string'));
  }
  let bindings = [];
  const bindFile = external_node_path_.join(root, BINDINGS_FILE);
  if (external_node_fs_.existsSync(bindFile)) {
    const j = readJsonFile(bindFile, limits.maxFileBytes, BINDINGS_FILE);
    if (!j.ok) return fail('invalid-input', j.reason);
    if (!Array.isArray(j.value)) return fail('invalid-input', `${BINDINGS_FILE} must be an array of { pathPrefix, service } objects`);
    bindings = j.value;
  } else notes.push(`no ${BINDINGS_FILE}: no finding can be tied to a service, so every finding reports exposure as not assessed`);

  const ingested = ingestDeploymentFiles({ config, root, paths, environment, repository, revision, identities });
  if (ingested.status !== 'ok') return fail(ingested.code ?? 'invalid-config', ingested.reason ?? 'ingest failed');
  let graph = ingested.graph;

  const observation = { supplied: false, accepted: 0, rejected: 0, status: 'not-supplied', coverage: null };
  const traceName = TRACE_FILES.find((n) => external_node_fs_.existsSync(external_node_path_.join(root, n)));
  if (traceName) {
    observation.supplied = true;
    const t = readFileBounded(external_node_path_.join(root, traceName), limits.maxFileBytes);
    if (t.status !== 'ok') { observation.status = 'unreadable'; notes.push(`${traceName} was not read: ${t.reason}`); }
    else {
      const imp = importTraceLines(t.text, { environment });
      if (imp.status !== 'ok') { observation.status = imp.status; notes.push(`${traceName} was not imported: ${imp.reason}`); }
      else {
        observation.accepted = imp.set.stats.accepted; observation.rejected = imp.set.stats.rejected;
        const corr = correlateObservations(graph, imp.set, { now: clock });
        if (corr.status !== 'ok') { observation.status = corr.status; notes.push(`traces were not correlated: ${corr.reason}`); }
        else {
          const applied = applyCorrelation(graph, corr);
          if (applied.ok) { graph = applied.graph; observation.status = 'correlated'; observation.coverage = corr.coverage; }
          else { observation.status = 'invalid-graph'; notes.push('correlated traces produced an invalid graph and were not applied'); }
        }
      }
    }
  }

  let findings = [];
  let integrity = 'not-supplied';
  if (Array.isArray(suppliedFindings)) {
    integrity = 'in-memory';
    findings = suppliedFindings.filter((f) => f && typeof f === 'object' && !Array.isArray(f));
    if (findings.length > MAX_FINDINGS) { notes.push(`${findings.length - MAX_FINDINGS} finding(s) beyond the ${MAX_FINDINGS} limit were not given a context`); findings = findings.slice(0, MAX_FINDINGS); }
  } else if (findingsFile) {
    const s = readScanFindings(findingsFile, { maxBytes: limits.maxFileBytes, verify: verifySignature });
    if (!s.ok) return fail('invalid-input', s.reason);
    integrity = s.integrity;
    findings = s.findings;
    if (findings.length > MAX_FINDINGS) { notes.push(`${findings.length - MAX_FINDINGS} finding(s) beyond the ${MAX_FINDINGS} limit were not given a context`); findings = findings.slice(0, MAX_FINDINGS); }
    if (integrity === 'unsigned') notes.push('the scan result carries no signature, so its integrity was not verified');
  }

  const attached = (0,projection/* attachBoundaryContext */.Nu)({ config, findings, graph, bindings, now: clock });
  if (attached.status !== 'ok') return { ...attached, report: null };
  const contexts = attached.findings.map((f) => f.boundaryContext).filter(Boolean);
  const rows = attached.findings.map((f) => ({
    id: f.id ?? null, stableId: f.stableId ?? null, file: f.file ?? null, line: Number.isInteger(f.line) ? f.line : null, vuln: f.vuln ?? null,
    ...(f.boundaryContext ? (0,projection/* boundaryFields */.Q)(f.boundaryContext) : { boundaryContext: null, boundaryView: null, notAnalyzed: 'the context could not be computed for this finding' }),
  }));
  const report = {
    schema: BOUNDARIES_REPORT_SCHEMA, schemaVersion: BOUNDARIES_REPORT_VERSION,
    feature: DEPLOYMENT_FEATURE, environment, repository, revision,
    graph: {
      digest: graph.digest, nodeCount: graph.nodes.length, edgeCount: graph.edges.length, gapCount: graph.gaps.length,
      unresolvedNodeCount: graph.nodes.filter((n) => !n.resolved).length,
      gaps: graph.gaps.map((g) => ({ code: g.code, subject: g.subject, file: g.file ?? null, message: g.message })),
      files: ingested.files, sourceCount: graph.sources.length,
    },
    observation,
    scanResult: { supplied: Boolean(findingsFile) || integrity === 'in-memory', integrity, findingCount: findings.length },
    coverage: (0,projection/* boundaryCoverage */.V2)(contexts),
    findings: rows,
    errors: attached.errors,
    notes,
    statement: 'Configured relationships were not exercised and runtime traffic coverage is not established; a path that is not listed has not been shown to be absent.',
  };
  return (0,assurance_config/* typed */.nE)('ok', null, 'boundary contexts built from local files', { feature: DEPLOYMENT_FEATURE, report, graph });
}

/** Text form of a report. Reuses each context's own projected text; adds nothing about safety. */
function renderBoundariesText(report) {
  const L = [];
  L.push(`Deployment boundaries (environment ${report.environment}${report.repository ? `, repository ${report.repository}` : ''})`);
  L.push(`  Graph: ${report.graph.nodeCount} node(s), ${report.graph.edgeCount} edge(s), ${report.graph.gapCount} gap(s), ${report.graph.unresolvedNodeCount} unresolved; digest ${report.graph.digest.slice(0, 12)}`);
  for (const f of report.graph.files) L.push(`    ${f.file}: ${f.adapter ?? 'not read'} (${f.status})`);
  for (const g of report.graph.gaps.slice(0, 20)) L.push(`    gap ${g.code}: ${g.subject}`);
  if (report.graph.gaps.length > 20) L.push(`    and ${report.graph.gaps.length - 20} more gap(s)`);
  L.push(`  Traces: ${report.observation.status}${report.observation.supplied ? ` (${report.observation.accepted} accepted, ${report.observation.rejected} rejected)` : ''}`);
  L.push(`  Scan result: ${report.scanResult.supplied ? `${report.scanResult.findingCount} finding(s), integrity ${report.scanResult.integrity}` : 'not supplied, so no finding was analyzed'}`);
  for (const f of report.findings) {
    L.push(`  ${f.id ?? f.stableId ?? 'finding'} ${f.file ?? ''}${f.line ? `:${f.line}` : ''} ${f.vuln ?? ''}`.trimEnd());
    for (const t of f.boundaryView?.text ?? [f.notAnalyzed ?? 'not analyzed']) L.push(`    ${t}`);
  }
  for (const line of report.coverage.lines) L.push(line);
  for (const n of report.notes) L.push(`  Note: ${n}`);
  L.push(`  ${report.statement}`);
  return `${L.join('\n')}\n`;
}


/***/ })

};
