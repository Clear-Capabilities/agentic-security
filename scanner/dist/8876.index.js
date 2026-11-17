export const id = 8876;
export const ids = [8876];
export const modules = {

/***/ 18876:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {


// EXPORTS
__webpack_require__.d(__webpack_exports__, {
  H2: () => (/* binding */ DEPLOYMENT_FEATURE),
  qz: () => (/* binding */ MAX_INGEST_FILES),
  In: () => (/* binding */ ingestDeploymentConfig),
  Bi: () => (/* binding */ ingestDeploymentFiles)
});

// UNUSED EXPORTS: ADAPTER_NAMES, detectFormat, invalidateChangedSources, resolveUnderRoot

// EXTERNAL MODULE: external "node:fs"
var external_node_fs_ = __webpack_require__(73024);
// EXTERNAL MODULE: external "node:path"
var external_node_path_ = __webpack_require__(76760);
// EXTERNAL MODULE: ./src/posture/assurance/identity.js
var identity = __webpack_require__(41877);
// EXTERNAL MODULE: ./src/posture/assurance/config.js
var assurance_config = __webpack_require__(90385);
// EXTERNAL MODULE: ./src/posture/assurance/bounded-io.js
var bounded_io = __webpack_require__(49447);
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

// EXTERNAL MODULE: ./src/lineage/deployment/iam-eval.js
var iam_eval = __webpack_require__(1086);
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
    if (actions.join(',').length > 250) kit.gap('limit-exceeded', subject, 'a statement\'s action list is longer than the graph records; the clipped list leaves decisions about the missing actions unresolved');
    if (conditioned && (0,iam_eval/* statementAttrs */.c2)(actions, st.Condition).conditionSupported !== true) kit.gap('unsupported-syntax', subject, 'a statement condition uses an operator or value outside the supported subset (StringEquals, StringNotEquals, Bool, ArnEquals); decisions it can affect stay unresolved');
    for (const r of resources.slice(0, MAX_RESOURCES_PER_STATEMENT)) {
      const target = kit.node('resource', `aws/${r}`, { trustZone: 'internal', attrs: r === '*' ? { wildcard: true } : {} });
      // threat-model FR-03.1: the action list (and whether it was clipped) and the condition, in a form the path search can decide
      const attrs = (0,iam_eval/* statementAttrs */.c2)(actions, conditioned ? st.Condition : null);
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
    const r = (0,bounded_io/* readFileBounded */.Y1)(real, maxBytes);
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


/***/ }),

/***/ 49447:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   Y1: () => (/* binding */ readFileBounded)
/* harmony export */ });
/* unused harmony exports capOutput, withDeadline, retryBounded, guardedModelCall */
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(73024);
/* harmony import */ var _egress_policy_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(45712);
/* harmony import */ var _egress_redact_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(11723);
/* harmony import */ var _egress_audit_js__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(37355);
/* harmony import */ var _config_js__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(90385);
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
  if (!Number.isInteger(maxBytes) || maxBytes < 1) return (0,_config_js__WEBPACK_IMPORTED_MODULE_4__/* .typed */ .nE)('blocked', 'invalid-config', 'maxBytes must be a positive integer');
  let fd;
  try {
    fd = node_fs__WEBPACK_IMPORTED_MODULE_0__.openSync(filePath, 'r');
    const st = node_fs__WEBPACK_IMPORTED_MODULE_0__.fstatSync(fd);
    if (!st.isFile()) return (0,_config_js__WEBPACK_IMPORTED_MODULE_4__/* .typed */ .nE)('blocked', 'limit-exceeded', 'not a regular file');
    if (st.size > maxBytes) return (0,_config_js__WEBPACK_IMPORTED_MODULE_4__/* .typed */ .nE)('blocked', 'limit-exceeded', `file is ${st.size} bytes, over the ${maxBytes} byte limit`, { bytes: st.size });
    const buf = Buffer.alloc(maxBytes + 1);
    const n = node_fs__WEBPACK_IMPORTED_MODULE_0__.readSync(fd, buf, 0, maxBytes + 1, 0);
    if (n > maxBytes) return (0,_config_js__WEBPACK_IMPORTED_MODULE_4__/* .typed */ .nE)('blocked', 'limit-exceeded', `file grew past the ${maxBytes} byte limit while reading`);
    return (0,_config_js__WEBPACK_IMPORTED_MODULE_4__/* .typed */ .nE)('ok', null, 'read', { text: buf.subarray(0, n).toString('utf8'), bytes: n });
  } catch (e) {
    return (0,_config_js__WEBPACK_IMPORTED_MODULE_4__/* .typed */ .nE)('blocked', 'missing-dependency', `cannot read ${filePath}: ${e.code || e.message}`);
  } finally {
    if (fd !== undefined) { try { node_fs__WEBPACK_IMPORTED_MODULE_0__.closeSync(fd); } catch { /* already closed */ } }
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


/***/ })

};
