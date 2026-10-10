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

import { adapterContext, parseYamlDocuments, isObject, asArray, str, selectorMatches } from './adapter-kit.js';

export const KUBERNETES_PARSER = 'kubernetes-manifest';
export const KUBERNETES_PARSER_VERSION = '1';

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
export function parseKubernetes(text, fileCtx) {
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
