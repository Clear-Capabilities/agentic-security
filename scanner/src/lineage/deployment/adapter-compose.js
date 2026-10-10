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

import { adapterContext, parseYamlDocuments, isObject, asArray, str } from './adapter-kit.js';

export const COMPOSE_PARSER = 'compose-file';
export const COMPOSE_PARSER_VERSION = '1';

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

export function parseCompose(text, fileCtx) {
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
