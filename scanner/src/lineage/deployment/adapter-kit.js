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

import { load as loadYaml } from '../../util/yaml.js';
import { nodeIdOf } from './boundary-graph.js';

const ANCHOR_LIMIT = 100;

/**
 * Parse one YAML document, or several separated by `---`. Never throws.
 * Returns `{ docs }` or `{ gap }` where the gap is a typed unsupported or
 * malformed result. YAML merge keys are not expanded by the loader, so a
 * document that uses `<<` is reported by the adapter that needs the key.
 */
export function parseYamlDocuments(text, file) {
  const aliasCount = (text.match(/(^|[\s\[{,:-])\*[A-Za-z0-9_-]+/g) || []).length;
  if (aliasCount > ANCHOR_LIMIT) {
    return { gap: { code: 'unsupported-syntax', subject: file, file, message: `YAML uses ${aliasCount} aliases, over the limit of ${ANCHOR_LIMIT}; the file is not read` } };
  }
  const chunks = text.split(/^---[ \t]*$/m);
  const docs = [];
  for (const chunk of chunks) {
    let doc;
    try { doc = loadYaml(chunk); } catch (e) {
      return { gap: { code: 'malformed-input', subject: file, file, message: `not valid YAML (${String(e.message).split('\n')[0]})` } };
    }
    if (doc !== undefined && doc !== null) docs.push(doc);
  }
  return { docs };
}

export function isObject(v) { return v !== null && typeof v === 'object' && !Array.isArray(v); }
export function asArray(v) { return Array.isArray(v) ? v : []; }
export function str(v) { return typeof v === 'string' && v.length > 0 ? v : null; }

/** True when every entry of `selector` is present with the same value in `labels`. An empty selector selects nothing. */
export function selectorMatches(selector, labels) {
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
export function adapterContext({ file, digest, environment, repository, revision, parser, parserVersion }) {
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
  return nodeIdOf({ kind: node.kind, name: node.name, environment: node.kind === 'environment' ? node.name : (node.environment ?? null), tenant: node.kind === 'tenant' ? node.name : (node.tenant ?? null) });
}
