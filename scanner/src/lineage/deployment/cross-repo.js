// cross-repo.js: resolve deployment boundaries across repositories (X-304).
//
// Extends the idea behind cross-repo-link.js (an operator declares that a node
// in one repository depends on a node in another) from the data-flow graph to
// the deployment boundary graph, and adds the two things that file's
// declared-link flavour did not need: an exact revision on both ends, and an
// access scope.
//
// Inputs are all local and all explicit: boundary graph exports the operator
// supplies (one per repository), a list of declared dependencies, and the set
// of repositories the operator is authorized to read. This module has no
// network access and no way to fetch a missing repository: an unavailable one
// is a gap, not a lookup. The source file contains no import of any network or
// process module, and a test pins that.
//
// A link resolves only when every one of these holds, each tested in both
// directions:
//   - both repositories are in the access scope and a graph was supplied for
//     each (otherwise: access-denied / repository-unavailable);
//   - each supplied graph passes validation and says it is the repository it
//     was supplied as (otherwise: graph-integrity / identity-collision);
//   - the graph's revision equals the revision the declaration binds, exactly
//     (otherwise: version-mismatch, or revision-unknown when the graph has none);
//   - the declared service exists, resolved, in the graph of the repository it
//     is declared in (otherwise: unresolved-identity), and no second supplied
//     repository also resolves that identity (otherwise: identity-collision);
//   - a declared entry route exists in the callee graph and reaches the callee
//     service (otherwise the link stays unresolved; no route is guessed).
//
// An unresolved link is not dropped. It is kept in `links` with every gap code
// that blocked it, and, when both revisions are bound by the declaration, as
// an unresolved edge to an unresolved callee node in the federated graph, so
// the dependency stays visible to path queries as a path nobody could verify.

import { semanticId, digestOf } from '../../posture/assurance/identity.js';
import {
  buildBoundaryGraph, importBoundaryGraph, validateBoundaryGraph, nodeIdOf, indexGraph, findPath, boundaryCrossings,
} from './boundary-graph.js';

export const CROSS_REPO_PARSER = 'cross-repo-declaration';
export const CROSS_REPO_PARSER_VERSION = '1';
export const DEFAULT_DECLARATION_FILE = 'cross-repo-declarations.json';

const REV = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const SVC = /^[^\u0000-\u001f\u007f]{1,256}$/;

function isObj(v) { return v !== null && typeof v === 'object' && !Array.isArray(v); }

/** Check one declaration's shape. Returns an error message or null. Pure. */
export function checkDeclaration(d) {
  if (!isObj(d)) return 'declaration must be an object';
  for (const side of ['caller', 'callee']) {
    const s = d[side];
    if (!isObj(s)) return `${side} is required`;
    if (typeof s.repository !== 'string' || !NAME.test(s.repository)) return `${side}.repository must be a repository name`;
    if (typeof s.revision !== 'string' || !REV.test(s.revision)) return `${side}.revision must be an exact 40 or 64 hex commit`;
    if (typeof s.service !== 'string' || !SVC.test(s.service)) return `${side}.service must be a service name`;
    if (typeof s.environment !== 'string' || !NAME.test(s.environment)) return `${side}.environment must be an environment name`;
    if (s.tenant !== undefined && s.tenant !== null && (typeof s.tenant !== 'string' || !NAME.test(s.tenant))) return `${side}.tenant must be null or a name`;
  }
  if (d.caller.environment !== d.callee.environment) return 'a cross-repository link cannot join two environments';
  if ((d.caller.tenant ?? null) !== (d.callee.tenant ?? null)) return 'a cross-repository link declares one tenant; a tenant transition needs its own declaration of both sides';
  if (d.callee.route !== undefined && d.callee.route !== null) {
    const r = d.callee.route;
    if (!isObj(r) || (r.host !== undefined && typeof r.host !== 'string') || (r.path !== undefined && typeof r.path !== 'string')) return 'callee.route must be {host?, path?}';
    if (r.host === undefined && r.path === undefined) return 'callee.route needs a host or a path';
  }
  return null;
}

export function declarationId(d) {
  return semanticId('blink', {
    callerRepository: d?.caller?.repository, callerRevision: d?.caller?.revision, callerService: d?.caller?.service,
    calleeRepository: d?.callee?.repository, calleeRevision: d?.callee?.revision, calleeService: d?.callee?.service,
    environment: d?.caller?.environment, tenant: d?.caller?.tenant ?? null, route: d?.callee?.route ?? null,
  }, ['callerRepository', 'callerRevision', 'callerService', 'calleeRepository', 'calleeRevision', 'calleeService', 'environment', 'tenant', 'route']);
}

function pathUnder(prefix, p) {
  if (typeof prefix !== 'string' || typeof p !== 'string') return false;
  if (prefix === '/') return true;
  return p === prefix || p.startsWith(prefix.endsWith('/') ? prefix : `${prefix}/`);
}

/**
 * @param {object} p
 * @param {Array<{repository: string, text?: string, graph?: object}>} p.graphs  supplied exports, one per repository
 * @param {object[]} p.declarations
 * @param {{authorizedRepositories: string[]}} p.accessScope
 * @param {{file?: string}} [p.declarationSource]
 */
export function resolveCrossRepoBoundaries({ graphs = [], declarations = [], accessScope, declarationSource = {} } = {}) {
  const gaps = [];
  const gap = (code, subject, message) => gaps.push({ code, subject, file: null, message });
  if (!isObj(accessScope) || !Array.isArray(accessScope.authorizedRepositories)) {
    return { status: 'invalid-input', reason: 'accessScope.authorizedRepositories is required; with no scope nothing is authorized', graph: null, links: [], gaps: [] };
  }
  const authorized = new Set(accessScope.authorizedRepositories.filter(r => typeof r === 'string'));
  const declFile = declarationSource.file ?? DEFAULT_DECLARATION_FILE;

  // ---- load the supplied graphs
  const supplied = new Map(); // repository -> { graph, index } for usable ones
  const claimed = new Map();  // repository -> count of supplied entries claiming it
  for (const g of graphs) if (isObj(g) && typeof g.repository === 'string') claimed.set(g.repository, (claimed.get(g.repository) ?? 0) + 1);
  const usable = [];
  for (const entry of graphs) {
    if (!isObj(entry) || typeof entry.repository !== 'string') { gap('malformed-input', 'graphs', 'a supplied graph without a repository name is ignored'); continue; }
    const repo = entry.repository;
    if (!authorized.has(repo)) { gap('access-denied', repo, `repository '${repo}' is not in the access scope; its graph was supplied but is not read`); continue; }
    if (claimed.get(repo) > 1) { gap('identity-collision', repo, `${claimed.get(repo)} supplied graphs claim to be repository '${repo}'; none is used`); continue; }
    let graph;
    if (typeof entry.text === 'string') {
      const imp = importBoundaryGraph(entry.text);
      if (imp.status !== 'ok') { gap('graph-integrity', repo, `the graph supplied for '${repo}' is ${imp.status}: ${imp.reason ?? imp.errors.map(e => e.message).slice(0, 3).join('; ')}`); continue; }
      graph = imp.graph;
    } else if (isObj(entry.graph)) {
      const v = validateBoundaryGraph(entry.graph);
      if (!v.ok) { gap('graph-integrity', repo, `the graph supplied for '${repo}' failed validation: ${v.errors.slice(0, 3).map(e => e.message).join('; ')}`); continue; }
      graph = entry.graph;
    } else { gap('malformed-input', repo, 'a supplied graph needs text or graph'); continue; }
    if (graph.repository !== repo) { gap('identity-collision', repo, `the graph supplied as '${repo}' says it is repository '${graph.repository}'; it is not used`); continue; }
    supplied.set(repo, { graph, index: indexGraph(graph) });
    usable.push(graph);
  }

  // ---- resolve declarations
  const links = [];
  const crossEdges = [];
  const extraNodes = [];
  const sortedDecls = declarations.map((d, i) => ({ d, i })).sort((a, b) => (declarationId(a.d) < declarationId(b.d) ? -1 : declarationId(a.d) > declarationId(b.d) ? 1 : a.i - b.i));
  const declDigest = digestOf(sortedDecls.map(x => x.d)); // order independent: the same declarations give the same evidence digest
  for (const { d } of sortedDecls) {
    const bad = checkDeclaration(d);
    if (bad) { gap('malformed-input', 'declaration', bad); links.push({ declarationId: null, status: 'invalid', gapCodes: ['malformed-input'], evidence: null, transitions: null, edgeId: null }); continue; }
    const id = declarationId(d);
    const blocked = [];
    const block = (code, message) => { blocked.push(code); gap(code, id, message); };
    const env = d.caller.environment, tenant = d.caller.tenant ?? null;

    const callerOk = authorized.has(d.caller.repository), calleeOk = authorized.has(d.callee.repository);
    if (!callerOk) block('access-denied', `caller repository '${d.caller.repository}' is not in the access scope`);
    if (!calleeOk) block('access-denied', `callee repository '${d.callee.repository}' is not in the access scope`);
    const callerG = callerOk ? supplied.get(d.caller.repository) : null;
    const calleeG = calleeOk ? supplied.get(d.callee.repository) : null;
    if (callerOk && !callerG) block('repository-unavailable', `no usable graph was supplied for caller repository '${d.caller.repository}'`);
    if (calleeOk && !calleeG) block('repository-unavailable', `no usable graph was supplied for callee repository '${d.callee.repository}'`);

    for (const [side, g, decl] of [['caller', callerG, d.caller], ['callee', calleeG, d.callee]]) {
      if (!g) continue;
      if (g.graph.revision === null) block('revision-unknown', `the ${side} graph for '${decl.repository}' records no revision, so the declared revision cannot be verified`);
      else if (g.graph.revision !== decl.revision) block('version-mismatch', `the ${side} graph for '${decl.repository}' is at ${g.graph.revision.slice(0, 12)}, the declaration binds ${decl.revision.slice(0, 12)}`);
    }

    const callerNodeId = nodeIdOf({ kind: 'service', name: d.caller.service, environment: env, tenant });
    const calleeNodeId = nodeIdOf({ kind: 'service', name: d.callee.service, environment: env, tenant });
    let callerNode = null, calleeNode = null;
    if (callerG && !blocked.length) {
      callerNode = callerG.index.nodesById.get(callerNodeId);
      if (!callerNode || !callerNode.resolved) block('unresolved-identity', `service '${d.caller.service}' (${env}) is not a resolved service in '${d.caller.repository}' at the bound revision`);
      else if (callerNode.repository !== null && callerNode.repository !== d.caller.repository) block('identity-collision', `service '${d.caller.service}' is owned by '${callerNode.repository}', not '${d.caller.repository}'`);
    }
    if (calleeG && !blocked.length) {
      calleeNode = calleeG.index.nodesById.get(calleeNodeId);
      if (!calleeNode || !calleeNode.resolved) block('unresolved-identity', `service '${d.callee.service}' (${env}) is not a resolved service in '${d.callee.repository}' at the bound revision`);
      else if (calleeNode.repository !== null && calleeNode.repository !== d.callee.repository) block('identity-collision', `service '${d.callee.service}' is owned by '${calleeNode.repository}', not '${d.callee.repository}'`);
      else {
        const others = [...supplied.entries()].filter(([repo, s]) => repo !== d.callee.repository && s.index.nodesById.get(calleeNodeId)?.resolved);
        if (others.length) block('identity-collision', `service '${d.callee.service}' (${env}) is also defined by ${others.map(([r]) => `'${r}'`).sort().join(', ')}; the callee identity is ambiguous`);
      }
    }

    // route and privilege transitions
    let routeNode = null, routeChain = null;
    if (!blocked.length && d.callee.route) {
      const want = d.callee.route;
      const candidates = calleeG.graph.nodes.filter(n => n.kind === 'route' && n.environment === env && (n.tenant ?? null) === tenant
        && (want.host === undefined || n.attrs.host === want.host || n.attrs.host === '*') && (want.path === undefined || pathUnder(n.attrs.path, want.path)));
      for (const r of candidates.sort((a, b) => (a.id < b.id ? -1 : 1))) {
        const chain = findPath(calleeG.index.out, r.id, calleeNodeId, { accept: (e) => e.relation === 'routes-to' && e.pathState !== 'blocked', maxHops: 4 });
        if (chain) { routeNode = r; routeChain = chain; break; }
      }
      if (!routeNode) block('unresolved-identity', `no route matching ${JSON.stringify(want)} reaches '${d.callee.service}' in '${d.callee.repository}'`);
    }

    const crossRepo = { callerRepository: d.caller.repository, callerRevision: d.caller.revision, calleeRepository: d.callee.repository, calleeRevision: d.callee.revision };
    const source = { file: declFile, digest: declDigest, parser: CROSS_REPO_PARSER, parserVersion: CROSS_REPO_PARSER_VERSION };
    const baseEdge = { relation: 'calls', from: callerNodeId, environment: env, tenant, effect: 'none', provenance: 'static-config', confidence: 'high', observationInterval: null, completeness: null, sourceRevision: d.caller.revision, source, discriminator: `xrepo:${d.callee.repository}`, crossRepo, attrs: {} };

    if (blocked.length) {
      links.push({ declarationId: id, status: 'unresolved', caller: { ...d.caller }, callee: { ...d.callee }, gapCodes: [...new Set(blocked)].sort(), evidence: null, transitions: null, edgeId: null });
      // Keep the dependency visible as an unresolved path, bound to the revisions the operator declared.
      extraNodes.push(
        { kind: 'service', name: d.caller.service, environment: env, tenant, repository: null, trustZone: 'unknown', resolved: false, unresolvedReason: 'cross-repository caller could not be verified', attrs: {}, declaredBy: [] },
        { kind: 'service', name: d.callee.service, environment: env, tenant, repository: null, trustZone: 'unknown', resolved: false, unresolvedReason: `cross-repository callee could not be resolved (${[...new Set(blocked)].sort().join(', ')})`, attrs: {}, declaredBy: [] },
      );
      crossEdges.push({ ...baseEdge, to: calleeNodeId, pathState: 'unresolved', confidence: 'low' });
      continue;
    }

    const targetId = routeNode ? routeNode.id : calleeNodeId;
    const edge = { ...baseEdge, to: targetId, pathState: 'possible' };
    crossEdges.push(edge);

    const calleeAssumes = calleeG.graph.edges.filter(e => e.relation === 'assumes' && e.from === calleeNodeId);
    const callerAssumes = callerG.graph.edges.filter(e => e.relation === 'assumes' && e.from === callerNodeId);
    const privileges = calleeAssumes.map(a => ({
      identityNodeId: a.to,
      identity: calleeG.index.nodesById.get(a.to)?.name ?? null,
      identityResolved: calleeG.index.nodesById.get(a.to)?.resolved ?? false,
      assumesEdgeId: a.id,
      grants: calleeG.graph.edges.filter(e => e.relation === 'grants' && e.from === a.to)
        .map(e => ({ edgeId: e.id, resource: calleeG.index.nodesById.get(e.to)?.name ?? null, effect: e.effect, pathState: e.pathState, discriminator: e.discriminator }))
        .sort((x, y) => (x.edgeId < y.edgeId ? -1 : 1)),
    })).sort((x, y) => (x.identityNodeId < y.identityNodeId ? -1 : 1));
    const nodeRefs = (g, nodeId) => (g.index.nodesById.get(nodeId)?.declaredBy ?? []).map(r => ({ ...r }));
    links.push({
      declarationId: id,
      status: 'resolved',
      caller: { ...d.caller }, callee: { ...d.callee },
      gapCodes: [],
      edgeId: null, // filled once the federated graph assigns ids
      evidence: {
        declaration: { file: declFile, digest: declDigest },
        caller: { repository: d.caller.repository, revision: d.caller.revision, graphDigest: callerG.graph.digest, nodeId: callerNodeId, declaredBy: nodeRefs(callerG, callerNodeId) },
        callee: { repository: d.callee.repository, revision: d.callee.revision, graphDigest: calleeG.graph.digest, nodeId: calleeNodeId, declaredBy: nodeRefs(calleeG, calleeNodeId) },
        route: routeNode ? { nodeId: routeNode.id, name: routeNode.name, declaredBy: nodeRefs(calleeG, routeNode.id), chainEdgeIds: routeChain.map(e => e.id) } : null,
      },
      transitions: {
        entry: routeNode ? { routeNodeId: routeNode.id, trustZone: routeNode.trustZone } : null,
        callerIdentities: callerAssumes.map(a => ({ identityNodeId: a.to, identity: callerG.index.nodesById.get(a.to)?.name ?? null })).sort((x, y) => (x.identityNodeId < y.identityNodeId ? -1 : 1)),
        calleePrivileges: privileges,
      },
      _edge: edge,
    });
  }

  // ---- federated graph
  const nodes = [...usable.flatMap(g => g.nodes), ...extraNodes];
  const edges = [...usable.flatMap(g => g.edges), ...crossEdges];
  const sources = [...usable.flatMap(g => g.sources), { file: declFile, digest: declDigest, parser: CROSS_REPO_PARSER, parserVersion: CROSS_REPO_PARSER_VERSION, bytes: JSON.stringify(declarations).length }];
  const built = buildBoundaryGraph({ repository: null, revision: null, nodes, edges, gaps: [...usable.flatMap(g => g.gaps), ...gaps], sources });
  if (!built.ok) return { status: 'invalid-graph', reason: 'the federated graph failed validation', graph: null, links: links.map(({ _edge, ...l }) => l), gaps, errors: built.errors };

  // attach edge ids and boundary crossings to resolved links
  const fIndex = indexGraph(built.graph);
  const finalLinks = links.map(({ _edge, ...l }) => {
    if (l.status !== 'resolved') return l;
    const match = built.graph.edges.find(e => e.crossRepo && e.relation === 'calls' && e.from === _edge.from && e.to === _edge.to && e.crossRepo.calleeRepository === _edge.crossRepo.calleeRepository && e.crossRepo.calleeRevision === _edge.crossRepo.calleeRevision && e.crossRepo.callerRevision === _edge.crossRepo.callerRevision);
    return { ...l, edgeId: match?.id ?? null, transitions: { ...l.transitions, crossings: match ? boundaryCrossings(match, fIndex.nodesById) : [] } };
  });
  return { status: 'ok', reason: null, graph: built.graph, links: finalLinks, gaps: built.graph.gaps };
}
