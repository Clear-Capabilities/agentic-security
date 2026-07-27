// Cross-repo / cross-service taint — Recommendation #4 of the world-class
// roadmap.
//
// Discovers vulnerabilities that no single-repo scan can find: tainted
// data flowing from service A's HTTP request body, through A's response,
// into service B's consumer, then to a sink inside B. The "trust this
// because the upstream team owns it" assumption is what kills companies;
// the scanner catches it by reading a per-project service-graph file and
// propagating taint across service boundaries.
//
// Inputs:
//   .agentic-security/services.yml — declares service-to-service edges:
//
//     services:
//       payments:
//         repo: github.com/acme/payments
//         exposes:
//           - { route: "POST /charges",       taints: ["request.amount", "request.cardToken"] }
//         consumes:
//           - { source: "events.charge_created", fields: ["amount", "cardToken"] }
//       ledger:
//         repo: github.com/acme/ledger
//         exposes:
//           - { route: "GET /balances/:userId",  taints: ["pathParam.userId"] }
//
//     edges:
//       - { from: "payments", to: "ledger", via: "http", path: "/balances/{userId}" }
//       - { from: "payments", to: "fraud",  via: "kafka", topic: "events.charge_created" }
//
// The scanner uses this graph to:
//   1. Mark every "consumes" entry-point in each service as tainted-by-default
//   2. Walk the call graph from those entry points to any sink
//   3. When a finding's sink is reachable from a cross-service edge, emit a
//      `crossService: { from, to, via, path }` annotation
//   4. Bump severity by one tier because cross-service taint is by definition
//      reaching across a trust boundary
//
// In v1 we don't run BOTH services in one scan — that would require
// either a monorepo or a federated-scan API. We DO emit cross-service
// findings when the local service is on the receiving end of an edge,
// based on the declared upstream taint contract.

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as yaml from '../util/yaml.js';

const SERVICES_FILE_NAMES = ['services.yml', 'services.yaml'];

export function loadServiceGraph(scanRoot) {
  if (!scanRoot) return null;
  for (const name of SERVICES_FILE_NAMES) {
    const fp = path.join(scanRoot, '.agentic-security', name);
    if (!fs.existsSync(fp)) continue;
    try {
      const raw = fs.readFileSync(fp, 'utf8');
      const doc = yaml.load(raw);
      return _normalizeGraph(doc);
    } catch (e) {
      return { _error: `Failed to parse ${fp}: ${e.message}` };
    }
  }
  return null;
}

function _normalizeGraph(doc) {
  if (!doc || typeof doc !== 'object') return null;
  const services = {};
  for (const [name, def] of Object.entries(doc.services || {})) {
    services[name] = {
      name,
      repo: def.repo || null,
      exposes: Array.isArray(def.exposes) ? def.exposes : [],
      consumes: Array.isArray(def.consumes) ? def.consumes : [],
    };
  }
  const edges = Array.isArray(doc.edges) ? doc.edges.map(e => ({
    from: e.from, to: e.to,
    via: e.via || 'http',
    path: e.path || null,
    topic: e.topic || null,
  })) : [];
  return { services, edges };
}

/**
 * Identify the "current service" by name. Two heuristics:
 *   1. If the scanRoot's package.json / pyproject.toml / etc. name matches
 *      a service in the graph, that's us.
 *   2. Otherwise fall back to the basename of the scanRoot.
 */
export function identifyCurrentService(graph, scanRoot) {
  if (!graph || !graph.services) return null;
  // Try package.json / pyproject.toml name field.
  let projectName = null;
  try {
    const pkg = path.join(scanRoot, 'package.json');
    if (fs.existsSync(pkg)) {
      const j = JSON.parse(fs.readFileSync(pkg, 'utf8'));
      projectName = j.name;
    }
  } catch {}
  if (projectName && graph.services[projectName]) return graph.services[projectName];
  const base = path.basename(scanRoot);
  if (graph.services[base]) return graph.services[base];
  return null;
}

/**
 * Compute the list of incoming "edges" terminating at the current
 * service. Each edge identifies which upstream service is the source of
 * taint into this service.
 */
export function incomingEdges(graph, currentService) {
  if (!graph || !currentService) return [];
  return (graph.edges || []).filter(e => e.to === currentService.name);
}

/**
 * For each consume entry on the current service, locate the upstream
 * `exposes` entry that produces it (matched by path/topic) and return
 * the upstream-declared tainted fields. This is the data we use to
 * mark code entry points as tainted-by-default during scanning.
 */
export function upstreamTaintContract(graph, currentService) {
  if (!graph || !currentService) return [];
  const contracts = [];
  for (const consume of currentService.consumes || []) {
    for (const edge of (graph.edges || [])) {
      if (edge.to !== currentService.name) continue;
      const upstream = graph.services[edge.from];
      if (!upstream) continue;
      for (const expose of upstream.exposes || []) {
        const matches = (edge.via === 'http' && edge.path && expose.route && expose.route.includes(edge.path.split('?')[0]))
                     || (edge.via === 'kafka' && edge.topic && consume.source === edge.topic);
        if (matches) {
          contracts.push({
            upstreamService: upstream.name,
            via: edge.via,
            taintedFields: [...(consume.fields || []), ...(expose.taints || [])],
            consume,
            expose,
          });
        }
      }
    }
  }
  return contracts;
}

/**
 * Annotate findings whose source matches a cross-service taint contract.
 * Adds `crossService: { from, via, path, taintedFields }` and bumps
 * severity by one tier (medium → high, high → critical).
 */
export function annotateCrossServiceFindings(findings, graph, currentService) {
  if (!Array.isArray(findings) || !graph || !currentService) return { annotated: 0, bumped: 0 };
  const contracts = upstreamTaintContract(graph, currentService);
  if (!contracts.length) return { annotated: 0, bumped: 0 };
  let annotated = 0, bumped = 0;
  for (const f of findings) {
    const sourceExpr = (f.source && (f.source.snippet || f.source.expr)) || f.snippet || '';
    for (const contract of contracts) {
      const matches = contract.taintedFields.some(field => {
        const pat = new RegExp(`\\b${field.replace('.', '\\.')}\\b`);
        return pat.test(sourceExpr);
      });
      if (!matches) continue;
      f.crossService = {
        from: contract.upstreamService,
        to: currentService.name,
        via: contract.via,
        taintedField: contract.taintedFields.find(field => new RegExp(`\\b${field.replace('.', '\\.')}\\b`).test(sourceExpr)),
      };
      annotated++;
      // Severity bump.
      const ladder = ['info', 'low', 'medium', 'high', 'critical'];
      const cur = ladder.indexOf(f.severity);
      if (cur > 0 && cur < ladder.length - 1) {
        f._severityBumpReason = `cross-service-from:${contract.upstreamService}`;
        f.severity = ladder[cur + 1];
        bumped++;
      }
      break;
    }
  }
  return { annotated, bumped };
}

/**
 * Run the cross-service annotation pass — convenience entry point called
 * from the engine after the normal scan completes.
 */
export function runCrossServiceTaint(scanRoot, findings) {
  const graph = loadServiceGraph(scanRoot);
  if (!graph || graph._error) return { error: graph?._error, annotated: 0 };
  const current = identifyCurrentService(graph, scanRoot);
  if (!current) return { error: 'no-current-service-identified', annotated: 0 };
  return annotateCrossServiceFindings(findings, graph, current);
}

export const _internals = { _normalizeGraph, SERVICES_FILE_NAMES };
