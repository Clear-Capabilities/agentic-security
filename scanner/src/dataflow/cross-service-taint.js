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
//
// SCOPE NOTE (next-gen taint capability #7 rebuild): step 1 of the
// algorithm above ("mark every consume entry-point as tainted-by-default")
// is NOT implemented anywhere in this file, or anywhere else in the
// engine — there is no mechanism that seeds a NEW taint source from a
// `consumes` declaration (e.g. marking a Kafka consumer callback's
// message parameter as tainted). This module only ANNOTATES findings the
// taint engine already discovers via its own normal source catalog
// (`catalog.js`) with cross-service context; it never makes a
// previously-invisible flow visible. In practice this means an HTTP
// edge benefits fully (HTTP request sources — body/query/header/cookie —
// are extensively cataloged already), while a Kafka/queue edge benefits
// only when the consumed payload happens to ALSO reach an already-
// cataloged source through some other path — which is rare, since raw
// message-queue payloads have no catalog entry of their own. Seeding new
// sources from `consumes` declarations would be a genuinely separate,
// larger capability; left as a deliberate, documented boundary here
// rather than attempted in this rebuild.

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as yaml from '../util/yaml.js';

import { statePath } from '../posture/state-dir.js';
const SERVICES_FILE_NAMES = ['services.yml', 'services.yaml'];

export function loadServiceGraph(scanRoot) {
  if (!scanRoot) return null;
  for (const name of SERVICES_FILE_NAMES) {
    const fp = statePath(scanRoot, name);
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
 * Split a URL path into its non-empty segments, e.g. "/balances/:id" ->
 * ["balances", ":id"].
 */
function _pathSegments(p) {
  return String(p || '').split('/').filter(Boolean);
}

/**
 * True when a path segment is a parameter placeholder, in EITHER of the
 * two conventions this file's own schema comment documents:
 * Express/Koa-style `:userId` or template-style `{userId}`.
 */
function _isWildcardSegment(seg) {
  return /^:.+$/.test(seg) || /^\{[^}]+\}$/.test(seg);
}

/**
 * Structural path-template match between an `exposes[].route` entry
 * (e.g. "GET /balances/:userId") and an `edges[].path` entry (e.g.
 * "/balances/{userId}").
 *
 * The previous implementation did `expose.route.includes(edge.path)` — a
 * crude substring check. This file's OWN header comment documents the
 * two sides using DIFFERENT placeholder syntaxes (`:userId` vs
 * `{userId}`), so that substring check could never succeed on the
 * example it was written to describe — confirmed by direct reproduction
 * against that exact example, which returned zero contracts. Fixed by
 * comparing SEGMENT-BY-SEGMENT: a literal segment must match exactly, a
 * placeholder segment on EITHER side matches any segment on the other
 * (since we don't know the upstream's real parameter name convention
 * without parsing it, and the security question — "does an edge exist
 * pointing at this exact path shape" — doesn't depend on knowing it).
 * The route's leading HTTP method token (if present) is stripped before
 * comparing; method itself is not matched (this schema has no per-edge
 * method field), matching the pre-existing, unaudited behavior.
 */
function _pathTemplateMatches(exposeRoute, edgePath) {
  if (!exposeRoute || !edgePath) return false;
  const routePath = String(exposeRoute).replace(/^[A-Z]+\s+/, '');
  const a = _pathSegments(routePath);
  const b = _pathSegments(String(edgePath).split('?')[0]);
  if (a.length !== b.length) return false;
  return a.every((seg, i) => seg === b[i] || _isWildcardSegment(seg) || _isWildcardSegment(b[i]));
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
        const matches = (edge.via === 'http' && edge.path && expose.route && _pathTemplateMatches(expose.route, edge.path))
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

// Escapes every regex metacharacter in a literal field name before it is
// embedded in a `\b...\b` pattern. The previous version only replaced the
// FIRST `.` (`field.replace('.', '\\.')`, no `/g` flag) — any OTHER dot in
// a multi-segment field name (e.g. "a.b.c") was left as a live regex
// metacharacter matching any character, silently over-broadening the
// match. Fixed generally, for every metacharacter, not just repeated dots.
function _escapeRegex(s) {
  return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Provenance values (catalog.js's per-source `provenance` field, e.g.
// 'http-body' for req.body) that mean "this value arrived over an
// incoming HTTP request" — the signal used to correlate a finding with a
// declared `via: 'http'` cross-service edge.
const HTTP_PROVENANCE = new Set(['http-body', 'url-param', 'path-param', 'header', 'cookie']);

// Every provenance value attached anywhere on a finding: the primary
// source (`f.sourceProvenance`) plus every step in its source chain
// (`f.chain[].provenance`) — a finding can have more than one source
// reaching the sink, and any one of them may be the HTTP-originated one.
function _findingProvenances(f) {
  const provs = new Set();
  if (f && f.sourceProvenance) provs.add(f.sourceProvenance);
  if (f && Array.isArray(f.chain)) {
    for (const c of f.chain) { if (c && c.provenance) provs.add(c.provenance); }
  }
  return provs;
}

// Every textual source LABEL attached anywhere on a finding (the catalog
// entry's own fixed label, e.g. "req.body" — never the specific accessed
// property, which the engine does not retain on the finding today). Used
// only as a best-effort fallback for non-HTTP transports (Kafka/queue),
// where there is no provenance category to correlate against at all.
function _findingSourceText(f) {
  const parts = [];
  if (f && f.source && f.source.label) parts.push(f.source.label);
  if (f && Array.isArray(f.chain)) {
    for (const c of f.chain) { if (c && c.label) parts.push(c.label); }
  }
  return parts.join(' ');
}

/**
 * Annotate findings whose source matches a cross-service taint contract.
 * Adds `crossService: { from, to, via, taintedFields, matchedField,
 * precision }` and bumps severity by one tier (medium → high, high →
 * critical).
 *
 * The previous implementation matched a contract's declared field NAMES
 * as literal text against `f.source.snippet`/`f.source.expr` — fields
 * that confirmed direct code reading never exist on a real finding (the
 * real shape, set in `engine.js`, is `f.source = {file, line, label}`).
 * That made this function a structural no-op for every real taint-engine
 * finding, verified via a direct `runScan()` reproduction of the exact
 * scenario this file's own header describes.
 *
 * Fixed with two correlation strategies, chosen by transport, since a
 * real finding never carries the SPECIFIC field name that reached the
 * sink (only the catalog source's fixed label, e.g. "req.body" — see
 * `_findingSourceText`'s own comment):
 *   - `via: 'http'`: correlate by PROVENANCE — an HTTP request source is
 *     already reliably categorized by the catalog (`http-body`,
 *     `url-param`, `header`, `cookie`, …), so this is a real, sound
 *     signal rather than a text-match guess. `matchedField` is left null
 *     and `precision: 'transport'` records honestly that the match is at
 *     the endpoint level, not a specific declared field — the security
 *     conclusion (this value arrived across a declared trust boundary)
 *     holds regardless of which exact field it was.
 *   - every other transport (Kafka/queue): no provenance category exists
 *     for a raw message payload (per this file's own SCOPE NOTE), so the
 *     best available signal is literal field-name text matching against
 *     whatever source labels the finding does carry — kept as a
 *     best-effort fallback, `precision: 'field'` when it hits, but this
 *     will rarely fire until source-seeding from `consumes` declarations
 *     exists (documented as a separate, not-yet-attempted capability).
 */
export function annotateCrossServiceFindings(findings, graph, currentService) {
  if (!Array.isArray(findings) || !graph || !currentService) return { annotated: 0, bumped: 0 };
  const contracts = upstreamTaintContract(graph, currentService);
  if (!contracts.length) return { annotated: 0, bumped: 0 };
  let annotated = 0, bumped = 0;
  for (const f of findings) {
    for (const contract of contracts) {
      let matchedField = null;
      let matched = false;
      if (contract.via === 'http') {
        const provs = _findingProvenances(f);
        matched = [...provs].some(p => HTTP_PROVENANCE.has(p));
      } else {
        const text = _findingSourceText(f);
        matchedField = contract.taintedFields.find(field => new RegExp(`\\b${_escapeRegex(field)}\\b`).test(text)) || null;
        matched = !!matchedField;
      }
      if (!matched) continue;
      f.crossService = {
        from: contract.upstreamService,
        to: currentService.name,
        via: contract.via,
        taintedFields: contract.taintedFields,
        matchedField,
        precision: matchedField ? 'field' : 'transport',
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

export const _internals = { _normalizeGraph, SERVICES_FILE_NAMES, _pathTemplateMatches, _escapeRegex };
