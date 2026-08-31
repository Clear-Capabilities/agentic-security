//
// source-registry.js — Data Flow Explorer, Sub-project D, increment D2.
//
// Reclassifies scanner/src/dataflow/catalog.js's `kind: 'source'` entries
// (180 as of this writing — re-derive via `CATALOG.filter(e =>
// e.kind === 'source').length` rather than trusting this comment; the
// dataflow/CLAUDE.md count has already drifted twice) into DataFlowGraph
// v1's `SOURCE_CATEGORIES` / `coverageStatus` vocabulary (`schema.js`).
//
// This module is the MECHANICAL implementation of a binding, independently
// reviewed design — it is not a fresh design decision. Every mapping row
// below traces to `DESIGN_REGISTRIES.md`:
//   §4    — PROVENANCE_MAP, the primary mapping (keyed on the entry's
//           declared `provenance` field).
//   §4.1  — AGENT_TOOL_REFINEMENT: `agent-tool` provenance splits per-entry
//           between model-produced tool arguments and results/resources
//           flowing back to the model.
//   §4.2  — the `language === 'cpp'` descriptor-generic-I/O refinement:
//           `recv`/`recvfrom`/`read`/`fread`/`fgets` cannot say whether
//           they read a file, socket, pipe or stdin, so their C entries
//           demote to `partial`.
//   §4.3  — NO_PROVENANCE_OVERRIDES: the 82 entries with no declared
//           `provenance` at all, resolved by a per-entry-id override table.
//           Per §9.1, THIS module is the table's permanent home.
//   §6    — the `coverageStatus` decision procedure (modeled/partial/
//           candidate/unsupported — never `manual`, §6.5).
//   §7.1  — node kind is always `'source'` for a reclassified source entry
//           (checked by this module's own tests, not assumed).
//   §9.0  — the shared `{kind, category, coverageStatus, externality,
//           reason}` decision shape.
//
// Pure reclassification layer: reads CATALOG entries as DATA and maps them
// onto the target vocabulary. It never re-derives what a call site
// matches — `matchSource()` in dataflow/catalog.js already owns that, and
// duplicating it here would fork a matcher the corpus proves against one
// that nothing proves (DESIGN_REGISTRIES.md §1).
//
// Isolation: imports ONLY `CATALOG` from ../dataflow/catalog.js. Never
// dataflow/engine.js, never dataflow/summaries.js, never matcher internals
// (this PRD's §18.1 isolation principle, same basis Sub-project A/B/C use
// for their own `dataflow/` reuse).
//
// The field this module emits is `category` — NOT `subtype`. On a
// DataFlowGraph v1 node, `category` becomes `node.subtype` (§9.0). A
// registry must never itself emit a field literally called `subtype`: the
// two are the same vocabulary at different layers, and conflating them
// would let a registry decision validate as a real graph node without ever
// passing through Sub-project E's future graph builder.

import { CATALOG } from '../dataflow/catalog.js';

// ─────────────────────────────────────────────────────────────────────────
// §4 — PROVENANCE_MAP: the primary source-side mapping, keyed on the
// entry's declared `provenance` field (12 rows).
// ─────────────────────────────────────────────────────────────────────────

export const PROVENANCE_MAP = Object.freeze({
  'http-body':    Object.freeze({ category: 'http-body',             status: 'modeled', why: 'exact vocabulary match' }),
  'url-param':    Object.freeze({ category: 'http-query',            status: 'modeled', why: 'pure rename; the query string' }),
  'path-param':   Object.freeze({ category: 'http-route',            status: 'modeled', why: 'pure rename; a route/path segment' }),
  'header':       Object.freeze({ category: 'http-header',           status: 'modeled', why: 'pure rename' }),
  'cookie':       Object.freeze({ category: 'http-cookie',           status: 'modeled', why: 'pure rename' }),
  'env':          Object.freeze({ category: 'env-value',             status: 'modeled', why: 'pure rename' }),
  'cli':          Object.freeze({ category: 'cli-argument',          status: 'modeled', why: 'pure rename' }),
  // Both rows below carry a `language === 'cpp'` refinement (§4.2) — C's
  // I/O primitives are descriptor-generic, so their C entries demote to
  // `partial` (see CPP_DESCRIPTOR_GENERIC_PROVENANCE below).
  'network':      Object.freeze({ category: 'external-api-response', status: 'modeled', why: 'reads an outbound response body (fetch/axios/requests/urlopen)' }),
  'file-read':    Object.freeze({ category: 'storage-read',          status: 'modeled', why: "FR-101 groups 'files and object storage reads'; storage-read is its only encoding" }),
  'url-fragment': Object.freeze({ category: 'http-query',            status: 'partial', why: 'LOSSY: a fragment is URL-borne but never transmitted to the server; SOURCE_CATEGORIES has no http-fragment value' }),
  'stdin':        Object.freeze({ category: 'user-input',            status: 'partial', why: 'LOSSY: broadens to the generic category; no stdin/console value exists' }),
  // `agent-tool` is the one provenance value that does NOT resolve on the
  // provenance key alone — its 8 entries split directionally between
  // model-produced tool ARGUMENTS and tool RESULTS/resources flowing back
  // (§4.1). This row exists so the completeness guard still sees the key
  // covered, and records WHY it needs refinement. `status: 'split'` is an
  // INTERNAL marker only — reclassifySource() intercepts it before it can
  // ever reach a caller as a coverageStatus.
  'agent-tool':   Object.freeze({ category: null, status: 'split', why: 'REFINED PER ENTRY: arguments (model-produced) vs results/resources (returned to the model) are different SOURCE_CATEGORIES' }),
});

// ─────────────────────────────────────────────────────────────────────────
// §4.1 — agent-tool splits directionally. 8 rows.
// ─────────────────────────────────────────────────────────────────────────

export const AGENT_TOOL_REFINEMENT = Object.freeze({
  'py-mcp-tool':              Object.freeze({ category: 'ai-model-output',       status: 'partial', why: 'the tool parameter is whatever the model chose to pass; ai-model-output normally denotes a completion, so this is an approximation' }),
  'py-mcp-server-tool':       Object.freeze({ category: 'ai-model-output',       status: 'partial', why: 'as py-mcp-tool' }),
  'js-mcp-call-args':         Object.freeze({ category: 'ai-model-output',       status: 'partial', why: 'as py-mcp-tool' }),
  'js-mcp-request-params':    Object.freeze({ category: 'ai-model-output',       status: 'partial', why: 'as py-mcp-tool' }),
  'js-mcp-extra-args':        Object.freeze({ category: 'ai-model-output',       status: 'partial', why: 'as py-mcp-tool' }),
  'js-mcp-tool-result':       Object.freeze({ category: 'ai-tool-result',        status: 'modeled', why: 'literally a tool result' }),
  'py-mcp-tool-result':       Object.freeze({ category: 'ai-tool-result',        status: 'modeled', why: 'literally a tool result' }),
  'js-mcp-resource-contents': Object.freeze({ category: 'ai-retrieved-document', status: 'modeled', why: 'an MCP resource IS a retrieved document' }),
});

// ─────────────────────────────────────────────────────────────────────────
// §4.2 — C's I/O primitives are descriptor-generic. Within these two
// provenance buckets, a `cpp` entry cannot say whether it read a file, a
// socket, a pipe or stdin, so it is refined on top of PROVENANCE_MAP:
// category unchanged, status demoted to `partial`. This is a REFINEMENT of
// a declared value, not a fallback for a missing one (that's §4.3, a
// different mechanism entirely).
// ─────────────────────────────────────────────────────────────────────────

export const CPP_DESCRIPTOR_GENERIC_PROVENANCE = new Set(['network', 'file-read']);

const CPP_DESCRIPTOR_GENERIC_WHY = Object.freeze({
  'network': 'LOSSY: a raw socket receive is directionally ambiguous — on a client socket this is an API response, on a listening socket it is an inbound client request, which external-api-response mis-describes',
  'file-read': 'LOSSY: a C file descriptor / FILE* is equally a file, socket, pipe or stdin; the entry cannot say which',
});

// ─────────────────────────────────────────────────────────────────────────
// §4.3 — the 82 source entries carrying NO `provenance` field at all. The
// category comes from the entry's own descriptive metadata (id/label/
// framework), never from a field its author set for classification — hence
// `candidate` for every row, per §6.3's decision procedure. Per §9.1, THIS
// table is the permanent home for these mappings (the design-phase PoC's
// own copy is redundant now that this module ships). Keys must equal
// EXACTLY the set of source entries with no declared `provenance` — see
// this file's own test suite for the completeness guard that enforces
// that, in both directions, against the live catalog.
// ─────────────────────────────────────────────────────────────────────────

export const NO_PROVENANCE_OVERRIDES = Object.freeze({
  // Python / Flask
  'py-flask-request-args': 'http-query',
  'py-flask-request-form': 'http-body',
  'py-flask-request-json': 'http-body',
  'py-flask-request-values': 'http-query',      // merged query+form bag
  'py-flask-request-cookies': 'http-cookie',
  'py-flask-request-headers': 'http-header',
  'py-flask-request-data': 'http-body',
  // Python / FastAPI (call form; the annotation form DOES carry provenance)
  'py-fastapi-request-query': 'http-query',
  'py-fastapi-request-body': 'http-body',
  'py-fastapi-form': 'http-body',
  // Python / Django
  'py-django-request-GET': 'http-query',
  'py-django-request-POST': 'http-body',
  'py-django-request-FILES': 'http-upload',
  'py-django-request-META': 'http-header',
  // Python / stdlib
  'py-os-getenv': 'env-value',
  'py-os-environ': 'env-value',
  'py-input': 'user-input',
  // Java / Servlet
  'java-request-getParameter': 'http-query',
  'java-request-getHeader': 'http-header',
  'java-request-getCookies': 'http-cookie',
  'java-request-getInputStream': 'http-body',
  'java-request-getReader': 'http-body',
  // Java / stdlib
  'java-system-getenv': 'env-value',
  'java-system-getProperty': 'env-value',       // JVM system properties, env-adjacent
  // Java / Spring annotations
  'java-spring-requestparam': 'http-query',
  'java-spring-pathvariable': 'http-route',
  'java-spring-requestbody': 'http-body',
  'java-spring-requestheader': 'http-header',
  // C# / ASP.NET Core annotations
  'cs-aspnet-fromquery': 'http-query',
  'cs-aspnet-frombody': 'http-body',
  'cs-aspnet-fromform': 'http-body',
  'cs-aspnet-fromroute': 'http-route',
  'cs-aspnet-fromheader': 'http-header',
  'cs-request-params': 'http-query',            // merged bag
  // Go / net/http
  'go-r-form': 'http-body',                     // r.Form merges URL query + POST form
  'go-r-postform': 'http-body',
  'go-r-body': 'http-body',
  'go-r-formvalue': 'http-body',
  'go-r-postformvalue': 'http-body',
  'go-r-uquery': 'http-query',
  'go-r-uquery-get': 'http-query',
  // Go / gin
  'go-gin-query': 'http-query',
  'go-gin-bindjson': 'http-body',
  'go-gin-postform': 'http-body',
  'go-gin-shouldbind': 'http-body',
  'go-gin-shouldbindjson': 'http-body',
  // Go / echo
  'go-echo-param': 'http-route',
  'go-echo-formvalue': 'http-body',
  'go-echo-queryparam': 'http-query',
  'go-echo-bind': 'http-body',
  // Go / chi, fiber, buffalo, gorilla
  'go-chi-urlparam': 'http-route',
  'go-fiber-body': 'http-body',
  'go-fiber-query': 'http-query',
  'go-fiber-params': 'http-route',
  'go-fiber-formvalue': 'http-body',
  'go-fiber-cookies': 'http-cookie',
  'go-fiber-bodyparser': 'http-body',
  'go-buffalo-param': 'http-route',
  'go-buffalo-request': 'http-body',
  'go-gorilla-vars': 'http-route',
  // Ruby
  'rb-rails-params': 'http-body',               // merged query+body+route bag
  'rb-rails-cookies': 'http-cookie',
  'rb-rails-session': 'http-cookie',            // Rails sessions are cookie-backed by default
  'rb-env': 'env-value',
  'rb-sinatra-request-body': 'http-body',
  'rb-sinatra-request-env': 'http-header',      // the Rack env hash carries request headers
  'rb-sinatra-request-params': 'http-query',    // merged bag
  // PHP
  'php-request': 'http-body',                   // $_REQUEST merges GET+POST+COOKIE
  'php-get': 'http-query',
  'php-post': 'http-body',
  'php-cookie': 'http-cookie',
  'php-server': 'http-header',
  'php-symfony-query': 'http-query',
  'php-symfony-request': 'http-body',
  'php-symfony-cookies': 'http-cookie',
  'php-symfony-headers': 'http-header',
  'php-symfony-files': 'http-upload',
  'php-symfony-content': 'http-body',
  'php-symfony-get': 'http-query',              // merged bag
  // Kotlin
  'kt-request-param': 'http-query',
  'kt-request-header': 'http-header',
  'kt-ktor-parameters': 'http-query',
});

// ─────────────────────────────────────────────────────────────────────────
// Externality (§9.0's decision shape requires it on every returned
// decision). DESIGN_REGISTRIES.md §7.5's `CATEGORY_EXTERNALITY` table is
// SINK-focused only — D1's binding design does not specify a source-side
// equivalent, and the design-phase PoC's own `reclassifySource()` never
// computed one at all. This module must still emit the field (§9.0), so
// the value below is this increment's own resolution of that gap, derived
// from the one shipped precedent that exists: the flagship fixture's `web`
// node (`fixtures/build-flagship-fixture.mjs`) — `kind: 'source'`,
// `subtype: 'web-app'`, `externality: 'internal'`. That fixture models the
// checkout/registration form collection point as INTERNAL even though the
// person submitting the form is an anonymous public user — establishing
// that a source's externality reads the SAME counterparty rule §7.5 already
// states for sinks: *is the counterparty on the other side of this data
// exchange a party outside this program?* An end user hitting your own
// HTTP/GraphQL/gRPC/CLI endpoint, or your own process's env/argv/stdin, is
// your front door, not an outside party — so the analyzed system's own code
// is the counterparty, giving `internal`. (This is NOT "is the collection
// point itself part of the analyzed system" — every catalog source entry's
// collection point is trivially part of the analyzed system, or there
// would be no call site to catalog at all, so that framing collapses to
// "always true" and predicts nothing; it is specifically the identity of
// the COUNTERPARTY, symmetric with the sink-side rule, that this table
// encodes.) Nor is it "is the eventual human origin of the bytes untrusted"
// — every catalog source entry answers yes to that by construction, which
// is why it's a taint source at all, so that question cannot be what
// externality encodes either, or every source would trivially be
// `external` and the field would carry no information.
//
// This table mirrors CATEGORY_EXTERNALITY's own counterparty-rule reasoning,
// one class at a time:
//   - ordinary in-app collection points (HTTP shapes, CLI, env, stdin /
//     user-input) → `internal`, matching the flagship precedent directly:
//     the counterparty is this program's own front door, not an outside
//     party.
//   - genuinely third-party-origin categories (an external API's response
//     body, a webhook payload, anything AI-model/tool/resource-sourced) →
//     `external`, matching CATEGORY_EXTERNALITY's identical treatment of
//     the sink-side `external-api`/`webhook`/`ai-*` categories.
//   - store-shaped categories (a file/object-storage read, a DB read, a
//     queue message) → `unknown`, matching CATEGORY_EXTERNALITY's identical
//     reasoning for `database`/`object-storage`/`cache`/`queue`: the entry
//     gives no way to tell whether the store is local or third-party
//     managed.
//   - `declared` (the unreached operator-declaration path, §6.5) →
//     `unknown`, matching the sink table's own choice for that category.
//
// Evidence-grade consequence (§7.5, carried over unchanged for the source
// side): the accompanying evidence grade for any of the above is at best
// `declared` — it comes from this table, not from executed code — never
// `code`. Real externality resolution is FR-202's job, landing in Milestone 2.
// ─────────────────────────────────────────────────────────────────────────

export const SOURCE_CATEGORY_EXTERNALITY = Object.freeze({
  'http-body': 'internal', 'http-query': 'internal', 'http-route': 'internal',
  'http-header': 'internal', 'http-cookie': 'internal', 'http-upload': 'internal',
  'graphql-argument': 'internal', 'grpc-field': 'internal',
  'cli-argument': 'internal', 'env-value': 'internal', 'user-input': 'internal',
  'queue-message': 'unknown', 'database-read': 'unknown', 'storage-read': 'unknown',
  'external-api-response': 'external', 'webhook-payload': 'external',
  'ai-model-output': 'external', 'ai-tool-result': 'external',
  'ai-retrieved-document': 'external', 'ai-memory': 'external',
  'declared': 'unknown',
});

/**
 * Reclassify a single `kind: 'source'` catalog entry (from CATALOG) into
 * DataFlowGraph v1's vocabulary. Total: every entry gets a decision, none
 * throws, none is silently dropped (§6, §9's D2 item). Node kind is always
 * `'source'` (§7.1). `coverageStatus` is never `'manual'` (§6.5) and never
 * the internal `'split'` marker (intercepted before it can escape).
 *
 * @param {object} entry a CATALOG entry with `kind === 'source'`
 * @returns {{kind: 'source', category: string|null, coverageStatus: string, externality: string, reason: string}}
 */
export function reclassifySource(entry) {
  if (entry.provenance) {
    const row = PROVENANCE_MAP[entry.provenance];
    if (!row) {
      return {
        kind: 'source', category: null, coverageStatus: 'unsupported',
        externality: 'unknown', reason: `unmapped provenance ${entry.provenance}`,
      };
    }
    if (entry.language === 'cpp' && CPP_DESCRIPTOR_GENERIC_PROVENANCE.has(entry.provenance)) {
      const category = row.category;
      return {
        kind: 'source', category, coverageStatus: 'partial',
        externality: SOURCE_CATEGORY_EXTERNALITY[category] ?? 'unknown',
        reason: CPP_DESCRIPTOR_GENERIC_WHY[entry.provenance],
      };
    }
    if (row.status === 'split') {
      const ref = AGENT_TOOL_REFINEMENT[entry.id];
      if (!ref) {
        return {
          kind: 'source', category: null, coverageStatus: 'unsupported',
          externality: 'unknown', reason: `unrefined ${entry.provenance} entry ${entry.id}`,
        };
      }
      return {
        kind: 'source', category: ref.category, coverageStatus: ref.status,
        externality: SOURCE_CATEGORY_EXTERNALITY[ref.category] ?? 'unknown',
        reason: ref.why,
      };
    }
    return {
      kind: 'source', category: row.category, coverageStatus: row.status,
      externality: SOURCE_CATEGORY_EXTERNALITY[row.category] ?? 'unknown',
      reason: row.why,
    };
  }
  const category = NO_PROVENANCE_OVERRIDES[entry.id];
  if (!category) {
    return {
      kind: 'source', category: null, coverageStatus: 'unsupported',
      externality: 'unknown', reason: `no provenance field and no override for ${entry.id}`,
    };
  }
  // No declared classification field: inferred from the entry's own
  // descriptive metadata. Plausible, reviewed, but not author-declared —
  // hence `candidate`, never `modeled`/`partial` (§6.3).
  return {
    kind: 'source', category, coverageStatus: 'candidate',
    externality: SOURCE_CATEGORY_EXTERNALITY[category] ?? 'unknown',
    reason: 'inferred from entry id/label/framework; catalog.js declares no provenance for this entry',
  };
}

// Re-exported for callers that want the raw source-entry slice without
// re-filtering CATALOG themselves (the completeness guards in this
// module's own test suite are the primary consumer).
export const SOURCE_ENTRIES = Object.freeze(CATALOG.filter((e) => e.kind === 'source'));
