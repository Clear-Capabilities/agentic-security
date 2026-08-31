//
// Sub-project D, increment D1 — PROOF OF CONCEPT for the catalog → schema
// reclassification mapping. Deliberately throwaway-named, mirroring every
// prior sub-project's own first-increment precedent (C1's
// engine-provenance-interprocedural-poc, C4's path-store-poc, C5's
// path-query-poc, C6's flow-grade-poc): the mapping tables and the
// coverage-status rule are prototyped HERE as local functions, and shipped
// source under src/ is unmodified by this increment. D2/D3 absorb what this
// file proves into src/lineage/source-registry.js / sink-registry.js and
// delete this file in the same commit, per DESIGN_REGISTRIES.md §9.
//
// Everything asserted here is derived from the LIVE catalogs at test time,
// never from a hardcoded snapshot of them — the whole point of this file is
// that it fails loudly when a catalog entry is added whose classification
// string nobody has mapped.
//

import test from 'node:test';
import assert from 'node:assert/strict';

import { CATALOG } from '../../src/dataflow/catalog.js';
import { EXPANDED_SANITIZERS } from '../../src/dataflow/catalog-expanded.js';
import { PRIVACY_SINK_CATALOG, PRIVACY_SINK_CATEGORIES } from '../../src/dataflow/privacy-catalog.js';
import {
  NODE_KINDS, SOURCE_CATEGORIES, SINK_CATEGORIES, TRANSFORM_KINDS,
  COVERAGE_STATUS_VALUES, EXTERNALITY_VALUES,
} from '../../src/lineage/schema.js';

// ───────────────────────────────────────────────────────────────────────────
// Ground truth, extracted programmatically (DESIGN_REGISTRIES.md §2)
// ───────────────────────────────────────────────────────────────────────────

const SOURCES = CATALOG.filter((e) => e.kind === 'source');
const SINKS = CATALOG.filter((e) => e.kind === 'sink');

/** Every distinct `provenance` string on a source entry that HAS one. */
const DISTINCT_PROVENANCE = new Set(SOURCES.filter((e) => e.provenance).map((e) => e.provenance));
/** Every source entry id that carries NO `provenance` field at all. */
const NO_PROVENANCE_IDS = new Set(SOURCES.filter((e) => !e.provenance).map((e) => e.id));
/** Every distinct `vuln.cwe` on a sink entry — the sink side's only classification signal. */
const DISTINCT_SINK_CWE = new Set(SINKS.map((e) => e.vuln?.cwe ?? '<<none>>'));
/** Every distinct `category` actually used by a privacy-catalog entry. */
const DISTINCT_PRIVACY_CATEGORY = new Set(PRIVACY_SINK_CATALOG.map((e) => e.category));

// ───────────────────────────────────────────────────────────────────────────
// The mapping tables (DESIGN_REGISTRIES.md §4, §5, §6)
// ───────────────────────────────────────────────────────────────────────────

// Tier 1: the source-side primary key is the DECLARED `provenance` field.
// `null` category means "no SOURCE_CATEGORIES value models this".
const PROVENANCE_MAP = {
  'http-body':    { category: 'http-body',             status: 'modeled', why: 'exact vocabulary match' },
  'url-param':    { category: 'http-query',            status: 'modeled', why: 'pure rename; the query string' },
  'path-param':   { category: 'http-route',            status: 'modeled', why: 'pure rename; a route/path segment' },
  'header':       { category: 'http-header',           status: 'modeled', why: 'pure rename' },
  'cookie':       { category: 'http-cookie',           status: 'modeled', why: 'pure rename' },
  'env':          { category: 'env-value',             status: 'modeled', why: 'pure rename' },
  'cli':          { category: 'cli-argument',          status: 'modeled', why: 'pure rename' },
  'network':      { category: 'external-api-response', status: 'modeled', why: 'all 8 entries read an outbound response body (fetch/axios/requests/urlopen/recv)' },
  'file-read':    { category: 'storage-read',          status: 'modeled', why: "FR-101 groups 'files and object storage reads'; storage-read is its only encoding" },
  'url-fragment': { category: 'http-query',            status: 'partial', why: 'LOSSY: a fragment is URL-borne but never transmitted to the server; SOURCE_CATEGORIES has no http-fragment value' },
  'stdin':        { category: 'user-input',            status: 'partial', why: 'LOSSY: broadens to the generic category; no stdin/console value exists' },
  // `agent-tool` is the one provenance value that does NOT resolve on the
  // provenance key alone — its 8 entries split directionally between
  // model-produced tool ARGUMENTS and tool RESULTS flowing back. Resolved
  // per-entry-id below; this row exists so the completeness test still sees
  // the key covered, and records WHY it needs refinement.
  'agent-tool':   { category: null, status: 'split', why: 'REFINED PER ENTRY: arguments (model-produced) vs results/resources (returned to the model) are different SOURCE_CATEGORIES' },
};

const AGENT_TOOL_REFINEMENT = {
  'py-mcp-tool':             { category: 'ai-model-output',       status: 'partial', why: 'the tool parameter is whatever the model chose to pass; ai-model-output normally denotes a completion, so this is an approximation' },
  'py-mcp-server-tool':      { category: 'ai-model-output',       status: 'partial', why: 'as py-mcp-tool' },
  'js-mcp-call-args':        { category: 'ai-model-output',       status: 'partial', why: 'as py-mcp-tool' },
  'js-mcp-request-params':   { category: 'ai-model-output',       status: 'partial', why: 'as py-mcp-tool' },
  'js-mcp-extra-args':       { category: 'ai-model-output',       status: 'partial', why: 'as py-mcp-tool' },
  'js-mcp-tool-result':      { category: 'ai-tool-result',        status: 'modeled', why: 'literally a tool result' },
  'py-mcp-tool-result':      { category: 'ai-tool-result',        status: 'modeled', why: 'literally a tool result' },
  'js-mcp-resource-contents':{ category: 'ai-retrieved-document', status: 'modeled', why: 'an MCP resource IS a retrieved document' },
};

// Tier 2: the 82 source entries carrying NO `provenance`. The category comes
// from the entry's own descriptive metadata (id/label/framework), not from a
// field its author set for classification — hence `candidate` for every row,
// per §6's decision procedure. Keys are asserted to equal NO_PROVENANCE_IDS
// EXACTLY, so a newly-added unprovenanced source entry fails this file.
const NO_PROVENANCE_OVERRIDES = {
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
};

// The sink-side primary key is `vuln.cwe`. A `null` category is NOT a dropped
// entry — see §6: it is retained with a node kind and a stated reason, which
// is what AC-11 / FR-201 require.
const CWE_MAP = {
  'CWE-89':   { category: 'database',      status: 'modeled',     why: 'a SQL query call is unambiguously a database destination' },
  'CWE-943':  { category: 'database',      status: 'modeled',     why: 'NoSQL $where — still a database destination' },
  'CWE-22':   { category: 'file',          status: 'modeled',     why: 'path traversal sinks are filesystem reads/writes' },
  'CWE-73':   { category: 'file',          status: 'modeled',     why: 'arbitrary file write' },
  'CWE-918':  { category: 'external-api',  status: 'modeled',     why: 'SSRF sinks are outbound HTTP client calls' },
  'CWE-601':  { category: 'http-response', status: 'modeled',     why: 'a redirect is written as a response header' },
  'CWE-113':  { category: 'http-response', status: 'modeled',     why: 'response splitting — the sink IS the response header writer' },
  'CWE-79':   { category: null,            status: 'split',       why: 'REFINED ON `framework`: browser-DOM sinks and server-side response writers are different destinations' },
  'CWE-90':   { category: 'database',      status: 'candidate',   why: 'an LDAP directory is a queryable store, structurally like a DB, but FR-201 never names directory services' },
  // Everything below: the data\'s destination is IN-PROCESS COMPUTATION (an
  // interpreter, parser, template engine, regex engine, loader, or raw
  // memory). FR-201\'s category list is an EGRESS taxonomy and models none of
  // them. This is the single largest structural finding of D1 (§7.1).
  'CWE-78':   { category: null, status: 'unsupported', why: 'shell/process execution — no FR-201 category models process execution' },
  'CWE-95':   { category: null, status: 'unsupported', why: 'code evaluation (eval/Function/exec/compile) — destination is an interpreter' },
  'CWE-94':   { category: null, status: 'unsupported', why: 'code injection / template compilation — destination is an interpreter or template engine' },
  'CWE-1336': { category: null, status: 'unsupported', why: 'SSTI — destination is a template engine, not a data destination' },
  'CWE-502':  { category: null, status: 'unsupported', why: 'deserialization — destination is a deserializer' },
  'CWE-611':  { category: null, status: 'unsupported', why: 'XXE — destination is an XML parser' },
  'CWE-643':  { category: null, status: 'unsupported', why: 'XPath injection — destination is a query engine over an in-memory document' },
  'CWE-120':  { category: null, status: 'unsupported', why: 'buffer overflow — destination is raw memory' },
  'CWE-787':  { category: null, status: 'unsupported', why: 'out-of-bounds write — destination is raw memory' },
  'CWE-1333': { category: null, status: 'unsupported', why: 'ReDoS — destination is the regex engine' },
  'CWE-114':  { category: null, status: 'unsupported', why: 'untrusted library load — destination is the dynamic loader' },
};

/** CWE-79's refinement key. FR-201 lumps "browser DOM or client storage". */
const DOM_FRAMEWORKS = new Set(['dom', 'react']);

const PRIVACY_CATEGORY_MAP = {
  'log':           { category: 'log',            status: 'modeled', why: 'console/logger calls' },
  'response':      { category: 'http-response',  status: 'modeled', why: 'res.send / res.json' },
  'outboundHttp':  { category: 'external-api',   status: 'modeled', why: 'fetch / axios.post' },
  'fileWrite':     { category: 'file',           status: 'modeled', why: 'fs.writeFile / writeFileSync' },
  's3Upload':      { category: 'object-storage', status: 'modeled', why: 's3.putObject' },
  'emailSend':     { category: 'email',          status: 'modeled', why: 'nodemailer sendMail' },
  'storage':       { category: 'database',       status: 'modeled', why: 'both current entries are mongodb insertOne/insertMany with a collection|db|mongo receiver — the name is broader than its entries, but nothing splits TODAY' },
  'queues':        { category: 'queue',          status: 'modeled', why: "sqs sendMessage / sns|kafka publish; FR-201's `queue` covers 'queues, topics, streams, and event buses'" },
  'thirdPartySdk': { category: 'analytics',      status: 'partial', why: "LOSSY: the single receiverTypeIn alternation also matches sentry|datadog (monitoring), stripe (external-api) and intercom|braze (collaboration) — the true category is only decidable at MATCH time from the matched receiver, which a registry reclassifying ENTRIES never sees" },
};

// Category → node kind (§5). Every sink category that any catalog can
// currently produce, plus the in-process fallback for a null category.
const CATEGORY_NODE_KIND = {
  'log': 'log', 'stdout': 'log',
  'http-response': 'sink',
  'database': 'store', 'file': 'store', 'object-storage': 'store',
  'cache': 'store', 'client-storage': 'store', 'backup': 'store', 'export': 'store',
  'queue': 'queue',
  'external-api': 'external', 'webhook': 'external', 'email': 'external',
  'sms': 'external', 'push-notification': 'external', 'collaboration': 'external',
  'analytics': 'external', 'monitoring': 'external',
  'ai-model-provider': 'external', 'ai-agent': 'external', 'ai-tool': 'external',
  'ai-vector-store': 'external', 'ai-memory': 'external', 'ai-training': 'external',
  'ai-evaluation': 'external', 'ai-telemetry': 'external',
  'ai-local-model': 'process',
  'declared': 'sink',
};

// Category → externality (§8). A catalog entry carries NO host/provider/URL
// information at all, so externality is CATEGORY-derived, never entry-derived.
const CATEGORY_EXTERNALITY = {
  'log': 'internal', 'stdout': 'internal', 'http-response': 'internal',
  'file': 'internal', 'client-storage': 'internal',
  'database': 'unknown', 'object-storage': 'unknown', 'cache': 'unknown',
  'queue': 'unknown', 'backup': 'unknown', 'export': 'unknown',
  'external-api': 'external', 'webhook': 'external', 'email': 'external',
  'sms': 'external', 'push-notification': 'external', 'collaboration': 'external',
  'analytics': 'external', 'monitoring': 'external',
  'ai-model-provider': 'external', 'ai-agent': 'external', 'ai-tool': 'external',
  'ai-vector-store': 'external', 'ai-memory': 'external', 'ai-training': 'external',
  'ai-evaluation': 'external', 'ai-telemetry': 'external', 'ai-local-model': 'internal',
  'declared': 'unknown',
};

// ───────────────────────────────────────────────────────────────────────────
// The reclassification functions (D2/D3 implement exactly these)
// ───────────────────────────────────────────────────────────────────────────

function reclassifySource(entry) {
  if (entry.provenance) {
    const row = PROVENANCE_MAP[entry.provenance];
    if (!row) return { kind: 'source', category: null, coverageStatus: 'unsupported', reason: `unmapped provenance ${entry.provenance}` };
    if (row.status === 'split') {
      const ref = AGENT_TOOL_REFINEMENT[entry.id];
      if (!ref) return { kind: 'source', category: null, coverageStatus: 'unsupported', reason: `unrefined ${entry.provenance} entry ${entry.id}` };
      return { kind: 'source', category: ref.category, coverageStatus: ref.status, reason: ref.why };
    }
    return { kind: 'source', category: row.category, coverageStatus: row.status, reason: row.why };
  }
  const cat = NO_PROVENANCE_OVERRIDES[entry.id];
  if (!cat) {
    return { kind: 'source', category: null, coverageStatus: 'unsupported', reason: `no provenance field and no override for ${entry.id}` };
  }
  // No declared classification field: inferred from the entry's own
  // descriptive metadata. Plausible, reviewed, but not author-declared.
  return { kind: 'source', category: cat, coverageStatus: 'candidate', reason: 'inferred from entry id/label/framework; catalog.js declares no provenance for this entry' };
}

function reclassifySink(entry) {
  const cwe = entry.vuln?.cwe ?? '<<none>>';
  let row = CWE_MAP[cwe];
  if (!row) {
    return { kind: 'sink', category: null, coverageStatus: 'unsupported', reason: `unmapped CWE ${cwe}` };
  }
  if (row.status === 'split') {
    // The single documented refinement on the sink side.
    row = DOM_FRAMEWORKS.has(entry.framework)
      ? { category: 'client-storage', status: 'partial', why: "LOSSY: the destination is the rendered browser DOM; schema.js's `client-storage` is its encoding of FR-201's 'browser DOM or client storage' bullet, and under-names the DOM half" }
      : { category: 'http-response', status: 'modeled', why: 'a server-side response writer (res.send / PrintWriter / echo / Fprintf)' };
  }
  const category = row.category;
  const kind = category === null ? 'process' : (CATEGORY_NODE_KIND[category] ?? 'sink');
  const externality = category === null ? 'internal' : (CATEGORY_EXTERNALITY[category] ?? 'unknown');
  return { kind, category, coverageStatus: row.status, externality, reason: row.why };
}

function reclassifyPrivacySink(entry) {
  const row = PRIVACY_CATEGORY_MAP[entry.category];
  if (!row) return { kind: 'sink', category: null, coverageStatus: 'unsupported', reason: `unmapped privacy category ${entry.category}` };
  return {
    kind: CATEGORY_NODE_KIND[row.category] ?? 'sink',
    category: row.category,
    coverageStatus: row.status,
    externality: CATEGORY_EXTERNALITY[row.category] ?? 'unknown',
    reason: row.why,
  };
}

// ───────────────────────────────────────────────────────────────────────────
// D1/1 — COMPLETENESS. The drift guards.
// ───────────────────────────────────────────────────────────────────────────

test('D1/1a: every distinct source `provenance` string in CATALOG has a mapping row', () => {
  const unmapped = [...DISTINCT_PROVENANCE].filter((p) => !(p in PROVENANCE_MAP)).sort();
  assert.deepEqual(unmapped, [], `catalog.js gained provenance value(s) with no mapping: ${unmapped.join(', ')}`);
  // and no stale rows
  const stale = Object.keys(PROVENANCE_MAP).filter((p) => !DISTINCT_PROVENANCE.has(p)).sort();
  assert.deepEqual(stale, [], `PROVENANCE_MAP has rows for provenance values no entry carries: ${stale.join(', ')}`);
});

test('D1/1b: the no-provenance override table covers EXACTLY the unprovenanced source entries', () => {
  const overrideIds = new Set(Object.keys(NO_PROVENANCE_OVERRIDES));
  const missing = [...NO_PROVENANCE_IDS].filter((id) => !overrideIds.has(id)).sort();
  const stale = [...overrideIds].filter((id) => !NO_PROVENANCE_IDS.has(id)).sort();
  assert.deepEqual(missing, [], `source entries with no provenance and no override: ${missing.join(', ')}`);
  assert.deepEqual(stale, [], `override rows for entries that no longer need one: ${stale.join(', ')}`);
});

test('D1/1c: every distinct sink `vuln.cwe` in CATALOG has a mapping row', () => {
  const unmapped = [...DISTINCT_SINK_CWE].filter((c) => !(c in CWE_MAP)).sort();
  assert.deepEqual(unmapped, [], `catalog.js gained sink CWE(s) with no mapping: ${unmapped.join(', ')}`);
  const stale = Object.keys(CWE_MAP).filter((c) => !DISTINCT_SINK_CWE.has(c)).sort();
  assert.deepEqual(stale, [], `CWE_MAP has rows for CWEs no sink entry carries: ${stale.join(', ')}`);
});

test('D1/1d: every distinct privacy-catalog `category` has a mapping row', () => {
  const unmapped = [...DISTINCT_PRIVACY_CATEGORY].filter((c) => !(c in PRIVACY_CATEGORY_MAP)).sort();
  assert.deepEqual(unmapped, [], `privacy-catalog.js gained category(ies) with no mapping: ${unmapped.join(', ')}`);
  // PRIVACY_SINK_CATEGORIES is the DECLARED vocabulary; assert the mapping
  // covers the declared list too, not just the values entries happen to use.
  const undeclared = PRIVACY_SINK_CATEGORIES.filter((c) => !(c in PRIVACY_CATEGORY_MAP)).sort();
  assert.deepEqual(undeclared, [], `declared privacy categories with no mapping: ${undeclared.join(', ')}`);
});

test('D1/1e: the rule is TOTAL — every source and sink entry gets a decision, none throws, none is silently dropped', () => {
  for (const e of SOURCES) {
    const r = reclassifySource(e);
    assert.ok(NODE_KINDS.includes(r.kind), `${e.id}: bad node kind ${r.kind}`);
    assert.ok(COVERAGE_STATUS_VALUES.includes(r.coverageStatus), `${e.id}: bad coverageStatus ${r.coverageStatus}`);
    if (r.category !== null) assert.ok(SOURCE_CATEGORIES.includes(r.category), `${e.id}: ${r.category} not in SOURCE_CATEGORIES`);
    assert.ok(r.reason && r.reason.length > 0, `${e.id}: every decision must carry a reason (AC-11)`);
  }
  for (const e of SINKS) {
    const r = reclassifySink(e);
    assert.ok(NODE_KINDS.includes(r.kind), `${e.id}: bad node kind ${r.kind}`);
    assert.ok(COVERAGE_STATUS_VALUES.includes(r.coverageStatus), `${e.id}: bad coverageStatus ${r.coverageStatus}`);
    assert.ok(EXTERNALITY_VALUES.includes(r.externality), `${e.id}: bad externality ${r.externality}`);
    if (r.category !== null) assert.ok(SINK_CATEGORIES.includes(r.category), `${e.id}: ${r.category} not in SINK_CATEGORIES`);
    assert.ok(r.reason && r.reason.length > 0, `${e.id}: every decision must carry a reason (AC-11)`);
  }
  for (const e of PRIVACY_SINK_CATALOG) {
    const r = reclassifyPrivacySink(e);
    assert.ok(SINK_CATEGORIES.includes(r.category), `${e.id}: ${r.category} not in SINK_CATEGORIES`);
    assert.ok(COVERAGE_STATUS_VALUES.includes(r.coverageStatus));
  }
});

test('D1/1f: `split` is an INTERNAL table marker and never escapes as a coverageStatus', () => {
  assert.ok(!COVERAGE_STATUS_VALUES.includes('split'));
  const all = [...SOURCES.map(reclassifySource), ...SINKS.map(reclassifySink)];
  assert.equal(all.filter((r) => r.coverageStatus === 'split').length, 0);
});

// ───────────────────────────────────────────────────────────────────────────
// D1/2 — the `manual` resolution (the open question this increment closes)
// ───────────────────────────────────────────────────────────────────────────

test('D1/2a: NO catalog entry, in any of the three catalogs, ever yields coverageStatus `manual`', () => {
  const all = [
    ...SOURCES.map(reclassifySource),
    ...SINKS.map(reclassifySink),
    ...PRIVACY_SINK_CATALOG.map(reclassifyPrivacySink),
  ];
  const manual = all.filter((r) => r.coverageStatus === 'manual');
  assert.equal(manual.length, 0,
    '`manual` means "a human asserted this", per this codebase\'s own consistent precedent ' +
    '(posture/privacy-framework.js\'s BUCKETS, posture/auditor-walkthrough.js\'s "requires manual ' +
    'attestation", lineage/protection.js\'s EVIDENCE_GRADES, schema.js\'s EVIDENCE_TYPES). A catalog ' +
    'entry is analyzer-derived BY CONSTRUCTION, so a registry can never produce it.');
});

test('D1/2b: FR-101\'s own acceptance clause names exactly the four statuses a registry can emit', () => {
  // PRD FR-101: "shows both connected and disconnected sources, with
  // `modeled`, `partial`, `candidate`, or `unsupported` status." `manual` is
  // deliberately absent there but present in the node contract (10.3) —
  // corroborating D1/2a from the PRD side, not just from code precedent.
  const registryEmittable = ['modeled', 'partial', 'candidate', 'unsupported'];
  for (const s of registryEmittable) assert.ok(COVERAGE_STATUS_VALUES.includes(s));
  assert.deepEqual(
    COVERAGE_STATUS_VALUES.filter((s) => !registryEmittable.includes(s)),
    ['manual'],
    'the one status in the schema that no registry emits must be exactly `manual`',
  );
});

// ───────────────────────────────────────────────────────────────────────────
// D1/3 — representative real reclassifications, end to end
// ───────────────────────────────────────────────────────────────────────────

const byId = new Map(CATALOG.map((e) => [e.id, e]));

test('D1/3a: ten real entries, mixed kind / language / framework, produce the stated triples', () => {
  const expected = [
    // id                        kind       category                 coverageStatus
    ['js-req-body',              'source',  'http-body',             'modeled'],
    ['js-loc-hash',              'source',  'http-query',            'partial'],
    ['cpp-gets',                 'source',  'user-input',            'partial'],
    ['go-chi-urlparam',          'source',  'http-route',            'candidate'],
    ['php-symfony-files',        'source',  'http-upload',           'candidate'],
    ['js-mcp-resource-contents', 'source',  'ai-retrieved-document', 'modeled'],
    ['js-sql-query',             'store',   'database',              'modeled'],
    ['js-fetch',                 'external','external-api',          'modeled'],
    ['js-innerHTML-assign',      'store',   'client-storage',        'partial'],
    ['java-writer-write',        'sink',    'http-response',         'modeled'],
  ];
  for (const [id, kind, category, status] of expected) {
    const e = byId.get(id);
    assert.ok(e, `catalog entry ${id} no longer exists — the sample needs updating`);
    const r = e.kind === 'source' ? reclassifySource(e) : reclassifySink(e);
    assert.equal(r.kind, kind, `${id}: node kind`);
    assert.equal(r.category, category, `${id}: category`);
    assert.equal(r.coverageStatus, status, `${id}: coverageStatus`);
  }
});

test('D1/3b: every source entry maps to node kind `source` — no catalog source is a `boundary`', () => {
  // Checked, not assumed: a catalog source entry names a PROGRAM POINT where
  // external data enters. `boundary` in NODE_KINDS models a trust-zone
  // crossing, which is a property of an EDGE between two systems, and no
  // catalog entry carries system/zone information at all.
  const kinds = new Set(SOURCES.map((e) => reclassifySource(e).kind));
  assert.deepEqual([...kinds], ['source']);
});

test('D1/3c: sink node kinds are category-derived, and the in-process fallback is `process`', () => {
  const kinds = new Set(SINKS.map((e) => reclassifySink(e).kind));
  assert.deepEqual([...kinds].sort(), ['external', 'process', 'sink', 'store']);
  // Every unsupported sink is `process` — that is precisely WHY it is
  // unsupported: FR-201's list is an egress taxonomy and these are in-process
  // computation destinations.
  for (const e of SINKS) {
    const r = reclassifySink(e);
    if (r.coverageStatus === 'unsupported') assert.equal(r.kind, 'process', `${e.id}`);
    if (r.kind === 'process') assert.equal(r.coverageStatus, 'unsupported', `${e.id}`);
  }
});

// ───────────────────────────────────────────────────────────────────────────
// D1/4 — the privacy-catalog reconciliation, on real entries
// ───────────────────────────────────────────────────────────────────────────

test('D1/4a: at least one real entry from EVERY privacy category resolves to a SINK_CATEGORIES value', () => {
  const expected = {
    'log': 'log',
    'response': 'http-response',
    'outboundHttp': 'external-api',
    'thirdPartySdk': 'analytics',
    'fileWrite': 'file',
    's3Upload': 'object-storage',
    'emailSend': 'email',
    'storage': 'database',
    'queues': 'queue',
  };
  // covers all 9 — asserted against the DECLARED vocabulary, so a 10th
  // category added to PRIVACY_SINK_CATEGORIES fails here too.
  assert.deepEqual(Object.keys(expected).sort(), [...PRIVACY_SINK_CATEGORIES].sort());
  for (const [cat, want] of Object.entries(expected)) {
    const entry = PRIVACY_SINK_CATALOG.find((e) => e.category === cat);
    assert.ok(entry, `no privacy entry uses category ${cat}`);
    assert.equal(reclassifyPrivacySink(entry).category, want, `privacy ${cat}`);
  }
});

test('D1/4b: `storage` does NOT split today — proven from the real entries, not assumed', () => {
  // The scoping doc anticipated `storage` splitting across
  // database/object-storage/cache. Both entries that actually carry it are
  // mongodb inserts, so it resolves 1:1 to `database`. Recorded as a test so
  // a future redis/S3 entry under `storage` fails loudly instead of being
  // silently mis-mapped to `database`.
  const entries = PRIVACY_SINK_CATALOG.filter((e) => e.category === 'storage');
  assert.equal(entries.length, 2);
  for (const e of entries) {
    assert.match(e.framework, /^mongodb$/);
    assert.equal(reclassifyPrivacySink(e).category, 'database');
  }
});

test('D1/4c: `thirdPartySdk` is `partial` because ONE entry\'s receiver alternation spans four categories', () => {
  const e = PRIVACY_SINK_CATALOG.find((x) => x.category === 'thirdPartySdk');
  const recv = e.match.receiverTypeIn[0];
  // Real evidence for the `partial`: monitoring, payment and collaboration
  // providers sit in the same alternation as the analytics ones.
  for (const provider of ['sentry', 'datadog', 'stripe', 'intercom', 'segment']) {
    assert.ok(recv.includes(provider), `expected ${provider} in the receiver alternation`);
  }
  assert.equal(reclassifyPrivacySink(e).coverageStatus, 'partial');
});

test('D1/4d: the privacy vocabulary is NINE values, and is NOT the eight-value list the scoping doc named', () => {
  assert.equal(PRIVACY_SINK_CATEGORIES.length, 9);
  const scopingDocClaim = ['log', 'response', 'storage', 'queues', 'email', 'file', 'outbound', 'third-party'];
  assert.notDeepEqual([...PRIVACY_SINK_CATEGORIES].sort(), [...scopingDocClaim].sort());
  // four of the eight were paraphrases, not the real identifiers
  for (const invented of ['email', 'file', 'outbound', 'third-party']) {
    assert.ok(!PRIVACY_SINK_CATEGORIES.includes(invented), `${invented} is not a real privacy category`);
  }
});

// ───────────────────────────────────────────────────────────────────────────
// D1/5 — the honest `unsupported` case
// ───────────────────────────────────────────────────────────────────────────

test('D1/5a: a real entry with no confident mapping is marked `unsupported` and RETAINED, never dropped', () => {
  const e = byId.get('js-exec'); // child_process.exec, CWE-78
  assert.ok(e);
  const r = reclassifySink(e);
  assert.equal(r.category, null);
  assert.equal(r.coverageStatus, 'unsupported');
  assert.equal(r.kind, 'process');            // still a graph node — AC-11
  assert.match(r.reason, /process execution/); // with a coverage reason — AC-11
});

test('D1/5b: `unsupported` is a large, MEASURED share of the sink catalog, not a hypothetical', () => {
  const results = SINKS.map(reclassifySink);
  const unsupported = results.filter((r) => r.coverageStatus === 'unsupported').length;
  // Pinned so the number in DESIGN_REGISTRIES.md §7.1 can never go stale
  // silently — a drop here means new sink coverage landed and the design doc
  // needs re-reading, exactly the failure mode bench/layer-recall's
  // floor-not-equality gate suffered.
  assert.equal(SINKS.length, 194);
  assert.equal(unsupported, 82);                                                              // 42% of the sink catalog
  assert.equal(results.filter((r) => r.coverageStatus === 'modeled').length, 97);
  assert.equal(results.filter((r) => r.coverageStatus === 'partial').length, 6);              // the 6 DOM/React CWE-79 entries
  assert.equal(results.filter((r) => r.coverageStatus === 'candidate').length, 9);            // the 9 CWE-90 LDAP entries
  assert.equal(97 + 6 + 9 + 82, SINKS.length);
});

test('D1/5c: source-side coverage counts are pinned too', () => {
  const results = SOURCES.map(reclassifySource);
  assert.equal(SOURCES.length, 180);
  assert.equal(results.filter((r) => r.coverageStatus === 'modeled').length, 89);
  assert.equal(results.filter((r) => r.coverageStatus === 'partial').length, 9);     // 2 url-fragment + 2 stdin + 5 MCP argument entries
  assert.equal(results.filter((r) => r.coverageStatus === 'candidate').length, 82);  // every entry with no declared provenance
  assert.equal(results.filter((r) => r.coverageStatus === 'unsupported').length, 0); // the source side has NO unsupported entries
  assert.equal(89 + 9 + 82, SOURCES.length);
});

// ───────────────────────────────────────────────────────────────────────────
// D1/6 — unreachable schema categories (the disclosable gaps)
// ───────────────────────────────────────────────────────────────────────────

function reachableSourceCategories() {
  return new Set(SOURCES.map((e) => reclassifySource(e).category).filter(Boolean));
}
function reachableSinkCategories() {
  return new Set([
    ...SINKS.map((e) => reclassifySink(e).category),
    ...PRIVACY_SINK_CATALOG.map((e) => reclassifyPrivacySink(e).category),
  ].filter(Boolean));
}

test('D1/5d: privacy-catalog coverage counts are pinned too', () => {
  const results = PRIVACY_SINK_CATALOG.map(reclassifyPrivacySink);
  assert.equal(PRIVACY_SINK_CATALOG.length, 18);
  assert.equal(results.filter((r) => r.coverageStatus === 'modeled').length, 16);
  assert.equal(results.filter((r) => r.coverageStatus === 'partial').length, 2);  // both thirdPartySdk entries
  assert.equal(results.filter((r) => r.coverageStatus === 'candidate').length, 0);
  assert.equal(results.filter((r) => r.coverageStatus === 'unsupported').length, 0);
});

test('D1/6a: the SOURCE_CATEGORIES values no catalog entry can produce today', () => {
  const reachable = reachableSourceCategories();
  const unreachable = SOURCE_CATEGORIES.filter((c) => !reachable.has(c)).sort();
  assert.deepEqual(unreachable, [
    'ai-memory', 'database-read', 'declared', 'graphql-argument',
    'grpc-field', 'queue-message', 'webhook-payload',
  ], 'source-side coverage gap changed — re-read DESIGN_REGISTRIES.md §7.2');
  assert.equal(reachable.size, 14);
});

test('D1/6b: the SINK_CATEGORIES values no catalog entry can produce today — including EVERY ai-* sink', () => {
  const reachable = reachableSinkCategories();
  const unreachable = SINK_CATEGORIES.filter((c) => !reachable.has(c)).sort();
  assert.deepEqual(unreachable, [
    'ai-agent', 'ai-evaluation', 'ai-local-model', 'ai-memory',
    'ai-model-provider', 'ai-telemetry', 'ai-tool', 'ai-training',
    'ai-vector-store', 'backup', 'cache', 'collaboration', 'declared',
    'export', 'monitoring', 'push-notification', 'sms', 'stdout', 'webhook',
  ], 'sink-side coverage gap changed — re-read DESIGN_REGISTRIES.md §7.2');
  assert.equal(reachable.size, 10);
  // The headline: FR-205 (AI destinations) has ZERO sink-catalog coverage.
  const aiSinks = SINK_CATEGORIES.filter((c) => c.startsWith('ai-'));
  assert.equal(aiSinks.length, 9);
  for (const c of aiSinks) assert.ok(!reachable.has(c), `${c} unexpectedly reachable`);
  // ...while the SOURCE side does have AI coverage, via the MCP entries.
  const reachableSrc = reachableSourceCategories();
  assert.ok(SOURCE_CATEGORIES.filter((c) => c.startsWith('ai-')).some((c) => reachableSrc.has(c)));
});

// ───────────────────────────────────────────────────────────────────────────
// D1/7 — TRANSFORM_KINDS confirmation for D4
// ───────────────────────────────────────────────────────────────────────────

test('D1/7a: TRANSFORM_KINDS matches PRD 10.6 exactly, in order', () => {
  // PRD 10.6: "kind: mask, redact, tokenize, hash, encrypt, decrypt, encode,
  // decode, aggregate, truncate, normalize, custom, or unknown"
  assert.deepEqual([...TRANSFORM_KINDS], [
    'mask', 'redact', 'tokenize', 'hash', 'encrypt', 'decrypt', 'encode',
    'decode', 'aggregate', 'truncate', 'normalize', 'custom', 'unknown',
  ]);
  assert.equal(TRANSFORM_KINDS.length, 13);
  // PRD 10.6: "Masking, hashing, tokenization, and encryption must never be
  // treated as synonyms" — four distinct values, no aliasing.
  for (const k of ['mask', 'hash', 'tokenize', 'encrypt']) assert.ok(TRANSFORM_KINDS.includes(k));
  assert.equal(new Set(TRANSFORM_KINDS).size, TRANSFORM_KINDS.length);
});

test('D1/7b: D4 has a real, non-empty starting corpus — but it is NOT in CATALOG', () => {
  // The 382 CATALOG sanitizers + 324 EXPANDED_SANITIZERS are the general
  // engine's threat-class sanitizers (`effect`/`appliesTo`), NOT
  // TRANSFORM_KINDS-shaped privacy transforms. privacy-catalog.js's own
  // PRIVACY_TRANSFORM_CALLEES set is the one genuinely transform-shaped list,
  // and it is PRIVATE (unexported) — reachable only through the
  // isPrivacyTransformCallee predicate. D4 must resolve that access problem;
  // D1 only records it.
  assert.equal(CATALOG.filter((e) => e.kind === 'sanitizer').length, 382);
  assert.equal(EXPANDED_SANITIZERS.length, 324);
  assert.ok(EXPANDED_SANITIZERS.every((e) => e.kind === 'sanitizer'),
    'catalog-expanded.js is sanitizer-only — it contributes NO source or sink entries');
});

// ───────────────────────────────────────────────────────────────────────────
// D1/8 — catalog shape facts D2/D3 depend on (and that are currently
// mis-stated in dataflow/CLAUDE.md)
// ───────────────────────────────────────────────────────────────────────────

test('D1/8a: catalog sizes, re-derived — dataflow/CLAUDE.md\'s "655 (149/124/382)" is stale', () => {
  assert.equal(CATALOG.length, 756);
  assert.equal(SOURCES.length, 180);
  assert.equal(SINKS.length, 194);
  assert.equal(CATALOG.filter((e) => e.kind === 'sanitizer').length, 382);
});

test('D1/8b: sink entries carry NO `category` field — `vuln.cwe` is the only classification signal', () => {
  assert.equal(SINKS.filter((e) => e.category).length, 0);
  assert.equal(SINKS.filter((e) => e.vuln?.cwe).length, SINKS.length);
});

test('D1/8c: 82 of 180 source entries declare no `provenance` at all — whole languages are affected', () => {
  assert.equal(NO_PROVENANCE_IDS.size, 82);
  const byLang = {};
  for (const e of SOURCES) {
    byLang[e.language] ??= { with: 0, without: 0 };
    byLang[e.language][e.provenance ? 'with' : 'without'] += 1;
  }
  // go / java / rb / php declare provenance on ZERO of their source entries.
  for (const lang of ['go', 'java', 'rb', 'php']) {
    assert.equal(byLang[lang].with, 0, `${lang} unexpectedly gained a provenance-carrying source entry`);
    assert.ok(byLang[lang].without > 0);
  }
});

test('D1/8d: no catalog entry carries destination/host information — externality must be category-derived', () => {
  const destinationish = ['host', 'url', 'provider', 'destination', 'externality', 'system'];
  for (const e of CATALOG) {
    for (const f of destinationish) {
      assert.ok(!(f in e), `catalog entry ${e.id} unexpectedly carries a ${f} field`);
    }
  }
});
