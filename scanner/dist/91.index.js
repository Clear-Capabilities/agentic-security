export const id = 91;
export const ids = [91,218,752];
export const modules = {

/***/ 9091:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {


// EXPORTS
__webpack_require__.d(__webpack_exports__, {
  runStdio: () => (/* binding */ runStdio)
});

// EXTERNAL MODULE: external "node:fs"
var external_node_fs_ = __webpack_require__(3024);
// EXTERNAL MODULE: external "node:crypto"
var external_node_crypto_ = __webpack_require__(7598);
// EXTERNAL MODULE: external "node:path"
var external_node_path_ = __webpack_require__(6760);
// EXTERNAL MODULE: external "node:url"
var external_node_url_ = __webpack_require__(3136);
// EXTERNAL MODULE: external "node:fs/promises"
var promises_ = __webpack_require__(1455);
// EXTERNAL MODULE: ./src/posture/fix-history.js
var fix_history = __webpack_require__(4407);
// EXTERNAL MODULE: ./src/fix/apply-fix-service.js
var apply_fix_service = __webpack_require__(7730);
// EXTERNAL MODULE: ./src/posture/material-change.js
var material_change = __webpack_require__(4629);
// EXTERNAL MODULE: ./src/fix/approver-registry.js
var approver_registry = __webpack_require__(437);
;// CONCATENATED MODULE: ./src/posture/deterministic-fix.js
// Deterministic fix synthesis (#1) — for the narrow set of vulnerability classes
// where a context-INDEPENDENT literal swap is a safe, correct fix, produce a
// full-file replacement from the current file content. No LLM, no guessing, no
// per-finding bloat in last-scan.json (the patch is materialized on demand by
// synthesize_fix from the live file, not stored on every finding).
//
// Safety: every patch this produces is still gated by verify_fix before apply_fix
// writes it (original finding gone + no new ≥medium + lint clean). So a swap that
// a rule mis-attributed simply fails verification instead of landing a bad edit —
// this module widens the deterministic-fix surface without weakening the gate.
//
// Returns { patch: { [relFile]: newContent }, ruleId } or null when no
// deterministic fix applies to the finding.

const JS_EXT = /\.(?:js|jsx|ts|tsx|mjs|cjs)$/i;
const PY_EXT = /\.py$/i;

// Each rule gates on the finding's cwe/family, then rewrites the whole-file
// content. transform() returns the new content, or null when nothing changed
// (e.g. the vulnerable token isn't literally present — then we don't claim a fix).
const RULES = [
  {
    id: 'weak-hash-sha256',
    // md5 / sha1 → sha256. Every occurrence in the file is a weak hash, so
    // swapping them all is safe; the verifier confirms the weak-hash finding is
    // gone and nothing worse appeared.
    applies: (f) => /CWE-(?:327|328|916)/.test(f.cwe || '') || /weak.?hash/i.test(f.family || ''),
    transform: (content, file) => {
      let out = content;
      if (JS_EXT.test(file)) {
        out = out.replace(/(\bcreateHash\s*\(\s*['"`])(?:md5|sha1)(['"`])/gi, '$1sha256$2');
      } else if (PY_EXT.test(file)) {
        out = out.replace(/\bhashlib\.(?:md5|sha1)\s*\(/g, 'hashlib.sha256(');
      }
      return out !== content ? out : null;
    },
  },
  {
    id: 'tls-verify-on',
    // Disabled TLS verification → enabled. rejectUnauthorized:false → true (JS),
    // verify=False → verify=True (Python requests).
    applies: (f) => /CWE-295/.test(f.cwe || '') || /tls.?no.?verify|cert.?(?:none|verify)/i.test(f.family || ''),
    transform: (content, file) => {
      let out = content;
      if (JS_EXT.test(file)) {
        out = out.replace(/(\brejectUnauthorized\s*:\s*)false\b/g, '$1true');
      } else if (PY_EXT.test(file)) {
        out = out.replace(/(\bverify\s*=\s*)False\b/g, '$1True');
      }
      return out !== content ? out : null;
    },
  },
];

function synthesizeDeterministicPatch(finding, fileContent) {
  if (!finding || typeof fileContent !== 'string' || !finding.file) return null;
  for (const rule of RULES) {
    try {
      if (!rule.applies(finding)) continue;
      const next = rule.transform(fileContent, finding.file);
      if (next && next !== fileContent) return { patch: { [finding.file]: next }, ruleId: rule.id };
    } catch { /* a single rule failing must never break synthesis */ }
  }
  return null;
}

// EXTERNAL MODULE: ./src/posture/integrity.js
var integrity = __webpack_require__(1130);
// EXTERNAL MODULE: ./src/posture/state-dir.js
var state_dir = __webpack_require__(1174);
// EXTERNAL MODULE: ./src/posture/cache-economics.js
var cache_economics = __webpack_require__(8752);
// EXTERNAL MODULE: ./src/mcp/redact.js
var redact = __webpack_require__(3468);
// EXTERNAL MODULE: ./src/report/index.js + 3 modules
var report = __webpack_require__(457);
// EXTERNAL MODULE: ./src/posture/provenance/schema.js
var schema = __webpack_require__(4594);
// EXTERNAL MODULE: ./src/server/graph-loader.js
var graph_loader = __webpack_require__(8218);
// EXTERNAL MODULE: ./src/server/routes.js
var routes = __webpack_require__(4268);
// EXTERNAL MODULE: ./src/lineage/redact-graph.js
var redact_graph = __webpack_require__(334);
;// CONCATENATED MODULE: ./src/mcp/dataflow-tools.js
// dataflow-tools.js — Milestone 4, sub-project MCP tools.
//
// Thin, read-only MCP adapter over the DataFlowGraph v1 artifact. Every
// piece of actual graph-loading and graph-query logic here is REUSED,
// unmodified, from scanner/src/server/ (built for the `explore` HTTP
// server, Milestone 3): loadSignedGraph does the signed-artifact
// load+verify, the four handleX functions do the lookups. This module
// adds nothing but MCP tool shape (name/description/inputSchema/handler)
// and MCP-appropriate error handling — no new graph-query logic is
// written here, on purpose (see this sub-project's own scoping doc).





const META = { source: 'agentic-security-mcp', untrusted_excerpts: true };

function _loadOrFailure(sessionRoot) {
  const loaded = (0,graph_loader.loadSignedGraph)(sessionRoot);
  if (loaded.ok) return { graph: loaded.graph };
  return {
    failure: {
      _meta: META,
      hasResult: false,
      reason: loaded.reason,
      message: loaded.message,
    },
  };
}

// KNOWN, DISCLOSED GAP (not fixed in this increment): this plan's own scope
// item 1 required dataflow_get_graph to paginate/offload per query_taint's
// precedent (`_maybeOffload` in tools.js) once a graph is large. That
// precedent offloads a single flat array; a graph has three (nodes/edges/
// flows) plus a top-level evidence array, so a correct offload design needs
// its own real scoping pass, not a same-shape reuse. Returning the whole
// graph inline risks exceeding stdio.js's MAX_LINE_BYTES (4MB) on a large
// scan. Left for a follow-up increment rather than shipping a rushed,
// under-designed pagination scheme in a security-fix round.
const dataflow_get_graph = {
  name: 'dataflow_get_graph',
  description: 'Return the full DataFlowGraph v1 artifact from the last signed, verified deep-mode scan: nodes, edges, flows, scope, coverage, and limitations. Requires a prior `AGENTIC_SECURITY_LINEAGE_DEEP=1 agentic-security scan`. KNOWN GAP: does not yet paginate/offload for very large graphs (may exceed the stdio transport line cap) — a future increment will add this, matching query_taint\'s own precedent.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: {},
  },
  async handler(_args, ctx) {
    const { graph, failure } = _loadOrFailure(ctx.sessionRoot);
    if (failure) return failure;
    const { status, body } = (0,routes/* handleGraph */.fn)(graph);
    return {
      _meta: META,
      hasResult: true,
      status,
      data: (0,redact_graph/* _redactGraph */.zl)(body.data),
      digest: body.digest,
      schemaVersion: body.schemaVersion,
      extensions: body.extensions,
      scope: body.scope,
      coverage: body.coverage,
      limitations: body.limitations,
    };
  },
};

const dataflow_get_node = {
  name: 'dataflow_get_node',
  description: 'Look up one node by canonical id in the DataFlowGraph v1 artifact.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: { id: { type: 'string', minLength: 1, maxLength: 512 } },
    required: ['id'],
  },
  async handler({ id }, ctx) {
    const { graph, failure } = _loadOrFailure(ctx.sessionRoot);
    if (failure) return failure;
    const { status, body } = (0,routes/* handleNode */.d5)(graph, id);
    return {
      _meta: META,
      hasResult: true,
      notFound: status === 404,
      data: (0,redact_graph/* _redactNode */.T2)(body.data),
      canonicalIds: body.canonicalIds,
    };
  },
};

const dataflow_get_edge = {
  name: 'dataflow_get_edge',
  description: 'Look up one edge by canonical id in the DataFlowGraph v1 artifact.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: { id: { type: 'string', minLength: 1, maxLength: 512 } },
    required: ['id'],
  },
  async handler({ id }, ctx) {
    const { graph, failure } = _loadOrFailure(ctx.sessionRoot);
    if (failure) return failure;
    const { status, body } = (0,routes/* handleEdge */.Yu)(graph, id);
    return {
      _meta: META,
      hasResult: true,
      notFound: status === 404,
      data: body.data,
      canonicalIds: body.canonicalIds,
    };
  },
};

const dataflow_get_flow = {
  name: 'dataflow_get_flow',
  description: 'Look up one flow by canonical id in the DataFlowGraph v1 artifact, including its contributing node/edge canonical ids.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: { id: { type: 'string', minLength: 1, maxLength: 512 } },
    required: ['id'],
  },
  async handler({ id }, ctx) {
    const { graph, failure } = _loadOrFailure(ctx.sessionRoot);
    if (failure) return failure;
    const { status, body } = (0,routes/* handleFlow */.jg)(graph, id);
    return {
      _meta: META,
      hasResult: true,
      notFound: status === 404,
      data: body.data,
      canonicalIds: body.canonicalIds,
    };
  },
};

;// CONCATENATED MODULE: ./src/posture/agents-memory.js
// AGENTS.md — writable continual-learning memory (harness-anatomy #2).
//
// LangChain post:
//   "Harnesses support memory file standards like AGENTS.md which get
//    injected into context on agent start. As agents add and edit this file,
//    harnesses load the updated file into context. This is a form of
//    continual learning where agents durably store knowledge from one
//    session and inject that knowledge into future sessions."
//
// Distinct from CLAUDE.md:
//   - CLAUDE.md = human-authored project conventions, gotchas, layout.
//   - AGENTS.md = agent-authored notes ("what worked / didn't work / I'd try
//                  differently next time"). Append-only. Bounded.
//
// Lives at `<project>/.agentic-security/AGENTS.md`.
//
// Bounds:
//   - MAX_BYTES (default 20 KB) — past this, the oldest entries rotate to
//     `AGENTS.md.archive` (also bounded; oldest archive entries are dropped).
//   - MAX_ENTRY_BYTES (default 2 KB) — caps a single appendage.
//   - Entries are append-only with an ISO timestamp + section divider, so
//     readers can grep / slice by date without parsing.
//
// We deliberately avoid tying AGENTS.md to a session-id namespace. The post's
// recommendation is FLAT continual learning — the whole project's agents see
// each other's notes. Subagents that want session-scoped scratch use the
// agent-scratchpad surface instead.





const MEMORY_FILE = '.agentic-security/AGENTS.md';
const ARCHIVE_FILE = '.agentic-security/AGENTS.md.archive';
const MAX_BYTES = 20 * 1024;
const MAX_ENTRY_BYTES = 2 * 1024;
const ARCHIVE_MAX_BYTES = 200 * 1024;
const HEADER = '# AGENTS.md\n\nAgent-authored continual-learning notes. Each entry: timestamp + agent name + one short paragraph. New entries appended at the bottom; oldest entries rotate to AGENTS.md.archive when this file exceeds 20 KB.\n\n';

function _resolve(scanRoot) { return (0,state_dir/* statePath */.BQ)(scanRoot, 'AGENTS.md'); }
function _archivePath(scanRoot) { return (0,state_dir/* statePath */.BQ)(scanRoot, 'AGENTS.md.archive'); }

function readAgentsMemory(scanRoot) {
  const fp = _resolve(scanRoot);
  if (!external_node_fs_.existsSync(fp)) return '';
  try { return external_node_fs_.readFileSync(fp, 'utf8'); } catch { return ''; }
}

function appendAgentsMemory(scanRoot, { agent, body }) {
  if (typeof agent !== 'string' || !agent.length) {
    return { ok: false, reason: 'agent: required string' };
  }
  if (!/^[A-Za-z0-9_.-]{1,64}$/.test(agent)) {
    return { ok: false, reason: 'agent: must match [A-Za-z0-9_.-]{1,64}' };
  }
  if (typeof body !== 'string' || !body.trim().length) {
    return { ok: false, reason: 'body: required non-empty string' };
  }
  let snippet = body.trim();
  // Strip control chars and cap.
  snippet = snippet.replace(/[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f]/g, ' ');
  if (snippet.length > MAX_ENTRY_BYTES) {
    snippet = snippet.slice(0, MAX_ENTRY_BYTES) + '…';
  }
  const ts = new Date().toISOString();
  const entry = `\n## ${ts}  agent: ${agent}\n\n${snippet}\n`;
  try {
    const fp = _resolve(scanRoot);
    if (!(0,state_dir.stateWritesEnabled)()) return;
  external_node_fs_.mkdirSync(external_node_path_.dirname(fp), { recursive: true });
    if (!external_node_fs_.existsSync(fp)) external_node_fs_.writeFileSync(fp, HEADER);
    external_node_fs_.appendFileSync(fp, entry);
    _maybeRotate(scanRoot);
    const stat = external_node_fs_.statSync(fp);
    return { ok: true, entryBytes: entry.length, fileSize: stat.size };
  } catch (e) {
    return { ok: false, reason: `write-failed: ${e.message}` };
  }
}

function _maybeRotate(scanRoot) {
  const fp = _resolve(scanRoot);
  let body;
  try { body = external_node_fs_.readFileSync(fp, 'utf8'); } catch { return; }
  if (body.length <= MAX_BYTES) return;
  // Split on the `## ` entry headers. Keep the most-recent N until the head
  // (everything before the cut) drops below MAX_BYTES/2; move the head to
  // the archive.
  const head = HEADER;
  const trailing = body.slice(head.length);
  const sections = trailing.split(/(?=\n## )/g).filter(s => s.length);
  // Walk from the end, accumulating until we have roughly MAX_BYTES/2 of
  // recent entries. Everything else goes to the archive.
  let kept = '', archive = '', accum = 0;
  for (let i = sections.length - 1; i >= 0; i--) {
    if (accum + sections[i].length <= MAX_BYTES / 2) {
      kept = sections[i] + kept;
      accum += sections[i].length;
    } else {
      archive = sections.slice(0, i + 1).join('') + archive;
      break;
    }
  }
  try {
    external_node_fs_.writeFileSync(fp, head + kept);
    if (archive.length) {
      const arcFp = _archivePath(scanRoot);
      let existing = '';
      try { existing = external_node_fs_.existsSync(arcFp) ? external_node_fs_.readFileSync(arcFp, 'utf8') : ''; } catch {}
      let next = existing + archive;
      if (next.length > ARCHIVE_MAX_BYTES) {
        // Drop oldest entries until under cap.
        const oldestSplit = next.split(/(?=\n## )/g).filter(s => s.length);
        while (oldestSplit.length && next.length > ARCHIVE_MAX_BYTES) {
          oldestSplit.shift();
          next = oldestSplit.join('');
        }
      }
      external_node_fs_.writeFileSync(arcFp, next);
    }
  } catch { /* best-effort rotation */ }
}

// Public summary helper for the SessionStart hook. Returns a tail aligned
// to a section header (no leading partial entry, no leading newline).
function summarizeForSession(scanRoot, { maxBytes = 6 * 1024 } = {}) {
  const body = readAgentsMemory(scanRoot);
  if (!body) return null;
  if (body.length <= maxBytes) return body;
  const tail = body.slice(-maxBytes);
  const firstSection = tail.indexOf('\n## ');
  if (firstSection < 0) return tail;
  // Slice past the leading `\n` so the result starts with `## `.
  return tail.slice(firstSection + 1);
}

const _internals = { MAX_BYTES, MAX_ENTRY_BYTES, MEMORY_FILE, ARCHIVE_FILE };

// EXTERNAL MODULE: external "node:os"
var external_node_os_ = __webpack_require__(8161);
;// CONCATENATED MODULE: ./src/posture/cve-lookup.js
// CVE lookup — read-only against the per-install OSV / KEV / EPSS caches.
//
// LangChain harness-anatomy post:
//   "Knowledge cutoffs mean that models can't directly access new data like
//    updated library versions without the user providing them directly."
//
// The validator and any subagent reasoning about an SCA finding can call
// `lookup_cve(cve_id)` to get the most recently-cached OSV advisory, the
// CISA KEV entry if listed, and the EPSS exploit-prediction percentile, all
// with `staleness` metadata so the caller can decide whether to trust the
// cached value.
//
// This module deliberately NEVER triggers a network fetch — the scan
// pipeline is the only thing that populates the cache. If a CVE isn't
// cached, we return `present: false` for that source rather than blocking
// on a fetch and risking a multi-second MCP timeout.






const CACHE_DIR = external_node_path_.join(external_node_os_.homedir(), '.claude', 'agentic-security', 'osv-cache');

function _keyToPath(key) {
  const safe = external_node_crypto_.createHash('sha256').update(key).digest('hex');
  return external_node_path_.join(CACHE_DIR, safe + '.json');
}

function _readCache(key) {
  const fp = _keyToPath(key);
  if (!external_node_fs_.existsSync(fp)) return { present: false };
  let body;
  try { body = external_node_fs_.readFileSync(fp, 'utf8'); }
  catch { return { present: false, error: 'unreadable' }; }
  let parsed;
  try { parsed = JSON.parse(body); }
  catch { return { present: false, error: 'unparseable' }; }
  let mtime = null;
  try { mtime = external_node_fs_.statSync(fp).mtimeMs; } catch {}
  return { present: true, data: parsed, cachedAt: mtime, ageMs: mtime ? Date.now() - mtime : null };
}

function _stalenessTier(ageMs) {
  if (ageMs === null || ageMs === undefined) return 'unknown';
  if (ageMs < 24 * 3600 * 1000) return 'fresh';        // <1d
  if (ageMs < 7 * 24 * 3600 * 1000) return 'recent';   // <1w
  if (ageMs < 30 * 24 * 3600 * 1000) return 'stale';   // <1mo
  return 'very-stale';
}

const CVE_RE = /^CVE-\d{4}-\d{1,7}$/i;

function lookupCve(rawId) {
  if (typeof rawId !== 'string' || !CVE_RE.test(rawId)) {
    return { ok: false, reason: 'invalid-cve-id', expected: 'CVE-YYYY-NNNN' };
  }
  const cve = rawId.toUpperCase();

  // KEV catalog — single cached blob keyed at 'kev:catalog'.
  const kevCacheRaw = _readCache('kev:catalog');
  let kev = { present: false };
  if (kevCacheRaw.present) {
    // The blob shape from engine.js: { ts, byCve: { 'CVE-XXX': { ... } } }
    // sessionStorage shim stores the value as the JSON-stringified inner
    // object directly (no extra wrapper).
    const blob = kevCacheRaw.data;
    const byCve = blob?.byCve || null;
    if (byCve && byCve[cve]) {
      kev = {
        present: true,
        ...byCve[cve],
        cachedAt: kevCacheRaw.cachedAt,
        ageMs: kevCacheRaw.ageMs,
        staleness: _stalenessTier(kevCacheRaw.ageMs),
      };
    } else if (byCve) {
      // Catalog is cached but doesn't list this CVE — meaningful negative.
      kev = {
        present: false, listedInCatalog: false,
        cachedAt: kevCacheRaw.cachedAt, ageMs: kevCacheRaw.ageMs,
        staleness: _stalenessTier(kevCacheRaw.ageMs),
      };
    }
  }

  // EPSS — per-CVE cache at 'epss:CVE-XXX'.
  const epssRaw = _readCache('epss:' + cve);
  let epss = { present: false };
  if (epssRaw.present) {
    epss = {
      present: epssRaw.data !== false,   // engine stores `false` for "looked up, no record"
      score: epssRaw.data?.score ?? null,
      percentile: epssRaw.data?.percentile ?? null,
      cachedAt: epssRaw.cachedAt,
      ageMs: epssRaw.ageMs,
      staleness: _stalenessTier(epssRaw.ageMs),
    };
  }

  // OSV — entries are keyed by vuln id (GHSA-... or CVE-...). The engine
  // caches them at 'vuln:<id>'. We do a direct CVE lookup AND a soft probe
  // for any known alias the caller provided implicitly through the KEV
  // hit's vendor/product (no — we keep this simple: direct lookup only).
  const osvRaw = _readCache('vuln:' + cve);
  let osv = { present: false };
  if (osvRaw.present) {
    osv = {
      present: true,
      data: osvRaw.data,
      cachedAt: osvRaw.cachedAt, ageMs: osvRaw.ageMs,
      staleness: _stalenessTier(osvRaw.ageMs),
    };
  }

  return {
    ok: true,
    cve,
    kev,
    epss,
    osv,
    sourcesFound: [kev.present, epss.present, osv.present].filter(Boolean).length,
    note: (kev.present || epss.present || osv.present)
      ? 'cached values only; staleness tier per source. The MCP tool does NOT trigger a network fetch.'
      : 'no cached data for this CVE on the current install. Run a scan against a project that depends on the affected package, or set $AGENTIC_SECURITY_OFFLINE=0 and run a scan to populate the cache.',
  };
}

const cve_lookup_internals = { CACHE_DIR, CVE_RE, _stalenessTier };

;// CONCATENATED MODULE: ./src/mcp/tools.js
// MCP tool implementations — PRD Feature 2, hardened against the OWASP MCP
// Top 10 (see ./redact.js, ./audit.js, ./server.js for sibling controls).
//
// Trust model:
//   - Session root fixed at server boot. No per-call retargeting.
//   - Path arguments lstat-checked (symlinks refused, OWASP MCP05) and
//     realpath-confined to session root.
//   - Tool outputs marked _meta.untrusted_excerpts:true (OWASP MCP03/MCP06)
//     because they may contain text from scanned files, which is adversary-
//     controlled in any context where the agent might read malicious code.
//   - Secret-shaped strings redacted on the way out (OWASP MCP01/MCP10).
//   - `apply_fix` requires confirm:true, valid HMAC signature on
//     last-scan.json, non-shadow finding, and confined file path.















// Git-origin provenance (Finding Provenance M0/M1). Distinct from
// `finding.provenance` (AI-authorship) and from an SCA entry's `provenance`
// (Sigstore/SLSA attestation) — see report/index.js's import comment.



// Lazy-loaded: these transitively pull in npm packages (@babel/core and
// friends) that aren't available in the plugin-cache install path
// (no node_modules). Deferring keeps the MCP server bootable everywhere;
// the import only runs when a tool that needs them is actually called.
let _runScan;
async function getRunScan() {
  if (!_runScan) _runScan = (await Promise.resolve(/* import() */).then(__webpack_require__.bind(__webpack_require__, 454))).runScan;
  return _runScan;
}
let _verifyFixCore;
async function getVerifyFixCore() {
  if (!_verifyFixCore) _verifyFixCore = (await __webpack_require__.e(/* import() */ 526).then(__webpack_require__.bind(__webpack_require__, 3526))).verifyFix;
  return _verifyFixCore;
}

const MAX_FILES_PER_SCAN = 1024;
const MAX_FILE_BYTES = 500_000;
const MAX_TOTAL_SCAN_BYTES = 50_000_000;
const tools_META = { source: 'agentic-security-mcp', untrusted_excerpts: true };

// OWASP A01 — refuse writes to paths that could subvert the security tool
// itself or the host's source-control / dependency state. A forged finding
// could otherwise tell apply_fix to overwrite our own rules.yml, our audit
// log, a .git/hooks/post-commit payload, a CI workflow, an IaC file, or a
// dependency manifest (premortem #3 expansion).
//
// Two kinds of guard:
//   - DIR-prefix matches anywhere under one of these directories
//   - FILE-suffix matches any path whose basename ends with one of these
const RESERVED_WRITE_PREFIXES = [
  '.git/',
  '.github/',
  '.gitlab/',
  '.circleci/',
  '.buildkite/',
  '.agentic-security/',
  'node_modules/',
  '.terraform/',
  '.aws/',
  'k8s/',
  'kubernetes/',
];
const RESERVED_WRITE_BASENAMES = new Set([
  'Dockerfile',
  'Jenkinsfile',
  '.gitlab-ci.yml',
  '.gitlab-ci.yaml',
  'package.json',
  'package-lock.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'pyproject.toml',
  'Pipfile',
  'Pipfile.lock',
  'poetry.lock',
  'requirements.txt',
  'go.mod',
  'go.sum',
  'Cargo.toml',
  'Cargo.lock',
  'composer.json',
  'composer.lock',
  'Gemfile',
  'Gemfile.lock',
  'pom.xml',
  'build.gradle',
  'build.gradle.kts',
]);
const RESERVED_WRITE_SUFFIXES = [
  '.tf',
  '.tfvars',
  'docker-compose.yml',
  'docker-compose.yaml',
  // _CONFINEMENT rule 3 — backup and lock files. The specific lock BASENAMES
  // above cover the ecosystems we know; this catches the rest (`deps.lock`,
  // `foo.bak`) without needing to enumerate them. Nothing an autofix should
  // ever be rewriting: a `.bak` is someone's safety copy and a `.lock` is
  // generated state.
  '.bak',
  '.lock',
];
// _CONFINEMENT rule 3 — build output. Matched as a PATH SEGMENT at any depth,
// not as a top-level prefix, because build output is routinely nested
// (`packages/web/dist/`, `services/api/target/`) and a top-level-only check
// would refuse the monorepo root and allow every package inside it.
//
// This matters most in THIS repository: `scanner/dist/` holds the shipped
// bundle, which carries its own SHA-256 integrity sidecar precisely because
// what it contains matters. Before this, `apply_fix` would rewrite it and
// report success.
//
// NOTE for a future change, deliberately not made here: the PREFIX list above
// (`node_modules/`, `.git/`, …) is still top-level-only, so a nested
// `packages/a/node_modules/` is not covered by it. That is a separate widening
// with its own blast radius and belongs in its own change with its own tests.
const RESERVED_WRITE_DIR_SEGMENTS = new Set(['dist', 'build', 'target']);
function _isReservedWritePath(sessionRoot, absFile) {
  // Resolve sessionRoot symlinks so the relative path is computed against
  // the same canonical root as `absFile` (which _confine already realpath'd).
  // On macOS /tmp → /private/tmp; without this normalization the relative
  // would contain "../" and the prefix check would miss the reserved path.
  const rootReal = external_node_fs_.realpathSync(external_node_path_.resolve(sessionRoot));
  const rel = external_node_path_.relative(rootReal, absFile).replace(/\\/g, '/');
  if (RESERVED_WRITE_PREFIXES.some(p => rel === p.replace(/\/$/, '') || rel.startsWith(p))) return true;
  const segments = rel.split('/');
  const base = segments[segments.length - 1] || '';
  if (RESERVED_WRITE_BASENAMES.has(base)) return true;
  if (RESERVED_WRITE_SUFFIXES.some(s => base === s || base.endsWith(s))) return true;
  // Any DIRECTORY segment that names build output — checked over
  // `segments.length - 1` so a source file legitimately called `build` or
  // `dist` is not refused for its own name; only living inside such a
  // directory counts.
  if (segments.slice(0, -1).some(seg => RESERVED_WRITE_DIR_SEGMENTS.has(seg))) return true;
  return false;
}

// LangChain harness-anatomy recommendation: the filesystem is the right
// collaboration / scratchpad surface for subagents. We carve out one writable
// directory inside the otherwise-reserved `.agentic-security/` tree —
// `.agentic-security/agent-scratchpad/<agent>/<session>/` — and expose
// `append_scratchpad` / `read_scratchpad` for in-progress agent state.
//
// Confinement rules:
//   - relative path required (no absolute / no `..`)
//   - must start with `agent-scratchpad/<agent>/<session>/`
//   - `<agent>` and `<session>` are restricted to `[A-Za-z0-9_.-]{1,64}`
//     (no slashes — keeps the prefix exactly three components deep)
//   - file basename: same charset rules
//   - max scratchpad bytes per file: SCRATCHPAD_MAX_FILE_BYTES
const SCRATCHPAD_PREFIX = '.agentic-security/agent-scratchpad/';
const SCRATCHPAD_NAME_RE = /^[A-Za-z0-9_.-]{1,64}$/;
const SCRATCHPAD_MAX_FILE_BYTES = 2 * 1024 * 1024;   // 2 MB per file
const SCRATCHPAD_MAX_TOTAL_BYTES = 50 * 1024 * 1024; // 50 MB per scan root

function _validateScratchpadPath(relPath) {
  if (typeof relPath !== 'string' || !relPath.length) {
    return { ok: false, reason: 'path: not a string' };
  }
  if (external_node_path_.isAbsolute(relPath)) return { ok: false, reason: 'path: must be relative' };
  if (relPath.includes('..')) return { ok: false, reason: 'path: must not contain ..' };
  const normalized = relPath.replace(/\\/g, '/');
  if (!normalized.startsWith(SCRATCHPAD_PREFIX)) {
    return { ok: false, reason: `path: must start with "${SCRATCHPAD_PREFIX}"` };
  }
  const rest = normalized.slice(SCRATCHPAD_PREFIX.length);
  const parts = rest.split('/');
  if (parts.length < 3) {
    return { ok: false, reason: 'path: must be agent-scratchpad/<agent>/<session>/<file>' };
  }
  const [agent, session, ...fileParts] = parts;
  if (!SCRATCHPAD_NAME_RE.test(agent)) return { ok: false, reason: `path: agent name "${agent}" not in [A-Za-z0-9_.-]{1,64}` };
  if (!SCRATCHPAD_NAME_RE.test(session)) return { ok: false, reason: `path: session id "${session}" not in [A-Za-z0-9_.-]{1,64}` };
  for (const p of fileParts) {
    if (!SCRATCHPAD_NAME_RE.test(p)) return { ok: false, reason: `path: file part "${p}" not in [A-Za-z0-9_.-]{1,64}` };
  }
  return { ok: true, agent, session, fileParts };
}

// Routes through the same lstat+realpath confinement every other write/
// path-taking tool uses (OWASP MCP05) — a lexical prefix/charset check
// alone doesn't stop a pre-planted symlink at any path component from
// relocating the write/read outside the session root. Throws on escape;
// callers must catch (see append_scratchpad / read_scratchpad).
function _scratchpadAbs(sessionRoot, relPath) {
  return _confine(sessionRoot, relPath.replace(/\\/g, '/'), 'scratchpad path');
}

function _scratchpadTotalBytes(sessionRoot) {
  const base = (0,state_dir/* statePath */.BQ)(sessionRoot, 'agent-scratchpad');
  if (!external_node_fs_.existsSync(base)) return 0;
  let total = 0;
  const walk = (dir) => {
    let entries;
    try { entries = external_node_fs_.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const fp = external_node_path_.join(dir, e.name);
      try {
        if (e.isFile()) { total += external_node_fs_.statSync(fp).size; }
        else if (e.isDirectory()) walk(fp);
      } catch { /* skip */ }
    }
  };
  walk(base);
  return total;
}

// ─── Path confinement ────────────────────────────────────────────────────────
// Lexical check + lstat symlink reject + realpath re-check. OWASP MCP05.
//
// For non-existent paths (apply_fix to a new file is a possible legitimate
// case; in practice we re-check existence at the use-site) we walk up the
// deepest existing ancestor and realpath that, so a parent-symlink can't
// silently relocate writes.
function _confine(sessionRoot, candidate, label) {
  if (typeof candidate !== 'string' || !candidate) throw new Error(`${label}: not a string`);
  const rootReal = external_node_fs_.realpathSync(external_node_path_.resolve(sessionRoot));
  const abs = external_node_path_.isAbsolute(candidate) ? candidate : external_node_path_.resolve(rootReal, candidate);

  // Lexical pre-check: rejects "../../etc/passwd" before any fs call.
  const relLex = external_node_path_.relative(rootReal, external_node_path_.resolve(abs));
  if (relLex === '' || relLex.startsWith('..') || external_node_path_.isAbsolute(relLex)) {
    throw new Error(`${label}: path "${candidate}" escapes session root`);
  }

  // If the path exists, the leaf must not be a symlink and its realpath
  // must still be under rootReal.
  if (external_node_fs_.existsSync(abs)) {
    if (external_node_fs_.lstatSync(abs).isSymbolicLink()) {
      throw new Error(`${label}: path "${candidate}" is a symbolic link (refused)`);
    }
    const real = external_node_fs_.realpathSync(abs);
    if (external_node_path_.relative(rootReal, real).startsWith('..')) {
      throw new Error(`${label}: path "${candidate}" resolves outside session root via symlink`);
    }
    return real;
  }

  // Path doesn't exist — walk up to the deepest existing ancestor and
  // realpath that. If a parent dir is a symlink pointing outside rootReal
  // we catch it here.
  let parent = external_node_path_.dirname(abs);
  while (parent !== external_node_path_.dirname(parent) && !external_node_fs_.existsSync(parent)) {
    parent = external_node_path_.dirname(parent);
  }
  const parentReal = external_node_fs_.realpathSync(parent);
  if (external_node_path_.relative(rootReal, parentReal).startsWith('..')) {
    throw new Error(`${label}: path "${candidate}" parent resolves outside session root`);
  }
  const suffix = external_node_path_.relative(parent, abs);
  return external_node_path_.resolve(parentReal, suffix);
}

function _readLastScanVerified(sessionRoot, { allowUnsigned = false } = {}) {
  const stateDirPath = (0,state_dir/* stateDir */.Pn)(sessionRoot);
  const scanFile = external_node_path_.join(stateDirPath, 'last-scan.json');
  const sigFile = scanFile + '.sig';
  if (!external_node_fs_.existsSync(scanFile)) return { scan: null, status: 'missing' };
  const body = external_node_fs_.readFileSync(scanFile, 'utf8');
  const ok = (0,integrity/* verifyLastScan */.Ef)(body, sigFile);
  if (ok === false) return { scan: null, status: 'tampered' };
  if (ok === null && !allowUnsigned) return { scan: null, status: 'unsigned' };
  let parsed;
  try { parsed = JSON.parse(body); }
  catch { return { scan: null, status: 'unparseable' }; }
  return { scan: parsed, status: ok ? 'verified' : 'unsigned' };
}

function _findById(scan, id) {
  if (!scan) return null;
  return (scan.findings || []).find(f => f.id === id)
      || (scan.secrets || []).find(f => f.id === id)
      || (scan.supplyChain || []).find(f => f.id === id)
      || (scan.logicVulns || []).find(f => f.id === id)
      || null;
}

// ─── Tool-output offloading (harness-anatomy #1) ────────────────────────────
// LangChain post: "the harness keeps the head and tail tokens of tool outputs
// above a threshold number of tokens and offloads the full output to the
// filesystem." We apply this to any MCP tool response whose findings array
// exceeds OFFLOAD_THRESHOLD entries: write the full list to a scratchpad
// file, return only head[0..3] + tail[-2..] + total + path. The agent can
// call `read_scratchpad(path)` to page through the rest.
//
// Design choices:
//   - Threshold is conservative (10) — anything bigger than a casual UI page
//     gets offloaded. Tunable via $AGENTIC_SECURITY_MCP_OFFLOAD_THRESHOLD.
//   - Offload location is the agent-scratchpad (not a separate dir) so the
//     same cleanup + size caps apply.
//   - File names are deterministic per response (sha256 of JSON.stringify)
//     so two identical responses share the same offload file.
//   - The session id is process.pid + boot timestamp short hash — collides
//     only across restarts within a millisecond, which is fine for cache.
const OFFLOAD_THRESHOLD = (() => {
  const v = parseInt(process.env.AGENTIC_SECURITY_MCP_OFFLOAD_THRESHOLD || '10', 10);
  return Number.isFinite(v) && v >= 1 ? v : 10;
})();
const MCP_SESSION_ID = `${process.pid}-${Date.now().toString(36).slice(-6)}`;

function _maybeOffload(sessionRoot, toolName, items) {
  if (!Array.isArray(items) || items.length <= OFFLOAD_THRESHOLD) {
    return { offloaded: false, items, total: items.length };
  }
  const head = items.slice(0, 3);
  const tail = items.slice(-2);
  const json = JSON.stringify({ tool: toolName, total: items.length, items }, null, 2);
  const hashShort = external_node_crypto_.createHash('sha256').update(json).digest('hex').slice(0, 10);
  const rel = `.agentic-security/agent-scratchpad/mcp-offload/${MCP_SESSION_ID}/${toolName}-${hashShort}.json`;
  const abs = external_node_path_.resolve(sessionRoot, rel);
  try {
    external_node_fs_.mkdirSync(external_node_path_.dirname(abs), { recursive: true });
    external_node_fs_.writeFileSync(abs, json);
  } catch (e) {
    // If we can't write to disk for some reason, fall back to returning
    // everything — the alternative would be silently dropping data, which
    // is worse than blowing the context.
    return { offloaded: false, items, total: items.length, offloadError: e.message };
  }
  return {
    offloaded: true,
    head, tail, total: items.length,
    scratchpadPath: rel,
    pagingHint: `call read_scratchpad({ path: "${rel}", offset, limit }) to page through; the file is { tool, total, items: [...] } JSON`,
  };
}

// ─── scan_diff ───────────────────────────────────────────────────────────────
// Test seam for the write boundary (PRD F6.4).
//
// `_confine` and `isReservedWrite` ARE the confinement contract in
// agents/_CONFINEMENT.md. A boundary is only worth what its refusals are worth,
// and refusals cannot be adversarially tested through the public tools without
// also exercising a real scan, a real patch and a real filesystem write — so
// the check would be measuring four things and attributing failure to one.
//
// Exported under the `_internals` convention this codebase already uses
// (see posture/poc-inprocess.js). Not part of the MCP tool surface.
const tools_internals = { _confine, isReservedWrite: _isReservedWritePath };

const scan_diff = {
  name: 'scan_diff',
  description: 'Scan a list of files for security findings. Use BEFORE writing a Write/Edit to disk so the agent can self-correct. Returns findings with severity, file:line, title, remediation. Snippets are redacted of obvious secret patterns. Paths confined to the session root; symlinks are refused.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      files: {
        type: 'array', minItems: 1, maxItems: MAX_FILES_PER_SCAN,
        items: { type: 'string', minLength: 1, maxLength: 4096 },
      },
      severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] },
    },
    required: ['files'],
  },
  async handler({ files, severity }, ctx) {
    const sessionRoot = ctx.sessionRoot;
    const abs = files.map(f => _confine(sessionRoot, f, 'files[]'));

    const fileContents = {};
    let totalBytes = 0;
    for (const a of abs) {
      let stat;
      try { stat = external_node_fs_.statSync(a); } catch { continue; }
      if (!stat.isFile()) continue;
      if (stat.size > MAX_FILE_BYTES) continue;
      totalBytes += stat.size;
      if (totalBytes > MAX_TOTAL_SCAN_BYTES) {
        throw new Error(`scan_diff: total scan size exceeds ${MAX_TOTAL_SCAN_BYTES} bytes`);
      }
      let content;
      try { content = external_node_fs_.readFileSync(a, 'utf8'); } catch { continue; }
      const rel = external_node_path_.relative(sessionRoot, a).replace(/\\/g, '/');
      fileContents[rel] = content;
    }

    // PRD R1 (docs/DETECTION_GAP_REMEDIATION_PRD.md): deep mode is default-on
    // for the interactive CLI scan but was never requested here, so an
    // agent's pre-write self-correction scan was regex/AST-only — blind to
    // any bug whose source and sink are connected only through a call
    // (`fileContents` scopes the deep engine's IR to exactly the files
    // passed in, same bound this tool already enforces via MAX_FILES_PER_SCAN
    // / MAX_TOTAL_SCAN_BYTES, so this does not turn scan_diff into a
    // full-project deep scan).
    const runScan = await getRunScan();
    // FR-704 (assurance-hardening PRD): this tool's own description promises
    // "runs scan in memory" — without this, runFullScan's own state writers
    // (dpia.md, ropa.md, privacy-framework.json, threat-model.json, and
    // others) fire unconditionally on every call, silently mutating the
    // user's real project on every pre-write self-correction scan. Confirmed
    // by direct execution before this fix (11 state artifacts written by a
    // single scan_diff-shaped call).
    const result = await (0,state_dir/* withStateWritesDisabled */.Ao)(() =>
      runScan(sessionRoot, { network: false, fileContents, deep: true, deepInCi: true }));
    const wantSet = new Set(Object.keys(fileContents));
    const sevRank = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
    const min = sevRank[severity] ?? 0;
    // Stage 6 correctness audit (historical): this used to only read
    // result.scan.findings (the SAST channel) — scan.secrets and
    // scan.logicVulns are separate arrays on the raw runScan() result, and a
    // hand-rolled 3-channel concat here was a second, divergent copy of the
    // merge report/index.js's normalizeFindings() already does (four
    // channels, plus per-channel defaulting and remediation-string
    // resolution the old concat re-implemented separately and could drift
    // from). Assurance-hardening PRD FR-105 ("JSON, SARIF, HTML, CSV, JUnit,
    // and MCP outputs derive from the same validated object"): route through
    // the same canonical merge every other output format uses.
    //
    // This closes the field-mapping/dedup divergence, but does NOT make
    // scan_diff surface SCA/supply-chain findings end to end: this handler
    // never builds a `depFileContents` map (everything a caller passes in
    // `files`, manifests included, lands in `fileContents`), and manifest-
    // based supply-chain detection in engine.js reads only `depFileContents`
    // — so `result.scan.supplyChain` is always empty for this tool today
    // regardless of this fix. That is a separate, real limitation (scan_diff
    // was designed for pre-write code self-correction, not manifest
    // scanning), left as-is rather than silently claimed fixed here.
    const findings = (0,report.normalizeFindings)(result.scan)
      .filter(f => wantSet.has(String(f.file || '').replace(/\\/g, '/')) && (sevRank[f.severity] ?? 0) >= min)
      .map(f => (0,redact/* redactFinding */.lE)({
        id: f.id, severity: f.severity, file: f.file, line: f.line,
        title: f.vuln, cwe: f.cwe,
        description: f.description, remediation: f.remediation,
      }));
    // Harness-anatomy #1: offload when the result exceeds OFFLOAD_THRESHOLD.
    // The agent gets a head+tail preview plus a path it can page through;
    // the full finding list lives on disk. This is the documented fix for
    // "context rot" — large tool outputs eat the model's attention budget.
    const off = _maybeOffload(sessionRoot, 'scan_diff', findings);
    if (off.offloaded) {
      return {
        _meta: tools_META,
        scannedFiles: Object.keys(fileContents).length,
        findingCount: off.total,
        offloaded: true,
        head: off.head, tail: off.tail,
        scratchpadPath: off.scratchpadPath,
        pagingHint: off.pagingHint,
      };
    }
    return {
      _meta: tools_META,
      scannedFiles: Object.keys(fileContents).length,
      findingCount: findings.length,
      findings,
    };
  },
};

// ─── query_taint ─────────────────────────────────────────────────────────────
const query_taint = {
  name: 'query_taint',
  description: 'Query whether the last verified scan found a taint path involving a given source and sink. Paginated — returns up to `limit` matches (default 10, max 50) starting at `offset` (default 0); set `truncated:true` and `totalMatches` tell you when to page.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      source: { type: 'string', minLength: 1, maxLength: 256 },
      sink: { type: 'string', minLength: 1, maxLength: 256 },
      limit: { type: 'integer', minimum: 1, maximum: 50 },
      offset: { type: 'integer', minimum: 0, maximum: 10000 },
    },
    required: ['source', 'sink'],
  },
  async handler({ source, sink, limit, offset }, ctx) {
    const { scan, status } = _readLastScanVerified(ctx.sessionRoot, { allowUnsigned: true });
    if (!scan) {
      return { _meta: tools_META, hasResult: false, status, message: `No usable scan state (${status}).` };
    }
    const lim = Number.isInteger(limit) ? Math.min(50, Math.max(1, limit)) : 10;
    const off = Number.isInteger(offset) ? Math.max(0, offset) : 0;
    const srcL = String(source).toLowerCase();
    const sinkL = String(sink).toLowerCase();
    // Filter first (cheap), then paginate (so totalMatches is accurate).
    // Harness-engineering note (post-derived): "context window != context
    // attention." Returning hundreds of matches to the agent in one shot
    // dilutes its reasoning; the agent receives a bounded slice plus the
    // cursor to fetch the rest if it wants.
    const all = (scan.findings || []).filter(f => {
      const hay = [f.description, f.title, f.vuln, f.snippet, JSON.stringify(f.trace || '')].join(' ').toLowerCase();
      return hay.includes(srcL) && hay.includes(sinkL);
    });
    const page = all.slice(off, off + lim).map(f => (0,redact/* redactFinding */.lE)({
      id: f.id, severity: f.severity, file: f.file, line: f.line,
      title: f.title || f.vuln, description: f.description,
      trace: f.trace || null,
    }));
    return {
      _meta: tools_META,
      hasResult: true,
      integrity: status,
      scanStartedAt: scan.startedAt || scan.meta?.startedAt || null,
      totalMatches: all.length,
      matchCount: page.length,
      offset: off,
      limit: lim,
      truncated: off + page.length < all.length,
      nextOffset: off + page.length < all.length ? off + page.length : null,
      matches: page,
    };
  },
};

// ─── explain_finding ─────────────────────────────────────────────────────────
const explain_finding = {
  name: 'explain_finding',
  description: 'Return full details for a single finding from the last verified scan. Snippet/description redacted of secret patterns.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      finding_id: { type: 'string', minLength: 1, maxLength: 256 },
    },
    required: ['finding_id'],
  },
  async handler({ finding_id }, ctx) {
    const { scan, status } = _readLastScanVerified(ctx.sessionRoot, { allowUnsigned: true });
    if (!scan) throw new Error(`No usable scan state (${status}).`);
    const f = _findById(scan, finding_id);
    if (!f) throw new Error(`Finding not found: ${finding_id}`);
    const redacted = (0,redact/* redactFinding */.lE)({
      id: f.id, severity: f.severity, file: f.file, line: f.line,
      title: f.title || f.vuln, cwe: f.cwe,
      description: f.description, remediation: f.remediation,
      snippet: f.snippet || null,
      trace: f.trace || null,
    });
    // Harness-anatomy #1: explain_finding's trace is the most-likely-large
    // field on a single finding. Offload when it crosses the threshold so
    // the agent gets a head/tail preview, not a 50-step trace dumped into
    // its context.
    let traceTrimmed = redacted.trace;
    let traceMeta = null;
    if (Array.isArray(redacted.trace) && redacted.trace.length > OFFLOAD_THRESHOLD) {
      const off = _maybeOffload(ctx.sessionRoot, 'explain_finding-trace', redacted.trace);
      if (off.offloaded) {
        traceTrimmed = [...off.head, { _gap: `... ${off.total - off.head.length - off.tail.length} more steps elided; read scratchpad ...` }, ...off.tail];
        traceMeta = {
          totalSteps: off.total,
          scratchpadPath: off.scratchpadPath,
          pagingHint: off.pagingHint,
        };
      }
    }
    return {
      _meta: tools_META,
      ...redacted,
      trace: traceTrimmed,
      traceOffload: traceMeta,
      confidence: f.confidence ?? null,
      hasReplacementFix: typeof f.fix?.replacement === 'string',
      integrity: status,
      // Risk-signal passthrough so agents can decide priority without
      // re-reading last-scan.json or re-fetching OSV/KEV/EPSS. compositeRisk
      // is the canonical sort key; the other fields are its provenance.
      compositeRisk: f.compositeRisk ?? null,
      compositeRiskTier: f.compositeRiskTier ?? null,
      compositeRiskFactors: Array.isArray(f.compositeRiskFactors) ? f.compositeRiskFactors : [],
      exploitability: f.exploitability ?? null,
      exploitabilityTier: f.exploitabilityTier ?? null,
      mitigationVerdict: f.mitigationVerdict ?? null,
      kev: !!(f.kev || f.kevListed || f.weaponized),
      epssScore: typeof f.epssScore === 'number' ? f.epssScore : null,
      epssPercentile: typeof f.epssPercentile === 'number' ? f.epssPercentile : null,
      exploitedNow: !!f.exploitedNow,
      // Which commit introduced this finding. `includeEmail` stays at its
      // DEFAULT (false) unconditionally — unlike the JSON report there is no
      // operator-set env escape for it here, because the consumer is an
      // agent that has no business receiving a committer's email address.
      // `pseudonymize`, by contrast, IS read back from the same env var
      // report/index.js's `_normalizedProvenance` reads
      // (AGENTIC_SECURITY_PSEUDONYMIZE_AUTHORS=1 / --pseudonymize-authors) —
      // fix-round item 4: an operator who set that policy was still getting
      // raw committer names (and, via providerEnrichment, raw reviewer
      // logins/CODEOWNERS lines) through this MCP surface because this call
      // passed no options object at all, silently defeating their policy at
      // this one output boundary while report/index.js honoured it.
      findingProvenance: f.findingProvenance ? (0,schema/* redactFindingProvenance */.As)(f.findingProvenance, {
        pseudonymize: process.env.AGENTIC_SECURITY_PSEUDONYMIZE_AUTHORS === '1',
      }) : null,
    };
  },
};

// ─── apply_fix ───────────────────────────────────────────────────────────────
const apply_fix = {
  name: 'apply_fix',
  description: 'Apply a fix for a finding. Two modes: (1) the stored fix.replacement, or (2) a caller-supplied `patch` (a files map) which is RE-VERIFIED inline (rescan-clean + no new ≥medium + lint) before any write — this unblocks findings that ship only a template or description. Refuses if last-scan.json fails its HMAC check, if the finding is shadow-marked, or if a path escapes the session root via lexical traversal OR a symlink. Requires confirm:true. Supports dry_run:true to preview without writing. On success, `verified:true` means verification passed but `verifiedFull:true` is the honest signal that every required leg (lint when configured, tests when a runner exists) genuinely ran — a false `verifiedFull` with `verified:true` means the pass is real but degraded (see `verify.degradedLegs`), not a full verification.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      finding_id: { type: 'string', minLength: 1, maxLength: 256 },
      confirm: { type: 'boolean' },
      dry_run: { type: 'boolean' },
      patch: {
        type: 'object',
        additionalProperties: { type: 'string', maxLength: 500_000 },
        minProperties: 1, maxProperties: 8,
      },
      // Stage 6 correctness audit: same gap and same fix as verify_fix — the
      // honesty gate is reachable but was never wired to any real caller.
      // Here it's stronger than advisory: the inline re-verify below already
      // gates the WRITE on `verdict.ok`, and verifyFixCore's own `ok`
      // formula already folds in `honesty.ok` when fixMeta is supplied — so
      // passing it through here makes a dishonest fixMeta (hand-wave
      // residual, uncited false-positive verdict) block the write itself,
      // not just report a verdict.
      fixMeta: {
        type: 'object',
        additionalProperties: false,
        properties: {
          residual: { type: 'string', maxLength: 2000 },
          verdict: { type: 'string', maxLength: 64 },
          evidence: { type: 'array', items: { type: 'string', maxLength: 500 }, maxItems: 20 },
          signals: {
            type: 'object',
            additionalProperties: false,
            properties: {
              sinkSignatureChanged: { type: 'boolean' },
              allCallersRouted: { type: 'boolean' },
              testDiscriminates: { type: 'boolean' },
              rateLimitOnly: { type: 'boolean' },
              docsOnly: { type: 'boolean' },
              logOnlyNoReject: { type: 'boolean' },
              partialSanitization: { type: 'boolean' },
            },
          },
          // FR-307/FR-1002: this schema had `additionalProperties: false`
          // and never declared `approval` — the property apply-fix-
          // service.js's high-impact-change gate has required since FR-307
          // was built. A real MCP caller supplying fixMeta.approval was
          // rejected by validate.js at the schema layer before the handler
          // ever ran, silently making the approval gate (and FR-1002's
          // identity check layered on it) unreachable from this tool's
          // only real production entry point. See D-0024.
          approval: {
            type: 'object',
            additionalProperties: false,
            properties: {
              approvedBy: { type: 'string', minLength: 1, maxLength: 200 },
              reason: { type: 'string', minLength: 1, maxLength: 1000 },
            },
          },
          // FR-1003: separation-of-duties. Self-reported the same way
          // approvedBy is — this tool has no way to determine who actually
          // wrote a patch, so `author` is a claim, checked against a
          // configurable policy the same way `approval` is.
          author: { type: 'string', minLength: 1, maxLength: 200 },
        },
      },
    },
    required: ['finding_id', 'confirm'],
  },
  async handler({ finding_id, confirm, dry_run = false, patch = null, fixMeta = null }, ctx) {
    if (confirm !== true) {
      return { _meta: tools_META, applied: false, reason: 'apply_fix requires confirm: true.' };
    }
    const { scan, status } = _readLastScanVerified(ctx.sessionRoot, { allowUnsigned: false });
    if (!scan) {
      return { _meta: tools_META, applied: false, reason: `last-scan.json failed integrity check: ${status}. Run a fresh scan.` };
    }
    const f = _findById(scan, finding_id);
    if (!f) return { _meta: tools_META, applied: false, reason: `Finding not found: ${finding_id}` };
    if (f._shadow === true) {
      return { _meta: tools_META, applied: false, reason: 'shadow findings cannot be auto-applied' };
    }

    // #3 — verifier-approved patch path. When the caller supplies `patch` (a
    // files map, same shape as verify_fix), apply_fix re-runs the verifier
    // INLINE and writes only if it passes: the original finding's stableId is
    // gone, no new ≥medium finding was introduced, and lint is clean. This lets
    // a deterministic OR LLM-synthesized patch be applied for the ~100% of
    // findings that ship only a template/description (no stored fix.replacement).
    // Security: all existing gates hold (confirm, last-scan HMAC, reserved
    // paths, confinement, fix-history backup + attempt budget); the write is
    // additionally gated on a FRESH verification, so a stale/forged patch can't
    // slip through — there is no token to replay, the verify runs here and now.
    if (patch && typeof patch === 'object' && Object.keys(patch).length) {
      if (!f.stableId) {
        return { _meta: tools_META, applied: false, reason: 'finding has no stableId — cannot verify a patch against it' };
      }
      const confinedAbs = {};
      for (const [rel, content] of Object.entries(patch)) {
        let abs;
        try { abs = _confine(ctx.sessionRoot, rel, 'patch key'); }
        catch (e) { return { _meta: tools_META, applied: false, reason: `path-escape refused: ${e.message}` }; }
        if (_isReservedWritePath(ctx.sessionRoot, abs)) {
          return { _meta: tools_META, applied: false, reason: `reserved path refused: ${rel}` };
        }
        confinedAbs[rel] = { abs, content: String(content) };
      }
      // Inline re-verify — the load-bearing gate. Must pass to write.
      let verdict;
      try {
        const _files = Object.fromEntries(Object.entries(confinedAbs).map(([rel, v]) => [rel, v.content]));
        if (process.env.AGENTIC_SECURITY_FIX_RUN_TESTS === '1') {
          // Addition #7 — connect the closed-loop verifier: add the project test
          // suite as a fourth verification leg (scan + lint + tests). Opt-in
          // because many repos have no runner and we must not fail-closed by
          // default. Normalized to the scan+lint verdict shape used below.
          const { verifyFixWithTests } = await __webpack_require__.e(/* import() */ 113).then(__webpack_require__.bind(__webpack_require__, 4113));
          const t = await verifyFixWithTests({ scanRoot: ctx.sessionRoot, originalFindingStableId: f.stableId, files: _files });
          verdict = { ok: t.ok, summary: t.summary, rescan: t.legs?.scan?.detail, lint: t.legs?.lint?.detail, tests: t.legs?.tests, testVerdict: t.verdict };
        } else {
          const verifyFixCore = await getVerifyFixCore();
          verdict = await verifyFixCore({
            scanRoot: ctx.sessionRoot,
            originalFindingStableId: f.stableId,
            files: _files,
            fixMeta,
          });
        }
      } catch (e) {
        return { _meta: tools_META, applied: false, reason: `patch verification failed: ${e.message}` };
      }
      if (!verdict.ok) {
        return {
          _meta: tools_META, applied: false,
          reason: `patch rejected by verifier: ${verdict.summary || verdict.rescan?.reason || 'did not verify'}`,
          verify: { rescan: verdict.rescan, lint: { runner: verdict.lint?.runner, ok: verdict.lint?.ok }, honesty: verdict.honesty || null },
        };
      }
      // FR-307/FR-1002/D-0024: this caller-supplied-patch branch writes via
      // applyFixHistory() directly and never called applyVerifiedFix() — so
      // the high-impact-change approval gate (auth/authZ/crypto/PII/schema/
      // infra-privilege/public-API) built for the OTHER apply_fix branch
      // (stored fix.replacement) never ran here at all, for any input. Since
      // this is the branch the tool's own description calls the one that
      // covers "~100% of findings that ship only a template," that gap was
      // the larger of the two found this cycle. Same before/after content
      // shape `apply-fix-service.js` already uses — read-first-in-try/catch
      // (D-0012), never existsSync-then-readFileSync.
      const filesForMaterialClassification = {};
      for (const [rel, v] of Object.entries(confinedAbs)) {
        let before = '';
        try { before = await promises_.readFile(v.abs, 'utf8'); } catch { /* new file — before stays '' */ }
        filesForMaterialClassification[rel] = { before, after: v.content };
      }
      const materialClassification = (0,material_change/* classifyFixMaterialRisk */.kz)(filesForMaterialClassification);
      if (dry_run) {
        return { _meta: tools_META, applied: false, dryRun: true, verified: true, files: Object.keys(confinedAbs), summary: verdict.summary, materialClassification };
      }
      if (materialClassification.highImpactCategories.length) {
        const approval = fixMeta && typeof fixMeta === 'object' ? fixMeta.approval : null;
        const hasApprovalEvidence = !!(approval && typeof approval === 'object' &&
          typeof approval.approvedBy === 'string' && approval.approvedBy.trim().length > 0 &&
          typeof approval.reason === 'string' && approval.reason.trim().length > 0);
        if (!hasApprovalEvidence) {
          return {
            _meta: tools_META, applied: false,
            reason: `high-impact change (${materialClassification.highImpactCategories.join(', ')}) requires approval evidence — pass fixMeta.approval: {approvedBy, reason} — before it can be applied`,
            materialClassification,
          };
        }
        const approverRegistry = (0,approver_registry/* loadApproverRegistry */.P4)(ctx.sessionRoot);
        const requiredRoles = (0,approver_registry/* requiredRolesFor */.Kq)(approverRegistry, materialClassification.highImpactCategories);
        const identityCheck = (0,approver_registry/* verifyApprover */.$N)(approverRegistry, approval.approvedBy, requiredRoles);
        if (!identityCheck.verified) {
          return {
            _meta: tools_META, applied: false,
            reason: `high-impact change (${materialClassification.highImpactCategories.join(', ')}) approval rejected: ${identityCheck.reason}`,
            materialClassification,
          };
        }
        // FR-1003: separation-of-duties, same no-op-unless-configured gate
        // as apply-fix-service.js's own copy — see approver-registry.js.
        const sodCheck = (0,approver_registry/* checkSeparationOfDuties */.I0)(approverRegistry, fixMeta?.author, approval.approvedBy);
        if (!sodCheck.ok) {
          return {
            _meta: tools_META, applied: false,
            reason: `high-impact change (${materialClassification.highImpactCategories.join(', ')}) approval rejected: ${sodCheck.reason}`,
            materialClassification,
          };
        }
      }
      const written = [];
      try {
        for (const [rel, v] of Object.entries(confinedAbs)) {
          const fileExisted = external_node_fs_.existsSync(v.abs);
          const originalContent = fileExisted ? await promises_.readFile(v.abs, 'utf8') : '';
          const entry = await (0,fix_history/* applyFix */.oM)({
            scanRoot: ctx.sessionRoot, file: rel, originalContent, newContent: v.content, fileExisted,
            findingId: f.id, stableId: f.stableId, ruleId: f.ruleId || f.cwe || f.family || null, vuln: f.vuln || f.title || null,
            findingProvenance: f.findingProvenance || null,
          });
          written.push({ file: rel, historyId: entry.id, backupPath: entry.backupPath });
        }
      } catch (e) {
        // FR-306: roll back every file THIS batch already wrote before the
        // failure — applyFixHistory already restored the one file that just
        // failed; this covers the rest, so a multi-file patch never leaves
        // some files patched and others not.
        for (const w of written) {
          try { await (0,fix_history/* revertEntryById */.rJ)(ctx.sessionRoot, w.historyId); } catch { /* best-effort; original error still propagates below */ }
        }
        if (e && e.name === 'FixAttemptBudgetExceededError') {
          return { _meta: tools_META, applied: false, reason: `budget-exceeded: ${e.message}`, budgetExceeded: true, attempts: e.attempts, maxAttempts: e.max, key: e.key };
        }
        throw e;
      }
      let acceptance = null;
      try { acceptance = (0,fix_history/* fixAcceptanceRate */.XR)(ctx.sessionRoot); } catch { /* best-effort */ }
      return { _meta: tools_META, applied: true, verified: true, patched: written, integrity: status, verify: { summary: verdict.summary }, acceptance, materialClassification };
    }

    if (typeof f.fix?.replacement !== 'string') {
      // Premortem #2: templates are patch-shaped text. Same reasoning as
      // the replacement path — do NOT pass through redactString here.
      return {
        _meta: tools_META, applied: false,
        reason: 'No full replacement available — only a template. Apply the template manually.',
        template: f.fix?.code || '',
        file: f.file, line: f.line,
      };
    }
    let absFile;
    try { absFile = _confine(ctx.sessionRoot, f.file, 'finding.file'); }
    catch (e) {
      return { _meta: tools_META, applied: false, reason: `path-escape refused: ${e.message}` };
    }
    if (_isReservedWritePath(ctx.sessionRoot, absFile)) {
      return { _meta: tools_META, applied: false, reason: `reserved path refused: writes to .git/, .agentic-security/, or node_modules/ are not permitted via apply_fix` };
    }
    if (!external_node_fs_.existsSync(absFile)) {
      return { _meta: tools_META, applied: false, reason: `File not found: ${absFile}` };
    }
    const originalContent = await promises_.readFile(absFile, 'utf8');

    if (dry_run) {
      return {
        _meta: tools_META,
        applied: false, dryRun: true,
        file: f.file,
        originalSize: originalContent.length,
        newSize: f.fix.replacement.length,
        diffSummary: `${originalContent.length} → ${f.fix.replacement.length} bytes`,
      };
    }

    // FR-301/A-08 (assurance-hardening PRD): this branch used to write
    // f.fix.replacement straight to disk with NO fresh verification — no
    // rescan, no lint, nothing confirming the stored replacement actually
    // closes the finding it claims to fix. The caller-patch branch above
    // already required this; there is no reason a STORED fix should be
    // trusted more than a caller-supplied one just because it shipped with
    // the finding. Routed through the same applyVerifiedFix() service the
    // CLI's `fix --apply` now also uses (src/fix/apply-fix-service.js) —
    // confinement/reserved-path are re-checked there too (harmless
    // redundancy with the dry_run preview above, kept for that preview's
    // size-diff shape) but the load-bearing addition is the verification
    // gate before the write.
    if (!f.stableId) {
      return { _meta: tools_META, applied: false, reason: 'finding has no stableId — cannot verify a stored fix against it' };
    }
    const result = await (0,apply_fix_service/* applyVerifiedFix */.On)({
      scanRoot: ctx.sessionRoot,
      finding: f,
      files: { [f.file]: f.fix.replacement },
      fixMeta,
    });
    if (!result.ok) {
      if (result.budgetExceeded) {
        return { _meta: tools_META, applied: false, reason: result.reason, budgetExceeded: true, attempts: result.attempts, maxAttempts: result.maxAttempts, key: result.key };
      }
      return { _meta: tools_META, applied: false, reason: result.reason, verify: result.verify || null };
    }
    // R25 (PRD §5): surface the running auto-fix acceptance rate after each
    // applied fix, so the closed loop reports its own success metric.
    let acceptance = null;
    try { acceptance = (0,fix_history/* fixAcceptanceRate */.XR)(ctx.sessionRoot); } catch { /* metric is best-effort */ }
    const entry = result.written[0];
    return {
      // FR-305: verifiedFull distinguishes "every required leg (lint, tests)
      // genuinely ran and passed" from "passed, but a required leg was
      // skipped or unavailable" — verified:true alone conflates them.
      _meta: tools_META, applied: true, verified: true, verifiedFull: result.verifiedFull,
      historyId: entry.historyId, file: entry.file, backupPath: entry.backupPath,
      integrity: status, attemptOrdinal: entry.attemptOrdinal, acceptance,
      verify: result.verify,
    };
  },
};

// ─── verify_fix ──────────────────────────────────────────────────────────────
// Closed-loop verification of a proposed patch BEFORE the agent applies it.
// Re-scans the patched files in-memory (no disk write), confirms the original
// stableId is gone, and runs the project's existing linter on the patched
// files. Returns a structured verdict the agent can use to decide whether to
// proceed with apply_fix.
const verify_fix = {
  name: 'verify_fix',
  description: 'Verify a proposed patch before applying. Re-scans the patched files in memory, runs the project linter, runs the project test suite, checks fix honesty (FULL/MITIGATION/WORKAROUND) when fixMeta is supplied, and re-runs the PoC when one exists. Returns { ok, rescan, lint, tests, honesty, poc, summary }. Does not write to the target project’s own files, but DOES append one record per attempt to .agentic-security/fix-metrics.jsonl for the measured fix-loop.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      stable_id: { type: 'string', minLength: 8, maxLength: 64 },
      files: {
        type: 'object',
        additionalProperties: { type: 'string', maxLength: 500_000 },
        minProperties: 1,
        maxProperties: 8,
      },
      // Stage 6 correctness audit: posture/fix-honesty-gate.js's deterministic
      // honesty checks (vague-assurance residual prose, unbacked false-
      // positive verdicts, tier/residual consistency) were fully built and
      // fix-verify.js already consulted them when given a `fixMeta` — but
      // this schema never had a `fixMeta` property, so no call through the
      // MCP surface could ever supply one. The gate can only run against
      // claims the AGENT self-reports (residual risk, verdict, evidence,
      // completeness signals) — nothing here is server-computable — so
      // fixing this meant exposing the property, not inventing a lookup.
      fixMeta: {
        type: 'object',
        additionalProperties: false,
        properties: {
          residual: { type: 'string', maxLength: 2000 },
          verdict: { type: 'string', maxLength: 64 },
          evidence: { type: 'array', items: { type: 'string', maxLength: 500 }, maxItems: 20 },
          signals: {
            type: 'object',
            additionalProperties: false,
            properties: {
              sinkSignatureChanged: { type: 'boolean' },
              allCallersRouted: { type: 'boolean' },
              testDiscriminates: { type: 'boolean' },
              rateLimitOnly: { type: 'boolean' },
              docsOnly: { type: 'boolean' },
              logOnlyNoReject: { type: 'boolean' },
              partialSanitization: { type: 'boolean' },
            },
          },
        },
      },
    },
    required: ['stable_id', 'files'],
  },
  async handler({ stable_id, files, fixMeta }, ctx) {
    // Confine every file path before passing to the verifier.
    const confined = {};
    for (const [relPath, content] of Object.entries(files || {})) {
      try {
        _confine(ctx.sessionRoot, relPath, 'files key');
      } catch (e) {
        return { _meta: tools_META, ok: false, reason: `path-escape refused: ${e.message}` };
      }
      confined[relPath] = String(content);
    }
    try {
      // The PoC-re-check leg (verifyFixCore's `pocLeg`) needs a `poc` param
      // to do anything — until now nothing supplied one, so it always
      // reported {status:'not-requested'} through this surface (see
      // posture/CLAUDE.md's disclosure). Rather than widening inputSchema
      // to make the CALLER pass PoC data back, look it up server-side: the
      // scan pipeline already attaches an HTTP-shaped f.poc to matching
      // findings by default (engine.js's annotatePocs), and last-scan.json
      // already carries it under the same stableId this handler receives.
      // Best-effort: a missing/unsigned/tampered scan just means no PoC is
      // available to re-check, not a verify_fix failure — the rescan/lint/
      // tests legs below are independent of this and still apply.
      let poc = null;
      try {
        const { scan: lastScan } = _readLastScanVerified(ctx.sessionRoot, { allowUnsigned: true });
        const orig = lastScan && (lastScan.findings || []).find(f => f.stableId === stable_id);
        if (orig && orig.poc && orig.poc.code) poc = { ...orig.poc, finding: orig };
      } catch { /* best-effort lookup; poc stays null */ }

      const verifyFixCore = await getVerifyFixCore();
      const r = await verifyFixCore({
        scanRoot: ctx.sessionRoot,
        originalFindingStableId: stable_id,
        files: confined,
        poc,
        fixMeta,
      });
      return {
        _meta: tools_META,
        ok: r.ok,
        rescan: { ok: r.rescan.ok, reason: r.rescan.reason, introduced: r.rescan.introduced || [] },
        lint: { runner: r.lint.runner, ok: r.lint.ok, skipped: r.lint.skipped || false, output: (0,redact/* redactString */.rd)(r.lint.output || '').slice(0, 1500) },
        // verifyFix computes five legs, not two — tests/honesty/poc were
        // being silently dropped here, leaving an agent with no structured
        // way to see WHY verification failed when the failure was in one
        // of those three (only the free-text summary carried it).
        // test-runner.js's runProjectTests never returns raw stdout/stderr,
        // so no redaction is needed there; honesty.violations are static,
        // code-generated strings; poc.reason is redacted defensively since
        // it can echo proof-harness detail derived from scanned source.
        tests: r.tests,
        honesty: r.honesty,
        poc: r.poc ? { ...r.poc, reason: r.poc.reason ? (0,redact/* redactString */.rd)(r.poc.reason) : r.poc.reason } : r.poc,
        summary: r.summary,
      };
    } catch (e) {
      return { _meta: tools_META, ok: false, reason: `verify_fix failed: ${e.message}` };
    }
  },
};

// ─── synthesize_fix ──────────────────────────────────────────────────────────
// Return the stored fix replacement + regression-test scaffold for a finding,
// WITHOUT applying anything. The agent can call verify_fix → apply_fix in
// sequence with the returned blob.
const synthesize_fix = {
  name: 'synthesize_fix',
  description: 'Return the stored fix replacement for a finding (replacement text + remediation + plan if the patch is too large). Read-only; never writes to disk. Use verify_fix → apply_fix to deploy.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      finding_id: { type: 'string', minLength: 1, maxLength: 256 },
    },
    required: ['finding_id'],
  },
  async handler({ finding_id }, ctx) {
    const { scan, status } = _readLastScanVerified(ctx.sessionRoot, { allowUnsigned: false });
    if (!scan) {
      return { _meta: tools_META, ok: false, reason: `last-scan.json failed integrity check: ${status}` };
    }
    const f = _findById(scan, finding_id);
    if (!f) return { _meta: tools_META, ok: false, reason: `Finding not found: ${finding_id}` };
    if (f._shadow === true) return { _meta: tools_META, ok: false, reason: 'shadow findings have no synthesized fix' };
    const fix = f.fix || {};
    const hasReplacement = typeof fix.replacement === 'string' && fix.replacement.length > 0;
    // Patch bounds: count files touched + LoC delta.
    let touchedFiles = 1;
    let locDelta = 0;
    if (hasReplacement) {
      let orig = '';
      try {
        const abs = _confine(ctx.sessionRoot, f.file, 'finding.file');
        orig = external_node_fs_.readFileSync(abs, 'utf8');
      } catch { /* ignore — counts will reflect new-only LoC */ }
      locDelta = Math.abs(fix.replacement.split('\n').length - orig.split('\n').length);
    }
    const oversized = touchedFiles > 3 || locDelta > 100;
    // #1 — deterministic autofix: for classes with a safe context-independent
    // swap (weak hash, TLS verify-off), materialize a full-file patch from the
    // live file. The agent passes `autofix.patch` straight to apply_fix, which
    // re-verifies it (rescan-clean + no new ≥medium + lint) before writing — so
    // even a mis-attributed swap can't land a bad edit. No stored replacement,
    // no per-finding bloat in last-scan.json.
    let autofix = null;
    if (!hasReplacement) {
      try {
        const abs = _confine(ctx.sessionRoot, f.file, 'finding.file');
        const det = synthesizeDeterministicPatch(f, external_node_fs_.readFileSync(abs, 'utf8'));
        if (det) autofix = { deterministic: true, ruleId: det.ruleId, patch: det.patch };
      } catch { /* best-effort — no file / no rule → no autofix */ }
    }
    // Premortem #2: `replacement` is a *patch* (the code we'll write to disk),
    // not a finding excerpt. Running it through redactString silently corrupts
    // valid patches whose content happens to match a secret-shape (e.g. a
    // placeholder like `password = "loadFromEnv"`). Patches MUST pass through
    // verbatim. Snippet/description/etc. continue to be redacted in
    // explain_finding / scan_diff — that's the right surface for redaction.
    return {
      _meta: tools_META,
      ok: true,
      stable_id: f.stableId || null,
      file: f.file, line: f.line,
      vuln: f.vuln,
      severity: f.severity,
      hasReplacement,
      replacement: hasReplacement ? fix.replacement : null,
      template: fix.code || null,
      autofix,
      // #15 — the regression test the scan annotator already generated for this
      // finding (present when a PoC was built). Surfaced here so the fix flow
      // writes the test alongside the patch; fix-verify-loop then runs it, so an
      // applied fix ships with a test that fails pre-fix and passes post-fix.
      regression_test: f.regression_test || null,
      remediation: typeof fix.description === 'string' ? fix.description : (typeof fix === 'string' ? fix : null),
      patchBounds: { touchedFiles, locDelta, oversized },
      // oversized can only be true when hasReplacement is true (locDelta is
      // only computed in that branch, and touchedFiles never varies) — a
      // `!hasReplacement` conjunct here was a structural contradiction that
      // made this permanently false. The correct signal: the stored
      // replacement itself is too big to trust auto-applying, and there's
      // no safer deterministic alternative.
      recommendsFixPlan: oversized && !autofix,
    };
  },
};

// ─── find_rule_module ───────────────────────────────────────────────────────
// Codebase-navigation helper (C.6). Answers "which file under scanner/src/
// implements the detector for CWE-X / family Y" by scanning the SAST and
// posture sources for `cwe:` / `family:` literals. Cheaper and more reliable
// than asking the agent to grep — premortem note: "grep for a common function
// name in a large codebase returns thousands of matches."
//
// Read-only; no findings consumed. Output is a list of file paths + the
// matching literal lines so the agent can verify before editing.
const find_rule_module = {
  name: 'find_rule_module',
  description: 'Find the file(s) under scanner/src/{sast,posture}/ that emit findings for a given CWE id or family name. Use BEFORE editing a rule — answers "where is the SQL-injection detector?" without grepping the whole tree. Returns at most 20 hits; refine the query if too broad.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      cwe: { type: 'string', minLength: 5, maxLength: 16 },
      family: { type: 'string', minLength: 2, maxLength: 64 },
    },
  },
  async handler({ cwe, family }, ctx) {
    if (!cwe && !family) {
      return { _meta: tools_META, ok: false, reason: 'provide cwe (e.g. "CWE-89") or family (e.g. "sql-injection")' };
    }
    // Pattern enforcement — the mini-schema validator doesn't do `pattern`.
    if (cwe && !/^CWE-\d+$/.test(cwe)) {
      return { _meta: tools_META, ok: false, reason: 'cwe must match /^CWE-\\d+$/ (e.g. "CWE-89")' };
    }
    if (family && !/^[a-z][a-z0-9-]+$/.test(family)) {
      return { _meta: tools_META, ok: false, reason: 'family must match /^[a-z][a-z0-9-]+$/ (e.g. "sql-injection")' };
    }
    const sessionRoot = ctx.sessionRoot;
    const roots = [
      external_node_path_.join(sessionRoot, 'scanner', 'src', 'sast'),
      external_node_path_.join(sessionRoot, 'scanner', 'src', 'posture'),
    ];
    const hits = [];
    const cweLit = cwe ? new RegExp(`['"\`]${cwe.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}['"\`]`) : null;
    // Family match is broader on purpose: detectors often emit findings
    // without an explicit `family:` field (it's backfilled by
    // posture/finding-defaults.js). We match the family literal anywhere in
    // the file (vuln-name strings, comments, ids) so e.g. searching for "csrf"
    // surfaces sast/csrf.js even though it doesn't tag findings with the field.
    const famLit = family ? new RegExp(`\\b${family.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/-/g, '[-_ ]?')}\\b`, 'i') : null;
    // Also try a filename-stem match when only family is given.
    const famFilename = family ? family.toLowerCase() : null;
    for (const root of roots) {
      if (!external_node_fs_.existsSync(root)) continue;
      let entries;
      try { entries = external_node_fs_.readdirSync(root); } catch { continue; }
      for (const entry of entries) {
        if (!entry.endsWith('.js')) continue;
        const abs = external_node_path_.join(root, entry);
        let stat;
        try { stat = external_node_fs_.statSync(abs); } catch { continue; }
        if (!stat.isFile() || stat.size > MAX_FILE_BYTES) continue;
        let body;
        try { body = external_node_fs_.readFileSync(abs, 'utf8'); } catch { continue; }
        const lines = body.split('\n');
        const matches = [];
        const stem = entry.replace(/\.js$/, '').toLowerCase();
        const filenameMatchesFamily = famFilename && (stem === famFilename || stem.includes(famFilename));
        if (filenameMatchesFamily) {
          matches.push({ line: 1, text: `<filename "${entry}" matches family>`, kind: 'filename' });
        }
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          if (cweLit && cweLit.test(line)) matches.push({ line: i + 1, text: line.trim().slice(0, 200), kind: 'cwe' });
          else if (famLit && famLit.test(line)) matches.push({ line: i + 1, text: line.trim().slice(0, 200), kind: 'family' });
          if (matches.length >= 5) break;
        }
        if (matches.length) {
          hits.push({
            file: external_node_path_.relative(sessionRoot, abs).replace(/\\/g, '/'),
            matchCount: matches.length,
            matches,
          });
          if (hits.length >= 20) break;
        }
      }
      if (hits.length >= 20) break;
    }
    return {
      _meta: tools_META,
      ok: true,
      query: { cwe: cwe || null, family: family || null },
      hitCount: hits.length,
      hits,
      truncated: hits.length >= 20,
    };
  },
};

// ─── append_scratchpad / read_scratchpad ───────────────────────────────────
// LangChain harness-anatomy: the filesystem is the durable agent scratchpad.
// These tools expose a tightly-confined slice of the project tree for
// in-progress agent state: PLAN.md decompositions, offloaded tool outputs,
// session notes that survive context resets.
//
// Confinement (validated in `_validateScratchpadPath`):
//   ALL paths must start with `.agentic-security/agent-scratchpad/<agent>/<session>/`
//   and consist of [A-Za-z0-9_.-]{1,64} path components — no `..`, no
//   absolute paths, no shell metacharacters. This is the ONE place inside
//   the otherwise-reserved `.agentic-security/` tree where agents can write.
// Limits:
//   - 2 MB per file (write attempts beyond this are refused).
//   - 50 MB total across the scratchpad — protects against runaway agents.
// Operators who want to clean up: `rm -rf .agentic-security/agent-scratchpad`.
//
// The post: "Agents can store intermediate outputs and maintain state that
// outlasts a single session." This is that mechanism.

const append_scratchpad = {
  name: 'append_scratchpad',
  description: 'Append text to a file under .agentic-security/agent-scratchpad/<agent>/<session>/. The ONLY writable location for in-progress agent state (PLAN.md, notes, offloaded tool outputs, decision logs). Path must start with that prefix; <agent>/<session>/file parts are restricted to [A-Za-z0-9_.-]{1,64}. Caps: 2 MB per file, 50 MB total across the scratchpad.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      path: { type: 'string', minLength: 1, maxLength: 256 },
      content: { type: 'string', minLength: 1, maxLength: 256 * 1024 },
    },
    required: ['path', 'content'],
  },
  async handler({ path: relPath, content }, ctx) {
    const v = _validateScratchpadPath(relPath);
    if (!v.ok) return { _meta: tools_META, ok: false, reason: v.reason };
    let abs;
    try { abs = _scratchpadAbs(ctx.sessionRoot, relPath); }
    catch (e) { return { _meta: tools_META, ok: false, reason: `path-escape refused: ${e.message}` }; }
    const total = _scratchpadTotalBytes(ctx.sessionRoot);
    if (total + content.length > SCRATCHPAD_MAX_TOTAL_BYTES) {
      return {
        _meta: tools_META, ok: false,
        reason: `scratchpad-total-exceeded: ${total} + ${content.length} > ${SCRATCHPAD_MAX_TOTAL_BYTES}. Clean up via "rm -rf .agentic-security/agent-scratchpad" or rotate sessions.`,
      };
    }
    let existing = 0;
    try { if (external_node_fs_.existsSync(abs)) existing = external_node_fs_.statSync(abs).size; } catch {}
    if (existing + content.length > SCRATCHPAD_MAX_FILE_BYTES) {
      return {
        _meta: tools_META, ok: false,
        reason: `scratchpad-file-exceeded: ${existing} + ${content.length} > ${SCRATCHPAD_MAX_FILE_BYTES}. Start a new file.`,
      };
    }
    try {
      external_node_fs_.mkdirSync(external_node_path_.dirname(abs), { recursive: true });
      external_node_fs_.appendFileSync(abs, content);
      return {
        _meta: tools_META, ok: true,
        path: relPath, bytesWritten: content.length, fileSize: existing + content.length,
        scratchpadTotal: total + content.length,
      };
    } catch (e) {
      return { _meta: tools_META, ok: false, reason: `write-failed: ${e.message}` };
    }
  },
};

const read_scratchpad = {
  name: 'read_scratchpad',
  description: 'Read a file under .agentic-security/agent-scratchpad/<agent>/<session>/. Paginated for large files via `offset` (default 0) and `limit` (default 4096 bytes, max 64 KB). Returns bytesRead, truncated, nextOffset for paging.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      path: { type: 'string', minLength: 1, maxLength: 256 },
      offset: { type: 'integer', minimum: 0, maximum: 100 * 1024 * 1024 },
      limit: { type: 'integer', minimum: 1, maximum: 64 * 1024 },
    },
    required: ['path'],
  },
  async handler({ path: relPath, offset, limit }, ctx) {
    const v = _validateScratchpadPath(relPath);
    if (!v.ok) return { _meta: tools_META, ok: false, reason: v.reason };
    let abs;
    try { abs = _scratchpadAbs(ctx.sessionRoot, relPath); }
    catch (e) { return { _meta: tools_META, ok: false, reason: `path-escape refused: ${e.message}` }; }
    if (!external_node_fs_.existsSync(abs)) return { _meta: tools_META, ok: false, reason: 'not-found' };
    let stat;
    try { stat = external_node_fs_.statSync(abs); } catch (e) { return { _meta: tools_META, ok: false, reason: `stat-failed: ${e.message}` }; }
    if (!stat.isFile()) return { _meta: tools_META, ok: false, reason: 'not-a-file' };
    const off = Number.isInteger(offset) ? Math.max(0, offset) : 0;
    const lim = Number.isInteger(limit) ? Math.min(64 * 1024, Math.max(1, limit)) : 4096;
    let buf;
    try {
      const fd = external_node_fs_.openSync(abs, 'r');
      const tmp = Buffer.alloc(lim);
      const read = external_node_fs_.readSync(fd, tmp, 0, lim, off);
      external_node_fs_.closeSync(fd);
      buf = tmp.slice(0, read);
    } catch (e) { return { _meta: tools_META, ok: false, reason: `read-failed: ${e.message}` }; }
    const text = buf.toString('utf8');
    return {
      _meta: tools_META, ok: true,
      path: relPath,
      offset: off, limit: lim, bytesRead: buf.length,
      totalSize: stat.size,
      truncated: off + buf.length < stat.size,
      nextOffset: off + buf.length < stat.size ? off + buf.length : null,
      content: text,
    };
  },
};

// ─── append_agents_memory / read_agents_memory ─────────────────────────────
// LangChain harness-anatomy #2: AGENTS.md as continual-learning surface.
// Lazy-import to keep the MCP module dependency-light.




const append_agents_memory = {
  name: 'append_agents_memory',
  description: 'Append a short narrative entry to AGENTS.md — agent-authored continual-learning notes. Use at session end to record "what worked / what didn\'t / what I\'d try differently next time" so the next agent can pick up the lesson. Bounded: 2 KB per entry, 20 KB total before rotation to AGENTS.md.archive. Use sparingly — narrative, not structured data.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      agent: { type: 'string', minLength: 1, maxLength: 64 },
      body: { type: 'string', minLength: 1, maxLength: 4096 },
    },
    required: ['agent', 'body'],
  },
  async handler({ agent, body }, ctx) {
    const r = appendAgentsMemory(ctx.sessionRoot, { agent, body });
    return { _meta: tools_META, ...r };
  },
};

const read_agents_memory = {
  name: 'read_agents_memory',
  description: 'Read the AGENTS.md continual-learning file (and AGENTS.md.archive if needed). Returns the most-recent ~6 KB tail by default; pass `full: true` for everything. The SessionStart hook already surfaces a summary; use this when an agent wants to look up specifics mid-session.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      full: { type: 'boolean' },
    },
  },
  async handler({ full }, ctx) {
    const body = readAgentsMemory(ctx.sessionRoot);
    if (!body) return { _meta: tools_META, present: false };
    if (full) return { _meta: tools_META, present: true, length: body.length, content: body };
    // Tail-only — same logic as summarizeForSession but inlined to avoid a
    // second import surface.
    const limit = 6 * 1024;
    if (body.length <= limit) return { _meta: tools_META, present: true, length: body.length, content: body };
    const tail = body.slice(-limit);
    const firstSection = tail.indexOf('\n## ');
    const slice = firstSection >= 0 ? tail.slice(firstSection) : tail;
    return { _meta: tools_META, present: true, length: body.length, truncated: true, content: slice };
  },
};

// ─── query_triage_memory ───────────────────────────────────────────────────
// Natural-language Q&A over past triage decisions (wont-fix / false-positive
// markings + reasons). Backed by .agentic-security/triage-memory.jsonl, which
// is auto-populated by triage.transition(). Returns at most 10 most-relevant
// past decisions.

const query_triage_memory = {
  name: 'query_triage_memory',
  description: 'Search past triage decisions (wont-fix / false-positive) by natural-language query. Returns up to 10 most-relevant past decisions with their reasons. Use when you see a new finding and want to know "did we already decide on something like this?" — answers in seconds without re-reading the full AGENTS.md narrative.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      query: { type: 'string', description: 'Free-text terms to match against past reasons / vuln text / file paths / family names.' },
    },
  },
  async handler({ query }, ctx) {
    const { queryMemory } = await Promise.resolve(/* import() */).then(__webpack_require__.bind(__webpack_require__, 1905));
    const raw = queryMemory(ctx.sessionRoot, query || '');
    // Stage 6 correctness audit: this returned queryMemory's output
    // verbatim, with no redaction pass — every other tool that echoes
    // scanned-source-derived text redacts it (mcp/CLAUDE.md's "Adding a new
    // tool" step 3). Round-trip through redactString the same way
    // redactFinding already does for its own opaque `.trace` field: results
    // here mix shapes (a triage decision's free-text `reason`, a finding's
    // `vuln`/`family`/file path), so scrubbing the whole serialized
    // structure catches secret-shaped substrings regardless of which field
    // they landed in, rather than hardcoding a field allowlist that could
    // miss one.
    let results;
    try { results = JSON.parse((0,redact/* redactString */.rd)(JSON.stringify(raw))); }
    catch { results = raw; }
    return {
      _meta: tools_META,
      count: results.length,
      results,
    };
  },
};

// ─── query_findings_memory ─────────────────────────────────────────────────
// Natural-language Q&A across the scanner's accumulated institutional
// memory: current findings + past triage decisions + scan history +
// AGENTS.md narrative. Use to answer "have we seen something like this
// before?" without reading multiple files.

const query_findings_memory = {
  name: 'query_findings_memory',
  description: 'Search the scanner accumulated memory (current scan findings + past wont-fix/false-positive decisions + scan history + AGENTS.md narrative) by natural-language terms. Returns top-10 results scored by term-match count and ranked finding > triage > history > AGENTS.md.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      query: { type: 'string', description: 'Natural-language search terms (2+ chars each).' },
    },
    required: ['query'],
  },
  async handler({ query }, ctx) {
    const { queryFindingsMemory } = await __webpack_require__.e(/* import() */ 839).then(__webpack_require__.bind(__webpack_require__, 3839));
    const raw = queryFindingsMemory(ctx.sessionRoot, query || '');
    // Stage 6 correctness audit — same redaction gap and same fix as
    // query_triage_memory just above: this mixes four differently-shaped
    // result kinds (finding / triage / history / AGENTS.md text), so a
    // whole-structure redactString round-trip is applied rather than a
    // per-field allowlist that could miss one of the four shapes.
    let body;
    try { body = JSON.parse((0,redact/* redactString */.rd)(JSON.stringify(raw))); }
    catch { body = raw; }
    return { _meta: tools_META, ...body };
  },
};

// ─── lookup_cve ────────────────────────────────────────────────────────────
// LangChain harness-anatomy #8: bridge the knowledge-cutoff gap by exposing
// the local OSV / KEV / EPSS cache as a structured tool. Read-only — never
// triggers a network fetch from the MCP path.
const lookup_cve = {
  name: 'lookup_cve',
  description: 'Look up a CVE id in the local OSV / KEV / EPSS caches. Returns staleness-tiered cached data (fresh / recent / stale / very-stale). Read-only — does NOT fetch fresh data; the scan pipeline is the only thing that populates the cache. Use to inform reasoning about an SCA finding without relying on the model\'s training cutoff.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      cve: { type: 'string', minLength: 9, maxLength: 20 },
    },
    required: ['cve'],
  },
  async handler({ cve }, _ctx) {
    const r = lookupCve(cve);
    return { _meta: tools_META, ...r };
  },
};

const query_cache_telemetry = {
  name: 'query_cache_telemetry',
  description: 'Read prompt-cache economics for the current session from the Claude Code transcript: cache-hit %, $ saved by caching, $ wasted on avoidable cache misses (model switches / TTL gaps / prefix changes), and a per-model breakdown. Read-only, no network. Use to reason about token-cost efficiency and whether a model switch is worth the cache rewarm.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      // Optional explicit transcript path; otherwise derived from the session root.
      transcript_path: { type: 'string', minLength: 1, maxLength: 4096 },
    },
    required: [],
  },
  async handler({ transcript_path } = {}, ctx) {
    const result = (0,cache_economics.analyzeTranscript)({ transcriptPath: transcript_path, projectDir: ctx?.sessionRoot || process.cwd() });
    if (!result.ok) return { _meta: tools_META, ok: false, reason: result.reason };
    return {
      _meta: tools_META,
      ok: true,
      metrics: result.metrics,
      leaks: result.leaks,
      report: (0,cache_economics.formatCacheReport)(result),
      statusline: (0,cache_economics.renderCacheStatusLine)(result.metrics),
    };
  },
};

// ─── synthesize_sca_upgrade ───────────────────────────────────────────────
// Phase 3 / Item 5 of the SCA improvement plan. Read-only counterpart to
// apply_sca_upgrade — produces a structured upgrade plan via the
// ecosystem's native --dry-run command. Safe to call any number of times.
let _scaUpgrade;
async function _getScaUpgrade() {
  if (!_scaUpgrade) _scaUpgrade = await __webpack_require__.e(/* import() */ 333).then(__webpack_require__.bind(__webpack_require__, 5333));
  return _scaUpgrade;
}
const synthesize_sca_upgrade = {
  name: 'synthesize_sca_upgrade',
  description: 'Generate an upgrade plan for a single SCA finding. Runs the ecosystem dry-run (npm install --dry-run, pip install --dry-run, cargo update --dry-run). Returns { ecosystem, package, currentVersion, targetVersion, isBreaking, command, manifestFiles, dryRun, testCommand }. No writes.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      finding_id: { type: 'string', minLength: 1, maxLength: 256 },
    },
    required: ['finding_id'],
  },
  async handler({ finding_id }, ctx) {
    const { scan, status } = _readLastScanVerified(ctx.sessionRoot, { allowUnsigned: true });
    if (!scan) throw new Error(`No usable scan state (${status}).`);
    const f = _findById(scan, finding_id);
    if (!f) throw new Error(`Finding not found: ${finding_id}`);
    if (f.type !== 'vulnerable_dep') {
      return { _meta: tools_META, ok: false, reason: 'finding is not an SCA vulnerable_dep — use synthesize_fix for SAST findings' };
    }
    const { planScaUpgrade } = await _getScaUpgrade();
    const plan = await planScaUpgrade({ scanRoot: ctx.sessionRoot, finding: f });
    return { _meta: tools_META, ...plan };
  },
};

// ─── apply_sca_upgrade ────────────────────────────────────────────────────
// Phase 3 / Item 5 of the SCA improvement plan. The MCP `apply_fix` path
// refuses every package-manager manifest by design. This tool bypasses
// that ONLY for the install pathway — it shells out to the ecosystem's
// native package manager (npm / pip / cargo / go) which is the right
// surface for safely modifying manifests + lockfiles. Backs up affected
// manifests before the install; runs the project's test command (if
// detected); rolls back manifests if tests fail.
const apply_sca_upgrade = {
  name: 'apply_sca_upgrade',
  description: 'Apply a vulnerable_dep upgrade. Backs up manifests, runs the package manager, runs the project test command, restores manifests on test failure. Requires confirm:true. Set run_tests:false to skip the test gate (NOT recommended).',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      finding_id: { type: 'string', minLength: 1, maxLength: 256 },
      confirm: { type: 'boolean' },
      run_tests: { type: 'boolean' },
    },
    required: ['finding_id', 'confirm'],
  },
  async handler({ finding_id, confirm, run_tests = true }, ctx) {
    if (confirm !== true) {
      return { _meta: tools_META, applied: false, reason: 'apply_sca_upgrade requires confirm: true.' };
    }
    const { scan, status } = _readLastScanVerified(ctx.sessionRoot, { allowUnsigned: false });
    if (!scan) {
      return { _meta: tools_META, applied: false, reason: `last-scan.json failed integrity check: ${status}. Run a fresh scan.` };
    }
    const f = _findById(scan, finding_id);
    if (!f) return { _meta: tools_META, applied: false, reason: `Finding not found: ${finding_id}` };
    if (f.type !== 'vulnerable_dep') {
      return { _meta: tools_META, applied: false, reason: 'finding is not an SCA vulnerable_dep — use apply_fix for SAST findings' };
    }
    const { applyScaUpgrade } = await _getScaUpgrade();
    const result = await applyScaUpgrade({ scanRoot: ctx.sessionRoot, finding: f, runTests: run_tests });
    return { _meta: tools_META, ...result };
  },
};

const ALL_TOOLS = [scan_diff, query_taint, explain_finding, apply_fix, verify_fix, synthesize_fix, find_rule_module, append_scratchpad, read_scratchpad, append_agents_memory, read_agents_memory, lookup_cve, synthesize_sca_upgrade, apply_sca_upgrade, query_triage_memory, query_findings_memory, query_cache_telemetry, dataflow_get_graph, dataflow_get_node, dataflow_get_edge, dataflow_get_flow];

;// CONCATENATED MODULE: ./src/mcp/validate.js
// Minimal JSON Schema validator — just the subset our tool schemas use.
// No deps. Throws on invalid input with a path-prefixed error message.
//
// Supported keywords: type (object/array/string/boolean/number),
// required, properties, items, enum, minItems, maxItems, maxLength,
// minLength, additionalProperties (only as `false` — strict).

const TYPE_OF = (v) => {
  if (v === null) return 'null';
  if (Array.isArray(v)) return 'array';
  return typeof v;
};

function validate(schema, value, path = 'arguments') {
  if (!schema) return;
  const t = schema.type;
  if (t === 'object') {
    if (TYPE_OF(value) !== 'object') throw new Error(`${path}: expected object, got ${TYPE_OF(value)}`);
    for (const req of schema.required || []) {
      if (!(req in value)) throw new Error(`${path}: missing required property "${req}"`);
    }
    if (schema.additionalProperties === false) {
      const allowed = new Set(Object.keys(schema.properties || {}));
      for (const k of Object.keys(value)) {
        if (!allowed.has(k)) throw new Error(`${path}: unexpected property "${k}"`);
      }
    }
    for (const [k, sub] of Object.entries(schema.properties || {})) {
      if (k in value) validate(sub, value[k], `${path}.${k}`);
    }
  } else if (t === 'array') {
    if (!Array.isArray(value)) throw new Error(`${path}: expected array, got ${TYPE_OF(value)}`);
    if (schema.minItems != null && value.length < schema.minItems) throw new Error(`${path}: minItems=${schema.minItems}, got length=${value.length}`);
    if (schema.maxItems != null && value.length > schema.maxItems) throw new Error(`${path}: maxItems=${schema.maxItems}, got length=${value.length}`);
    if (schema.items) for (let i = 0; i < value.length; i++) validate(schema.items, value[i], `${path}[${i}]`);
  } else if (t === 'string') {
    if (typeof value !== 'string') throw new Error(`${path}: expected string, got ${TYPE_OF(value)}`);
    if (schema.enum && !schema.enum.includes(value)) throw new Error(`${path}: must be one of [${schema.enum.join(', ')}]`);
    if (schema.maxLength != null && value.length > schema.maxLength) throw new Error(`${path}: maxLength=${schema.maxLength}, got length=${value.length}`);
    if (schema.minLength != null && value.length < schema.minLength) throw new Error(`${path}: minLength=${schema.minLength}, got length=${value.length}`);
  } else if (t === 'boolean') {
    if (typeof value !== 'boolean') throw new Error(`${path}: expected boolean, got ${TYPE_OF(value)}`);
  } else if (t === 'number' || t === 'integer') {
    if (typeof value !== 'number') throw new Error(`${path}: expected number, got ${TYPE_OF(value)}`);
    if (t === 'integer' && !Number.isInteger(value)) throw new Error(`${path}: expected integer`);
    if (schema.minimum != null && value < schema.minimum) throw new Error(`${path}: < minimum (${schema.minimum})`);
    if (schema.maximum != null && value > schema.maximum) throw new Error(`${path}: > maximum (${schema.maximum})`);
  }
}

;// CONCATENATED MODULE: ./src/mcp/audit.js
// Append-only audit log of MCP tool calls — OWASP MCP08.
//
// Format: one JSON object per line (NDJSON) at
//   <sessionRoot>/.agentic-security/mcp-audit.log
//
// Each entry carries `prev` — the SHA-256 of the previous entry's serialized
// form. The first entry's prev is "GENESIS". Tampering with any line breaks
// the chain from that point forward; a reader can detect partial truncation
// or in-place edits.
//
// REMOTE SINK (post-recommendation #10). The local file alone cannot detect
// a total rewrite — an attacker with FS write can re-author the whole log
// with fresh hashes. Closing that blind spot requires an off-host witness.
// Set $AGENTIC_SECURITY_AUDIT_WEBHOOK to a POST endpoint; every entry is
// fire-and-forget POSTed there in addition to the local append. Failures
// to reach the webhook are best-effort — they NEVER block a tool call,
// because that would let a network outage become a denial of service. They
// DO get recorded as `_remoteSinkErr` on the local entry, so an operator
// reviewing the log later can spot a forging attempt that targeted the
// remote (any gap between local-sequence and remote-sequence is evidence).
//
// Argument blobs are redacted (OWASP MCP01/MCP10) so credentials passed in
// arguments cannot leak via the audit trail OR via the remote sink.







const MAX_ARG_BYTES = 1024;
const GENESIS = 'GENESIS';
const REMOTE_TIMEOUT_MS = 1500;

// Per-process session ID (harness-anatomy #9). Stamped on every audit entry
// so downstream metrics can aggregate by session and surface outliers like
// "200 apply_fix calls in one session." The ID is `<pid>-<short-ts>` — not
// cryptographically unique, but enough to disambiguate concurrent runs on
// the same host. Stable for the lifetime of this Node process.
const SESSION_ID = `${process.pid}-${Date.now().toString(36).slice(-6)}`;

function _summarize(args) {
  let s;
  try { s = JSON.stringify(args); } catch { s = '<unserializable>'; }
  s = (0,redact/* redactArgsBlob */.MC)(s);
  if (s.length > MAX_ARG_BYTES) s = s.slice(0, MAX_ARG_BYTES) + `…(+${s.length - MAX_ARG_BYTES})`;
  return s;
}

function _sha(s) { return external_node_crypto_.createHash('sha256').update(s).digest('hex'); }

function _readLastEntryHash(logFile) {
  if (!external_node_fs_.existsSync(logFile)) return GENESIS;
  try {
    const all = external_node_fs_.readFileSync(logFile, 'utf8');
    const lines = all.split('\n').filter(Boolean);
    if (!lines.length) return GENESIS;
    return _sha(lines[lines.length - 1]);
  } catch { return GENESIS; }
}

// Fire-and-forget POST to the remote sink. Resolves to null on success,
// to a short error string on failure. Never throws; never blocks longer
// than REMOTE_TIMEOUT_MS. The local audit append happens regardless.
async function _postRemote(url, entry) {
  try {
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), REMOTE_TIMEOUT_MS);
    const r = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(entry),
      signal: controller.signal,
    });
    clearTimeout(t);
    if (!r.ok) return `HTTP ${r.status}`;
    return null;
  } catch (e) {
    return String((e && e.message) || e).slice(0, 200);
  }
}

function auditCall({ sessionRoot, tool, args, outcome, reason }) {
  if (!sessionRoot) return;
  try {
    // Safety: only write audit log if sessionRoot looks like a project root
    const MARKERS = ['.git', 'package.json', 'pyproject.toml', 'go.mod', 'Cargo.toml', 'pom.xml', 'composer.json', 'Gemfile'];
    let hasMarker = false;
    for (const m of MARKERS) { try { if (external_node_fs_.existsSync(external_node_path_.join(sessionRoot, m))) { hasMarker = true; break; } } catch {} }
    if (!hasMarker) return;
    const dir = (0,state_dir/* stateDir */.Pn)(sessionRoot);
    external_node_fs_.mkdirSync(dir, { recursive: true });
    const logFile = external_node_path_.join(dir, 'mcp-audit.log');
    const entry = {
      ts: new Date().toISOString(),
      sessionId: SESSION_ID,
      tool,
      outcome,
      ...(reason ? { reason } : {}),
      args: _summarize(args),
      prev: _readLastEntryHash(logFile),
    };
    external_node_fs_.appendFileSync(logFile, JSON.stringify(entry) + '\n');
    // Remote sink (post-recommendation #10). Fire-and-forget. We don't await
    // the promise so the tool call returns immediately; the remote POST runs
    // on its own microtask. Failures get logged to a sidecar file so the
    // operator can detect when the sink is unreachable.
    const webhook = process.env.AGENTIC_SECURITY_AUDIT_WEBHOOK;
    if (webhook) {
      _postRemote(webhook, entry).then((err) => {
        if (!err) return;
        try {
          const errFile = external_node_path_.join(dir, 'mcp-audit.remote-errors.log');
          external_node_fs_.appendFileSync(errFile, JSON.stringify({
            ts: new Date().toISOString(), entryTs: entry.ts, tool, err,
          }) + '\n');
        } catch { /* nothing else to do */ }
      });
    }
  } catch { /* audit failure must never break a tool call */ }
}

// Verify the chain from start to end. Returns
//   { ok: true, entries: N } if intact
//   { ok: false, brokenAt: <line-index>, expected, got } if any link breaks
// Reader/operator-facing tool.
function verifyAuditLog(logFile) {
  if (!fs.existsSync(logFile)) return { ok: true, entries: 0 };
  const text = fs.readFileSync(logFile, 'utf8');
  const lines = text.split('\n').filter(Boolean);
  let expectedPrev = GENESIS;
  for (let i = 0; i < lines.length; i++) {
    let entry;
    try { entry = JSON.parse(lines[i]); }
    catch { return { ok: false, brokenAt: i, reason: 'not JSON' }; }
    if (entry.prev !== expectedPrev) {
      return { ok: false, brokenAt: i, expected: expectedPrev, got: entry.prev };
    }
    expectedPrev = _sha(lines[i]);
  }
  return { ok: true, entries: lines.length };
}

;// CONCATENATED MODULE: ./src/mcp/server.js
// MCP server core — JSON-RPC 2.0 handler for the Model Context Protocol.
//
// Hardening posture (mapped to OWASP MCP Top 10):
//   - Session root chosen at server boot, no per-call retargeting (MCP02)
//   - Every tools/call argument validated against the tool's inputSchema (MCP02/MCP05)
//   - Every tools/call audited with a hash-chained log (MCP08)
//   - serverInfo.codeFingerprint = SHA-256 of MCP source files (MCP04/MCP09)
//     so a fleet can detect tampered or unauthorized server deployments
//   - AGENTIC_SECURITY_MCP_DISABLED=1 hard-disables all tool calls (MCP09)
//   - Stdio transport caps line/buffer size (./stdio.js) (MCP05 DoS)









const PROTOCOL_VERSION = '2025-03-26';
const SERVER_NAME = 'agentic-security';

// Premortem #6: read version from scanner/package.json at module load so the
// MCP `initialize` response can't silently drift from the shipped package
// version. A hardcoded constant rotted from 0.39.2 → wrong for every release
// that followed. Fall back to 'unknown' rather than a stale literal.
const SERVER_VERSION = (() => {
  try {
    const here = external_node_path_.dirname((0,external_node_url_.fileURLToPath)(import.meta.url));
    // scanner/src/mcp/ → scanner/package.json
    const pkgPath = external_node_path_.resolve(here, '..', '..', 'package.json');
    const pkg = JSON.parse(external_node_fs_.readFileSync(pkgPath, 'utf8'));
    if (typeof pkg.version === 'string' && pkg.version.length) return pkg.version;
  } catch { /* fall through */ }
  return 'unknown';
})();

const TOOLS_BY_NAME = Object.fromEntries(ALL_TOOLS.map(t => [t.name, t]));

// Code fingerprint — SHA-256 of the MCP source files concatenated in a
// stable order. Embedded in `initialize` response so a fleet operator can
// detect when an unapproved build is running (OWASP MCP04/MCP09).
function _codeFingerprint() {
  try {
    const here = external_node_path_.dirname((0,external_node_url_.fileURLToPath)(import.meta.url));
    const files = ['server.js', 'tools.js', 'dataflow-tools.js', 'stdio.js', 'audit.js', 'validate.js', 'redact.js'];
    const h = external_node_crypto_.createHash('sha256');
    for (const f of files) {
      try { h.update(f); h.update(external_node_fs_.readFileSync(external_node_path_.join(here, f))); } catch {}
    }
    return h.digest('hex');
  } catch { return null; }
}
const CODE_FINGERPRINT = _codeFingerprint();

function _err(id, code, message, data) {
  const out = { jsonrpc: '2.0', id, error: { code, message } };
  if (data !== undefined) out.error.data = data;
  return out;
}

function _ok(id, result) {
  return { jsonrpc: '2.0', id, result };
}

function createServer({ sessionRoot = process.cwd() } = {}) {
  const ctx = { sessionRoot };

  async function handleRequest(msg) {
    if (!msg || typeof msg !== 'object') return _err(null, -32600, 'Invalid Request');
    if (msg.jsonrpc !== '2.0') return _err(msg.id ?? null, -32600, 'Invalid Request: jsonrpc must be "2.0"');

    const isNotification = msg.id === undefined || msg.id === null;
    const id = msg.id ?? null;
    const disabled = process.env.AGENTIC_SECURITY_MCP_DISABLED === '1';

    switch (msg.method) {
      case 'initialize':
        return _ok(id, {
          protocolVersion: PROTOCOL_VERSION,
          capabilities: { tools: {} },
          serverInfo: {
            name: SERVER_NAME,
            version: SERVER_VERSION,
            codeFingerprint: CODE_FINGERPRINT,
            disabled,
          },
        });

      case 'notifications/initialized':
        return null;

      case 'ping':
        return _ok(id, {});

      case 'tools/list':
        return _ok(id, {
          tools: ALL_TOOLS.map(t => ({
            name: t.name,
            description: t.description,
            inputSchema: t.inputSchema,
          })),
        });

      case 'tools/call': {
        const name = msg.params?.name;
        const args = msg.params?.arguments ?? {};
        if (disabled) {
          auditCall({ sessionRoot, tool: name, args, outcome: 'rejected', reason: 'server-disabled' });
          return _ok(id, {
            content: [{ type: 'text', text: 'MCP server is disabled (AGENTIC_SECURITY_MCP_DISABLED=1).' }],
            isError: true,
          });
        }
        const tool = TOOLS_BY_NAME[name];
        if (!tool) {
          auditCall({ sessionRoot, tool: name, args, outcome: 'rejected', reason: 'unknown-tool' });
          return _err(id, -32602, `Unknown tool: ${name}`);
        }
        try { validate(tool.inputSchema, args); }
        catch (e) {
          auditCall({ sessionRoot, tool: name, args, outcome: 'rejected', reason: `invalid-args: ${e.message}` });
          return _ok(id, {
            content: [{ type: 'text', text: `Invalid arguments: ${e.message}` }],
            isError: true,
          });
        }
        try {
          const result = await tool.handler(args, ctx);
          auditCall({ sessionRoot, tool: name, args, outcome: 'ok' });
          return _ok(id, {
            content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
            isError: false,
          });
        } catch (e) {
          auditCall({ sessionRoot, tool: name, args, outcome: 'error', reason: e.message });
          return _ok(id, {
            content: [{ type: 'text', text: `Error: ${e.message}` }],
            isError: true,
          });
        }
      }

      default:
        if (isNotification) return null;
        return _err(id, -32601, `Method not found: ${msg.method}`);
    }
  }

  return { handleRequest, sessionRoot };
}

// NOTE: no default-singleton export. Callers must use createServer({...})
// with an explicit sessionRoot. Removed because the prior default was bound
// to process.cwd() at module-load time — a footgun for any caller that
// imported `handleRequest` directly (OWASP A05).



;// CONCATENATED MODULE: ./src/mcp/stdio.js
// Stdio transport for the MCP server — newline-delimited JSON in/out.
//
// MCP's stdio transport is NDJSON: one JSON-RPC message per line on stdin,
// one response per line on stdout. stderr is reserved for logging.
//
// Hardening:
//   - Per-message line cap (MAX_LINE_BYTES). A line over the cap is dropped
//     and the buffer state is reset so a long oversize payload can't peg
//     the parser via `buf += chunk` growth.
//   - Buffer hard cap (MAX_BUFFER_BYTES). Reached if input arrives with no
//     newlines (e.g., a peer streaming a 4GB stream of `a`). On overflow we
//     emit a parse-error response and reset.



const MAX_LINE_BYTES = 4 * 1024 * 1024;        // 4 MB per JSON-RPC message
const MAX_BUFFER_BYTES = 8 * 1024 * 1024;      // 8 MB sliding buffer

function runStdio({
  stdin = process.stdin,
  stdout = process.stdout,
  stderr = process.stderr,
  sessionRoot = process.cwd(),
} = {}) {
  const server = createServer({ sessionRoot });
  let buf = '';
  let overflowSkip = false; // true while we are dropping bytes until the next newline

  stdin.setEncoding('utf8');

  stdin.on('data', async (chunk) => {
    if (overflowSkip) {
      const nl = chunk.indexOf('\n');
      if (nl === -1) return;
      // Resume after the next newline.
      chunk = chunk.slice(nl + 1);
      overflowSkip = false;
    }

    buf += chunk;

    // Hard buffer cap — only triggers if a peer is streaming without newlines.
    if (buf.length > MAX_BUFFER_BYTES) {
      stderr.write(`mcp: input buffer exceeded ${MAX_BUFFER_BYTES} bytes — dropping until next newline\n`);
      const errResponse = { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error: input too large' } };
      stdout.write(JSON.stringify(errResponse) + '\n');
      buf = '';
      overflowSkip = true;
      return;
    }

    let nl;
    while ((nl = buf.indexOf('\n')) !== -1) {
      const line = buf.slice(0, nl).trim();
      buf = buf.slice(nl + 1);
      if (!line) continue;
      if (line.length > MAX_LINE_BYTES) {
        stderr.write(`mcp: dropped oversize line (${line.length} > ${MAX_LINE_BYTES} bytes)\n`);
        const errResponse = { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error: line too large' } };
        stdout.write(JSON.stringify(errResponse) + '\n');
        continue;
      }
      let msg;
      try { msg = JSON.parse(line); }
      catch (e) {
        stderr.write(`mcp: failed to parse line as JSON: ${e.message}\n`);
        const errResponse = { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } };
        stdout.write(JSON.stringify(errResponse) + '\n');
        continue;
      }
      try {
        const response = await server.handleRequest(msg);
        if (response !== null) stdout.write(JSON.stringify(response) + '\n');
      } catch (e) {
        stderr.write(`mcp: handler threw: ${e.message}\n`);
        const errResponse = { jsonrpc: '2.0', id: msg.id ?? null, error: { code: -32603, message: 'Internal error', data: e.message } };
        stdout.write(JSON.stringify(errResponse) + '\n');
      }
    }
  });

  stdin.on('end', () => { process.exit(0); });
}


/***/ }),

/***/ 8752:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   analyzeTranscript: () => (/* binding */ analyzeTranscript),
/* harmony export */   formatCacheReport: () => (/* binding */ formatCacheReport),
/* harmony export */   renderCacheStatusLine: () => (/* binding */ renderCacheStatusLine)
/* harmony export */ });
/* unused harmony export _internal */
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(3024);
/* harmony import */ var node_os__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(8161);
/* harmony import */ var node_path__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(6760);
// Prompt-cache economics — turn Claude Code's own transcript usage into a
// dollarized report: how much prompt caching saved, how much was wasted on
// avoidable cache misses, and what invalidated the cache.
//
// Source of truth: the Claude Code transcript at
//   ~/.claude/projects/<enc>/<session>.jsonl
// where <enc> is CLAUDE_PROJECT_DIR with `/` and `.` replaced by `-`. Each
// assistant turn carries `message.usage` with input/output/cache_read/
// cache_creation token counts (and a 5m/1h write split). We price those against
// per-model rates to compute real economics — no estimates, no network.
//
// Pure compute on parsed records; only `locateTranscript`/`parseTranscriptUsage`
// touch the filesystem. ESM (scanner tree). A trimmed CJS twin lives at
// hooks/lib/transcript.js for the CJS hooks; test/cache-economics.test.js asserts
// the two agree.




// Cents-scale money formatter (fmtUsd in risk-dollars.js targets five-figure
// breach costs and won't round sub-dollar values).
function money(n) {
  const v = Number(n) || 0;
  return Math.abs(v) >= 1 ? `$${v.toFixed(2)}` : `$${v.toFixed(4)}`;
}

// Per-1M-token rates (input / output). Mirror hooks/model-cost-advisor.js MODELS.
const MODEL_RATES = {
  fable:   { label: 'Fable 5',    in: 10, out: 50 },
  opus:    { label: 'Opus 4.8',   in: 5,  out: 25 },
  sonnet5: { label: 'Sonnet 5',   in: 3,  out: 15 },
  sonnet:  { label: 'Sonnet 4.6', in: 3,  out: 15 },
  haiku:   { label: 'Haiku 4.5',  in: 1,  out: 5 },
};
const CACHE_READ_MULT = 0.1;   // cache read ≈ 0.1× input
const CACHE_WRITE_MULT = 1.25; // 5-minute cache write ≈ 1.25× input
const CACHE_WRITE_1H_MULT = 2.0; // 1-hour cache write ≈ 2× input
const TTL_MS = 5 * 60 * 1000;

// Map any model string to a rate family. Returns null for unpriceable models
// (e.g. "<synthetic>" sidechain/compaction turns) so they're skipped.
function rateFor(model) {
  if (typeof model !== 'string') return null;
  const s = model.toLowerCase();
  if (s.includes('fable') || s.includes('mythos')) return MODEL_RATES.fable;
  if (s.includes('haiku')) return MODEL_RATES.haiku;
  if (s.includes('sonnet')) return (s.includes('sonnet-5') || s.includes('sonnet 5')) ? MODEL_RATES.sonnet5 : MODEL_RATES.sonnet;
  if (s.includes('opus')) return MODEL_RATES.opus;
  return null;
}

// ── Transcript discovery + parse ─────────────────────────────────────────────

function encodeProjectDir(dir) {
  return String(dir).replace(/[/.]/g, '-');
}

// Locate the session transcript. Prefer an explicit (hook-provided) path; else
// derive the project's transcript dir and take the most-recently-modified jsonl.
function locateTranscript({ transcriptPath, projectDir } = {}) {
  try {
    if (transcriptPath && node_fs__WEBPACK_IMPORTED_MODULE_0__.existsSync(transcriptPath)) return transcriptPath;
  } catch { /* fall through */ }
  try {
    const dir = node_path__WEBPACK_IMPORTED_MODULE_2__.join(node_os__WEBPACK_IMPORTED_MODULE_1__.homedir(), '.claude', 'projects', encodeProjectDir(projectDir || process.cwd()));
    if (!node_fs__WEBPACK_IMPORTED_MODULE_0__.existsSync(dir)) return null;
    const files = node_fs__WEBPACK_IMPORTED_MODULE_0__.readdirSync(dir)
      .filter(f => f.endsWith('.jsonl'))
      .map(f => ({ f: node_path__WEBPACK_IMPORTED_MODULE_2__.join(dir, f), m: node_fs__WEBPACK_IMPORTED_MODULE_0__.statSync(node_path__WEBPACK_IMPORTED_MODULE_2__.join(dir, f)).mtimeMs }))
      .sort((a, b) => b.m - a.m);
    return files.length ? files[0].f : null;
  } catch { return null; }
}

// Parse a transcript jsonl into per-assistant-turn usage records. Skips lines
// that aren't priceable assistant turns.
function parseTranscriptUsage(jsonlPath) {
  let raw;
  try { raw = node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(jsonlPath, 'utf8'); } catch { return []; }
  const records = [];
  for (const line of raw.split('\n')) {
    const t = line.trim();
    if (!t) continue;
    let o;
    try { o = JSON.parse(t); } catch { continue; }
    if (o.type !== 'assistant') continue;
    const msg = o.message;
    const u = msg && msg.usage;
    if (!u || !msg.model || !rateFor(msg.model)) continue;
    const cc = u.cache_creation || {};
    records.push({
      model: msg.model,
      input: u.input_tokens || 0,
      output: u.output_tokens || 0,
      cacheRead: u.cache_read_input_tokens || 0,
      cacheCreate: u.cache_creation_input_tokens || 0,
      cacheCreate5m: cc.ephemeral_5m_input_tokens || 0,
      cacheCreate1h: cc.ephemeral_1h_input_tokens || 0,
      ts: o.timestamp ? Date.parse(o.timestamp) : null,
    });
  }
  return records;
}

// ── Pure economics ───────────────────────────────────────────────────────────

function writeCostUsd(r, inRate) {
  const m5 = r.cacheCreate5m || 0, m1 = r.cacheCreate1h || 0;
  if (m5 + m1 > 0) return (m5 * CACHE_WRITE_MULT + m1 * CACHE_WRITE_1H_MULT) * inRate;
  return (r.cacheCreate || 0) * CACHE_WRITE_MULT * inRate; // breakdown absent
}

// Aggregate economics over parsed records.
function computeCacheEconomics(records) {
  let turns = 0, inTok = 0, outTok = 0, cacheRead = 0, cacheCreate = 0;
  let actualUsd = 0, uncachedUsd = 0, writePremiumUsd = 0;
  const perModel = {};

  for (const r of records) {
    const rate = rateFor(r.model);
    if (!rate) continue;
    turns++;
    const inRate = rate.in / 1e6, outRate = rate.out / 1e6;

    const readCost = r.cacheRead * inRate * CACHE_READ_MULT;
    const writeCost = writeCostUsd(r, inRate);
    const inCost = r.input * inRate;
    const outCost = r.output * outRate;
    const turnActual = readCost + writeCost + inCost + outCost;
    // What this turn would have cost with NO caching: every input-side token full price.
    const turnUncached = (r.cacheRead + r.cacheCreate + r.input) * inRate + outCost;

    actualUsd += turnActual;
    uncachedUsd += turnUncached;
    writePremiumUsd += writeCost - (r.cacheCreate * inRate); // the >1× premium paid to cache

    inTok += r.input; outTok += r.output; cacheRead += r.cacheRead; cacheCreate += r.cacheCreate;

    const key = rate.label;
    const pm = perModel[key] || (perModel[key] = { turns: 0, actualUsd: 0, cacheRead: 0, inputSide: 0 });
    pm.turns++; pm.actualUsd += turnActual; pm.cacheRead += r.cacheRead;
    pm.inputSide += r.cacheRead + r.cacheCreate + r.input;
  }

  const inputSide = cacheRead + cacheCreate + inTok;
  return {
    turns,
    tokens: { input: inTok, output: outTok, cacheRead, cacheCreate },
    actualUsd,
    uncachedUsd,
    savedUsd: uncachedUsd - actualUsd,         // net $ caching saved (can dip negative early)
    writePremiumUsd,                            // $ invested establishing caches
    cacheHitRatio: inputSide ? cacheRead / inputSide : 0,
    costPerTurnUsd: turns ? actualUsd / turns : 0,
    perModel,
  };
}

// Attribute cache drops: a turn that re-ingests a large prefix cold after a warm
// prior turn. Cause = model-switch | cache-expired | prefix-change.
function detectInvalidators(records) {
  const leaks = [];
  const MIN_WARM = 2000;
  for (let i = 1; i < records.length; i++) {
    const prev = records[i - 1], cur = records[i];
    const prevWarm = prev.cacheRead + prev.input + prev.cacheCreate;
    if (prevWarm < MIN_WARM) continue;
    const curFresh = cur.input + cur.cacheCreate;
    const coldish = cur.cacheRead < prevWarm * 0.25 && curFresh > prevWarm * 0.5;
    if (!coldish) continue;

    let cause;
    if (cur.model !== prev.model) cause = 'model-switch';
    else if (cur.ts && prev.ts && (cur.ts - prev.ts) > TTL_MS) cause = 'cache-expired';
    else cause = 'prefix-change';

    const rate = rateFor(cur.model);
    const inRate = rate ? rate.in / 1e6 : 0;
    // Extra paid vs. having kept the prefix as a cheap cache read.
    const wastedUsd = prevWarm * inRate * (1 - CACHE_READ_MULT);
    leaks.push({ turn: i, cause, wastedUsd, model: cur.model });
  }
  return leaks;
}

// Convenience: locate → parse → compute → detect. Returns { ok:false } when no
// transcript is available.
function analyzeTranscript(opts = {}) {
  const transcript = locateTranscript(opts);
  if (!transcript) return { ok: false, reason: 'no-transcript' };
  const records = parseTranscriptUsage(transcript);
  if (!records.length) return { ok: false, reason: 'no-priceable-turns', transcript };
  return {
    ok: true,
    transcript,
    metrics: computeCacheEconomics(records),
    leaks: detectInvalidators(records),
  };
}

// ── Report formatting ────────────────────────────────────────────────────────

const CAUSE_LABEL = {
  'model-switch': 'model switch (cache is model-scoped)',
  'cache-expired': 'cache expired (gap > 5-min TTL)',
  'prefix-change': 'prefix changed (system prompt / tools / context edit)',
};

// F6 — one-line HUD for a Claude Code statusLine command (mirrors
// watch-mode.js renderStatusLine). Takes the metrics from computeCacheEconomics.
function renderCacheStatusLine(metrics) {
  if (!metrics || !metrics.turns) return 'agentic-security: no session cost yet';
  const hit = Math.round(metrics.cacheHitRatio * 100);
  return `agentic-security: ${money(metrics.actualUsd)} · ${hit}% cached · ${money(metrics.costPerTurnUsd)}/turn`;
}

function formatCacheReport(result) {
  if (!result.ok) {
    return result.reason === 'no-transcript'
      ? 'agentic-security: no Claude Code transcript found for this project yet.'
      : 'agentic-security: transcript has no priceable model turns yet.';
  }
  const m = result.metrics;
  const lines = [];
  lines.push('');
  lines.push('  Prompt-cache economics — this session');
  lines.push(`  ${result.turns ?? m.turns} model turns\n`);
  lines.push(`  cache hit ratio     ${(m.cacheHitRatio * 100).toFixed(1)}%  (input-side tokens served from cache)`);
  lines.push(`  spent               ${money(m.actualUsd)}   (~${money(m.costPerTurnUsd)}/turn)`);
  lines.push(`  ▶ saved by caching  ${money(m.savedUsd)}   vs. ${money(m.uncachedUsd)} with no cache`);
  lines.push(`  invested in caches  ${money(m.writePremiumUsd)}   (write premium over base input)`);
  lines.push('');
  lines.push('  tokens: '
    + `${m.tokens.cacheRead.toLocaleString()} cached-read · `
    + `${m.tokens.cacheCreate.toLocaleString()} cache-write · `
    + `${m.tokens.input.toLocaleString()} fresh-in · `
    + `${m.tokens.output.toLocaleString()} out`);

  const models = Object.keys(m.perModel);
  if (models.length > 1) {
    lines.push('\n  by model:');
    for (const k of models.sort()) {
      const pm = m.perModel[k];
      const hr = pm.inputSide ? (pm.cacheRead / pm.inputSide * 100).toFixed(0) : '0';
      lines.push(`    ${k.padEnd(12)} ${pm.turns} turns · ${money(pm.actualUsd)} · ${hr}% cached`);
    }
  }

  if (result.leaks && result.leaks.length) {
    const wasted = result.leaks.reduce((s, l) => s + l.wastedUsd, 0);
    lines.push(`\n  ⚠ cache leaks (${result.leaks.length}, ~${money(wasted)} wasted re-ingesting context):`);
    const byCause = {};
    for (const l of result.leaks) {
      (byCause[l.cause] || (byCause[l.cause] = { n: 0, usd: 0 })).n++;
      byCause[l.cause].usd += l.wastedUsd;
    }
    for (const c of Object.keys(byCause).sort()) {
      lines.push(`    · ${byCause[c].n}× ${CAUSE_LABEL[c] || c} — ~${money(byCause[c].usd)}`);
    }
    lines.push('    Keep one model + a stable system prompt within a working window to avoid these.');
  } else {
    lines.push('\n  ✓ no cache leaks detected — your context stayed warm.');
  }
  lines.push('');
  return lines.join('\n');
}

// Test surface (underscore export is exempt from the dead-module gate).
const _internal = {
  MODEL_RATES, CACHE_READ_MULT, CACHE_WRITE_MULT, CACHE_WRITE_1H_MULT,
  rateFor, locateTranscript, parseTranscriptUsage, computeCacheEconomics, detectInvalidators,
};


/***/ }),

/***/ 8218:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   loadSignedGraph: () => (/* binding */ loadSignedGraph)
/* harmony export */ });
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(3024);
/* harmony import */ var _posture_state_dir_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(1174);
/* harmony import */ var _posture_integrity_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(1130);
// graph-loader.js — Milestone 3, sub-project Server, increment 1.
//
// Reads and VERIFIES the `.agentic-security/lineage-graph.json` artifact
// before `explore` is allowed to serve a single byte of it. Reuses
// `posture/integrity.js`'s `verifyLastScan` DIRECTLY (per the plan and the
// root CLAUDE.md's own instruction) — this module does not implement any
// signature comparison of its own. `verifyLastScan` already uses
// `crypto.timingSafeEqual` internally.
//
// Loaded ONCE at server startup (see bin/agentic-security.js's cmdExplore)
// and held in memory for the life of the process — this is a read-only,
// single-scan-snapshot server; a change to the graph on disk mid-session is
// out of scope for this increment (threat-model doc's own "P0 is
// read-only" framing).





/**
 * @param {string} scanRoot
 * @returns {{ok:true, graph:object} | {ok:false, reason:'missing'|'unsigned'|'tampered'|'malformed', message:string}}
 *
 * Four, and only four, distinct failure reasons — each with its own clear
 * message so an operator knows exactly what to do next:
 *   - 'missing'  — no lineage-graph.json at all. Run a scan with
 *                  AGENTIC_SECURITY_LINEAGE_DEEP=1 first.
 *   - 'unsigned' — the graph exists but its .sig sibling does not
 *                  (verifyLastScan returns null). Refuse to serve an
 *                  unverifiable graph.
 *   - 'tampered' — the graph exists and has a .sig, but the signature does
 *                  not match the body (verifyLastScan returns false). The
 *                  file was modified after signing, or signed under a
 *                  different install key.
 *   - 'malformed' — the body passed signature verification but is not
 *                  valid JSON. Should not happen from a normal scan; the
 *                  file may be corrupted on disk after signing.
 */
function loadSignedGraph(scanRoot) {
  const graphPath = (0,_posture_state_dir_js__WEBPACK_IMPORTED_MODULE_1__/* .statePath */ .BQ)(scanRoot, 'lineage-graph.json');
  const sigPath = graphPath + '.sig';

  if (!node_fs__WEBPACK_IMPORTED_MODULE_0__.existsSync(graphPath)) {
    return {
      ok: false,
      reason: 'missing',
      message: `No lineage graph found at ${graphPath}. Run a scan with AGENTIC_SECURITY_LINEAGE_DEEP=1 first (e.g. \`AGENTIC_SECURITY_LINEAGE_DEEP=1 agentic-security scan\`), then re-run \`agentic-security explore\`.`,
    };
  }

  let body;
  try {
    body = node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(graphPath, 'utf8');
  } catch (e) {
    return {
      ok: false,
      reason: 'missing',
      message: `Lineage graph found at ${graphPath} but could not be read: ${e && e.message ? e.message : e}.`,
    };
  }

  const verified = (0,_posture_integrity_js__WEBPACK_IMPORTED_MODULE_2__/* .verifyLastScan */ .Ef)(body, sigPath);
  if (verified === null) {
    return {
      ok: false,
      reason: 'unsigned',
      message: `Lineage graph at ${graphPath} has no signature file (${sigPath} is missing). Refusing to serve an unverifiable graph. Re-run the scan (AGENTIC_SECURITY_LINEAGE_DEEP=1) to regenerate both files together.`,
    };
  }
  if (verified === false) {
    return {
      ok: false,
      reason: 'tampered',
      message: `Lineage graph at ${graphPath} FAILED signature verification — its contents do not match ${sigPath}. The file may have been modified after the scan, or signed under a different install key. Refusing to serve a tampered graph. Re-run the scan to regenerate it.`,
    };
  }

  let graph;
  try {
    graph = JSON.parse(body);
  } catch (e) {
    return {
      ok: false,
      reason: 'malformed',
      message: `Lineage graph at ${graphPath} passed signature verification but is not valid JSON (${e && e.message ? e.message : e}). This should not happen from a normal scan — the file may be corrupted. Re-run the scan to regenerate it.`,
    };
  }

  return { ok: true, graph };
}


/***/ }),

/***/ 4268:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   Yo: () => (/* binding */ handleScan),
/* harmony export */   Yu: () => (/* binding */ handleEdge),
/* harmony export */   d5: () => (/* binding */ handleNode),
/* harmony export */   fn: () => (/* binding */ handleGraph),
/* harmony export */   jg: () => (/* binding */ handleFlow)
/* harmony export */ });
/* unused harmony export wrapResponse */
// routes.js — Milestone 3, sub-project Server, increment 1.
//
// Five pure GET-endpoint handlers, each `(graph, ...) -> {status, body}`.
// No req/res access anywhere in this file — that is what makes these
// handlers unit-testable without an HTTP layer at all. http-server.js is
// the only module that touches node:http and calls into these.
//
// Every response body is wrapped in `wrapResponse`, which adds the exact
// envelope fields PRD line 1326 names (quoted in the implementation plan):
// "base graph/snapshot digest, schema/extension versions, scope, coverage,
// limitations, and contributing canonical IDs."

/**
 * Shared response envelope. Maps PRD line 1326's required fields onto the
 * graph's own real fields:
 *   - digest              -> graph.graphId (the base graph/snapshot digest)
 *   - schemaVersion        -> graph.schemaVersion
 *   - extensions           -> graph.extensions (schema/extension versions —
 *                             today always `{}`; see schema.js)
 *   - scope                -> graph.scope
 *   - coverage              -> graph.coverage
 *   - limitations           -> graph.limitations
 *   - canonicalIds          -> see the design note below
 *
 * "contributing canonical IDs" design decision (disclosed per the plan):
 * for `handleScan`/`handleGraph`, which describe the WHOLE graph rather
 * than one entity, `canonicalIds` is `null` — the response body for
 * `handleGraph` already IS the full nodes/edges/flows arrays, so echoing
 * every id again here would be pure duplication with no informational
 * gain, and for a large graph would materially bloat the response for
 * zero benefit. For `handleNode`/`handleEdge`, `canonicalIds` is the
 * single id the response is about. For `handleFlow`, `canonicalIds` is
 * the flow's own id PLUS the node/edge ids that flow's evidence draws
 * from (source, sink, edgeIds) — a flow is a derived record referencing
 * several underlying entities, and naming all of them here is genuinely
 * useful metadata a client would otherwise have to re-derive from the
 * flow body itself.
 */
function wrapResponse(data, graph, { canonicalIds = null } = {}) {
  return {
    digest: graph?.graphId ?? null,
    schemaVersion: graph?.schemaVersion ?? null,
    extensions: graph?.extensions ?? {},
    scope: graph?.scope ?? null,
    coverage: graph?.coverage ?? null,
    limitations: graph?.limitations ?? [],
    canonicalIds,
    data,
  };
}

function _findById(list, id) {
  if (!Array.isArray(list)) return null;
  return list.find((item) => item && item.id === id) ?? null;
}

/** Scan/graph metadata — NOT the full node/edge arrays. */
function handleScan(graph) {
  const data = {
    schemaVersion: graph?.schemaVersion ?? null,
    graphId: graph?.graphId ?? null,
    generatedAt: graph?.generatedAt ?? null,
    scope: graph?.scope ?? null,
    scanHealth: graph?.scanHealth ?? null,
    coverage: graph?.coverage ?? null,
  };
  return { status: 200, body: wrapResponse(data, graph, { canonicalIds: null }) };
}

/** The full graph document. No pagination/filtering in S1 (that's `query`'s job, S2). */
function handleGraph(graph) {
  return { status: 200, body: wrapResponse(graph, graph, { canonicalIds: null }) };
}

/** Look up one node by id. 404 with a clear body if not found. */
function handleNode(graph, id) {
  const node = _findById(graph?.nodes, id);
  if (!node) {
    return { status: 404, body: wrapResponse({ error: `node not found: ${id}` }, graph, { canonicalIds: [] }) };
  }
  return { status: 200, body: wrapResponse(node, graph, { canonicalIds: [id] }) };
}

/** Look up one edge by id. 404 with a clear body if not found. */
function handleEdge(graph, id) {
  const edge = _findById(graph?.edges, id);
  if (!edge) {
    return { status: 404, body: wrapResponse({ error: `edge not found: ${id}` }, graph, { canonicalIds: [] }) };
  }
  return { status: 200, body: wrapResponse(edge, graph, { canonicalIds: [id] }) };
}

/** Look up one flow by id. 404 with a clear body if not found. */
function handleFlow(graph, id) {
  const flow = _findById(graph?.flows, id);
  if (!flow) {
    return { status: 404, body: wrapResponse({ error: `flow not found: ${id}` }, graph, { canonicalIds: [] }) };
  }
  const contributing = new Set([id]);
  if (flow.source) contributing.add(flow.source);
  if (flow.sink) contributing.add(flow.sink);
  for (const eid of (flow.edgeIds || [])) contributing.add(eid);
  return { status: 200, body: wrapResponse(flow, graph, { canonicalIds: [...contributing] }) };
}


/***/ })

};
