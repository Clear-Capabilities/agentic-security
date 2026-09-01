# Milestone 4, sub-project MCP tools — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expose the `DataFlowGraph v1` artifact read-only via 4 new MCP tools (`dataflow_get_graph`, `dataflow_get_node`, `dataflow_get_edge`, `dataflow_get_flow`), so an MCP agent client can query the lineage graph the same way it already queries scan findings via `query_taint`/`explain_finding`.

**Architecture:** A new thin adapter module, `scanner/src/mcp/dataflow-tools.js`, wraps two ALREADY-BUILT, unmodified pieces: `scanner/src/server/graph-loader.js`'s `loadSignedGraph(scanRoot)` (signed-artifact load + verify) and `scanner/src/server/routes.js`'s pure handler functions (`handleGraph`/`handleNode`/`handleEdge`/`handleFlow`). No new graph-query logic is written — this sub-project is pure wiring plus MCP-shaped error handling and evidence-note redaction.

**Tech Stack:** Node ESM, `node:test`, no new npm dependency (matches `scanner/src/server/CLAUDE.md`'s own "no new npm dependency, ever, without re-opening this decision first" convention — this plan does not need one).

**Spec:** `docs/superpowers/plans/2026-09-01-data-flow-explorer-m4-mcp-tools-scoping.md` (this sub-project's own scoping doc) and `docs/superpowers/plans/2026-09-01-data-flow-explorer-m4-scoping.md` (the M4 top-level doc). PRD deliverable: "MCP read-only tools" (§26, Milestone 4).

## Global Constraints

- **Read-only.** None of the 4 new tools writes anything, anywhere. No `RESERVED_WRITE_*` concerns apply.
- **Reuse, never fork, `loadSignedGraph` and the 4 `routes.js` handlers.** Do not reimplement graph lookup/traversal logic inside `scanner/src/mcp/`.
- **Every tool's failure path returns a structured result, never throws**, for all 4 of `loadSignedGraph`'s failure reasons (`missing`/`unsigned`/`tampered`/`malformed`) — mirrors `query_taint`'s own "No usable scan state" precedent (`scanner/src/mcp/tools.js:478-481`), not `explain_finding`'s `throw new Error(...)` precedent (`scanner/src/mcp/tools.js:530`). A missing/tampered graph is an expected, first-class outcome for a tool an agent may call before any deep-mode scan has run — not an exceptional one.
- **`META = { source: 'agentic-security-mcp', untrusted_excerpts: true }`** (already defined at `scanner/src/mcp/tools.js:52`) is included as `_meta` on every successful result, matching every other read-only tool in the file.
- **Audit logging requires no new code** — confirmed this session: `scanner/src/mcp/server.js` calls `auditCall` generically for every registered tool's `ok`/`error`/`rejected` outcome. Registering the 4 tools in `ALL_TOOLS` (Task 2) is sufficient.
- **No dependency on `frontend/`.** `lib/query-language.js`'s query grammar is explicitly OUT of scope for this sub-project (a `dataflow_query` tool is deferred — see the scoping doc's own "Explicitly deferred" section).

---

## Task 1: `dataflow-tools.js` — the 4 tool definitions

**Files:**
- Create: `scanner/src/mcp/dataflow-tools.js`
- Test: `scanner/test/mcp-dataflow-tools.test.js`

**Interfaces:**
- Consumes: `loadSignedGraph(scanRoot)` from `scanner/src/server/graph-loader.js` (returns `{ok:true, graph}` or `{ok:false, reason, message}`, `reason` one of `'missing'|'unsigned'|'tampered'|'malformed'`); `handleGraph(graph)`, `handleNode(graph, id)`, `handleEdge(graph, id)`, `handleFlow(graph, id)` from `scanner/src/server/routes.js` (each returns `{status, body}`, `body = wrapResponse(data, graph, {canonicalIds})`); `redactString` from `scanner/src/mcp/redact.js` (confirm its exact export name and signature by reading the file before use — do not guess).
- Produces: `dataflow_get_graph`, `dataflow_get_node`, `dataflow_get_edge`, `dataflow_get_flow` — 4 named exports, each `{name, description, inputSchema, async handler(args, ctx)}`, the exact shape `query_taint`/`explain_finding` already use (`scanner/src/mcp/tools.js:463-514`). `ctx.sessionRoot` is the scan root (same contract every existing tool handler already relies on).

- [ ] **Step 1: Write the failing tests for the shared graph-loading helper and all 4 tools' success/failure paths**

Create `scanner/test/mcp-dataflow-tools.test.js`. Reuse the exact temp-project + signed-graph fixture pattern from `scanner/test/server/graph-loader.test.js` (`_mkTmpProject`/`_writeGraph`, copied — this test file is independent of `test/server/`, so duplicate the ~15-line helpers rather than importing across the `test/` vs `test/server/` boundary, matching how other `scanner/test/*.test.js` files each define their own tmp-project helper rather than sharing one).

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { signLastScan } from '../src/posture/integrity.js';
import { statePath } from '../src/posture/state-dir.js';
import {
  dataflow_get_graph,
  dataflow_get_node,
  dataflow_get_edge,
  dataflow_get_flow,
} from '../src/mcp/dataflow-tools.js';

function _mkTmpProject() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agsec-mcp-dataflow-'));
  fs.writeFileSync(path.join(root, 'package.json'), '{"name":"tmp","version":"1.0.0"}');
  return root;
}

function _writeGraph(root, graphObj, { sign = true } = {}) {
  const graphPath = statePath(root, 'lineage-graph.json');
  fs.mkdirSync(path.dirname(graphPath), { recursive: true });
  const body = JSON.stringify(graphObj, null, 2);
  fs.writeFileSync(graphPath, body);
  if (sign) fs.writeFileSync(graphPath + '.sig', signLastScan(body));
  return graphPath;
}

const SAMPLE_GRAPH = {
  schemaVersion: '1.0.0',
  graphId: 'dfg:test-sample',
  extensions: {},
  scope: { root: '/tmp/fixture' },
  coverage: null,
  limitations: [],
  nodes: [{ id: 'node:api', kind: 'source', subtype: 'http-endpoint' }],
  edges: [{ id: 'edge:api-db', from: 'node:api', to: 'node:store', protection: {} }],
  flows: [{ id: 'flow:1', source: 'node:api', sink: 'node:store', edgeIds: ['edge:api-db'] }],
};

const TOOLS = {
  dataflow_get_graph,
  dataflow_get_node,
  dataflow_get_edge,
  dataflow_get_flow,
};

for (const [toolName, tool] of Object.entries(TOOLS)) {
  test(`${toolName}: missing graph -> hasResult:false, reason "missing"`, async () => {
    const root = _mkTmpProject();
    try {
      const args = toolName === 'dataflow_get_graph' ? {} : { id: 'node:api' };
      const result = await tool.handler(args, { sessionRoot: root });
      assert.equal(result.hasResult, false);
      assert.equal(result.reason, 'missing');
      assert.match(result.message, /No lineage graph found/);
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  test(`${toolName}: unsigned graph -> hasResult:false, reason "unsigned"`, async () => {
    const root = _mkTmpProject();
    try {
      _writeGraph(root, SAMPLE_GRAPH, { sign: false });
      const args = toolName === 'dataflow_get_graph' ? {} : { id: 'node:api' };
      const result = await tool.handler(args, { sessionRoot: root });
      assert.equal(result.hasResult, false);
      assert.equal(result.reason, 'unsigned');
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  test(`${toolName}: tampered graph -> hasResult:false, reason "tampered"`, async () => {
    const root = _mkTmpProject();
    try {
      _writeGraph(root, SAMPLE_GRAPH);
      // Tamper AFTER signing, matching graph-loader.test.js's own precedent.
      const graphPath = statePath(root, 'lineage-graph.json');
      fs.writeFileSync(graphPath, JSON.stringify({ ...SAMPLE_GRAPH, graphId: 'dfg:tampered' }, null, 2));
      const args = toolName === 'dataflow_get_graph' ? {} : { id: 'node:api' };
      const result = await tool.handler(args, { sessionRoot: root });
      assert.equal(result.hasResult, false);
      assert.equal(result.reason, 'tampered');
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
}

test('dataflow_get_graph: real signed graph -> hasResult:true, full graph body', async () => {
  const root = _mkTmpProject();
  try {
    _writeGraph(root, SAMPLE_GRAPH);
    const result = await dataflow_get_graph.handler({}, { sessionRoot: root });
    assert.equal(result.hasResult, true);
    assert.equal(result._meta.source, 'agentic-security-mcp');
    assert.equal(result.data.graphId, 'dfg:test-sample');
    assert.equal(result.data.nodes.length, 1);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('dataflow_get_node: real signed graph, found -> the node', async () => {
  const root = _mkTmpProject();
  try {
    _writeGraph(root, SAMPLE_GRAPH);
    const result = await dataflow_get_node.handler({ id: 'node:api' }, { sessionRoot: root });
    assert.equal(result.hasResult, true);
    assert.equal(result.data.id, 'node:api');
    assert.deepEqual(result.canonicalIds, ['node:api']);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('dataflow_get_node: real signed graph, not found -> hasResult:true, 404-shaped body', async () => {
  const root = _mkTmpProject();
  try {
    _writeGraph(root, SAMPLE_GRAPH);
    const result = await dataflow_get_node.handler({ id: 'node:does-not-exist' }, { sessionRoot: root });
    // The graph loaded and verified fine; the ID just wasn't found — this is
    // NOT a loadSignedGraph failure, so hasResult stays true (matching
    // routes.js's own handleNode, which returns status:404 with a body,
    // never throws). Distinguish via `.notFound`, set true only on this path.
    assert.equal(result.hasResult, true);
    assert.equal(result.notFound, true);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('dataflow_get_edge: real signed graph, found -> the edge', async () => {
  const root = _mkTmpProject();
  try {
    _writeGraph(root, SAMPLE_GRAPH);
    const result = await dataflow_get_edge.handler({ id: 'edge:api-db' }, { sessionRoot: root });
    assert.equal(result.hasResult, true);
    assert.equal(result.data.id, 'edge:api-db');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('dataflow_get_flow: real signed graph, found -> the flow with contributing canonicalIds', async () => {
  const root = _mkTmpProject();
  try {
    _writeGraph(root, SAMPLE_GRAPH);
    const result = await dataflow_get_flow.handler({ id: 'flow:1' }, { sessionRoot: root });
    assert.equal(result.hasResult, true);
    assert.equal(result.data.id, 'flow:1');
    // handleFlow's own contract: canonicalIds = [flow id, source, sink, ...edgeIds]
    assert.ok(result.canonicalIds.includes('node:api'));
    assert.ok(result.canonicalIds.includes('edge:api-db'));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('dataflow_get_graph: inputSchema rejects unknown properties', () => {
  assert.equal(dataflow_get_graph.inputSchema.additionalProperties, false);
});

test('dataflow_get_node: inputSchema requires id', () => {
  assert.deepEqual(dataflow_get_node.inputSchema.required, ['id']);
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `node --test test/mcp-dataflow-tools.test.js` (from `scanner/`)
Expected: FAIL — `Cannot find module '../src/mcp/dataflow-tools.js'` (file does not exist yet).

- [ ] **Step 3: Read `redact.js` to confirm its exact export before use**

Run: `grep -n "^export" scanner/src/mcp/redact.js`. Confirm the redaction function's real name and signature (this plan's own author has not re-verified it against current source — do not assume `redactString(s)` is the exact signature; read it and use whatever it actually is). Apply it to `evidence[].location.note` fields only, per the scoping doc's own decision 5 — every other field on a node/edge/flow (kind, subtype, verdicts, IDs, `storeDetail`/`queueDetail`) is structural/category-level, never raw code, and is NOT redacted.

- [ ] **Step 4: Implement `scanner/src/mcp/dataflow-tools.js`**

```js
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

import { loadSignedGraph } from '../server/graph-loader.js';
import { handleGraph, handleNode, handleEdge, handleFlow } from '../server/routes.js';
// import { redactString } from './redact.js'; // exact name confirmed in Step 3

const META = { source: 'agentic-security-mcp', untrusted_excerpts: false };

function _loadOrFailure(sessionRoot) {
  const loaded = loadSignedGraph(sessionRoot);
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

// Redacts evidence[].location.note in place on a COPY of the graph slice
// being returned — never mutates the loaded graph object, which may be
// reused across calls within the same process lifetime by other tools.
function _redactEvidenceNotes(data) {
  if (!data || !Array.isArray(data.evidence)) return data;
  return {
    ...data,
    evidence: data.evidence.map((e) => {
      if (!e?.location?.note) return e;
      return { ...e, location: { ...e.location, note: /* redactString(e.location.note) */ e.location.note } };
    }),
  };
}

export const dataflow_get_graph = {
  name: 'dataflow_get_graph',
  description: 'Return the full DataFlowGraph v1 artifact from the last signed, verified deep-mode scan: nodes, edges, flows, scope, coverage, and limitations. Requires a prior `AGENTIC_SECURITY_LINEAGE_DEEP=1 agentic-security scan`.',
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: {},
  },
  async handler(_args, ctx) {
    const { graph, failure } = _loadOrFailure(ctx.sessionRoot);
    if (failure) return failure;
    const { status, body } = handleGraph(graph);
    return {
      _meta: META,
      hasResult: true,
      status,
      data: _redactEvidenceNotes(body.data),
      digest: body.digest,
      schemaVersion: body.schemaVersion,
      scope: body.scope,
      coverage: body.coverage,
      limitations: body.limitations,
    };
  },
};

export const dataflow_get_node = {
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
    const { status, body } = handleNode(graph, id);
    return {
      _meta: META,
      hasResult: true,
      notFound: status === 404,
      data: body.data,
      canonicalIds: body.canonicalIds,
    };
  },
};

export const dataflow_get_edge = {
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
    const { status, body } = handleEdge(graph, id);
    return {
      _meta: META,
      hasResult: true,
      notFound: status === 404,
      data: body.data,
      canonicalIds: body.canonicalIds,
    };
  },
};

export const dataflow_get_flow = {
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
    const { status, body } = handleFlow(graph, id);
    return {
      _meta: META,
      hasResult: true,
      notFound: status === 404,
      data: body.data,
      canonicalIds: body.canonicalIds,
    };
  },
};
```

**Important re-verification note for the implementer:** the code above is written from a direct read of `graph-loader.js`/`routes.js` earlier in this planning pass, but re-read both files yourself before trusting field names verbatim (`body.data`/`body.digest`/etc. come from `wrapResponse`'s exact shape — confirmed at `scanner/src/server/routes.js:39-50` as of this plan's writing, but re-confirm, per this repo's own verification-discipline convention). Do not skip Step 3's `redact.js` check — the commented-out `redactString(...)` calls above are placeholders and MUST be replaced with a real call before this task is done; ship nothing with evidence notes unredacted.

- [ ] **Step 5: Run tests to verify they pass**

Run: `node --test test/mcp-dataflow-tools.test.js` (from `scanner/`)
Expected: PASS, all tests green.

- [ ] **Step 6: Commit**

```bash
git add scanner/src/mcp/dataflow-tools.js scanner/test/mcp-dataflow-tools.test.js
git commit -m "feat(mcp): add dataflow-tools.js — 4 read-only DataFlowGraph MCP tool definitions"
```

---

## Task 2: Register the 4 tools, wire test:mcp, update CLAUDE.md

**Files:**
- Modify: `scanner/src/mcp/tools.js`
- Modify: `scanner/package.json`
- Modify: `scanner/src/mcp/CLAUDE.md`

**Interfaces:**
- Consumes: `dataflow_get_graph`, `dataflow_get_node`, `dataflow_get_edge`, `dataflow_get_flow` from Task 1's `dataflow-tools.js`.
- Produces: nothing new — this task only wires Task 1's exports into the tool registry, test scope, and documentation.

- [ ] **Step 1: Read the exact tool-registration mechanism**

Run: `grep -n "ALL_TOOLS" scanner/src/mcp/tools.js scanner/src/mcp/server.js`. Confirm exactly how `ALL_TOOLS` (defined at `scanner/src/mcp/tools.js:1547` as of this plan's writing — re-confirm the line) is consumed by `server.js` (a `Map` keyed by `name`? a `.find()`? read it, don't guess) before editing, since Task 2's own correctness depends on `server.js`'s real dispatch shape, not an assumption.

- [ ] **Step 2: Add the import and extend `ALL_TOOLS`**

At the top of `scanner/src/mcp/tools.js`, add:

```js
import { dataflow_get_graph, dataflow_get_node, dataflow_get_edge, dataflow_get_flow } from './dataflow-tools.js';
```

Change the `ALL_TOOLS` line (confirm its exact current contents first — this plan's own citation may drift):

```js
export const ALL_TOOLS = [scan_diff, query_taint, explain_finding, apply_fix, verify_fix, synthesize_fix, find_rule_module, append_scratchpad, read_scratchpad, append_agents_memory, read_agents_memory, lookup_cve, synthesize_sca_upgrade, apply_sca_upgrade, query_triage_memory, query_findings_memory, query_cache_telemetry, dataflow_get_graph, dataflow_get_node, dataflow_get_edge, dataflow_get_flow];
```

- [ ] **Step 3: Add the new test file to `test:mcp`**

In `scanner/package.json`, the `test:mcp` script is confirmed (this session) to be:
```
"test:mcp": "node --test test/mcp.test.js test/mcp-protocol-smoke.test.js test/mcp-audit.test.js test/audit-cli.test.js test/mcp-scratchpad.test.js test/mcp-offload.test.js test/sca-upgrade.test.js test/lsp-server.test.js"
```
Add `test/mcp-dataflow-tools.test.js` to this space-separated list (confirmed NOT a glob — an omitted file gets zero CI coverage, the exact gap this session already found and fixed once for `frontend/package.json`'s own `query-language.test.js`).

- [ ] **Step 4: Run the scoped test to verify wiring**

Run: `npm run test:mcp` (from `scanner/`)
Expected: PASS, including the new file's tests, confirming both the registration (Step 2, verified indirectly via any existing "every ALL_TOOLS entry has a valid inputSchema"-shaped test if one exists — check `test/mcp.test.js` for such a test and note in the commit if none exists) and the scoping (Step 3) are correct.

- [ ] **Step 5: Update `scanner/src/mcp/CLAUDE.md`**

Add 4 rows to the `## Tools exposed today` table:

```
| `dataflow_get_graph` | ✓ | reads the signed `lineage-graph.json` (via `server/graph-loader.js`, reused unmodified); returns the full DataFlowGraph v1 artifact |
| `dataflow_get_node` | ✓ | as above, ID-scoped node lookup (via `server/routes.js`'s `handleNode`, reused unmodified) |
| `dataflow_get_edge` | ✓ | as above, ID-scoped edge lookup (`handleEdge`) |
| `dataflow_get_flow` | ✓ | as above, ID-scoped flow lookup (`handleFlow`), includes contributing node/edge canonical ids |
```

Re-derive and correct the tool count line (currently "17 tools, not 12" — re-run `grep -c "name: '" scanner/src/mcp/tools.js` and update to the real new count; this doc's own text already warns against hardcoding it, so do not just write "21" without running the grep).

- [ ] **Step 6: Full gate**

Run: `npm test` (from `scanner/`)
Expected: PASS, exit code 0. Capture and report the real exit code — do not assume green from Step 4's scoped pass alone.

- [ ] **Step 7: Commit**

```bash
git add scanner/src/mcp/tools.js scanner/package.json scanner/src/mcp/CLAUDE.md
git commit -m "feat(mcp): register 4 dataflow-tools in ALL_TOOLS, wire test:mcp, document"
```

---

## Explicitly deferred (not this plan's job)

- `dataflow_query` (query-language-backed search) — real architectural question about a `scanner/` → `frontend/` dependency or a shared package; named in the scoping doc, not built here.
- Any write-capable dataflow MCP tool.
- Watch-mode / live graph updates.
