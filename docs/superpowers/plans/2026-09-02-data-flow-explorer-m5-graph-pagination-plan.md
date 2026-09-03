# M5 Large-Graph Server/Worker-Side Pagination Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the real, already-disclosed "whole graph always transferred" gap named in two places in the code (`server/routes.js`'s own "that's `query`'s job, S2" comment, `mcp/dataflow-tools.js`'s own "does not yet paginate/offload" comment) by shipping the `POST /api/v1/query` server endpoint the M3-Server sub-project already scoped and deferred, then extending the MCP `dataflow_get_graph` tool with the same filter capability.

**Architecture:** One real, already-tested primitive — `export-json.js`'s `_filterGraph(graph, filter)` — gets a new sibling, `validateFilterShape(filter)`, extracted verbatim from the CLI's own existing inline validation logic. Both the new server endpoint and the extended MCP tool reuse this one pair of functions; nothing about filtering itself is reinvented.

**Tech Stack:** Node.js ESM, `node:http` (already in use), no new dependencies.

**Spec:** `docs/superpowers/plans/2026-09-02-data-flow-explorer-m5-graph-pagination-scoping.md`

## Global Constraints

- Every existing `server/http-server.js` security property (Host check, session-token check, request-size cap, CSP/`no-store` headers, generic 500 body) applies unchanged to the new route — never bypassed or reordered.
- `validateFilterShape` must reject exactly what the CLI's own inline logic already rejects today (non-object, array, non-array `nodeIds`/`edgeIds`) — extracted verbatim, not rewritten, since Task 1 also makes the CLI call the extracted function instead of its own inline copy.
- No change to `_filterGraph` itself.
- No frontend/UI work in this plan.
- No new npm dependency.
- An unfiltered `dataflow_get_graph`/`GET /api/v1/graph` call still returns the whole graph inline, unchanged — this plan does not add a hard size cap or forced offload; that stays real, disclosed, deferred scope.

---

### Task 1: `POST /api/v1/query` server endpoint

**Files:**
- Modify: `scanner/src/lineage/export-json.js` (extract `validateFilterShape`)
- Modify: `scanner/bin/agentic-security.js` (use the extracted validator instead of its own inline copy)
- Modify: `scanner/src/server/routes.js` (new `handleQuery`)
- Modify: `scanner/src/server/http-server.js` (body-content accumulation, new `ROUTES` entry, dispatch-call signature)
- Modify: `scanner/src/server/CLAUDE.md` (move `POST /api/v1/query` out of "What this does NOT do")
- Test: `scanner/test/lineage/export-json.test.js` (extend — `validateFilterShape`)
- Test: `scanner/test/server/routes.test.js` (extend — `handleQuery`)
- Test: `scanner/test/server/http-server.test.js` (extend — real live POST request)

**Interfaces:**
- Consumes: nothing new from earlier tasks (first task).
- Produces: `validateFilterShape(filter) -> {valid: boolean, error: string|null}` (exported from `export-json.js`) — Task 2 imports this directly.

- [ ] **Step 1: Write the failing test for `validateFilterShape`**

Add to `scanner/test/lineage/export-json.test.js` (find the existing `_filterGraph`/`exportGraphJSON` test block and add nearby — check the file's own existing imports first and match them):

```js
import { validateFilterShape } from '../../src/lineage/export-json.js';

test('validateFilterShape: accepts undefined, {}, and well-formed {nodeIds,edgeIds}', () => {
  assert.deepEqual(validateFilterShape(undefined), { valid: true, error: null });
  assert.deepEqual(validateFilterShape({}), { valid: true, error: null });
  assert.deepEqual(validateFilterShape({ nodeIds: ['a'], edgeIds: ['b'] }), { valid: true, error: null });
  assert.deepEqual(validateFilterShape({ nodeIds: [] }), { valid: true, error: null });
});

test('validateFilterShape: rejects non-object, array, and non-array nodeIds/edgeIds', () => {
  assert.equal(validateFilterShape('not-an-object').valid, false);
  assert.equal(validateFilterShape(null).valid, false);
  assert.equal(validateFilterShape([]).valid, false);
  assert.equal(validateFilterShape({ nodeIds: 'not-an-array' }).valid, false);
  assert.equal(validateFilterShape({ edgeIds: 'not-an-array' }).valid, false);
  assert.equal(validateFilterShape(42).valid, false);
  const r = validateFilterShape('bad');
  assert.match(r.error, /must be a JSON object/);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd scanner && node --test test/lineage/export-json.test.js`
Expected: FAIL — `validateFilterShape` is not exported.

- [ ] **Step 3: Extract `validateFilterShape` into `export-json.js`**

Find `_filterGraph`'s own export in `export-json.js` (`export function _filterGraph(graph, filter) {`) and add immediately before it:

```js
/**
 * `validateFilterShape(filter) -> {valid, error}` — shape-validates an
 * `opts.filter` value BEFORE it ever reaches `_filterGraph`. `_filterGraph`
 * does `new Set(filter.nodeIds ?? [])`, and `new Set("not-an-array")`
 * iterates a string as characters instead of throwing (a real JS
 * foot-gun) — a malformed-but-truthy filter would otherwise silently
 * produce an empty/wrong graph instead of a clear error. `undefined`
 * (no filter at all) and `{}` (an empty, valid filter) both pass.
 * Extracted from `bin/agentic-security.js`'s own original inline
 * `--filter` validation (verbatim logic, not rewritten) so the CLI,
 * the `explore` server's new `POST /api/v1/query` endpoint, and the
 * `dataflow_get_graph` MCP tool all share the identical protection
 * rather than three independent, potentially-drifting copies.
 */
export function validateFilterShape(filter) {
  if (filter === undefined) return { valid: true, error: null };
  if (typeof filter !== 'object' || filter === null || Array.isArray(filter)
    || (filter.nodeIds !== undefined && !Array.isArray(filter.nodeIds))
    || (filter.edgeIds !== undefined && !Array.isArray(filter.edgeIds))) {
    // Deliberately starts with "must be", not "filter must be" — the CLI
    // wraps this with its own "--filter file \"X\"" prefix (see
    // bin/agentic-security.js's own call site); the server/MCP call sites
    // use it standalone, where "must be a JSON object..." already reads
    // correctly with no file-path context needed.
    return { valid: false, error: 'must be a JSON object of the form {"nodeIds":[...],"edgeIds":[...]} (both optional, but if present must be arrays)' };
  }
  return { valid: true, error: null };
}

```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd scanner && node --test test/lineage/export-json.test.js`
Expected: PASS, including the 2 new tests.

- [ ] **Step 5: Wire the CLI to use the extracted validator (refactor, not new behavior)**

In `scanner/bin/agentic-security.js`, add `validateFilterShape` to the existing `export-json.js` import (find the file's own top-level or dynamic import of `export-json.js` — `cmdDataflowExport` imports `exportGraphJSON` dynamically inside the function body per the existing `format === 'json'` branch; add `validateFilterShape` to that SAME import statement, or add a static top-level import if `export-json.js` is already statically imported elsewhere in this file — check first, match the existing style).

Find:

```js
    // Shape-validate rather than pass through whatever JSON.parse returned —
    // found by Task 1's own review: exportGraphJSON's _filterGraph does
    // `new Set(filter.nodeIds ?? [])`, and `new Set("not-an-array")`
    // iterates a string as characters instead of throwing (a real JS
    // foot-gun, reproduced live by the reviewer), so a malformed-but-valid
    // --filter file silently produced an empty graph instead of a clear
    // error. Only nodeIds/edgeIds are ever read by any consumer of this
    // opts.filter — reject anything else here, before it reaches them.
    if (typeof filter !== 'object' || filter === null || Array.isArray(filter)
      || (filter.nodeIds !== undefined && !Array.isArray(filter.nodeIds))
      || (filter.edgeIds !== undefined && !Array.isArray(filter.edgeIds))) {
      process.stderr.write(`agentic-security dataflow export: --filter file "${args.flags.filter}" must be a JSON object of the form {"nodeIds":[...],"edgeIds":[...]} (both optional, but if present must be arrays).\n`);
      return 2;
    }
```

Replace with:

```js
    // Milestone 5, large-graph pagination: this shape check now lives in
    // export-json.js's validateFilterShape (extracted verbatim from what
    // was previously this file's own inline copy) so the server's new
    // POST /api/v1/query endpoint and the dataflow_get_graph MCP tool
    // share the identical protection rather than a third, drifting copy.
    const { validateFilterShape } = await import('../src/lineage/export-json.js');
    const filterCheck = validateFilterShape(filter);
    if (!filterCheck.valid) {
      process.stderr.write(`agentic-security dataflow export: --filter file "${args.flags.filter}" ${filterCheck.error}.\n`);
      return 2;
    }
```

(If `export-json.js` is already statically imported at the top of this file, use that static import for `validateFilterShape` instead of a dynamic one here — check the file's own top-level imports first; only fall back to a dynamic import matching this function's own existing dynamic-import style for `exportGraphJSON` if no static import exists.)

- [ ] **Step 6: Run the CLI's own existing filter tests to confirm the refactor is behavior-preserving**

Run: `cd scanner && node --test test/cli/dataflow-export-privacy.test.js test/cli/dataflow-recipients.test.js` (both exercise `--filter`) and any dedicated `--filter`-validation CLI test file if one exists (grep `test/cli/` for `--filter.*must be a JSON object` to find it).
Expected: PASS, unchanged — same error message text and same exit code 2 on a malformed filter file, since the extracted function's error string was designed to slot into the exact same `process.stderr.write` template.

- [ ] **Step 7: Write the failing test for `handleQuery`**

Add to `scanner/test/server/routes.test.js` (same file, same `graph` fixture already loaded at the top):

```js
import { handleQuery } from '../../src/server/routes.js'; // add to the existing import line instead of a new one

test('handleQuery: valid filter narrows the graph via _filterGraph, same envelope as handleGraph', () => {
  const targetNode = graph.nodes[0];
  const { status, body } = handleQuery(graph, { nodeIds: [targetNode.id], edgeIds: [] });
  assert.equal(status, 200);
  assert.equal(body.digest, graph.graphId);
  assert.equal(body.canonicalIds, null);
  assert.deepEqual(body.data.nodes, [targetNode]);
  assert.equal(body.data.edges.length, 0);
});

test('handleQuery: undefined/empty filter returns the whole graph, same as handleGraph', () => {
  const { status, body } = handleQuery(graph, undefined);
  assert.equal(status, 200);
  assert.deepEqual(body.data.nodes, graph.nodes);
});

test('handleQuery: malformed filter -> 400 with a clear message, never throws', () => {
  const { status, body } = handleQuery(graph, { nodeIds: 'not-an-array' });
  assert.equal(status, 400);
  assert.match(body.error, /must be a JSON object/);
});
```

- [ ] **Step 8: Run test to verify it fails**

Run: `cd scanner && node --test test/server/routes.test.js`
Expected: FAIL — `handleQuery` is not exported.

- [ ] **Step 9: Add `handleQuery` to `routes.js`**

Add the `validateFilterShape`/`_filterGraph` import to `routes.js`'s top (it currently imports nothing from `export-json.js` — check first):

```js
import { _filterGraph, validateFilterShape } from '../lineage/export-json.js';
```

Add, right after `handleGraph`:

```js
/**
 * A deterministic typed projection query — Milestone 5's own
 * `POST /api/v1/query`, the S2 endpoint `handleGraph`'s own header
 * comment named and deferred. `filter` is the exact `{nodeIds, edgeIds}`
 * shape `dataflow export --filter`/`exportGraphJSON` already use — reused
 * via `_filterGraph`, never reimplemented. `undefined`/`{}` returns the
 * whole graph, identical to `handleGraph`. A malformed filter is a 400,
 * never a thrown exception reaching the caller.
 */
export function handleQuery(graph, filter) {
  const check = validateFilterShape(filter);
  if (!check.valid) {
    return { status: 400, body: { error: check.error } };
  }
  return { status: 200, body: wrapResponse(_filterGraph(graph, filter), graph, { canonicalIds: null }) };
}
```

- [ ] **Step 10: Run test to verify it passes**

Run: `cd scanner && node --test test/server/routes.test.js`
Expected: PASS, including the 3 new tests.

- [ ] **Step 11: Wire the new route + real body parsing into `http-server.js`**

Add `handleQuery` to the existing `routes.js` import:

```js
import { handleScan, handleGraph, handleNode, handleEdge, handleFlow, handleQuery } from './routes.js';
```

Add the new route to `ROUTES` (note the 3rd `body` argument every OTHER handler here still ignores — only this one reads it):

```js
const ROUTES = [
  { method: 'GET', pattern: /^\/api\/v1\/scan\/?$/, handler: (graph) => handleScan(graph) },
  { method: 'GET', pattern: /^\/api\/v1\/graph\/?$/, handler: (graph) => handleGraph(graph) },
  { method: 'GET', pattern: /^\/api\/v1\/nodes\/([^/]+)\/?$/, handler: (graph, m) => handleNode(graph, decodeURIComponent(m[1])) },
  { method: 'GET', pattern: /^\/api\/v1\/edges\/([^/]+)\/?$/, handler: (graph, m) => handleEdge(graph, decodeURIComponent(m[1])) },
  { method: 'GET', pattern: /^\/api\/v1\/flows\/([^/]+)\/?$/, handler: (graph, m) => handleFlow(graph, decodeURIComponent(m[1])) },
  { method: 'POST', pattern: /^\/api\/v1\/query\/?$/, handler: (graph, m, body) => handleQuery(graph, body?.filter) },
];
```

Find the body-reading block (currently only tracks size):

```js
    // 3. Request-size cap, applied uniformly (S1's GET endpoints have no
    // meaningful body, but the middleware exists now so S2's POST
    // endpoints inherit it without retrofitting).
    let bodySize = 0;
    let aborted = false;
    req.on('data', (chunk) => {
      if (aborted) return;
      bodySize += chunk.length;
      if (bodySize > MAX_REQUEST_BODY_BYTES) {
        aborted = true;
        _sendJson(res, 413, { error: 'request body too large' });
        finish(413);
        // Stop reading further body bytes only once the 413 response has
        // actually been flushed to the client — destroying the request
        // stream immediately can race the response write and cut it off
        // before the client sees it.
        res.once('finish', () => { try { req.destroy(); } catch { /* best-effort */ } });
      }
    });

    req.on('end', () => {
      if (aborted) return;

      // 4. Route.
      let matched = null;
      let match = null;
      for (const route of ROUTES) {
        if (route.method !== method) continue;
        const m = route.pattern.exec(urlPath);
        if (m) { matched = route; match = m; break; }
      }
      if (!matched) {
        _sendJson(res, 404, { error: 'not found' });
        finish(404);
        return;
      }

      try {
        const result = matched.handler(graph, match);
        _sendJson(res, result.status, result.body);
        finish(result.status);
      } catch {
        _sendJson(res, 500, { error: 'internal error' });
        finish(500);
      }
    });
```

Replace with (adds real body-content accumulation alongside the unchanged size cap, JSON-parses only for a route that's actually POST and actually matched, 400 on malformed JSON rather than letting a parse exception fall through to the generic 500):

```js
    // 3. Request-size cap, applied uniformly (S1's GET endpoints have no
    // meaningful body; Milestone 5's own POST /api/v1/query is the first
    // real consumer). Milestone 5 also starts accumulating the actual body
    // BYTES (not just the size) — no earlier route needed them.
    let bodySize = 0;
    let bodyChunks = [];
    let aborted = false;
    req.on('data', (chunk) => {
      if (aborted) return;
      bodySize += chunk.length;
      if (bodySize > MAX_REQUEST_BODY_BYTES) {
        aborted = true;
        _sendJson(res, 413, { error: 'request body too large' });
        finish(413);
        // Stop reading further body bytes only once the 413 response has
        // actually been flushed to the client — destroying the request
        // stream immediately can race the response write and cut it off
        // before the client sees it.
        res.once('finish', () => { try { req.destroy(); } catch { /* best-effort */ } });
        return;
      }
      bodyChunks.push(chunk);
    });

    req.on('end', () => {
      if (aborted) return;

      // 4. Route.
      let matched = null;
      let match = null;
      for (const route of ROUTES) {
        if (route.method !== method) continue;
        const m = route.pattern.exec(urlPath);
        if (m) { matched = route; match = m; break; }
      }
      if (!matched) {
        _sendJson(res, 404, { error: 'not found' });
        finish(404);
        return;
      }

      // Milestone 5: parse the body ONLY for a matched route, and only as
      // JSON when non-empty — every pre-M5 GET route still ignores this
      // 3rd argument entirely, so an empty/missing body for them is a
      // no-op, not an error.
      let body;
      if (bodyChunks.length > 0) {
        try {
          body = JSON.parse(Buffer.concat(bodyChunks).toString('utf8'));
        } catch {
          _sendJson(res, 400, { error: 'malformed JSON request body' });
          finish(400);
          return;
        }
      }

      try {
        const result = matched.handler(graph, match, body);
        _sendJson(res, result.status, result.body);
        finish(result.status);
      } catch {
        _sendJson(res, 500, { error: 'internal error' });
        finish(500);
      }
    });
```

- [ ] **Step 12: Write the failing live-server test**

Add to `scanner/test/server/http-server.test.js`, using the file's own real, already-existing `request(port, {...}, body)` and `startTestServer(overrides)` helpers (defined at the top of the file — `request`'s 3rd positional argument is the raw body string; `startTestServer` returns `{server, port, sessionToken}`) — do not reimplement this plumbing:

```js
test('POST /api/v1/query: valid filter narrows the graph over a real live request', async () => {
  const { server, port, sessionToken } = await startTestServer();
  try {
    const targetNodeId = GRAPH.nodes[0].id;
    const payload = JSON.stringify({ filter: { nodeIds: [targetNodeId], edgeIds: [] } });
    const res = await request(
      port,
      {
        method: 'POST',
        path: '/api/v1/query',
        headers: {
          host: `127.0.0.1:${port}`,
          [TOKEN_HEADER]: sessionToken,
          'content-type': 'application/json',
          'content-length': Buffer.byteLength(payload),
        },
      },
      payload,
    );
    assert.equal(res.status, 200, `expected 200, got ${res.status}: ${JSON.stringify(res.body)}`);
    assert.equal(res.body.data.nodes.length, 1);
    assert.equal(res.body.data.nodes[0].id, targetNodeId);
    assert.equal(res.body.digest, GRAPH.graphId);
  } finally {
    server.close();
  }
});

test('POST /api/v1/query: omitting the body returns the whole graph, unchanged', async () => {
  const { server, port, sessionToken } = await startTestServer();
  try {
    const res = await request(port, {
      method: 'POST',
      path: '/api/v1/query',
      headers: { host: `127.0.0.1:${port}`, [TOKEN_HEADER]: sessionToken },
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.data.nodes.length, GRAPH.nodes.length);
  } finally {
    server.close();
  }
});

test('POST /api/v1/query: missing session token -> 401, same as every other route', async () => {
  const { server, port } = await startTestServer();
  try {
    const res = await request(port, {
      method: 'POST',
      path: '/api/v1/query',
      headers: { host: `127.0.0.1:${port}` },
    });
    assert.equal(res.status, 401);
  } finally {
    server.close();
  }
});

test('POST /api/v1/query: malformed JSON body -> 400, never a 500', async () => {
  const { server, port, sessionToken } = await startTestServer();
  try {
    const bad = '{not valid json';
    const res = await request(
      port,
      {
        method: 'POST',
        path: '/api/v1/query',
        headers: {
          host: `127.0.0.1:${port}`,
          [TOKEN_HEADER]: sessionToken,
          'content-type': 'application/json',
          'content-length': Buffer.byteLength(bad),
        },
      },
      bad,
    );
    assert.equal(res.status, 400);
    assert.match(String(res.body.error ?? res.body), /malformed JSON/);
  } finally {
    server.close();
  }
});

test('POST /api/v1/query: an invalid filter shape -> 400 with a clear message', async () => {
  const { server, port, sessionToken } = await startTestServer();
  try {
    const payload = JSON.stringify({ filter: { nodeIds: 'not-an-array' } });
    const res = await request(
      port,
      {
        method: 'POST',
        path: '/api/v1/query',
        headers: {
          host: `127.0.0.1:${port}`,
          [TOKEN_HEADER]: sessionToken,
          'content-type': 'application/json',
          'content-length': Buffer.byteLength(payload),
        },
      },
      payload,
    );
    assert.equal(res.status, 400);
    assert.match(res.body.error, /must be a JSON object/);
  } finally {
    server.close();
  }
});

test('POST /api/v1/query: oversized body -> 413, same cap as every other route', async () => {
  const { server, port, sessionToken } = await startTestServer();
  try {
    const big = 'x'.repeat(70 * 1024); // > MAX_REQUEST_BODY_BYTES (64KB)
    const res = await request(
      port,
      {
        method: 'POST',
        path: '/api/v1/query',
        headers: {
          host: `127.0.0.1:${port}`,
          [TOKEN_HEADER]: sessionToken,
          'content-type': 'application/json',
          'content-length': Buffer.byteLength(big),
        },
      },
      big,
    );
    assert.equal(res.status, 413);
  } finally {
    server.close();
  }
});
```

- [ ] **Step 13: Run test to verify it fails, then implement is already done (Step 11) — verify it passes**

Run: `cd scanner && node --test test/server/http-server.test.js`
Expected: FAIL before Step 11's `http-server.js` changes are confirmed in place (they should already be — this step is verification, not new implementation); PASS after.

- [ ] **Step 14: Update `scanner/src/server/CLAUDE.md`**

In the "What's here" table's Sub-project Server increment-1 section, add a new row (or extend the existing `routes.js` row) documenting `handleQuery`/`POST /api/v1/query`. In the "What this does NOT do" section, remove the `POST /api/v1/query` sentence (it's no longer deferred) — keep `POST /api/v1/export` and everything else in that list unchanged, since only the query endpoint is what this task ships.

- [ ] **Step 15: Run the full server + lineage scopes**

Run: `cd scanner && npm run test:server` and `npm run test:lineage`
Expected: PASS, exit 0, both.

- [ ] **Step 16: Commit**

```bash
git add src/lineage/export-json.js bin/agentic-security.js src/server/routes.js src/server/http-server.js src/server/CLAUDE.md test/lineage/export-json.test.js test/server/routes.test.js test/server/http-server.test.js
git commit -m "feat(server): POST /api/v1/query — the deferred M3-Server S2 endpoint (M5 large-graph pagination, Task 1)"
```

---

### Task 2: `dataflow_get_graph` MCP tool gains an optional `filter` input

**Files:**
- Modify: `scanner/src/mcp/dataflow-tools.js`
- Modify: `scanner/src/mcp/CLAUDE.md`
- Test: `scanner/test/mcp-dataflow-tools.test.js`

**Interfaces:**
- Consumes: `validateFilterShape`/`_filterGraph` from `export-json.js` (Task 1).
- Produces: nothing further downstream — last task.

- [ ] **Step 1: Write the failing test**

Add to `scanner/test/mcp-dataflow-tools.test.js`, using the file's own real, already-existing `_mkTmpProject()`/`_writeGraph(root, graphObj)`/`SAMPLE_GRAPH` helpers (`SAMPLE_GRAPH` has exactly one node, `node:api`, one edge `edge:api-db`, one flow `flow:1`):

```js
test('dataflow_get_graph: an optional filter narrows the returned graph via _filterGraph', async () => {
  const root = _mkTmpProject();
  try {
    _writeGraph(root, SAMPLE_GRAPH);
    const result = await dataflow_get_graph.handler({ filter: { nodeIds: ['node:api'], edgeIds: [] } }, { sessionRoot: root });
    assert.equal(result.hasResult, true);
    assert.equal(result.data.nodes.length, 1);
    assert.equal(result.data.nodes[0].id, 'node:api');
    assert.equal(result.data.edges.length, 0);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('dataflow_get_graph: omitting filter still returns the whole graph, unchanged', async () => {
  const root = _mkTmpProject();
  try {
    _writeGraph(root, SAMPLE_GRAPH);
    const result = await dataflow_get_graph.handler({}, { sessionRoot: root });
    assert.equal(result.hasResult, true);
    assert.equal(result.data.nodes.length, 1);
    assert.equal(result.data.edges.length, 1);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('dataflow_get_graph: a malformed filter returns a clear tool-error result, never throws', async () => {
  const root = _mkTmpProject();
  try {
    _writeGraph(root, SAMPLE_GRAPH);
    const result = await dataflow_get_graph.handler({ filter: { nodeIds: 'not-an-array' } }, { sessionRoot: root });
    assert.equal(result.hasResult, false);
    assert.equal(result.reason, 'invalid-filter');
    assert.match(result.message, /must be a JSON object/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('dataflow_get_graph: inputSchema accepts a well-formed filter and rejects an unknown top-level property', () => {
  assert.equal(dataflow_get_graph.inputSchema.properties.filter.type, 'object');
  assert.equal(dataflow_get_graph.inputSchema.additionalProperties, false);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd scanner && npm run test:mcp`
Expected: FAIL — `dataflow_get_graph`'s `inputSchema` currently declares `properties: {}` with no `filter`, and the handler ignores `_args` entirely (confirm this directly by reading the current handler body before writing the fix).

- [ ] **Step 3: Extend the input schema and handler**

In `scanner/src/mcp/dataflow-tools.js`, add the import:

```js
import { _filterGraph, validateFilterShape } from '../lineage/export-json.js';
```

Find `dataflow_get_graph`'s `inputSchema`:

```js
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: {},
  },
```

Replace with:

```js
  inputSchema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      filter: {
        type: 'object',
        additionalProperties: false,
        properties: {
          nodeIds: { type: 'array', items: { type: 'string' } },
          edgeIds: { type: 'array', items: { type: 'string' } },
        },
      },
    },
  },
```

Find the handler's body (`async handler(_args, ctx) {`) — it currently ignores `_args`. Change the parameter name to `args` (it's used now) and add filter validation + application right after the `_loadOrFailure` call, before `handleGraph`:

```js
  async handler(args, ctx) {
    const { graph, failure } = _loadOrFailure(ctx.sessionRoot);
    if (failure) return failure;
    // Milestone 5, large-graph pagination: reuses the exact same
    // validateFilterShape/_filterGraph pair the new POST /api/v1/query
    // server endpoint and the CLI's own --filter both use — one real,
    // shared primitive, not a third drifting copy.
    const filterCheck = validateFilterShape(args?.filter);
    if (!filterCheck.valid) {
      return { _meta: META, hasResult: false, reason: 'invalid-filter', message: filterCheck.error };
    }
    const { status, body } = handleGraph(graph);
    return {
      _meta: META,
      hasResult: true,
      status,
      data: _redactGraph(args?.filter ? _filterGraph(body.data, args.filter) : body.data),
      digest: body.digest,
      schemaVersion: body.schemaVersion,
      extensions: body.extensions,
      scope: body.scope,
      coverage: body.coverage,
      limitations: body.limitations,
    };
  },
```

(Filter BEFORE redact — `_filterGraph` narrows the entity arrays, `_redactGraph` then only has to scrub what's actually being returned. Confirm this order matches `export-json.js`'s own `exportGraphJSON`, which does the same filter-then-redact order, before finalizing.)

- [ ] **Step 4: Run test to verify it passes**

Run: `cd scanner && npm run test:mcp`
Expected: PASS, including the 3 new tests.

- [ ] **Step 5: Update the tool description and `mcp/CLAUDE.md`**

Update `dataflow_get_graph`'s own `description` string to mention the new optional `filter` parameter (keep the existing "KNOWN GAP" sentence about pagination/offload, but rephrase it to be accurate: a supplied `filter` now narrows the response; an OMITTED filter still returns the whole graph inline with the same size-cap risk as before — this task does not add a forced fallback).

In `scanner/src/mcp/CLAUDE.md`'s tool table, update the `dataflow_get_graph` row's "Known gap" note to reflect the real, current state: filtering is now available and closes the gap FOR A CALLER THAT USES IT; an unfiltered call is still unprotected against a very large graph, disclosed as real, deferred scope (do not overclaim the gap is fully closed).

- [ ] **Step 6: Run the full MCP scope**

Run: `cd scanner && npm run test:mcp`
Expected: PASS, exit 0.

- [ ] **Step 7: `npm run build`**

Neither `bin/agentic-security.js` (already rebuilt in Task 1) nor any other bundle-relevant file changed further in this task unless Task 1's own build is stale — check `git status` for `dist/` before deciding whether a rebuild is needed here; if `bin/agentic-security.js` had no further changes since Task 1's own commit, no rebuild is needed for Task 2.

- [ ] **Step 8: Commit**

```bash
git add src/mcp/dataflow-tools.js src/mcp/CLAUDE.md test/mcp-dataflow-tools.test.js
git commit -m "feat(mcp): dataflow_get_graph gains an optional filter, reusing the query endpoint's own primitive (M5 large-graph pagination, Task 2)"
```
