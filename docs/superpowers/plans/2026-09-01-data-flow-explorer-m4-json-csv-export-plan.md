# Milestone 4, sub-project JSON/CSV export — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Two new, pure, deterministic serialization functions —
`exportGraphJSON` and `exportFlowsCSV` — over the already-built
`DataFlowGraph v1` artifact, satisfying PRD §17.5's redaction/scope/digest
requirements and AC-14's reproducibility requirement, as foundational
building blocks for later M4 sub-projects (HTML report, PNG/SVG/PDF export,
Regulatory Overlay evidence packs, DPIA/RoPA). No CLI/slash-command wiring
in this plan — that is sub-project #5's job.

**Architecture:** Task 1 extracts the MCP-tools sub-project's own,
already-fixed redaction logic (`_redactNode`/`_redactEvidence`/
`_redactGraph`) out of `scanner/src/mcp/dataflow-tools.js` into a new
shared module, `scanner/src/lineage/redact-graph.js`, so this export path
reuses proven code rather than risking the exact redaction gap that
sub-project's own whole-branch review just found and fixed. Task 2 builds
`exportGraphJSON` on top of it plus a new content-digest function. Task 3
builds `exportFlowsCSV`, reusing `scanner/src/lineage/protection.js`'s
already-shipped `aggregateVerdicts` for per-dimension flow verdicts
(scanner-native — the frontend's own `worstVerdict` in
`frontend/src/lib/protection-visual.js` does the identical thing but lives
in a different package this plan does not import from).

**Tech Stack:** Node ESM, `node:test`, `node:crypto` (SHA-256, already used
throughout `scanner/src/posture/`), no new npm dependency.

**Spec:** `docs/superpowers/plans/2026-09-01-data-flow-explorer-m4-json-csv-export-scoping.md`
(this sub-project's own scoping doc, corrected against the M4 top-level
doc's own citation error) and `docs/superpowers/plans/2026-09-01-data-flow-explorer-m4-scoping.md`.
PRD: §17.5 ("Self-contained export"), AC-14 ("Export reproducibility").

## Global Constraints

- **No CLI/slash-command wiring, no HTML bundling, no PNG/SVG/PDF, no
  node/edge CSV.** Pure serialization functions only — see each sub-project
  doc's own "Do NOT touch" section.
- **Redaction is mandatory by default** (`redact: true`) on every export
  function that can carry scanned-source-derived content. Never emit
  unredacted content unless the caller explicitly opts out.
- **Determinism (AC-14):** the same graph in must always produce the same
  bytes out, except for an explicit, separately-surfaced `exportedAt`
  timestamp field. Sort every array that isn't already graph-order-stable
  before emit if key ordering could vary.
- **No new npm dependency.**
- **Real-fixture grounding:** every expected test value must come from
  reading `scanner/src/lineage/fixtures/flagship-graph.json` directly (the
  real, committed, scanner-side fixture — confirmed this session to be
  the one already used by `test/lineage/*.test.js` via a plain
  `fs.readFileSync`/`path.join(__dirname, '../../src/lineage/fixtures/flagship-graph.json')`,
  never a JS import, and never `frontend/`'s own copy), never guessed.

---

## Task 1: Extract redaction logic into `scanner/src/lineage/redact-graph.js`

**Files:**
- Create: `scanner/src/lineage/redact-graph.js`
- Modify: `scanner/src/mcp/dataflow-tools.js`
- Test: existing `scanner/test/mcp-dataflow-tools.test.js` must stay green
  unmodified (behavior-preservation proof) — no new test file for this task.

**Interfaces:**
- Consumes: `redactString` from `scanner/src/mcp/redact.js` (already
  imported by `dataflow-tools.js` today — re-confirm the import stays
  correct once the functions move).
- Produces: `_redactNode(node)`, `_redactEvidence(evidence)`,
  `_redactGraph(data)` — same names, same signatures, same behavior,
  exported (not prefixed-private anymore, since a second module now needs
  them — but keep the `_` prefix on the name itself, since these remain
  internal-use utility functions, not a public API surface with a stability
  contract).

- [ ] **Step 1: Create `redact-graph.js` with the moved functions**

Copy the following EXACTLY from `scanner/src/mcp/dataflow-tools.js` (lines
30-91 as of this plan's writing — re-locate the exact current lines before
copying, do not assume they haven't shifted), changing only the import
source and adding `export` to each function:

```js
// redact-graph.js — Milestone 4. Shared redaction logic for the
// DataFlowGraph v1 artifact, extracted from the MCP-tools sub-project's
// own dataflow-tools.js (where a whole-branch security review found and
// fixed the real gap this logic closes — see that sub-project's own
// CLAUDE.md section, "Dataflow-tools redaction scope"). Any export path
// that returns graph content to a consumer outside the scan process must
// reuse this module rather than re-deriving redaction logic — that is
// exactly the "two near-identical copies" bug class this extraction
// exists to prevent (the same bug class M3-UX-Filters' own
// `rowMatchesFilters` duplication hit once already this session).

import { redactString } from '../mcp/redact.js';

// Redacts every scanned-source-derived string field on a COPY of the data
// being returned — never mutates the loaded graph object, which may be
// reused across calls within the same process lifetime by other callers.
//
// Three real source-derived surfaces, confirmed by reading the graph
// pipeline directly (findings from the MCP-tools sub-project's own
// follow-up security review, not assumed from the schema alone):
//   - `node.destination.raw`/`.literalValue` — resolve-destination.js's
//     `resolveDestination()` lifts these straight out of scanned call-site
//     arguments (`renderExpr(arg0)` / `String(arg0.value)`); a hardcoded
//     connection string, webhook URL, or API-key literal used as a
//     destination argument lands here verbatim.
//   - `evidence[].claim` — composed from resolved values in
//     graph-builder.js; can echo the same literal content.
//   - `evidence[].location.note` / `.snippet` — schema-declared free-text
//     fields; `.note` is fixture-only today (the real emitter uses
//     `{file,line}`, never `{note}`) and `.snippet` is always null today,
//     but both are declared string fields a future evidence producer could
//     populate with raw source text, so both stay defensively redacted
//     rather than trusting today's producers to never change.
export function _redactNode(node) {
  if (!node?.destination) return node;
  const d = node.destination;
  if (typeof d.raw !== 'string' && typeof d.literalValue !== 'string') return node;
  return {
    ...node,
    destination: {
      ...d,
      raw: typeof d.raw === 'string' ? redactString(d.raw) : d.raw,
      literalValue: typeof d.literalValue === 'string' ? redactString(d.literalValue) : d.literalValue,
    },
  };
}

export function _redactEvidence(evidence) {
  if (!Array.isArray(evidence)) return evidence;
  return evidence.map((e) => {
    if (!e || typeof e !== 'object') return e;
    return {
      ...e,
      claim: typeof e.claim === 'string' ? redactString(e.claim) : e.claim,
      snippet: typeof e.snippet === 'string' ? redactString(e.snippet) : e.snippet,
      location: e.location?.note
        ? { ...e.location, note: redactString(e.location.note) }
        : e.location,
    };
  });
}

// Full-graph redaction: every node's destination, plus the top-level
// evidence array. Edges/flows carry only evidenceRefs (id strings into
// graph.evidence), never embedded evidence objects or destination-shaped
// fields — confirmed against dataflow-graph.schema.json — so they need no
// redaction pass of their own here.
export function _redactGraph(data) {
  if (!data) return data;
  return {
    ...data,
    nodes: Array.isArray(data.nodes) ? data.nodes.map(_redactNode) : data.nodes,
    evidence: _redactEvidence(data.evidence),
  };
}
```

- [ ] **Step 2: Update `dataflow-tools.js` to import from the new module**

Remove the moved function bodies from `dataflow-tools.js`. Replace the
local definitions with an import:

```js
import { _redactNode, _redactEvidence, _redactGraph } from '../lineage/redact-graph.js';
```

Remove the now-unused `redactString` import from `dataflow-tools.js` IF
(and only if) nothing else in that file still uses it directly — check
before removing (re-read the file's full current content; do not assume).

- [ ] **Step 3: Run the existing MCP test suite to prove zero behavior change**

Run: `npm run test:mcp` (from `scanner/`)
Expected: PASS, same count as before this task (150 as of this plan's
writing — re-confirm the real current count by running it BEFORE this
task's edit too, and compare — a silent count change either direction is
a signal something moved wrong).

- [ ] **Step 4: Commit**

```bash
git add scanner/src/lineage/redact-graph.js scanner/src/mcp/dataflow-tools.js
git commit -m "refactor(lineage): extract graph redaction into a shared module"
```

---

## Task 2: `exportGraphJSON` + content digest

**Files:**
- Create: `scanner/src/lineage/export-json.js`
- Test: `scanner/test/lineage/export-json.test.js`

**Interfaces:**
- Consumes: `_redactGraph` from `./redact-graph.js` (Task 1); nothing else
  new — the digest function is self-contained (`node:crypto` only).
- Produces: `computeGraphDigest(graph)` and `exportGraphJSON(graph, opts)`,
  both exported for direct testing and for reuse by later M4 sub-projects
  (the HTML report, evidence packs).

- [ ] **Step 1: Write the failing tests**

Create `scanner/test/lineage/export-json.test.js`:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { computeGraphDigest, exportGraphJSON } from '../../src/lineage/export-json.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FLAGSHIP_PATH = path.join(__dirname, '../../src/lineage/fixtures/flagship-graph.json');
const flagship = JSON.parse(fs.readFileSync(FLAGSHIP_PATH, 'utf8'));

test('computeGraphDigest: same graph in twice -> identical digest', () => {
  const d1 = computeGraphDigest(flagship);
  const d2 = computeGraphDigest(JSON.parse(JSON.stringify(flagship)));
  assert.equal(d1, d2);
  assert.match(d1, /^[0-9a-f]{64}$/);
});

test('computeGraphDigest: a changed node id changes the digest', () => {
  const mutated = JSON.parse(JSON.stringify(flagship));
  mutated.nodes[0].id = mutated.nodes[0].id + '-mutated';
  assert.notEqual(computeGraphDigest(flagship), computeGraphDigest(mutated));
});

test('computeGraphDigest: generatedAt does NOT affect the digest', () => {
  const a = { ...flagship, generatedAt: '2020-01-01T00:00:00.000Z' };
  const b = { ...flagship, generatedAt: '2099-01-01T00:00:00.000Z' };
  assert.equal(computeGraphDigest(a), computeGraphDigest(b));
});

test('exportGraphJSON: default redact:true, envelope shape', () => {
  const result = exportGraphJSON(flagship);
  assert.equal(typeof result.exportedAt, 'string');
  assert.equal(result.schemaVersion, flagship.schemaVersion);
  assert.equal(result.digest, computeGraphDigest(flagship));
  assert.deepEqual(result.scope, flagship.scope);
  assert.deepEqual(result.coverage, flagship.coverage);
  assert.deepEqual(result.limitations, flagship.limitations);
  assert.equal(result.confidential, true);
  assert.ok(result.graph);
  assert.equal(result.graph.nodes.length, flagship.nodes.length);
});

test('exportGraphJSON: AC-14 reproducibility, excluding exportedAt only', () => {
  const a = exportGraphJSON(flagship);
  const b = exportGraphJSON(flagship);
  const { exportedAt: _a, ...aRest } = a;
  const { exportedAt: _b, ...bRest } = b;
  assert.deepEqual(aRest, bRest);
});

test('exportGraphJSON: redact:false returns unredacted content, confidential stays true', () => {
  const result = exportGraphJSON(flagship, { redact: false });
  assert.equal(result.confidential, true);
  // Real check: find a real flagship node with a non-null destination and
  // confirm its raw/literalValue survive verbatim when redact:false — read
  // the real fixture to find one before writing this assertion's literal
  // expected value; do not guess a destination string.
});

test('exportGraphJSON: filter narrows to the given nodeIds/edgeIds', () => {
  const oneNodeId = flagship.nodes[0].id;
  const result = exportGraphJSON(flagship, { filter: { nodeIds: [oneNodeId], edgeIds: [] } });
  assert.equal(result.graph.nodes.length, 1);
  assert.equal(result.graph.nodes[0].id, oneNodeId);
  // flows/edges referencing the filtered-out nodes should also narrow —
  // confirm the real expected behavior against the real fixture's own
  // edge/flow structure before asserting an exact count (do not guess).
});
```

- [ ] **Step 2: Run to verify failure**

Run: `node --test test/lineage/export-json.test.js` (from `scanner/`)
Expected: FAIL — module not found.

- [ ] **Step 3: Implement `export-json.js`**

```js
// export-json.js — Milestone 4, sub-project JSON/CSV export.
//
// Deterministic JSON export of a DataFlowGraph v1 document, satisfying
// PRD §17.5 (embed filtered-or-full graph; default-redacted; scan health/
// scope/versions/limitations/generated timestamp; tamper-evident digest;
// confidential-content disclosure) and AC-14 (export reproducibility).
//
// graph.graphId is scan-metadata-derived (dfg:<repo>:<commit>:<config>,
// see ids.js), NOT a content digest — confirmed by direct read before this
// module was written. computeRunAttestation (posture/attestation.js) runs
// over scan.findings only, never the lineage graph — confirmed by direct
// read of bin/agentic-security.js's two call sites. This module computes
// its own content digest instead of reusing either.

import * as crypto from 'node:crypto';
import { _redactGraph } from './redact-graph.js';

// Canonicalization allowlist, mirroring posture/attestation.js's own
// discipline (an explicit allowlist, not a denylist — a new volatile
// field cannot leak into the digest without being added deliberately).
// Every array is sorted by id before hashing so emission order never
// affects the digest.
function _canonicalizeGraph(graph) {
  const sortById = (arr) => (Array.isArray(arr) ? [...arr].sort((a, b) => String(a.id).localeCompare(String(b.id))) : []);
  return {
    schemaVersion: graph?.schemaVersion ?? null,
    nodes: sortById(graph?.nodes).map((n) => ({ id: n.id, kind: n.kind, subtype: n.subtype ?? null, coverageStatus: n.coverageStatus ?? null })),
    edges: sortById(graph?.edges).map((e) => ({ id: e.id, from: e.from, to: e.to, protection: e.protection ?? null })),
    flows: sortById(graph?.flows).map((f) => ({ id: f.id, source: f.source, sink: f.sink, policyVerdict: f.policyVerdict ?? null, protectionSummary: f.protectionSummary ?? null })),
    dataElements: sortById(graph?.dataElements).map((d) => ({ id: d.id, dataClasses: [...(d.dataClasses ?? [])].sort() })),
  };
}

export function computeGraphDigest(graph) {
  const canon = _canonicalizeGraph(graph);
  return crypto.createHash('sha256').update(JSON.stringify(canon)).digest('hex');
}

function _filterGraph(graph, filter) {
  if (!filter) return graph;
  const nodeIds = new Set(filter.nodeIds ?? []);
  const edgeIds = new Set(filter.edgeIds ?? []);
  return {
    ...graph,
    nodes: (graph.nodes ?? []).filter((n) => nodeIds.has(n.id)),
    edges: (graph.edges ?? []).filter((e) => edgeIds.has(e.id)),
    // flows/dataElements narrowing: confirm the real, correct rule against
    // the fixture during Step 1's test-writing pass (a flow whose source/
    // sink/edgeIds fall fully inside the filtered set stays; partial
    // overlap needs a real decision — do not guess, decide and document
    // it here when implementing).
  };
}

export function exportGraphJSON(graph, opts = {}) {
  const redact = opts.redact !== false;
  const filtered = _filterGraph(graph, opts.filter);
  const body = redact ? _redactGraph(filtered) : filtered;
  return {
    exportedAt: new Date().toISOString(),
    schemaVersion: graph?.schemaVersion ?? null,
    digest: computeGraphDigest(graph),
    scope: graph?.scope ?? null,
    coverage: graph?.coverage ?? null,
    limitations: graph?.limitations ?? [],
    confidential: true,
    graph: body,
  };
}
```

**Re-verification note for the implementer:** the `_filterGraph` flow/
dataElement-narrowing rule above is deliberately left as a real decision
for you to make and document, not guessed in this plan — read
`frontend/src/lib/focus-controls.js`'s own `{nodeIds, edgeIds}` shape one
more time to confirm this export's filter input matches it exactly (decision
2 in the scoping doc), then decide the flow-narrowing rule and write it
into both the code and this task's own test file before calling it done.

- [ ] **Step 4: Run tests to verify they pass, fixing the two flagged real-value gaps first**

Before running, fill in the two tests marked "read the real fixture before
asserting" above with real values read from `flagship-graph.json`.

Run: `node --test test/lineage/export-json.test.js` (from `scanner/`)
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add scanner/src/lineage/export-json.js scanner/test/lineage/export-json.test.js
git commit -m "feat(lineage): add exportGraphJSON + computeGraphDigest"
```

---

## Task 3: `exportFlowsCSV`

**Files:**
- Create: `scanner/src/lineage/export-csv.js`
- Test: `scanner/test/lineage/export-csv.test.js`

**Interfaces:**
- Consumes: `aggregateVerdicts` from `./protection.js` (already shipped —
  confirm its exact signature, `aggregateVerdicts(verdicts: string[]) ->
  string`, throws on an unrecognized verdict, returns `'not_assessed'` on
  empty input, by reading the file directly before use).
- Produces: `exportFlowsCSV(graph)`, exported.

- [ ] **Step 1: Write the failing tests**

Create `scanner/test/lineage/export-csv.test.js`. Read the REAL flagship
fixture's own flow/edge/dataElement data before writing expected row
values — do not guess. At minimum:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { exportFlowsCSV } from '../../src/lineage/export-csv.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FLAGSHIP_PATH = path.join(__dirname, '../../src/lineage/fixtures/flagship-graph.json');
const flagship = JSON.parse(fs.readFileSync(FLAGSHIP_PATH, 'utf8'));

test('exportFlowsCSV: header row matches the documented column list', () => {
  const csv = exportFlowsCSV(flagship);
  const [header] = csv.split('\n');
  assert.equal(header, 'id,source,sink,dataClasses,transitVerdict,atRestVerdict,handlingVerdict,policyVerdict,coverageStatus');
});

test('exportFlowsCSV: one data row per real flow, in graph order', () => {
  const csv = exportFlowsCSV(flagship);
  const rows = csv.split('\n').slice(1);
  assert.equal(rows.length, flagship.flows.length);
});

// Real per-row assertions: pick ONE real flow from flagship.flows, read
// its real source/sink node ids, its real dataElementIds -> dataClasses,
// and its real edgeIds -> protection verdicts, compute the expected
// aggregated transitVerdict/atRestVerdict/handlingVerdict BY HAND against
// aggregateVerdicts' own documented precedence, and assert the exact row.
// Do not invent an expected value — trace it from the real fixture.

test('exportFlowsCSV: a field containing a comma is quoted', () => {
  // Construct a minimal synthetic graph (not the fixture) with a
  // dataClasses array that, once joined, would contain a comma unescaped —
  // confirm the real join character chosen for multi-value dataClasses
  // (this plan does not prescribe one; decide when implementing — a
  // semicolon join avoids embedding a raw CSV delimiter and needing outer
  // quoting for the common case, but document whichever choice is made)
  // and assert correct escaping either way.
});
```

- [ ] **Step 2: Run to verify failure**

Run: `node --test test/lineage/export-csv.test.js` (from `scanner/`)
Expected: FAIL — module not found.

- [ ] **Step 3: Implement `export-csv.js`**

```js
// export-csv.js — Milestone 4, sub-project JSON/CSV export.
//
// One row per FLOW (not node, not edge — the closest analogue in this
// domain to report/index.js's own toCSV's "one row per finding", per this
// sub-project's own scoping doc decision 3). Node/edge CSV exports are
// deferred, named explicitly in that doc, not attempted here.

import { aggregateVerdicts } from './protection.js';

// Same escaping convention as report/index.js's own toCSV — quote only
// when a comma/quote/newline is present, double embedded quotes.
function esc(v) {
  if (v == null) return '';
  const s = String(v);
  return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}

function _dataClassesForFlow(flow, dataElementsById) {
  const classes = new Set();
  for (const deId of flow.dataElementIds ?? []) {
    const de = dataElementsById.get(deId);
    for (const c of de?.dataClasses ?? []) classes.add(c);
  }
  return [...classes].sort();
}

function _dimensionVerdict(flow, edgesById, dimension) {
  const verdicts = (flow.edgeIds ?? [])
    .map((id) => edgesById.get(id)?.protection?.[dimension]?.verdict)
    .filter(Boolean);
  return aggregateVerdicts(verdicts);
}

export function exportFlowsCSV(graph) {
  const dataElementsById = new Map((graph.dataElements ?? []).map((d) => [d.id, d]));
  const edgesById = new Map((graph.edges ?? []).map((e) => [e.id, e]));
  const header = ['id', 'source', 'sink', 'dataClasses', 'transitVerdict', 'atRestVerdict', 'handlingVerdict', 'policyVerdict', 'coverageStatus'];
  const rows = [header.join(',')];
  for (const flow of graph.flows ?? []) {
    rows.push([
      esc(flow.id), esc(flow.source), esc(flow.sink),
      esc(_dataClassesForFlow(flow, dataElementsById).join(';')),
      esc(_dimensionVerdict(flow, edgesById, 'transit')),
      esc(_dimensionVerdict(flow, edgesById, 'atRest')),
      esc(_dimensionVerdict(flow, edgesById, 'handling')),
      esc(flow.policyVerdict), esc(flow.coverageStatus),
    ].join(','));
  }
  return rows.join('\n');
}
```

**Re-verification note:** confirm `aggregateVerdicts`' real signature/
throw-behavior against `protection.js` before trusting the code above —
this plan's own author read it during scoping, but re-confirm.
`_dataClassesForFlow`'s `;`-join is this plan's own chosen convention
(documented in the header comment above) — keep it, or change it and
update both the code comment and the escaping test accordingly; do not
leave the two disagreeing.

- [ ] **Step 4: Run tests to verify they pass**, filling in the real
  per-row assertions and the escaping test's real join-character decision
  first.

Run: `node --test test/lineage/export-csv.test.js` (from `scanner/`)
Expected: PASS.

- [ ] **Step 5: Wire both new test files into `test:lineage`, update CLAUDE.md, full gate**

Add `test/lineage/export-json.test.js` and `test/lineage/export-csv.test.js`
to `scanner/package.json`'s `test:lineage` script (confirmed this session
to be an explicit file list, same gotcha class as `test:mcp` — check the
real current string before editing). Add a short new row to
`scanner/src/lineage/CLAUDE.md`'s own module table documenting
`redact-graph.js`/`export-json.js`/`export-csv.js` (one row each, or one
combined row — implementer's judgment, matching this file's own existing
density).

Run: `npm test` (from `scanner/`)
Expected: PASS, exit code 0. Capture and report the real exit code.

- [ ] **Step 6: Commit**

```bash
git add scanner/src/lineage/export-csv.js scanner/test/lineage/export-csv.test.js scanner/package.json scanner/src/lineage/CLAUDE.md
git commit -m "feat(lineage): add exportFlowsCSV; wire new export tests into test:lineage"
```

---

## Explicitly deferred (not this plan's job)

- Any CLI/slash-command wiring.
- HTML report bundling (sub-project #3).
- PNG/SVG/PDF export (sub-project #4).
- Node/edge CSV exports.
- A `verifyGraphDigest` counterpart — no consumer needs to verify yet.
