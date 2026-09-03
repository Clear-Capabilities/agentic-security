# Data Flow Explorer M5 Cross-Repository Graph Import Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the "declared" half of FR-304 (Cross-repository/federated
graph import) — M5 deliverable #8, the FINAL remaining item of the Data
Flow Explorer PRD's 8-deliverable, 5-milestone plan — as a new
graph-attached `CrossRepoLink` extension record, a portable
remote-graph-export loader, additive `graph-builder.js`/`coverage.js`/
`index.js` wiring, and a new top-level `federate declare|list` CLI
dispatcher.

**Architecture:** A pure §10.10 extension-contract module
(`cross-repo-link.js`, mirrors `recipient-profile.js`'s own file shape)
defines the `CrossRepoLink` record shape and its stable id (`ids.js`'s
new `crossRepoLinkId`). A separate, impure loader (`federation-loader.js`)
reads a REMOTE repo's already-exported `DataFlowGraph v1` JSON artifact
(`dataflow export --format json`'s own artifact), verifying it via a
self-consistency digest check (never authentication) plus the existing
`validateGraph()`. `graph-builder.js` gains an additive
`opts.crossRepoLinks(graph) -> CrossRepoLink[]` hook (the graph's SIXTH
such hook, after `resolveSiteDecision`/`resolveDestination`/
`resolveTransitProtection`/`buildRecipientProfile`/`correlateObservations`),
composed by `coverage.js` over a pre-loaded, existence-gated
`opts.crossRepoLinkRecords` array that `index.js` loads once per scan
from `.agentic-security/cross-repo-links.json`. A new top-level CLI
dispatcher, `federate`, reuses `governance-edit.js`'s established
preview/version-guard/backup/audit write contract (and
`bin/agentic-security.js`'s existing `_writeConfigAtomic` helper,
unmodified) to let an operator declare a link (`federate declare`) or
audit already-declared ones against live state (`federate list`) — this
writes operator config, never the scanned graph, so it is deliberately
NOT a `dataflow` subcommand, the identical reasoning `governance`/
`remediation` already establish (now a third repetition of the pattern).

**Tech Stack:** Node.js ESM throughout (`scanner/src/lineage/`,
`scanner/bin/agentic-security.js`), Node's built-in `node:test` +
`node:assert/strict` for tests, `node:crypto` for SHA-256 digests/ids,
`node:fs`/`node:path` for file I/O. No new npm dependency, matching the
package's own zero-new-dependency convention.

**Spec:**
`docs/superpowers/plans/2026-09-02-data-flow-explorer-m5-cross-repo-scoping.md`.
**One correction to that document, independently verified against the
real code before this plan was written**: its opening file list implies
`graph-loader.js` lives under `scanner/src/lineage/`; it actually lives
at `scanner/src/server/graph-loader.js` (confirmed via
`scanner/src/server/CLAUDE.md` and the file itself). Every reference to
`loadSignedGraph` in this plan uses the correct path. Everything else in
the scoping doc was independently confirmed correct against the real
code and is followed exactly, not redesigned.

## Global Constraints

Copied verbatim from the spec's own "Global constraints for a future
implementation plan" section — every task's requirements implicitly
include these:

- No frontend/UI work — CLI/JSON export only, matching every M4/M5
  decision-intelligence deliverable's own established backend-first
  precedent.
- No live/network fetch of a remote graph, ever — `--remote-graph` is
  always a local file path the operator has already placed there (a
  copied CI artifact, a shared drive, a manual scp) — this codebase's
  own "no runtime cloud calls" convention (root `CLAUDE.md`) applies
  here exactly as it does everywhere else.
- No change to `nodeId`/`edgeId`/`flowId`/`dataElementId` or their
  discriminator shapes.
- No array-merge of two graphs' `nodes[]`/`edges[]` under any
  circumstance — each repo's graph stays independently
  `validateGraph()`-clean, unmodified, forever.
- `provenance: 'manual'` only — this deliverable never writes `'schema'`
  to `CrossRepoLink.provenance` (that value stays reserved for a future
  "imported"/auto-correlated producer, per the correction in the spec's
  own "The real correction" section).
- The remote-side digest check is a self-consistency check, never
  authentication — the CLI and `commands/federate.md` must both say so
  plainly, never imply a stronger trust guarantee than exists.

---

### Task 1: `cross-repo-link.js` contract + `ids.js`'s `crossRepoLinkId`

**Files:**
- Create: `scanner/src/lineage/cross-repo-link.js`
- Modify: `scanner/src/lineage/ids.js` (append `crossRepoLinkId`, after
  the existing `observationImportId` function at the end of the file)
- Test: `scanner/test/lineage/cross-repo-link.test.js`
- Modify: `scanner/package.json` (wire the new test file into
  `test:lineage`)

**Interfaces:**
- Produces (from `cross-repo-link.js`): `CROSS_REPO_LINK_VERSION`
  (string `'1.0.0'`); `CROSS_REPO_LINKS_FILENAME` (string
  `'cross-repo-links.json'`); `CROSS_REPO_LINK_RELATIONSHIP` (string
  `'data_flow'`); `validateCrossRepoLink(record) -> {valid: boolean,
  errors: Array<{path: string, message: string}>}`.
- Produces (from `ids.js`): `crossRepoLinkId({localGraphId,
  localGraphDigest, localNodeId, remoteGraphId, remoteGraphDigest,
  remoteNodeId, relationship}, discriminatorParts = []) -> string`
  (format `crosslink:<12-hex>`).
- Consumes: `EDGE_PROVENANCE_VALUES` from the already-shipped
  `scanner/src/lineage/schema.js`.
- Consumed by: Task 3 (`index.js`'s `_loadCrossRepoLinkRecords`), Task 4
  (`cmdFederateDeclare`).

- [ ] **Step 1: Write the failing test file**

Create `scanner/test/lineage/cross-repo-link.test.js`:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { crossRepoLinkId } from '../../src/lineage/ids.js';
import {
  CROSS_REPO_LINK_VERSION,
  CROSS_REPO_LINKS_FILENAME,
  CROSS_REPO_LINK_RELATIONSHIP,
  validateCrossRepoLink,
} from '../../src/lineage/cross-repo-link.js';
import { EDGE_PROVENANCE_VALUES } from '../../src/lineage/schema.js';

function baseInputs() {
  return {
    localGraphId: 'dfg:repo-a:abc123:default',
    localGraphDigest: 'sha256:local-digest',
    localNodeId: 'node:sink:aaaaaaaaaaaa',
    remoteGraphId: 'dfg:repo-b:def456:default',
    remoteGraphDigest: 'sha256:remote-digest',
    remoteNodeId: 'node:source:bbbbbbbbbbbb',
    relationship: 'data_flow',
  };
}

test('crossRepoLinkId is deterministic for identical inputs and differs on any input change', () => {
  const inputs = baseInputs();
  const a = crossRepoLinkId(inputs);
  const b = crossRepoLinkId(inputs);
  assert.equal(a, b);
  assert.match(a, /^crosslink:[0-9a-f]+$/);
  assert.notEqual(a, crossRepoLinkId({ ...inputs, localGraphDigest: 'sha256:different' }));
  assert.notEqual(a, crossRepoLinkId({ ...inputs, remoteGraphDigest: 'sha256:different' }));
  assert.notEqual(a, crossRepoLinkId({ ...inputs, localNodeId: 'node:sink:cccccccccccc' }));
  assert.notEqual(a, crossRepoLinkId({ ...inputs, remoteNodeId: 'node:source:dddddddddddd' }));
  assert.notEqual(a, crossRepoLinkId(inputs, ['discriminator-1']));
});

test('crossRepoLinkId never collides two different repo pairs sharing identical bare node-shape strings', () => {
  // The referential-soundness finding this deliverable's scoping doc
  // settles: a plain node id string is never looked up against a merged
  // set — both graphs' own graphId+graphDigest are baked into the id.
  const pairA = crossRepoLinkId({
    localGraphId: 'dfg:repo-a:c1:default', localGraphDigest: 'd1', localNodeId: 'node:sink:xxxxxxxxxxxx',
    remoteGraphId: 'dfg:repo-b:c2:default', remoteGraphDigest: 'd2', remoteNodeId: 'node:source:yyyyyyyyyyyy',
    relationship: 'data_flow',
  });
  const pairB = crossRepoLinkId({
    localGraphId: 'dfg:repo-c:c3:default', localGraphDigest: 'd3', localNodeId: 'node:sink:xxxxxxxxxxxx',
    remoteGraphId: 'dfg:repo-d:c4:default', remoteGraphDigest: 'd4', remoteNodeId: 'node:source:yyyyyyyyyyyy',
    relationship: 'data_flow',
  });
  assert.notEqual(pairA, pairB);
});

test('CROSS_REPO_LINK_VERSION/CROSS_REPO_LINKS_FILENAME/CROSS_REPO_LINK_RELATIONSHIP are the expected literals', () => {
  assert.equal(CROSS_REPO_LINK_VERSION, '1.0.0');
  assert.equal(CROSS_REPO_LINKS_FILENAME, 'cross-repo-links.json');
  assert.equal(CROSS_REPO_LINK_RELATIONSHIP, 'data_flow');
});

function validRecord(overrides = {}) {
  const inputs = baseInputs();
  return {
    id: crossRepoLinkId(inputs),
    version: CROSS_REPO_LINK_VERSION,
    provenance: 'manual',
    relationship: 'data_flow',
    local: { graphId: inputs.localGraphId, graphDigest: inputs.localGraphDigest, nodeId: inputs.localNodeId },
    remote: {
      repository: 'remote-service', sourceFile: '/tmp/remote-export.json',
      graphId: inputs.remoteGraphId, graphDigest: inputs.remoteGraphDigest, nodeId: inputs.remoteNodeId,
    },
    rationale: "Payment events flow from remote-service into this repo's ingestion endpoint.",
    declaredBy: 'ross',
    declaredAt: '2026-09-02T00:00:00.000Z',
    ...overrides,
  };
}

test('validateCrossRepoLink: a well-formed record is valid', () => {
  const { valid, errors } = validateCrossRepoLink(validRecord());
  assert.deepEqual(errors, []);
  assert.equal(valid, true);
});

test('validateCrossRepoLink: rationale may be null', () => {
  const { valid, errors } = validateCrossRepoLink(validRecord({ rationale: null }));
  assert.deepEqual(errors, []);
  assert.equal(valid, true);
});

test('validateCrossRepoLink: non-object record is invalid', () => {
  assert.equal(validateCrossRepoLink(null).valid, false);
  assert.equal(validateCrossRepoLink('x').valid, false);
  assert.equal(validateCrossRepoLink([]).valid, false);
});

test('validateCrossRepoLink: id must start with "crosslink:"', () => {
  const { valid, errors } = validateCrossRepoLink(validRecord({ id: 'node:not-a-crosslink' }));
  assert.equal(valid, false);
  assert.ok(errors.some((e) => e.path === '$.id'));
});

test('validateCrossRepoLink: provenance must be a real EDGE_PROVENANCE_VALUES member', () => {
  const bad = validateCrossRepoLink(validRecord({ provenance: 'made-up' }));
  assert.equal(bad.valid, false);
  assert.ok(bad.errors.some((e) => e.path === '$.provenance'));
  // Every real EDGE_PROVENANCE_VALUES member is structurally acceptable —
  // this deliverable's own CLI only ever writes 'manual', but the schema
  // reuse must not artificially narrow what the FIELD itself accepts.
  for (const v of EDGE_PROVENANCE_VALUES) {
    assert.equal(validateCrossRepoLink(validRecord({ provenance: v })).valid, true, `provenance "${v}" must validate`);
  }
});

test('validateCrossRepoLink: relationship must be exactly "data_flow"', () => {
  const { valid, errors } = validateCrossRepoLink(validRecord({ relationship: 'something_else' }));
  assert.equal(valid, false);
  assert.ok(errors.some((e) => e.path === '$.relationship'));
});

test('validateCrossRepoLink: local must be an object with non-empty graphId/graphDigest/nodeId', () => {
  assert.equal(validateCrossRepoLink(validRecord({ local: null })).valid, false);
  assert.equal(validateCrossRepoLink(validRecord({ local: { graphId: '', graphDigest: 'd', nodeId: 'n' } })).valid, false);
  assert.equal(validateCrossRepoLink(validRecord({ local: { graphId: 'g', graphDigest: '', nodeId: 'n' } })).valid, false);
  assert.equal(validateCrossRepoLink(validRecord({ local: { graphId: 'g', graphDigest: 'd', nodeId: '' } })).valid, false);
});

test('validateCrossRepoLink: remote requires repository and sourceFile in addition to graphId/graphDigest/nodeId', () => {
  const inputs = baseInputs();
  const base = { graphId: inputs.remoteGraphId, graphDigest: inputs.remoteGraphDigest, nodeId: inputs.remoteNodeId };
  assert.equal(validateCrossRepoLink(validRecord({ remote: { ...base, sourceFile: '/tmp/x.json' } })).valid, false, 'missing repository');
  assert.equal(validateCrossRepoLink(validRecord({ remote: { ...base, repository: 'svc' } })).valid, false, 'missing sourceFile');
  assert.equal(validateCrossRepoLink(validRecord({ remote: { ...base, repository: '', sourceFile: '/tmp/x.json' } })).valid, false, 'empty repository');
});

test('validateCrossRepoLink: declaredBy/declaredAt are required non-empty strings', () => {
  assert.equal(validateCrossRepoLink(validRecord({ declaredBy: '' })).valid, false);
  assert.equal(validateCrossRepoLink(validRecord({ declaredAt: null })).valid, false);
});

test('validateCrossRepoLink: never confirms local.nodeId/remote.nodeId actually exist in any real graph — zero graph access', () => {
  // A record naming node ids that could never exist in ANY real graph
  // still validates structurally — this module has no graph to check
  // against, by design.
  const { valid } = validateCrossRepoLink(validRecord({
    local: { graphId: 'g', graphDigest: 'd', nodeId: 'node:this-id-cannot-possibly-exist-anywhere' },
  }));
  assert.equal(valid, true);
});

test('cross-repo-link.js imports only ./schema.js — zero graph/fs access, mirrors scenario.js\'s own boundary', async () => {
  const { readFileSync } = await import('node:fs');
  const { fileURLToPath } = await import('node:url');
  const src = readFileSync(fileURLToPath(new URL('../../src/lineage/cross-repo-link.js', import.meta.url)), 'utf8');
  const specifiers = [...src.matchAll(/^\s*import[^'"]*['"]([^'"]+)['"]/gm)].map((m) => m[1]);
  assert.deepEqual(specifiers, ['./schema.js']);
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd scanner && node --test test/lineage/cross-repo-link.test.js`
Expected: FAIL — `Cannot find module '../../src/lineage/cross-repo-link.js'`
(and `crossRepoLinkId` is not exported from `ids.js`).

- [ ] **Step 3: Implement `crossRepoLinkId` in `ids.js`**

Append to the end of `scanner/src/lineage/ids.js` (after
`observationImportId`):

```js

/**
 * A CrossRepoLink record's id (M5 deliverable #8, FR-304 "declared"
 * half, §10.10) — NOT a DataFlowGraph v1 entity, mirrors
 * `recipientProfileId`'s own precedent exactly: `(graphId, graphDigest,
 * ...)` doubled for both endpoints. This is the concrete mechanism that
 * makes "id collision is impossible by construction" real rather than
 * aspirational: two links between structurally identical node shapes in
 * two different repo pairs cannot collide, because both graphs' own
 * `graphId`+`graphDigest` are baked into the id material on both sides —
 * a bare node id string is never looked up against a merged or ambiguous
 * set.
 */
export function crossRepoLinkId(
  {
    localGraphId, localGraphDigest, localNodeId,
    remoteGraphId, remoteGraphDigest, remoteNodeId,
    relationship,
  },
  discriminatorParts = [],
) {
  return `crosslink:${_hash(_canon([
    localGraphId, localGraphDigest, localNodeId,
    remoteGraphId, remoteGraphDigest, remoteNodeId,
    relationship, ...discriminatorParts,
  ]))}`;
}
```

- [ ] **Step 4: Implement `cross-repo-link.js`**

Create `scanner/src/lineage/cross-repo-link.js`:

```js
// cross-repo-link.js — M5 deliverable #8 (FR-304's "declared" half only,
// per the M5 top-level scoping doc's own DFG-025 row and this
// deliverable's own scoping doc, 2026-09-02). The CrossRepoLink
// extension contract — a graph-attached array (mirrors
// `graph.recipientProfiles[]`'s own precedent, `recipient-profile.js`),
// NEVER a DataFlowGraph v1 core-schema edge: `validate.js`'s
// `_validateEdge` requires both endpoints of an edge to resolve against
// the ONE graph's own `nodeIds` set, so a foreign node id from a
// different repo's build can never pass `validateGraph()` — settling,
// not merely motivating, the decision that a cross-repo link must be a
// separate extension record.
//
// Mirrors `recipient-profile.js`'s own file shape exactly (pure module,
// `{valid, errors}` validator, zero graph access at construction time),
// with the one real, disclosed departure that module's own header also
// discloses for itself: no per-field `fieldEvidence` map, since every
// field on a CrossRepoLink is uniformly operator-declared (no
// code-derived half) — closer to `ObligationMapping`'s single
// record-level `factType` shape (here, `provenance`) than to
// `RecipientProfile`'s per-field one.
//
// `provenance` reuses `schema.js`'s own `EDGE_PROVENANCE_VALUES` — this
// deliverable's CLI is the FIRST real producer of `'manual'` anywhere in
// this codebase (confirmed by the scoping investigation: every shipped
// edge is `provenance: 'code'`, unconditionally, per Milestone 2
// Sub-project F increment 1). `'schema'` stays reserved on the SAME
// field for a future "imported"/auto-correlated producer (FR-304's
// second flavor — destination/schema-based automatic cross-repo edge
// correlation) — explicitly out of scope for this deliverable, per the
// scoping doc's own "The real correction" section.

import { EDGE_PROVENANCE_VALUES } from './schema.js';

export const CROSS_REPO_LINK_VERSION = '1.0.0';

// The operator-config filename this deliverable's CLI reads/writes,
// resolved via `posture/state-dir.js`'s `statePath()` — mirrors
// `recipient-registry.js`'s own `RECIPIENT_CONFIG_FILENAME` precedent.
export const CROSS_REPO_LINKS_FILENAME = 'cross-repo-links.json';

// Fixed, single legal value — mirrors `edge.relationship`'s own single
// legal value ('data_flow', validate.js's `_validateEdge`). No new
// taxonomy is introduced for this deliverable.
export const CROSS_REPO_LINK_RELATIONSHIP = 'data_flow';

function _isNonEmptyString(v) { return typeof v === 'string' && v.length > 0; }
function _isStringOrNull(v) { return v === null || v === undefined || typeof v === 'string'; }
function _isPlainObject(v) { return v !== null && typeof v === 'object' && !Array.isArray(v); }

// Shared endpoint-shape check for `local`/`remote` — `local` always
// checks {graphId, graphDigest, nodeId}; `remote` additionally checks
// {repository, sourceFile} via `extraFields`.
function _validateEndpoint(endpoint, label, err, extraFields = []) {
  if (!_isPlainObject(endpoint)) {
    err(`$.${label}`, `${label} is required and must be an object`);
    return;
  }
  if (!_isNonEmptyString(endpoint.graphId)) err(`$.${label}.graphId`, `${label}.graphId is required`);
  if (!_isNonEmptyString(endpoint.graphDigest)) err(`$.${label}.graphDigest`, `${label}.graphDigest is required`);
  if (!_isNonEmptyString(endpoint.nodeId)) err(`$.${label}.nodeId`, `${label}.nodeId is required`);
  for (const field of extraFields) {
    if (!_isNonEmptyString(endpoint[field])) err(`$.${label}.${field}`, `${label}.${field} is required`);
  }
}

/**
 * Structural validation only — mirrors `validateRecipientProfile`'s/
 * `validateScenario`'s own `{valid, errors}` shape and "never throws"
 * contract. Never confirms `local.nodeId`/`remote.nodeId` actually exist
 * in any real graph — that needs real graph content, which this pure
 * module deliberately has no access to (mirrors `scenario.js`'s own
 * "structural-only, zero graph access" boundary exactly). That check is
 * `federation-loader.js`'s (for the remote side) and the CLI's own
 * `loadSignedGraph` call (for the local side) job, at declare time.
 *
 * @param {object} record
 * @returns {{valid: boolean, errors: Array<{path: string, message: string}>}}
 */
export function validateCrossRepoLink(record) {
  const errors = [];
  const err = (p, message) => errors.push({ path: p, message });

  if (!_isPlainObject(record)) {
    err('$', 'CrossRepoLink record must be an object');
    return { valid: false, errors };
  }

  if (!_isNonEmptyString(record.id) || !record.id.startsWith('crosslink:')) {
    err('$.id', 'id is required and must start with "crosslink:"');
  }
  if (!_isNonEmptyString(record.version)) err('$.version', 'version is required');
  if (!EDGE_PROVENANCE_VALUES.includes(record.provenance)) {
    err('$.provenance', `unrecognized provenance "${record.provenance}" — must be one of ${EDGE_PROVENANCE_VALUES.join('|')}`);
  }
  if (record.relationship !== CROSS_REPO_LINK_RELATIONSHIP) {
    err('$.relationship', `relationship must be "${CROSS_REPO_LINK_RELATIONSHIP}" (got "${record.relationship}")`);
  }

  _validateEndpoint(record.local, 'local', err);
  _validateEndpoint(record.remote, 'remote', err, ['repository', 'sourceFile']);

  if (!_isStringOrNull(record.rationale)) err('$.rationale', 'rationale must be a string or null');
  if (!_isNonEmptyString(record.declaredBy)) err('$.declaredBy', 'declaredBy is required');
  if (!_isNonEmptyString(record.declaredAt)) err('$.declaredAt', 'declaredAt is required');

  return { valid: errors.length === 0, errors };
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cd scanner && node --test test/lineage/cross-repo-link.test.js`
Expected: PASS, all tests green.

- [ ] **Step 6: Wire the new test file into `test:lineage`**

Edit `scanner/package.json`'s `test:lineage` script: append
` test/lineage/cross-repo-link.test.js` to the end of the existing
space-separated file list (after `test/lineage/runtime-corroboration-wiring.test.js`).

- [ ] **Step 7: Run the full scoped suite to confirm wiring**

Run: `cd scanner && npm run test:lineage`
Expected: PASS, including the new file, no regressions.

- [ ] **Step 8: Commit**

```bash
git add scanner/src/lineage/cross-repo-link.js scanner/src/lineage/ids.js \
  scanner/test/lineage/cross-repo-link.test.js scanner/package.json
git commit -m "feat(lineage): add the CrossRepoLink extension contract (M5 deliverable #8, Task 1)"
```

---

### Task 2: `federation-loader.js`

**Files:**
- Create: `scanner/src/lineage/federation-loader.js`
- Test: `scanner/test/lineage/federation-loader.test.js`
- Modify: `scanner/package.json` (wire the new test file into
  `test:lineage`)

**Interfaces:**
- Consumes: `validateGraph` from `./validate.js`; `computeGraphDigest`
  from `./export-json.js` (both already shipped).
- Produces: `loadRemoteGraphExport(filePath: string) -> {ok: boolean,
  graph: object|null, digest: string|null, digestMatches: boolean|null,
  reason: 'missing'|'malformed'|'invalid-graph'|'digest-mismatch'|null,
  message: string|null}`. `ok:false` only for `missing`/`malformed`/
  `invalid-graph`; `digest-mismatch` is `ok:true, digestMatches:false` —
  a non-blocking warning, never a failure.
- Consumed by: Task 4 (`cmdFederateDeclare`, `cmdFederateList`).
- Deliberately does NOT consume `loadSignedGraph` from
  `scanner/src/server/graph-loader.js` — see the module header below for
  why (the corrected file location per this plan's own header note).

- [ ] **Step 1: Write the failing test file**

Create `scanner/test/lineage/federation-loader.test.js`:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { graphId } from '../../src/lineage/ids.js';
import { emptyGraphEnvelope } from '../../src/lineage/schema.js';
import { exportGraphJSON, computeGraphDigest } from '../../src/lineage/export-json.js';
import { loadRemoteGraphExport } from '../../src/lineage/federation-loader.js';

function tmpFile(name) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'agsec-federation-loader-'));
  return path.join(dir, name);
}

function validEnvelopeFile() {
  const graph = emptyGraphEnvelope({ graphId: graphId({ repository: 'remote-svc' }) });
  const exported = exportGraphJSON(graph, { redact: false });
  const filePath = tmpFile('remote-export.json');
  fs.writeFileSync(filePath, JSON.stringify(exported, null, 2));
  return { filePath, graph, exported };
}

test('loadRemoteGraphExport: missing file — ok:false, reason "missing"', () => {
  const r = loadRemoteGraphExport(path.join(os.tmpdir(), 'this-file-does-not-exist-agsec-federation.json'));
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'missing');
  assert.equal(r.graph, null);
  assert.match(r.message, /No remote graph export found/);
});

test('loadRemoteGraphExport: no filePath at all — ok:false, reason "missing"', () => {
  const r = loadRemoteGraphExport(undefined);
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'missing');
});

test('loadRemoteGraphExport: malformed JSON — ok:false, reason "malformed"', () => {
  const filePath = tmpFile('bad.json');
  fs.writeFileSync(filePath, '{not valid json');
  const r = loadRemoteGraphExport(filePath);
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'malformed');
});

test('loadRemoteGraphExport: valid JSON but not an exportGraphJSON envelope — ok:false, reason "malformed"', () => {
  const filePath = tmpFile('not-an-envelope.json');
  fs.writeFileSync(filePath, JSON.stringify({ hello: 'world' }));
  const r = loadRemoteGraphExport(filePath);
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'malformed');
});

test('loadRemoteGraphExport: envelope has digest+graph but graph fails validateGraph — ok:false, reason "invalid-graph"', () => {
  const filePath = tmpFile('invalid-graph.json');
  const badGraph = { nodes: [{ id: 'not-a-real-node-id-shape' }] }; // missing required fields, wrong id prefix
  fs.writeFileSync(filePath, JSON.stringify({ digest: computeGraphDigest(badGraph), graph: badGraph }));
  const r = loadRemoteGraphExport(filePath);
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'invalid-graph');
  assert.equal(r.graph, null);
});

test('loadRemoteGraphExport: digest mismatch — ok:true, digestMatches:false, reason "digest-mismatch", still returns the graph', () => {
  const { filePath, exported } = validEnvelopeFile();
  const tampered = { ...exported, digest: 'sha256:0000000000000000000000000000000000000000000000000000000000000000' };
  fs.writeFileSync(filePath, JSON.stringify(tampered));
  const r = loadRemoteGraphExport(filePath);
  assert.equal(r.ok, true);
  assert.equal(r.digestMatches, false);
  assert.equal(r.reason, 'digest-mismatch');
  assert.ok(r.graph);
  assert.match(r.message, /NOT authentication/);
});

test('loadRemoteGraphExport: a genuinely valid, self-consistent export — ok:true, digestMatches:true, reason:null', () => {
  const { filePath, graph } = validEnvelopeFile();
  const r = loadRemoteGraphExport(filePath);
  assert.equal(r.ok, true);
  assert.equal(r.digestMatches, true);
  assert.equal(r.reason, null);
  assert.deepEqual(r.graph, graph);
  assert.equal(r.digest, computeGraphDigest(graph));
});

test('federation-loader.js never reuses loadSignedGraph for the remote side — the per-install-HMAC-key trust model is deliberately the WRONG one for a cross-machine remote file', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(fileURLToPath(new URL('../../src/lineage/federation-loader.js', import.meta.url)), 'utf8');
  assert.ok(!src.includes('graph-loader'), 'must never import scanner/src/server/graph-loader.js\'s loadSignedGraph for the remote side');
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd scanner && node --test test/lineage/federation-loader.test.js`
Expected: FAIL — `Cannot find module '../../src/lineage/federation-loader.js'`.

- [ ] **Step 3: Implement `federation-loader.js`**

Create `scanner/src/lineage/federation-loader.js`:

```js
// federation-loader.js — M5 deliverable #8 (FR-304's "declared" half):
// loadRemoteGraphExport(filePath) reads an exportGraphJSON-shaped file
// (dataflow export --format json's own artifact) — chosen over
// scanner/src/server/graph-loader.js's loadSignedGraph for the
// cross-machine reason this deliverable's own scoping investigation
// found: loadSignedGraph authenticates against a PER-INSTALL HMAC key,
// which is the wrong trust model for a file that crossed a repo/machine
// boundary in the common case (two repos scanned on two different
// machines sign under two different keys by default, so pointing
// loadSignedGraph at a second repo's checkout would, in the common case,
// correctly report 'tampered' even though nothing was actually
// tampered with). exportGraphJSON's portable, embedded-digest artifact
// is a SELF-CONSISTENCY check instead — never authentication, disclosed
// as such everywhere this module or its callers describe it.
//
// Mirrors graph-loader.js's own four-distinct-outcome discipline, with
// one structural difference: a digest mismatch here is NOT a blocking
// failure (`ok:false`) the way graph-loader.js's four reasons all are —
// it is a WARNING the caller must show, never silently swallowed, and
// does not by itself block a --yes write (the operator is explicitly
// asserting this file). `ok:true, digestMatches:false` is therefore a
// real, valid, non-failing outcome; only `missing`/`malformed`/
// `invalid-graph` set `ok:false`.

import * as fs from 'node:fs';
import { validateGraph } from './validate.js';
import { computeGraphDigest } from './export-json.js';

/**
 * @param {string} filePath
 * @returns {{
 *   ok: boolean,
 *   graph: object|null,
 *   digest: string|null,
 *   digestMatches: boolean|null,
 *   reason: 'missing'|'malformed'|'invalid-graph'|'digest-mismatch'|null,
 *   message: string|null,
 * }}
 */
export function loadRemoteGraphExport(filePath) {
  if (!filePath || typeof filePath !== 'string' || !fs.existsSync(filePath)) {
    return {
      ok: false, graph: null, digest: null, digestMatches: null, reason: 'missing',
      message: `No remote graph export found at ${filePath}. Run \`dataflow export --format json\` in the remote repository and point --remote-graph at the resulting file.`,
    };
  }

  let body;
  try {
    body = fs.readFileSync(filePath, 'utf8');
  } catch (e) {
    return {
      ok: false, graph: null, digest: null, digestMatches: null, reason: 'missing',
      message: `Remote graph export found at ${filePath} but could not be read: ${e && e.message ? e.message : e}.`,
    };
  }

  let parsed;
  try {
    parsed = JSON.parse(body);
  } catch (e) {
    return {
      ok: false, graph: null, digest: null, digestMatches: null, reason: 'malformed',
      message: `Remote graph export at ${filePath} is not valid JSON (${e && e.message ? e.message : e}).`,
    };
  }

  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)
    || typeof parsed.digest !== 'string' || !parsed.digest
    || !parsed.graph || typeof parsed.graph !== 'object' || Array.isArray(parsed.graph)) {
    return {
      ok: false, graph: null, digest: null, digestMatches: null, reason: 'malformed',
      message: `Remote graph export at ${filePath} does not look like an \`exportGraphJSON\` artifact — expected top-level "digest" (string) and "graph" (object) fields. Run \`dataflow export --format json\` to produce a valid one.`,
    };
  }

  const { valid, errors } = validateGraph(parsed.graph);
  if (!valid) {
    return {
      ok: false, graph: null, digest: parsed.digest, digestMatches: null, reason: 'invalid-graph',
      message: `Remote graph export at ${filePath} does not contain a well-formed DataFlowGraph v1 document: ${errors.map((e) => `${e.path}: ${e.message}`).join('; ')}`,
    };
  }

  const recomputed = computeGraphDigest(parsed.graph);
  const digestMatches = recomputed === parsed.digest;
  if (!digestMatches) {
    return {
      ok: true, graph: parsed.graph, digest: parsed.digest, digestMatches: false, reason: 'digest-mismatch',
      message: 'WARNING: the remote export\'s embedded digest does not match its own content (self-consistency check failed) — this is NOT authentication, only a check that the file has not been altered since it was exported. Proceeding is a real trust decision the operator is making explicitly.',
    };
  }

  return { ok: true, graph: parsed.graph, digest: parsed.digest, digestMatches: true, reason: null, message: null };
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd scanner && node --test test/lineage/federation-loader.test.js`
Expected: PASS, all tests green.

- [ ] **Step 5: Wire the new test file into `test:lineage`**

Edit `scanner/package.json`'s `test:lineage` script: append
` test/lineage/federation-loader.test.js` to the end of the file list
(after the `cross-repo-link.test.js` entry added in Task 1).

- [ ] **Step 6: Run the full scoped suite to confirm wiring**

Run: `cd scanner && npm run test:lineage`
Expected: PASS, no regressions.

- [ ] **Step 7: Commit**

```bash
git add scanner/src/lineage/federation-loader.js \
  scanner/test/lineage/federation-loader.test.js scanner/package.json
git commit -m "feat(lineage): add loadRemoteGraphExport, the portable remote-graph reader (M5 deliverable #8, Task 2)"
```

---

### Task 3: Graph-attachment wiring (`graph-builder.js`, `coverage.js`, `index.js`)

**Files:**
- Modify: `scanner/src/lineage/graph-builder.js`
- Modify: `scanner/src/lineage/coverage.js`
- Modify: `scanner/src/lineage/index.js`
- Test: `scanner/test/lineage/cross-repo-link-wiring.test.js`
- Modify: `scanner/package.json` (wire the new test file into
  `test:lineage`)

**Interfaces:**
- Consumes: `CROSS_REPO_LINKS_FILENAME`, `validateCrossRepoLink` from
  Task 1's `cross-repo-link.js`. Does NOT consume anything from Task 2
  (`federation-loader.js` is used only by the CLI, Task 4).
- Produces: `graph.crossRepoLinks: CrossRepoLink[]` — always present on
  every graph `buildDataFlowGraph`/`buildGraphWithCoverage`/
  `buildLineageGraph` return, `[]` when no hook/records are supplied.
  `opts.crossRepoLinks(graph) -> CrossRepoLink[]` — the new
  `graph-builder.js` hook. `opts.crossRepoLinkRecords: CrossRepoLink[] |
  undefined` — the new `coverage.js`/`buildLineageGraph` option (a
  pre-loaded array; `undefined` means "no `cross-repo-links.json` on
  disk").
- Consumed by: Task 4's CLI only indirectly (the CLI writes
  `cross-repo-links.json` directly; a LATER scan is what causes this
  wiring to actually populate `graph.crossRepoLinks`). Not a hard
  dependency of Task 4's own tests.

- [ ] **Step 1: Write the failing test file**

Create `scanner/test/lineage/cross-repo-link-wiring.test.js`:

```js
//
// cross-repo-link-wiring.test.js — M5 deliverable #8 (FR-304 "declared"
// half), graph-attachment wiring. Real-code proof that
// `opts.crossRepoLinks` — graph-builder.js's SIXTH additive hook of the
// `opts.buildRecipientProfile`/`opts.correlateObservations` shape — is
// wired correctly: composes additively, is byte-identical when omitted
// (mirroring `M2A1/hook-1`'s own precedent, per this package's own
// CLAUDE.md), and (via coverage.js's default wiring) drops a stale
// declaration whose local.nodeId no longer resolves against the current
// graph while keeping a valid one, reporting the drop via console.error
// rather than silently keeping it. index.js's own existence-gated
// single-load-per-call wiring is proven end to end.
//

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fsp from 'node:fs/promises';
import * as path from 'node:path';
import * as os from 'node:os';
import { parseJsFile } from '../../src/ir/parser-js.js';
import { buildCallGraph } from '../../src/ir/callgraph.js';
import { buildDataFlowGraph } from '../../src/lineage/graph-builder.js';
import { buildGraphWithCoverage } from '../../src/lineage/coverage.js';
import { buildLineageGraph } from '../../src/lineage/index.js';
import { crossRepoLinkId } from '../../src/lineage/ids.js';
import { CROSS_REPO_LINK_VERSION, CROSS_REPO_LINKS_FILENAME } from '../../src/lineage/cross-repo-link.js';

function irOf(files) {
  const perFile = {};
  for (const [f, code] of Object.entries(files)) perFile[f] = parseJsFile(f, code);
  return buildCallGraph(perFile);
}

const SOURCE = 'function h(req, res){ const pw = req.body.password; res.send(pw); }';

function sinkNodeOf(graph) {
  const n = graph.nodes.find((x) => x.kind === 'sink');
  assert.ok(n, 'fixture must produce a real sink node');
  return n;
}

function fakeRecord(overrides = {}) {
  const inputs = {
    localGraphId: 'dfg:local:c1:default', localGraphDigest: 'ld', localNodeId: 'node:sink:placeholder',
    remoteGraphId: 'dfg:remote:c2:default', remoteGraphDigest: 'rd', remoteNodeId: 'node:source:placeholder',
    relationship: 'data_flow',
  };
  return {
    id: crossRepoLinkId(inputs),
    version: CROSS_REPO_LINK_VERSION,
    provenance: 'manual',
    relationship: 'data_flow',
    local: { graphId: inputs.localGraphId, graphDigest: inputs.localGraphDigest, nodeId: inputs.localNodeId },
    remote: { repository: 'remote-svc', sourceFile: '/tmp/remote.json', graphId: inputs.remoteGraphId, graphDigest: inputs.remoteGraphDigest, nodeId: inputs.remoteNodeId },
    rationale: 'test',
    declaredBy: 'tester',
    declaredAt: '2026-09-02T00:00:00.000Z',
    ...overrides,
  };
}

// ── graph-builder.js: no-op when omitted, composes when supplied ────────

test('cross-repo-link-wiring/1: graph.crossRepoLinks is always [] when opts.crossRepoLinks is omitted', () => {
  const cg = irOf({ 'a.js': SOURCE });
  const r = buildDataFlowGraph(cg, { repository: 'r', generatedAt: '1970-01-01T00:00:00.000Z' });
  assert.deepEqual(r.graph.crossRepoLinks, []);
});

test('cross-repo-link-wiring/1b: omitting opts.crossRepoLinks leaves every other field byte-identical to a run with a no-op hook', () => {
  const cg = irOf({ 'a.js': SOURCE });
  const baseline = buildDataFlowGraph(cg, { repository: 'r', generatedAt: '1970-01-01T00:00:00.000Z' });
  const withNoopHook = buildDataFlowGraph(cg, { repository: 'r', generatedAt: '1970-01-01T00:00:00.000Z', crossRepoLinks: () => [] });
  assert.deepEqual(baseline.graph, withNoopHook.graph);
});

test('cross-repo-link-wiring/2: opts.crossRepoLinks, when it returns records, populates graph.crossRepoLinks (sorted by id)', () => {
  const cg = irOf({ 'a.js': SOURCE });
  const recordA = fakeRecord({ id: 'crosslink:aaaa' });
  const recordB = fakeRecord({ id: 'crosslink:bbbb' });
  const r = buildDataFlowGraph(cg, { repository: 'r', generatedAt: '1970-01-01T00:00:00.000Z', crossRepoLinks: () => [recordB, recordA] });
  assert.deepEqual(r.graph.crossRepoLinks.map((x) => x.id), ['crosslink:aaaa', 'crosslink:bbbb']);
});

test('cross-repo-link-wiring/3: opts.crossRepoLinks receives the REAL, finished graph — can look up a real node id in graph.nodes', () => {
  const cg = irOf({ 'a.js': SOURCE });
  let seenNodeIds = null;
  buildDataFlowGraph(cg, {
    repository: 'r', generatedAt: '1970-01-01T00:00:00.000Z',
    crossRepoLinks: (graph) => { seenNodeIds = graph.nodes.map((n) => n.id); return []; },
  });
  assert.ok(Array.isArray(seenNodeIds) && seenNodeIds.length > 0, 'the hook must see the real, populated node array, never an empty envelope');
});

// ── coverage.js: default hook drops a stale record, keeps a valid one ──

test('cross-repo-link-wiring/4: coverage.js\'s default hook drops a record whose local.nodeId is not in the current graph, keeps one that is', () => {
  const cg = irOf({ 'a.js': SOURCE });
  const { graph: probe } = buildDataFlowGraph(cg, { repository: 'r', generatedAt: '1970-01-01T00:00:00.000Z' });
  const realNodeId = sinkNodeOf(probe).id;
  const staleRecord = fakeRecord({ id: 'crosslink:stale', local: { graphId: 'g', graphDigest: 'd', nodeId: 'node:sink:this-node-was-removed' } });
  const validRecord = fakeRecord({ id: 'crosslink:valid', local: { graphId: 'g', graphDigest: 'd', nodeId: realNodeId } });
  const originalError = console.error;
  const errors = [];
  console.error = (msg) => errors.push(msg);
  let built;
  try {
    built = buildGraphWithCoverage(cg, { repository: 'r', generatedAt: '1970-01-01T00:00:00.000Z', crossRepoLinkRecords: [staleRecord, validRecord] });
  } finally { console.error = originalError; }
  assert.deepEqual(built.graph.crossRepoLinks.map((x) => x.id), ['crosslink:valid']);
  assert.ok(errors.some((m) => m.includes('crosslink:stale')), 'the drop must be reported, never silent');
});

test('cross-repo-link-wiring/5: coverage.js installs NO default hook when opts.crossRepoLinkRecords is undefined — graph.crossRepoLinks stays []', () => {
  const cg = irOf({ 'a.js': SOURCE });
  const built = buildGraphWithCoverage(cg, { repository: 'r', generatedAt: '1970-01-01T00:00:00.000Z' });
  assert.deepEqual(built.graph.crossRepoLinks, []);
});

// ── index.js: single-load-per-call, existence-gated ─────────────────────

async function tmpProject() {
  const d = await fsp.mkdtemp(path.join(os.tmpdir(), 'lineage-crosslink-wiring-'));
  await fsp.writeFile(path.join(d, 'package.json'), '{"name":"t"}');
  return d;
}

test('cross-repo-link-wiring/6: buildLineageGraph with NO cross-repo-links.json — graph.crossRepoLinks stays [] end to end', async () => {
  const dir = await tmpProject();
  try {
    const r = buildLineageGraph(irOf({ 'a.js': SOURCE }), { repository: 'r', scanRoot: dir });
    assert.equal(r.status, 'complete');
    assert.deepEqual(r.graph.crossRepoLinks, []);
  } finally { await fsp.rm(dir, { recursive: true, force: true }); }
});

test('cross-repo-link-wiring/7: buildLineageGraph with a real, valid cross-repo-links.json declares the link end to end', async () => {
  const dir = await tmpProject();
  try {
    const cg = irOf({ 'a.js': SOURCE });
    const { graph: probe } = buildDataFlowGraph(cg, { repository: 'r', generatedAt: '1970-01-01T00:00:00.000Z' });
    const realNodeId = sinkNodeOf(probe).id;
    const record = fakeRecord({ id: 'crosslink:real', local: { graphId: 'g', graphDigest: 'd', nodeId: realNodeId } });
    await fsp.mkdir(path.join(dir, '.agentic-security'), { recursive: true });
    await fsp.writeFile(path.join(dir, '.agentic-security', CROSS_REPO_LINKS_FILENAME), JSON.stringify({ links: [record] }));
    const r = buildLineageGraph(cg, { repository: 'r', scanRoot: dir, generatedAt: '1970-01-01T00:00:00.000Z' });
    assert.equal(r.status, 'complete');
    assert.deepEqual(r.graph.crossRepoLinks.map((x) => x.id), ['crosslink:real']);
  } finally { await fsp.rm(dir, { recursive: true, force: true }); }
});

test('cross-repo-link-wiring/8: buildLineageGraph with a malformed cross-repo-links.json degrades to [] rather than crashing the scan', async () => {
  const dir = await tmpProject();
  try {
    await fsp.mkdir(path.join(dir, '.agentic-security'), { recursive: true });
    await fsp.writeFile(path.join(dir, '.agentic-security', CROSS_REPO_LINKS_FILENAME), '{not valid json');
    const r = buildLineageGraph(irOf({ 'a.js': SOURCE }), { repository: 'r', scanRoot: dir });
    assert.equal(r.status, 'complete');
    assert.deepEqual(r.graph.crossRepoLinks, []);
  } finally { await fsp.rm(dir, { recursive: true, force: true }); }
});

test('cross-repo-link-wiring/9: buildLineageGraph with a cross-repo-links.json containing one malformed and one valid entry keeps only the valid one', async () => {
  const dir = await tmpProject();
  try {
    const cg = irOf({ 'a.js': SOURCE });
    const { graph: probe } = buildDataFlowGraph(cg, { repository: 'r', generatedAt: '1970-01-01T00:00:00.000Z' });
    const realNodeId = sinkNodeOf(probe).id;
    const valid = fakeRecord({ id: 'crosslink:ok', local: { graphId: 'g', graphDigest: 'd', nodeId: realNodeId } });
    const malformed = { id: 'not-a-real-id', bogus: true };
    await fsp.mkdir(path.join(dir, '.agentic-security'), { recursive: true });
    await fsp.writeFile(path.join(dir, '.agentic-security', CROSS_REPO_LINKS_FILENAME), JSON.stringify({ links: [malformed, valid] }));
    const r = buildLineageGraph(cg, { repository: 'r', scanRoot: dir, generatedAt: '1970-01-01T00:00:00.000Z' });
    assert.deepEqual(r.graph.crossRepoLinks.map((x) => x.id), ['crosslink:ok']);
  } finally { await fsp.rm(dir, { recursive: true, force: true }); }
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd scanner && node --test test/lineage/cross-repo-link-wiring.test.js`
Expected: FAIL — `graph.crossRepoLinks` is `undefined` (the field
doesn't exist yet); `buildGraphWithCoverage`'s call with
`crossRepoLinkRecords` doesn't error but the field stays `undefined`
too.

- [ ] **Step 3: Implement the `graph-builder.js` hook**

In `scanner/src/lineage/graph-builder.js`, insert this documentation
paragraph after the existing "M5 deliverable #7 ... correlateObservations"
header comment paragraph (immediately before the line `// Reuse boundary
(§12, confirmed against the source): imports ONLY`):

```js
//
// M5 deliverable #8 (FR-304 "declared" half only, §10.10): `opts.
// crossRepoLinks(graph) -> CrossRepoLink[]`, a SIXTH additive hook of
// the identical shape — applied once every graph array AND
// `recipientProfiles` are populated, mirroring `opts.buildRecipientProfile`'s
// own placement exactly (the hook can validate a declared
// `local.nodeId` against the CURRENT graph's own real node set).
// `graph.crossRepoLinks` is always present — mirrors
// `graph.recipientProfiles[]`'s own "always an array, possibly empty"
// shape, NOT `graph.runtimeCorroboration`'s own "genuinely absent when
// the hook is omitted" shape, since a CrossRepoLink array has no
// `not_evaluated` state to preserve the way runtime corroboration does.
```

Then insert the following block into `buildDataFlowGraph`, immediately
after the existing line

```js
  graph.recipientProfiles = [...recipientProfilesById.values()].sort(byId);
```

and before the comment `// M5 deliverable #7 (FR-505 §7.12, AC-29): a
FIFTH additive hook of the`:

```js
  // M5 deliverable #8 (FR-304 "declared" half only, §10.10): a SIXTH
  // additive hook of the identical shape — `opts.crossRepoLinks(graph) ->
  // CrossRepoLink[]`. Runs here, after nodes/edges/flows/dataElements AND
  // recipientProfiles are populated, mirroring `opts.buildRecipientProfile`'s
  // own placement exactly: the hook can validate a declared `local.nodeId`
  // against the CURRENT graph's own real node set (a stale declaration, from
  // before a node was renamed/removed in a later rescan, is DROPPED and
  // reported by the hook itself, never silently kept stale — matching
  // `applyScenario`'s own "skippedOperations, never thrown" honesty
  // precedent; see `coverage.js`'s default hook for where that drop/report
  // logic lives). `graph.crossRepoLinks` is always present (mirrors
  // `graph.recipientProfiles`'s own "always an array, possibly empty" shape,
  // not `graph.runtimeCorroboration`'s own "genuinely absent when the hook
  // is omitted" shape — a CrossRepoLink array has no not_evaluated-vs-empty
  // distinction to preserve the way runtime corroboration does). Never in
  // `dataflow-graph.schema.json`, never routed through `validateGraph()` —
  // the SECOND §10.10 extension array ever attached directly to the graph
  // object (after `graph.recipientProfiles[]`).
  graph.crossRepoLinks = typeof opts.crossRepoLinks === 'function'
    ? [...(opts.crossRepoLinks(graph) || [])].sort(byId)
    : [];
```

- [ ] **Step 4: Implement the `coverage.js` default hook**

In `scanner/src/lineage/coverage.js`, add a new `@param` block to the
big JSDoc comment above `buildGraphWithCoverage`, immediately after the
existing `@param {string} [opts.observationWindowEnd]` block:

```js
 * @param {Array<object>} [opts.crossRepoLinkRecords] M5 deliverable #8
 *   (FR-304 "declared" half): a PRE-LOADED `CrossRepoLink[]` array —
 *   never a path, the read happens once, upstream, in `index.js`'s
 *   `buildLineageGraph` (mirroring `opts.recipientConfig`'s own
 *   wording). `undefined` means "no cross-repo-links.json was
 *   consulted" (`index.js`'s own `existsSync` gate never found the
 *   file) and installs NO default `opts.crossRepoLinks` hook at all —
 *   `graph.crossRepoLinks` still reads `[]` either way (the same
 *   visible OUTCOME as "consulted and genuinely empty"), unlike
 *   `opts.runtimeObservations`'s own `undefined`-vs-`[]` distinction,
 *   because a CrossRepoLink array carries no `not_evaluated` state to
 *   preserve the way runtime corroboration does (see `graph-builder.js`'s
 *   own comment on this hook for the full reasoning). The default hook,
 *   when installed, DROPS any record whose `local.nodeId` is not present
 *   in the graph's own current `nodes[]` (a stale declaration from
 *   before a rescan), reporting each dropped id via `console.error`
 *   rather than silently keeping it.
```

Then, inside `buildGraphWithCoverage`'s call to `buildDataFlowGraph`,
insert the following property immediately after the existing
`correlateObservations: opts.correlateObservations ?? (...)` block and
before the closing `});`:

```js
    // M5 deliverable #8 (FR-304 "declared" half): identical composition
    // pattern to `opts.correlateObservations` immediately above — a
    // caller-supplied hook always wins. The default is installed ONLY when
    // `opts.crossRepoLinkRecords` is genuinely defined (`index.js`'s own
    // `existsSync` gate against `.agentic-security/cross-repo-links.json`
    // found the file); when it is `undefined`, NO hook is installed and
    // `graph.crossRepoLinks` stays `[]` via `graph-builder.js`'s own
    // unconditional default — there is no `not_evaluated` state for this
    // array to preserve, unlike `correlateObservations`'s own
    // `undefined`-vs-`[]` distinction. When installed, the default hook
    // drops any record whose `local.nodeId` no longer resolves against the
    // CURRENT graph's own real node set (a stale declaration from before a
    // rescan renamed/removed the node) rather than silently keeping it —
    // matching `applyScenario`'s own "skippedOperations, never thrown"
    // honesty precedent — and reports every drop via `console.error`.
    crossRepoLinks: opts.crossRepoLinks
      ?? (opts.crossRepoLinkRecords !== undefined
        ? ((graph) => {
          const nodeIds = new Set((graph.nodes ?? []).map((n) => n.id));
          const kept = [];
          const dropped = [];
          for (const record of opts.crossRepoLinkRecords) {
            if (record && record.local && nodeIds.has(record.local.nodeId)) kept.push(record);
            else dropped.push(record);
          }
          if (dropped.length > 0) {
            console.error(`agentic-security: dropped ${dropped.length} stale cross-repo link${dropped.length === 1 ? '' : 's'} (local.nodeId not found in the current graph): ${dropped.map((r) => (r && r.id) || '(malformed)').join(', ')}`);
          }
          return kept;
        })
        : undefined),
```

- [ ] **Step 5: Implement the `index.js` load**

In `scanner/src/lineage/index.js`, add the import (after the existing
`import { loadObservations } from './observation-store.js';` line):

```js
// M5 deliverable #8 (FR-304 "declared" half): loaded ONCE, here —
// mirroring `privacySinkPolicy`'s own existence-gated, single-computation
// discipline below (never `recipientConfig`'s unconditional-call one — a
// missing cross-repo-links.json here means "no links declared", a real,
// distinguishable-from-empty state worth keeping honest the same way
// `privacy-policy.json`'s absence is, per this deliverable's own scoping
// doc). `validateCrossRepoLink` is imported directly (not a separate
// loader module) — see `_loadCrossRepoLinkRecords` below for why this
// small, local, tolerant reader lives here rather than in
// `cross-repo-link.js` (which must stay a PURE, zero-fs-access module,
// mirroring `scenario.js`'s own boundary) or `federation-loader.js`
// (which owns only the REMOTE side).
import { validateCrossRepoLink, CROSS_REPO_LINKS_FILENAME } from './cross-repo-link.js';
```

Then add this local helper function, placed after the imports and
before the `buildLineageGraph` JSDoc comment:

```js
// A small, LOCAL, tolerant loader for the operator-declared
// cross-repo-links.json config file — mirrors `loadRecipientConfig`'s own
// fail-closed, skip-the-whole-entry-on-any-defect discipline
// (recipient-registry.js), but kept local to this file rather than
// exported from `cross-repo-link.js`/`federation-loader.js` (see the
// import comment above for the full reasoning). Never throws; a missing
// file is never reached here at all (the caller already gated on
// `fs.existsSync`); a malformed file or a malformed individual link
// degrades to an empty/partial array with a console warning naming the
// count skipped, mirroring `loadRecipientConfig`'s own per-entry
// discipline.
function _loadCrossRepoLinkRecords(filePath) {
  let raw;
  try {
    raw = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (e) {
    console.error(`agentic-security: bad JSON in cross-repo links file (${filePath}) — falling back to no declared links (${e.message})`);
    return [];
  }
  if (!raw || typeof raw !== 'object' || Array.isArray(raw) || !Array.isArray(raw.links)) {
    console.error(`agentic-security: cross-repo links file ${filePath} has no "links" array — falling back to no declared links (expected {"links": [...]})`);
    return [];
  }
  const records = [];
  let skipped = 0;
  for (const record of raw.links) {
    const { valid } = validateCrossRepoLink(record);
    if (!valid) { skipped += 1; continue; }
    records.push(record);
  }
  if (skipped > 0) {
    console.error(`agentic-security: skipped ${skipped} malformed cross-repo-link entr${skipped === 1 ? 'y' : 'ies'} in ${filePath} (each must be a valid CrossRepoLink-shaped object)`);
  }
  return records;
}
```

Then, inside `buildLineageGraph`'s `try` block, insert the following
immediately after the `runtimeObservations` computation (right before
`const built = buildGraphWithCoverage(callGraph, {`):

```js
    // M5 deliverable #8 (FR-304 "declared" half): the operator's declared
    // cross-repo links, loaded exactly once here — the same
    // single-computation discipline every other config load in this
    // function follows. Existence is checked EXPLICITLY, exactly like
    // `privacySinkPolicy` above.
    const _crossRepoLinksFile = opts.scanRoot ? statePath(opts.scanRoot, CROSS_REPO_LINKS_FILENAME) : null;
    const crossRepoLinkRecords = _crossRepoLinksFile && fs.existsSync(_crossRepoLinksFile)
      ? _loadCrossRepoLinkRecords(_crossRepoLinksFile)
      : undefined;
```

Finally, add `crossRepoLinkRecords,` to the options object literal
passed to `buildGraphWithCoverage`, immediately after the existing
`runtimeObservations,` line:

```js
      recipientConfig,
      runtimeObservations,
      crossRepoLinkRecords,
      observationWindowStart: opts.observationWindowStart,
      observationWindowEnd: opts.observationWindowEnd,
    });
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `cd scanner && node --test test/lineage/cross-repo-link-wiring.test.js`
Expected: PASS, all 9 tests green.

- [ ] **Step 7: Wire the new test file into `test:lineage`**

Edit `scanner/package.json`'s `test:lineage` script: append
` test/lineage/cross-repo-link-wiring.test.js` to the end of the file
list.

- [ ] **Step 8: Run the full scoped suite to confirm no regressions**

Run: `cd scanner && npm run test:lineage`
Expected: PASS in full — this step is the real regression proof for the
additive hook placement in `graph-builder.js`/`coverage.js`/`index.js`,
since those files are exercised by dozens of pre-existing tests.

- [ ] **Step 9: Commit**

```bash
git add scanner/src/lineage/graph-builder.js scanner/src/lineage/coverage.js \
  scanner/src/lineage/index.js scanner/test/lineage/cross-repo-link-wiring.test.js \
  scanner/package.json
git commit -m "feat(lineage): wire graph.crossRepoLinks into graph-builder/coverage/index (M5 deliverable #8, Task 3)"
```

---

### Task 4: The CLI (`federate declare`/`federate list`)

**Files:**
- Modify: `scanner/bin/agentic-security.js`
- Modify: `scanner/src/posture/artifact-registry.js`
- Test: `scanner/test/cli/federate-declare-list.test.js`
- Modify: `scanner/package.json` (wire the new test file into
  `test:mcp`)

**Interfaces:**
- Consumes: `CROSS_REPO_LINK_VERSION`, `CROSS_REPO_LINKS_FILENAME`,
  `CROSS_REPO_LINK_RELATIONSHIP`, `validateCrossRepoLink` from Task 1's
  `cross-repo-link.js`; `crossRepoLinkId` from Task 1's `ids.js`;
  `loadRemoteGraphExport` from Task 2's `federation-loader.js`;
  `loadSignedGraph` from the ALREADY-SHIPPED
  `scanner/src/server/graph-loader.js` (note: not
  `scanner/src/lineage/`, per this plan's own header correction);
  `computeGraphDigest` from the already-shipped
  `scanner/src/lineage/export-json.js`; `statePath`/`isSafeStateDir`
  from the already-shipped `scanner/src/posture/state-dir.js`;
  `auditCall` from the already-shipped `scanner/src/mcp/audit.js`;
  `_writeConfigAtomic(fp, content)` — ALREADY DEFINED, unmodified, in
  `scanner/bin/agentic-security.js` (used identically by
  `cmdGovernancePropose`).
- Produces: `cmdFederateDeclare(args) -> Promise<number>`,
  `cmdFederateList(args) -> Promise<number>`, and the `case 'federate':`
  dispatch branch in `main()`.
- Does NOT depend on Task 3's graph-attachment wiring — `federate
  declare`/`federate list` read/write `cross-repo-links.json` and the
  local/remote graph artifacts directly; a later scan is what causes
  Task 3's wiring to read the file this task writes.

- [ ] **Step 1: Write the failing test file**

Create `scanner/test/cli/federate-declare-list.test.js`:

```js
// federate-declare-list.test.js — M5 deliverable #8 (FR-304's "declared"
// half). CLI subprocess tests for `agentic-security federate
// declare|list`. Mirrors test/cli/governance-propose-edit.test.js's real
// -subprocess spawnSync pattern, plus test/cli/dataflow-recipients.test.js's
// real-git-fixture + real-deep-scan pattern for producing a genuine,
// signed local lineage graph and a genuine remote graph export.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createGitFixture } from '../helpers/build-git-fixture.js';
import { statePath } from '../../src/posture/state-dir.js';

const CLI = fileURLToPath(new URL('../../bin/agentic-security.js', import.meta.url));

const SINK_SOURCE = 'function h(req, res){ const pw = req.body.password; res.send(pw); }';

function _scanWithLineage(fx) {
  return spawnSync(process.execPath, [CLI, 'scan', '.'], {
    cwd: fx.root, encoding: 'utf8', timeout: 60000,
    env: { ...process.env, AGENTIC_SECURITY_LINEAGE_DEEP: '1' },
  });
}

function _localGraphNodeId(fx) {
  const graphPath = statePath(fx.root, 'lineage-graph.json');
  const graph = JSON.parse(fs.readFileSync(graphPath, 'utf8'));
  const n = graph.nodes.find((x) => x.kind === 'sink');
  assert.ok(n, 'the local fixture must produce a real sink node');
  return n.id;
}

function _buildRemoteExport(remoteExportPath) {
  const fx = createGitFixture();
  fx.writeFile('server.js', SINK_SOURCE);
  fx.commit('add sink');
  const scanR = _scanWithLineage(fx);
  assert.ok(scanR.status <= 3, `remote scan must exit <=3; got ${scanR.status}: ${scanR.stderr}`);
  const exportR = spawnSync(process.execPath, [CLI, 'dataflow', 'export', '.', '--format', 'json', '--no-redact', '--output', remoteExportPath], {
    cwd: fx.root, encoding: 'utf8', timeout: 30000,
  });
  assert.equal(exportR.status, 0, exportR.stderr);
  const exported = JSON.parse(fs.readFileSync(remoteExportPath, 'utf8'));
  const remoteNode = exported.graph.nodes.find((x) => x.kind === 'sink');
  assert.ok(remoteNode, 'the remote fixture must produce a real sink node');
  fx.cleanup();
  return remoteNode.id;
}

function _declare(fx, extraArgs) {
  return spawnSync(process.execPath, [CLI, 'federate', 'declare', '.', ...extraArgs], {
    cwd: fx.root, encoding: 'utf8', timeout: 15000,
  });
}

function _list(fx, extraArgs = []) {
  return spawnSync(process.execPath, [CLI, 'federate', 'list', '.', ...extraArgs], {
    cwd: fx.root, encoding: 'utf8', timeout: 15000,
  });
}

test('federate declare: without --yes, previews and does NOT write', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('server.js', SINK_SOURCE);
  fx.commit('add sink');
  const scanR = _scanWithLineage(fx);
  assert.ok(scanR.status <= 3, scanR.stderr);
  const localNodeId = _localGraphNodeId(fx);
  const remoteExportPath = path.join(fx.root, 'remote-export.json');
  const remoteNodeId = _buildRemoteExport(remoteExportPath);

  const r = _declare(fx, ['--local-node', localNodeId, '--remote-graph', remoteExportPath, '--remote-node', remoteNodeId, '--repository', 'remote-svc']);
  assert.equal(r.status, 0, r.stderr);
  const configPath = statePath(fx.root, 'cross-repo-links.json');
  assert.equal(fs.existsSync(configPath), false, 'no --yes must never write');
  const report = JSON.parse(r.stdout);
  assert.equal(report.written, false);
  assert.match(report.record.id, /^crosslink:[0-9a-f]+$/);
});

test('federate declare: with --yes, writes atomically, no backup on the first write, and appends a real audit event', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('server.js', SINK_SOURCE);
  fx.commit('add sink');
  const scanR = _scanWithLineage(fx);
  assert.ok(scanR.status <= 3, scanR.stderr);
  const localNodeId = _localGraphNodeId(fx);
  const remoteExportPath = path.join(fx.root, 'remote-export.json');
  const remoteNodeId = _buildRemoteExport(remoteExportPath);

  const r = _declare(fx, ['--local-node', localNodeId, '--remote-graph', remoteExportPath, '--remote-node', remoteNodeId, '--repository', 'remote-svc', '--rationale', 'test link', '--yes']);
  assert.equal(r.status, 0, r.stderr);
  const configPath = statePath(fx.root, 'cross-repo-links.json');
  const written = JSON.parse(fs.readFileSync(configPath, 'utf8'));
  assert.equal(written.links.length, 1);
  assert.equal(written.links[0].local.nodeId, localNodeId);
  assert.equal(written.links[0].remote.nodeId, remoteNodeId);
  assert.equal(written.links[0].remote.repository, 'remote-svc');
  assert.equal(written.links[0].provenance, 'manual');

  const backupDir = statePath(fx.root, 'cross-repo-links-backups');
  const backupCount = fs.existsSync(backupDir) ? fs.readdirSync(backupDir).length : 0;
  assert.equal(backupCount, 0, 'no backup on the very first write — nothing existed to back up');

  const auditLogPath = statePath(fx.root, 'mcp-audit.log');
  assert.ok(fs.existsSync(auditLogPath));
  const auditContent = fs.readFileSync(auditLogPath, 'utf8');
  assert.match(auditContent, /federate_declare/);
  assert.match(auditContent, /"outcome":"ok"/);
});

test('federate declare: a second declare on the same repo pair creates a backup of the first write and APPENDS, never replaces', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('server.js', SINK_SOURCE);
  fx.commit('add sink');
  const scanR = _scanWithLineage(fx);
  assert.ok(scanR.status <= 3, scanR.stderr);
  const localNodeId = _localGraphNodeId(fx);
  const remoteExportPath = path.join(fx.root, 'remote-export.json');
  const remoteNodeId = _buildRemoteExport(remoteExportPath);

  const r1 = _declare(fx, ['--local-node', localNodeId, '--remote-graph', remoteExportPath, '--remote-node', remoteNodeId, '--repository', 'remote-svc', '--yes']);
  assert.equal(r1.status, 0, r1.stderr);
  const r2 = _declare(fx, ['--local-node', localNodeId, '--remote-graph', remoteExportPath, '--remote-node', remoteNodeId, '--repository', 'remote-svc', '--rationale', 'a second link', '--yes']);
  assert.equal(r2.status, 0, r2.stderr);

  const backupDir = statePath(fx.root, 'cross-repo-links-backups');
  const backups = fs.readdirSync(backupDir);
  assert.equal(backups.length, 1, 'exactly one backup after the second write');

  const configPath = statePath(fx.root, 'cross-repo-links.json');
  const written = JSON.parse(fs.readFileSync(configPath, 'utf8'));
  assert.equal(written.links.length, 2, 'the second declare must APPEND, never replace');
});

test('federate declare: missing --local-node/--remote-graph/--remote-node each exit 2', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('server.js', SINK_SOURCE);
  fx.commit('add sink');
  const scanR = _scanWithLineage(fx);
  assert.ok(scanR.status <= 3, scanR.stderr);

  assert.equal(_declare(fx, ['--remote-graph', 'x.json', '--remote-node', 'node:x']).status, 2);
  assert.equal(_declare(fx, ['--local-node', 'node:x', '--remote-node', 'node:x']).status, 2);
  assert.equal(_declare(fx, ['--local-node', 'node:x', '--remote-graph', 'x.json']).status, 2);
});

test('federate declare: --local-node not present in the current locally-scanned graph exits 2, writes nothing', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('server.js', SINK_SOURCE);
  fx.commit('add sink');
  const scanR = _scanWithLineage(fx);
  assert.ok(scanR.status <= 3, scanR.stderr);
  const remoteExportPath = path.join(fx.root, 'remote-export.json');
  const remoteNodeId = _buildRemoteExport(remoteExportPath);

  const r = _declare(fx, ['--local-node', 'node:sink:doesnotexist000000', '--remote-graph', remoteExportPath, '--remote-node', remoteNodeId, '--yes']);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /--local-node/);
  const configPath = statePath(fx.root, 'cross-repo-links.json');
  assert.equal(fs.existsSync(configPath), false);
});

test('federate declare: --remote-node not present in the remote export exits 2, writes nothing', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('server.js', SINK_SOURCE);
  fx.commit('add sink');
  const scanR = _scanWithLineage(fx);
  assert.ok(scanR.status <= 3, scanR.stderr);
  const localNodeId = _localGraphNodeId(fx);
  const remoteExportPath = path.join(fx.root, 'remote-export.json');
  _buildRemoteExport(remoteExportPath);

  const r = _declare(fx, ['--local-node', localNodeId, '--remote-graph', remoteExportPath, '--remote-node', 'node:source:doesnotexist000000', '--yes']);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /--remote-node/);
});

test('federate declare: a missing --remote-graph file exits 2 with a clear message, writes nothing', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('server.js', SINK_SOURCE);
  fx.commit('add sink');
  const scanR = _scanWithLineage(fx);
  assert.ok(scanR.status <= 3, scanR.stderr);
  const localNodeId = _localGraphNodeId(fx);

  const r = _declare(fx, ['--local-node', localNodeId, '--remote-graph', path.join(fx.root, 'no-such-file.json'), '--remote-node', 'node:x', '--yes']);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /No remote graph export found/);
});

test('federate declare: --base-digest mismatch (a concurrent edit) is refused, exit 2, never writes', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('server.js', SINK_SOURCE);
  fx.commit('add sink');
  const scanR = _scanWithLineage(fx);
  assert.ok(scanR.status <= 3, scanR.stderr);
  const localNodeId = _localGraphNodeId(fx);
  const remoteExportPath = path.join(fx.root, 'remote-export.json');
  const remoteNodeId = _buildRemoteExport(remoteExportPath);

  const staleDigest = crypto.createHash('sha256').update('{"links":[{"someone-else-declared":true}]}').digest('hex');
  const r = _declare(fx, ['--local-node', localNodeId, '--remote-graph', remoteExportPath, '--remote-node', remoteNodeId, '--yes', '--base-digest', staleDigest]);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /concurrent|changed|digest/i);
  const configPath = statePath(fx.root, 'cross-repo-links.json');
  assert.equal(fs.existsSync(configPath), false);
});

test('federate declare: a digest-mismatched remote export is a printed warning, but --yes still writes', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('server.js', SINK_SOURCE);
  fx.commit('add sink');
  const scanR = _scanWithLineage(fx);
  assert.ok(scanR.status <= 3, scanR.stderr);
  const localNodeId = _localGraphNodeId(fx);

  const remoteExportPath = path.join(fx.root, 'remote-export.json');
  const remoteNodeId = _buildRemoteExport(remoteExportPath);
  // Tamper the digest AFTER building a genuinely valid export.
  const exported = JSON.parse(fs.readFileSync(remoteExportPath, 'utf8'));
  exported.digest = 'sha256:0000000000000000000000000000000000000000000000000000000000000000';
  fs.writeFileSync(remoteExportPath, JSON.stringify(exported));

  const r = _declare(fx, ['--local-node', localNodeId, '--remote-graph', remoteExportPath, '--remote-node', remoteNodeId, '--yes']);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stderr, /WARNING/);
  const configPath = statePath(fx.root, 'cross-repo-links.json');
  assert.equal(fs.existsSync(configPath), true, 'a digest mismatch must not block --yes — the operator is explicitly asserting this file');
});

test('federate list: no cross-repo-links.json at all — an empty list, exit 0', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('server.js', SINK_SOURCE);
  fx.commit('add sink');
  const scanR = _scanWithLineage(fx);
  assert.ok(scanR.status <= 3, scanR.stderr);

  const r = _list(fx);
  assert.equal(r.status, 0, r.stderr);
  const report = JSON.parse(r.stdout);
  assert.deepEqual(report.links, []);
});

test('federate list: reports a real, valid declared link as still-valid on both sides', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('server.js', SINK_SOURCE);
  fx.commit('add sink');
  const scanR = _scanWithLineage(fx);
  assert.ok(scanR.status <= 3, scanR.stderr);
  const localNodeId = _localGraphNodeId(fx);
  const remoteExportPath = path.join(fx.root, 'remote-export.json');
  const remoteNodeId = _buildRemoteExport(remoteExportPath);
  const declareR = _declare(fx, ['--local-node', localNodeId, '--remote-graph', remoteExportPath, '--remote-node', remoteNodeId, '--yes']);
  assert.equal(declareR.status, 0, declareR.stderr);

  const r = _list(fx);
  assert.equal(r.status, 0, r.stderr);
  const report = JSON.parse(r.stdout);
  assert.equal(report.localGraphAvailable, true);
  assert.equal(report.links.length, 1);
  assert.equal(report.links[0].local.stillValid, true);
  assert.equal(report.links[0].remote.ok, true);
  assert.equal(report.links[0].remote.nodeStillPresent, true);
  assert.equal(report.links[0].remote.digestMatches, true);
});

test('federate list: a declared link whose remote export file has since moved reports remote.ok:false, reason "missing" — never fabricates "still valid"', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('server.js', SINK_SOURCE);
  fx.commit('add sink');
  const scanR = _scanWithLineage(fx);
  assert.ok(scanR.status <= 3, scanR.stderr);
  const localNodeId = _localGraphNodeId(fx);
  const remoteExportPath = path.join(fx.root, 'remote-export.json');
  const remoteNodeId = _buildRemoteExport(remoteExportPath);
  const declareR = _declare(fx, ['--local-node', localNodeId, '--remote-graph', remoteExportPath, '--remote-node', remoteNodeId, '--yes']);
  assert.equal(declareR.status, 0, declareR.stderr);
  fs.unlinkSync(remoteExportPath);

  const r = _list(fx);
  assert.equal(r.status, 0, r.stderr);
  const report = JSON.parse(r.stdout);
  assert.equal(report.links[0].remote.ok, false);
  assert.equal(report.links[0].remote.reason, 'missing');
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd scanner && node --test test/cli/federate-declare-list.test.js`
Expected: FAIL — `Unknown command: federate`, exit code 4 (main()'s own
unrecognized-command path), on every test.

- [ ] **Step 3: Implement `cmdFederateDeclare` and `cmdFederateList`**

In `scanner/bin/agentic-security.js`, insert these two functions
immediately after the existing `cmdGovernancePropose` function (right
after its closing `}` and before the `// ── remediation
open/update/accept-risk/list` comment block):

```js
// agentic-security federate declare [path] --local-node <node-id>
// --remote-graph <file> --remote-node <node-id> [--repository <label>]
// [--relationship data_flow] [--rationale <text>] [--output <file>]
// [--yes] [--base-digest <hex>] — M5 deliverable #8 (FR-304's "declared"
// half). Declares a CrossRepoLink between a node in the CURRENT
// locally-scanned graph and a node in a REMOTE graph export
// (`dataflow export --format json`'s own artifact, loaded via
// federation-loader.js's loadRemoteGraphExport — never loadSignedGraph,
// which authenticates against a per-install HMAC key, the wrong trust
// model for a file that crossed a repo/machine boundary).
//
// Reuses cmdGovernancePropose's exact write contract: (1) version guard
// on cross-repo-links.json BEFORE any read of the remote file or any
// validation; (2) loads+validates the remote export (a digest-mismatch
// is a printed warning, never silently swallowed, and never blocks
// --yes — the operator is explicitly asserting this file); (3) confirms
// --local-node exists in the CURRENT locally-scanned graph and
// --remote-node exists in the loaded remote export's own nodes[];
// (4) on --yes: backup, atomic write (via the already-shipped
// _writeConfigAtomic), a real hash-chained audit event. Exit codes
// mirror cmdGovernancePropose's own scheme: 0 success (incl. preview),
// 1 validation failure, 2 usage/version-guard/node-not-found, 4 an
// unexpected I/O error during the write itself — uncaught, falling
// through to main()'s own outer catch/process.exit(4), the identical,
// deliberate non-pattern cmdGovernancePropose itself relies on (no local
// try/catch here either).
async function cmdFederateDeclare(args) {
  const target = args._[2] || '.'; // args._ = ['federate', 'declare', <path>?]
  const targetAbs = path.resolve(target);

  const localNodeFlag = args.flags['local-node'];
  const remoteGraphFlag = args.flags['remote-graph'];
  const remoteNodeFlag = args.flags['remote-node'];
  if (!localNodeFlag || typeof localNodeFlag !== 'string') {
    process.stderr.write('agentic-security federate declare: --local-node <node-id> is required.\n');
    return 2;
  }
  if (!remoteGraphFlag || typeof remoteGraphFlag !== 'string') {
    process.stderr.write('agentic-security federate declare: --remote-graph <file> is required.\n');
    return 2;
  }
  if (!remoteNodeFlag || typeof remoteNodeFlag !== 'string') {
    process.stderr.write('agentic-security federate declare: --remote-node <node-id> is required.\n');
    return 2;
  }

  const { CROSS_REPO_LINK_VERSION, CROSS_REPO_LINKS_FILENAME, CROSS_REPO_LINK_RELATIONSHIP, validateCrossRepoLink } = await import('../src/lineage/cross-repo-link.js');

  const relationshipFlag = args.flags.relationship ?? CROSS_REPO_LINK_RELATIONSHIP;
  if (relationshipFlag !== CROSS_REPO_LINK_RELATIONSHIP) {
    process.stderr.write(`agentic-security federate declare: --relationship must be "${CROSS_REPO_LINK_RELATIONSHIP}" (got "${relationshipFlag}") — no other relationship value is defined.\n`);
    return 2;
  }

  const { statePath, isSafeStateDir } = await import('../src/posture/state-dir.js');
  const { crossRepoLinkId } = await import('../src/lineage/ids.js');
  const { loadRemoteGraphExport } = await import('../src/lineage/federation-loader.js');
  const { loadSignedGraph } = await import('../src/server/graph-loader.js');
  const { computeGraphDigest } = await import('../src/lineage/export-json.js');

  const configPath = statePath(targetAbs, CROSS_REPO_LINKS_FILENAME);
  const currentRaw = fs.existsSync(configPath) ? fs.readFileSync(configPath, 'utf8') : '{"links":[]}';
  const currentDigest = crypto.createHash('sha256').update(currentRaw).digest('hex');

  // Version guard runs BEFORE any read of the remote file or any
  // validation — mirrors cmdGovernancePropose's own ordering exactly.
  const baseDigestFlag = args.flags['base-digest'];
  if (baseDigestFlag && baseDigestFlag !== currentDigest) {
    process.stderr.write('agentic-security federate declare: the cross-repo-links file changed since --base-digest was computed (a concurrent edit) — refusing to write. Re-read the current file and recompute your declaration.\n');
    return 2;
  }

  let currentDoc;
  try {
    currentDoc = JSON.parse(currentRaw);
  } catch (e) {
    process.stderr.write(`agentic-security federate declare: the current cross-repo-links file is not valid JSON: ${e.message}\n`);
    return 2;
  }
  if (!currentDoc || typeof currentDoc !== 'object' || Array.isArray(currentDoc) || !Array.isArray(currentDoc.links)) {
    process.stderr.write('agentic-security federate declare: the current cross-repo-links file has no "links" array (expected {"links": [...]}).\n');
    return 2;
  }

  // Step 2: load and validate the remote export. A digest-mismatch is a
  // printed WARNING, never a blocking failure — the operator is
  // explicitly asserting this file.
  const remote = loadRemoteGraphExport(path.resolve(remoteGraphFlag));
  if (!remote.ok) {
    process.stderr.write(`agentic-security federate declare: could not load --remote-graph "${remoteGraphFlag}": ${remote.message}\n`);
    return 2;
  }
  if (!remote.digestMatches) {
    process.stderr.write(`agentic-security federate declare: WARNING — ${remote.message}\n`);
  }
  const remoteNode = (remote.graph.nodes ?? []).find((n) => n.id === remoteNodeFlag);
  if (!remoteNode) {
    process.stderr.write(`agentic-security federate declare: --remote-node "${remoteNodeFlag}" was not found in the remote export's own nodes.\n`);
    return 2;
  }

  // Step 3: confirm --local-node exists in the CURRENT locally-scanned
  // graph — loadSignedGraph is the correct mechanism here (the LOCAL
  // side, same install, same machine).
  const local = loadSignedGraph(targetAbs);
  if (!local.ok) {
    process.stderr.write(`agentic-security federate declare: could not load the local scanned graph: ${local.message}\n`);
    return 2;
  }
  const localNode = (local.graph.nodes ?? []).find((n) => n.id === localNodeFlag);
  if (!localNode) {
    process.stderr.write(`agentic-security federate declare: --local-node "${localNodeFlag}" was not found in the current locally-scanned graph.\n`);
    return 2;
  }

  const localGraphDigest = computeGraphDigest(local.graph);
  const idInputs = {
    localGraphId: local.graph.graphId, localGraphDigest, localNodeId: localNodeFlag,
    remoteGraphId: remote.graph.graphId, remoteGraphDigest: remote.digest, remoteNodeId: remoteNodeFlag,
    relationship: relationshipFlag,
  };
  const record = {
    id: crossRepoLinkId(idInputs),
    version: CROSS_REPO_LINK_VERSION,
    provenance: 'manual',
    relationship: relationshipFlag,
    local: { graphId: local.graph.graphId, graphDigest: localGraphDigest, nodeId: localNodeFlag },
    remote: {
      // Honest placeholder literal when the operator supplied none — no
      // code-derived signal exists to name "which repo" a bare exported
      // JSON file came from (mirrors recipient-registry.js's own
      // `graphId ?? '(no graph)'` precedent).
      repository: args.flags.repository ?? '(unspecified)',
      sourceFile: path.resolve(remoteGraphFlag),
      graphId: remote.graph.graphId, graphDigest: remote.digest, nodeId: remoteNodeFlag,
    },
    rationale: args.flags.rationale ?? null,
    declaredBy: process.env.USER || process.env.USERNAME || '(unspecified)',
    declaredAt: new Date().toISOString(),
  };

  const { valid, errors } = validateCrossRepoLink(record);
  if (!valid) {
    process.stderr.write(`agentic-security federate declare: constructed record failed validation:\n${errors.map((e) => `  ${e.path}: ${e.message}`).join('\n')}\n`);
    return 1;
  }

  const yes = !!args.flags.yes;
  let written = false;
  let backupPath = null;
  if (yes) {
    if (!isSafeStateDir(path.dirname(configPath))) {
      process.stderr.write(`agentic-security federate declare: refusing to write — "${targetAbs}" does not look like a project directory.\n`);
      return 2;
    }
    const backupDir = statePath(targetAbs, 'cross-repo-links-backups');
    const candidateBackupPath = path.join(backupDir, `${Date.now()}-${crypto.randomBytes(4).toString('hex')}.bak`);
    if (fs.existsSync(configPath)) {
      fs.mkdirSync(backupDir, { recursive: true });
      fs.copyFileSync(configPath, candidateBackupPath);
      backupPath = candidateBackupPath;
    }
    const merged = { ...currentDoc, links: [...currentDoc.links, record] };
    await _writeConfigAtomic(configPath, JSON.stringify(merged, null, 2));
    written = true;
    const { auditCall } = await import('../src/mcp/audit.js');
    auditCall({
      sessionRoot: targetAbs, tool: 'federate_declare',
      args: {
        file: CROSS_REPO_LINKS_FILENAME, id: record.id, localNodeId: localNodeFlag, remoteNodeId: remoteNodeFlag,
        digestMatches: remote.digestMatches, beforeDigest: currentDigest, backupPath,
      },
      outcome: 'ok',
    });
  }

  const report = { currentDigest, record, digestMatches: remote.digestMatches, written, backupPath };
  const outputPath = args.flags.output;
  if (outputPath) {
    fs.writeFileSync(path.resolve(outputPath), JSON.stringify(report, null, 2));
  } else {
    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
  }
  return 0;
}

// agentic-security federate list [path] [--output <file>] — M5
// deliverable #8. Read-only. Reads cross-repo-links.json and, for each
// entry, reports whether local.nodeId still resolves against the
// current loadSignedGraph output and whether remote.sourceFile still
// exists/parses/digest-matches/still names the declared remote node —
// never fabricates "still valid" when it cannot check (mirrors
// `dataflow observations list`'s own precedent). Exit codes: 0 success
// (including an empty list), 2 a malformed cross-repo-links.json.
async function cmdFederateList(args) {
  const target = args._[2] || '.'; // args._ = ['federate', 'list', <path>?]
  const targetAbs = path.resolve(target);

  const { statePath } = await import('../src/posture/state-dir.js');
  const { CROSS_REPO_LINKS_FILENAME } = await import('../src/lineage/cross-repo-link.js');
  const { loadRemoteGraphExport } = await import('../src/lineage/federation-loader.js');
  const { loadSignedGraph } = await import('../src/server/graph-loader.js');

  const configPath = statePath(targetAbs, CROSS_REPO_LINKS_FILENAME);
  let links = [];
  if (fs.existsSync(configPath)) {
    let doc;
    try {
      doc = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    } catch (e) {
      process.stderr.write(`agentic-security federate list: ${configPath} is not valid JSON: ${e.message}\n`);
      return 2;
    }
    links = Array.isArray(doc?.links) ? doc.links : [];
  }

  const local = loadSignedGraph(targetAbs);
  const localNodeIds = local.ok ? new Set((local.graph.nodes ?? []).map((n) => n.id)) : null;

  const results = links.map((record) => {
    // `stillValid` is null — "could not check" — whenever there is no
    // current local graph to check against, never fabricated as true or
    // false.
    const localStillValid = localNodeIds ? localNodeIds.has(record?.local?.nodeId) : null;

    let remoteStatus;
    const sourceFile = record?.remote?.sourceFile;
    if (typeof sourceFile !== 'string' || !sourceFile) {
      remoteStatus = { checked: false, reason: 'no sourceFile recorded on this record' };
    } else {
      const remote = loadRemoteGraphExport(sourceFile);
      if (!remote.ok) {
        remoteStatus = { checked: true, ok: false, reason: remote.reason, message: remote.message };
      } else {
        const nodeStillPresent = (remote.graph.nodes ?? []).some((n) => n.id === record?.remote?.nodeId);
        remoteStatus = { checked: true, ok: true, digestMatches: remote.digestMatches, nodeStillPresent };
      }
    }

    return {
      id: record?.id ?? null,
      local: { nodeId: record?.local?.nodeId ?? null, stillValid: localStillValid },
      remote: { sourceFile: sourceFile ?? null, nodeId: record?.remote?.nodeId ?? null, ...remoteStatus },
      rationale: record?.rationale ?? null,
      declaredBy: record?.declaredBy ?? null,
      declaredAt: record?.declaredAt ?? null,
    };
  });

  const report = { links: results, localGraphAvailable: local.ok };
  const outputPath = args.flags.output;
  if (outputPath) {
    fs.writeFileSync(path.resolve(outputPath), JSON.stringify(report, null, 2));
  } else {
    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
  }
  return 0;
}
```

- [ ] **Step 4: Wire the `case 'federate':` dispatch**

In `scanner/bin/agentic-security.js`'s `main()`, insert this case block
immediately after the existing `case 'governance':` block's closing
`break;` (right before `case 'remediation':`):

```js
      case 'federate': {
        // NOT a `dataflow` subcommand — this writes operator-declared
        // config (cross-repo-links.json), never the scanned graph. Same
        // distinction that made `governance`/`remediation` their own
        // dispatchers. See cmdFederateDeclare's own header comment for
        // the full exit-code/backup/audit contract.
        const sub = args._[1];
        if (sub === 'declare') { process.exit(await cmdFederateDeclare(args)); }
        else if (sub === 'list') { process.exit(await cmdFederateList(args)); }
        else {
          process.stderr.write(`agentic-security federate: unrecognized sub-command "${sub}" — must be "declare" or "list".\n`);
          process.exit(2);
        }
        break;
      }
```

- [ ] **Step 5: Add the `federate` block to the USAGE string**

In `scanner/bin/agentic-security.js`'s `const USAGE = \`...\`` template
literal, insert this block immediately after the existing
`governance propose-edit [path] --patch <file.json> ...` block (three
lines) and before `remediation open [path] ...`:

```
  federate declare [path] --local-node <node-id> --remote-graph <file>
                               --remote-node <node-id> [--repository <label>]
                               [--relationship data_flow] [--rationale <text>]
                               [--output <file>] [--yes] [--base-digest <hex>]
                               Declare a CrossRepoLink between a node in the
                               current locally-scanned graph and a node in a
                               remote graph export (dataflow export --format
                               json). Without --yes, previews and writes nothing.
  federate list [path] [--output <file>]
                               List every declared cross-repo link, reporting
                               whether each side still resolves.
```

- [ ] **Step 6: Register the two new artifacts in `artifact-registry.js`**

In `scanner/src/posture/artifact-registry.js`, add this entry
immediately after the existing `recipient-profiles-backups` entry:

```js
  // M5 deliverable #8 (FR-304 "declared" half): backups of
  // cross-repo-links.json written by `federate declare --yes`, mirrors
  // the `recipient-profiles-backups` precedent immediately above
  // exactly.
  { name: 'cross-repo-links-backups', kind: 'dir', classification: 'generated', retentionClass: 'backup', note: 'per-declare backups written by `federate declare --yes`, mirrors the recipient-profiles-backups/ precedent — one directory entry covers every timestamped .bak file inside it' },
```

And add this entry immediately after the existing
`recipient-profiles.json` entry:

```js
  { name: 'cross-repo-links.json', kind: 'file', classification: 'operator-config', note: 'M5 deliverable #8 (FR-304 "declared" half) — declared local<->remote node links between two independently-scanned repos, written via `federate declare --yes`, never scanner-regenerable, so a routine reset must never delete it' },
```

- [ ] **Step 7: Run the test to verify it passes**

Run: `cd scanner && node --test test/cli/federate-declare-list.test.js`
Expected: PASS, all tests green. (This test spawns real `scan`/`dataflow
export`/`federate` subprocesses and runs real git fixtures — expect it
to take tens of seconds, not milliseconds.)

- [ ] **Step 8: Wire the new test file into `test:mcp`**

Edit `scanner/package.json`'s `test:mcp` script: append
` test/cli/federate-declare-list.test.js` to the end of the file list
(after `test/cli/dataflow-observations.test.js`).

- [ ] **Step 9: Confirm the artifact-registry completeness guard passes**

Run: `cd scanner && node --test test/artifact-registry-completeness.test.js test/artifact-registry.test.js`
Expected: PASS — confirms the two new `statePath()` literals
(`cross-repo-links.json`, `cross-repo-links-backups`) used in
`cmdFederateDeclare`/`cmdFederateList` are now registered.

- [ ] **Step 10: Run the full scoped suites**

Run: `cd scanner && npm run test:mcp && npm run test:lineage`
Expected: PASS in full, no regressions.

- [ ] **Step 11: Rebuild the bundle**

Run: `cd scanner && npm run build`
Expected: succeeds; `dist/agentic-security.mjs` and its `.sha256`
sidecar are regenerated (the CLI test spawns
`scanner/bin/agentic-security.js` directly, not the bundle, but the
bundle must stay current per the root `CLAUDE.md`'s build invariant
before this change can be relied on elsewhere, e.g. `commands/federate.md`'s
own `Implementation` block).

- [ ] **Step 12: Commit**

```bash
git add scanner/bin/agentic-security.js scanner/src/posture/artifact-registry.js \
  scanner/test/cli/federate-declare-list.test.js scanner/package.json \
  scanner/dist/agentic-security.mjs scanner/dist/agentic-security.mjs.sha256
git commit -m "feat(cli): add federate declare|list, the M5 deliverable #8 write surface (Task 4)"
```

---

### Task 5: `commands/federate.md` + documentation updates

**Files:**
- Create: `commands/federate.md`
- Modify: `CLAUDE.md` (root — dispatcher count 13 → 14)
- Modify: `scanner/src/lineage/CLAUDE.md` (new module-table section)

**Interfaces:**
- Consumes: nothing programmatically — this task is documentation only.
  Depends on Task 4's CLI being complete (the markdown's `Implementation`
  block invokes `agentic-security federate "$@"`, which must exist).
- Produces: nothing consumed by later tasks — this is the final task.

- [ ] **Step 1: Create `commands/federate.md`**

Create `commands/federate.md`:

```markdown
---
description: Declare (or list) a CrossRepoLink between a node in this repo's scanned graph and a node in a remote repo's graph export.
argument-hint: "declare|list [path] [flags]"
---

## Federate

The "declared" half of FR-304 (cross-repository/federated graph edges) —
M5 deliverable #8, the FINAL item of the Data Flow Explorer PRD. An
operator explicitly names a local node and a remote node and asserts
that data flows between them; nothing is inferred or auto-correlated.

**CLI-only, this half only.** FR-304's "imported"/auto-correlated flavor
— matching a repo's own resolved destination against another repo's own
source, the way a future schema-derived-edge bridge would — needs
prerequisite work that does not exist yet (M2 Sub-project F2/F3's
schema-derived edges, and the remaining Sub-project A destination-
resolver increments) and is a materially larger, separately-scoped
design problem. Not attempted here.

**No array-merge, ever.** Each repo's own `DataFlowGraph v1` document
stays its own separate, unmodified, independently-`validateGraph()`-clean
artifact. A `CrossRepoLink` is a new, graph-attached extension record
(`graph.crossRepoLinks[]`) naming one local node id and one remote node
id — never a core-schema edge. `validate.js`'s `_validateEdge` makes a
cross-repo entry in `graph.edges[]` structurally impossible to pass
`validateGraph()` at all, which is why this deliverable never attempts
one.

**The remote-side trust model is a self-consistency check, never
authentication.** `--remote-graph` points at a local file — always a
copied CI artifact, a shared drive, a manual `scp`, never a live network
fetch (this codebase's own "no runtime cloud calls" convention applies
here exactly as it does everywhere else). The remote export's own
embedded digest is recomputed and compared against its own content; a
mismatch is printed as a WARNING and does not by itself block `--yes` —
the operator declaring the link is explicitly asserting that file's
authenticity, not this tool. `loadSignedGraph`'s per-install HMAC key
(the mechanism the LOCAL side uses) is deliberately never used for the
remote side — two repos scanned on two different machines sign under two
different keys by default, so authenticating the remote file that way
would, in the common case, incorrectly report tampering that never
happened.

**`provenance: 'manual'` only.** This deliverable is the first real
producer of that value anywhere in this codebase — `'schema'` stays
reserved on the same field for a future "imported"/auto-correlated
producer.

### `declare`

Declares a link between a node in the current, already-scanned local
graph and a node in a remote repo's graph export.

#### Options

| Flag | Required | Notes |
|---|---|---|
| `--local-node <node-id>` | Yes | Must exist in the CURRENT locally-scanned graph (`.agentic-security/lineage-graph.json`, verified via the same signed-graph loader `explore`/`dataflow export` use). |
| `--remote-graph <file>` | Yes | A local file — the output of `dataflow export --format json` run in the REMOTE repository, copied here by any means (CI artifact, shared drive, `scp`). Never fetched over the network. |
| `--remote-node <node-id>` | Yes | Must exist in the remote export's own `nodes[]`. |
| `--repository <label>` | No | An operator-supplied label naming the remote repository — no code-derived signal exists to determine this from a bare exported JSON file. Defaults to `"(unspecified)"` when omitted. |
| `--relationship data_flow` | No | The only legal value — mirrors `edge.relationship`'s own single legal value. Any other value is a usage error. |
| `--rationale <text>` | No | Operator free text explaining the link. |
| `--output <file>` | No | Where the preview/result report is written. Omitting prints to stdout. |
| `--yes` | No | Perform the real write (backup + atomic write + audit event). Omitted, this is a dry-run preview only. |
| `--base-digest <hex>` | No | A SHA-256 digest of the `cross-repo-links.json` content the declaration was computed against. A mismatch refuses the write as a concurrent-edit conflict (exit 2) before any validation or write happens. When the project has no `cross-repo-links.json` yet, the digest to compute is `sha256('{"links":[]}')` (the compact, no-whitespace literal). |

Exit codes: `0` success (both the dry-run-preview path and the real
write path, including a digest-mismatch warning on the remote export);
`1` the constructed record fails structural validation (should not
normally happen — every field is derived from already-validated inputs);
`2` a usage/argument error (a missing required flag, an unreadable
`--remote-graph`, `--local-node`/`--remote-node` not found on their
respective sides), a version-guard rejection, or the target not looking
like a real project directory; `4` an unexpected I/O error during the
write itself — nothing was written, and no audit event is recorded for a
failed attempt.

### `list`

Read-only. Reads `cross-repo-links.json` and, for each entry, reports
whether `local.nodeId` still resolves against the current locally-scanned
graph and whether `remote.sourceFile` still exists/parses/digest-matches
and still names the declared remote node — never fabricates "still
valid" when it cannot check (e.g. the remote file has moved, or no local
graph exists yet).

#### Options

| Flag | Required | Notes |
|---|---|---|
| `--output <file>` | No | Where the listing is written. Omitting prints to stdout. |

Exit codes: `0` success (including an empty list); `2` a malformed
`cross-repo-links.json`.

### Examples

```
/federate declare --local-node node:sink:abc123 \
  --remote-graph ../other-repo/remote-export.json \
  --remote-node node:source:def456 \
  --repository payments-service --rationale "Order events flow in from payments-service" \
  --yes
/federate list
```

## Implementation

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs federate "$@"
exit $?
```
```

- [ ] **Step 2: Update the root `CLAUDE.md` dispatcher table row**

In `/Users/ross/code/agentic-security/.claude/worktrees/dataflow-m5-cross-repo/CLAUDE.md`,
find the `commands/` row in the "Repository layout" table:

```
| `commands/` | Slash-command markdown files. 13 dispatchers: `secure`, `find-and-fix-everything`, `scan`, `triage`, `fix`, `posture`, `compliance`, `supply`, `setup`, `labs`, `dataflow`, `governance`, `remediation`. Every capability is a mode of a dispatcher (e.g. CI gates live at `/setup --ci`, the red/blue/auditor deep-dive at `/triage --deep`); the legacy single-purpose aliases redirect via `hooks/legacy-alias-redirect.js`. |
```

Replace with:

```
| `commands/` | Slash-command markdown files. 14 dispatchers: `secure`, `find-and-fix-everything`, `scan`, `triage`, `fix`, `posture`, `compliance`, `supply`, `setup`, `labs`, `dataflow`, `governance`, `remediation`, `federate`. Every capability is a mode of a dispatcher (e.g. CI gates live at `/setup --ci`, the red/blue/auditor deep-dive at `/triage --deep`); the legacy single-purpose aliases redirect via `hooks/legacy-alias-redirect.js`. |
```

- [ ] **Step 3: Add the new module-table section to `scanner/src/lineage/CLAUDE.md`**

In `scanner/src/lineage/CLAUDE.md`, insert this new section immediately
after the existing "Milestone 5, Runtime-Corroborated Digital Twin
(FR-505, deliverable #7, 7b only) — COMPLETE" section's closing
paragraph (the one ending "...not attempted here.") and before the
"## Conventions" section:

```markdown
## Milestone 5, Cross-Repository/Federated Graph Import (deliverable #8, FR-304 "declared" half) — COMPLETE. This closes out the M5 top-level scoping doc's own 8-deliverable list in full.

Ships only the "declared" half of FR-304 — an operator explicitly names
a local node and a remote node and asserts a `data_flow` relationship
between them — never the "imported"/auto-correlated half (destination/
schema-based automatic cross-repo edge matching), which needs
prerequisites that do not exist yet (M2 Sub-project F2/F3's
schema-derived edges, the remaining Sub-project A destination-resolver
increments) and is a materially larger, separately-scoped design
problem.

| Module | Responsibility |
|---|---|
| `docs/superpowers/plans/2026-09-02-data-flow-explorer-m5-cross-repo-scoping.md` + `…-plan.md` | The scoping investigation's own real correction against the parent M5 row: FR-304's "declared or imported" is two mechanisms with two different dependency profiles (`DFG-025`'s own `DFG-002`+`DFG-007` dependencies only make sense once this split is explicit), not one phrase to scope as a unit — this deliverable covers only the "declared" half. Also settles, via direct reading of `validate.js`'s `_validateEdge`, that a cross-repo entry can never be a core-schema `graph.edges[]` member at all (both endpoints must resolve against the ONE graph's own `nodeIds` set) — the id-collision risk the parent row named cannot actually occur under a correctly-scoped design, since a foreign node id is never looked up against a merged set. |
| `cross-repo-link.js` | The `CrossRepoLink` §10.10 extension contract — mirrors `recipient-profile.js`'s own file shape exactly (pure module, `{valid, errors}` validator, zero graph access at construction time), with the one real, disclosed departure that module's own header discloses for itself: no per-field `fieldEvidence` map, since every field on a `CrossRepoLink` is uniformly operator-declared. `provenance` reuses `schema.js`'s already-shipped `EDGE_PROVENANCE_VALUES` — this deliverable's CLI is the first real producer of `'manual'` anywhere in this codebase (every shipped edge is `provenance: 'code'`, per Milestone 2 Sub-project F increment 1). `relationship` is fixed to `'data_flow'`, mirroring `edge.relationship`'s own single legal value. `ids.js` gained `crossRepoLinkId({localGraphId, localGraphDigest, localNodeId, remoteGraphId, remoteGraphDigest, remoteNodeId, relationship}, discriminatorParts)` — mirrors `recipientProfileId`'s own `(graphId, graphDigest, ...)` discriminator shape, doubled for both endpoints. |
| `federation-loader.js` | `loadRemoteGraphExport(filePath) -> {ok, graph, digest, digestMatches, reason, message}` — reads an `exportGraphJSON`-shaped file (`dataflow export --format json`'s own artifact), recomputes `computeGraphDigest(parsed.graph)` and compares it to the file's own embedded `digest`, then runs the existing `validateGraph(parsed.graph)` before anything reads a referenced remote node id. Deliberately does NOT reuse `scanner/src/server/graph-loader.js`'s `loadSignedGraph` for the remote side — that function authenticates against a PER-INSTALL HMAC key, the wrong trust model for a file that crossed a repo/machine boundary in the common case (two repos scanned on two different machines sign under two different keys by default). Four distinct outcomes: `missing`, `malformed` (not JSON, or not an `exportGraphJSON` envelope), `invalid-graph` (fails `validateGraph()`), and `digest-mismatch` — the one outcome that is NOT a blocking failure (`ok:true, digestMatches:false`): a self-consistency check, never authentication, surfaced as a warning the CLI must show and does not by itself refuse. |
| `graph-builder.js` (extended, additively) | Gained a SIXTH additive hook of the `opts.buildRecipientProfile`/`opts.correlateObservations` shape: `opts.crossRepoLinks(graph) -> CrossRepoLink[]`, applied once every graph array AND `recipientProfiles` are populated (the hook can validate a declared `local.nodeId` against the CURRENT graph's own real node set). `graph.crossRepoLinks` is always present — mirrors `graph.recipientProfiles[]`'s own "always an array, possibly empty" shape (unlike `graph.runtimeCorroboration`'s own "genuinely absent when the hook is omitted" shape, since a `CrossRepoLink` array has no `not_evaluated` state to preserve). Never in `dataflow-graph.schema.json`, never routed through `validateGraph()` — the SECOND §10.10 extension array ever attached directly to the graph object. |
| `coverage.js` (extended, additively) | `buildGraphWithCoverage` composes a default `opts.crossRepoLinks` hook over a PRE-LOADED `opts.crossRepoLinkRecords` array (mirroring `opts.recipientConfig`'s own precedent) — installed only when `opts.crossRepoLinkRecords !== undefined`. The default hook DROPS any record whose `local.nodeId` no longer resolves against the graph's own current node set (a stale declaration from before a rescan renamed/removed the node), reporting every drop via `console.error` rather than silently keeping it stale — matching `applyScenario`'s own "skippedOperations, never thrown" honesty precedent. |
| `index.js` (extended, additively) | Loads `.agentic-security/cross-repo-links.json` exactly once per `buildLineageGraph` call, gated on `fs.existsSync` — mirroring the `privacySinkPolicy` existence-gated pattern, not `recipientConfig`'s unconditional-call one, since a missing file here means "no links declared." A small, local, tolerant `_loadCrossRepoLinkRecords` reader (per-entry validated via `validateCrossRepoLink`, mirroring `loadRecipientConfig`'s own fail-closed, skip-the-whole-entry-on-any-defect discipline) lives in this file rather than in `cross-repo-link.js` (which must stay a pure, zero-fs-access module) or `federation-loader.js` (which owns only the REMOTE side). |
| `bin/agentic-security.js` (extended, additively) | `cmdFederateDeclare`/`cmdFederateList`, dispatched via a NEW top-level `case 'federate':` (not a `dataflow` subcommand — this writes operator-declared config, never the scanned graph, the identical reasoning `commands/governance.md`/`commands/remediation.md` already establish, now a THREE-times-repeated pattern). `federate declare` reuses `governance-edit.js`'s exact 5-part write contract (version guard before any read of the remote file or validation; load+validate the remote export, a digest-mismatch printed as a warning that never blocks `--yes`; confirm `--local-node` exists in the current local graph via `loadSignedGraph` and `--remote-node` exists in the remote export's own `nodes[]`; on `--yes`, backup to `cross-repo-links-backups/` then an atomic write (via the already-shipped `_writeConfigAtomic`) then a real hash-chained `federate_declare` audit event via `auditCall`). `federate list` mirrors `dataflow observations list`'s own precedent — read-only, never fabricates "still valid" when it cannot check. Both registered in `posture/artifact-registry.js` (`cross-repo-links.json`: `operator-config`; `cross-repo-links-backups/`: `generated`/`backup`). |
| `commands/federate.md` | New top-level dispatcher markdown (14th dispatcher, root `CLAUDE.md`'s own dispatcher count updated to match) — same frontmatter/Options-table/Examples/Implementation-block shape as `commands/governance.md`. States plainly: CLI-only, "declared" flavor of FR-304 only, every write backs up the prior file and appends a real audit event, the remote-side trust model is a self-consistency digest check, never cryptographic authentication. |

**Explicitly NOT modified**: `dataflow-graph.schema.json`, `validate.js`'s
`validateGraph()` (the new record is never routed through it, mirroring
`RecipientProfile`); no live/network fetch of a remote graph, ever; no
array-merge of two graphs' `nodes[]`/`edges[]` under any circumstance;
no change to `nodeId`/`edgeId`/`flowId`/`dataElementId` or their
discriminator shapes; `provenance: 'manual'` only (never `'schema'`,
reserved for a future "imported"/auto-correlated producer).

**Deliberately out of scope (disclosed, real follow-up, not this
deliverable's job):** FR-304's "imported"/auto-correlated flavor (needs
M2 Sub-project F2/F3 and the remaining Sub-project A increments as real
prerequisites); full graph merge of any kind; any cryptographic
cross-machine authentication of a remote graph export (the existing
`agentic-security attest`/`verify-attestation` Ed25519 mechanism is the
right existing tool for a future increment that wants real third-party
verifiability, judged out of proportion to a P2, narrowly-scoped first
cut here); automatic cross-repo `RecipientProfile` consolidation (a
`CrossRepoLink` connects two NODES and says nothing about whether two
`RecipientProfile` records describe the same real-world vendor); a
live-refresh/auto-resync mechanism (`federate list`'s own validity check
is read-only and on-demand).
```

- [ ] **Step 4: Verify the doc-drift checker is unaffected**

Run: `cd scanner && node scripts/check-doc-drift.mjs` (if this script
exists and is runnable standalone — check `scanner/package.json` for its
wiring; if it is only invoked as part of a larger gate, run that gate's
scoped script instead, e.g. `npm run test:lifecycle`).
Expected: no new drift reported — the new `cross-repo-link.js`/
`federation-loader.js` files are now referenced in `scanner/src/lineage/CLAUDE.md`
(added in Step 3 above), which is what this class of checker looks for.

- [ ] **Step 5: Commit**

```bash
git add commands/federate.md CLAUDE.md scanner/src/lineage/CLAUDE.md
git commit -m "docs: add commands/federate.md and document M5 deliverable #8 (Task 5)"
```

---

## Final verification (run once, after all 5 tasks land)

- [ ] Run the full local gate: `cd scanner && npm test`
- [ ] Run the pre-push gate: `cd scanner && npm run gate:prepush` (or
  push through the installed `.githooks/pre-push` hook)
- [ ] Confirm `git status`/`git diff --cached --name-only` matches
  exactly the files this plan touched — no stray `.agentic-security/`
  state from running the CLI tests locally, no missing new files.
