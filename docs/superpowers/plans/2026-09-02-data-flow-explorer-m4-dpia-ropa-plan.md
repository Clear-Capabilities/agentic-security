# M4 Deliverable #10 (Graph-Derived DPIA/RoPA Export, DFG-020) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Populate the already-built-but-starved `flow.governanceRefs`
field on a real `DataFlowGraph v1` document, and add two new
`agentic-security dataflow export --format dpia|ropa` CLI export
formats, reusing the taint-engine-era governance-field infrastructure
and Privacy View's own row-computation logic rather than re-deriving
either.

**Architecture:** One new opts-hook in `graph-builder.js`
(`resolveGovernanceRefs`), composed by `coverage.js` exactly like its
three siblings; two new pure emit functions in a new
`scanner/src/lineage/export-privacy.js` module, consuming
`frontend/src/views/privacy-view.js#computePrivacyViewModel` directly
(the first live `scanner/` → `frontend/` module import, confirmed safe —
see the scoping doc); two new CLI format branches in the already-shipped
`dataflow export` command.

**Tech Stack:** Node.js ESM, existing `dataflow/privacy-governance.js`
infrastructure, existing `frontend/src/views/privacy-view.js`.

**Spec:** `AGENTIC_SECURITY_DATA_FLOW_EXPLORER_PRD.md` §7.4 (Privacy
View), line 1836 (migration flag), DFG-020. Scoping doc:
`docs/superpowers/plans/2026-09-02-data-flow-explorer-m4-dpia-ropa-scoping.md`
(read this first — every design decision below is grounded there, with
citations to the real files read).

## Global Constraints

- No new npm dependency.
- `governanceRefs` population is unconditional once
  `AGENTIC_SECURITY_LINEAGE_DEEP=1` is set — no second migration flag
  (ruled in the scoping doc: this precedent already holds for
  `resolveSiteDecision`/`resolveDestination`/`resolveTransitProtection`,
  none of which carry a second flag beyond the graph's own existence
  requirement).
- Never fabricate a governance fact. Every field is either
  operator-supplied (`.agentic-security/privacy-governance.json`) or the
  literal `MANUAL_REQUIRED` sentinel — reuse
  `dataflow/privacy-governance.js`'s existing `governanceRecordFor`/
  `loadPrivacyGovernanceConfig`/`GOVERNANCE_FIELDS`/`MANUAL_REQUIRED`
  unmodified, never re-implement any part of this.
- Reuse `computePrivacyViewModel` from
  `frontend/src/views/privacy-view.js` for row computation in both new
  emit functions — do not re-derive lifecycle-stage/dataClass/protection-
  verdict logic a second time.
- Real-graph tests required for every new function, matching this
  session's own hard-won lesson (sub-project 6b's blocking bugs were
  missed by hand-built-fixture-only task reviews) — use
  `bench/data-lineage/runner.mjs#buildFixtureGraph` against a real fixture
  for at least one test per new function, not only hand-built graphs.
- New test files must be added to `scanner/package.json`'s `test:lineage`
  (backend) or the frontend's own test runner (for anything under
  `frontend/test/`) — check `frontend/README.md`/`package.json` for the
  exact command before assuming it mirrors `scanner/`'s.

---

### Task 1: `resolveGovernanceRefs` hook — populate `flow.governanceRefs`

**Files:**
- Modify: `scanner/src/lineage/graph-builder.js` (the flow-mint site,
  currently `scanner/src/lineage/graph-builder.js:875`, — **re-read the
  real current file first**, this plan's own line-number citations may
  have drifted since this plan was written for other reasons; search for
  the literal `governanceRefs: {}` string in the flow-mint block, not
  the line number)
- Modify: `scanner/src/lineage/coverage.js` (`buildGraphWithCoverage`'s
  hook composition, currently around line 449-455 — same
  re-read-before-editing rule)
- Test: `scanner/test/lineage/governance-refs.test.js` (new)

**Interfaces:**
- Consumes: `governanceRecordFor(dataClass, config)`,
  `loadPrivacyGovernanceConfig(scanRoot)`, `GOVERNANCE_FIELDS`,
  `MANUAL_REQUIRED` — all from `../dataflow/privacy-governance.js`
  (exact real exported signatures — re-read that file's real current
  content before writing code that calls it; the plan's own citations
  above reflect a read taken during scoping, which may have drifted).
- Produces: `opts.resolveGovernanceRefs(dataClasses: string[]) ->
  Record<string, {value: string, source: 'operator_provided' |
  'manual_required'}>` — a new, additive `graph-builder.js` hook, applied
  at the flow-mint site. Later tasks (Task 2) consume the resulting
  `flow.governanceRefs` shape directly; no other interface changes.

- [ ] **Step 1: Read the real current flow-mint site and hook-composition code**

Read `scanner/src/lineage/graph-builder.js`'s flow-mint block (search for
`governanceRefs: {}`) and `scanner/src/lineage/coverage.js`'s
`buildGraphWithCoverage` function IN FULL before writing anything. Confirm:
- the flow-mint block's local variable name for the flow's own
  `dataElement` (this plan's own scoping-time read used `de`, with
  `de.id`/`de.dataClasses` in scope — confirm this is still accurate)
- `resolveTransitProtection`'s exact composition line in `coverage.js`,
  to mirror its shape precisely for `resolveGovernanceRefs`
- `dataflow/privacy-governance.js`'s real current exports (function
  signatures, `GOVERNANCE_FIELDS` array contents, `MANUAL_REQUIRED`
  string value)

- [ ] **Step 2: Add the `resolveGovernanceRefs` hook to `graph-builder.js`**

At the flow-mint site, change:

```js
coverageStatus: snk.coverageStatus, findingRefs: [], governanceRefs: {},
```

to:

```js
// Deliverable #10 (DFG-020, graph-derived DPIA/RoPA migration):
// opts.resolveGovernanceRefs(dataClasses) -> governance-field record,
// applied at this exact mint point — same additive-hook shape every
// sibling hook in this file uses (resolveSiteDecision/resolveDestination/
// resolveTransitProtection), byte-identical graph when omitted. Never
// fabricates a governance fact — the hook itself (composed by
// coverage.js's default) only ever attaches operator-supplied config or
// the MANUAL_REQUIRED sentinel dataflow/privacy-governance.js already
// establishes; this mint site has no opinion of its own.
coverageStatus: snk.coverageStatus, findingRefs: [],
governanceRefs: opts.resolveGovernanceRefs?.(de.dataClasses ?? []) ?? {},
```

(Confirm `de` is genuinely the right variable name after Step 1's real
read — if it has drifted, use whatever the real current code calls the
flow's own `dataElement`.)

- [ ] **Step 3: Add the default composition in `coverage.js`**

In `buildGraphWithCoverage`, add a fourth composed hook alongside the
three existing ones:

```js
const built = buildDataFlowGraph(callGraph, {
  ...opts,
  resolveSiteDecision: opts.resolveSiteDecision ?? resolveSiteDecision,
  resolveDestination: opts.resolveDestination ?? resolveDestination,
  resolveTransitProtection: opts.resolveTransitProtection
    ?? ((site) => resolveTransitProtectionForSite(site, opts.transitEvidenceByFile ?? new Map())),
  // Deliverable #10: opts.resolveGovernanceRefs, composed the same way
  // every sibling hook is — a caller-supplied hook always wins. The
  // default closes over opts.privacyGovernanceConfig, a PRE-LOADED
  // config object (mirroring opts.transitEvidenceByFile's own
  // single-computation-per-buildLineageGraph-call discipline — never
  // read the filesystem itself here).
  resolveGovernanceRefs: opts.resolveGovernanceRefs
    ?? ((dataClasses) => {
      const record = {};
      for (const cls of dataClasses) {
        const clsRecord = governanceRecordFor(cls, opts.privacyGovernanceConfig ?? null);
        for (const field of GOVERNANCE_FIELDS) {
          // Worst-case-wins across multiple data classes on one flow,
          // mirroring this package's own established
          // aggregateVerdicts()-style precedent (protection.js) rather
          // than silently picking whichever data class happened to be
          // iterated last: an operator-provided value only wins over an
          // already-recorded operator-provided value for the SAME field
          // if this is the first class seen; MANUAL_REQUIRED never
          // overwrites an already-resolved operator-provided value.
          if (!record[field] || record[field].source === 'manual_required') {
            record[field] = clsRecord[field];
          }
        }
      }
      return record;
    }),
});
```

Add the import: `import { governanceRecordFor, GOVERNANCE_FIELDS } from '../dataflow/privacy-governance.js';` at the top of `coverage.js`, alongside its existing imports.

**Verify the multi-class worst-case-wins tie-break above against a real
test case (Step 5) — do not assume it is correct without a test proving
it**: a flow carrying TWO data classes (e.g. `['PII', 'PHI']`) where an
operator has configured a value for `purpose` under `PII` but not `PHI`
must resolve `purpose` to the `PII`-configured value, not
`MANUAL_REQUIRED`, regardless of iteration order.

- [ ] **Step 4: Wire `opts.privacyGovernanceConfig` through `index.js`**

`scanner/src/lineage/index.js#buildLineageGraph` already loads
`opts.privacySinkPolicy` once per call (Sub-project G's own
single-computation precedent — read that block for the exact pattern).
Add an analogous, SEPARATE single load:

```js
const privacyGovernanceConfig = loadPrivacyGovernanceConfig(opts.scanRoot);
```

(import `loadPrivacyGovernanceConfig` from `../dataflow/privacy-governance.js`),
threaded into the `buildGraphWithCoverage` call as
`privacyGovernanceConfig`. Unlike `privacySinkPolicy` (which
deliberately stays `undefined` unless a real file exists on disk, so
`not_evaluated` and `prohibited` don't collapse),
`loadPrivacyGovernanceConfig` already has its OWN honest empty default
(`{byClass: {}, default: {}}` — never throws, confirmed in Step 1's
read) — no equivalent existence-gating is needed here, since
`governanceRecordFor` already resolves an empty config to
`MANUAL_REQUIRED` for every field, which is the correct, honest answer
when no config exists.

- [ ] **Step 5: Write the test file**

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { buildGraphWithCoverage } from '../../src/lineage/coverage.js';
import { parseJsFile } from '../../src/ir/parser-js.js';
import { buildCallGraph } from '../../src/ir/callgraph.js';
import { MANUAL_REQUIRED, GOVERNANCE_FIELDS } from '../../src/dataflow/privacy-governance.js';

function _mkScanRoot() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'governance-refs-'));
}

// Same real, proven PHI-to-model-provider shape used throughout M4
// sub-projects 6b/6c (bench/data-lineage/fixtures/js-ai-model-output-to-ai-model-provider-phi).
const PHI_SOURCE = `function summarizePatient(anthropic, params) {
  const patientRecord = params.arguments.patient_record;
  anthropic.messages.create({
    model: 'claude-3',
    messages: [{ role: 'user', content: patientRecord }],
  });
}
`;

function _buildRealGraph(source, opts = {}) {
  const perFile = { 'source.js': parseJsFile('source.js', source) };
  const callGraph = buildCallGraph(perFile);
  return buildGraphWithCoverage(callGraph, { repository: 'test-repo', generatedAt: '1970-01-01T00:00:00.000Z', ...opts }).graph;
}

test('governanceRefs: with no privacy-governance.json on disk, every field on a real flow is honestly MANUAL_REQUIRED', () => {
  const scanRoot = _mkScanRoot();
  try {
    const graph = _buildRealGraph(PHI_SOURCE, { scanRoot });
    assert.ok(graph.flows.length >= 1);
    const flow = graph.flows[0];
    assert.ok(flow.governanceRefs && Object.keys(flow.governanceRefs).length > 0, 'flow.governanceRefs must be populated, not the pre-fix empty {}');
    for (const field of GOVERNANCE_FIELDS) {
      assert.equal(flow.governanceRefs[field].value, MANUAL_REQUIRED);
      assert.equal(flow.governanceRefs[field].source, 'manual_required');
    }
  } finally {
    fs.rmSync(scanRoot, { recursive: true, force: true });
  }
});

test('governanceRefs: an operator-supplied privacy-governance.json is genuinely attached, distinguishable by source', () => {
  const scanRoot = _mkScanRoot();
  try {
    fs.mkdirSync(path.join(scanRoot, '.agentic-security'), { recursive: true });
    fs.writeFileSync(
      path.join(scanRoot, '.agentic-security', 'privacy-governance.json'),
      JSON.stringify({ byClass: { PHI: { purpose: 'Clinical summarization', lawfulBasis: 'Consent' } } }),
    );
    const graph = _buildRealGraph(PHI_SOURCE, { scanRoot });
    const flow = graph.flows[0];
    assert.equal(flow.governanceRefs.purpose.value, 'Clinical summarization');
    assert.equal(flow.governanceRefs.purpose.source, 'operator_provided');
    assert.equal(flow.governanceRefs.lawfulBasis.value, 'Consent');
    // A field NOT configured for PHI must still honestly read MANUAL_REQUIRED
    // — never silently inherit an unrelated default.
    assert.equal(flow.governanceRefs.retention.value, MANUAL_REQUIRED);
  } finally {
    fs.rmSync(scanRoot, { recursive: true, force: true });
  }
});

test('governanceRefs: a hook-omitted call (opts.resolveGovernanceRefs not composed) stays byte-identical to the pre-fix empty {}', () => {
  // Confirms buildDataFlowGraph called BARE (bypassing buildGraphWithCoverage's
  // own default composition) is unaffected — matching every sibling hook's
  // own "byte-identical when omitted" precedent.
  const { buildDataFlowGraph } = require('../../src/lineage/graph-builder.js');
  void buildDataFlowGraph; // placeholder — replace with a real ESM import; this file is ESM (see the import block above), never require().
});

test('REAL CORPUS: sweeping bench/data-lineage/ fixtures never throws building governanceRefs, with and without operator config', async () => {
  const { buildFixtureGraph } = await import('../../../bench/data-lineage/runner.mjs');
  const fs2 = await import('node:fs');
  const path2 = await import('node:path');
  const url = await import('node:url');
  const __dirname2 = path2.dirname(url.fileURLToPath(import.meta.url));
  const FIXTURES_ROOT = path2.join(__dirname2, '../../../bench/data-lineage/fixtures');
  const fixtureIds = fs2.readdirSync(FIXTURES_ROOT).filter((f) => fs2.statSync(path2.join(FIXTURES_ROOT, f)).isDirectory());
  assert.ok(fixtureIds.length > 0);
  for (const fixtureId of fixtureIds) {
    const srcPath = path2.join(FIXTURES_ROOT, fixtureId, 'source.js');
    if (!fs2.existsSync(srcPath)) continue;
    const source = fs2.readFileSync(srcPath, 'utf8');
    const graph = buildFixtureGraph(fixtureId, source);
    for (const flow of graph.flows) {
      assert.ok(flow.governanceRefs, `${fixtureId}: flow ${flow.id} missing governanceRefs`);
    }
  }
});
```

Fix Step 5's placeholder `require()` test before finalizing — it was
written to flag "this needs a real ESM-compatible byte-identical-when-
omitted test" rather than to ship as-is; replace it with a genuine test
calling `buildDataFlowGraph` (imported at the top of the file alongside
`buildGraphWithCoverage`) directly with NO `resolveGovernanceRefs` in
`opts`, asserting `flow.governanceRefs` is `{}` — proving the hook truly
is opt-in at the `buildDataFlowGraph` level and only `buildGraphWithCoverage`
supplies a default.

- [ ] **Step 6: Run tests, wire into `test:lineage`, commit**

Run: `cd scanner && node --test test/lineage/governance-refs.test.js`.
Expected: all PASS.

Add `test/lineage/governance-refs.test.js` to the `test:lineage` script
in `package.json`. Run `npm run test:lineage` and confirm it passes with
the new file included.

```bash
git add scanner/src/lineage/graph-builder.js scanner/src/lineage/coverage.js scanner/src/lineage/index.js scanner/test/lineage/governance-refs.test.js scanner/package.json
git commit -m "feat(lineage): populate flow.governanceRefs from privacy-governance.json (M4 deliverable #10)"
```

---

### Task 2: `export-privacy.js` — graph-derived DPIA/RoPA emit functions

**Files:**
- Create: `scanner/src/lineage/export-privacy.js`
- Test: `scanner/test/lineage/export-privacy.test.js`

**Interfaces:**
- Consumes: `computePrivacyViewModel(graph, state, queryPredicate)` from
  `../../../frontend/src/views/privacy-view.js` (confirmed live-importable
  from Node with zero DOM dependency during scoping — re-confirm with a
  quick `node -e "import(...)"` check before relying on it, in case
  `privacy-view.js` gained a new top-level import since scoping).
  `GOVERNANCE_FIELDS`, `MANUAL_REQUIRED` from `../dataflow/privacy-governance.js`.
- Produces: `emitGraphDpiaArtifact(graph, opts)`,
  `emitGraphRopaArtifact(graph, opts)` — both return a Markdown string,
  both accept an optional `opts.filter` (`{nodeIds, edgeIds}`, the SAME
  shape `export-json.js#exportGraphJSON`'s own `opts.filter` already
  uses) for scoped export. Task 3's CLI wiring imports both.

- [ ] **Step 1: Read the real current `computePrivacyViewModel`/`computePrivacyRow` and `_filterGraph`**

Read `frontend/src/views/privacy-view.js` in full (both functions) and
`scanner/src/lineage/export-json.js`'s `_filterGraph` function in full —
the new module reuses `_filterGraph`'s own filtering rule (re-export it
if it isn't already exported, or duplicate the tiny function ONLY if
exporting it would be a larger, unrelated change — check first whether
`_filterGraph` is already exported before assuming either path).

- [ ] **Step 2: Write `export-privacy.js`**

```js
// export-privacy.js — Milestone 4 deliverable #10 (DFG-020): graph-derived
// DPIA/RoPA export, migrating off the Layer-2 taint engine's
// dataflow/privacy-taint.js#emitDpiaArtifact / privacy-governance.js#emitRopaArtifact
// (which derive from piiFields — name-in-argument classification, no
// path/alias/field-mapping precision) onto the real DataFlowGraph v1's
// field-identity-tracked flows.
//
// Reuses frontend/src/views/privacy-view.js#computePrivacyViewModel
// DIRECTLY (the first live scanner/ -> frontend/ module import in this
// codebase — confirmed safe: that module only touches document/window
// inside renderPrivacyView's own function body, never at module top
// level, so importing it from plain Node never executes any DOM code)
// rather than re-deriving lifecycle-stage/dataClass/protection-verdict
// row computation a second time. This mirrors this package's own
// established discipline of reusing an already-correct, already-tested
// computation rather than a parallel copy that can drift.
//
// Both emit functions mirror their taint-engine-era predecessors'
// structure/wording (GDPR Art. 35 framing for DPIA, the register-not-
// narrative RoPA table) but are populated from real graph rows.

import { computePrivacyViewModel } from '../../../frontend/src/views/privacy-view.js';
import { GOVERNANCE_FIELDS, MANUAL_REQUIRED } from '../dataflow/privacy-governance.js';
// _filterGraph must be exported from export-json.js first (Step 3) — it
// filters the GRAPH itself against opts.filter's real {nodeIds, edgeIds}
// shape, matching every sibling `dataflow export` format's own --filter
// convention. Do NOT thread opts.filter into computePrivacyViewModel's
// own state.filters — that parameter expects a completely different
// shape (per-facet selected-value arrays, e.g. {dataClass:[...]}) and
// would silently no-op. See Step 3 for the full reasoning.
import { _filterGraph } from './export-json.js';

function _emptyState() {
  return { selectedId: null };
}

function _scopedViewModel(graph, filter) {
  const scopedGraph = filter ? _filterGraph(graph, filter) : graph;
  return computePrivacyViewModel(scopedGraph, _emptyState(), null);
}

/** Group computePrivacyViewModel's rows by data class, mirroring emitDpiaArtifact's own grouping. */
function _groupRowsByClass(rows) {
  const grouped = new Map();
  for (const row of rows) {
    for (const cls of row.dataClasses) {
      let g = grouped.get(cls);
      if (!g) { g = []; grouped.set(cls, g); }
      g.push(row);
    }
  }
  return grouped;
}

/**
 * Graph-derived DPIA (Data Protection Impact Assessment) — narrative
 * Markdown, mirroring dataflow/privacy-taint.js#emitDpiaArtifact's own
 * structure. `opts.filter` scopes to a subset of the graph (the "filtered
 * ... from the selected graph scope" requirement, PRD §7.4).
 */
export function emitGraphDpiaArtifact(graph, opts = {}) {
  const viewModel = _scopedViewModel(graph, opts.filter);
  const visibleRows = viewModel.rows.filter((r) => r.visible !== false);
  const grouped = _groupRowsByClass(visibleRows);

  const lines = [];
  lines.push('# Data Protection Impact Assessment (DPIA)');
  lines.push('');
  lines.push(`Generated by agentic-security scanner (graph-derived) on ${(opts.generatedAt ?? new Date().toISOString()).slice(0, 10)}.`);
  lines.push('');
  lines.push('This is an automated DPIA scaffold derived from real data-flow analysis');
  lines.push('(field identity, path provenance, and protection verdicts). It must be');
  lines.push('reviewed and completed by a privacy officer before use.');
  lines.push('');
  if (grouped.size === 0) {
    lines.push('No regulated data classes were identified in this graph scope.');
    return lines.join('\n');
  }
  lines.push('## Data classes identified');
  lines.push('');
  for (const [cls, rows] of grouped) {
    lines.push(`### ${cls} (${rows.length} flow(s))`);
    lines.push('');
    for (const row of rows.slice(0, 20)) {
      lines.push(`- \`${row.dataElementName}\` — ${row.sourceCategory ?? 'unknown source'} -> ${row.sinkCategory ?? 'unknown sink'} (protection: ${row.protectionSummary})`);
    }
    if (rows.length > 20) lines.push(`- … and ${rows.length - 20} more`);
    lines.push('');
    lines.push(`**Governance fields for ${cls}:**`);
    lines.push('');
    // Worst-case-wins across this class's own rows, same tie-break as
    // Task 1's resolveGovernanceRefs default — never silently pick
    // whichever row happened to be iterated last.
    const merged = {};
    for (const row of rows) {
      for (const field of GOVERNANCE_FIELDS) {
        const r = row.governanceRefs?.[field];
        if (!r) continue;
        if (!merged[field] || merged[field].source === 'manual_required') merged[field] = r;
      }
    }
    for (const field of GOVERNANCE_FIELDS) {
      const r = merged[field] ?? { value: MANUAL_REQUIRED, source: 'manual_required' };
      lines.push(`- ${field}: \`${r.value}\`${r.source === 'operator_provided' ? ' (operator-provided)' : ''}`);
    }
    lines.push('');
  }
  lines.push('## Regulatory framework mapping');
  lines.push('');
  lines.push('- **GDPR Art. 35** — DPIA required when processing is likely to result in high risk to data subjects.');
  lines.push('- **CCPA §1798.130** — Notice + access rights for collected personal information.');
  if (grouped.has('PHI')) lines.push('- **HIPAA §164.308** — Administrative safeguards for ePHI access.');
  if (grouped.has('PCI')) lines.push('- **PCI DSS Req. 3** — Protect stored cardholder data.');
  lines.push('');
  lines.push('_This document organizes automated technical assessment evidence. It does');
  lines.push('not certify compliance and is not a legal determination — see the graph\'s');
  lines.push('own `disclaimer`/`limitations` fields for the full caveat._');
  return lines.join('\n');
}

/**
 * Graph-derived RoPA (Record of Processing Activities, GDPR Art. 30) —
 * tabular Markdown register, mirroring
 * dataflow/privacy-governance.js#emitRopaArtifact's own format, but ONE
 * ROW PER (dataClass x destination) rather than per dataClass alone — a
 * real, disclosed precision improvement the graph's own per-flow
 * sink/destination resolution makes possible (the taint-engine version
 * has no destination-resolution concept at all).
 */
export function emitGraphRopaArtifact(graph, opts = {}) {
  const viewModel = _scopedViewModel(graph, opts.filter);
  const visibleRows = viewModel.rows.filter((r) => r.visible !== false);

  const lines = [];
  lines.push('# Record of Processing Activities (RoPA) — GDPR Art. 30, graph-derived');
  lines.push('');
  lines.push('Generated by agentic-security scanner (graph-derived). Every governance');
  lines.push('field below is either supplied by an operator');
  lines.push('(.agentic-security/privacy-governance.json) or marked');
  lines.push(`\`${MANUAL_REQUIRED}\` — none are inferable from source code, and none are`);
  lines.push(`guessed. A privacy officer must fill in every \`${MANUAL_REQUIRED}\` cell`);
  lines.push('before this document is usable as a real RoPA.');
  lines.push('');
  if (visibleRows.length === 0) {
    lines.push('No regulated data flows were identified in this graph scope.');
    return lines.join('\n');
  }
  const header = ['Data class', 'Field', 'Source', 'Destination', 'Protection', ...GOVERNANCE_FIELDS];
  lines.push(`| ${header.join(' | ')} |`);
  lines.push(`|${header.map(() => '---').join('|')}|`);
  let gapCount = 0;
  for (const row of visibleRows) {
    for (const cls of row.dataClasses.length ? row.dataClasses : ['(unclassified)']) {
      const fieldValues = GOVERNANCE_FIELDS.map((f) => {
        const r = row.governanceRefs?.[f] ?? { value: MANUAL_REQUIRED, source: 'manual_required' };
        if (r.source === 'manual_required') gapCount++;
        return r.value;
      });
      lines.push(`| ${[cls, row.dataElementName, row.sourceCategory ?? 'unknown', row.sinkCategory ?? 'unknown', row.protectionSummary, ...fieldValues].join(' | ')} |`);
    }
  }
  lines.push('');
  lines.push(`${gapCount} field(s) across ${visibleRows.length} flow(s) require manual input.`);
  return lines.join('\n');
}
```

- [ ] **Step 3: Fix the filter wiring — `opts.filter` must filter the GRAPH, never `state.filters`**

**Resolved during plan review, not left open**: `frontend/src/lib/row-filters.js#matchesFilters(row, filters)`
expects `filters` shaped like `{dataClass: [...], protection: [...],
transitVerdict: [...], sourceCategory: [...], ...}` (per-facet arrays of
SELECTED VALUES — `LIST_FACETS`' own key list, confirmed by reading the
real file) — a COMPLETELY different shape from `opts.filter`'s
`{nodeIds, edgeIds}` (`export-json.js`'s own convention, shared by every
other `dataflow export` format). Step 2's draft code
(`filters: opts.filter ?? {}`) is WRONG: passing `{nodeIds, edgeIds}` as
`state.filters` would silently match NONE of `LIST_FACETS`' keys, so
EVERY row stays visible regardless of `--filter` — a silent no-op, not a
crash, exactly the kind of bug this session's own real-graph-testing
discipline exists to catch.

**Fix**: filter the GRAPH itself, before calling `computePrivacyViewModel`,
reusing `export-json.js`'s own `_filterGraph(graph, filter)` against the
real `{nodeIds, edgeIds}` shape — matching every sibling format's own
`--filter` convention exactly. `_filterGraph` is currently module-private
in `export-json.js`; export it (`export function _filterGraph(...)`,
same name, just add the `export` keyword — a small, low-risk, additive
change) and import it into `export-privacy.js`. Both emit functions
change from:

```js
const viewModel = computePrivacyViewModel(graph, { ..._emptyState(), filters: opts.filter ?? {} }, null);
```

to:

```js
const scopedGraph = opts.filter ? _filterGraph(graph, opts.filter) : graph;
const viewModel = computePrivacyViewModel(scopedGraph, _emptyState(), null);
```

Update `_emptyState()` to no longer need a `filters` key at all (it was
only ever going to carry the wrong shape) — `{selectedId: null}` is
sufficient, since `computePrivacyViewModel`'s own `matchesFilters(row,
state.filters ?? {})` call already degrades to "no facets active, every
row visible" on an empty/absent `filters` object, which is exactly the
"no --filter given" case.

- [ ] **Step 4: Write the test file**

Mirror Task 1's own real-graph test pattern (`buildGraphWithCoverage`
over `parseJsFile`/`buildCallGraph`, plus one real-corpus sweep via
`buildFixtureGraph`). Required cases:
- A real graph with a real PHI flow and a real operator-supplied
  `privacy-governance.json` produces a DPIA whose governance-fields
  section shows the operator value, not `MANUAL_REQUIRED`.
- The SAME graph with no config produces the honest all-`MANUAL_REQUIRED`
  answer.
- A RoPA table row count matches the real flow/dataClass count exactly
  (a non-vacuous count assertion, not just "table exists").
- `opts.filter` genuinely narrows the output (fewer rows/classes than
  the unfiltered call on the same graph) — resolve this test against
  whichever filter semantics Step 3 settled on.
- An empty graph (no flows) produces the "no regulated data" honest
  message, never a crash, for both functions.
- REAL CORPUS: sweep `bench/data-lineage/fixtures/` — both emit functions
  never throw on any real fixture, with and without a governance config.

- [ ] **Step 5: Run tests, wire into `test:lineage`, commit**

```bash
cd scanner && node --test test/lineage/export-privacy.test.js
npm run test:lineage
git add scanner/src/lineage/export-privacy.js scanner/test/lineage/export-privacy.test.js scanner/package.json
git commit -m "feat(lineage): graph-derived DPIA/RoPA emit functions (M4 deliverable #10)"
```

---

### Task 3: CLI wiring (`dataflow export --format dpia|ropa`)

**Files:**
- Modify: `scanner/bin/agentic-security.js` (`DATAFLOW_EXPORT_FORMATS`,
  `cmdDataflowExport`'s format dispatch)
- Test: `scanner/test/cli/dataflow-export-privacy.test.js` (new)

**Interfaces:**
- Consumes: `emitGraphDpiaArtifact`, `emitGraphRopaArtifact` from
  `../src/lineage/export-privacy.js` (Task 2's real exports).
- Produces: nothing new for later tasks — terminal task.

- [ ] **Step 1: Read the real current `cmdDataflowExport` in full**

Search `async function cmdDataflowExport` in `bin/agentic-security.js`
and read the WHOLE function — the plan's own scoping-time citations
(`DATAFLOW_EXPORT_FORMATS`, the `format === 'json'`/`'csv'` branches,
`opts.filter` construction) may have drifted since. Confirm exactly how
`opts.filter` is built from the `--filter <file>` flag (the plan's Task 2
Step 3 decision must match whatever shape actually reaches
`cmdDataflowExport`'s own `opts` object here).

- [ ] **Step 2: Add `'dpia'`/`'ropa'` to `DATAFLOW_EXPORT_FORMATS`**

```js
const DATAFLOW_EXPORT_FORMATS = new Set(['png', 'pdf', 'svg', 'json', 'csv', 'html', 'dpia', 'ropa']);
```

- [ ] **Step 3: Add the new format branch**

Mirror the existing `json`/`csv` branches exactly (no `--view` support —
confirm the existing `--view has no effect on --format ${format}` guard
already correctly covers `dpia`/`ropa` too, since they're added to the
same non-view-scoped set those branches guard against; re-read that
guard's own condition before assuming):

```js
} else if (format === 'dpia') {
  const { emitGraphDpiaArtifact } = await import('../src/lineage/export-privacy.js');
  data = emitGraphDpiaArtifact(graph, opts);
} else if (format === 'ropa') {
  const { emitGraphRopaArtifact } = await import('../src/lineage/export-privacy.js');
  data = emitGraphRopaArtifact(graph, opts);
}
```

- [ ] **Step 4: Confirm `--redact`/output-writing behave sensibly for the new formats**

Read the existing `--no-redact has no effect on --format csv` guard and
decide (a real ruling, not left implicit) whether `dpia`/`ropa` need the
same guard — `emitGraphDpiaArtifact`/`emitGraphRopaArtifact` never call
`exportGraphJSON`'s own redaction path, so `--redact`/`--no-redact` has
no effect on them either, matching CSV's own precedent. Add the
equivalent guard message if the existing code structure makes that the
established pattern (check whether CSV's guard is a `--format`-keyed
conditional near the top of the flag-validation block, and mirror it).

- [ ] **Step 5: Write the CLI integration test**

Mirror `test/cli/attest-obligations.test.js`'s real-scan-then-CLI-call
pattern: real git fixture with the proven PHI_SOURCE shape, real scan
with `AGENTIC_SECURITY_LINEAGE_DEEP=1`, `dataflow export . --format dpia
--output dpia.md`, assert exit 0 and real Markdown content (a `# Data
Protection Impact Assessment` header, at least one data class section);
same for `--format ropa` (a `# Record of Processing Activities` header,
a real Markdown table). Also test `--filter` narrows the dpia/ropa
output on a graph with more than one flow (construct a two-flow fixture
if the existing PHI-only shape doesn't produce two).

- [ ] **Step 6: Run tests, rebuild, run full gates**

```bash
cd scanner
node --test test/cli/dataflow-export-privacy.test.js
npm run build
npm run test:posture
npm run test:lineage
npm run test:server
npm run test:smoke
npm run test:lifecycle
```

Capture and report every real exit code. Confirm
`dist/agentic-security.mjs.sha256` matches (`cd dist && shasum -a 256 -c agentic-security.mjs.sha256`).

- [ ] **Step 7: Update docs**

`scanner/src/lineage/CLAUDE.md`: add a table row for
`export-privacy.js` under the Milestone 4 export section, mirroring
`export-json.js`/`export-csv.js`'s own row style. Note the new
`scanner/` → `frontend/` live-import precedent explicitly (this is the
first one — say so, the same way sub-project 6b's own
`posture/` → `lineage/` first-import was disclosed in `posture/CLAUDE.md`).

`scanner/bin/agentic-security.js`'s own `--help` text (search for the
existing `dataflow export [path] --format png|pdf|svg|json|csv|html`
usage line) — add `dpia|ropa` to the format list.

`docs/superpowers/plans/2026-09-01-data-flow-explorer-m4-scoping.md`'s
row #10 — mark COMPLETE, matching sub-project #6's own precedent for
this update (done AFTER merge, not part of this task's own commit, per
that same precedent).

- [ ] **Step 8: Commit**

```bash
git add scanner/bin/agentic-security.js scanner/test/cli/dataflow-export-privacy.test.js scanner/src/lineage/CLAUDE.md
git commit -m "feat(cli): wire graph-derived DPIA/RoPA into dataflow export --format dpia|ropa (M4 deliverable #10)"
```

## Self-review notes (per the writing-plans skill, already applied above)

- **Spec coverage**: PRD §7.4's "generate filtered DPIA and RoPA exports
  from the selected graph scope" is satisfied by Task 3's `--filter`
  support; "state that the diagram is code-derived and must be reviewed"
  is satisfied by both emit functions' own disclaimer text (Task 2).
  "Behind a migration flag" is satisfied by the ruling in Task 1's Global
  Constraints (AGENTIC_SECURITY_LINEAGE_DEEP=1 IS the flag).
- **Known open decision, flagged rather than guessed**: Task 2 Step 3's
  `opts.filter` shape question is the single largest correctness risk in
  this plan — the draft code assumes one shape, but the plan explicitly
  requires verifying it against the real `matchesFilters`/filter-facet
  code before trusting it, rather than silently shipping a wrong
  assumption the way a less careful plan might.
- **Placeholder scan**: Task 1 Step 5's `require()` test is a deliberate,
  flagged placeholder (explicitly marked as such, with an exact
  instruction for what to replace it with) — not a silently-shipped TODO.
