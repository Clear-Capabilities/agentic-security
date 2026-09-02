# Milestone 4, sub-project 6b (obligation predicate/mapping engine) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the first real `graph:` predicate type — a declarative,
graph-fact-reading predicate evaluated against a shipped `DataFlowGraph v1`
document, wired into `auditor-walkthrough.js`'s existing typed-predicate
dispatch, minting real `ObligationMapping` records via 6a's already-shipped
contract, proven end-to-end against one real control (HIPAA §164.312(e),
transmission security).

**Architecture:** A new, standalone module,
`scanner/src/lineage/obligation-predicates.js`, evaluates a small
declarative match object against a graph's `flows[]`/`edges[]`/
`dataElements[]`/`nodes[]` (joined by id — no pre-joined view exists) and
mints a real `ObligationMapping` record. `auditor-walkthrough.js` gains one
new, additive `else if (m.startsWith('graph:'))` branch in its existing
predicate-dispatch loop — the three existing branches (`family:`/`module:`/
`rule:`) and their status computation are UNCHANGED.

**Tech Stack:** Plain ESM, zero new npm dependency.

**Spec:** `docs/superpowers/plans/2026-09-01-data-flow-explorer-m4-obligation-predicate-scoping.md`
(read this first — it has the full ruling set this plan implements:
`frameworkVersion` from `controlsDigest`, `applicabilityInputs` stays
all-`null`, the declarative-match-object pattern, the state-vocabulary
remap, HIPAA §164.312(e) as the first real case) and 6a's own module,
`scanner/src/lineage/obligation-mapping.js` (already shipped — read its
real exports before writing code against it).

## Global Constraints

- The three existing predicate branches in `auditor-walkthrough.js`'s
  `evaluateFramework` (`family:`/`module:`/`rule:`) and their status
  computation (`anySignal`/`allCleared`/`anyCleared`/
  `hasUnverifiableMapping` → `present`/`partial`/`absent`/`manual`) MUST
  NOT change behavior. The new `graph:` branch is purely additive — it
  contributes to the SAME status variables (so a control's overall
  present/partial/absent/manual status still makes sense when it has a mix
  of predicate types), and SEPARATELY collects a real `ObligationMapping`
  record onto the per-control result object.
- `frameworkVersion` on every minted record is `fw.controlsDigest` — never
  a hand-typed literal (no catalog carries a real version field; see the
  scoping doc's own ruling 3).
- `applicabilityInputs` on every minted record has all seven keys
  explicitly `null` — this sub-project does not build applicability-input
  config (scoping doc ruling 5). This is a deliberate, honest answer, not
  a placeholder to "fix" later in this same plan.
- `factType` on every graph-predicate-derived record is `'code_inferred'`
  (the graph itself is static-analysis-derived).
- State derivation (scoping doc ruling 4), in this exact priority order:
  `scan.lineageGraph` absent entirely → `'unknown'`; graph present but the
  predicate matches zero relevant flows → `'not_applicable'`; graph
  present, predicate applicable, every relevant flow clears →
  `'evidence_supported'`; graph present, predicate applicable, at least
  one relevant flow fails → `'gap_detected'`.
- The HIPAA catalog's existing `family:crypto-tls-no-verify`/
  `family:crypto-tls-version` mappings on §164.312(e) are AUGMENTED
  (a `graph:` entry added alongside them), never removed — the existing
  family-based detection stays real signal for repos with no lineage
  graph at all (the common case, since lineage is opt-in).
- `obligation-predicates.js` is a NEW cross-package dependency direction
  (`scanner/src/posture/` importing from `scanner/src/lineage/`) —
  confirmed via repo-wide grep that no `posture/*.js` file imports from
  `lineage/` today. This is a real, disclosed first-of-its-kind
  connection, not a violation of an existing isolation boundary (unlike
  `dataflow/`↔`lineage/`, which IS a documented, enforced isolation
  principle — `posture/`↔`lineage/` has no such rule; it's simply never
  had a reason to connect before this sub-project).

---

### Task 1: `obligation-predicates.js` — the graph-fact predicate evaluator + record builder

**Files:**
- Create: `scanner/src/lineage/obligation-predicates.js`
- Test: `scanner/test/lineage/obligation-predicates.test.js`

**Interfaces:**
- Consumes: `computeGraphDigest` from `./export-json.js` (already shipped);
  `obligationId` from `./ids.js` (already shipped, sub-project 6a);
  `OBLIGATION_STATES`, `validateObligationMapping` from
  `./obligation-mapping.js` (already shipped, sub-project 6a).
- Produces: `evaluateGraphFlowPredicate(spec, graph)` →
  `{applicable, matched, contributingGraphIds, evidence, resultsCount,
  failedCount}`; `buildObligationMappingFromGraphPredicate({framework,
  frameworkVersion, requirementId, requirementSource, predicateLabel,
  graph, evaluation})` → a full, `validateObligationMapping`-clean
  `ObligationMapping` record (or the `'unknown'`-state record shape when
  `graph` is `null`/`undefined`). Task 2 imports both.

- [ ] **Step 1: Write the failing tests**

Create `scanner/test/lineage/obligation-predicates.test.js`:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  evaluateGraphFlowPredicate,
  buildObligationMappingFromGraphPredicate,
} from '../../src/lineage/obligation-predicates.js';
import { validateObligationMapping } from '../../src/lineage/obligation-mapping.js';

// A minimal, hand-built graph — just enough shape for a `graph-flow`
// predicate to walk: one dataElement (PHI), one external sink node, one
// edge carrying a transit verdict, one flow tying them together. Two
// variants: PROTECTED (positive) and UNPROTECTED (negative).
function _minimalGraph({ transitVerdict, dataClass = 'PHI', sinkKind = 'external' }) {
  return {
    graphId: 'dfg:test-repo:abc123:default',
    nodes: [
      { id: 'node:src1', kind: 'api' },
      { id: 'node:sink1', kind: sinkKind },
    ],
    edges: [
      {
        id: 'edge:e1',
        from: 'node:src1', to: 'node:sink1',
        protection: { transit: { verdict: transitVerdict, evidenceGrade: 'code' }, atRest: { verdict: 'not_assessed', evidenceGrade: 'none' }, handling: { verdict: 'not_assessed', evidenceGrade: 'none' } },
        evidenceRefs: ['evidence:ev1'],
      },
    ],
    dataElements: [
      { id: 'data:d1', name: 'patient_record', dataClasses: [dataClass] },
    ],
    flows: [
      { id: 'flow:f1', dataElementIds: ['data:d1'], source: 'node:src1', sink: 'node:sink1', edgeIds: ['edge:e1'] },
    ],
  };
}

const PROTECTED_SPEC = { type: 'graph-flow', dataClass: 'PHI', sinkKind: 'external', dimension: 'transit', requiredVerdict: 'protected' };

test('evaluateGraphFlowPredicate: a protected flow matches, contributes its flow id and edge evidence', () => {
  const graph = _minimalGraph({ transitVerdict: 'protected' });
  const r = evaluateGraphFlowPredicate(PROTECTED_SPEC, graph);
  assert.equal(r.applicable, true);
  assert.equal(r.matched, true);
  assert.deepEqual(r.contributingGraphIds, ['flow:f1']);
  assert.deepEqual(r.evidence, ['evidence:ev1']);
  assert.equal(r.resultsCount, 1);
  assert.equal(r.failedCount, 0);
});

test('evaluateGraphFlowPredicate: an unprotected flow does not match', () => {
  const graph = _minimalGraph({ transitVerdict: 'unprotected' });
  const r = evaluateGraphFlowPredicate(PROTECTED_SPEC, graph);
  assert.equal(r.applicable, true);
  assert.equal(r.matched, false);
  assert.equal(r.failedCount, 1);
});

test('evaluateGraphFlowPredicate: no relevant flows (wrong dataClass) is not_applicable, not a false match', () => {
  const graph = _minimalGraph({ transitVerdict: 'protected', dataClass: 'PII' });
  const r = evaluateGraphFlowPredicate(PROTECTED_SPEC, graph);
  assert.equal(r.applicable, false);
  assert.equal(r.matched, null);
  assert.deepEqual(r.contributingGraphIds, []);
});

test('evaluateGraphFlowPredicate: no relevant flows (wrong sink kind) is not_applicable', () => {
  const graph = _minimalGraph({ transitVerdict: 'protected', sinkKind: 'store' });
  const r = evaluateGraphFlowPredicate(PROTECTED_SPEC, graph);
  assert.equal(r.applicable, false);
});

test('evaluateGraphFlowPredicate: a flow with no edges / missing edge is treated as not_assessed, not a crash', () => {
  const graph = _minimalGraph({ transitVerdict: 'protected' });
  graph.flows[0].edgeIds = ['edge:does-not-exist'];
  const r = evaluateGraphFlowPredicate(PROTECTED_SPEC, graph);
  assert.equal(r.applicable, true);
  assert.equal(r.matched, false);
});

test('evaluateGraphFlowPredicate: a real graph with zero flows at all is not_applicable, never throws', () => {
  const graph = { graphId: 'dfg:x:y:default', nodes: [], edges: [], dataElements: [], flows: [] };
  assert.doesNotThrow(() => evaluateGraphFlowPredicate(PROTECTED_SPEC, graph));
  const r = evaluateGraphFlowPredicate(PROTECTED_SPEC, graph);
  assert.equal(r.applicable, false);
});

// =====================================================================
// buildObligationMappingFromGraphPredicate — the record-minting half
// =====================================================================

function _baseArgs(graph, evaluation) {
  return {
    framework: 'hipaa-security-rule',
    frameworkVersion: 'test-digest-123',
    requirementId: '§164.312(e)',
    requirementSource: 'https://example.test/hipaa',
    predicateLabel: 'graph:transit-protection:PHI:external:transit:protected',
    graph,
    evaluation,
  };
}

test('buildObligationMappingFromGraphPredicate: a matched predicate produces an evidence_supported, validateObligationMapping-clean record', () => {
  const graph = _minimalGraph({ transitVerdict: 'protected' });
  const evaluation = evaluateGraphFlowPredicate(PROTECTED_SPEC, graph);
  const record = buildObligationMappingFromGraphPredicate(_baseArgs(graph, evaluation));
  assert.equal(record.state, 'evidence_supported');
  assert.equal(record.frameworkVersion, 'test-digest-123');
  assert.equal(record.factType, 'code_inferred');
  assert.deepEqual(record.applicabilityInputs, {
    entityRole: null, jurisdiction: null, dataSubject: null, businessProcess: null,
    merchantLevel: null, systemScope: null, aiSystemRole: null,
  });
  const { valid, errors } = validateObligationMapping(record);
  assert.equal(valid, true, JSON.stringify(errors));
});

test('buildObligationMappingFromGraphPredicate: a failed predicate produces gap_detected', () => {
  const graph = _minimalGraph({ transitVerdict: 'unprotected' });
  const evaluation = evaluateGraphFlowPredicate(PROTECTED_SPEC, graph);
  const record = buildObligationMappingFromGraphPredicate(_baseArgs(graph, evaluation));
  assert.equal(record.state, 'gap_detected');
  assert.equal(validateObligationMapping(record).valid, true);
});

test('buildObligationMappingFromGraphPredicate: no relevant flows produces not_applicable', () => {
  const graph = _minimalGraph({ transitVerdict: 'protected', dataClass: 'PII' });
  const evaluation = evaluateGraphFlowPredicate(PROTECTED_SPEC, graph);
  const record = buildObligationMappingFromGraphPredicate(_baseArgs(graph, evaluation));
  assert.equal(record.state, 'not_applicable');
  assert.equal(validateObligationMapping(record).valid, true);
});

test('buildObligationMappingFromGraphPredicate: a null/absent graph produces unknown, never throws', () => {
  const record = buildObligationMappingFromGraphPredicate({
    framework: 'hipaa-security-rule', frameworkVersion: 'test-digest-123',
    requirementId: '§164.312(e)', requirementSource: null,
    predicateLabel: 'graph:transit-protection:PHI:external:transit:protected',
    graph: null, evaluation: null,
  });
  assert.equal(record.state, 'unknown');
  assert.equal(validateObligationMapping(record).valid, true);
});

test('buildObligationMappingFromGraphPredicate: the id is a real obligationId, stable for identical inputs', () => {
  const graph = _minimalGraph({ transitVerdict: 'protected' });
  const evaluation = evaluateGraphFlowPredicate(PROTECTED_SPEC, graph);
  const a = buildObligationMappingFromGraphPredicate(_baseArgs(graph, evaluation));
  const b = buildObligationMappingFromGraphPredicate(_baseArgs(graph, evaluation));
  assert.match(a.id, /^obligation:[0-9a-f]{12}$/);
  assert.equal(a.id, b.id);
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd scanner && node --test test/lineage/obligation-predicates.test.js`
Expected: FAIL — the module does not exist yet.

- [ ] **Step 3: Implement `obligation-predicates.js`**

```js
// obligation-predicates.js — Milestone 4 sub-project 6b: the graph-fact
// predicate evaluator + ObligationMapping record builder (FR-504 §7.12).
//
// A `graph-flow` predicate spec is a small declarative match object,
// mirroring dataflow/catalog.js's own established `match`-object +
// hand-written-matcher pattern (this codebase's convention for "a small
// declarative query, evaluated by a hand-written function," rather than a
// general query language) — {type:'graph-flow', dataClass, sinkKind,
// dimension, requiredVerdict}. No pre-joined "enriched flow" view exists
// on a shipped DataFlowGraph v1 document, so evaluateGraphFlowPredicate
// builds its own id->entity Maps and joins flow.dataElementIds/.sink
// against dataElements[]/nodes[], exactly as graph-builder.js's own
// internal loops already do.
//
// buildObligationMappingFromGraphPredicate mints a real ObligationMapping
// record (sub-project 6a) from an evaluation result. State derivation
// (scoping doc ruling 4): graph absent -> unknown; predicate matches zero
// relevant flows -> not_applicable; every relevant flow clears ->
// evidence_supported; at least one relevant flow fails -> gap_detected.
// applicabilityInputs stays all-null (ruling 5 — no operator-config
// source for it exists anywhere in this codebase yet, a deliberately
// deferred, separate increment).

import { computeGraphDigest } from './export-json.js';
import { obligationId } from './ids.js';

export function evaluateGraphFlowPredicate(spec, graph) {
  const dataElementsById = new Map((graph?.dataElements ?? []).map((d) => [d.id, d]));
  const nodesById = new Map((graph?.nodes ?? []).map((n) => [n.id, n]));
  const edgesById = new Map((graph?.edges ?? []).map((e) => [e.id, e]));

  const relevantFlows = (graph?.flows ?? []).filter((f) => {
    const des = (f.dataElementIds ?? []).map((id) => dataElementsById.get(id)).filter(Boolean);
    const hasClass = des.some((d) => (d.dataClasses ?? []).includes(spec.dataClass));
    if (!hasClass) return false;
    const sinkNode = nodesById.get(f.sink);
    return !!sinkNode && sinkNode.kind === spec.sinkKind;
  });

  if (relevantFlows.length === 0) {
    return { applicable: false, matched: null, contributingGraphIds: [], evidence: [], resultsCount: 0, failedCount: 0 };
  }

  const results = relevantFlows.map((f) => {
    const edge = edgesById.get((f.edgeIds ?? [])[0]);
    const verdict = edge?.protection?.[spec.dimension]?.verdict ?? 'not_assessed';
    return { flow: f, edge, verdict, cleared: verdict === spec.requiredVerdict };
  });

  return {
    applicable: true,
    matched: results.every((r) => r.cleared),
    contributingGraphIds: results.map((r) => r.flow.id),
    evidence: results.flatMap((r) => r.edge?.evidenceRefs ?? []),
    resultsCount: results.length,
    failedCount: results.filter((r) => !r.cleared).length,
  };
}

const _NULL_APPLICABILITY_INPUTS = Object.freeze({
  entityRole: null, jurisdiction: null, dataSubject: null, businessProcess: null,
  merchantLevel: null, systemScope: null, aiSystemRole: null,
});

export function buildObligationMappingFromGraphPredicate({
  framework, frameworkVersion, requirementId, requirementSource, predicateLabel, graph, evaluation,
}) {
  const graphId = graph?.graphId ?? null;
  const graphDigest = graph ? computeGraphDigest(graph) : null;

  let state;
  if (!graph) state = 'unknown';
  else if (!evaluation.applicable) state = 'not_applicable';
  else if (evaluation.matched) state = 'evidence_supported';
  else state = 'gap_detected';

  return {
    id: obligationId({ framework, frameworkVersion, requirementId, graphId: graphId ?? '', graphDigest: graphDigest ?? '' }),
    graphId: graphId ?? '(no graph)',
    graphDigest: graphDigest ?? '(no graph)',
    framework,
    frameworkVersion,
    requirementId,
    requirementSource: requirementSource ?? null,
    applicabilityInputs: { ..._NULL_APPLICABILITY_INPUTS },
    state,
    predicate: predicateLabel,
    factType: 'code_inferred',
    contributingGraphIds: evaluation?.contributingGraphIds ?? [],
    evidence: evaluation?.evidence ?? [],
    conflicts: [],
    missingManualArtifacts: [],
    reviewer: null,
    reviewedAt: null,
    expiresAt: null,
  };
}
```

Note: `graphId ?? ''`/`graphDigest ?? ''` in the `obligationId` call (not
`'(no graph)'`) — `validateObligationMapping` requires `record.graphId`/
`record.graphDigest` to be non-empty strings, so the RECORD's own fields
use the human-readable `'(no graph)'` placeholder (still a valid non-empty
string), while the id-hash material uses `''` so `_canon`'s own null/
undefined-to-`''` normalization stays the single source of truth for what
"absent" hashes to — avoiding two different sentinel values for the same
"no graph" case reaching two different parts of the record.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd scanner && node --test test/lineage/obligation-predicates.test.js`
Expected: PASS, all tests.

- [ ] **Step 5: Wire into the test:lineage npm script**

Add `test/lineage/obligation-predicates.test.js` to `scanner/package.json`'s
`test:lineage` script, near the other `test/lineage/obligation-*.test.js`
entry.

- [ ] **Step 6: Commit**

```bash
git add scanner/src/lineage/obligation-predicates.js scanner/test/lineage/obligation-predicates.test.js scanner/package.json
git commit -m "feat(lineage): add the graph-fact obligation predicate evaluator (FR-504 §7.12, sub-project 6b)"
```

---

### Task 2: Wire `graph:` predicate dispatch into `auditor-walkthrough.js` + the real HIPAA §164.312(e) case

**Files:**
- Modify: `scanner/src/posture/auditor-walkthrough.js`
- Modify: `scanner/src/posture/compliance-frameworks/hipaa-security-rule.json`
- Test: `scanner/test/lineage/obligation-predicates-walkthrough.test.js`
  (a NEW file, kept separate from `test/posture/`'s own
  `auditor-walkthrough.test.js` — this sub-project's own end-to-end proof
  needs a real built `DataFlowGraph v1` document, which is a `lineage/`
  concern, not a `posture/` one; read `test/posture/auditor-walkthrough.test.js`
  first to confirm it does NOT already cover this — it should not, since
  `graph:` doesn't exist there yet)

**Interfaces:**
- Consumes: `evaluateGraphFlowPredicate`, `buildObligationMappingFromGraphPredicate`
  from `../lineage/obligation-predicates.js` (Task 1).
- Produces: `evaluateFramework`'s return objects gain one new, optional key,
  `obligationMappings: ObligationMapping[]` (empty array when a control has
  no `graph:` mappings — never `undefined`, so a caller can always safely
  read `.length`).

- [ ] **Step 1: Read the real current `evaluateFramework` before editing**

Read `scanner/src/posture/auditor-walkthrough.js` in full — this plan's own
excerpt in the scoping doc's investigation may have shifted line numbers
since. Confirm the exact current shape of the `for (const m of maps)` loop
(the `family:`/`module:`/`rule:` branches) and the `results.push({...})`
call at the end of the per-control loop, before making any edit.

- [ ] **Step 2: Write the failing end-to-end test**

Create `scanner/test/lineage/obligation-predicates-walkthrough.test.js`:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { loadFramework, evaluateFramework } from '../../src/posture/auditor-walkthrough.js';
import { validateObligationMapping } from '../../src/lineage/obligation-mapping.js';

function _minimalGraph({ transitVerdict }) {
  return {
    graphId: 'dfg:test-repo:abc123:default',
    nodes: [
      { id: 'node:src1', kind: 'api' },
      { id: 'node:sink1', kind: 'external' },
    ],
    edges: [
      {
        id: 'edge:e1',
        from: 'node:src1', to: 'node:sink1',
        protection: { transit: { verdict: transitVerdict, evidenceGrade: 'code' }, atRest: { verdict: 'not_assessed', evidenceGrade: 'none' }, handling: { verdict: 'not_assessed', evidenceGrade: 'none' } },
        evidenceRefs: [],
      },
    ],
    dataElements: [
      { id: 'data:d1', name: 'patient_record', dataClasses: ['PHI'] },
    ],
    flows: [
      { id: 'flow:f1', dataElementIds: ['data:d1'], source: 'node:src1', sink: 'node:sink1', edgeIds: ['edge:e1'] },
    ],
  };
}

function _mkScanRoot() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'obligation-walkthrough-'));
}

test('evaluateFramework: HIPAA §164.312(e) mints a real evidence_supported ObligationMapping when transit is protected', () => {
  const scanRoot = _mkScanRoot();
  try {
    const fw = loadFramework(scanRoot, 'hipaa-security-rule');
    assert.ok(fw, 'the real hipaa-security-rule.json catalog must load');
    const graph = _minimalGraph({ transitVerdict: 'protected' });
    const scan = { findings: [], secrets: [], logicVulns: [], supplyChain: [], components: [], lineageGraph: graph };
    const evaluation = evaluateFramework(scanRoot, fw, scan);
    const control = evaluation.find((e) => e.control.id === '§164.312(e)');
    assert.ok(control, 'the real §164.312(e) control must be present in the real catalog');
    assert.ok(Array.isArray(control.obligationMappings));
    const mapping = control.obligationMappings.find((m) => m.framework === 'hipaa-security-rule');
    assert.ok(mapping, 'a real graph: predicate must have produced a mapping for this control');
    assert.equal(mapping.state, 'evidence_supported');
    assert.equal(mapping.frameworkVersion, fw.controlsDigest);
    assert.equal(validateObligationMapping(mapping).valid, true);
  } finally {
    fs.rmSync(scanRoot, { recursive: true, force: true });
  }
});

test('evaluateFramework: HIPAA §164.312(e) mints gap_detected when transit is unprotected (negative proof)', () => {
  const scanRoot = _mkScanRoot();
  try {
    const fw = loadFramework(scanRoot, 'hipaa-security-rule');
    const graph = _minimalGraph({ transitVerdict: 'unprotected' });
    const scan = { findings: [], secrets: [], logicVulns: [], supplyChain: [], components: [], lineageGraph: graph };
    const evaluation = evaluateFramework(scanRoot, fw, scan);
    const control = evaluation.find((e) => e.control.id === '§164.312(e)');
    const mapping = control.obligationMappings.find((m) => m.framework === 'hipaa-security-rule');
    assert.equal(mapping.state, 'gap_detected');
    assert.equal(validateObligationMapping(mapping).valid, true);
  } finally {
    fs.rmSync(scanRoot, { recursive: true, force: true });
  }
});

test('evaluateFramework: HIPAA §164.312(e) mints unknown when no lineage graph is present (the common, opt-in-off case)', () => {
  const scanRoot = _mkScanRoot();
  try {
    const fw = loadFramework(scanRoot, 'hipaa-security-rule');
    const scan = { findings: [], secrets: [], logicVulns: [], supplyChain: [], components: [] }; // no lineageGraph key at all
    const evaluation = evaluateFramework(scanRoot, fw, scan);
    const control = evaluation.find((e) => e.control.id === '§164.312(e)');
    const mapping = control.obligationMappings.find((m) => m.framework === 'hipaa-security-rule');
    assert.equal(mapping.state, 'unknown');
    assert.equal(validateObligationMapping(mapping).valid, true);
  } finally {
    fs.rmSync(scanRoot, { recursive: true, force: true });
  }
});

test('evaluateFramework: the existing family:crypto-tls-* mappings on §164.312(e) still contribute to the ordinary present/partial/absent/manual status, unchanged', () => {
  // A real, disclosed regression guard: adding the graph: branch must not
  // change how the pre-existing family: mappings drive `status`.
  const scanRoot = _mkScanRoot();
  try {
    const fw = loadFramework(scanRoot, 'hipaa-security-rule');
    const scan = { findings: [], secrets: [], logicVulns: [], supplyChain: [], components: [] };
    const evaluation = evaluateFramework(scanRoot, fw, scan);
    const control = evaluation.find((e) => e.control.id === '§164.312(e)');
    // Zero findings of either crypto-tls family -> both family: mappings
    // clear ("no open findings") -> allCleared stays true for THAT half;
    // status is still driven by the existing logic, not the new graph:
    // branch (which, with no lineageGraph, produces only a mapping, not a
    // status contribution of its own — see Task 2 Step 3's own ruling).
    assert.ok(['present', 'partial'].includes(control.status), `expected the pre-existing status logic to still produce present/partial, got ${control.status}`);
  } finally {
    fs.rmSync(scanRoot, { recursive: true, force: true });
  }
});
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd scanner && node --test test/lineage/obligation-predicates-walkthrough.test.js`
Expected: FAIL (no `graph:` branch exists yet, `control.obligationMappings`
is `undefined`).

- [ ] **Step 4: Add the `graph:` predicate branch**

Add the import at the top of `scanner/src/posture/auditor-walkthrough.js`
(alongside its existing imports — read the file's current import block
first and add to it, don't assume its exact current line number):

```js
import { evaluateGraphFlowPredicate, buildObligationMappingFromGraphPredicate } from '../lineage/obligation-predicates.js';
```

Inside the `for (const m of maps)` loop, add a new branch AFTER the
existing `rule:` branch (do not reorder the existing three):

```js
      } else if (m.startsWith('graph:')) {
        // A graph: mapping never contributes to anySignal/allCleared/
        // anyCleared/hasUnverifiableMapping — the existing
        // present/partial/absent/manual status stays driven entirely by
        // the family:/module:/rule: mappings a control already has (this
        // task's own Global Constraint: purely additive). It instead
        // mints a real ObligationMapping record, collected separately.
        //
        // First real predicate (scoping doc ruling 6): PHI/PII flowing to
        // an external sink must cross a protected transit edge. The
        // predicate STRING itself is currently a fixed label (not yet a
        // parsed mini-language) — the first real graph: mapping this
        // sub-project ships is HIPAA §164.312(e)'s
        // "graph:transit-protection:PHI:external:transit:protected",
        // hardcoded to this one spec until a second real case proves the
        // parsing is worth generalizing (YAGNI — do not invent a parser
        // for one caller).
        const spec = { type: 'graph-flow', dataClass: 'PHI', sinkKind: 'external', dimension: 'transit', requiredVerdict: 'protected' };
        const graph = scan.lineageGraph ?? null;
        const evaluation = graph ? evaluateGraphFlowPredicate(spec, graph) : null;
        const mapping = buildObligationMappingFromGraphPredicate({
          framework: fw.id,
          frameworkVersion: fw.controlsDigest,
          requirementId: c.id,
          requirementSource: fw.url ?? null,
          predicateLabel: m,
          graph,
          evaluation,
        });
        obligationMappings.push(mapping);
        obs.push(`(graph mapping) ${m} -> ${mapping.state}.`);
      }
```

Immediately before the `for (const m of maps)` loop, initialize the
collector (near the loop's other per-control accumulators — `obs`,
`contributingFindings`, etc.):

```js
    const obligationMappings = [];
```

In the `results.push({...})` call at the end of the per-control loop, add
the new key:

```js
    results.push({
      control: c,
      status,
      observations: obs,
      controlRefs: dedupedRefs,
      derivedProvenance: deriveComplianceProvenance(contributingFindings),
      obligationMappings,
      ...(evidence ? { evidence, partiallyEvidenced: evidence.tier === 'weak' || evidence.tier === 'unmeasured' } : {}),
    });
```

- [ ] **Step 5: Add the real HIPAA catalog mapping**

In `scanner/src/posture/compliance-frameworks/hipaa-security-rule.json`,
find the `§164.312(e)` control (confirm its current exact `mapsTo` array
first — do not assume the two entries below are the only ones still
present) and ADD a third entry, alongside (never replacing) the existing
two:

```json
      "mapsTo": [
        "family:crypto-tls-no-verify",
        "family:crypto-tls-version",
        "graph:transit-protection:PHI:external:transit:protected"
      ]
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd scanner && node --test test/lineage/obligation-predicates-walkthrough.test.js`
Expected: PASS, all 4 tests.

There is no single dedicated test file for `auditor-walkthrough.js` — its
real coverage is spread across several files in `test/` (confirmed via
`grep -rl "auditor-walkthrough\|evaluateFramework\|loadFramework"
scanner/test/*.js`): `compliance-mapping-liveness.test.js`,
`compliance-severity-threshold.test.js`, `compliance-severity-policy.test.js`,
`framework-provenance-controlrefs.test.js`, `evidence-grade-wording.test.js`
(all five already wired into the `test:posture` npm script). Run:

```
cd scanner && node --test test/compliance-mapping-liveness.test.js test/compliance-severity-threshold.test.js test/compliance-severity-policy.test.js test/framework-provenance-controlrefs.test.js test/evidence-grade-wording.test.js
```

Expected: PASS, UNCHANGED pass count from before this task — this is the
explicit confirmation (not an assumption) that the existing
`family:`/`module:`/`rule:` behavior genuinely didn't regress. (Re-verify
this file list against a real `grep` at task-execution time — this plan's
own list could drift if another file starts exercising
`auditor-walkthrough.js` before this task runs.)

- [ ] **Step 7: Run the full `test:lineage` and `test:posture` scopes**

Run: `cd scanner && npm run test:lineage && npm run test:posture`
Expected: both PASS in full.

- [ ] **Step 8: Commit**

```bash
git add scanner/src/posture/auditor-walkthrough.js scanner/src/posture/compliance-frameworks/hipaa-security-rule.json scanner/test/lineage/obligation-predicates-walkthrough.test.js
git commit -m "feat(compliance): wire the graph: predicate type into auditor-walkthrough.js, HIPAA §164.312(e) end to end"
```

---

### Task 3: Docs — CLAUDE.md rows + scoping doc completion marks

**Files:**
- Modify: `scanner/src/lineage/CLAUDE.md`
- Modify: `scanner/src/posture/CLAUDE.md` (only if it independently
  documents `auditor-walkthrough.js`'s predicate types by name — check
  first with `grep -n "family:\|module:\|rule:" scanner/src/posture/CLAUDE.md`;
  skip this file's edit if it doesn't)
- Modify: `docs/superpowers/plans/2026-09-01-data-flow-explorer-m4-obligation-overlay-scoping.md`
  (mark 6b COMPLETE, mirroring 6a's own row update)

**Interfaces:**
- Consumes: nothing new — documentation only, describing what Tasks 1-2
  shipped.
- Produces: nothing consumed by later tasks (final task in this plan).

- [ ] **Step 1: Add `obligation-predicates.js` to the lineage module index**

In `scanner/src/lineage/CLAUDE.md`'s "Milestone 4, Regulatory Obligation
Overlay" sub-heading (added by sub-project 6a — find it via
`grep -n "Regulatory Obligation Overlay" scanner/src/lineage/CLAUDE.md`),
add a row for the new module, alongside `obligation-mapping.js`'s own row,
and update that sub-heading's own status line from "sub-project 6a —
COMPLETE. 6b ... not yet started" to reflect 6b's own completion:

```
| `obligation-predicates.js` | The graph-fact predicate evaluator + `ObligationMapping` record builder (sub-project 6b). `evaluateGraphFlowPredicate(spec, graph)` walks a shipped graph's `flows[]`/`edges[]`/`dataElements[]`/`nodes[]` (joined by id) against a small declarative match object, mirroring `dataflow/catalog.js`'s own established match-object pattern. `buildObligationMappingFromGraphPredicate(...)` mints a real, `validateObligationMapping`-clean record. Wired into `posture/auditor-walkthrough.js`'s existing typed-predicate dispatch as a new, additive `graph:` branch — the first real case is HIPAA §164.312(e)'s transit-protection check. |
```

- [ ] **Step 2: Mark 6b COMPLETE in its own scoping doc and the parent doc**

In `docs/superpowers/plans/2026-09-01-data-flow-explorer-m4-obligation-overlay-scoping.md`'s
decomposition-section item 2 (6b), update the status the same way 6a's own
item 1 was updated — `**— COMPLETE (<date>)**` — and add one sentence
naming what shipped (the module, the wiring, the one real HIPAA case).

- [ ] **Step 3: Run the doc-drift checker**

Run: `cd scanner && npm run test:lifecycle`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add scanner/src/lineage/CLAUDE.md docs/superpowers/plans/2026-09-01-data-flow-explorer-m4-obligation-overlay-scoping.md
# (add scanner/src/posture/CLAUDE.md too, only if Step 0's grep found something to update)
git commit -m "docs(lineage): document obligation-predicates.js, mark M4 sub-project 6b COMPLETE"
```
