# Milestone 4, sub-project 6a (ObligationMapping extension contract) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Define the `ObligationMapping` record shape (FR-504, PRD §7.12 and
§10.10) as a pure, self-contained schema/validation module — the smallest,
lowest-risk piece of sub-project #6, unblocking 6b (the predicate/mapping
engine) and 6c (evidence-pack export).

**Architecture:** A single new pure module (`scanner/src/lineage/
obligation-mapping.js`) defining the record's enums and a structural
validator, plus one new ID-generation function added to the existing
`ids.js`. Per this sub-project's own scoping doc's binding ruling,
`ObligationMapping` records are explicitly NOT `DataFlowGraph v1` entities
— never added to `dataflow-graph.schema.json`, never routed through
`validate.js`'s `validateGraph()`, never given a `node:`/`edge:`/`flow:`/
`data:` canonical ID. They are a separate, versioned artifact that
references the base graph by ID and exact digest (PRD §10.10: "associated
with, but not required inside, the immutable base graph"), following the
exact precedent `ids.js`'s `provenanceNodeId`/`provenanceEdgeId` already
established for the identical problem (a real, stable-ID'd entity that is
deliberately not a base-graph entity).

**Tech Stack:** Plain ESM, zero new npm dependency, zero new imports in the
new module itself (matching `flow-grade.js`'s own "pure function library,
zero imports" precedent — this module has even less reason to import
anything, since a record's shape check needs no graph traversal).

**Spec:** `docs/superpowers/plans/2026-09-01-data-flow-explorer-m4-obligation-overlay-scoping.md`
(read this first — it has the full ruling set this plan implements) and
`AGENTIC_SECURITY_DATA_FLOW_EXPLORER_PRD.md:497-517` (FR-504 §7.12's own
field list) + `:970` (the §10.10 table row for `ObligationMapping`) +
`:976-985` (the cross-cutting rules binding on every extension contract).

## Global Constraints

- `obligation-mapping.js` MUST import nothing at all — zero specifiers,
  enforced by a self-checking test (see Task 1, mirroring
  `test/lineage/flow-grade.test.js`'s own `flow-grade.js` boundary test
  exactly).
- `ObligationMapping` records are NEVER added to `dataflow-graph.schema.json`
  and NEVER routed through `validate.js`'s `validateGraph()` — this is a
  binding ruling from the scoping doc, not a style preference. Do not add
  anything to `dataflow-graph.schema.json`'s `required` array or `$defs`.
  This also means `test/lineage/json-schema-parity.test.js` needs ZERO
  changes — confirm this explicitly in Task 1's own test run rather than
  assuming it.
- The new `ids.js` function (`obligationId`) is added to the EXISTING
  `ids.js` file (not a new file) — `ids.js` already hosts multiple ID
  namespaces (`dfg:`, `node:`/`edge:`/`flow:`/`data:`/`evidence:`/
  `transform:`, `pnode:`/`pedge:`/`ppath:`), and this is one more.
- FR-504's own applicability-inputs rule (PRD line 512) is binding:
  "explicitly configured or marked unknown — never guessed from a field
  name." Every `applicabilityInputs` key defaults to `null` (meaning "not
  configured"), never silently omitted from the object.
- AC-28's own binding rule (PRD line 1743): a record's `state` of
  `evidence_supported` means only that the mapped predicate's evidence is
  supported — never "the organization is compliant." This module cannot
  enforce that at the UI/rendering layer (out of scope here — that's 6b's
  and any future rendering task's job), but it DOES enforce the one
  structural piece within its reach: `accepted_exception` requires a real
  `reviewer` and `expiresAt` (an exception with no owner or no expiry is
  the silent-permanent-waiver failure mode this state exists to prevent).

---

### Task 1: `obligation-mapping.js` — enums + structural validator

**Files:**
- Create: `scanner/src/lineage/obligation-mapping.js`
- Test: `scanner/test/lineage/obligation-mapping.test.js`

**Interfaces:**
- Consumes: nothing (zero imports).
- Produces: `OBLIGATION_STATES` (array of 6 strings), `OBLIGATION_FACT_TYPES`
  (array of 6 strings), `APPLICABILITY_INPUT_KEYS` (array of 7 strings),
  `validateObligationMapping(record)` → `{valid: boolean, errors: Array<{path, message}>}`.
  Task 2 (the `ids.js` addition) and any future 6b work import
  `OBLIGATION_STATES`/`OBLIGATION_FACT_TYPES`/`APPLICABILITY_INPUT_KEYS`
  from this file rather than redefining them.

- [ ] **Step 1: Write the failing tests**

Create `scanner/test/lineage/obligation-mapping.test.js`:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  OBLIGATION_STATES,
  OBLIGATION_FACT_TYPES,
  APPLICABILITY_INPUT_KEYS,
  validateObligationMapping,
} from '../../src/lineage/obligation-mapping.js';

// =====================================================================
// Import boundary — mirrors flow-grade.test.js's own boundary test
// exactly (§16.1's precedent, cited by this sub-project's own scoping
// doc as the pattern to follow).
// =====================================================================

test('boundary: obligation-mapping.js imports NOTHING — its specifier list is EXACTLY []', () => {
  const modulePath = fileURLToPath(new URL('../../src/lineage/obligation-mapping.js', import.meta.url));
  const src = fs.readFileSync(modulePath, 'utf8');
  const specifiers = [...src.matchAll(/(?:from|import)\s*\(?\s*['"]([^'"]+)['"]/g)].map((m) => m[1]);
  assert.deepEqual(specifiers, [], 'obligation-mapping.js must import nothing — a pure schema/validation module');
});

// =====================================================================
// Fixture helper — a minimal, fully valid record. Every test below
// starts from a deep-enough clone of this and mutates one field.
// =====================================================================

function _validRecord(overrides = {}) {
  return {
    id: 'obligation:abcdef012345',
    graphId: 'dfg:test-repo:abc123:default',
    graphDigest: 'a'.repeat(64),
    framework: 'gdpr',
    frameworkVersion: '2016/679',
    requirementId: 'Art.30',
    requirementSource: 'https://gdpr-info.eu/art-30-gdpr/',
    applicabilityInputs: {
      entityRole: null,
      jurisdiction: null,
      dataSubject: null,
      businessProcess: null,
      merchantLevel: null,
      systemScope: null,
      aiSystemRole: null,
    },
    state: 'unknown',
    predicate: 'flow.policyVerdict === "permitted" for all cross-border transfer flows',
    factType: 'declared',
    contributingGraphIds: ['flow:1234567890ab'],
    evidence: [],
    conflicts: [],
    missingManualArtifacts: [],
    reviewer: null,
    reviewedAt: null,
    expiresAt: null,
    ...overrides,
  };
}

test('a fully valid record passes with zero errors', () => {
  const { valid, errors } = validateObligationMapping(_validRecord());
  assert.equal(valid, true);
  assert.deepEqual(errors, []);
});

test('all applicabilityInputs null is VALID — "not configured" is an honest, allowed answer (FR-504\'s own rule)', () => {
  const { valid } = validateObligationMapping(_validRecord());
  assert.equal(valid, true);
});

test('non-object input is rejected, never throws', () => {
  for (const bad of [null, undefined, 'x', 42, [], () => {}]) {
    assert.doesNotThrow(() => validateObligationMapping(bad));
    const { valid, errors } = validateObligationMapping(bad);
    assert.equal(valid, false);
    assert.ok(errors.length >= 1);
  }
});

for (const field of ['id', 'graphId', 'graphDigest', 'framework', 'frameworkVersion', 'requirementId', 'predicate']) {
  test(`missing required string field "${field}" is rejected`, () => {
    const record = _validRecord({ [field]: undefined });
    const { valid, errors } = validateObligationMapping(record);
    assert.equal(valid, false);
    assert.ok(errors.some((e) => e.path === `$.${field}`), `expected an error at $.${field}, got: ${JSON.stringify(errors)}`);
  });
}

test('an id not prefixed "obligation:" is rejected', () => {
  const { valid, errors } = validateObligationMapping(_validRecord({ id: 'node:abcdef012345' }));
  assert.equal(valid, false);
  assert.ok(errors.some((e) => e.path === '$.id'));
});

test('an unrecognized state is rejected, and every real OBLIGATION_STATES member is accepted', () => {
  const { valid: badValid } = validateObligationMapping(_validRecord({ state: 'definitely_compliant' }));
  assert.equal(badValid, false);
  for (const state of OBLIGATION_STATES) {
    const { valid, errors } = validateObligationMapping(_validRecord({
      state,
      // accepted_exception has its own extra requirement, satisfy it here
      reviewer: state === 'accepted_exception' ? 'jdoe' : null,
      expiresAt: state === 'accepted_exception' ? '2027-01-01T00:00:00.000Z' : null,
    }));
    assert.equal(valid, true, `state "${state}" should be valid, got errors: ${JSON.stringify(errors)}`);
  }
});

test('an unrecognized factType is rejected, and every real OBLIGATION_FACT_TYPES member is accepted', () => {
  const { valid: badValid } = validateObligationMapping(_validRecord({ factType: 'vibes' }));
  assert.equal(badValid, false);
  for (const factType of OBLIGATION_FACT_TYPES) {
    const { valid } = validateObligationMapping(_validRecord({ factType }));
    assert.equal(valid, true, `factType "${factType}" should be valid`);
  }
});

test('applicabilityInputs missing entirely is rejected', () => {
  const { valid, errors } = validateObligationMapping(_validRecord({ applicabilityInputs: undefined }));
  assert.equal(valid, false);
  assert.ok(errors.some((e) => e.path === '$.applicabilityInputs'));
});

test('applicabilityInputs as an array (not an object) is rejected', () => {
  const { valid } = validateObligationMapping(_validRecord({ applicabilityInputs: [] }));
  assert.equal(valid, false);
});

test('every real APPLICABILITY_INPUT_KEYS member accepts a non-null string too', () => {
  for (const key of APPLICABILITY_INPUT_KEYS) {
    const record = _validRecord();
    record.applicabilityInputs[key] = 'controller';
    const { valid, errors } = validateObligationMapping(record);
    assert.equal(valid, true, `key "${key}" set to a string should be valid, got: ${JSON.stringify(errors)}`);
  }
});

test('an applicabilityInputs key set to a non-string, non-null value is rejected', () => {
  const record = _validRecord();
  record.applicabilityInputs.jurisdiction = 42;
  const { valid, errors } = validateObligationMapping(record);
  assert.equal(valid, false);
  assert.ok(errors.some((e) => e.path === '$.applicabilityInputs.jurisdiction'));
});

test('contributingGraphIds/evidence/conflicts/missingManualArtifacts default to valid when omitted', () => {
  const record = _validRecord({
    contributingGraphIds: undefined,
    evidence: undefined,
    conflicts: undefined,
    missingManualArtifacts: undefined,
  });
  const { valid, errors } = validateObligationMapping(record);
  assert.equal(valid, true, `expected omitted arrays to default cleanly, got: ${JSON.stringify(errors)}`);
});

test('contributingGraphIds containing a non-string entry is rejected', () => {
  const { valid, errors } = validateObligationMapping(_validRecord({ contributingGraphIds: ['flow:abc', 42] }));
  assert.equal(valid, false);
  assert.ok(errors.some((e) => e.path === '$.contributingGraphIds'));
});

test('accepted_exception without a reviewer is rejected', () => {
  const { valid, errors } = validateObligationMapping(_validRecord({
    state: 'accepted_exception', reviewer: null, expiresAt: '2027-01-01T00:00:00.000Z',
  }));
  assert.equal(valid, false);
  assert.ok(errors.some((e) => e.path === '$.reviewer'));
});

test('accepted_exception without an expiresAt is rejected', () => {
  const { valid, errors } = validateObligationMapping(_validRecord({
    state: 'accepted_exception', reviewer: 'jdoe', expiresAt: null,
  }));
  assert.equal(valid, false);
  assert.ok(errors.some((e) => e.path === '$.expiresAt'));
});

test('accepted_exception with both a reviewer and an expiresAt is valid', () => {
  const { valid } = validateObligationMapping(_validRecord({
    state: 'accepted_exception', reviewer: 'jdoe', expiresAt: '2027-01-01T00:00:00.000Z',
  }));
  assert.equal(valid, true);
});

test('a non-accepted_exception state does NOT require reviewer/expiresAt', () => {
  const { valid } = validateObligationMapping(_validRecord({
    state: 'gap_detected', reviewer: null, expiresAt: null,
  }));
  assert.equal(valid, true);
});

test('multiple simultaneous errors are all reported, not just the first', () => {
  const { valid, errors } = validateObligationMapping(_validRecord({
    id: undefined, state: 'bogus', factType: 'bogus',
  }));
  assert.equal(valid, false);
  assert.ok(errors.length >= 3);
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd scanner && node --test test/lineage/obligation-mapping.test.js`
Expected: FAIL — the module does not exist yet (`Cannot find module`).

- [ ] **Step 3: Implement `obligation-mapping.js`**

```js
// obligation-mapping.js — Milestone 4 sub-project 6a: the ObligationMapping
// extension contract (FR-504 §7.12, PRD §10.10's own field list).
//
// A PURE schema/validation module for ObligationMapping records. Zero
// imports, matching flow-grade.js's own "pure function library" precedent
// — this file has even less reason to import anything, since a record's
// shape check needs no graph traversal.
//
// ObligationMapping records are explicitly NOT DataFlowGraph v1 entities
// (PRD §10.10: extension records are "associated with, but not required
// inside" the immutable base graph) — never added to
// dataflow-graph.schema.json, never routed through validate.js's
// validateGraph(), never given a node:/edge:/flow:/data: canonical ID.
// See ids.js's obligationId() for the id scheme and its own header
// comment for why (mirrors provenanceNodeId/provenanceEdgeId's own
// precedent for "a real, stable-ID'd entity that deliberately is not a
// base-graph entity").
//
// The predicate/mapping ENGINE that actually produces real records from a
// real graph is a separate, later sub-project — this file only defines
// what a valid record looks like.

// PRD line 503-508's own six states.
export const OBLIGATION_STATES = Object.freeze([
  'evidence_supported', 'gap_detected', 'unknown',
  'manual_required', 'not_applicable', 'accepted_exception',
]);

// PRD §10.10's cross-cutting fact-typing rule, applied to every extension
// contract, not just this one.
export const OBLIGATION_FACT_TYPES = Object.freeze([
  'code_inferred', 'config_correlated', 'runtime_observed',
  'declared', 'manual', 'hypothetical',
]);

// FR-504's own applicability-inputs list (line 512): "entity role,
// jurisdiction, data subject, business process, merchant level, system
// scope, AI-system role... must be explicitly configured or marked
// unknown — never guessed from a field name." Every key defaults to
// null (== "not configured") rather than being omitted, so a record can
// never silently lack an input the PRD requires be shown.
export const APPLICABILITY_INPUT_KEYS = Object.freeze([
  'entityRole', 'jurisdiction', 'dataSubject', 'businessProcess',
  'merchantLevel', 'systemScope', 'aiSystemRole',
]);

function _isNonEmptyString(v) {
  return typeof v === 'string' && v.length > 0;
}

function _isStringOrNull(v) {
  return v === null || v === undefined || typeof v === 'string';
}

function _isStringArray(v) {
  return Array.isArray(v) && v.every((x) => typeof x === 'string');
}

/**
 * Structural validation only — no cross-reference into any real graph
 * (this module has zero graph access by design). Returns {valid, errors}
 * — errors is an array of {path, message}, mirroring validate.js's own
 * shape. Never throws.
 */
export function validateObligationMapping(record) {
  const errors = [];
  const err = (path, message) => errors.push({ path, message });

  if (!record || typeof record !== 'object' || Array.isArray(record)) {
    err('$', 'obligation mapping record must be an object');
    return { valid: false, errors };
  }

  if (!_isNonEmptyString(record.id) || !record.id.startsWith('obligation:')) {
    err('$.id', 'id is required and must start with "obligation:"');
  }
  if (!_isNonEmptyString(record.graphId)) err('$.graphId', 'graphId is required');
  if (!_isNonEmptyString(record.graphDigest)) err('$.graphDigest', 'graphDigest is required');
  if (!_isNonEmptyString(record.framework)) err('$.framework', 'framework is required');
  if (!_isNonEmptyString(record.frameworkVersion)) err('$.frameworkVersion', 'frameworkVersion is required');
  if (!_isNonEmptyString(record.requirementId)) err('$.requirementId', 'requirementId is required');
  if (!_isStringOrNull(record.requirementSource)) err('$.requirementSource', 'requirementSource must be a string or null');

  if (!record.applicabilityInputs || typeof record.applicabilityInputs !== 'object' || Array.isArray(record.applicabilityInputs)) {
    err('$.applicabilityInputs', 'applicabilityInputs is required and must be an object');
  } else {
    for (const key of APPLICABILITY_INPUT_KEYS) {
      if (!_isStringOrNull(record.applicabilityInputs[key])) {
        err(`$.applicabilityInputs.${key}`, `applicabilityInputs.${key} must be a string or null`);
      }
    }
  }

  if (!OBLIGATION_STATES.includes(record.state)) {
    err('$.state', `unrecognized state "${record.state}" — must be one of ${OBLIGATION_STATES.join('|')}`);
  }
  if (!_isNonEmptyString(record.predicate)) err('$.predicate', 'predicate is required');
  if (!OBLIGATION_FACT_TYPES.includes(record.factType)) {
    err('$.factType', `unrecognized factType "${record.factType}" — must be one of ${OBLIGATION_FACT_TYPES.join('|')}`);
  }

  if (!_isStringArray(record.contributingGraphIds ?? [])) err('$.contributingGraphIds', 'contributingGraphIds must be an array of strings');
  if (!_isStringArray(record.evidence ?? [])) err('$.evidence', 'evidence must be an array of strings');
  if (!_isStringArray(record.conflicts ?? [])) err('$.conflicts', 'conflicts must be an array of strings');
  if (!_isStringArray(record.missingManualArtifacts ?? [])) err('$.missingManualArtifacts', 'missingManualArtifacts must be an array of strings');

  if (!_isStringOrNull(record.reviewer)) err('$.reviewer', 'reviewer must be a string or null');
  if (!_isStringOrNull(record.reviewedAt)) err('$.reviewedAt', 'reviewedAt must be a string or null');
  if (!_isStringOrNull(record.expiresAt)) err('$.expiresAt', 'expiresAt must be a string or null');

  // AC-28's own binding rule: PRD line 514 is explicit that
  // evidence_supported means only "this predicate's evidence is
  // supported," never organizational compliance — this module does NOT
  // reject a record for having some null applicability inputs alongside
  // evidence_supported (an input can be genuinely inapplicable to a
  // given predicate). What IS enforced structurally: accepted_exception
  // requires a real reviewer and expiresAt — an exception with no owner
  // or no expiry is exactly the silent-permanent-waiver failure mode
  // this state exists to prevent from being invisible.
  if (record.state === 'accepted_exception') {
    if (!_isNonEmptyString(record.reviewer)) err('$.reviewer', 'accepted_exception requires a reviewer');
    if (!_isNonEmptyString(record.expiresAt)) err('$.expiresAt', 'accepted_exception requires an expiresAt');
  }

  return { valid: errors.length === 0, errors };
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd scanner && node --test test/lineage/obligation-mapping.test.js`
Expected: PASS, all tests.

- [ ] **Step 5: Confirm zero drift on the two touch points this task deliberately does NOT modify**

Run: `cd scanner && node --test test/lineage/json-schema-parity.test.js`
Expected: PASS, unchanged pass count from before this task — this is the
explicit confirmation (not an assumption) that skipping
`dataflow-graph.schema.json` was the right call, per this plan's own
Global Constraints.

Run: `cd scanner && npm run test:lineage`
Expected: PASS, full scope green (this new test file needs to be added to
the `test:lineage` npm script — see Step 6).

- [ ] **Step 6: Wire into the test:lineage npm script**

Modify `scanner/package.json`'s `test:lineage` script to add
`test/lineage/obligation-mapping.test.js` — insert it near the other
`test/lineage/*.test.js` entries (alphabetical-ish grouping the script
already roughly follows; exact insertion point doesn't matter, just don't
drop any existing entry).

- [ ] **Step 7: Commit**

```bash
git add scanner/src/lineage/obligation-mapping.js scanner/test/lineage/obligation-mapping.test.js scanner/package.json
git commit -m "feat(lineage): add the ObligationMapping extension contract (FR-504 §7.12)"
```

---

### Task 2: `obligationId` — the ID-generation function

**Files:**
- Modify: `scanner/src/lineage/ids.js`
- Test: `scanner/test/lineage/ids.test.js` (add to the existing file, do not create a new one)

**Interfaces:**
- Consumes: nothing new (uses the file's own existing private `_hash`/
  `_canon` helpers).
- Produces: `obligationId({framework, frameworkVersion, requirementId, graphId}, discriminatorParts = [])` →
  a string of the form `obligation:<12-hex-char-hash>`. Any future 6b
  predicate-engine work calls this to mint real record ids.

- [ ] **Step 1: Write the failing test**

Add to `scanner/test/lineage/ids.test.js` (append near the existing
`provenanceNodeId`/`provenanceEdgeId`/`evidenceId` tests — read the file
first to match its existing import list and add `obligationId` to the
existing `import {...} from '../../src/lineage/ids.js'` statement rather
than adding a second import line):

```js
test('obligationId is deterministic, correctly prefixed, and discriminates on every input field', () => {
  const base = { framework: 'gdpr', frameworkVersion: '2016/679', requirementId: 'Art.30', graphId: 'dfg:repo:abc:default' };
  const id = obligationId(base);
  assert.match(id, /^obligation:[0-9a-f]{12}$/);
  assert.equal(obligationId(base), id, 'same inputs must produce the same id');

  assert.notEqual(obligationId({ ...base, framework: 'hipaa' }), id);
  assert.notEqual(obligationId({ ...base, frameworkVersion: '2013' }), id);
  assert.notEqual(obligationId({ ...base, requirementId: 'Art.32' }), id);
  assert.notEqual(obligationId({ ...base, graphId: 'dfg:repo:def:default' }), id, 'the same (framework,requirement) pair against a different base graph must not collide');
});

test('obligationId honors an extra discriminator (e.g. for a re-evaluated mapping against the same graph)', () => {
  const base = { framework: 'gdpr', frameworkVersion: '2016/679', requirementId: 'Art.30', graphId: 'dfg:repo:abc:default' };
  assert.notEqual(obligationId(base, ['re-eval-2']), obligationId(base, ['re-eval-1']));
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd scanner && node --test test/lineage/ids.test.js`
Expected: FAIL — `obligationId` is not exported yet.

- [ ] **Step 3: Add `obligationId` to `ids.js`**

Insert after the existing `provenanceEdgeId` function (or after whichever
function is last in the file — read the file first to find the real
insertion point; do not reorder existing functions):

```js
/**
 * An ObligationMapping record's id (FR-504 §7.12, sub-project 6a) — NOT a
 * DataFlowGraph v1 entity, so validate.js's id-prefix regexes and
 * json-schema-parity.test.js's $defs audit need zero change, mirroring
 * why provenanceNodeId/provenanceEdgeId are prefixed outside the
 * node:/edge:/flow: family. Discriminated by
 * (framework, frameworkVersion, requirementId, graphId) — the same
 * (framework, requirement) pair evaluated against two different base
 * graphs, or two different snapshots of the same repository, must never
 * collide into one id.
 */
export function obligationId(
  { framework, frameworkVersion, requirementId, graphId },
  discriminatorParts = [],
) {
  return `obligation:${_hash(_canon([framework, frameworkVersion, requirementId, graphId, ...discriminatorParts]))}`;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd scanner && node --test test/lineage/ids.test.js`
Expected: PASS, all tests including the two new ones.

- [ ] **Step 5: Commit**

```bash
git add scanner/src/lineage/ids.js scanner/test/lineage/ids.test.js
git commit -m "feat(lineage): add obligationId — the ObligationMapping id scheme"
```

---

### Task 3: Docs — `scanner/src/lineage/CLAUDE.md` module index row + M4 doc completion mark

**Files:**
- Modify: `scanner/src/lineage/CLAUDE.md`
- Modify: `docs/superpowers/plans/2026-09-01-data-flow-explorer-m4-obligation-overlay-scoping.md`

**Interfaces:**
- Consumes: nothing new — documentation only, describing what Tasks 1-2
  shipped.
- Produces: nothing consumed by later tasks (final task in this plan).

- [ ] **Step 1: Add `obligation-mapping.js` to the module index**

`scanner/src/lineage/CLAUDE.md` has a per-module index table (the same one
`ids.js`'s own row lives in — read the file first to find the exact table
and match its existing row style/column count). Add a row:

```
| `obligation-mapping.js` | The `ObligationMapping` extension contract (FR-504 §7.12, sub-project 6a). Pure schema/validation module, zero imports (boundary-tested, mirrors `flow-grade.js`'s own precedent). Records are explicitly NOT `DataFlowGraph v1` entities — never in `dataflow-graph.schema.json`, never routed through `validate.js`. See `ids.js`'s `obligationId()` for the id scheme. |
```

Also update `ids.js`'s own existing row (found via `grep -n "ids.js |" scanner/src/lineage/CLAUDE.md`, or search the table for the line listing `nodeId`/`edgeId`/etc.) to mention `obligationId` alongside the existing function list, matching this repo's own established convention (`scanner/CLAUDE.md`'s Stop hook — `hooks/session-stop-drift-check.js` — flags new files in `scanner/src/{sast,posture,dataflow}` not yet mentioned in the relevant subdir CLAUDE.md; `src/lineage/` is covered by the same discipline even if the hook's own path list doesn't name it explicitly).

- [ ] **Step 2: Mark 6a's own line in the scoping doc's decomposition section as shipped**

In `docs/superpowers/plans/2026-09-01-data-flow-explorer-m4-obligation-overlay-scoping.md`'s
"Recommended decomposition" section, update item 1 (6a) to note it's
COMPLETE, matching the style used for M4's own top-level doc's completed
rows (`**— COMPLETE (<date>)**`) — do not invent a new format, copy the
exact existing convention from `2026-09-01-data-flow-explorer-m4-scoping.md`.

- [ ] **Step 3: Run the doc-drift checker**

Run: `cd scanner && npm run test:lifecycle`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add scanner/src/lineage/CLAUDE.md docs/superpowers/plans/2026-09-01-data-flow-explorer-m4-obligation-overlay-scoping.md
git commit -m "docs(lineage): document obligation-mapping.js, mark sub-project 6a COMPLETE"
```
