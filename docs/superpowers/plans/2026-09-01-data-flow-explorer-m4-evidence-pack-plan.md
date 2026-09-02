# M4 Sub-project 6c: Evidence-Pack Export Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a signed, versioned "evidence pack" artifact for a
Regulatory Obligation Overlay framework evaluation (FR-504), and wire it
into the existing `attest`/`verify-attestation` CLI commands.

**Architecture:** A fourth sibling in the `evidence-bundle.js` family
(`posture/evidence-bundle.js` → `posture/provenance-evidence-bundle.js` →
`posture/compliance-evidence-signing.js` → this module), reusing that
family's Ed25519 key infrastructure and generic `canonicalJson`
serializer directly. Pure builder function over already-computed inputs
(a `DataFlowGraph v1` document, a loaded framework, and
`evaluateFramework`'s own per-control evaluation array) — no new
detection, no new graph traversal beyond a small id-lookup join for the
evidence index.

**Tech Stack:** Node.js ESM, `node:crypto` (Ed25519, already used
throughout this family), `node:test` + `node:assert/strict`.

**Spec:** `AGENTIC_SECURITY_DATA_FLOW_EXPLORER_PRD.md` FR-504 (line
497-517). Scoping doc:
`docs/superpowers/plans/2026-09-01-data-flow-explorer-m4-evidence-pack-scoping.md`
(read this first — it maps every PRD-required field to its real source
and explains the evidence-index design decision).

## Global Constraints

- Never throws on malformed/absent input (this package's established
  convention, stated in `obligation-predicates.js`'s own header and
  followed by every sibling signed-bundle module).
- `scanner/src/lineage/` is never imported FROM in a way that creates a
  new `lineage/` → `posture/` edge — this module lives in `posture/` and
  imports `lineage/export-json.js`'s `computeGraphDigest`, extending the
  ALREADY-established `posture/` → `lineage/` direction (6b), never the
  reverse.
- Reuse, do not reimplement: `ensureKeyPair`, `keyPaths`, `canonicalJson`
  from `posture/evidence-bundle.js`; `EVIDENCE_GRADE_DISCLAIMER` from
  `posture/evidence-grade-wording.js`; `computeGraphDigest` from
  `lineage/export-json.js`.
- Every new exported function needs real-graph tests
  (`buildGraphWithCoverage` output, via `bench/data-lineage/runner.mjs`'s
  `buildFixtureGraph` or the same parse→build pipeline `obligation-predicates-walkthrough.test.js`
  already uses), never ONLY hand-built fixtures — the exact gap that let
  two blocking bugs through 6b's task-level reviews.
- New test files added to `scanner/package.json`'s `test:lineage` OR
  `test:posture` script (whichever directory the file lives under) or
  `npm run test:lifecycle` will fail the build.

---

### Task 1: `obligation-evidence-pack.js` — the pack builder + sign/verify trio

**Files:**
- Create: `scanner/src/posture/obligation-evidence-pack.js`
- Test: `scanner/test/obligation-evidence-pack.test.js`

**Interfaces:**
- Consumes: `ensureKeyPair()`/`keyPaths()`/`canonicalJson()` from
  `./evidence-bundle.js` (exact signatures as shipped — read that file if
  unsure, do not guess); `EVIDENCE_GRADE_DISCLAIMER` from
  `./evidence-grade-wording.js`; `computeGraphDigest(graph)` from
  `../lineage/export-json.js`; the real `DataFlowGraph v1` shape (`nodes`,
  `edges`, `flows`, `dataElements`, each with an `id`; `flow.dataElementIds`,
  `flow.source`, `flow.sink`, `flow.edgeIds`; `edge.protection.{transit,atRest,handling}.verdict`)
  — same join pattern `obligation-predicates.js` already establishes, read
  that file's `evaluateGraphFlowPredicate` for the exact id→entity Map
  construction to mirror (do not import it — this is a design precedent to
  copy, the two modules solve different problems).
- Produces: `OBLIGATION_EVIDENCE_PACK_SCHEMA` (string constant),
  `buildObligationEvidencePack(args) -> pack`,
  `signObligationEvidencePack(pack, privateKeyPem) -> signedPack`,
  `verifyObligationEvidencePack(pack, publicKeyPem) -> {ok, reason}`. Task
  2's CLI wiring imports all four of these plus the re-exported
  `ensureKeyPair`/`keyPaths`.

- [ ] **Step 1: Write the module**

```js
// obligation-evidence-pack.js — Milestone 4 sub-project 6c: signed,
// versioned evidence packs for a Regulatory Obligation Overlay framework
// evaluation (FR-504, PRD §10.10). Fourth sibling in the
// evidence-bundle.js family — see that module's own header for the
// shared-key rationale, and provenance-evidence-bundle.js for the most
// directly mirrored precedent (same reused ensureKeyPair/keyPaths/
// canonicalJson, own schema string, own build/sign/verify trio, own
// top-level-key allowlist).
//
// WHAT THIS IS NOT
// -----------------
// Not a reuse of evidence-bundle.js's own bundle shape (that's a single
// FINDING's evidence — proofTier/taintPath/etc; this artifact has no
// finding at all). Not compliance-evidence-signing.js's ComplianceEvidence
// manifest either — that signs the pre-existing family:/module:/rule:-
// driven present/partial/absent/manual walkthrough status; this signs the
// newer, additive graph: mapping type's own real ObligationMapping
// records (evaluateGraphFlowPredicate/buildObligationMappingFromGraphPredicate,
// sub-project 6b) — a distinct FR-504 artifact with its own field list
// (scope, framework versions, facts, evidence index, unknown/manual
// items, accepted exceptions, scan health, limitations, graph digest,
// reproducibility metadata).
//
// THE EVIDENCE-INDEX DESIGN DECISION (see the scoping doc for the full
// writeup)
// -----------------------------------------------------------------
// A real ObligationMapping record's own `evidence[]` is structurally
// always empty today (graph-builder.js:692 hardcodes `edgeIds: []` on
// every minted edge, disclosed in obligation-predicates.js's own header).
// Rather than ship an evidence pack whose "evidence index" is honestly,
// permanently empty, this module builds a REAL evidence index from each
// fact's own `contributingGraphIds` (real flow ids
// evaluateGraphFlowPredicate already returns) — resolving each flow id
// back into a small, real summary (source/sink kind, dataElement
// dataClasses, the edge's own transit/atRest/handling verdicts) by
// joining against the graph's own entity arrays. `record.evidence` is
// still carried through verbatim on each fact (honest, even though
// empty) — the evidence index is an ADDITIONAL section built from data
// that genuinely IS populated, not a replacement that hides the gap.

import { ensureKeyPair, keyPaths, canonicalJson } from './evidence-bundle.js';
import { EVIDENCE_GRADE_DISCLAIMER } from './evidence-grade-wording.js';
import { computeGraphDigest } from '../lineage/export-json.js';
import * as crypto from 'node:crypto';

export const OBLIGATION_EVIDENCE_PACK_SCHEMA = 'agentic-security/obligation-evidence-pack@1';

function _asArray(v) {
  return Array.isArray(v) ? v : [];
}

/**
 * Resolve one ObligationMapping fact's contributingGraphIds (real flow
 * ids) into a small, real, human-and-machine-readable summary per flow —
 * the evidence index's own per-fact contribution. Never throws: a flow id
 * that no longer resolves against this graph (a stale pack re-evaluated
 * against a newer graph, or a malformed fact) is simply skipped, not
 * fabricated.
 */
function _resolveEvidenceForFact(fact, joins) {
  const { flowsById, nodesById, edgesById, dataElementsById } = joins;
  const flowIds = _asArray(fact?.contributingGraphIds);
  const resolved = [];
  for (const flowId of flowIds) {
    const flow = flowsById.get(flowId);
    if (!flow) continue;
    const sourceNode = nodesById.get(flow.source);
    const sinkNode = nodesById.get(flow.sink);
    const edge = edgesById.get(_asArray(flow.edgeIds)[0]);
    const dataClasses = _asArray(flow.dataElementIds)
      .map((id) => dataElementsById.get(id))
      .filter(Boolean)
      .flatMap((d) => _asArray(d.dataClasses));
    resolved.push({
      flowId,
      source: sourceNode ? { kind: sourceNode.kind ?? null, subtype: sourceNode.subtype ?? null } : null,
      sink: sinkNode ? { kind: sinkNode.kind ?? null, subtype: sinkNode.subtype ?? null } : null,
      dataClasses: [...new Set(dataClasses)],
      transitVerdict: edge?.protection?.transit?.verdict ?? null,
      atRestVerdict: edge?.protection?.atRest?.verdict ?? null,
      handlingVerdict: edge?.protection?.handling?.verdict ?? null,
    });
  }
  return resolved;
}

function _buildJoins(graph) {
  return {
    flowsById: new Map(_asArray(graph?.flows).filter(Boolean).map((f) => [f.id, f])),
    nodesById: new Map(_asArray(graph?.nodes).filter(Boolean).map((n) => [n.id, n])),
    edgesById: new Map(_asArray(graph?.edges).filter(Boolean).map((e) => [e.id, e])),
    dataElementsById: new Map(_asArray(graph?.dataElements).filter(Boolean).map((d) => [d.id, d])),
  };
}

/**
 * Build an unsigned evidence pack from a framework evaluation. Never
 * throws: every field degrades honestly on missing input rather than
 * fabricating a value — a null/absent graph yields empty facts/
 * evidenceIndex and a null graphDigest/scope, never a guess.
 *
 * @param {object} args
 * @param {object|null} args.graph - the scan's DataFlowGraph v1 document (scan.lineageGraph), or null
 * @param {object} args.framework - the loaded framework object (auditor-walkthrough.js#loadFramework's return)
 * @param {Array}  args.evaluation - auditor-walkthrough.js#evaluateFramework's return (per-control entries, each carrying .obligationMappings)
 * @param {object|null} [args.scanHealth] - scan.scanHealth, passed through verbatim; null if not supplied, never fabricated
 * @param {string|null} [args.engineVersion]
 * @param {string|null} [args.rulesetVersion]
 * @param {string|null} [args.bundleSha]
 * @param {string} [args.generatedAt] - defaults to new Date().toISOString()
 */
export function buildObligationEvidencePack({
  graph, framework, evaluation, scanHealth, engineVersion, rulesetVersion, bundleSha, generatedAt,
} = {}) {
  const facts = _asArray(evaluation).flatMap((e) => _asArray(e?.obligationMappings));
  const joins = _buildJoins(graph);
  const evidenceIndex = facts.map((fact) => ({
    obligationId: fact?.id ?? null,
    requirementId: fact?.requirementId ?? null,
    evidence: _resolveEvidenceForFact(fact, joins),
  }));

  return {
    schema: OBLIGATION_EVIDENCE_PACK_SCHEMA,
    framework: {
      id: framework?.id ?? null,
      name: framework?.name ?? null,
      version: framework?.controlsDigest ?? null,
      publisher: framework?.publisher ?? null,
      url: framework?.url ?? null,
    },
    scope: graph?.scope ?? null,
    facts,
    evidenceIndex,
    unknownItems: facts.filter((f) => f?.state === 'unknown'),
    manualItems: facts.filter((f) => f?.state === 'manual_required'),
    acceptedExceptions: facts.filter((f) => f?.state === 'accepted_exception'),
    scanHealth: scanHealth ?? null,
    limitations: _asArray(graph?.limitations),
    graphDigest: graph ? computeGraphDigest(graph) : null,
    reproducibility: {
      graphId: graph?.graphId ?? null,
      graphDigest: graph ? computeGraphDigest(graph) : null,
      engineVersion: engineVersion ?? null,
      rulesetVersion: rulesetVersion ?? null,
      bundleSha: bundleSha ?? null,
      generatedAt: generatedAt ?? new Date().toISOString(),
    },
    disclaimer: EVIDENCE_GRADE_DISCLAIMER,
  };
}

/** Sign a pack. Returns a new object; the input is not mutated. */
export function signObligationEvidencePack(pack, privateKeyPem) {
  const sig = crypto.sign(null, Buffer.from(canonicalJson(pack), 'utf8'), privateKeyPem);
  return {
    ...pack,
    signature: { algorithm: 'ed25519', canonicalisation: OBLIGATION_EVIDENCE_PACK_SCHEMA, value: sig.toString('base64') },
  };
}

const OBLIGATION_EVIDENCE_PACK_TOP_LEVEL_KEYS = new Set([
  'schema', 'framework', 'scope', 'facts', 'evidenceIndex', 'unknownItems',
  'manualItems', 'acceptedExceptions', 'scanHealth', 'limitations',
  'graphDigest', 'reproducibility', 'disclaimer', 'signature',
]);

/**
 * Verify with a PUBLIC key only. Rejects any top-level key outside the
 * allowlist BEFORE checking the signature — same EA-03 discipline every
 * sibling in this family carries: a signature only covers the bytes it
 * was computed over, so a key stapled on after signing would otherwise
 * verify as authentic.
 */
export function verifyObligationEvidencePack(pack, publicKeyPem) {
  if (!pack || typeof pack !== 'object') return { ok: false, reason: 'pack is not an object' };
  if (pack.schema !== OBLIGATION_EVIDENCE_PACK_SCHEMA) return { ok: false, reason: `unrecognised schema: ${pack.schema}` };
  const unknownKeys = Object.keys(pack).filter((k) => !OBLIGATION_EVIDENCE_PACK_TOP_LEVEL_KEYS.has(k));
  if (unknownKeys.length) {
    return { ok: false, reason: `unrecognised top-level key(s) not covered by the signature: ${unknownKeys.join(', ')}` };
  }
  const sig = pack.signature;
  if (!sig?.value) return { ok: false, reason: 'pack is unsigned' };
  if (sig.algorithm !== 'ed25519') return { ok: false, reason: `unsupported algorithm: ${sig.algorithm}` };
  if (!publicKeyPem) return { ok: false, reason: 'no public key supplied' };
  const { signature, ...unsigned } = pack;
  let ok = false;
  try {
    ok = crypto.verify(null, Buffer.from(canonicalJson(unsigned), 'utf8'), publicKeyPem, Buffer.from(sig.value, 'base64'));
  } catch (e) {
    return { ok: false, reason: `verification error: ${e.message}` };
  }
  return ok
    ? { ok: true, reason: null }
    : { ok: false, reason: 'signature does not match the pack contents — it was modified after signing' };
}

export { ensureKeyPair, keyPaths };
```

- [ ] **Step 2: Write the test file**

Build real inputs the way `test/lineage/obligation-predicates-walkthrough.test.js`
already does — `loadFramework(scanRoot, 'hipaa-security-rule')` +
`evaluateFramework(scanRoot, fw, scan)` with a real, hand-built-but-valid
`DataFlowGraph v1` `scan.lineageGraph` (copy that test file's own
`_minimalGraph` helper — same shape, same HIPAA §164.312(e) predicate).
Also exercise the REAL pipeline at least once via
`bench/data-lineage/runner.mjs`'s `buildFixtureGraph` against
`bench/data-lineage/fixtures/js-ai-model-output-to-ai-model-provider-phi/source.js`
(the AC-07 flagship fixture 6b's own final review used) — this closes the
"never only a hand-built fixture" Global Constraint for THIS module's own
evidence-index join logic, which is new code with its own id-lookup logic
that could have the same class of bug 6b's blocking findings did.

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateKeyPairSync } from 'node:crypto';
import { loadFramework, evaluateFramework } from '../src/posture/auditor-walkthrough.js';
import {
  OBLIGATION_EVIDENCE_PACK_SCHEMA,
  buildObligationEvidencePack,
  signObligationEvidencePack,
  verifyObligationEvidencePack,
} from '../src/posture/obligation-evidence-pack.js';
import { buildFixtureGraph } from '../../bench/data-lineage/runner.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES_ROOT = path.join(__dirname, '../../bench/data-lineage/fixtures');

function _minimalGraph({ transitVerdict }) {
  return {
    graphId: 'dfg:test-repo:abc123:default',
    scope: { source: 'test' },
    limitations: ['Test fixture — not a real scan.'],
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
  return fs.mkdtempSync(path.join(os.tmpdir(), 'obligation-evidence-pack-'));
}

function _keys() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return {
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }),
  };
}

test('buildObligationEvidencePack: a real evaluateFramework run over a protected HIPAA flow produces every PRD-named field, non-vacuously', () => {
  const scanRoot = _mkScanRoot();
  try {
    const fw = loadFramework(scanRoot, 'hipaa-security-rule');
    const graph = _minimalGraph({ transitVerdict: 'protected' });
    const scan = { findings: [], secrets: [], logicVulns: [], supplyChain: [], components: [], lineageGraph: graph, scanHealth: { overall: 'healthy' } };
    const evaluation = evaluateFramework(scanRoot, fw, scan);
    const pack = buildObligationEvidencePack({
      graph, framework: fw, evaluation, scanHealth: scan.scanHealth,
      engineVersion: '9.9.9', rulesetVersion: 'r1', bundleSha: 'sha1', generatedAt: '2026-01-01T00:00:00.000Z',
    });

    assert.equal(pack.schema, OBLIGATION_EVIDENCE_PACK_SCHEMA);
    assert.equal(pack.framework.id, 'hipaa-security-rule');
    assert.equal(pack.framework.version, fw.controlsDigest);
    assert.deepEqual(pack.scope, { source: 'test' });
    assert.ok(pack.facts.length >= 1, 'must carry at least the HIPAA §164.312(e) graph: fact');
    const fact = pack.facts.find((f) => f.requirementId === '§164.312(e)');
    assert.ok(fact);
    assert.equal(fact.state, 'evidence_supported');

    // The evidence-index join: this fact's own contributingGraphIds must
    // resolve to a real, non-empty evidence entry pulled from the graph —
    // not the vestigial, always-empty record.evidence.
    const idx = pack.evidenceIndex.find((e) => e.obligationId === fact.id);
    assert.ok(idx);
    assert.equal(idx.evidence.length, 1);
    assert.equal(idx.evidence[0].flowId, 'flow:f1');
    assert.deepEqual(idx.evidence[0].dataClasses, ['PHI']);
    assert.equal(idx.evidence[0].transitVerdict, 'protected');
    assert.equal(idx.evidence[0].sink.kind, 'external');

    assert.deepEqual(pack.unknownItems, []);
    assert.deepEqual(pack.manualItems, []);
    assert.deepEqual(pack.acceptedExceptions, []);
    assert.deepEqual(pack.scanHealth, { overall: 'healthy' });
    assert.deepEqual(pack.limitations, ['Test fixture — not a real scan.']);
    assert.match(pack.graphDigest, /^[0-9a-f]{64}$/);
    assert.equal(pack.reproducibility.graphId, graph.graphId);
    assert.equal(pack.reproducibility.graphDigest, pack.graphDigest);
    assert.equal(pack.reproducibility.engineVersion, '9.9.9');
    assert.ok(pack.disclaimer.length > 0);
  } finally {
    fs.rmSync(scanRoot, { recursive: true, force: true });
  }
});

test('buildObligationEvidencePack: an unassessed (not_assessed) flow is honestly unknown, and unknownItems/evidenceIndex agree', () => {
  const scanRoot = _mkScanRoot();
  try {
    const fw = loadFramework(scanRoot, 'hipaa-security-rule');
    const graph = _minimalGraph({ transitVerdict: 'not_assessed' });
    const scan = { findings: [], secrets: [], logicVulns: [], supplyChain: [], components: [], lineageGraph: graph };
    const evaluation = evaluateFramework(scanRoot, fw, scan);
    const pack = buildObligationEvidencePack({ graph, framework: fw, evaluation });

    const fact = pack.facts.find((f) => f.requirementId === '§164.312(e)');
    assert.equal(fact.state, 'unknown');
    assert.equal(pack.unknownItems.length, 1);
    assert.equal(pack.unknownItems[0].id, fact.id);
    const idx = pack.evidenceIndex.find((e) => e.obligationId === fact.id);
    assert.equal(idx.evidence[0].transitVerdict, 'not_assessed');
  } finally {
    fs.rmSync(scanRoot, { recursive: true, force: true });
  }
});

test('buildObligationEvidencePack: a null graph degrades every graph-derived field honestly, never throws', () => {
  const scanRoot = _mkScanRoot();
  try {
    const fw = loadFramework(scanRoot, 'hipaa-security-rule');
    const scan = { findings: [], secrets: [], logicVulns: [], supplyChain: [], components: [] };
    const evaluation = evaluateFramework(scanRoot, fw, scan);
    let pack;
    assert.doesNotThrow(() => { pack = buildObligationEvidencePack({ graph: null, framework: fw, evaluation }); });
    assert.equal(pack.scope, null);
    assert.equal(pack.graphDigest, null);
    assert.deepEqual(pack.limitations, []);
    const fact = pack.facts.find((f) => f.requirementId === '§164.312(e)');
    assert.equal(fact.state, 'unknown');
    const idx = pack.evidenceIndex.find((e) => e.obligationId === fact.id);
    assert.deepEqual(idx.evidence, []);
  } finally {
    fs.rmSync(scanRoot, { recursive: true, force: true });
  }
});

test('buildObligationEvidencePack: malformed inputs (undefined args, non-array evaluation) never throw', () => {
  assert.doesNotThrow(() => buildObligationEvidencePack());
  assert.doesNotThrow(() => buildObligationEvidencePack({ graph: 'not-a-graph', framework: null, evaluation: 'not-an-array' }));
  const pack = buildObligationEvidencePack({ graph: {}, framework: null, evaluation: [{ obligationMappings: null }, null] });
  assert.deepEqual(pack.facts, []);
});

test('sign/verify round trip: a genuine pack verifies with the matching public key', () => {
  const scanRoot = _mkScanRoot();
  try {
    const fw = loadFramework(scanRoot, 'hipaa-security-rule');
    const graph = _minimalGraph({ transitVerdict: 'protected' });
    const scan = { lineageGraph: graph };
    const evaluation = evaluateFramework(scanRoot, fw, scan);
    const pack = buildObligationEvidencePack({ graph, framework: fw, evaluation });
    const { privateKeyPem, publicKeyPem } = _keys();
    const signed = signObligationEvidencePack(pack, privateKeyPem);
    assert.equal(signed.signature.algorithm, 'ed25519');
    const r = verifyObligationEvidencePack(signed, publicKeyPem);
    assert.equal(r.ok, true, r.reason);
  } finally {
    fs.rmSync(scanRoot, { recursive: true, force: true });
  }
});

test('verify: tampering with any field invalidates the signature (EA-03 proof, not just a comment)', () => {
  const scanRoot = _mkScanRoot();
  try {
    const fw = loadFramework(scanRoot, 'hipaa-security-rule');
    const graph = _minimalGraph({ transitVerdict: 'protected' });
    const evaluation = evaluateFramework(scanRoot, fw, { lineageGraph: graph });
    const pack = buildObligationEvidencePack({ graph, framework: fw, evaluation });
    const { privateKeyPem, publicKeyPem } = _keys();
    const signed = signObligationEvidencePack(pack, privateKeyPem);

    const tamperedFact = JSON.parse(JSON.stringify(signed));
    tamperedFact.facts[0].state = 'evidence_supported'; // was unknown/gap_detected/etc — flip it
    assert.equal(verifyObligationEvidencePack(tamperedFact, publicKeyPem).ok, false);

    const stapledKey = { ...signed, injected: 'malicious' };
    const r = verifyObligationEvidencePack(stapledKey, publicKeyPem);
    assert.equal(r.ok, false);
    assert.match(r.reason, /unrecognised top-level key/);
  } finally {
    fs.rmSync(scanRoot, { recursive: true, force: true });
  }
});

test('verify: an unsigned pack, a wrong-algorithm signature, and a missing public key all fail cleanly', () => {
  const pack = buildObligationEvidencePack({ graph: null, framework: null, evaluation: [] });
  assert.equal(verifyObligationEvidencePack(pack, 'anything').ok, false);
  assert.equal(verifyObligationEvidencePack({ ...pack, signature: { algorithm: 'rsa', value: 'x' } }, 'anything').ok, false);
  const { privateKeyPem, publicKeyPem } = _keys();
  const signed = signObligationEvidencePack(pack, privateKeyPem);
  assert.equal(verifyObligationEvidencePack(signed, null).ok, false);
  void publicKeyPem;
});

test('REAL PIPELINE: the AC-07 flagship fixture (PHI reaching anthropic.messages.create()) produces a valid, non-vacuous evidence index end to end', () => {
  const scanRoot = _mkScanRoot();
  try {
    const fixtureId = 'js-ai-model-output-to-ai-model-provider-phi';
    const source = fs.readFileSync(path.join(FIXTURES_ROOT, fixtureId, 'source.js'), 'utf8');
    const graph = buildFixtureGraph(fixtureId, source);
    const fw = loadFramework(scanRoot, 'hipaa-security-rule');
    const evaluation = evaluateFramework(scanRoot, fw, { lineageGraph: graph });
    let pack;
    assert.doesNotThrow(() => { pack = buildObligationEvidencePack({ graph, framework: fw, evaluation }); });
    assert.match(pack.graphDigest, /^[0-9a-f]{64}$/);
    const fact = pack.facts.find((f) => f.requirementId === '§164.312(e)');
    assert.ok(fact, 'the real pipeline must still produce the 6b HIPAA fact on this fixture');
    // 6b's own final review pinned this fixture's real answer as 'unknown'
    // (an unresolved-but-real-category sink, never assessed for transit) —
    // if that regresses, this pack's own facts[] would silently ship a
    // wrong compliance state.
    assert.equal(fact.state, 'unknown');
    const idx = pack.evidenceIndex.find((e) => e.obligationId === fact.id);
    assert.ok(idx.evidence.length >= 1, 'the evidence index must resolve at least one real contributing flow from the real pipeline, not just a hand-built fixture');
  } finally {
    fs.rmSync(scanRoot, { recursive: true, force: true });
  }
});
```

- [ ] **Step 3: Run the new test file**

Run: `cd scanner && node --test test/obligation-evidence-pack.test.js`
Expected: all tests PASS, 0 fail.

- [ ] **Step 4: Wire into `test:posture` and commit**

Add `test/obligation-evidence-pack.test.js` to the `test:posture` script
in `scanner/package.json` (it lives under `posture/`, tests a `posture/`
module — matches every sibling bundle's own test placement:
`evidence-bundle.test.js`/`provenance-evidence-bundle.test.js`/
`compliance-evidence-signing.test.js` are all in `test:posture` today —
confirm this with `grep '"test:posture"' package.json` before assuming).
Run `npm run test:posture` and confirm it passes with the new file
included (capture the real exit code).

```bash
git add scanner/src/posture/obligation-evidence-pack.js scanner/test/obligation-evidence-pack.test.js scanner/package.json
git commit -m "feat(compliance): add signed evidence-pack export for the Regulatory Obligation Overlay (FR-504, M4 sub-project 6c)"
```

---

### Task 2: CLI wiring (`attest --obligations`, `verify-attestation`) + docs

**Files:**
- Modify: `scanner/bin/agentic-security.js` (`cmdAttest`, `cmdVerifyAttestation`)
- Modify: `scanner/CLAUDE.md` ("Signed, portable evidence (PRD D2)" section)
- Modify: `scanner/src/lineage/CLAUDE.md` (sub-project #6 table row)
- Modify: `docs/superpowers/plans/2026-09-01-data-flow-explorer-m4-scoping.md` (row #6, mark 6c COMPLETE — final step, after merge is verified, not part of this task's own commit)
- Test: `scanner/test/cli/attest-obligations.test.js` (new) — confirmed
  real precedent to mirror exactly: `scanner/test/cli/attest-provenance.test.js`
  (uses `spawnSync`, `test/helpers/build-git-fixture.js#createGitFixture`,
  the `status <= 3` scan-exit convention, and asserts against files under
  `.agentic-security/attestations/`). One real difference: that test scans
  with `--provenance`; this one must scan with
  `AGENTIC_SECURITY_LINEAGE_DEEP=1` in the child's `env` (not a CLI flag —
  confirm this against `scanner/src/lineage/CLAUDE.md`'s Sub-project E,
  increment 5 row before writing the test) so `scan.lineageGraph` actually
  exists for the pack to draw on. Wire the new file into `test:posture` in
  `scanner/package.json`, alongside the already-listed
  `test/cli/attest-provenance.test.js`.

**Interfaces:**
- Consumes: Task 1's `buildObligationEvidencePack`,
  `signObligationEvidencePack`, `verifyObligationEvidencePack`,
  `OBLIGATION_EVIDENCE_PACK_SCHEMA`, `ensureKeyPair`, `keyPaths` — all
  from `../src/posture/obligation-evidence-pack.js`.
- Consumes: `loadFramework`, `evaluateFramework` from
  `../src/posture/auditor-walkthrough.js` (already imported patterns
  elsewhere in `bin/agentic-security.js` — check how `/compliance
  --walkthrough` invokes these today and match the exact call shape,
  including how `scanRoot`/`scan` are loaded from `last-scan.json` and
  `scan.lineageGraph`).
- Produces: nothing new for later tasks — this is the terminal task.

- [ ] **Step 1: Read the real current `cmdAttest`/`cmdVerifyAttestation`**

Read `scanner/bin/agentic-security.js` around `cmdAttest` (search for
`async function cmdAttest`) and `cmdVerifyAttestation` (search for `async
function cmdVerifyAttestation`) in full before editing — line numbers in
this plan are informative, not authoritative; the file has moved since
this plan was written for other reasons.

- [ ] **Step 2: Add the `--obligations` branch to `cmdAttest`**

Insert a new `if (args.flags.obligations) { ... }` branch, structured
exactly like the existing `if (args.flags.provenance) { ... }` branch
immediately above it in the same function: load `last-scan.json`, resolve
the framework id from `args.flags.obligations === true ? undefined :
args.flags.obligations` — but unlike `--provenance` (which is a broad
"attest everything" toggle with an optional narrowing id), `--obligations`
genuinely REQUIRES a framework id (an evidence pack only exists per
framework — no "attest every framework" loop exists anywhere in this
codebase). If `args.flags.obligations === true` (no id given), print a
usage error naming the bundled framework ids (`listFrameworks(scanRoot)`)
and return 2.

Real shape (write the actual code, not a paraphrase — confirm every
import path and field name against the real files before finalizing):

```js
if (args.flags.obligations) {
  const frameworkId = args.flags.obligations === true ? null : args.flags.obligations;
  if (!frameworkId) {
    const { listFrameworks } = await import('../src/posture/auditor-walkthrough.js');
    console.error('Usage: agentic-security attest --obligations <framework-id>');
    console.error(`Bundled frameworks: ${listFrameworks(scanRoot).map((f) => f.id).join(', ')}`);
    return 2;
  }
  const { loadFramework, evaluateFramework } = await import('../src/posture/auditor-walkthrough.js');
  const {
    buildObligationEvidencePack, signObligationEvidencePack, ensureKeyPair,
  } = await import('../src/posture/obligation-evidence-pack.js');

  let scan;
  try { scan = JSON.parse(fs.readFileSync(statePath(scanRoot, 'last-scan.json'), 'utf8')); }
  catch { console.error('No .agentic-security/last-scan.json — run a scan first.'); return 2; }

  const fw = loadFramework(scanRoot, frameworkId);
  if (!fw) { console.error(`Unknown framework: ${frameworkId}`); return 2; }

  const evaluation = evaluateFramework(scanRoot, fw, scan);
  const pack = buildObligationEvidencePack({
    graph: scan.lineageGraph ?? null,
    framework: fw,
    evaluation,
    scanHealth: scan.scanHealth ?? null,
    engineVersion: scan.engineVersion || null,
    rulesetVersion: scan.rulesetVersion || null,
    bundleSha: scan.bundleSha || null,
  });

  const kp = ensureKeyPair();
  if (kp.created) console.error(`Generated a new signing key at ${kp.privateKey} (public: ${kp.publicKey}).`);

  const outDir = statePath(scanRoot, 'attestations');
  fs.mkdirSync(outDir, { recursive: true });
  const signed = signObligationEvidencePack(pack, kp.privateKeyPem);
  const name = `evidence-pack-${frameworkId}.json`.replace(/[^\w.-]/g, '_');
  fs.writeFileSync(path.join(outDir, name), JSON.stringify(signed, null, 2) + '\n');

  console.log(`Signed evidence pack for ${frameworkId} → ${path.relative(scanRoot, path.join(outDir, name))}`);
  console.log(`Public key (share this with whoever verifies): ${kp.publicKey}`);
  console.log('');
  console.log(`  facts: ${pack.facts.length}  unknown: ${pack.unknownItems.length}  manual: ${pack.manualItems.length}  accepted exceptions: ${pack.acceptedExceptions.length}`);
  console.log('');
  console.log('A pack proves its contents are unmodified since signing. It does NOT');
  console.log('certify compliance — read the pack\'s own `disclaimer` field.');
  if (!scan.lineageGraph) {
    console.log('');
    console.log('NOTE: this scan has no lineageGraph (AGENTIC_SECURITY_LINEAGE_DEEP=1 was');
    console.log('not set) — every graph: fact in this pack reads "unknown", by design.');
  }
  return 0;
}
```

Confirm `statePath`/`listFrameworks`/`loadFramework`/`evaluateFramework`
are imported/available exactly as written above by grepping the real
file — do not assume the import style (some are top-level imports in this
file, some are lazy `await import(...)` inside the command function,
matching the `--provenance` branch's own lazy-import style is the
correct precedent here).

- [ ] **Step 3: Add the fifth auto-detect branch to `cmdVerifyAttestation`**

Insert a new schema-marker branch BEFORE the final `verifyEvidenceBundle`
fallback, structured exactly like the existing `PROVENANCE_BUNDLE_SCHEMA`
branch immediately above it:

```js
const { verifyObligationEvidencePack, OBLIGATION_EVIDENCE_PACK_SCHEMA } = await import('../src/posture/obligation-evidence-pack.js');
if (bundle.schema === OBLIGATION_EVIDENCE_PACK_SCHEMA) {
  const or = verifyObligationEvidencePack(bundle, publicKeyPem);
  if (!or.ok) { console.error(`✗ INVALID — ${or.reason}`); return 1; }
  console.log('✓ VALID — the evidence pack is exactly what the signer produced.');
  console.log('');
  console.log(`  framework: ${bundle.framework?.id}  version: ${bundle.framework?.version}`);
  console.log(`  facts: ${bundle.facts?.length ?? 0}  unknown: ${bundle.unknownItems?.length ?? 0}  manual: ${bundle.manualItems?.length ?? 0}  accepted exceptions: ${bundle.acceptedExceptions?.length ?? 0}`);
  if (bundle.graphDigest) console.log(`  graph digest: ${bundle.graphDigest}`);
  console.log('');
  console.log(`  ${bundle.disclaimer}`);
  return 0;
}
```

Place this dispatch check in the SAME relative position the plan's own
Step 1 read confirms the `PROVENANCE_BUNDLE_SCHEMA` check occupies (before
the generic `verifyEvidenceBundle` fallback, after the `ComplianceEvidence`
`@type` check) — the ordering matters because `verifyEvidenceBundle`
assumes a finding-bundle shape and would misinterpret an evidence pack the
same way its own comment already warns about for a provenance bundle.

- [ ] **Step 4: Run the full CLI integration test + smoke**

Write `test/cli/attest-obligations.test.js` mirroring
`test/cli/attest-provenance.test.js`'s exact idiom (see that file's real
content, already read during scoping — `spawnSync`, `createGitFixture`,
the `status <= 3` scan-exit convention): a temp git fixture with a file
whose code reaches an external sink with a classifiable data element (a
minimal PHI-to-fetch shape is enough — it does not need to match
HIPAA's own real predicate exactly, just produce SOME `lineageGraph`),
scan with `AGENTIC_SECURITY_LINEAGE_DEEP=1` set in `spawnSync`'s `env`,
run `attest --obligations hipaa-security-rule`, assert exit 0 and a
written `.agentic-security/attestations/evidence-pack-hipaa-security-rule.json`
carrying `schema: 'agentic-security/obligation-evidence-pack@1'` and a
real signature; run `verify-attestation` on that file and assert exit 0
and the printed VALID line; then hand-edit one field in the written JSON
file on disk (e.g. flip a fact's `state`) and confirm `verify-attestation`
on the tampered file now exits 1. Also assert `attest --obligations` with
no framework id argument exits 2 with a usage message.

Run: `cd scanner && node --test test/cli/attest-obligations.test.js`
Expected: PASS.

Run: `npm run build` (bin/ changed) then `npm run test:smoke` (sanity —
confirm the bundle still runs end to end on the vulnerable-js fixture).

- [ ] **Step 5: Update docs**

`scanner/CLAUDE.md`'s "Signed, portable evidence (PRD D2)" section: add
one line naming `attest --obligations <framework-id>` alongside the
existing `attest [--id <finding>]` bullet, and note it writes to the same
`.agentic-security/attestations/` directory.

`scanner/src/lineage/CLAUDE.md`'s M4 sub-project #6 table: change "6b
(predicate engine) — COMPLETE. 6c (evidence-pack export) not yet started."
to mark 6c COMPLETE, and add one table row for
`obligation-evidence-pack.js` mirroring the existing `obligation-mapping.js`/
`obligation-predicates.js` rows' own style (one sentence: what it is,
where it's wired, the one real design decision — the evidence-index
join — named in one clause).

- [ ] **Step 6: Commit**

```bash
git add scanner/bin/agentic-security.js scanner/test/cli/attest-obligations.test.js scanner/package.json scanner/CLAUDE.md scanner/src/lineage/CLAUDE.md
git commit -m "feat(compliance): wire evidence-pack export into attest/verify-attestation CLI (M4 sub-project 6c)"
```

## Self-review notes (already applied above, recorded per the writing-plans skill)

- **Spec coverage**: all nine PRD-named fields (scope, framework versions,
  facts, evidence index, unknown/manual items, accepted exceptions, scan
  health, limitations, graph digest, reproducibility metadata) plus the
  "signed/versioned" requirement are each mapped to a concrete field in
  Task 1's builder and verified by Task 1's own test.
- **Placeholder scan**: no "add appropriate error handling" language above
  — every degrade-honestly case (`null` graph, malformed evaluation,
  missing framework) has real code and a real test.
- **Type consistency**: `buildObligationEvidencePack`'s return field names
  (`facts`, `evidenceIndex`, `unknownItems`, `manualItems`,
  `acceptedExceptions`, `graphDigest`, `reproducibility`, `disclaimer`)
  are used identically in Task 1's own tests and Task 2's CLI wiring —
  checked side by side before finalizing this plan.
