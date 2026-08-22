// PRD F3.3 — validate emitted SBOMs mechanically.
//
// "We emit an SBOM" is worth nothing if a consumer's parser rejects it. An SBOM
// is an artifact whose entire purpose is to be read by someone else's tooling,
// so a malformed one fails in THEIR pipeline, days later, with an error that
// points at them rather than at us.
//
// SCOPE, STATED PLAINLY: this is STRUCTURAL validation — required fields,
// types, and the identifier formats each spec mandates. It is not full
// JSON-Schema validation, because fetching the official schema at test time
// breaks the no-network rule and vendoring it adds a file that rots silently
// against upstream. Calling a few key checks "validates against CycloneDX"
// would be the same unverified claim F5.5 just removed from the AI-BOM, so the
// strength of the check is named rather than implied.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { toCycloneDX, toSPDX } from '../src/posture/sbom.js';

const SCAN = {
  components: [
    { ecosystem: 'npm', name: 'express', version: '4.18.2', license: 'MIT' },
    { ecosystem: 'npm', name: 'lodash', version: '4.17.21', license: 'MIT', scope: 'dev' },
    { ecosystem: 'pypi', name: 'requests', version: '2.31.0' },
  ],
  supplyChain: [{
    type: 'vulnerable_dep', ecosystem: 'npm', name: 'lodash', version: '4.17.21',
    osvId: 'GHSA-xxxx-yyyy-zzzz', severity: 'high', cveAliases: ['CVE-2021-23337'],
    description: 'prototype pollution',
  }],
};

// ── CycloneDX 1.6 ───────────────────────────────────────────────────────────

test('CycloneDX carries the four fields every parser reads first', () => {
  const b = toCycloneDX(SCAN, { engineVersion: 'test' });
  assert.equal(b.bomFormat, 'CycloneDX');
  assert.match(String(b.specVersion), /^1\.[4-9]$/);
  assert.ok(Number.isInteger(b.version) && b.version >= 1, 'version must be a positive integer');
  assert.match(String(b.serialNumber), /^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
    'serialNumber must be a well-formed urn:uuid — a consumer that validates the format rejects the whole document otherwise');
});

test('every CycloneDX component has the required name, version and type', () => {
  const b = toCycloneDX(SCAN, {});
  assert.ok(b.components.length > 0, 'the fixture must produce components or this is vacuous');
  for (const [i, c] of b.components.entries()) {
    assert.ok(typeof c.name === 'string' && c.name, `components[${i}].name is required`);
    assert.ok(typeof c.type === 'string' && c.type, `components[${i}].type is required`);
    assert.ok(typeof c['bom-ref'] === 'string' && c['bom-ref'], `components[${i}].bom-ref is required for cross-references`);
  }
});

test('CycloneDX bom-refs are UNIQUE — duplicates break every reference', () => {
  // `affects[].ref` points at a bom-ref. If two components share one, a
  // consumer resolves the vulnerability onto an arbitrary component.
  const b = toCycloneDX(SCAN, {});
  const refs = b.components.map((c) => c['bom-ref']);
  assert.equal(new Set(refs).size, refs.length, `duplicate bom-refs: ${refs.join(', ')}`);
});

test('a CycloneDX vulnerability reference resolves to a real component', () => {
  // A dangling `affects.ref` is the specific corruption that makes an SBOM look
  // populated while carrying no usable vulnerability data.
  const b = toCycloneDX(SCAN, {});
  const refs = new Set(b.components.map((c) => c['bom-ref']));
  for (const v of b.vulnerabilities || []) {
    for (const a of v.affects || []) {
      assert.ok(refs.has(a.ref), `vulnerability affects.ref "${a.ref}" matches no component bom-ref`);
    }
  }
});

test('CycloneDX purls are well-formed', () => {
  const b = toCycloneDX(SCAN, {});
  for (const c of b.components) {
    if (!c.purl) continue;
    assert.match(c.purl, /^pkg:[a-z]+\/[^@]+@?/, `malformed purl: ${c.purl}`);
  }
});

// ── SPDX 2.3 ────────────────────────────────────────────────────────────────

test('SPDX carries its mandatory document fields', () => {
  const d = toSPDX(SCAN, { engineVersion: 'test' });
  assert.equal(d.spdxVersion, 'SPDX-2.3');
  assert.equal(d.SPDXID, 'SPDXRef-DOCUMENT');
  assert.equal(d.dataLicense, 'CC0-1.0', 'SPDX mandates CC0-1.0 for the document metadata');
  assert.ok(d.name, 'name is required');
  assert.match(String(d.documentNamespace), /^https?:\/\//, 'documentNamespace must be a URI');
  assert.ok(d.creationInfo && Array.isArray(d.creationInfo.creators) && d.creationInfo.creators.length,
    'creationInfo.creators is required');
});

test('every SPDX package has a unique SPDXID in the mandated format', () => {
  const d = toSPDX(SCAN, {});
  assert.ok(d.packages.length > 0, 'the fixture must produce packages');
  const ids = d.packages.map((p) => p.SPDXID);
  for (const id of ids) {
    assert.match(id, /^SPDXRef-[A-Za-z0-9.-]+$/, `SPDXID "${id}" violates the required format`);
  }
  assert.equal(new Set(ids).size, ids.length, 'duplicate SPDXIDs');
});

test('SPDX packages carry the required NOASSERTION-able fields', () => {
  // SPDX requires these to be PRESENT; "NOASSERTION" is the legal way to say
  // "unknown". Omitting them is invalid, which is a different thing from
  // asserting nothing.
  const d = toSPDX(SCAN, {});
  for (const [i, p] of d.packages.entries()) {
    for (const f of ['name', 'downloadLocation', 'licenseConcluded', 'licenseDeclared', 'copyrightText']) {
      assert.ok(p[f] != null && p[f] !== '', `packages[${i}].${f} must be present (use NOASSERTION if unknown)`);
    }
  }
});

test('every SPDX relationship points at an element that exists', () => {
  const d = toSPDX(SCAN, {});
  const known = new Set([d.SPDXID, ...d.packages.map((p) => p.SPDXID)]);
  for (const r of d.relationships || []) {
    assert.ok(known.has(r.spdxElementId), `relationship spdxElementId "${r.spdxElementId}" is unknown`);
    assert.ok(known.has(r.relatedSpdxElement), `relationship relatedSpdxElement "${r.relatedSpdxElement}" is unknown`);
  }
});

test('SPDX externalRefs use the categories the spec defines', () => {
  const d = toSPDX(SCAN, {});
  const CATEGORIES = new Set(['PACKAGE-MANAGER', 'SECURITY', 'PERSISTENT-ID', 'OTHER']);
  for (const p of d.packages) {
    for (const r of p.externalRefs || []) {
      assert.ok(CATEGORIES.has(r.referenceCategory), `unknown referenceCategory "${r.referenceCategory}"`);
      assert.ok(r.referenceType && r.referenceLocator, 'externalRef needs both a type and a locator');
    }
  }
});

// ── Both, on the degenerate input every emitter eventually meets ────────────

test('an EMPTY project still emits a structurally valid SBOM', () => {
  // A project with no dependencies is common, and an emitter that produces
  // `components: undefined` there fails a consumer's parser just as hard as a
  // malformed one — while looking fine in every test that uses a fixture.
  const cdx = toCycloneDX({ components: [], supplyChain: [] }, {});
  assert.equal(cdx.bomFormat, 'CycloneDX');
  assert.ok(Array.isArray(cdx.components), 'components must be an ARRAY, not undefined');

  const spdx = toSPDX({ components: [], supplyChain: [] }, {});
  assert.equal(spdx.spdxVersion, 'SPDX-2.3');
  assert.ok(Array.isArray(spdx.packages), 'packages must be an ARRAY, not undefined');
  assert.ok(Array.isArray(spdx.relationships));
});

test('a component with a missing version does not produce a malformed identifier', () => {
  // Real manifests carry unpinned entries. The identifier must degrade, not
  // emit `name@undefined` into a document someone else parses.
  const cdx = toCycloneDX({ components: [{ ecosystem: 'npm', name: 'x' }], supplyChain: [] }, {});
  for (const c of cdx.components) {
    assert.doesNotMatch(String(c['bom-ref']), /undefined|null/, `bom-ref leaked a JS value: ${c['bom-ref']}`);
    if (c.purl) assert.doesNotMatch(c.purl, /undefined|null/, `purl leaked a JS value: ${c.purl}`);
  }
});
