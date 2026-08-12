// 0.7.0 Feat-6: SBOM (CycloneDX 1.6 + SPDX 2.3) smoke + shape tests.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '../src/runScan.js';
import { toCycloneDX, toSPDX } from '../src/posture/sbom.js';
import { parseManifests } from '../src/engine.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIX = (n) => path.join(__dirname, 'fixtures', n);

// Stage 4 correctness audit: _makePurl (engine.js) percent-encodes name and
// namespace/group but concatenates `version` raw: `${version?'@'+version:''}`.
// The package-url spec requires every purl component to be percent-encoded.
// A semver build-metadata suffix (`1.0.0+build.123`, entirely legal semver
// and common in real packages) produces a purl with a literal, un-encoded
// `+` — which any spec-compliant purl consumer decodes as a space, silently
// corrupting the version string for external tools (vuln databases,
// dependency-resolution systems) that ingest this SBOM/PURL data.
test('purl: version component is percent-encoded (build-metadata "+" does not leak through raw)', () => {
  const components = parseManifests({
    'package.json': JSON.stringify({ dependencies: { 'some-lib': '1.0.0+build.123' } }),
  });
  const c = components.find(x => x.name === 'some-lib');
  assert.ok(c, 'expected the component to be parsed');
  assert.equal(c.purl, 'pkg:npm/some-lib@1.0.0%2Bbuild.123',
    `expected the '+' to be percent-encoded; got ${c.purl}`);
});

test('SBOM — CycloneDX 1.6 has correct top-level fields', async () => {
  const { scan, meta } = await runScan(FIX('vulnerable-js'));
  const cdx = toCycloneDX(scan, meta);
  assert.equal(cdx.bomFormat, 'CycloneDX');
  assert.equal(cdx.specVersion, '1.6');
  assert.match(cdx.serialNumber, /^urn:uuid:/);
  assert.equal(cdx.metadata.tools[0].name, 'agentic-security');
  assert.ok(Array.isArray(cdx.components), 'components is array');
  // Every component has required fields
  for (const c of cdx.components) {
    assert.ok(c.type === 'library', 'type is library');
    assert.ok(c.name && c.version && c.purl, `missing fields on ${JSON.stringify(c)}`);
    assert.ok(c['bom-ref'], 'bom-ref required');
    assert.match(c.purl, /^pkg:/);
  }
  // If supplyChain has CVEs, CycloneDX should expose them as `vulnerabilities[]`
  if ((scan.supplyChain || []).some(s => s.type === 'vulnerable_dep')) {
    assert.ok(Array.isArray(cdx.vulnerabilities) && cdx.vulnerabilities.length > 0,
      'expected vulnerabilities[] when CVEs are present');
    const v = cdx.vulnerabilities[0];
    assert.ok(v.id, 'vuln id required');
    assert.ok(Array.isArray(v.affects), 'affects[] required');
  }
});

test('SBOM — SPDX 2.3 has correct top-level fields', async () => {
  const { scan, meta } = await runScan(FIX('vulnerable-js'));
  const spdx = toSPDX(scan, meta);
  assert.equal(spdx.spdxVersion, 'SPDX-2.3');
  assert.equal(spdx.dataLicense, 'CC0-1.0');
  assert.equal(spdx.SPDXID, 'SPDXRef-DOCUMENT');
  assert.match(spdx.documentNamespace, /^https?:\/\//);
  assert.ok(Array.isArray(spdx.packages), 'packages is array');
  for (const p of spdx.packages) {
    assert.match(p.SPDXID, /^SPDXRef-Package-\d+$/);
    assert.ok(p.name && p.versionInfo, 'name + versionInfo required');
    assert.ok(p.externalRefs.some(r => r.referenceType === 'purl'), 'purl externalRef required');
  }
  // Relationships must reference DOCUMENT and each package
  assert.equal(spdx.relationships.length, spdx.packages.length);
});
