// 0.7.0 Feat-6: SBOM emitters — CycloneDX 1.6 (JSON) + SPDX 2.3 (JSON).
//
// Reuses scan.components (parseManifests output) and scan.supplyChain to attach
// vulnerability metadata to each component. No outbound calls; pure transform.
//
// CycloneDX schema reference: https://cyclonedx.org/docs/1.6/json/
// SPDX 2.3 schema reference:  https://spdx.github.io/spdx-spec/v2.3/

import * as crypto from 'node:crypto';
import { isDeterministic } from './deterministic.js';

function _purl(c) {
  if (c.purl) return c.purl;
  const eco = c.ecosystem || 'generic';
  const name = encodeURIComponent(c.name || '');
  const ver = encodeURIComponent(c.version || '');
  // pkg:npm/<name>@<version> — pkg URL spec
  return `pkg:${eco === 'npm' ? 'npm' : eco === 'pypi' ? 'pypi' : eco === 'maven' ? 'maven' : eco === 'cargo' ? 'cargo' : eco === 'go' ? 'golang' : eco === 'rubygems' ? 'gem' : eco === 'composer' ? 'composer' : eco}/${name}@${ver}`;
}

function _bomRef(c) {
  return `${c.ecosystem || 'pkg'}:${c.name}@${c.version}`;
}

// CycloneDX `serialNumber` and SPDX `documentNamespace` are both required to
// identify a document, and both were minted with crypto.randomUUID() — so two
// scans of identical input produced different bytes, and `--deterministic` did
// not actually make an SBOM reproducible. An attestation over an SBOM is only
// meaningful if the SBOM can be regenerated and compared.
//
// Under --deterministic the identifier is derived from the document's own
// content instead of randomness. That preserves what the identifier is FOR:
// different content still yields a different id, while identical content
// yields an identical one — the standard reproducible-build treatment. Outside
// deterministic mode the random UUID is unchanged, so ordinary scans keep
// per-run-unique document ids.
function _stableUuidFrom(seed) {
  const h = crypto.createHash('sha256').update(String(seed)).digest('hex');
  // Shape the digest as a v4-looking UUID: the version/variant nibbles are set
  // so consumers that validate the format still accept it.
  return [
    h.slice(0, 8),
    h.slice(8, 12),
    `4${h.slice(13, 16)}`,
    `${((parseInt(h[16], 16) & 0x3) | 0x8).toString(16)}${h.slice(17, 20)}`,
    h.slice(20, 32),
  ].join('-');
}

function _documentUuid(seed) {
  return isDeterministic() ? _stableUuidFrom(seed) : crypto.randomUUID();
}

export function toCycloneDX(scan, meta = {}) {
  const components = scan.components || [];
  const supplyChain = (scan.supplyChain || []).filter(s => s.type === 'vulnerable_dep');
  const serialNumber = `urn:uuid:${_documentUuid(JSON.stringify(components.map(_bomRef)))}`;

  const cdxComponents = components.map(c => ({
    type: 'library',
    'bom-ref': _bomRef(c),
    name: c.name,
    version: c.version,
    purl: _purl(c),
    ...(c.license ? { licenses: [{ license: { id: c.license } }] } : {}),
    ...(c.scope ? { scope: c.scope === 'dev' ? 'optional' : 'required' } : {}),
  }));

  const vulnerabilities = supplyChain.map((s, i) => ({
    // The last-resort id was crypto.randomUUID(), which reintroduced
    // per-run drift for any advisory carrying neither an osvId nor an
    // advisory string. Index within the (already deterministically sorted)
    // supplyChain array identifies it just as well and is reproducible.
    'bom-ref': `${_bomRef({ ecosystem: s.ecosystem, name: s.name, version: s.version })}#${s.osvId || s.advisory || `unidentified-${i}`}`,
    id: s.osvId || (s.cveAliases || [])[0] || s.advisory,
    source: { name: 'OSV.dev', url: `https://osv.dev/vulnerability/${s.osvId || ''}` },
    references: (s.cveAliases || []).map(cve => ({ id: cve, source: { name: 'NVD' } })),
    ratings: [
      ...(s.severity ? [{ severity: s.severity, method: 'other' }] : []),
      ...(s.cvssVector ? [{ vector: s.cvssVector, method: 'CVSSv3' }] : []),
    ],
    description: s.description || s.advisory || '',
    affects: [{ ref: _bomRef({ ecosystem: s.ecosystem, name: s.name, version: s.version }) }],
    properties: [
      ...(s.epssScore != null ? [{ name: 'epss:score', value: String(s.epssScore) }] : []),
      ...(s.epssPercentile != null ? [{ name: 'epss:percentile', value: String(s.epssPercentile) }] : []),
      ...(s.functionReachable ? [{ name: 'agentic-security:functionReachable', value: s.functionReachable }] : []),
    ],
  }));

  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    serialNumber,
    version: 1,
    metadata: {
      timestamp: meta.startedAt || new Date().toISOString(),
      tools: [{ vendor: 'Clear Capabilities', name: 'agentic-security', version: meta.engineVersion || 'dev' }],
      component: { type: 'application', name: 'scan-target', version: '1.0.0' },
    },
    components: cdxComponents,
    ...(vulnerabilities.length ? { vulnerabilities } : {}),
  };
}

export function toSPDX(scan, meta = {}) {
  const components = scan.components || [];
  const supplyChain = (scan.supplyChain || []).filter(s => s.type === 'vulnerable_dep');
  const docNamespace = `https://agentic-security.local/spdx/${_documentUuid(JSON.stringify(components.map(_bomRef)))}`;
  const ts = meta.startedAt || new Date().toISOString();

  const packages = components.map((c, i) => ({
    SPDXID: `SPDXRef-Package-${i}`,
    name: c.name,
    versionInfo: c.version,
    downloadLocation: 'NOASSERTION',
    filesAnalyzed: false,
    licenseConcluded: c.license || 'NOASSERTION',
    licenseDeclared: c.license || 'NOASSERTION',
    copyrightText: 'NOASSERTION',
    externalRefs: [{
      referenceCategory: 'PACKAGE-MANAGER',
      referenceType: 'purl',
      referenceLocator: _purl(c),
    }],
  }));

  // SPDX expresses CVEs as external refs on the package, not separate elements
  const cveByName = {};
  for (const s of supplyChain) {
    const k = `${s.ecosystem}:${s.name}@${s.version}`;
    (cveByName[k] = cveByName[k] || []).push(...(s.cveAliases || (s.osvId ? [s.osvId] : [])));
  }
  for (let i = 0; i < components.length; i++) {
    const c = components[i];
    const k = `${c.ecosystem}:${c.name}@${c.version}`;
    if (cveByName[k] && cveByName[k].length) {
      packages[i].externalRefs.push(...cveByName[k].map(cve => ({
        referenceCategory: 'SECURITY',
        referenceType: 'cve',
        referenceLocator: cve,
      })));
    }
  }

  return {
    spdxVersion: 'SPDX-2.3',
    dataLicense: 'CC0-1.0',
    SPDXID: 'SPDXRef-DOCUMENT',
    name: 'agentic-security-sbom',
    documentNamespace: docNamespace,
    creationInfo: {
      created: ts,
      creators: [`Tool: agentic-security-${meta.engineVersion || 'dev'}`],
    },
    packages,
    relationships: packages.map(p => ({
      spdxElementId: 'SPDXRef-DOCUMENT',
      relatedSpdxElement: p.SPDXID,
      relationshipType: 'DESCRIBES',
    })),
  };
}
