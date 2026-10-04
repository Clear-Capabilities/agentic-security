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
  // Same rule as _bomRef: no version means no `@version` segment at all, not an
  // empty or undefined one. purl consumers treat `pkg:npm/x@` as malformed.
  const ver = c.version ? encodeURIComponent(c.version) : '';
  // pkg:npm/<name>@<version> — pkg URL spec
  return `pkg:${eco === 'npm' ? 'npm' : eco === 'pypi' ? 'pypi' : eco === 'maven' ? 'maven' : eco === 'cargo' ? 'cargo' : eco === 'go' ? 'golang' : eco === 'rubygems' ? 'gem' : eco === 'composer' ? 'composer' : eco}/${name}${ver ? `@${ver}` : ''}`;
}

function _bomRef(c) {
  // A component with no version is ordinary — unpinned entries appear in real
  // manifests — and the identifier must DEGRADE rather than interpolate a JS
  // value. `npm:x@undefined` is not a version anyone can resolve, and it ships
  // inside a document whose whole purpose is to be parsed by someone else's
  // tooling, where it fails days later pointing at them rather than at us.
  const eco = c.ecosystem || 'pkg';
  const name = c.name || 'unknown';
  return c.version ? `${eco}:${name}@${c.version}` : `${eco}:${name}`;
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

// The bom-ref a vulnerability points at: the component's own ref when it has one (language components do), else the
// derived one. A different resolved build of the same package is a different component and keeps its own ref.
function _vulnTargetRef(components, s) {
  const hit = components.find(c => c.bomRef && c.name === s.name && c.version === s.version && (c.ecosystem || '') === (s.ecosystem || ''));
  return hit ? hit.bomRef : _bomRef({ ecosystem: s.ecosystem, name: s.name, version: s.version });
}

export function toCycloneDX(scan, meta = {}) {
  const components = [...(scan.components || []), ...((scan.languageBom && scan.languageBom.components) || [])];
  scan = scan.languageBom ? { ...scan, bomRoot: scan.languageBom.root || scan.bomRoot, bomDependencies: scan.languageBom.dependencies, bomCompositions: scan.languageBom.compositions, bomProperties: scan.languageBom.properties } : scan;
  const supplyChain = (scan.supplyChain || []).filter(s => s.type === 'vulnerable_dep');
  const serialNumber = `urn:uuid:${_documentUuid(JSON.stringify(components.map(_bomRef)))}`;

  // Language components (Hackage, Nix) carry their own identity, scope, hashes and build provenance; every other
  // component keeps exactly the shape it always had. A version is written only when one is known (a null or empty
  // version is not a valid CycloneDX string), and nothing here invents a license.
  const refOf = (c) => c.bomRef || _bomRef(c);
  const cdxComponents = components.map(c => ({
    type: c.cdxType || 'library',
    'bom-ref': refOf(c),
    name: c.name,
    ...(c.version ? { version: c.version } : (c.bomRef ? {} : { version: c.version })),
    ...(c.purl || !c.bomRef ? { purl: _purl(c) } : {}),
    ...(c.license ? { licenses: [{ license: { id: c.license } }] } : {}),
    ...(c.cdxScope ? { scope: c.cdxScope } : (c.scope ? { scope: c.scope === 'dev' ? 'optional' : 'required' } : {})),
    ...(Array.isArray(c.hashes) && c.hashes.length ? { hashes: c.hashes } : {}),
    ...(Array.isArray(c.externalReferences) && c.externalReferences.length ? { externalReferences: c.externalReferences } : {}),
    ...(Array.isArray(c.properties) && c.properties.length ? { properties: c.properties } : {}),
  }));
  const knownRefs = new Set([...cdxComponents.map(x => x['bom-ref']), ...(scan.bomRoot ? [scan.bomRoot['bom-ref']] : [])]);
  const cdxDependencies = (scan.bomDependencies || [])
    .filter(d => knownRefs.has(d.ref))
    .map(d => ({ ref: d.ref, dependsOn: (d.dependsOn || []).filter(r => knownRefs.has(r)) }));
  const cdxCompositions = (scan.bomCompositions || [])
    .map(c => ({ aggregate: c.aggregate, dependencies: (c.dependencies || []).filter(r => knownRefs.has(r)) }))
    .filter(c => c.dependencies.length);

  const vulnerabilities = supplyChain.map((s, i) => ({
    // The last-resort id was crypto.randomUUID(), which reintroduced
    // per-run drift for any advisory carrying neither an osvId nor an
    // advisory string. Index within the (already deterministically sorted)
    // supplyChain array identifies it just as well and is reproducible.
    'bom-ref': `${_vulnTargetRef(components, s)}#${s.osvId || s.advisory || `unidentified-${i}`}`,
    id: s.osvId || (s.cveAliases || [])[0] || s.advisory,
    source: { name: 'OSV.dev', url: `https://osv.dev/vulnerability/${s.osvId || ''}` },
    references: (s.cveAliases || []).map(cve => ({ id: cve, source: { name: 'NVD' } })),
    ratings: [
      ...(s.severity ? [{ severity: s.severity, method: 'other' }] : []),
      ...(s.cvssVector ? [{ vector: s.cvssVector, method: 'CVSSv3' }] : []),
    ],
    description: s.description || s.advisory || '',
    affects: [{ ref: _vulnTargetRef(components, s) }],
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
      component: scan.bomRoot ? { ...scan.bomRoot } : { type: 'application', name: 'scan-target', version: '1.0.0' },
      ...(Array.isArray(scan.bomProperties) && scan.bomProperties.length ? { properties: scan.bomProperties } : {}),
    },
    components: cdxComponents,
    ...(cdxDependencies.length ? { dependencies: cdxDependencies } : {}),
    ...(cdxCompositions.length ? { compositions: cdxCompositions } : {}),
    ...(vulnerabilities.length ? { vulnerabilities } : {}),
  };
}

export function toSPDX(scan, meta = {}) {
  const components = [...(scan.components || []), ...((scan.languageBom && scan.languageBom.components) || [])];
  scan = scan.languageBom ? { ...scan, bomRoot: scan.languageBom.root || scan.bomRoot, bomDependencies: scan.languageBom.dependencies } : scan;
  const supplyChain = (scan.supplyChain || []).filter(s => s.type === 'vulnerable_dep');
  const docNamespace = `https://agentic-security.local/spdx/${_documentUuid(JSON.stringify(components.map(_bomRef)))}`;
  // SPDX 2.3 `created` is YYYY-MM-DDThh:mm:ssZ: fractional seconds are not part of the format.
  const ts = (meta.startedAt || new Date().toISOString()).replace(/\.\d+(Z|[+-]\d{2}:\d{2})$/, (_m, z) => (z === 'Z' ? 'Z' : z));

  const spdxIdOfRef = new Map();
  // The described application itself is a package, so dependency edges that start at it have an element to attach to.
  const rootPackage = scan.bomRoot && scan.bomRoot['bom-ref'] ? [{
    SPDXID: 'SPDXRef-Package-root', name: scan.bomRoot.name, ...(scan.bomRoot.version ? { versionInfo: scan.bomRoot.version } : {}),
    downloadLocation: 'NOASSERTION', filesAnalyzed: false, licenseConcluded: 'NOASSERTION', licenseDeclared: 'NOASSERTION', copyrightText: 'NOASSERTION',
    primaryPackagePurpose: 'APPLICATION', externalRefs: [],
  }] : [];
  if (rootPackage.length) spdxIdOfRef.set(scan.bomRoot['bom-ref'], 'SPDXRef-Package-root');
  const packages = components.map((c, i) => {
    const id = `SPDXRef-Package-${i}`;
    if (c.bomRef) spdxIdOfRef.set(c.bomRef, id);
    return {
      SPDXID: id,
      name: c.name,
      ...((c.version || !c.bomRef) ? { versionInfo: c.version } : {}),
      downloadLocation: 'NOASSERTION',
      filesAnalyzed: false,
      ...(Array.isArray(c.hashes) && c.hashes.length ? { checksums: c.hashes.map(h => ({ algorithm: String(h.alg).replace('-', ''), checksumValue: h.content })) } : {}),
      licenseConcluded: c.license || 'NOASSERTION',
      licenseDeclared: c.license || 'NOASSERTION',
      copyrightText: 'NOASSERTION',
      ...(c.bomRef ? { primaryPackagePurpose: 'LIBRARY' } : {}),
      externalRefs: [...((c.purl || !c.bomRef) ? [{
        referenceCategory: 'PACKAGE-MANAGER',
        referenceType: 'purl',
        referenceLocator: _purl(c),
      }] : [])],
    };
  });

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
    packages: [...rootPackage, ...packages],
    relationships: [
      ...[...rootPackage, ...packages].map(p => ({
        spdxElementId: 'SPDXRef-DOCUMENT',
        relatedSpdxElement: p.SPDXID,
        relationshipType: 'DESCRIBES',
      })),
      // Dependency edges between language components. Runtime edges are DEPENDS_ON; a build- or test-only target is
      // expressed with the SPDX 2.3 *_DEPENDENCY_OF relationship so the scope survives the conversion.
      ...(scan.bomDependencies || []).flatMap(d => (d.dependsOn || []).map(to => {
        const a = spdxIdOfRef.get(d.ref); const b = spdxIdOfRef.get(to);
        if (!a || !b) return null;
        const kind = (d.kinds || {})[to] || 'runtime';
        if (kind === 'test') return { spdxElementId: b, relatedSpdxElement: a, relationshipType: 'TEST_DEPENDENCY_OF' };
        if (kind === 'build') return { spdxElementId: b, relatedSpdxElement: a, relationshipType: 'BUILD_DEPENDENCY_OF' };
        return { spdxElementId: a, relatedSpdxElement: b, relationshipType: 'DEPENDS_ON' };
      })).filter(Boolean),
    ],
  };
}
