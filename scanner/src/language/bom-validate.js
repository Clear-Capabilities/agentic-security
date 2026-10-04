// Structural validation of CycloneDX 1.6 and SPDX 2.3 JSON documents, plus package-URL grammar (X-010).
//
// STRENGTH, STATED PLAINLY: this is a hand-written validator of the rules the two specifications state for the parts
// of a document this project emits (required fields, types, enumerations, identifier formats, uniqueness of
// identifiers, and that every reference resolves). It is not the official JSON Schema: that file cannot be fetched
// under the no-network rule and a vendored copy would rot silently, so a document that passes here has been checked
// against the written rules but not by the specification's own schema tooling. Anything not listed here is not checked.
//
// Never throws: a document from anywhere is an expected input. Returns {valid, errors:[{path, message}]}.

const err = (errors, path, message) => errors.push({ path, message });
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const isStr = (v) => typeof v === 'string' && v.length > 0;
const DATE_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;
const HEX = /^[0-9a-fA-F]+$/;

// ── package URL ──────────────────────────────────────────────────────────────
const PURL_TYPE = /^[a-z][a-z0-9.+-]*$/;
const PCT = /^(?:[A-Za-z0-9._~!$&'()*+,;=:@%-]|%[0-9A-Fa-f]{2})*$/;
const LOWERCASE_NAMESPACE_TYPES = new Set(['github', 'gitlab', 'bitbucket']);
const NAMESPACELESS = new Set(['hackage', 'pypi', 'npm']);          // npm scopes use a namespace; checked below
const GENERIC_QUALIFIERS = new Set(['download_url', 'vcs_url', 'checksum', 'repository_url', 'arch', 'distro']);

/** Validates a purl against the package-url grammar and the registered-type rules that apply to the types we emit. */
export function validatePurl(purl) {
  const errors = [];
  if (typeof purl !== 'string' || !purl.startsWith('pkg:')) { errors.push('a purl starts with "pkg:"'); return { valid: false, errors }; }
  let rest = purl.slice(4);
  let subpath = null; let qualifiers = null;
  const hash = rest.indexOf('#'); if (hash >= 0) { subpath = rest.slice(hash + 1); rest = rest.slice(0, hash); }
  const q = rest.indexOf('?'); if (q >= 0) { qualifiers = rest.slice(q + 1); rest = rest.slice(0, q); }
  const slash = rest.indexOf('/');
  if (slash <= 0) { errors.push('a purl needs a type and a name separated by "/"'); return { valid: false, errors }; }
  const type = rest.slice(0, slash);
  if (!PURL_TYPE.test(type)) errors.push(`type "${type}" must be lowercase letters, digits, ".", "+" or "-" and start with a letter`);
  let body = rest.slice(slash + 1);
  let version = null;
  const at = body.lastIndexOf('@'); if (at >= 0) { version = body.slice(at + 1); body = body.slice(0, at); }
  if (version !== null && version === '') errors.push('an empty version after "@" is not allowed');
  const segs = body.split('/');
  const name = segs[segs.length - 1]; const namespace = segs.slice(0, -1);
  if (!name) errors.push('the name is required');
  for (const s of [...namespace, name]) { if (s !== undefined && !PCT.test(s)) errors.push(`segment "${s}" is not correctly percent-encoded`); }
  if (version !== null && !PCT.test(version)) errors.push(`version "${version}" is not correctly percent-encoded`);
  if (LOWERCASE_NAMESPACE_TYPES.has(type)) {
    if (namespace.length !== 1) errors.push(`${type} purls need exactly one namespace (the owner)`);
    for (const s of [...namespace, name]) if (s && s !== s.toLowerCase()) errors.push(`${type} namespace and name are lowercase`);
  }
  if (NAMESPACELESS.has(type) && type !== 'npm' && namespace.length) errors.push(`${type} purls have no namespace`);
  if (type === 'hackage' && name && /[^A-Za-z0-9%-]/.test(name)) errors.push('a hackage package name uses letters, digits and "-"');
  if (qualifiers !== null) {
    const seen = new Set(); let prev = '';
    for (const pair of qualifiers.split('&')) {
      const eq = pair.indexOf('=');
      if (eq <= 0) { errors.push(`qualifier "${pair}" must be key=value`); continue; }
      const k = pair.slice(0, eq); const v = pair.slice(eq + 1);
      if (!/^[a-z][a-z0-9._-]*$/.test(k)) errors.push(`qualifier key "${k}" must be lowercase`);
      if (seen.has(k)) errors.push(`duplicate qualifier "${k}"`); seen.add(k);
      if (k < prev) errors.push('qualifiers must be sorted by key'); prev = k;
      if (v === '') errors.push(`qualifier "${k}" has an empty value (omit it instead)`);
      if (!PCT.test(v)) errors.push(`qualifier "${k}" value is not correctly percent-encoded`);
      if (type === 'generic' && !GENERIC_QUALIFIERS.has(k)) errors.push(`"${k}" is not a recognised qualifier for pkg:generic`);
    }
  }
  if (subpath !== null && subpath.split('/').some((s) => s === '.' || s === '..')) errors.push('a subpath may not contain "." or ".." segments');
  return { valid: errors.length === 0, errors };
}

// ── CycloneDX 1.6 ────────────────────────────────────────────────────────────
const CDX_COMPONENT_TYPES = new Set(['application', 'framework', 'library', 'container', 'platform', 'operating-system', 'device', 'device-driver', 'firmware', 'file', 'machine-learning-model', 'data', 'cryptographic-asset']);
const CDX_SCOPES = new Set(['required', 'optional', 'excluded']);
const CDX_HASH_ALGS = new Set(['MD5', 'SHA-1', 'SHA-256', 'SHA-384', 'SHA-512', 'SHA3-256', 'SHA3-384', 'SHA3-512', 'BLAKE2b-256', 'BLAKE2b-384', 'BLAKE2b-512', 'BLAKE3']);
const CDX_HASH_LEN = { 'MD5': [32], 'SHA-1': [40], 'SHA-256': [64], 'SHA-384': [96], 'SHA-512': [128], 'SHA3-256': [64], 'SHA3-384': [96], 'SHA3-512': [128], 'BLAKE2b-256': [64], 'BLAKE2b-384': [96], 'BLAKE2b-512': [128], 'BLAKE3': [64] };
const CDX_EXT_REF_TYPES = new Set(['vcs', 'issue-tracker', 'website', 'advisories', 'bom', 'mailing-list', 'social', 'chat', 'documentation', 'support', 'source-distribution', 'distribution', 'distribution-intake', 'license', 'build-meta', 'build-system', 'release-notes', 'security-contact', 'model-card', 'log', 'configuration', 'evidence', 'formulation', 'attestation', 'threat-model', 'adversary-model', 'risk-assessment', 'vulnerability-assertion', 'exploitability-statement', 'pentest-report', 'static-analysis-report', 'dynamic-analysis-report', 'runtime-analysis-report', 'component-analysis-report', 'maturity-report', 'certification-report', 'quality-metrics', 'codified-infrastructure', 'poam', 'other']);
const CDX_AGGREGATES = new Set(['complete', 'incomplete', 'incomplete_first_party_only', 'incomplete_first_party_proprietary_only', 'incomplete_first_party_opensource_only', 'incomplete_third_party_only', 'incomplete_third_party_proprietary_only', 'incomplete_third_party_opensource_only', 'unknown', 'not_specified']);
const CDX_SEVERITIES = new Set(['critical', 'high', 'medium', 'low', 'info', 'none', 'unknown']);

function cdxProperties(list, path, errors) {
  if (list === undefined) return;
  if (!Array.isArray(list)) { err(errors, path, 'properties must be an array'); return; }
  list.forEach((p, i) => { if (!isObj(p) || !isStr(p.name)) err(errors, `${path}[${i}]`, 'a property needs a name'); else if (p.value !== undefined && typeof p.value !== 'string') err(errors, `${path}[${i}].value`, 'a property value is a string'); });
}

function cdxComponent(c, path, errors, refs) {
  if (!isObj(c)) { err(errors, path, 'a component must be an object'); return; }
  if (!CDX_COMPONENT_TYPES.has(c.type)) err(errors, `${path}.type`, `type "${c.type}" is not a CycloneDX 1.6 component type`);
  if (!isStr(c.name)) err(errors, `${path}.name`, 'name is required');
  if (c.version !== undefined && typeof c.version !== 'string') err(errors, `${path}.version`, 'version must be a string when present (omit it when unknown)');
  if (c.version === '') err(errors, `${path}.version`, 'an empty version is not a version');
  if (c['bom-ref'] !== undefined) {
    if (!isStr(c['bom-ref'])) err(errors, `${path}.bom-ref`, 'bom-ref must be a non-empty string');
    else if (refs.has(c['bom-ref'])) err(errors, `${path}.bom-ref`, `duplicate bom-ref "${c['bom-ref']}"`);
    else refs.add(c['bom-ref']);
  }
  if (c.purl !== undefined) { const v = validatePurl(c.purl); if (!v.valid) err(errors, `${path}.purl`, `${c.purl}: ${v.errors.join('; ')}`); }
  if (c.scope !== undefined && !CDX_SCOPES.has(c.scope)) err(errors, `${path}.scope`, `scope "${c.scope}" must be required, optional or excluded`);
  if (c.hashes !== undefined) {
    if (!Array.isArray(c.hashes)) err(errors, `${path}.hashes`, 'hashes must be an array');
    else c.hashes.forEach((h, i) => {
      if (!isObj(h) || !CDX_HASH_ALGS.has(h.alg)) { err(errors, `${path}.hashes[${i}].alg`, `unknown hash algorithm "${h && h.alg}"`); return; }
      if (typeof h.content !== 'string' || !HEX.test(h.content) || !CDX_HASH_LEN[h.alg].includes(h.content.length)) err(errors, `${path}.hashes[${i}].content`, `${h.alg} content must be ${CDX_HASH_LEN[h.alg].join('/')} hex characters`);
    });
  }
  if (c.licenses !== undefined && !Array.isArray(c.licenses)) err(errors, `${path}.licenses`, 'licenses must be an array');
  if (c.externalReferences !== undefined) {
    if (!Array.isArray(c.externalReferences)) err(errors, `${path}.externalReferences`, 'externalReferences must be an array');
    else c.externalReferences.forEach((r, i) => { if (!isObj(r) || !isStr(r.url)) err(errors, `${path}.externalReferences[${i}].url`, 'url is required'); if (!isObj(r) || !CDX_EXT_REF_TYPES.has(r.type)) err(errors, `${path}.externalReferences[${i}].type`, `type "${r && r.type}" is not a CycloneDX 1.6 reference type`); });
  }
  cdxProperties(c.properties, `${path}.properties`, errors);
  if (c.components !== undefined) { if (!Array.isArray(c.components)) err(errors, `${path}.components`, 'components must be an array'); else c.components.forEach((x, i) => cdxComponent(x, `${path}.components[${i}]`, errors, refs)); }
}

/** @returns {{valid:boolean, errors:{path:string,message:string}[]}} */
export function validateCycloneDX16(doc) {
  const errors = [];
  try {
    if (!isObj(doc)) return { valid: false, errors: [{ path: '$', message: 'a CycloneDX document is a JSON object' }] };
    if (doc.bomFormat !== 'CycloneDX') err(errors, '$.bomFormat', 'bomFormat must be "CycloneDX"');
    if (typeof doc.specVersion !== 'string' || !/^1\.[0-9]+$/.test(doc.specVersion)) err(errors, '$.specVersion', 'specVersion must be a string such as "1.6"');
    else if (doc.specVersion !== '1.6') err(errors, '$.specVersion', `this validator checks 1.6, got ${doc.specVersion}`);
    if (doc.serialNumber !== undefined && !/^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(String(doc.serialNumber))) err(errors, '$.serialNumber', 'serialNumber must be a urn:uuid');
    if (doc.version !== undefined && !(Number.isInteger(doc.version) && doc.version >= 1)) err(errors, '$.version', 'version must be an integer of at least 1');
    const refs = new Set();
    const md = doc.metadata;
    if (md !== undefined) {
      if (!isObj(md)) err(errors, '$.metadata', 'metadata must be an object');
      else {
        if (md.timestamp !== undefined && !DATE_TIME.test(String(md.timestamp))) err(errors, '$.metadata.timestamp', 'timestamp must be an ISO 8601 date-time');
        if (md.component !== undefined) cdxComponent(md.component, '$.metadata.component', errors, refs);
        cdxProperties(md.properties, '$.metadata.properties', errors);
      }
    }
    if (doc.components !== undefined) { if (!Array.isArray(doc.components)) err(errors, '$.components', 'components must be an array'); else doc.components.forEach((c, i) => cdxComponent(c, `$.components[${i}]`, errors, refs)); }
    if (doc.dependencies !== undefined) {
      if (!Array.isArray(doc.dependencies)) err(errors, '$.dependencies', 'dependencies must be an array');
      else {
        const seen = new Set();
        doc.dependencies.forEach((d, i) => {
          if (!isObj(d) || !isStr(d.ref)) { err(errors, `$.dependencies[${i}].ref`, 'ref is required'); return; }
          if (!refs.has(d.ref)) err(errors, `$.dependencies[${i}].ref`, `"${d.ref}" is not the bom-ref of any component`);
          if (seen.has(d.ref)) err(errors, `$.dependencies[${i}].ref`, `a second entry for "${d.ref}"`); seen.add(d.ref);
          if (d.dependsOn !== undefined) { if (!Array.isArray(d.dependsOn)) err(errors, `$.dependencies[${i}].dependsOn`, 'dependsOn must be an array'); else d.dependsOn.forEach((r, j) => { if (!refs.has(r)) err(errors, `$.dependencies[${i}].dependsOn[${j}]`, `"${r}" is not the bom-ref of any component`); }); }
        });
      }
    }
    if (doc.compositions !== undefined) {
      if (!Array.isArray(doc.compositions)) err(errors, '$.compositions', 'compositions must be an array');
      else doc.compositions.forEach((c, i) => {
        if (!isObj(c) || !CDX_AGGREGATES.has(c.aggregate)) err(errors, `$.compositions[${i}].aggregate`, `aggregate "${c && c.aggregate}" is not a CycloneDX 1.6 value`);
        for (const k of ['assemblies', 'dependencies']) if (isObj(c) && c[k] !== undefined) { if (!Array.isArray(c[k])) err(errors, `$.compositions[${i}].${k}`, `${k} must be an array`); else c[k].forEach((r, j) => { if (!refs.has(r)) err(errors, `$.compositions[${i}].${k}[${j}]`, `"${r}" is not the bom-ref of any component`); }); }
      });
    }
    if (doc.vulnerabilities !== undefined) {
      if (!Array.isArray(doc.vulnerabilities)) err(errors, '$.vulnerabilities', 'vulnerabilities must be an array');
      else {
        const vrefs = new Set();
        doc.vulnerabilities.forEach((v, i) => {
          if (!isObj(v)) { err(errors, `$.vulnerabilities[${i}]`, 'a vulnerability is an object'); return; }
          if (v['bom-ref'] !== undefined) { if (vrefs.has(v['bom-ref']) || refs.has(v['bom-ref'])) err(errors, `$.vulnerabilities[${i}].bom-ref`, `duplicate bom-ref "${v['bom-ref']}"`); vrefs.add(v['bom-ref']); }
          for (const [j, r] of (v.ratings || []).entries()) if (r.severity !== undefined && !CDX_SEVERITIES.has(r.severity)) err(errors, `$.vulnerabilities[${i}].ratings[${j}].severity`, `severity "${r.severity}" is not a CycloneDX value`);
          for (const [j, a] of (v.affects || []).entries()) if (!isObj(a) || !refs.has(a.ref)) err(errors, `$.vulnerabilities[${i}].affects[${j}].ref`, `"${a && a.ref}" is not the bom-ref of any component`);
        });
      }
    }
  } catch (e) { err(errors, '$', `validator error: ${String((e && e.message) || e)}`); }
  return { valid: errors.length === 0, errors };
}

// ── SPDX 2.3 ─────────────────────────────────────────────────────────────────
const SPDX_ID = /^SPDXRef-[A-Za-z0-9.-]+$/;
const SPDX_CHECKSUMS = { SHA1: 40, SHA224: 56, SHA256: 64, SHA384: 96, SHA512: 128, 'SHA3-256': 64, 'SHA3-384': 96, 'SHA3-512': 128, 'BLAKE2b-256': 64, 'BLAKE2b-384': 96, 'BLAKE2b-512': 128, BLAKE3: null, MD2: 32, MD4: 32, MD5: 32, MD6: null, ADLER32: 8 };
const SPDX_REF_CATEGORIES = new Set(['SECURITY', 'PACKAGE-MANAGER', 'PERSISTENT-ID', 'OTHER']);
const SPDX_RELATIONSHIPS = new Set(['AMENDS', 'ANCESTOR_OF', 'BUILD_DEPENDENCY_OF', 'BUILD_TOOL_OF', 'CONTAINED_BY', 'CONTAINS', 'COPY_OF', 'DATA_FILE_OF', 'DEPENDENCY_MANIFEST_OF', 'DEPENDENCY_OF', 'DEPENDS_ON', 'DESCENDANT_OF', 'DESCRIBED_BY', 'DESCRIBES', 'DEV_DEPENDENCY_OF', 'DEV_TOOL_OF', 'DISTRIBUTION_ARTIFACT', 'DOCUMENTATION_OF', 'DYNAMIC_LINK', 'EXAMPLE_OF', 'EXPANDED_FROM_ARCHIVE', 'FILE_ADDED', 'FILE_DELETED', 'FILE_MODIFIED', 'GENERATED_FROM', 'GENERATES', 'HAS_PREREQUISITE', 'METAFILE_OF', 'OPTIONAL_COMPONENT_OF', 'OPTIONAL_DEPENDENCY_OF', 'OTHER', 'PACKAGE_OF', 'PATCH_APPLIED', 'PATCH_FOR', 'PREREQUISITE_FOR', 'PROVIDED_DEPENDENCY_OF', 'REQUIREMENT_DESCRIPTION_FOR', 'RUNTIME_DEPENDENCY_OF', 'SPECIFICATION_FOR', 'STATIC_LINK', 'TEST_CASE_OF', 'TEST_DEPENDENCY_OF', 'TEST_OF', 'TEST_TOOL_OF', 'VARIANT_OF']);

/** @returns {{valid:boolean, errors:{path:string,message:string}[]}} */
export function validateSPDX23(doc) {
  const errors = [];
  try {
    if (!isObj(doc)) return { valid: false, errors: [{ path: '$', message: 'an SPDX document is a JSON object' }] };
    if (doc.spdxVersion !== 'SPDX-2.3') err(errors, '$.spdxVersion', 'spdxVersion must be "SPDX-2.3"');
    if (doc.dataLicense !== 'CC0-1.0') err(errors, '$.dataLicense', 'dataLicense must be "CC0-1.0"');
    if (doc.SPDXID !== 'SPDXRef-DOCUMENT') err(errors, '$.SPDXID', 'the document SPDXID is "SPDXRef-DOCUMENT"');
    if (!isStr(doc.name)) err(errors, '$.name', 'name is required');
    if (!isStr(doc.documentNamespace) || !/^[a-z][a-z0-9+.-]*:\/\/[^\s#]+$/i.test(doc.documentNamespace)) err(errors, '$.documentNamespace', 'documentNamespace must be an absolute URI without a fragment');
    const ci = doc.creationInfo;
    if (!isObj(ci)) err(errors, '$.creationInfo', 'creationInfo is required');
    else {
      if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(String(ci.created))) err(errors, '$.creationInfo.created', 'created must be YYYY-MM-DDThh:mm:ssZ');
      if (!Array.isArray(ci.creators) || !ci.creators.length || ci.creators.some((c) => !/^(?:Tool|Organization|Person): .+/.test(String(c)))) err(errors, '$.creationInfo.creators', 'creators must be "Tool|Organization|Person: name"');
    }
    const ids = new Set(['SPDXRef-DOCUMENT']);
    if (doc.packages !== undefined) {
      if (!Array.isArray(doc.packages)) err(errors, '$.packages', 'packages must be an array');
      else doc.packages.forEach((p, i) => {
        const path = `$.packages[${i}]`;
        if (!isObj(p)) { err(errors, path, 'a package is an object'); return; }
        if (!SPDX_ID.test(String(p.SPDXID))) err(errors, `${path}.SPDXID`, 'SPDXID must match SPDXRef-[A-Za-z0-9.-]+');
        else if (ids.has(p.SPDXID)) err(errors, `${path}.SPDXID`, `duplicate SPDXID "${p.SPDXID}"`); else ids.add(p.SPDXID);
        if (!isStr(p.name)) err(errors, `${path}.name`, 'name is required');
        if (!isStr(p.downloadLocation)) err(errors, `${path}.downloadLocation`, 'downloadLocation is required (NOASSERTION when unknown)');
        if (p.versionInfo !== undefined && typeof p.versionInfo !== 'string') err(errors, `${path}.versionInfo`, 'versionInfo must be a string when present (omit it when unknown)');
        if (p.filesAnalyzed !== undefined && typeof p.filesAnalyzed !== 'boolean') err(errors, `${path}.filesAnalyzed`, 'filesAnalyzed must be a boolean');
        for (const k of ['licenseConcluded', 'licenseDeclared', 'copyrightText']) if (p[k] !== undefined && !isStr(p[k])) err(errors, `${path}.${k}`, `${k} must be a string`);
        for (const [j, c] of (p.checksums || []).entries()) {
          if (!isObj(c) || !(c.algorithm in SPDX_CHECKSUMS)) { err(errors, `${path}.checksums[${j}].algorithm`, `unknown checksum algorithm "${c && c.algorithm}"`); continue; }
          const len = SPDX_CHECKSUMS[c.algorithm];
          if (typeof c.checksumValue !== 'string' || !HEX.test(c.checksumValue) || (len && c.checksumValue.length !== len)) err(errors, `${path}.checksums[${j}].checksumValue`, `${c.algorithm} value must be ${len || 'a number of'} hex characters`);
        }
        for (const [j, r] of (p.externalRefs || []).entries()) {
          if (!isObj(r) || !SPDX_REF_CATEGORIES.has(r.referenceCategory)) err(errors, `${path}.externalRefs[${j}].referenceCategory`, `category "${r && r.referenceCategory}" is not an SPDX 2.3 value`);
          if (!isObj(r) || !isStr(r.referenceType) || !isStr(r.referenceLocator)) err(errors, `${path}.externalRefs[${j}]`, 'referenceType and referenceLocator are required');
          else if (r.referenceType === 'purl') { const v = validatePurl(r.referenceLocator); if (!v.valid) err(errors, `${path}.externalRefs[${j}].referenceLocator`, `${r.referenceLocator}: ${v.errors.join('; ')}`); }
        }
      });
    }
    if (doc.relationships !== undefined) {
      if (!Array.isArray(doc.relationships)) err(errors, '$.relationships', 'relationships must be an array');
      else doc.relationships.forEach((r, i) => {
        const path = `$.relationships[${i}]`;
        if (!isObj(r)) { err(errors, path, 'a relationship is an object'); return; }
        if (!SPDX_RELATIONSHIPS.has(r.relationshipType)) err(errors, `${path}.relationshipType`, `relationshipType "${r.relationshipType}" is not an SPDX 2.3 value`);
        for (const k of ['spdxElementId', 'relatedSpdxElement']) if (!(ids.has(r[k]) || r[k] === 'NONE' || r[k] === 'NOASSERTION')) err(errors, `${path}.${k}`, `"${r[k]}" is not the SPDXID of any element`);
      });
    }
  } catch (e) { err(errors, '$', `validator error: ${String((e && e.message) || e)}`); }
  return { valid: errors.length === 0, errors };
}
