import { PROVENANCE_STATUS, FINDING_PROVENANCE_SCHEMA_VERSION } from './schema.js';

const VALID_STATUSES = new Set(Object.values(PROVENANCE_STATUS));

export function validateFindingProvenance(finding) {
  const errors = [];
  const fp = finding && finding.findingProvenance;
  if (!fp || typeof fp !== 'object') {
    errors.push('missing findingProvenance object');
    return { valid: false, errors };
  }
  if (!VALID_STATUSES.has(fp.status)) errors.push(`invalid status: ${fp.status}`);
  if (!Array.isArray(fp.evidenceAttribution)) errors.push('evidenceAttribution must be an array');
  if (!Array.isArray(fp.limitations)) errors.push('limitations must be an array');
  // A version field nothing ever compares against is decoration, not a
  // contract. These objects are persisted (last-scan.json, the provenance
  // cache) and read back by later releases, so an object stamped with a
  // version this build does not know is exactly what the field exists to
  // catch — and it is the only reason to carry it at all.
  if (!fp.schemaVersion) errors.push('missing schemaVersion');
  else if (fp.schemaVersion !== FINDING_PROVENANCE_SCHEMA_VERSION) {
    errors.push(`unsupported schemaVersion: ${fp.schemaVersion} (this build understands ${FINDING_PROVENANCE_SCHEMA_VERSION})`);
  }
  return { valid: errors.length === 0, errors };
}

export function validateFindingsProvenance(findings) {
  const results = (findings || []).map((f) => ({ id: f.id, ...validateFindingProvenance(f) }));
  return { valid: results.every((r) => r.valid), failures: results.filter((r) => !r.valid) };
}
