import { PROVENANCE_STATUS } from './schema.js';

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
  if (!fp.schemaVersion) errors.push('missing schemaVersion');
  return { valid: errors.length === 0, errors };
}

export function validateFindingsProvenance(findings) {
  const results = (findings || []).map((f) => ({ id: f.id, ...validateFindingProvenance(f) }));
  return { valid: results.every((r) => r.valid), failures: results.filter((r) => !r.valid) };
}
