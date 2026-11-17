// Plan inputs, resolved ONE way for every route (verified-remediation PRD AC-04.5): the CLI's `repair plan` and the MCP tool
// `repair_plan` both call `planFromInputs`, so the same finding, profile and source give the same contract and obligations.
//
// The finding comes from the SIGNED scan state only (an unsigned or tampered scan supplies nothing), or is declared by the operator
// with a family and a file, in which case its custody is `unresolved` and it says so. A profile file that resolves inside the
// repository is repository-supplied: its facts are `declared`, never `approved`.
import fs from 'node:fs';
import path from 'node:path';
import { stateDir } from '../posture/state-dir.js';
import { verifyLastScan } from '../posture/integrity.js';
import { normalizeFinding } from './schemas.js';
import { planRepair } from './coordinator.js';
import { importedFinding } from './import.js';

const FAMILY_BY_CWE = { 'CWE-89': 'sql-injection', 'CWE-639': 'object-authorization', 'CWE-284': 'object-authorization', 'CWE-285': 'object-authorization', 'CWE-862': 'object-authorization', 'CWE-863': 'object-authorization', 'CWE-918': 'ssrf', 'CWE-22': 'path-traversal', 'CWE-23': 'path-traversal', 'CWE-36': 'path-traversal', 'CWE-73': 'path-traversal', 'CWE-916': 'password-storage', 'CWE-759': 'password-storage', 'CWE-760': 'password-storage', 'CWE-256': 'password-storage', 'CWE-798': 'credential', 'CWE-259': 'credential', 'CWE-321': 'credential', 'CWE-362': 'workflow', 'CWE-367': 'workflow', 'CWE-841': 'workflow', 'CWE-837': 'workflow' };
export const familyForFinding = (f) => FAMILY_BY_CWE[String(f?.cwe || '').toUpperCase().replace(/^(\d)/, 'CWE-$1')] || null;
export const FAMILIES_SUPPORTED = Object.freeze(['sql-injection', 'object-authorization', 'ssrf', 'path-traversal', 'password-storage', 'dependency', 'credential', 'workflow', 'infrastructure']);

export function signedFinding(root, id) {
  const file = path.join(stateDir(root), 'last-scan.json');
  let body;
  try { body = fs.readFileSync(file, 'utf8'); } catch { return { finding: null, reason: 'no scan state (run a scan first, or declare the family and file)' }; }
  if (verifyLastScan(body, `${file}.sig`) !== true) return { finding: null, reason: 'the scan state signature does not verify' };
  const scan = JSON.parse(body);
  const f = (scan.findings || []).find((x) => x.stableId === id || x.id === id);
  return f ? { finding: f, commit: scan.git?.commit || scan.commit || null } : { finding: null, reason: `finding ${id} is not in the signed scan` };
}

/** Is `p` inside `root` after resolving links? Unknown counts as inside (the weaker trust). */
export function insideRoot(root, p) {
  try { const r = fs.realpathSync(root); const f = fs.realpathSync(p); return f === r || f.startsWith(r + path.sep); } catch { return true; }
}

/**
 * @param {{root:string, profilePath:string, findingId?:string, family?:string, file?:string}} o
 * @returns {{plan:object|null, blocked:string[], problems:string[], status:'ok'|'usage'|'blocked'}}
 */
export function planFromInputs(o) {
  let profile;
  try { profile = JSON.parse(fs.readFileSync(o.profilePath, 'utf8')); } catch (e) { return { plan: null, blocked: [], problems: [`the profile could not be read: ${String(e.message).slice(0, 160)}`], status: 'usage' }; }
  if (o.family && !FAMILIES_SUPPORTED.includes(o.family)) return { plan: null, blocked: [], problems: [`family must be one of ${FAMILIES_SUPPORTED.join(', ')}`], status: 'usage' };
  let finding; let commit = null; let family = o.family || null;
  if (o.importId) {
    // An imported finding (FR-13): from the signed import record, only when it maps to the current source.
    const s = importedFinding(o.root, String(o.importId), String(o.findingId || ''));
    if (!s.finding) return { plan: null, blocked: [s.reason], problems: [], status: 'blocked' };
    finding = s.finding; family = family || s.family; commit = s.commit;
  } else if (o.findingId) {
    const s = signedFinding(o.root, String(o.findingId));
    if (!s.finding) return { plan: null, blocked: [s.reason], problems: [], status: 'blocked' };
    finding = { ...normalizeFinding(s.finding, { commit: s.commit }), stableId: s.finding.stableId, id: s.finding.id };
    family = family || familyForFinding(s.finding);
    commit = typeof s.commit === 'string' && /^[0-9a-f]{40}$/.test(s.commit) ? s.commit : null;
  } else if (o.family && o.file) {
    finding = { ...normalizeFinding({ file: String(o.file), id: `declared:${o.family}:${o.file}` }, { custody: 'unresolved' }), declaredBy: 'operator' };
  } else return { plan: null, blocked: [], problems: ['name a finding id, or a family and a file for a finding the scanner did not report'], status: 'usage' };
  if (!family) return { plan: null, blocked: [`the finding has no repair family in this milestone; name one of ${FAMILIES_SUPPORTED.join(', ')}`], problems: [], status: 'blocked' };
  const origin = insideRoot(o.root, o.profilePath) ? 'repository-file' : 'operator-profile-outside-repository';
  const r = planRepair({ root: o.root, finding, family, profile, profileOrigin: origin, commit });
  if (!r.plan) return { plan: null, blocked: r.blocked, problems: r.problems, status: r.problems.length ? 'usage' : 'blocked' };
  return { plan: r.plan, blocked: r.blocked, problems: [], status: r.blocked.length ? 'blocked' : 'ok' };
}
