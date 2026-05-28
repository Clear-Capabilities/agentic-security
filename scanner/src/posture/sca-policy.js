// SCA policy — declarative per-project rules for vulnerable_dep findings.
// Phase 4 / Item 7 of the SCA improvement plan.
//
// Reads .agentic-security/sca-policy.yml. Three classes of rule:
//
//   accept-risk        — per-CVE or per-package suppression with reason +
//                        optional expiry. Treated as "wont-fix" — the
//                        finding still appears but is marked suppressed.
//   sla                — per-severity / per-tier deadlines for remediation.
//                        Findings older than the SLA are escalated.
//   major-version-freeze — refuse automated major-version bumps per
//                          ecosystem. /fix --sca consults this before
//                          calling apply_sca_upgrade on a breaking change.
//
// Policy file shape:
//
//   accept-risk:
//     - cve: CVE-2024-12345
//       reason: "patched upstream; bundled vendor copy doesn't include affected code"
//       expires: 2026-12-31
//     - package: log4j-core
//       version: 2.17.1
//       reason: "we run on Java 21; JNDI lookup is disabled at runtime"
//       expires: 2026-06-30
//
//   sla:
//     critical-kev: 7d
//     critical: 30d
//     high: 90d
//     medium: 180d
//
//   major-version-freeze:
//     npm: [react, vue]            # never auto-upgrade these across majors
//     pypi: [django]
//
// Default policy (no file) is permissive: nothing is suppressed and no
// SLA is enforced. Users opt in by creating the file.

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as yaml from 'js-yaml';

const DEFAULT_POLICY = {
  acceptRisk: [],
  sla: {},
  majorVersionFreeze: {},
};

export function loadScaPolicy(scanRoot) {
  if (!scanRoot) return null;
  for (const name of ['sca-policy.yml', 'sca-policy.yaml', 'sca-policy.json']) {
    const p = path.join(scanRoot, '.agentic-security', name);
    if (!fs.existsSync(p)) continue;
    try {
      const raw = fs.readFileSync(p, 'utf8');
      const doc = name.endsWith('.json') ? JSON.parse(raw) : yaml.load(raw);
      return _normalize(doc);
    } catch (e) {
      return { _error: `Failed to parse ${p}: ${e.message}` };
    }
  }
  return null;
}

function _normalize(doc) {
  return {
    acceptRisk: Array.isArray(doc?.['accept-risk']) ? doc['accept-risk'].map(_normalizeAccept) : [],
    sla: _normalizeSla(doc?.sla || {}),
    majorVersionFreeze: _normalizeMajor(doc?.['major-version-freeze'] || {}),
  };
}

function _normalizeAccept(entry) {
  return {
    cve: entry.cve ? String(entry.cve).toUpperCase() : null,
    package: entry.package ? String(entry.package).toLowerCase() : null,
    version: entry.version ? String(entry.version) : null,
    ecosystem: entry.ecosystem ? String(entry.ecosystem).toLowerCase() : null,
    reason: entry.reason || '',
    expires: entry.expires || null,
  };
}

function _normalizeSla(sla) {
  const out = {};
  for (const [k, v] of Object.entries(sla)) {
    out[k.toLowerCase()] = _parseSlaDuration(v);
  }
  return out;
}

function _parseSlaDuration(v) {
  if (typeof v === 'number') return v * 86400_000; // bare number = days
  const m = String(v).match(/^(\d+)([dwmy])$/i);
  if (!m) return null;
  const n = parseInt(m[1], 10);
  const unit = m[2].toLowerCase();
  const factor = { d: 86400_000, w: 7 * 86400_000, m: 30 * 86400_000, y: 365 * 86400_000 }[unit];
  return factor ? n * factor : null;
}

function _normalizeMajor(maj) {
  const out = {};
  for (const [eco, list] of Object.entries(maj)) {
    if (Array.isArray(list)) out[eco.toLowerCase()] = list.map(s => String(s).toLowerCase());
  }
  return out;
}

// Check whether an accept-risk entry is currently active (not expired).
function _accepted(entry, today = new Date()) {
  if (!entry.expires) return true;
  const exp = new Date(entry.expires);
  if (Number.isNaN(+exp)) return true; // unparseable: treat as still active
  return exp >= today;
}

// Match a finding against the accept-risk list. Returns the matching entry
// or null.
export function matchAcceptRisk(finding, policy, today = new Date()) {
  if (!policy || !Array.isArray(policy.acceptRisk)) return null;
  const cves = Array.isArray(finding.cveAliases) ? finding.cveAliases.map(c => String(c).toUpperCase()) : [];
  if (finding.osvId) cves.push(String(finding.osvId).toUpperCase());
  const pkgName = String(finding.name || '').toLowerCase();
  for (const entry of policy.acceptRisk) {
    if (!_accepted(entry, today)) continue;
    if (entry.cve && cves.includes(entry.cve)) return entry;
    if (entry.package && pkgName === entry.package) {
      if (entry.version && finding.version && entry.version !== finding.version) continue;
      if (entry.ecosystem && finding.ecosystem && entry.ecosystem !== finding.ecosystem) continue;
      return entry;
    }
  }
  return null;
}

// Apply policy to a list of SCA findings. Marks accept-risk hits as
// suppressed; computes SLA deadlines; flags major-version-freeze packages
// so /fix --sca knows not to auto-upgrade them.
//
// Returns { suppressed: number, slaTagged: number, frozen: number }.
export function applyScaPolicy(findings, policy, scanTime = new Date()) {
  const stats = { suppressed: 0, slaTagged: 0, frozen: 0 };
  if (!policy || !Array.isArray(findings)) return stats;
  for (const f of findings) {
    if (!f || f.type !== 'vulnerable_dep') continue;
    // Accept-risk suppression
    const acceptance = matchAcceptRisk(f, policy, scanTime);
    if (acceptance) {
      f.suppressed = true;
      f.suppressionReason = acceptance.reason || 'accepted-risk';
      f.suppressionSource = 'sca-policy.yml';
      f.suppressionExpires = acceptance.expires || null;
      stats.suppressed++;
      continue;
    }
    // SLA tag: pick the narrowest applicable bucket.
    const slaKey = (f.kev || f.kevListed) && f.severity === 'critical' ? 'critical-kev'
                 : f.severity;
    if (policy.sla && policy.sla[slaKey]) {
      const startMs = f.firstSeenAt ? Date.parse(f.firstSeenAt) : +scanTime;
      const deadline = startMs + policy.sla[slaKey];
      f.slaDeadline = new Date(deadline).toISOString();
      f.slaOverdue = +scanTime > deadline;
      stats.slaTagged++;
    }
    // Major-version freeze
    if (policy.majorVersionFreeze
        && Array.isArray(policy.majorVersionFreeze[f.ecosystem])
        && policy.majorVersionFreeze[f.ecosystem].includes(String(f.name).toLowerCase())) {
      f.majorVersionFrozen = true;
      stats.frozen++;
    }
  }
  return stats;
}

// Materialize a wont-fix triage decision into a new accept-risk entry.
// Called by the triage → suppression bridge (Phase 4 / Item 7 of the SCA
// plan): when a user marks a vulnerable_dep finding wont-fix, the policy
// file is updated so future scans automatically suppress it.
//
// If the policy file doesn't exist, one is created with safe defaults.
export function appendAcceptRiskFromTriage(scanRoot, finding, reason) {
  if (!scanRoot || !finding) return { ok: false, reason: 'missing arguments' };
  const dir = path.join(scanRoot, '.agentic-security');
  const fp = path.join(dir, 'sca-policy.yml');
  let policy = loadScaPolicy(scanRoot);
  if (policy && policy._error) return { ok: false, reason: policy._error };
  if (!policy) policy = { acceptRisk: [], sla: {}, majorVersionFreeze: {} };
  // Defensive: even if a policy file existed, it may have been parsed into a
  // value that shares references with DEFAULT_POLICY. Force a fresh array.
  if (!Array.isArray(policy.acceptRisk)) policy.acceptRisk = [];

  // De-dupe — don't add a second entry for the same CVE.
  const cves = Array.isArray(finding.cveAliases) ? finding.cveAliases.map(c => String(c).toUpperCase()) : [];
  if (finding.osvId) cves.push(String(finding.osvId).toUpperCase());
  for (const entry of policy.acceptRisk) {
    if (entry.cve && cves.includes(entry.cve)) return { ok: false, reason: 'CVE already in accept-risk list', cve: entry.cve };
  }

  const newEntry = {
    cve: cves[0] || null,
    package: finding.name ? String(finding.name).toLowerCase() : null,
    version: finding.version || null,
    ecosystem: finding.ecosystem || null,
    reason: reason || `Marked wont-fix in triage on ${new Date().toISOString().slice(0, 10)}`,
    expires: null,
  };
  policy.acceptRisk.push(newEntry);

  try { fs.mkdirSync(dir, { recursive: true }); } catch {}
  const serialized = yaml.dump({
    'accept-risk': policy.acceptRisk.map(e => {
      const o = {};
      if (e.cve) o.cve = e.cve;
      if (e.package) o.package = e.package;
      if (e.version) o.version = e.version;
      if (e.ecosystem) o.ecosystem = e.ecosystem;
      o.reason = e.reason;
      if (e.expires) o.expires = e.expires;
      return o;
    }),
    sla: policy.sla && Object.keys(policy.sla).length ? Object.fromEntries(Object.entries(policy.sla).map(([k, v]) => [k, _formatSlaDuration(v)])) : undefined,
    'major-version-freeze': policy.majorVersionFreeze && Object.keys(policy.majorVersionFreeze).length ? policy.majorVersionFreeze : undefined,
  });
  fs.writeFileSync(fp, serialized);
  return { ok: true, entry: newEntry, path: fp };
}

function _formatSlaDuration(ms) {
  if (typeof ms !== 'number') return ms;
  const days = Math.round(ms / 86400_000);
  return `${days}d`;
}
