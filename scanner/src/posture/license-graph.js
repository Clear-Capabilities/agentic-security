// License-graph supply-chain analyzer — Item #5 of the world-class+3 plan.
//
// Extends posture/license-policy.js (per-component allow/deny/review) with:
//
//   1. TRANSITIVE COPYLEFT CONTAMINATION
//      An MIT-licensed direct dep that pulls in a GPL/AGPL transitive
//      dep. Today's per-component check passes because the direct dep is
//      MIT — but the GPL is the actual exposure.
//
//   2. RELICENSING-RISK LICENSES
//      BSL, SSPL, Elastic 2.0, Common Clause, Server Side Public License,
//      Functional Source License, Sustainable Use License, etc.
//      Permissive at first install — later versions or downstream usage
//      may breach the additional terms.
//
//   3. DISTRIBUTION-MODE-AWARE POLICY
//      "SaaS" vs "Binary" vs "Library" have radically different obligations.
//      AGPL is fine for proprietary internal usage but kills SaaS;
//      GPL is fine for a SaaS web app but kills a published library;
//      LGPL static-link concerns only apply to native binary distribution.
//
//   4. DUAL-LICENSE TRAP DETECTION
//      Packages declared as `(MIT OR Apache-2.0)` are usually fine, but
//      `(GPL-2.0 OR Commercial)` are a contractual trap — the open option
//      auto-converts your code to GPL unless you've signed a commercial
//      agreement.
//
//   5. LICENSE-CHANGE DETECTION
//      Packages known to have relicensed (Elastic, Redis, Sentry,
//      HashiCorp Terraform, MongoDB) — flag the boundary version.
//
// Default mode: SaaS. Override via
// .agentic-security/license-policy.yml `distributionMode:`.
//
// Opt-out: AGENTIC_SECURITY_NO_LICENSE_GRAPH=1

import * as fs from 'node:fs';
import * as path from 'node:path';

// ── License taxonomy ───────────────────────────────────────────────────────

const LICENSE_FAMILIES = {
  permissive:      new Set(['MIT', 'APACHE-2.0', 'BSD-2-CLAUSE', 'BSD-3-CLAUSE', 'BSD-4-CLAUSE', 'ISC', '0BSD', 'CC0-1.0', 'UNLICENSE', 'WTFPL', 'ZLIB', 'PSF-2.0', 'PYTHON-2.0', 'POSTGRESQL', 'OPENSSL', 'X11']),
  weak_copyleft:   new Set(['LGPL-2.0', 'LGPL-2.1', 'LGPL-3.0', 'LGPL-2.1-OR-LATER', 'LGPL-3.0-OR-LATER', 'MPL-1.1', 'MPL-2.0', 'EPL-1.0', 'EPL-2.0', 'CDDL-1.0', 'CDDL-1.1']),
  strong_copyleft: new Set(['GPL-2.0', 'GPL-2.0-ONLY', 'GPL-2.0-OR-LATER', 'GPL-3.0', 'GPL-3.0-ONLY', 'GPL-3.0-OR-LATER']),
  network_copyleft: new Set(['AGPL-1.0', 'AGPL-3.0', 'AGPL-3.0-ONLY', 'AGPL-3.0-OR-LATER']),
  source_available: new Set(['BSL-1.1', 'SSPL-1.0', 'ELASTIC-2.0', 'ELASTIC-1.0', 'COMMONS-CLAUSE', 'FSL-1.0', 'FSL-1.1', 'CONFLUENT-COMMUNITY', 'BUSL-1.1', 'PARITY-7.0.0', 'POLYFORM-NONCOMMERCIAL', 'POLYFORM-PERIMETER', 'POLYFORM-INTERNAL-USE']),
  proprietary:     new Set(['UNLICENSED', 'NOLICENSE', 'PROPRIETARY', 'COMMERCIAL']),
};

const KNOWN_RELICENSED = [
  // pkg-name regex → { from, to, atVersion, ecosystem }
  { pkg: /^elasticsearch$/i,  from: 'Apache-2.0',  to: 'Elastic-2.0 / SSPL', atVersion: '>=7.11.0', ecosystem: 'java/npm' },
  { pkg: /^@elastic\/elasticsearch$/i, from: 'Apache-2.0', to: 'Elastic-2.0 / SSPL', atVersion: '>=8.0.0', ecosystem: 'npm' },
  { pkg: /^redis$/i,          from: 'BSD-3-Clause', to: 'RSALv2 / SSPL',     atVersion: '>=7.4',      ecosystem: 'multi' },
  { pkg: /^@sentry\/.*$/i,    from: 'BSD-3-Clause', to: 'FSL-1.1',           atVersion: '>=8.0.0',    ecosystem: 'npm' },
  { pkg: /^terraform.*$/i,    from: 'MPL-2.0',      to: 'BSL-1.1',           atVersion: '>=1.6.0',    ecosystem: 'multi' },
  { pkg: /^mongodb$/i,        from: 'AGPL-3.0',     to: 'SSPL-1.0',          atVersion: '>=4.4',      ecosystem: 'multi' },
  { pkg: /^vault$/i,          from: 'MPL-2.0',      to: 'BSL-1.1',           atVersion: '>=1.15.0',   ecosystem: 'go' },
  { pkg: /^consul$/i,         from: 'MPL-2.0',      to: 'BSL-1.1',           atVersion: '>=1.17.0',   ecosystem: 'go' },
  { pkg: /^cockroachdb?$/i,   from: 'Apache-2.0',   to: 'CCL (modified)',    atVersion: '>=19.2',     ecosystem: 'go' },
];

function _normLicense(s) { return String(s || '').toUpperCase().replace(/[()]/g, '').trim(); }

function _classify(license) {
  if (!license) return 'unknown';
  const l = _normLicense(license);
  // Compound: pick worst family.
  if (/\s(?:AND|OR|WITH)\s/i.test(l)) {
    const parts = l.split(/\s+(?:AND|OR|WITH)\s+/i).map(p => p.trim()).filter(Boolean);
    const families = parts.map(_classify);
    // Worst → best: source_available > network_copyleft > strong > weak > permissive > unknown.
    for (const f of ['source_available', 'network_copyleft', 'strong_copyleft', 'weak_copyleft', 'permissive']) {
      if (families.includes(f)) return f;
    }
    return 'unknown';
  }
  for (const [fam, set] of Object.entries(LICENSE_FAMILIES)) {
    if (set.has(l)) return fam;
  }
  return 'unknown';
}

// ── Distribution-mode policy ───────────────────────────────────────────────

const DEFAULT_DIST_MODE = 'saas';

const DIST_MODE_MATRIX = {
  saas: {
    permissive:       { verdict: 'allow', why: 'Compatible with SaaS distribution.' },
    weak_copyleft:    { verdict: 'allow', why: 'Weak-copyleft (LGPL/MPL/CDDL/EPL) — SaaS distribution does not trigger reciprocity for unmodified usage.' },
    strong_copyleft:  { verdict: 'review', why: 'GPL/CGPL is compatible with SaaS (no distribution of binary) but propagates if you ever publish the source or a derived binary. Confirm internal-only.' },
    network_copyleft: { verdict: 'deny', why: 'AGPL "network use as distribution" — SaaS deployment triggers source-disclosure obligations.' },
    source_available: { verdict: 'deny', why: 'Source-available licenses (BSL/SSPL/Elastic/CommonsClause) restrict competitive SaaS offerings.' },
    proprietary:      { verdict: 'deny', why: 'Component has no license / declares proprietary — cannot redistribute.' },
    unknown:          { verdict: 'review', why: 'Unknown license — verify via upstream repo.' },
  },
  binary: {
    permissive:       { verdict: 'allow', why: 'Compatible with binary distribution.' },
    weak_copyleft:    { verdict: 'review', why: 'LGPL has static-linking obligations; MPL has file-level reciprocity. Confirm linkage model.' },
    strong_copyleft:  { verdict: 'deny', why: 'GPL copyleft propagates to the entire distributed binary.' },
    network_copyleft: { verdict: 'deny', why: 'AGPL is even more restrictive than GPL for distribution.' },
    source_available: { verdict: 'deny', why: 'Source-available licenses (BSL/SSPL/Elastic/CommonsClause) impose use restrictions that often conflict with binary distribution to customers.' },
    proprietary:      { verdict: 'deny', why: 'Component has no license / declares proprietary — cannot bundle.' },
    unknown:          { verdict: 'review', why: 'Unknown license — verify via upstream repo.' },
  },
  library: {
    permissive:       { verdict: 'allow', why: 'Compatible with library publishing.' },
    weak_copyleft:    { verdict: 'review', why: 'LGPL/MPL transitive deps complicate downstream users of YOUR library.' },
    strong_copyleft:  { verdict: 'deny', why: 'GPL locks all downstream users of your library into GPL.' },
    network_copyleft: { verdict: 'deny', why: 'AGPL forces downstream users into AGPL.' },
    source_available: { verdict: 'deny', why: 'Source-available licenses block downstream commercial use of your library.' },
    proprietary:      { verdict: 'deny', why: 'Component has no license — cannot redistribute via your library.' },
    unknown:          { verdict: 'review', why: 'Unknown license — verify via upstream repo.' },
  },
};

// ── Transitive walker ──────────────────────────────────────────────────────

function _depPathLabel(c) {
  return `${c.ecosystem || '?'}:${c.name}@${c.version || '?'}`;
}

/**
 * Build the dep graph + collect transitive contamination paths.
 *
 * components — list of component objects (already produced by the engine).
 *              expects: { ecosystem, name, version, license, transitive (boolean),
 *              importedBy: string[] (optional) }.
 */
export function analyzeLicenseGraph(components, options) {
  const opts = options || {};
  const mode = (opts.distributionMode || DEFAULT_DIST_MODE).toLowerCase();
  const matrix = DIST_MODE_MATRIX[mode] || DIST_MODE_MATRIX[DEFAULT_DIST_MODE];
  if (!Array.isArray(components) || components.length === 0) {
    return { findings: [], summary: { total: 0, deny: 0, review: 0, allow: 0, unknown: 0 }, distributionMode: mode };
  }
  const byKey = new Map();
  for (const c of components) byKey.set(_depPathLabel(c), c);
  const findings = [];
  const summary = { total: components.length, deny: 0, review: 0, allow: 0, unknown: 0 };

  for (const c of components) {
    const family = _classify(c.license);
    const verdict = matrix[family] || matrix.unknown;
    summary[verdict.verdict] = (summary[verdict.verdict] || 0) + 1;
    if (verdict.verdict === 'allow') continue;

    const isTransitive = !!c.transitive;
    let path = [_depPathLabel(c)];
    if (isTransitive && Array.isArray(c.importedBy) && c.importedBy.length) {
      // Walk up the graph (one hop in v1 — sufficient for "direct dep that
      // pulled in this offender").
      path = [c.importedBy[0], _depPathLabel(c)];
    }

    findings.push({
      id: `license-graph:${_depPathLabel(c)}:${family}:${verdict.verdict}`,
      kind: 'license', family: 'license-graph',
      severity: verdict.verdict === 'deny' ? 'high' : 'low',
      file: c.filePath || 'package.json', line: 0,
      vuln: `${verdict.verdict === 'deny' ? 'License-incompatible' : 'License-review-needed'}: ${c.name}@${c.version || '?'} (${c.license || 'no license'}) under ${mode} distribution mode`,
      description: verdict.why + (isTransitive ? ` Transitive dep pulled in via ${path.slice(0, -1).join(' → ')}.` : ''),
      remediation: verdict.verdict === 'deny'
        ? `Replace ${c.name}@${c.version || '?'} with a permissively-licensed alternative, OR switch to a different distribution mode (set distributionMode: in .agentic-security/license-policy.yml), OR negotiate a commercial license with the upstream.`
        : `Have legal review confirm ${c.license} compatibility with ${mode} distribution. Once approved, add ${c.name} to the policy allow-list.`,
      package: c.name,
      version: c.version,
      ecosystem: c.ecosystem,
      license: c.license || null,
      licenseFamily: family,
      distributionMode: mode,
      isTransitive,
      depPath: path,
    });
  }

  // ── Dual-license trap detection ─────────────────────────────────────────
  for (const c of components) {
    if (!c.license) continue;
    const lic = _normLicense(c.license);
    if (!/\bOR\b/i.test(lic)) continue;
    const atoms = lic.split(/\s+OR\s+/i).map(s => s.trim());
    const hasCommercial = atoms.some(a => /COMMERCIAL|PROPRIETARY|ENTERPRISE/.test(a));
    const hasStrongCopyleft = atoms.some(a => LICENSE_FAMILIES.strong_copyleft.has(a) || LICENSE_FAMILIES.network_copyleft.has(a));
    if (hasCommercial && hasStrongCopyleft) {
      findings.push({
        id: `license-graph:dual-license-trap:${_depPathLabel(c)}`,
        kind: 'license', family: 'license-dual-trap',
        severity: 'high',
        file: c.filePath || 'package.json', line: 0,
        vuln: `Dual-license trap: ${c.name}@${c.version} offers ${c.license} — the open option is copyleft, the alternative requires a commercial agreement`,
        description: 'Dual GPL-OR-Commercial licensing means: if you have not signed a commercial agreement with the upstream, your usage falls under GPL/AGPL and propagates to your codebase. Common pattern with Qt LGPL/Commercial, MongoDB AGPL/Commercial pre-SSPL, GraalVM.',
        remediation: 'Verify with legal whether a commercial agreement is in place. If not, you are bound by the copyleft option — propagate that to your distribution mode policy.',
        package: c.name, version: c.version, license: c.license,
      });
      summary.deny = (summary.deny || 0) + 1;
    }
  }

  // ── Known relicensed packages ───────────────────────────────────────────
  for (const c of components) {
    for (const r of KNOWN_RELICENSED) {
      if (!r.pkg.test(c.name)) continue;
      findings.push({
        id: `license-graph:relicensed:${_depPathLabel(c)}`,
        kind: 'license', family: 'license-relicense',
        severity: 'medium',
        file: c.filePath || 'package.json', line: 0,
        vuln: `${c.name}@${c.version}: upstream relicensed from ${r.from} → ${r.to} (boundary ${r.atVersion})`,
        description: `Upstream relicensing event for ${c.name}. Older versions were ${r.from}; ${r.atVersion} and later are ${r.to}. Verify which side of the boundary your version is on, and update your policy.`,
        remediation: `Pin to a pre-relicense version if the new terms are unacceptable, OR adopt a fork (e.g. OpenSearch for Elasticsearch, Valkey for Redis, OpenTofu for Terraform).`,
        package: c.name, version: c.version, license: c.license, relicenseInfo: r,
      });
    }
  }

  return { findings, summary, distributionMode: mode };
}

// ── Policy file loader (extends posture/license-policy.js shape) ───────────

export function loadLicenseGraphPolicy(scanRoot) {
  if (!scanRoot) return { distributionMode: DEFAULT_DIST_MODE };
  const fp = path.join(scanRoot, '.agentic-security', 'license-policy.yml');
  if (!fs.existsSync(fp)) return { distributionMode: DEFAULT_DIST_MODE };
  try {
    const raw = fs.readFileSync(fp, 'utf8');
    const m = /\bdistributionMode\s*:\s*['"]?(saas|binary|library)['"]?/i.exec(raw);
    return { distributionMode: m ? m[1].toLowerCase() : DEFAULT_DIST_MODE };
  } catch { return { distributionMode: DEFAULT_DIST_MODE }; }
}

export const _internals = {
  LICENSE_FAMILIES, DIST_MODE_MATRIX, KNOWN_RELICENSED,
  _classify, _normLicense,
};
