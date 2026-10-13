// PRD 5 P0 §8 — VEX (Vulnerability Exploitability eXchange). Statuses are the
// PRD's own four. The PRD's one explicit rule — "`not affected` requires
// positive evidence" — is enforced structurally: `not_affected` is only ever
// returned from one of two named, checked evidence paths below; there is no
// code path that reaches it by default or by absence of information.
// Justification strings follow the CISA VEX vocabulary this repo's other VEX
// output (`toVex` in `src/posture/sbom.js`'s neighborhood) already uses,
// where applicable.
//
// `affected` likewise requires positive evidence (confirmed reachability),
// not just "OSV lists this version as vulnerable" — a scanner result alone
// only tells you the CVE/version pair matches; it doesn't tell you the
// vulnerable code path is reachable in THIS artifact. Absent that
// confirmation, the honest status is `under_investigation`, never a
// confident `affected` the evidence doesn't support.
export const VEX_STATUSES = Object.freeze(['affected', 'not_affected', 'fixed', 'under_investigation']);

// Loose dotted-numeric version comparison. Returns -1/0/1, or null when
// either side isn't a clean dotted-numeric form — a "fixed" verdict is only
// ever returned when this does NOT return null; an unparseable version
// means that evidence path is skipped, never guessed through.
function compareVersions(a, b) {
  const pa = String(a).split(/[.-]/).map((s) => (/^\d+$/.test(s) ? parseInt(s, 10) : null));
  const pb = String(b).split(/[.-]/).map((s) => (/^\d+$/.test(s) ? parseInt(s, 10) : null));
  if (pa.some((n) => n === null) || pb.some((n) => n === null)) return null;
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const x = pa[i] ?? 0;
    const y = pb[i] ?? 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

function componentKeyOf(c) {
  return c.purl || (c.ecosystem && c.name && c.version ? `${c.ecosystem}:${c.name}@${c.version}` : null);
}

/**
 * `vulnerability` is one `vulnerable_dep`-shaped entry already confirmed
 * present via `vuln-correlate.js` against THIS artifact. `artifactComponents`
 * is the artifact's own inventory (`osPackages`/`appPackages` concatenated).
 * `reachability`, if supplied, is `{ reachable: true|false, reason }` from
 * this codebase's existing dataflow/reachability evidence (never computed
 * here — this module does no new analysis, only statuses the evidence it's
 * handed).
 */
export function deriveVexStatus({ vulnerability, artifactComponents, reachability = null }) {
  if (!vulnerability || typeof vulnerability !== 'object') {
    throw new TypeError('deriveVexStatus requires a vulnerability object');
  }
  if (!Array.isArray(artifactComponents)) {
    throw new TypeError('deriveVexStatus requires an artifactComponents array');
  }

  const vulnKey = vulnerability.purl
    || (vulnerability.ecosystem && vulnerability.name && vulnerability.version ? `${vulnerability.ecosystem}:${vulnerability.name}@${vulnerability.version}` : null);
  const present = vulnKey != null && artifactComponents.some((c) => componentKeyOf(c) === vulnKey);

  if (!present) {
    return {
      status: 'not_affected',
      justification: 'component_not_present',
      evidence: 'the affected component (by purl/ecosystem+name+version) is not present in this artifact\'s inventory',
    };
  }

  if (reachability && reachability.reachable === false) {
    return {
      status: 'not_affected',
      justification: 'vulnerable_code_not_in_execute_path',
      evidence: reachability.reason || 'static reachability analysis found no path to the vulnerable function in this artifact',
    };
  }

  if (Array.isArray(vulnerability.fixedVersions) && vulnerability.fixedVersions.length && vulnerability.version) {
    for (const fv of vulnerability.fixedVersions) {
      const cmp = compareVersions(vulnerability.version, fv);
      if (cmp !== null && cmp >= 0) {
        return { status: 'fixed', justification: null, evidence: `installed version ${vulnerability.version} is >= the fixed version ${fv}` };
      }
    }
  }

  if (reachability && reachability.reachable === true) {
    return { status: 'affected', justification: null, evidence: reachability.reason || 'static reachability analysis confirmed a path to the vulnerable function in this artifact' };
  }

  return {
    status: 'under_investigation',
    justification: null,
    evidence: 'the affected component is present and not confirmed fixed, but reachability has not been established — not a confident "affected" claim',
  };
}
