// Dependency finding basis (PRD FR 08). Records WHY a dependency finding exists
// and how strong the evidence about the dependency itself is, kept apart from
// reachability. A version match is a version match: unknown reachability is
// recorded as unknown and is never a reason to drop or call the finding safe.
//
// Version bases, weakest to strongest. None of them is deployment evidence:
//   declared-constraint  a range or pin in a manifest
//   locked               an entry in a lock file
//   resolved-graph       a resolved dependency graph (not produced by this scanner today)
//   deployment-evidence  an artifact or runtime inventory (never inferred from the repository)

const LOCK_FILES = /(?:^|\/)(?:package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|Cargo\.lock|poetry\.lock|Pipfile\.lock|go\.sum|Gemfile\.lock|composer\.lock|gradle\.lockfile|packages\.lock\.json|stack\.yaml\.lock|cabal\.project\.freeze|flake\.lock|mix\.lock|pubspec\.lock)$/;

export function versionBasisOf(file) {
  return LOCK_FILES.test(String(file || '')) ? 'locked' : 'declared-constraint';
}

function rangesOf(sc) {
  if (Array.isArray(sc.affectedRanges) && sc.affectedRanges.length) return sc.affectedRanges;
  return null;
}

/** Add `basis` to every dependency vulnerability finding. Pure with respect to severity and visibility. */
export function annotateScaBasis(supplyChain) {
  for (const sc of supplyChain || []) {
    if (!sc || sc.type !== 'vulnerable_dep') continue;
    const vb = versionBasisOf(sc.file);
    const gaps = [];
    if (!rangesOf(sc)) gaps.push('affected range not recorded for this advisory');
    if (!sc.advisoryModified) gaps.push('advisory timestamp not recorded');
    if (!sc.fixedVersions || !sc.fixedVersions.length) gaps.push('no fixed version known');
    if (vb === 'declared-constraint') gaps.push('version comes from a declared constraint; the installed version may differ');
    gaps.push('no deployment evidence: a dependency listed here is not proof that it is deployed');
    sc.basis = {
      schema: 'sca-basis/1',
      ecosystem: sc.ecosystem || null,
      package: sc.name || null,
      resolvedVersion: sc.version || null,
      versionBasis: vb,
      source: { file: sc.file || null, line: sc.line ?? null, direct: sc.isDirect ?? null, chain: sc.depChain || [] },
      advisory: {
        id: sc.osvId || null,
        aliases: sc.cveAliases || [],
        affectedRanges: rangesOf(sc),
        fixedVersions: sc.fixedVersions || [],
        source: sc.advisorySource || 'osv.dev',
        modified: sc.advisoryModified || null,
        published: sc.advisoryPublished || null,
      },
      matchBasis: 'version-range',
      reachability: sc.functionReachable || (sc.reachable ? 'import-reachable' : 'unknown'),
      reachabilityNote: 'reachability is optional context and never removes a valid version match',
      deploymentEvidence: 'none',
      gaps,
    };
  }
  return supplyChain;
}

/**
 * Merge findings that are the same advisory under different identifiers (an
 * OSV/GHSA id and its CVE alias) for the same package version. The merged
 * finding keeps every identifier and every affected occurrence, so no
 * component or file is lost. Returns the new list; inputs are not mutated.
 */
export function dedupeAdvisoryAliases(supplyChain) {
  const out = [];
  const groups = new Map(); // component key -> [{ids:Set, primary}]
  for (const sc of supplyChain || []) {
    if (!sc || sc.type !== 'vulnerable_dep') { out.push(sc); continue; }
    const ck = `${sc.ecosystem}\0${sc.name}\0${sc.version}`;
    const ids = new Set([sc.osvId, ...(sc.cveAliases || [])].filter(Boolean));
    const list = groups.get(ck) || groups.set(ck, []).get(ck);
    const hit = list.find((g) => [...ids].some((i) => g.ids.has(i)));
    const occ = { file: sc.file || null, line: sc.line ?? null, direct: sc.isDirect ?? null, chain: sc.depChain || [] };
    if (!hit) {
      const primary = { ...sc, occurrences: [occ], advisoryIds: [...ids].sort() };
      list.push({ ids, primary });
      out.push(primary);
      continue;
    }
    for (const i of ids) hit.ids.add(i);
    hit.primary.advisoryIds = [...hit.ids].sort();
    if (!hit.primary.occurrences.some((o) => o.file === occ.file && o.line === occ.line)) hit.primary.occurrences.push(occ);
    if (sc.osvId && sc.osvId !== hit.primary.osvId) (hit.primary.mergedAdvisories ||= []).push(sc.osvId);
  }
  return out;
}
