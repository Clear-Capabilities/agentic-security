export const id = 4629;
export const ids = [4629];
export const modules = {

/***/ 74629:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   detectSourceArtifactMismatch: () => (/* binding */ detectSourceArtifactMismatch)
/* harmony export */ });
// PRD 5 P0 §7 — Source vs Artifact Mismatch. This is the PRD's own "Killer
// Demonstration": a developer fixes a vulnerability in source on Monday, but
// production is still serving Friday's image.
//
// Scenario A — "Git: fixed / Production image: vulnerable": an OSV advisory
// the DEPLOYED ARTIFACT's own vuln-correlate.js result reports against the
// version it actually has installed, that the CURRENT source scan does NOT
// report against the version source has installed/declared — i.e. source
// has moved past this specific advisory (patched, upgraded) but the
// artifact's installed version has not.
//
// Scenario B — "Git: vulnerable / Built artifact: affected component
// absent": the current source scan flags an advisory against some package,
// but that PACKAGE (by ecosystem+name, independent of version) is not
// present anywhere in the artifact's own component inventory at all — a
// dev-only/optional dependency that never actually shipped in this build.
//
// The matching key for a scenario-A/B pair is the OSV advisory id ALONE
// (`osvId`) — never the purl, which bakes the VERSION into the key. Keying
// on purl was tried first and is wrong: source and artifact are, by this
// comparison's entire premise, usually running DIFFERENT versions of the
// same package, so a purl-based key would make every version difference
// look like two independent mismatches instead of comparing "does this
// specific advisory affect each side's own installed version". An OSV
// advisory id already uniquely identifies one vulnerability against one
// package, so comparing by id alone correctly asks "is THIS advisory
// present on one side and absent on the other", regardless of which exact
// version is installed on either side.
//
// Pure comparison only — no new detection. `sourceVulnerabilities` is the
// output of a normal source-tree SCA scan (queryOSV-shaped `vulnerable_dep`
// entries); `artifactVulnerabilities`/`artifactComponents` are
// vuln-correlate.js's/inventory.js's output for one specific image.
function advisoryKey(v) {
  return v.osvId || `no-osv-id:${v.ecosystem}:${v.name}`;
}

function packageIdentity(c) {
  return `${c.ecosystem}:${c.name}`;
}

function detectSourceArtifactMismatch({ sourceVulnerabilities, artifactVulnerabilities, artifactComponents }) {
  if (!Array.isArray(sourceVulnerabilities) || !Array.isArray(artifactVulnerabilities) || !Array.isArray(artifactComponents)) {
    throw new TypeError('detectSourceArtifactMismatch requires sourceVulnerabilities/artifactVulnerabilities/artifactComponents arrays');
  }

  const sourceKeyed = new Map();
  for (const v of sourceVulnerabilities) {
    if (v.type && v.type !== 'vulnerable_dep') continue;
    sourceKeyed.set(advisoryKey(v), v);
  }
  const artifactKeyed = new Map();
  for (const v of artifactVulnerabilities) {
    if (v.type && v.type !== 'vulnerable_dep') continue;
    artifactKeyed.set(advisoryKey(v), v);
  }
  const artifactPackageIdentities = new Set(artifactComponents.map(packageIdentity));

  const scenarioA = [...artifactKeyed.entries()]
    .filter(([key]) => !sourceKeyed.has(key))
    .map(([, v]) => v);

  const scenarioB = [...sourceKeyed.entries()]
    .filter(([, v]) => !artifactPackageIdentities.has(packageIdentity(v)))
    .map(([, v]) => v);

  return {
    scenarioA,
    scenarioB,
    hasMismatch: scenarioA.length > 0 || scenarioB.length > 0,
  };
}


/***/ })

};
