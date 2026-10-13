export const id = 5206;
export const ids = [5206];
export const modules = {

/***/ 15206:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   correlateImageVulnerabilities: () => (/* binding */ correlateImageVulnerabilities)
/* harmony export */ });
// PRD 5 P0 §4 — Container Vulnerability Analysis. "Reuse current SCA
// semantics where technically valid": this module does nothing but hand an
// image's OS + application package inventory to the engine's existing
// OSV/KEV/EPSS query path (`queryOSV`, imported via `src/sca/index.js`),
// exactly as every other SCA finding in this codebase gets its CVE data.
// `queryOSVFn` is injected (not imported directly) so this module's own
// tests never make a real network call and stay independent of engine.js's
// load cost; the CLI wiring passes the real `queryOSV`.
async function correlateImageVulnerabilities({ inventory, fileContents, queryOSVFn }) {
  if (typeof queryOSVFn !== 'function') throw new TypeError('correlateImageVulnerabilities requires queryOSVFn(components, allFileContents)');
  if (!inventory || !Array.isArray(inventory.osPackages) || !Array.isArray(inventory.appPackages)) {
    throw new TypeError('correlateImageVulnerabilities requires an inventory with osPackages/appPackages arrays');
  }
  const components = [...inventory.osPackages, ...inventory.appPackages];
  const vulnerabilities = await queryOSVFn(components, fileContents || {});
  return { components, vulnerabilities };
}


/***/ })

};
