export const id = 5117;
export const ids = [5117];
export const modules = {

/***/ 35117:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   exampleRunner: () => (/* binding */ exampleRunner)
/* harmony export */ });
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(73024);
/* harmony import */ var node_os__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(48161);
/* harmony import */ var node_path__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(76760);
/* harmony import */ var _coordinator_js__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(50382);
/* harmony import */ var _recipes_js__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(60681);
/* harmony import */ var _intake_js__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(30356);
// Running a recipe's examples (verified-remediation PRD FR-11, M3-02): each positive or independent example is a real repair run, on a
// copy of the example project, with the recipe as the ONLY proposer. The finding is the scanner's own finding of the recipe's family on
// that project when the scanner reports one (its stable id lets the central verifier tell a finding the project already had from one
// the patch introduced), otherwise a declared one. Nothing here judges anything: the coordinator and its obligations do.







async function findingFor(root, entry, family) {
  try {
    const { runFullScan } = await Promise.resolve(/* import() */).then(__webpack_require__.bind(__webpack_require__, 67198));
    const scan = await runFullScan({ fileContents: { [entry]: node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(node_path__WEBPACK_IMPORTED_MODULE_2__.join(root, entry), 'utf8') }, scanRoot: root, provenance: false }, () => {});
    const f = (scan.findings || []).find((x) => (0,_intake_js__WEBPACK_IMPORTED_MODULE_5__/* .familyForFinding */ .lG)(x) === family);
    if (f) return { findingId: f.id, id: f.id, stableId: f.stableId, file: entry, cwe: f.cwe };
  } catch { /* fall through to a declared finding */ }
  return { findingId: `recipe-example:${family}:${entry}`, file: entry };
}

/** The `run` dependency `evaluateRecipe` takes, bound to an assurance configuration that enables execution. */
function exampleRunner({ config, policy = { schema: 'agentic-security/repair-policy', schemaVersion: '1.0.0', budgets: { rounds: 1 } } }) {
  return async ({ recipe, example, dir, planOnly }) => {
    const root = node_fs__WEBPACK_IMPORTED_MODULE_0__.mkdtempSync(node_path__WEBPACK_IMPORTED_MODULE_2__.join(node_os__WEBPACK_IMPORTED_MODULE_1__.tmpdir(), `recipe-${recipe.recipeId}-${example.id}-`));
    try {
      node_fs__WEBPACK_IMPORTED_MODULE_0__.cpSync(dir, root, { recursive: true });
      const profile = JSON.parse(node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(node_path__WEBPACK_IMPORTED_MODULE_2__.join(root, 'profile.json'), 'utf8'));
      const finding = await findingFor(root, profile.application.entry, example.family);
      const p = (0,_coordinator_js__WEBPACK_IMPORTED_MODULE_3__/* .planRepair */ .RZ)({ root, finding, family: example.family, profile, profileOrigin: 'repository-file' });
      if (!p.plan) return { disposition: 'plan-failed', reasons: [...p.problems, ...p.blocked], contract: null };
      if (planOnly) return { contract: p.plan.contract };
      const r = await (0,_coordinator_js__WEBPACK_IMPORTED_MODULE_3__/* .runRepair */ .Lq)({ root, plan: p.plan, config, proposers: [(0,_recipes_js__WEBPACK_IMPORTED_MODULE_4__/* .recipeProposer */ .Hi)(recipe)], policy });
      return {
        disposition: r.record.disposition, reasons: r.record.reasons,
        obligationDigests: Object.fromEntries(p.plan.contract.obligations.map((o) => [o.id, o.inputsDigest ?? null])),
      };
    } finally {
      try { node_fs__WEBPACK_IMPORTED_MODULE_0__.rmSync(root, { recursive: true, force: true }); } catch { /* temporary */ }
    }
  };
}


/***/ })

};
