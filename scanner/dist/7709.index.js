export const id = 7709;
export const ids = [7709];
export const modules = {

/***/ 7709:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   exportFlowsCSV: () => (/* binding */ exportFlowsCSV)
/* harmony export */ });
/* harmony import */ var _protection_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(965);
// export-csv.js — Milestone 4, sub-project JSON/CSV export.
//
// One row per FLOW (not node, not edge — the closest analogue in this
// domain to report/index.js's own toCSV's "one row per finding", per this
// sub-project's own scoping doc decision 3). Node/edge CSV exports are
// deferred, named explicitly in that doc, not attempted here.



// Same escaping convention as report/index.js's own toCSV — quote only
// when a comma/quote/newline is present, double embedded quotes.
function esc(v) {
  if (v == null) return '';
  const s = String(v);
  return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}

// Join character for a flow's multiple `dataClasses` values in one CSV
// cell: `;`, not `,`. Chosen (this module's own decision, not prescribed
// by the plan) because `,` is CSV's own delimiter — joining multiple
// classes with it would put a raw delimiter inside a single logical cell
// value, forcing outer quoting for the ordinary multi-class case (e.g. a
// field classified both PCI and PII). `;` never collides with the CSV
// grammar, so the common case ("PCI;PII") never needs quoting at all.
// `esc()` still quotes correctly if a comma ends up in cell content for
// any other reason (see export-csv.test.js's own escaping test) — this
// choice only avoids manufacturing that case in the common path.
const DATA_CLASSES_JOIN = ';';

function _dataClassesForFlow(flow, dataElementsById) {
  const classes = new Set();
  for (const deId of flow.dataElementIds ?? []) {
    const de = dataElementsById.get(deId);
    for (const c of de?.dataClasses ?? []) classes.add(c);
  }
  return [...classes].sort();
}

function _dimensionVerdict(flow, edgesById, dimension) {
  const verdicts = (flow.edgeIds ?? [])
    .map((id) => edgesById.get(id)?.protection?.[dimension]?.verdict)
    .filter(Boolean);
  return (0,_protection_js__WEBPACK_IMPORTED_MODULE_0__/* .aggregateVerdicts */ .SX)(verdicts);
}

function exportFlowsCSV(graph) {
  const dataElementsById = new Map((graph.dataElements ?? []).map((d) => [d.id, d]));
  const edgesById = new Map((graph.edges ?? []).map((e) => [e.id, e]));
  const header = ['id', 'source', 'sink', 'dataClasses', 'transitVerdict', 'atRestVerdict', 'handlingVerdict', 'policyVerdict', 'coverageStatus'];
  const rows = [header.join(',')];
  for (const flow of graph.flows ?? []) {
    rows.push([
      esc(flow.id), esc(flow.source), esc(flow.sink),
      esc(_dataClassesForFlow(flow, dataElementsById).join(DATA_CLASSES_JOIN)),
      esc(_dimensionVerdict(flow, edgesById, 'transit')),
      esc(_dimensionVerdict(flow, edgesById, 'atRest')),
      esc(_dimensionVerdict(flow, edgesById, 'handling')),
      esc(flow.policyVerdict), esc(flow.coverageStatus),
    ].join(','));
  }
  return rows.join('\n');
}


/***/ })

};
