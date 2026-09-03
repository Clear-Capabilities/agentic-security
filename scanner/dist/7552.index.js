export const id = 7552;
export const ids = [7552];
export const modules = {

/***/ 7552:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   buildDeletionReport: () => (/* binding */ buildDeletionReport),
/* harmony export */   buildExportReport: () => (/* binding */ buildExportReport),
/* harmony export */   writeDeletionReport: () => (/* binding */ writeDeletionReport),
/* harmony export */   writeExportReport: () => (/* binding */ writeExportReport)
/* harmony export */ });
/* unused harmony exports DELETION_REPORT_FILE, EXPORT_REPORT_FILE */
/* harmony import */ var _state_dir_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(1174);
// FR-706 (assurance-hardening PRD): manifest-based export and deletion
// reports — "Operators can prove what was exported, deleted, retained, or
// failed."
//
// Two report kinds, one shared per-item shape ({name, status, ...}), each
// written by its one real caller in bin/agentic-security.js:
//   - `cmdReset` builds a deletion report from the SAME target/preserved
//     data it already computes for its console output (see FR-702/FR-703),
//     reshaped into a durable, structured artifact instead of only ever
//     printed and lost. Written on BOTH a dry run (items carry status
//     'planned') and a real run (status 'deleted'/'failed'), so an operator
//     can prove either "what would happen" or "what did happen" depending
//     on which they asked for — `dryRun` on the report says which.
//   - `cmdExport` (new) builds an export report after copying every
//     currently-present registered artifact to an operator-chosen
//     destination, naming what was copied (with a hash) and what failed.
//
// Each report is a SINGLE OVERWRITTEN file per kind — the same "last
// action" precedent as last-scan.json, not an ever-growing log. An
// operator who needs a persistent audit trail across many runs should
// retain these externally (commit them, forward to their own SIEM); this
// module's job is only to make the LAST action's outcome durable and
// provable, not to be the audit log itself.



const DELETION_REPORT_FILE = 'deletion-report.json';
const EXPORT_REPORT_FILE = 'export-report.json';

function buildDeletionReport({ mode, dryRun, root, items, preserved }) {
  const list = Array.isArray(items) ? items : [];
  const preservedList = Array.isArray(preserved) ? preserved : [];
  return {
    schema: 'agentic-security/deletion-report@1',
    generatedAt: new Date().toISOString(),
    mode: mode || 'reset',
    dryRun: !!dryRun,
    root: root || null,
    items: list,
    preserved: preservedList,
    summary: {
      planned: list.filter(i => i.status === 'planned').length,
      deleted: list.filter(i => i.status === 'deleted').length,
      failed: list.filter(i => i.status === 'failed').length,
      preserved: preservedList.length,
    },
  };
}

function writeDeletionReport(scanRoot, report) {
  try {
    const fp = (0,_state_dir_js__WEBPACK_IMPORTED_MODULE_0__.statePath)(scanRoot, DELETION_REPORT_FILE);
    return (0,_state_dir_js__WEBPACK_IMPORTED_MODULE_0__/* .safeWriteState */ .Ep)(fp, JSON.stringify(report, null, 2) + '\n') ? fp : null;
  } catch { return null; }
}

function buildExportReport({ root, outDir, items }) {
  const list = Array.isArray(items) ? items : [];
  return {
    schema: 'agentic-security/export-report@1',
    generatedAt: new Date().toISOString(),
    root: root || null,
    outDir: outDir || null,
    items: list,
    summary: {
      exported: list.filter(i => i.status === 'exported').length,
      failed: list.filter(i => i.status === 'failed').length,
    },
  };
}

function writeExportReport(scanRoot, report) {
  try {
    const fp = (0,_state_dir_js__WEBPACK_IMPORTED_MODULE_0__.statePath)(scanRoot, EXPORT_REPORT_FILE);
    return (0,_state_dir_js__WEBPACK_IMPORTED_MODULE_0__/* .safeWriteState */ .Ep)(fp, JSON.stringify(report, null, 2) + '\n') ? fp : null;
  } catch { return null; }
}


/***/ })

};
