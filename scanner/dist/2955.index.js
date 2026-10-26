export const id = 2955;
export const ids = [2955];
export const modules = {

/***/ 2955:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   findSiblings: () => (/* binding */ findSiblings)
/* harmony export */ });
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(73024);
/* harmony import */ var node_path__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(76760);
/* harmony import */ var _rule_compiler_proposal_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(51006);
/* harmony import */ var _state_dir_js__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(92582);
// Sibling-exposure search for a verified fix (PRD 1, requirement 6, step 8: "look for equivalent sibling exposures").
//
// A fix that closes one instance of a flaw says nothing about the same shape written somewhere else. This finds candidates two ways,
// and reports where each came from:
//   * `scan`       other findings from the last scan with the same weakness or title (what the engine already believes);
//   * `structural` other places in the repository whose line has the SAME SHAPE as the vulnerable line: the vulnerable line is
//                  generalized (call names kept, strings and other identifiers become classes) by the rule compiler's own
//                  generalizer and searched across the source files. This finds copies the engine did not flag.
// The result is a list of CANDIDATES for a person to look at, not a verdict that each one is exploitable. Bounded in files, bytes,
// matches and time; a bound that is hit is reported (`truncated`), because "no siblings found" must never mean "stopped looking".





const SOURCE_EXT = /\.(?:js|mjs|cjs|jsx|ts|tsx|py|rb|php|java|kt|go|rs|cs|c|cc|cpp|h|hpp|sh|swift|scala)$/i;
const SKIP = new Set(['.git', 'node_modules', 'dist', 'build', 'vendor', _state_dir_js__WEBPACK_IMPORTED_MODULE_3__/* .STATE_DIR_NAME */ .Ky, 'coverage', '__pycache__']);
const SIBLING_LIMITS = Object.freeze({ maxFiles: 5000, maxFileBytes: 512 * 1024, maxMatches: 100, budgetMs: 8000 });

const sameSpot = (a, b) => node_path__WEBPACK_IMPORTED_MODULE_1__.resolve(a) === node_path__WEBPACK_IMPORTED_MODULE_1__.resolve(b);

/**
 * @param {object} o
 * @param {string} o.root           repository root
 * @param {{file: string, line: number, id?: string, cwe?: string, vuln?: string}} o.finding
 * @param {object[]} [o.scanFindings] findings from the last scan
 * @returns {{siblings: object[], truncated: string[], pattern: string|null}}
 */
function findSiblings({ root, finding, scanFindings = [], limits = SIBLING_LIMITS, now = Date.now }) {
  const out = []; const seen = new Set(); const truncated = [];
  const add = (s) => { const k = `${s.file}:${s.line ?? ''}`; if (!seen.has(k)) { seen.add(k); out.push(s); } };
  for (const x of scanFindings) {
    if (!x || x.id === finding.id || x.stableId === finding.stableId && finding.stableId) continue;
    if (x.file === finding.file && x.line === finding.line) continue;
    if ((finding.cwe && x.cwe === finding.cwe) || (finding.vuln && x.vuln === finding.vuln)) add({ source: 'scan', file: x.file, line: x.line ?? null, id: x.id ?? null });
  }
  let pattern = null;
  let line = '';
  try {
    const abs = node_path__WEBPACK_IMPORTED_MODULE_1__.resolve(root, finding.file);
    line = (node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(abs, 'utf8').split('\n')[finding.line - 1] ?? '').trim();
  } catch { /* the flagged file is gone; only the scan-based siblings are available */ }
  if (line.length >= 8) {
    pattern = (0,_rule_compiler_proposal_js__WEBPACK_IMPORTED_MODULE_2__/* .generalizeLine */ .Ry)(line);
    let rx = null;
    try { rx = new RegExp(pattern); } catch { rx = null; }
    if (rx) {
      const deadline = now() + limits.budgetMs; let files = 0; let matches = 0;
      const base = node_fs__WEBPACK_IMPORTED_MODULE_0__.realpathSync(root);
      const walk = (dir) => {
        if (truncated.length) return;
        let ents = [];
        try { ents = node_fs__WEBPACK_IMPORTED_MODULE_0__.readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name)); } catch { return; }
        for (const e of ents) {
          if (truncated.length) return;
          if (SKIP.has(e.name) || e.isSymbolicLink()) continue;
          const p = node_path__WEBPACK_IMPORTED_MODULE_1__.join(dir, e.name);
          if (e.isDirectory()) { walk(p); continue; }
          if (!e.isFile() || !SOURCE_EXT.test(e.name)) continue;
          if (++files > limits.maxFiles) { truncated.push(`file limit (${limits.maxFiles})`); return; }
          if (now() > deadline) { truncated.push('time budget'); return; }
          let text; try { const st = node_fs__WEBPACK_IMPORTED_MODULE_0__.statSync(p); if (st.size > limits.maxFileBytes) continue; text = node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(p, 'utf8'); } catch { continue; }
          const lines = text.split('\n');
          for (let i = 0; i < lines.length; i++) {
            if (lines[i].length > 2000 || !rx.test(lines[i].trim())) continue;
            const rel = node_path__WEBPACK_IMPORTED_MODULE_1__.relative(base, node_fs__WEBPACK_IMPORTED_MODULE_0__.realpathSync(p));
            if (sameSpot(node_path__WEBPACK_IMPORTED_MODULE_1__.resolve(base, rel), node_path__WEBPACK_IMPORTED_MODULE_1__.resolve(base, finding.file)) && i + 1 === finding.line) continue;
            add({ source: 'structural', file: rel, line: i + 1, text: lines[i].trim().slice(0, 160) });
            if (++matches >= limits.maxMatches) { truncated.push(`match limit (${limits.maxMatches})`); return; }
          }
        }
      };
      walk(base);
    }
  }
  return { siblings: out, truncated, pattern };
}


/***/ })

};
