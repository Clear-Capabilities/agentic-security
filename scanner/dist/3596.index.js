export const id = 3596;
export const ids = [3596];
export const modules = {

/***/ 53596:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   sweepHaskellSiblings: () => (/* binding */ sweepHaskellSiblings)
/* harmony export */ });
/* unused harmony export HS_SWEEP_VERSION */
/* harmony import */ var _dataflow_catalog_haskell_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(7225);
/* harmony import */ var _lineage_source_seeding_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(88383);
// Root-cause sweep for Haskell (X-008). The generic sweep anchors on a `callee(args)` text shape, which Haskell's
// juxtaposition syntax never produces, so a confirmed Haskell finding swept nothing. This sweep works on the IR: for
// each confirmed finding it takes the RESOLVED sink callee from the model catalog and lists every other call of that
// same callee in the project, then accounts for all of them:
//
//     found === candidates + mitigated
//
// `found` is every other call site of the callee (the finding's own site, and the sites of other findings in the same
// group, are the origins and are excluded). `mitigated` is a site where a detector already produced a finding for a
// different reason, `candidates` is the rest. A candidate whose argument is a literal constant is flagged
// (`constantArgument`) and stays a candidate: the flag is information, not a verdict. Nothing is dropped.
//
// Resolution is by import-qualified callee, so an unrelated function that merely shares a name is not a sibling.




const HS_SWEEP_VERSION = 'haskell-sweep/1';
const SAMPLE_LIMIT = 100;
const isHs = (f) => /\.l?hs$/i.test(f || '');
const BY_ID = new Map(_dataflow_catalog_haskell_js__WEBPACK_IMPORTED_MODULE_0__/* .HASKELL_CATALOG */ .R.filter((e) => e.kind === 'sink').map((e) => [e.id, e]));

const allConstant = (e) => {
  let constant = true; let sawLiteral = false;
  (0,_lineage_source_seeding_js__WEBPACK_IMPORTED_MODULE_1__/* .walkExpr */ .lN)(e, (x) => {
    if (x.kind === 'literal') sawLiteral = true;
    else if (x.kind === 'ident' && !(x.hs && x.hs.functionRef)) constant = false;
    else if (x.kind === 'member') constant = false;
  });
  return constant && sawLiteral;
};

/**
 * @param {object[]} findings confirmed findings (only Haskell IR-taint findings are swept)
 * @param {{functions: Map}} callGraph the project call graph (ir/index.js buildProjectIR)
 */
function sweepHaskellSiblings(findings, callGraph) {
  const groups = new Map();
  for (const f of findings || []) {
    if (!f || !isHs(f.file) || f.parser !== 'IR-TAINT' || !f.sink || !f.sink.label) continue;
    const entry = BY_ID.get(f.sink.label);
    if (!entry || !entry.match || !entry.match.callee) continue;
    const key = entry.match.callee;
    if (!groups.has(key)) groups.set(key, { callee: key, entry, findings: [] });
    groups.get(key).findings.push(f);
  }
  const sites = new Map();                                  // callee -> [{file, line, constantArgument}]
  const wanted = new Set(groups.keys());
  for (const fn of callGraph && callGraph.functions ? callGraph.functions.values() : []) {
    if (!isHs(fn.file) || !fn.cfg) continue;
    for (const node of Object.values(fn.cfg.nodes)) {
      const visit = (e) => {
        if (e.kind === 'call' && typeof e.callee === 'string' && wanted.has(e.callee)) {
          const entry = groups.get(e.callee).entry;
          const arg = (e.args || [])[entry.argIndex || 0];
          if (!sites.has(e.callee)) sites.set(e.callee, []);
          sites.get(e.callee).push({ file: fn.file, line: e.line || node.line || null, constantArgument: arg ? allConstant(arg) : false });
        }
      };
      if (node.kind === 'call' && typeof node.callee === 'string' && wanted.has(node.callee)) visit(node);
      for (const root of (0,_lineage_source_seeding_js__WEBPACK_IMPORTED_MODULE_1__/* .exprRoots */ .Zf)(node)) (0,_lineage_source_seeding_js__WEBPACK_IMPORTED_MODULE_1__/* .walkExpr */ .lN)(root, visit);
    }
  }
  const covered = new Map();                                // "file:line" -> true, any finding at that site
  for (const f of findings || []) if (f && f.file && Number.isInteger(f.line)) covered.set(`${f.file}:${f.line}`, true);
  const sweeps = [];
  const totals = { found: 0, candidates: 0, mitigated: 0 };
  for (const [callee, g] of [...groups.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1))) {
    const origin = new Set(g.findings.map((f) => `${f.file}:${f.line}`));
    const seen = new Set(); const all = [];
    for (const s of sites.get(callee) || []) { const k = `${s.file}:${s.line}`; if (origin.has(k) || seen.has(k)) continue; seen.add(k); all.push(s); }
    all.sort((a, b) => (a.file + String(a.line)).localeCompare(b.file + String(b.line), undefined, { numeric: true }));
    const instances = all.map((s) => ({ ...s, status: covered.has(`${s.file}:${s.line}`) ? 'mitigated' : 'candidate' }));
    const mitigated = instances.filter((i) => i.status === 'mitigated').length;
    const candidates = instances.length - mitigated;
    sweeps.push({
      callee, cwe: g.entry.vuln.cwe, family: g.entry.hs && g.entry.hs.family, origins: [...origin].sort(), findingIds: g.findings.map((f) => f.id).sort(),
      found: instances.length, candidates, mitigated, constantArgumentCandidates: instances.filter((i) => i.status === 'candidate' && i.constantArgument).length,
      instances: instances.slice(0, SAMPLE_LIMIT), instancesTruncated: instances.length > SAMPLE_LIMIT, remaining: candidates,
      note: 'siblings are other calls of the same import-qualified sink; a candidate is unreviewed, not vulnerable',
    });
    totals.found += instances.length; totals.candidates += candidates; totals.mitigated += mitigated;
  }
  return { version: HS_SWEEP_VERSION, sweeps, totals };
}


/***/ })

};
