export const id = 7227;
export const ids = [7227];
export const modules = {

/***/ 7227:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   evaluatePolicy: () => (/* binding */ evaluatePolicy)
/* harmony export */ });
/* unused harmony export _internals */
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(3024);
/* harmony import */ var node_child_process__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(1421);
// Policy-as-code gate (FR-SDLC-9).
//
// Today's CI gate is `--fail-on <severity>`. That's coarse. Customers want
// to write nuanced rules: "fail if any sql-injection finding has
// confidence ≥ 0.8 AND the file is under src/api/", or "fail if total
// exploitability score across critical findings exceeds 5".
//
// We support two modes:
//
//   1. EXTERNAL OPA: if the `opa` binary is on PATH and `--policy <file.rego>`
//      is supplied, we shell out to `opa eval -d <file> -i <findings.json>
//      "data.<package>.deny"`. This is the right answer for customers who
//      already use OPA elsewhere.
//
//   2. EMBEDDED MINI: when no opa binary is available, fall back to a tiny
//      DSL that's a strict subset of rego. Rules read top-level
//      `package`/`deny` blocks; each `deny` is a JS-evaluable expression
//      over findings[]. This lets the v1 ship without an external binary
//      dep while documenting the upgrade path.




// ─── External OPA ─────────────────────────────────────────────────────────

function _haveOpa() {
  try {
    const r = (0,node_child_process__WEBPACK_IMPORTED_MODULE_1__.spawnSync)('opa', ['version'], { stdio: 'ignore', timeout: 3000 });
    return r.status === 0;
  } catch { return false; }
}

function _runOpa(policyFile, findingsJsonPath, packageName) {
  const r = (0,node_child_process__WEBPACK_IMPORTED_MODULE_1__.spawnSync)('opa', [
    'eval', '-d', policyFile, '-i', findingsJsonPath,
    `data.${packageName}.deny`,
  ], { encoding: 'utf8', timeout: 10_000 });
  if (r.error) return { ok: false, reason: `opa-error:${r.error.code || r.error.message}` };
  if (r.status !== 0) return { ok: false, reason: `opa-exit:${r.status}`, stderr: r.stderr };
  try {
    const parsed = JSON.parse(r.stdout);
    const result = parsed.result?.[0]?.expressions?.[0]?.value;
    return { ok: true, denials: Array.isArray(result) ? result : [] };
  } catch (e) {
    return { ok: false, reason: `opa-output-parse:${e.message}` };
  }
}

// ─── Embedded mini DSL ────────────────────────────────────────────────────
//
// Rego is too big to reimplement. We support a tiny shape:
//
//   # POLICY: agentic-security policy-gate v1
//   deny[msg] {
//     finding := input.findings[_]
//     finding.severity == "critical"
//     msg := sprintf("critical finding: %v at %v", [finding.vuln, finding.file])
//   }
//
// Parser strategy: extract each `deny[msg] { ... }` block; translate the
// body to a JS predicate. The grammar we accept is:
//
//   - `<lhs> == <value>` / `<lhs> != <value>` / `<lhs> > <num>` / `<lhs> < <num>`
//   - `<lhs>` references `finding.<field>` or `input.<field>`
//   - `msg := "..."` or `msg := sprintf("...", [args])` — the msg literal
//   - newlines + `;` as separators
//
// Anything more complex requires the external OPA binary.

function _parseEmbedded(policyText) {
  const blocks = [];
  // Match each `deny[NAME] { ... }` block (or `deny { ... }`).
  const blockRe = /\bdeny(?:\s*\[\s*(\w+)\s*\])?\s*\{([\s\S]*?)\}/g;
  let m;
  while ((m = blockRe.exec(policyText))) {
    const body = m[2];
    const conditions = [];
    let msgExpr = `"policy violation"`;
    for (const line of body.split(/[\n;]/)) {
      const ln = line.trim();
      if (!ln || ln.startsWith('#')) continue;
      // Assignment: `<id> := <expr>`
      const asn = ln.match(/^(\w+)\s*:=\s*(.+)$/);
      if (asn && asn[1] !== 'msg') continue;  // skip non-msg assignments
      if (asn && asn[1] === 'msg') { msgExpr = asn[2].trim(); continue; }
      // Comparison: `finding.<field> <op> <value>`
      const cmp = ln.match(/^(finding|input)\.([a-zA-Z_][\w.]*)\s*(==|!=|<=|>=|<|>)\s*(.+)$/);
      if (!cmp) continue;
      const [, scope, field, op, valueRaw] = cmp;
      let value = valueRaw.trim();
      if (/^".*"$/.test(value)) value = JSON.stringify(value.slice(1, -1));
      conditions.push({ scope, field, op, value });
    }
    blocks.push({ conditions, msgExpr });
  }
  return blocks;
}

function _evalBlock(block, finding) {
  for (const c of block.conditions) {
    const lhs = _resolvePath(finding, c.field);
    let rhs;
    try { rhs = JSON.parse(c.value); }
    catch { rhs = c.value.replace(/^"|"$/g, ''); }
    if (c.op === '==' && lhs !==  rhs) return null;
    if (c.op === '!=' && lhs === rhs) return null;
    if (c.op === '>'  && !(Number(lhs)  > Number(rhs))) return null;
    if (c.op === '<'  && !(Number(lhs)  < Number(rhs))) return null;
    if (c.op === '>=' && !(Number(lhs) >= Number(rhs))) return null;
    if (c.op === '<=' && !(Number(lhs) <= Number(rhs))) return null;
  }
  return _renderMsg(block.msgExpr, finding);
}

function _resolvePath(obj, dotPath) {
  return dotPath.split('.').reduce((o, k) => (o == null ? undefined : o[k]), obj);
}

function _renderMsg(expr, finding) {
  // Strip outer quotes if string literal.
  const m = expr.match(/^["'](.+)["']$/);
  if (m) return m[1];
  // sprintf shape: sprintf("...", [a, b])
  const sf = expr.match(/^sprintf\s*\(\s*"([^"]+)"\s*,\s*\[(.+)\]\s*\)$/);
  if (sf) {
    const fmt = sf[1];
    const args = sf[2].split(',').map(s => _resolvePath(finding, s.trim().replace(/^finding\./, '')));
    let i = 0;
    return fmt.replace(/%v/g, () => String(args[i++] ?? ''));
  }
  return expr;
}

function _runEmbedded(policyText, findings) {
  const blocks = _parseEmbedded(policyText);
  const denials = [];
  for (const f of findings) {
    for (const b of blocks) {
      const msg = _evalBlock(b, f);
      if (msg) denials.push(msg);
    }
  }
  return { ok: true, denials };
}

// ─── Public API ────────────────────────────────────────────────────────────

/**
 * Evaluate a policy file against the findings list.
 * Returns { ok, denials, runner } — denials is an array of human-readable
 * strings (one per violation). When denials.length > 0, the gate fails.
 */
function evaluatePolicy(policyPath, findings, opts = {}) {
  if (!policyPath || !node_fs__WEBPACK_IMPORTED_MODULE_0__.existsSync(policyPath)) {
    return { ok: false, reason: 'policy-file-missing' };
  }
  const policyText = node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(policyPath, 'utf8');
  const useExternal = !opts.embeddedOnly && _haveOpa();
  if (useExternal) {
    // Write findings to a temp file the opa binary reads.
    const tmp = `/tmp/as-policy-${Date.now()}.json`;
    node_fs__WEBPACK_IMPORTED_MODULE_0__.writeFileSync(tmp, JSON.stringify({ findings }));
    const pkgMatch = policyText.match(/^\s*package\s+([\w.]+)/m);
    const pkg = pkgMatch ? pkgMatch[1] : 'main';
    const r = _runOpa(policyPath, tmp, pkg);
    try { node_fs__WEBPACK_IMPORTED_MODULE_0__.unlinkSync(tmp); } catch {}
    if (r.ok) return { ...r, runner: 'opa' };
    // Fall through to embedded on opa error.
  }
  const r = _runEmbedded(policyText, findings);
  return { ...r, runner: 'embedded' };
}

const _internals = { _parseEmbedded, _evalBlock, _runEmbedded };


/***/ })

};
