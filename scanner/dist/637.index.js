export const id = 637;
export const ids = [637];
export const modules = {

/***/ 5637:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   computePrDelta: () => (/* binding */ computePrDelta),
/* harmony export */   netNewGate: () => (/* binding */ netNewGate),
/* harmony export */   renderPrDeltaText: () => (/* binding */ renderPrDeltaText)
/* harmony export */ });
/* harmony import */ var node_child_process__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(1421);
/* harmony import */ var _engine_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(7691);
// Shadowscan / security-DELTA on PR (v0.72).
//
// Most SAST PR-comment integrations show absolute counts — "12 findings
// detected in changed files." Engineers can't act on that: 11 of those
// 12 already existed before they touched the file. They want a DELTA:
// what did THIS PR introduce, what did it remove, what changed.
//
// This module diffs two scans (PR branch vs base) by stableId and emits
// both a JSON delta and a human-readable summary suitable for embedding
// in a PR comment. Reuses the existing `history-scan.js` machinery for
// the at-ref scans.
//
// Algorithm:
//   1. Scan the base ref (in-memory via runFullScan, no checkout)
//   2. Scan the head ref (same way)
//   3. Key findings by stableId
//   4. Emit:
//        - introduced: findings in head not in base
//        - resolved:   findings in base not in head
//        - persistent: findings in both (changed severity/cwe → 'shifted')
//   5. Severity-summary counts each side
//
// Output shape stays stable so downstream renderers (advisor-tone PR
// comment) can transform without re-walking IR.




const FILE_EXT_RE = /\.(?:js|jsx|ts|tsx|mjs|cjs|py|java|cs|kt|go|rb|php|sol|swift|rs|tf|yml|yaml|json|toml|md)$/i;
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

function _git(root, args) {
  const r = (0,node_child_process__WEBPACK_IMPORTED_MODULE_0__.spawnSync)('git', args, { cwd: root, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  return { ok: r.status === 0, stdout: r.stdout || '', stderr: r.stderr || '' };
}

function _readFileAtRef(root, ref, file) {
  const r = _git(root, ['show', `${ref}:${file}`]);
  return r.ok ? r.stdout : null;
}

function _listFilesAtRef(root, ref) {
  const r = _git(root, ['ls-tree', '-r', '--name-only', ref]);
  if (!r.ok) return [];
  return r.stdout.trim().split('\n').filter(p => {
    if (!p) return false;
    if (p.includes('/node_modules/') || p.includes('/.venv/')) return false;
    return FILE_EXT_RE.test(p);
  });
}

async function _scanAtRef(root, ref) {
  const files = _listFilesAtRef(root, ref);
  const fileContents = {};
  for (const f of files) {
    const c = _readFileAtRef(root, ref, f);
    if (c != null) fileContents[f] = c;
  }
  // `provenance:false` — a base-ref snapshot, not the current working state.
  // Beyond the wasted git walks, updateLifecycle marks every open stableId
  // absent from the finding set it is handed as `remediated`; running the PR
  // delta gate would silently rewrite the project's lifecycle store from the
  // base ref's findings.
  return (0,_engine_js__WEBPACK_IMPORTED_MODULE_1__/* .runFullScan */ .wW)({ fileContents, scanRoot: root, provenance: false }, () => {});
}

function _summary(findings) {
  const out = { total: 0 };
  for (const s of SEVERITIES) out[s] = 0;
  for (const f of (findings || [])) {
    const s = f.severity || 'info';
    if (out[s] !== undefined) out[s]++;
    out.total++;
  }
  return out;
}

function _changedFiles(root, baseRef, headRef) {
  const r = _git(root, ['diff', '--name-only', `${baseRef}...${headRef}`]);
  if (!r.ok) return new Set();
  return new Set(r.stdout.trim().split('\n').filter(Boolean));
}

/**
 * Top-level entry: compute the delta between two refs.
 *
 *   root:     scan root (a git repo)
 *   baseRef:  the ref to compare against (e.g. main, origin/main)
 *   headRef:  the ref to score (e.g. HEAD, the PR branch). Defaults HEAD.
 *
 * Returns:
 *   {
 *     baseRef, headRef,
 *     changedFiles: [...],          // git diff --name-only base...head
 *     base:        { findings, summary, secrets, supplyChain, logicVulns },
 *     head:        { findings, summary, secrets, supplyChain, logicVulns },
 *     introduced:  Finding[],       // new in head only
 *     resolved:    Finding[],       // removed from base
 *     persistent:  Finding[],       // same stableId in both (no semantic change)
 *     shifted:     Finding[],       // same stableId, severity OR cwe changed
 *     summary:     { introduced: SeveritySummary, resolved, persistent, net },
 *   }
 *
 * `net` is per-severity (head − base). A negative critical count means
 * the PR resolved a critical finding overall.
 */
async function computePrDelta(root, { baseRef, headRef = 'HEAD' } = {}) {
  if (!baseRef) throw new Error('computePrDelta: baseRef is required');
  const changedFiles = [..._changedFiles(root, baseRef, headRef)];
  const baseScan = await _scanAtRef(root, baseRef);
  const headScan = await _scanAtRef(root, headRef);
  const baseById = new Map();
  const headById = new Map();
  for (const f of (baseScan.findings || [])) {
    const k = f.stableId || f.id;
    if (k) baseById.set(k, f);
  }
  for (const f of (headScan.findings || [])) {
    const k = f.stableId || f.id;
    if (k) headById.set(k, f);
  }
  const introduced = [];
  const resolved = [];
  const persistent = [];
  const shifted = [];
  for (const [k, f] of headById) {
    if (!baseById.has(k)) introduced.push(f);
    else {
      const base = baseById.get(k);
      if (base.severity !== f.severity || base.cwe !== f.cwe) {
        shifted.push({ from: base, to: f });
      } else {
        persistent.push(f);
      }
    }
  }
  for (const [k, f] of baseById) {
    if (!headById.has(k)) resolved.push(f);
  }
  // Net severity (head − base).
  const net = {};
  const baseSummary = _summary(baseScan.findings || []);
  const headSummary = _summary(headScan.findings || []);
  for (const s of [...SEVERITIES, 'total']) net[s] = (headSummary[s] || 0) - (baseSummary[s] || 0);
  return {
    baseRef, headRef,
    changedFiles,
    base: {
      findings: baseScan.findings || [],
      summary: baseSummary,
      secrets: baseScan.secrets || [],
      supplyChain: baseScan.supplyChain || [],
      logicVulns: baseScan.logicVulns || [],
    },
    head: {
      findings: headScan.findings || [],
      summary: headSummary,
      secrets: headScan.secrets || [],
      supplyChain: headScan.supplyChain || [],
      logicVulns: headScan.logicVulns || [],
    },
    introduced,
    resolved,
    persistent,
    shifted,
    summary: {
      introduced: _summary(introduced),
      resolved: _summary(resolved),
      persistent: _summary(persistent),
      net,
    },
  };
}

/**
 * Lightweight text summary used as a CLI fallback when --json isn't set.
 */
// R24 (PRD §5) — net-new CI gate. Blocks the build ONLY on findings the PR
// INTRODUCED (delta.introduced), at or above `failOn` severity — never on the
// pre-existing backlog. This is the only SAST CI posture teams tolerate
// long-term. Pure + deterministic: takes a delta, returns the gate decision.
const _NETNEW_SEV_RANK = { critical: 3, high: 2, medium: 1, low: 0, info: -1 };
function netNewGate(delta, failOn = 'critical') {
  const introduced = (delta && Array.isArray(delta.introduced)) ? delta.introduced : [];
  if (failOn === 'none') return { fail: false, failOn, introducedCount: introduced.length, blocked: [] };
  const threshold = _NETNEW_SEV_RANK[failOn] ?? 3;
  const blocked = introduced.filter((f) => (_NETNEW_SEV_RANK[f.severity] ?? -1) >= threshold);
  return { fail: blocked.length > 0, failOn, introducedCount: introduced.length, blocked };
}

function renderPrDeltaText(delta) {
  const i = delta.summary.introduced;
  const r = delta.summary.resolved;
  const lines = [];
  lines.push(`Delta: ${delta.baseRef} → ${delta.headRef}`);
  lines.push(`Changed files: ${delta.changedFiles.length}`);
  lines.push('');
  if (delta.introduced.length === 0 && delta.resolved.length === 0 && delta.shifted.length === 0) {
    lines.push('No security delta. Safe to merge.');
    return lines.join('\n');
  }
  lines.push(`Introduced: ${delta.introduced.length}  ` +
    `(crit ${i.critical} · high ${i.high} · med ${i.medium} · low ${i.low})`);
  lines.push(`Resolved:   ${delta.resolved.length}  ` +
    `(crit ${r.critical} · high ${r.high} · med ${r.medium} · low ${r.low})`);
  if (delta.shifted.length) lines.push(`Shifted:    ${delta.shifted.length}`);
  if (delta.introduced.length) {
    lines.push('');
    lines.push('Newly introduced:');
    for (const f of delta.introduced.slice(0, 20)) {
      lines.push(`  + ${f.severity.padEnd(8)} ${f.cwe || ''} ${f.vuln} (${f.file}:${f.line})`);
    }
    if (delta.introduced.length > 20) lines.push(`  … ${delta.introduced.length - 20} more`);
  }
  return lines.join('\n');
}


/***/ })

};
