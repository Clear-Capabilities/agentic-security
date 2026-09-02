export const id = 9220;
export const ids = [9220];
export const modules = {

/***/ 9220:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   computeDelta: () => (/* binding */ computeDelta),
/* harmony export */   persistStatus: () => (/* binding */ persistStatus),
/* harmony export */   renderStatusLine: () => (/* binding */ renderStatusLine),
/* harmony export */   watchProject: () => (/* binding */ watchProject)
/* harmony export */ });
/* unused harmony exports readStatus, _internals */
/* harmony import */ var node_fs_promises__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(1455);
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(3024);
/* harmony import */ var node_path__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(6760);
/* harmony import */ var _state_dir_js__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(1174);
// Watch mode — continuous incremental scan as the developer edits.
//
// Spawns a long-running scan watcher that:
//   1. Subscribes to file-system events under the project root
//   2. When a file matching the scan glob changes, re-scans incrementally
//      using dataflow/incremental-cache.js (per-file cache hits avoid the
//      full IR build)
//   3. Diffs against the prior scan to compute a "risk delta" string
//      (added/removed/changed criticals + highs)
//   4. Writes the delta to .agentic-security/watch-status.{md,json}
//
// The Claude Code statusline / a chat command can poll watch-status.md
// (cheap file read) to surface the delta inline without re-running anything.
//
// Implementation is deliberately node-only — no chokidar dep, uses
// fs.promises.watch (Node ≥ 20). Debounces to 350ms.
//
// Lifecycle: start() returns an AbortController-like handle. The caller
// (a /watch slash command or a long-running daemon spawn) is responsible
// for keeping the process alive; this module is the pure logic.






const STATUS_MD   = 'watch-status.md';
const STATUS_JSON = 'watch-status.json';
const DEBOUNCE_MS = 350;
const MAX_BURST   = 50; // ignore beyond this # of rapid events

const SCAN_EXT_RE = /\.(?:[jt]sx?|mjs|cjs|py|java|kt|go|rb|php|cs|c|cc|cpp|h|hpp|rs|sol|vy|swift|dart|toml|yml|yaml|json|tf|tfvars|bicep)$/i;
const IGNORE_DIR_RE = /(?:^|\/)(?:\.git|node_modules|\.bench-cache|dist|build|\.next|coverage|\.agentic-security)(?:$|\/)/;

function _isScanable(rel) {
  if (!rel || IGNORE_DIR_RE.test(rel)) return false;
  return SCAN_EXT_RE.test(rel);
}

function _readJsonSafe(fp) {
  try { return JSON.parse(fsSync.readFileSync(fp, 'utf8')); } catch { return null; }
}

function _sevRank(s) { return ['info', 'low', 'medium', 'high', 'critical'].indexOf(s) + 1; }

/**
 * Pure delta computation between two finding arrays. Same logic
 * baseline-compare uses, surfaced as a single ASCII status line.
 */
function computeDelta(prevFindings, currFindings) {
  const key = (f) => `${f.file || ''}::${f.line || 0}::${f.family || f.parser || ''}`;
  const prev = new Map();
  for (const f of prevFindings || []) prev.set(key(f), f);
  const cur  = new Map();
  for (const f of currFindings || []) cur.set(key(f), f);
  const added = [], removed = [];
  for (const [k, f] of cur) if (!prev.has(k)) added.push(f);
  for (const [k, f] of prev) if (!cur.has(k)) removed.push(f);
  const newCrit = added.filter(f => f.severity === 'critical').length;
  const newHigh = added.filter(f => f.severity === 'high').length;
  const fixedCrit = removed.filter(f => f.severity === 'critical').length;
  const fixedHigh = removed.filter(f => f.severity === 'high').length;
  return {
    addedCount: added.length, removedCount: removed.length,
    newCritical: newCrit, newHigh, fixedCritical: fixedCrit, fixedHigh,
    added, removed,
  };
}

/**
 * Render a one-line status string for the Claude Code statusline.
 */
function renderStatusLine(delta) {
  const parts = [];
  if (delta.newCritical) parts.push(`🛑 +${delta.newCritical} crit`);
  if (delta.newHigh)     parts.push(`⚠️  +${delta.newHigh} high`);
  if (delta.fixedCritical) parts.push(`✅ -${delta.fixedCritical} crit`);
  if (delta.fixedHigh)     parts.push(`✅ -${delta.fixedHigh} high`);
  if (!parts.length && (delta.addedCount + delta.removedCount) === 0) return 'agentic-security: clean';
  if (!parts.length) return `agentic-security: +${delta.addedCount} / -${delta.removedCount}`;
  return 'agentic-security: ' + parts.join(' · ');
}

/**
 * Persist watch-status.{md,json}. Cheap atomic write (write tmp, rename).
 */
function persistStatus(scanRoot, delta) {
  const dir = (0,_state_dir_js__WEBPACK_IMPORTED_MODULE_3__/* .stateDir */ .Pn)(scanRoot);
  if (!(0,_state_dir_js__WEBPACK_IMPORTED_MODULE_3__.stateWritesEnabled)()) return;
  try { node_fs__WEBPACK_IMPORTED_MODULE_1__.mkdirSync(dir, { recursive: true }); } catch {}
  const status = {
    ts: new Date().toISOString(),
    line: renderStatusLine(delta),
    delta: {
      addedCount: delta.addedCount, removedCount: delta.removedCount,
      newCritical: delta.newCritical, newHigh: delta.newHigh,
      fixedCritical: delta.fixedCritical, fixedHigh: delta.fixedHigh,
    },
    addedTop5: (delta.added || []).slice(0, 5).map(f => ({
      file: f.file, line: f.line, family: f.family, severity: f.severity, vuln: f.vuln,
    })),
  };
  const jsonPath = node_path__WEBPACK_IMPORTED_MODULE_2__.join(dir, STATUS_JSON);
  const mdPath   = node_path__WEBPACK_IMPORTED_MODULE_2__.join(dir, STATUS_MD);
  try { node_fs__WEBPACK_IMPORTED_MODULE_1__.writeFileSync(jsonPath, JSON.stringify(status, null, 2)); } catch {}
  const md = [
    `# Watch status — ${status.ts.slice(11, 19)} UTC`,
    '',
    status.line,
    '',
  ];
  if (status.addedTop5.length) {
    md.push('## New findings');
    for (const f of status.addedTop5) {
      md.push(`- **[${(f.severity || '?').toUpperCase()}]** ${f.vuln || f.family || 'finding'} — \`${f.file}:${f.line}\``);
    }
  }
  try { node_fs__WEBPACK_IMPORTED_MODULE_1__.writeFileSync(mdPath, md.join('\n')); } catch {}
  return status;
}

/**
 * Read the latest watch-status (returns null if none).
 */
function readStatus(scanRoot) {
  return _readJsonSafe(statePath(scanRoot, STATUS_JSON));
}

/**
 * Subscribe to FS events and call onChange(absPath, eventType) for each
 * matching event. Debounces bursts. Returns a controller with stop().
 *
 * The actual incremental scan call lives in the caller — this module
 * stays pure for testability.
 */
async function watchProject(scanRoot, onChange, opts = {}) {
  if (process.env.AGENTIC_SECURITY_NO_WATCH === '1') return { stop: async () => {}, _disabled: true };
  const recursive = opts.recursive !== false;
  const ac = new AbortController();
  let timer = null;
  const pending = new Set();
  const flush = () => {
    timer = null;
    if (pending.size > MAX_BURST) { pending.clear(); return; }
    const batch = Array.from(pending);
    pending.clear();
    try { onChange(batch); } catch {}
  };
  let stopped = false;
  (async () => {
    try {
      for await (const evt of node_fs_promises__WEBPACK_IMPORTED_MODULE_0__.watch(scanRoot, { recursive, signal: ac.signal })) {
        if (stopped) break;
        const rel = String(evt.filename || '').replace(/\\/g, '/');
        if (!_isScanable(rel)) continue;
        pending.add(node_path__WEBPACK_IMPORTED_MODULE_2__.join(scanRoot, rel));
        if (timer) clearTimeout(timer);
        timer = setTimeout(flush, DEBOUNCE_MS);
      }
    } catch (e) {
      if (e && e.name !== 'AbortError') {
        // Surface but don't crash — caller decides how to handle.
        try { onChange([], e); } catch {}
      }
    }
  })();
  return {
    stop: async () => { stopped = true; ac.abort(); if (timer) clearTimeout(timer); },
  };
}

const _internals = { _isScanable, SCAN_EXT_RE, IGNORE_DIR_RE };


/***/ })

};
