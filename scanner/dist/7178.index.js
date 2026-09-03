export const id = 7178;
export const ids = [7178];
export const modules = {

/***/ 7178:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   runHistory: () => (/* binding */ runHistory),
/* harmony export */   runWhatIf: () => (/* binding */ runWhatIf)
/* harmony export */ });
/* unused harmony export listHistoricalRefs */
/* harmony import */ var node_child_process__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(1421);
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(3024);
/* harmony import */ var node_path__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(6760);
/* harmony import */ var _util_git_hardening_js__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(8844);
/* harmony import */ var _engine_js__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(5591);
// Time-travel + counterfactual scanning (v0.68).
//
// Two new modes that exploit the pure-input shape of runFullScan:
//
//   1. `runHistory` — walks N historical git refs, scans each, emits a
//      per-ref timeline of finding counts + identifies findings introduced
//      and resolved between each pair of consecutive refs.
//
//   2. `runWhatIf` — overlays virtual file contents onto the working tree,
//      scans the modified state, returns delta vs. the baseline scan.
//      Useful for "what if I delete this middleware" / "what if I add this
//      new route" / "what if I downgrade this dependency."
//
// Both modes read source via `git show <ref>:<path>` and feed the byte
// content into runFullScan's fileContents map directly. No `git checkout`
// or worktree write — the user's working tree is never disturbed.







const MAX_FILES_PER_SCAN = 5000;

// `root` is the scan target's repository, not this project's own trusted
// checkout — hardened per FR-PROV-024 / the second Finding Provenance PRD
// audit (same exposure class as provenance/git-evidence.js's `_run`).
function _git(root, args) {
  const r = (0,node_child_process__WEBPACK_IMPORTED_MODULE_0__.spawnSync)('git', (0,_util_git_hardening_js__WEBPACK_IMPORTED_MODULE_3__/* .hardenGitArgs */ .Ax)(args), { cwd: root, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, env: (0,_util_git_hardening_js__WEBPACK_IMPORTED_MODULE_3__/* .hardenGitEnv */ .Si)() });
  return { ok: r.status === 0, stdout: r.stdout || '', stderr: r.stderr || '' };
}

// Enumerate refs going back `since` from HEAD at `interval` steps.
// `since`: a git-readable duration like '6.months', '30.days', '1.year'.
// `interval`: same shape; used to step backward.
function listHistoricalRefs(root, { since = '6.months', interval = '1.month' } = {}) {
  // First, get the oldest reachable commit within `since`.
  const log = _git(root, ['log', `--since=${since}`, '--format=%H %at %s']);
  if (!log.ok) return [];
  const rows = log.stdout.trim().split('\n').filter(Boolean).map(l => {
    const [sha, ts, ...subject] = l.split(' ');
    return { sha, timestamp: Number(ts), subject: subject.join(' ') };
  });
  if (rows.length === 0) return [];
  // Step backward by `interval`-equivalent timestamps. Convert interval
  // to seconds (rough: assume month=30d).
  const ivSec = _approxSeconds(interval);
  const picks = [];
  let last = rows[0].timestamp + 1; // ensure HEAD itself is included
  for (const row of rows) {
    if (row.timestamp <= last - ivSec) {
      picks.push(row);
      last = row.timestamp;
    }
  }
  // Always include HEAD as the first sample.
  return [{ sha: 'HEAD', timestamp: rows[0].timestamp, subject: rows[0].subject }, ...picks];
}

function _approxSeconds(d) {
  const m = String(d).match(/^(\d+(?:\.\d+)?)\.(seconds?|minutes?|hours?|days?|weeks?|months?|years?)$/);
  if (!m) return 30 * 86400;
  const v = Number(m[1]);
  const u = m[2];
  const mult = u.startsWith('second') ? 1
    : u.startsWith('minute') ? 60
    : u.startsWith('hour')   ? 3600
    : u.startsWith('day')    ? 86400
    : u.startsWith('week')   ? 7 * 86400
    : u.startsWith('month')  ? 30 * 86400
    : u.startsWith('year')   ? 365 * 86400
    : 86400;
  return v * mult;
}

// List all the source files at a given ref (relative paths). Filter to
// files the scanner actually processes.
function _listFilesAtRef(root, ref) {
  const r = _git(root, ['ls-tree', '-r', '--name-only', ref]);
  if (!r.ok) return [];
  return r.stdout.trim().split('\n').filter(p => {
    if (!p) return false;
    if (p.includes('/node_modules/') || p.includes('/.venv/')) return false;
    return /\.(?:js|jsx|ts|tsx|mjs|cjs|py|java|cs|kt|go|rb|php|sol|swift|rs|tf|yml|yaml|json|toml|md)$/i.test(p);
  });
}

function _readFileAtRef(root, ref, file) {
  // `--no-textconv`: this blob-cat form of `show` was verified NOT
  // reachable via a hostile textconv driver in current git — kept for
  // defense-in-depth/uniformity, same as pr-delta.js's equivalent.
  const r = _git(root, ['show', '--no-textconv', `${ref}:${file}`]);
  if (!r.ok) return null;
  return r.stdout;
}

async function _scanAtRef(root, ref) {
  const files = _listFilesAtRef(root, ref).slice(0, MAX_FILES_PER_SCAN);
  const fileContents = {};
  for (const f of files) {
    const c = _readFileAtRef(root, ref, f);
    if (c != null) fileContents[f] = c;
  }
  // `provenance:false` — this is a HISTORICAL ref, not "the state of this repo
  // right now". Two things must not happen here: resolving git provenance for
  // findings that already are a point in history (pure waste), and letting
  // updateLifecycle see this partial, historical finding set as the current
  // one — it marks every open stableId NOT in the set as `remediated`, so one
  // per-ref scan would mass-remediate the whole project's real open findings.
  const scan = await (0,_engine_js__WEBPACK_IMPORTED_MODULE_4__/* .runFullScan */ .wW)({ fileContents, scanRoot: root, provenance: false }, () => {});
  return {
    ref,
    fileCount: Object.keys(fileContents).length,
    findings: (scan.findings || []).map(_compact),
    logicVulns: (scan.logicVulns || []).length,
    secrets: (scan.secrets || []).length,
  };
}

function _compact(f) {
  return {
    stableId: f.stableId || f.id,
    file: f.file,
    line: f.line,
    vuln: f.vuln,
    severity: f.severity,
    cwe: f.cwe,
    family: f.family || null,
  };
}

// Top-level: scan each historical ref + diff consecutive snapshots.
//
// Returns:
//   {
//     refs: [{ ref, when, fileCount, findings, secretsN, logicVulnsN }],
//     timeline: [{ from, to, introduced: [...], resolved: [...] }],
//   }
async function runHistory(root, opts = {}) {
  const refs = listHistoricalRefs(root, opts);
  if (refs.length === 0) return { error: 'no-refs-in-window', refs: [], timeline: [] };
  const snapshots = [];
  for (const r of refs) {
    try {
      const s = await _scanAtRef(root, r.sha);
      snapshots.push({ ...s, when: new Date(r.timestamp * 1000).toISOString(), subject: r.subject });
    } catch (e) {
      snapshots.push({ ref: r.sha, error: e.message, when: new Date(r.timestamp * 1000).toISOString() });
    }
  }
  // Walk pairs from oldest → newest. snapshots[] is currently HEAD→old;
  // reverse so timeline reads forward in time.
  const ordered = [...snapshots].reverse();
  const timeline = [];
  for (let i = 1; i < ordered.length; i++) {
    const a = ordered[i - 1];
    const b = ordered[i];
    const idsA = new Set((a.findings || []).map(f => f.stableId));
    const idsB = new Set((b.findings || []).map(f => f.stableId));
    const introduced = (b.findings || []).filter(f => !idsA.has(f.stableId));
    const resolved   = (a.findings || []).filter(f => !idsB.has(f.stableId));
    timeline.push({
      from: a.ref, fromWhen: a.when, to: b.ref, toWhen: b.when,
      introducedN: introduced.length,
      resolvedN: resolved.length,
      introduced: introduced.slice(0, 50),
      resolved: resolved.slice(0, 50),
    });
  }
  return { refs: snapshots, timeline };
}

// Counterfactual scan: apply a virtual overlay then scan.
// overlays: [{ file, content }]
// remove: [file] — files to virtually delete (skipped from scan input)
async function runWhatIf(root, { overlays = [], remove = [] } = {}) {
  // Collect baseline working-tree files.
  const baseFiles = _walkWorkingTree(root).slice(0, MAX_FILES_PER_SCAN);
  const fileContents = {};
  const removeSet = new Set(remove);
  for (const rel of baseFiles) {
    if (removeSet.has(rel)) continue;
    try { fileContents[rel] = node_fs__WEBPACK_IMPORTED_MODULE_1__.readFileSync(node_path__WEBPACK_IMPORTED_MODULE_2__.join(root, rel), 'utf8'); } catch {}
  }
  // Apply overlays — these replace or add files.
  for (const o of overlays) {
    if (o && typeof o.file === 'string' && typeof o.content === 'string') {
      fileContents[o.file] = o.content;
    }
  }
  // Baseline (without overlays) for delta computation.
  // Both legs are hypothetical snapshots being differenced against each other,
  // never the repo's current state — `provenance:false` for the same reason as
  // _scanAtRef above (no provenance to resolve, and updateLifecycle must not
  // treat either snapshot as "what is open right now").
  const baseScan = await (0,_engine_js__WEBPACK_IMPORTED_MODULE_4__/* .runFullScan */ .wW)({ fileContents: _baselineFor(fileContents, overlays, remove, root), scanRoot: root, provenance: false }, () => {});
  const whatIfScan = await (0,_engine_js__WEBPACK_IMPORTED_MODULE_4__/* .runFullScan */ .wW)({ fileContents, scanRoot: root, provenance: false }, () => {});
  const baseIds = new Set((baseScan.findings || []).map(f => f.stableId || f.id));
  const wIds = new Set((whatIfScan.findings || []).map(f => f.stableId || f.id));
  const introduced = (whatIfScan.findings || []).filter(f => !baseIds.has(f.stableId || f.id)).map(_compact);
  const removed    = (baseScan.findings || []).filter(f => !wIds.has(f.stableId || f.id)).map(_compact);
  return {
    baselineFindings: (baseScan.findings || []).length,
    whatIfFindings: (whatIfScan.findings || []).length,
    delta: whatIfScan.findings.length - baseScan.findings.length,
    introduced,
    removed,
  };
}

function _baselineFor(fileContents, overlays, remove, root) {
  // Reverse the overlay: restore original content (from disk) for any
  // overlay'd file; re-add any virtually-removed file. Paths are resolved
  // relative to the scan root, NOT the cwd.
  const base = { ...fileContents };
  for (const o of overlays) {
    if (!o || typeof o.file !== 'string') continue;
    try { base[o.file] = node_fs__WEBPACK_IMPORTED_MODULE_1__.readFileSync(node_path__WEBPACK_IMPORTED_MODULE_2__.join(root, o.file), 'utf8'); }
    catch { delete base[o.file]; }
  }
  for (const rel of (remove || [])) {
    try { base[rel] = node_fs__WEBPACK_IMPORTED_MODULE_1__.readFileSync(node_path__WEBPACK_IMPORTED_MODULE_2__.join(root, rel), 'utf8'); } catch {}
  }
  return base;
}

function _walkWorkingTree(root) {
  const out = [];
  const exclude = new Set(['node_modules', '.git', '.venv', 'dist', 'build', '__pycache__', 'target', '.next', '.nuxt']);
  function walk(dir, rel = '') {
    let entries;
    try { entries = node_fs__WEBPACK_IMPORTED_MODULE_1__.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (exclude.has(e.name)) continue;
      const full = node_path__WEBPACK_IMPORTED_MODULE_2__.join(dir, e.name);
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory()) walk(full, r);
      else if (e.isFile() && /\.(?:js|jsx|ts|tsx|mjs|cjs|py|java|cs|kt|go|rb|php|sol|swift|rs|tf|yml|yaml|json|toml|md)$/i.test(e.name)) {
        out.push(r);
      }
    }
  }
  walk(root);
  return out;
}


/***/ })

};
