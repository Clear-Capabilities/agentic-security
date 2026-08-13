export const id = 513;
export const ids = [513,117];
export const modules = {

/***/ 3117:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   iI: () => (/* binding */ summarizeForBadge),
/* harmony export */   renderBadge: () => (/* binding */ renderBadge)
/* harmony export */ });
/* unused harmony exports badgeFromScanRoot, renderSvg, _internal */
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(3024);
/* harmony import */ var node_path__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(6760);
/* harmony import */ var _posture_state_dir_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(1174);
// Live SVG badge generator (v0.72).
//
// Every repo can drop a badge in its README pulling from the latest scan:
//
//   ![agentic-security](https://agentic-security.dev/badge?repo=<slug>)
//
// or self-hosted via the CLI subcommand emitting an inline <img> URL or
// a static SVG. The badge format borrows from shields.io for visual
// consistency. Reads from .agentic-security/last-scan.json or accepts a
// scan object directly.
//
// Output formats:
//   - 'svg'  — inline SVG string (default; the bytes you'd serve)
//   - 'json' — { label, count, color, severity } for a frontend renderer
//
// Style variants:
//   - 'flat'         — shields.io flat
//   - 'for-the-badge' — caps + thicker
//
// Color is driven by the highest non-zero severity:
//   critical → red
//   high     → orange
//   medium   → yellow
//   low      → blue
//   info     → lightgrey
//   none     → brightgreen





const COLORS = {
  critical:    '#e05d44',  // red
  high:        '#fe7d37',  // orange
  medium:      '#dfb317',  // yellow
  low:         '#007ec6',  // blue
  info:        '#9f9f9f',  // grey
  none:        '#4c1',     // brightgreen
  label:       '#555',
};

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

function _readLastScan(scanRoot) {
  if (!scanRoot) return null;
  const fp = (0,_posture_state_dir_js__WEBPACK_IMPORTED_MODULE_2__/* .statePath */ .BQ)(scanRoot, 'last-scan.json');
  if (!node_fs__WEBPACK_IMPORTED_MODULE_0__.existsSync(fp)) return null;
  try { return JSON.parse(node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(fp, 'utf8')); }
  catch { return null; }
}

function _ageString(ts) {
  if (!ts) return null;
  const ageMs = Date.now() - new Date(ts).getTime();
  if (isNaN(ageMs) || ageMs < 0) return null;
  const min = Math.floor(ageMs / 60_000);
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h ago`;
  const day = Math.floor(hr / 24);
  return `${day}d ago`;
}

/**
 * Compute the badge value from a scan object.
 *
 * Returns:
 *   {
 *     label:    'agentic-security',
 *     summary:  'critical 0 · high 2 · medium 5' | 'passing' | 'no scan',
 *     color:    '#fe7d37',
 *     highest:  'high' | 'none' | 'unknown',
 *     ageStr:   '4h ago' | null,
 *     counts:   { critical, high, medium, low, info },
 *     total:    7,
 *   }
 */
function summarizeForBadge(scan) {
  if (!scan || !Array.isArray(scan.findings)) {
    return {
      label: 'agentic-security',
      summary: 'no scan',
      color: COLORS.info,
      highest: 'unknown',
      ageStr: null,
      counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      total: 0,
    };
  }
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of scan.findings) {
    const s = f.severity || 'info';
    if (counts[s] !== undefined) counts[s]++;
  }
  let highest = 'none';
  for (const s of SEVERITIES) { if (counts[s] > 0) { highest = s; break; } }
  const color = COLORS[highest] || COLORS.info;
  const summary = highest === 'none'
    ? 'passing'
    : `crit ${counts.critical} · high ${counts.high} · med ${counts.medium}`;
  const total = SEVERITIES.reduce((a, s) => a + counts[s], 0);
  return {
    label: 'agentic-security',
    summary,
    color,
    highest,
    ageStr: _ageString(scan.timestamp || scan.when || scan.lastScan),
    counts,
    total,
  };
}

/**
 * Compute the badge from .agentic-security/last-scan.json under `scanRoot`.
 */
function badgeFromScanRoot(scanRoot) {
  return summarizeForBadge(_readLastScan(scanRoot));
}

function _xmlEscape(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function _textWidth(s) {
  // Rough character width — works fine for the small badge label range.
  return s.length * 7 + 10;
}

/**
 * Render an inline SVG matching shields.io's flat style. Self-contained
 * (no external font references) so the badge works in any README.
 */
function renderSvg(b, opts = {}) {
  if (!b) b = summarizeForBadge(null);
  const style = opts.style || 'flat';
  const labelText = b.label;
  const valueText = b.ageStr ? `${b.summary} · ${b.ageStr}` : b.summary;
  const lblW = _textWidth(labelText);
  const valW = _textWidth(valueText);
  const totalW = lblW + valW;
  const h = style === 'for-the-badge' ? 28 : 20;
  const fontSize = style === 'for-the-badge' ? 12 : 11;
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${totalW}" height="${h}" role="img" aria-label="${_xmlEscape(labelText)}: ${_xmlEscape(valueText)}">
  <title>${_xmlEscape(labelText)}: ${_xmlEscape(valueText)}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r"><rect width="${totalW}" height="${h}" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="${lblW}" height="${h}" fill="${COLORS.label}"/>
    <rect x="${lblW}" width="${valW}" height="${h}" fill="${b.color}"/>
    <rect width="${totalW}" height="${h}" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="${fontSize}">
    <text aria-hidden="true" x="${lblW / 2}" y="${h - 6}" fill="#010101" fill-opacity=".3">${_xmlEscape(labelText)}</text>
    <text x="${lblW / 2}" y="${h - 7}">${_xmlEscape(labelText)}</text>
    <text aria-hidden="true" x="${lblW + valW / 2}" y="${h - 6}" fill="#010101" fill-opacity=".3">${_xmlEscape(valueText)}</text>
    <text x="${lblW + valW / 2}" y="${h - 7}">${_xmlEscape(valueText)}</text>
  </g>
</svg>`;
}

/**
 * Public entry: produce the badge in the requested format.
 *
 *   format: 'svg' (default) | 'json'
 *   style:  'flat' (default) | 'for-the-badge'
 *   scanRoot: directory containing .agentic-security/last-scan.json
 *   scan: pre-loaded scan object (skips disk read)
 */
function renderBadge({ format = 'svg', style = 'flat', scanRoot, scan } = {}) {
  const summary = summarizeForBadge(scan || _readLastScan(scanRoot));
  if (format === 'json') {
    return JSON.stringify({
      schemaVersion: 1,
      label: summary.label,
      message: summary.summary,
      color: summary.color,
      highest: summary.highest,
      ageStr: summary.ageStr,
      counts: summary.counts,
      total: summary.total,
    });
  }
  return renderSvg(summary, { style });
}

const _internal = { COLORS, _ageString, _readLastScan };


/***/ }),

/***/ 8513:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   leaderboardRowFor: () => (/* binding */ leaderboardRowFor)
/* harmony export */ });
/* unused harmony exports rankRows, _internal */
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(3024);
/* harmony import */ var node_path__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(6760);
/* harmony import */ var _badge_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(3117);
/* harmony import */ var _posture_state_dir_js__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(1174);
// Leaderboard backend (v0.72).
//
// Generates the data shape that powers the future public leaderboard at
// agentic-security.dev/leaderboard. The leaderboard ranks repos by their
// security posture under our scanner — F1-on-CVE-history when we can
// compute it, otherwise just last-scan severity counts.
//
// Public hosting of the site is deferred — we ship the data side now so
// the future site is a thin frontend over this JSON.
//
// One leaderboard row per repo:
//
//   {
//     repo: 'owner/name',
//     score: { critical, high, medium, low, info, total },
//     postureGrade: 'A' | 'B' | 'C' | 'D' | 'F',
//     lastScanAge: '4h',
//     topCwe: 'CWE-89',
//     deltaTrend: 'improving' | 'flat' | 'regressing',
//     badgeUrl: 'https://agentic-security.dev/badge?repo=…',
//   }
//
// The grader is intentionally coarse — single letter — so the leaderboard
// stays scannable. Tie-break by lowest critical-count, then by recency.






// Grade thresholds. Critical findings dominate; high/medium contribute
// secondarily. These numbers are heuristic — calibrate against the
// public leaderboard corpus once data lands.
function _postureGrade(counts) {
  if (!counts) return 'F';
  const c = counts.critical || 0;
  const h = counts.high || 0;
  const m = counts.medium || 0;
  if (c === 0 && h === 0 && m === 0) return 'A';
  if (c === 0 && h === 0 && m <= 5)  return 'B';
  if (c === 0 && h <= 2)             return 'C';
  if (c <= 1 && h <= 5)              return 'D';
  return 'F';
}

function _ageString(ts) {
  if (!ts) return null;
  const ageMs = Date.now() - new Date(ts).getTime();
  if (isNaN(ageMs) || ageMs < 0) return null;
  const min = Math.floor(ageMs / 60_000);
  if (min < 60) return `${min}m`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h`;
  const day = Math.floor(hr / 24);
  return `${day}d`;
}

function _topCwe(scan) {
  if (!scan || !Array.isArray(scan.findings)) return null;
  const counts = new Map();
  for (const f of scan.findings) {
    if (!f.cwe) continue;
    counts.set(f.cwe, (counts.get(f.cwe) || 0) + 1);
  }
  let topCwe = null, topN = 0;
  for (const [cwe, n] of counts) {
    if (n > topN) { topCwe = cwe; topN = n; }
  }
  return topCwe;
}

function _deltaTrend(history) {
  // history: array of past scan summaries with `.timestamp` + `.severityCounts.critical`
  if (!Array.isArray(history) || history.length < 2) return 'flat';
  const recent = history.slice(-3);
  const first = recent[0].severityCounts || {};
  const last = recent[recent.length - 1].severityCounts || {};
  const fScore = (first.critical || 0) * 4 + (first.high || 0);
  const lScore = (last.critical || 0) * 4 + (last.high || 0);
  if (lScore < fScore - 1) return 'improving';
  if (lScore > fScore + 1) return 'regressing';
  return 'flat';
}

/**
 * Build a single leaderboard row for a repo. Reads the latest scan from
 * `<scanRoot>/.agentic-security/last-scan.json` and (optionally) history
 * from `<scanRoot>/.agentic-security/scan-history.jsonl`.
 *
 * `repo` is the GitHub slug ('owner/name'); used to drive the badge URL.
 */
function leaderboardRowFor({ scanRoot, repo, badgeBase = 'https://agentic-security.dev/badge' } = {}) {
  if (!repo) throw new Error('leaderboardRowFor: repo slug is required');
  const lastScanPath = (0,_posture_state_dir_js__WEBPACK_IMPORTED_MODULE_3__/* .statePath */ .BQ)(scanRoot || '.', 'last-scan.json');
  let scan = null;
  try { scan = JSON.parse(node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(lastScanPath, 'utf8')); } catch {}
  const summary = (0,_badge_js__WEBPACK_IMPORTED_MODULE_2__/* .summarizeForBadge */ .iI)(scan);
  const grade = _postureGrade(summary.counts);
  const topCwe = _topCwe(scan);

  // Optional scan history for the trend signal.
  const historyPath = (0,_posture_state_dir_js__WEBPACK_IMPORTED_MODULE_3__/* .statePath */ .BQ)(scanRoot || '.', 'scan-history.jsonl');
  let history = [];
  if (node_fs__WEBPACK_IMPORTED_MODULE_0__.existsSync(historyPath)) {
    try {
      history = node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(historyPath, 'utf8').split('\n')
        .map(l => l.trim()).filter(Boolean)
        .map(l => { try { return JSON.parse(l); } catch { return null; } })
        .filter(Boolean);
    } catch {}
  }
  const deltaTrend = _deltaTrend(history);

  return {
    repo,
    score: { ...summary.counts, total: summary.total },
    postureGrade: grade,
    lastScanAge: _ageString(scan?.timestamp || scan?.when),
    topCwe,
    deltaTrend,
    badgeUrl: `${badgeBase}?repo=${encodeURIComponent(repo)}`,
    badgeMarkdown: `![agentic-security](${badgeBase}?repo=${encodeURIComponent(repo)})`,
  };
}

/**
 * Rank a list of rows for the leaderboard. Sort by:
 *   1. lower critical count
 *   2. lower high count
 *   3. higher postureGrade (A > F)
 *   4. fresher lastScanAge
 *
 * Returns the input rows annotated with `rank` (1-indexed).
 */
function rankRows(rows) {
  if (!Array.isArray(rows)) return [];
  const gradeOrder = { A: 0, B: 1, C: 2, D: 3, F: 4 };
  const sorted = [...rows].sort((a, b) => {
    const ac = a.score?.critical || 0;
    const bc = b.score?.critical || 0;
    if (ac !== bc) return ac - bc;
    const ah = a.score?.high || 0;
    const bh = b.score?.high || 0;
    if (ah !== bh) return ah - bh;
    const ag = gradeOrder[a.postureGrade] ?? 5;
    const bg = gradeOrder[b.postureGrade] ?? 5;
    if (ag !== bg) return ag - bg;
    return 0;
  });
  return sorted.map((r, i) => ({ ...r, rank: i + 1 }));
}

const _internal = { _postureGrade, _ageString, _topCwe, _deltaTrend };


/***/ })

};
