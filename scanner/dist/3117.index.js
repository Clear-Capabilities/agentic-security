export const id = 3117;
export const ids = [3117];
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


/***/ })

};
