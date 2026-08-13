export const id = 675;
export const ids = [675];
export const modules = {

/***/ 6675:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   runOnce: () => (/* binding */ runOnce)
/* harmony export */ });
/* unused harmony exports readDeps, _queryOsvForDep, loadState, persistState, loadConfig, formatPayload, _internals */
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(3024);
/* harmony import */ var node_path__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(6760);
/* harmony import */ var _state_dir_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(1174);
// Continuous CVE-watch daemon.
//
// Polls OSV for the project's dependency tree on a schedule (or one-shot),
// diffs new advisories against state, fires the configured webhook on each
// new ID. Multi-ecosystem: reads npm / pip / cargo / gem / pub / composer /
// go.mod / maven manifests via the same DEP_FILE_NAMES list runScan uses.
//
// Why this exists separately from `/scan --sca`:
//   - `/scan` is interactive; this runs unattended, daily, in a cron / GitHub Action.
//   - `/scan` reports the FULL set of advisories for the tree; this reports
//     only the DELTA since the last run.
//   - This produces a webhook fire, not a console report.
//
// Configuration is read from `.agentic-security/cve-alerts.json`:
//   {
//     "alertUrl":  "https://hooks.slack.com/services/...",
//     "alertType": "slack" | "discord" | "generic",
//     "minSeverity": "low" | "medium" | "high" | "critical"   (optional)
//   }
//
// State is persisted to `.agentic-security/cve-alerts-state.json`:
//   { "known": ["CVE-2024-1234", "GHSA-...", ...], "lastRun": "2026-…" }
//
// The daemon NEVER fires a webhook for an advisory ID it has already seen;
// the state file is the deduplication primitive.





const OSV_API = 'https://api.osv.dev/v1/query';


// Multi-ecosystem dep extraction. Each entry: { manifest filename → ecosystem }
const ECOSYSTEM_BY_MANIFEST = {
  'package.json':    'npm',
  'requirements.txt':'PyPI',
  'pyproject.toml':  'PyPI',
  'Pipfile':         'PyPI',
  'Pipfile.lock':    'PyPI',
  'poetry.lock':     'PyPI',
  'Gemfile':         'RubyGems',
  'Gemfile.lock':    'RubyGems',
  'go.mod':          'Go',
  'go.sum':          'Go',
  'Cargo.toml':      'crates.io',
  'Cargo.lock':      'crates.io',
  'composer.json':   'Packagist',
  'composer.lock':   'Packagist',
  'pom.xml':         'Maven',
  'build.gradle':    'Maven',
  'build.gradle.kts':'Maven',
  'pubspec.yaml':    'Pub',
  'pubspec.lock':    'Pub',
};

// ─── Manifest readers ─────────────────────────────────────────────────────

function _readPackageJson(content) {
  try {
    const j = JSON.parse(content);
    return [
      ...Object.keys(j.dependencies || {}),
      ...Object.keys(j.devDependencies || {}),
      ...Object.keys(j.peerDependencies || {}),
      ...Object.keys(j.optionalDependencies || {}),
    ];
  } catch { return []; }
}

function _readRequirementsTxt(content) {
  // Each non-blank, non-comment line is "pkg" or "pkg==1.2.3" or "pkg>=1.2".
  const out = [];
  for (const raw of content.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#') || line.startsWith('-')) continue;
    const m = /^([A-Za-z0-9_.\-]+)/.exec(line);
    if (m) out.push(m[1]);
  }
  return out;
}

function _readPyprojectToml(content) {
  // We don't ship a TOML parser; do a best-effort line scan for the common
  // dep-table shapes. Caller is OK if this misses some — the full SCA scan
  // does the heavy lifting.
  const out = new Set();
  // PEP 621 [project] dependencies = ["foo", "bar>=1.0"]
  // Poetry [tool.poetry.dependencies] foo = "^1.0"
  let inDeps = false;
  for (const raw of content.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    if (/^\[(?:tool\.poetry\.)?(?:dev-)?dependencies\]/i.test(line) || /^\[project\.optional-dependencies\.[^\]]+\]/.test(line)) {
      inDeps = true; continue;
    }
    if (/^\[[^\]]+\]/.test(line)) { inDeps = false; continue; }
    // Inline "dependencies = [...]" form within [project]
    const inline = /dependencies\s*=\s*\[([^\]]+)\]/i.exec(line);
    if (inline) {
      for (const item of inline[1].split(',')) {
        const m = /^[\s"']*([A-Za-z0-9_.\-]+)/.exec(item);
        if (m) out.add(m[1]);
      }
    }
    if (inDeps) {
      const m = /^([A-Za-z0-9_.\-]+)\s*=/.exec(line);
      if (m && m[1] !== 'python') out.add(m[1]);
    }
  }
  return [...out];
}

function _readGemfile(content) {
  const out = [];
  for (const raw of content.split('\n')) {
    const m = /^\s*gem\s+['"]([^'"]+)['"]/.exec(raw);
    if (m) out.push(m[1]);
  }
  return out;
}

function _readGoMod(content) {
  const out = [];
  let inRequire = false;
  for (const raw of content.split('\n')) {
    const line = raw.trim();
    if (line.startsWith('require (')) { inRequire = true; continue; }
    if (inRequire && line === ')') { inRequire = false; continue; }
    if (inRequire || line.startsWith('require ')) {
      // "require module/path v1.2.3" or just "module/path v1.2.3" inside block
      const m = /(?:require\s+)?([A-Za-z0-9_./\-]+)\s+v/.exec(line);
      if (m) out.push(m[1]);
    }
  }
  return out;
}

function _readCargoToml(content) {
  // Lines under [dependencies] / [dev-dependencies] / [build-dependencies]
  // shaped as `pkg = "1.0"` or `pkg = { … }`.
  const out = new Set();
  let inDeps = false;
  for (const raw of content.split('\n')) {
    const line = raw.trim();
    if (/^\[(?:dev-|build-)?dependencies\]/.test(line)) { inDeps = true; continue; }
    if (/^\[[^\]]+\]/.test(line)) { inDeps = false; continue; }
    if (inDeps) {
      const m = /^([A-Za-z0-9_\-]+)\s*=/.exec(line);
      if (m) out.add(m[1]);
    }
  }
  return [...out];
}

function _readComposerJson(content) {
  try {
    const j = JSON.parse(content);
    return [
      ...Object.keys(j.require || {}).filter(k => k !== 'php'),
      ...Object.keys(j['require-dev'] || {}).filter(k => k !== 'php'),
    ];
  } catch { return []; }
}

function _readMavenLikeXml(content) {
  // crude <artifactId>x</artifactId> extraction. Misses parent POM inheritance;
  // for full coverage the /scan --sca path is the right tool.
  const out = [];
  const re = /<artifactId>\s*([^<\s]+)\s*<\/artifactId>/g;
  let m;
  while ((m = re.exec(content)) !== null) out.push(m[1]);
  return out;
}

function _readPubspecYaml(content) {
  const out = new Set();
  let inDeps = false;
  for (const raw of content.split('\n')) {
    const line = raw.trimEnd();
    if (/^(dev_|)dependencies\s*:/i.test(line)) { inDeps = true; continue; }
    if (line && !line.startsWith(' ') && !line.startsWith('\t')) {
      // top-level key other than dependencies / dev_dependencies
      if (!/^(dev_|)dependencies\s*:/i.test(line)) inDeps = false;
    }
    if (inDeps) {
      const m = /^\s+([A-Za-z0-9_]+)\s*:/.exec(line);
      if (m && m[1] !== 'sdk' && m[1] !== 'flutter') out.add(m[1]);
    }
  }
  return [...out];
}

const MANIFEST_READERS = {
  'package.json': _readPackageJson,
  'requirements.txt': _readRequirementsTxt,
  'pyproject.toml': _readPyprojectToml,
  'Pipfile': _readPyprojectToml,           // close-enough shape
  'Gemfile': _readGemfile,
  'go.mod': _readGoMod,
  'Cargo.toml': _readCargoToml,
  'composer.json': _readComposerJson,
  'pom.xml': _readMavenLikeXml,
  'build.gradle': _readMavenLikeXml,
  'build.gradle.kts': _readMavenLikeXml,
  'pubspec.yaml': _readPubspecYaml,
};

function readDeps(scanRoot) {
  // Walks the scan root looking for known manifest files. Returns a flat
  // [{name, ecosystem}, ...] list; deduplicated across manifests so a
  // package in both package.json and yarn.lock isn't queried twice.
  const seen = new Set();
  const out = [];
  function walk(dir, depth) {
    if (depth > 4) return;   // shallow walk; manifests live near the root
    let entries;
    try { entries = node_fs__WEBPACK_IMPORTED_MODULE_0__.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (e.name.startsWith('.') && e.name !== '.gradle') continue;
      if (e.name === 'node_modules' || e.name === 'venv' || e.name === '__pycache__'
          || e.name === 'vendor' || e.name === 'dist' || e.name === 'build'
          || e.name === 'target') continue;
      const fp = node_path__WEBPACK_IMPORTED_MODULE_1__.join(dir, e.name);
      if (e.isDirectory()) { walk(fp, depth + 1); continue; }
      if (!ECOSYSTEM_BY_MANIFEST[e.name]) continue;
      let content;
      try { content = node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(fp, 'utf8'); } catch { continue; }
      const reader = MANIFEST_READERS[e.name];
      if (!reader) continue;
      const ecosystem = ECOSYSTEM_BY_MANIFEST[e.name];
      for (const name of reader(content)) {
        const key = `${ecosystem}::${name}`;
        if (seen.has(key)) continue;
        seen.add(key);
        out.push({ name, ecosystem });
      }
    }
  }
  walk(scanRoot, 0);
  return out;
}

// ─── OSV query ────────────────────────────────────────────────────────────

async function _queryOsvForDep({ name, ecosystem }, { fetchImpl = globalThis.fetch, timeoutMs = 4000 } = {}) {
  // POST { package: { name, ecosystem } } — returns the full vulnerability
  // list for the package (any version). The daemon doesn't filter by version
  // because we treat "new advisory ID" as the signal, not "your installed
  // version is affected" — that's what /scan --sca produces.
  try {
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), timeoutMs);
    const res = await fetchImpl(OSV_API, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ package: { name, ecosystem } }),
      signal: controller.signal,
    });
    clearTimeout(t);
    if (!res.ok) return [];
    const j = await res.json();
    return Array.isArray(j.vulns) ? j.vulns : [];
  } catch { return []; }
}

// ─── State persistence ───────────────────────────────────────────────────

function loadState(scanRoot) {
  const fp = (0,_state_dir_js__WEBPACK_IMPORTED_MODULE_2__/* .statePath */ .BQ)(scanRoot, 'cve-alerts-state.json');
  if (!node_fs__WEBPACK_IMPORTED_MODULE_0__.existsSync(fp)) return { known: new Set(), lastRun: null };
  try {
    const j = JSON.parse(node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(fp, 'utf8'));
    return { known: new Set(j.known || []), lastRun: j.lastRun || null };
  } catch { return { known: new Set(), lastRun: null }; }
}

function persistState(scanRoot, state) {
  const fp = (0,_state_dir_js__WEBPACK_IMPORTED_MODULE_2__/* .statePath */ .BQ)(scanRoot, 'cve-alerts-state.json');
  if (!(0,_state_dir_js__WEBPACK_IMPORTED_MODULE_2__.stateWritesEnabled)()) return;
  node_fs__WEBPACK_IMPORTED_MODULE_0__.mkdirSync(node_path__WEBPACK_IMPORTED_MODULE_1__.dirname(fp), { recursive: true });
  node_fs__WEBPACK_IMPORTED_MODULE_0__.writeFileSync(fp, JSON.stringify({
    known: [...state.known].sort(),
    lastRun: state.lastRun,
  }, null, 2));
}

function loadConfig(scanRoot) {
  const fp = (0,_state_dir_js__WEBPACK_IMPORTED_MODULE_2__/* .statePath */ .BQ)(scanRoot, 'cve-alerts.json');
  if (!node_fs__WEBPACK_IMPORTED_MODULE_0__.existsSync(fp)) return null;
  try { return JSON.parse(node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(fp, 'utf8')); } catch { return null; }
}

// ─── Webhook formatting ──────────────────────────────────────────────────

function _truncate(s, n) { s = String(s || ''); return s.length > n ? s.slice(0, n) + '…' : s; }

function formatPayload(alertType, newAdvisories) {
  // alertType: 'slack' | 'discord' | 'generic'
  // Slack and Discord both accept `{ text }` for simple messages.
  const lines = newAdvisories.slice(0, 10).map(a =>
    `• \`${a.ecosystem}:${a.pkg}\` — ${a.id} (${a.severity || 'unknown'})${a.summary ? ' — ' + _truncate(a.summary, 100) : ''}`
  );
  const overflow = newAdvisories.length > 10 ? `\n+${newAdvisories.length - 10} more` : '';
  const text = `🚨 *New CVEs in your dependencies* (${newAdvisories.length})\n` + lines.join('\n') + overflow + '\n\nRun `/scan --all` to assess impact.';
  if (alertType === 'slack' || alertType === 'discord') return { text };
  // Generic webhook: full structured payload.
  return { event: 'new_cve', count: newAdvisories.length, advisories: newAdvisories };
}

async function _post(url, payload, { fetchImpl = globalThis.fetch, timeoutMs = 4000 } = {}) {
  try {
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), timeoutMs);
    const res = await fetchImpl(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });
    clearTimeout(t);
    return { ok: res.ok, status: res.status };
  } catch (e) { return { ok: false, error: String(e?.message || e).slice(0, 200) }; }
}

// ─── Severity filter ─────────────────────────────────────────────────────

const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, unknown: 0 };

function _normalizeSeverity(vuln) {
  // OSV severity has a few possible shapes. Best-effort.
  const dbSpec = vuln.database_specific?.severity || '';
  if (/critical/i.test(dbSpec)) return 'critical';
  if (/high/i.test(dbSpec)) return 'high';
  if (/medium|moderate/i.test(dbSpec)) return 'medium';
  if (/low/i.test(dbSpec)) return 'low';
  // CVSS score
  const score = vuln.severity?.[0]?.score;
  if (typeof score === 'number') {
    if (score >= 9) return 'critical';
    if (score >= 7) return 'high';
    if (score >= 4) return 'medium';
    return 'low';
  }
  return 'unknown';
}

// ─── Main entry — runOnce ───────────────────────────────────────────────

async function runOnce(scanRoot, opts = {}) {
  // opts: { alertUrl, alertType, minSeverity, dryRun, offline, fetchImpl,
  //         logger, throttleMs }
  const log = opts.logger || ((msg) => process.stderr.write(msg + '\n'));
  const cfg = loadConfig(scanRoot);
  const alertUrl = opts.alertUrl || cfg?.alertUrl || process.env.CVE_ALERT_URL;
  const alertType = opts.alertType || cfg?.alertType || 'slack';
  const minSeverity = opts.minSeverity || cfg?.minSeverity || 'low';
  const dryRun = !!opts.dryRun;
  const offline = !!opts.offline || process.env.AGENTIC_SECURITY_OFFLINE === '1';
  const fetchImpl = opts.fetchImpl || globalThis.fetch;
  const throttleMs = typeof opts.throttleMs === 'number' ? opts.throttleMs : 50;

  if (offline && !dryRun) {
    return { ok: false, reason: 'offline-mode-set' };
  }
  if (typeof fetchImpl !== 'function') {
    return { ok: false, reason: 'fetch-unavailable' };
  }

  const deps = readDeps(scanRoot);
  if (deps.length === 0) {
    return { ok: true, depsChecked: 0, newAdvisories: [], alertSent: false, reason: 'no-deps-found' };
  }

  const state = loadState(scanRoot);
  const newAdvisories = [];
  const sevFloor = SEV_RANK[minSeverity] ?? 0;

  for (const dep of deps) {
    const vulns = await _queryOsvForDep(dep, { fetchImpl, timeoutMs: opts.timeoutMs });
    for (const v of vulns) {
      if (!v.id || state.known.has(v.id)) continue;
      const sev = _normalizeSeverity(v);
      if ((SEV_RANK[sev] ?? 0) < sevFloor) {
        // Below user's floor; remember the ID so we don't re-fire next run,
        // but don't surface in the alert.
        state.known.add(v.id);
        continue;
      }
      newAdvisories.push({
        id: v.id,
        pkg: dep.name,
        ecosystem: dep.ecosystem,
        severity: sev,
        summary: v.summary || '',
        published: v.published || null,
      });
      state.known.add(v.id);
    }
    if (throttleMs > 0) await new Promise(r => setTimeout(r, throttleMs));
  }

  state.lastRun = new Date().toISOString();
  if (!dryRun) persistState(scanRoot, state);

  let alertSent = false;
  let alertError = null;
  if (newAdvisories.length > 0 && alertUrl && !dryRun) {
    const payload = formatPayload(alertType, newAdvisories);
    const r = await _post(alertUrl, payload, { fetchImpl, timeoutMs: opts.timeoutMs });
    alertSent = r.ok;
    if (!r.ok) alertError = r.error || `HTTP ${r.status}`;
  }

  log(`agentic-security cve-watch: deps=${deps.length} new=${newAdvisories.length} sent=${alertSent}${alertError ? ' err=' + alertError : ''}${dryRun ? ' (dry-run)' : ''}`);

  return {
    ok: true,
    depsChecked: deps.length,
    newAdvisories,
    alertSent,
    alertError,
    minSeverity,
    dryRun,
  };
}

const _internals = {
  ECOSYSTEM_BY_MANIFEST,
  MANIFEST_READERS,
  _readPackageJson, _readRequirementsTxt, _readPyprojectToml, _readGemfile,
  _readGoMod, _readCargoToml, _readComposerJson, _readMavenLikeXml, _readPubspecYaml,
  _normalizeSeverity,
};


/***/ })

};
