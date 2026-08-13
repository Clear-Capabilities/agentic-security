export const id = 301;
export const ids = [301];
export const modules = {

/***/ 1301:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   describeTarget: () => (/* binding */ describeTarget),
/* harmony export */   loadTargetManifest: () => (/* binding */ loadTargetManifest),
/* harmony export */   validateTarget: () => (/* binding */ validateTarget)
/* harmony export */ });
/* unused harmony export _internals */
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(3024);
/* harmony import */ var node_path__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(6760);
// Verifier target harness (FR-LIVE-HARNESS).
//
// Customer projects describe how to bring up the app they want the verifier
// to execute PoCs against. The manifest lives at
// `.agentic-security/verifier-target.yaml` and the verifier reads it before
// running `--live` mode. v1 supports two manifest shapes:
//
//   shape: docker-compose
//   compose: docker-compose.yml
//   service: web
//   port: 3000
//   wait-for: http://localhost:3000/healthz
//
//   ─── or ───
//
//   shape: command
//   start: npm run dev
//   port: 3000
//   wait-for: http://localhost:3000/healthz
//   stop: pkill -f "npm run dev"
//
// We DO NOT execute the manifest in this module — that's the verifier
// sandbox's job (and the customer's explicit opt-in via --live). This
// module parses, validates, and surfaces a structured object the verifier
// can act on (or refuse to act on).




const MANIFEST_PATH = node_path__WEBPACK_IMPORTED_MODULE_1__.join('.agentic-security', 'verifier-target.yaml');

// Minimal YAML subset parser — keep parity with the polyglot bench parser,
// scoped to the small set of keys this manifest uses. Standalone here to
// avoid a runtime dep.
function _parse(text) {
  const out = {};
  for (const raw of String(text || '').split(/\r?\n/)) {
    const line = raw.replace(/#.*$/, '').trim();
    if (!line) continue;
    const m = line.match(/^([\w-]+)\s*:\s*(.*)$/);
    if (!m) continue;
    const [, key, val] = m;
    out[key] = _coerce(val);
  }
  return out;
}

function _coerce(v) {
  if (v === undefined || v === null) return null;
  v = String(v).trim();
  if (/^".*"$/.test(v)) return v.slice(1, -1);
  if (/^'.*'$/.test(v)) return v.slice(1, -1);
  if (/^-?\d+$/.test(v)) return parseInt(v, 10);
  return v;
}

/**
 * Read the verifier-target manifest from scanRoot. Returns:
 *   { ok: true, target } — successfully parsed and validated
 *   { ok: false, reason } — manifest missing or invalid
 *
 * Never throws.
 */
function loadTargetManifest(scanRoot) {
  const fp = node_path__WEBPACK_IMPORTED_MODULE_1__.join(scanRoot || process.cwd(), MANIFEST_PATH);
  if (!node_fs__WEBPACK_IMPORTED_MODULE_0__.existsSync(fp)) return { ok: false, reason: 'no-manifest' };
  let raw;
  try { raw = node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(fp, 'utf8'); }
  catch (e) { return { ok: false, reason: `read-error:${e.message}` }; }
  const parsed = _parse(raw);
  const shape = parsed.shape;
  if (shape !== 'docker-compose' && shape !== 'command') {
    return { ok: false, reason: `unknown-shape:${shape || 'missing'}` };
  }
  if (shape === 'docker-compose') {
    if (!parsed.compose || !parsed.service) {
      return { ok: false, reason: 'docker-compose-shape-needs-compose-and-service' };
    }
  }
  if (shape === 'command') {
    if (!parsed.start) {
      return { ok: false, reason: 'command-shape-needs-start' };
    }
  }
  const target = {
    shape,
    compose: parsed.compose || null,
    service: parsed.service || null,
    start:   parsed.start   || null,
    stop:    parsed.stop    || null,
    port:    parsed.port    || null,
    waitFor: parsed['wait-for'] || parsed.waitFor || null,
    url:     parsed.url || (parsed.port ? `http://localhost:${parsed.port}` : null),
  };
  return { ok: true, target };
}

/**
 * Render a quick summary for human consumption (CLI output, logs).
 */
function describeTarget(target) {
  if (!target) return '(none)';
  if (target.shape === 'docker-compose') {
    return `docker-compose service ${target.service} from ${target.compose} on ${target.url || `:${target.port}`}`;
  }
  if (target.shape === 'command') {
    return `command "${target.start}" on ${target.url || `:${target.port}`}`;
  }
  return `unknown-shape ${target.shape}`;
}

/**
 * Pre-flight safety check: refuse to bring up a target whose start command
 * looks dangerous. Curated allowlist of common shapes; everything else
 * requires AGENTIC_SECURITY_VERIFY_TARGET_OK=1 to opt in explicitly.
 */
function validateTarget(target) {
  if (!target) return { ok: false, reason: 'no-target' };
  if (target.shape === 'docker-compose') {
    // docker-compose is safe-ish by design.
    return { ok: true };
  }
  if (target.shape === 'command') {
    const SAFE_HINTS = [
      /^npm\s+(?:run\s+)?(?:dev|start|serve)/,
      /^yarn\s+(?:dev|start|serve)/,
      /^pnpm\s+(?:run\s+)?(?:dev|start|serve)/,
      /^node\s+/,
      /^python(?:\d?)\s+-m\s+/,
      /^python(?:\d?)\s+\S+\.py/,
      /^uvicorn\s+/,
      /^gunicorn\s+/,
      /^flask\s+run/,
      /^go\s+run\s+/,
      /^java\s+-jar\s+/,
      /^cargo\s+run/,
    ];
    if (process.env.AGENTIC_SECURITY_VERIFY_TARGET_OK === '1') return { ok: true, escaped: true };
    if (!SAFE_HINTS.some(re => re.test(target.start))) {
      return { ok: false, reason: `start-command-not-in-safe-allowlist (set AGENTIC_SECURITY_VERIFY_TARGET_OK=1 to override)` };
    }
    return { ok: true };
  }
  return { ok: false, reason: `unknown-shape:${target.shape}` };
}

const _internals = { MANIFEST_PATH };


/***/ })

};
