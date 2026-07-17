// Attack-surface completeness inventory (addition #2).
//
// Enumerates every attacker-reachable entry point across a codebase and
// assigns each a disposition, producing an auditable coverage ledger. The
// point is completeness: rather than only reporting where a finding fired,
// this lists every surface an attacker can *reach* (HTTP routes, queue
// consumers, cron jobs, CLI arg parsing, environment reads, file uploads,
// webhooks) and states, for each, whether it was traced clean, has an open
// finding, or otherwise. A reviewer can then audit the coverage rather than
// trust that "no finding == safe."
//
// Entry-point types (7):
//   http     — inbound HTTP routes (from opts.routes; one entry per route)
//   queue    — message-queue consumers (Kafka / SQS / RabbitMQ / pub-sub)
//   cron     — scheduled jobs (@Scheduled, cron.schedule, setInterval, celery)
//   cli      — command-line argument parsing (argv / argparse / commander / …)
//   env      — environment-variable reads (process.env / getenv)
//   upload   — file-upload sinks (multer / req.files / MultipartFile)
//   webhook  — inbound webhook handlers (route path or /webhook literal)
//
// Granularity: HTTP/webhook routes are enumerated per route. The regex-
// discovered surfaces are enumerated per (type, file) — a source file that
// exposes a surface is counted once for that surface, recording the first
// matching line. This avoids double-counting an import line plus its use
// site (e.g. `import multer` + `multer(...)`) while still distinguishing
// distinct surface types that share a file.
//
// No throwing: every public entry degrades to an empty/zeroed ledger.

// ── Entry-point type order (fixed — drives byType key order) ────────────────
const ENTRY_TYPES = ['http', 'queue', 'cron', 'cli', 'env', 'upload', 'webhook'];

// ── Regex-discovered surface patterns ──────────────────────────────────────
// Non-global regexes (no /g) so repeated .test()/.exec() calls are stateless.
// Ordered roughly most-specific → most-generic within each type.
const SURFACE_PATTERNS = {
  queue: [
    /@KafkaListener\b/,
    /@SqsListener\b/,
    /@RabbitListener\b/,
    /\b(?:sqs|kafka|rabbit)\w*\s*\.\s*(?:consume|subscribe|receiveMessage|poll|on)\b/i,
    /new\s+(?:Kafka)?Consumer\s*\(/,
    /\.consume\s*\(/,
    /\.subscribe\s*\(/,
  ],
  cron: [
    /@Scheduled\b/,
    /cron\.schedule\s*\(/,
    /\bnode-cron\b/,
    /@shared_task\b/,
    /@periodic_task\b/,
    /@(?:app\.)?task\b/,          // celery
    /setInterval\s*\(/,           // interval used as a recurring job
  ],
  cli: [
    /process\.argv\b/,
    /\bargparse\b/,
    /\bcommander\b/,
    /\byargs\b/,
    /\bcobra\.Command\b/,
    /\bflag\.Parse\s*\(/,
  ],
  env: [
    /process\.env\.\w+/,
    /os\.getenv\s*\(/,
    /System\.getenv\s*\(/,
  ],
  upload: [
    /\bmulter\b/,
    /\breq\.files?\b/,
    /\brequest\.files?\b/,
    /multipart\/form-data/i,
    /\bMultipartFile\b/,
  ],
  webhook: [
    /['"`][^'"`]*\/webhook[^'"`]*['"`]/i,   // a "/webhook…" string literal
  ],
};

// Auth tokens — presence near an entry point in the same file promotes its
// trust boundary from unauthenticated → authenticated. `\bauth\b` matches the
// bare token only (not "author" / "oauth", which retain their word chars).
const AUTH_TOKEN = /(?:@PreAuthorize|requireAuth|require_auth|login_required|isAuthenticated|authenticate\w*|authorize\w*|authMiddleware|authGuard|\bauth\b)/i;

const AUTH_WINDOW = 8;   // lines above/below the entry point to scan for auth

// ── Input normalization ─────────────────────────────────────────────────────
// Accept either a Map<filepath,string> or a plain object {path: source}.
function _entries(fileContents) {
  if (!fileContents) return [];
  if (fileContents instanceof Map) {
    return [...fileContents.entries()].filter(([, v]) => typeof v === 'string');
  }
  if (typeof fileContents === 'object') {
    return Object.entries(fileContents).filter(([, v]) => typeof v === 'string');
  }
  return [];
}

function _emptyCoverage() {
  const byType = {};
  for (const t of ENTRY_TYPES) byType[t] = 0;
  return { total: 0, byType, tracedSafe: 0, finding: 0, notReachable: 0, noInput: 0 };
}

function _authNear(lines, line) {
  const lo = Math.max(0, line - 1 - AUTH_WINDOW);
  const hi = Math.min(lines.length, line + AUTH_WINDOW);
  return AUTH_TOKEN.test(lines.slice(lo, hi).join('\n'));
}

function _routeHasInput(route) {
  if (Array.isArray(route.params) && route.params.length) return true;
  const p = typeof route.path === 'string' ? route.path : '';
  // :id (Express/Koa), {id} (FastAPI/Spring), <id> (Flask/Django) → has input.
  return /[:{<]\w/.test(p);
}

function _clip(s, n = 80) {
  const str = String(s == null ? '' : s).trim();
  return str.length > n ? str.slice(0, n) : str;
}

// ── Core ─────────────────────────────────────────────────────────────────────

export function buildEntrypointInventory(fileContents, opts = {}) {
  const coverage = _emptyCoverage();
  const entrypoints = [];
  try {
    const routes = Array.isArray(opts && opts.routes) ? opts.routes : [];
    const findings = Array.isArray(opts && opts.findings) ? opts.findings : [];
    const findingFiles = new Set(
      findings.map(f => (f && typeof f.file === 'string' ? f.file : null)).filter(Boolean),
    );

    // 1) HTTP / webhook entry points — one per route.
    for (const route of routes) {
      if (!route || typeof route !== 'object') continue;
      const file = typeof route.file === 'string' && route.file ? route.file : '(unknown)';
      const line = Number.isInteger(route.line) ? route.line : 0;
      const method = typeof route.method === 'string' ? route.method : 'GET';
      const path = typeof route.path === 'string' ? route.path : '';
      const isWebhook = /webhook/i.test(path) || /webhook/i.test(String(route.handler || ''));
      const type = isWebhook ? 'webhook' : 'http';
      const name = _clip(route.handler || `${method} ${path}`.trim() || type);

      // Trust: an authenticated route (hasAuth) or a nearby auth token wins.
      let trust = route.hasAuth === true ? 'authenticated' : 'unauthenticated';
      if (trust === 'unauthenticated' && fileContents) {
        const src = _srcOf(fileContents, file);
        if (src && _authNear(src.split(/\r?\n/), line)) trust = 'authenticated';
      }

      let disposition;
      if (findingFiles.has(file)) disposition = 'finding';
      else if (type === 'http' && !_routeHasInput(route)) disposition = 'no-input';
      else disposition = 'traced-safe';

      entrypoints.push({ type, file, line, name, trust, disposition });
    }

    // 2) Regex-discovered surfaces — one per (type, file), first matching line.
    for (const [file, source] of _entries(fileContents)) {
      const lines = source.split(/\r?\n/);
      for (const type of ENTRY_TYPES) {
        const pats = SURFACE_PATTERNS[type];
        if (!pats) continue;   // http has no file-scan pattern (routes-only)
        let hitLine = -1;
        let hitText = '';
        outer:
        for (let i = 0; i < lines.length; i++) {
          for (const re of pats) {
            const m = re.exec(lines[i]);
            if (m) { hitLine = i + 1; hitText = _clip(m[0] || type); break outer; }
          }
        }
        if (hitLine < 0) continue;

        const trust = _authNear(lines, hitLine) ? 'authenticated' : 'unauthenticated';
        // Regex surfaces inherently carry attacker-controlled input (a queue
        // message, an env value, a CLI arg, an upload). Only HTTP routes get
        // the optional 'no-input' disposition.
        const disposition = findingFiles.has(file) ? 'finding' : 'traced-safe';
        entrypoints.push({ type, file, line: hitLine, name: hitText || type, trust, disposition });
      }
    }

    // 3) Roll up the coverage ledger.
    coverage.total = entrypoints.length;
    for (const e of entrypoints) {
      if (coverage.byType[e.type] != null) coverage.byType[e.type]++;
      if (e.disposition === 'finding') coverage.finding++;
      else if (e.disposition === 'not-reachable') coverage.notReachable++;
      else if (e.disposition === 'no-input') coverage.noInput++;
      else coverage.tracedSafe++;
    }
  } catch (_) {
    // Degrade to whatever we accumulated before the error (or empty).
    return { entrypoints, coverage: _recount(entrypoints) };
  }
  return { entrypoints, coverage };
}

// Defensive re-count used only on the error path.
function _recount(entrypoints) {
  const coverage = _emptyCoverage();
  coverage.total = entrypoints.length;
  for (const e of entrypoints) {
    if (coverage.byType[e.type] != null) coverage.byType[e.type]++;
    if (e.disposition === 'finding') coverage.finding++;
    else if (e.disposition === 'not-reachable') coverage.notReachable++;
    else if (e.disposition === 'no-input') coverage.noInput++;
    else coverage.tracedSafe++;
  }
  return coverage;
}

function _srcOf(fileContents, file) {
  if (!fileContents) return null;
  if (fileContents instanceof Map) {
    const v = fileContents.get(file);
    return typeof v === 'string' ? v : null;
  }
  const v = fileContents[file];
  return typeof v === 'string' ? v : null;
}

// ── Engine wiring helper ─────────────────────────────────────────────────────
// Annotates a scan object in place with scan.entrypointInventory. Never throws;
// absent inputs yield an empty ledger.
export function annotateEntrypointCoverage(scan) {
  if (!scan || typeof scan !== 'object') return scan;
  try {
    const fileContents = scan.fileContents || scan._fileContents || null;
    const routes = Array.isArray(scan.routes) ? scan.routes : [];
    const findings = Array.isArray(scan.findings) ? scan.findings : [];
    if (!fileContents && routes.length === 0) {
      scan.entrypointInventory = { entrypoints: [], coverage: _emptyCoverage() };
      return scan;
    }
    scan.entrypointInventory = buildEntrypointInventory(fileContents || {}, { routes, findings });
  } catch (_) {
    scan.entrypointInventory = { entrypoints: [], coverage: _emptyCoverage() };
  }
  return scan;
}

export const _internals = { SURFACE_PATTERNS, ENTRY_TYPES, AUTH_TOKEN, _entries };
