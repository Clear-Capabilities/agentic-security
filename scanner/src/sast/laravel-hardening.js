// Laravel framework hardening.
//
// Extends scanner/src/sast/php.js with Laravel-specific patterns. Targets
// `.env`, `config/*.php`, controllers, models, and routes.
//
// Coverage:
//   1. APP_DEBUG=true in .env (production-shaped)
//   2. APP_KEY= empty
//   3. dd() / dump() / var_dump() left in controller / model / view
//   4. Eloquent model without $fillable / $guarded (mass assignment)
//   5. SESSION_SECURE_COOKIE=false
//   6. CSRF disabled via VerifyCsrfToken::$except wildcard
//   7. DB::raw with $request input concatenated
//   8. Hash::needsRehash usage without follow-up Hash::make

const _ENV_FILE_RE = /(?:^|[\\/])\.env(?:\.[\w-]+)?$/;
const _PHP_FILE_RE = /\.php$/i;
const _MODEL_FILE_RE = /(?:^|[\\/])(?:app[\\/])?Models[\\/]/;
const _ROUTES_FILE_RE = /(?:^|[\\/])routes[\\/]/;

function _line(raw, idx) {
  return raw.slice(0, idx).split('\n').length;
}

// Heuristic for "this PHP file is an application (not the framework / vendor)".
// The framework itself defines dd/dump as helpers; flagging calls inside the
// framework source is pure false-positive.
function _isApplicationPhpFile(file, raw) {
  if (/(?:^|[\\/])(?:vendor|node_modules)[\\/]/.test(file)) return false;
  if (/(?:^|[\\/])src[\\/]Illuminate[\\/]/.test(file)) return false;
  if (/(?:^|[\\/])framework[\\/]src[\\/]/.test(file)) return false;
  if (/\bnamespace\s+Illuminate\\/.test(raw)) return false;
  // Must look like a Laravel application file.
  return /\bnamespace\s+App\\\w+/.test(raw) ||
         /\b(?:use|extends|implements)\s+(?:App|Illuminate)\\/.test(raw);
}

export function scanLaravelHardening(file, raw) {
  if (!file || !raw || typeof raw !== 'string') return [];
  if (raw.length > 200_000) return [];

  const findings = [];

  // ── .env file checks ────────────────────────────────────────────────────
  if (_ENV_FILE_RE.test(file)) {
    // APP_DEBUG=true
    for (const m of raw.matchAll(/^\s*APP_DEBUG\s*=\s*true\b/gmi)) {
      findings.push({
        id: `laravel:app-debug-true:${file}:${_line(raw, m.index)}`,
        file, line: _line(raw, m.index),
        vuln: 'Laravel APP_DEBUG=true in .env',
        severity: /\.env\.example$|\.env\.dev$|\.env\.local$/.test(file) ? 'medium' : 'critical',
        family: 'laravel-debug-enabled',
        cwe: 'CWE-489',
        confidence: 0.95,
        description: 'APP_DEBUG=true exposes the Whoops/Ignition error page on any exception — full stack trace, environment, query log, request payload. Catastrophic in production.',
        remediation: 'Set APP_DEBUG=false in every production .env. Use APP_ENV=local + APP_DEBUG=true only locally.',
      });
    }
    // APP_KEY empty
    for (const m of raw.matchAll(/^\s*APP_KEY\s*=\s*$/gm)) {
      findings.push({
        id: `laravel:app-key-empty:${file}:${_line(raw, m.index)}`,
        file, line: _line(raw, m.index),
        vuln: 'Laravel APP_KEY is empty',
        severity: 'critical',
        family: 'laravel-no-app-key',
        cwe: 'CWE-321',
        confidence: 0.95,
        description: 'APP_KEY is the encryption key for cookies / sessions / Crypt::encrypt. An empty key disables Laravel\'s encryption entirely and makes signed URLs / Laravel Sanctum / encrypted casts insecure.',
        remediation: 'Run `php artisan key:generate` and commit the result to your secrets store (NOT to the .env in source). Rotate immediately if the key was ever empty in production.',
      });
    }
    // SESSION_SECURE_COOKIE=false
    for (const m of raw.matchAll(/^\s*SESSION_SECURE_COOKIE\s*=\s*false\b/gmi)) {
      findings.push({
        id: `laravel:session-not-secure:${file}:${_line(raw, m.index)}`,
        file, line: _line(raw, m.index),
        vuln: 'Laravel SESSION_SECURE_COOKIE=false',
        severity: /\.env\.example$|\.env\.dev$/.test(file) ? 'medium' : 'high',
        family: 'laravel-cookie-not-secure',
        cwe: 'CWE-614',
        confidence: 0.9,
        description: 'Session cookie is not marked Secure — sent over plain HTTP. Any network observer steals the session.',
        remediation: 'Set SESSION_SECURE_COOKIE=true (and SESSION_HTTP_ONLY=true, SESSION_SAME_SITE=lax).',
      });
    }
    return findings;
  }

  // ── PHP source checks ───────────────────────────────────────────────────
  if (!_PHP_FILE_RE.test(file)) return [];
  if (!_isApplicationPhpFile(file, raw)) return [];

  // 1. dd() / dump() / var_dump() left in code — only as standalone calls,
  // not as method declarations (`function dump(...)`) or method references
  // (`->dump`, `::dump`).
  for (const m of raw.matchAll(/(?<!function\s)(?<!->)(?<!::)\b(?:dd|dump|var_dump)\s*\(/g)) {
    findings.push({
      id: `laravel:debug-dump:${file}:${_line(raw, m.index)}`,
      file, line: _line(raw, m.index),
      vuln: 'Laravel dd() / dump() / var_dump() left in source',
      severity: 'medium',
      family: 'laravel-debug-leak',
      cwe: 'CWE-209',
      confidence: 0.8,
      description: 'dd() halts execution and dumps every variable in scope (often including request / database / config). If reached in production it leaks PII, DB connection strings, and API keys.',
      remediation: 'Remove the dd()/dump()/var_dump() call. Use \\Log::debug() / \\Log::info() with explicit fields if you need ongoing diagnostics.',
    });
  }

  // 2. Eloquent model without $fillable AND without $guarded
  if (_MODEL_FILE_RE.test(file) && /\bextends\s+Model\b/.test(raw) && /\bclass\s+(\w+)\s+extends\s+Model\b/.test(raw)) {
    if (!/\$fillable\s*=/.test(raw) && !/\$guarded\s*=/.test(raw)) {
      const m = /\bclass\s+\w+\s+extends\s+Model\b/.exec(raw);
      findings.push({
        id: `laravel:mass-assignment:${file}:${_line(raw, m.index)}`,
        file, line: _line(raw, m.index),
        vuln: 'Eloquent model has no $fillable or $guarded — mass assignment risk',
        severity: 'high',
        family: 'laravel-mass-assignment',
        cwe: 'CWE-915',
        confidence: 0.85,
        description: 'Without $fillable (allow-list) or $guarded (deny-list), Model::create($request->all()) accepts every field — including ones the user shouldn\'t set (is_admin, role_id, balance).',
        remediation: 'Add protected $fillable = [\'name\', \'email\', ...]; with the explicit allow-list. Or protected $guarded = [\'id\', \'is_admin\', ...]; with the deny-list. Never set $guarded = [].',
      });
    }
  }

  // 3. CSRF exception wildcard in VerifyCsrfToken
  for (const m of raw.matchAll(/protected\s+\$except\s*=\s*\[\s*['"]\*['"]/g)) {
    findings.push({
      id: `laravel:csrf-wildcard-except:${file}:${_line(raw, m.index)}`,
      file, line: _line(raw, m.index),
      vuln: 'VerifyCsrfToken::$except = [\'*\'] — CSRF disabled globally',
      severity: 'critical',
      family: 'laravel-csrf-disabled',
      cwe: 'CWE-352',
      confidence: 0.95,
      description: 'Wildcard exception in VerifyCsrfToken disables CSRF protection on every POST endpoint. Cross-origin state-changing requests succeed.',
      remediation: 'Restrict $except to specific webhook routes (e.g., ["stripe/webhook", "api/svix/*"]). For SPA APIs, use Sanctum stateful auth which provides CSRF via XSRF-TOKEN cookie.',
    });
  }

  // 4. DB::raw with concatenated request input
  for (const m of raw.matchAll(/DB::raw\s*\(\s*['"][^'"]*['"]\s*\.\s*\$(?:request|input)/g)) {
    findings.push({
      id: `laravel:db-raw-injection:${file}:${_line(raw, m.index)}`,
      file, line: _line(raw, m.index),
      vuln: 'Laravel DB::raw(...) with concatenated request input — SQL injection',
      severity: 'critical',
      family: 'laravel-sql-injection',
      cwe: 'CWE-89',
      confidence: 0.95,
      description: 'DB::raw() bypasses query bindings. Concatenating user input into the SQL string lets the attacker rewrite the query.',
      remediation: 'Use bindings: DB::select("SELECT * FROM users WHERE email = ?", [$request->email]). Or use the Eloquent / Query Builder where() chain.',
    });
  }

  // 5. App\Console\Kernel::commands missing schedule() restrictions — skip (out of scope here).

  // 6. Plain password comparison via ==
  for (const m of raw.matchAll(/\$(?:user|model)->password\s*==\s*\$(?:request|input)\b/g)) {
    findings.push({
      id: `laravel:plain-password-compare:${file}:${_line(raw, m.index)}`,
      file, line: _line(raw, m.index),
      vuln: 'Plaintext password comparison ($user->password == $request->password)',
      severity: 'critical',
      family: 'laravel-plain-password',
      cwe: 'CWE-916',
      confidence: 0.85,
      description: 'Comparing the user\'s password column to the request value with == implies the password is stored plaintext (or the comparison is wrong against a bcrypt hash).',
      remediation: 'Use Hash::check($request->password, $user->password). Store passwords with Hash::make() — never plaintext.',
    });
  }

  // 7. Route::middleware('web')->... missing auth on admin
  if (_ROUTES_FILE_RE.test(file)) {
    for (const m of raw.matchAll(/Route::(?:get|post|put|patch|delete)\s*\(\s*['"](\/admin[^'"]*)['"][^;]*?(?:->name\s*\([^)]*\))?[^;]*?;/g)) {
      const block = m[0];
      if (!/middleware\s*\([^)]*['"](?:auth|auth:sanctum|auth:web|admin)['"]/.test(block)) {
        findings.push({
          id: `laravel:admin-route-no-auth:${file}:${_line(raw, m.index)}`,
          file, line: _line(raw, m.index),
          vuln: `Admin route ${m[1]} has no auth middleware`,
          severity: 'high',
          family: 'laravel-missing-auth',
          cwe: 'CWE-862',
          confidence: 0.75,
          description: 'A route under /admin/* is declared without ->middleware(\'auth\') (or auth:sanctum, etc.). Anyone reaching the URL bypasses authentication.',
          remediation: 'Wrap admin routes in Route::middleware([\'auth\', \'can:admin\'])->prefix(\'admin\')->group(function () { ... }).',
        });
      }
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Validation rule list that fetches a URL after an SSRF guard, without 'bail'
// (CWE-918). Project-wide: the rule classes live in their own files.
//
// Laravel runs EVERY rule of an attribute's list even after one has failed,
// unless the list starts with 'bail' (or the request sets
// $stopOnFirstFailure). A list that puts a guard rule first (one that refuses
// private, loopback and metadata addresses) and a rule that fetches the URL
// after it (to check its content type, say) therefore fetches the very URL the
// guard rejected: the guard only adds an error message. Reported at the
// attribute's list, where 'bail' belongs.
// ---------------------------------------------------------------------------

const _RULE_CLASS_RE = /\bclass\s+(\w+)\s+(?:extends\s+[\w\\]+\s+)?implements\s+[^{]*\b(?:ValidationRule|Rule|InvokableRule|ImplicitRule|DataAwareRule)\b/;
// An outbound HTTP request made by the rule itself.
const _RULE_FETCH_RE = /\bHttp::(?:get|head|post|send)\s*\(|\bHttp::[^;]{0,300}?->\s*(?:get|head|post|send)\s*\(|->\s*(?:head|get|request|send)\s*\(\s*\$\w+|\bcurl_exec\s*\(|\bfile_get_contents\s*\(\s*\$|\bget_headers\s*\(\s*\$|\bfopen\s*\(\s*\$/;
// A rule whose job is refusing internal destinations.
const _GUARD_BODY_RE = /FILTER_FLAG_NO_PRIV_RANGE|FILTER_FLAG_NO_RES_RANGE|\bis(?:Public|Private|Internal|Reserved|Loopback)(?:Host|Ip|Address|Url)?\s*\(|\b(?:private|reserved|internal)\s+(?:ip|address|network|range)/i;
const _GUARD_NAME_RE = /^(?:\w*(?:Safe|Public|External|Ssrf)\w*(?:Url|Uri|Host|Address)\w*|\w*(?:Not|No)(?:Private|Internal|Local)\w*|\w*Ssrf\w*)$/;

function _phpLine(code, idx) { return code.slice(0, idx).split('\n').length; }

function _bracketEnd(code, open) {
  let d = 0;
  for (let i = open; i < code.length; i++) {
    const c = code[i];
    if (c === '"' || c === "'") { const q = c; i++; while (i < code.length && code[i] !== q) { if (code[i] === '\\') i++; i++; } continue; }
    if (c === '[' || c === '(') d++;
    else if (c === ']' || c === ')') { d--; if (d === 0) return i; }
  }
  return -1;
}

export function scanLaravelFetchRuleWithoutBail(fileContents) {
  const out = [];
  const php = Object.entries(fileContents || {}).filter(([p, c]) => /\.php$/i.test(p) && typeof c === 'string' && c.length < 500_000
    && !/(?:^|[\\/])(?:vendor|tests?)[\\/]/i.test(p));
  if (!php.length) return out;
  const fetchers = new Set();
  const guards = new Set();
  for (const [, c] of php) {
    const m = _RULE_CLASS_RE.exec(c);
    if (!m) continue;
    // the fetch must happen in the rule's own code
    if (_RULE_FETCH_RE.test(c)) fetchers.add(m[1]);
    if (_GUARD_BODY_RE.test(c) || _GUARD_NAME_RE.test(m[1])) guards.add(m[1]);
  }
  if (!fetchers.size || !guards.size) return out;
  for (const [file, c] of php) {
    if (!/\bnew\s+\w+\s*\(/.test(c)) continue;
    if (/\$stopOnFirstFailure\s*=\s*true/.test(c)) continue;
    const keyRe = /(['"])[\w.*-]+\1\s*=>\s*\[/g;
    let k;
    while ((k = keyRe.exec(c))) {
      const open = k.index + k[0].length - 1;
      const close = _bracketEnd(c, open);
      if (close < 0) continue;
      const list = c.slice(open + 1, close);
      if (/(['"])bail\1/.test(list)) continue;
      // `new \App\Rules\Name(` is reduced to its last segment
      const items = [...list.matchAll(/\bnew\s+([\w\\]{1,200})\s*\(/g)].map((x) => [x[0], x[1].split('\\').pop()]);
      // a guard that fetches is itself the first request; the defect needs a separate later fetcher
      const gi = items.findIndex((x) => guards.has(x[1]));
      if (gi < 0) continue;
      const fetcher = items.slice(gi + 1).find((x) => fetchers.has(x[1]) && !guards.has(x[1]));
      if (!fetcher) continue;
      const line = _phpLine(c, k.index);
      out.push({
        id: `laravel:fetch-rule-without-bail:${file}:${line}`,
        file, line,
        vuln: 'SSRF: URL fetched by a validation rule that runs after the SSRF guard rejected it (no bail)',
        severity: 'high',
        family: 'ssrf',
        cwe: 'CWE-918',
        parser: 'LARAVEL',
        confidence: 0.7,
        snippet: (c.split('\n')[line - 1] || '').trim().slice(0, 200),
        description: `This validation list runs \`${items[gi][1]}\`, which refuses internal destinations, and then \`${fetcher[1]}\`, which makes a request to the URL. Without 'bail' Laravel runs every rule of the list even after one fails, so the request goes to the address the guard just rejected; the guard only adds an error message.`,
        remediation: "Start the list with 'bail' so validation stops at the first failing rule (or set `$stopOnFirstFailure = true` on the form request), and keep the guard before any rule that touches the network.",
      });
    }
  }
  return out;
}
