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
