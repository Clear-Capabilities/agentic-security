// PHP-specific detectors. Covers the canonical PHP foot-guns:
//
//   - $_REQUEST / $_GET / $_POST flowing into eval / system / exec / passthru / shell_exec / `` / popen / proc_open
//   - unserialize() on user input
//   - include / require with user-controlled path (LFI / RFI)
//   - mysql_query with concatenated user input
//   - extract($_REQUEST) — direct variable injection
//   - md5/sha1 used for password hashing
//   - phpinfo() exposed in production code
//   - assert with string argument

const RE = {
  dangerCall: /\b(?:eval|assert|system|exec|passthru|shell_exec|popen|proc_open|pcntl_exec)\s*\(\s*[^)]*\$(?:_(?:REQUEST|GET|POST|COOKIE|FILES|SERVER)|HTTP_)/g,
  backtickInterp: /`[^`]*\$(?:_(?:REQUEST|GET|POST|COOKIE)|[A-Z_a-z][\w]*)[^`]*`/g,
  unserialize: /\bunserialize\s*\(\s*\$(?:_(?:REQUEST|GET|POST|COOKIE)|HTTP_)/g,
  includeUser: /\b(?:include|include_once|require|require_once)\s*[(\s]+\$(?:_(?:REQUEST|GET|POST|COOKIE)|HTTP_)/g,
  mysqlConcat: /\bmysql(?:i)?_(?:query|real_query)\s*\(\s*[^)]*['"]\s*\.\s*\$(?:_(?:REQUEST|GET|POST)|HTTP_)/g,
  extractRequest: /\bextract\s*\(\s*\$(?:_REQUEST|_GET|_POST|HTTP_GET_VARS|HTTP_POST_VARS)\s*[,)]/g,
  passwordHashMd5: /\b(?:md5|sha1)\s*\(\s*\$(?:_(?:REQUEST|GET|POST)|password|passwd|pwd|hash_input)/gi,
  phpinfo: /\bphpinfo\s*\(/g,
  // Structural (taint-independent): a shell or SQL sink built with string
  // concat (`'…' .`) or double-quote `$var` interpolation is the injection
  // shape regardless of the source token — the rules above require the literal
  // $_REQUEST/$_GET/$_POST on the sink line, which misses framework idioms
  // (`$f = $r->query->get('x'); shell_exec('gzip ' . $f)`).
  cmdInjectionStructural: /\b(?:shell_exec|exec|system|passthru|popen|proc_open|pcntl_exec)\s*\(\s*(?:"[^"\n]*\$|'[^'\n]*'\s*\.|"[^"\n]*"\s*\.)/g,
  sqlInjectionStructural: /\b(?:DB::raw|DB::select|DB::statement|DB::insert|DB::update|DB::delete|whereRaw|orWhereRaw|havingRaw|selectRaw|orderByRaw|mysqli_query|mysql_query|pg_query|pg_send_query|sqlite_query|->query|->rawQuery)\s*\(\s*(?:DB::raw\s*\(\s*)?(?:"[^"\n]*\$|"[^"\n]*"\s*\.|'[^'\n]*'\s*\.)/g,
};

function lineOf(raw, idx) { return raw.substring(0, idx).split('\n').length; }

export function scanPhp(fp, raw) {
  if (!/\.(?:php|phtml|phar)$/i.test(fp)) return [];
  if (!raw || raw.length > 500_000) return [];
  const findings = [];
  const seen = new Set();
  const push = (f) => { if (!seen.has(f.id)) { seen.add(f.id); findings.push(f); } };

  for (const [key, re] of Object.entries(RE)) {
    const r = new RegExp(re.source, re.flags);
    let m;
    while ((m = r.exec(raw))) {
      const line = lineOf(raw, m.index);
      const meta = {
        dangerCall: {
          vuln: 'Command/Code Injection: dangerous function call with user input ($_REQUEST/$_GET/$_POST)',
          severity: 'critical', cwe: 'CWE-78',
          remediation: 'Never pass $_REQUEST/$_GET/$_POST into eval, system, exec, passthru, shell_exec, popen, or assert with a string. Use escapeshellarg() if you absolutely must, but prefer an array-form exec via proc_open. The right answer is usually: don\'t shell out at all; call a library.',
        },
        backtickInterp: {
          vuln: 'Command Injection: backtick command interpolates a PHP variable',
          severity: 'critical', cwe: 'CWE-78',
          remediation: 'Backticks invoke the shell. Use `proc_open` with an array form so the shell never parses your input.',
        },
        unserialize: {
          vuln: 'Insecure Deserialization: unserialize() on user input',
          severity: 'critical', cwe: 'CWE-502',
          remediation: 'PHP unserialize() will call __destruct / __wakeup on every class in the serialized graph — a gadget chain in the codebase becomes RCE. Replace with json_decode for any input crossing a trust boundary.',
        },
        includeUser: {
          vuln: 'Local/Remote File Inclusion: include/require with user-controlled path',
          severity: 'critical', cwe: 'CWE-98',
          remediation: 'Never include() / require() a user-controlled path. If you need a dispatch table, build it as `$pages = ["home" => "home.php", ...]; include $pages[$_GET["page"]] ?? "404.php";` with an explicit whitelist.',
        },
        mysqlConcat: {
          vuln: 'SQL Injection: mysql(i)_query with concatenated $_REQUEST/$_GET/$_POST',
          severity: 'critical', cwe: 'CWE-89',
          remediation: 'Use prepared statements: `$stmt = $mysqli->prepare("SELECT ... WHERE id = ?"); $stmt->bind_param("i", $id);`. The mysql_* family was deprecated in PHP 5.5 and removed in 7.0 — migrate to mysqli or PDO.',
        },
        extractRequest: {
          vuln: 'Variable Injection: extract($_REQUEST) creates arbitrary local variables from request',
          severity: 'critical', cwe: 'CWE-915',
          remediation: 'Never call `extract()` on a user-controlled array — it overwrites local variables, including `$is_admin`, `$auth_user`, etc. Read the specific fields you want explicitly.',
        },
        passwordHashMd5: {
          vuln: 'Weak password hashing — md5/sha1 are not password-hashing functions',
          severity: 'high', cwe: 'CWE-916',
          remediation: 'Use password_hash($pwd, PASSWORD_ARGON2ID) and password_verify(). md5 and sha1 are too fast for password storage — modern GPUs crack the full keyspace of an 8-char alphanumeric in hours.',
        },
        phpinfo: {
          vuln: 'phpinfo() exposes environment, headers, paths, and INI settings',
          severity: 'high', cwe: 'CWE-200',
          remediation: 'Delete phpinfo() before deploy. It leaks the PHP version, loaded extensions, environment variables, document root, and request headers — a one-shot recon page for an attacker.',
        },
        cmdInjectionStructural: {
          vuln: 'Command Injection: shell function built with string concat / interpolation',
          severity: 'critical', cwe: 'CWE-78',
          remediation: 'Use the array form of proc_open(["gzip", $f], ...) so no shell parses the string, and validate inputs. Never concatenate or interpolate values into shell_exec/exec/system/passthru.',
        },
        sqlInjectionStructural: {
          vuln: 'SQL Injection: raw query built with string concat / interpolation',
          severity: 'critical', cwe: 'CWE-89',
          remediation: 'Use parameter bindings: DB::select("SELECT … WHERE name = ?", [$name]) or the query builder with bindings. Never concatenate/interpolate into DB::raw / whereRaw / mysqli_query.',
        },
      }[key];
      push({
        id: `php-${key}:${fp}:${line}`,
        file: fp, line,
        vuln: meta.vuln, severity: meta.severity, cwe: meta.cwe,
        snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
        remediation: meta.remediation,
        parser: 'PHP',
        confidence: 0.85,
      });
    }
  }
  return findings;
}
