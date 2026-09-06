// Python sink-side SAST (FR-PY-SAST — Phase-2 G3 blocker).
//
// The polyglot benchmark in v0.50.0 showed Python detector coverage is the
// single largest blocker behind the polyglot F1 gap (target 0.85, today 0.727).
// This module fills the most-common Python sink shapes:
//
//   - SQLAlchemy text() with f-string concat → SQL injection
//   - os.system / subprocess with shell=True or string concat → command injection
//   - pickle.loads / yaml.load on request data → insecure deserialization
//   - eval / exec on request data → code injection
//   - flask.send_file / send_from_directory with user-controlled path → path traversal
//   - requests with verify=False → insecure HTTPS
//
// Limits:
//   - Regex-based, no Python AST today (tree-sitter integration is Phase 5).
//   - "User-controlled" is shape-matched, not flow-traced (any `request.`
//     reference in the same call site qualifies). This is conservative —
//     we'll miss flows that route through helpers, and we'll false-positive
//     when `request.` is unrelated to the sink. Calibration is the answer
//     (FR-LEARN-5), not pre-filtering.

import { blankComments } from './_comment-strip.js';

const PY_EXT_RE = /\.py$/i;

function lineOf(raw, idx) { return raw.substring(0, idx).split('\n').length; }

// ─── SQLAlchemy text() with f-string ──────────────────────────────────────
//
// `engine.execute(text(f"SELECT ... {var}"))`
// `connection.execute(text(f"..."))`
// The dangerous shape is text() wrapping an f-string. Parameterized queries
// use `text("... :name").bindparams(name=...)` — the f-string variant
// indicates concat.

const SQLA_TEXT_FSTRING_RE = /\btext\s*\(\s*f['"][^'"]*\{[^}]+\}/g;
const SQLA_RAW_EXEC_CONCAT_RE = /\b(?:cursor|conn|connection|session)\s*\.\s*execute\s*\(\s*(?:f['"][^'"]*\{|['"][^'"]*['"]\s*[+%])/g;
// A common shape: build the SQL in a previous line as an f-string, then pass
// the variable to text() / execute(). We detect the f-string with SQL keywords
// AND a `{...}` interpolation directly. The f-string body can contain inner
// quotes (single quotes inside double-quoted f-string and vice versa) so we
// use two parallel patterns rather than a single character class that excludes
// both quote kinds.
//
// Two real-world false positives, both from the same underlying defect —
// this regex checked for a co-occurring keyword-shaped substring and a `{}`
// interpolation, not an actual SQL statement being assigned:
//
//   query = f"SELECT * FROM users WHERE id = {user_id}"   -> should fire
//   print(f"[{position}] {len(selected)} readable pages")  -> was firing
//   raise RuntimeError(f"Selected TAR members exceed {N} bytes")  -> was firing
//
// Case-insensitive matching with no word boundary let the SQL keyword
// alternation match inside ordinary English/identifier text — "Select" is
// the first six letters of "Selected", and "select" is the first six of the
// variable name "selected". `\b...\b` fixes that: a word boundary requires a
// non-word/word transition, which does not exist between "Select" and the
// trailing "ed" (both are word characters), so "Selected"/"selected" no
// longer match while "SELECT"/"select" as complete tokens still do.
//
// The vuln title claims "f-string SQL ASSIGNED TO VARIABLE", but the regex
// never actually checked for an assignment — it fired on any f-string
// anywhere, including a bare argument to print()/raise. Requiring
// `IDENT = ` (optionally through an opening paren, for a wrapped assignment)
// immediately before the f-string makes the check match what its own name
// promises, and excludes the print()/raise-message shape entirely.
const SQLA_FSTRING_SQL_ASSIGN_RE = /\b[A-Za-z_]\w*\s*=\s*\(?\s*(?:f"[^"]*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^"]*\{[^}]*\}|f'[^']*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^']*\{[^}]*\})/gi;

// ─── Command injection ────────────────────────────────────────────────────
//
// `os.system(...)` with anything other than a literal
// `subprocess.run(...,  shell=True)`
// `subprocess.Popen(..., shell=True)`
// `subprocess.call(..., shell=True)`

// os.system is dangerous when the argument is anything but a pure quoted
// literal. We use a negative lookahead for the "pure literal" shape:
// `os.system("literal text")` is safe; everything else gets flagged.
const PY_OS_SYSTEM_RE = /\bos\s*\.\s*system\s*\((?!\s*['"][^'"]*['"]\s*\))/g;
const PY_SUBPROCESS_SHELL_TRUE_RE = /\bsubprocess\s*\.\s*(?:run|Popen|call|check_call|check_output)\s*\([^)]*shell\s*=\s*True/g;
const PY_SHELL_EXEC_CONCAT_RE = /\bos\s*\.\s*(?:popen|exec[lv]p?)\s*\(/g;

// ─── Insecure deserialization ─────────────────────────────────────────────

const PY_PICKLE_LOADS_RE = /\bpickle\s*\.\s*loads?\s*\(/g;
const PY_YAML_UNSAFE_LOAD_RE = /\byaml\s*\.\s*(?:unsafe_load|load)\s*\((?![^)]*Loader\s*=\s*(?:yaml\.SafeLoader|SafeLoader))/g;
const PY_MARSHAL_LOADS_RE = /\bmarshal\s*\.\s*loads?\s*\(/g;

// ─── Code injection ───────────────────────────────────────────────────────

const PY_EVAL_USER_RE = /\b(?:eval|exec)\s*\(\s*[^)]*(?:request\.|flask\.request|input\s*\(|sys\.argv|os\.environ)/g;
const PY_COMPILE_USER_RE = /\bcompile\s*\([^)]*(?:request\.|input\s*\(|sys\.argv)/g;

// ─── Path traversal ───────────────────────────────────────────────────────
//
// `flask.send_file(user_path)` — known sink when path comes from request.
// `flask.send_from_directory(dir, user_filename)` — same.
// `open(user_path)` — generic file read with user input.

// send_file with anything other than a pure literal path is dangerous.
const PY_SEND_FILE_RE = /\b(?:flask\.)?send_file\s*\(\s*(?!['"][^'"]+['"]\s*\))/gi;
const PY_SEND_FROM_DIR_RE = /\b(?:flask\.)?send_from_directory\s*\([^)]*,\s*(?:request\.|[a-zA-Z_]\w*)\s*[,)]/g;
const PY_OPEN_USER_RE = /\bopen\s*\(\s*(?:request\.|f['"][^'"]*\{[^}]+\})/g;

// ─── Insecure transport ───────────────────────────────────────────────────

const PY_REQUESTS_VERIFY_FALSE_RE = /\brequests\s*\.\s*(?:get|post|put|delete|patch|head|request)\s*\([^)]*verify\s*=\s*False/g;
const PY_URLLIB_NOCHECK_RE = /\bssl\s*\.\s*_create_unverified_context\s*\(/g;

// ─── SSRF ─────────────────────────────────────────────────────────────────

const PY_REQUESTS_USER_URL_RE = /\brequests\s*\.\s*(?:get|post|put|delete|patch|head|request)\s*\(\s*(?:request\.|f['"][^'"]*\{[^}]+\})/g;
const PY_URLLIB_USER_URL_RE = /\b(?:urllib\.request\.urlopen|urlopen)\s*\(\s*(?:request\.|f['"][^'"]*\{[^}]+\})/g;

// ─── XXE ──────────────────────────────────────────────────────────────────

const PY_XML_INSECURE_RE = /\blxml\.etree\.(?:parse|fromstring)\s*\([^)]*\)(?!\s*[^.]*\bresolve_entities\s*=\s*False)/g;
const PY_XML_ETREE_USER_RE = /\bxml\.etree\.ElementTree\.(?:parse|fromstring)\s*\(\s*(?:request\.|f['"][^'"]*\{)/g;

// ─── Detector ─────────────────────────────────────────────────────────────

const RULES = [
  // Each rule: { re, vuln, severity, cwe, family, parser }
  { re: SQLA_TEXT_FSTRING_RE,        vuln: 'SQL Injection (SQLAlchemy text() with f-string)',     severity: 'critical', cwe: 'CWE-89',  family: 'sql-injection' },
  { re: SQLA_RAW_EXEC_CONCAT_RE,     vuln: 'SQL Injection (cursor.execute with concat)',          severity: 'critical', cwe: 'CWE-89',  family: 'sql-injection' },
  { re: SQLA_FSTRING_SQL_ASSIGN_RE,  vuln: 'SQL Injection (f-string SQL assigned to variable)',   severity: 'high',     cwe: 'CWE-89',  family: 'sql-injection' },
  { re: PY_OS_SYSTEM_RE,             vuln: 'Command Injection (os.system with variable arg)',     severity: 'critical', cwe: 'CWE-78',  family: 'command-injection' },
  { re: PY_SUBPROCESS_SHELL_TRUE_RE, vuln: 'Command Injection (subprocess shell=True)',           severity: 'critical', cwe: 'CWE-78',  family: 'command-injection' },
  { re: PY_SHELL_EXEC_CONCAT_RE,     vuln: 'Command Injection (os.popen / os.execlp)',            severity: 'high',     cwe: 'CWE-78',  family: 'command-injection' },
  { re: PY_PICKLE_LOADS_RE,          vuln: 'Insecure Deserialization (pickle.loads on untrusted)', severity: 'critical', cwe: 'CWE-502', family: 'insecure-deserialization' },
  { re: PY_YAML_UNSAFE_LOAD_RE,      vuln: 'Insecure Deserialization (yaml.load without SafeLoader)', severity: 'critical', cwe: 'CWE-502', family: 'insecure-deserialization' },
  { re: PY_MARSHAL_LOADS_RE,         vuln: 'Insecure Deserialization (marshal.loads)',            severity: 'high',     cwe: 'CWE-502', family: 'insecure-deserialization' },
  { re: PY_EVAL_USER_RE,             vuln: 'Code Injection (eval/exec on request data)',          severity: 'critical', cwe: 'CWE-94',  family: 'code-injection' },
  { re: PY_COMPILE_USER_RE,          vuln: 'Code Injection (compile() on user input)',            severity: 'high',     cwe: 'CWE-94',  family: 'code-injection' },
  { re: PY_SEND_FILE_RE,             vuln: 'Path Traversal (flask.send_file with user-controlled path)', severity: 'high', cwe: 'CWE-22', family: 'path-traversal' },
  { re: PY_SEND_FROM_DIR_RE,         vuln: 'Path Traversal (flask.send_from_directory)',          severity: 'high',     cwe: 'CWE-22',  family: 'path-traversal' },
  { re: PY_OPEN_USER_RE,             vuln: 'Path Traversal (open with user-controlled path)',     severity: 'high',     cwe: 'CWE-22',  family: 'path-traversal' },
  { re: PY_REQUESTS_VERIFY_FALSE_RE, vuln: 'Insecure HTTPS (requests verify=False)',              severity: 'medium',   cwe: 'CWE-295', family: 'insecure-http' },
  { re: PY_URLLIB_NOCHECK_RE,        vuln: 'Insecure HTTPS (ssl._create_unverified_context)',     severity: 'medium',   cwe: 'CWE-295', family: 'insecure-http' },
  { re: PY_REQUESTS_USER_URL_RE,     vuln: 'SSRF (requests with user-controlled URL)',            severity: 'high',     cwe: 'CWE-918', family: 'ssrf' },
  { re: PY_URLLIB_USER_URL_RE,       vuln: 'SSRF (urlopen with user-controlled URL)',             severity: 'high',     cwe: 'CWE-918', family: 'ssrf' },
  { re: PY_XML_INSECURE_RE,          vuln: 'XXE (lxml without resolve_entities=False)',           severity: 'high',     cwe: 'CWE-611', family: 'xxe' },
  { re: PY_XML_ETREE_USER_RE,        vuln: 'XXE (xml.etree.ElementTree on user input)',           severity: 'high',     cwe: 'CWE-611', family: 'xxe' },
];

export function scanPythonSinks(fp, raw) {
  if (!PY_EXT_RE.test(fp)) return [];
  if (!raw || raw.length > 500_000) return [];
  // Skip test files — Python projects use `test_*.py` / `*_test.py` / `tests/`.
  if (/(?:^|\/)(?:tests?|test_|_test\.py$)/i.test(fp) && !/fixtures?/i.test(fp)) return [];
  const code = blankComments(raw, 'py');
  const findings = [];
  const seen = new Set();
  for (const rule of RULES) {
    const re = new RegExp(rule.re.source, rule.re.flags);
    let m;
    while ((m = re.exec(code))) {
      const line = lineOf(raw, m.index);
      const id = `${rule.family}:${fp}:${line}:${rule.cwe}`;
      if (seen.has(id)) continue;
      seen.add(id);
      findings.push({
        id,
        file: fp,
        line,
        vuln: rule.vuln,
        severity: rule.severity,
        cwe: rule.cwe,
        family: rule.family,
        stride: _strideForFamily(rule.family),
        snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
        parser: 'PY-SAST',
        confidence: 0.7,
        remediation: _remediationFor(rule.family, rule.vuln),
      });
    }
  }
  return findings;
}

function _strideForFamily(fam) {
  return {
    'sql-injection':            'Tampering',
    'command-injection':        'Elevation of Privilege',
    'insecure-deserialization': 'Elevation of Privilege',
    'code-injection':           'Elevation of Privilege',
    'path-traversal':           'Information Disclosure',
    'insecure-http':            'Information Disclosure',
    'ssrf':                     'Spoofing',
    'xxe':                      'Information Disclosure',
  }[fam] || 'Tampering';
}

function _remediationFor(fam, vuln) {
  switch (fam) {
    case 'sql-injection':
      return 'Use parameterized queries: `connection.execute(text("SELECT ... WHERE id = :id"), {"id": id})` instead of f-string concat. For raw `cursor.execute`, pass the value as the second positional argument; never concatenate.';
    case 'command-injection':
      return 'Avoid `os.system` and `shell=True`. Use `subprocess.run([\'binary\', arg1, arg2], check=True)` with arguments as a list — the shell never sees the values, so shell metacharacters cannot be injected.';
    case 'insecure-deserialization':
      return 'Never `pickle.loads` untrusted bytes. Use `json.loads` for structured data. For YAML, use `yaml.safe_load`. For `marshal`, switch to JSON or a schema-validated alternative.';
    case 'code-injection':
      return 'Replace `eval` / `exec` with a safe parser appropriate to the input class — `ast.literal_eval` for Python literals, `json.loads` for JSON, a domain-specific parser for everything else.';
    case 'path-traversal':
      return 'Validate the user path is inside the intended directory: `os.path.realpath(os.path.join(base, user_path)).startswith(os.path.realpath(base))`. For `flask.send_from_directory`, ensure the filename is a known allowlisted value.';
    case 'insecure-http':
      return 'Remove `verify=False`. If you genuinely need to disable TLS verification for a known internal endpoint, scope it to that endpoint and document why; never broadly across `requests` calls.';
    case 'ssrf':
      return 'Validate the URL against an allowlist before fetching. Block private IP ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.169.254 / metadata IPs).';
    case 'xxe':
      return 'Configure the XML parser to disable external entities: lxml `etree.XMLParser(resolve_entities=False, no_network=True)`; defusedxml is the safest drop-in.';
    default:
      return `Address the ${vuln} finding above.`;
  }
}

// For tests + the no-dead-modules check.
export const _ruleCount = RULES.length;
