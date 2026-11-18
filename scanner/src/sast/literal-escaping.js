// Hand-built string literals for another parser (CWE-94, and CWE-89 / CWE-78 when the literal is plainly SQL or a shell command).
//
// Two shapes, both about a program that builds a quoted literal of some other language by hand instead of with that language's
// encoder:
//
//   quote escaped, backslash not   `s.replace("'", "\\'")`, `s.replace(/"/g, '\\"')`, `str_replace("'", "\\'", $s)`. Prefixing each quote
//                                  with a backslash is only meaningful to a parser that reads backslash escapes (source code, an
//                                  expression, a script). Such a parser also reads a backslash already in the value: `x\` becomes
//                                  `x\\'`, the escape is consumed by the value's own backslash, the quote closes the literal and the
//                                  rest of the value is parsed as code. Silent when the same statement (or the lines around it)
//                                  escapes backslashes first, uses a character class that covers both, or wraps the value in a real encoder.
//   quoted interpolation          a JS/TS template literal that is a line of generated code (it ends in `;`) and places a value
//   in generated code             between double quotes as a call argument: `` `assertEq(x.name(), "${opts.name}");` ``. Nothing
//                                  escapes the value at all; the fix is `JSON.stringify(v)` (or the target language's encoder).
//
// The CWE is chosen from what the literal is for: SQL text gets CWE-89, a shell command CWE-78, anything else (source code, an
// expression, a script) CWE-94.
const FILE_RE = /\.(?:py|m?[jt]sx?|cjs|php)$/i;

// the searched-for quote, as a string or a one-character regex
const QUOTE_ARG = String.raw`(?:'"'|"\\""|"'"|'\\''|\/\\?"\/g?|\/\\?'\/g?|` + '`"`|`\'`)';
// the replacement: a backslash followed by that quote
const ESCAPED_ARG = String.raw`(?:'\\\\"'|"\\\\\\""|"\\\\'"|'\\\\\\''|` + '`\\\\\\\\"`|`\\\\\\\\\'`)';
const JS_PY_RE = new RegExp(String.raw`\.(?:replace|replaceAll)\s*\(\s*` + QUOTE_ARG + String.raw`\s*,\s*` + ESCAPED_ARG + String.raw`\s*[,)]`, 'g');
const PHP_RE = new RegExp(String.raw`\bstr_replace\s*\(\s*` + QUOTE_ARG + String.raw`\s*,\s*` + ESCAPED_ARG + String.raw`\s*,`, 'g');

// backslashes escaped first, both escaped by one class, or a real encoder used: the fix
const BACKSLASH_FIRST = new RegExp([
  String.raw`(?:replace|replaceAll|str_replace)\s*\(\s*(?:'\\\\+'|"\\\\+"|\/\\\\+\/g?|r'\\\\+')`, // replace('\\', ...)
  String.raw`(?:replace|replaceAll)\s*\(\s*\/\[[^\]\n]*\\\\[^\]\n]*\]`, // replace(/[\\"]/g, ...)
  String.raw`\baddslashes\s*\(`,
].join('|'));
// an encoder wrapped around the escaped value itself (an encoder elsewhere on the line, e.g. the other branch of a ternary, is not)
const ENCODER_AROUND = /\b(?:json\.dumps|JSON\.stringify|repr|json_encode|var_export)\s*\([^()\n]{0,80}$/;

// a template literal ending in `;` that puts an interpolation between double quotes as a call argument
const TEMPLATE_RE = /`([^`\n]{0,400})`/g;
const QUOTED_ARG_IN_TEMPLATE = /[(,]\s*"\$\{([^{}]{1,120})\}"\s*[,)]/;

const SQL_HINT = /\b(?:SELECT\s[\s\S]{0,200}\bFROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b|\b(?:execute|executemany|query|raw)\s*\(/;
const SHELL_HINT = /\b(?:subprocess|os\.system|os\.popen|child_process|execSync|spawnSync|shell_exec|proc_open|passthru)\b|\bexec\s*\(\s*['"`]/;

const lineOf = (code, i) => code.slice(0, i).split('\n').length;
const around = (lines, line, n) => lines.slice(Math.max(0, line - 1 - n), Math.min(lines.length, line + n)).join('\n');

function cweFor(win) {
  if (SQL_HINT.test(win)) return ['CWE-89', 'SQL'];
  if (SHELL_HINT.test(win)) return ['CWE-78', 'a shell command'];
  return ['CWE-94', 'code another interpreter parses'];
}

export function scanLiteralEscaping(file, code) {
  if (!FILE_RE.test(file) || /\.min\.[jt]s$/i.test(file) || !code || code.length > 500_000) return [];
  const isPhp = /\.php$/i.test(file);
  const isJs = /\.(?:m?[jt]sx?|cjs)$/i.test(file);
  const out = []; const seen = new Set();
  const lines = code.split('\n');
  const push = (line, sub, cwe, vuln, description, remediation) => {
    const key = `${sub}:${line}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({
      id: `literal-escaping:${sub}:${file}:${line}`, file, line, vuln, severity: 'high', cwe,
      family: cwe === 'CWE-89' ? 'sql-injection' : cwe === 'CWE-78' ? 'command-injection' : 'code-injection',
      subfamily: sub, description, remediation, parser: 'LITERAL-ESCAPING', confidence: 0.6,
      snippet: (lines[line - 1] || '').trim().slice(0, 200),
    });
  };

  // shape 1: quote escaped with a backslash, backslash itself not escaped
  if (/\\\\["']|\\\\\\["']/.test(code)) {
    const re = new RegExp((isPhp ? PHP_RE : JS_PY_RE).source, 'g');
    let m;
    while ((m = re.exec(code))) {
      const line = lineOf(code, m.index);
      if (BACKSLASH_FIRST.test(around(lines, line, 3))) continue;
      if (ENCODER_AROUND.test(code.slice(Math.max(0, m.index - 160), m.index))) continue;
      const [cwe, what] = cweFor(around(lines, line, 8));
      push(line, 'quote-without-backslash', cwe,
        'Incomplete literal escaping: quotes escaped with a backslash, backslashes not escaped',
        `Each quote in the value is prefixed with a backslash so it can sit inside a quoted literal of ${what}, but a backslash already in the value is left alone. A value ending in a backslash turns the added escape into an escaped backslash, the quote then closes the literal, and the rest of the value is read as syntax.`,
        'Escape backslashes before quotes (`.replace("\\\\", "\\\\\\\\")` first), or better, use the target language\'s own encoder: `json.dumps`/`repr` in Python, `JSON.stringify` in JavaScript, a parameterized query for SQL, an argument array for a process.');
    }
  }

  // shape 2: a value placed between double quotes in a template literal that is a line of generated code
  if (isJs && code.includes('"${')) {
    let m;
    TEMPLATE_RE.lastIndex = 0;
    while ((m = TEMPLATE_RE.exec(code))) {
      const body = m[1];
      if (!/;\s*$/.test(body)) continue; // generated statements end in `;`; prose and markup do not
      if (/<\/?[A-Za-z][\w-]*[\s>]/.test(body)) continue; // markup, a different encoder
      const q = body.match(QUOTED_ARG_IN_TEMPLATE);
      if (!q) continue;
      if (/\b(?:JSON\.stringify|escape\w*|quote\w*|encode\w*|sanitize\w*)\s*\(/i.test(q[1])) continue;
      if (/^\s*['"`]/.test(q[1])) continue; // a literal written here, not a value from elsewhere
      const line = lineOf(code, m.index);
      const [cwe, what] = cweFor(body);
      push(line, 'generated-code-quoted-interpolation', cwe,
        'Value interpolated between quotes in generated code without encoding',
        `This template literal is a statement of generated ${cwe === 'CWE-94' ? 'source code' : what} and places \`${q[1].trim()}\` between double quotes with no encoding. A value containing a double quote or a backslash closes the string literal and the rest of the value becomes code in the generated file.`,
        'Build the literal with an encoder (`JSON.stringify(value)` produces a double-quoted literal with quotes, backslashes and control characters escaped), or reject values outside a known-safe character set.');
    }
  }
  return out;
}
