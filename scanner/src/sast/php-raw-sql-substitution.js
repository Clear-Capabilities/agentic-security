// PHP: raw SQL built by substituting values into a query string (CWE-89).
//
// Two shapes the line-local SQL rules in php.js do not see, because neither concatenates a request superglobal on the sink line:
//
//   rawSubstitution   a query builder's raw method (whereRaw, orWhereRaw, havingRaw, selectRaw, orderByRaw, groupByRaw, DB::raw) whose
//                     first argument is a string-substitution call (strtr, str_replace, sprintf, vsprintf), optionally wrapped in one
//                     other call, and which is given no bindings argument. Substituting values into the SQL text is the injection;
//                     the bindings array is the fix. A sprintf whose literal format has only numeric conversions (%d, %u, %f) is
//                     skipped: the value is forced to a number.
//   implodeInList     a SQL fragment (`IN (`) concatenated with implode() over an array taken straight from json_decode, explode,
//                     unserialize or a request superglobal, so the elements reach the SQL unconverted. Mapping the array through
//                     intval/floatval first (array_map('intval', ...)) is the fix and is not flagged.
//
// The rule does not decide whether the substituted values are attacker text; the finding says so.

import { blankComments } from './_comment-strip.js';

const RAW_CALL = /(?:->|::)\s*(whereRaw|orWhereRaw|havingRaw|orHavingRaw|selectRaw|orderByRaw|groupByRaw)\s*\(|\bDB::raw\s*\(/g;
const SUBST_HEAD = /^(?:[\w\\$>:-]+\s*\(\s*)?(strtr|str_replace|str_ireplace|sprintf|vsprintf)\s*\(/;
const NUMERIC_FORMAT = /^(['"])(?:[^%'"\\]|\\.|%%|%[-+ 0]*\d*(?:\.\d+)?[dufFeEbcoxX])*\1$/;
const IMPLODE_IN = /\bIN\s*\(\s*["']\s*\.\s*implode\s*\(\s*(['"][^'"]*['"])\s*,\s*((?:json_decode|explode|unserialize)\s*\(|\$_(?:GET|POST|REQUEST|COOKIE)\b)/gi;

/** Index of the bracket closing the one opened just before `open`, skipping quoted strings; -1 when unbalanced. */
function closeParen(src, open) {
  let depth = 1;
  for (let i = open; i < src.length && i - open < 4000; i++) {
    const c = src[i];
    if (c === '"' || c === "'") {
      for (i++; i < src.length && src[i] !== c; i++) if (src[i] === '\\') i++;
      continue;
    }
    if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') { depth--; if (depth === 0) return i; }
  }
  return -1;
}

/** Split a call's argument text at top-level commas. */
function topLevelArgs(text) {
  const out = []; let depth = 0; let start = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '"' || c === "'") { for (i++; i < text.length && text[i] !== c; i++) if (text[i] === '\\') i++; continue; }
    if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') depth--;
    else if (c === ',' && depth === 0) { out.push(text.slice(start, i)); start = i + 1; }
  }
  out.push(text.slice(start));
  return out.map((s) => s.trim()).filter(Boolean);
}

const lineOf = (src, idx) => src.slice(0, idx).split('\n').length;

// A value quoted for SQL or forced to a number before it is substituted.
const SQL_SAFE_CALL = /(?:->|::)\s*quote\s*\(|\b(?:intval|floatval|boolval|(?:mysqli_|pg_|sqlite_)?(?:real_)?escape_(?:string|literal)|addslashes)\s*\(|\(\s*(?:int|integer|float|double|bool)\s*\)/;
const SQL_SAFE_EXPR = /(?:(?:\$?[\w\\]+(?:\s*(?:->|::)\s*\w+\s*(?:\([^()]*\))?)*?\s*)?(?:->|::)\s*quote|\b(?:intval|floatval|boolval|(?:mysqli_|pg_|sqlite_)?(?:real_)?escape_(?:string|literal)|addslashes))\s*\([^()]*(?:\([^()]*\)[^()]*)*\)|\(\s*(?:int|integer|float|double|bool)\s*\)\s*\$[\w>\-[\]']+/g;

/** True when every substituted value is quoted, numeric, a literal, or a local whose every assignment in view is one of those. */
function valuesAreSafe(valuesText, before) {
  const t = valuesText.replace(/'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"/g, "''").replace(SQL_SAFE_EXPR, '0');
  if (/\$this\b/.test(t)) return false;
  for (const v of new Set([...t.matchAll(/\$(\w+)/g)].map((m) => m[1]))) {
    const assigns = [...before.matchAll(new RegExp(`\\$${v}\\s*=(?![=>])([^;]*)`, 'g'))];
    if (!assigns.length || !assigns.every((a) => SQL_SAFE_CALL.test(a[1]))) return false;
  }
  return true;
}

export function scanPhpRawSqlSubstitution(fp, input) {
  if (!/\.(?:php|phtml)$/i.test(fp) || typeof input !== 'string' || input.length > 500_000) return [];
  if (!/Raw\s*\(|DB::raw|implode/.test(input)) return [];
  const raw = blankComments(input, 'php');
  const lines = raw.split('\n');
  const out = []; const seen = new Set();
  const push = (key, idx, vuln, description, remediation) => {
    const line = lineOf(raw, idx);
    const id = `php-${key}:${fp}:${line}`;
    if (seen.has(id)) return;
    seen.add(id);
    out.push({
      id, file: fp, line, vuln, severity: 'high', cwe: 'CWE-89', family: 'sql-injection', description, remediation,
      snippet: (lines[line - 1] || '').trim().slice(0, 200), parser: 'PHP', confidence: 0.7,
    });
  };

  for (const m of raw.matchAll(RAW_CALL)) {
    const open = m.index + m[0].length;
    const close = closeParen(raw, open);
    if (close < 0) continue;
    const args = topLevelArgs(raw.slice(open, close));
    if (args.length !== 1) continue; // a second argument is the bindings array
    const head = args[0].match(SUBST_HEAD);
    if (!head) continue;
    if (head[1] === 'sprintf' || head[1] === 'vsprintf') {
      const inner = args[0].slice(head[0].length);
      const end = closeParen(inner, 0);
      const fmt = topLevelArgs(end < 0 ? inner : inner.slice(0, end))[0] || '';
      if (NUMERIC_FORMAT.test(fmt)) continue;
    }
    // the substituted values: everything after the template (strtr, sprintf) or the replacement argument (str_replace)
    const inner = args[0].slice(head[0].length);
    const innerEnd = closeParen(inner, 0);
    const substArgs = topLevelArgs(innerEnd < 0 ? inner : inner.slice(0, innerEnd));
    const values = head[1].startsWith('str_') ? substArgs.slice(1, 2) : substArgs.slice(1);
    if (values.length && valuesAreSafe(values.join(','), raw.slice(Math.max(0, m.index - 3000), m.index))) continue;
    const method = m[1] || 'DB::raw';
    push('rawSubstitution', m.index, `SQL Injection: ${method}() given SQL built by ${head[1]}() with no bindings`,
      `The SQL passed to \`${method}\` is produced by \`${head[1]}\`, which writes values into the query text, and no bindings array is passed. A value holding a quote or SQL syntax changes the query. Whether those values can come from a user is not checked here.`,
      `Put placeholders (\`?\` or \`:name\`) in the SQL and pass the values as the bindings argument: \`->${m[1] || 'whereRaw'}($sql, $bindings)\`. Cast values that must be numbers with (int)/(float).`);
  }

  for (const m of raw.matchAll(IMPLODE_IN)) {
    push('implodeInList', m.index, 'SQL Injection: IN (...) list built by implode() over an unconverted decoded or request array',
      'An `IN (...)` list is built by joining an array taken straight from decoded or request input into the SQL text. Any element that is not a number is written into the query as SQL.',
      "Convert every element before joining (`implode(',', array_map('intval', $ids))`), or build one placeholder per element and pass the array as bindings.");
  }
  return out;
}
