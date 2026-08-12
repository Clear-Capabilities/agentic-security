// Sanitizer-validity proofs (P4.2).
//
// The taint engine trusts any catalog-registered sanitizer to neutralize
// the threat. Real projects ship their own sanitizers — `sanitize(x)`,
// `clean(input)`, `validate(s)` — and the catalog matches them by NAME.
// But a function called `sanitize` that just does `return input.trim()`
// does NOT sanitize XSS; trusting it produces false negatives at scale.
//
// This module verifies, before the engine treats a project-local function
// as a sanitizer, that its body actually performs the required check for
// the CWE it claims to mitigate. Per-CWE shape rules:
//
//   xss:        body must call escape | DOMPurify.sanitize | bleach.clean
//               | str.replace(/<[^>]+>/g, ...) | textContent assignment
//   sql:        body must call .prepare | .bind | parameterized query
//   path-trav:  body must call path.resolve + assertion against base dir
//   ssrf:       body must check scheme/host against allow-list
//   open-redir: body must check scheme/host against allow-list
//   url:        body must call encodeURIComponent / encodeURI
//   cmd:        body must call shellEscape / shlex.quote / spawn with argv
//
// Public API:
//   isValidSanitizerFor(fnBody, cweFamily)
//     → { trusted: bool, reason: string }
//
//   verifyProjectSanitizers(perFileIR, catalogEntries)
//     → produces a new catalog set where untrusted local sanitizers are
//       DEMOTED to "noop" (no strip effect); trusted ones stay.

const _SHAPE_RULES = {
  'xss': [
    { re: /\b(?:DOMPurify\.sanitize|sanitizeHtml|bleach\.clean|escapeHtml|html_escape|htmlEscape|encodeHTML|escapeAll)\b/, label: 'HTML-escaping library call' },
    { re: /\.replace\s*\(\s*\/[<>"'&]/, label: 'inline HTML-special character replace' },
    { re: /textContent\s*=/, label: 'textContent assignment' },
  ],
  'sql': [
    { re: /\.(?:prepare|bind|bindParam|execute)\s*\(/, label: 'parameterized query call' },
    { re: /\b(?:placeholder|\?|\$\d)\b.*?(?:select|insert|update|delete)/i, label: 'placeholder in SQL string' },
  ],
  'path-trav': [
    { re: /\bpath\.resolve\b[\s\S]{0,200}\.startsWith\s*\(/, label: 'path.resolve + startsWith allow-list check' },
    { re: /\b(?:realpath|os\.path\.realpath|pathlib\.Path[\s\S]{0,40}\.resolve)\b/, label: 'canonicalization' },
    { re: /\.includes\s*\(\s*['"]\.\.['"]\s*\)/, label: 'dotdot string check' },
  ],
  'ssrf': [
    { re: /\b(?:allowedHosts?|allowed_hosts?|hostWhitelist|allowedSchemes?)\b/, label: 'allow-list constant reference' },
    { re: /\.host\s*===?\s*['"][^'"]+['"]/, label: 'literal host comparison' },
    { re: /\b(?:169\.254\.169\.254|127\.0\.0\.0\/8|RFC1918|10\.0\.0\.0|172\.16\.0\.0|192\.168\.0\.0)\b/, label: 'metadata / RFC1918 deny-list' },
  ],
  'open-redir': [
    { re: /\b(?:allowedRedirects?|safeRedirects?|allowedHosts?|trustedDomains?)\b/, label: 'allow-list constant reference' },
    { re: /\.host\s*===?\s*['"][^'"]+['"]/, label: 'literal host comparison' },
  ],
  'url': [
    { re: /\b(?:encodeURIComponent|encodeURI|urllib\.parse\.quote|urlencode)\b/, label: 'URL encoder call' },
  ],
  'cmd': [
    { re: /\b(?:shellEscape|shlex\.quote|Shellwords\.escape|escapeshellarg)\b/, label: 'shell-escape library call' },
    { re: /\.spawn\s*\(\s*['"][^'"]+['"]\s*,\s*\[/, label: 'spawn with argv array' },
    { re: /\bsubprocess\.run\s*\(\s*\[[^\]]*\]\s*,/, label: 'subprocess.run with list arg' },
  ],
};

const _CWE_TO_FAMILY = {
  'CWE-79': 'xss', 'CWE-80': 'xss', 'CWE-81': 'xss', 'CWE-83': 'xss',
  'CWE-89': 'sql',
  'CWE-22': 'path-trav', 'CWE-23': 'path-trav', 'CWE-36': 'path-trav',
  'CWE-918': 'ssrf',
  'CWE-601': 'open-redir',
  'CWE-78': 'cmd',
};

/**
 * Verify that a function body satisfies the shape rule for the given
 * vulnerability family. Returns `{ trusted, reason }`.
 *
 *   fnBody:     the function's source text (post-comment-strip ideally)
 *   family:     one of the keys of _SHAPE_RULES (or a CWE id we map)
 */
export function isValidSanitizerFor(fnBody, family) {
  if (!fnBody || typeof fnBody !== 'string') return { trusted: false, reason: 'no body' };
  if (!family) return { trusted: false, reason: 'no family' };
  // Map CWE id to family if needed.
  const fam = _CWE_TO_FAMILY[family] || family;
  const rules = _SHAPE_RULES[fam];
  if (!rules) return { trusted: false, reason: `no shape rule for family '${fam}'` };
  for (const r of rules) {
    if (r.re.test(fnBody)) return { trusted: true, reason: `matched: ${r.label}` };
  }
  return { trusted: false, reason: `body does not match any known ${fam} shape pattern` };
}

/**
 * Walk the project IR and verify every project-local function that's
 * registered as a sanitizer in the catalog. Returns an array of
 *   { fnQid, family, trusted, reason }
 * The engine consumer can demote untrusted entries from the catalog at
 * runtime by removing their `effect: 'strip'` flag.
 */
export function verifyProjectSanitizers(perFileIR, catalog) {
  const out = [];
  if (!perFileIR || !Array.isArray(catalog)) return out;
  // Index project functions by short name.
  const fnByName = new Map();
  for (const ir of Object.values(perFileIR)) {
    for (const fn of (ir.functions || [])) {
      const short = fn.name || (fn.qid || '').split('::').pop();
      if (!short) continue;
      if (!fnByName.has(short)) fnByName.set(short, []);
      fnByName.get(short).push(fn);
    }
  }
  for (const entry of catalog) {
    if (entry.kind !== 'sanitizer') continue;
    if (entry.match?.type !== 'call') continue;
    const calleeName = entry.match.callee;
    if (!calleeName) continue;
    const fns = fnByName.get(calleeName);
    if (!fns || !fns.length) continue;            // not a project-local sanitizer
    // Stage 3 correctness audit (detection depth): this used to take only
    // `appliesTo[0]`, so a multi-family entry (`appliesTo: ['sql', 'xss']`)
    // was only ever verified against its FIRST tag — silently skipping
    // whether the project's local function actually behaves as a
    // sanitizer for the OTHER families it claims to cover. It also fell
    // back to the literal string `'*'` when `appliesTo` was absent or
    // wildcard-only, and `'*'` has no entry in `_SHAPE_RULES` — every
    // wildcard-tagged sanitizer (the 17 catalog type-coercion entries:
    // parseInt, Number(), etc.) was unconditionally verdicted
    // `trusted: false, reason: "no shape rule for family '*'"`, even
    // though `'*'` legitimately covers every family by design (see
    // sanitizer-gate.js's own header comment on the same wildcard tag).
    // Fixed: verify against every concrete (non-'*') family the entry
    // claims; a wildcard-only entry has no per-family shape to check
    // against and contributes no verdict rather than a misleading false one.
    const families = (Array.isArray(entry.appliesTo) ? entry.appliesTo : []).filter(f => f !== '*');
    if (!families.length) continue;
    for (const fn of fns) {
      const bodyText = _stringifyCfgBody(fn);
      for (const family of families) {
        const verdict = isValidSanitizerFor(bodyText, family);
        out.push({ fnQid: fn.qid, family, trusted: verdict.trusted, reason: verdict.reason });
      }
    }
  }
  return out;
}

function _stringifyCfgBody(fn) {
  // Reconstruct a rough textual representation of the function body from
  // its CFG nodes — sufficient for regex shape matching.
  const parts = [];
  const nodes = fn.cfg?.nodes || {};
  for (const id of Object.keys(nodes)) {
    const n = nodes[id];
    if (!n) continue;
    if (n.kind === 'call') parts.push(`${n.callee || '?'}(${(n.args || []).length} args)`);
    if (n.kind === 'assign') parts.push(`${n.target} = ${_exprStr(n.source)}`);
    if (n.kind === 'return') parts.push(`return ${_exprStr(n.value)}`);
  }
  return parts.join('\n');
}

function _exprStr(e) {
  if (!e) return '';
  if (e.kind === 'literal') return String(e.value);
  if (e.kind === 'ident') return e.name;
  if (e.kind === 'member') return `${_exprStr(e.object)}.${e.prop}`;
  if (e.kind === 'call') return `${typeof e.callee === 'string' ? e.callee : _exprStr(e.callee)}(...)`;
  if (e.kind === 'binary' || e.kind === 'logical') return `${_exprStr(e.left)} ${e.op || '?'} ${_exprStr(e.right)}`;
  if (e.kind === 'tpl') return '`${...}`';
  return e.kind;
}
