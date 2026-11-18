// Path and file handling defects that are not plain request-to-sink taint.
//
// Each rule keys on the semantics of the code (which API, which missing
// guard), never on a project. All rules read the comment-blanked view the
// engine hands every detector, and every rule is language-gated.
//
//   path-ref-join-read       CWE-22  A document reference (a `$ref`, an include,
//                                    a `${file:...}` value) or a decoded name is
//                                    joined under a base directory and the result
//                                    is read (or returned by a path helper) with
//                                    no containment check in the function.
//   php-upload-client-name   CWE-22  A client-supplied upload filename is
//                                    concatenated into the destination of a file
//                                    move/copy without being reduced to a basename.
//   ruby-request-path-serve  CWE-22  A request URL path flows, through methods of
//                                    the same file, into a method that streams
//                                    the named file back. Reported at the call.
//   weak-clean-guard         CWE-22  `Clean(p) != p` (or normpath/normalize) used
//                                    as the traversal check on a relative path:
//                                    cleaning keeps a leading `..`, so the check
//                                    passes exactly the input it was meant to stop.
//   bare-prefix-containment  CWE-22  Containment decided by a raw string prefix of
//                                    a resolved path, with no trailing separator:
//                                    `/srv/app-evil` starts with `/srv/app`.
//   go-request-path-join     CWE-22  A Go handler joins a request value (query,
//                                    form, route parameter) into a filesystem
//                                    path with no Base / IsLocal / containment
//                                    check in the function.
//   go-decoded-path-forwarded CWE-22 A Go middleware decodes a path rewritten
//                                    from the incoming escaped path into URL.Path
//                                    and forwards the request without normalizing.
//   unmasked-file-mode       CWE-732 A permission mode parsed from data (metadata,
//                                    an archive header) is applied with chmod
//                                    without masking it to the permission bits,
//                                    so setuid/setgid/sticky bits are honoured.
//   suffix-extension-denylist CWE-434 An upload extension denylist enforced only
//                                    by checking the end of the name, so a name
//                                    with the blocked extension in the middle
//                                    (`x.php.jpg`) passes.

function lineOf(code, idx) {
  let n = 1;
  for (let i = 0; i < idx && i < code.length; i++) if (code.charCodeAt(i) === 10) n++;
  return n;
}

function escRe(s) { return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

// Index of the bracket matching the one at `open` (same kind), or -1.
function matchBracket(code, open) {
  const o = code[open];
  const c = o === '(' ? ')' : o === '{' ? '}' : ']';
  let d = 0;
  for (let i = open; i < code.length; i++) {
    const ch = code[i];
    if (ch === '"' || ch === "'" || ch === '`') {
      // skip a string literal on one line (or a backtick across lines)
      const q = ch; i++;
      while (i < code.length && code[i] !== q) {
        if (code[i] === '\\') i++;
        else if (q !== '`' && code[i] === '\n') break;
        i++;
      }
      continue;
    }
    if (ch === o) d++;
    else if (ch === c) { d--; if (d === 0) return i; }
  }
  return -1;
}

function langOf(fp) {
  const m = /\.([a-z0-9]+)$/i.exec(fp || '');
  const e = m ? m[1].toLowerCase() : '';
  if (e === 'py') return 'py';
  if (e === 'go') return 'go';
  if (e === 'cs') return 'cs';
  if (e === 'rs') return 'rs';
  if (e === 'php') return 'php';
  if (e === 'rb') return 'rb';
  if (/^(?:js|jsx|mjs|cjs|ts|tsx|mts|cts)$/.test(e)) return 'js';
  if (e === 'java' || e === 'kt') return 'java';
  return null;
}

// Parameter names from a parameter-list text, any of the supported languages.
function paramNames(text, lang) {
  const out = [];
  let depth = 0, cur = '';
  const parts = [];
  for (const ch of String(text)) {
    if ('([{<'.includes(ch)) depth++;
    else if (')]}>'.includes(ch)) depth--;
    if (ch === ',' && depth === 0) { parts.push(cur); cur = ''; } else cur += ch;
  }
  if (cur.trim()) parts.push(cur);
  for (let p of parts) {
    p = p.replace(/=.*$/s, '').trim();
    if (!p) continue;
    let name = null;
    if (lang === 'go') name = (/^(\w+)/.exec(p) || [])[1];
    else if (lang === 'py' || lang === 'js' || lang === 'rs' || lang === 'rb') name = (/^[*&]*(?:mut\s+)?(\w+)/.exec(p.replace(/^(?:public|private|protected|readonly)\s+/, '')) || [])[1];
    else if (lang === 'php') name = (/\$(\w+)/.exec(p) || [])[1];
    else { const ids = p.match(/\w+/g); name = ids ? ids[ids.length - 1] : null; }
    if (name && name !== 'self' && name !== 'this') out.push(name);
  }
  return out;
}

// Functions of a file: { name, params, start, bodyStart, end }. Offsets index
// the comment-blanked code. Brace languages by bracket matching, Python by
// indentation, Ruby by the `end` at the definition's indentation.
function functionsOf(code, lang) {
  const fns = [];
  if (lang === 'py' || lang === 'rb') {
    const lines = code.split('\n');
    const offs = []; let o = 0;
    for (const l of lines) { offs.push(o); o += l.length + 1; }
    const head = lang === 'py' ? /^(\s*)(?:async\s+)?def\s+(\w+)\s*\(/ : /^(\s*)def\s+(?:self\.)?(\w+[?!]?)\s*(\(|$|\s)/;
    for (let i = 0; i < lines.length; i++) {
      const m = head.exec(lines[i]);
      if (!m) continue;
      const ind = m[1].length;
      let params = [];
      const pIdx = offs[i] + lines[i].indexOf('(', m[0].length - 1 - (m[3] === '(' || lang === 'py' ? 0 : 1));
      if ((lang === 'py' || m[3] === '(') && code[pIdx] === '(') {
        const close = matchBracket(code, pIdx);
        if (close > 0) params = paramNames(code.slice(pIdx + 1, close).replace(/:[^,]*/g, ''), lang);
      } else if (lang === 'rb') {
        params = paramNames(lines[i].slice(m[0].length), lang);
      }
      let j = i + 1;
      if (lang === 'py') {
        // skip the rest of a multi-line signature
        while (j < lines.length && !/:\s*$/.test(lines[j - 1]) && j < i + 30) j++;
        while (j < lines.length && (lines[j].trim() === '' || lines[j].search(/\S/) > ind)) j++;
      } else {
        while (j < lines.length && !(lines[j].search(/\S/) === ind && /^\s*end\b/.test(lines[j]))) j++;
      }
      const endLine = Math.min(j, lines.length) - 1;
      fns.push({ name: m[2], params, start: offs[i], bodyStart: offs[Math.min(i + 1, lines.length - 1)], end: offs[endLine] + lines[endLine].length });
    }
    return fns;
  }
  let head;
  if (lang === 'go') head = /\bfunc\s*(?:\([^)]*\)\s*)?(\w+)\s*(?:\[[^\]]*\])?\s*\(/g;
  else if (lang === 'php') head = /\bfunction\s+&?(\w+)\s*\(/g;
  else if (lang === 'rs') head = /\bfn\s+(\w+)\s*(?:<[^>{]*>)?\s*\(/g;
  else if (lang === 'js') head = /(?:\bfunction\s*\*?\s*(\w+)\s*(?:<[^>(]*>)?\s*\(|^[ \t]*(?:(?:public|private|protected|static|async|override|readonly|get|set)[ \t])*(\w+)\s*(?:<[^>(]*>)?\s*\(|\b(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?(?:function\s*)?\()/gm;
  else head = /(?:^|[\s;{}])(?:(?:public|private|protected|internal|static|async|override|virtual|sealed|abstract|final|unsafe|extern|new|synchronized)[ \t])*[\w<>\[\],.?]+(?:\s*<[^>]*>)?\s+(\w+)\s*(?:<[^>]*>)?\s*\(/g;
  let m;
  while ((m = head.exec(code))) {
    const name = m[1] || m[2] || m[3];
    if (!name || /^(?:if|for|while|switch|catch|return|new|using|lock|foreach|sizeof|typeof|when|else|function)$/.test(name)) continue;
    const pOpen = m.index + m[0].length - 1;
    const pClose = matchBracket(code, pOpen);
    if (pClose < 0) continue;
    // the body brace: next `{` after the parameter list, with no `;` before it
    let k = pClose + 1;
    while (k < code.length && code[k] !== '{' && code[k] !== ';') {
      if (code[k] === '=' && code[k + 1] === '>' && lang !== 'js') break;
      k++;
    }
    if (code[k] !== '{') {
      if (lang === 'js' && code[k] === '=' && code[k + 1] === '>') {
        let b = k + 2; while (/\s/.test(code[b] || '')) b++;
        if (code[b] !== '{') continue;
        k = b;
      } else continue;
    }
    const bEnd = matchBracket(code, k);
    if (bEnd < 0) continue;
    fns.push({ name, params: paramNames(code.slice(pOpen + 1, pClose), lang), start: m.index, bodyStart: k + 1, end: bEnd });
    if (lang !== 'js' && lang !== 'go') head.lastIndex = Math.max(head.lastIndex, pClose);
  }
  return fns;
}

// Simple forward propagation over assignments in a body: a variable assigned
// from an expression mentioning a tainted name becomes tainted. Returns the set.
function propagate(body, seeds, lang, killRe = null) {
  const t = new Set(seeds);
  const assign = lang === 'php'
    ? /\$(\w+)\s*(?:\?\?=|\.=|=(?![=>]))\s*([^;]+);/g
    : lang === 'go'
      ? /\b(\w+)(?:,[ \t]?\w+)?(?:,[ \t]?\w+)?[ \t]*(?::=|=(?!=))[ \t]*([^\n;]+)/g
      : /\b(?:(?:var|let|const|val|auto|string|String|str)\s+)?(\w+)\s*(?::\s*[\w.<>\[\]|, ]+)?\s*(?:\+=|=(?![=>]))\s*([^\n;]+)/g;
  for (let pass = 0; pass < 3; pass++) {
    let m; const r = new RegExp(assign.source, assign.flags);
    while ((m = r.exec(body))) {
      const v = m[1], rhs = m[2];
      if (t.has(v)) {
        if (killRe && killRe.test(rhs)) t.delete(v);
        continue;
      }
      for (const s of t) {
        if (new RegExp(`(?:^|[^\\w$])${lang === 'php' ? '\\$' : ''}${escRe(s)}\\b`).test(rhs)) {
          if (!(killRe && killRe.test(rhs))) t.add(v);
          break;
        }
      }
    }
  }
  return t;
}

const mentions = (text, name, lang) => new RegExp(`(?:^|[^\\w$.])${lang === 'php' ? '\\$' : ''}${escRe(name)}\\b`).test(text);

function finding(fp, line, code, o) {
  const snippet = (code.split('\n')[line - 1] || '').trim().slice(0, 200);
  return {
    id: `${o.rule}:${fp}:${line}`,
    file: fp, line,
    severity: o.severity || 'high',
    vuln: o.vuln,
    cwe: o.cwe,
    family: o.family,
    parser: 'PATH-FILE-HANDLING',
    description: o.description,
    remediation: o.remediation,
    snippet,
    confidence: o.confidence || 0.7,
  };
}

// ---------------------------------------------------------------------------
// Rule: path-ref-join-read
// ---------------------------------------------------------------------------

// A name that denotes a reference taken from a document: `$ref`, `ref`,
// `resolved_ref`, `fileRef`, `reference`, an include target.
// Case-sensitive on purpose: `href`, `pref`, `fixtureFile` are not references.
const REF_PARAM = /^ref$|_ref$|[a-z]Ref$|^ref_?(?:path|name|uri|url)$|^ref(?:Path|Name|Uri|Url)$|^[Rr]eference(?:_?[Pp]ath)?$|_reference$|[a-z]Reference$|^include(?:_?(?:path|file|name|target)|Path|File|Name|Target)?$|^included?_?(?:path|file)$/;
// A function whose job is to resolve such a reference.
const REF_FN = /(?:^|_)ref(?:s|erences?)?(?:_|$)|[a-z]Ref(?:s|erences?)?(?:[A-Z]|$)|^Ref(?:s|erences?)?[A-Z]|^[Rr]esolve_?(?:[Ff]ile_?)?[Rr]efs?|[Ii]nclude_?[Ff]ile|[Rr]esolve_?[Ii]nclude/;
const REF_FN_PARAM = /path|file|name|ref|target|uri|url|value/i;

// Decoders whose output may contain separators or `..` even when the encoded
// input did not.
const DECODED = /\b(?:url\.(?:PathUnescape|QueryUnescape)|\w+\.FromStandard(?:Path|Name)|unquote(?:_plus)?|url2pathname|decodeURIComponent|decodeURI|Uri\.UnescapeDataString|HttpUtility\.UrlDecode|WebUtility\.UrlDecode|urldecode|rawurldecode)\s*\(/;

const JOIN = {
  py: /\bos\.path\.join\s*\(|\bjoinpath\s*\(|\b(?:Path|PurePath|PosixPath)\s*\(\s*[\w.]+\s*,|\b[\w.]*(?:base|root|dir|folder|directory)\w*\s*\/\s*(?=[\w(])/gi,
  cs: /\bPath\s*\.\s*(?:Combine|Join)\s*\(/g,
  go: /\b(?:filepath|path)\s*\.\s*Join\s*\(/g,
  rs: /\.join\s*\(/g,
  js: /\bpath\s*\.\s*(?:join|resolve)\s*\(/g,
  java: /\b(?:Paths\s*\.\s*get|Path\s*\.\s*of)\s*\(\s*\w+\s*,|\.resolve\s*\(|new\s+File\s*\(\s*\w+\s*,/g,
};

const READ_CALL = /\b(?:open|read_text|read_bytes|load\w*|read\w*|\w*_?(?:load|read)\w*|File\s*\.\s*(?:ReadAll\w+|Open\w*|ReadLines)|os\s*\.\s*(?:Open|ReadFile|OpenFile)|ioutil\s*\.\s*ReadFile|fs\s*::\s*(?:read\w*)|File\s*::\s*open|readFile\w*|createReadStream|Files\s*\.\s*(?:read\w*|newInputStream|lines)|new\s+(?:FileInputStream|FileReader|StreamReader))\s*\(/gi;

const CONTAIN = /\bis_relative_to\s*\(|\.relative_to\s*\(|\bcommonpath\s*\(|\bcommonprefix\s*\(|\.StartsWith\s*\(|\bHasPrefix\s*\(|\.startswith\s*\(|\.startsWith\s*\(|\.starts_with\s*\(|\bstrip_prefix\s*\(|\bfilepath\s*\.\s*(?:Rel|IsLocal)\s*\(|\bfs\s*\.\s*ValidPath\s*\(|\bGetRelativePath\s*\(|\bpath\s*\.\s*relative\s*\(|\bsafe_join\s*\(|\bsecure_filename\s*\(|\bbasename\s*\(|\bGetFileName\s*\(|\bBase\s*\(|\bnormalize\s*\(\s*\)\s*\.\s*startsWith/;
// `escapes` (a root-escape check), never `escape`: `PathUnescape` decodes.
const CONTAIN_FN_NAME = /within|inside|contain|escapes|outside|allowed|confine|safe_?join|secure|under_?root|in_?root|is_?sub|(?:check|validate|ensure|assert|verify|require)\w*(?:path|sandbox|root|dir)|sandbox/i;

function scanRefJoinRead(fp, code, lang, fns) {
  const out = [];
  const joinRe = JOIN[lang];
  if (!joinRe) return out;
  // Same-file helpers whose body performs a containment check.
  const containHelpers = new Set(fns.filter((f) => CONTAIN.test(code.slice(f.bodyStart, f.end))).map((f) => f.name));
  for (const fn of fns) {
    const body = code.slice(fn.bodyStart, fn.end);
    if (CONTAIN.test(body)) continue;
    let guarded = false;
    for (const h of containHelpers) if (h !== fn.name && new RegExp(`\\b${escRe(h)}\\s*\\(`).test(body)) { guarded = true; break; }
    if (guarded) continue;
    const callRe = /\b(\w+)\s*\(/g; let cm;
    while ((cm = callRe.exec(body))) if (CONTAIN_FN_NAME.test(cm[1])) { guarded = true; break; }
    if (guarded) continue;

    const seeds = fn.params.filter((p) => REF_PARAM.test(p) || (REF_FN.test(fn.name) && REF_FN_PARAM.test(p)));
    const tainted = propagate(body, seeds, lang);
    const r = new RegExp(joinRe.source, joinRe.flags);
    let m;
    while ((m = r.exec(body))) {
      // The joined operands after the base (the base itself is trusted).
      let rest = '';
      let exprEnd;
      if (body[m.index + m[0].length - 1] === '(') {
        const close = matchBracket(body, m.index + m[0].length - 1);
        if (close < 0) continue;
        const inner = body.slice(m.index + m[0].length, close);
        const comma = splitTopComma(inner);
        if (comma < 0) continue;
        rest = inner.slice(comma + 1);
        exprEnd = close;
      } else if (/\/\s*$/.test(m[0])) {
        const lineEnd = body.indexOf('\n', m.index);
        rest = body.slice(m.index + m[0].length, lineEnd < 0 ? body.length : lineEnd);
        exprEnd = lineEnd < 0 ? body.length : lineEnd;
      } else {
        // Path(base, x) / Paths.get(base, x) / new File(base, x): the prefix
        // already consumed the base and the comma.
        const close = matchBracket(body, body.lastIndexOf('(', m.index + m[0].length));
        rest = body.slice(m.index + m[0].length, close < 0 ? m.index + m[0].length + 120 : close);
        exprEnd = close < 0 ? m.index + m[0].length : close;
      }
      const decoded = DECODED.test(rest);
      const fromRef = [...tainted].some((t) => mentions(rest, t, lang));
      if (!decoded && !fromRef) continue;
      // Where does the joined path go: assigned to a variable, returned, or
      // passed straight to a read?
      const lineStart = body.lastIndexOf('\n', m.index) + 1;
      const stmt = body.slice(lineStart, body.indexOf('\n', exprEnd) < 0 ? body.length : body.indexOf('\n', exprEnd));
      const asg = /^[ \t]*(?:(?:var|let|const|val)[ \t])?(\w+)(?:,[ \t]?\w+)?(?:,[ \t]?\w+)?[ \t]*(?::[ \t]?[\w.<>\[\]]+[ \t]?)?(?::=|=(?!=))/.exec(stmt);
      const returned = /^\s*return\b/.test(stmt);
      let reaches = false;
      const preLine = body.slice(lineStart, m.index);
      const rr = new RegExp(READ_CALL.source, 'gi');
      let rm;
      while ((rm = rr.exec(preLine))) { reaches = true; break; }
      if (!reaches && asg) {
        const joined = propagate(body.slice(exprEnd), [asg[1]], lang);
        const after = body.slice(exprEnd);
        const rr2 = new RegExp(READ_CALL.source, 'gi');
        while ((rm = rr2.exec(after))) {
          const open = rm.index + rm[0].length - 1;
          const close = matchBracket(after, open);
          const args = after.slice(open + 1, close < 0 ? open + 200 : close);
          if ([...joined].some((j) => mentions(args, j, lang))) { reaches = true; break; }
        }
        // a read method called on the joined path itself: `p.read_text()`
        if (!reaches && [...joined].some((j) => new RegExp(`\\b${escRe(j)}\\s*\\.\\s*(?:read_text|read_bytes|open|ReadAllText|read_to_string)\\s*\\(`).test(after))) reaches = true;
      }
      // A path helper that returns a decoded name joined under its root.
      // Go's `path` package builds slash-separated names for remotes and URLs;
      // only an OS path (`filepath`) names a local file.
      if (!reaches && returned && decoded && (lang !== 'go' || /^filepath/.test(m[0]))) reaches = true;
      if (!reaches) continue;
      const line = lineOf(code, fn.bodyStart + m.index);
      out.push(finding(fp, line, code, {
        rule: 'path-ref-join-read', cwe: 'CWE-22', family: 'path-traversal',
        vuln: decoded ? 'Path traversal: decoded name joined under a root without containment check' : 'Path traversal: document reference joined under a base directory and read without containment check',
        description: decoded
          ? 'A name that was decoded (unescaped) is joined under a root directory and used as a filesystem path, and the function never checks that the result stays under the root. Decoding can produce separators and `..` segments that were not visible before it, so the join can address files outside the root.'
          : 'A reference taken from a document (a `$ref`, an include, a file reference) is joined under a base directory and the resulting file is read, with no check that the resolved path stays under that directory. A reference such as `../../etc/passwd` or an absolute path reads any file the process can open.',
        remediation: 'Resolve the joined path and refuse it unless it is inside the allowed root: Python `resolved.is_relative_to(base.resolve())`, Go `filepath.Rel(root, p)` rejecting a `..` result or `filepath.IsLocal(name)` before joining, C# `Path.GetRelativePath(root, full)` rejecting `..`/rooted results, Rust `canonicalize()` then `starts_with(root)`. Also reject absolute references, which most join functions let replace the base outright.',
      }));
    }
  }
  return out;
}

// Index of the first top-level comma in an argument text, or -1.
function splitTopComma(s) {
  let d = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === '"' || c === "'" || c === '`') { const q = c; i++; while (i < s.length && s[i] !== q) { if (s[i] === '\\') i++; i++; } continue; }
    if ('([{'.includes(c)) d++;
    else if (')]}'.includes(c)) d--;
    else if (c === ',' && d === 0) return i;
  }
  return -1;
}

// ---------------------------------------------------------------------------
// Rule: php-upload-client-name
// ---------------------------------------------------------------------------

const PHP_CLIENT_NAME_CALL = /->\s*(?:getClientOriginalName|getClientName|getClientFilename)\s*\(\s*\)|\$_FILES\s*\[[^\]]+\]\s*\[\s*['"]name['"]\s*\]/;
const PHP_NAME_SANITIZER = /\b(?:basename|sanitize_filename|sanitize_file_name|getRandomName|uniqid|md5|sha1|hash|bin2hex|random_bytes|preg_replace|Str::random|Str::slug|pathinfo)\s*\(/i;
const PHP_FS_DEST_SINK = /\b(?:move_uploaded_file|rename|copy|file_put_contents|fopen|symlink|link)\s*\(/g;

function scanPhpUploadClientName(fp, code, fns) {
  const out = [];
  // Same-file getters that hand back the client-supplied original name: a
  // method whose body returns a property that is assigned from a variable or
  // property named for the client/original filename.
  const clientProps = new Set();
  let m;
  const asgProp = /\$this\s*->\s*(\w+)\s*=\s*\$(\w+)\s*;/g;
  while ((m = asgProp.exec(code))) {
    if (/^(?:original_?name|client_?(?:file_?)?name|original_?file_?name|upload(?:ed)?_?name)$/i.test(m[2])) clientProps.add(m[1]);
  }
  for (const p of [...code.matchAll(/(?:protected|private|public|var)\s+(?:\??\w+\s+)?\$(\w+)/g)].map((x) => x[1])) {
    if (/^(?:original_?name|client_?(?:file_?)?name|original_?file_?name)$/i.test(p)) clientProps.add(p);
  }
  const getters = new Set();
  for (const fn of fns) {
    const body = code.slice(fn.bodyStart, fn.end).trim();
    const r = /^return\s+\$this\s*->\s*(\w+)\s*;$/.exec(body);
    if (r && clientProps.has(r[1]) && fn.params.length === 0) getters.add(fn.name);
  }
  const getterRe = getters.size ? new RegExp(`\\$this\\s*->\\s*(?:${[...getters].map(escRe).join('|')})\\s*\\(\\s*\\)`) : null;
  const isClientExpr = (s) => PHP_CLIENT_NAME_CALL.test(s) || (getterRe && getterRe.test(s));

  for (const fn of fns) {
    const body = code.slice(fn.bodyStart, fn.end);
    // Variables holding the client name (unsanitized).
    const seeds = [];
    const asg = /\$(\w+)\s*(\?\?=|=(?![=>]))\s*([^;]+);/g;
    while ((m = asg.exec(body))) if (isClientExpr(m[3]) && !PHP_NAME_SANITIZER.test(m[3])) seeds.push({ v: m[1], at: m.index });
    if (!seeds.length && !isClientExpr(body)) continue;
    const tainted = propagate(body, seeds.map((s) => s.v), 'php', PHP_NAME_SANITIZER);
    // A variable sanitized anywhere in the function is not reported.
    for (const v of [...tainted]) if (new RegExp(`\\$${escRe(v)}\\s*=\\s*[^;]*${PHP_NAME_SANITIZER.source}`, 'i').test(body)) tainted.delete(v);
    // An extension cut off the name (the last `.` segment) holds no separator,
    // and one checked against an allowlist is a fixed value.
    for (const v of [...tainted]) {
      if (new RegExp(`\\$${escRe(v)}\\s*=\\s*[^;]*\\b(?:array_pop|end)\\s*\\(|\\bin_array\\s*\\(\\s*\\$${escRe(v)}\\b|\\$${escRe(v)}\\s*=\\s*[^;]*PATHINFO_EXTENSION`).test(body)) tainted.delete(v);
    }
    // Destinations: concatenation of a tainted name (or the client
    // expression inline) into a path that reaches a filesystem move/copy.
    const concatOf = (s) => [...tainted].some((t) => new RegExp(`\\.\\s*\\$${escRe(t)}\\b|\\$${escRe(t)}\\s*\\.|\\{\\$${escRe(t)}\\}|"[^"]*\\$${escRe(t)}\\b`).test(s))
      || (isClientExpr(s) && /\.\s*(?:\$this\s*->|\$_FILES)|->\s*\w+\(\)\s*\./.test(s) && !PHP_NAME_SANITIZER.test(s));
    const dests = new Map(); // var -> offset of the concatenation
    const asg2 = /\$(\w+)\s*=(?![=>])\s*([^;]+);/g;
    while ((m = asg2.exec(body))) if (concatOf(m[2])) dests.set(m[1], m.index);
    const sr = new RegExp(PHP_FS_DEST_SINK.source, 'g');
    while ((m = sr.exec(body))) {
      const open = m.index + m[0].length - 1;
      const close = matchBracket(body, open);
      const args = body.slice(open + 1, close < 0 ? open + 200 : close);
      let at = -1;
      if (concatOf(args)) at = m.index;
      else for (const [d, off] of dests) if (mentions(args, d, 'php')) { at = off; break; }
      if (at < 0) continue;
      const line = lineOf(code, fn.bodyStart + at + (body.slice(at).match(/^\s*/) || [''])[0].length);
      out.push(finding(fp, line, code, {
        rule: 'php-upload-client-name', cwe: 'CWE-22', family: 'path-traversal',
        vuln: 'Path traversal: client-supplied upload filename used in the destination path',
        description: 'The filename the client sent with the upload is concatenated into the destination path of a file move or copy without being reduced to a bare name. A name such as `../../public/shell.php` writes outside the upload directory.',
        remediation: 'Never use the client filename as a path. Generate the stored name (a random name with an extension chosen from an allowlist), or at least pass the client name through `basename()` and a filename sanitizer before joining it to the target directory.',
      }));
      break;
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Rule: ruby-request-path-serve
// ---------------------------------------------------------------------------

const RB_REQUEST_PATH = /\b(?:URI\s*(?:\.\s*parse\s*\(|\()\s*[\w.]*\.request_(?:url|uri)\b[^)]*\)\s*\.\s*path|\.request_(?:url|uri|path)\b|env\s*\[\s*['"](?:PATH_INFO|REQUEST_PATH|REQUEST_URI)['"]\s*\]|\b(?:req|request)\s*\.\s*(?:path_info|path|fullpath)\b)/;
const RB_FILE_STREAM = /\b(?:File\s*\.\s*(?:read|binread|open|new|size|foreach|readlines)|IO\s*\.\s*(?:read|binread|copy_stream|readlines)|stream_file_data|send_file|send_data\s*\(\s*File\s*\.\s*read)\s*\(?\s*/g;
const RB_GUARD = /start_with\?|\bexpand_path\b|\brealpath\b|\bcleanpath\b|\bbasename\b|['"]\.\.['"]|\.\.\//;

function scanRubyRequestPathServe(fp, code, fns) {
  const out = [];
  const bodyOf = (f) => code.slice(f.bodyStart, f.end);
  // Methods that stream a file named by one of their parameters.
  const direct = new Map(); // name -> Set(param index)
  for (const f of fns) {
    const body = bodyOf(f);
    const idx = new Set();
    f.params.forEach((p, i) => {
      const r = new RegExp(RB_FILE_STREAM.source, 'g'); let m;
      while ((m = r.exec(body))) {
        const after = body.slice(m.index + m[0].length, m.index + m[0].length + 80);
        if (new RegExp(`^${escRe(p)}\\b`).test(after)) { idx.add(i); break; }
      }
    });
    if (idx.size && !RB_GUARD.test(body)) direct.set(f.name, idx);
  }
  if (!direct.size) return out;
  // Taint: locals assigned from a request path; parameters of methods called
  // with a tainted argument (same file), to a fixpoint.
  const taintedParams = new Map(fns.map((f) => [f, new Set()]));
  const taintOf = (f) => {
    const body = bodyOf(f);
    const t = new Set(taintedParams.get(f));
    const asg = /(?:^|\n)\s*(\w+)\s*(?:\+=|=(?![=~>]))\s*([^\n]+)/g; let m;
    for (let pass = 0; pass < 2; pass++) {
      asg.lastIndex = 0;
      while ((m = asg.exec(body))) {
        if (RB_REQUEST_PATH.test(m[2]) || [...t].some((x) => mentions(m[2], x, 'rb'))) t.add(m[1]);
      }
    }
    return t;
  };
  for (let iter = 0; iter < 4; iter++) {
    let changed = false;
    for (const f of fns) {
      const t = taintOf(f);
      if (!t.size) continue;
      const body = bodyOf(f);
      for (const g of fns) {
        const cr = new RegExp(`(?:^|[^\\w.])${escRe(g.name)}\\s*\\(([^)\\n]*)\\)|(?:^|[^\\w.])${escRe(g.name)}[ \\t]+([^\\n]+)`, 'g'); let m;
        while ((m = cr.exec(body))) {
          const args = (m[1] ?? m[2] ?? '').replace(/\s+(?:if|unless)\b.*$/, '').split(',');
          args.forEach((a, i) => {
            if (i < g.params.length && [...t].some((x) => mentions(a, x, 'rb')) && !taintedParams.get(g).has(g.params[i])) { taintedParams.get(g).add(g.params[i]); changed = true; }
          });
        }
      }
    }
    if (!changed) break;
  }
  for (const f of fns) {
    const t = taintOf(f);
    if (!t.size) continue;
    const body = bodyOf(f);
    if (RB_GUARD.test(body)) continue;
    for (const [name, idx] of direct) {
      if (name === f.name) continue;
      const cr = new RegExp(`(?:^|[^\\w.])${escRe(name)}\\s*\\(([^)\\n]*)\\)`, 'g'); let m;
      while ((m = cr.exec(body))) {
        const args = m[1].split(',');
        if (![...idx].some((i) => args[i] !== undefined && [...t].some((x) => mentions(args[i], x, 'rb')))) continue;
        const line = lineOf(code, f.bodyStart + m.index + 1);
        out.push(finding(fp, line, code, {
          rule: 'ruby-request-path-serve', cwe: 'CWE-22', family: 'path-traversal',
          vuln: 'Path traversal: request path served as a file',
          description: `The path of the incoming request reaches \`${name}\`, which reads the named file and sends it back, and nothing between the request and this call confines it to a served directory. A request for \`/../../etc/passwd\` is served.`,
          remediation: 'Resolve the requested path against the served root (`File.expand_path(path, root)`) and refuse it unless the result starts with the root plus a separator; or serve only from an explicit allowlist of files.',
        }));
      }
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Rule: go-request-path-join
// ---------------------------------------------------------------------------

// A value read from the HTTP request (query, form, route parameter) in a Go
// handler is joined, as is, into a filesystem path. filepath.Join cleans the
// result, so `..` segments in the request value climb out of the base
// directory: Join("/srv/subs", "../../etc/passwd") is "/etc/passwd". Reported at
// the join; silent when the function reduces the value to its last element,
// checks it for `..` or locality, checks the joined path's containment, or
// matches it against a pattern.
const GO_REQ_SOURCE = /\br\s*\.\s*URL\s*\.\s*Query\s*\(\s*\)\s*\.\s*Get\s*\(|\b(?:r|req|request)\s*\.\s*(?:FormValue|PostFormValue|PathValue)\s*\(|\bmux\s*\.\s*Vars\s*\(\s*\w+\s*\)\s*\[|\bchi\s*\.\s*URLParam\s*\(|\b(?:c|ctx)\s*\.\s*(?:Query|Param|PostForm|FormValue|DefaultQuery|QueryParam|Params)\s*\(/;
const GO_JOIN = /\b(?:filepath|path)\s*\.\s*Join\s*\(/g;

function splitArgs(text) {
  const parts = []; let rest = text; let k;
  while ((k = splitTopComma(rest)) >= 0) { parts.push(rest.slice(0, k)); rest = rest.slice(k + 1); }
  parts.push(rest);
  return parts;
}

// ---------------------------------------------------------------------------
// Rule: go-decoded-path-forwarded
// ---------------------------------------------------------------------------

// A Go middleware rewrites the request path from the request's own escaped
// path, decodes the result into URL.Path (url.PathUnescape), and hands the
// request to the next handler without normalizing it. Decoding turns `%2e%2e`
// and `%2f` into `..` and `/`, so the path the next handler routes and
// authorizes on contains traversal segments that were not visible when the
// incoming path was matched. Reported at the forward; silent when the function
// normalizes (JoinPath, path.Clean) or rejects `..`.
const GO_REQ_PATH = /\b(\w+)\s*\.\s*URL\s*\.\s*(?:RawPath|Path|EscapedPath\s*\(\s*\))/;

function scanGoDecodedPathForwarded(fp, code, fns) {
  const out = [];
  if (!/\bPathUnescape\s*\(/.test(code) || !/\.\s*ServeHTTP\s*\(/.test(code)) return out;
  for (const f of fns) {
    const body = code.slice(f.bodyStart, f.end);
    const dec = /\b(\w+)\s*\.\s*URL\s*\.\s*Path\s*(?:,\s*\w+\s*)?=\s*url\s*\.\s*PathUnescape\s*\(\s*([^)\n]+)\)/.exec(body);
    if (!dec) continue;
    const reqVar = dec[1];
    // locals holding the incoming path
    const seeds = [];
    const asg = /\b(\w+)\s*:?=\s*([^\n;]+)/g; let a;
    while ((a = asg.exec(body))) if (GO_REQ_PATH.test(a[2]) && !/PathUnescape/.test(a[2])) seeds.push(a[1]);
    const tainted = propagate(body, seeds, 'go');
    // what was decoded: the raw path rewritten from the incoming path, or a tainted local
    const arg = dec[2].trim();
    let fromRequest = [...tainted].some((t) => mentions(arg, t, 'go'));
    if (!fromRequest && new RegExp(`^${escRe(reqVar)}\\s*\\.\\s*URL\\s*\\.\\s*RawPath$`).test(arg)) {
      const rw = new RegExp(`\\b${escRe(reqVar)}\\s*\\.\\s*URL\\s*\\.\\s*RawPath\\s*=(?!=)\\s*([^\\n;]+)`).exec(body);
      fromRequest = !!rw && [...tainted].some((t) => mentions(rw[1], t, 'go'));
    }
    if (!fromRequest) continue;
    if (/\bJoinPath\s*\(|\bpath\s*\.\s*Clean\s*\(|\bfilepath\s*\.\s*Clean\s*\(|["`]\.\.["`/]/.test(body)) continue;
    const fwd = /\b\w+(?:\s*\.\s*\w+)*\s*\.\s*ServeHTTP\s*\(\s*\w+\s*,\s*(\w+)\s*\)/g; let m;
    while ((m = fwd.exec(body))) {
      if (m[1] !== reqVar || m.index < dec.index) continue;
      const line = lineOf(code, f.bodyStart + m.index);
      out.push(finding(fp, line, code, {
        rule: 'go-decoded-path-forwarded', cwe: 'CWE-22', family: 'path-traversal', severity: 'medium',
        vuln: 'Path traversal: rewritten request path decoded and forwarded without normalization',
        description: 'The request path is rewritten from the incoming escaped path and decoded into `URL.Path`, then the request is passed to the next handler without normalizing the result. Decoding turns `%2e%2e` and `%2f` into `..` and `/`, so the next handler routes and authorizes on a path with traversal segments that were not visible when the incoming path was matched.',
        remediation: 'Normalize after decoding (`req.URL = req.URL.JoinPath()` or `path.Clean`) and reject the request when the normalized path differs from the decoded one; or match and rewrite on the decoded, cleaned path only.',
      }));
      break;
    }
  }
  return out;
}

function scanGoRequestPathJoin(fp, code, fns) {
  const out = [];
  if (!GO_REQ_SOURCE.test(code)) return out;
  for (const f of fns) {
    const body = code.slice(f.bodyStart, f.end);
    if (!GO_REQ_SOURCE.test(body)) continue;
    const seeds = [];
    const asg = /\b(\w+)(?:\s*,\s*\w+)?\s*:?=\s*([^\n;]+)/g; let a;
    // Base, or a project helper that sanitizes / validates the path, ends the taint
    // (filepath.Clean does not: it keeps a leading `..`).
    const kill = /\b(?:filepath|path)\s*\.\s*Base\s*\(|\b\w*(?:[Ss]anitiz|[Ss]afe[A-Z_]|[Vv]alidat|[Cc]onfine)\w*\s*\(/;
    while ((a = asg.exec(body))) if (GO_REQ_SOURCE.test(a[2]) && !kill.test(a[2])) seeds.push(a[1]);
    if (!seeds.length) continue;
    const tainted = propagate(body, seeds, 'go', kill);
    const jr = new RegExp(GO_JOIN.source, 'g'); let m;
    while ((m = jr.exec(body))) {
      const open = m.index + m[0].length - 1;
      const close = matchBracket(body, open);
      if (close < 0) continue;
      const args = splitArgs(body.slice(open + 1, close)).map((x) => x.trim());
      // the request value as a whole, later argument of the join
      const hit = args.slice(1).find((x) => tainted.has(x));
      if (!hit) continue;
      const v = escRe(hit);
      const guarded = new RegExp(
        `\\b(?:filepath|path)\\s*\\.\\s*(?:Base|IsLocal|Rel)\\s*\\(\\s*${v}\\b`
        + `|\\bstrings\\s*\\.\\s*(?:Contains|ContainsAny|Index|HasPrefix|HasSuffix)\\s*\\(\\s*${v}\\s*,`
        + `|\\bMatchString\\s*\\(\\s*${v}\\b|\\bValidPath\\s*\\(|\\bIsLocal\\s*\\(|\\bfilepath\\s*\\.\\s*Rel\\s*\\(`
        + `|\\bstrings\\s*\\.\\s*HasPrefix\\s*\\(|\\bSecureJoin\\s*\\(|\\bOpenInRoot\\s*\\(|\\bOpenRoot\\s*\\(|\\bos\\s*\\.\\s*Root\\b`
        + `|["\`]\\.\\.["\`]`).test(body);
      if (guarded) continue;
      const line = lineOf(code, f.bodyStart + m.index);
      out.push(finding(fp, line, code, {
        rule: 'go-request-path-join', cwe: 'CWE-22', family: 'path-traversal',
        vuln: 'Path traversal: request value joined into a filesystem path',
        description: `\`${hit}\` is read from the HTTP request and joined into a filesystem path with no check in this handler. Join cleans the result, so a value like \`../../etc/passwd\` climbs out of the base directory and names any file the process can read or write.`,
        remediation: 'Reduce the value to a single element with `filepath.Base` (and reject `.`, `..` and empty), or require `filepath.IsLocal(v)` before joining, or open through an `os.Root` for the base directory (Go 1.24+). If subdirectories are allowed, check the joined path with `filepath.Rel` against the base and reject a result that starts with `..`.',
      }));
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Rule: weak-clean-guard
// ---------------------------------------------------------------------------

function scanWeakCleanGuard(fp, code, lang, fns) {
  const out = [];
  let re;
  if (lang === 'go') re = /\b(?:path|filepath)\s*\.\s*Clean\s*\(\s*(\w+)\s*\)\s*!=\s*(\w+)\b|\b(\w+)\s*!=\s*(?:path|filepath)\s*\.\s*Clean\s*\(\s*(\w+)\s*\)/g;
  else if (lang === 'py') re = /\bos\.path\.normpath\s*\(\s*(\w+)\s*\)\s*!=\s*(\w+)\b|\b(\w+)\s*!=\s*os\.path\.normpath\s*\(\s*(\w+)\s*\)/g;
  else if (lang === 'js') re = /\bpath(?:\s*\.\s*posix)?\s*\.\s*normalize\s*\(\s*(\w+)\s*\)\s*!==?\s*(\w+)\b|\b(\w+)\s*!==?\s*path(?:\s*\.\s*posix)?\s*\.\s*normalize\s*\(\s*(\w+)\s*\)/g;
  else return out;
  let m;
  while ((m = re.exec(code))) {
    const a = m[1] || m[4], b = m[2] || m[3];
    if (a !== b) continue;
    const fn = fns.find((f) => f.bodyStart <= m.index && m.index < f.end);
    const body = fn ? code.slice(fn.bodyStart, fn.end) : code;
    const v = escRe(a);
    // A real `..` / absolute-path check on the same value elsewhere in the
    // function makes the clean comparison a canonical-form check, not the
    // traversal guard.
    // a separate `..` rejection, as a function (`HasPrefix(v, "..")`) or a method (`v.startsWith('..')`)
    const other = new RegExp(`(?:HasPrefix|Contains|startswith|startsWith|includes|indexOf|in)\\s*\\(?\\s*${v}\\s*,?\\s*['"]\\.\\.|\\b${v}\\s*\\.\\s*(?:startsWith|startswith|starts_with|includes|indexOf|contains|Contains|StartsWith)\\s*\\(\\s*['"]\\.\\.|['"]\\.\\.['"]\\s*(?:in|===?|==)\\s*|\\.\\.\\s*['"]\\s*in\\s+${v}|\\bIsLocal\\s*\\(|\\bValidPath\\s*\\(|\\bIsAbs\\s*\\(\\s*${v}|\\bisabs\\s*\\(\\s*${v}|\\bisAbsolute\\s*\\(\\s*${v}|is_relative_to|relative_to|\\bRel\\s*\\(|path\\s*\\.\\s*relative\\s*\\(|split\\s*\\([^)]*\\)[^\\n]*\\.\\.`);
    if (other.test(body)) continue;
    // A value made absolute before the comparison is safe: Clean of a rooted
    // path cannot keep a leading `..`.
    if (new RegExp(`${v}\\s*(?::=|=)\\s*['"]\\/['"]\\s*\\+|${v}\\s*(?::=|=)\\s*(?:path|filepath)\\s*\\.\\s*Join\\s*\\(\\s*['"]\\/['"]`).test(body)) continue;
    const line = lineOf(code, m.index);
    out.push(finding(fp, line, code, {
      rule: 'weak-clean-guard', cwe: 'CWE-22', family: 'weak-path-guard', severity: 'high',
      vuln: 'Path traversal: path normalisation compared with itself as the traversal check',
      description: 'The traversal check rejects a path only when cleaning it changes it. Cleaning a relative path keeps leading `..` elements (`../x` is already clean), so the inputs that escape the root pass the check unchanged.',
      remediation: 'Check the property that matters: Go `fs.ValidPath(p)` or `filepath.IsLocal(p)`, Python `PurePosixPath(p)` with no `..` part and not absolute, Node `!path.isAbsolute(p) && !p.split(/[\\\\/]/).includes("..")`; or join under the root and verify containment of the resolved result.',
    }));
  }
  return out;
}

// ---------------------------------------------------------------------------
// Rule: bare-prefix-containment
// ---------------------------------------------------------------------------

function scanBarePrefixContainment(fp, code, lang, fns) {
  const out = [];
  let re, resolver, sepRe;
  if (lang === 'php') {
    re = /\bstrpos\s*\(\s*\$(\w+)\s*,\s*\$(\w+)\s*\)\s*===\s*0\b|\bstr_starts_with\s*\(\s*\$(\w+)\s*,\s*\$(\w+)\s*\)/g;
    resolver = /\brealpath\s*\(/;
    sepRe = (v) => new RegExp(`\\$${v}\\s*(?:\\.=|=\\s*[^;]*\\.\\s*)(?:DIRECTORY_SEPARATOR|['"][\\\\/]['"])|\\$${v}\\s*\\.\\s*(?:DIRECTORY_SEPARATOR|['"][\\\\/]['"])`);
  } else if (lang === 'js') {
    // The root may be a member (`this.root`, `this.config.basePath`) resolved where it is set.
    re = /\b(\w+)\s*\.\s*startsWith\s*\(\s*([\w.]{1,120})\s*\)/g;
    // `resolve` / `normalize` imported by name from the path module are the path functions too,
    // and so is a same-class `this.resolve...Path(...)` helper.
    const bare = /\bimport\s*\{[^}]*\b(?:resolve|normalize)\b[^}]*\}\s*from\s*['"](?:node:)?path['"]|\{[^}]*\b(?:resolve|normalize)\b[^}]*\}\s*=\s*require\s*\(\s*['"](?:node:)?path['"]/.test(code);
    resolver = bare
      ? /(?:\bpath\s*\.\s*resolve|\brealpath(?:Sync)?|\bfs\s*\.\s*realpathSync|\bpath\s*\.\s*normalize|(?<![\w$.])(?:resolve|normalize)|\bthis\s*\.\s*(?:resolve|normali[sz]e|canonicali[sz]e)\w*Path)\s*\(/
      : /\b(?:path\s*\.\s*resolve|realpath(?:Sync)?|fs\s*\.\s*realpathSync|path\s*\.\s*normalize)\s*\(/;
    sepRe = (v) => new RegExp(`${v}\\s*(?:\\+=|=[^;\\n]*\\+)\\s*(?:path\\s*\\.\\s*sep|\\bsep\\b|['"][\\\\/]['"])|${v}\\s*\\+\\s*(?:path\\s*\\.\\s*sep|\\bsep\\b|['"][\\\\/]['"])|${v}\\s*\\.\\s*endsWith\\s*\\(`);
  } else if (lang === 'py') {
    re = /\b(\w+)\s*\.\s*startswith\s*\(\s*(\w+)\s*\)/g;
    resolver = /\bos\.path\.(?:realpath|abspath|normpath)\s*\(/;
    sepRe = (v) => new RegExp(`${v}\\s*(?:\\+=|=[^\\n]*\\+)\\s*(?:os\\.sep|['"][\\\\/]['"])|${v}\\s*\\+\\s*(?:os\\.sep|['"][\\\\/]['"])|os\\.path\\.join\\s*\\(\\s*${v}\\s*,\\s*['"]['"]`);
  } else if (lang === 'go') {
    re = /\bstrings\s*\.\s*HasPrefix\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)/g;
    resolver = /\bfilepath\s*\.\s*(?:Abs|EvalSymlinks|Clean)\s*\(/;
    sepRe = (v) => new RegExp(`${v}\\s*(?:\\+=|:?=[^\\n]*\\+)\\s*(?:string\\s*\\(\\s*(?:filepath|os)\\s*\\.\\s*(?:Separator|PathSeparator)|['"][\\\\/]['"])|${v}\\s*\\+\\s*(?:string\\s*\\(|['"][\\\\/]['"])`);
  } else return out;
  let m;
  while ((m = re.exec(code))) {
    const a = m[1] || m[3], b = m[2] || m[4];
    if (!a || !b || a === b) continue;
    const fn = fns.find((f) => f.bodyStart <= m.index && m.index < f.end);
    if (!fn) continue;
    const body = code.slice(fn.bodyStart, fn.end);
    const pfx = lang === 'php' ? '\\$' : '\\b';
    const assignedFromResolver = (v) => {
      if (lang === 'js' && /\./.test(v)) {
        // a member root: resolved where it is assigned, anywhere in the file
        const mv = v.split(/\s*\.\s*/).map(escRe).join('\\s*\\.\\s*');
        return new RegExp(`${mv}\\s*=(?!=)\\s*[^;\\n]*${resolver.source}`).test(code);
      }
      return new RegExp(`${pfx}${escRe(v)}\\s*(?::=|=(?!=))\\s*[^;\\n]*${resolver.source}`).test(body)
        || (lang === 'go' && new RegExp(`\\b${escRe(v)}\\s*,\\s*\\w+\\s*:?=\\s*${resolver.source}`).test(body));
    };
    // Both sides resolved paths: this is a filesystem containment decision.
    if (!assignedFromResolver(a) || !assignedFromResolver(b)) continue;
    if (sepRe(escRe(b)).test(body)) continue;
    // A separate `..` rejection on the path makes the prefix test a second
    // line of defence, not the containment decision.
    if (/['"]\.\.['"]|['"]\.\.\/['"]/.test(body)) continue;
    const line = lineOf(code, m.index);
    out.push(finding(fp, line, code, {
      rule: 'bare-prefix-containment', cwe: 'CWE-22', family: 'weak-path-guard', severity: 'medium',
      vuln: 'Path traversal: containment decided by a string prefix without a trailing separator',
      description: 'Whether a resolved path is inside an allowed directory is decided by checking that the path string starts with the directory string. Without a trailing separator, a sibling directory whose name extends the root (`/srv/data-private` for root `/srv/data`) passes the check.',
      remediation: 'Compare against the root with a trailing separator appended (and accept the root itself by equality), or use a path-aware relation: Python `Path.is_relative_to`, Go `filepath.Rel` rejecting `..`, Node `path.relative` rejecting `..` and absolute results.',
    }));
  }
  return out;
}

// ---------------------------------------------------------------------------
// Rule: unmasked-file-mode (Go)
// ---------------------------------------------------------------------------

const GO_MODE_SOURCE = /\bstrconv\s*\.\s*Parse(?:Uint|Int)\s*\(|\.\s*parse\w*(?:Int|Uint|Mode|Octal)\w*\s*\(|\b(?:hdr|header|h|th|tarHeader|zipHeader)\s*\.\s*Mode\b|\.ExternalAttrs\b/i;
const GO_MODE_MASK = /\.Perm\s*\(\s*\)|&\s*(?:0o?[0-7]{3,4}|os\s*\.\s*ModePerm|fs\s*\.\s*ModePerm|0x1ff)\b|&\^\s*(?:os|fs)\s*\.\s*Mode(?:Setuid|Setgid|Sticky)/;

function scanUnmaskedFileMode(fp, code, fns) {
  const out = [];
  for (const fn of fns) {
    const body = code.slice(fn.bodyStart, fn.end);
    if (!/\b(?:Chmod|Lchmod|lChmod|lchmod)\s*\(/.test(body)) continue;
    const seeds = [];
    const asg = /\b(\w+)(?:,[ \t]?\w+)?(?:,[ \t]?\w+)?[ \t]*:?=[ \t]*([^\n]+)/g; let m;
    while ((m = asg.exec(body))) if (GO_MODE_SOURCE.test(m[2]) && !GO_MODE_MASK.test(m[2])) seeds.push(m[1]);
    const tainted = propagate(body, seeds, 'go', GO_MODE_MASK);
    // a variable masked anywhere in the function is treated as masked
    for (const v of [...tainted]) if (new RegExp(`\\b${escRe(v)}\\s*(?:=|&=|&\\^=)\\s*[^\\n]*${GO_MODE_MASK.source}|\\b${escRe(v)}\\s*(?:&=|&\\^=)`).test(body)) tainted.delete(v);
    const sink = /\b(?:os\s*\.\s*)?(?:Chmod|Lchmod|lChmod|lchmod)\s*\(/g;
    while ((m = sink.exec(body))) {
      const open = m.index + m[0].length - 1;
      const close = matchBracket(body, open);
      if (close < 0) continue;
      const args = body.slice(open + 1, close);
      const c = splitTopComma(args);
      const modeArg = c < 0 ? args : args.slice(c + 1);
      if (GO_MODE_MASK.test(modeArg)) continue;
      const direct = GO_MODE_SOURCE.test(modeArg);
      if (!direct && ![...tainted].some((t) => mentions(modeArg, t, 'go'))) continue;
      const line = lineOf(code, fn.bodyStart + m.index);
      out.push(finding(fp, line, code, {
        rule: 'unmasked-file-mode', cwe: 'CWE-732', family: 'file-permissions', severity: 'medium',
        vuln: 'Incorrect permission assignment: mode from data applied without masking special bits',
        description: 'A file mode read from data (stored metadata, an archive header) is applied with chmod as is. The value can carry setuid, setgid and sticky bits, so a file from an untrusted source can be made a setuid executable owned by the user who restores it.',
        remediation: 'Apply only the permission bits: `os.Chmod(p, mode.Perm())` or `mode & 0o777`; restore special bits only behind an explicit opt-in for trusted sources.',
      }));
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Rule: suffix-extension-denylist
// ---------------------------------------------------------------------------

const DENY_NAME = /(?:block|den(?:y|ied)|forbid|black|disallow|banned|dangerous|unsafe|executable)\w*ext|ext\w*(?:block|den(?:y|ied)|forbid|black|disallow|banned)/i;
// The value tested must be a file name, not an environment key or a token.
const FILENAME_VAR = /file|name|path|upload|media|attach/i;

function scanSuffixDenylist(fp, code, lang, fns) {
  const out = [];
  let loopRe, suffixRe;
  if (lang === 'php') {
    loopRe = /\bforeach\s*\(\s*(?:\$[\w>-]+|self::\w+\(\)|static::\w+\(\)|\$this->\w+\(\))\s+as\s+\$(\w+)\s*\)/g;
    suffixRe = (v) => new RegExp(`\\bstr_ends_with\\s*\\([^;]*\\$${v}\\b|\\bsubstr\\s*\\([^;]*-\\s*strlen\\s*\\([^;]*\\$${v}\\b|\\bpreg_match\\s*\\([^;]*\\$${v}[^;]*\\$`);
  } else if (lang === 'js') {
    loopRe = /\bfor\s*\(\s*(?:const|let|var)\s+(\w+)\s+of\s+[\w.]+\s*\)|\.\s*(?:some|find|every)\s*\(\s*\(?\s*(\w+)\s*\)?\s*=>/g;
    suffixRe = (v) => new RegExp(`\\.endsWith\\s*\\([^)]*\\b${v}\\b`);
  } else if (lang === 'py') {
    loopRe = /\bfor\s+(\w+)\s+in\s+[\w.]+/g;
    suffixRe = (v) => new RegExp(`\\.endswith\\s*\\([^)]*\\b${v}\\b`);
  } else return out;
  let m;
  while ((m = loopRe.exec(code))) {
    const v = m[1] || m[2];
    // the iterated collection must be named as a denylist of extensions
    const head = m[0] + code.slice(Math.max(0, m.index - 120), m.index).split('\n').pop();
    if (!DENY_NAME.test(head)) continue;
    const fn = fns.find((f) => f.bodyStart <= m.index && m.index < f.end);
    const body = fn ? code.slice(fn.bodyStart, fn.end) : '';
    // A segment-wise check anywhere in the function is the correct form.
    if (/\bexplode\s*\(\s*['"]\.['"]|\.split\s*\(\s*['"]\.['"]|\.split\s*\(\s*\/\\\.\/|\bin_array\s*\([^;]*\bexplode\b/.test(body)) continue;
    const window = code.slice(m.index, m.index + 600);
    const s = suffixRe(escRe(v)).exec(window);
    if (!s || !FILENAME_VAR.test(s[0].replace(new RegExp(`\\b${escRe(v)}\\b`, 'g'), ''))) continue;
    const line = lineOf(code, m.index + s.index);
    out.push(finding(fp, line, code, {
      rule: 'suffix-extension-denylist', cwe: 'CWE-434', family: 'file-upload', severity: 'high',
      vuln: 'Unrestricted upload: extension denylist checked only at the end of the name',
      description: 'Blocked extensions are rejected only when the filename ends with them. A name that carries the blocked extension in the middle (`shell.php.jpg`, `x.php.anything`) passes, and servers configured to run any file with a `.php` segment execute it.',
      remediation: 'Split the name on `.` and reject it if ANY segment (case-folded) is a blocked extension, or better, accept only an allowlist of final extensions and store uploads under generated names outside the web root.',
    }));
  }
  return out;
}

export function scanPathFileHandling(fp, code) {
  const lang = langOf(fp);
  if (!lang || !code || code.length > 600_000) return [];
  const fns = functionsOf(code, lang);
  const out = [];
  out.push(...scanRefJoinRead(fp, code, lang, fns));
  if (lang === 'php') out.push(...scanPhpUploadClientName(fp, code, fns));
  if (lang === 'rb') out.push(...scanRubyRequestPathServe(fp, code, fns));
  out.push(...scanWeakCleanGuard(fp, code, lang, fns));
  out.push(...scanBarePrefixContainment(fp, code, lang, fns));
  if (lang === 'go') out.push(...scanUnmaskedFileMode(fp, code, fns));
  if (lang === 'go') out.push(...scanGoRequestPathJoin(fp, code, fns));
  if (lang === 'go') out.push(...scanGoDecodedPathForwarded(fp, code, fns));
  out.push(...scanSuffixDenylist(fp, code, lang, fns));
  const seen = new Set();
  return out.filter((f) => (seen.has(f.id) ? false : (seen.add(f.id), true)));
}

export const _internal = { functionsOf, langOf };
