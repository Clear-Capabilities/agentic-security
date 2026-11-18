// Credentials forwarded across a hand-written redirect follow: CWE-200.
//
// THE SHAPE. Code that follows redirects itself (it reads the Location header, or turns the HTTP client's own redirect handling off and
// loops) and re-issues the request with the SAME headers or options object it was given:
//
//     def request(verb, url, opts)
//       response = perform(verb, url, opts)
//       if response.status in REDIRECTS
//         request(verb, url.merge(response.headers["location"]), opts)     # Authorization travels to whatever host Location names
//
//     for _ in range(MAX):
//         resp = client.get(url, headers=headers, follow_redirects=False)   # same headers on every hop
//         url = next_redirect(resp)
//
// A redirect to another origin then receives the caller's Authorization, Cookie or Proxy-Authorization header. HTTP clients that follow
// redirects themselves drop those headers when the origin changes; code that replaces that logic has to do the same. The fix compares the
// origin (scheme, host and port) of the current and next URL and strips the credentials when it differs.
//
// WHAT MUST BE TRUE TO REPORT.
//   1. A redirect is followed by hand: a Location header read, or a request made with the client's redirect following turned off inside a
//      loop that reassigns the URL from something redirect-shaped.
//   2. The re-issued request passes an options or headers object as a bare identifier (`opts`, `req_opts`, `headers=headers`), and that
//      identifier is not reassigned between hops. A wrapper call in that position (`strip_credentials(opts, a, b)`) is the fix and does not
//      match.
//   3. The function does not strip credentials on an origin comparison. A strip gated only on the host name still reports: a redirect
//      from https to http on the same host, or to another port, still carries the header.
//
// Deliberately NOT modelled: redirects followed by a library (its own stripping applies), a per-hop rebuild of the headers in a helper
// whose name says nothing, and Go/Java/C# (their clients strip by default and no hand-written follow was seen on real code).

const FILE_RE = /\.(?:rb|py|js|jsx|mjs|cjs|ts|tsx|php)$/i;
const PREFILTER = /location|redirect/i;

const LOCATION_READ = /(?:\bheaders?\b\s*(?:\[\s*['"]location['"]\s*\]|\.(?:get|fetch)\(\s*['"]location['"]|\.location\b)|\bget(?:Response)?Header\(\s*['"]location['"])/i;
const MANUAL_REDIRECT = /\b(?:follow_redirects|allow_redirects)\s*=\s*False\b|\bredirect\s*:\s*['"]manual['"]|\bmaxRedirects\s*:\s*0\b|\bfollowRedirects?\s*:\s*false\b|\bCURLOPT_FOLLOWLOCATION\s*(?:,|=>)\s*(?:false|0)\b/;

// The names an options or headers bag goes by. A positional argument must be one of these to count as forwarded.
const BAG_NAME = /^(?:req_?opts|request_?opts|opts|options|req_?options|request_?options|init|headers|hdrs|http_?headers|request_?headers|req_?headers|kwargs|config|settings|params_and_headers)$/i;

// A credential strip, and the comparisons that make it origin-scoped.
const STRIP_RE = /authorization|cookie|credential/i;
const ORIGIN_CMP = /\borigin\b|\bnetloc\b|cross_?origin|same_?origin|crossOrigin|sameOrigin|\b(?:scheme|protocol)\b[\s\S]*\bport\b|\bport\b[\s\S]*\b(?:scheme|protocol)\b/i;

const isTest = (f) => /(?:^|\/)(?:spec|specs|test|tests|__tests__)\//.test(f) || /(?:_spec|_test|\.test|\.spec)\.\w+$/.test(f) || /(?:^|\/)test_[^/]*\.py$/.test(f);

const indentOf = (s) => (s.match(/^[ \t]*/) || [''])[0].length;

/** Extent of the function enclosing line `i`: { start, end, name, params } or null. */
function enclosingFunction(lines, i, lang) {
  if (lang === 'py' || lang === 'rb') {
    const myIndent = indentOf(lines[i]);
    const headRe = lang === 'py' ? /^(\s*)(?:async\s+)?def\s+(\w+)\s*\(([^)]*)/ : /^(\s*)def\s+(?:self\.)?(\w+[?!]?)\s*(?:\(([^)]*)\)|([^\n#]*))?/;
    for (let k = i; k >= 0 && i - k < 400; k--) {
      const m = lines[k].match(headRe);
      if (!m || (k !== i && m[1].length >= myIndent)) continue;
      const ind = m[1].length;
      let end = k + 1;
      if (lang === 'py') {
        // A signature can span lines: collect parameters until the line ending in ':'.
        let sig = m[3] || ''; let s = k;
        while (s < lines.length && !/\)\s*(?:->[^:]*)?:\s*$/.test(lines[s]) && s - k < 30) { s++; sig += ' ' + (lines[s] || ''); }
        end = s + 1;
        while (end < lines.length && (lines[end].trim() === '' || indentOf(lines[end]) > ind)) end++;
        return { start: k, end, name: m[2], params: paramNames(sig) };
      }
      const endRe = new RegExp(`^\\s{${ind}}end\\b`);
      while (end < lines.length && !endRe.test(lines[end])) end++;
      return { start: k, end, name: m[2], params: paramNames(m[3] ?? m[4] ?? '') };
    }
    return null;
  }
  // Brace languages: walk back to a function header and brace-match its body.
  // Three header forms, tried one at a time; the leading modifiers are stripped by a loop, not a repeated regex group.
  const FN = /\bfunction\b\s*(\w*)\s*\(([^)]*)\)/;
  const METHOD = /^(\w+)\s*\(([^)]*)\)\s*(?::[^{=]+)?\{/;
  const ARROW = /(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*(?::[^=]+)?=>/;
  const MODIFIER = /^(?:public|private|protected|static|async|override)\s+/;
  for (let k = i; k >= 0 && i - k < 400; k--) {
    let t = lines[k].trim();
    while (MODIFIER.test(t)) t = t.replace(MODIFIER, '');
    const m = lines[k].match(FN) || t.match(METHOD) || lines[k].match(ARROW);
    if (!m) continue;
    const name = m[1] || '';
    if (/^(?:if|for|while|switch|catch|return|elseif|foreach)$/.test(name)) continue;
    let depth = 0; let opened = false; let end = -1;
    for (let r = k; r < lines.length && r - k < 600 && end < 0; r++) {
      for (const ch of lines[r]) {
        if (ch === '{') { depth++; opened = true; } else if (ch === '}') { depth--; if (opened && depth === 0) { end = r + 1; break; } }
      }
    }
    if (end < 0 || end <= i) continue;
    return { start: k, end, name, params: paramNames(m[2] ?? '') };
  }
  return null;
}

function paramNames(sig) {
  return String(sig || '').split(',').map((p) => p.replace(/^[\s*&]+/, '').replace(/^\$/, '').match(/^(\w+)/)?.[1]).filter(Boolean);
}

/** Argument text of the call whose name starts at `col` on line `ln`, across up to 12 lines. */
function callArgs(lines, ln, openIdx) {
  let depth = 0; let out = '';
  for (let r = ln; r < lines.length && r - ln < 12; r++) {
    const s = r === ln ? lines[r].slice(openIdx) : lines[r];
    for (const ch of s) {
      if (ch === '(') { depth++; if (depth === 1) continue; }
      if (ch === ')') { depth--; if (depth === 0) return out; }
      if (depth >= 1) out += ch;
    }
    out += '\n';
  }
  return null;
}

/** Top-level comma split. */
function splitArgs(s) {
  const out = []; let depth = 0; let cur = ''; let q = null;
  for (const ch of s) {
    if (q) { cur += ch; if (ch === q) q = null; continue; }
    if (ch === '"' || ch === "'" || ch === '`') { q = ch; cur += ch; continue; }
    if ('([{'.includes(ch)) depth++;
    if (')]}'.includes(ch)) depth--;
    if (ch === ',' && depth === 0) { out.push(cur.trim()); cur = ''; continue; }
    cur += ch;
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}

/** The bag identifier an argument list forwards, or null. */
function forwardedBag(args, params) {
  for (const a of splitArgs(args)) {
    const kw = a.match(/^(?:headers|options|opts|init)\s*(?:=|:|=>)\s*\$?(\w+)$/i) || a.match(/^:headers\s*=>\s*(\w+)$/);
    if (kw) return kw[1];
    const star = a.match(/^\*\*(\w+)$/);
    if (star && params.includes(star[1])) return star[1];
    const bare = a.match(/^\$?(\w+)$/);
    if (bare && BAG_NAME.test(bare[1]) && params.includes(bare[1])) return bare[1];
  }
  return null;
}

// A statement that rebinds the name. A keyword argument on its own line (`headers=headers,`) is not one.
const reassigns = (text, name) => new RegExp(`(?:^|;)\\s*(?:(?:let|const|var|my)\\s+)?\\$?${name}\\s*(?::[^=\\n]+)?(?:=(?!=)|\\|\\|=)(?![^\\n]*,\\s*$)`, 'm').test(text);

/** True when the code strips credentials on an origin comparison. A strip keyed on the host alone does not count. */
function stripsOnOrigin(body, file) {
  if (!STRIP_RE.test(body) && !STRIP_RE.test(file)) return false;
  return ORIGIN_CMP.test(body) || ORIGIN_CMP.test(file);
}

export function scanRedirectCredentialForwarding(file, code) {
  if (!FILE_RE.test(file) || typeof code !== 'string' || !PREFILTER.test(code) || isTest(file)) return [];
  const lang = /\.py$/i.test(file) ? 'py' : /\.rb$/i.test(file) ? 'rb' : 'brace';
  const lines = code.split('\n');
  const out = []; const seen = new Set();
  const report = (line, fn, bag, how) => {
    if (seen.has(line)) return;
    seen.add(line);
    out.push({
      id: `redirect-credential-forwarding:${file}:${line}`,
      file, line,
      vuln: 'Credentials forwarded to a redirect target without an origin check',
      severity: 'medium',
      cwe: 'CWE-200',
      family: 'data-exposure',
      stride: 'Information Disclosure',
      description: `\`${fn.name || 'this function'}\` follows redirects itself (${how}) and re-sends \`${bag}\` unchanged to the next location. A redirect to another origin receives the Authorization, Cookie or Proxy-Authorization header meant for the first one. Whether a caller puts credentials in \`${bag}\` is not checked here.`,
      remediation: 'Before re-issuing the request, compare the origin (scheme, host and port) of the current URL with the redirect target, and when it differs send a copy of the headers without Authorization, Cookie and Proxy-Authorization. Comparing the host alone is not enough.',
      snippet: (lines[line - 1] || '').trim().slice(0, 200),
      parser: 'REDIRECT-CREDS',
      confidence: 0.6,
    });
  };

  for (let i = 0; i < lines.length; i++) {
    const loc = LOCATION_READ.test(lines[i]);
    const manual = !loc && MANUAL_REDIRECT.test(lines[i]);
    if (!loc && !manual) continue;
    const fn = enclosingFunction(lines, i, lang);
    if (!fn || !fn.params.length) continue;
    const body = lines.slice(fn.start, fn.end).join('\n');
    if (stripsOnOrigin(body, '')) continue;

    if (loc) {
      // The variable the Location value lands in; a validation call on it (`validate_location(base, loc)`) is a guard.
      const locVar = (lines[i].match(/^\s*(?:(?:let|const|var)\s+)?\$?(\w+)\s*(?::[^=]+)?=(?!=)/) || [])[1];
      // A re-issued request after the Location read that forwards a parameter bag.
      for (let r = i; r < fn.end; r++) {
        if (locVar && new RegExp(`\\b\\w*(?:valid|check|ensure|assert|verify|origin|allow|trust)\\w*[!?]?\\s*\\([^)]*\\b${locVar}\\b`, 'i').test(lines[r])) break;
        const re = /\b(\w+)\s*\(/g; let m;
        while ((m = re.exec(lines[r]))) {
          const callee = m[1];
          const isRecursion = callee === fn.name && r !== fn.start;
          const isRequest = /^(?:request|_request|do_request|perform_request|execute_request|send_request|make_request|fetch|http_request|urlopen)$/i.test(callee);
          if (!isRecursion && !isRequest) continue;
          const args = callArgs(lines, r, m.index + m[0].length - 1);
          if (!args) continue;
          const bag = forwardedBag(args, fn.params);
          if (!bag) continue;
          if (reassigns(lines.slice(fn.start + 1, r).join('\n'), bag)) continue;
          report(r + 1, fn, bag, 'it reads the Location header');
        }
      }
      continue;
    }

    // Manual follow: the call with redirects off, inside a loop that reassigns the URL from a redirect.
    let callLine = i;
    while (callLine > fn.start && !/\w\s*\(/.test(lines[callLine])) callLine--;
    // The headers argument may sit on any line of the call.
    let hdrLine = -1; let bag = null;
    for (let r = Math.max(fn.start, i - 12); r <= Math.min(fn.end - 1, i + 12); r++) {
      const h = lines[r].match(/\bheaders\s*(?:=(?!=)|:)\s*\$?(\w+)\s*,?\s*$/) || lines[r].match(/\bheaders\s*(?:=(?!=)|:)\s*\$?(\w+)\s*[,)]/);
      if (h && h[1] !== 'None' && h[1] !== 'null' && h[1] !== 'undefined') { hdrLine = r; bag = h[1]; break; }
    }
    if (!bag) continue;
    // Enclosing loop.
    let loopStart = -1; let loopEnd = -1;
    for (let k = hdrLine; k > fn.start; k--) {
      if (/^\s*(?:for|while)\b|\bwhile\s*\(|\bfor\s*\(/.test(lines[k]) && indentOf(lines[k]) < indentOf(lines[hdrLine])) {
        loopStart = k;
        const ind = indentOf(lines[k]);
        loopEnd = k + 1;
        while (loopEnd < fn.end && (lines[loopEnd].trim() === '' || indentOf(lines[loopEnd]) > ind || /^\s*[})\]]/.test(lines[loopEnd]) && indentOf(lines[loopEnd]) > ind)) loopEnd++;
        break;
      }
    }
    if (loopStart < 0) continue;
    const loopBody = lines.slice(loopStart, loopEnd).join('\n');
    if (!/redirect|location/i.test(loopBody.replace(MANUAL_REDIRECT, ''))) continue;
    if (reassigns(loopBody, bag)) continue;
    if (STRIP_RE.test(loopBody)) continue;
    report(hdrLine + 1, fn, bag, 'its HTTP client is told not to follow redirects and the call runs in a loop');
  }
  return out;
}
