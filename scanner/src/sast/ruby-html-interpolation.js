// Ruby: a method's argument interpolated, unescaped, into markup that is then marked html_safe (CWE-79).
//
// xss-reflected-multilang.js covers `params`/`request` reaching `render inline:`, `raw` and `.html_safe` on one line. A helper or a
// renderer LIBRARY never touches `params`: its input is its caller's argument, and the published advisories in that shape are a view
// helper that interpolates its argument into a string and calls `.html_safe` on it. This rule follows one method's arguments through its
// own body:
//
//   tainted     the method's parameters, block parameters of a call on a tainted value (`tags.map do |tag|`, `h.each_pair do |k, v|`),
//               and locals assigned (`=`, `||=`, `+=`, `<<`) from an expression that uses a tainted name without an escaper.
//   sink        a string literal holding markup (`<`) with an unescaped tainted interpolation, marked safe on the same line
//               (`"...#{x}...".html_safe`, `raw("...#{x}...")`), or a tainted local that holds such markup marked safe (`html.html_safe`).
//
// Not a sink: an attribute or element built by hand without `html_safe` (`"<a href=\"#{url}\">"` in a renderer). Measured on the
// independent population's development split, HTML renderer libraries (documentation and Markdown renderers, the framework's own tag
// builder) are full of that shape with values escaped further up, so it was dropped for its false positives.
//
// An interpolation is escaped when it calls an HTML or URL escaper, a tag helper, or reduces to a number (`h(x)`, `ERB::Util.
// html_escape(x)`, `CGI.escapeHTML(x)`, `sanitize(x)`, `x.to_i`, `x.size`). Where a local carried the argument into the markup, the finding
// is reported at the line that interpolated it, which is where the escape belongs and where real fixes put it.
// The rule does not decide whether a caller passes attacker text; the finding says so.

const FILE_RE = /\.rb$/i;
const PREFILTER = /html_safe|\braw\s*\(/;
const ESCAPED = /\b(?:h|html_escape|html_escape_once|escape_html|escapeHTML|escape_once|sanitize|strip_tags|escape_javascript|url_encode|u|j)(?:\s*\(|\s+[\w@:'"])|\b(?:CGI|ERB::Util|Rack::Utils|URI)\.\w+|\.\s*(?:to_i|to_f|to_r|size|length|count|id|object_id|to_json|present\?|blank\?|nil\?|empty\?)\b|\b(?:content_tag|link_to|image_tag|dom_id)\b|\btag\.[a-z_]+(?=\s*[(\s]|$)/;
const DEF_RE = /^(\s*)def\s+(?:self\.)?([\w?!=]+|\[\]=?)\s*(?:\(([^)]*)\)|\s+([^#=].*?))?\s*$/;

const lineOf = (lines, i) => i + 1;

/** Blank `#` comments that are not interpolations, keeping offsets. */
function stripComment(line) {
  let inS = null;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (inS) { if (c === '\\') { i++; continue; } if (c === inS) inS = null; continue; }
    if (c === '"' || c === "'") { inS = c; continue; }
    if (c === '#' && line[i + 1] !== '{') return line.slice(0, i);
  }
  return line;
}

function paramNames(src) {
  if (!src) return [];
  return src.split(',').map((p) => p.trim().replace(/^[*&]+/, '').replace(/[:=].*$/, '').trim()).filter((n) => /^[a-z_]\w*$/.test(n));
}

/** Each `#{...}` expression in a line, with its offset. */
function interpolations(line) {
  const out = [];
  for (let i = line.indexOf('#{'); i !== -1; i = line.indexOf('#{', i + 2)) {
    let depth = 1; let j = i + 2;
    for (; j < line.length && depth; j++) { if (line[j] === '{') depth++; else if (line[j] === '}') depth--; }
    out.push({ at: i, expr: line.slice(i + 2, j - 1) });
  }
  return out;
}

const NAME_RE = (n) => new RegExp(`(?<![\\w@$.:])${n.replace(/[?!]/g, '\\$&')}(?![\\w?!:])`);
// The value an expression prints: a call's arguments are not its return value (`hint(name)` prints the hint, not `name`), so argument
// lists of calls other than a receiver chain on the name are dropped before looking for a tainted name.
function printedPart(expr) {
  let e = expr; let prev;
  do { prev = e; e = e.replace(/([A-Za-z_][\w:]*[?!]?)\s*\([^()]*\)/g, '$1'); } while (e !== prev);
  return e;
}
const usesAny = (expr, names) => names.find((n) => NAME_RE(n).test(expr)) || null;
const printsAny = (expr, names) => usesAny(printedPart(expr), names);

function analyseMethod(lines, start, end, params) {
  const tainted = new Map(params.map((p) => [p, { entry: null, markup: false }]));
  const hits = [];
  for (let i = start + 1; i < end; i++) {
    const line = stripComment(lines[i]);
    if (!line.trim()) continue;
    const names = [...tainted.keys()];
    if (!names.length) break;
    const unescapedInterp = interpolations(line).filter((x) => !ESCAPED.test(x.expr)).map((x) => ({ ...x, name: printsAny(x.expr, names) })).filter((x) => x.name);

    // sink A: markup with an unescaped interpolation marked safe on this line
    const markedSafe = /\.html_safe\b/.test(line) || /\braw\s*\(/.test(line);
    if (markedSafe && /<[!a-zA-Z\/]/.test(line)) {
      for (const x of unescapedInterp) {
        const t = tainted.get(x.name);
        hits.push({ line: t?.entry ?? lineOf(lines, i), sinkLine: lineOf(lines, i), name: x.name, kind: 'html_safe' });
      }
    }
    // sink A, second form: a local that holds tainted markup is marked safe
    for (const m of line.matchAll(/\b([a-z_]\w*)\s*\.html_safe\b|\braw\s*\(\s*([a-z_]\w*)\s*\)/g)) {
      const n = m[1] || m[2]; const t = tainted.get(n);
      if (t?.markup) hits.push({ line: t.entry ?? lineOf(lines, i), sinkLine: lineOf(lines, i), name: n, kind: 'html_safe' });
    }

    // propagation: block parameters of a call on a tainted value
    const blk = line.match(/^(.*?)(?:\bdo|\{)\s*\|([^|]+)\|/);
    if (blk && usesAny(blk[1], names) && !ESCAPED.test(blk[1])) {
      const src = tainted.get(usesAny(blk[1], names));
      for (const p of paramNames(blk[2].replace(/[()]/g, ''))) if (!tainted.has(p)) tainted.set(p, { entry: src?.entry ?? null, markup: false });
    }
    // propagation: assignment
    const asg = line.match(/^\s*([a-z_]\w*)\s*(\|\|=|\+=|<<|=(?!=|~|>))\s*(.+)$/);
    if (asg) {
      const [, target, , rhs] = asg;
      const viaInterp = interpolations(rhs).filter((x) => !ESCAPED.test(x.expr)).map((x) => printsAny(x.expr, names)).find(Boolean);
      const bare = !viaInterp && !ESCAPED.test(rhs) ? usesAny(rhs.replace(/"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'/g, '""'), names) : null;
      const from = viaInterp || bare;
      const prev = tainted.get(target);
      if (from) {
        const src = tainted.get(from);
        const markup = /<[!a-zA-Z\/]/.test(rhs) || !!src?.markup || !!prev?.markup;
        tainted.set(target, { entry: viaInterp ? lineOf(lines, i) : (prev?.entry ?? src?.entry ?? null), markup });
      } else if (prev && asg[2] === '=' && target !== from) {
        tainted.delete(target); // reassigned from something untainted
      }
    }
  }
  return hits;
}

export function scanRubyHtmlInterpolation(file, code) {
  if (!FILE_RE.test(file) || typeof code !== 'string' || !PREFILTER.test(code)) return [];
  if (/(?:^|\/)(?:spec|test)\//.test(file) || /_(?:spec|test)\.rb$/.test(file)) return [];
  const lines = code.split('\n');
  const out = []; const seen = new Set();
  for (let i = 0; i < lines.length; i++) {
    const d = lines[i].match(DEF_RE);
    if (!d) continue;
    const indent = d[1];
    let end = i + 1;
    const endRe = new RegExp(`^${indent}end\\b`);
    while (end < lines.length && end - i < 400 && !endRe.test(lines[end])) end++;
    if (end >= lines.length || end - i >= 400) continue;
    const params = paramNames(d[3] ?? d[4]);
    if (!params.length) continue;
    for (const h of analyseMethod(lines, i, end, params)) {
      if (seen.has(h.line)) continue;
      seen.add(h.line);
      const where = h.line === h.sinkLine ? '' : ` It is marked safe at line ${h.sinkLine}.`;
      out.push({
        id: `ruby-html-interpolation:${file}:${h.line}`,
        file, line: h.line,
        vuln: 'XSS: method argument interpolated into markup marked html_safe',
        severity: 'medium',
        cwe: 'CWE-79',
        family: 'xss',
        stride: 'Tampering',
        description: `\`${d[2]}\` interpolates \`${h.name}\`, which comes from its arguments, into HTML without escaping it.${where} Text with \`"\`, \`<\` or \`>\` in it becomes markup or script in the page. Whether a caller passes text an attacker controls is not checked here.`,
        remediation: 'Escape the value where it is interpolated (`ERB::Util.html_escape(x)`, `CGI.escapeHTML(x)`, or `h(x)` in a view), or build the element with a tag helper (`content_tag`, `tag.span`) that escapes attributes and content, and do not call `html_safe` on a string that holds unescaped input.',
        snippet: (lines[h.line - 1] || '').trim().slice(0, 200),
        parser: 'RUBY-HTML',
        confidence: 0.55,
      });
    }
  }
  return out;
}
