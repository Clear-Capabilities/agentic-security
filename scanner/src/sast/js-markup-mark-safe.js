// JavaScript/TypeScript: a value interpolated, unescaped, into markup that is then marked safe, or JSON.stringify output written into
// inline script text (CWE-79).
//
// The flow engine reports XSS when a request value reaches an HTML sink. Framework and renderer code never sees the request: it builds
// markup from its own arguments and hands it to a function that tells the template layer not to escape it again. The rule follows the
// markup string to that call:
//
//   markSafe     a template literal holding a tag (`<x`) passed to a mark-safe function (markHTMLString, unsafeHTML, unsafeStatic,
//                `new SafeString`, bypassSecurityTrustHtml, `__html:`), directly or through a local assigned the template, where an
//                interpolation is a bare value (a name, a member chain, `.toString()`), not an escaper or another call.
//   scriptJson   `${JSON.stringify(x)}` written into inline script text: after an unclosed `<script>` tag in the same template, or as
//                the value of a `window.x = ` / `globalThis.x = ` assignment held in a string. JSON.stringify does not escape `<`, so a
//                value holding `</script>` ends the script element and starts markup.
//
// An interpolation is escaped when it calls anything other than a plain conversion (`escapeHTML(x)`, `toAttributeString(x)`,
// `stringifyForScript(x)`, `encodeURIComponent(x)`, a render helper that returns markup), or is a number literal. The rule does not decide
// whether the value can hold attacker text; the finding says so.

const FILE_RE = /\.(?:[cm]?[jt]sx?)$/i;
const PREFILTER = /markHTMLString|unsafeHTML|unsafeStatic|SafeString|bypassSecurityTrustHtml|__html|JSON\.stringify/;
const MARK_SAFE = /\b(markHTMLString|unsafeHTML|unsafeStatic|bypassSecurityTrustHtml)\s*\(\s*|\bnew\s+(?:[\w$]+\.)?(SafeString)\s*\(\s*|\b(__html)\s*:\s*/g;
// a bare value: identifier or member chain, optionally followed by a plain conversion
const CONVERSION_TAIL = /\.(?:toString|trim|join|toLowerCase|toUpperCase)\([^()]*\)$/;
const NAME_CHAIN = /^[A-Za-z_$][\w$.?[\]'"]*$/;
const isBare = (e) => NAME_CHAIN.test(e.replace(CONVERSION_TAIL, '')) && !/\.\./.test(e);

/** Parse a template literal starting at the backtick `at`; returns { end, quasis[], exprs[{text, at}] } or null. */
function readTemplate(src, at) {
  const quasis = []; const exprs = [];
  let i = at + 1; let q = '';
  while (i < src.length) {
    const c = src[i];
    if (c === '\\') { q += c + (src[i + 1] || ''); i += 2; continue; }
    if (c === '`') { quasis.push(q); return { end: i + 1, quasis, exprs }; }
    if (c === '$' && src[i + 1] === '{') {
      quasis.push(q); q = '';
      const start = i + 2; let depth = 1; let j = start;
      while (j < src.length && depth) {
        const d = src[j];
        if (d === '`') { const inner = readTemplate(src, j); if (!inner) return null; j = inner.end; continue; }
        if (d === '"' || d === "'") { j++; while (j < src.length && src[j] !== d && src[j] !== '\n') { if (src[j] === '\\') j++; j++; } j++; continue; }
        if (d === '{') depth++; else if (d === '}') depth--;
        j++;
      }
      if (depth) return null;
      exprs.push({ text: src.slice(start, j - 1).trim(), at: start });
      i = j; continue;
    }
    q += c; i++;
    if (i - at > 20000) return null;
  }
  return null;
}

const lineOf = (src, idx) => src.slice(0, idx).split('\n').length;
const isEscaped = (e) => !isBare(e);

// an escaper's vocabulary, for the right-hand side of the local an interpolation names
const ESCAPER_CALL = /^\s*(?:await\s+)?[\w$.]*(?:escape|encode|sanitiz|stringifyForScript|toAttributeString|purify)\w*\s*\(/i;

/** Where an interpolation sits in markup: element text or an attribute value count; a tag name or a bare attribute list does not. */
function inMarkupValue(text) {
  if (!/<[a-zA-Z!\/]/.test(text)) return false;
  const lt = text.lastIndexOf('<'); const gt = text.lastIndexOf('>');
  if (gt > lt) return true; // element text
  return /=\s*["']?[^"'<>]*$/.test(text.slice(lt)); // inside an attribute value
}

/** The bare interpolations of a template that sit inside markup, skipping locals last assigned from an escaper before `before`. */
function unescapedInMarkup(t, src, before) {
  const hits = [];
  let text = '';
  for (let k = 0; k < t.exprs.length; k++) {
    text += t.quasis[k];
    const e = t.exprs[k].text;
    if (inMarkupValue(text) && !isEscaped(e)) {
      const name = e.match(/^[A-Za-z_$][\w$]*$/)?.[0];
      const assigns = name ? [...src.slice(Math.max(0, before - 4000), before).matchAll(new RegExp(`(?:^|[^\\w$.])${name.replace(/\$/g, '\\$')}\\s*(?::\\s*[\\w<>\\[\\]]+\\s*)?=(?![=>])([^;\\n]*)`, 'g'))] : [];
      if (!(assigns.length && ESCAPER_CALL.test(assigns[assigns.length - 1][1]))) hits.push(t.exprs[k]);
    }
    text += '\u0000';
  }
  return hits;
}

function jsonInScript(t) {
  const hits = [];
  let text = '';
  for (let k = 0; k < t.exprs.length; k++) {
    text += t.quasis[k];
    const e = t.exprs[k].text;
    // a module constant or a literal serializes to text the author wrote
    if (/^JSON\.stringify\s*\(/.test(e) && /\)$/.test(e) && !/^JSON\.stringify\s*\(\s*(?:[A-Z][A-Z0-9_]*|['"`\d][^,()]*)\s*\)$/.test(e)) {
      const openScript = /<script\b[^>]*>(?![\s\S]*<\/script>)[\s\S]*$/i.test(text);
      const globalAssign = /(?:^|[;\n{(])\s*(?:window|globalThis|self)[.[][\w$.[\]'"]*\s*=\s*$/.test(text);
      if (openScript || globalAssign) hits.push(t.exprs[k]);
    }
    text += '\u0000';
  }
  return hits;
}

export function scanJsMarkupMarkSafe(fp, src) {
  if (!FILE_RE.test(fp) || typeof src !== 'string' || src.length > 800_000 || !PREFILTER.test(src)) return [];
  if (/(?:^|\/)(?:__tests__|tests?|spec|__mocks__|fixtures?)\//i.test(fp) || /\.(?:test|spec)\.[cm]?[jt]sx?$/i.test(fp)) return [];
  const lines = src.split('\n');
  const out = []; const seen = new Set();
  const report = (kind, idx, sinkIdx, expr, vuln, description) => {
    const line = lineOf(src, idx);
    const id = `js-markup-${kind}:${fp}:${line}`;
    if (seen.has(id)) return;
    seen.add(id);
    const sinkLine = lineOf(src, sinkIdx);
    out.push({
      id, file: fp, line, vuln, severity: 'medium', cwe: 'CWE-79', family: 'xss',
      description: description + (sinkLine !== line ? ` It is marked safe at line ${sinkLine}.` : '') + ' Whether the value can hold text an attacker controls is not checked here.',
      remediation: kind === 'scriptJson'
        ? 'Serialize data for an inline script with an encoder that escapes `<`, `>`, `&`, U+2028 and U+2029 (for example replace `<` with `\\u003c` after JSON.stringify), or pass the data in a JSON `<script type="application/json">` element read with textContent.'
        : 'Escape each value for its context where it is interpolated (an HTML or attribute escaper for markup, a CSS escaper that neutralises `</style>` for style text), or build the element with the template layer so it escapes for you, and mark safe only markup whose every value is escaped.',
      snippet: (lines[line - 1] || '').trim().slice(0, 200), parser: 'JS-MARKUP', confidence: 0.55,
    });
  };

  // locals assigned a template literal: name -> template
  const held = new Map();
  for (const m of src.matchAll(/\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::\s*string\s*)?=\s*`/g)) {
    const t = readTemplate(src, m.index + m[0].length - 1);
    if (t) held.set(m[1], { t, at: m.index });
  }

  for (const m of src.matchAll(MARK_SAFE)) {
    const fn = m[1] || m[2] || m[3];
    const argAt = m.index + m[0].length;
    let t = null;
    if (src[argAt] === '`') t = readTemplate(src, argAt);
    else {
      const id = src.slice(argAt).match(/^([A-Za-z_$][\w$]*)\s*[),}]/);
      const h = id && held.get(id[1]);
      if (h && h.at < m.index) t = h.t;
    }
    if (!t) continue;
    for (const e of unescapedInMarkup(t, src, m.index)) {
      report('markSafe', e.at, m.index, e.text, 'XSS: value interpolated unescaped into markup that is marked safe',
        `\`${e.text}\` is interpolated into markup without escaping and the result is passed to \`${fn}\`, which stops the template layer escaping it.`);
    }
  }

  for (let i = src.indexOf('`'); i !== -1; ) {
    const t = readTemplate(src, i);
    if (!t) { i = src.indexOf('`', i + 1); continue; }
    for (const e of jsonInScript(t)) {
      report('scriptJson', e.at, e.at, e.text, 'XSS: JSON.stringify output written into inline script text',
        '`JSON.stringify` output is written into inline script text. It does not escape `<`, so a string value holding `</script>` ends the script element and the rest is parsed as markup.');
    }
    i = src.indexOf('`', t.end);
  }
  return out;
}
