// JavaScript/TypeScript: a value escaped for a regular expression by escaping only `.` (CWE-185).
//
// Code that turns a configured host name or path into a pattern often writes `host.replace(/\./g, '\\.')` and appends the result to the
// pattern source. Only the dot is escaped: `*`, `+`, `?`, `(`, `[`, `|`, `^`, `$` and `\` in the value keep their regex meaning, so the
// pattern matches strings the author did not intend (an allow-list of hosts or paths that admits other hosts or paths), or fails to
// compile. The fix is a complete escape of every metacharacter (`s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')`).
//
//   sink    `.replace(/\./g, '\\.')`, `.replace(/[.]/g, ...)` or `.replaceAll('.', '\\.')` whose result is used as regex source: on a
//           line that builds a `RegExp`, appends to or assigns a variable named like a pattern (`regex`, `pattern`, `re`), or sits in a
//           string or template holding regex syntax (`\/`, `.*`, `[^`, `(?:`, `https?:`), in a file that compiles patterns.
//   silent  a chain that also escapes other metacharacters on the same value, and a file with no `RegExp` or regex-named value.

const FILE_RE = /\.(?:[cm]?[jt]sx?)$/i;
// a dot-only escape: replace(/\./g, '\\.') / replace(/[.]/g, '\\.') / replaceAll('.', '\\.') / replaceAll(/\./g, '\\.')
const DOT_ONLY = /\.replace(?:All)?\s*\(\s*(?:\/(?:\\\.|\[\.\])\/g?|(['"])\.\1)\s*,\s*(['"])\\\\\.\2\s*\)/g;
const OTHER_ESCAPE = /\.replace(?:All)?\s*\(\s*(?:\/(?:\\[*+?()[\]^$|]|\[[^\]]*[*+?(^$|][^\]]*\])|(['"])[*+?()[\]^$|\\]\1)/;
const REGEX_USE = /\bRegExp\s*\(|\b[\w$]*(?:regex|regexp|pattern|Regex|RegExp|Pattern)[\w$]*\s*(?:\+?=|:)|\bre\s*\+?=|\\\\?\/|\.\*|\[\^|\(\?:|https\?:/;

const lineOf = (src, idx) => src.slice(0, idx).split('\n').length;

export function scanJsIncompleteRegexEscape(fp, src) {
  if (!FILE_RE.test(fp) || typeof src !== 'string' || src.length > 800_000) return [];
  if (!/replace/.test(src) || !/\bRegExp\b|regex/i.test(src)) return [];
  if (/(?:^|\/)(?:__tests__|tests?|spec|fixtures?)\//i.test(fp) || /\.(?:test|spec)\.[cm]?[jt]sx?$/i.test(fp)) return [];
  const lines = src.split('\n');
  const out = []; const seen = new Set();
  for (const m of src.matchAll(DOT_ONLY)) {
    const line = lineOf(src, m.index);
    const text = lines[line - 1] || '';
    if (OTHER_ESCAPE.test(text)) continue;
    // the line around the escape, with the escape itself removed so its own `\\.` is not read as regex syntax
    const ctx = text.replace(m[0], '');
    if (!REGEX_USE.test(ctx)) continue;
    const id = `js-incomplete-regex-escape:${fp}:${line}`;
    if (seen.has(id)) continue;
    seen.add(id);
    out.push({
      id, file: fp, line,
      vuln: 'Incomplete regular-expression escaping: only `.` is escaped before the value is used as pattern source',
      severity: 'medium', cwe: 'CWE-185', family: 'regex-injection',
      description: 'The value is escaped for a regular expression by escaping only `.`, then used as pattern source. Other metacharacters in it (`*`, `+`, `?`, `(`, `[`, `|`, `\\`) keep their meaning, so the pattern can match hosts or paths that were not meant to match, or fail to compile.',
      remediation: "Escape every regex metacharacter: `value.replace(/[.*+?^${}()|[\\]\\\\]/g, '\\\\$&')`, and escape each literal part of a pattern built from configuration, not only the host.",
      snippet: text.trim().slice(0, 200), parser: 'JS-REGEX', confidence: 0.6,
    });
  }
  return out;
}
