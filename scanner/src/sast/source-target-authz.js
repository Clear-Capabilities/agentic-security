// Copy or move that checks the destination but not the origin: CWE-285.
//
// THE SHAPE (Python). An operation takes a source object and a target object of the same kind (`source_folder` / `target_folder`,
// `src_board` / `dest_board`). It asks whether the caller may use the TARGET, and never asks about the SOURCE:
//
//     def copy_items(self, request, source_folder, target_folder):
//         items = source_folder.items()
//         if not target_folder.check_access(request.user):     # the destination is checked
//             raise PermissionDenied()
//         clone(items, into=target_folder)                     # the origin was never checked: its content is read out
//
// Copying reads the source, so a caller who may write somewhere they own can pull in content from an object they may not read. The fix
// asks the same question of the source.
//
// WHAT MUST BE TRUE TO REPORT.
//   1. A function that names both `<src-prefix>_<stem>` and `<dst-prefix>_<stem>` (source/src/from/origin and target/dest/destination/to).
//   2. An authorization-shaped call that receives the caller (`request.user`, `user`, `current_user`, `g.user`, ...) is applied to the
//      target: `target_x.<check>(request.user)` or `<check>(..., target_x, ...)`.
//   3. No authorization-shaped call in that function mentions the source variable.
//   4. Elsewhere in the same file, the same check method is applied to a source-role variable of the same stem: the file itself shows
//      that origins are checked with it. Without that, a target-only check may be the application's deliberate model.
// The finding is reported at the target check, the place where the source check belongs.
//
// Deliberately not modelled: brace languages (no development-split entry yet), checks performed inside a helper that receives the source
// under another name, and origins checked through a derived value (a list of its children).

const FILE_RE = /\.py$/i;
const PREFILTER = /\b(?:source|src|origin|from)_\w+[\s\S]*\b(?:target|dest|destination|to)_\w+/;
const isTest = (f) => /(?:^|\/)(?:tests?|specs?)\//.test(f) || /(?:^|\/)test_[^/]*\.py$/.test(f) || /_test\.py$/.test(f);

const SRC = 'source|src|origin|from';
const DST = 'target|dest|destination|to';
const CALLER = /\b(?:request\s*\.\s*user|current_user|g\s*\.\s*user|self\s*\.\s*request\s*\.\s*user|user|actor|principal)\b/;
// An authorization-shaped method name: a permission or access predicate, or a `check_*` that receives the caller.
const CHECK_NAME = /^(?:check_\w+|has_\w*(?:perm|permission|permissions|access)\w*|can_\w+|user_can\w*|is_\w*(?:allowed|authori[sz]ed|accessible|visible)\w*|may_\w+|assert_\w*(?:perm|access)\w*|require_\w*(?:perm|access)\w*)$/;

const indentOf = (s) => (s.match(/^[ \t]*/) || [''])[0].length;
const isBlank = (s) => !s.trim() || /^\s*#/.test(s);

function functions(lines) {
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    const d = lines[i].match(/^(\s*)(?:async\s+)?def\s+(\w+)\s*\(/);
    if (!d) continue;
    const ind = d[1].length;
    let end = i + 1;
    while (end < lines.length && (isBlank(lines[end]) || indentOf(lines[end]) > ind)) end++;
    out.push({ name: d[2], start: i, end });
  }
  return out;
}

/** Authorization-shaped calls in a line range: [{ line, method, receiver, args }]. */
function checkCalls(lines, from, to) {
  const out = [];
  const text = lines.slice(from, to).join('\n');
  for (const m of text.matchAll(/(?:\b([A-Za-z_][\w.]{0,120}?)\s*\.\s*)?\b([A-Za-z_]\w{0,80})\s*\(/g)) {
    if (!CHECK_NAME.test(m[2])) continue;
    let depth = 0, j = m.index + m[0].length - 1, k = j;
    for (; k < text.length && k < j + 600; k++) {
      if (text[k] === '(') depth++;
      else if (text[k] === ')' && --depth === 0) break;
    }
    const args = text.slice(j + 1, k);
    const receiver = m[1] || '';
    out.push({ line: from + text.slice(0, m.index).split('\n').length, method: m[2], receiver, args });
  }
  return out;
}

const mentions = (c, v) => new RegExp(`(?<![\\w.])${v}(?!\\w)`).test(`${c.receiver} ${c.args}`);

export function scanSourceTargetAuthz(file, code) {
  if (!FILE_RE.test(file) || typeof code !== 'string' || code.length > 1_000_000 || isTest(file) || !PREFILTER.test(code)) return [];
  const lines = code.split('\n');
  const fns = functions(lines);
  // Which check methods does the file apply to a source-role variable, per stem?
  const sourceChecked = new Set();   // `${method}|${stem}`
  const perFn = fns.map((f) => ({ f, calls: checkCalls(lines, f.start, f.end) }));
  for (const { calls } of perFn) for (const c of calls) {
    const all = `${c.receiver} ${c.args}`;
    for (const m of all.matchAll(new RegExp(`(?<![\\w.])(?:${SRC})_([a-z]\\w{1,40})(?!\\w)`, 'g'))) sourceChecked.add(`${c.method}|${m[1]}`);
  }
  const out = [];
  for (const { f, calls } of perFn) {
    const body = lines.slice(f.start, f.end).join('\n');
    const stems = new Set();
    for (const m of body.matchAll(new RegExp(`(?<![\\w.])(?:${DST})_([a-z]\\w{1,40})(?!\\w)`, 'g'))) stems.add(m[1]);
    for (const stem of stems) {
      const srcVar = (body.match(new RegExp(`(?<![\\w.])((?:${SRC})_${stem})(?!\\w)`)) || [])[1];
      if (!srcVar) continue;
      const dstVar = (body.match(new RegExp(`(?<![\\w.])((?:${DST})_${stem})(?!\\w)`)) || [])[1];
      const onTarget = calls.find((c) => mentions(c, dstVar) && CALLER.test(c.args) && sourceChecked.has(`${c.method}|${stem}`));
      if (!onTarget) continue;
      if (calls.some((c) => mentions(c, srcVar))) continue;
      out.push({
        id: `source-target-authz:${file}:${onTarget.line}:${srcVar}`,
        file, line: onTarget.line,
        vuln: `Copy/move checks the destination (${dstVar}) but not the origin (${srcVar})`,
        severity: 'high',
        cwe: 'CWE-285',
        family: 'broken-access-control',
        stride: 'Information Disclosure',
        description: `${f.name}() takes ${srcVar} and ${dstVar}. It applies ${onTarget.method}() to ${dstVar} for the caller, and no authorization check in the function mentions ${srcVar}. Elsewhere in this file ${onTarget.method}() is applied to a source ${stem}, so origins are meant to be checked: here a caller who may use the destination can read content out of an origin they were never checked against.`,
        remediation: `Apply the same check to ${srcVar} (for example ${srcVar}.${onTarget.method}(request.user)) before reading from it.`,
        snippet: lines[onTarget.line - 1].trim().slice(0, 200),
        parser: 'AUTHZ-SOURCE-TARGET',
        confidence: 0.55,
      });
    }
  }
  return out;
}
