// Sibling-guard omission — CWE-22.
//
// THE SHAPE, taken from a real advisory rather than from prose. GHSA-95cv-r8x4-vh75
// (alist): a batch-rename handler reads two fields off the same request object
// and passes only one of them through the project's own path guard.
//
//     for _, renameObject := range req.RenameObjects {
//         err := checkRelativePath(renameObject.NewName)   // guarded
//         if err != nil { ... return }
//         filePath := fmt.Sprintf("%s/%s", reqPath, renameObject.SrcName)  // NOT guarded
//         fs.Rename(ctx, filePath, renameObject.NewName)
//     }
//
// The upstream fix adds `checkRelativePath(renameObject.SrcName)` above the
// existing call. Two lines, one sibling field.
//
// WHY THIS IS HIGH PRECISION BY CONSTRUCTION. The rule never decides what a
// guard is. It OBSERVES the codebase applying some function to one field and
// then finds a sibling field of the SAME receiver, in the SAME function, that
// reaches a path-ish operation without it. The claim is therefore always
// "this file guards X and forgets Y" — falsifiable by a reviewer looking at one
// screen of code, with the guard name and both fields carried on the finding.
// It is the intra-function form of the argument `convention-deviation.js` makes
// at project scope.
//
// Deliberately NOT modelled:
//   · guards applied through a wrapper or in a callee — a cross-function version
//     needs the taint engine's summaries, and inflating this rule to guess at it
//     would trade the property that makes it credible.
//   · languages beyond Go. The shape is general, but the measured need is Go
//     (0/72 on the independent population), and each language needs its own
//     field-access and sink vocabulary verified against real code first.
//
// Found via the F1.1 root-cause histogram: this entry was one of 12 of 25 Go
// entries where the vulnerable file produced NO finding of any kind.

const GO_FILE_RE = /\.go$/i;

// `ident.Field` / `ident.Field.Sub` — a receiver and at least one field.
// Anchored on a word boundary so `a.b` inside a longer chain still resolves to
// its own receiver rather than to a substring.
const FIELD_ACCESS = /\b([A-Za-z_]\w*)\.([A-Z]\w*)\b/g;

// A call of the form `name(<receiver>.<Field>)`, single argument. The single
// argument matters: a multi-argument call is far more likely to be the
// operation itself (`fsRename(path, name)`) than a validator.
const GUARD_CALL = /\b([A-Za-z_]\w*)\s*\(\s*([A-Za-z_]\w*)\.([A-Z]\w*)\s*\)/g;

// Callees that are never guards even when called with one field argument —
// these consume a value, they do not validate it. Without this the rule reads
// `log.Printf(req.Name)` as establishing a convention.
const NOT_A_GUARD = /^(?:print|println|printf|sprintf|fprintf|log|logf|append|len|cap|new|make|string|byte|error|errorf|wrap|wrapf|panic|recover|close|delete|copy)$/i;

// Operations where an unvalidated relative path is a traversal. Kept narrow and
// literal: every entry is either a filesystem call or the string-building step
// that feeds one.
const PATH_SINK = new RegExp([
  // "%s/%s" style path joins. FORWARD slash only, deliberately.
  //
  // This originally accepted `/` OR `\`, and that produced a false positive on
  // real code (rclone `cmd/bisync/help.go:72`): a help-text formatter
  // `fmt.Sprintf("- %s - (%s) %s  \n", …)` contains a BACKSLASH as part of the
  // `\n` escape, which read as a path separator. A Go format string that builds
  // a path uses `/`; a backslash in one is nearly always an escape sequence.
  // Found on real code rather than by a fixture, which is the argument for
  // measuring a new rule against the independent population before trusting it.
  String.raw`\bfmt\.Sprintf\s*\(\s*"[^"]*/[^"]*"`,
  String.raw`\bfilepath\.(?:Join|Clean|Abs|Walk)\s*\(`,
  String.raw`\bpath\.Join\s*\(`,
  String.raw`\bos\.(?:Open|OpenFile|Create|Remove|RemoveAll|Rename|ReadFile|WriteFile|Stat|Mkdir|MkdirAll)\s*\(`,
  String.raw`\bioutil\.(?:ReadFile|WriteFile)\s*\(`,
  String.raw`\b\w*[Ff]s\.(?:Rename|Remove|Copy|Move|Open|Create|Link)\s*\(`,
  String.raw`\b(?:fsRename|fsRemove|fsCopy|fsMove)\s*\(`,
].join('|'));

/** Split a Go source file into top-level function bodies by brace matching. */
function goFunctions(src) {
  const out = [];
  const re = /\bfunc\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\(/g;
  let m;
  while ((m = re.exec(src))) {
    const open = src.indexOf('{', m.index);
    if (open < 0) continue;
    let depth = 0, end = open;
    for (let i = open; i < src.length; i++) {
      const ch = src[i];
      if (ch === '{') depth++;
      else if (ch === '}') { depth--; if (depth === 0) { end = i; break; } }
    }
    if (end <= open) continue;
    out.push({ name: m[1], body: src.slice(open, end + 1), offset: open });
    re.lastIndex = end;
  }
  return out;
}

const lineOf = (src, index) => src.slice(0, index).split('\n').length;

export function scanSiblingGuard(fp, raw) {
  if (!raw || !GO_FILE_RE.test(String(fp || ''))) return [];
  if (raw.length > 500_000) return [];

  const findings = [];
  for (const fn of goFunctions(raw)) {
    // 1. Which (receiver, field) pairs does some single-arg call validate?
    //    receiver -> Map<field, guardName>
    const guarded = new Map();
    let g;
    const guardRe = new RegExp(GUARD_CALL.source, 'g');
    while ((g = guardRe.exec(fn.body))) {
      const [, callee, recv, field] = g;
      if (NOT_A_GUARD.test(callee)) continue;
      if (!guarded.has(recv)) guarded.set(recv, new Map());
      guarded.get(recv).set(field, callee);
    }
    if (!guarded.size) continue;

    // 2. Every (receiver, field) the function touches, at EVERY offset.
    //
    // Recording only the first occurrence was the first version's bug and it
    // made the rule silent on the very advisory it was written from: the first
    // mention of `renameObject.SrcName` is the `if … == ""` emptiness check,
    // several lines above the `fmt.Sprintf` that actually builds the path. A
    // field is interesting wherever it reaches a sink, not where it debuts.
    const touched = new Map();
    let a;
    const accessRe = new RegExp(FIELD_ACCESS.source, 'g');
    while ((a = accessRe.exec(fn.body))) {
      const [, recv, field] = a;
      if (!touched.has(recv)) touched.set(recv, new Map());
      const byField = touched.get(recv);
      if (!byField.has(field)) byField.set(field, []);
      byField.get(field).push(a.index);
    }

    for (const [recv, fields] of touched) {
      const guards = guarded.get(recv);
      if (!guards || !guards.size) continue;           // no convention on this receiver
      for (const [field, offsets] of fields) {
        if (guards.has(field)) continue;               // this field IS guarded
        // 3. Does the unguarded sibling reach a path-ish operation at ANY of
        //    its uses? Field and sink must share a line — the shape the advisory
        //    shows, and the one a reviewer confirms without tracing dataflow.
        const at = offsets.find((off) => {
          const lineStart = fn.body.lastIndexOf('\n', off) + 1;
          const lineEnd = fn.body.indexOf('\n', off);
          return PATH_SINK.test(fn.body.slice(lineStart, lineEnd < 0 ? undefined : lineEnd));
        });
        if (at === undefined) continue;

        const [guardedField, guardName] = [...guards.entries()][0];
        findings.push({
          id: `sibling-guard:${fp}:${recv}.${field}`,
          severity: 'high',
          file: fp,
          line: lineOf(fn.body, at) + lineOf(raw, fn.offset) - 1,
          vuln: `Path traversal — \`${recv}.${field}\` skips the \`${guardName}\` guard its sibling \`${recv}.${guardedField}\` uses`,
          cwe: 'CWE-22',
          family: 'sibling-guard-omission',
          parser: 'SIBLING-GUARD',
          description:
            `\`${fn.name}\` validates \`${recv}.${guardedField}\` with \`${guardName}\`, then builds a filesystem `
            + `path from the sibling field \`${recv}.${field}\` without applying the same check. A relative path in `
            + `\`${field}\` therefore escapes the intended directory.`,
          remediation: `Apply \`${guardName}(${recv}.${field})\` before using it, exactly as the sibling field does.`,
          // T2.2 — an absence-claim must record what it looked for, so a
          // reviewer (or a refutation lens) can contradict it mechanically.
          checkedFor: guardName,
          evidenceGuardedSibling: `${recv}.${guardedField}`,
          evidenceUnguardedField: `${recv}.${field}`,
        });
      }
    }
  }
  return findings;
}
