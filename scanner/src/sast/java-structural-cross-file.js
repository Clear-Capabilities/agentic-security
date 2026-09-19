// SARD_80_F1 W5.41/W5.42 — cross-file literal-resolution SUPPRESSION for
// this codebase's Java taint-independent structural detectors
// (java-structural.js's SQLi/cmdi rules, java-bench-extras.js's CWE-601
// open-redirect rule).
//
// W5.40 root-caused java-structural.js's own remaining CWE-89 false-
// positive bucket (175 of 186 fps, on the real corpus) to Juliet's Flow
// Variant 51+ idiom: "data passed as an argument from one method to
// another, in a DIFFERENT class" — confirmed via a direct fetch of the
// public mirror's own `CWE89_SQL_Injection__database_executeQuery_51a.java`
// / `_51b.java` pair. File `_51a`'s `goodG2B()` calls
// `(new ..._51b()).goodG2BSink("foo")` with a hardcoded literal; the sink
// itself lives in `_51b`'s `goodG2BSink(String data)`, where `data` is a
// bare method PARAMETER with no same-file assignment at all. Every real
// caller of `goodG2BSink` passes a literal — but that caller lives in a
// SIBLING FILE, invisible to the detector's own same-file-only literal-
// tracking helper. W5.42 found the SAME idiom manifests identically in
// java-bench-extras.js's independent CWE-601 `response.sendRedirect`
// detector (a separate, independently-tuned copy of the same "nearest
// assignment is a literal" heuristic).
//
// This module is a SEPARATE, project-wide post-loop pass — NOT a change to
// either detector's per-file call signature — deliberately mirroring
// `csharp-cross-file.js`'s own W5.31 design of a standalone project-wide
// pass rather than threading extra context through the per-file detector
// cascade. `engine.js`'s `_runFileCascade` is explicitly documented as
// self-contained so it can run inside a worker thread for deep-mode scans;
// threading sibling-file content through that interface would require
// verifying both the sync AND worker code paths carry it correctly, a
// substantially larger and riskier change than this suppression-only pass,
// which only ever needs read access to the whole project's file contents —
// already available at the SAME post-loop stage `scanCsharpCrossFile`
// itself runs at in engine.js.
//
// Unlike csharp-cross-file.js (which ADDS genuinely new findings from
// cross-file taint), this module only ever SUPPRESSES an already-emitted
// finding: it re-derives the exact same "is the concatenated/redirected
// variable provably a literal" question each detector already asks, using
// the SAME regexes and the SAME literal-tracking mechanism (imported, not
// duplicated, to avoid drift), extended with an optional sibling-file
// fallback — see `java-structural.js`'s own `_resolveParamLiteralViaAllCallSites`
// header comment for why the fallback ALSO requires matching the sink's own
// declared class name, not just its bare method name: Juliet reuses the
// SAME generic method names (bad/badSink/goodG2B/goodG2BSink/…) identically
// across thousands of otherwise-unrelated flow-variant files living in the
// SAME directory, and blind scrambling preserves that collision by design
// (the same original word always hashes to the same opaque token,
// everywhere) — confirmed directly against the real corpus during W5.41's
// own verification (a bare-name search across one directory's ~980 sibling
// files matched hundreds of unrelated classes' own same-named methods,
// causing an unrelated caller elsewhere in the directory to make the check
// fail closed even for the intended pair).
//
// It never invents a new detection capability and never touches any other
// detector's findings.
//
// Scope, deliberately conservative and matching every other interprocedural
// mechanism in this codebase: SAME DIRECTORY ONLY (Juliet's own convention
// — a flow variant's split-file siblings always live together), and a real,
// non-literal call site ANYWHERE (same file or any sibling, for the SAME
// class) still fails the check closed, exactly like the same-file-only
// version already does — this can only ever suppress a finding that a
// same-file-only reading of every real caller would ALSO have deemed safe,
// not guess from partial information.
import { blankComments } from './_comment-strip.js';
import { deadBranchRanges, isLineInDeadRange } from './java-ast-folding.js';
import { RE as STRUCTURAL_RE, _trailingIdentIsLiteral } from './java-structural.js';
import { SEND_REDIRECT_RE, _nearestAssignIsLiteral } from './java-bench-extras.js';

function _parseProject(fileContents) {
  const javaFiles = Object.entries(fileContents || {}).filter(([p, raw]) => /\.java$/i.test(p) && raw);
  const byDir = new Map();
  const parsedByFile = new Map(); // file -> { raw, code, deadRanges }
  for (const [file, raw] of javaFiles) {
    if (raw.length > 500_000) continue;
    const dir = file.slice(0, file.lastIndexOf('/'));
    if (!byDir.has(dir)) byDir.set(dir, []);
    byDir.get(dir).push(file);
    let code;
    try { code = blankComments(raw); } catch { continue; }
    let ranges = [];
    try { ranges = deadBranchRanges(raw); } catch { /* parse error → no AST info, same fallback as the detectors themselves use */ }
    parsedByFile.set(file, { raw, code, deadRanges: ranges });
  }
  return { javaFiles, byDir, parsedByFile };
}

function _siblingsOf(file, byDir, parsedByFile) {
  const dir = file.slice(0, file.lastIndexOf('/'));
  return (byDir.get(dir) || [])
    .filter((f) => f !== file)
    .map((f) => parsedByFile.get(f))
    .filter(Boolean)
    .map((s) => ({ code: s.code, deadRanges: s.deadRanges }));
}

export function computeJavaStructuralCrossFileSuppressions(fileContents) {
  const drop = new Set();
  const { javaFiles, byDir, parsedByFile } = _parseProject(fileContents);
  if (javaFiles.length < 2) return drop;

  for (const [file] of javaFiles) {
    const self = parsedByFile.get(file);
    if (!self) continue;
    const siblingFiles = _siblingsOf(file, byDir, parsedByFile);
    if (!siblingFiles.length) continue;

    // java-structural.js's own SQLi/cmdi structural detectors.
    for (const re of Object.values(STRUCTURAL_RE)) {
      const r = new RegExp(re.source, re.flags);
      let m;
      while ((m = r.exec(self.code))) {
        const varName = m[1];
        if (!varName) continue;
        if (self.deadRanges.length) {
          const line0 = self.code.substring(0, m.index).split('\n').length;
          // A sink already inside a dead range never produced a finding in
          // the first place — nothing to suppress; skip re-deriving it here.
          if (isLineInDeadRange(line0, self.deadRanges)) continue;
        }
        if (_trailingIdentIsLiteral(self.code, varName, m.index, self.deadRanges, 0, siblingFiles)) {
          const line = self.code.substring(0, m.index).split('\n').length;
          drop.add(`${file}:${line}`);
        }
      }
    }

    // java-bench-extras.js's own CWE-601 response.sendRedirect detector.
    const redirectRe = new RegExp(SEND_REDIRECT_RE.source, SEND_REDIRECT_RE.flags);
    let rm;
    while ((rm = redirectRe.exec(self.code))) {
      const arg = (rm[1] || '').trim();
      if (!/^[A-Za-z_]\w*$/.test(arg)) continue; // only a bare identifier is a literal-tracking candidate
      if (self.deadRanges.length) {
        const line0 = self.code.substring(0, rm.index).split('\n').length;
        if (isLineInDeadRange(line0, self.deadRanges)) continue;
      }
      if (_nearestAssignIsLiteral(self.code, arg, rm.index, self.deadRanges, 0, siblingFiles)) {
        const line = self.code.substring(0, rm.index).split('\n').length;
        drop.add(`${file}:${line}`);
      }
    }
  }
  return drop;
}
