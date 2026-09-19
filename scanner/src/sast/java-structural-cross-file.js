// SARD_80_F1 W5.41 — cross-file literal-resolution SUPPRESSION for
// java-structural.js's own structural SQLi/cmdi detectors.
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
// SIBLING FILE, invisible to `java-structural.js`'s own same-file-only
// `_resolveParamLiteralViaAllCallSites`.
//
// This module is a SEPARATE, project-wide post-loop pass — NOT a change to
// `scanJavaStructural`'s per-file call signature — deliberately mirroring
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
// finding: it re-derives the exact same "is the concatenated variable
// provably a literal" question java-structural.js's own detectors already
// ask, using the SAME regexes and the SAME `_trailingIdentIsLiteral`
// mechanism (imported, not duplicated, to avoid drift), extended with an
// optional sibling-file fallback — see that function's own header comment
// (java-structural.js) for why the fallback ALSO requires matching the
// sink's own declared class name, not just its bare method name: Juliet
// reuses the SAME generic method names (bad/badSink/goodG2B/goodG2BSink/…)
// identically across thousands of otherwise-unrelated flow-variant files
// living in the SAME directory, and blind scrambling preserves that
// collision by design (the same original word always hashes to the same
// opaque token, everywhere) — confirmed directly against the real corpus
// during this fix's own verification (a bare-name search across one
// directory's ~980 sibling files matched hundreds of unrelated classes'
// own same-named methods, causing an unrelated caller elsewhere in the
// directory to make this check fail closed even for the intended pair).
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
import { RE, _trailingIdentIsLiteral } from './java-structural.js';

export function computeJavaStructuralCrossFileSuppressions(fileContents) {
  const drop = new Set();
  const javaFiles = Object.entries(fileContents || {}).filter(([p, raw]) => /\.java$/i.test(p) && raw);
  if (javaFiles.length < 2) return drop;

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
    try { ranges = deadBranchRanges(raw); } catch { /* parse error → no AST info, same fallback as scanJavaStructural itself */ }
    parsedByFile.set(file, { raw, code, deadRanges: ranges });
  }

  for (const [file] of javaFiles) {
    const self = parsedByFile.get(file);
    if (!self) continue;
    const dir = file.slice(0, file.lastIndexOf('/'));
    const siblingFiles = (byDir.get(dir) || [])
      .filter((f) => f !== file)
      .map((f) => parsedByFile.get(f))
      .filter(Boolean)
      .map((s) => ({ code: s.code, deadRanges: s.deadRanges }));
    if (!siblingFiles.length) continue;

    for (const re of Object.values(RE)) {
      const r = new RegExp(re.source, re.flags);
      let m;
      while ((m = r.exec(self.code))) {
        const varName = m[1];
        if (!varName) continue;
        if (self.deadRanges.length) {
          const line0 = self.code.substring(0, m.index).split('\n').length;
          // A sink already inside a dead range never produced a finding in
          // the first place (scanJavaStructural's own check) — nothing to
          // suppress; skip re-deriving it here too.
          if (isLineInDeadRange(line0, self.deadRanges)) continue;
        }
        if (_trailingIdentIsLiteral(self.code, varName, m.index, self.deadRanges, 0, siblingFiles)) {
          const line = self.code.substring(0, m.index).split('\n').length;
          drop.add(`${file}:${line}`);
        }
      }
    }
  }
  return drop;
}
