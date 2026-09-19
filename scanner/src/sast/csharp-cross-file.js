// SARD_80_F1 W5.31 — genuine cross-FILE C# interprocedural taint.
//
// W5.30 fixed a receiver-qualified call (`Sink.BadSink(data, …)`) being
// invisible to `csharp-analysis.js`'s interprocedural taint-seeding when the
// callee's class lives in the SAME file. It could not, by itself, fix
// Juliet's own real corpus shape for this idiom (Flow Variant 51/52/53/54/
// 61/66-75/81, "…in a different class in the same/different package") —
// every one of those flow variants splits the caller and the sink class
// across TWO PHYSICAL FILES (confirmed via the public C# mirror's own
// `CWE36_..._Params_Get_Web_51a.cs`/`_51b.cs` pair), and `analyzeCSharpIR`
// only ever sees one file's own `ir` — it cannot know a receiver name
// resolves to a class declared somewhere else in the project, let alone
// re-analyze that class's method with the caller's taint applied.
//
// This module is the project-wide layer that closes that gap. It parses
// EVERY `.cs` file once, builds a project-wide class registry, and for each
// caller's receiver-qualified call whose receiver does NOT resolve to a
// class in the SAME file (W5.30 already covers that) but DOES resolve,
// unambiguously, to a `static` method on a class declared in EXACTLY ONE
// OTHER file, re-runs that callee file's own analysis with the parameter
// seeded as externally tainted (via `analyzeCSharpIR`'s `externalTaintedParams`
// option) and re-runs the full detector suite against it. Any finding that
// was NOT already present in that file's own ordinary (un-seeded) scan is
// genuinely new — attributable to this cross-file flow and nothing else —
// and is the only thing this module reports; every finding the ordinary
// per-file scan already produces on its own is excluded by an id-diff so
// nothing is ever double-counted.
//
// Deliberately conservative, matching every other interprocedural mechanism
// in this codebase: SINGLE HOP only (a callee that itself forwards the value
// to a THIRD file's method is not covered — the same scope boundary
// `csharp-analysis.js`'s own same-file W4.C41/W5.30 mechanisms already
// accept); an AMBIGUOUS class name (declared in 2+ files) or an ambiguous
// method match (2+ static candidates of that name on that class) is left
// unresolved rather than guessed, exactly like the same-file case.
import { buildCSharpIR, analyzeCSharpIR, runCSharpDetectors } from './csharp.js';
import { argIsTainted } from '../posture/csharp-analysis.js';

export function scanCsharpCrossFile(fileContents) {
  const csFiles = Object.entries(fileContents).filter(([p]) => /\.cs$/i.test(p));
  if (csFiles.length < 2) return [];

  const parsed = new Map(); // file -> { raw, ir }
  for (const [file, raw] of csFiles) {
    if (!raw || raw.length > 500_000) continue;
    let ir;
    try { ir = buildCSharpIR(raw); } catch { continue; }
    parsed.set(file, { raw, ir });
  }
  if (parsed.size < 2) return [];

  // Project-wide class registry: className -> [{file, class}]. A name
  // declared in 2+ files is intentionally left ambiguous (never guessed).
  const classRegistry = new Map();
  for (const [file, { ir }] of parsed) {
    for (const c of ir.classes) {
      if (!classRegistry.has(c.name)) classRegistry.set(c.name, []);
      classRegistry.get(c.name).push({ file, class: c });
    }
  }

  // Baseline per-file analysis: needed both for the caller-side
  // `argIsTainted` check (via the caller's own un-seeded flow) and to diff
  // away findings the ordinary per-file scan already produces on its own.
  const baseline = new Map(); // file -> { analysis, ir, raw, findingIds }
  for (const [file, { raw, ir }] of parsed) {
    let analysis;
    try { analysis = analyzeCSharpIR(ir); } catch { continue; }
    let findings;
    try { findings = runCSharpDetectors(file, raw, ir, analysis); } catch { findings = []; }
    baseline.set(file, { analysis, ir, raw, findingIds: new Set(findings.map(f => f.id)) });
  }

  // externalTaintByFile: targetFile -> Map(calleeMethodObject -> Set(paramName))
  const externalTaintByFile = new Map();
  for (const [callerFile, { ir: callerIr }] of parsed) {
    const callerBase = baseline.get(callerFile);
    if (!callerBase) continue;
    const localClassNames = new Set(callerIr.classes.map(c => c.name));
    for (const caller of callerIr.methods) {
      const callerFlow = callerBase.analysis.methodFlow.get(caller);
      if (!callerFlow) continue;
      for (const call of caller.calls || []) {
        if (!call.receiver) continue; // bare calls: same-file only, W4.C41 already covers
        if (localClassNames.has(call.receiver)) continue; // same-file class: W5.30 already covers
        const candidates = classRegistry.get(call.receiver);
        if (!candidates || candidates.length !== 1) continue; // unknown/ambiguous class name
        const { file: targetFile, class: targetClass } = candidates[0];
        if (targetFile === callerFile) continue; // defensive; shouldn't happen given the check above
        const targetParsed = parsed.get(targetFile);
        if (!targetParsed) continue;
        const methodCandidates = targetClass.methods.filter(m =>
          m.name === call.method && (m.modifiers || []).includes('static'));
        if (methodCandidates.length !== 1) continue; // ambiguous/no static match on that class
        const callee = methodCandidates[0];
        for (let i = 0; i < (call.args || []).length; i++) {
          const param = (callee.params || [])[i];
          if (!param) continue;
          if (!argIsTainted(callerFlow, call.args[i])) continue;
          if (!externalTaintByFile.has(targetFile)) externalTaintByFile.set(targetFile, new Map());
          const m = externalTaintByFile.get(targetFile);
          if (!m.has(callee)) m.set(callee, new Set());
          m.get(callee).add(param.name);
        }
      }
    }
  }

  const crossFileFindings = [];
  for (const [targetFile, externalTaintedParams] of externalTaintByFile) {
    const targetParsed = parsed.get(targetFile);
    const base = baseline.get(targetFile);
    if (!targetParsed || !base) continue;
    let enrichedAnalysis;
    try { enrichedAnalysis = analyzeCSharpIR(targetParsed.ir, { externalTaintedParams }); } catch { continue; }
    let enrichedFindings;
    try { enrichedFindings = runCSharpDetectors(targetFile, targetParsed.raw, targetParsed.ir, enrichedAnalysis); } catch { continue; }
    for (const f of enrichedFindings) {
      if (base.findingIds.has(f.id)) continue; // already found by the ordinary per-file scan
      f.isCrossFile = true;
      crossFileFindings.push(f);
    }
  }
  return crossFileFindings;
}
