// Analysis-coverage honesty report (roadmap #5 + #6).
//
// A "perfect" SAST scanner must publish its blind spots, not hide them. This
// module turns three things the engine already knows internally into an
// explicit, user-facing coverage summary:
//
//   1. Per-language ANALYSIS TIER — which languages in this scan got the full
//      IR + taint engine vs. only pattern (regex) detectors. The taint engine
//      is wired for js/ts/py/java/cs/kt/go/php/rb; everything else
//      (c/c++/rust/swift/solidity/dart/…) is pattern-only today.
//   2. Files SKIPPED and why (too large, too dense, timed out).
//   3. UNMODELED-SINK candidates (#5) — calls that match a dangerous shape but
//      have NO finding at their line, i.e. likely recall blind spots to verify.
//
// All of this is informational; it never changes a finding's severity.

// Languages that flow through the Layer-1 IR + Layer-2 taint engine.
export const IR_TAINT_LANGS = new Set(['js', 'ts', 'py', 'java', 'cs', 'kt', 'go', 'php', 'rb']);

const EXT_TO_LANG = {
  js: 'js', jsx: 'js', mjs: 'js', cjs: 'js', ts: 'ts', tsx: 'ts',
  py: 'py', pyw: 'py', java: 'java', go: 'go', rb: 'rb', php: 'php',
  cs: 'cs', kt: 'kt', kts: 'kt', swift: 'swift', rs: 'rs',
  c: 'c', h: 'c', cpp: 'cpp', cc: 'cpp', cxx: 'cpp', hpp: 'cpp',
  sol: 'sol', dart: 'dart', scala: 'scala', m: 'objc',
};

export function langOfFile(file) {
  if (typeof file !== 'string') return null;
  const ext = file.split('.').pop().toLowerCase();
  return EXT_TO_LANG[ext] || null;
}

// Given the list of scanned files, report which languages got IR-taint vs.
// pattern-only analysis, with a per-language file count.
export function computeAnalysisTiers(fileList) {
  const counts = {};
  for (const f of fileList || []) {
    const l = langOfFile(f);
    if (!l) continue;
    counts[l] = (counts[l] || 0) + 1;
  }
  const irTaint = {}, patternOnly = {};
  for (const [lang, n] of Object.entries(counts)) {
    (IR_TAINT_LANGS.has(lang) ? irTaint : patternOnly)[lang] = n;
  }
  return {
    irTaint,        // { js: 12, py: 4 }
    patternOnly,    // { rs: 3, sol: 1 }  → flow analysis NOT applied
    languages: Object.keys(counts).sort(),
  };
}

// Dangerous-call shapes worth surfacing when no finding lands on their line.
// Deliberately conservative + cross-language; this is a "did we miss a sink?"
// prompt for the user, emitted at info level only.
const DANGER_TOKENS = [
  [/\beval\s*\(/, 'eval'],
  [/\bnew\s+Function\s*\(/, 'Function-constructor'],
  [/\bvm\.\s*runIn\w+\s*\(/, 'vm.runIn*'],
  [/\bchild_process\b|\bexecSync?\s*\(|\bspawnSync?\s*\(/, 'child_process'],
  [/\bdeserialize\s*\(|readObject\s*\(|ObjectInputStream\b/, 'deserialize'],
  [/\byaml\.\s*load\s*\(|\bsafe_load\b/, 'yaml.load'],
  [/\bpickle\.\s*loads?\s*\(/, 'pickle.load'],
  [/\bMarshal\.\s*load\b|\bunserialize\s*\(/, 'unserialize'],
  [/\bRuntime\b[\s\S]{0,40}\.exec\s*\(|\bProcessBuilder\b/, 'Runtime.exec/ProcessBuilder'],
  [/\bos\.\s*system\s*\(|\bsubprocess\.\s*(?:call|run|Popen)\s*\(/, 'os.system/subprocess'],
  [/\.innerHTML\s*=|\bdangerouslySetInnerHTML\b/, 'innerHTML'],
];

// Scan file contents for danger tokens that have NO finding on their line.
// findings: array with {file,line}. fc: { path: content }. Returns a capped
// example list + total count. Lines are 1-based to match finding lines.
export function countUnmodeledSinkCandidates(fc, findings, opts = {}) {
  const cap = opts.cap || 12;
  const covered = new Set();
  for (const f of findings || []) {
    if (f && f.file && typeof f.line === 'number') covered.add(`${f.file}:${f.line}`);
  }
  const examples = [];
  let count = 0;
  for (const [file, content] of Object.entries(fc || {})) {
    if (typeof content !== 'string') continue;
    const lines = content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      for (const [re, token] of DANGER_TOKENS) {
        if (!re.test(lines[i])) continue;
        if (covered.has(`${file}:${i + 1}`)) continue; // already flagged → modelled
        count++;
        if (examples.length < cap) examples.push({ file, line: i + 1, token });
        break; // one token per line is enough
      }
    }
  }
  return { count, examples };
}

// One-line CLI summary of an analysis-coverage object.
export function summarizeCoverage(meta) {
  if (!meta) return 'coverage: (none)';
  const t = meta.analysisTier || {};
  const irLangs = Object.keys(t.irTaint || {});
  const patLangs = Object.keys(t.patternOnly || {});
  const parts = [
    `scanned=${meta.filesScanned ?? '?'}`,
    `skipped=${(meta.filesSkipped || 0) + (meta.filesDenseSkipped || 0)}`,
    `timedOut=${meta.filesTimedOut || 0}`,
    `ir-taint=[${irLangs.join(',')}]`,
  ];
  if (patLangs.length) parts.push(`pattern-only=[${patLangs.join(',')}]`);
  if (meta.unmodeledSinkCandidates?.count) parts.push(`unmodeled-sink-candidates=${meta.unmodeledSinkCandidates.count}`);
  return parts.join(' · ');
}
