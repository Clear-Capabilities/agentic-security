// IR entry point.
//
// Build per-file IR for every JS/TS/Python/Java file in a project, then
// build the cross-file call graph on top.

import { parseJsFile } from './parser-js.js';
import { parseCSharpFile } from './parser-cs.js';
import { parseKotlinFile } from './parser-kt.js';
import { parsePythonFile as parsePythonFileRegex } from './parser-py.js';
import {
  parsePythonFile as parsePythonFileCst,
  parsePythonFilesBatch as parsePythonFilesBatchCst,
  probePythonAvailable,
  noteParserDegradation,
  pythonParserDegradation,
  resetPythonParserDegradation,
} from './parser-py-cst.js';
import { parseJavaFile } from './parser-java.js';
import { parseGoFile } from './parser-go.js';
import { parsePhpFile } from './parser-php.js';
import { parseRubyFile } from './parser-rb.js';
import { parseCppFile, cppExtRe } from './parser-cpp.js';
import { buildCallGraph } from './callgraph.js';
import { buildClassHierarchy } from './class-hierarchy.js';
import { computeSSA, isSSAEnabled } from './ssa.js';

// ── per-file parse-failure observability ────────────────────────────────────
// Both dispatch loops below wrap every language's parser in a bare try/catch
// so one pathological file cannot abort IR construction for the whole project
// (the load-bearing case: a RangeError out of parser-cs.js on real Godot C#
// sources). Bare, that makes a SYSTEMATIC parser failure indistinguishable
// from "this language isn't present in the tree" — coverage just reads 0.
//
// So the failures are counted, and are printed on stderr when
// AGENTIC_SECURITY_IR_PARSE_DEBUG=1, following the precedent set by
// parser-py-cst.js's AGENTIC_SECURITY_PY_PARSER_DEBUG and
// sast/cpp-dataflow.js's `_parseErrorCount`. The counter is cumulative for
// the process and readable via `irParseFailures()`.
const _parseFailures = { count: 0, byLanguage: Object.create(null), firstError: null };

function _langOf(file) {
  const m = /\.([A-Za-z0-9+]+)$/.exec(String(file || ''));
  return m ? m[1].toLowerCase() : 'unknown';
}

// Exported under a `_`-prefixed name for tests: every parser in the tree is
// hardened enough that synthesising a real throw from outside is unreliable,
// so the counter/stderr behaviour is asserted directly against this helper
// (the two catch sites below are its only production callers).
export function _noteParseFailure(file, err) {
  const lang = _langOf(file);
  _parseFailures.count++;
  _parseFailures.byLanguage[lang] = (_parseFailures.byLanguage[lang] || 0) + 1;
  const msg = String((err && (err.message || err)) || 'unknown error');
  if (!_parseFailures.firstError) _parseFailures.firstError = { file, message: msg };
  if (process.env.AGENTIC_SECURITY_IR_PARSE_DEBUG === '1') {
    process.stderr.write(
      `[ir] parse failed (${lang}): ${file}: ${(err && err.name) || 'Error'}: ${msg.split('\n')[0]}\n`,
    );
  }
}

// Cumulative per-process view of files whose parser threw. Exported so a
// caller (bench harness, ir-stats sidecar, a future telemetry surface) can
// tell "no findings because the language is absent" apart from "no findings
// because every file of that language failed to parse".
export function irParseFailures() {
  return {
    count: _parseFailures.count,
    byLanguage: { ..._parseFailures.byLanguage },
    firstError: _parseFailures.firstError ? { ..._parseFailures.firstError } : null,
  };
}

// Test-only reset so a counter assertion doesn't inherit another test's state.
export function _resetIrParseFailures() {
  _parseFailures.count = 0;
  _parseFailures.byLanguage = Object.create(null);
  _parseFailures.firstError = null;
}

// Pick the Python parser based on env + capability probe.
//   AGENTIC_SECURITY_PY_PARSER=cst   — force AST parser; error if unavailable
//   AGENTIC_SECURITY_PY_PARSER=regex — force the legacy regex parser
//   AGENTIC_SECURITY_PY_PARSER=auto (default) — try CST, fall back silently
//
// The default is `auto` for one minor release so we can validate the CST
// path in real-world deployments without regressing customers who don't
// have python3 on PATH. Flip the default to `cst` once the equivalence
// corpus has run clean for two consecutive releases.
function _chooseParser() {
  const choice = (process.env.AGENTIC_SECURITY_PY_PARSER || 'auto').toLowerCase();
  // Explicitly forced regex is still a loss of `fn.calls` (no interprocedural
  // Python taint). Record it so a caller that REQUIRES the CST path — the
  // CVE-replay corpus gate — reports an environment error instead of scoring
  // the resulting miss as a detection regression.
  if (choice === 'regex') { noteParserDegradation('forced-regex-parser'); return { parser: 'regex' }; }
  if (choice === 'cst') {
    const cap = probePythonAvailable();
    if (!cap.ok) {
      throw new Error(`AGENTIC_SECURITY_PY_PARSER=cst but Python is unavailable: ${cap.reason}`);
    }
    return { parser: 'cst' };
  }
  // auto: prefer cst when capability is present. A regex selection here is a
  // DEGRADATION, not a neutral choice — the regex parser emits no `fn.calls`,
  // so Python loses interprocedural taint for this run. Record it so callers
  // that require the CST path (the CVE-replay corpus gate) can distinguish an
  // environment failure from a detection regression.
  const cap = probePythonAvailable();
  if (!cap.ok) { noteParserDegradation(`python-unavailable:${cap.reason}`); return { parser: 'regex' }; }
  return { parser: 'cst' };
}

function _parsePythonFiles(pyEntries) {
  // pyEntries: [{ file, content }, ...]
  const choice = _chooseParser();
  if (choice.parser === 'cst') {
    const batch = parsePythonFilesBatchCst(pyEntries);
    if (batch !== null) return batch;
    // Silent fall-through to regex when the CST path failed mid-run (e.g.
    // helper crashed). Operators see this in stderr when debugging is on.
    if (process.env.AGENTIC_SECURITY_PY_PARSER_DEBUG === '1') {
      process.stderr.write('parser-py-cst: batch failed; falling back to regex parser\n');
    }
    noteParserDegradation('batch-fallback-to-regex');
  }
  // Regex per-file parse — matches the old behavior exactly.
  return pyEntries.map(({ file, content }) => parsePythonFileRegex(file, content)).filter(Boolean);
}

// Synchronous default — JS/TS + Python only. Engine.js calls this directly.
// Java IR requires async import of java-parser; callers who want it can use
// buildProjectIRAsync instead.
export function buildProjectIR(fileContents) {
  const perFile = {};
  const pyBatch = [];
  for (const [file, code] of Object.entries(fileContents || {})) {
    // Each branch is wrapped so one pathological file (e.g. a deeply nested
    // expression tree that blows the regex-parser's recursive descent, seen
    // in practice on real-world C# under Godot's proof-corpus run) can never
    // abort IR construction for the entire project. A single parser failure
    // degrades to "unparsed" for that file, exactly like a parser returning
    // null — it does not zero out every other language's coverage.
    try {
      if (/\.(?:js|jsx|ts|tsx|mjs|cjs)$/i.test(file)) {
        const ir = parseJsFile(file, code);
        if (ir) perFile[file] = ir;
      } else if (/\.py$/i.test(file)) {
        // Defer Python files to a single batched subprocess call.
        pyBatch.push({ file, content: code });
      } else if (/\.cs$/i.test(file)) {
        const ir = parseCSharpFile(file, code);
        if (ir) perFile[file] = ir;
      } else if (/\.kt$/i.test(file)) {
        const ir = parseKotlinFile(file, code);
        if (ir) perFile[file] = ir;
      } else if (/\.go$/i.test(file)) {
        const ir = parseGoFile(file, code);
        if (ir) perFile[file] = ir;
      } else if (/\.(?:php|phtml)$/i.test(file)) {
        const ir = parsePhpFile(file, code);
        if (ir) perFile[file] = ir;
      } else if (/\.rb$/i.test(file)) {
        const ir = parseRubyFile(file, code);
        if (ir) perFile[file] = ir;
      } else if (cppExtRe().test(file)) {
        const ir = parseCppFile(file, code);
        if (ir) perFile[file] = ir;
      }
    } catch (err) { _noteParseFailure(file, err); /* skip this file; never abort the batch */ }
  }
  if (pyBatch.length) {
    for (const ir of _parsePythonFiles(pyBatch)) {
      if (ir && ir.file) perFile[ir.file] = ir;
    }
  }
  if (isSSAEnabled()) {
    for (const ir of Object.values(perFile)) {
      for (const fn of (ir.functions || [])) {
        try { computeSSA(fn.cfg); } catch {}
      }
    }
  }
  // PRD R7 (docs/DETECTION_GAP_REMEDIATION_PRD.md): buildCallGraph's
  // re-export map (aliased `export {x as y} from './z'`, CJS
  // `module.exports = require('./z')`) only populates when fileContents is
  // passed — without it, a call to an aliased re-export can never resolve
  // (no function is literally named the alias anywhere), a dropped edge,
  // not just an imprecise one.
  const cg = buildCallGraph(perFile, fileContents);
  const cha = buildClassHierarchy(perFile);
  return { perFile, callGraph: cg, cha };
}

// Async variant — includes Java IR via java-parser.
export async function buildProjectIRAsync(fileContents) {
  const perFile = {};
  const pyBatch = [];
  for (const [file, code] of Object.entries(fileContents || {})) {
    // See buildProjectIR's comment: per-file try/catch so one pathological
    // file can't abort IR construction for the whole project.
    try {
      if (/\.(?:js|jsx|ts|tsx|mjs|cjs)$/i.test(file)) {
        const ir = parseJsFile(file, code);
        if (ir) perFile[file] = ir;
      } else if (/\.py$/i.test(file)) {
        pyBatch.push({ file, content: code });
      } else if (/\.cs$/i.test(file)) {
        const ir = parseCSharpFile(file, code);
        if (ir) perFile[file] = ir;
      } else if (/\.kt$/i.test(file)) {
        const ir = parseKotlinFile(file, code);
        if (ir) perFile[file] = ir;
      } else if (/\.java$/i.test(file)) {
        try {
          const ir = await parseJavaFile(file, code);
          if (ir) perFile[file] = ir;
        } catch (err) { _noteParseFailure(file, err); }
      } else if (/\.go$/i.test(file)) {
        const ir = parseGoFile(file, code);
        if (ir) perFile[file] = ir;
      } else if (/\.(?:php|phtml)$/i.test(file)) {
        const ir = parsePhpFile(file, code);
        if (ir) perFile[file] = ir;
      } else if (/\.rb$/i.test(file)) {
        const ir = parseRubyFile(file, code);
        if (ir) perFile[file] = ir;
      } else if (cppExtRe().test(file)) {
        const ir = parseCppFile(file, code);
        if (ir) perFile[file] = ir;
      }
    } catch (err) { _noteParseFailure(file, err); /* skip this file; never abort the batch */ }
  }
  if (pyBatch.length) {
    for (const ir of _parsePythonFiles(pyBatch)) {
      if (ir && ir.file) perFile[ir.file] = ir;
    }
  }
  if (isSSAEnabled()) {
    for (const ir of Object.values(perFile)) {
      for (const fn of (ir.functions || [])) {
        try { computeSSA(fn.cfg); } catch {}
      }
    }
  }
  // PRD R7 (docs/DETECTION_GAP_REMEDIATION_PRD.md): buildCallGraph's
  // re-export map (aliased `export {x as y} from './z'`, CJS
  // `module.exports = require('./z')`) only populates when fileContents is
  // passed — without it, a call to an aliased re-export can never resolve
  // (no function is literally named the alias anywhere), a dropped edge,
  // not just an imprecise one.
  const cg = buildCallGraph(perFile, fileContents);
  const cha = buildClassHierarchy(perFile);
  return { perFile, callGraph: cg, cha };
}

// `parsePythonFile` is the single-file shim. We re-export the dispatcher
// so existing imports (e.g. tests that import { parsePythonFile } from
// './ir/index.js') keep working. The dispatcher routes to CST or regex
// according to the same rules as the batch path.
export function parsePythonFile(file, code) {
  if (!file || typeof code !== 'string') return null;
  const choice = _chooseParser();
  if (choice.parser === 'cst') {
    const r = parsePythonFileCst(file, code);
    if (r) return r;
  }
  return parsePythonFileRegex(file, code);
}

export { parseJsFile, parseJavaFile, parseCSharpFile, parseKotlinFile, parseGoFile, parsePhpFile, parseRubyFile, parseCppFile, buildCallGraph, buildClassHierarchy, computeSSA, isSSAEnabled, probePythonAvailable, pythonParserDegradation, resetPythonParserDegradation };
