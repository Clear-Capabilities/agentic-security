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
} from './parser-py-cst.js';
import { parseJavaFile } from './parser-java.js';
import { parseGoFile } from './parser-go.js';
import { parsePhpFile } from './parser-php.js';
import { parseRubyFile } from './parser-rb.js';
import { parseCppFile, cppExtRe } from './parser-cpp.js';
import { buildCallGraph } from './callgraph.js';
import { buildClassHierarchy } from './class-hierarchy.js';
import { computeSSA, isSSAEnabled } from './ssa.js';

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
  if (choice === 'regex') return { parser: 'regex' };
  if (choice === 'cst') {
    const cap = probePythonAvailable();
    if (!cap.ok) {
      throw new Error(`AGENTIC_SECURITY_PY_PARSER=cst but Python is unavailable: ${cap.reason}`);
    }
    return { parser: 'cst' };
  }
  // auto: prefer cst when capability is present.
  const cap = probePythonAvailable();
  return { parser: cap.ok ? 'cst' : 'regex' };
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
    } catch { /* per-file parse failure: skip, don't abort the batch */ }
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
  const cg = buildCallGraph(perFile);
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
        } catch { /* skip */ }
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
    } catch { /* per-file parse failure: skip, don't abort the batch */ }
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
  const cg = buildCallGraph(perFile);
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

export { parseJsFile, parseJavaFile, parseCSharpFile, parseKotlinFile, parseGoFile, parsePhpFile, parseRubyFile, parseCppFile, buildCallGraph, buildClassHierarchy, computeSSA, isSSAEnabled, probePythonAvailable };
