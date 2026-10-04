// Adapter that plugs the Haskell parser into the language pipeline contracts
// (CORE-003), so parse outcomes reach scan health instead of staying inside the
// parser. A missing or corrupt grammar becomes `missing_grammar`, a budget bound
// becomes `timed_out` (deadline) or `unresolved` (size/depth), and syntax errors
// and opaque boundaries become `unresolved-branch` outcomes. Findings from other
// languages are never touched.

import { isRegisteredLanguageProducer, registerLanguageProducer } from './contracts.js';
import { parseHaskell } from './haskell-parser.js';
import { loadHaskellGrammar } from './haskell-grammar.js';

export const HASKELL_PARSE_PRODUCER = 'language:haskell-parse';

// Boundaries whose content the parser could not see. cpp and ffi are disclosed on
// the parse result but do not make the file unresolved: both CPP branches are
// parsed and a foreign declaration's own Haskell signature is.
const OPAQUE_BOUNDARIES = new Set(['th-splice', 'th-quote', 'th-name-quote', 'th-top-level-splice', 'quasiquote', 'hsc', 'generated']);

export function ensureHaskellParseProducer() {
  if (!isRegisteredLanguageProducer(HASKELL_PARSE_PRODUCER)) {
    registerLanguageProducer({ id: HASKELL_PARSE_PRODUCER, language: 'haskell', capability: 'parse', evidenceKinds: ['source'], version: '1' });
  }
  return HASKELL_PARSE_PRODUCER;
}

/**
 * @param {{grammarSource?:Function, budgets?:object, mode?:string, onParse?:(file:string, parse:object)=>void}} [opts]
 */
export function createHaskellAdapter(opts = {}) {
  ensureHaskellParseProducer();
  return {
    id: HASKELL_PARSE_PRODUCER,
    language: 'haskell',
    hasGrammar: () => loadHaskellGrammar({ grammarSource: opts.grammarSource }).available,
    analyze(file, content) {
      const parse = parseHaskell(content, { file, grammarSource: opts.grammarSource, budgets: opts.budgets, mode: opts.mode });
      if (typeof opts.onParse === 'function') opts.onParse(file, parse);
      if (parse.status === 'budget_exceeded' && parse.budget && parse.budget.name === 'deadlineMs') {
        throw Object.assign(new Error(`Haskell parser deadline exceeded for ${file}`), { code: 'LANG_TIMEOUT' });
      }
      const unresolved = [];
      if (parse.status === 'budget_exceeded') unresolved.push({ line: 1, reason: `parser budget exceeded: ${parse.budget.name}` });
      else if (parse.status === 'failed') throw new Error(parse.errors[0] ? parse.errors[0].detail : 'Haskell parse failed');
      else {
        for (const e of parse.errors) unresolved.push({ line: e.span ? e.span.startLine : 1, reason: `syntax-error: ${e.kind}` });
        for (const b of parse.boundaries) if (OPAQUE_BOUNDARIES.has(b.kind)) unresolved.push({ line: b.span.startLine, reason: `opaque-boundary: ${b.kind}` });
      }
      return { findings: [], unresolved, parse };
    },
  };
}
