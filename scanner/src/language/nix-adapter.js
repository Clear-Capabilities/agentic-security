// Adapter that plugs the Nix parser and config IR into the language pipeline
// contracts (CORE-003), so parse outcomes reach scan health instead of staying
// inside the parser. A missing or corrupt grammar becomes `missing_grammar`, a
// deadline hit becomes `timed_out`, and syntax errors, dynamic attributes,
// dynamic imports, lazy recursion and IR/parser budget hits become `unresolved`
// outcomes. Findings from other languages are never touched.

import { isRegisteredLanguageProducer, registerLanguageProducer } from './contracts.js';
import { analyzeNix } from './nix-ir.js';
import { loadNixGrammar } from './nix-grammar.js';

export const NIX_PARSE_PRODUCER = 'language:nix-parse';

export function ensureNixParseProducer() {
  if (!isRegisteredLanguageProducer(NIX_PARSE_PRODUCER)) {
    registerLanguageProducer({ id: NIX_PARSE_PRODUCER, language: 'nix', capability: 'parse', evidenceKinds: ['source'], version: '1' });
  }
  return NIX_PARSE_PRODUCER;
}

/**
 * @param {{grammarSource?:Function, budgets?:object, irBudgets?:object, onParse?:(file:string, result:object)=>void}} [opts]
 */
export function createNixAdapter(opts = {}) {
  ensureNixParseProducer();
  return {
    id: NIX_PARSE_PRODUCER,
    language: 'nix',
    hasGrammar: () => loadNixGrammar({ grammarSource: opts.grammarSource }).available,
    analyze(file, content) {
      const result = analyzeNix(content, { file, grammarSource: opts.grammarSource, budgets: opts.budgets, irBudgets: opts.irBudgets });
      if (typeof opts.onParse === 'function') opts.onParse(file, result);
      const { parse, ir } = result;
      if (parse.status === 'budget_exceeded' && parse.budget && parse.budget.name === 'deadlineMs') {
        throw Object.assign(new Error(`Nix parser deadline exceeded for ${file}`), { code: 'LANG_TIMEOUT' });
      }
      if (parse.status === 'failed' && !parse.errors.length) throw new Error('Nix parse failed');
      const unresolved = ir.unresolved.map((u) => ({ line: u.span ? u.span.startLine : 1, reason: `${u.kind}: ${u.detail}` }));
      return { findings: [], unresolved, parse, ir };
    },
  };
}
