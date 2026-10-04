// Shipped Haskell lexical/layout grammar data (HS-001).
//
// This is the grammar asset the parser in haskell-parser.js loads. It is plain
// data inside the package, so a default offline install parses Haskell with no
// GHC, no cabal, no network and no optional dependency.
//
// Provenance. The tables below are original work, written from the public
// Haskell 2010 Report lexical syntax (chapter 2) and layout rule (section 10.3)
// plus the documented GHC extension keywords. No third-party grammar source or
// generated parser table is copied in, so there is no upstream licence to carry
// beyond this project's own. The pinned checksum covers the canonical JSON of
// GRAMMAR_DATA: any edit, truncation or substitution fails loadHaskellGrammar
// with a `corrupt-grammar` gap instead of parsing with a different language
// definition.

import * as crypto from 'node:crypto';

export const GRAMMAR_DATA = Object.freeze({
  name: 'haskell-lexical-layout',
  version: '1.0.0',
  languageReport: 'Haskell 2010',
  license: 'PolyForm-Internal-Use-1.0.0',
  origin: 'original; derived from the public Haskell 2010 Report and GHC user guide, no third-party grammar code',
  keywords: Object.freeze([
    'case', 'class', 'data', 'default', 'deriving', 'do', 'else', 'foreign', 'if', 'import', 'in',
    'infix', 'infixl', 'infixr', 'instance', 'let', 'module', 'newtype', 'of', 'then', 'type',
    'where', 'mdo',
  ]),
  reservedOps: Object.freeze(['..', ':', '::', '=', '\\', '|', '<-', '->', '@', '~', '=>']),
  layoutKeywords: Object.freeze(['where', 'let', 'do', 'of', 'mdo']),
  symbolChars: '!#$%&*+./<=>?@\\^|-~:',
  declarationKeywords: Object.freeze([
    'import', 'data', 'newtype', 'type', 'class', 'instance', 'deriving', 'default', 'foreign',
    'infix', 'infixl', 'infixr', 'module',
  ]),
  cppDirectives: Object.freeze([
    'if', 'ifdef', 'ifndef', 'else', 'elif', 'endif', 'define', 'undef', 'include', 'error',
    'warning', 'line', 'pragma',
  ]),
  // Operators that feed a value to the function on their right, so that function
  // is applied even without a visible argument.
  forwardingOps: Object.freeze(['&', '>>=', '>>', '=<<', '<&>', '>=>', '<=<']),
});

export const HASKELL_GRAMMAR_SHA256 = '26a6650e48976accacd0bbd5246e306a84e25be63b4e52a5876938316355e05d';

export function grammarChecksum(data) {
  return crypto.createHash('sha256').update(JSON.stringify(data)).digest('hex');
}

const REQUIRED_LISTS = ['keywords', 'reservedOps', 'layoutKeywords', 'declarationKeywords', 'cppDirectives', 'forwardingOps'];

/**
 * Loads and verifies the grammar. Never throws.
 * @param {{grammarSource?: (() => object|null|undefined)}} [opts] test/ops hook that
 *   substitutes the data source, so absent and corrupt installs can be exercised.
 * @returns {{available:boolean, grammar?:object, checksum?:string, gap?:{kind:string, detail:string}}}
 */
export function loadHaskellGrammar(opts = {}) {
  let data;
  try {
    data = typeof opts.grammarSource === 'function' ? opts.grammarSource() : GRAMMAR_DATA;
  } catch (err) {
    return { available: false, gap: { kind: 'missing-grammar', detail: `grammar could not be read: ${(err && err.message) || err}` } };
  }
  if (data === null || data === undefined) {
    return { available: false, gap: { kind: 'missing-grammar', detail: 'Haskell grammar asset is absent' } };
  }
  let checksum;
  try { checksum = grammarChecksum(data); } catch { checksum = null; }
  if (checksum !== HASKELL_GRAMMAR_SHA256) {
    return { available: false, gap: { kind: 'corrupt-grammar', detail: `Haskell grammar checksum mismatch (got ${checksum || 'unhashable'})` } };
  }
  for (const k of REQUIRED_LISTS) {
    if (!Array.isArray(data[k])) return { available: false, gap: { kind: 'corrupt-grammar', detail: `Haskell grammar is missing table "${k}"` } };
  }
  return { available: true, grammar: data, checksum };
}
