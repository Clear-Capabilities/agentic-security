// Shipped Nix lexical and expression grammar data (NIX-001).
//
// This is the grammar asset nix-parser.js loads. It is plain data inside the
// package, so a default offline install parses Nix with no `nix` binary, no
// network and no optional native dependency.
//
// Provenance. The tables are original work, written from the public Nix
// language reference (lexical syntax, operator precedence table, string and
// indented-string escape rules). No third-party grammar source or generated
// parser table is copied in. The pinned checksum covers the canonical JSON of
// GRAMMAR_DATA: any edit, truncation or substitution makes loadNixGrammar
// return a `corrupt-grammar` gap instead of parsing with a different language
// definition.

import * as crypto from 'node:crypto';

export const GRAMMAR_DATA = Object.freeze({
  name: 'nix-lexical-expression',
  version: '1.0.0',
  languageReference: 'Nix language reference (expression syntax)',
  license: 'PolyForm-Internal-Use-1.0.0',
  origin: 'original; derived from the public Nix language reference, no third-party grammar code',
  keywords: Object.freeze(['if', 'then', 'else', 'assert', 'with', 'let', 'in', 'rec', 'inherit']),
  // Binary operators by binding strength (higher binds tighter) and associativity.
  binaryOps: Object.freeze({
    '++': Object.freeze({ prec: 12, assoc: 'right' }),
    '*': Object.freeze({ prec: 11, assoc: 'left' }),
    '/': Object.freeze({ prec: 11, assoc: 'left' }),
    '+': Object.freeze({ prec: 10, assoc: 'left' }),
    '-': Object.freeze({ prec: 10, assoc: 'left' }),
    '//': Object.freeze({ prec: 8, assoc: 'right' }),
    '<': Object.freeze({ prec: 7, assoc: 'none' }),
    '<=': Object.freeze({ prec: 7, assoc: 'none' }),
    '>': Object.freeze({ prec: 7, assoc: 'none' }),
    '>=': Object.freeze({ prec: 7, assoc: 'none' }),
    '==': Object.freeze({ prec: 6, assoc: 'none' }),
    '!=': Object.freeze({ prec: 6, assoc: 'none' }),
    '&&': Object.freeze({ prec: 5, assoc: 'left' }),
    '||': Object.freeze({ prec: 4, assoc: 'left' }),
    '->': Object.freeze({ prec: 3, assoc: 'right' }),
  }),
  // Binding strength of the unary and postfix forms between the binary levels.
  precedence: Object.freeze({ negate: 14, hasAttr: 13, not: 9 }),
  punctuation: Object.freeze([
    '...', '//', '++', '->', '==', '!=', '<=', '>=', '&&', '||', '${',
    '?', '@', ':', ';', ',', '.', '=', '{', '}', '[', ']', '(', ')', '+', '-', '*', '/', '<', '>', '!',
  ]),
  // Regular string escapes; any other `\x` yields x.
  stringEscapes: Object.freeze({ n: '\n', r: '\r', t: '\t' }),
  // Indented string escapes after `''\`; any other char yields itself.
  indentedEscapes: Object.freeze({ n: '\n', r: '\r', t: '\t' }),
  pathStart: '^(?:~|[A-Za-z0-9._+-]*)/(?![/*])(?=[A-Za-z0-9._+$-])',
  pathChars: '[A-Za-z0-9._+/~-]',
  searchPath: '^<[A-Za-z0-9._+-]+(?:/[A-Za-z0-9._+-]+)*>',
  uri: "^[A-Za-z][A-Za-z0-9+.-]*:[A-Za-z0-9%/?:@&=+$,\\-_.!~*']+",
  number: '^(?:[0-9]+\\.[0-9]*(?:[Ee][+-]?[0-9]+)?|\\.[0-9]+(?:[Ee][+-]?[0-9]+)?|[0-9]+(?:[Ee][+-]?[0-9]+)?)',
  identifier: "^[A-Za-z_][A-Za-z0-9_'-]*",
});

export const NIX_GRAMMAR_SHA256 = '464c3c4d5f6ae60479d873e3c40aa2d49c1e303fab6c120d6d440792a0e5aa42';

export function nixGrammarChecksum(data) {
  return crypto.createHash('sha256').update(JSON.stringify(data)).digest('hex');
}

const REQUIRED = ['keywords', 'binaryOps', 'punctuation', 'stringEscapes', 'indentedEscapes'];
const REQUIRED_STRINGS = ['pathStart', 'pathChars', 'searchPath', 'uri', 'number', 'identifier'];

/**
 * Loads and verifies the grammar. Never throws.
 * @param {{grammarSource?: (() => object|null|undefined)}} [opts] test/ops hook that
 *   substitutes the data source, so absent and corrupt installs can be exercised.
 * @returns {{available:boolean, grammar?:object, checksum?:string, gap?:{kind:string, detail:string}}}
 */
export function loadNixGrammar(opts = {}) {
  let data;
  try {
    data = typeof opts.grammarSource === 'function' ? opts.grammarSource() : GRAMMAR_DATA;
  } catch (err) {
    return { available: false, gap: { kind: 'missing-grammar', detail: `grammar could not be read: ${(err && err.message) || err}` } };
  }
  if (data === null || data === undefined) {
    return { available: false, gap: { kind: 'missing-grammar', detail: 'Nix grammar asset is absent' } };
  }
  let checksum;
  try { checksum = nixGrammarChecksum(data); } catch { checksum = null; }
  if (checksum !== NIX_GRAMMAR_SHA256) {
    return { available: false, gap: { kind: 'corrupt-grammar', detail: `Nix grammar checksum mismatch (got ${checksum || 'unhashable'})` } };
  }
  for (const k of REQUIRED) {
    if (data[k] === null || typeof data[k] !== 'object') return { available: false, gap: { kind: 'corrupt-grammar', detail: `Nix grammar is missing table "${k}"` } };
  }
  for (const k of REQUIRED_STRINGS) {
    if (typeof data[k] !== 'string') return { available: false, gap: { kind: 'corrupt-grammar', detail: `Nix grammar is missing pattern "${k}"` } };
  }
  return { available: true, grammar: data, checksum };
}
