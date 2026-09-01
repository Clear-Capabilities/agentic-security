import { test } from 'node:test';
import assert from 'node:assert/strict';
import { tokenize, parseQuery } from '../src/lib/query-language.js';

test('tokenize: a simple field:value pair', () => {
  const tokens = tokenize('class:PCI');
  // The ':' is a real OP token (required by the parser, which unconditionally
  // expects an OP token between a FIELD and its value/value-list, and matches
  // the documented Token type union) — NOT absorbed silently into the FIELD
  // token. This assertion was fixed from the brief's original ['FIELD',
  // 'VALUE'] (no OP token), which contradicted the != test below, the
  // parser's own required OP lookup, and every parseQuery test that already
  // passed with an OP-emitting tokenizer.
  assert.deepEqual(tokens.map((t) => t.type), ['FIELD', 'OP', 'VALUE']);
  assert.equal(tokens[0].value, 'class');
  assert.equal(tokens[2].value, 'PCI');
});

test('tokenize: AND/OR are recognized as keywords, case-insensitively', () => {
  const tokens = tokenize('class:PCI and sink:log OR class:PHI');
  assert.deepEqual(
    tokens.map((t) => t.type),
    ['FIELD', 'OP', 'VALUE', 'AND', 'FIELD', 'OP', 'VALUE', 'OR', 'FIELD', 'OP', 'VALUE'],
  );
});

test('tokenize: parenthesized multi-value lists and quoted strings', () => {
  const tokens = tokenize('sink:(log,database,external_api) AND field:"card_number"');
  const types = tokens.map((t) => t.type);
  assert.ok(types.includes('LPAREN') && types.includes('RPAREN') && types.includes('COMMA'));
  const fieldValueToken = tokens.find((t) => t.value === 'card_number');
  assert.ok(fieldValueToken, 'a quoted value must tokenize to its unquoted content');
});

test('tokenize: != operator', () => {
  const tokens = tokenize('transit.verdict!=protected');
  assert.ok(tokens.some((t) => t.type === 'OP' && t.value === '!='));
});

test('tokenize: an unterminated quoted string reports a real error, not a crash', () => {
  const result = tokenize('field:"unterminated');
  assert.ok(result.error);
  assert.equal(typeof result.pos, 'number');
});

test('parseQuery: a single comparison', () => {
  const { ast, error } = parseQuery('class:PCI');
  assert.equal(error, undefined);
  assert.deepEqual(ast, { type: 'COMPARISON', field: 'class', op: ':', values: ['PCI'] });
});

test('parseQuery: AND binds tighter than OR (implicit precedence)', () => {
  const { ast } = parseQuery('class:PCI AND sink:log OR class:PHI');
  // Expected shape: OR(AND(class:PCI, sink:log), class:PHI) — AND groups
  // its operands before OR combines the result with the third clause,
  // matching every common query-language convention and the PRD's own
  // examples' implied grouping (never explicitly stated in the PRD text
  // itself — this is this plan's own, disclosed, defensible choice).
  assert.equal(ast.type, 'OR');
  assert.equal(ast.left.type, 'AND');
});

test('parseQuery: parenthesized multi-value list becomes an OR-across-values comparison', () => {
  const { ast } = parseQuery('sink:(log,database,external_api)');
  assert.deepEqual(ast, { type: 'COMPARISON', field: 'sink', op: ':', values: ['log', 'database', 'external_api'] });
});

test('parseQuery: explicit parentheses override precedence', () => {
  const { ast } = parseQuery('class:PCI AND (sink:log OR sink:database)');
  assert.equal(ast.type, 'AND');
  assert.equal(ast.right.type, 'OR');
});

test('parseQuery: != operator', () => {
  const { ast } = parseQuery('transit.verdict!=protected');
  assert.deepEqual(ast, { type: 'COMPARISON', field: 'transit.verdict', op: '!=', values: ['protected'] });
});

test('parseQuery: a bare unquoted/quoted term with no field: prefix is a TEXT node', () => {
  const { ast } = parseQuery('"card_number"');
  assert.deepEqual(ast, { type: 'TEXT', value: 'card_number' });
});

test('parseQuery: a malformed query returns a real, actionable error — never a partial/silent AST', () => {
  const { ast, error } = parseQuery('class:PCI AND');
  assert.equal(ast, undefined);
  assert.ok(error);
  assert.ok(error.message.length > 0);
  assert.equal(typeof error.pos, 'number');
});

test('parseQuery: unbalanced parentheses is a real error', () => {
  const { error } = parseQuery('(class:PCI AND sink:log');
  assert.ok(error);
});

test('parseQuery: an empty query string is valid and matches everything (no filter applied)', () => {
  const { ast, error } = parseQuery('');
  assert.equal(error, undefined);
  assert.equal(ast, null);
});
