import { test } from 'node:test';
import assert from 'node:assert/strict';
import { tokenize, parseQuery, compileQuery } from '../src/lib/query-language.js';
import { FLAGSHIP_GRAPH } from '../src/data/flagship-graph.js';

const FLOW_KEYS = FLAGSHIP_GRAPH.extensions.fixtureFlowKeys;

function flowByKey(key) { return FLAGSHIP_GRAPH.flows.find((f) => f.id === FLOW_KEYS[key]); }

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

test('compileQuery: class:PCI matches only PCI-classified flows', () => {
  const { ast } = parseQuery('class:PCI');
  const predicate = compileQuery(ast, FLAGSHIP_GRAPH);
  assert.ok(predicate(flowByKey('flow.pci.payment_api')));
  assert.ok(!predicate(flowByKey('flow.phi.ai')));
});

test('compileQuery: transit.verdict!=protected excludes protected-transit flows', () => {
  const { ast } = parseQuery('transit.verdict!=protected');
  const predicate = compileQuery(ast, FLAGSHIP_GRAPH);
  // Read against the real fixture (frontend/src/data/flagship-graph.js):
  // flow.pci.payment_api's own edges are edge:54d5b1db3415 (transit
  // verdict "not_assessed") and edge:b397f3640150 (transit verdict
  // "unprotected") — neither is "protected", so this flow is correctly
  // included by "!=protected".
  assert.ok(predicate(flowByKey('flow.pci.payment_api')));
  // Real, disclosed finding from reading every edge in the fixture: NOT A
  // SINGLE edge anywhere in the flagship fixture has a transit verdict of
  // "protected" (transit is only ever "not_assessed" or "unprotected" —
  // only the HANDLING dimension has a "protected" verdict anywhere, on
  // edge:d613505336aa, the maskCard() edge). So "transit.verdict!=protected"
  // is honestly a match-everything query against this specific fixture —
  // confirmed here rather than assumed, exactly as the brief asks.
  assert.ok(FLAGSHIP_GRAPH.flows.every(predicate), 'no flow in the fixture has a protected transit edge');
});

test('compileQuery: sink:(...) matches on the sink node\'s real subtype, NOT the PRD\'s illustrative SINK_CATEGORIES vocabulary (real, disclosed mismatch)', () => {
  // Real finding from running this against the fixture: the `sink`
  // accessor (Step 2's own reference implementation) reads the sink
  // node's `subtype` field verbatim — for flow.pci.raw_log's sink
  // (node:log:608492464d54) that is "application-logs", not the coarser
  // "log" category PRD §15.2's own illustrative example
  // (`sink:(log,database,external_api)`) implies. "log" is not an exact
  // match for "application-logs" via this accessor's exact-value
  // comparison, so the PRD's own literal example query does NOT match
  // this flow against the real fixture — confirmed by running it, not
  // assumed:
  const { ast: prdAst } = parseQuery('sink:(log,database,external_api)');
  const prdPredicate = compileQuery(prdAst, FLAGSHIP_GRAPH);
  assert.ok(
    !prdPredicate(flowByKey('flow.pci.raw_log')),
    'sink accessor matches node.subtype exactly ("application-logs"), never the coarser SINK_CATEGORIES vocabulary the PRD\'s own example implies — a real, disclosed mismatch for a future increment to reconcile',
  );
  // The real, correct way to match this fixture's sink today is by its
  // actual subtype value (quoted, since bare unquoted VALUE tokens can't
  // contain '-' per tokenize()'s own isFieldChar):
  const { ast } = parseQuery('sink:("application-logs","postgres-table","payment-api")');
  const predicate = compileQuery(ast, FLAGSHIP_GRAPH);
  assert.ok(predicate(flowByKey('flow.pci.raw_log')), 'flow.pci.raw_log\'s real sink subtype is "application-logs"');
});

test('compileQuery: AND requires both sides', () => {
  const { ast } = parseQuery('class:PCI AND policy:permitted');
  const predicate = compileQuery(ast, FLAGSHIP_GRAPH);
  // Read against the real fixture: flow.pci.payment_api's own policyVerdict
  // is "not_evaluated", never "permitted" — in fact grepping every flow in
  // the fixture, no flow's policyVerdict is ever "permitted" (only
  // "not_evaluated" or "manual_review_required" occur). So the AND is
  // correctly false for the only real PCI flow with an external sink.
  assert.ok(!predicate(flowByKey('flow.pci.payment_api')));
  assert.ok(FLAGSHIP_GRAPH.flows.every((f) => !predicate(f)), 'no flow in the fixture has policyVerdict "permitted"');
});

test('compileQuery: ai:true uses TOPOLOGY-based AI relevance, never dataElement.aiContexts (confirmed always empty)', () => {
  const { ast } = parseQuery('ai:true');
  const predicate = compileQuery(ast, FLAGSHIP_GRAPH);
  assert.ok(predicate(flowByKey('flow.pci.ai')), 'flow.pci.ai touches an AI-subtype node topologically');
});

test('compileQuery: field:"card_number" matches the exact data element name', () => {
  const { ast } = parseQuery('field:"card_number"');
  const predicate = compileQuery(ast, FLAGSHIP_GRAPH);
  assert.ok(predicate(flowByKey('flow.pci.payment_api')));
  assert.ok(!predicate(flowByKey('flow.phi.ai')));
});

test('compileQuery: destination.external:true matches flows whose path touches an external node', () => {
  const { ast } = parseQuery('destination.external:true');
  const predicate = compileQuery(ast, FLAGSHIP_GRAPH);
  assert.ok(predicate(flowByKey('flow.pci.payment_api')), 'Payment API is external');
});

test('compileQuery: coverage:(partial,unsupported,unknown) — ground against the real fixture, no unresolved-coverage flow may exist, so confirm the honest empty-match case rather than assuming', () => {
  const { ast } = parseQuery('coverage:(partial,unsupported,unknown)');
  const predicate = compileQuery(ast, FLAGSHIP_GRAPH);
  const anyMatch = FLAGSHIP_GRAPH.flows.some(predicate);
  // Read against the real fixture: every single node's coverageStatus is
  // "modeled" (confirmed by reading every node in flagship-graph.js) — none
  // is "partial"/"unsupported"/"unknown". So the honest, correct answer is
  // that this query matches nothing in the current fixture.
  assert.equal(anyMatch, false, 'every node in the fixture has coverageStatus "modeled"; none of partial/unsupported/unknown occurs');
});

test('compileQuery: an unrecognized field name is a real, reported condition, never a silent always-false', () => {
  // Design decision made in Step 2's reference implementation: compileQuery
  // does NOT throw at compile time (parseQuery has no field-name knowledge
  // and never validates field names either) — the returned PREDICATE
  // function throws when it is actually invoked against a flow and hits an
  // unrecognized field name. This is a real, actionable error rather than a
  // silent always-false predicate for a typo'd field name. A future query
  // bar (Task 4, not this task) must catch this thrown error and surface it
  // to the user rather than letting it propagate as an unhandled exception.
  const { ast } = parseQuery('nonexistent_field:foo');
  const predicate = compileQuery(ast, FLAGSHIP_GRAPH);
  assert.throws(() => predicate(FLAGSHIP_GRAPH.flows[0]), /unrecognized query field/);
});

test('compileQuery: an empty/null ast matches everything', () => {
  const predicate = compileQuery(null, FLAGSHIP_GRAPH);
  assert.ok(FLAGSHIP_GRAPH.flows.every(predicate));
});
