# M3-UX, sub-project Query: implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development to implement this plan
> task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship PRD §15.2's query language, §15.3's 9 focus controls, two
real saved views, and basic text search — all as pure functions over the
real, already-populated graph fields the parent scoping doc's own audit
confirmed, wired into the existing view/selection/filter contract with
no new rendering paradigm.

**Architecture:** A hand-written tokenizer + recursive-descent parser
producing a small AST, a separate pure evaluator turning that AST into a
`(graph, node|edge|flow) -> boolean` predicate, and 9 pure graph-
traversal functions for focus controls — all in a new
`frontend/src/lib/query-language.js`. `lib/state.js` gains one new
`filters.query` string field. A new `components/query-bar.js` (thin
render, like every other component) wires it into the shell.

**Tech Stack:** Plain JS, zero build step, zero new dependency. `node
--test` + `test/dom-shim.js` for the render half.

**Spec:** `docs/superpowers/plans/2026-09-01-data-flow-explorer-m3-ux-scoping.md`
(read this first — the full per-dimension real-vs-inert data audit, and
why semantic zoom/6 filter dimensions/aliases are out of scope).

## Global Constraints

- `frontend/` only, no `scanner/` changes — every field this sub-project
  reads already exists and is populated by real scan code (confirmed in
  the scoping doc's own audit).
- No new dependency, no build step.
- **A malformed query must never silently broaden the visible graph** —
  PRD §15.2's own explicit requirement. On a parse error, the graph
  stays at its LAST valid filter state; the error is shown, not
  swallowed.
- **`node.aliases`/`dataElement.aliases` are confirmed ALWAYS empty in
  real scan output** (found during this plan's own final grounding pass,
  a real addition to the parent scoping doc's own audit — `node.aliases:
  []` and `dataElement.aliases: []` are both unconditional literals in
  `graph-builder.js`, never populated). §15.3's "Show alternate names/
  aliases" focus control is therefore implemented as a REAL function
  (reads `node.aliases`, correctly returns nothing extra today) rather
  than omitted — the function is honest and forward-compatible for when
  a future increment populates real aliases — but this is disclosed
  here and in the final docs update as another confirmed-inert PRD
  clause, not silently built as if it already does something.
- Every new test file added to `frontend/package.json`'s test script.

---

### Task 1: Query language tokenizer + parser (pure, produces an AST)

**Files:**
- Create: `frontend/src/lib/query-language.js`
- Test: `frontend/test/query-language.test.js` (new)

**Interfaces:**
- Produces: `tokenize(queryString) -> Token[]` where `Token = {type:
  'FIELD'|'VALUE'|'OP'|'AND'|'OR'|'LPAREN'|'RPAREN'|'COMMA'|'BANG_COLON',
  value: string, pos: number}`.
- Produces: `parseQuery(queryString) -> {ast: Node} | {error: {message:
  string, pos: number}}` — NEVER throws; a malformed query returns the
  `error` shape (Global Constraint above), so every caller can check
  `.error` and keep the prior state.
- AST node shapes: `{type: 'AND'|'OR', left, right}`,
  `{type: 'COMPARISON', field: string, op: ':'|'!=', values: string[]}`
  (a bare `field:value` is `values: ['value']`; `field:(a,b,c)` is
  `values: ['a','b','c']`, meaning "OR across these values" per §15.2's
  own examples), `{type: 'TEXT', value: string}` (a bare quoted/unquoted
  term with no `field:` prefix — basic search, Task 2).

- [ ] **Step 1: Write failing tokenizer tests**

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { tokenize, parseQuery } from '../src/lib/query-language.js';

test('tokenize: a simple field:value pair', () => {
  const tokens = tokenize('class:PCI');
  assert.deepEqual(tokens.map((t) => t.type), ['FIELD', 'VALUE']);
  assert.equal(tokens[0].value, 'class');
  assert.equal(tokens[1].value, 'PCI');
});

test('tokenize: AND/OR are recognized as keywords, case-insensitively', () => {
  const tokens = tokenize('class:PCI and sink:log OR class:PHI');
  assert.deepEqual(tokens.map((t) => t.type), ['FIELD', 'VALUE', 'AND', 'FIELD', 'VALUE', 'OR', 'FIELD', 'VALUE']);
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
```

- [ ] **Step 2: Implement `tokenize`**

```js
// Hand-written tokenizer for PRD §15.2's grammar. No regex-based
// single-pass lexing — the grammar has quoted strings (which must
// suppress internal `:`/`(`/`)`/`,` interpretation) and needs real
// position tracking for actionable error messages, both easier to get
// right with an explicit character-scanning loop.
const KEYWORDS = new Set(['and', 'or']);

export function tokenize(input) {
  const tokens = [];
  let i = 0;
  const isFieldChar = (c) => /[a-zA-Z0-9_.]/.test(c);

  while (i < input.length) {
    const c = input[i];
    if (c === ' ' || c === '\t' || c === '\n') { i++; continue; }
    if (c === '(') { tokens.push({ type: 'LPAREN', value: '(', pos: i }); i++; continue; }
    if (c === ')') { tokens.push({ type: 'RPAREN', value: ')', pos: i }); i++; continue; }
    if (c === ',') { tokens.push({ type: 'COMMA', value: ',', pos: i }); i++; continue; }
    if (c === '!' && input[i + 1] === '=') { tokens.push({ type: 'OP', value: '!=', pos: i }); i += 2; continue; }
    if (c === ':') { tokens.push({ type: 'OP', value: ':', pos: i }); i++; continue; }
    if (c === '"') {
      const start = i;
      i++;
      let value = '';
      while (i < input.length && input[i] !== '"') { value += input[i]; i++; }
      if (input[i] !== '"') return { error: true, pos: start, message: 'unterminated quoted string' };
      i++; // consume closing quote
      tokens.push({ type: 'VALUE', value, pos: start });
      continue;
    }
    if (isFieldChar(c)) {
      const start = i;
      let word = '';
      while (i < input.length && isFieldChar(input[i])) { word += input[i]; i++; }
      const lower = word.toLowerCase();
      if (lower === 'and') tokens.push({ type: 'AND', value: word, pos: start });
      else if (lower === 'or') tokens.push({ type: 'OR', value: word, pos: start });
      else {
        // A bare word followed by ':' is a FIELD; otherwise it's a
        // TEXT-search VALUE (Task 2 evaluates TEXT nodes; the parser
        // just needs to tell the two shapes apart here by lookahead).
        const nextNonSpace = input.slice(i).match(/^\s*(:|!=)/);
        tokens.push({ type: nextNonSpace ? 'FIELD' : 'VALUE', value: word, pos: start });
      }
      continue;
    }
    return { error: true, pos: i, message: `unexpected character "${c}"` };
  }
  return tokens;
}
```

- [ ] **Step 3: Run to verify Step 1's tests pass; handle the tokenizer's own error return**

Run: `cd frontend && node --test test/query-language.test.js`

Since `tokenize` can return `{error, pos, message}` instead of an array
on a malformed input (unterminated string, unexpected character), add:

```js
test('tokenize: an unterminated quoted string reports a real error, not a crash', () => {
  const result = tokenize('field:"unterminated');
  assert.ok(result.error);
  assert.equal(typeof result.pos, 'number');
});
```

- [ ] **Step 4: Write failing parser tests**

```js
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
```

- [ ] **Step 5: Implement `parseQuery`**

A standard recursive-descent parser: `parseOr` calls `parseAnd`
repeatedly across `OR` tokens; `parseAnd` calls `parseAtom` repeatedly
across (implicit or explicit) `AND` tokens/adjacency; `parseAtom`
handles `(expr)`, `field OP value-or-list`, and bare TEXT terms.

```js
export function parseQuery(input) {
  if (input.trim() === '') return { ast: null };
  const tokenResult = tokenize(input);
  if (!Array.isArray(tokenResult)) return { error: { message: tokenResult.message, pos: tokenResult.pos } };
  const tokens = tokenResult;
  let pos = 0;

  function peek() { return tokens[pos]; }
  function advance() { return tokens[pos++]; }
  function fail(message) {
    const t = peek();
    throw { message, pos: t ? t.pos : input.length };
  }

  function parseOr() {
    let node = parseAnd();
    while (peek()?.type === 'OR') {
      advance();
      node = { type: 'OR', left: node, right: parseAnd() };
    }
    return node;
  }

  function parseAnd() {
    let node = parseAtom();
    while (peek()?.type === 'AND') {
      advance();
      node = { type: 'AND', left: node, right: parseAtom() };
    }
    return node;
  }

  function parseAtom() {
    const t = peek();
    if (!t) fail('unexpected end of query');
    if (t.type === 'LPAREN') {
      advance();
      const inner = parseOr();
      if (peek()?.type !== 'RPAREN') fail('expected closing ")"');
      advance();
      return inner;
    }
    if (t.type === 'FIELD') {
      advance();
      const opToken = advance();
      if (!opToken || opToken.type !== 'OP') fail(`expected ":" or "!=" after field "${t.value}"`);
      const values = parseValueList();
      return { type: 'COMPARISON', field: t.value, op: opToken.value, values };
    }
    if (t.type === 'VALUE') {
      advance();
      return { type: 'TEXT', value: t.value };
    }
    fail(`unexpected token "${t.value}"`);
  }

  function parseValueList() {
    if (peek()?.type === 'LPAREN') {
      advance();
      const values = [];
      values.push(expectValue());
      while (peek()?.type === 'COMMA') { advance(); values.push(expectValue()); }
      if (peek()?.type !== 'RPAREN') fail('expected closing ")" in value list');
      advance();
      return values;
    }
    return [expectValue()];
  }

  function expectValue() {
    const t = peek();
    if (!t || t.type !== 'VALUE') fail('expected a value');
    advance();
    return t.value;
  }

  try {
    const ast = parseOr();
    if (pos < tokens.length) fail(`unexpected trailing token "${peek().value}"`);
    return { ast };
  } catch (e) {
    if (e && typeof e.message === 'string') return { error: e };
    throw e; // a genuine bug, not a user-facing parse error — do not swallow
  }
}
```

- [ ] **Step 6: Run full test file, commit**

Run: `cd frontend && node --test test/query-language.test.js`
Expected: PASS, all tests.

```bash
git add frontend/src/lib/query-language.js frontend/test/query-language.test.js
git commit -m "feat(frontend): query language tokenizer + recursive-descent parser (PRD §15.2)"
```

---

### Task 2: AST → predicate evaluator (field mapping)

**Files:**
- Modify: `frontend/src/lib/query-language.js` (add evaluator, same file)
- Test: `frontend/test/query-language.test.js` (extend)

**Interfaces:**
- Produces: `compileQuery(ast, graph) -> (flow) -> boolean` — the
  predicate operates on a FLOW (matching how filtering already works
  throughout this codebase — Privacy/Inventory both filter at the flow
  level), with field accessors reaching into the flow's own source/sink
  nodes, data element, and edges as needed. `ast === null` (empty query)
  compiles to `() => true` (matches everything).

- [ ] **Step 1: Write failing tests, grounded in the real flagship fixture**

```js
import { FLAGSHIP_GRAPH } from '../src/data/flagship-graph.js';
const FLOW_KEYS = FLAGSHIP_GRAPH.extensions.fixtureFlowKeys;

function flowByKey(key) { return FLAGSHIP_GRAPH.flows.find((f) => f.id === FLOW_KEYS[key]); }

test('compileQuery: class:PCI matches only PCI-classified flows', () => {
  const { ast } = parseQuery('class:PCI');
  const predicate = compileQuery(ast, FLAGSHIP_GRAPH);
  assert.ok(predicate(flowByKey('flow.pci.payment_api')));
  assert.ok(!predicate(flowByKey('flow.phi.ai')));
});

test('compileQuery: transit.verdict!=protected excludes protected-transit flows', () => {
  const { ast } = parseQuery('transit.verdict!=protected');
  const predicate = compileQuery(ast, FLAGSHIP_GRAPH);
  // Ground this against the REAL fixture's own real transit verdicts —
  // read flagship-graph.js's own edge data for flow.pci.payment_api
  // (confirmed elsewhere this session: its own edges are real and
  // include an unprotected transit hop) before asserting the exact
  // expected boolean; do not guess.
});

test('compileQuery: sink:(log,database,external_api) matches any of the listed sink categories', () => {
  const { ast } = parseQuery('sink:(log,database,external_api)');
  const predicate = compileQuery(ast, FLAGSHIP_GRAPH);
  assert.ok(predicate(flowByKey('flow.pci.raw_log')), 'flow.pci.raw_log ends at a log sink');
});

test('compileQuery: AND requires both sides', () => {
  const { ast } = parseQuery('class:PCI AND policy:permitted');
  const predicate = compileQuery(ast, FLAGSHIP_GRAPH);
  // Ground the expected result against flow.pci.payment_api's own real
  // policyVerdict in the fixture (read it first) before asserting.
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
  // Assert whichever is actually true against the real fixture — read
  // its real node coverageStatus values first, don't guess a boolean.
});

test('compileQuery: an unrecognized field name is a real, reported condition, never a silent always-false', () => {
  // Design decision for the implementer to resolve and document: does
  // compileQuery throw, or does parseQuery/a wrapping validator reject
  // unknown field names before compileQuery ever runs? Either is
  // acceptable IF it surfaces as a real, actionable error to the query
  // bar (Task 4) — a silent always-false predicate for a typo'd field
  // name would violate the "never silently broaden OR silently narrow
  // to nothing without saying why" spirit of §15.2's own requirement.
  // Write this test against whichever mechanism you implement.
});

test('compileQuery: an empty/null ast matches everything', () => {
  const predicate = compileQuery(null, FLAGSHIP_GRAPH);
  assert.ok(FLAGSHIP_GRAPH.flows.every(predicate));
});
```

Fill in the flagship-fixture-grounded assertions (`transit.verdict!=
protected`, `class:PCI AND policy:permitted`, `coverage:(...)`) by
reading the real fixture data first (`frontend/src/data/flagship-
graph.js`), the same discipline Golden's own sub-project established
this session for `golden-trace.test.js`'s real step count — never guess
what the fixture contains.

- [ ] **Step 2: Implement `compileQuery` and the field-mapping table**

```js
import { isAiRelevantFlow, flowPathNodeIds } from './flow-path.js';

// Field name -> accessor function: (graph, flow) -> string[] (the set of
// real values that field name means for THIS flow — a comparison
// matches if ANY of a COMPARISON's own `values` appears in this set).
// Grounded in the parent scoping doc's own real-vs-inert audit — every
// accessor here reads a field CONFIRMED populated by real scan code.
const FIELD_ACCESSORS = {
  class: (graph, flow) => {
    const de = graph.dataElements.find((d) => flow.dataElementIds.includes(d.id));
    return de?.dataClasses ?? [];
  },
  field: (graph, flow) => {
    const de = graph.dataElements.find((d) => flow.dataElementIds.includes(d.id));
    return de?.name ? [de.name] : [];
  },
  sink: (graph, flow) => {
    const sinkNode = graph.nodes.find((n) => n.id === flow.sink);
    return sinkNode?.subtype ? [sinkNode.subtype] : [];
  },
  source: (graph, flow) => {
    const sourceNode = graph.nodes.find((n) => n.id === flow.source);
    return sourceNode?.subtype ? [sourceNode.subtype] : [];
  },
  'transit.verdict': (graph, flow) => edgeVerdicts(graph, flow, 'transit'),
  'at_rest.verdict': (graph, flow) => edgeVerdicts(graph, flow, 'atRest'),
  'handling.verdict': (graph, flow) => edgeVerdicts(graph, flow, 'handling'),
  policy: (graph, flow) => (flow.policyVerdict ? [flow.policyVerdict] : []),
  coverage: (graph, flow) => {
    const pathNodeIds = flowPathNodeIds(graph, flow);
    return graph.nodes.filter((n) => pathNodeIds.has(n.id)).map((n) => n.coverageStatus);
  },
  ai: (graph, flow) => [String(isAiRelevantFlow(graph, flow))],
  'destination.external': (graph, flow) => {
    const pathNodeIds = flowPathNodeIds(graph, flow);
    const anyExternal = graph.nodes.some((n) => pathNodeIds.has(n.id) && n.externality?.value === 'external');
    return [String(anyExternal)];
  },
};

function edgeVerdicts(graph, flow, dimension) {
  return flow.edgeIds
    .map((id) => graph.edges.find((e) => e.id === id))
    .filter(Boolean)
    .map((e) => e.protection[dimension].verdict);
}

export function compileQuery(ast, graph) {
  if (ast === null || ast === undefined) return () => true;
  return (flow) => evaluateNode(ast, graph, flow);
}

function evaluateNode(node, graph, flow) {
  if (node.type === 'AND') return evaluateNode(node.left, graph, flow) && evaluateNode(node.right, graph, flow);
  if (node.type === 'OR') return evaluateNode(node.left, graph, flow) || evaluateNode(node.right, graph, flow);
  if (node.type === 'TEXT') return matchesText(graph, flow, node.value);
  if (node.type === 'COMPARISON') {
    const accessor = FIELD_ACCESSORS[node.field];
    if (!accessor) {
      // Real, reported condition (Step 1's own deliberately-open test) —
      // throwing here, caught by compileQuery's own caller (Task 4's
      // query bar), is the chosen mechanism: it surfaces as a real error
      // to the user rather than silently matching nothing. Document
      // this choice at the call site too.
      throw new Error(`unrecognized query field "${node.field}"`);
    }
    const realValues = accessor(graph, flow).map((v) => String(v).toLowerCase());
    const matches = node.values.some((v) => realValues.includes(v.toLowerCase()));
    return node.op === '!=' ? !matches : matches;
  }
  throw new Error(`unknown AST node type "${node.type}"`);
}

function matchesText(graph, flow, term) {
  const lower = term.toLowerCase();
  const sourceLabel = graph.nodes.find((n) => n.id === flow.source)?.label ?? '';
  const sinkLabel = graph.nodes.find((n) => n.id === flow.sink)?.label ?? '';
  const de = graph.dataElements.find((d) => flow.dataElementIds.includes(d.id));
  return [sourceLabel, sinkLabel, de?.name ?? ''].some((s) => s.toLowerCase().includes(lower));
}
```

- [ ] **Step 3: Run full test file, commit**

Run: `cd frontend && node --test test/query-language.test.js`
Expected: PASS, all tests including the flagship-fixture-grounded ones
you filled in against real data.

```bash
git add frontend/src/lib/query-language.js frontend/test/query-language.test.js
git commit -m "feat(frontend): query predicate evaluator over real, confirmed-populated graph fields"
```

---

### Task 3: Focus controls (9 pure graph-traversal functions)

**Files:**
- Create: `frontend/src/lib/focus-controls.js`
- Test: `frontend/test/focus-controls.test.js` (new)

**Interfaces:**
- Produces: 9 functions, each `(graph, selectedNodeId | {fromId, toId})
  -> {nodeIds: Set<string>, edgeIds: Set<string>}` — the SAME shape
  `architecture-view.js`'s own `resolveSelection` already returns for
  `selection`, so the render layer needs zero new consumption code:
  `showUpstream(graph, nodeId)`, `showDownstream(graph, nodeId)`,
  `showAllPaths(graph, nodeId)`, `showShortestPath(graph, fromId,
  toId)`, `showExternalPathsOnly(graph)`, `showUnprotectedPathsOnly(graph)`,
  `showAliases(graph, nodeId)` (disclosed-inert today, per Global
  Constraints), `showDisconnected(graph)`, `resetToOverview()` (returns
  the same empty selection shape `resolveSelection(graph, null)`
  already produces — reuse that function directly, don't reimplement).

- [ ] **Step 1: Write failing tests against the real flagship fixture**

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { FLAGSHIP_GRAPH } from '../src/data/flagship-graph.js';
import {
  showUpstream, showDownstream, showAllPaths, showShortestPath,
  showExternalPathsOnly, showUnprotectedPathsOnly, showAliases, showDisconnected,
} from '../src/lib/focus-controls.js';

const NODE_KEYS = FLAGSHIP_GRAPH.extensions.fixtureNodeKeys;

test('showDownstream: from Web App, includes every node reachable by following edges forward', () => {
  const result = showDownstream(FLAGSHIP_GRAPH, NODE_KEYS['node.web']);
  assert.ok(result.nodeIds.has(NODE_KEYS['node.web']));
  // Ground the exact expected downstream set against the real fixture's
  // own edges (read flagship-graph.js) before asserting further members
  // — Web App is the flagship's own real entry point, so its downstream
  // set should be large; confirm the real reachable set, don't guess it.
});

test('showUpstream: from a deep sink, includes only nodes that can reach it', () => {
  const result = showUpstream(FLAGSHIP_GRAPH, NODE_KEYS['node.postgres']);
  assert.ok(result.nodeIds.has(NODE_KEYS['node.postgres']));
  assert.ok(!result.nodeIds.has(NODE_KEYS['node.analytics']), 'a node with no path TO PostgreSQL must not appear in its upstream set — confirm this is real against the fixture\'s own topology first');
});

test('showAllPaths: is the union of showUpstream and showDownstream from the same node', () => {
  const nodeId = NODE_KEYS['node.payments'];
  const up = showUpstream(FLAGSHIP_GRAPH, nodeId);
  const down = showDownstream(FLAGSHIP_GRAPH, nodeId);
  const all = showAllPaths(FLAGSHIP_GRAPH, nodeId);
  for (const id of up.nodeIds) assert.ok(all.nodeIds.has(id));
  for (const id of down.nodeIds) assert.ok(all.nodeIds.has(id));
});

test('showShortestPath: between two connected nodes, returns a real, connected path (each edge in the result genuinely links two nodes in the result)', () => {
  const result = showShortestPath(FLAGSHIP_GRAPH, NODE_KEYS['node.web'], NODE_KEYS['node.postgres']);
  assert.ok(result.nodeIds.has(NODE_KEYS['node.web']));
  assert.ok(result.nodeIds.has(NODE_KEYS['node.postgres']));
  for (const edgeId of result.edgeIds) {
    const edge = FLAGSHIP_GRAPH.edges.find((e) => e.id === edgeId);
    assert.ok(result.nodeIds.has(edge.from) && result.nodeIds.has(edge.to), 'every edge in a shortest-path result must connect two nodes also in the result');
  }
});

test('showShortestPath: between two DISCONNECTED nodes, returns an empty (not crashing, not falsely-connected) result', () => {
  // Find or construct a real pair with no path between them in the
  // fixture (or use a small hand-built disconnected graph if the real
  // fixture is too densely connected to have one) — confirm behavior
  // against a genuine negative case, not just the positive one above.
});

test('showExternalPathsOnly: includes only nodes/edges on a path that touches an external node', () => {
  const result = showExternalPathsOnly(FLAGSHIP_GRAPH);
  assert.ok(result.nodeIds.has(NODE_KEYS['node.payment_api']), 'Payment API is external');
});

test('showUnprotectedPathsOnly: includes only edges whose worst verdict is unprotected or unknown', () => {
  const result = showUnprotectedPathsOnly(FLAGSHIP_GRAPH);
  // Ground against the real fixture's own edges with unprotected/unknown
  // verdicts (several exist, confirmed elsewhere this session) — assert
  // at least one real such edge is included, and confirm a real fully-
  // protected edge (if one exists in the fixture) is excluded.
});

test('showAliases: reads the real node.aliases field, honestly returns nothing extra today (confirmed always empty in real scan output)', () => {
  const result = showAliases(FLAGSHIP_GRAPH, NODE_KEYS['node.web']);
  assert.ok(result.nodeIds.has(NODE_KEYS['node.web']), 'the node itself is always included');
  // The flagship fixture's own aliases arrays are empty (confirmed this
  // session) — assert the function does NOT invent or crash on this,
  // it just returns the base node with no additional alias-linked nodes.
});

test('showDisconnected: returns nodes with zero edges — confirm against the real fixture whether any exist, don\'t assume', () => {
  const result = showDisconnected(FLAGSHIP_GRAPH);
  for (const id of result.nodeIds) {
    const hasAnyEdge = FLAGSHIP_GRAPH.edges.some((e) => e.from === id || e.to === id);
    assert.ok(!hasAnyEdge, `node ${id} was returned as disconnected but has a real edge`);
  }
});
```

Fill in every "ground against the real fixture" comment by actually
reading `frontend/src/data/flagship-graph.js`'s real node/edge data
first — this plan deliberately does not hand you the exact expected
sets, matching the "read real output before asserting" discipline this
session's own prior sub-projects (Golden, Inventory) already established
and consistently found real, useful corrections when followed.

- [ ] **Step 2: Implement all 9 functions**

```js
function buildAdjacency(graph) {
  const forward = new Map(); // nodeId -> [{edgeId, toId}]
  const backward = new Map(); // nodeId -> [{edgeId, fromId}]
  for (const n of graph.nodes) { forward.set(n.id, []); backward.set(n.id, []); }
  for (const e of graph.edges) {
    forward.get(e.from)?.push({ edgeId: e.id, toId: e.to });
    backward.get(e.to)?.push({ edgeId: e.id, fromId: e.from });
  }
  return { forward, backward };
}

function bfsDirection(graph, startId, adjacencyKey, adjacency) {
  const nodeIds = new Set([startId]);
  const edgeIds = new Set();
  const queue = [startId];
  while (queue.length > 0) {
    const current = queue.shift();
    for (const { edgeId, toId, fromId } of adjacency.get(current) ?? []) {
      const nextId = adjacencyKey === 'forward' ? toId : fromId;
      edgeIds.add(edgeId);
      if (!nodeIds.has(nextId)) { nodeIds.add(nextId); queue.push(nextId); }
    }
  }
  return { nodeIds, edgeIds };
}

export function showDownstream(graph, nodeId) {
  const { forward } = buildAdjacency(graph);
  return bfsDirection(graph, nodeId, 'forward', forward);
}

export function showUpstream(graph, nodeId) {
  const { backward } = buildAdjacency(graph);
  return bfsDirection(graph, nodeId, 'backward', backward);
}

export function showAllPaths(graph, nodeId) {
  const down = showDownstream(graph, nodeId);
  const up = showUpstream(graph, nodeId);
  return {
    nodeIds: new Set([...down.nodeIds, ...up.nodeIds]),
    edgeIds: new Set([...down.edgeIds, ...up.edgeIds]),
  };
}

export function showShortestPath(graph, fromId, toId) {
  const { forward } = buildAdjacency(graph);
  const cameFrom = new Map(); // nodeId -> {viaEdgeId, fromId}
  const visited = new Set([fromId]);
  const queue = [fromId];
  let found = false;
  while (queue.length > 0 && !found) {
    const current = queue.shift();
    for (const { edgeId, toId: nextId } of forward.get(current) ?? []) {
      if (visited.has(nextId)) continue;
      visited.add(nextId);
      cameFrom.set(nextId, { viaEdgeId: edgeId, fromId: current });
      if (nextId === toId) { found = true; break; }
      queue.push(nextId);
    }
  }
  if (!found) return { nodeIds: new Set(), edgeIds: new Set() };
  const nodeIds = new Set([toId]);
  const edgeIds = new Set();
  let cursor = toId;
  while (cursor !== fromId) {
    const step = cameFrom.get(cursor);
    edgeIds.add(step.viaEdgeId);
    nodeIds.add(step.fromId);
    cursor = step.fromId;
  }
  return { nodeIds, edgeIds };
}

export function showExternalPathsOnly(graph) {
  const externalNodeIds = new Set(graph.nodes.filter((n) => n.externality?.value === 'external').map((n) => n.id));
  const nodeIds = new Set();
  const edgeIds = new Set();
  for (const flow of graph.flows) {
    const pathNodeIds = new Set([flow.source, flow.sink]);
    for (const edgeId of flow.edgeIds) {
      const edge = graph.edges.find((e) => e.id === edgeId);
      if (edge) { pathNodeIds.add(edge.from); pathNodeIds.add(edge.to); }
    }
    if ([...pathNodeIds].some((id) => externalNodeIds.has(id))) {
      for (const id of pathNodeIds) nodeIds.add(id);
      for (const edgeId of flow.edgeIds) edgeIds.add(edgeId);
    }
  }
  return { nodeIds, edgeIds };
}

const UNPROTECTED_VERDICTS = new Set(['unprotected', 'mixed', 'unknown']);
export function showUnprotectedPathsOnly(graph) {
  const nodeIds = new Set();
  const edgeIds = new Set();
  for (const edge of graph.edges) {
    const verdicts = [edge.protection.transit.verdict, edge.protection.atRest.verdict, edge.protection.handling.verdict];
    if (verdicts.some((v) => UNPROTECTED_VERDICTS.has(v))) {
      edgeIds.add(edge.id);
      nodeIds.add(edge.from);
      nodeIds.add(edge.to);
    }
  }
  return { nodeIds, edgeIds };
}

export function showAliases(graph, nodeId) {
  const node = graph.nodes.find((n) => n.id === nodeId);
  const nodeIds = new Set([nodeId]);
  // Real, honest implementation: node.aliases is confirmed ALWAYS empty
  // in real scan output today (Global Constraints) — this correctly
  // returns just the base node until a future increment populates real
  // alias data, at which point this function needs no further change.
  for (const alias of node?.aliases ?? []) {
    const aliasNode = graph.nodes.find((n) => n.label === alias || n.id === alias);
    if (aliasNode) nodeIds.add(aliasNode.id);
  }
  return { nodeIds, edgeIds: new Set() };
}

export function showDisconnected(graph) {
  const connectedIds = new Set();
  for (const e of graph.edges) { connectedIds.add(e.from); connectedIds.add(e.to); }
  const nodeIds = new Set(graph.nodes.filter((n) => !connectedIds.has(n.id)).map((n) => n.id));
  return { nodeIds, edgeIds: new Set() };
}
```

(`resetToOverview` is not implemented here — Task 4 wires the existing
`resolveSelection(graph, null)` directly for that control, per this
task's own Interfaces note; do not duplicate it in this file.)

- [ ] **Step 3: Run full test file, commit**

Run: `cd frontend && node --test test/focus-controls.test.js`
Expected: PASS, all tests including every fixture-grounded one you
filled in against real data.

```bash
git add frontend/src/lib/focus-controls.js frontend/test/focus-controls.test.js
git commit -m "feat(frontend): 9 focus-control graph traversals (PRD §15.3)"
```

---

### Task 4: Wire into `state.js`/UI — query bar, saved views, focus-control menu

**Files:**
- Modify: `frontend/src/lib/state.js` (add `filters.query` field)
- Create: `frontend/src/components/query-bar.js`
- Modify: `frontend/src/app.js` (wire the new component in)
- Modify: `frontend/src/shell.js` (a real slot for the query bar — read
  its current header/tabs structure first, place it sensibly, e.g.
  alongside the view tabs row, matching this session's own A11y
  precedent of adding a new control into an existing shell row rather
  than a new region)
- Test: `frontend/test/state.test.js` (extend), `frontend/test/
  query-bar.test.js` (new)
- Create: `frontend/styles/query-bar.css`, wired into `index.html`

This task has real UI-placement latitude — read `shell.js`/`app.js`'s
CURRENT full content first (this plan was written against a snapshot
earlier in this session; both files have been touched by later
sub-projects since, re-verify before editing).

- [ ] **Step 1: Add `filters.query` to `lib/state.js`**

A plain string field alongside the existing `dataClass`/`protection`/
`ai`/`table` keys already in `state.filters`. No new top-level state
field — `query` is itself just one more key inside the existing
`filters` object, which already round-trips through the hash as JSON
(confirmed by reading `serializeStateToHash`/`parseStateFromHash`'s
existing `filters` handling). Add a test confirming a `query` string
round-trips through the hash correctly (mirroring an existing filters
round-trip test in `state.test.js` — read one and match its style).

- [ ] **Step 2: Build `components/query-bar.js`**

`computeQueryBarViewModel(state) -> {queryText: string, error: {message,
pos} | null}` (pure — parses `state.filters.query ?? ''` via `parseQuery`,
surfaces the error if any) and `renderQueryBar(viewModel, railEl,
onQueryChange)` (a text input + error message area, built via `el()`).
On a parse error, the input's own value still updates (so the user can
see/fix what they typed) but `onQueryChange` is NOT called with the
broken query — the caller (`app.js`) must not apply a filter change when
`compileQuery` would throw or the AST is an error shape, per this whole
sub-project's own "never silently broaden" requirement. Also render
the saved-view chips (`PCI Exposure`, `AI + Regulated Data` — the exact
query text for each, decided here, real and disclosed: `class:PCI` for
`PCI Exposure`; `class:(PII,PHI) AND ai:true` for `AI + Regulated Data`
— re-confirm these produce non-empty, sensible results against the real
flagship fixture before finalizing, adjust the exact query text if not).

- [ ] **Step 3: Wire into `app.js`**

Compute `compileQuery` from the current `state.filters.query` (parsed
once per `rerender()`, reusing the pattern every other compute step
already follows) and thread the resulting predicate into whichever
views' own filtering already exists (Privacy/Inventory's own
`rowMatchesFilters`-style functions) as an ADDITIONAL condition — a row/
flow must pass BOTH the existing dataClass/protection/ai filters AND the
new query predicate. Read `privacy-view.js`'s/`inventory-view.js`'s own
current filter-application code first to find the exact right insertion
point; do not duplicate their existing filtering logic.

- [ ] **Step 4: Wire focus controls into a real menu**

A small menu/button group (exact UI — dropdown vs. inline buttons —
implementer's own judgment, disclosed) offering the 9 named controls
when a node/flow is selected, calling the Task 3 functions and feeding
the result into `shellApi.setSelection`-equivalent state (the existing
`selectedId` mechanism doesn't directly carry a MULTI-node "focus" set
today — read `architecture-view.js`'s own `resolveSelection` again: it
already accepts a `flow`/`node`/`edge` id and computes a `{nodeIds,
edgeIds}` set FROM it. A focus control's own `{nodeIds, edgeIds}`
result needs a different consumption path than a single `selectedId` —
this is real, new design work: either (a) extend `computeArchitectureViewModel`
to accept an optional pre-computed selection override, bypassing
`resolveSelection`'s own single-id lookup, or (b) represent a focus
result as a synthetic flow-like id the existing mechanism already
understands. Pick one, implement it, and disclose the choice — this is
the single most architecturally consequential decision left open in
this task, on purpose, since it depends on details of `resolveSelection`'s
real current shape this plan's own author did not fully re-derive.

- [ ] **Step 5: Tests + full suite + commit**

Real, filled-in tests for `computeQueryBarViewModel`/`renderQueryBar`
(parse-error display, saved-view chip click applies the right query),
and at least one integration-level test confirming a query genuinely
narrows a real view's rendered rows against the flagship fixture (e.g.
Privacy View shows fewer rows with `class:PCI` applied than with no
query). Run `cd frontend && npm test` — PASS, real exit code. Add every
new test file to `package.json`.

```bash
git add frontend/src/lib/state.js frontend/src/components/query-bar.js frontend/src/app.js frontend/src/shell.js frontend/styles/query-bar.css frontend/index.html frontend/test/state.test.js frontend/test/query-bar.test.js frontend/package.json
git commit -m "feat(frontend): wire query bar, saved views, and focus controls into the shell"
```

---

### Task 5: Docs + scanner gate + final review

**Files:**
- Modify: `frontend/CLAUDE.md`
- Modify: `docs/superpowers/plans/2026-09-01-data-flow-explorer-m3-ux-scoping.md`

- [ ] **Step 1: Add a "Milestone 3, sub-project UX-Query" section to
  `frontend/CLAUDE.md`**, matching every prior sub-project's own voice:
  what's real (the parser, the 9 focus controls, saved views, basic
  search), what's honestly inert (the `showAliases` control, until real
  alias data exists), and the Task 4 architectural choice made for
  threading a multi-node focus result through the existing single-
  `selectedId` selection mechanism.
- [ ] **Step 2: Mark the M3-UX scoping doc's own Query row COMPLETE.**
- [ ] **Step 3: `cd frontend && npm test` and `cd scanner && npm test`**,
  both green, real captured exit codes.
- [ ] **Step 4: Commit.**

```bash
git add frontend/CLAUDE.md docs/superpowers/plans/2026-09-01-data-flow-explorer-m3-ux-scoping.md
git commit -m "docs(frontend): M3-UX Query sub-project complete"
```

## Final integration checklist (coordinator, after all 5 tasks)

- Re-read every changed file in full.
- `cd frontend && npm test` green, real captured exit code.
- `cd scanner && npm test` green, real captured exit code.
- Manually confirm (real browser, `agentic-security explore` or `npm run
  serve`) that typing `class:PCI` into the query bar genuinely narrows
  Privacy View's rows, that an intentionally malformed query
  (`class:PCI AND`) shows a real error and does NOT clear the filter,
  and that at least 2 of the 9 focus controls visibly change Architecture
  View's dimming when clicked.
