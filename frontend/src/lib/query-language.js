// PRD §15.2's query language: a small DSL for filtering the Data Flow
// Explorer's views (e.g. `class:PCI AND sink:(log,database,external_api)`).
// This module is ONLY the tokenizer + recursive-descent parser, producing
// an AST — no evaluation, no UI. A later increment consumes the AST to
// actually filter a graph/view.
//
// Hand-written tokenizer, not regex-based single-pass lexing — the grammar
// has quoted strings (which must suppress internal `:`/`(`/`)`/`,`
// interpretation) and needs real position tracking for actionable error
// messages, both easier to get right with an explicit character-scanning
// loop.
//
// `parseQuery` NEVER throws to its caller, matching `state.js`'s own
// convention of never letting a malformed/adversarial user-supplied string
// (there, a URL hash; here, a query string) crash the caller — a bad query
// returns a structured `{error: {message, pos}}` instead, so a caller can
// check `.error` and keep the prior state rather than losing the page.

import { isAiRelevantFlow, flowPathNodeIds } from './flow-path.js';

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
        // A bare word followed by ':' or '!=' is a FIELD; otherwise it's a
        // TEXT-search VALUE (a later increment evaluates TEXT nodes; the
        // parser just needs to tell the two shapes apart here by lookahead).
        const nextNonSpace = input.slice(i).match(/^\s*(:|!=)/);
        tokens.push({ type: nextNonSpace ? 'FIELD' : 'VALUE', value: word, pos: start });
      }
      continue;
    }
    return { error: true, pos: i, message: `unexpected character "${c}"` };
  }
  return tokens;
}

// A standard recursive-descent parser: parseOr calls parseAnd repeatedly
// across OR tokens; parseAnd calls parseAtom repeatedly across explicit AND
// tokens; parseAtom handles `(expr)`, `field OP value-or-list`, and bare
// TEXT terms.
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

// AST -> predicate. `compileQuery(ast, graph) -> (flow) -> boolean`. The
// predicate operates on a FLOW (matching how filtering already works
// throughout this codebase — Privacy/Inventory both filter at the flow
// level), with field accessors reaching into the flow's own source/sink
// nodes, data element, and edges as needed.

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
