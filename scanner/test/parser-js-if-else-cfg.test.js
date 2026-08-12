// Stage 3 correctness audit (detection depth): the if/else CFG-linking bug.
//
// parser-js.js models an `if` as a condition node followed by a "join" noop
// that both branches converge on. Babel visits an IfStatement's `consequent`
// then its `alternate` as ordinary children of the same enter/exit pair, with
// no boundary hook between them — so fn._cursor (the "most recently emitted
// node" pointer used as the predecessor for the next addNode() call) was
// never reset before the alternate was traversed. The alternate's first node
// ended up linked as a successor of the CONSEQUENT's tail rather than a
// second branch off the condition node itself. Two concrete consequences:
//   1. The `if` node kept only ONE outgoing edge (into the consequent),
//      never the "false" edge into the alternate — applyPathFeasibility's
//      constant-condition pruning treats a single-edge `if` as unconditional,
//      so a real vulnerability behind an else-branch can be pruned away.
//   2. The alternate's entry state was reachable only "after" the
//      consequent executed, corrupting any taint-state reasoning that
//      depends on the branches being mutually exclusive alternatives rather
//      than sequential code.
//
// These are pure IR-shape tests — no taint engine needed — so the CFG's
// edges are asserted directly against buildProjectIR's output.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildProjectIR } from '../src/ir/index.js';

function cfgOf(code, fnName = 'h') {
  const { perFile } = buildProjectIR({ 'a.js': code });
  const fn = perFile['a.js'].functions.find(f => f.name === fnName);
  assert.ok(fn, `expected a function named ${fnName}`);
  return fn.cfg.nodes;
}

test('an if/else condition node has two outgoing edges, one into each branch', () => {
  const nodes = cfgOf(`
    function h(req, db) {
      if (req.query.flag) {
        db.query('SELECT 1');
      } else {
        db.query('SELECT * FROM users WHERE id = ' + req.query.id);
      }
    }
  `);
  const ifNode = Object.values(nodes).find(n => n.kind === 'if');
  assert.ok(ifNode, 'expected an if node');
  assert.equal(ifNode.succ.length, 2,
    `if node must have exactly 2 outgoing edges (true + false branch), got ${ifNode.succ.length}: ${JSON.stringify(ifNode.succ)}`);
});

test('the alternate branch\'s first node is a direct successor of the condition, not of the consequent\'s tail', () => {
  const nodes = cfgOf(`
    function h(req, db) {
      if (req.query.flag) {
        db.query('SELECT 1');
      } else {
        db.query('SELECT * FROM users WHERE id = ' + req.query.id);
      }
    }
  `);
  const ifNode = Object.values(nodes).find(n => n.kind === 'if');
  const callNodes = Object.values(nodes).filter(n => n.kind === 'call');
  assert.equal(callNodes.length, 2, 'expected one call node per branch');
  const sqliCall = callNodes.find(n =>
    n.args.some(a => JSON.stringify(a).includes('binary') || JSON.stringify(a).includes('id')));
  assert.ok(sqliCall, 'expected to find the else-branch db.query call');
  assert.ok(sqliCall.pred.includes(ifNode.id),
    `the else-branch call's predecessor must be the if node directly (got pred=${JSON.stringify(sqliCall.pred)})`);
  const thenCall = callNodes.find(n => n !== sqliCall);
  assert.ok(!sqliCall.pred.includes(thenCall.id),
    'the else-branch call must NOT be linked as a successor of the then-branch\'s call');
});

test('both branches converge on the same join node, which reaches function exit', () => {
  const nodes = cfgOf(`
    function h(req, db) {
      if (req.query.flag) {
        db.query('SELECT 1');
      } else {
        db.query('SELECT * FROM users WHERE id = ' + req.query.id);
      }
    }
  `);
  const callNodes = Object.values(nodes).filter(n => n.kind === 'call');
  const joins = new Set();
  for (const c of callNodes) for (const s of c.succ) joins.add(s);
  assert.equal(joins.size, 1, `both branches must converge on exactly one join node, got ${joins.size}`);
  const [joinId] = [...joins];
  const joinNode = nodes[joinId];
  assert.equal(joinNode.kind, 'noop');
  assert.ok(joinNode.pred.length === 2, `join node must have both branch tails as predecessors, got ${JSON.stringify(joinNode.pred)}`);
});

test('an empty else branch still gets a direct condition-to-join edge (the false path)', () => {
  const nodes = cfgOf(`
    function h(req, db) {
      if (req.query.flag) {
        db.query('SELECT 1');
      } else {}
    }
  `);
  const ifNode = Object.values(nodes).find(n => n.kind === 'if');
  assert.equal(ifNode.succ.length, 2,
    `empty-else if node must still have 2 outgoing edges, got ${ifNode.succ.length}`);
});

test('an else-if chain links each condition off the previous condition\'s false edge', () => {
  const nodes = cfgOf(`
    function h(req, db) {
      if (req.query.a) {
        db.query('A');
      } else if (req.query.b) {
        db.query('B');
      } else {
        db.query('C');
      }
    }
  `);
  const ifNodes = Object.values(nodes).filter(n => n.kind === 'if');
  assert.equal(ifNodes.length, 2, 'expected two if nodes (outer + else-if)');
  const [outer, inner] = ifNodes[0].succ.length >= ifNodes[1].succ.length ? ifNodes : [ifNodes[1], ifNodes[0]];
  assert.ok(outer.succ.includes(inner.id),
    `outer condition's false edge must lead into the else-if's condition node (outer.succ=${JSON.stringify(outer.succ)}, inner.id=${inner.id})`);
});
