// Found via bench/holdout-independent/microledger (SARD_80_F1_SCANNER_PRD.md
// P1 item 6, an independent external-holdout fixture): `exprFromCst`'s
// generic "binaryExpression" fallback branch hardcoded `op: '?'` for EVERY
// binary expression regardless of the real operator, and only ever took the
// first two operands. chevrotain's `binaryExpression` production for a chain
// like `"a" + query + "b"` is FLAT — one node listing all 3 operands and
// both `+` tokens, not a nested binary tree — so a 3+-operand concatenation
// silently dropped every operand past the second on top of mislabeling the
// operator. A tainted value sitting in the third (or later) operand of a
// concatenation was therefore invisible to the taint walker regardless of
// what the operator said.
//
// Confirmed via direct CST inspection (`node.children.BinaryOperator` is
// chevrotain's own token array for this production; `.image` is the literal
// operator text) rather than guessed. Fixed by left-folding all operands
// with their real operators.
//
// NOTE ON SCOPE: fixing this did NOT explain everything found while
// investigating microledger — a SEPARATE, deeper, still-open issue (adding a
// second method to the same class can suppress an EARLIER method's already-
// correct finding, confirmed via byte-identical CFG output before and after
// this fix) is disclosed, not chased further, in
// bench/holdout-independent/README.md. This file only tests the fix that
// actually landed: correct operator + all operands for an N-ary chain.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseJavaFile } from '../src/ir/parser-java.js';
import { runScan } from '../src/runScan.js';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { mkTestTmp } from './helpers/tmp.js';

function mkTmp(code) {
  const dir = mkTestTmp('as-java-nary-concat-');
  fs.writeFileSync(path.join(dir, 'X.java'), code);
  return dir;
}

test('exprFromCst: a 3-operand string concatenation preserves ALL operands and the real "+" operator (not "?")', async () => {
  const dir = mkTmp(`
public class X {
    void f(String query) {
        String s = "<div>Results for: " + query + "</div>";
    }
}
`);
  const ir = await parseJavaFile(path.join(dir, 'X.java'), fs.readFileSync(path.join(dir, 'X.java'), 'utf8'));
  const assignNode = Object.values(ir.functions[0].cfg.nodes).find(n => n.kind === 'assign' && n.target === 's');
  assert.ok(assignNode, 'expected an assign node for `s`');
  // Left-folded: (("<div>..." + query) + "</div>"). Both operators must be
  // the real "+", never the old hardcoded "?".
  assert.equal(assignNode.source.kind, 'binary');
  assert.equal(assignNode.source.op, '+');
  assert.equal(assignNode.source.left.kind, 'binary');
  assert.equal(assignNode.source.left.op, '+');
  assert.equal(assignNode.source.left.right.kind, 'ident');
  assert.equal(assignNode.source.left.right.name, 'query');
  assert.equal(assignNode.source.right.kind, 'literal');
});

test('end-to-end: taint in the MIDDLE operand of a 3-part concatenation reaches an XSS sink', async () => {
  const dir = mkTmp(`
package x;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
public class X {
    public void render(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String query = request.getParameter("q");
        response.getWriter().write("<div>Results for: " + query + "</div>");
    }
}
`);
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const taint = (scan.findings || []).filter(f => f.parser === 'IR-TAINT');
  assert.ok(taint.some(f => /xss/i.test(f.vuln)),
    `expected XSS via IR-TAINT with taint in the middle operand, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});
