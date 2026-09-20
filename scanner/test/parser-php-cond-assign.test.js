import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parsePhpFile } from '../src/ir/parser-php.js';
import { runScan } from '../src/runScan.js';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

// SARD PHP corpus: `if (($value = fgets($handle, 4096)) == false) { ... }` —
// an assignment embedded inside an `if`/`while` condition — is the single
// dominant real-world PHP idiom for reading a file/stream line by line
// (238 of 995 dev-split cases use exactly this shape). `_lowerStmt`'s
// assignment regex only matches STATEMENT-position assignments; an
// assignment nested inside a condition is part of the if/while's own `cond`
// expression text and was silently invisible — `$value` never got a real
// assign CFG node at all, so every source read this way (fgets, fread,
// preg_match, etc.) was undetectable regardless of what catalog entries
// exist for the RHS callee.

test('php: an if-condition embedded assignment produces a real assign node before the if', () => {
  const code = '<?php\nfunction run($handle) {\n  if (($value = fgets($handle, 4096)) == false) {\n    $value = "";\n  }\n  return $value;\n}\n';
  const ir = parsePhpFile('a.php', code);
  assert.ok(ir);
  const nodes = Object.values(ir.functions[0].cfg.nodes);
  const assign = nodes.find(n => n.kind === 'assign' && n.target === '$value' && n.source && n.source.kind === 'call');
  assert.ok(assign, `expected a $value assign from fgets() — got: ${nodes.map(n => `${n.kind}:${n.target||n.callee||''}`).join(',')}`);
  assert.equal(assign.source.callee, 'fgets');
  const ifNode = nodes.find(n => n.kind === 'if');
  assert.ok(ifNode, 'expected an if node');
  // Not asserting on ifNode.cond's shape here: parser-php.js has a
  // separate, pre-existing gap where `==`/`!=`/comparison operators are not
  // lowered at all (any comparison expression is {kind:'unknown'}), which
  // this change does not touch. What matters for taint purposes is that the
  // ASSIGN node above exists with the real source expression — the `if`'s
  // own cond value is never consulted for straight-line taint propagation.
});

test('php: a while-condition embedded assignment also produces a real assign node', () => {
  const code = '<?php\nfunction run($handle) {\n  while (($line = fgets($handle)) !== false) {\n    echo $line;\n  }\n}\n';
  const ir = parsePhpFile('a.php', code);
  assert.ok(ir);
  const nodes = Object.values(ir.functions[0].cfg.nodes);
  const assign = nodes.find(n => n.kind === 'assign' && n.target === '$line');
  assert.ok(assign, `expected a $line assign — got: ${nodes.map(n => n.kind).join(',')}`);
});

// This was BLOCKED on a pre-existing, general dataflow/engine.js bug — not
// this parser fix, not PHP-specific, and not something this file's own
// lowering introduced — root-caused by direct inspection + an isolated
// repro (removing the embedded-assignment lowering above changed nothing
// about the failure): `_activeConstantVars`, a single Map reset once per
// analyzeFunction call and never forked per CFG branch, sat outside the
// properly branch-merged `state` access-path Set and made `exprTaint`'s
// ident case short-circuit to `false` for any variable name it had ever
// seen assigned a literal on ANY branch, regardless of the current,
// correctly-unioned taint state at the actual use site. This exact idiom
// (an initial/error-branch literal default for a variable later populated
// by a real, tainted read) was the SARD PHP corpus's single most common
// shape for CWE-78/89/90/91/98 combined, and very likely the dominant
// reason this corpus's CWE-78 recall stayed at 0 even after the backtick,
// fgets-source, and this cond-assign fix all landed on their own.
// FIXED (SARD_80_F1_SCANNER_PRD.md engine-level work, same session):
// `_activeConstantVars` was removed entirely — the mechanism was pure
// redundant overreach in the first place (a literal assignment already
// correctly clears the access-path lattice via removePathAndDescendants in
// the same 'assign' handling), so removing it made the lattice's own
// already-correct, path-sensitive merge the sole source of truth. See
// test/constant-propagation-path-sensitivity.test.js for the dedicated
// engine-level regression coverage. No longer skipped — this test now
// passes for real.
test('php: end-to-end — fgets read inside an if-condition, then into system(), reaches a command-injection finding', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'php-condassign-'));
  try {
    fs.writeFileSync(path.join(dir, 'a.php'),
      '<?php\n$handle = @fopen("/tmp/x.txt", "r");\nif ($handle) {\n  if (($value = fgets($handle, 4096)) == false) {\n    $value = "";\n  }\n  fclose($handle);\n} else {\n  $value = "";\n}\n$query = "cat \'". $value . "\'";\nsystem($query);\n');
    const { scan } = await runScan(dir, { deep: true, deepInCi: true });
    const hit = (scan.findings || []).find(f => f.family === 'command-injection');
    assert.ok(hit, `expected a command-injection finding — got families: ${(scan.findings || []).map(f => f.family).join(',')}`);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('php: an ordinary if-condition with no embedded assignment is unaffected', () => {
  const code = '<?php\nfunction run($x) {\n  if ($x == 5) {\n    return 1;\n  }\n  return 0;\n}\n';
  const ir = parsePhpFile('a.php', code);
  assert.ok(ir);
  const nodes = Object.values(ir.functions[0].cfg.nodes);
  const ifNode = nodes.find(n => n.kind === 'if');
  assert.ok(ifNode);
  assert.equal(JSON.parse(JSON.stringify(ifNode.cond)).kind !== undefined, true);
});
