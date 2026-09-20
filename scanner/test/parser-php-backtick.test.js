import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parsePhpFile } from '../src/ir/parser-php.js';
import { runScan } from '../src/runScan.js';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

// SARD PHP corpus: the backtick shell-execution operator (`` `cmd` ``,
// equivalent to shell_exec()) is this corpus's single most common
// command-injection shape (83 of 224 bad dev-split cases use it as their
// FIRST source assignment) — but parser-php.js had no recognizer for it at
// all, the same gap parser-rb.js once had for Ruby's identical operator (see
// ir/CLAUDE.md's Ruby row). It fell through every _lowerExpr branch to
// {kind:'unknown'}, silently dropping the shell command and any interpolated
// taint inside it.

test('php: backtick assigned to a variable lowers to a call carrying the interpolated command', () => {
  const code = '<?php\nfunction run($cmd) {\n  $out = `ls -la $cmd`;\n  return $out;\n}\n';
  const ir = parsePhpFile('a.php', code);
  assert.ok(ir);
  const nodes = Object.values(ir.functions[0].cfg.nodes);
  const assign = nodes.find(n => n.kind === 'assign' && n.target === '$out');
  assert.ok(assign, `expected $out assignment — got: ${nodes.map(n => n.kind).join(',')}`);
  assert.equal(assign.source.kind, 'call');
  assert.equal(assign.source.callee, '__php_backtick_exec__');
  // The interpolated $cmd must survive as a real sub-expression, not be
  // swallowed into an opaque literal string.
  const flat = JSON.stringify(assign.source);
  assert.ok(flat.includes('"cmd"') || flat.includes("'cmd'") || flat.includes('$cmd'),
    `expected $cmd to survive in the lowered args — got: ${flat}`);
});

test('php: a bare backtick statement (no assignment) is still lowered', () => {
  const code = '<?php\nfunction run($cmd) {\n  `rm -rf $cmd`;\n}\n';
  const ir = parsePhpFile('a.php', code);
  assert.ok(ir);
  const nodes = Object.values(ir.functions[0].cfg.nodes);
  const call = nodes.find(n => n.kind === 'call' && n.callee === '__php_backtick_exec__');
  assert.ok(call, `expected a backtick call node — got: ${nodes.map(n => n.kind).join(',')}`);
});

test('php: end-to-end — $_GET into a backtick reaches a command-injection finding under deep mode', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'php-backtick-'));
  try {
    fs.writeFileSync(path.join(dir, 'a.php'),
      '<?php\n$cmd = $_GET["cmd"];\n$out = `ls -la $cmd`;\necho $out;\n');
    const { scan } = await runScan(dir, { deep: true, deepInCi: true });
    const hit = (scan.findings || []).find(f => f.family === 'command-injection' || /command injection/i.test(f.vuln || ''));
    assert.ok(hit, `expected a command-injection finding — got families: ${(scan.findings || []).map(f => f.family).join(',')}`);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('php: a literal-only backtick command does not spuriously blow up the parser', () => {
  const code = '<?php\nfunction run() {\n  $out = `ls -la /tmp`;\n  return $out;\n}\n';
  const ir = parsePhpFile('a.php', code);
  assert.ok(ir);
  const nodes = Object.values(ir.functions[0].cfg.nodes);
  assert.ok(nodes.some(n => n.kind === 'assign' && n.target === '$out'));
});
