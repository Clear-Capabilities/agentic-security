import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parsePhpFile } from '../src/ir/parser-php.js';
import { runScan } from '../src/runScan.js';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

// SARD PHP corpus, CWE-98 (PHP local/remote file inclusion): `include`/
// `require`/`include_once`/`require_once` are PHP LANGUAGE CONSTRUCTS, not
// function calls — `include $page . ".php";` has no `(` immediately after
// the keyword when written without parens, and even the parenthesized form
// (`include($page)`) never matched the statement-form call regex because
// `matchBalancedCall`'s callee prefix requires an identifier that isn't a
// reserved keyword being special-cased elsewhere. Lowered to a synthetic
// call (`__php_include__`), same convention as `__php_echo__`.

test('php: include with no parens lowers to a call carrying the path expression', () => {
  const code = '<?php\nfunction run($page) {\n  include $page . ".php";\n}\n';
  const ir = parsePhpFile('a.php', code);
  assert.ok(ir);
  const nodes = Object.values(ir.functions[0].cfg.nodes);
  const call = nodes.find(n => n.kind === 'call' && n.callee === '__php_include__');
  assert.ok(call, `expected __php_include__ call — got: ${nodes.map(n => n.kind).join(',')}`);
});

test('php: require_once with parens also lowers', () => {
  const code = '<?php\nfunction run($page) {\n  require_once($page);\n}\n';
  const ir = parsePhpFile('a.php', code);
  assert.ok(ir);
  const nodes = Object.values(ir.functions[0].cfg.nodes);
  const call = nodes.find(n => n.kind === 'call' && n.callee === '__php_include__');
  assert.ok(call, `expected __php_include__ call — got: ${nodes.map(n => n.kind).join(',')}`);
});

// SARD_80_F1 W5.13 — the real public SARD PHP suite generator's own CWE-98
// shape (confirmed via stivalet/PHP-Vuln-test-suite-generator's own
// construction.xml) assigns the include EXPRESSION to a variable
// (`$var = include(...)`), not a bare statement — a completely different
// code path (_lowerExpr, not _lowerStmt) that the tests above never
// exercised.
test('php: include used as an assignment RHS ($var = include(...)) also lowers to __php_include__', () => {
  const code = '<?php\nfunction run($page) {\n  $result = include($page . ".php");\n}\n';
  const ir = parsePhpFile('a.php', code);
  assert.ok(ir);
  const nodes = Object.values(ir.functions[0].cfg.nodes);
  const assign = nodes.find(n => n.kind === 'assign' && n.source && n.source.kind === 'call' && n.source.callee === '__php_include__');
  assert.ok(assign, `expected an assign whose source is a __php_include__ call — got: ${JSON.stringify(nodes.map(n => ({kind: n.kind, source: n.source})))}`);
});

test('php: end-to-end — tainted data into $var = include(...) reaches a code-injection finding (real corpus shape)', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'php-include-expr-'));
  try {
    fs.writeFileSync(path.join(dir, 'a.php'),
      '<?php\n$tainted = $_GET["UserData"];\n$var = include("\'". $tainted . ".php\'");\n');
    const { scan } = await runScan(dir, { deep: true });
    const hit = (scan.findings || []).find(f => f.family === 'code-injection' && f.parser === 'IR-TAINT');
    assert.ok(hit, `expected a file-inclusion finding — got families: ${(scan.findings || []).map(f => f.family).join(',')}`);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('php: a hardcoded path assigned via $var = include(...) does not fire', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'php-include-expr-safe-'));
  try {
    fs.writeFileSync(path.join(dir, 'a.php'),
      '<?php\n$safe = "literal_page";\n$var = include("\'". $safe . ".php\'");\n');
    const { scan } = await runScan(dir, { deep: true });
    const hit = (scan.findings || []).find(f => f.family === 'code-injection' && f.parser === 'IR-TAINT');
    assert.ok(!hit, 'a literal-only value reaching $var = include(...) must not fire the taint sink');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('php: end-to-end — $_GET into include reaches a code-injection finding under deep mode', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'php-include-'));
  try {
    fs.writeFileSync(path.join(dir, 'a.php'),
      '<?php\n$page = $_GET["page"];\ninclude $page . ".php";\n');
    const { scan } = await runScan(dir, { deep: true });
    const hit = (scan.findings || []).find(f => f.family === 'code-injection' || /inclusion/i.test(f.vuln || ''));
    assert.ok(hit, `expected a file-inclusion finding — got families: ${(scan.findings || []).map(f => f.family).join(',')}`);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('php: a hardcoded include path does not fire', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'php-include-safe-'));
  try {
    fs.writeFileSync(path.join(dir, 'a.php'), '<?php\ninclude "header.php";\n');
    const { scan } = await runScan(dir, { deep: true });
    const hit = (scan.findings || []).find(f => f.family === 'code-injection' && f.parser === 'IR-TAINT');
    assert.ok(!hit, 'a literal include path must not fire the taint sink');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
