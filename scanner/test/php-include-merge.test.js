import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { runScan } from '../src/runScan.js';
import { mergePhpIncludes, _resetPhpIncludeMergeCounter } from '../src/ir/php-include-merge.js';
import { parsePhpFile } from '../src/ir/parser-php.js';

// SARD_80_F1 W5.7 — PHP's `include`/`require` genuinely executes in the
// caller's own variable scope, unlike an ordinary function call. Before this
// module, a two-file split (a source assignment in one file, a sink using
// that variable in the includer) was structurally invisible: `include` was
// modeled purely as a CWE-98 sink over its own path argument. See the
// module's own header for the full rationale.

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'php-include-merge-'));
}

test('mergePhpIncludes: splices an included file\'s top-level assign into the includer\'s CFG', () => {
  _resetPhpIncludeMergeCounter();
  const perFile = {
    'source.php': parsePhpFile('source.php', '<?php\n$tainted = $_GET["x"];\n'),
    'main.php': parsePhpFile('main.php', '<?php\ninclude_once("source.php");\n$y = 1;\n'),
  };
  mergePhpIncludes(perFile);
  const fn = perFile['main.php'].functions.find(f => f.qid === perFile['main.php'].topLevel);
  const assigns = Object.values(fn.cfg.nodes).filter(n => n.kind === 'assign');
  const spliced = assigns.find(n => n.target === '$tainted');
  assert.ok(spliced, 'expected a spliced $tainted assign node in main.php\'s CFG');
});

test('end-to-end: a source in one file reaches a sink in the includer via a literal include', async () => {
  const dir = tmpDir();
  try {
    fs.writeFileSync(path.join(dir, 'source_input.php'), '<?php\n$tainted = $_GET["UserData"];\n');
    fs.writeFileSync(path.join(dir, 'main.php'),
      '<?php\ninclude_once("source_input.php");\n' +
      '$query = "//User[username/text()=\'". $tainted . "\']";\n' +
      '$xml->xpath($query);\n');
    const { scan } = await runScan(dir, { deep: true, deepInCi: true });
    const hit = (scan.findings || []).find(f => f.cwe === 'CWE-91' && f.parser === 'IR-TAINT');
    assert.ok(hit, `expected a cross-file XPath injection finding — got: ${(scan.findings || []).map(f => `${f.parser}:${f.cwe}`).join(',')}`);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('a dynamic (non-literal) include path is left alone — never merged, never mistainted', async () => {
  const dir = tmpDir();
  try {
    fs.writeFileSync(path.join(dir, 'source_input.php'), '<?php\n$tainted = $_GET["UserData"];\n');
    fs.writeFileSync(path.join(dir, 'main.php'),
      '<?php\n$page = $_GET["page"];\ninclude($page . ".php");\n' +
      '$query = "//User[username/text()=\'". $tainted . "\']";\n' +
      '$xml->xpath($query);\n');
    const { scan } = await runScan(dir, { deep: true, deepInCi: true });
    const xpathHit = (scan.findings || []).find(f => f.cwe === 'CWE-91');
    assert.ok(!xpathHit, 'a dynamic include path must never merge an unrelated file\'s assignments');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('an include of a file with no matching path on the scan surface is a no-op (does not throw)', async () => {
  const dir = tmpDir();
  try {
    fs.writeFileSync(path.join(dir, 'main.php'),
      '<?php\ninclude_once("does_not_exist.php");\n$y = 1;\n');
    const { scan } = await runScan(dir, { deep: true, deepInCi: true });
    assert.ok(Array.isArray(scan.findings));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('mutual includes (A includes B, B includes A) terminate without hanging or throwing', () => {
  _resetPhpIncludeMergeCounter();
  const perFile = {
    'a.php': parsePhpFile('a.php', '<?php\ninclude_once("b.php");\n$x = 1;\n'),
    'b.php': parsePhpFile('b.php', '<?php\ninclude_once("a.php");\n$y = $_GET["z"];\n'),
  };
  assert.doesNotThrow(() => mergePhpIncludes(perFile));
});

test('a self-include does not duplicate or infinitely clone the includer\'s own nodes', () => {
  _resetPhpIncludeMergeCounter();
  const perFile = {
    'a.php': parsePhpFile('a.php', '<?php\ninclude_once("a.php");\n$x = $_GET["y"];\n'),
  };
  assert.doesNotThrow(() => mergePhpIncludes(perFile));
});

test('the include call node itself is preserved unchanged — its own CWE-98 path-taint sink still applies', async () => {
  const dir = tmpDir();
  try {
    fs.writeFileSync(path.join(dir, 'header.php'), '<?php\n$safe = 1;\n');
    fs.writeFileSync(path.join(dir, 'a.php'), '<?php\ninclude("header.php");\n');
    const { scan } = await runScan(dir, { deep: true, deepInCi: true });
    const hit = (scan.findings || []).find(f => f.family === 'code-injection' && f.parser === 'IR-TAINT');
    assert.ok(!hit, 'a literal include path must still not fire the taint sink after merging');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
