// Sound taint-kill for type-coercion sanitizers (SARD_80_F1_SCANNER_PRD.md).
//
// Every other sanitizer in this engine only DEMOTES (sanitizer-gate.js /
// proof-gate.js), because its effect is family-specific — an HTML escaper
// does nothing for SQLi, so killing taint on any sanitizer call would risk
// dropping a real vulnerability. A catalog entry tagged `appliesTo: ['*']`
// (intval, filter_var(...VALIDATE_INT), parseInt, Integer.parseInt,
// strconv.Atoi, ...) is different in kind: it changes the VALUE'S TYPE, so
// the result cannot carry injection syntax for ANY family. These tests prove
// the engine now treats that specific, catalog-registered class of call as
// genuinely clean, both when assigned to a variable and when used inline as
// a sink argument — and that an ordinary family-specific sanitizer (an HTML
// escaper) is NOT affected by this change and still only demotes.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { runScan } from '../src/runScan.js';

async function scanSource(name, body) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-coercion-kill-'));
  fs.mkdirSync(path.join(dir, 'src'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'src', name), body);
  process.env.AGENTIC_SECURITY_DEEP = '1';
  const prevCi = process.env.AGENTIC_SECURITY_DEEP_IN_CI;
  process.env.AGENTIC_SECURITY_DEEP_IN_CI = '1';
  try {
    const { scan } = await runScan(dir);
    return scan.findings || [];
  } finally {
    delete process.env.AGENTIC_SECURITY_DEEP;
    if (prevCi === undefined) delete process.env.AGENTIC_SECURITY_DEEP_IN_CI;
    else process.env.AGENTIC_SECURITY_DEEP_IN_CI = prevCi;
  }
}

const taintOnly = (findings) => findings.filter((f) => f.parser === 'IR-TAINT');

test('a value assigned from a coercion sanitizer does not taint a later sink', async () => {
  const findings = await scanSource('a.php', `<?php
$id = intval($_GET['id']);
mysql_query("SELECT * FROM t WHERE id=" . $id);
`);
  assert.equal(taintOnly(findings).filter(f => f.cwe === 'CWE-89').length, 0,
    `intval() must kill taint, got: ${JSON.stringify(findings.map(f => [f.parser, f.cwe, f.line]))}`);
});

test('a coercion sanitizer used inline in the sink argument does not fire', async () => {
  const findings = await scanSource('b.php', `<?php
mysql_query("SELECT * FROM t WHERE id=" . intval($_GET['id']));
`);
  assert.equal(taintOnly(findings).filter(f => f.cwe === 'CWE-89').length, 0,
    `inline intval() must kill taint, got: ${JSON.stringify(findings.map(f => [f.parser, f.cwe, f.line]))}`);
});

test('the raw, un-coerced value still fires when NOT passed through a coercion sanitizer', async () => {
  const findings = await scanSource('c.php', `<?php
$id = $_GET['id'];
mysql_query("SELECT * FROM t WHERE id=" . $id);
`);
  assert.ok(taintOnly(findings).some(f => f.cwe === 'CWE-89'),
    `sanity check: the same shape WITHOUT intval() must still fire, got: ${JSON.stringify(findings.map(f => [f.parser, f.cwe, f.line]))}`);
});

test('an HTML escaper (family-specific, not a coercion) still only demotes, never kills, an unrelated-family finding', async () => {
  const findings = await scanSource('d.php', `<?php
$id = htmlspecialchars($_GET['id']);
mysql_query("SELECT * FROM t WHERE id=" . $id);
`);
  const hits = taintOnly(findings).filter(f => f.cwe === 'CWE-89');
  assert.ok(hits.length >= 1,
    `htmlspecialchars() must NOT kill a SQLi finding (it only defeats XSS), got: ${JSON.stringify(findings.map(f => [f.parser, f.cwe, f.line, f.sanitized]))}`);
});

// SARD_80_F1 W5.49 — PHP's sprintf("...%d...", $tainted) is a PER-ARGUMENT
// coercion, confirmed as the real generator's own CWE-89/CWE-91 "safe"
// construction shape (stivalet/PHP-Vuln-test-suite-generator's
// bin/XML/construction.xml: `$query = sprintf("SELECT * FROM student where
// id=%d", $tainted);`, marked safe="1").

test('sprintf with a %d-bound tainted argument does not taint the resulting query (real generator shape)', async () => {
  const findings = await scanSource('e.php', `<?php
$tainted = $_GET['id'];
$query = sprintf("SELECT * FROM student where id=%d", $tainted);
mysqli_query($conn, $query);
`);
  assert.equal(taintOnly(findings).filter(f => f.cwe === 'CWE-89').length, 0,
    `sprintf('%d', ...) must kill taint on that argument, got: ${JSON.stringify(findings.map(f => [f.parser, f.cwe, f.line]))}`);
});

test('sprintf with a %s-bound tainted argument still fires (no coercion, raw pass-through)', async () => {
  const findings = await scanSource('f.php', `<?php
$tainted = $_GET['name'];
$query = sprintf("SELECT * FROM student where name='%s'", $tainted);
mysqli_query($conn, $query);
`);
  assert.ok(taintOnly(findings).some(f => f.cwe === 'CWE-89'),
    `sprintf('%s', ...) must NOT kill taint (raw string pass-through), got: ${JSON.stringify(findings.map(f => [f.parser, f.cwe, f.line]))}`);
});

test('sprintf with a %c-bound tainted argument still fires (arbitrary byte, not a safe coercion)', async () => {
  const findings = await scanSource('g.php', `<?php
$tainted = $_GET['code'];
$query = sprintf("SELECT * FROM student where initial='%c'", $tainted);
mysqli_query($conn, $query);
`);
  assert.ok(taintOnly(findings).some(f => f.cwe === 'CWE-89'),
    `sprintf('%c', ...) must NOT be treated as a safe coercion (arbitrary byte output), got: ${JSON.stringify(findings.map(f => [f.parser, f.cwe, f.line]))}`);
});

// Explicit positional argnum (`%1$d`) is handled by `_sprintfSafeArgIndices`
// itself (see engine.js) but not exercised end-to-end here: PHP's `\$`
// escape-in-double-quoted-string handling has its own, pre-existing,
// unrelated lowering bug in parser-php.js (confirmed while writing this
// test: `\$d` is mis-lowered as template interpolation of a variable named
// `$d`, not as a literal `$d`), and the real generator source this fix
// targets never uses positional argnum syntax at all (only plain %d/%u/%s) —
// so this isn't a gap this fix needs to close.

test('sprintf with a mixed %d and %s still fires for the %s-bound tainted argument only', async () => {
  const findings = await scanSource('i.php', `<?php
$safeId = $_GET['id'];
$tainted = $_GET['name'];
$query = sprintf("SELECT * FROM student where id=%d and name='%s'", $safeId, $tainted);
mysqli_query($conn, $query);
`);
  assert.ok(taintOnly(findings).some(f => f.cwe === 'CWE-89'),
    `the %s-bound argument must still fire even though the %d-bound one is coerced, got: ${JSON.stringify(findings.map(f => [f.parser, f.cwe, f.line]))}`);
});

test('sprintf with a non-literal format string is never treated as a coercion (fails closed)', async () => {
  const findings = await scanSource('j.php', `<?php
$fmt = $_GET['fmt'];
$tainted = $_GET['id'];
$query = sprintf($fmt, $tainted);
mysqli_query($conn, $query);
`);
  assert.ok(taintOnly(findings).some(f => f.cwe === 'CWE-89'),
    `a non-literal format string must fail closed (no coercion assumed), got: ${JSON.stringify(findings.map(f => [f.parser, f.cwe, f.line]))}`);
});

// A %d-coerced value is safe for SYNTAX-ESCAPING injection (SQL/XPath/LDAP/
// command) but NOT for RESOURCE-SELECTION vulnerabilities (file inclusion,
// path traversal): a purely numeric value can still select an unintended
// resource. Confirmed as a real, reproducible regression (not hypothetical)
// during this fix's own real-corpus verification against the public
// generator's own CWE-98 sample (`bin/XML/construction.xml`):
// `include(sprintf("pages/'%d'.php", $tainted))` is marked UNSAFE by the
// generator itself despite the %d coercion.
test('sprintf feeding a file-path-shaped template (contains a file extension) still fires even with a %d-bound argument', async () => {
  const findings = await scanSource('k.php', `<?php
$tainted = $_GET['page'];
$path = sprintf("pages/%d.php", $tainted);
include($path);
`);
  assert.ok(taintOnly(findings).some(f => f.cwe === 'CWE-98'),
    `a %d-coerced file-path template must NOT be treated as safe (numeric coercion doesn't prevent unauthorized resource selection), got: ${JSON.stringify(findings.map(f => [f.parser, f.cwe, f.line]))}`);
});

test('sprintf feeding a path-separator-shaped template still fires even with a %d-bound argument', async () => {
  const findings = await scanSource('l.php', `<?php
$tainted = $_GET['dir'];
$path = sprintf("/var/data/%d", $tainted);
readfile($path);
`);
  assert.ok(taintOnly(findings).length > 0,
    `a %d-coerced path-separator template must NOT be treated as safe, got: ${JSON.stringify(findings.map(f => [f.parser, f.cwe, f.line]))}`);
});

test('sprintf feeding a genuine SQL query (no path markers) is still correctly treated as coerced', async () => {
  const findings = await scanSource('m.php', `<?php
$tainted = $_GET['id'];
$query = sprintf("SELECT * FROM student where id=%d", $tainted);
mysqli_query($conn, $query);
`);
  assert.equal(taintOnly(findings).filter(f => f.cwe === 'CWE-89').length, 0,
    `sanity check: the file-path exclusion must not affect ordinary SQL templates, got: ${JSON.stringify(findings.map(f => [f.parser, f.cwe, f.line]))}`);
});
