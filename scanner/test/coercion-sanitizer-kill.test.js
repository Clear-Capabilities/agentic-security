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
