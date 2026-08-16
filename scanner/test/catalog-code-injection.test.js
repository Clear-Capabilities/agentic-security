// Taint-recall PRD (80%): code-injection sink catalog entries. Only
// php-eval and rb-eval are exercised end-to-end here — the java/cs/go/kt
// entries added alongside them (java-spel-parseexpression,
// cs-datatable-compute, go-template-parse, kt-scriptengine-eval) are all
// independently correct but their corpus fixtures are blocked by the
// chained-call CFG-drop bug (parser-java.js CST-based; parser-cs.js/
// parser-go.js via the shared matchBalancedCall helper) — confirmed via
// direct CFG inspection for all four, tracked as the next P5 item in
// docs/TAINT_RECALL_80PCT_PRD.md rather than re-verified with a dedicated
// unit test here (there is nothing to test until that lands — the sink
// entries themselves have no bug, the parser never hands them a call to
// match against).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runScan } from '../src/runScan.js';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

function mkTmp(name, filename, code) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `as-codeinj-catalog-${name}-`));
  fs.writeFileSync(path.join(dir, filename), code);
  return dir;
}

async function taintFindings(dir) {
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  return (scan.findings || []).filter(f => f.parser === 'IR-TAINT');
}

test('php-eval: eval($_GET-derived code) fires Code Injection via IR-TAINT', async () => {
  const dir = mkTmp('php', 'run.php', `<?php
$code = $_GET['code'];
eval($code);
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /code injection/i.test(f.vuln)),
    `expected Code Injection, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('rb-eval: eval(params-derived code) fires Code Injection via IR-TAINT', async () => {
  const dir = mkTmp('rb', 'run.rb', `
def run(params)
  code = params[:code]
  eval(code)
end
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /code injection/i.test(f.vuln)),
    `expected Code Injection, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('rb-eval precision: eval() of a hardcoded literal does not fire', async () => {
  const dir = mkTmp('rb-clean', 'run.rb', `
def run
  eval("1 + 1")
end
`);
  const taint = await taintFindings(dir);
  assert.equal(taint.filter(f => /code injection/i.test(f.vuln)).length, 0,
    `a hardcoded eval() must not fire, got: ${taint.map(f => f.vuln).join(', ')}`);
});
