// Taint-recall PRD (80%): code-injection sink catalog entries. cs/go/kt now
// have real end-to-end tests too — the chained-call CFG-drop bug that
// originally blocked them (parser-cs.js/parser-go.js/parser-kt.js, all via
// the shared matchBalancedCall-based chain-following) has since been fixed.
// java-spel-parseexpression remains untested here: Java uses a SEPARATE,
// CST-based parser (parser-java.js) with its own, still-unfixed chained-call
// defect — a distinct P5 item, not the one this fix closed.

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

test('cs-datatable-compute: new DataTable().Compute(expr, "") fires Code Injection via IR-TAINT (chained-call fix)', async () => {
  const dir = mkTmp('cs', 'Calculator.cs', `
using System.Data;
using Microsoft.AspNetCore.Mvc;

class Calculator {
    object Eval([FromQuery] string expr) {
        return new DataTable().Compute(expr, "");
    }
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /code injection/i.test(f.vuln)),
    `expected Code Injection, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('go-template-parse: template.New("page").Parse(userTemplate) fires Code Injection via IR-TAINT (chained-call fix)', async () => {
  const dir = mkTmp('go', 'render.go', `
package render

import (
	"io"
	"net/http"
	"text/template"
)

func Render(userTemplate string, w io.Writer, data any) {
	t, _ := template.New("page").Parse(userTemplate)
	t.Execute(w, data)
}

func Handler(w http.ResponseWriter, r *http.Request) {
	Render(r.URL.Query().Get("tpl"), w, nil)
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /code injection/i.test(f.vuln)),
    `expected Code Injection, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('kt-scriptengine-eval: ScriptEngineManager().getEngineByName("js").eval(userCode) fires Code Injection via IR-TAINT (3-level chain)', async () => {
  const dir = mkTmp('kt', 'ScriptRunner.kt', `
import javax.script.ScriptEngineManager
import javax.servlet.http.HttpServletRequest

class ScriptRunner {
    fun run(userCode: String): Any? {
        return ScriptEngineManager().getEngineByName("js").eval(userCode)
    }
    fun handler(request: HttpServletRequest): Any? {
        return run(request.getParameter("code"))
    }
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /code injection/i.test(f.vuln)),
    `expected Code Injection, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});
