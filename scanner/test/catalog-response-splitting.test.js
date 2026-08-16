// Taint-recall PRD (80%): response-splitting/header-injection sink catalog
// entries across php/js/cs/kt/java, plus a real engine bug (exprIsSource
// never checked bare-identifier expressions) found while debugging the PHP
// entry.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runScan } from '../src/runScan.js';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

function mkTmp(name, filename, code) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `as-respsplit-catalog-${name}-`));
  fs.writeFileSync(path.join(dir, filename), code);
  return dir;
}

async function taintFindings(dir) {
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  return (scan.findings || []).filter(f => f.parser === 'IR-TAINT');
}

// Taint-recall PRD (80%): matchSource has always supported a bare-identifier
// GLOBAL lookup (PHP's $_GET, Ruby's params/ENV, JS's location), but neither
// exprIsSource nor exprTaint's early check ever invoked it for
// expr.kind === 'ident' — only 'member'/'call'. So a global referenced
// DIRECTLY (not first assigned to a local, not read through a member/
// subscript) was invisible to taint no matter how it was used.
test('a bare-identifier global source ($_GET, no member/subscript access) is recognized', async () => {
  const dir = mkTmp('php-bare-global', 'direct.php', `<?php
header("X-Trace: " . $_GET["trace"]);
`);
  // This exact shape is what the real corpus fixture (php-respsplit) uses —
  // PHP's own parser mis-splits `$_GET["trace"]`'s string literal, leaving a
  // bare `$_GET` ident as one of the concat's parts (a separate, pre-existing
  // PHP parser quirk, not what this test targets). The point here is that
  // THAT residue — a bare-identifier global reference with no member/
  // subscript access reaching exprTaint — is still recognized, which it was
  // not before this fix.
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /header|splitting|crlf/i.test(f.vuln)),
    `expected a finding through the bare $_GET reference, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('php-header: header("X: " . $_GET[...]) fires HTTP Response Splitting via IR-TAINT', async () => {
  const dir = mkTmp('php', 'trace.php', `<?php
header("X-Trace: " . $_GET["trace"]);
echo "ok";
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /header|splitting|crlf/i.test(f.vuln)),
    `expected Response Splitting, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('js-response-setheader: res.setHeader(name, req.query.x) fires HTTP Response Splitting via IR-TAINT', async () => {
  const dir = mkTmp('js', 'handler.js', `
const express = require('express');
const app = express();
app.get('/h', (req, res) => {
  res.setHeader('X-Trace', req.query.trace);
  res.end('ok');
});
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /header|splitting|crlf/i.test(f.vuln)),
    `expected Response Splitting, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('cs-headers-add: Response.Headers.Add(name, tainted) fires Header Injection via IR-TAINT (distinct API from AddHeader)', async () => {
  const dir = mkTmp('cs', 'TraceController.cs', `
using Microsoft.AspNetCore.Mvc;

public class TraceController : Controller {
    public string Trace([FromQuery] string trace) {
        Response.Headers.Add("X-Trace", trace);
        return "ok";
    }
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /header|splitting|crlf/i.test(f.vuln)),
    `expected Header Injection, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('cs-headers-add precision: List<T>.Add(...) is not mislabeled as header injection', async () => {
  const dir = mkTmp('cs-clean', 'ListAdd.cs', `
using System.Collections.Generic;
public class C {
    public void Handler(string x) {
        var items = new List<string>();
        items.Add(x);
    }
}
`);
  const taint = await taintFindings(dir);
  assert.equal(taint.filter(f => /header|splitting|crlf/i.test(f.vuln)).length, 0,
    `List<T>.Add must not fire the header sink, got: ${taint.map(f => f.vuln).join(', ')}`);
});

test('kt-servlet-setheader / java-servlet-setheader: resp.setHeader(name, tainted) fires Header Injection via IR-TAINT', async () => {
  const dir = mkTmp('kt', 'TraceHandler.kt', `
import javax.servlet.http.HttpServletResponse
import javax.servlet.http.HttpServletRequest

class TraceHandler {
    fun trace(traceId: String, resp: HttpServletResponse) {
        resp.setHeader("X-Trace", traceId)
    }
    fun handler(request: HttpServletRequest, resp: HttpServletResponse) {
        trace(request.getParameter("traceId"), resp)
    }
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /header|splitting|crlf/i.test(f.vuln)),
    `expected Header Injection, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});
