// Taint-engine PRD P1 — `case 'return'` never checked the sink catalog.
//
// dataflow/engine.js's step() checks `_sinkFindingsForCall` from `case
// 'assign'` (x = sink(y)) and `case 'call'` (bare statement sink(y)) — but
// `case 'return'` only ever called `exprTaint(node.value, ...)` to mark the
// FUNCTION's return tainted for interprocedural callers. It never asked
// whether `node.value` itself is a sink-shaped call. `return
// File.ReadAllText(path)` — idiomatic ASP.NET Core, and the equivalent
// shape in any language — was therefore structurally invisible to IR-TAINT.
//
// JS is accidentally immune: Babel's CallExpression visitor emits a
// standalone 'call' CFG node for every CallExpression it walks, including
// ones nested inside a return argument, so JS gets an incidental extra node
// that already triggers the case 'call' sink-check. Every hand-rolled
// parser (C#, Java, Kotlin, Go, PHP, Ruby) does not do this and was
// exposed. C# is used here because it's where this was found and
// independently reproduced (return wc.DownloadString(url) / return
// File.ReadAllText(path) / return Redirect(next) all produced zero
// IR-TAINT findings from runTaintEngine on their own IR before this fix).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { runScan } from '../src/runScan.js';

function mkTmp(name, files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `as-retsink-${name}-`));
  for (const [rel, content] of Object.entries(files)) {
    const fp = path.join(dir, rel);
    fs.mkdirSync(path.dirname(fp), { recursive: true });
    fs.writeFileSync(fp, content);
  }
  return dir;
}

test('C#: a sink call as the direct return value fires (return File.ReadAllText(path))', async () => {
  const dir = mkTmp('cs-return-sink', {
    'FileController.cs': `
using System.IO;
public class FileController {
    public string LoadFile([FromQuery] string path) {
        return File.ReadAllText(path);
    }
}
`,
  });
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const irFindings = (scan.findings || []).filter(f => f.parser === 'IR-TAINT');
  const pathFindings = irFindings.filter(f => /path|traversal/i.test(f.vuln || ''));
  assert.ok(pathFindings.length >= 1,
    `expected File.ReadAllText(path) in a return statement to fire Path Traversal, got IR-TAINT findings: ${JSON.stringify(irFindings.map(f => f.vuln))}`);
});

test('C#: an untainted literal returned through the same sink shape stays silent', async () => {
  // Precision half — the fix must not make case 'return' fire unconditionally
  // on any sink-shaped call; only on one whose argument is actually tainted.
  const dir = mkTmp('cs-return-clean', {
    'FileController.cs': `
using System.IO;
public class FileController {
    public string LoadFile() {
        return File.ReadAllText("config.json");
    }
}
`,
  });
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const irFindings = (scan.findings || []).filter(f => f.parser === 'IR-TAINT');
  assert.equal(irFindings.length, 0,
    `expected no IR-TAINT findings on an untainted literal, got: ${JSON.stringify(irFindings.map(f => f.vuln))}`);
});

test('JS: return of a sink call was already caught before this fix — confirms no double-count', async () => {
  // JS is the accidentally-immune case (Babel emits a redundant standalone
  // 'call' node even inside a return argument). This pins that the fix does
  // not introduce a SECOND finding for the same statement now that
  // case 'return' also checks the sink catalog.
  const dir = mkTmp('js-return-sink', {
    'app.js': `
const express = require('express');
const app = express();
function run(req) {
  return eval(req.query.code);
}
app.get('/run', (req, res) => res.send(run(req)));
`,
  });
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  const irFindings = (scan.findings || []).filter(f => f.parser === 'IR-TAINT');
  const codeFindings = irFindings.filter(f => /code|eval/i.test(f.vuln || ''));
  assert.equal(codeFindings.length, 1,
    `expected exactly one Code Injection finding (not zero, not doubled), got: ${JSON.stringify(codeFindings.map(f => `${f.vuln}@${f.line}`))}`);
});
