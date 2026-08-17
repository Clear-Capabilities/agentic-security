// Taint-recall PRD (80%): a call's own RECEIVER can be tainted independent
// of its arguments — `tainted.toString()`, `tainted.getBytes()`,
// `tainted.trim()` — and exprTaint's `case 'call'` never checked for this.
// `argsTainted` only looks at the call's OWN arguments (there may be none,
// or they may be unrelated); `_nestedCallReturnTainted` resolves the callee
// as a FUNCTION NAME via the call graph, which a bare method name like
// `toString` never does. So a no-arg (or otherwise argument-unrelated)
// method call on a tainted value silently dropped taint at that call site.
//
// Two distinct IR shapes need distinct handling (see `_calleeReceiverTainted`
// in engine.js): parser-js.js (Babel) emits a structured `{kind:'member',
// object, prop}` callee, so the receiver is `callee.object`. The five
// hand-rolled parsers (cs/go/kt/php/rb) plus parser-java.js and parser-py.js
// instead emit a flat, dot-joined STRING callee ("cmd.toString") — the
// receiver there is recovered by slicing off everything after the last '.'.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { runScan } from '../src/runScan.js';

function mkTmp(name, files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `as-recv-taint-${name}-`));
  for (const [file, content] of Object.entries(files)) {
    fs.writeFileSync(path.join(dir, file), content);
  }
  return dir;
}

async function taintFindings(dir) {
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  return (scan.findings || []).filter(f => f.parser === 'IR-TAINT');
}

test('JS (structured member callee): a no-arg method call on a tainted receiver still flows into a sink', async () => {
  const dir = mkTmp('js', {
    'app.js': `
const { exec } = require('child_process');
function handler(req) {
  const cmd = req.query.cmd;
  exec(cmd.toString());
}
`,
  });
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /command injection/i.test(f.vuln)),
    `expected a Command Injection finding through cmd.toString(), got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('JS: an untainted receiver\'s no-arg method call does not spuriously fire (precision check)', async () => {
  const dir = mkTmp('js-clean', {
    'app.js': `
const { exec } = require('child_process');
function handler() {
  const cmd = "ls -la";
  exec(cmd.toString());
}
`,
  });
  const taint = await taintFindings(dir);
  assert.equal(taint.filter(f => /command injection/i.test(f.vuln)).length, 0,
    `a literal-built command must not fire, got: ${taint.map(f => f.vuln).join(', ')}`);
});

test('Java (flat dot-joined string callee): a no-arg method call on a tainted receiver still flows into a sink', async () => {
  const dir = mkTmp('java', {
    'Parser.java': `
import javax.xml.parsers.*;
import org.springframework.web.bind.annotation.RequestParam;
public class Parser {
  public org.w3c.dom.Document parse(byte[] xml) throws Exception {
    return DocumentBuilderFactory.newInstance().newDocumentBuilder()
      .parse(new java.io.ByteArrayInputStream(xml));
  }
  void handler(@RequestParam String xml) throws Exception {
    parse(xml.getBytes());
  }
}
`,
  });
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /xxe/i.test(`${f.vuln} ${f.cwe}`)),
    `expected an XXE finding through xml.getBytes(), got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});
