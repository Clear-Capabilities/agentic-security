// Taint-engine PRD P1 — C# catalog additions found missing during the
// investigation: Redirect/LocalRedirect (open redirect), Response.Write
// (XSS), Response.AddHeader (header injection), XmlDocument.Load/LoadXml
// (XXE), DirectorySearcher (LDAP injection). None of these CWEs (601, 79,
// 113, 611, 90) could be IR-TAINT-caught without a sink entry, regardless
// of engine quality. Each test proves the entry fires end-to-end on a
// genuinely tainted example.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runScan } from '../src/runScan.js';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

function mkTmp(name, code) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `as-cs-catalog-p1-${name}-`));
  fs.writeFileSync(path.join(dir, 'C.cs'), code);
  return dir;
}

async function taintFindings(dir) {
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  return (scan.findings || []).filter(f => f.parser === 'IR-TAINT');
}

test('cs-redirect: Controller.Redirect(userInput) fires Open Redirect via IR-TAINT', async () => {
  const dir = mkTmp('redirect', `
public class C : Controller {
    public IActionResult Go([FromQuery] string next) {
        return Redirect(next);
    }
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /redirect/i.test(`${f.vuln} ${f.cwe}`)),
    `expected Open Redirect, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('cs-localredirect: Controller.LocalRedirect(userInput) fires Open Redirect via IR-TAINT', async () => {
  const dir = mkTmp('localredirect', `
public class C : Controller {
    public IActionResult Go([FromQuery] string next) {
        return LocalRedirect(next);
    }
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /redirect/i.test(`${f.vuln} ${f.cwe}`)),
    `expected Open Redirect, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('cs-response-write: Response.Write(userInput) fires XSS via IR-TAINT', async () => {
  const dir = mkTmp('response-write', `
public class C {
    public void Handler([FromQuery] string name, HttpResponse Response) {
        Response.Write(name);
    }
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /xss|cross.site/i.test(`${f.vuln} ${f.cwe}`)),
    `expected XSS, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('cs-response-write precision: a differently-receivered .Write(...) does not fire this sink', async () => {
  const dir = mkTmp('response-write-clean', `
public class C {
    public void Handler([FromQuery] string name) {
        Console.Write(name);
    }
}
`);
  const taint = await taintFindings(dir);
  assert.equal(taint.filter(f => /xss|cross.site/i.test(`${f.vuln} ${f.cwe}`)).length, 0,
    `Console.Write must not trigger the Response.Write sink, got: ${taint.map(f => f.vuln).join(', ')}`);
});

test('cs-response-addheader: Response.AddHeader(name, userInput) fires header injection via IR-TAINT', async () => {
  const dir = mkTmp('addheader', `
public class C {
    public void Handler([FromQuery] string val, HttpResponse Response) {
        Response.AddHeader("X-Custom", val);
    }
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /header|splitting/i.test(`${f.vuln} ${f.cwe}`)),
    `expected Header Injection, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('cs-xmldoc-load: XmlDocument.Load(userInput) fires XXE via IR-TAINT', async () => {
  const dir = mkTmp('xmlload', `
public class C {
    public void Handler([FromQuery] string path) {
        var xmlDoc = new XmlDocument();
        xmlDoc.Load(path);
    }
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /xxe|xml/i.test(`${f.vuln} ${f.cwe}`)),
    `expected XXE, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('cs-xmldoc-loadxml: XmlDocument.LoadXml(userInput) fires XXE via IR-TAINT', async () => {
  const dir = mkTmp('loadxml', `
public class C {
    public void Handler([FromQuery] string xml) {
        var doc = new XmlDocument();
        doc.LoadXml(xml);
    }
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /xxe|xml/i.test(`${f.vuln} ${f.cwe}`)),
    `expected XXE, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('cs-directorysearcher: new DirectorySearcher(concatenated filter) fires LDAP injection via IR-TAINT', async () => {
  const dir = mkTmp('ldap', `
public class C {
    public void Handler([FromQuery] string uid) {
        var filter = "(uid=" + uid + ")";
        var searcher = new DirectorySearcher(filter);
    }
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /ldap/i.test(`${f.vuln} ${f.cwe}`)),
    `expected LDAP Injection, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});
