// Taint-recall PRD (80%): XXE sink catalog entries across the remaining
// languages the corpus's xxe family covers, plus two real parser bugs found
// while debugging the java entries.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runScan } from '../src/runScan.js';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

function mkTmp(name, filename, code) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `as-xxe-catalog-${name}-`));
  fs.writeFileSync(path.join(dir, filename), code);
  return dir;
}

async function taintFindings(dir) {
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  return (scan.findings || []).filter(f => f.parser === 'IR-TAINT');
}

// Taint-recall PRD (80%): `new X(arg)` (unqualifiedClassInstanceCreationExpression)
// hardcoded args to []. Every constructor call in Java silently discarded its
// arguments — a sink modeled as a constructor call (argIndex-based) could
// never see a tainted constructor argument regardless of catalog
// correctness. This is what blocked `b.parse(new ByteArrayInputStream(xml))`:
// the sink (`parse`) was already cataloged, but `xml` never reached it
// because `new ByteArrayInputStream(xml)`'s own args were dropped one level
// up.
test('parser-java constructor-argument regression: new X(arg) keeps its argument', async () => {
  const { parseJavaFile } = await import('../src/ir/parser-java.js');
  const ir = await parseJavaFile('T.java', `
import java.io.ByteArrayInputStream;
public class T {
  void f(byte[] x) {
    g(new ByteArrayInputStream(x));
  }
}
`);
  const fn = ir.functions.find(f => f.name === 'T.f');
  assert.ok(fn);
  const call = Object.values(fn.cfg.nodes).find(n => n.kind === 'call' && n.callee === 'g');
  assert.ok(call, 'expected the g(...) call node');
  const ctorArg = call.args[0];
  assert.equal(ctorArg.kind, 'call');
  assert.equal(ctorArg.callee, 'ByteArrayInputStream');
  assert.equal(ctorArg.args.length, 1, `expected the constructor to keep its own argument, got: ${JSON.stringify(ctorArg.args)}`);
  assert.equal(ctorArg.args[0].kind, 'ident');
  assert.equal(ctorArg.args[0].name, 'x');
});

test('java-DocumentBuilder-parse: b.parse(new ByteArrayInputStream(xml)) fires XXE via IR-TAINT', async () => {
  const dir = mkTmp('java', 'Parser.java', `
import javax.xml.parsers.*;
import java.io.*;
import org.springframework.web.bind.annotation.RequestBody;
public class Parser {
  public org.w3c.dom.Document parse(@RequestBody byte[] xml) throws Exception {
    DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
    DocumentBuilder b = f.newDocumentBuilder();
    return b.parse(new ByteArrayInputStream(xml));
  }
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /xxe/i.test(f.vuln)),
    `expected XXE, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('kt-documentbuilder-parse: b.parse(...) fires XXE via IR-TAINT (Kotlin)', async () => {
  const dir = mkTmp('kt', 'Parse.kt', `
import javax.xml.parsers.DocumentBuilderFactory
import java.io.ByteArrayInputStream
import javax.servlet.http.HttpServletRequest

fun parse(xml: ByteArray) {
  val f = DocumentBuilderFactory.newInstance()
  val b = f.newDocumentBuilder()
  b.parse(ByteArrayInputStream(xml))
}

fun handler(request: HttpServletRequest) {
  parse(request.getParameter("xml"))
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /xxe/i.test(f.vuln)),
    `expected XXE, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('js-libxml-parsexmlstring: libxmljs.parseXmlString(req.body, ...) fires XXE via IR-TAINT', async () => {
  const dir = mkTmp('js', 'parse.js', `
const libxml = require('libxmljs');
function parse(req, res) {
  const doc = libxml.parseXmlString(req.body, { noent: true, dtdload: true });
  res.send(doc.toString());
}
module.exports = parse;
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /xxe/i.test(f.vuln)),
    `expected XXE, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('php-domdocument-loadxml: DOMDocument::loadXML($_POST) fires XXE via IR-TAINT', async () => {
  const dir = mkTmp('php', 'parse.php', `<?php
$doc = new DOMDocument();
$doc->loadXML($_POST["xml"], LIBXML_NOENT | LIBXML_DTDLOAD);
echo $doc->saveXML();
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /xxe/i.test(f.vuln)),
    `expected XXE, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('go-xml-newdecoder: xml.NewDecoder(r.Body) fires XXE via IR-TAINT', async () => {
  const dir = mkTmp('go', 'parse.go', `
package parse

import (
	"encoding/xml"
	"io"
	"net/http"
)

func Parse(r io.Reader) (any, error) {
	d := xml.NewDecoder(r)
	d.Strict = false
	var v any
	err := d.Decode(&v)
	return v, err
}

func Handler(w http.ResponseWriter, r *http.Request) (any, error) {
	return Parse(r.Body)
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /xxe/i.test(f.vuln)),
    `expected XXE, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});
