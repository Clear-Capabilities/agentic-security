// Taint-recall PRD (80%): XPath-injection sink catalog entries added across
// all 8 languages the corpus's xpath-injection family covers — previously
// only Java had a (narrower) entry, so this family measured 0/8 despite the
// vuln class existing in real code across every one of these languages.
// java-xpath-compile already existed; java-xpath-evaluate is new (the
// corpus fixture calls XPath.evaluate() directly, never .compile()).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runScan } from '../src/runScan.js';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

function mkTmp(name, filename, code) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `as-xpath-catalog-${name}-`));
  fs.writeFileSync(path.join(dir, filename), code);
  return dir;
}

async function taintFindings(dir) {
  const { scan } = await runScan(dir, { deep: true, deepInCi: true });
  return (scan.findings || []).filter(f => f.parser === 'IR-TAINT');
}

test('java-xpath-evaluate: XPath.evaluate(expr, doc, ...) fires XPath Injection via IR-TAINT', async () => {
  const dir = mkTmp('java', 'Lookup.java', `
import javax.xml.xpath.*;
import org.w3c.dom.Document;
public class Lookup {
  public String find(Document doc, javax.servlet.http.HttpServletRequest req) throws Exception {
    XPath xp = XPathFactory.newInstance().newXPath();
    String name = req.getParameter("name");
    return (String) xp.evaluate("//user[@name='" + name + "']", doc, XPathConstants.STRING);
  }
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /xpath/i.test(f.vuln)),
    `expected XPath Injection, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('cs-xml-selectnodes: XmlDocument.SelectNodes(concatenated) fires XPath Injection via IR-TAINT', async () => {
  const dir = mkTmp('cs', 'Lookup.cs', `
using System.Xml;
using Microsoft.AspNetCore.Mvc;
class Lookup {
    XmlNodeList Find(XmlDocument doc, [FromQuery] string name) {
        return doc.SelectNodes("//user[@name='" + name + "']");
    }
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /xpath/i.test(f.vuln)),
    `expected XPath Injection, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

// Taint-recall PRD (80%): this fixture's chained shape
// (`xp.compile(tainted).evaluate(doc, NODESET)`) is exactly what exposed
// the args-union bug in the chained-call fix — the tainted value lives on
// the INNER call (.compile), not the outer one (.evaluate), and a
// kt-xpath-evaluate catalog entry (argIndex 'all') is what makes it
// reachable now that bare-name matching only ever sees "evaluate" (the
// terminal segment) once the two calls are joined into one node.
test('kt-xpath-compile: XPath.compile(concatenated).evaluate(...) fires XPath Injection via IR-TAINT', async () => {
  const dir = mkTmp('kt', 'Lookup.kt', `
import javax.xml.xpath.*
import org.w3c.dom.Document
import javax.servlet.http.HttpServletRequest

class Lookup {
    fun find(xp: XPath, doc: Document, request: HttpServletRequest): Any {
        val name = request.getParameter("name")
        return xp.compile("//user[@name='" + name + "']").evaluate(doc, XPathConstants.NODESET)
    }
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /xpath/i.test(f.vuln)),
    `expected XPath Injection, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('py-lxml-xpath: tree.xpath(concatenated) fires XPath Injection via IR-TAINT', async () => {
  const dir = mkTmp('py', 'lookup.py', `
def find_user(tree, name):
    return tree.xpath("//user[@name='" + name + "']")

def handler(tree, request):
    return find_user(tree, request.args.get("name"))
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /xpath/i.test(f.vuln)),
    `expected XPath Injection, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('rb-nokogiri-xpath: doc.xpath(interpolated) fires XPath Injection via IR-TAINT', async () => {
  const dir = mkTmp('rb', 'lookup.rb', `
class Lookup
  def find(doc, name)
    doc.xpath("//user[@name='#{name}']")
  end

  def handler(doc, params)
    find(doc, params[:name])
  end
end
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /xpath/i.test(f.vuln)),
    `expected XPath Injection, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('js-xpath-select: xpath.select(concatenated, doc) fires XPath Injection via IR-TAINT', async () => {
  const dir = mkTmp('js', 'lookup.js', `
const xpath = require('xpath');
function find(doc, user) {
  return xpath.select("//user[@name='" + user + "']", doc);
}
module.exports = (req, doc) => {
  return find(doc, req.query.user);
};
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /xpath/i.test(f.vuln)),
    `expected XPath Injection, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('php-domxpath-query: DOMXPath::query(concatenated) fires XPath Injection via IR-TAINT', async () => {
  const dir = mkTmp('php', 'lookup.php', `<?php
function find_user($doc, $name) {
    $xp = new DOMXPath($doc);
    return $xp->query("//user[@name='" . $name . "']");
}
function handler($doc) {
    return find_user($doc, $_GET['name']);
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /xpath/i.test(f.vuln)),
    `expected XPath Injection, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});

test('php-domxpath-query precision: an unrelated PDO ->query() is not mislabeled as XPath Injection', async () => {
  const dir = mkTmp('php-clean', 'db.php', `<?php
function lookup($pdo, $id) {
    return $pdo->query("SELECT * FROM t WHERE id = " . $id);
}
`);
  const taint = await taintFindings(dir);
  assert.equal(taint.filter(f => /xpath/i.test(f.vuln)).length, 0,
    `PDO::query() must not fire the XPath sink, got: ${taint.map(f => f.vuln).join(', ')}`);
});

test('go-htmlquery-find: htmlquery.Find(doc, concatenated) fires XPath Injection via IR-TAINT', async () => {
  const dir = mkTmp('go', 'lookup.go', `
package lookup

import (
	"net/http"

	"github.com/antchfx/htmlquery"
	"golang.org/x/net/html"
)

func Find(doc *html.Node, name string) []*html.Node {
	return htmlquery.Find(doc, "//user[@name='"+name+"']")
}

func Handler(w http.ResponseWriter, r *http.Request, doc *html.Node) []*html.Node {
	return Find(doc, r.URL.Query().Get("name"))
}
`);
  const taint = await taintFindings(dir);
  assert.ok(taint.some(f => /xpath/i.test(f.vuln)),
    `expected XPath Injection, got: ${taint.map(f => f.vuln).join(', ') || '(none)'}`);
});
