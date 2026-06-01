// XXE detector (CWE-611) — Java/Python (existing) + PHP/Go/Ruby (extended).
// Each non-Java/Python stack is XXE-safe by default; we flag the explicit
// external-entity opt-in, and the default-safe parse must stay clean.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanXXE as s } from '../src/sast/xxe.js';

const fires = (fp, code) => s(fp, code).some((f) => f.cwe === 'CWE-611');
const clean = (fp, code) => s(fp, code).every((f) => f.cwe !== 'CWE-611');

test('PHP — LIBXML_NOENT/DTDLOAD opt-in fires; default parse clean', () => {
  assert.ok(fires('p.php', '<?php $d = new DOMDocument(); $d->loadXML($_POST["xml"], LIBXML_NOENT | LIBXML_DTDLOAD);'));
  assert.ok(fires('p.php', '<?php $x = simplexml_load_string($_POST["xml"], "SimpleXMLElement", LIBXML_NOENT);'));
  assert.ok(clean('p.php', '<?php $d = new DOMDocument(); $d->loadXML($_POST["xml"]);'));
  assert.ok(clean('p.php', '<?php $x = simplexml_load_string($_POST["xml"]);'));
  assert.ok(clean('p.php', '<?php echo "hello";'));
});

test('Go — Decoder Strict=false / custom Entity fires; default decoder clean', () => {
  assert.ok(fires('p.go', 'package main\nimport ("encoding/xml";"os")\nfunc p(f *os.File){ d := xml.NewDecoder(f); d.Strict=false; var v any; d.Decode(&v) }'));
  assert.ok(fires('p.go', 'package main\nimport ("encoding/xml";"os")\nfunc p(f *os.File){ d := xml.NewDecoder(f); d.Entity = map[string]string{}; d.Decode(nil) }'));
  assert.ok(clean('p.go', 'package main\nimport ("encoding/xml";"os")\nfunc p(f *os.File){ d := xml.NewDecoder(f); var v any; d.Decode(&v) }'));
  // Strict=false WITHOUT any xml decoder context must not fire.
  assert.ok(clean('p.go', 'package main\ntype T struct{ Strict bool }\nfunc p(){ t := T{}; t.Strict = false }'));
});

test('Ruby — Nokogiri noent/dtdload fires; default parse clean', () => {
  assert.ok(fires('p.rb', 'require "nokogiri"\ndef p(xml)\n  Nokogiri::XML(xml) { |c| c.noent }\nend\n'));
  assert.ok(fires('p.rb', 'require "nokogiri"\ndef p(xml)\n  Nokogiri::XML::Document.parse(xml) { |c| c.dtdload.noent }\nend\n'));
  assert.ok(clean('p.rb', 'require "nokogiri"\ndef p(xml)\n  Nokogiri::XML(xml)\nend\n'));
  // noent WITHOUT a Nokogiri/LibXML hint must not fire.
  assert.ok(clean('p.rb', 'def p(c)\n  c.noent\nend\n'));
});

test('Java/Python regression — vuln fires, hardened clean', () => {
  assert.ok(fires('P.java', 'import javax.xml.parsers.*;\nclass P { void p(String s) throws Exception { DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(s); } }'));
  assert.ok(clean('P.java', 'import javax.xml.parsers.*;\nclass P { void p(String s) throws Exception { DocumentBuilderFactory f = DocumentBuilderFactory.newInstance(); f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true); f.newDocumentBuilder().parse(s); } }'));
  assert.ok(clean('x.py', 'from defusedxml import ElementTree as ET\ndef p(s): return ET.fromstring(s)'));
});

test('non-XML languages produce nothing', () => {
  assert.deepEqual(s('a.ts', 'const x = parseXml(input);'), []);
});
