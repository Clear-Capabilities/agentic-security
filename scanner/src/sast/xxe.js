// XML External Entity (XXE) detection for Java and Python.
// Node.js xml2js/libxmljs/sax is already covered in engine.js SINK_PATTERNS.
//
// Java vulnerable APIs:
//   - DocumentBuilderFactory.newInstance()      (CWE-611)
//   - SAXParserFactory.newInstance()
//   - XMLInputFactory.newInstance()              (StAX)
//   - SAXBuilder()                                (JDOM)
//   - SchemaFactory.newInstance()
//   - TransformerFactory.newInstance()
//   - XMLReaderFactory.createXMLReader()
//
// Java-safe configurations (any one suppresses the finding for the file):
//   - setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
//   - setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)
//   - setExpandEntityReferences(false)
//   - setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false)
//   - setXIncludeAware(false) + setExpandEntityReferences(false)
//
// Python vulnerable APIs:
//   - lxml.etree.parse / fromstring                (CVE class — XXE possible)
//   - xml.etree.ElementTree.parse / fromstring     (older Python; modern is safer
//                                                   but defusedxml is the canonical fix)
//   - xml.sax.parse / parseString / make_parser
//   - xml.dom.minidom.parse / parseString
//   - xml.dom.pulldom.parse / parseString
//
// Python-safe configurations:
//   - `from defusedxml` import anywhere in the file
//   - `import defusedxml`
//   - For lxml: parser with `resolve_entities=False, no_network=True`

const JAVA_VULN_PATTERNS = [
  { name: 'DocumentBuilderFactory', re: /\bDocumentBuilderFactory\s*\.\s*newInstance\s*\(\s*\)/g },
  { name: 'SAXParserFactory',       re: /\bSAXParserFactory\s*\.\s*newInstance\s*\(\s*\)/g },
  { name: 'XMLInputFactory',        re: /\bXMLInputFactory\s*\.\s*newInstance\s*\(\s*\)/g },
  { name: 'SAXBuilder',             re: /\bnew\s+SAXBuilder\s*\(\s*\)/g },
  { name: 'SchemaFactory',          re: /\bSchemaFactory\s*\.\s*newInstance\s*\(/g },
  { name: 'TransformerFactory',     re: /\bTransformerFactory\s*\.\s*newInstance\s*\(\s*\)/g },
  { name: 'XMLReaderFactory',       re: /\bXMLReaderFactory\s*\.\s*createXMLReader\s*\(/g },
];

const JAVA_SAFE_RES = [
  /setFeature\s*\(\s*["']http:\/\/apache\.org\/xml\/features\/disallow-doctype-decl["']\s*,\s*true\s*\)/,
  /setFeature\s*\(\s*XMLConstants\.FEATURE_SECURE_PROCESSING\s*,\s*true\s*\)/,
  /setExpandEntityReferences\s*\(\s*false\s*\)/,
  /XMLInputFactory\.IS_SUPPORTING_EXTERNAL_ENTITIES\s*,\s*false/,
  /setFeature\s*\(\s*["']http:\/\/xml\.org\/sax\/features\/external-general-entities["']\s*,\s*false\s*\)/,
  /setFeature\s*\(\s*["']http:\/\/xml\.org\/sax\/features\/external-parameter-entities["']\s*,\s*false\s*\)/,
];

const PYTHON_VULN_PATTERNS = [
  { name: 'lxml.etree.parse',    re: /\blxml\.etree\.(?:parse|fromstring|XMLParser)\s*\(/g },
  { name: 'lxml.etree (aliased)', re: /\b(?:from\s+lxml\s+import\s+etree\b[\s\S]{0,200}?\b)?etree\s*\.\s*(?:parse|fromstring|XMLParser)\s*\(/g },
  { name: 'xml.etree.ElementTree', re: /\b(?:xml\.etree\.ElementTree|ET)\s*\.\s*(?:parse|fromstring|XMLParser)\s*\(/g },
  { name: 'xml.sax',             re: /\bxml\.sax\s*\.\s*(?:parse|parseString|make_parser)\s*\(/g },
  { name: 'xml.dom.minidom',     re: /\bxml\.dom\.minidom\s*\.\s*(?:parse|parseString)\s*\(/g },
  { name: 'xml.dom.pulldom',     re: /\bxml\.dom\.pulldom\s*\.\s*(?:parse|parseString)\s*\(/g },
  { name: 'minidom (aliased)',   re: /\bminidom\s*\.\s*(?:parse|parseString)\s*\(/g },
];

const PYTHON_DEFUSED_RE = /(?:^|\n)\s*(?:from\s+defusedxml\b|import\s+defusedxml\b)/;
// lxml-specific: XMLParser(resolve_entities=False, no_network=True) is the
// upstream-recommended safe shape.
const PYTHON_LXML_SAFE_RE = /XMLParser\s*\([^)]*\bresolve_entities\s*=\s*False\b[^)]*\)/;

// ── PHP / Go / Ruby ─────────────────────────────────────────────────────────
// Each of these XML stacks is XXE-SAFE BY DEFAULT in current versions; the
// vulnerability appears only when the caller explicitly opts INTO external-
// entity / DTD-loading behavior. So we flag the opt-in flags, not the parse
// call itself — the plain parse is correctly clean.
//
// PHP:   loadXML / simplexml_load_string|file with LIBXML_NOENT, LIBXML_DTDLOAD,
//        or LIBXML_DTDVALID. (PHP >= 8.0 disables entity substitution by
//        default; these flags re-enable it.)
const PHP_XXE_RE =
  /\b(?:loadXML|simplexml_load_string|simplexml_load_file)\s*\([^;]*\bLIBXML_(?:NOENT|DTDLOAD|DTDVALID)\b/g;
// Go:   encoding/xml Decoder made unsafe by `Strict = false` or a custom
//       `Entity` map that defines expansions. Gated on an xml-decoder hint.
const GO_XXE_RE =
  /\b\w+\s*\.\s*(?:Strict\s*=\s*false|Entity\s*=\s*(?:map\[string\]string|xml\.HTMLEntity))/g;
const GO_XML_HINT_RE = /\b(?:encoding\/xml|xml\.NewDecoder|xml\.Decoder)\b/;
// Ruby: Nokogiri parse whose options enable NOENT / DTDLOAD / replace_entities.
//       Default Nokogiri::XML(xml) is safe. Gated on a Nokogiri/LibXML hint.
const RUBY_XXE_RE =
  /\.\s*(?:noent|dtdload|dtdvalid|replace_entities)\b/g;
const RUBY_XML_HINT_RE = /\bNokogiri\s*::\s*XML\b|\bLibXML\b|\bXML::Parser\b/;

import { blankComments } from './_comment-strip.js';

function _stripLineComment(s, lang) {
  if (lang === 'java') return blankComments(s);
  if (lang === 'py') return blankComments(s, 'py');
  return s;
}

function _lineOf(raw, idx) {
  return raw.substring(0, idx).split('\n').length;
}

export function scanXXE(fp, raw) {
  if (!raw || raw.length > 500_000) return [];
  const findings = [];

  if (/\.java$/i.test(fp)) {
    const code = _stripLineComment(raw, 'java');
    // If ANY known-safe configuration appears in the file, suppress all Java XXE
    // findings in that file. This is intentionally generous — false negatives
    // here are preferable to flagging code that's already hardened.
    const fileSafe = JAVA_SAFE_RES.some(r => r.test(code));
    if (fileSafe) return [];
    for (const p of JAVA_VULN_PATTERNS) {
      const re = new RegExp(p.re.source, p.re.flags);
      let m;
      while ((m = re.exec(code))) {
        const line = _lineOf(raw, m.index);
        findings.push({
          id: `xxe:${fp}:${line}:${p.name}`,
          file: fp, line,
          vuln: `XXE: ${p.name} created without external-entity protections`,
          severity: 'high',
          cwe: 'CWE-611',
          stride: 'Information Disclosure',
          snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
          remediation: `Disable external entities before using the parser. For ${p.name} call setFeature("http://apache.org/xml/features/disallow-doctype-decl", true) and setExpandEntityReferences(false), or use XMLConstants.FEATURE_SECURE_PROCESSING. Prefer DTDs to be rejected at parse time.`,
          confidence: 0.85,
          parser: 'XXE',
        });
      }
    }
    return findings;
  }

  if (/\.py$/i.test(fp)) {
    const code = _stripLineComment(raw, 'py');
    if (PYTHON_DEFUSED_RE.test(code)) return [];
    for (const p of PYTHON_VULN_PATTERNS) {
      const re = new RegExp(p.re.source, p.re.flags);
      let m;
      while ((m = re.exec(code))) {
        // lxml-only safe shape: caller passed an XMLParser with resolve_entities=False
        if (/lxml/i.test(p.name) && PYTHON_LXML_SAFE_RE.test(code)) continue;
        const line = _lineOf(raw, m.index);
        findings.push({
          id: `xxe:${fp}:${line}:${p.name}`,
          file: fp, line,
          vuln: `XXE: ${p.name} parses XML without external-entity protections`,
          severity: 'high',
          cwe: 'CWE-611',
          stride: 'Information Disclosure',
          snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
          remediation: 'Use defusedxml instead: `from defusedxml import ElementTree as ET` (drop-in replacement). For lxml, pass an XMLParser with resolve_entities=False, no_network=True.',
          confidence: 0.85,
          parser: 'XXE',
        });
      }
    }
    return findings;
  }

  // ── PHP / Go / Ruby: flag the explicit opt-in to external entities ──────────
  const _emitOptIn = (code, re, gate, mkVuln, mkRem) => {
    if (gate && !gate.test(code)) return;
    const r = new RegExp(re.source, re.flags);
    let m;
    const seen = new Set();
    while ((m = r.exec(code))) {
      const line = _lineOf(raw, m.index);
      if (seen.has(line)) continue;
      seen.add(line);
      findings.push({
        id: `xxe:${fp}:${line}`,
        file: fp, line,
        vuln: mkVuln(), severity: 'high', cwe: 'CWE-611',
        stride: 'Information Disclosure',
        snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
        remediation: mkRem(), confidence: 0.8, parser: 'XXE',
      });
    }
  };

  if (/\.(?:php|phtml)$/i.test(fp)) {
    const code = blankComments(raw, 'py');
    _emitOptIn(code, PHP_XXE_RE, null,
      () => 'XXE: XML parsed with LIBXML_NOENT / LIBXML_DTDLOAD (external entities enabled)',
      () => 'Drop the LIBXML_NOENT / LIBXML_DTDLOAD flags — PHP >= 8.0 disables entity substitution by default, so plain loadXML($xml) / simplexml_load_string($xml) is safe. If you must accept DTDs, set libxml_set_external_entity_loader to reject network/file access.');
    return findings;
  }

  if (/\.go$/i.test(fp)) {
    const code = blankComments(raw);
    _emitOptIn(code, GO_XXE_RE, GO_XML_HINT_RE,
      () => 'XXE: encoding/xml Decoder configured with Strict=false or a custom Entity map',
      () => 'Go\'s encoding/xml ignores external entities by default — do not set Strict=false or populate Decoder.Entity with untrusted input. Leave the decoder at its defaults.');
    return findings;
  }

  if (/\.rb$/i.test(fp)) {
    const code = blankComments(raw, 'py');
    _emitOptIn(code, RUBY_XXE_RE, RUBY_XML_HINT_RE,
      () => 'XXE: Nokogiri parse options enable external entities (NOENT / DTDLOAD / replace_entities)',
      () => 'Remove noent/dtdload/replace_entities — Nokogiri::XML(xml) is safe by default (entities are not expanded, DTDs are not loaded). Never enable these on untrusted XML.');
    return findings;
  }

  return [];
}
