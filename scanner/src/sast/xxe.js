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

  return [];
}
