// Java native deserialization detection.
//
// Each of these APIs accepts a stream and turns it into objects — if the
// stream comes from an attacker (HTTP body, file upload, cache, message queue)
// gadget chains in classpath libraries (Commons Collections, Spring,
// Hibernate, etc.) can yield RCE. There's no general-purpose fix; the only
// safe approach is to avoid native serialization for untrusted data.
//
// Patterns:
//   - new ObjectInputStream(...).readObject()                CWE-502
//   - XStream.fromXML(<tainted>)                              XStream class
//   - JSON.parseObject(<tainted>, Object.class)               fastjson autoType
//   - new XMLDecoder(...).readObject()                        java.beans.XMLDecoder
//   - SerializationUtils.deserialize(...)                     Apache Commons-Lang
//   - new Yaml().load(...)                                    SnakeYAML load() (vs safeLoad)
//   - HessianInput.readObject() / Hessian2Input.readObject()  Hessian

const PATTERNS = [
  {
    name: 'ObjectInputStream.readObject',
    re: /\bnew\s+ObjectInputStream\s*\([^)]*\)\s*\.\s*readObject\s*\(|\b(\w+)\s*\.\s*readObject\s*\(\s*\)/g,
    severity: 'critical',
    vuln: 'Insecure Java Deserialization: ObjectInputStream.readObject()',
    remediation: 'ObjectInputStream.readObject() invokes gadget chains in many common libraries (Commons Collections, Spring, ROME). Replace native serialization with a typed format (JSON+Jackson with default-typing OFF, Protocol Buffers, MessagePack). If you must keep Java serialization, validate the class graph via ObjectInputFilter (Java 9+) before any field read, and reject any class not on an allowlist.',
    // We only fire on `readObject()` calls when an `ObjectInputStream` is
    // constructed in the same file — narrows false positives on unrelated
    // .readObject() shapes.
    requireOIS: true,
  },
  {
    name: 'XMLDecoder.readObject',
    re: /\bnew\s+(?:[\w]+\.)*XMLDecoder\s*\(/g,
    severity: 'critical',
    vuln: 'Insecure Java Deserialization: XMLDecoder (arbitrary code via XML)',
    remediation: 'java.beans.XMLDecoder is designed to instantiate arbitrary classes — there is no safe way to decode an untrusted XMLDecoder stream. Use Jackson/JSON or DOM-based parsing with a typed model instead.',
  },
  {
    name: 'XStream.fromXML',
    re: /\b\w+\s*\.\s*(?:fromXML|fromJSON)\s*\(/g,
    severity: 'high',
    vuln: 'Insecure Java Deserialization: XStream.fromXML without TypePermission whitelist',
    remediation: 'XStream pre-1.4.18 default-permits all types. Either upgrade to 1.4.18+ (which sets a NoTypePermission default) AND explicitly allow your DTO classes with allowTypesByWildcard(...), or migrate to Jackson with default-typing disabled.',
    // file-level signal: ensure this is XStream-shaped code (import or class
    // mention somewhere in file) — `.fromXML(` is rare enough that we accept
    // the broad regex above but file-gate it on XStream presence.
    requireXStream: true,
  },
  {
    name: 'fastjson.parseObject',
    re: /\b(?:JSON|com\.alibaba\.fastjson\.JSON)\s*\.\s*(?:parseObject|parse)\s*\([^)]*,\s*(?:Object\.class|Class\s*\.\s*forName|[A-Z][\w$.]*\.class)\s*[,)]/g,
    severity: 'critical',
    vuln: 'Insecure Java Deserialization: fastjson.parseObject with autoType target',
    remediation: 'fastjson has historically shipped many autoType bypass CVEs. Migrate to fastjson2 with @type filtering disabled, or to Jackson with default-typing disabled. If staying on fastjson 1.x: set ParserConfig.getGlobalInstance().setAutoTypeSupport(false) AND maintain an explicit denylist.',
  },
  {
    name: 'SnakeYAML new Yaml().load()',
    re: /\bnew\s+(?:[\w]+\.)*Yaml\s*\(\s*\)/g,
    severity: 'critical',
    vuln: 'Insecure Java Deserialization: SnakeYAML new Yaml().load() (gadget RCE)',
    remediation: 'new Yaml().load() instantiates arbitrary classes via the !!java/object tag. Use `new Yaml(new SafeConstructor())` or upgrade to SnakeYAML 2.0+ where the default constructor is safe.',
    // file-level suppression: SafeConstructor seen in file
    safeFileRe: /\bnew\s+Yaml\s*\(\s*new\s+SafeConstructor\s*\(/,
  },
  {
    name: 'Hessian.readObject',
    re: /\b(?:Hessian(?:2)?Input|HessianFactory)\s*[^;]*?\.\s*readObject\s*\(/g,
    severity: 'high',
    vuln: 'Insecure Java Deserialization: Hessian readObject (gadget RCE)',
    remediation: 'Hessian shares the Java-serialization-style gadget surface. Either upgrade to Hessian-Lite with strict class filtering, or replace with JSON/Protobuf.',
  },
  {
    name: 'Commons SerializationUtils.deserialize',
    re: /\b(?:SerializationUtils|org\.apache\.commons\.lang3?\.SerializationUtils)\s*\.\s*deserialize\s*\(/g,
    severity: 'critical',
    vuln: 'Insecure Java Deserialization: Apache Commons SerializationUtils.deserialize',
    remediation: 'SerializationUtils.deserialize is a thin wrapper around ObjectInputStream — same RCE surface as raw native deserialization. Replace with a JSON/Protobuf round-trip.',
  },
];

import { blankComments } from './_comment-strip.js';

function _lineOf(raw, idx) { return raw.substring(0, idx).split('\n').length; }

export function scanJavaDeserialization(fp, raw) {
  if (!/\.(?:java|kt|kts|scala|groovy|gradle)$/i.test(fp)) return [];
  if (!raw || raw.length > 500_000) return [];
  const code = blankComments(raw);
  // Pre-pass: detect any ObjectInputStream construction in the file. Without
  // one, a bare .readObject() call is almost certainly RMI/JDBC/socket noise
  // unrelated to native serialization gadgets.
  const hasOIS = /\bnew\s+ObjectInputStream\b/.test(code);
  // Pre-pass for XStream — gate the broad `.fromXML(` regex.
  const hasXStream = /\bXStream\b|\bxstream\.|com\.thoughtworks\.xstream/.test(code);
  const findings = [];
  const seen = new Set();
  const push = (f) => { if (!seen.has(f.id)) { seen.add(f.id); findings.push(f); } };

  for (const p of PATTERNS) {
    if (p.safeFileRe && p.safeFileRe.test(code)) continue;
    if (p.requireXStream && !hasXStream) continue;
    const re = new RegExp(p.re.source, p.re.flags);
    let m;
    while ((m = re.exec(code))) {
      if (p.requireOIS && !hasOIS) continue;
      // For the ObjectInputStream pattern, the second branch (bare \w+.readObject)
      // only fires when there's an OIS in the file AND the method receiver isn't
      // obviously a JDBC ResultSet (rs/results/rset names).
      if (p.requireOIS && m[1] && /^(?:rs|result|results|rset|resultset)$/i.test(m[1])) continue;
      const line = _lineOf(raw, m.index);
      push({
        id: `java-deser:${fp}:${line}:${p.name.replace(/\s+/g, '_')}`,
        file: fp, line,
        vuln: p.vuln,
        severity: p.severity,
        cwe: 'CWE-502',
        stride: 'Elevation of Privilege',
        snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
        remediation: p.remediation,
        confidence: 0.85,
        parser: 'JAVA-DESER',
      });
    }
  }
  return findings;
}
