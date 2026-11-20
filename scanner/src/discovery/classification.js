//
// The weakness a discovery candidate claims, as specific as the evidence allows.
//
// A lens names a broad class (injection is CWE-74, authorization CWE-285). Every candidate used to carry its lens's CWE, so a
// shell-injection proposal was recorded as CWE-74 and a missing ownership check as CWE-285, whatever the model had argued. The
// hunter may now propose one specific CWE. A proposal is a claim to check, not an answer to trust:
//
//   1. it must be one CWE the lens can raise (`LENS_CWES`; the wildcard and chained lenses may raise any listed one), so an
//      authorization lens cannot file a cryptography weakness;
//   2. for a weakness that is an operation on a value (command, query, markup, code, path, request, deserialization, XML, regular
//      expression, header, redirect, log), the cited line (or the two after it, where a statement's sink usually sits) must hold
//      that kind of operation (`OPERATION_EVIDENCE`). A command-injection claim cited on a line with no process call is refused;
//   3. a weakness with no syntactic operation (authorization, business logic, resource limits) is accepted as `model-proposed`:
//      nothing here can establish it, and it stays a hypothesis for the refutation panel.
//
// A refused or missing proposal keeps the lens CWE and is marked `cweBasis: 'lens'`, the honest broad classification. Exactly one
// CWE is ever recorded: listing alternatives would only raise the chance of matching an answer key.

const CWE_RE = /^CWE-(\d{1,5})$/;
export function normalizeCwe(v) {
  if (typeof v === 'number' && Number.isInteger(v) && v > 0) return `CWE-${v}`;
  if (typeof v !== 'string') return null;
  const m = v.trim().toUpperCase().replace(/^CWE[\s:_-]*/, 'CWE-').match(CWE_RE);
  return m ? `CWE-${Number(m[1])}` : null;
}

const L = (...n) => n.map((x) => `CWE-${x}`);
const LENS_CWES = Object.freeze({
  injection: L(74, 77, 78, 79, 80, 88, 89, 90, 91, 93, 94, 95, 96, 113, 117, 502, 564, 611, 643, 652, 917, 943, 1236, 1336),
  authz: L(284, 285, 639, 862, 863, 425, 915, 269, 266, 732, 287, 306, 288),
  crypto: L(295, 323, 326, 327, 328, 329, 330, 331, 338, 347, 759, 760, 916, 208),
  'business-logic': L(840, 841, 20, 1284, 362, 367, 682, 190, 191, 837, 799),
  'feature-abuse': L(799, 770, 400, 1333, 409, 834, 835, 674, 918, 601, 1050),
});
const ANY_LENS = new Set([...Object.values(LENS_CWES).flat(), ...L(22, 23, 352, 384, 1321, 200, 209, 359, 1173, 710, 1188, 1104)]);

// The operation a value-operation weakness needs on the cited lines. Matched against the code the model was shown.
const OP = {
  command: /\b(?:exec(?:Sync|File|FileSync)?|spawn(?:Sync)?|system|popen|Popen|subprocess|shell_exec|passthru|proc_open|pcntl_exec|Runtime|ProcessBuilder|Process\.Start|exec\.Command|Command|IO\.popen|Open3|%x|os\.system)\b|`[^`]*\$\{/,
  query: /\b(?:query|execute|exec|raw|rawQuery|prepare|createQuery|executeQuery|executeUpdate|find|findOne|aggregate|where|whereRaw|select|cursor|sql|SQL)\b|\b(?:SELECT|INSERT|UPDATE|DELETE)\b/i,
  markup: /innerHTML|outerHTML|insertAdjacentHTML|dangerouslySetInnerHTML|\.html\s*\(|document\.write|\.write\s*\(|\.send\s*\(|render|v-html|html_safe|raw\s*\(|\becho\b|\bprint\b|Markup|mark_safe|format_html|Response|<\/?[a-z]/i,
  code: /\b(?:eval|Function|compile|exec|vm\.|runInContext|template|render|Template|instance_eval|class_eval|module_eval|send|public_send|getattr|__import__|importlib|expression|parseExpression|SpEL|ScriptEngine|constantize)\b/,
  deserialize: /deserializ|unserializ|pickle|loads?\s*\(|readObject|Marshal|YAML|ObjectInputStream|BinaryFormatter|fromXML|readValue|jsonpickle/i,
  xml: /xml|DocumentBuilder|SAXParser|XMLReader|etree|lxml|XmlReader|Nokogiri|parseString|TransformerFactory|Unmarshaller/i,
  xpath: /xpath|XPath|selectNodes|evaluate\s*\(/,
  ldap: /ldap|LDAP|search\s*\(|DirContext/,
  header: /header|Header|setHeader|addHeader|Set-Cookie|Location/,
  log: /\blog|logger|Logger|console\.|print|warn|error\s*\(|info\s*\(|debug\s*\(/,
  path: /\b(?:open|read|write|File|Path|path|join|resolve|unlink|rmdir|mkdir|sendFile|send_file|readFile|writeFile|createReadStream|fopen|file_get_contents|include|require|ZipEntry|extract)\b|\bfs\./,
  request: /\b(?:fetch|request|get|post|urlopen|urllib|http|https|axios|curl|HttpClient|WebClient|RestTemplate|URL|URI|Net::HTTP|open-uri|got|superagent|Http\.)\b/i,
  redirect: /redirect|Redirect|Location|sendRedirect/,
  regex: /RegExp|regex|Regex|\bre\.|Pattern|\.match\s*\(|\.test\s*\(|=~|preg_|\.replace\s*\(/,
};
const OPERATION_EVIDENCE = Object.freeze({
  'CWE-77': OP.command, 'CWE-78': OP.command, 'CWE-88': OP.command,
  'CWE-89': OP.query, 'CWE-564': OP.query, 'CWE-943': OP.query,
  'CWE-79': OP.markup, 'CWE-80': OP.markup,
  'CWE-94': OP.code, 'CWE-95': OP.code, 'CWE-96': OP.code, 'CWE-917': OP.code, 'CWE-1336': OP.code,
  'CWE-502': OP.deserialize, 'CWE-611': OP.xml, 'CWE-643': OP.xpath, 'CWE-652': OP.xpath, 'CWE-90': OP.ldap,
  'CWE-113': OP.header, 'CWE-93': OP.header, 'CWE-117': OP.log,
  'CWE-22': OP.path, 'CWE-23': OP.path, 'CWE-918': OP.request, 'CWE-601': OP.redirect, 'CWE-1333': OP.regex,
});

/** Strip a string to its code shape for evidence matching: comments are not operations. */
function codeOnly(line) { return String(line || '').replace(/\/\/.*$|#(?![{!]).*$/, ''); }

/**
 * Decide the CWE of a candidate. `lens` is the lens record; `proposed` the model's value; `evidenceLines` the shown text of the
 * cited line and the two after it. Returns `{ cwe, cweBasis, lensCwe, proposedCwe, cweRejected }`.
 */
export function classifyCandidate(lens, proposed, evidenceLines = []) {
  const lensCwe = lens?.cwe || null;
  const p = normalizeCwe(proposed);
  const base = { cwe: lensCwe, cweBasis: 'lens', lensCwe, proposedCwe: p };
  if (!p) return proposed == null || proposed === '' ? base : { ...base, cweRejected: 'not-a-cwe' };
  if (p === lensCwe) return { ...base, cweBasis: 'lens' };
  const allowed = LENS_CWES[lens?.key] ? new Set(LENS_CWES[lens.key]) : ANY_LENS;
  if (!allowed.has(p)) return { ...base, cweRejected: 'outside-lens' };
  const need = OPERATION_EVIDENCE[p];
  if (need) {
    const text = evidenceLines.map(codeOnly).join('\n');
    if (!need.test(text)) return { ...base, cweRejected: 'no-operation-on-cited-lines' };
    return { ...base, cwe: p, cweBasis: 'operation-checked' };
  }
  return { ...base, cwe: p, cweBasis: 'model-proposed' };
}
