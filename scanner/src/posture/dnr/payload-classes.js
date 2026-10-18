// Payload classes for the Detection-and-Response loop (PRD 7). A class is a GENERIC, structural description of what an
// exploit of a vulnerability family looks like on the wire (a shell metacharacter followed by a command word, a `..`
// path segment, a request to a loopback address). It is deliberately not an indicator of compromise: nothing here names
// an attacker address, domain, malware hash or user agent, because no proof ever observed one. A detection built from a
// class can say "this request has the shape of a command injection against /api/export"; it cannot say who sent it.
//
// The same matcher (`matchesClass`) is used when a detection is validated, when historical logs are hunted, and when
// the rendered rules are described, so the rule that is tested is the rule that ships.

export const PAYLOAD_CLASSES = Object.freeze({
  'sql-injection': {
    cwe: ['CWE-89', 'CWE-564'],
    behavior: 'SQL metacharacters change the structure of a database query built from request input',
    matcher: 'regex',
    indicators: [
      /(?:'|%27)\s*(?:or|and)\s+(?:'|%27|"|%22|\d)/i,
      /union(?:\s|\+|%20|\/\*.*?\*\/)+(?:all(?:\s|\+|%20)+)?select/i,
      /(?:;|%3b)\s*(?:drop|insert|update|delete|alter|truncate)(?:\s|\+|%20)/i,
      /(?:--|#|%23)(?:\s|\+|%20|$)/,
      /\b(?:sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\(?\s*['"]?\d/i,
    ],
    exemplars: { positive: ["' OR '1'='1", '1 UNION SELECT NULL,NULL--', "x'; DROP TABLE users--"], benign: ['alice', '42', "o'brien", 'blue-widget', 'sleeping bag'] },
    effects: { process: 'none', network: 'none', db: 'query-structure-altered' },
  },
  'command-injection': {
    cwe: ['CWE-78', 'CWE-77', 'CWE-88'],
    behavior: 'shell metacharacters followed by a command cause the server to run an attacker-chosen command',
    matcher: 'regex',
    indicators: [
      /(?:;|\||&&|\|\||`|\$\(|%3b|%7c|%26%26|%60|%24%28|%0a|\r?\n)(?:[ \t+]|%20){0,16}(?:cat|ls|id|whoami|uname|curl|wget|nc|ncat|bash|sh|zsh|python\d?|perl|ruby|php|node|touch|rm|chmod|ping|nslookup|dig|env|printenv)(?:\b|\s|%20|\+)/i,
      /\$\{IFS\}|%24%7bIFS%7d/i,
    ],
    exemplars: { positive: ['report.pdf; cat /etc/passwd', 'a | whoami', '$(id)', 'x`uname -a`'], benign: ['report.pdf', 'quarterly summary', 'a-b_c.txt', 'cat photos', 'id'] },
    effects: { process: 'child-process-spawned', network: 'none', db: 'none' },
  },
  'path-traversal': {
    cwe: ['CWE-22', 'CWE-23', 'CWE-36', 'CWE-73'],
    behavior: 'parent-directory segments in a path parameter reach files outside the intended directory',
    matcher: 'regex',
    indicators: [/(?:^|[\\/]|%2f|%5c)\.\.(?:[\\/]|%2f|%5c|$)/i, /%2e%2e(?:[\\/]|%2f|%5c)/i, /\.\.;\//, /%252e%252e/i, /\.{3,16}[\\/]/],
    exemplars: { positive: ['../../etc/passwd', '..%2f..%2fetc%2fpasswd', '....//....//etc/passwd'], benign: ['report.pdf', 'docs/readme.txt', 'a..b.txt', 'v1.2..3'] },
    effects: { process: 'none', network: 'none', db: 'none', file: 'file-outside-root-accessed' },
  },
  ssrf: {
    cwe: ['CWE-918'],
    behavior: 'a server-side request is directed at an internal, loopback or metadata address chosen by the caller',
    matcher: 'regex',
    indicators: [
      /(?:^|[/@=:])(?:127(?:\.\d{1,3}){3}|localhost|0\.0\.0\.0|\[?::1\]?|0x7f[0-9a-f]{6}|2130706433)(?:[:/?#]|$)/i,
      /169\.254\.\d{1,3}\.\d{1,3}/,
      /(?:^|[/@=])(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})(?:[:/?#]|$)/,
      /metadata\.google\.internal|metadata\.azure\.com/i,
    ],
    exemplars: { positive: ['http://169.254.169.254/latest/meta-data/', 'http://127.0.0.1:8080/admin', 'http://localhost/'], benign: ['https://example.com/image.png', 'https://cdn.example.org/a.jpg', 'http://127.example.com.invalid/ok'] },
    effects: { process: 'none', network: 'outbound-to-internal-address', db: 'none' },
  },
  deserialization: {
    cwe: ['CWE-502'],
    behavior: 'a serialized object stream is supplied where the application deserializes request data',
    matcher: 'regex',
    indicators: [/rO0AB/, /(?:%ac|\\xac)(?:%ed|\\xed)(?:%00|\\x00)(?:%05|\\x05)/i, /gASV|gAJ[A-Za-z]/, /(?:^|[^A-Za-z0-9])O:\d{1,4}:"[A-Za-z_\\]/, /!!python\/object|!ruby\/object/i, /__reduce__|cos\\nsystem|c__builtin__/],
    exemplars: { positive: ['rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA', 'gASVKAAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjAJpZJSFlFKULg==', 'O:8:"stdClass":0:{}'], benign: ['hello world', 'Order 12345', 'rolling stones'] },
    effects: { process: 'object-graph-instantiated', network: 'none', db: 'none' },
  },
  'file-write': {
    cwe: ['CWE-434', 'CWE-646'],
    behavior: 'a file name with an executable extension or a traversal segment is accepted by a file-writing operation',
    matcher: 'regex',
    indicators: [/\.(?:php\d?|phtml|phar|jsp|jspx|aspx?|cgi|sh|exe|dll)(?:[.\s%;]|$)/i, /(?:^|[\\/]|%2f|%5c)\.\.(?:[\\/]|%2f|%5c)/i, /%00/],
    exemplars: { positive: ['shell.php', 'avatar.png.php', '../../var/www/html/x.jsp'], benign: ['photo.png', 'invoice-2024.pdf', 'notes.txt'] },
    effects: { process: 'none', network: 'none', db: 'none', file: 'file-written-by-request' },
  },
  'buffer-overflow': {
    cwe: ['CWE-120', 'CWE-121', 'CWE-122', 'CWE-787', 'CWE-125', 'CWE-119'],
    behavior: 'an input far longer than any legitimate value is supplied to a fixed-size buffer',
    matcher: 'length',
    minLength: 512,
    indicators: [],
    exemplars: { positive: ['A'.repeat(600), 'B'.repeat(4096)], benign: ['alice', 'a normal sentence of moderate length', 'x'.repeat(64)] },
    effects: { process: 'memory-corruption-possible', network: 'none', db: 'none' },
  },
  'auth-bypass': {
    cwe: ['CWE-287', 'CWE-306', 'CWE-285', 'CWE-862', 'CWE-863', 'CWE-639', 'CWE-284'],
    behavior: 'a protected operation succeeds for a request that carries no credential',
    matcher: 'behavior',
    indicators: [],
    exemplars: { positive: [''], benign: [''] },
    effects: { process: 'none', network: 'none', db: 'none', access: 'protected-operation-without-credential' },
  },
});

export const PAYLOAD_CLASS_NAMES = Object.freeze(Object.keys(PAYLOAD_CLASSES));

/** Map a CWE id (`CWE-89`, `89`, `cwe-89`) to a payload class name, or null when no class describes it. */
export function classForCwe(cwe) {
  const m = /(\d{1,5})/.exec(String(cwe ?? ''));
  if (!m) return null;
  const want = `CWE-${Number(m[1])}`;
  for (const [name, def] of Object.entries(PAYLOAD_CLASSES)) if (def.cwe.includes(want)) return name;
  return null;
}

/** Percent-decode once, tolerating malformed escapes (a hostile value must never throw here). */
function decodeOnce(value) {
  const s = String(value ?? '');
  try { return decodeURIComponent(s.replace(/\+/g, ' ')); } catch { return s; }
}

/**
 * Does `value` look like an exploit of `className`? Checks the raw and the once-decoded form, so an encoded payload and a
 * plain one are treated alike. `behavior` classes have no value test: they match on request behavior, not content.
 */
export function matchesClass(className, value) {
  const def = PAYLOAD_CLASSES[className];
  if (!def || def.matcher === 'behavior') return false;
  const raw = String(value ?? '').slice(0, 65536);
  const forms = raw === decodeOnce(raw) ? [raw] : [raw, decodeOnce(raw)];
  if (def.matcher === 'length') return forms.some((f) => f.length >= def.minLength);
  return forms.some((f) => def.indicators.some((re) => re.test(f)));
}
