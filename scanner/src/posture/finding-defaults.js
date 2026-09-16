// Premortem #8: backfill the `parser` and `family` fields on every finding.
//
// Symptom this fixes: a smoke run on test/fixtures/vulnerable-js reported 31
// findings, all with `parser: null` — which silenced the PARSER_PRIOR boost in
// confidence.js, AND 20/31 had `family: null` — which silenced the entire
// calibration table in calibration.js. The annotation pipeline downstream
// expected these fields to be set by every detector, but most regex-style
// detectors emit a plain Finding shape without them.
//
// We backfill, never overwrite. Detector-set values win.

// Lightweight family inference. CWE-based first, then title/vuln keyword.
const _CWE_FAMILY = {
  'CWE-78':  'command-injection',
  'CWE-79':  'xss',
  'CWE-80':  'xss',
  'CWE-87':  'xss',
  'CWE-89':  'sql-injection',
  'CWE-90':  'ldap-injection',
  'CWE-91':  'xpath-injection',
  'CWE-94':  'code-injection',
  'CWE-95':  'code-injection',
  'CWE-98':  'code-injection',
  'CWE-22':  'path-traversal',
  'CWE-23':  'path-traversal',
  'CWE-36':  'path-traversal',
  'CWE-200': 'info-disclosure',
  'CWE-209': 'info-disclosure',
  'CWE-134': 'format-string',
  'CWE-256': 'hardcoded-secret',
  'CWE-259': 'hardcoded-secret',
  'CWE-287': 'broken-auth',
  'CWE-295': 'cert-validation',
  'CWE-306': 'broken-auth',
  'CWE-307': 'rate-limit',
  'CWE-326': 'weak-crypto',
  'CWE-327': 'weak-crypto',
  'CWE-328': 'weak-crypto',
  'CWE-329': 'weak-crypto',
  'CWE-330': 'weak-rng',
  'CWE-338': 'weak-rng',
  'CWE-345': 'integrity',
  'CWE-352': 'csrf',
  'CWE-384': 'session-fixation',
  'CWE-434': 'unrestricted-upload',
  'CWE-470': 'code-injection',
  'CWE-502': 'insecure-deserialization',
  'CWE-601': 'open-redirect',
  'CWE-611': 'xxe',
  'CWE-639': 'idor',
  'CWE-640': 'broken-auth',
  'CWE-732': 'permissions',
  'CWE-770': 'rate-limit',
  'CWE-776': 'xxe',
  'CWE-798': 'hardcoded-secret',
  'CWE-829': 'supply-chain',
  'CWE-862': 'missing-authz',
  'CWE-863': 'broken-authz',
  'CWE-915': 'mass-assignment',
  'CWE-918': 'ssrf',
  'CWE-1004': 'cookie-flag',
  'CWE-1021': 'clickjacking',
  'CWE-1287': 'idor',
  'CWE-1321': 'prototype-pollution',
  'CWE-1333': 'redos',
};

const _KEYWORD_FAMILY = [
  [/sql\s*injection/i,       'sql-injection'],
  [/command\s*injection/i,   'command-injection'],
  [/code\s*injection|eval|insecure\s*eval/i, 'code-injection'],
  [/cross[-\s]?site\s*scripting|\bxss\b/i,    'xss'],
  [/path\s*traversal|directory\s*traversal/i, 'path-traversal'],
  [/server[-\s]?side\s*request\s*forgery|\bssrf\b/i, 'ssrf'],
  [/cross[-\s]?site\s*request\s*forgery|\bcsrf\b/i,  'csrf'],
  [/open\s*redirect/i,       'open-redirect'],
  [/\bxxe\b|external\s*entity/i, 'xxe'],
  [/\bidor\b|insecure\s*direct\s*object/i, 'idor'],
  [/mass[-\s]?assignment|over[-\s]?posting/i, 'mass-assignment'],
  [/prototype\s*pollution/i, 'prototype-pollution'],
  [/deserialization|deserialize/i, 'insecure-deserialization'],
  [/weak\s*(?:crypto|hash|cipher)|\bmd5\b|\bsha1\b|\brc4\b/i, 'weak-crypto'],
  [/weak\s*rng|insecure\s*random|math\.random/i, 'weak-rng'],
  [/hardcoded\s*(?:secret|credential|key|password|token)|secret\s*in\s*code/i, 'hardcoded-secret'],
  [/jwt|json\s*web\s*token/i, 'broken-auth'],
  [/jndi/i,                  'jndi-injection'],
  [/log\s*injection|log4shell/i, 'log-injection'],
  [/insecure\s*http|http\s*without\s*tls|missing\s*https/i, 'insecure-http'],
  [/host\s*header/i,         'host-header'],
  [/rate[-\s]?limit/i,       'rate-limit'],
  [/vulnerable\s*dependency|cve-\d{4}-\d+|known\s*vulnerable\s*component/i, 'vulnerable-dep'],
  [/prompt\s*injection|llm\s*injection/i, 'prompt-injection'],
  [/clickjacking|x-frame-options/i, 'clickjacking'],
  [/zip[-\s]?slip/i,         'path-traversal'],
];

function _inferFamily(f) {
  if (!f || typeof f !== 'object') return null;
  if (typeof f.family === 'string' && f.family.length) return f.family;
  if (typeof f.cwe === 'string' && _CWE_FAMILY[f.cwe]) return _CWE_FAMILY[f.cwe];
  const hay = `${f.vuln || ''} ${f.title || ''} ${f.description || ''}`.slice(0, 600);
  for (const [re, fam] of _KEYWORD_FAMILY) {
    if (re.test(hay)) return fam;
  }
  return null;
}

function _inferParser(f) {
  if (!f || typeof f !== 'object') return 'REGEX';
  if (typeof f.parser === 'string' && f.parser.length) return f.parser;
  // SCA findings carry pkg/component/purl; tag them so triage and validator
  // can short-circuit (LLM validator already special-cases parser SCA).
  if (f.parser === 'SCA' || f.kind === 'sca' ||
      typeof f.pkg === 'string' || typeof f.component === 'string' ||
      typeof f.purl === 'string') return 'SCA';
  if (f.custom === true) return 'CUSTOM_RULE';
  // Findings carrying a source/sink chain are layer-2 taint outputs.
  if (Array.isArray(f.chain) && f.chain.length && f.source && f.sink) return 'IR-TAINT';
  // AST-driven detectors mark themselves; fall back to REGEX otherwise.
  return 'REGEX';
}

export function backfillFindingDefaults(findings) {
  if (!Array.isArray(findings)) return;
  for (const f of findings) {
    if (!f || typeof f !== 'object') continue;
    if (!f.parser) f.parser = _inferParser(f);
    if (!f.family) {
      const fam = _inferFamily(f);
      if (fam) f.family = fam;
    }
  }
}

// Exported for tests.
export const _internals = { _CWE_FAMILY, _KEYWORD_FAMILY, _inferFamily, _inferParser };
