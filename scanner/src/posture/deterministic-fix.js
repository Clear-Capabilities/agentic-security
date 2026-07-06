// Deterministic fix synthesis (#1) — for the narrow set of vulnerability classes
// where a context-INDEPENDENT literal swap is a safe, correct fix, produce a
// full-file replacement from the current file content. No LLM, no guessing, no
// per-finding bloat in last-scan.json (the patch is materialized on demand by
// synthesize_fix from the live file, not stored on every finding).
//
// Safety: every patch this produces is still gated by verify_fix before apply_fix
// writes it (original finding gone + no new ≥medium + lint clean). So a swap that
// a rule mis-attributed simply fails verification instead of landing a bad edit —
// this module widens the deterministic-fix surface without weakening the gate.
//
// Returns { patch: { [relFile]: newContent }, ruleId } or null when no
// deterministic fix applies to the finding.

const JS_EXT = /\.(?:js|jsx|ts|tsx|mjs|cjs)$/i;
const PY_EXT = /\.py$/i;

// Each rule gates on the finding's cwe/family, then rewrites the whole-file
// content. transform() returns the new content, or null when nothing changed
// (e.g. the vulnerable token isn't literally present — then we don't claim a fix).
const RULES = [
  {
    id: 'weak-hash-sha256',
    // md5 / sha1 → sha256. Every occurrence in the file is a weak hash, so
    // swapping them all is safe; the verifier confirms the weak-hash finding is
    // gone and nothing worse appeared.
    applies: (f) => /CWE-(?:327|328|916)/.test(f.cwe || '') || /weak.?hash/i.test(f.family || ''),
    transform: (content, file) => {
      let out = content;
      if (JS_EXT.test(file)) {
        out = out.replace(/(\bcreateHash\s*\(\s*['"`])(?:md5|sha1)(['"`])/gi, '$1sha256$2');
      } else if (PY_EXT.test(file)) {
        out = out.replace(/\bhashlib\.(?:md5|sha1)\s*\(/g, 'hashlib.sha256(');
      }
      return out !== content ? out : null;
    },
  },
  {
    id: 'tls-verify-on',
    // Disabled TLS verification → enabled. rejectUnauthorized:false → true (JS),
    // verify=False → verify=True (Python requests).
    applies: (f) => /CWE-295/.test(f.cwe || '') || /tls.?no.?verify|cert.?(?:none|verify)/i.test(f.family || ''),
    transform: (content, file) => {
      let out = content;
      if (JS_EXT.test(file)) {
        out = out.replace(/(\brejectUnauthorized\s*:\s*)false\b/g, '$1true');
      } else if (PY_EXT.test(file)) {
        out = out.replace(/(\bverify\s*=\s*)False\b/g, '$1True');
      }
      return out !== content ? out : null;
    },
  },
];

export function synthesizeDeterministicPatch(finding, fileContent) {
  if (!finding || typeof fileContent !== 'string' || !finding.file) return null;
  for (const rule of RULES) {
    try {
      if (!rule.applies(finding)) continue;
      const next = rule.transform(fileContent, finding.file);
      if (next && next !== fileContent) return { patch: { [finding.file]: next }, ruleId: rule.id };
    } catch { /* a single rule failing must never break synthesis */ }
  }
  return null;
}
