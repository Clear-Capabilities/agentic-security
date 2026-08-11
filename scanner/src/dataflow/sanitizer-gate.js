// Generalised, recall-preserving sanitizer gate.
//
// The catalog carries 381 sanitizer entries (all languages, all kinds; count
// via CATALOG.filter(e => e.kind === 'sanitizer').length — re-derive rather
// than trust a hardcoded number here, since this comment has been wrong
// before) tagged by family via `appliesTo` (sql, xss, url, cmd, *, …). Before
// this module only `appliesTo: ['sql']` was ever consumed — by
// proven-clean.js — so a correctly sanitized xss/url/cmd flow was still
// reported at full confidence. That is a pure false-positive source.
//
// This gate NEVER removes a finding. It sets `sanitized` plus a proof object and
// lets the existing proof gate in engine.js do the demotion, exactly as
// proven-clean.js does. That matters because a mislabelled sanitizer would
// otherwise hide a real vulnerability: the C/C++ work found strncpy and snprintf
// tagged effect:'strip' when they bound length rather than sanitising content.

import { CATALOG } from './catalog.js';

// Map a finding to a sanitizer family using its CWE first (stable) and its vuln
// text second (human-authored, so only a fallback).
const _CWE_FAMILY = {
  'CWE-89': 'sql',
  'CWE-79': 'xss',
  'CWE-78': 'cmd',
  'CWE-22': 'url',
  'CWE-918': 'url',
  'CWE-601': 'url',
};

const _TEXT_FAMILY = [
  [/sql/i, 'sql'],
  [/xss|cross-site scripting/i, 'xss'],
  [/command injection/i, 'cmd'],
  [/path traversal|ssrf|redirect/i, 'url'],
];

export function familyOfFinding(f) {
  if (!f) return null;
  if (f.cwe && _CWE_FAMILY[f.cwe]) return _CWE_FAMILY[f.cwe];
  const text = `${f.vuln || ''} ${f.family || ''}`;
  for (const [re, fam] of _TEXT_FAMILY) if (re.test(text)) return fam;
  return null;
}

// callee name → set of families it sanitizes, built once from the catalog.
let _index = null;
function _sanitizerIndex() {
  if (_index) return _index;
  _index = new Map();
  for (const e of CATALOG) {
    if (!e || e.kind !== 'sanitizer') continue;
    const callee = e.match && e.match.type === 'call' ? e.match.callee : null;
    if (!callee) continue;
    const fams = Array.isArray(e.appliesTo) ? e.appliesTo : [];
    const cur = _index.get(callee) || new Set();
    for (const f of fams) cur.add(f);
    _index.set(callee, cur);
  }
  return _index;
}

export function _sanitizerFamilies() {
  const out = new Set();
  for (const fams of _sanitizerIndex().values()) for (const f of fams) out.add(f);
  return [...out].sort();
}

// ctx.sanitizersOnPath: { [findingId]: string[] } — callee names observed on the
// flow that produced the finding. The engine supplies it; when absent the gate
// is a no-op, which keeps this safe to call unconditionally.
export function applySanitizerGate(findings, ctx) {
  const list = Array.isArray(findings) ? findings : [];
  const onPath = (ctx && ctx.sanitizersOnPath) || null;
  if (!onPath) return list;
  const index = _sanitizerIndex();

  for (const f of list) {
    const fam = familyOfFinding(f);
    if (!fam) continue;
    const observed = onPath[f.id] || onPath[f.stableId];
    if (!Array.isArray(observed) || !observed.length) continue;
    const matching = observed.filter(name => {
      const fams = index.get(name);
      // `*` is the catalog's universal tag, carried by the 17 type-coercion
      // entries (parseInt/intval/Atoi/TryParse/…) that neutralise every
      // injection family by making the value non-stringy. Matching it
      // literally against 'sql'/'xss' never succeeds, which left that whole
      // tier inert.
      return fams && (fams.has(fam) || fams.has('*'));
    });
    if (!matching.length) continue;
    // Label only. The proof gate decides what to do with the label.
    f.sanitized = true;
    f.sanitizerProof = { sanitizers: matching, family: fam };
  }
  return list;
}
