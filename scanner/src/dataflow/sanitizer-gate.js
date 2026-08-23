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
//
// CWE-22 (path traversal) maps to the catalog's real 'path' family
// (py-pathlib-resolve / cs-path-getfullpath / kt-path-canonical, all
// appliesTo:['path']) — it used to collapse to 'url' alongside CWE-918/601,
// which meant those genuine path-containment sanitizers could never match a
// CWE-22 finding at all (permanently inert gate for that CWE), AND any
// url-family sanitizer (URL-percent-encoding: encodeURIComponent etc.)
// satisfied the family check for CWE-22/918/601 findings even though
// percent-encoding neutralizes none of them. SSRF (CWE-918) and open
// redirect (CWE-601) are host/scheme allow-list problems, not encoding
// problems, and the catalog has no dedicated family for either — mapping
// them to a family with zero real catalog matches (rather than borrowing
// 'url') means this gate correctly never fires for them, leaving that
// containment to engine.js's separate dropGuardedFindings host-allowlist
// recognition instead of a false "proven clean" from an unrelated encoder.
const _CWE_FAMILY = {
  'CWE-89': 'sql',
  'CWE-79': 'xss',
  'CWE-78': 'cmd',
  'CWE-22': 'path',
  'CWE-918': 'ssrf-host-allowlist-only',   // no catalog family — see above
  'CWE-601': 'redirect-allowlist-only',    // no catalog family — see above
};

const _TEXT_FAMILY = [
  [/sql/i, 'sql'],
  [/xss|cross-site scripting/i, 'xss'],
  [/command injection/i, 'cmd'],
  [/path traversal/i, 'path'],
  // No catalog family for ssrf/redirect — deliberately no fallback entry
  // (see the _CWE_FAMILY comment above); familyOfFinding returns null and
  // applySanitizerGate's `if (!fam) continue;` safely no-ops.
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
// Functions that UNDO an encoding, keyed by the family they reverse.
//
// The gate labelled a flow `sanitized` whenever a matching sanitizer appeared
// on the path, with no notion that a later call could reverse it. Measured by
// bench/mutation: `he.decode(escapeHtml(req.query.name))` reaching an HTML sink
// was reported as SANITIZED — a missed XSS, because the decode puts back
// exactly what the escape took out.
//
// Family-keyed, not a flat list, because reversal is family-specific:
// `decodeURIComponent` undoes percent-encoding and does nothing at all to HTML
// entities, so treating it as a universal un-sanitizer would throw away correct
// sanitization claims.
//
// A match REFUSES the label rather than removing a finding. That is the safe
// direction: the cost of being wrong here is a finding kept at full confidence
// (a possible false positive), while the cost of the previous behaviour was a
// real vulnerability reported as clean.
const _UNSANITIZERS = {
  xss: new Set([
    'unescape', 'unescapeHtml', 'unescapeHtml3', 'unescapeHtml4',
    'StringEscapeUtils.unescapeHtml3', 'StringEscapeUtils.unescapeHtml4',
    'he.decode', 'entities.decode', 'html.decode', 'htmlparser2.decodeHTML',
    'decodeHTML', 'decodeHTMLStrict', 'decodeEntities',
    'html.unescape', 'html_entity_decode', 'htmlspecialchars_decode',
    '_.unescape', 'lodash.unescape',
  ]),
  url: new Set([
    'decodeURI', 'decodeURIComponent', 'unquote', 'unquote_plus',
    'URLDecoder.decode', 'urldecode', 'querystring.unescape',
  ]),
  // sql / cmd / path have no encoding to reverse in the same sense: their
  // sanitizers parameterise or canonicalise rather than encode, and there is no
  // inverse call. Deliberately absent rather than guessed at.
};

/** Does any callee observed on this path undo the sanitization claimed for `fam`? */
export function _reversedOnPath(observed, fam) {
  const undoers = _UNSANITIZERS[fam];
  if (!undoers) return null;
  for (const name of observed) {
    if (undoers.has(name)) return name;
    // A member call may be recorded bare. Only accept a leaf that is
    // unambiguous on its own — `decode` alone is not (jwt.decode, base64
    // decode), and matching it would void correct claims.
    const leaf = String(name).split('.').pop();
    if (leaf !== name && undoers.has(leaf) && leaf !== 'decode') return name;
  }
  return null;
}

export function applySanitizerGate(findings, ctx) {
  const list = Array.isArray(findings) ? findings : [];
  const onPath = (ctx && ctx.sanitizersOnPath) || null;
  const undoPath = (ctx && ctx.unsanitizersOnPath) || {};
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
    // A reversal anywhere on the path voids the claim. Order is not consulted:
    // `sanitizersOnPath` is a set of observed callees, and a decode that
    // precedes the escape is not a shape worth modelling separately when the
    // conservative answer — refuse the label — is also the safe one.
    const undone = undoPath[f.id] || undoPath[f.stableId] || [];
    const reversedBy = _reversedOnPath(undone, fam);
    if (reversedBy) {
      f.sanitizerReversedBy = reversedBy;
      continue;
    }
    // Label only. The proof gate decides what to do with the label.
    f.sanitized = true;
    f.sanitizerProof = { sanitizers: matching, family: fam };
  }
  return list;
}
