// Privacy data-classification taxonomy (assurance-hardening PRD FR-402).
//
// `privacy-taint.js` used to carry a single hardcoded PII_PATTERNS const
// with exactly four buckets (PII/PHI/PCI/FIN) and no version — extending it
// (a new regulated-data class, a missed field-name pattern for an existing
// class) meant editing this package's source. FR-402's acceptance criterion
// is specifically that the taxonomy is versioned AND customizable without a
// source change, so this module splits the taxonomy out as data:
//
//   - DEFAULT_TAXONOMY ships the seven classes the PRD names by name (PII,
//     PHI, PCI, FIN, CREDENTIALS, GEOLOCATION, DEVICE_ID), each carrying a
//     default severity and a list of field-name regex patterns.
//   - loadPrivacyTaxonomy(scanRoot) reads an OPTIONAL operator config at
//     .agentic-security/privacy-taxonomy.json and merges it over the
//     defaults: a class name that already exists gets its patterns
//     APPENDED (mode:'extend', the default) or REPLACED (mode:'replace');
//     a class name that doesn't exist is added as a brand-new
//     organization-defined class. No scanner source file is touched by
//     either path.
//
// Degrades the same way every other operator-config reader in this
// codebase does (see posture/network-policy-import.js, custom-rules.js):
// a missing file returns the built-in taxonomy unchanged; a malformed one
// logs a warning and falls back to the built-in taxonomy rather than
// throwing and aborting the scan.

import * as fs from 'node:fs';
import { statePath } from '../posture/state-dir.js';

export const BUILTIN_TAXONOMY_VERSION = '1.0.0';

// Severity ranking used to pick the worst-case severity when a single
// field/finding matches more than one class (e.g. a "ssn_and_password"
// field matching both PII and CREDENTIALS).
export const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1 };

export const DEFAULT_TAXONOMY = Object.freeze({
  PII: {
    severity: 'medium',
    patterns: [
      '\\bfirst[_-]?name\\b', '\\blast[_-]?name\\b', '\\bfull[_-]?name\\b',
      '\\bemail([_-]?address)?\\b', '\\bphone([_-]?number)?\\b', '\\bmobile\\b',
      '\\baddress(?:_?(?:line|street|city|zip|postal))?\\b',
      '\\bdob\\b', '\\bdate[_-]?of[_-]?birth\\b', '\\bbirthday\\b', '\\bbirthdate\\b',
      '\\bage\\b', '\\bgender\\b', '\\bethnicity\\b', '\\brace\\b', '\\bnationality\\b',
      '\\bssn\\b', '\\bsocial[_-]?security', '\\bnational[_-]?id', '\\bpassport\\b',
      '\\bdriver[_-]?license\\b', '\\btax[_-]?id\\b', '\\bgovernment[_-]?id\\b',
      '\\bip[_-]?address\\b',
    ],
  },
  PHI: {
    severity: 'high',
    patterns: [
      '\\b(?:medical|patient|health)[_-]?record\\b',
      '\\bdiagnosis\\b', '\\bcondition\\b', '\\bsymptom\\b', '\\btreatment\\b',
      '\\bmedication\\b', '\\bprescription\\b', '\\bdosage\\b',
      '\\bicd[_-]?(?:9|10|11)\\b', '\\bcpt[_-]?code\\b', '\\bmrn\\b',
      '\\bmedical[_-]?record[_-]?number\\b', '\\bdoctor[_-]?name\\b',
      '\\bphysician\\b', '\\binsurance[_-]?id\\b', '\\bhealth[_-]?plan\\b',
    ],
  },
  PCI: {
    severity: 'high',
    patterns: [
      '\\bcredit[_-]?card[_-]?(?:number|num|no)?\\b',
      '\\bcard[_-]?(?:number|num|no)\\b',
      '\\b(?:cvc|cvv)2?\\b', '\\bcvc[_-]?code\\b',
      '\\bexp(?:iry|iration)?(?:_?date)?\\b',
      '\\bcardholder[_-]?name\\b', '\\bpan\\b',
      '\\biban\\b', '\\brouting[_-]?number\\b',
      '\\baccount[_-]?number\\b',
    ],
  },
  FIN: {
    severity: 'medium',
    patterns: [
      '\\bsalary\\b', '\\bincome\\b', '\\bbalance\\b', '\\btransaction[_-]?amount\\b',
      '\\bbank[_-]?account\\b',
      '\\bcredit[_-]?score\\b', '\\bnet[_-]?worth\\b',
    ],
  },
  CREDENTIALS: {
    severity: 'critical',
    patterns: [
      '\\bpassword\\b', '\\bpasswd\\b', '\\bapi[_-]?key\\b', '\\bsecret[_-]?key\\b',
      '\\baccess[_-]?token\\b', '\\brefresh[_-]?token\\b', '\\bauth[_-]?token\\b',
      '\\bprivate[_-]?key\\b', '\\bclient[_-]?secret\\b', '\\bsession[_-]?token\\b',
      '\\bsecurity[_-]?answer\\b', '\\bpin[_-]?code\\b',
    ],
  },
  GEOLOCATION: {
    severity: 'medium',
    patterns: [
      '\\bgeo[_-]?location\\b', '\\blatitude\\b', '\\blongitude\\b',
      '\\bgps[_-]?coord(?:inates?)?\\b', '\\bprecise[_-]?location\\b',
      '\\bcurrent[_-]?location\\b',
    ],
  },
  DEVICE_ID: {
    severity: 'low',
    patterns: [
      '\\bdevice[_-]?id\\b', '\\bimei\\b', '\\budid\\b', '\\bmac[_-]?address\\b',
      '\\badvertising[_-]?id\\b', '\\bidfa\\b', '\\bandroid[_-]?id\\b',
    ],
  },
});

function _taxonomyStatePath(scanRoot) {
  return statePath(scanRoot, 'privacy-taxonomy.json');
}

/**
 * Compile a taxonomy (class -> {severity, patterns: string[]}) into
 * class -> {severity, regexes: RegExp[]} for repeated use across a scan.
 */
export function compileTaxonomy(taxonomy) {
  const compiled = {};
  for (const [cls, def] of Object.entries(taxonomy || {})) {
    const patterns = Array.isArray(def?.patterns) ? def.patterns : [];
    const regexes = [];
    for (const p of patterns) {
      try { regexes.push(new RegExp(p, 'i')); } catch { /* skip an invalid operator-supplied pattern */ }
    }
    compiled[cls] = { severity: def?.severity || 'medium', regexes };
  }
  return compiled;
}

const _BUILTIN_COMPILED = compileTaxonomy(DEFAULT_TAXONOMY);

/**
 * Merge an operator-supplied taxonomy config over DEFAULT_TAXONOMY.
 * Never mutates DEFAULT_TAXONOMY. `raw.classes[name].mode` controls how an
 * existing class is merged: 'extend' (default) appends patterns to the
 * built-in list; 'replace' discards the built-in patterns for that class.
 * A class name not present in DEFAULT_TAXONOMY is added as-is (a new
 * organization-defined class) and defaults to severity 'medium' if unset.
 */
function _mergeTaxonomy(raw) {
  const merged = {};
  for (const [cls, def] of Object.entries(DEFAULT_TAXONOMY)) {
    merged[cls] = { severity: def.severity, patterns: [...def.patterns] };
  }
  const classes = raw && typeof raw.classes === 'object' && raw.classes ? raw.classes : {};
  let customized = false;
  for (const [cls, def] of Object.entries(classes)) {
    const patterns = Array.isArray(def?.patterns) ? def.patterns.filter(p => typeof p === 'string') : [];
    if (!patterns.length) continue;
    customized = true;
    const existing = merged[cls];
    if (existing && def?.mode !== 'replace') {
      merged[cls] = {
        severity: typeof def?.severity === 'string' ? def.severity : existing.severity,
        patterns: [...existing.patterns, ...patterns],
      };
    } else {
      merged[cls] = {
        severity: typeof def?.severity === 'string' ? def.severity : (existing?.severity || 'medium'),
        patterns,
      };
    }
  }
  return { taxonomy: merged, customized };
}

/**
 * Load the effective privacy taxonomy for a scan: the built-in defaults,
 * merged with .agentic-security/privacy-taxonomy.json when present. Never
 * throws — a missing file returns the built-in taxonomy; a malformed one
 * logs a warning and falls back to the built-in taxonomy untouched.
 *
 * Returns { version, taxonomy, compiled, customized }.
 */
export function loadPrivacyTaxonomy(scanRoot) {
  if (!scanRoot) {
    return { version: BUILTIN_TAXONOMY_VERSION, taxonomy: DEFAULT_TAXONOMY, compiled: _BUILTIN_COMPILED, customized: false };
  }
  const fp = _taxonomyStatePath(scanRoot);
  // Read-first, not existsSync()-then-readFileSync() — the file can vanish
  // between those two calls (TOCTOU). ENOENT is the expected "no config"
  // case and degrades silently; anything else (bad JSON, permission
  // denied) logs a warning and falls back the same way.
  let raw = null;
  try {
    raw = JSON.parse(fs.readFileSync(fp, 'utf8'));
  } catch (e) {
    if (e.code !== 'ENOENT') {
      console.error(`agentic-security: bad JSON in privacy-taxonomy.json — falling back to the built-in taxonomy (${e.message})`);
    }
    raw = null;
  }
  if (!raw) {
    return { version: BUILTIN_TAXONOMY_VERSION, taxonomy: DEFAULT_TAXONOMY, compiled: _BUILTIN_COMPILED, customized: false };
  }
  const { taxonomy, customized } = _mergeTaxonomy(raw);
  const version = typeof raw.taxonomyVersion === 'string' && raw.taxonomyVersion
    ? raw.taxonomyVersion
    : (customized ? `${BUILTIN_TAXONOMY_VERSION}+custom` : BUILTIN_TAXONOMY_VERSION);
  return { version, taxonomy, compiled: compileTaxonomy(taxonomy), customized };
}

/**
 * Classify a field/variable name against a compiled taxonomy (see
 * compileTaxonomy). Returns an array of matched class names, in the
 * taxonomy's own key order — defaults to the built-in taxonomy when none
 * is supplied, so existing callers with a single argument are unaffected.
 */
export function classifyFieldAgainst(name, compiled) {
  if (!name) return [];
  const out = [];
  for (const [cls, def] of Object.entries(compiled || _BUILTIN_COMPILED)) {
    for (const re of def.regexes) {
      if (re.test(name)) { out.push(cls); break; }
    }
  }
  return out;
}

/**
 * Worst-case (highest) severity among a set of matched class names, per
 * the given compiled taxonomy. Falls back to 'medium' for an empty or
 * unrecognized class list — same default the pre-FR-402 code used.
 */
export function severityForClasses(classes, compiled) {
  const table = compiled || _BUILTIN_COMPILED;
  let best = null;
  for (const cls of classes || []) {
    const sev = table[cls]?.severity;
    if (!sev) continue;
    if (!best || (SEVERITY_RANK[sev] || 0) > (SEVERITY_RANK[best] || 0)) best = sev;
  }
  return best || 'medium';
}
