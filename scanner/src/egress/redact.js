// Outbound-payload content redaction (assurance-hardening PRD FR-603).
//
// policy.js decides WHETHER a call is allowed to leave the machine at all.
// This module decides WHAT is allowed to be IN the payload once a call is
// already permitted — the content-level companion to that call-level gate.
// Both read the same operator config (egress-policy.yml) via
// policy.js's exported loadPolicyConfig, so there is one config surface
// for the whole egress epic rather than a second file for redaction.
//
// Four categories, applied in a fixed order so an earlier, more specific
// pass never fights a later, more general one over the same span (mirrors
// llm-validator/redact.js's own most-specific-first rationale):
//
//   1. Proprietary paths — an operator-listed glob (`proprietaryPaths`)
//      whose CONTENT must never leave at all, matched via util/glob.js's
//      matchesAnyGlob (reused, not reimplemented — the same matcher FR-602
//      uses for egress-policy.yml's deniedPaths/allowedPaths). Whole-span
//      replacement, not a substring redaction, and it short-circuits every
//      other pass — there is nothing left to redact once the whole thing
//      is gone.
//   2. Secrets — reuses llm-validator/redact.js's redactSecrets VERBATIM
//      (the proven, independently-tested implementation described there;
//      not reimplemented here). That module's own header already noted
//      this was "already partially done ... for its own path only" before
//      this cycle — this module is what makes it reachable beyond that one
//      caller as a named, general capability.
//   3. PII/PHI/PCI/FIN — reuses dataflow/privacy-taxonomy.js's field-name
//      vocabulary (FR-402) as the single source of truth for "what counts
//      as PII" across the codebase, applied with the same
//      `name(:|=)"value"` shape llm-validator/redact.js's KEY_VALUE_RE
//      already proved works for secrets. The CREDENTIALS class is skipped
//      here — pass 2 already owns that category via redactSecrets, and
//      redacting it twice under two different placeholder names would be
//      confusing without adding any actual protection.
//   4. Customer data — organization-defined only. egress-policy.yml's
//      `customerDataPatterns` (raw regex strings, operator-authored). No
//      built-in default: unlike PII, "customer data" has no generic shape
//      the harness could safely guess (an internal account-number format,
//      a tenant-naming scheme, ...) — this category is a no-op until an
//      operator configures it, by design.
//
// Returns { text, redactions, categories: {...} } so a caller can report
// HOW MUCH was removed per category (FR-604's audit metadata wants exactly
// this: counts, not content) without retaining what was actually removed.

import { loadPolicyConfig } from './policy.js';
import { redactSecrets } from '../llm-validator/redact.js';
import { loadPrivacyTaxonomy } from '../dataflow/privacy-taxonomy.js';
import { matchesAnyGlob } from '../util/glob.js';

const PROPRIETARY_PLACEHOLDER = '[REDACTED-PROPRIETARY-CONTENT]';
const PII_PLACEHOLDER = '[REDACTED-PII]';
const CUSTOMER_DATA_PLACEHOLDER = '[REDACTED-CUSTOMER-DATA]';

/**
 * Build one `name(:|=)"value"` regex per taxonomy class (excluding
 * CREDENTIALS — see module header). Mirrors llm-validator/redact.js's
 * KEY_VALUE_RE shape exactly, generalized to an arbitrary field-name
 * pattern list instead of a fixed word list.
 */
function _buildPiiKeyValueRegexes(taxonomy) {
  const regexes = [];
  for (const [cls, def] of Object.entries(taxonomy || {})) {
    if (cls === 'CREDENTIALS') continue;
    const patterns = Array.isArray(def?.patterns) ? def.patterns : [];
    if (!patterns.length) continue;
    let re;
    try {
      // Named groups, not positional (\1/\2/\3) — several taxonomy field
      // patterns carry their OWN capturing group (e.g. PII's
      // `email([_-]?address)?`), which would silently shift every
      // positional backreference below it. \k<quote> sidesteps that
      // entirely regardless of how many groups the alternation contains.
      re = new RegExp(
        '(?<keyName>' + patterns.join('|') + ')(?<opWs>\\s*[:=]\\s*)(?<quote>[\'"`])(?<value>[^\'"`]+)\\k<quote>',
        'gi'
      );
    } catch {
      continue; // an operator-supplied pattern (privacy-taxonomy.json) can be invalid regex
    }
    regexes.push(re);
  }
  return regexes;
}

/**
 * Redact PII/PHI/PCI/FIN-shaped `key: "value"` / `key = "value"` spans.
 * taxonomy defaults to the built-in DEFAULT_TAXONOMY when not supplied.
 */
export function redactPii(text, { taxonomy } = {}) {
  if (typeof text !== 'string' || text.length === 0) {
    return { text: typeof text === 'string' ? text : '', redactions: 0 };
  }
  const effectiveTaxonomy = taxonomy || loadPrivacyTaxonomy(null).taxonomy;
  let out = text;
  let redactions = 0;
  for (const re of _buildPiiKeyValueRegexes(effectiveTaxonomy)) {
    out = out.replace(re, (...args) => {
      const groups = args[args.length - 1];
      redactions++;
      return `${groups.keyName}${groups.opWs}${groups.quote}${PII_PLACEHOLDER}${groups.quote}`;
    });
  }
  return { text: out, redactions };
}

/** Redact organization-defined customer-data patterns. No-op with no patterns configured. */
export function redactCustomerData(text, { patterns = [] } = {}) {
  if (typeof text !== 'string' || text.length === 0 || !patterns.length) {
    return { text: typeof text === 'string' ? text : '', redactions: 0 };
  }
  let out = text;
  let redactions = 0;
  for (const p of patterns) {
    let re;
    try { re = new RegExp(p, 'gi'); } catch { continue; } // invalid operator-supplied regex — skip, don't throw
    out = out.replace(re, () => { redactions++; return CUSTOMER_DATA_PLACEHOLDER; });
  }
  return { text: out, redactions };
}

/** True when filePath matches an operator-configured proprietary-path glob. */
export function isProprietaryPath(filePath, { proprietaryPaths = [] } = {}) {
  if (!filePath || !proprietaryPaths.length) return false;
  return matchesAnyGlob(filePath, proprietaryPaths);
}

/**
 * Apply the full redaction pipeline to one span of outbound prompt text.
 *
 * @param {object} opts
 * @param {string} opts.text - the text about to be sent to a model endpoint.
 * @param {string} [opts.filePath] - the source file this text was drawn
 *   from, if any — evaluated against `proprietaryPaths`.
 * @param {string} [opts.scanRoot] - project root, for reading
 *   egress-policy.yml when `policy` is not already supplied.
 * @param {object} [opts.taxonomy] - a pre-loaded privacy taxonomy (avoids
 *   re-reading privacy-taxonomy.json per call in a hot loop); defaults to
 *   loadPrivacyTaxonomy(scanRoot).taxonomy.
 * @param {object} [opts.policy] - a pre-loaded egress-policy.yml document
 *   (avoids re-reading it per call); defaults to loadPolicyConfig(scanRoot).
 * @returns {{text: string, redactions: number, categories: {proprietaryPath: number, secrets: number, pii: number, customerData: number}}}
 */
export function redactPayload({ text, filePath = null, scanRoot = null, taxonomy = null, policy = null } = {}) {
  const categories = { proprietaryPath: 0, secrets: 0, pii: 0, customerData: 0 };
  if (typeof text !== 'string' || text.length === 0) {
    return { text: typeof text === 'string' ? text : '', redactions: 0, categories };
  }

  const cfg = policy || loadPolicyConfig(scanRoot) || {};
  const proprietaryPaths = Array.isArray(cfg.proprietaryPaths) ? cfg.proprietaryPaths : [];
  if (isProprietaryPath(filePath, { proprietaryPaths })) {
    categories.proprietaryPath = 1;
    return { text: PROPRIETARY_PLACEHOLDER, redactions: 1, categories };
  }

  let out = text;

  const secretResult = redactSecrets(out);
  out = secretResult.text;
  categories.secrets = secretResult.redactions;

  const piiEnabled = cfg.redactPii !== false; // default ON — this category has a safe built-in default, unlike customerDataPatterns
  if (piiEnabled) {
    const effectiveTaxonomy = taxonomy || loadPrivacyTaxonomy(scanRoot).taxonomy;
    const piiResult = redactPii(out, { taxonomy: effectiveTaxonomy });
    out = piiResult.text;
    categories.pii = piiResult.redactions;
  }

  const customerDataPatterns = Array.isArray(cfg.customerDataPatterns) ? cfg.customerDataPatterns : [];
  const customerResult = redactCustomerData(out, { patterns: customerDataPatterns });
  out = customerResult.text;
  categories.customerData = customerResult.redactions;

  const redactions = categories.proprietaryPath + categories.secrets + categories.pii + categories.customerData;
  return { text: out, redactions, categories };
}

export const _internals = { _buildPiiKeyValueRegexes, PROPRIETARY_PLACEHOLDER, PII_PLACEHOLDER, CUSTOMER_DATA_PLACEHOLDER };
