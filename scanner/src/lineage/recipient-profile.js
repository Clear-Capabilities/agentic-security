// recipient-profile.js — Milestone 4 sub-project: the RecipientProfile
// extension contract (FR-506 §7.12, "Third-Party and Cross-Border
// Intelligence", PRD §10.10's own field list, PRD lines 541-548).
//
// A PURE schema/validation module for RecipientProfile records — mirrors
// obligation-mapping.js's own STRUCTURE closely: a §10.10 extension
// record ("associated with, but not required inside" the immutable base
// graph, per PRD §10.10) — never added to dataflow-graph.schema.json,
// never routed through validate.js's validateGraph(), never given a
// node:/edge:/flow:/data: canonical ID. See ids.js's recipientProfileId()
// for the id scheme, mirroring obligationId()'s own precedent exactly (a
// real, stable-ID'd extension record deliberately outside the
// node:/edge:/flow: family).
//
// This task does NOT populate real records from real data — that is two
// later, separate tasks (a small curated technical-provider catalog,
// code-derived; and an operator-declared config file, for facts code can
// never determine on its own, like legal entity/jurisdiction/DPA status).
// This file only defines what a valid record looks like.
//
// Two deliberate, disclosed departures from obligation-mapping.js's own
// precedent, both real architectural decisions, not oversights:
//
// 1. PER-FIELD evidence typing, not ObligationMapping's single
//    record-level `factType`. ObligationMapping is one predicate
//    evaluated once, so one factType describing how that predicate's
//    truth was established is enough. A RecipientProfile is a bag of
//    independent facts about one external recipient, populated from TWO
//    genuinely different sources on the SAME record: a curated technical
//    catalog can code-derive `provider`/`serviceType`/`technicalEndpoint`
//    from what the code actually calls, but `legalEntity`/`jurisdiction`-
//    adjacent facts like `dpaStatus`/`transferMechanism`/etc. can only
//    ever be operator-declared — no code path can ever discover a
//    vendor's DPA status by reading source. Collapsing that onto one
//    record-level factType would force every profile to claim either
//    "everything here is code-derived" (false for the declared fields) or
//    "everything here is declared" (throws away the real code-derived
//    provenance the catalog module DOES have) — so `fieldEvidence` gives
//    each populated field its own `{factType, source}` pair instead. This
//    is what makes "never fabricate a fact with no disclosed source" a
//    STRUCTURALLY enforced property of this record shape, not merely a
//    convention repeated from ObligationMapping without adaptation.
//
// 2. This file imports `OBLIGATION_FACT_TYPES` from `./obligation-mapping.js`
//    — the first time one §10.10 extension-contract module imports from
//    another. (obligation-mapping.js itself has zero imports, by design,
//    per its own header comment — that is a property of THAT module, not
//    a rule this file is bound by.) The fact-type vocabulary a graph fact
//    claim can carry (code_inferred/config_correlated/runtime_observed/
//    declared/manual/hypothetical) is one general concept with nothing
//    obligation-specific about it — it is already this codebase's real,
//    shipped vocabulary for "how was this fact established." Reusing it
//    here is exactly what this package's own CLAUDE.md "Conventions"
//    section already requires ("every enum here is a single source of
//    truth for its concept") — minting a second, equivalent enum under a
//    new name would violate that rule, not respect it.

import { OBLIGATION_FACT_TYPES } from './obligation-mapping.js';

export const RECIPIENT_PROCESSOR_ROLES = Object.freeze(['processor', 'controller', 'joint_controller', 'unknown']);
export const RECIPIENT_DPA_STATUSES = Object.freeze(['in_place', 'not_in_place', 'unknown']);
export const RECIPIENT_CONFIDENCE_LEVELS = Object.freeze(['high', 'medium', 'low']);

// The complete set of "real recipient fact" fields, per the task brief's
// own field list (PRD lines 541-548 — no fewer). Every field in this list
// whose value is non-null (scalar) or non-empty (array) MUST have a
// matching `fieldEvidence` key naming a real factType. Record-level
// metadata — `contributingGraphIds`/`confidence`/`owner`/`reviewDate`/
// `conflicts`/`expiration` — is deliberately NOT in this list: it
// describes the RECORD, not a recipient fact, and needs no per-field
// provenance tag of its own (mirrors ObligationMapping's own
// `contributingGraphIds` field, which carries no factType either).
export const RECIPIENT_FACT_FIELDS = Object.freeze([
  'technicalEndpoint', 'provider', 'serviceType', 'legalEntity',
  'processorRole', 'servicePurpose', 'subprocessorChain',
  'processingCountries', 'dataResidencyCommitment', 'observedRegion',
  'dpaStatus', 'transferMechanism', 'transferImpactReviewStatus',
  'retentionCommitment',
]);

const _ARRAY_FACT_FIELDS = new Set(['subprocessorChain', 'processingCountries']);

function _isNonEmptyString(v) {
  return typeof v === 'string' && v.length > 0;
}

function _isStringOrNull(v) {
  return v === null || v === undefined || typeof v === 'string';
}

function _isStringArray(v) {
  return Array.isArray(v) && v.every((x) => typeof x === 'string');
}

function _isPopulated(field, value) {
  if (_ARRAY_FACT_FIELDS.has(field)) return Array.isArray(value) && value.length > 0;
  return value !== null && value !== undefined;
}

/**
 * Structural validation only — no cross-reference into any real graph
 * (this module reuses only a shared enum from obligation-mapping.js; it
 * has zero graph access by design). Returns {valid, errors} — errors is
 * an array of {path, message}, mirroring validateObligationMapping's own
 * shape exactly. Never throws.
 */
export function validateRecipientProfile(record) {
  const errors = [];
  const err = (path, message) => errors.push({ path, message });

  if (!record || typeof record !== 'object' || Array.isArray(record)) {
    err('$', 'recipient profile record must be an object');
    return { valid: false, errors };
  }

  if (!_isNonEmptyString(record.id) || !record.id.startsWith('recipient:')) {
    err('$.id', 'id is required and must start with "recipient:"');
  }
  if (!_isNonEmptyString(record.graphId)) err('$.graphId', 'graphId is required');
  if (!_isNonEmptyString(record.graphDigest)) err('$.graphDigest', 'graphDigest is required');
  if (!_isNonEmptyString(record.recipientKey)) err('$.recipientKey', 'recipientKey is required');

  if (!_isStringOrNull(record.technicalEndpoint)) err('$.technicalEndpoint', 'technicalEndpoint must be a string or null');
  if (!_isStringOrNull(record.provider)) err('$.provider', 'provider must be a string or null');
  if (!_isStringOrNull(record.serviceType)) err('$.serviceType', 'serviceType must be a string or null');
  if (!_isStringOrNull(record.legalEntity)) err('$.legalEntity', 'legalEntity must be a string or null');
  if (!_isStringOrNull(record.servicePurpose)) err('$.servicePurpose', 'servicePurpose must be a string or null');
  if (!_isStringOrNull(record.dataResidencyCommitment)) err('$.dataResidencyCommitment', 'dataResidencyCommitment must be a string or null');
  if (!_isStringOrNull(record.observedRegion)) err('$.observedRegion', 'observedRegion must be a string or null');
  if (!_isStringOrNull(record.transferMechanism)) err('$.transferMechanism', 'transferMechanism must be a string or null');
  if (!_isStringOrNull(record.transferImpactReviewStatus)) err('$.transferImpactReviewStatus', 'transferImpactReviewStatus must be a string or null');
  if (!_isStringOrNull(record.retentionCommitment)) err('$.retentionCommitment', 'retentionCommitment must be a string or null');
  if (!_isStringOrNull(record.owner)) err('$.owner', 'owner must be a string or null');
  if (!_isStringOrNull(record.reviewDate)) err('$.reviewDate', 'reviewDate must be a string or null');
  if (!_isStringOrNull(record.expiration)) err('$.expiration', 'expiration must be a string or null');

  if (record.processorRole !== null && record.processorRole !== undefined && !RECIPIENT_PROCESSOR_ROLES.includes(record.processorRole)) {
    err('$.processorRole', `unrecognized processorRole "${record.processorRole}" — must be null or one of ${RECIPIENT_PROCESSOR_ROLES.join('|')}`);
  }
  if (record.dpaStatus !== null && record.dpaStatus !== undefined && !RECIPIENT_DPA_STATUSES.includes(record.dpaStatus)) {
    err('$.dpaStatus', `unrecognized dpaStatus "${record.dpaStatus}" — must be null or one of ${RECIPIENT_DPA_STATUSES.join('|')}`);
  }
  if (record.confidence !== null && record.confidence !== undefined && !RECIPIENT_CONFIDENCE_LEVELS.includes(record.confidence)) {
    err('$.confidence', `unrecognized confidence "${record.confidence}" — must be null or one of ${RECIPIENT_CONFIDENCE_LEVELS.join('|')}`);
  }

  if (!_isStringArray(record.subprocessorChain ?? [])) err('$.subprocessorChain', 'subprocessorChain must be an array of strings');
  if (!_isStringArray(record.contributingGraphIds ?? [])) err('$.contributingGraphIds', 'contributingGraphIds must be an array of strings');
  if (!_isStringArray(record.conflicts ?? [])) err('$.conflicts', 'conflicts must be an array of strings');

  const countries = record.processingCountries ?? [];
  if (!_isStringArray(countries)) {
    err('$.processingCountries', 'processingCountries must be an array of strings');
  } else {
    countries.forEach((c, i) => {
      if (!/^[A-Z]{2}$/.test(c)) {
        err(`$.processingCountries[${i}]`, `processingCountries entry "${c}" must be a 2-uppercase-letter ISO-3166-alpha-2-shaped string`);
      }
    });
  }

  // The load-bearing structural rule: every populated fact field must
  // have a matching fieldEvidence entry naming a real factType from
  // OBLIGATION_FACT_TYPES, and every fieldEvidence key must correspond to
  // a real fact field — a typo'd key would otherwise silently produce an
  // unenforced, orphaned evidence entry.
  if (!record.fieldEvidence || typeof record.fieldEvidence !== 'object' || Array.isArray(record.fieldEvidence)) {
    err('$.fieldEvidence', 'fieldEvidence is required and must be an object');
  } else {
    for (const field of RECIPIENT_FACT_FIELDS) {
      if (!_isPopulated(field, record[field])) continue; // null/empty needs no evidence — nothing to attribute
      const ev = record.fieldEvidence[field];
      if (!ev || typeof ev !== 'object' || Array.isArray(ev)) {
        err(`$.fieldEvidence.${field}`, `fieldEvidence.${field} is required because "${field}" is populated`);
        continue;
      }
      if (!OBLIGATION_FACT_TYPES.includes(ev.factType)) {
        err(`$.fieldEvidence.${field}.factType`, `unrecognized factType "${ev.factType}" — must be one of ${OBLIGATION_FACT_TYPES.join('|')}`);
      }
      if (!_isStringOrNull(ev.source)) {
        err(`$.fieldEvidence.${field}.source`, `fieldEvidence.${field}.source must be a string or null`);
      }
    }
    for (const key of Object.keys(record.fieldEvidence)) {
      if (!RECIPIENT_FACT_FIELDS.includes(key)) {
        err(`$.fieldEvidence.${key}`, `fieldEvidence has an orphaned key "${key}" — not a real recipient-profile fact field`);
      }
    }
  }

  return { valid: errors.length === 0, errors };
}
