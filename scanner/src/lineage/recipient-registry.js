// recipient-registry.js — Milestone 4 sub-project: FR-506 ("Third-Party
// and Cross-Border Intelligence"), Task 2. Resolves a real
// `RecipientProfile` (Task 1's own extension-contract module,
// `recipient-profile.js`) from the only two real sources this codebase has
// for these facts:
//
//   1. A small, curated technical-provider catalog, CODE-derived — "what
//      does the code actually call, and what hostname does the resolved
//      destination literally name" (`resolveTechnicalProvider`).
//   2. An operator-declared config file — facts no code path can ever
//      determine on its own (legal entity, jurisdiction, DPA status, ...)
//      (`loadRecipientConfig`).
//
// `buildRecipientProfile` combines the two into one record, per-field
// `fieldEvidence` intact, and returns `null` when neither source produced
// anything for a given sink site — a site with genuinely zero recipient
// information is not worth minting an all-null record for.
//
// ── The curated catalog — precision over recall (disclosed, not guessed) ──
//
// Mirrors `transform-catalog.js`'s own established discipline: a short,
// correct list beats a padded, guessed one. Seeded from real signals only:
//
//   - `anthropic` / `openai` — the ONLY two `framework` values in
//     `dataflow/catalog.js` naming a real AI-provider technical service
//     (confirmed by reading that file directly: `js-anthropic-messages-
//     create`, `js-openai-chat-completions-create`,
//     `js-openai-responses-create`). Matched via BOTH `frameworkNames`
//     (an exact match against the sink site's own `framework`) and real,
//     well-known hostnames for each company (not catalog-derived — no
//     literal hostname string exists anywhere in `catalog.js`/
//     `privacy-catalog.js`, confirmed by grep; these are ordinary,
//     well-known, real-world hostnames for real companies).
//   - Google Cloud Pub/Sub — `privacy-catalog.js`'s `privacy-js-queue-
//     publish` entry carries `framework: 'pubsub'`, and that value is used
//     by EXACTLY ONE catalog entry (confirmed by grep) — unambiguous, so
//     it is matched via `frameworkNames` too.
//   - Amazon S3 — `privacy-catalog.js`'s `privacy-js-s3-putObject` entry
//     carries `category: 's3Upload'` (which `sink-registry.js`'s own
//     `PRIVACY_CATEGORY_MAP` reclassifies to `object-storage`), a real,
//     already-matched signal for a real external recipient. Matched via
//     `hostnamePatterns` ONLY, deliberately NOT via `frameworkNames`:
//     that entry's `framework` value is `'aws-sdk'`, and the IDENTICAL
//     `'aws-sdk'` value is ALSO used by `privacy-js-queue-sendMessage`
//     (Amazon SQS) — genuinely ambiguous, since one `framework` string
//     names two different AWS services with two different `serviceType`s.
//     A `frameworkNames: ['aws-sdk']` catalog entry would silently
//     mislabel whichever of {S3, SQS} it didn't intend, so this module
//     never keys on it at all. No SQS catalog entry is added either — the
//     brief names only S3 as worth considering, and adding a second AWS
//     entry off the same disclosed ambiguity would be scope creep beyond
//     what was actually verified.
//
// Disclosed gaps, not guessed at: `mongodb` (storage) and `nodemailer`
// (email) are genuinely ambiguous — either could be self-hosted or a
// third-party managed service, and neither entry's own `framework` value
// reliably names ONE external company the way `anthropic`/`openai`/
// `pubsub` do — so both are left out. Google Cloud Storage
// (`storage.googleapis.com`) is also left out: no catalog entry anywhere
// in this codebase names it (confirmed by grep), so a hostname pattern for
// it would be an invented signal, not a real one. Stripe/Sentry/Datadog/
// etc. appear only inside `privacy-js-analytics-track`/`-identify`'s
// `receiverTypeIn` regex alternation, all sharing ONE `framework` value
// (`'analytics'`) that cannot distinguish which specific company matched
// at a given call site — too coarse to use.
//
// ── Reuse boundary ──────────────────────────────────────────────────────
//
// Imports ONLY `node:fs`, `./recipient-profile.js` (the enums this module
// validates operator config entries against), `./ids.js`
// (`recipientProfileId`), and `./export-json.js` (`computeGraphDigest`,
// the SAME `graph?.graphId ?? null` / `computeGraphDigest(graph)` pattern
// `obligation-predicates.js`'s `buildObligationMappingFromGraphPredicate`
// already establishes for a §10.10 extension record). Never
// `dataflow/engine.js`, never `dataflow/summaries.js` — this module reads
// only the already-resolved `site`/`graph` shapes other modules hand it.

import * as fs from 'node:fs';
import {
  RECIPIENT_PROCESSOR_ROLES,
  RECIPIENT_DPA_STATUSES,
  RECIPIENT_CONFIDENCE_LEVELS,
} from './recipient-profile.js';
import { recipientProfileId } from './ids.js';
import { computeGraphDigest } from './export-json.js';

export const RECIPIENT_CONFIG_FILENAME = 'recipient-profiles.json';

// =========================================================================
// The curated technical-provider catalog.
// =========================================================================

// Each pattern is tested against the BARE HOSTNAME extracted from
// `literalValue` via `_bareHostname` (fix-round-1, I4 — testing the RAW
// literal string let a path/query-embedded lookalike like
// 'https://attacker.io/anthropic.com' incorrectly match) via
// `new RegExp(p, 'i').test(...)`, so every pattern anchors on a domain
// BOUNDARY (`(^|[./])`, start-of-string or a literal dot) before the
// hostname and a domain terminator (`(?=[:/]|$)`, a port/path separator
// or end-of-string) after it — never a bare `$'` end anchor, which would
// only ever match a bareHost string containing nothing but the hostname
// (still correct against a bare host, since that's exactly what it is
// now).
export const TECHNICAL_PROVIDER_CATALOG = Object.freeze([
  Object.freeze({
    provider: 'anthropic',
    serviceType: 'ai-model-provider',
    hostnamePatterns: ['(^|[./])anthropic\\.com(?=[:/]|$)'],
    frameworkNames: ['anthropic'],
  }),
  Object.freeze({
    provider: 'openai',
    serviceType: 'ai-model-provider',
    hostnamePatterns: ['(^|[./])openai\\.com(?=[:/]|$)'],
    frameworkNames: ['openai'],
  }),
  Object.freeze({
    provider: 'Google Cloud Pub/Sub',
    serviceType: 'message-queue',
    hostnamePatterns: ['(^|[./])pubsub\\.googleapis\\.com(?=[:/]|$)'],
    frameworkNames: ['pubsub'],
  }),
  Object.freeze({
    provider: 'Amazon S3',
    serviceType: 'object-storage',
    // Hostname-only, deliberately — see the header comment's explanation
    // of why 'aws-sdk' is never used as a frameworkNames match. Covers
    // the plain (`s3.amazonaws.com`), region-qualified
    // (`s3.us-west-2.amazonaws.com` / `s3-us-west-2.amazonaws.com`), and
    // bucket-prefixed virtual-hosted (`my-bucket.s3[...].amazonaws.com`)
    // real URL shapes in one pattern.
    hostnamePatterns: ['(^|[./])s3([.-][a-z0-9-]+)?\\.amazonaws\\.com(?=[:/]|$)'],
    frameworkNames: [],
  }),
]);

/**
 * `resolveTechnicalProvider({framework, literalValue}) ->
 * {provider, serviceType} | null` — never throws. Matches EITHER a
 * catalog entry's own `frameworkNames` (exact match against the sink
 * site's own `framework`, checked first) OR a `hostnamePatterns` regex
 * test against `literalValue` (when a framework match didn't already
 * resolve it). Returns `null` on no match — never a guess.
 */
export function resolveTechnicalProvider(input) {
  try {
    const framework = input && typeof input === 'object' ? input.framework : undefined;
    const literalValue = input && typeof input === 'object' ? input.literalValue : undefined;

    if (typeof framework === 'string' && framework.length > 0) {
      const byFramework = TECHNICAL_PROVIDER_CATALOG.find((e) => e.frameworkNames.includes(framework));
      if (byFramework) return { provider: byFramework.provider, serviceType: byFramework.serviceType };
    }

    if (typeof literalValue === 'string' && literalValue.length > 0) {
      // fix-round-1, I4: match against the BARE HOSTNAME, never the raw
      // literal — testing the whole string let
      // 'https://attacker.io/anthropic.com' (a path, not a host) and
      // 'https://attacker.io/proxy?to=https://api.anthropic.com' (a query
      // value) both incorrectly match the Anthropic pattern, attaching a
      // real company's operator-declared legal/DPA facts to a flow whose
      // actual destination is attacker.io. `_bareHostname` is defined
      // below in this same file and hoisted, so it's callable from here.
      const bareHost = _bareHostname(literalValue) ?? '';
      const byHost = TECHNICAL_PROVIDER_CATALOG.find((e) =>
        e.hostnamePatterns.some((p) => new RegExp(p, 'i').test(bareHost)));
      if (byHost) return { provider: byHost.provider, serviceType: byHost.serviceType };
    }

    return null;
  } catch {
    return null;
  }
}

// =========================================================================
// A tiny, local bare-hostname extractor — no URL-parsing dependency, per
// this codebase's established zero-new-dependencies precedent. Handles a
// scheme-prefixed URL, a bare host, and strips a trailing path/query/
// fragment/port. Not a general URL parser — good enough for the one thing
// this module needs it for (a `recipientKey` fallback).
// =========================================================================

function _bareHostname(literalValue) {
  if (typeof literalValue !== 'string' || literalValue.length === 0) return null;
  const withoutScheme = literalValue.replace(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, '');
  const host = withoutScheme.split(/[/?#]/)[0].split(':')[0].trim();
  return host.length > 0 ? host.toLowerCase() : null;
}

// =========================================================================
// loadRecipientConfig — mirrors drift-policy.js's loadDriftPolicies
// EXACTLY: never throws; a missing file degrades to the empty shape; a
// malformed-JSON file logs a warning and degrades to the empty shape; each
// individual recipient entry is validated loosely, and a malformed one is
// SKIPPED IN ITS ENTIRETY (never just one bad field) with a warning naming
// the count — mirroring loadDriftPolicies' own per-entry (not per-field)
// skip discipline. `recipients` is an OBJECT keyed by recipientKey (not an
// array like `policies`), so this iterates `Object.entries` rather than
// `.filter()`s an array — the fail-closed philosophy is identical.
// =========================================================================

function _isNonEmptyString(v) { return typeof v === 'string' && v.length > 0; }
function _isStringOrNull(v) { return v === null || v === undefined || typeof v === 'string'; }
function _isStringArray(v) { return Array.isArray(v) && v.every((x) => typeof x === 'string'); }
function _isCountryArray(v) { return Array.isArray(v) && v.every((c) => typeof c === 'string' && /^[A-Z]{2}$/.test(c)); }

// The complete set of operator-declarable fields, per the task brief's own
// config shape — a 1:1 mapping onto RecipientProfile fields this module
// can ONLY ever fill from operator config (the fact fields) plus the five
// record-level metadata fields (confidence/owner/reviewDate/conflicts/
// expiration), which need no fieldEvidence of their own (see
// recipient-profile.js's own header comment on why those five are
// excluded from RECIPIENT_FACT_FIELDS).
// fix-round-1, M7: `servicePurpose`/`observedRegion` were both real
// RECIPIENT_FACT_FIELDS (recipient-profile.js) and both real fields
// `buildRecipientProfile`'s own `facts` object initializes below, but were
// missing from this list — an operator declaring either in
// recipient-profiles.json had it silently ignored (never validated, never
// copied into the built profile).
const _RECIPIENT_CONFIG_FACT_FIELDS = Object.freeze([
  'legalEntity', 'processorRole', 'servicePurpose', 'subprocessorChain', 'processingCountries',
  'dataResidencyCommitment', 'observedRegion', 'dpaStatus', 'transferMechanism',
  'transferImpactReviewStatus', 'retentionCommitment',
]);
// The remaining five operator-declarable fields — confidence/owner/
// reviewDate/conflicts/expiration — are record-level metadata, copied
// directly in buildRecipientProfile's own return literal below with no
// fieldEvidence entry, per recipient-profile.js's own header comment.

/**
 * Validates one recipient-config entry against Task 1's own real enums.
 * Fail-closed per the brief's own instruction: a malformed value on ANY
 * field skips the WHOLE entry (never just that one field) — the simpler,
 * more conservative of the two options the brief names, and the one that
 * mirrors `loadDriftPolicies`' own "validate the whole shape, skip the
 * whole entry on a defect" discipline most closely.
 */
export function isValidRecipientConfigEntry(entry) {
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return false;
  if (!_isStringOrNull(entry.legalEntity)) return false;
  if (entry.processorRole != null && !RECIPIENT_PROCESSOR_ROLES.includes(entry.processorRole)) return false;
  if (!_isStringOrNull(entry.servicePurpose)) return false;
  if (entry.subprocessorChain != null && !_isStringArray(entry.subprocessorChain)) return false;
  if (entry.processingCountries != null && !_isCountryArray(entry.processingCountries)) return false;
  if (!_isStringOrNull(entry.dataResidencyCommitment)) return false;
  if (!_isStringOrNull(entry.observedRegion)) return false;
  if (entry.dpaStatus != null && !RECIPIENT_DPA_STATUSES.includes(entry.dpaStatus)) return false;
  if (!_isStringOrNull(entry.transferMechanism)) return false;
  if (!_isStringOrNull(entry.transferImpactReviewStatus)) return false;
  if (!_isStringOrNull(entry.retentionCommitment)) return false;
  if (entry.confidence != null && !RECIPIENT_CONFIDENCE_LEVELS.includes(entry.confidence)) return false;
  if (!_isStringOrNull(entry.owner)) return false;
  if (!_isStringOrNull(entry.reviewDate)) return false;
  if (entry.conflicts != null && !_isStringArray(entry.conflicts)) return false;
  if (!_isStringOrNull(entry.expiration)) return false;
  return true;
}

export function loadRecipientConfig(configFilePath) {
  const EMPTY = { recipients: {} };
  if (!configFilePath) return EMPTY;

  let raw = null;
  try {
    raw = JSON.parse(fs.readFileSync(configFilePath, 'utf8'));
  } catch (e) {
    if (e.code !== 'ENOENT') {
      console.error(`agentic-security: bad JSON in recipient config file (${configFilePath}) — falling back to no recipients (${e.message})`);
    }
    return EMPTY;
  }

  if (!raw || typeof raw !== 'object' || Array.isArray(raw) || !raw.recipients || typeof raw.recipients !== 'object' || Array.isArray(raw.recipients)) {
    console.error(`agentic-security: recipient config file ${configFilePath} has no "recipients" object — falling back to no recipients (expected {"recipients": {...}})`);
    return EMPTY;
  }

  const recipients = {};
  let skipped = 0;
  for (const [key, entry] of Object.entries(raw.recipients)) {
    if (!_isNonEmptyString(key) || !isValidRecipientConfigEntry(entry)) {
      skipped += 1;
      continue;
    }
    recipients[key] = entry;
  }
  if (skipped > 0) {
    console.error(`agentic-security: skipped ${skipped} malformed recipient-config entr${skipped === 1 ? 'y' : 'ies'} in ${configFilePath} (each must be a valid recipient-profile-shaped object)`);
  }
  return { recipients };
}

// =========================================================================
// buildRecipientProfile — the real resolution function.
// =========================================================================

/**
 * `buildRecipientProfile(site, graph, opts) -> RecipientProfile | null`.
 *
 * `site` is the shape `graph-builder.js`'s `enumerateSinkSites` produces:
 * `{file, qid, nodeId, line, calleeExpr, args, entry, decision, ambiguity,
 * destination?}` — `entry` is the RAW catalog entry (where `framework`
 * actually lives, `site.entry.framework`, never `site.framework`);
 * `destination`, when present, is `resolve-destination.js`'s own
 * `{resolutionStatus, raw, literalValue, blockingExpression}` shape and
 * may be `undefined` if resolution was never attempted.
 *
 * `graph` is a built `DataFlowGraph v1` document (or `graphAfter` in a
 * diff context) — used only for `graphId`/`graphDigest`, mirroring
 * `obligation-predicates.js`'s own `graph?.graphId ?? null` /
 * `graph ? computeGraphDigest(graph) : null` pattern exactly. `graph` may
 * be omitted/null; the record still builds, honestly labeled `'(no
 * graph)'` (that same precedent's own fallback literal).
 *
 * `opts.recipientConfig` is `loadRecipientConfig`'s own return shape
 * (`{recipients: {...}}`) — omitted/malformed degrades to "no operator
 * declarations", never a throw.
 */
export function buildRecipientProfile(site, graph, opts = {}) {
  if (!site || typeof site !== 'object') return null;

  const framework = site.entry && typeof site.entry === 'object' ? site.entry.framework : undefined;
  const destination = site.destination && typeof site.destination === 'object' ? site.destination : null;
  const literalValue = destination && destination.resolutionStatus === 'literal' && typeof destination.literalValue === 'string'
    ? destination.literalValue
    : null;

  const techMatch = resolveTechnicalProvider({ framework, literalValue });

  let recipientKey = null;
  if (techMatch && typeof techMatch.provider === 'string' && techMatch.provider.length > 0) {
    recipientKey = techMatch.provider;
  } else {
    recipientKey = _bareHostname(literalValue);
  }
  if (!recipientKey) return null; // no key, no profile — never fabricate one

  const recipients = opts && opts.recipientConfig && typeof opts.recipientConfig === 'object' && opts.recipientConfig.recipients
    && typeof opts.recipientConfig.recipients === 'object'
    ? opts.recipientConfig.recipients
    : null;
  const configEntry = recipients ? recipients[recipientKey] : null;

  if (!techMatch && !configEntry) return null; // genuinely nothing to say about this site

  const fieldEvidence = {};
  const facts = {
    technicalEndpoint: null, provider: null, serviceType: null, legalEntity: null,
    processorRole: null, servicePurpose: null, subprocessorChain: [],
    processingCountries: [], dataResidencyCommitment: null, observedRegion: null,
    dpaStatus: null, transferMechanism: null, transferImpactReviewStatus: null,
    retentionCommitment: null,
  };

  if (techMatch) {
    facts.provider = techMatch.provider;
    facts.serviceType = techMatch.serviceType;
    fieldEvidence.provider = { factType: 'code_inferred', source: 'recipient-registry:catalog' };
    fieldEvidence.serviceType = { factType: 'code_inferred', source: 'recipient-registry:catalog' };
    if (literalValue) {
      facts.technicalEndpoint = literalValue;
      fieldEvidence.technicalEndpoint = { factType: 'code_inferred', source: 'recipient-registry:catalog' };
    }
  }

  if (configEntry) {
    for (const field of _RECIPIENT_CONFIG_FACT_FIELDS) {
      const value = configEntry[field];
      const populated = Array.isArray(value) ? value.length > 0 : (value !== null && value !== undefined);
      if (!populated) continue;
      facts[field] = value;
      fieldEvidence[field] = { factType: 'declared', source: RECIPIENT_CONFIG_FILENAME };
    }
  }

  const graphId = graph && typeof graph === 'object' ? (graph.graphId ?? null) : null;
  const graphDigest = graph && typeof graph === 'object' ? computeGraphDigest(graph) : null;

  return {
    id: recipientProfileId({ graphId: graphId ?? '', graphDigest: graphDigest ?? '', recipientKey }),
    graphId: graphId ?? '(no graph)',
    graphDigest: graphDigest ?? '(no graph)',
    recipientKey,
    ...facts,
    fieldEvidence,
    contributingGraphIds: [],
    confidence: configEntry && configEntry.confidence != null ? configEntry.confidence : null,
    owner: configEntry && configEntry.owner != null ? configEntry.owner : null,
    reviewDate: configEntry && configEntry.reviewDate != null ? configEntry.reviewDate : null,
    conflicts: configEntry && Array.isArray(configEntry.conflicts) ? configEntry.conflicts : [],
    expiration: configEntry && configEntry.expiration != null ? configEntry.expiration : null,
  };
}
