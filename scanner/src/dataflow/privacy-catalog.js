// FR-403 (assurance-hardening PRD), Steps 1-2 of D-0041's decomposition plan:
// "Track flows through ... storage, logs, responses, analytics, email,
// files, object storage, queues, and outbound APIs."
//
// STEP 1: A catalog of PRIVACY-LEAK (CWE-359) sink entries, in the EXACT shape
// `dataflow/catalog.js` already uses for every other family (see that
// module's own header for the full `{kind, id, language, framework, match,
// argIndex, vuln}` contract) — mirroring `privacy-taint.js`'s existing
// `SINK_PATTERNS` (log/response/outboundHttp/thirdPartySdk/fileWrite/
// s3Upload/emailSend) plus the 2 sink categories FR-403 names that had no
// coverage anywhere (generic storage/DB, queues).
//
// DELIBERATELY NOT MERGED INTO `catalog.js`'s own `CATALOG` EXPORT, and NOT
// wired into `matchSinkOrSanitizer`/`runTaintEngine` — this is the single
// most important design decision in this file, found DURING implementation
// (not anticipated by D-0041's original grounding pass, which characterized
// step 1 as "zero behavior change"). `CATALOG` is a shared, always-active
// singleton: matchSinkOrSanitizer/matchSource read it unconditionally for
// EVERY scan, with no per-family or per-source filtering at the taint-state
// level (a tainted value's origin family is never recorded — only whether
// it is tainted at all). Appending these sink entries directly to `CATALOG`
// would therefore make them reachable by every ALREADY-ACTIVE general
// security source (`req.body`, `req.query`, etc.) immediately, producing
// spurious CWE-359 "privacy-leak" findings for ordinary attacker-input
// flows that have nothing to do with data actually classified PII/PHI/PCI
// by `privacy-taxonomy.js` — a real, immediate false-positive class, not
// the "zero risk" step D-0041's own step 1 was meant to be. Keeping this
// catalog in its own file, imported by nothing yet, is what makes it
// genuinely inert: these entries do not affect any scan's output until a
// future step (D-0041 step 3) builds a privacy-specific matcher that
// consults ONLY the sources `privacy-taxonomy.js` actually classifies,
// never the general engine's already-active source set.
//
// Registered in `test/no-dead-modules.test.js`'s ALLOWLIST — a deliberate,
// staged capability with no consumer yet, not an oversight.

import { classifyFieldAgainst } from './privacy-taxonomy.js';
import { _languageFamilyExtensions } from './catalog.js';

export const PRIVACY_SINK_CATALOG = [
  // ── log ──────────────────────────────────────────────────────────────────
  { kind: 'sink', id: 'privacy-js-console-log', language: 'js', framework: 'node', category: 'log',
    match: { type: 'call', callee: 'log', receiverTypeIn: ['console'] }, argIndex: 'all',
    vuln: { name: 'Privacy Leak (console.log)', severity: 'medium', cwe: 'CWE-359',
            remediation: 'Do not log regulated data (PII/PHI/PCI). Redact or hash the field before logging.' } },
  { kind: 'sink', id: 'privacy-js-console-error', language: 'js', framework: 'node', category: 'log',
    match: { type: 'call', callee: 'error', receiverTypeIn: ['console'] }, argIndex: 'all',
    vuln: { name: 'Privacy Leak (console.error)', severity: 'medium', cwe: 'CWE-359',
            remediation: 'Do not log regulated data (PII/PHI/PCI). Redact or hash the field before logging.' } },
  { kind: 'sink', id: 'privacy-js-logger-info', language: 'js', framework: 'node', category: 'log',
    match: { type: 'call', callee: 'info', receiverTypeIn: ['log|logger|Logger'] }, argIndex: 'all',
    vuln: { name: 'Privacy Leak (logger.info)', severity: 'medium', cwe: 'CWE-359',
            remediation: 'Do not log regulated data (PII/PHI/PCI). Redact or hash the field before logging.' } },
  { kind: 'sink', id: 'privacy-js-logger-warn', language: 'js', framework: 'node', category: 'log',
    match: { type: 'call', callee: 'warn', receiverTypeIn: ['log|logger|Logger'] }, argIndex: 'all',
    vuln: { name: 'Privacy Leak (logger.warn)', severity: 'medium', cwe: 'CWE-359',
            remediation: 'Do not log regulated data (PII/PHI/PCI). Redact or hash the field before logging.' } },

  // ── response ─────────────────────────────────────────────────────────────
  { kind: 'sink', id: 'privacy-js-res-send', language: 'js', framework: 'express', category: 'response',
    match: { type: 'call', callee: 'send', receiverTypeIn: ['res|response'] }, argIndex: 0,
    vuln: { name: 'Privacy Leak (response body)', severity: 'high', cwe: 'CWE-359',
            remediation: 'Do not return regulated data (PII/PHI/PCI) in an API response unless the requester is authorized and the field is required.' } },
  { kind: 'sink', id: 'privacy-js-res-json', language: 'js', framework: 'express', category: 'response',
    match: { type: 'call', callee: 'json', receiverTypeIn: ['res|response'] }, argIndex: 0,
    vuln: { name: 'Privacy Leak (response body)', severity: 'high', cwe: 'CWE-359',
            remediation: 'Do not return regulated data (PII/PHI/PCI) in an API response unless the requester is authorized and the field is required.' } },

  // ── outboundHttp ─────────────────────────────────────────────────────────
  { kind: 'sink', id: 'privacy-js-fetch', language: 'js', framework: 'browser', category: 'outboundHttp',
    match: { type: 'call', callee: 'fetch' }, argIndex: 1,
    vuln: { name: 'Privacy Leak (outbound HTTP request)', severity: 'high', cwe: 'CWE-359',
            remediation: 'Do not send regulated data (PII/PHI/PCI) to a third-party endpoint without a documented data-processing agreement.' } },
  { kind: 'sink', id: 'privacy-js-axios-post', language: 'js', framework: 'axios', category: 'outboundHttp',
    match: { type: 'call', callee: 'post', receiverTypeIn: ['axios'] }, argIndex: 1,
    vuln: { name: 'Privacy Leak (outbound HTTP request)', severity: 'high', cwe: 'CWE-359',
            remediation: 'Do not send regulated data (PII/PHI/PCI) to a third-party endpoint without a documented data-processing agreement.' } },

  // ── thirdPartySdk (analytics) ────────────────────────────────────────────
  { kind: 'sink', id: 'privacy-js-analytics-track', language: 'js', framework: 'analytics', category: 'thirdPartySdk',
    match: { type: 'call', callee: 'track', receiverTypeIn: ['stripe|sentry|datadog|segment|amplitude|mixpanel|posthog|braze|intercom|analytics'] }, argIndex: 'all',
    vuln: { name: 'Privacy Leak (third-party analytics)', severity: 'high', cwe: 'CWE-359',
            remediation: 'Do not send regulated data (PII/PHI/PCI) to an analytics/SDK provider — pseudonymize identifiers instead of raw fields.' } },
  { kind: 'sink', id: 'privacy-js-analytics-identify', language: 'js', framework: 'analytics', category: 'thirdPartySdk',
    match: { type: 'call', callee: 'identify', receiverTypeIn: ['stripe|sentry|datadog|segment|amplitude|mixpanel|posthog|braze|intercom|analytics'] }, argIndex: 'all',
    vuln: { name: 'Privacy Leak (third-party analytics)', severity: 'high', cwe: 'CWE-359',
            remediation: 'Do not send regulated data (PII/PHI/PCI) to an analytics/SDK provider — pseudonymize identifiers instead of raw fields.' } },

  // ── fileWrite ────────────────────────────────────────────────────────────
  { kind: 'sink', id: 'privacy-js-fs-writeFile', language: 'js', framework: 'node', category: 'fileWrite',
    match: { type: 'call', callee: 'writeFile', receiverTypeIn: ['fs'] }, argIndex: 1,
    vuln: { name: 'Privacy Leak (file write)', severity: 'medium', cwe: 'CWE-359',
            remediation: 'Do not write regulated data (PII/PHI/PCI) to an unencrypted file without a documented retention and access-control policy.' } },
  { kind: 'sink', id: 'privacy-js-fs-writeFileSync', language: 'js', framework: 'node', category: 'fileWrite',
    match: { type: 'call', callee: 'writeFileSync', receiverTypeIn: ['fs'] }, argIndex: 1,
    vuln: { name: 'Privacy Leak (file write)', severity: 'medium', cwe: 'CWE-359',
            remediation: 'Do not write regulated data (PII/PHI/PCI) to an unencrypted file without a documented retention and access-control policy.' } },

  // ── s3Upload (object storage) ────────────────────────────────────────────
  { kind: 'sink', id: 'privacy-js-s3-putObject', language: 'js', framework: 'aws-sdk', category: 's3Upload',
    match: { type: 'call', callee: 'putObject', receiverTypeIn: ['s3|S3Client|aws'] }, argIndex: 0,
    vuln: { name: 'Privacy Leak (object storage upload)', severity: 'high', cwe: 'CWE-359',
            remediation: 'Do not upload regulated data (PII/PHI/PCI) to object storage without server-side encryption and a documented access policy.' } },

  // ── emailSend ────────────────────────────────────────────────────────────
  { kind: 'sink', id: 'privacy-js-sendMail', language: 'js', framework: 'nodemailer', category: 'emailSend',
    match: { type: 'call', callee: 'sendMail' }, argIndex: 0,
    vuln: { name: 'Privacy Leak (outbound email)', severity: 'medium', cwe: 'CWE-359',
            remediation: 'Do not include regulated data (PII/PHI/PCI) in an outbound email body beyond what the recipient is authorized to receive.' } },

  // ── storage (generic DB — the first of FR-403's 2 previously-uncovered categories) ──
  { kind: 'sink', id: 'privacy-js-mongo-insertOne', language: 'js', framework: 'mongodb', category: 'storage',
    match: { type: 'call', callee: 'insertOne', receiverTypeIn: ['collection|db|mongo'] }, argIndex: 0,
    vuln: { name: 'Privacy Leak (database write)', severity: 'medium', cwe: 'CWE-359',
            remediation: 'Regulated data (PII/PHI/PCI) written to a database must be covered by a documented retention, access-control, and encryption-at-rest policy.' } },
  { kind: 'sink', id: 'privacy-js-mongo-insertMany', language: 'js', framework: 'mongodb', category: 'storage',
    match: { type: 'call', callee: 'insertMany', receiverTypeIn: ['collection|db|mongo'] }, argIndex: 0,
    vuln: { name: 'Privacy Leak (database write)', severity: 'medium', cwe: 'CWE-359',
            remediation: 'Regulated data (PII/PHI/PCI) written to a database must be covered by a documented retention, access-control, and encryption-at-rest policy.' } },

  // ── queues (the second of FR-403's 2 previously-uncovered categories) ────
  { kind: 'sink', id: 'privacy-js-queue-sendMessage', language: 'js', framework: 'aws-sdk', category: 'queues',
    match: { type: 'call', callee: 'sendMessage', receiverTypeIn: ['queue|sqs|SQS'] }, argIndex: 0,
    vuln: { name: 'Privacy Leak (message queue)', severity: 'medium', cwe: 'CWE-359',
            remediation: 'Regulated data (PII/PHI/PCI) placed on a queue is readable by every consumer with queue access — document who can subscribe before sending it.' } },
  { kind: 'sink', id: 'privacy-js-queue-publish', language: 'js', framework: 'pubsub', category: 'queues',
    match: { type: 'call', callee: 'publish', receiverTypeIn: ['queue|sns|SNS|topic|pubsub|kafka|producer'] }, argIndex: 0,
    vuln: { name: 'Privacy Leak (message queue)', severity: 'medium', cwe: 'CWE-359',
            remediation: 'Regulated data (PII/PHI/PCI) placed on a queue is readable by every consumer with queue access — document who can subscribe before sending it.' } },
];

// All 9 sink categories FR-403 names (7 already covered by privacy-taint.js's
// own SINK_PATTERNS, plus storage/queues) — used by this module's own tests
// to assert coverage is genuinely complete, not just "some entries exist."
export const PRIVACY_SINK_CATEGORIES = Object.freeze([
  'log', 'response', 'outboundHttp', 'thirdPartySdk', 'fileWrite', 's3Upload', 'emailSend', 'storage', 'queues',
]);

// ─── D-0041 STEP 2: a "declared-as" source matcher ─────────────────────────
//
// The one genuine gap `catalog.js`'s existing `match.type` shapes (`call`,
// `member`, `global`, `annotation`) leave uncovered: every one of them
// matches an EXPRESSION PATTERN (a specific callee, a specific property
// read, a specific decorator). A privacy source is a different kind of
// fact entirely — "this declaration's NAME classifies as PII/PHI/PCI/etc."
// — decided by `privacy-taxonomy.js`'s regex-per-class taxonomy, not by
// what expression touches it. There is no fixed name to put in a `match`
// object; the classification must run against WHATEVER name a declaration
// actually has.
//
// Modeled after `matchAnnotationParams` (catalog.js) rather than the CFG-
// node matchers: that function is also NOT consulted mid-walk against an
// expression — it runs ONCE PER FUNCTION against the IR's own
// `fn.paramAnnotations` side-channel, before the walk starts, and its
// result is unioned into the entry taint-state (see `dataflow/CLAUDE.md`'s
// own note that annotation matching "is not consulted during the CFG
// walk"). `matchPrivacyDeclSource(s)` below follow that same shape:
// pure, pre-walk, name-classification functions a future step 3 will call
// once per function/file against real declaration names, unioning any hit
// into a privacy-specific entry taint-state — never against `catalog.js`'s
// own `CATALOG`, for the exact isolation reason this file's header
// explains for the sink half.

/**
 * Classify one declaration name. Returns `{name, classes}` when it matches
 * at least one taxonomy class, or `null` when it matches none — `null`
 * rather than `{name, classes: []}` so a caller can filter with a plain
 * truthiness check, matching `classifyFieldAgainst`'s own "empty array
 * means no match" contract one level up.
 */
export function matchPrivacyDeclSource(declName, compiled) {
  if (!declName) return null;
  const classes = classifyFieldAgainst(declName, compiled);
  return classes.length ? { name: declName, classes } : null;
}

/**
 * Classify every name in a list of declarations (variable names, function
 * params, object-literal keys — whatever a caller's IR extraction
 * produces) against the taxonomy. Returns a Map<name, classes[]> so a
 * caller gets both "which names are sources" (the key set) and "which
 * classes triggered it" (the value) in one pass, without re-classifying.
 * Never throws on malformed input — a non-array degrades to an empty Map.
 */
export function matchPrivacyDeclSources(declNames, compiled) {
  const out = new Map();
  for (const name of Array.isArray(declNames) ? declNames : []) {
    const hit = matchPrivacyDeclSource(name, compiled);
    if (hit) out.set(hit.name, hit.classes);
  }
  return out;
}

// D-0046/D-0047 (FR-403 step 3, grounding): mirrors `catalog.js`'s
// matchSinkOrSanitizer(calleeExpr, file, receiverType) shape/contract
// exactly (array of hits, or null) so a future isolated privacy walker can
// consult it the same way the general walker consults the general catalog
// -- but reads ONLY PRIVACY_SINK_CATALOG, never CATALOG. This is a linear
// scan, not `catalog.js`'s CALLEE_INDEX Map lookup: at ~20 entries a scan is
// plenty fast, and avoiding the shared index machinery (which is private/
// unexported, and keyed by a shared module-level Map) keeps the two
// catalogs fully decoupled -- exactly the isolation D-0042 requires, now
// extended to the sink-matching CODE PATH, not just the entry DATA.
// `_languageFamilyExtensions` is the one thing imported from catalog.js: a
// pure, stateless helper with no shared mutable state and no coupling to
// the general taint engine's behavior, reused to avoid duplicating the
// language-extension regex table.

function _privacyLanguageAllowed(entry, file) {
  if (!file) return true;
  const res = _languageFamilyExtensions(entry.language);
  if (!res.length) return true; // unmapped language stays permissive
  return res.some((re) => re.test(file));
}

function _privacyReceiverTypeAllowed(entry, receiverType) {
  const pats = entry.match && entry.match.receiverTypeIn;
  if (!pats || !pats.length) return true;
  if (!receiverType) return true;
  return pats.some((p) => new RegExp(p, 'i').test(String(receiverType)));
}

// Duplicated from catalog.js's private (unexported) `_calleeIndexHits`
// name-extraction logic rather than exporting it from catalog.js -- keeping
// this file's only catalog.js dependency to the one pure helper above.
function _privacyCalleeNames(calleeExpr) {
  let last = null;
  let full = null;
  if (typeof calleeExpr === 'string') {
    full = calleeExpr;
    last = calleeExpr.includes('.') ? calleeExpr.slice(calleeExpr.lastIndexOf('.') + 1) : calleeExpr;
  } else if (calleeExpr && calleeExpr.kind === 'member' && calleeExpr.prop) {
    last = calleeExpr.prop;
    if (calleeExpr.object && calleeExpr.object.kind === 'ident') full = `${calleeExpr.object.name}.${calleeExpr.prop}`;
  } else if (calleeExpr && calleeExpr.kind === 'ident') {
    last = calleeExpr.name || null;
  }
  return { last, full };
}

export function matchPrivacySink(calleeExpr, file, receiverType) {
  if (!calleeExpr) return null;
  const { last, full } = _privacyCalleeNames(calleeExpr);
  if (!last && !full) return null;
  const hits = PRIVACY_SINK_CATALOG.filter((e) => {
    if (!e || e.kind !== 'sink') return false;
    const cName = e.match && e.match.callee;
    if (!cName) return false;
    if (cName !== last && cName !== full) return false;
    if (!_privacyLanguageAllowed(e, file)) return false;
    if (!_privacyReceiverTypeAllowed(e, receiverType)) return false;
    return true;
  });
  return hits.length ? hits : null;
}

// FR-403 step 3, item (d): safe-transformation recognition. Mirrors
// dataflow/CLAUDE.md's own documented philosophy for the general engine's
// sanitizers EXACTLY -- "Sanitizer entries are RECORDED, never trusted to
// kill taint" -- for the identical reason: a value hashed/masked/encrypted
// might still be REVERSIBLE (a weak hash, a partial mask, a home-rolled
// "encrypt" that's really just base64) or applied on only ONE branch. A
// privacy-deep finding that passed through one of these callees is
// DEMOTED (confidence, never severity/existence), not deleted -- the same
// recall-preserving direction every other precision annotator in this
// codebase takes. A named list, not exhaustive, mirroring engine.js's own
// _UNSANITIZER_CALLEES precedent (dataflow/CLAUDE.md: "modelled, but only
// for a named list... a project-local decoder is not recognised").
const PRIVACY_TRANSFORM_CALLEES = new Set([
  // Cryptographic hash (one-way, not generally reversible)
  'createHash', 'sha256', 'sha512', 'md5', 'hash', 'hashSync', 'hashPassword',
  // Password/key-derivation hashing
  'bcrypt', 'scrypt', 'pbkdf2', 'pbkdf2Sync', 'argon2',
  // Symmetric/asymmetric encryption
  'createCipher', 'createCipheriv', 'encrypt', 'seal',
  // Masking / redaction / anonymization -- named, not pattern-matched, since
  // a bare substring match on "mask" would over-fire on unrelated code
  // (e.g. a bitmask helper named `applyMask`).
  'mask', 'redact', 'anonymize', 'pseudonymize', 'tokenize',
]);

/**
 * True when `calleeExpr` is one of the named privacy-transform callees.
 * Mirrors matchPrivacySink's own bare/dotted callee-name matching.
 */
export function isPrivacyTransformCallee(calleeExpr) {
  if (!calleeExpr) return false;
  const { last, full } = _privacyCalleeNames(calleeExpr);
  return PRIVACY_TRANSFORM_CALLEES.has(last) || PRIVACY_TRANSFORM_CALLEES.has(full);
}
