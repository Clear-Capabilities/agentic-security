//
// transform-catalog.js — Data Flow Explorer, Sub-project D, increment D4.
//
// Recognizes that a CALL performs a security- or privacy-relevant data
// transformation, and classifies it into DataFlowGraph v1's §10.6
// vocabulary: `TRANSFORM_KINDS` × `REVERSIBILITY_VALUES` (`schema.js`).
//
// ─── What makes this module different from D2/D3 ────────────────────────
//
// `source-registry.js` (D2) and `sink-registry.js` (D3) are RECLASSIFICATION
// layers: they read `dataflow/catalog.js`'s already-proven, corpus-backed
// entries and map them onto a new vocabulary. This module has no such input.
// `DESIGN_REGISTRIES.md` §8.2/§8.3 measured why:
//   - the 706 sanitizer entries are keyed on `effect` + a THREAT CLASS
//     ("does this neutralize XSS"), not on "what kind of transformation is
//     this and is it reversible" — reclassifying them would be a category
//     error;
//   - the one genuinely transform-shaped list that exists,
//     `privacy-catalog.js`'s `PRIVACY_TRANSFORM_CALLEES`, is a private
//     Set behind a BOOLEAN predicate (`isPrivacyTransformCallee`) that
//     tells a caller *that* a callee is a transform but never *which kind*.
// So this catalog is written from scratch. §8.3 left the access problem
// open between "a lineage-side table of its own" and "export the Set from
// privacy-catalog.js"; this increment's plan settles it as the former —
// this module imports NOTHING from `scanner/src/dataflow/` at all (see
// Isolation below).
//
// ─── Isolation ──────────────────────────────────────────────────────────
//
// Imports ONLY `TRANSFORM_KINDS` / `REVERSIBILITY_VALUES` from ./schema.js.
// Never `dataflow/catalog.js`, never `dataflow/privacy-catalog.js`, never
// `dataflow/engine.js` / `dataflow/summaries.js` / any matcher internals
// (this PRD's §18.1 isolation principle, the same basis every Sub-project
// A–D module uses).
//
// ─── The scope boundary this module must NOT cross ──────────────────────
//
// PRD §10.6 lists nine things a Transformation entity must identify. This
// module produces FOUR of them, and it is a hard error for it to produce
// any of the rest:
//
//   PRODUCED: kind; reversibility; algorithm (when the callee pattern
//   itself names one — never guessed); evidence + confidence.
//
//   NOT PRODUCED, because they need a CALL SITE and this module only ever
//   sees a callee PATTERN: input/output access paths, function code
//   location, "applies on all feasible paths or only some paths",
//   key-management evidence.
//
//   NOT PRODUCED, because Milestone 1's own binding scope decision forbids
//   it: **"control credit granted or denied and the reason."** The parent
//   scoping doc's Decision 2 reads: *"Sub-project D (transformation-kind
//   recognition) is in scope for Milestone 1; awarding verdict 'credit'
//   from that recognition is explicitly out of scope and stays
//   `not_assessed` until Milestone 2."* Recognizing that a `mask` happened
//   is this module's job. Deciding whether that `mask` earns "protected"
//   is `protection.js`'s `aggregateVerdicts()` — Milestone 2's FR-401-405
//   analyzers, reading this module's output. If you find yourself adding a
//   field that answers "is this transform good enough", stop.
//
// A future Sub-project E graph builder is what calls this once per real
// call site and combines the answer with location/path data to build an
// actual `Transformation` entity.
//
// ─── §10.6's "never synonyms" rule ──────────────────────────────────────
//
// *"Masking, hashing, tokenization, and encryption must never be treated
// as synonyms."* Each is its own kind here, with its own reversibility,
// and no entry may collapse two of them:
//   mask     → irreversible (information is destroyed);
//   hash     → irreversible (one-way by construction);
//   tokenize → REVERSIBLE (a token is designed to be detokenized by the
//              vault that issued it — this is precisely the property that
//              makes it not-a-mask);
//   encrypt  → REVERSIBLE (designed to be decrypted).
//
// ─── Curated, not exhaustive (and the confidence rule) ──────────────────
//
// This is new detection capability, so it favors PRECISION over recall. A
// callee this catalog does not recognize returns `null` — never a guess.
//
//   confidence: 'high'   — the pattern identifies both the callee AND its
//                          transformation semantics unambiguously: a
//                          qualified library/module API (`crypto.createHash`,
//                          `bcrypt.hash`, `hashlib.sha256`) or a platform
//                          global whose name is effectively reserved
//                          (`encodeURIComponent`, `btoa`).
//   confidence: 'medium' — EITHER the name is unqualified and an
//                          application could define it with unrelated
//                          semantics (`maskCard`, `tokenize`, `normalize`),
//                          OR the API is genuinely general-purpose and its
//                          per-call-site semantics vary (`_.truncate` is
//                          string shortening, not necessarily a privacy
//                          control).
//
// There is no 'low' tier: a pattern that would only justify 'low' does not
// belong in a curated catalog at all — it belongs in the disclosed-gap
// list below.
//
// ─── Deliberate gaps (disclosed, per this PRD's own convention) ─────────
//
//  1. `custom` and `unknown` are NEVER emitted. They are a consumer's
//     fallback vocabulary for a transform-shaped call this catalog does not
//     recognize; the honest answer from a RECOGNIZER is `null`. Whoever
//     must still materialize a Transformation entity for an unrecognized
//     call is the one who chooses between `custom` and `unknown`.
//  2. `anonymize*` / `pseudonymize*` are deliberately EXCLUDED even though
//     both are real, common names (and both are in `privacy-catalog.js`'s
//     own private Set). Neither maps onto a single `TRANSFORM_KINDS` value:
//     anonymization is variously masking, redaction or aggregation, and
//     pseudonymization is variously tokenization or keyed hashing. Forcing
//     either into one kind is exactly the synonym-collapse §10.6 forbids.
//  3. `aggregate` and `tokenize` are the THINNEST kinds here — one
//     naming-convention entry each. Aggregation is normally a data-shape
//     operation (`.reduce()`, `.groupBy()`) with no security-relevant
//     callee to key on, and payment/PII tokenization vaults are
//     overwhelmingly vendor-proprietary, so no non-invented library entry
//     was available. `tokenize*` additionally collides with NLP/lexer
//     tokenization (`tokenize(sourceText)`), which is a real transformation
//     but not this one — hence 'medium' and an evidence string that says so.
//  4. Serialization/deserialization (`JSON.stringify`, `JSON.parse`) is
//     NOT cataloged as `encode`/`decode`. `MAPPING_TYPES` in `schema.js`
//     already has `serialization`/`deserialization` as their own values —
//     they are an edge's mapping type, not a transformation kind.
//  5. Argument-borne facts are never read. `crypto.createHash('sha256')`
//     yields `algorithm: null` here, because this module classifies a
//     CALLEE pattern and never sees a call site's arguments. A future
//     graph builder with the call site in hand can refine it.
//  6. `encodeURIComponent` is ALSO a sanitizer in `dataflow/catalog.js`.
//     That is not a conflict: "neutralizes XSS" and "is an `encode`
//     transformation" are two different axes for two different consumers.
//     This module never imports or consults that classification.
//  7. Factory attribution (task review M1a): `crypto.createHash`/
//     `createCipheriv`/`createHmac`, and Java's `MessageDigest.getInstance`,
//     classify the FACTORY call, not the later call where the data actually
//     flows (`h.update(pii); h.digest()`). Sub-project E — the first real
//     consumer of this module, which attaches access paths and code
//     location to build a real Transformation entity — must not assume the
//     factory call site is where the input/output paths live; it is only
//     the call site that names WHICH transformation is about to happen.
//  8. Language scope (task review M1b): the `py`/`java` entries (9 of 42)
//     are ahead of this engine's current JS/TS-only scope (Sub-project D's
//     own scoping doc explicitly excludes any language beyond JS/TS) and
//     cannot fire against anything this codebase parses today. Kept,
//     disclosed rather than removed, since each carries a distinctive
//     qualified receiver (`hashlib.*`, `base64.*`,
//     `MessageDigest.getInstance`) with no plausible JS collision risk.
//  9. The `language` field (task review M1c) is DOCUMENTARY ONLY —
//     `_entryMatches` never reads it. Matching is language-agnostic by
//     construction; a caller must not assume passing a `language` hint
//     narrows which entries can match, because none does.
//
// ─── Entry shape ────────────────────────────────────────────────────────
//
// Structurally parallel to `dataflow/catalog.js` (one entry per logical
// row, with `id` / `language` / `match`) for a future reader's
// familiarity — but it is NOT that catalog's data and never reads it.
//
//   { id, language,  // documentary only — see gap 9 above, never read by matching
//     kind, reversibility, algorithm, confidence,
//     match: { type: 'call',        callee }          // bare/global call
//          | { type: 'member-call', object, method }  // `object.method()`
//          | { type: 'name-pattern', pattern, notObjects? },
//     evidence,   // '{name}' is replaced with the matched callee text
//     examples }  // every entry is proven matchable by a real test
//

import { TRANSFORM_KINDS, REVERSIBILITY_VALUES } from './schema.js';

// Receivers that mean "this is still the global builtin" for a `call`
// entry — `window.btoa(x)` is `btoa(x)`.
const GLOBAL_RECEIVERS = Object.freeze(['window', 'globalThis', 'global', 'self']);

// A naming-convention pattern matches `verb`, `verbSomething`, `verb_something`
// and `verb2` — but never `verbed`/`verbing`/`verbal`, and never a name that
// merely CONTAINS the verb (`applyMask` is a bitmask helper, not a mask
// transform — `privacy-catalog.js`'s own comment records that same trap).
const namingConvention = (verb) => new RegExp(`^${verb}(?=[A-Z_0-9]|$)`);

export const TRANSFORM_CATALOG = Object.freeze([
  // ─── hash — irreversible by construction ───────────────────────────────
  { id: 'js-node-create-hash',    language: 'js',   kind: 'hash', reversibility: 'irreversible', algorithm: null,       confidence: 'high',   match: { type: 'member-call', object: 'crypto', method: 'createHash' },   evidence: "call to '{name}' — Node's built-in cryptographic hash factory (the digest algorithm is an argument, not read here)", examples: ['crypto.createHash'] },
  { id: 'js-node-create-hmac',    language: 'js',   kind: 'hash', reversibility: 'irreversible', algorithm: null,       confidence: 'high',   match: { type: 'member-call', object: 'crypto', method: 'createHmac' },   evidence: "call to '{name}' — Node's built-in keyed-MAC factory; a keyed hash, still one-way (the digest algorithm is an argument, not read here)", examples: ['crypto.createHmac'] },
  { id: 'js-node-pbkdf2',         language: 'js',   kind: 'hash', reversibility: 'irreversible', algorithm: 'pbkdf2',   confidence: 'high',   match: { type: 'member-call', object: 'crypto', method: 'pbkdf2' },       evidence: "call to '{name}' — Node's built-in PBKDF2 key-derivation function", examples: ['crypto.pbkdf2'] },
  { id: 'js-node-pbkdf2-sync',    language: 'js',   kind: 'hash', reversibility: 'irreversible', algorithm: 'pbkdf2',   confidence: 'high',   match: { type: 'member-call', object: 'crypto', method: 'pbkdf2Sync' },   evidence: "call to '{name}' — Node's built-in PBKDF2 key-derivation function (sync form)", examples: ['crypto.pbkdf2Sync'] },
  { id: 'js-node-scrypt',         language: 'js',   kind: 'hash', reversibility: 'irreversible', algorithm: 'scrypt',   confidence: 'high',   match: { type: 'member-call', object: 'crypto', method: 'scrypt' },       evidence: "call to '{name}' — Node's built-in scrypt key-derivation function", examples: ['crypto.scrypt'] },
  { id: 'js-node-scrypt-sync',    language: 'js',   kind: 'hash', reversibility: 'irreversible', algorithm: 'scrypt',   confidence: 'high',   match: { type: 'member-call', object: 'crypto', method: 'scryptSync' },   evidence: "call to '{name}' — Node's built-in scrypt key-derivation function (sync form)", examples: ['crypto.scryptSync'] },
  { id: 'js-webcrypto-digest',    language: 'js',   kind: 'hash', reversibility: 'irreversible', algorithm: null,       confidence: 'high',   match: { type: 'member-call', object: 'subtle', method: 'digest' },       evidence: "call to '{name}' — the Web Crypto API's SubtleCrypto.digest (the digest algorithm is an argument, not read here)", examples: ['crypto.subtle.digest'] },
  { id: 'js-bcrypt-hash',         language: 'js',   kind: 'hash', reversibility: 'irreversible', algorithm: 'bcrypt',   confidence: 'high',   match: { type: 'member-call', object: 'bcrypt', method: 'hash' },         evidence: "call to '{name}' — the bcrypt password-hashing library", examples: ['bcrypt.hash'] },
  { id: 'js-bcrypt-hash-sync',    language: 'js',   kind: 'hash', reversibility: 'irreversible', algorithm: 'bcrypt',   confidence: 'high',   match: { type: 'member-call', object: 'bcrypt', method: 'hashSync' },     evidence: "call to '{name}' — the bcrypt password-hashing library (sync form)", examples: ['bcrypt.hashSync'] },
  { id: 'js-argon2-hash',         language: 'js',   kind: 'hash', reversibility: 'irreversible', algorithm: 'argon2',   confidence: 'high',   match: { type: 'member-call', object: 'argon2', method: 'hash' },         evidence: "call to '{name}' — the argon2 password-hashing library", examples: ['argon2.hash'] },
  { id: 'py-hashlib-sha256',      language: 'py',   kind: 'hash', reversibility: 'irreversible', algorithm: 'sha256',   confidence: 'high',   match: { type: 'member-call', object: 'hashlib', method: 'sha256' },      evidence: "call to '{name}' — Python's stdlib hashlib; the callee name itself states the digest algorithm", examples: ['hashlib.sha256'] },
  { id: 'py-hashlib-sha512',      language: 'py',   kind: 'hash', reversibility: 'irreversible', algorithm: 'sha512',   confidence: 'high',   match: { type: 'member-call', object: 'hashlib', method: 'sha512' },      evidence: "call to '{name}' — Python's stdlib hashlib; the callee name itself states the digest algorithm", examples: ['hashlib.sha512'] },
  { id: 'py-hashlib-sha1',        language: 'py',   kind: 'hash', reversibility: 'irreversible', algorithm: 'sha1',     confidence: 'high',   match: { type: 'member-call', object: 'hashlib', method: 'sha1' },        evidence: "call to '{name}' — Python's stdlib hashlib; the callee name itself states the digest algorithm (recognized, not endorsed: SHA-1 is broken for collision resistance)", examples: ['hashlib.sha1'] },
  { id: 'py-hashlib-md5',         language: 'py',   kind: 'hash', reversibility: 'irreversible', algorithm: 'md5',      confidence: 'high',   match: { type: 'member-call', object: 'hashlib', method: 'md5' },         evidence: "call to '{name}' — Python's stdlib hashlib; the callee name itself states the digest algorithm (recognized, not endorsed: MD5 is broken)", examples: ['hashlib.md5'] },
  { id: 'java-message-digest',    language: 'java', kind: 'hash', reversibility: 'irreversible', algorithm: null,       confidence: 'high',   match: { type: 'member-call', object: 'MessageDigest', method: 'getInstance' }, evidence: "call to '{name}' — the JCA MessageDigest factory (the digest algorithm is an argument, not read here)", examples: ['MessageDigest.getInstance'] },

  // ─── encrypt — reversible by design ────────────────────────────────────
  { id: 'js-node-cipheriv',       language: 'js',   kind: 'encrypt', reversibility: 'reversible', algorithm: null,      confidence: 'high',   match: { type: 'member-call', object: 'crypto', method: 'createCipheriv' }, evidence: "call to '{name}' — Node's built-in symmetric cipher factory (the cipher suite is an argument, not read here)", examples: ['crypto.createCipheriv'] },
  { id: 'js-node-cipher-legacy',  language: 'js',   kind: 'encrypt', reversibility: 'reversible', algorithm: null,      confidence: 'high',   match: { type: 'member-call', object: 'crypto', method: 'createCipher' },   evidence: "call to '{name}' — Node's deprecated symmetric cipher factory (removed in Node 22; still present in legacy code)", examples: ['crypto.createCipher'] },
  { id: 'js-node-public-encrypt', language: 'js',   kind: 'encrypt', reversibility: 'reversible', algorithm: null,      confidence: 'high',   match: { type: 'member-call', object: 'crypto', method: 'publicEncrypt' },  evidence: "call to '{name}' — Node's built-in public-key encryption (the key and padding are arguments, not read here)", examples: ['crypto.publicEncrypt'] },
  { id: 'js-webcrypto-encrypt',   language: 'js',   kind: 'encrypt', reversibility: 'reversible', algorithm: null,      confidence: 'high',   match: { type: 'member-call', object: 'subtle', method: 'encrypt' },        evidence: "call to '{name}' — the Web Crypto API's SubtleCrypto.encrypt (the cipher suite is an argument, not read here)", examples: ['crypto.subtle.encrypt'] },
  { id: 'app-encrypt-naming',     language: '*',    kind: 'encrypt', reversibility: 'reversible', algorithm: null,      confidence: 'medium', match: { type: 'name-pattern', pattern: namingConvention('encrypt') },      evidence: "callee name '{name}' matches the `encrypt*` naming convention (medium: an application-defined name, not a library API — the cipher and key management are unknown)", examples: ['encrypt', 'encryptCardNumber', 'vault.encryptField'] },

  // ─── decrypt — the direct counterparts ─────────────────────────────────
  { id: 'js-node-decipheriv',     language: 'js',   kind: 'decrypt', reversibility: 'reversible', algorithm: null,      confidence: 'high',   match: { type: 'member-call', object: 'crypto', method: 'createDecipheriv' }, evidence: "call to '{name}' — Node's built-in symmetric decipher factory (the cipher suite is an argument, not read here)", examples: ['crypto.createDecipheriv'] },
  { id: 'js-node-decipher-legacy',language: 'js',   kind: 'decrypt', reversibility: 'reversible', algorithm: null,      confidence: 'high',   match: { type: 'member-call', object: 'crypto', method: 'createDecipher' },   evidence: "call to '{name}' — Node's deprecated symmetric decipher factory (removed in Node 22; still present in legacy code)", examples: ['crypto.createDecipher'] },
  { id: 'js-node-private-decrypt',language: 'js',   kind: 'decrypt', reversibility: 'reversible', algorithm: null,      confidence: 'high',   match: { type: 'member-call', object: 'crypto', method: 'privateDecrypt' },   evidence: "call to '{name}' — Node's built-in private-key decryption (the key and padding are arguments, not read here)", examples: ['crypto.privateDecrypt'] },
  { id: 'js-webcrypto-decrypt',   language: 'js',   kind: 'decrypt', reversibility: 'reversible', algorithm: null,      confidence: 'high',   match: { type: 'member-call', object: 'subtle', method: 'decrypt' },          evidence: "call to '{name}' — the Web Crypto API's SubtleCrypto.decrypt (the cipher suite is an argument, not read here)", examples: ['crypto.subtle.decrypt'] },
  { id: 'app-decrypt-naming',     language: '*',    kind: 'decrypt', reversibility: 'reversible', algorithm: null,      confidence: 'medium', match: { type: 'name-pattern', pattern: namingConvention('decrypt') },        evidence: "callee name '{name}' matches the `decrypt*` naming convention (medium: an application-defined name, not a library API)", examples: ['decrypt', 'decryptCardNumber', 'vault.decryptField'] },

  // ─── encode — reversible ───────────────────────────────────────────────
  { id: 'js-encode-uri-component',language: 'js',   kind: 'encode', reversibility: 'reversible', algorithm: null,       confidence: 'high',   match: { type: 'call', callee: 'encodeURIComponent' },                        evidence: "call to '{name}' — the ECMAScript global URI-component encoder (classified here on the TRANSFORMATION axis; its separate role as an XSS sanitizer is a different axis this module never consults)", examples: ['encodeURIComponent', 'window.encodeURIComponent'] },
  { id: 'js-encode-uri',          language: 'js',   kind: 'encode', reversibility: 'reversible', algorithm: null,       confidence: 'high',   match: { type: 'call', callee: 'encodeURI' },                                 evidence: "call to '{name}' — the ECMAScript global URI encoder", examples: ['encodeURI'] },
  { id: 'js-btoa',                language: 'js',   kind: 'encode', reversibility: 'reversible', algorithm: 'base64',   confidence: 'high',   match: { type: 'call', callee: 'btoa' },                                      evidence: "call to '{name}' — the platform global base64 encoder (base64 by specification, so the algorithm is statically knowable from the callee alone)", examples: ['btoa', 'window.btoa'] },
  { id: 'py-b64encode',           language: 'py',   kind: 'encode', reversibility: 'reversible', algorithm: 'base64',   confidence: 'high',   match: { type: 'member-call', object: 'base64', method: 'b64encode' },        evidence: "call to '{name}' — Python's stdlib base64 encoder", examples: ['base64.b64encode'] },
  { id: 'py-b64encode-urlsafe',   language: 'py',   kind: 'encode', reversibility: 'reversible', algorithm: 'base64',   confidence: 'high',   match: { type: 'member-call', object: 'base64', method: 'urlsafe_b64encode' }, evidence: "call to '{name}' — Python's stdlib URL-safe base64 encoder", examples: ['base64.urlsafe_b64encode'] },

  // ─── decode — the direct counterparts ──────────────────────────────────
  { id: 'js-decode-uri-component',language: 'js',   kind: 'decode', reversibility: 'reversible', algorithm: null,       confidence: 'high',   match: { type: 'call', callee: 'decodeURIComponent' },                        evidence: "call to '{name}' — the ECMAScript global URI-component decoder", examples: ['decodeURIComponent', 'window.decodeURIComponent'] },
  { id: 'js-decode-uri',          language: 'js',   kind: 'decode', reversibility: 'reversible', algorithm: null,       confidence: 'high',   match: { type: 'call', callee: 'decodeURI' },                                 evidence: "call to '{name}' — the ECMAScript global URI decoder", examples: ['decodeURI'] },
  { id: 'js-atob',                language: 'js',   kind: 'decode', reversibility: 'reversible', algorithm: 'base64',   confidence: 'high',   match: { type: 'call', callee: 'atob' },                                      evidence: "call to '{name}' — the platform global base64 decoder (base64 by specification, so the algorithm is statically knowable from the callee alone)", examples: ['atob', 'window.atob'] },
  { id: 'py-b64decode',           language: 'py',   kind: 'decode', reversibility: 'reversible', algorithm: 'base64',   confidence: 'high',   match: { type: 'member-call', object: 'base64', method: 'b64decode' },        evidence: "call to '{name}' — Python's stdlib base64 decoder", examples: ['base64.b64decode'] },
  { id: 'py-b64decode-urlsafe',   language: 'py',   kind: 'decode', reversibility: 'reversible', algorithm: 'base64',   confidence: 'high',   match: { type: 'member-call', object: 'base64', method: 'urlsafe_b64decode' }, evidence: "call to '{name}' — Python's stdlib URL-safe base64 decoder", examples: ['base64.urlsafe_b64decode'] },

  // ─── mask — irreversible; naming convention only, by measurement ───────
  // Masking has no canonical library the way hashing does: it is written
  // per-application (`maskCard`, `maskSSN`, `maskEmail`). The convention IS
  // the only reliable signal, so this kind tops out at 'medium'.
  { id: 'app-mask-naming',        language: '*',    kind: 'mask',     reversibility: 'irreversible', algorithm: null,   confidence: 'medium', match: { type: 'name-pattern', pattern: namingConvention('mask') },           evidence: "callee name '{name}' matches the app-level `mask*` naming convention (medium: no canonical masking library exists to key on, and a same-named application function could be e.g. a bitmask helper)", examples: ['maskCard', 'maskSSN', 'pii.maskEmail'] },

  // ─── redact — irreversible; naming convention only ─────────────────────
  { id: 'app-redact-naming',      language: '*',    kind: 'redact',   reversibility: 'irreversible', algorithm: null,   confidence: 'medium', match: { type: 'name-pattern', pattern: namingConvention('redact') },         evidence: "callee name '{name}' matches the app-level `redact*` naming convention (medium: the well-known log redactors are configured declaratively, not called by a stable name, so there is no library API to key on)", examples: ['redact', 'redactSecrets', 'log.redactFields'] },

  // ─── tokenize — REVERSIBLE, and deliberately not a mask ────────────────
  { id: 'app-tokenize-naming',    language: '*',    kind: 'tokenize', reversibility: 'reversible',   algorithm: null,   confidence: 'medium', match: { type: 'name-pattern', pattern: namingConvention('tokenize') },       evidence: "callee name '{name}' matches the `tokenize*` naming convention (medium: tokenization vaults are overwhelmingly vendor-proprietary, so no library API was available to key on; and this name also denotes NLP/lexer tokenization, a different transformation entirely)", examples: ['tokenize', 'tokenizeCard', 'vault.tokenizePAN'] },

  // ─── aggregate — irreversible (per-record detail is discarded) ─────────
  { id: 'app-aggregate-naming',   language: '*',    kind: 'aggregate', reversibility: 'irreversible', algorithm: null,  confidence: 'medium', match: { type: 'name-pattern', pattern: namingConvention('aggregate') },      evidence: "callee name '{name}' matches the `aggregate*` naming convention (medium: this is the thinnest kind in the catalog — aggregation is normally an unnamed data-shape operation like `.reduce()`/`.groupBy()` with no callee to key on)", examples: ['aggregate', 'aggregateByRegion', 'collection.aggregate'] },

  // ─── truncate — irreversible ───────────────────────────────────────────
  { id: 'js-lodash-truncate',     language: 'js',   kind: 'truncate', reversibility: 'irreversible', algorithm: null,   confidence: 'medium', match: { type: 'member-call', object: '_', method: 'truncate' },              evidence: "call to '{name}' — lodash's string truncation (medium not because the callee is ambiguous but because the API is general-purpose: it is not necessarily applied as a privacy control)", examples: ['_.truncate'] },
  // `notObjects` keeps a real, unrelated Node API out: `fs.truncate` /
  // `fsPromises.truncate` shorten a FILE, they do not transform a value.
  { id: 'app-truncate-naming',    language: '*',    kind: 'truncate', reversibility: 'irreversible', algorithm: null,   confidence: 'medium', match: { type: 'name-pattern', pattern: namingConvention('truncate'), notObjects: ['fs', 'fsPromises', 'fsp'] }, evidence: "callee name '{name}' matches the `truncate*` naming convention (medium: general-purpose shortening, not necessarily a privacy control; `fs.truncate`, which shortens a file rather than a value, is excluded)", examples: ['truncate', 'truncateEmail', 'text.truncateTo'] },

  // ─── normalize — reversibility genuinely UNKNOWN ───────────────────────
  // Unicode normalization can be lossless (NFC/NFD round-trip) or lossy
  // (NFKC/NFKD), path normalization discards `..` segments, and email
  // normalization lowercases and strips tags. The callee alone cannot say
  // which — so `unknown` is the honest value, not an overclaim in either
  // direction.
  { id: 'app-normalize-naming',   language: '*',    kind: 'normalize', reversibility: 'unknown',     algorithm: null,   confidence: 'medium', match: { type: 'name-pattern', pattern: namingConvention('normalize') },      evidence: "callee name '{name}' matches the `normalize*` convention, which the ecosystem uses consistently for normalization (String.prototype.normalize, path.normalize, validator.normalizeEmail) — medium because this name-level match cannot tell the ECMAScript builtin from a same-named application function, and the normalization FORM (lossy or lossless) is never knowable from the callee", examples: ['normalize', 'normalizeEmail', 'path.normalize', 'validator.normalizeEmail'] },
]);

/**
 * Split a callee descriptor into the pieces the matchers need.
 * Returns `null` for anything malformed — a caller that could not fully
 * resolve a callee may legitimately hand over a partial descriptor, and
 * that is "no match", never a crash.
 */
function _normalizeDescriptor(descriptor) {
  if (!descriptor || typeof descriptor !== 'object' || Array.isArray(descriptor)) return null;

  if (descriptor.type === 'call') {
    const { callee } = descriptor;
    if (typeof callee !== 'string' || callee.trim() === '') return null;
    const segs = callee.split('.').filter(Boolean);
    if (segs.length === 0) return null;
    return {
      name: segs[segs.length - 1],
      object: segs.length >= 2 ? segs[segs.length - 2] : null,
      display: callee,
      bare: segs.length === 1,
    };
  }

  if (descriptor.type === 'member-call') {
    const { object, method } = descriptor;
    if (typeof object !== 'string' || object.trim() === '') return null;
    if (typeof method !== 'string' || method.trim() === '') return null;
    const objSegs = object.split('.').filter(Boolean);
    if (objSegs.length === 0) return null;
    return {
      name: method,
      object: objSegs[objSegs.length - 1],
      display: `${object}.${method}`,
      bare: false,
    };
  }

  return null;
}

function _entryMatches(entry, c) {
  const m = entry.match;
  if (m.type === 'call') {
    if (c.name !== m.callee) return false;
    return c.bare || GLOBAL_RECEIVERS.includes(c.object);
  }
  if (m.type === 'member-call') {
    return c.object === m.object && c.name === m.method;
  }
  if (m.type === 'name-pattern') {
    if (!m.pattern.test(c.name)) return false;
    if (m.notObjects && c.object && m.notObjects.includes(c.object)) return false;
    return true;
  }
  return false;
}

/**
 * Classify a callee pattern as a §10.6 data transformation.
 *
 * @param {{type: 'call', callee: string}
 *        |{type: 'member-call', object: string, method: string}} calleeDescriptor
 *   A bare call (`maskCard(x)` → `{type:'call', callee:'maskCard'}`) or a
 *   method call (`crypto.createHash('sha256')` →
 *   `{type:'member-call', object:'crypto', method:'createHash'}`). A dotted
 *   `callee` string (`'crypto.createHash'`) is accepted too and resolves
 *   identically. Anything else — including `undefined`, a partial shape or
 *   an unrecognized `type` — returns `null` rather than throwing.
 *
 * @returns {{kind: string, reversibility: string, algorithm: string|null,
 *            confidence: 'high'|'medium', evidence: string}|null}
 *   `null` when this catalog recognizes no transformation. `kind` is always
 *   a `TRANSFORM_KINDS` value and `reversibility` always a
 *   `REVERSIBILITY_VALUES` value. There is deliberately NO control-credit
 *   field — see this file's header.
 */
export function recognizeTransformation(calleeDescriptor) {
  const c = _normalizeDescriptor(calleeDescriptor);
  if (!c) return null;

  // First match wins. Exact `call`/`member-call` entries are listed ahead
  // of the naming-convention entries for each kind, so a library API can
  // never be reported as a weaker naming-convention match.
  for (const entry of TRANSFORM_CATALOG) {
    if (!_entryMatches(entry, c)) continue;
    return {
      kind: entry.kind,
      reversibility: entry.reversibility,
      algorithm: entry.algorithm,
      confidence: entry.confidence,
      evidence: entry.evidence.replace('{name}', c.display),
    };
  }
  return null;
}

/**
 * The exact key set of a non-null `recognizeTransformation` result.
 * Exported so a consumer — and this module's own tests — can assert the
 * shape without hand-copying it, and so Decision 2's boundary (no
 * control-credit field, ever) is enforceable structurally rather than by
 * reading prose.
 */
export const TRANSFORM_DECISION_KEYS = Object.freeze([
  'kind', 'reversibility', 'algorithm', 'confidence', 'evidence',
]);

/** Confidence tiers this catalog can emit. There is deliberately no 'low'. */
export const TRANSFORM_CONFIDENCE_VALUES = Object.freeze(['high', 'medium']);

/**
 * The `TRANSFORM_KINDS` values this catalog deliberately never emits — a
 * recognizer's honest answer for an unrecognized callee is `null`, and
 * choosing between `custom` and `unknown` belongs to whoever must still
 * materialize a Transformation entity. Kept as data (not prose alone) so a
 * test can pin it, per this package's disclose-the-gap convention.
 */
export const NEVER_EMITTED_KINDS = Object.freeze(['custom', 'unknown']);

// ─────────────────────────────────────────────────────────────────────────
// Load-time integrity check. This is the ONLY use of the two schema.js
// imports, and it is deliberate: a catalog that hardcodes enum strings
// without ever referencing the source of truth is exactly the silent-drift
// hazard this package's own conventions warn about. A failure here is a
// programming error in THIS file (never bad caller input), so failing at
// import is correct — a catalog entry carrying a value outside
// `TRANSFORM_KINDS`/`REVERSIBILITY_VALUES` would otherwise reach a
// DataFlowGraph v1 Transformation entity and validate nowhere.
// ─────────────────────────────────────────────────────────────────────────
for (const entry of TRANSFORM_CATALOG) {
  Object.freeze(entry);
  Object.freeze(entry.match);
  Object.freeze(entry.examples);
  if (!TRANSFORM_KINDS.includes(entry.kind)) {
    throw new Error(`transform-catalog.js: entry '${entry.id}' has kind '${entry.kind}', which is not in TRANSFORM_KINDS`);
  }
  if (NEVER_EMITTED_KINDS.includes(entry.kind)) {
    throw new Error(`transform-catalog.js: entry '${entry.id}' emits '${entry.kind}', which this catalog must never emit (return null instead)`);
  }
  if (!REVERSIBILITY_VALUES.includes(entry.reversibility)) {
    throw new Error(`transform-catalog.js: entry '${entry.id}' has reversibility '${entry.reversibility}', which is not in REVERSIBILITY_VALUES`);
  }
}
