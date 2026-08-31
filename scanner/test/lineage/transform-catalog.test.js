//
// transform-catalog.test.js — Data Flow Explorer, Sub-project D, increment D4.
//
// Proves `src/lineage/transform-catalog.js`'s transformation-kind
// recognition, including:
//   - AC-02's own worked example (a `maskCard()` transform vs. a raw log
//     call), the acceptance criterion this whole increment exists to serve;
//   - §10.6's explicit "masking, hashing, tokenization and encryption must
//     never be treated as synonyms" rule;
//   - Decision 2's binding boundary: no control-credit field, ever;
//   - every catalog entry being genuinely matchable (no prose-only rows).
//
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  TRANSFORM_CATALOG,
  TRANSFORM_DECISION_KEYS,
  TRANSFORM_CONFIDENCE_VALUES,
  NEVER_EMITTED_KINDS,
  recognizeTransformation,
} from '../../src/lineage/transform-catalog.js';
import { TRANSFORM_KINDS, REVERSIBILITY_VALUES } from '../../src/lineage/schema.js';

// ─────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────

/** Every descriptor form an example name can legitimately arrive as. */
function descriptorsFor(exampleName) {
  const out = [{ type: 'call', callee: exampleName }];
  const segs = exampleName.split('.');
  if (segs.length >= 2) {
    out.push({ type: 'member-call', object: segs.slice(0, -1).join('.'), method: segs[segs.length - 1] });
  }
  return out;
}

const KINDS_IN_CATALOG = [...new Set(TRANSFORM_CATALOG.map(e => e.kind))].sort();

// ─────────────────────────────────────────────────────────────────────────
// D4/1 — AC-02's own worked example
// ─────────────────────────────────────────────────────────────────────────

test('D4/1a: AC-02 — maskCard() is recognized as a mask transform', () => {
  const decision = recognizeTransformation({ type: 'call', callee: 'maskCard' });
  assert.ok(decision, 'maskCard must be recognized');
  assert.equal(decision.kind, 'mask');
  assert.equal(decision.reversibility, 'irreversible');
  assert.equal(decision.algorithm, null);
  assert.equal(decision.confidence, 'medium', 'a naming-convention match is medium, never high');
  assert.match(decision.evidence, /maskCard/, 'evidence must name the pattern actually matched');
});

test('D4/1b: AC-02 — a raw log call is recognized as NO transformation at all', () => {
  // The raw-log half of AC-02. This module's job is only to report that it
  // recognizes no transformation here — deciding that logging a card number
  // is an ISSUE belongs to a sink registry plus Milestone 2's analyzers,
  // never to this catalog.
  assert.equal(recognizeTransformation({ type: 'member-call', object: 'logger', method: 'info' }), null);
  assert.equal(recognizeTransformation({ type: 'member-call', object: 'console', method: 'log' }), null);
  assert.equal(recognizeTransformation({ type: 'call', callee: 'log' }), null);
});

test('D4/1c: AC-02 — the masked and raw call sites are distinguishable by this module alone', () => {
  const masked = recognizeTransformation({ type: 'call', callee: 'maskCard' });
  const raw = recognizeTransformation({ type: 'member-call', object: 'logger', method: 'info' });
  assert.notDeepEqual(masked, raw);
  assert.ok(masked !== null && raw === null,
    'the whole point of AC-02: the masked flow carries a transformation decision, the raw one carries none');
});

test('D4/1d: AC-02 — masking is applied through a receiver too (pii.maskEmail)', () => {
  const decision = recognizeTransformation({ type: 'member-call', object: 'pii', method: 'maskEmail' });
  assert.equal(decision.kind, 'mask');
  assert.match(decision.evidence, /pii\.maskEmail/);
});

// ─────────────────────────────────────────────────────────────────────────
// D4/2 — §10.6: never synonyms
// ─────────────────────────────────────────────────────────────────────────

test('D4/2a: mask, hash, tokenize and encrypt resolve to four DIFFERENT kinds', () => {
  const mask = recognizeTransformation({ type: 'call', callee: 'maskCard' });
  const hash = recognizeTransformation({ type: 'member-call', object: 'bcrypt', method: 'hash' });
  const tokenize = recognizeTransformation({ type: 'call', callee: 'tokenizeCard' });
  const encrypt = recognizeTransformation({ type: 'member-call', object: 'crypto', method: 'createCipheriv' });

  const kinds = [mask.kind, hash.kind, tokenize.kind, encrypt.kind];
  assert.deepEqual(kinds, ['mask', 'hash', 'tokenize', 'encrypt']);
  assert.equal(new Set(kinds).size, 4, '§10.6: these four must never be treated as synonyms');
});

test('D4/2b: the four are also distinguished by REVERSIBILITY, not just by label', () => {
  // A catalog could satisfy D4/2a with four labels that all mean the same
  // thing. Reversibility is the semantic half of the same rule: a token is
  // designed to be detokenized; a mask and a hash destroy information.
  assert.equal(recognizeTransformation({ type: 'call', callee: 'maskCard' }).reversibility, 'irreversible');
  assert.equal(recognizeTransformation({ type: 'member-call', object: 'bcrypt', method: 'hash' }).reversibility, 'irreversible');
  assert.equal(recognizeTransformation({ type: 'call', callee: 'tokenizeCard' }).reversibility, 'reversible');
  assert.equal(recognizeTransformation({ type: 'member-call', object: 'crypto', method: 'createCipheriv' }).reversibility, 'reversible');
});

test('D4/2c: encrypt and decrypt are distinct kinds, not one bidirectional kind', () => {
  assert.equal(recognizeTransformation({ type: 'member-call', object: 'crypto', method: 'createCipheriv' }).kind, 'encrypt');
  assert.equal(recognizeTransformation({ type: 'member-call', object: 'crypto', method: 'createDecipheriv' }).kind, 'decrypt');
  assert.equal(recognizeTransformation({ type: 'call', callee: 'encodeURIComponent' }).kind, 'encode');
  assert.equal(recognizeTransformation({ type: 'call', callee: 'decodeURIComponent' }).kind, 'decode');
});

// ─────────────────────────────────────────────────────────────────────────
// D4/3 — totality: every entry is genuinely matchable, no prose-only rows
// ─────────────────────────────────────────────────────────────────────────

test('D4/3a: every catalog entry declares at least one example', () => {
  for (const entry of TRANSFORM_CATALOG) {
    assert.ok(Array.isArray(entry.examples) && entry.examples.length > 0, `${entry.id} declares no example`);
  }
});

test('D4/3b: every example of every entry matches, and yields that entry\'s own classification', () => {
  for (const entry of TRANSFORM_CATALOG) {
    for (const example of entry.examples) {
      for (const descriptor of descriptorsFor(example)) {
        const decision = recognizeTransformation(descriptor);
        const where = `${entry.id} / ${example} / ${descriptor.type}`;
        assert.ok(decision, `${where}: expected a match, got null`);
        assert.equal(decision.kind, entry.kind, where);
        assert.equal(decision.reversibility, entry.reversibility, where);
        assert.equal(decision.algorithm, entry.algorithm, where);
        assert.equal(decision.confidence, entry.confidence, where);
        assert.match(decision.evidence, new RegExp(example.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')),
          `${where}: evidence must name the pattern actually matched`);
      }
    }
  }
});

test('D4/3c: the dotted-call and member-call descriptor forms agree exactly', () => {
  // A future caller may resolve `crypto.createHash(...)` either way; the two
  // must never produce different classifications.
  for (const example of ['crypto.createHash', 'bcrypt.hashSync', 'hashlib.md5', 'crypto.subtle.encrypt', '_.truncate']) {
    const [asCall, asMember] = descriptorsFor(example);
    assert.deepEqual(recognizeTransformation(asCall), recognizeTransformation(asMember), example);
  }
});

test('D4/3d: entry ids are unique', () => {
  const ids = TRANSFORM_CATALOG.map(e => e.id);
  assert.equal(new Set(ids).size, ids.length);
});

// ─────────────────────────────────────────────────────────────────────────
// D4/4 — enum discipline: kind/reversibility/confidence are always valid
// ─────────────────────────────────────────────────────────────────────────

test('D4/4a: every entry\'s kind and reversibility are live schema.js enum values', () => {
  for (const entry of TRANSFORM_CATALOG) {
    assert.ok(TRANSFORM_KINDS.includes(entry.kind), `${entry.id}: ${entry.kind}`);
    assert.ok(REVERSIBILITY_VALUES.includes(entry.reversibility), `${entry.id}: ${entry.reversibility}`);
    assert.ok(TRANSFORM_CONFIDENCE_VALUES.includes(entry.confidence), `${entry.id}: ${entry.confidence}`);
  }
});

test('D4/4b: every returned decision, over every example, carries valid enum values', () => {
  let checked = 0;
  for (const entry of TRANSFORM_CATALOG) {
    for (const example of entry.examples) {
      for (const descriptor of descriptorsFor(example)) {
        const d = recognizeTransformation(descriptor);
        assert.ok(TRANSFORM_KINDS.includes(d.kind));
        assert.ok(REVERSIBILITY_VALUES.includes(d.reversibility));
        assert.ok(TRANSFORM_CONFIDENCE_VALUES.includes(d.confidence));
        assert.ok(d.algorithm === null || (typeof d.algorithm === 'string' && d.algorithm.length > 0));
        assert.ok(typeof d.evidence === 'string' && d.evidence.length > 0);
        checked += 1;
      }
    }
  }
  assert.ok(checked >= TRANSFORM_CATALOG.length, 'the sweep must actually have run');
});

test('D4/4c: `custom` and `unknown` are never emitted — null is the honest no-match answer', () => {
  assert.deepEqual(NEVER_EMITTED_KINDS, ['custom', 'unknown']);
  for (const entry of TRANSFORM_CATALOG) {
    assert.ok(!NEVER_EMITTED_KINDS.includes(entry.kind), `${entry.id} emits a fallback kind`);
  }
});

test('D4/4d: every non-fallback TRANSFORM_KINDS value is reachable — measured, not assumed', () => {
  const expected = TRANSFORM_KINDS.filter(k => !NEVER_EMITTED_KINDS.includes(k)).sort();
  assert.deepEqual(KINDS_IN_CATALOG, expected,
    'each of the 11 real kinds must have at least one entry; a kind deliberately left empty must be removed from this assertion AND disclosed in the module header');
});

// ─────────────────────────────────────────────────────────────────────────
// D4/5 — Decision 2's boundary: NO control-credit field, ever
// ─────────────────────────────────────────────────────────────────────────

const CREDIT_LIKE = /credit|granted|denied|verdict|protected|protection|control|approved|compliant|passes/i;

test('D4/5a: a decision\'s key set is EXACTLY the five allowed keys', () => {
  for (const entry of TRANSFORM_CATALOG) {
    for (const example of entry.examples) {
      const d = recognizeTransformation({ type: 'call', callee: example });
      assert.deepEqual(Object.keys(d).sort(), [...TRANSFORM_DECISION_KEYS].sort(), `${entry.id} / ${example}`);
    }
  }
});

test('D4/5b: no decision key resembles a control-credit / protection-verdict field', () => {
  for (const key of TRANSFORM_DECISION_KEYS) {
    assert.ok(!CREDIT_LIKE.test(key), `decision key '${key}' looks like a protection verdict`);
  }
  for (const entry of TRANSFORM_CATALOG) {
    for (const example of entry.examples) {
      const d = recognizeTransformation({ type: 'call', callee: example });
      for (const key of Object.keys(d)) {
        assert.ok(!CREDIT_LIKE.test(key), `${entry.id}: decision key '${key}' looks like a protection verdict`);
      }
    }
  }
});

test('D4/5c: no catalog ENTRY carries a control-credit-like field either', () => {
  // The decision object is derived from the entry, so an entry-level credit
  // field is the likeliest way one would leak in later.
  for (const entry of TRANSFORM_CATALOG) {
    for (const key of Object.keys(entry)) {
      assert.ok(!CREDIT_LIKE.test(key), `${entry.id}: entry field '${key}' looks like a protection verdict`);
    }
    for (const key of Object.keys(entry.match)) {
      assert.ok(!CREDIT_LIKE.test(key), `${entry.id}: match field '${key}' looks like a protection verdict`);
    }
  }
});

test('D4/5d: the module exports no function that could award credit', () => {
  // Decision 2 is a boundary on the module's whole surface, not only on the
  // shape of one return value.
  const exported = ['TRANSFORM_CATALOG', 'TRANSFORM_DECISION_KEYS', 'TRANSFORM_CONFIDENCE_VALUES',
    'NEVER_EMITTED_KINDS', 'recognizeTransformation'];
  for (const name of exported) {
    assert.ok(!CREDIT_LIKE.test(name), `export '${name}' looks like a protection-verdict API`);
  }
});

// ─────────────────────────────────────────────────────────────────────────
// D4/6 — precision: a genuine non-match returns null, never a guess
// ─────────────────────────────────────────────────────────────────────────

test('D4/6a: plausible-but-uncataloged callees return null', () => {
  const uncataloged = [
    { type: 'call', callee: 'transform' },
    { type: 'call', callee: 'process' },
    { type: 'call', callee: 'sanitize' },
    { type: 'call', callee: 'convert' },
    { type: 'member-call', object: 'db', method: 'query' },
    { type: 'member-call', object: 'res', method: 'send' },
    { type: 'call', callee: 'JSON.stringify' },   // serialization is a MAPPING_TYPE, not a transform kind
    { type: 'call', callee: 'JSON.parse' },
  ];
  for (const d of uncataloged) {
    assert.equal(recognizeTransformation(d), null, JSON.stringify(d));
  }
});

test('D4/6b: the naming conventions do not fire on merely-containing or inflected names', () => {
  // `privacy-catalog.js`'s own comment records this exact trap: a substring
  // match on "mask" over-fires on a bitmask helper.
  for (const callee of ['applyMask', 'unmask', 'masked', 'masking', 'bitmaskOf',
    'redacted', 'tokenizer', 'aggregation', 'truncated', 'normalization', 'denormalize']) {
    assert.equal(recognizeTransformation({ type: 'call', callee }), null, callee);
  }
});

test('D4/6c: `fs.truncate` is excluded — it shortens a FILE, not a value', () => {
  assert.equal(recognizeTransformation({ type: 'member-call', object: 'fs', method: 'truncate' }), null);
  assert.equal(recognizeTransformation({ type: 'call', callee: 'fs.truncate' }), null);
  assert.equal(recognizeTransformation({ type: 'member-call', object: 'fsPromises', method: 'truncate' }), null);
  // ...while an ordinary value truncation still matches.
  assert.equal(recognizeTransformation({ type: 'call', callee: 'truncateEmail' }).kind, 'truncate');
});

test('D4/6d: `anonymize`/`pseudonymize` are deliberately NOT cataloged (disclosed gap)', () => {
  // Both are real, common names. Neither maps onto ONE TRANSFORM_KINDS
  // value, so cataloging either would collapse kinds §10.6 forbids
  // collapsing. This test exists so the omission is a recorded decision
  // rather than an oversight someone later "fixes" silently.
  assert.equal(recognizeTransformation({ type: 'call', callee: 'anonymize' }), null);
  assert.equal(recognizeTransformation({ type: 'call', callee: 'anonymizeUser' }), null);
  assert.equal(recognizeTransformation({ type: 'call', callee: 'pseudonymize' }), null);
});

test('D4/6e: a `call` entry for a platform global does not fire on an arbitrary receiver', () => {
  assert.equal(recognizeTransformation({ type: 'member-call', object: 'window', method: 'btoa' }).kind, 'encode');
  assert.equal(recognizeTransformation({ type: 'member-call', object: 'myCodec', method: 'btoa' }), null);
});

// ─────────────────────────────────────────────────────────────────────────
// D4/7 — algorithm is reported only when the callee itself names one
// ─────────────────────────────────────────────────────────────────────────

test('D4/7a: algorithm is populated only where the callee pattern states it', () => {
  assert.equal(recognizeTransformation({ type: 'member-call', object: 'bcrypt', method: 'hash' }).algorithm, 'bcrypt');
  assert.equal(recognizeTransformation({ type: 'member-call', object: 'argon2', method: 'hash' }).algorithm, 'argon2');
  assert.equal(recognizeTransformation({ type: 'member-call', object: 'hashlib', method: 'sha256' }).algorithm, 'sha256');
  assert.equal(recognizeTransformation({ type: 'call', callee: 'btoa' }).algorithm, 'base64');
});

test('D4/7b: an argument-borne algorithm is never guessed', () => {
  // `crypto.createHash('sha256')` names its algorithm in an ARGUMENT. This
  // module classifies a callee pattern and never sees a call site, so the
  // honest answer is null.
  assert.equal(recognizeTransformation({ type: 'member-call', object: 'crypto', method: 'createHash' }).algorithm, null);
  assert.equal(recognizeTransformation({ type: 'member-call', object: 'crypto', method: 'createCipheriv' }).algorithm, null);
  assert.equal(recognizeTransformation({ type: 'call', callee: 'encryptCardNumber' }).algorithm, null);
});

// ─────────────────────────────────────────────────────────────────────────
// D4/8 — confidence discipline
// ─────────────────────────────────────────────────────────────────────────

test('D4/8a: every naming-convention entry is medium, never high', () => {
  for (const entry of TRANSFORM_CATALOG) {
    if (entry.match.type !== 'name-pattern') continue;
    assert.equal(entry.confidence, 'medium', `${entry.id}: a naming-convention match can never be high-confidence`);
  }
});

test('D4/8b: there is no `low` tier — a low-confidence pattern belongs in the disclosed gaps, not the catalog', () => {
  assert.deepEqual(TRANSFORM_CONFIDENCE_VALUES, ['high', 'medium']);
  for (const entry of TRANSFORM_CATALOG) {
    assert.notEqual(entry.confidence, 'low');
  }
});

// ─────────────────────────────────────────────────────────────────────────
// D4/9 — malformed input never throws
// ─────────────────────────────────────────────────────────────────────────

test('D4/9a: malformed, partial and unknown-type descriptors return null, never throw', () => {
  const malformed = [
    undefined, null, {}, [], 0, '', 'maskCard', true, () => {},
    { type: 'unknown-type' },
    { type: 'call' },
    { type: 'call', callee: null },
    { type: 'call', callee: '' },
    { type: 'call', callee: '   ' },
    { type: 'call', callee: '.' },
    { type: 'call', callee: 42 },
    { type: 'member-call' },
    { type: 'member-call', object: 'crypto' },
    { type: 'member-call', method: 'createHash' },
    { type: 'member-call', object: '', method: 'createHash' },
    { type: 'member-call', object: 'crypto', method: '' },
    { type: 'member-call', object: 'crypto', method: null },
    { type: 'member', object: 'req', prop: 'body' }, // a dataflow/catalog.js member READ, not a call
  ];
  for (const input of malformed) {
    let result;
    assert.doesNotThrow(() => { result = recognizeTransformation(input); }, `threw on ${JSON.stringify(input)}`);
    assert.equal(result, null, `expected null for ${JSON.stringify(input)}`);
  }
});

// ─────────────────────────────────────────────────────────────────────────
// D4/10 — isolation (PRD §18.1) and the shipped catalog's measured shape
// ─────────────────────────────────────────────────────────────────────────

test('D4/10a: the module imports nothing from scanner/src/dataflow/', async () => {
  const { readFileSync } = await import('node:fs');
  const { fileURLToPath } = await import('node:url');
  const src = readFileSync(fileURLToPath(new URL('../../src/lineage/transform-catalog.js', import.meta.url)), 'utf8');
  const specifiers = [...src.matchAll(/^\s*import[^'"]*['"]([^'"]+)['"]/gm)].map(m => m[1]);
  assert.deepEqual(specifiers, ['./schema.js'],
    'D4 is new data, not a reclassification: schema.js is the only permitted import');
  // Static specifiers are pinned above; this catches a dynamic import too.
  // Deliberately scoped to import syntax, not raw text: the module header
  // DISCUSSES dataflow/catalog.js and dataflow/privacy-catalog.js at length
  // (recording why neither is a usable input), and that prose must stay.
  assert.ok(!/from\s*['"][^'"]*dataflow[^'"]*['"]/.test(src), 'no static import from dataflow/');
  assert.ok(!/import\s*\(\s*['"][^'"]*dataflow/.test(src), 'no dynamic import from dataflow/');
});

test('D4/10b: the catalog\'s measured shape is pinned as equality, not a floor', () => {
  // Pinned so a later increment adding or dropping entries has to state it.
  // Re-measured by this test on every run; never copied from prose.
  const perKind = {};
  for (const entry of TRANSFORM_CATALOG) perKind[entry.kind] = (perKind[entry.kind] || 0) + 1;
  assert.deepEqual(perKind, {
    hash: 15,
    encrypt: 5,
    decrypt: 5,
    encode: 5,
    decode: 5,
    mask: 1,
    redact: 1,
    tokenize: 1,
    aggregate: 1,
    truncate: 2,
    normalize: 1,
  });
  assert.equal(TRANSFORM_CATALOG.length, 42);
});

test('D4/10c: the catalog and its entries are frozen', () => {
  assert.ok(Object.isFrozen(TRANSFORM_CATALOG));
  for (const entry of TRANSFORM_CATALOG) {
    assert.ok(Object.isFrozen(entry), entry.id);
    assert.ok(Object.isFrozen(entry.match), entry.id);
  }
});
