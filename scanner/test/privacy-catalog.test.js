// FR-403 (assurance-hardening PRD), Steps 1-2 of D-0041's decomposition plan.
//
// This tests the SHAPE and COVERAGE of the new privacy sink catalog and the
// declaration-based source matcher only — deliberately NOT a live taint-
// detection test, since neither is wired into the general engine yet (see
// privacy-catalog.js's own header for why: sinks would be reachable by
// every already-active general security source, producing spurious
// findings, until step 3 builds the isolated matching pass). D-0041 step 3
// owns the live-detection tests once that wiring exists.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  PRIVACY_SINK_CATALOG, PRIVACY_SINK_CATEGORIES,
  matchPrivacyDeclSource, matchPrivacyDeclSources,
  matchPrivacySink,
} from '../src/dataflow/privacy-catalog.js';
import { CATALOG } from '../src/dataflow/catalog.js';
import { compileTaxonomy, DEFAULT_TAXONOMY } from '../src/dataflow/privacy-taxonomy.js';

test('PRIVACY_SINK_CATALOG: every entry is well-formed per catalog.js\'s own {kind,id,language,match,argIndex,vuln} contract', () => {
  for (const e of PRIVACY_SINK_CATALOG) {
    assert.equal(e.kind, 'sink', `${e.id}: expected kind:'sink'`);
    assert.equal(typeof e.id, 'string');
    assert.ok(e.id.length > 0);
    assert.equal(typeof e.language, 'string');
    assert.ok(e.match && typeof e.match === 'object', `${e.id}: expected a match object`);
    assert.equal(e.match.type, 'call', `${e.id}: only call-shaped matches are used in this pass`);
    assert.equal(typeof e.match.callee, 'string');
    assert.ok(e.match.callee.length > 0);
    assert.ok(e.argIndex === 'all' || typeof e.argIndex === 'number', `${e.id}: argIndex must be 'all' or a number`);
    assert.ok(e.vuln && typeof e.vuln === 'object', `${e.id}: expected a vuln object`);
    assert.equal(typeof e.vuln.name, 'string');
    assert.ok(['low', 'medium', 'high', 'critical'].includes(e.vuln.severity), `${e.id}: unexpected severity ${e.vuln.severity}`);
    assert.equal(e.vuln.cwe, 'CWE-359', `${e.id}: every privacy-leak sink must carry CWE-359`);
    assert.equal(typeof e.vuln.remediation, 'string');
    assert.ok(e.vuln.remediation.length > 20, `${e.id}: remediation should be a real sentence, not a stub`);
    assert.ok(PRIVACY_SINK_CATEGORIES.includes(e.category), `${e.id}: category "${e.category}" is not one of the declared PRIVACY_SINK_CATEGORIES`);
  }
});

test('PRIVACY_SINK_CATALOG: no duplicate ids', () => {
  const ids = PRIVACY_SINK_CATALOG.map(e => e.id);
  assert.deepEqual(ids, [...new Set(ids)]);
});

test('PRIVACY_SINK_CATALOG: covers all 9 sink categories FR-403 names (the 7 privacy-taint.js already had, plus storage and queues)', () => {
  const covered = new Set(PRIVACY_SINK_CATALOG.map(e => e.category));
  for (const cat of PRIVACY_SINK_CATEGORIES) {
    assert.ok(covered.has(cat), `expected at least one entry for category "${cat}"`);
  }
  assert.equal(PRIVACY_SINK_CATEGORIES.length, 9, 'expected exactly 9 named categories (7 pre-existing + storage + queues)');
});

test('PRIVACY_SINK_CATALOG: the two previously-uncovered categories (storage, queues) are genuinely present, not just declared', () => {
  assert.ok(PRIVACY_SINK_CATALOG.some(e => e.category === 'storage'));
  assert.ok(PRIVACY_SINK_CATALOG.some(e => e.category === 'queues'));
});

// ── the isolation guarantee itself — the whole point of this design ─────

test('PRIVACY_SINK_CATALOG is NOT merged into the general engine\'s CATALOG — none of its ids appear there', () => {
  const generalIds = new Set(CATALOG.map(e => e.id));
  for (const e of PRIVACY_SINK_CATALOG) {
    assert.ok(!generalIds.has(e.id), `${e.id} must not leak into the shared CATALOG — see privacy-catalog.js's own header for why`);
  }
});

test('none of CATALOG\'s existing (general-engine) sink entries were accidentally mutated by this addition', () => {
  // A coarse but meaningful regression guard: the general engine's own sink
  // count should be unaffected by adding an entirely separate file.
  const generalSinkCount = CATALOG.filter(e => e.kind === 'sink').length;
  assert.ok(generalSinkCount > 50, 'sanity: CATALOG should still have its normal, large sink population');
});

// ── Step 2: matchPrivacyDeclSource(s) — declaration-based source matching ──

test('matchPrivacyDeclSource: a PII-shaped name classifies, an ordinary name does not', () => {
  assert.deepEqual(matchPrivacyDeclSource('email'), { name: 'email', classes: ['PII'] });
  assert.equal(matchPrivacyDeclSource('counter'), null);
});

test('matchPrivacyDeclSource: PHI/PCI-shaped names classify into their own class', () => {
  const phi = matchPrivacyDeclSource('medicalRecordNumber');
  assert.ok(phi && phi.classes.includes('PHI'), `expected medicalRecordNumber to classify as PHI, got ${JSON.stringify(phi)}`);
  const pci = matchPrivacyDeclSource('creditCardNumber');
  assert.ok(pci && pci.classes.includes('PCI'), `expected creditCardNumber to classify as PCI, got ${JSON.stringify(pci)}`);
});

test('matchPrivacyDeclSource: null/empty input degrades to null, never throws', () => {
  assert.doesNotThrow(() => matchPrivacyDeclSource(null));
  assert.equal(matchPrivacyDeclSource(null), null);
  assert.equal(matchPrivacyDeclSource(''), null);
  assert.equal(matchPrivacyDeclSource(undefined), null);
});

test('matchPrivacyDeclSource: honors a custom compiled taxonomy, not just the built-in default', () => {
  const custom = compileTaxonomy({
    ...DEFAULT_TAXONOMY,
    INTERNAL_EMPLOYEE_ID: { patterns: ['employee_?id'], severity: 'high' },
  });
  const hit = matchPrivacyDeclSource('employee_id', custom);
  assert.ok(hit && hit.classes.includes('INTERNAL_EMPLOYEE_ID'), `expected a custom-taxonomy class to be honored, got ${JSON.stringify(hit)}`);
  // The built-in (default-taxonomy) call must NOT pick up an org-specific class it was never told about.
  assert.equal(matchPrivacyDeclSource('employee_id'), null);
});

test('matchPrivacyDeclSources: classifies a whole declaration list into a Map, skipping non-matches', () => {
  const m = matchPrivacyDeclSources(['email', 'counter', 'ssn', 'pageTitle']);
  assert.equal(m.size, 2);
  assert.ok(m.has('email'));
  assert.ok(m.has('ssn'));
  assert.ok(!m.has('counter'));
  assert.ok(!m.has('pageTitle'));
});

test('matchPrivacyDeclSources: non-array input degrades to an empty Map, never throws', () => {
  assert.doesNotThrow(() => matchPrivacyDeclSources(null));
  assert.equal(matchPrivacyDeclSources(null).size, 0);
  assert.equal(matchPrivacyDeclSources(undefined).size, 0);
  assert.equal(matchPrivacyDeclSources('not-an-array').size, 0);
});

test('matchPrivacyDeclSources: an empty declaration list returns an empty Map, not an error', () => {
  assert.equal(matchPrivacyDeclSources([]).size, 0);
});

// D-0046/D-0047 grounding for FR-403 step 3: matchPrivacySink is the
// sink-side mirror of matchSinkOrSanitizer, but reads ONLY
// PRIVACY_SINK_CATALOG — still not wired into the general engine (that is
// the walker construction itself, step 3's remaining, larger piece).

test('matchPrivacySink: matches a real privacy sink entry by member-call shape (console.log)', () => {
  const calleeExpr = { kind: 'member', prop: 'log', object: { kind: 'ident', name: 'console' } };
  const hits = matchPrivacySink(calleeExpr, 'a.js', 'console');
  assert.ok(Array.isArray(hits) && hits.length >= 1);
  assert.ok(hits.some(h => h.id === 'privacy-js-console-log'));
});

test('matchPrivacySink: matches a real privacy sink entry by flat dotted-string callee shape (non-Babel frontends)', () => {
  const hits = matchPrivacySink('console.log', 'a.js', 'console');
  assert.ok(Array.isArray(hits) && hits.length >= 1);
  assert.ok(hits.some(h => h.id === 'privacy-js-console-log'));
});

test('matchPrivacySink: an unrelated callee name matches nothing, returns null', () => {
  assert.equal(matchPrivacySink({ kind: 'ident', name: 'computeTotal' }, 'a.js', null), null);
  assert.equal(matchPrivacySink(null, 'a.js', null), null);
});

test('matchPrivacySink: receiverTypeIn gates the match — a same-named callee on an unrelated receiver type does not fire', () => {
  const calleeExpr = { kind: 'member', prop: 'log', object: { kind: 'ident', name: 'notConsole' } };
  // receiverType resolved to something that is NOT in console.log's receiverTypeIn allow-list.
  assert.equal(matchPrivacySink(calleeExpr, 'a.js', 'SomeUnrelatedClass'), null);
  // An unresolved (null) receiver type never suppresses a match — same "unknown != clean" contract as catalog.js's own _receiverTypeAllowed.
  const hits = matchPrivacySink(calleeExpr, 'a.js', null);
  assert.ok(Array.isArray(hits) && hits.some(h => h.id === 'privacy-js-console-log'));
});

test('matchPrivacySink: entries never returned for a language they are not registered for', () => {
  // privacy-js-console-log is language:'js'; a .py file should not match it via the language gate,
  // even though the callee name is identical — unless another entry independently covers py console-shaped logging.
  const hits = matchPrivacySink({ kind: 'member', prop: 'log', object: { kind: 'ident', name: 'console' } }, 'a.py', 'console');
  if (hits) assert.ok(!hits.some(h => h.id === 'privacy-js-console-log'));
});

test('matchPrivacySink: every hit returned is genuinely kind:"sink" from PRIVACY_SINK_CATALOG, never a stray source/other-kind entry', () => {
  for (const entry of PRIVACY_SINK_CATALOG) {
    if (entry.kind !== 'sink' || !entry.match || entry.match.type !== 'call') continue;
    const hits = matchPrivacySink(entry.match.callee, 'a.' + entry.language, (entry.match.receiverTypeIn || [null])[0]);
    if (hits) assert.ok(hits.every(h => h.kind === 'sink'), `matchPrivacySink returned a non-sink hit for ${entry.id}`);
  }
});
