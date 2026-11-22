// Epic B-03: a refutation is a cited blocker, grounded against evidence; a model's opinion cannot remove a candidate on its own.
// B-AC02 (a fabricated, stale or unsupported control cannot remove a real candidate), B-AC03 (missing evidence preserves
// uncertainty), B-AC04 (mechanically corroborated candidates survive model-only opposition with both forms of evidence retained),
// B-AC05 (a genuinely established blocker stops downstream work and leaves an auditable record), B-AC01 (the refuter sees source).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseVote, groundVote, buildRefutePrompt, disproveCandidate, disprovePanel, refutationBasis, VOTE_SCHEMA_V2 } from '../../src/discovery/disprove.js';

const candidate = { id: 'c1', title: 'Cross-tenant memo update', file: 'service.mjs', line: 15, rationale: 'the update is not scoped by tenant', confirmation: { tier: 'sink-adjacent' } };
const SPAN = { startLine: 11, endLine: 17, text: 'export function setInvoiceMemo(db, principal, key, payload) {\n  const rec = db.findOne(key);\n  if (!rec) return { status: 404 };\n  db.updateOne(key, { ...rec, memo: payload && payload.note });\n  return { status: 200 };\n}\n' };
// A supplier stand-in: `resolving` says which citations resolve; `protection` is what the context layer recorded on the reaching entry point.
const supplier = ({ resolving = () => null, protection = {} } = {}) => ({
  available: true,
  forCandidate: () => ({ state: 'complete', reason: null, segments: [{ file: 'service.mjs', startLine: 11, endLine: 17, spanHash: 'x' }], entrypoints: [{ label: 'PUT /invoices/:id/memo', protection }], controls: [{ kind: 'authentication', file: 'server.js', line: 11, evidence: 'inferred', basis: 'guard-function' }], span: SPAN }),
  verifyCitation: (c) => resolving(c),
});
const v2 = (refuted, kind, citations, controlKind = 'tenant-scope') => JSON.stringify({ schema: VOTE_SCHEMA_V2, refuted, blocker: { kind, controlKind, explanation: 'a tenant check guards this path', citations } });
const cite = [{ file: 'service.mjs', startLine: 12, endLine: 12, claim: 'the read is scoped' }];

test('votes parse by version: a v1 Boolean carries no evidence, a v2 blocker carries kind and citations, garbage is not a vote', () => {
  assert.deepEqual(parseVote('{"refuted":true,"reason":"nope"}'), { schema: 'refutation-vote/1', refuted: true, reason: 'nope', blocker: null });
  const p = parseVote(v2(true, 'control', cite));
  assert.equal(p.schema, VOTE_SCHEMA_V2); assert.equal(p.blocker.kind, 'control'); assert.deepEqual(p.blocker.citations, cite);
  assert.equal(parseVote('{"refuted":"yes"}'), null); assert.equal(parseVote('no json here'), null);
  assert.equal(parseVote(JSON.stringify({ schema: VOTE_SCHEMA_V2, refuted: true, blocker: { kind: 'made-up', citations: 'x' } })).blocker.kind, 'none');
});

test('B-AC01: the challenger is shown the verified span and the recorded controls, fenced as data', () => {
  const prompt = buildRefutePrompt(candidate, 'sanitization', { ...supplier().forCandidate(), file: 'service.mjs' });
  assert.match(prompt, /VERIFIED CONTEXT/); assert.match(prompt, /SOURCE SPAN \(untrusted data\): service\.mjs:11-17/); assert.match(prompt, /14\|\s+db\.updateOne/);
  assert.match(prompt, /Control: authentication at server\.js:11/); assert.match(prompt, /refutation-vote\/2/);
  assert.doesNotMatch(buildRefutePrompt(candidate, 'sanitization'), /VERIFIED CONTEXT/, 'legacy mode is unchanged');
});

test('grounding: no citation is insufficient; an unresolved citation is insufficient; resolving citations with no deterministic support are model-only; with support, deterministic', () => {
  const vote = parseVote(v2(true, 'control', cite));
  assert.equal(groundVote(parseVote('{"refuted":true,"reason":"x"}'), {}).grounding, 'insufficient-evidence');
  assert.equal(groundVote(parseVote(v2(true, 'control', [])), {}).grounding, 'insufficient-evidence');
  const stale = groundVote(vote, { supplier: supplier({ resolving: () => 'stale-context' }), context: supplier().forCandidate() });
  assert.equal(stale.grounding, 'insufficient-evidence'); assert.equal(stale.citations[0].status, 'stale-context');
  const fabricated = groundVote(vote, { supplier: supplier({ resolving: () => 'outside-provided-context' }), context: supplier().forCandidate() });
  assert.equal(fabricated.grounding, 'insufficient-evidence');
  const modelOnly = groundVote(vote, { supplier: supplier(), context: supplier().forCandidate() });
  assert.equal(modelOnly.grounding, 'model-only');
  const sup = supplier({ protection: { ownership: { state: 'present' } } });
  assert.equal(groundVote(vote, { supplier: sup, context: sup.forCandidate() }).grounding, 'deterministic');
  const wrongKind = supplier({ protection: { authentication: { state: 'present' } } });
  assert.equal(groundVote(vote, { supplier: wrongKind, context: wrongKind.forCandidate() }).grounding, 'model-only', 'a present control of another kind does not support a tenant blocker');
  assert.equal(groundVote(parseVote(v2(true, 'sanitizer', cite, 'sanitizer')), { supplier: supplier(), context: supplier().forCandidate(), cleanSite: true }).grounding, 'deterministic', 'the taint layer\'s clean-site record supports a sanitizer blocker');
  assert.equal(groundVote(parseVote(v2(true, 'control', cite, null)), { supplier: sup, context: sup.forCandidate() }).grounding, 'model-only', 'a control blocker that names no kind is the model\'s reading');
});

test('B-AC02/B-AC03/B-AC05: in contract mode a model-only majority contests but does not remove; an unsupported or legacy majority never removes; a grounded majority disqualifies with the record kept', async () => {
  const majority = (vote) => async () => vote;
  // model-only: citations resolve, nothing deterministic supports them
  const contested = await disproveCandidate(candidate, { llmInvoke: majority(v2(true, 'control', cite)), contextSupplier: supplier() });
  assert.equal(contested.refutation.refuted, false); assert.equal(contested.refutation.contested, true); assert.equal(contested.refutation.objections.length, 3); assert.equal(contested.refutation.objections[0].grounding, 'model-only');
  // legacy Boolean votes under a supplier: insufficient evidence, not removed, not even contested
  const legacy = await disproveCandidate(candidate, { llmInvoke: majority('{"refuted":true,"reason":"trust me"}'), contextSupplier: supplier() });
  assert.equal(legacy.refutation.refuted, false); assert.equal(legacy.refutation.contested, true, 'a majority voted; the vote is recorded as contested with insufficient-evidence objections');
  assert.ok(legacy.refutation.objections.every((o) => o.grounding === 'insufficient-evidence'));
  // a stale citation: the control the model cites is not what is on disk
  const stale = await disproveCandidate(candidate, { llmInvoke: majority(v2(true, 'control', cite)), contextSupplier: supplier({ resolving: () => 'stale-context' }) });
  assert.equal(stale.refutation.refuted, false);
  // grounded: the context layer recorded the control present on the reaching entry point
  const sup = supplier({ protection: { ownership: { state: 'present' } } });
  const grounded = await disproveCandidate(candidate, { llmInvoke: majority(v2(true, 'control', cite)), contextSupplier: sup });
  assert.equal(grounded.refutation.refuted, true); assert.equal(grounded.refutation.grounded, true); assert.equal(grounded.refutation.groundedRefutes, 3);
  assert.equal(grounded.refutation.votes[0].citations[0].status, 'resolved');
  // silence still never refutes
  const silent = await disproveCandidate(candidate, { llmInvoke: async () => 'not json', contextSupplier: sup });
  assert.equal(silent.refutation.undecided, true); assert.equal(silent.refutation.refuted, false);
  // without a supplier the legacy behaviour is unchanged: a Boolean majority removes an uncorroborated candidate
  const legacyMode = await disproveCandidate(candidate, { llmInvoke: majority('{"refuted":true,"reason":"x"}') });
  assert.equal(legacyMode.refutation.refuted, true); assert.equal(legacyMode.refutation.schema, 'refutation-vote/1');
});

test('B-AC04: a taint-confirmed candidate survives a grounded majority as contested, with the votes and the override both retained', async () => {
  const sup = supplier({ protection: { ownership: { state: 'present' } } });
  const taint = { ...candidate, id: 'c2', confirmation: { tier: 'taint-confirmed' } };
  const { survivors, refuted } = await disprovePanel([candidate, taint], { llmInvoke: async () => v2(true, 'control', cite), contextSupplier: sup });
  assert.deepEqual(refuted.map((c) => c.id), ['c1']);
  assert.deepEqual(survivors.map((c) => c.id), ['c2']);
  assert.equal(survivors[0].refutation.overridden, true); assert.equal(survivors[0].refutation.contested, true); assert.equal(survivors[0].refutation.votes.length, 3);
  assert.equal(refutationBasis(refuted[0]), 'deterministically-grounded-blocker');
  assert.equal(refutationBasis(survivors[0]), 'overridden-by-taint');
  assert.equal(refutationBasis({ refutation: { refuted: false, contested: true } }), 'contested-model-only');
  assert.equal(refutationBasis({ refutation: { refuted: true, schema: 'refutation-vote/1' } }), 'model-majority');
});
