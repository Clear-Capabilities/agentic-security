// PRD Epic 6 — deterministic refutation of agent-produced logic claims.
//
// The tier's value is entirely in the refusals. A lens that upholds everything
// adds a provenance record and no information; what makes this worth running is
// that a fabricated citation, a misquote, or a claim contradicted by the source
// comes back REFUTED without a model being asked twice.
import test from 'node:test';
import assert from 'node:assert/strict';

import {
  ingestLogicClaims, verifyLogicClaim, renderLogicClaimSummary,
  PRODUCER, VERIFIER_CITATION, VERIFIER_CORROBORATION,
} from '../src/posture/logic-claims.js';
import { assertSeparation } from '../src/posture/verification-separation.js';

const UNAUTHED = [
  "const express = require('express');",
  'const router = express.Router();',
  '',
  "router.get('/orders/:id', async (req, res) => {",
  '  const order = await db.orders.findById(req.params.id);',
  '  res.json(order);',
  '});',
  '',
  'module.exports = router;',
].join('\n');

const AUTHED = [
  "const express = require('express');",
  'const router = express.Router();',
  '',
  "router.get('/orders/:id', requireAuth, async (req, res) => {",
  '  const order = await db.orders.findById(req.params.id);',
  '  if (order.ownerId !== req.user.id) return res.status(403).end();',
  '  res.json(order);',
  '});',
  '',
  'module.exports = router;',
].join('\n');

const files = { 'routes/orders.js': UNAUTHED, 'routes/authed.js': AUTHED };

const claim = (over = {}) => ({
  file: 'routes/orders.js', line: 5, kind: 'missing-authentication',
  vuln: 'Order lookup has no authentication', severity: 'high',
  snippet: 'const order = await db.orders.findById(req.params.id);', ...over,
});

test('a claim backed by the source is corroborated', () => {
  const f = verifyLogicClaim(claim(), files);
  assert.equal(f.consensus.verdict, 'upheld');
  assert.equal(f.quarantined, false);
});

test('a fabricated file is refuted, not accepted', () => {
  const f = verifyLogicClaim(claim({ file: 'routes/does-not-exist.js' }), files);
  assert.equal(f.consensus.verdict, 'refuted');
  assert.equal(f.quarantined, true);
  assert.match(f.verification.verdicts[0].reason, /does not exist/);
});

test('a line past the end of the file is refuted', () => {
  const f = verifyLogicClaim(claim({ line: 900, snippet: null }), files);
  const citation = f.verification.verdicts.find((v) => v.verifierId === VERIFIER_CITATION);
  assert.equal(citation.verdict, 'refuted');
  assert.match(citation.reason, /outside/);
});

test('a misquote is refuted — a claim that misquotes the code was not written from it', () => {
  const f = verifyLogicClaim(claim({ snippet: 'if (user.isAdmin) { grantEverything(); }' }), files);
  const q = f.verification.verdicts.find((v) => v.lens === 'quotation');
  assert.equal(q.verdict, 'refuted');
});

test('a right-file wrong-line quote is UNDECIDED, not refuted and not upheld', () => {
  // Line 9 is `module.exports`; the quoted line is 5, four lines outside the
  // ±3 window. Close-but-off citations stay upheld on purpose — an agent
  // reading a file is off by a line, not by a block.
  const f = verifyLogicClaim(claim({ line: 9 }), files);
  const q = f.verification.verdicts.find((v) => v.lens === 'quotation');
  assert.equal(q.verdict, 'undecided');
  assert.match(q.reason, /not at the cited line/);
});

test('a claim with no snippet is UNDECIDED on quotation — silence is not corroboration', () => {
  const f = verifyLogicClaim(claim({ snippet: '' }), files);
  const q = f.verification.verdicts.find((v) => v.lens === 'quotation');
  assert.equal(q.verdict, 'undecided');
});

test('"no authentication" against a handler that plainly authenticates is refuted', () => {
  // The lens that actually earns its keep: the source contradicts the claim.
  const f = verifyLogicClaim(claim({
    file: 'routes/authed.js', line: 5,
    snippet: 'const order = await db.orders.findById(req.params.id);',
  }), files);
  const c = f.verification.verdicts.find((v) => v.verifierId === VERIFIER_CORROBORATION);
  assert.equal(c.verdict, 'refuted');
  assert.match(c.reason, /does authenticate/);
});

test('"no ownership check" against a handler that scopes to the user is refuted', () => {
  const f = verifyLogicClaim(claim({
    file: 'routes/authed.js', line: 6, kind: 'missing-ownership-check',
    snippet: 'if (order.ownerId !== req.user.id) return res.status(403).end();',
  }), files);
  const c = f.verification.verdicts.find((v) => v.verifierId === VERIFIER_CORROBORATION);
  assert.equal(c.verdict, 'refuted');
});

test('a kind with no deterministic lens is UNDECIDED, never counted as agreement', () => {
  const f = verifyLogicClaim(claim({ kind: 'race-condition' }), files);
  const c = f.verification.verdicts.find((v) => v.verifierId === VERIFIER_CORROBORATION);
  assert.equal(c.verdict, 'undecided');
  assert.match(c.reason, /no deterministic lens/);
});

test('an unknown kind degrades to `other` rather than being trusted', () => {
  const f = verifyLogicClaim(claim({ kind: 'totally-made-up' }), files);
  assert.equal(f.kind, 'other');
});

test('a refuted claim is QUARANTINED, never deleted and never severity-touched', () => {
  const input = [claim(), claim({ file: 'nope.js' })];
  const r = ingestLogicClaims(input, { fileContents: files });
  assert.equal(r.claims.length, 2, 'a refuted claim must still be returned');
  assert.equal(r.claims[1].quarantined, true);
  assert.equal(r.claims[1].severity, 'high', 'severity must not be touched');
  assert.equal(r.summary.refuted, 1);
  assert.equal(r.summary.corroborated, 1);
});

test('no lens can verify a claim it produced', () => {
  // Structural, not conventional: if a lens ever ran under the producer id the
  // separation check refuses rather than recording a self-vote.
  const f = verifyLogicClaim(claim(), files);
  const sep = assertSeparation(f, PRODUCER);
  assert.equal(sep.ok, false);
  assert.match(sep.reason, /separation violated/);
});

test('the summary leads with what could not be corroborated', () => {
  const line = renderLogicClaimSummary({ total: 3, corroborated: 1, refuted: 1, unverifiable: 1 });
  assert.match(line, /REFUTED/);
  assert.match(line, /quarantined, not deleted/);
});

test('a Map of file contents works the same as an object', () => {
  const f = verifyLogicClaim(claim(), new Map(Object.entries(files)));
  assert.equal(f.consensus.verdict, 'upheld');
});

test('a malformed claim never disappears from the batch', () => {
  const r = ingestLogicClaims([null, claim()], { fileContents: files });
  assert.equal(r.claims.length, 2);
  assert.equal(r.summary.total, 2);
});
