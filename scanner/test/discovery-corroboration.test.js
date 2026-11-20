// When the taint engine may overrule a refutation panel, and how a candidate the panel never examined is marked.
//
// Before: any taint finding within two lines of a candidate made it `taint-confirmed`, and a taint-confirmed candidate survives
// a refuting panel majority (mechanical precedence, GA-06 §4). Measured on a real hunt: the panel voted 3-0 against a wildcard
// "Potential Vulnerability in Anthropic API" candidate and it survived as confirmed because a SQL-injection flow sat on the
// line. Now the taint finding must be the same class of weakness the candidate claims (confirm.js `taintCorroborates`).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { makeTaintProbe } from '../src/discovery/index.js';
import { taintCorroborates, confirmCandidate } from '../src/discovery/confirm.js';
import { disprovePanel } from '../src/discovery/disprove.js';
import { toFindingShape, judgeCandidates } from '../src/discovery/judge.js';
import { buildProjectIR } from '../src/ir/index.js';

// One real SQL-injection flow: the deep engine reports CWE-89 on line 6.
const APP = "const express = require('express');\nconst db = require('./db');\nconst app = express();\napp.get('/u', (req, res) => {\n  const id = req.query.id;\n  db.query('SELECT * FROM users WHERE id = ' + id);\n  res.send('ok');\n});\n";
const cand = (lens, cwe, line = 6) => ({ id: `c-${lens}-${line}`, lens, cwe, title: `${lens} claim`, file: 'app.js', line, family: lens });
const refuteAll = async () => JSON.stringify({ refuted: true, reason: 'no' });

test('a taint finding corroborates a claim of the same weakness class only', () => {
  assert.equal(taintCorroborates('CWE-74', 'CWE-89'), true, 'injection lens, SQL injection flow');
  assert.equal(taintCorroborates('CWE-89', 'CWE-79'), true, 'both injection');
  assert.equal(taintCorroborates('CWE-285', 'CWE-862'), true);
  assert.equal(taintCorroborates('CWE-327', 'CWE-328'), true);
  assert.equal(taintCorroborates('CWE-710', 'CWE-89'), false, 'wildcard claims nothing a flow can confirm');
  assert.equal(taintCorroborates('CWE-840', 'CWE-89'), false, 'business logic');
  assert.equal(taintCorroborates('CWE-327', 'CWE-89'), false, 'crypto claim, injection flow');
  assert.equal(taintCorroborates('CWE-74', 'CWE-22'), false, 'path traversal is not in the injection class');
  assert.equal(taintCorroborates(null, 'CWE-89'), false);
});

test('the probe: same line, same class is taint-confirmed; same line, other class is only sink-adjacent', async () => {
  const { perFile, callGraph } = buildProjectIR({ 'app.js': APP });
  const probe = makeTaintProbe(perFile, callGraph);
  const inj = await confirmCandidate(cand('injection', 'CWE-74'), { taintProbe: probe });
  assert.equal(inj.confirmation.tier, 'taint-confirmed');
  assert.equal(inj.confirmation.evidence.cwe, 'CWE-89');
  const wild = await confirmCandidate(cand('wildcard', 'CWE-710'), { taintProbe: probe });
  assert.equal(wild.confirmation.tier, 'sink-adjacent');
  assert.deepEqual(wild.confirmation.evidence.cwes, ['CWE-89']);
  const crypto = await confirmCandidate(cand('crypto', 'CWE-327'), { taintProbe: probe });
  assert.equal(crypto.confirmation.tier, 'sink-adjacent');
});

test('a 3-0 refutation removes a candidate the taint hit does not corroborate, and is overridden only for one it does', async () => {
  const { perFile, callGraph } = buildProjectIR({ 'app.js': APP });
  const probe = makeTaintProbe(perFile, callGraph);
  const confirmed = [];
  for (const c of [cand('injection', 'CWE-74'), cand('wildcard', 'CWE-710'), cand('business-logic', 'CWE-840')]) confirmed.push(await confirmCandidate(c, { taintProbe: probe }));
  const { survivors, refuted } = await disprovePanel(confirmed, { llmInvoke: refuteAll });
  assert.deepEqual(survivors.map((c) => c.lens), ['injection']);
  assert.equal(survivors[0].refutation.refuteCount, 3);
  assert.equal(survivors[0].refutation.overridden, true);
  assert.deepEqual(refuted.map((c) => c.lens).sort(), ['business-logic', 'wildcard']);
  for (const r of refuted) assert.equal(r.refutation.refuteCount, 3);
});

test('a candidate whose panel ran and cast no vote is marked unvetted with the lowest confidence tier; a voted one is not', () => {
  const base = { id: 'x1', lens: 'injection', cwe: 'CWE-74', title: 't', file: 'a.js', line: 3, family: 'injection', confirmation: { tier: 'unconfirmed' } };
  const silent = toFindingShape({ ...base, refutation: { votes: [], voterCount: 0, refuteCount: 0, refuted: false, undecided: true } });
  const voted = toFindingShape({ ...base, refutation: { votes: [{ angle: 'reachability', refuted: false }], voterCount: 1, refuteCount: 0, refuted: false, undecided: false } });
  const neverPanelled = toFindingShape(base);
  assert.equal(silent.unvetted, true);
  assert.equal(silent.confidenceTier, 'very-low');
  assert.equal(neverPanelled.unvetted, undefined, 'a candidate that never went to a panel (another producer) is not marked');
  assert.equal(voted.unvetted, undefined);
  assert.equal(voted.confidenceTier, undefined);
  assert.equal(silent.stableId, voted.stableId, 'the flag does not change the stable id');
  assert.equal(silent.severity, 'low', 'severity still comes from the confirmation tier');
  // the judge passes the flag through to the fresh findings a report shows
  const { fresh } = judgeCandidates([{ ...base, refutation: { undecided: true } }], null, null);
  assert.equal(fresh[0].unvetted, true);
});
