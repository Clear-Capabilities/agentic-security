import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { tempProject, cleanup, build, reviewWith } from './helpers.js';
import { scriptedReader } from '../../src/context-intelligence/evaluation/scripted-reader.js';
import { reviewsToCandidates, adjudicate } from '../../src/context-intelligence/candidates.js';

const BIN = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../bin/agentic-security.js');
const git = (dir, ...a) => spawnSync('git', ['-c', 'user.email=t@t', '-c', 'user.name=t', '-c', 'commit.gpgsign=false', ...a], { cwd: dir, encoding: 'utf8' });

test('context diff between a git ref and the working tree reports changed routes and the protection change', () => {
  const dir = tempProject('eval/corpus/c01/b');
  try {
    git(dir, 'init', '-q'); git(dir, 'add', '-A'); const c = git(dir, 'commit', '-qm', 'base');
    assert.equal(c.status, 0, c.stderr);
    const app = path.join(dir, 'src', 'app.js');
    fs.writeFileSync(app, fs.readFileSync(app, 'utf8').replace(/ AND owner_id = \$2/, '').replace(/, \[req\.params\.id, req\.user\.id\]/, ', [req.params.id]'));
    const env = { ...process.env }; for (const k of Object.keys(env)) if (/^AGENTIC_SECURITY_(LLM|EGRESS)/.test(k)) delete env[k];
    const r = spawnSync(process.execPath, [BIN, 'context', 'diff', '--root', dir, '--from', 'HEAD', '--format', 'json'], { encoding: 'utf8', env });
    assert.equal(r.status, 0, r.stderr + r.stdout);
    const j = JSON.parse(r.stdout);
    const d = j.diff || j;
    assert.equal(d.changed.length, 1);
    assert.equal(d.added.length + d.removed.length, 0);
  } finally { cleanup(dir); }
});

test('the same defect found through several routes is one finding with every route as a witness', async () => {
  const dir = tempProject('js-app');
  try {
    const run = await reviewWith(dir, scriptedReader(), { packIds: ['authz-idor'] });
    const records = [];
    for (const [, res] of run.result.results) {
      if (res.state === 'succeeded' && res.review) { const lj = run.loadJob(res.job); records.push({ review: res.review, entrypoints: lj.entrypoints.map(e => ({ id: e.id, label: e.label })), pack: lj.pack }); }
    }
    const cands = reviewsToCandidates(records);
    const witnessTotal = cands.reduce((n, c) => n + c.witnesses.length, 0);
    const flaggedReviews = records.filter(r => r.review.conclusion === 'potential_issue').length;
    assert.ok(flaggedReviews >= 1, 'the fixture has at least one flagged route');
    assert.equal(witnessTotal, flaggedReviews, 'every flagged route is a witness of some candidate');
    assert.ok(cands.length <= flaggedReviews);
  } finally { cleanup(dir); }
});

test('adjudication sets severity from the confirmation tier, never from the model, and marks advisory-only hypotheses', async () => {
  const cand = (over) => ({ id: 'abc123', focusAreaId: 'f', lens: 'authz', title: 't', file: 'src/app.js', line: 9, family: 'access-control', cwe: 'CWE-639', rationale: 'r', entryPoint: 'GET /x', sink: 's', origin: 'context-intelligence', questionPack: 'authz-idor/1', advisoryOnly: false, witnesses: [{ entrypointId: 'e', label: 'GET /x', contextHash: 'h', questionPack: 'authz-idor/1' }], sourceSpanEvidence: [], scopeIntegrity: {}, reviewStatus: 'completed', uncertainties: [], severity: 'critical', ...over });
  const adj = await adjudicate([cand({}), cand({ id: 'def456', advisoryOnly: true })], { taintProbe: async () => null });
  assert.equal(adj.advisory.length, 1);
  for (const f of adj.findings) {
    assert.notEqual(f.severity, 'critical');
    assert.equal(f.discovery.confirmation.tier, 'unconfirmed');
    assert.ok(f.contextIntelligence && f.contextIntelligence.note);
  }
});
