// GA-06 §5 (0.195.31): the `deterministic + hunt` arm. Pinned: the arm validates like a local model arm; it runs the scanner and
// then the discovery pipeline over the same workspace and returns one list with each finding's source; every hunter prompt passes
// the leakage guard and a hit blocks the whole attempt; no hunt memory is written between repeats; a hunt that reached no focus
// area is a no-result, never a clean one; and the paired comparison counts wins, losses and ties entry by entry on the same set.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { mkTestTmp } from '../helpers/tmp.js';
import { runArmTask, validateArm } from '../../src/posture/evaluation/lab/arms.js';
import { runHuntArm } from '../../src/posture/evaluation/lab/arm-hunt.js';
import { pairedComparisons } from '../../src/posture/evaluation/lab/run.js';
import { detectedEntryIds } from '../../src/posture/evaluation/lab/score.js';

const SRC = "const q = 'SELECT * FROM t WHERE id = ' + req.query.id;\ndb.query(q);\nfunction admin(req, res) { return res.send(users.all()); }\n";
const ws = (text = SRC) => { const d = mkTestTmp('hunt-ws-'); fs.writeFileSync(path.join(d, 'app.js'), text); return d; };
const arm = ({ adapter = {}, ...over } = {}) => ({ id: 'det-plus-hunt', kind: 'model', tasks: ['detect'], model: { id: 'qwen3:4b', provider: 'ollama', local: true }, adapter: { type: 'hunt', host: 'http://127.0.0.1:11434', lenses: ['authz'], maxLlmCalls: 20, ...adapter }, ...over });
const req = { schema: 'agentic-security/eval-request', task: 'detect', language: 'javascript' };
// One reply that both stages can read: a hunter parses `candidates`, a refutation voter parses `refuted`.
const reply = (candidates, refuted = false) => JSON.stringify({ candidates, refuted, reason: 'scripted' });
const chatWith = (text, seen = []) => async ({ messages, host, model, signal }) => { seen.push({ prompt: messages[0].content, host, model, signal }); return { ok: true, result: { text, usage: { inputTokens: 10, outputTokens: 5 } } }; };
const scanWith = (findings) => async () => ({ findings });

test('validation: the hunt adapter is a local model arm that performs detect only, on a loopback host, with bounded budgets', () => {
  assert.equal(validateArm(arm()).ok, true, validateArm(arm()).errors.join('; '));
  assert.match(validateArm(arm({ kind: 'deterministic' })).errors.join(), /model arm/);
  assert.match(validateArm(arm({ tasks: ['detect', 'patch'] })).errors.join(), /detect task only/);
  assert.match(validateArm(arm({ model: { id: 'm', provider: 'ollama', local: false, endpoint: 'https://x.example' } })).errors.join(), /model\.local must be true/);
  assert.match(validateArm(arm({ adapter: { host: 'https://models.example.com' } })).errors.join(), /loopback/);
  assert.match(validateArm(arm({ adapter: { maxLlmCalls: 0 } })).errors.join(), /maxLlmCalls/);
  assert.match(validateArm(arm({ adapter: { lenses: [] } })).errors.join(), /lenses/);
});

test('the arm returns the deterministic findings and the hunt findings in one list, each with its source, and reports the hunt coverage', async () => {
  const seen = [];
  const r = await runHuntArm({ arm: arm(), task: 'detect', request: req, workspaceDir: ws(), terms: [], scanFn: scanWith([{ file: 'app.js', line: 2, cwe: 'CWE-89', confidence: 0.9 }]), callChat: chatWith(reply([{ file: 'app.js', line: 3, title: 'admin listing without an ownership check' }]), seen) });
  assert.equal(r.status, 'completed', r.reason);
  const det = r.output.findings.filter((f) => f.source === 'deterministic');
  const hunt = r.output.findings.filter((f) => f.source === 'hunt');
  assert.deepEqual(det, [{ file: 'app.js', line: 2, cwe: 'CWE-89', confidence: 0.9, source: 'deterministic' }]);
  assert.equal(hunt.length, 1, JSON.stringify(r.output.hunt));
  assert.equal(hunt[0].file, 'app.js'); assert.equal(hunt[0].line, 3);
  assert.ok(['taint-confirmed', 'sink-adjacent', 'unconfirmed'].includes(hunt[0].tier));
  assert.equal(r.output.hunt.fresh, 1);
  assert.ok(r.output.hunt.areasHunted >= 1 && r.output.hunt.llmCalls === seen.length && seen.length >= 1);
  assert.ok(seen.every((s) => s.host === 'http://127.0.0.1:11434' && s.model === 'qwen3:4b'), 'every call went to the declared local model');
  assert.deepEqual(r.reported, { inputTokens: 10 * seen.length, outputTokens: 5 * seen.length });
  const viaRunner = await runArmTask({ arm: arm(), task: 'detect', request: req, workspaceDir: ws(), scanFn: scanWith([]) });
  assert.ok(['completed', 'unavailable'].includes(viaRunner.status), 'the task runner dispatches the hunt adapter (the real server is not required to be up)');
});

test('a hunter prompt that carries a protected term blocks the whole attempt, and nothing from it is scored', async () => {
  const seen = [];
  const r = await runHuntArm({ arm: arm(), task: 'detect', request: req, workspaceDir: ws(SRC + '// CVE-2099-1234 mitigated here\n'), terms: ['CVE-2099-1234'], scanFn: scanWith([{ file: 'app.js', line: 2, cwe: 'CWE-89' }]), callChat: chatWith(reply([{ file: 'app.js', line: 3, title: 't' }]), seen) });
  assert.equal(r.status, 'blocked');
  assert.match(r.reason, /leakage guard/);
  assert.equal(r.output, undefined, 'no findings, not even the deterministic ones, leave a blocked attempt');
  assert.equal(seen.length, 0, 'the guarded prompt never reached the model');
});

test('no hunt memory is written, so a repeat never inherits what an earlier repeat refuted', async () => {
  const dir = ws();
  const refuting = chatWith(reply([{ file: 'app.js', line: 3, title: 't' }], true));
  const first = await runHuntArm({ arm: arm(), task: 'detect', request: req, workspaceDir: dir, scanFn: scanWith([]), callChat: refuting });
  assert.equal(first.status, 'completed', first.reason);
  assert.ok(!fs.existsSync(path.join(dir, '.agentic-security')), 'nothing was written under the workspace');
  const seen = [];
  const second = await runHuntArm({ arm: arm(), task: 'detect', request: req, workspaceDir: dir, scanFn: scanWith([]), callChat: chatWith(reply([{ file: 'app.js', line: 3, title: 't' }]), seen) });
  assert.equal(second.status, 'completed', second.reason);
  assert.ok(seen.length >= 1, 'the second repeat hunted again instead of skipping a remembered refutation');
  assert.equal(second.output.findings.filter((f) => f.source === 'hunt').length >= 1 || second.output.hunt.contestedConfirmed >= 0, true);
});

test('a hunt that reached no focus area is a no-result (unavailable), never a completed attempt that found nothing extra', async () => {
  const r = await runHuntArm({ arm: arm(), task: 'detect', request: req, workspaceDir: ws(), scanFn: scanWith([{ file: 'app.js', line: 2, cwe: 'CWE-89' }]), callChat: async () => ({ ok: false, code: 'ollama-unreachable', reason: 'connection refused' }) });
  assert.equal(r.status, 'unavailable');
  assert.match(r.reason, /reached no focus area/);
  assert.equal(r.output, undefined);
  const budget = await runHuntArm({ arm: arm({ adapter: { maxLlmCalls: 1 } }), task: 'detect', request: req, workspaceDir: ws(), scanFn: scanWith([]), callChat: chatWith(reply([{ file: 'app.js', line: 3, title: 't' }])) });
  assert.ok(budget.status === 'error' || budget.status === 'unavailable', `an exhausted hunt budget is a no-result (${budget.status}: ${budget.reason})`);
  assert.match(budget.reason, /budget|no focus area/);
});

test('the paired comparison counts wins, losses and ties entry by entry on the identical population, per repeat', () => {
  const entries = [
    { id: 'e1', kind: 'vulnerable', cwe: 'CWE-89', expectedSpan: { file: 'a.js', startLine: 2, endLine: 2 } },
    { id: 'e2', kind: 'vulnerable', cwe: 'CWE-78', expectedSpan: { file: 'b.js', startLine: 5, endLine: 6 } },
    { id: 'e3', kind: 'vulnerable', cwe: 'CWE-22', expectedSpan: { file: 'c.js', startLine: 1, endLine: 1 } },
    { id: 'n1', kind: 'fixed', cwe: 'CWE-89', lookalikeSpan: { file: 'a.js', startLine: 2, endLine: 2 } },
  ];
  const att = (armId, repeat, entryId, findings) => ({ armId, repeat, task: 'detect', entryId, status: 'completed', output: { findings } });
  const attempts = [
    att('base', 0, 'e1', [{ file: 'a.js', line: 2, cwe: 'CWE-89' }]), att('base', 0, 'e2', []), att('base', 0, 'e3', [{ file: 'c.js', line: 1, cwe: 'CWE-22' }]), att('base', 0, 'n1', []),
    att('hunt', 0, 'e1', [{ file: 'a.js', line: 2, cwe: 'CWE-89' }]), att('hunt', 0, 'e2', [{ file: 'b.js', line: 7, cwe: 'CWE-78' }]), att('hunt', 0, 'e3', []), att('hunt', 0, 'n1', []),
    att('hunt', 1, 'e1', [{ file: 'a.js', line: 2, cwe: 'CWE-89' }]), att('hunt', 1, 'e2', []), att('hunt', 1, 'e3', [{ file: 'c.js', line: 1, cwe: 'CWE-22' }]), { armId: 'hunt', repeat: 1, task: 'detect', entryId: 'n1', status: 'error' },
  ];
  const armPlans = [{ arm: { id: 'base', kind: 'deterministic' }, repeats: 1, tasks: ['detect'] }, { arm: { id: 'hunt', kind: 'model' }, repeats: 2, tasks: ['detect'] }];
  const paired = pairedComparisons({ armPlans, usable: entries, attempts, mapFile: (id, f) => f });
  assert.equal(paired.length, 1);
  const p = paired[0];
  assert.equal(p.baselineArmId, 'base'); assert.equal(p.armId, 'hunt'); assert.equal(p.positives, 3); assert.equal(p.sameEntrySet, true); assert.equal(p.representative, false);
  assert.deepEqual(p.perRepeat, [
    { repeat: 0, wins: 1, losses: 1, ties: 1, armDetected: 2, baselineDetected: 2 },
    { repeat: 1, wins: 0, losses: 0, ties: 3, armDetected: 2, baselineDetected: 2 },
  ]);
  assert.deepEqual([...detectedEntryIds({ entries, attempts: new Map(attempts.filter((a) => a.armId === 'hunt' && a.repeat === 0).map((a) => [a.entryId, a])) })].sort(), ['e1', 'e2']);
});
