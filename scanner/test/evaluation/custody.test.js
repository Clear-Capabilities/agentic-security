// QA-002.AC03: custodian isolation and planted-leakage fixtures. SYNTHETIC data only.
//
// "Planted leakage attempts fail" is tested by planting each kind of leak and
// asserting the control fires, AND by asserting the clean control passes (a guard
// that rejects everything would also pass the first half).
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkTestTmp } from '../helpers/tmp.js';
import {
  protectedTermsFrom, auditText, guardPrompt, auditWorkspace, stageWorkspace, custodianWriteLabels, custodianReadLabels, sealLabels,
  assertCustodyIsolation, engineEnvironment, LABEL_FILE,
} from '../../src/posture/evaluation/custody.js';
import { runEvaluation } from '../../src/posture/evaluation/runner.js';
import { runInBoundary } from '../../src/sandbox/trust-boundary.js';
import { detectBackend } from '../../src/sandbox/capabilities.js';
import { DOMAINS } from '../../src/sandbox/trust-domains.js';
import { suite, resolver, FIXTURES, SYN_FINDING } from '../helpers/evaluation-suite.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SRC = path.resolve(HERE, '..', '..', 'src');
const { defects, negatives } = suite();
const TERMS = protectedTermsFrom({
  defects, negatives,
  advisoryText: ['A crafted id parameter is concatenated into the lookup statement'],
  fixedSourceHints: ['db.query("SELECT * FROM users WHERE id = ?", [id])'],
});
const CUSTODIAN = { domain: DOMAINS.VERIFIER, role: 'custodian' };

function plantedWorkspace(mutate) {
  const dir = mkTestTmp('eval-leak-src-');
  fs.cpSync(path.join(FIXTURES, 'syn-sqli-js', 'pre'), dir, { recursive: true });
  mutate(dir);
  return dir;
}

describe('[QA-002.AC03] prompts and workspaces: answer keys, advisory prose and fixed-source hints are excluded', () => {
  test('protected terms come from evidence, advisory prose, benchmark names and fix hints', () => {
    assert.ok(TERMS.includes('synthetic-review-note-sqli'));
    assert.ok(TERMS.includes('a crafted id parameter is concatenated into the lookup statement'));
    assert.ok(TERMS.some((t) => t.includes('select * from users where id = ?')));
    assert.ok(TERMS.includes('owasp benchmark'));
  });

  test('planted prompt leaks fail; the clean prompt passes', () => {
    const planted = [
      'Review app.js. Note synthetic-review-note-sqli says the query is injectable.',
      'Advisory: A crafted id parameter is concatenated into the lookup statement.',
      'The fixed version uses db.query("SELECT * FROM users WHERE id = ?", [id]).',
      'This case comes from the OWASP Benchmark suite.',
      'See GHSA-abcd-1234-wxyz for details.',
      'Relevant: CVE-2024-12345.',
    ];
    for (const p of planted) { const g = guardPrompt(p, TERMS); assert.equal(g.ok, false, p); assert.ok(g.leaks.length >= 1); }
    assert.equal(guardPrompt('Review app.js for injection risks in request handling.', TERMS).ok, true);
    assert.deepEqual(auditText('plain text', TERMS), []);
  });

  test('a short or generic term cannot be protected (no substring noise)', () => {
    assert.equal(protectedTermsFrom({ advisoryText: ['sql', 'id'] }).filter((t) => !t.includes('owasp') && t !== 'juliet' && !t.includes('answer') && !t.includes('ground') && !t.includes('cve-replay') && !t.includes('corpus') && !t.includes('sard')).length, 0);
  });

  test('planted workspace leaks are quarantined and the staged copy is removed', () => {
    const plants = {
      'an answer-key file': (d) => fs.writeFileSync(path.join(d, 'expected.json'), '{"app.js":[8]}'),
      'a label file in a subdirectory': (d) => { fs.mkdirSync(path.join(d, 'meta')); fs.writeFileSync(path.join(d, 'meta', 'labels.json'), '[]'); },
      'an advisory record': (d) => fs.writeFileSync(path.join(d, 'advisory.md'), 'text'),
      'a benchmark answer file': (d) => fs.writeFileSync(path.join(d, 'result.json'), '{}'),
      'advisory prose in a comment': (d) => fs.appendFileSync(path.join(d, 'app.js'), '\n// A crafted id parameter is concatenated into the lookup statement\n'),
      'a fixed-source hint in a comment': (d) => fs.appendFileSync(path.join(d, 'app.js'), '\n// db.query("SELECT * FROM users WHERE id = ?", [id])\n'),
      'an advisory id in a comment': (d) => fs.appendFileSync(path.join(d, 'app.js'), '\n// fixes GHSA-abcd-1234-wxyz\n'),
      'a symlink out of the tree': (d) => fs.symlinkSync('/etc/hosts', path.join(d, 'link.txt')),
    };
    for (const [name, mutate] of Object.entries(plants)) {
      const src = plantedWorkspace(mutate);
      const dest = path.join(mkTestTmp('eval-leak-dst-'), 'ws');
      const r = stageWorkspace({ srcDir: src, destDir: dest, terms: TERMS });
      assert.equal(r.ok, false, `${name} must be quarantined`);
      assert.equal(r.quarantined, true);
      assert.equal(fs.existsSync(dest), false, `${name}: the leaking workspace must not remain on disk`);
      assert.ok(r.leaks.length >= 1);
    }
    const clean = stageWorkspace({ srcDir: path.join(FIXTURES, 'syn-sqli-js', 'pre'), destDir: path.join(mkTestTmp('eval-clean-dst-'), 'ws'), terms: TERMS });
    assert.equal(clean.ok, true, JSON.stringify(clean.leaks));
    assert.ok(fs.existsSync(path.join(clean.destDir, 'app.js')));
  });

  test('all the shipped synthetic target trees pass the audit', () => {
    for (const id of ['syn-sqli-js', 'syn-cmd-py', 'syn-nearmiss-js']) for (const v of ['pre', 'post']) {
      const dir = path.join(FIXTURES, id, v);
      if (fs.existsSync(dir)) assert.equal(auditWorkspace(dir, TERMS).ok, true, `${id}/${v}`);
    }
  });

  test('the audit is bounded: too many files is a failure, never a pass', () => {
    const dir = mkTestTmp('eval-many-');
    for (let i = 0; i < 12; i++) fs.writeFileSync(path.join(dir, `f${i}.txt`), 'x');
    const r = auditWorkspace(dir, [], { maxFiles: 5 });
    assert.equal(r.ok, false);
    assert.ok(r.leaks.some((l) => l.kind === 'audit-truncated'));
  });

  test('quarantine is recorded as a run outcome when the pinned tree itself contains a leak', async () => {
    // Pin the leaky tree: build a one-target protocol over it, so only the audit (not the digest check) can stop it.
    const { buildSyntheticSuite } = await import('../../src/posture/evaluation/synthetic.js');
    const root = mkTestTmp('eval-pinned-leak-');
    fs.cpSync(FIXTURES, root, { recursive: true });
    fs.appendFileSync(path.join(root, 'syn-sqli-js', 'pre', 'app.js'), '\n// fixes GHSA-abcd-1234-wxyz\n');
    const leaky = buildSyntheticSuite({ fixturesDir: root });
    assert.ok(leaky.protocol, 'the leaky tree is pinned, so the digest check passes');
    const calls = [];
    const { run } = await runEvaluation({
      protocol: leaky.protocol, config: { layer: 'deep-taint' }, resolveTarget: (t, v) => ({ dir: path.join(root, t.id, v) }), protectedTerms: TERMS, split: 'dev',
      scanFn: async (dir) => { calls.push(dir); return { findings: [SYN_FINDING()] }; },
    });
    const q = run.outcomes.find((o) => o.targetId === 'syn-sqli-js' && o.variant === 'pre');
    assert.equal(q.status, 'quarantined');
    assert.match(q.failureReason, /leakage control/);
    assert.equal(run.totals.quarantined, 1);
    assert.equal(calls.some((d) => d.includes('syn-sqli-js-pre')), false);
    assert.ok(calls.length >= 1, 'control: clean targets in the same run were still scanned');
  });
});

describe('[QA-002.AC03] the custodian holds the labels; workers and the engine cannot read or write them', () => {
  test('only the custodian writes; workers, targets and signers are denied; a bad label rejects the whole write', () => {
    const dir = path.join(mkTestTmp('eval-custody-'), 'labels');
    for (const actor of [{ domain: DOMAINS.WORKER, role: 'custodian' }, { domain: DOMAINS.TARGET, role: 'custodian' }, { domain: DOMAINS.SIGNER, role: 'custodian' }, { domain: DOMAINS.VERIFIER, role: 'worker' }, null]) {
      const r = custodianWriteLabels(dir, actor, { defects, negatives });
      assert.equal(r.ok, false);
      assert.equal(r.errors[0].code, 'CUSTODY_DENIED');
    }
    assert.equal(fs.existsSync(dir), false, 'a denied write leaves nothing on disk');
    const bad = { ...defects[0], language: '' };
    assert.equal(custodianWriteLabels(dir, CUSTODIAN, { defects: [bad], negatives: [] }).ok, false);
    assert.equal(fs.existsSync(path.join(dir, LABEL_FILE)), false);
    const ok = custodianWriteLabels(dir, CUSTODIAN, { defects, negatives });
    assert.equal(ok.ok, true, JSON.stringify(ok.errors));
    assert.equal(ok.labelsHash, sealLabels(defects, negatives));
    assert.equal(fs.statSync(path.join(dir, LABEL_FILE)).mode & 0o777, 0o600);
    assert.equal(fs.statSync(dir).mode & 0o777, 0o700);
  });

  test('only the verifier domain reads sealed labels, and only while they match the sealed hash', () => {
    const dir = path.join(mkTestTmp('eval-custody-'), 'labels');
    const { labelsHash } = custodianWriteLabels(dir, CUSTODIAN, { defects, negatives });
    for (const d of [DOMAINS.WORKER, DOMAINS.TARGET, DOMAINS.SIGNER, 'nonsense', undefined]) {
      const r = custodianReadLabels(dir, { domain: d }, { expectedHash: labelsHash });
      assert.equal(r.ok, false, String(d));
      assert.equal(r.errors[0].code, 'CUSTODY_DENIED');
    }
    const read = custodianReadLabels(dir, CUSTODIAN, { expectedHash: labelsHash });
    assert.equal(read.ok, true);
    assert.equal(read.defects.length, defects.length);
    // Tamper: change a label after sealing.
    const file = path.join(dir, LABEL_FILE);
    const data = JSON.parse(fs.readFileSync(file, 'utf8'));
    data.defects[0].location.startLine = 1;
    fs.writeFileSync(file, JSON.stringify(data));
    const tampered = custodianReadLabels(dir, CUSTODIAN, { expectedHash: labelsHash });
    assert.equal(tampered.ok, false);
    assert.equal(tampered.errors[0].code, 'LABELS_HASH_MISMATCH');
  });

  test('a workspace that contains or sits inside the label directory is refused', () => {
    const base = mkTestTmp('eval-overlap-');
    const labels = path.join(base, 'labels'); fs.mkdirSync(labels);
    assert.equal(assertCustodyIsolation(labels, base).ok, false, 'workspace contains the labels');
    assert.equal(assertCustodyIsolation(labels, path.join(labels, 'ws')).ok, false, 'workspace inside the labels');
    assert.equal(assertCustodyIsolation(labels, labels).ok, false);
    const other = mkTestTmp('eval-other-');
    assert.equal(assertCustodyIsolation(labels, other).ok, true);
  });

  test('the engine environment carries no label path, evaluation variable or secret', () => {
    const labelDir = '/srv/custodian/labels';
    const env = engineEnvironment({
      PATH: '/usr/bin', LANG: 'C', AGENTIC_SECURITY_EVAL_LABELS: labelDir, AGENTIC_EVAL_KEY: 'x', SOME_PATH_LIST: `/a:${labelDir}:/b`,
      AWS_SECRET_ACCESS_KEY: 'shh', GITHUB_TOKEN: 'ghp_x',
    }, { labelDir });
    assert.deepEqual(Object.keys(env).sort(), ['LANG', 'PATH']);
  });

  test('the scan function is handed the staged workspace and a scrubbed environment, never the label directory', async () => {
    const labelDir = path.join(mkTestTmp('eval-lbl-'), 'labels');
    custodianWriteLabels(labelDir, CUSTODIAN, { defects, negatives });
    const seen = [];
    process.env.AGENTIC_SECURITY_EVAL_LABELS = labelDir;
    try {
      await runEvaluation({
        protocol: suite().protocol, config: { layer: 'deep-taint' }, resolveTarget: resolver(), protectedTerms: TERMS, split: 'dev',
        scanFn: async (dir, o) => { seen.push({ dir, env: o.env }); return { findings: [] }; },
      });
    } finally { delete process.env.AGENTIC_SECURITY_EVAL_LABELS; }
    assert.ok(seen.length > 0);
    for (const s of seen) {
      assert.equal(assertCustodyIsolation(labelDir, s.dir).ok, true);
      assert.ok(!JSON.stringify(s.env).includes(labelDir));
      assert.equal(Object.keys(s.env).some((k) => /EVAL/i.test(k)), false);
    }
  });

  test('sealed targets need an explicit custodian grant to run', async () => {
    const r = await runEvaluation({ protocol: suite().protocol, config: { layer: 'deep-taint' }, resolveTarget: resolver(), scanFn: async () => ({ findings: [] }), split: 'sealed' });
    assert.equal(r.ok, false);
    assert.equal(r.errors[0].code, 'SEALED_ACCESS');
    const all = await runEvaluation({ protocol: suite().protocol, config: { layer: 'deep-taint' }, resolveTarget: resolver(), scanFn: async () => ({ findings: [] }), split: 'all' });
    assert.equal(all.ok, false);
  });
});

describe('[QA-002.AC03] the engine under test cannot read the label directory through the sandbox boundary', () => {
  // Same honesty rule as test/trust-boundary.test.js: where the host cannot prove read denial the boundary must
  // report `blocked` and run nothing. Nothing here asserts an outcome that was not executed.
  const BACKEND = detectBackend();

  test('a target in the boundary cannot read the sealed labels; where the boundary cannot prove that, it is blocked and nothing runs', async () => {
    const base = mkTestTmp('eval-boundary-');
    const labelDir = path.join(base, 'labels');
    custodianWriteLabels(labelDir, CUSTODIAN, { defects, negatives });
    const root = path.join(base, 'ws'); fs.mkdirSync(root);
    const probe = `try { const s = require('fs').readFileSync(${JSON.stringify(path.join(labelDir, LABEL_FILE))}, 'utf8'); console.log('LEAKED:' + s.length); } catch (e) { console.log('DENIED'); }`;
    const r = await runInBoundary([process.execPath, '-e', probe], { root, labelDirs: [labelDir], timeoutMs: 20000 });
    if (r.blocked) {
      assert.equal(r.executed, false, 'a blocked boundary must not have run the target');
      assert.ok(r.reasons.length >= 1);
      return;
    }
    assert.equal(r.executed, true);
    assert.ok(['userspace', 'namespace'].includes(BACKEND), `an executed run implies a proved backend, got ${BACKEND}`);
    assert.match(r.targetOutput.stdout, /DENIED/);
    assert.doesNotMatch(r.targetOutput.stdout, /LEAKED/);
    // Control: without the label directory declared, the same probe CAN read it, so the denial above is caused by `labelDirs`.
    const control = await runInBoundary([process.execPath, '-e', probe], { root, labelDirs: [], timeoutMs: 20000 });
    assert.match(control.targetOutput.stdout, /LEAKED/);
  });

  test('a workspace overlapping the label directory is refused by the boundary itself', async () => {
    const base = mkTestTmp('eval-boundary-overlap-');
    const labelDir = path.join(base, 'labels');
    custodianWriteLabels(labelDir, CUSTODIAN, { defects, negatives });
    const r = await runInBoundary([process.execPath, '-e', '1'], { root: base, labelDirs: [labelDir] });
    assert.equal(r.blocked, true);
    assert.equal(r.executed, false);
  });
});

describe('[QA-002.AC03] static isolation: nothing in the engine can reach the custodian', () => {
  function walk(dir, out = []) {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) walk(p, out); else if (e.name.endsWith('.js')) out.push(p);
    }
    return out;
  }

  test('no module outside posture/evaluation imports the evaluation tooling', () => {
    const inside = path.join(SRC, 'posture', 'evaluation') + path.sep;
    const offenders = [];
    for (const f of walk(SRC)) {
      if (f.startsWith(inside)) continue;
      const text = fs.readFileSync(f, 'utf8');
      if (/from\s+['"][^'"]*\/evaluation\/(custody|labels|runner|score|gates|protocol)\.js['"]/.test(text)) offenders.push(path.relative(SRC, f));
    }
    assert.deepEqual(offenders, []);
  });

  test('no evaluation module other than the custodian reads the label file by name', () => {
    const dir = path.join(SRC, 'posture', 'evaluation');
    const readers = walk(dir).filter((f) => fs.readFileSync(f, 'utf8').includes('LABEL_FILE')).map((f) => path.basename(f));
    assert.deepEqual(readers, ['custody.js']);
  });

  test('the engine entry points do not import the evaluation directory (control: the scan child, which must not either)', () => {
    for (const rel of ['engine.js', 'runScan.js', 'posture/evaluation/scan-child.js']) {
      const text = fs.readFileSync(path.join(SRC, rel), 'utf8');
      assert.doesNotMatch(text, /evaluation\/(custody|labels|score|gates|protocol)\.js/, rel);
    }
  });
});
