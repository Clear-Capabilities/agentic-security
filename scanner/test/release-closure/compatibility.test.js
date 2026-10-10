// REL-001.AC03: compatibility tests retain existing Haskell/Nix and advertised core-language behaviour, and an
// unsupported remote prerequisite can never be counted as a passing local gate.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { CLOSURE_STEPS, runClosure, evaluateClosureRecord, applicability } from '../../../scripts/release-closure.mjs';
import { runScan } from '../../src/runScan.js';
import { mkTestTmp } from '../helpers/tmp.js';
import { REPO, PKG, COMMIT, ALL_PRESENT, NO_REMOTE_TOOLS, fakeExec } from '../helpers/closure-fixtures.js';

const CLEAN = (record) => ({ commit: COMMIT, tree: record.tree, dirtyPaths: [] });
const NINE = ['js/ts', 'python', 'java', 'kotlin', 'go', 'ruby', 'php', 'c#', 'rust'];

function copyExample(rel, into) {
  fs.cpSync(path.join(REPO, 'examples', rel), into, { recursive: true });
  return into;
}
const keyOf = (f) => `${f.id}|${f.severity}|${f.file}|${f.line}|${f.vuln}|${f.cwe}|${f.family}`;

test('[REL-001.AC03] the plan carries the Haskell, Nix and core-language compatibility suites and benches', () => {
  const ids = CLOSURE_STEPS.map((s) => s.id);
  for (const id of ['compat-haskell', 'compat-nix', 'compat-language', 'compat-language-support', 'compat-corpus', 'compat-layer-recall']) assert.ok(ids.includes(id), id);
  const scripts = Object.fromEntries(CLOSURE_STEPS.map((s) => [s.id, s.run.script]));
  assert.equal(scripts['compat-haskell'], 'test:haskell');
  assert.equal(scripts['compat-nix'], 'test:nix');
  assert.equal(scripts['compat-corpus'], 'bench:cve-replay:check');
  assert.equal(scripts['compat-layer-recall'], 'bench:layer-recall:check');
  // the per-language bench the compat step relies on covers all nine advertised core languages
  const baseline = JSON.parse(fs.readFileSync(path.join(REPO, 'bench', 'layer-recall', 'baseline.json'), 'utf8'));
  for (const lang of NINE) assert.ok((baseline.totalByLanguage[lang] ?? 0) > 0, `${lang} has scored corpus entries`);
});

test('[REL-001.AC03] with every new assurance feature off, Haskell and Nix scans are the same as with the global kill switch set', async () => {
  const root = mkTestTmp('compat-');
  copyExample('haskell-app/vulnerable', path.join(root, 'hs'));
  copyExample('nixos-host/vulnerable', path.join(root, 'nix'));
  const was = process.env.AGENTIC_SECURITY_NO_ASSURANCE;
  try {
    for (const dir of ['hs', 'nix']) {
      delete process.env.AGENTIC_SECURITY_NO_ASSURANCE;
      const base = (await runScan(path.join(root, dir), {})).scan.findings.map(keyOf).sort();
      process.env.AGENTIC_SECURITY_NO_ASSURANCE = '1';
      const killed = (await runScan(path.join(root, dir), {})).scan.findings.map(keyOf).sort();
      assert.ok(base.length > 0, `${dir}: the documented vulnerable example still produces findings`);
      assert.deepEqual(killed, base, `${dir}: no new feature changes the output`);
    }
  } finally {
    if (was === undefined) delete process.env.AGENTIC_SECURITY_NO_ASSURANCE; else process.env.AGENTIC_SECURITY_NO_ASSURANCE = was;
  }
});

test('[REL-001.AC03] the documented Haskell and Nix families are still detected on the vulnerable examples', async () => {
  const root = mkTestTmp('compat-fam-');
  copyExample('haskell-app/vulnerable', path.join(root, 'hs'));
  copyExample('nixos-host/vulnerable', path.join(root, 'nix'));
  const hs = (await runScan(path.join(root, 'hs'), {})).scan.findings;
  const nix = (await runScan(path.join(root, 'nix'), {})).scan.findings;
  assert.ok(hs.some((f) => /\.hs$|\.cabal$/.test(f.file)), 'a Haskell finding is attributed to a Haskell file');
  assert.ok(nix.some((f) => /\.nix$/.test(f.file)), 'a Nix finding is attributed to a Nix file');
  const clean = (await runScan(copyExample('haskell-app/fixed', path.join(root, 'fixed')), {})).scan.findings;
  assert.ok(clean.length < hs.length, 'the fixed example still has fewer findings than the vulnerable one');
});

test('[REL-001.AC03] a remote prerequisite that is unavailable locally is unsupported, is not run, and is never counted as a passing local gate', () => {
  const exec = fakeExec();
  const { record } = runClosure({ repoRoot: REPO, outDir: mkTestTmp('closure-remote-'), env: NO_REMOTE_TOOLS, exec });
  const remote = CLOSURE_STEPS.filter((s) => s.remote);
  assert.ok(remote.length >= 2);
  for (const s of remote) {
    const r = record.steps.find((x) => x.id === s.id);
    assert.equal(r.state, 'unsupported', `${s.id} is unsupported here`);
    assert.equal(r.log, null);
    assert.equal(r.exitCode, null);
    assert.equal(exec.calls.some((c) => c.cmd === 'npm' && c.args[1] === s.run.script), false, `${s.id} was not run locally`);
  }
  // the darwin stand-in also lacks tools for non-remote steps? none of them declare any
  const v = evaluateClosureRecord(record, CLEAN(record), { pkg: PKG });
  assert.equal(v.localOk, true, 'the local gate judges only what can run locally');
  assert.equal(v.publishable, false, 'but the evidence is not publishable while a remote prerequisite is unattested');
  assert.deepEqual(v.remotePending.map((p) => p.id).sort(), remote.map((s) => s.id).sort());
  assert.equal(record.steps.filter((s) => s.state === 'pass').length, CLOSURE_STEPS.length - remote.length, 'unsupported steps are not in the passing count');
});

test('[REL-001.AC03] only a successful attestation for this exact commit satisfies a remote prerequisite', () => {
  const { record } = runClosure({ repoRoot: REPO, outDir: mkTestTmp('closure-remote-'), env: NO_REMOTE_TOOLS, exec: fakeExec() });
  const remote = CLOSURE_STEPS.filter((s) => s.remote);
  const legs = (s, commit) => (s.remote.legs || []).map((name, i) => ({ name, jobId: 1 + i, commit, conclusion: 'success' }));
  const att = (s, over = {}) => ({ stepId: s.id, commit: COMMIT, conclusion: 'success', source: { kind: 'github-actions-jobs', legs: legs(s, over.commit || COMMIT) }, ...over });
  const judge = (attestations) => evaluateClosureRecord(record, CLEAN(record), { pkg: PKG, attestations });
  assert.equal(judge(remote.map((s) => att(s))).publishable, true, 'control: both attested for this commit');
  assert.equal(judge(remote.slice(1).map((s) => att(s))).publishable, false, 'one still missing');
  assert.equal(judge(remote.map((s) => att(s, { commit: 'f'.repeat(40) }))).publishable, false, 'another commit does not count');
  assert.equal(judge(remote.map((s) => att(s, { conclusion: 'failure' }))).publishable, false, 'a failed run does not count');
  assert.equal(judge(remote.map((s) => att(s, { stepId: 'foundation' }))).publishable, false, 'an attestation for another step does not count');
  assert.equal(judge(remote.map((s) => att(s))).localOk, true);
});

test('[REL-001.AC03] a remote-capable step that runs locally and fails is a hard failure, not a pending prerequisite', () => {
  const exec = fakeExec({ fail: [] });
  const failing = CLOSURE_STEPS.find((s) => s.remote);
  const bad = (cmd, args, o) => (cmd === 'npm' && args[1] === failing.run.script ? { ...exec(cmd, args, o), status: 1 } : exec(cmd, args, o));
  const { record } = runClosure({ repoRoot: REPO, outDir: mkTestTmp('closure-remote-'), env: ALL_PRESENT, exec: bad });
  assert.equal(record.steps.find((s) => s.id === failing.id).state, 'fail');
  const v = evaluateClosureRecord(record, CLEAN(record), { pkg: PKG });
  assert.equal(v.localOk, false);
  assert.equal(v.remotePending.length, 0);
  // and the same step passing locally needs no attestation
  const ok = runClosure({ repoRoot: REPO, outDir: mkTestTmp('closure-remote-'), env: ALL_PRESENT, exec: fakeExec() }).record;
  const v2 = evaluateClosureRecord(ok, CLEAN(ok), { pkg: PKG });
  assert.equal(v2.publishable, true);
});

test('[REL-001.AC03] applicability names the missing platform, tool or path instead of guessing', () => {
  const step = { needs: { platforms: ['linux'], tools: ['ghc'], paths: ['/etc/NIXOS'] } };
  assert.match(applicability(step, { platform: 'darwin', hasTool: () => true, exists: () => true }).reason, /needs platform linux/);
  assert.match(applicability(step, { platform: 'linux', hasTool: () => false, exists: () => true }).reason, /tool 'ghc'/);
  assert.match(applicability(step, { platform: 'linux', hasTool: () => true, exists: () => false }).reason, /\/etc\/NIXOS/);
  assert.deepEqual(applicability(step, { platform: 'linux', hasTool: () => true, exists: () => true }), { applicable: true });
  assert.deepEqual(applicability({}, { platform: 'win32', hasTool: () => false, exists: () => false }), { applicable: true });
});
