// Contract test for detector spec synthesis (docs/reference/detector-spec-synthesis-contract.md): the real synthesis runs with an injected
// transport and reader (no network, no model) and the proposal, its sinks and sanitizers, the accepted reply keys and the exit codes are
// held to the page in both directions. The never-incorporated rule is exercised: the output path confinement, nothing written by the
// synthesis itself, no scanner or CLI module importing it, and the real CLI refusing with the feature off.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { mkTestTmp } from '../helpers/tmp.js';
import { REPO, readPage, fieldsUnder, sameFields } from '../helpers/contract-page.js';
import {
  synthesizeDetectorSpec, validateDetectorSpec, proposalOutputPath, writeProposal, buildPrompt,
  FEATURE_ID, EXIT, SEVERITIES, LANGUAGES, SYNTHESIS_LIMITS,
} from '../../src/discovery/detector-spec-synthesis.js';

const PAGE = readPage('docs/reference/detector-spec-synthesis-contract.md');
const SCRIPT = path.join(REPO, 'scripts', 'synthesize-detector.mjs');
const ENV_ON = { AGENTIC_SECURITY_ASSURANCE_DETECTOR_SPEC_SYNTHESIS: '1' };
const ENDPOINT = 'http://127.0.0.1:11434/v1/chat';

const nonceOf = (text) => (/BEGIN-UNTRUSTED-CODE-EXCERPT-([a-f0-9]+)/.exec(text) || [])[1];
const reply = (text, over = {}) => JSON.stringify({
  challenge: nonceOf(text), cwe: 'CWE-89', language: 'java',
  sinks: [
    { method: 'executeQuery', receiverType: 'Statement', argIdx: 0, taintRequired: true, note: 'the SQL text' },
    { method: 'execute', argIdx: 'any', taintRequired: false },
  ],
  sanitizers: [{ method: 'setString', note: 'a bound parameter' }],
  severity: 'high', remediation: 'Use a prepared statement with bound parameters instead of concatenating the query text.', ...over,
});

function project() {
  const root = mkTestTmp('agsec-dss-contract-');
  fs.writeFileSync(path.join(root, 'package.json'), '{}');
  fs.mkdirSync(path.join(root, 'samples'));
  const sample = path.join(root, 'samples', 'Bad.java');
  fs.writeFileSync(sample, 'class Bad { void run(String q) { stmt.executeQuery("SELECT * FROM t WHERE x = " + q); } }\n');
  return { root, sample };
}
const reader = (p, max) => ({ status: 'ok', text: fs.readFileSync(p, 'utf8').slice(0, max) });
async function withEgressDefault(fn) {
  const keys = ['AGENTIC_SECURITY_EGRESS_MODE', 'AGENTIC_SECURITY_EGRESS_DENY'];
  const prev = Object.fromEntries(keys.map((k) => [k, process.env[k]]));
  for (const k of keys) delete process.env[k];
  try { return await fn(); } finally { for (const k of keys) if (prev[k] !== undefined) process.env[k] = prev[k]; }
}
const listTree = (dir, base = dir) => fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
  const p = path.join(dir, e.name);
  return e.isDirectory() ? listTree(p, base) : [path.relative(base, p)];
}).sort();

const { root, sample } = project();
const before = listTree(root);
let calls = 0;
const run = await withEgressDefault(() => synthesizeDetectorSpec({
  cwe: 'CWE-89', lang: 'java', files: [sample], scanRoot: root, endpoint: ENDPOINT, env: ENV_ON, cwd: root,
  transport: async ({ text }) => { calls++; return reply(text); }, readFile: reader,
}));

test('contract: a valid reply becomes a proposal with exactly the documented fields at every level', () => {
  assert.equal(run.status, 'ok', run.reason);
  assert.equal(run.exitCode, EXIT.ok);
  assert.equal(calls, 1);
  sameFields(run.spec, fieldsUnder(PAGE, 'Proposal'), 'proposal');
  sameFields(run.spec.sinks[0], fieldsUnder(PAGE, 'Sink'), 'sink');
  sameFields(run.spec.sinks[1], fieldsUnder(PAGE, 'Sink'), 'sink without a note', ['note']);
  assert.equal(run.spec.sinks[1].note, undefined, 'a sink with no note has no note field');
  assert.equal(run.spec.sinks[1].receiverType, null, 'a missing receiverType becomes null');
  sameFields(run.spec.sanitizers[0], fieldsUnder(PAGE, 'Sanitizer'), 'sanitizer');
  assert.deepEqual(run.spec.synthesizedFrom, ['Bad.java']);
  assert.ok(!Number.isNaN(Date.parse(run.spec.synthesizedAt)));
  assert.equal(run.spec.challenge, undefined, 'the nonce is dropped from the proposal');
  assert.ok(PAGE.includes(`\`${run.spec.review}\``), 'the fixed review text is quoted on the page verbatim');
});

test('contract: the reply keys the prompt asks for are exactly the documented ones, and an extra key refuses the reply', () => {
  const asked = [...buildPrompt({ cwe: 'CWE-89', lang: 'java', samples: [{ name: 'a', text: 'x' }], nonce: 'abc' }).matchAll(/^ {2}"(\w+)":/gm)].map((m) => m[1]);
  assert.deepEqual(asked.sort(), [...fieldsUnder(PAGE, 'Model reply')].sort());
  const good = JSON.parse(reply('BEGIN-UNTRUSTED-CODE-EXCERPT-abc'));
  const want = { nonce: 'abc', cwe: 'CWE-89', lang: 'java' };
  assert.equal(validateDetectorSpec(good, want).ok, true);
  const { sanitizers, ...noSanitizers } = good;
  assert.ok(sanitizers);
  const omitted = validateDetectorSpec(noSanitizers, want);
  assert.equal(omitted.ok, true, 'sanitizers may be omitted');
  assert.deepEqual(omitted.spec.sanitizers, []);
  assert.equal(validateDetectorSpec({ ...good, pattern: '(a+)+$' }, want).ok, false, 'an unknown top-level key refuses');
  assert.equal(validateDetectorSpec({ ...good, sinks: [{ ...good.sinks[0], regex: '.*' }] }, want).ok, false, 'an unknown sink key refuses');
  assert.equal(validateDetectorSpec({ ...good, sanitizers: [{ method: 'x', extra: 1 }] }, want).ok, false, 'an unknown sanitizer key refuses');
  assert.equal(validateDetectorSpec({ ...good, challenge: 'other' }, want).ok, false, 'a wrong nonce refuses');
});

test('contract: the documented value limits are the enforced ones', () => {
  const good = JSON.parse(reply('BEGIN-UNTRUSTED-CODE-EXCERPT-abc'));
  const want = { nonce: 'abc', cwe: 'CWE-89', lang: 'java' };
  const v = (over) => validateDetectorSpec({ ...good, ...over }, want).ok;
  const sink = good.sinks[0];
  assert.equal(v({ sinks: [] }), false);
  assert.equal(v({ sinks: Array(20).fill(sink) }), true);
  assert.equal(v({ sinks: Array(21).fill(sink) }), false);
  assert.equal(v({ sanitizers: Array(21).fill({ method: 'x' }) }), false);
  assert.equal(v({ sinks: [{ ...sink, argIdx: 63 }] }), true);
  assert.equal(v({ sinks: [{ ...sink, argIdx: 64 }] }), false);
  assert.equal(v({ sinks: [{ ...sink, method: 'exec(.*)' }] }), false, 'a method is an identifier, never a pattern');
  assert.equal(v({ remediation: 'too short' }), false);
  assert.equal(v({ remediation: 'x'.repeat(1001) }), false);
  assert.equal(v({ remediation: 'line one is long enough\nline two' }), false);
  assert.equal(v({ sinks: [{ ...sink, note: 'n'.repeat(301) }] }), false);
  assert.deepEqual([...SEVERITIES], ['critical', 'high', 'medium', 'low']);
  for (const s of SEVERITIES) assert.ok(PAGE.includes(`\`${s}\``));
  for (const l of LANGUAGES) assert.ok(PAGE.includes(`\`${l}\``), `${l} is on the page`);
  assert.deepEqual({ ...SYNTHESIS_LIMITS }, { maxFiles: 12, maxFileBytes: 64 * 1024, maxTotalBytes: 192 * 1024 });
  assert.equal(FEATURE_ID, 'detector-spec-synthesis');
});

test('contract: the exit codes are the documented four', () => {
  assert.deepEqual(Object.values(EXIT).map((c) => String(c)).sort(), fieldsUnder(PAGE, 'Exit codes').sort());
});

test('contract: synthesis itself writes no proposal; only the egress audit under .agentic-security/ appears', () => {
  const after = listTree(root);
  const added = after.filter((f) => !before.includes(f));
  assert.ok(added.every((f) => f.startsWith(`.agentic-security${path.sep}`)), `unexpected files: ${added.join(', ')}`);
  assert.ok(!added.some((f) => f.endsWith('.json') && !f.includes('audit')), 'no proposal-like file was written');
});

test('contract: a proposal is written only inside the working directory, never under scanner/src, never over a file without --force', () => {
  const cwd = mkTestTmp('agsec-dss-out-');
  for (const bad of ['../outside.json', path.join('scanner', 'src', 'sast', 'proposal.json'), path.join('a', 'scanner', 'src', 'p.json')]) {
    const r = writeProposal(run.spec, bad, { cwd });
    assert.equal(r.ok, false, `${bad} is refused`);
  }
  assert.deepEqual(listTree(cwd), [], 'a refused path writes nothing');
  const first = writeProposal(run.spec, 'proposal.json', { cwd });
  assert.equal(first.ok, true);
  assert.deepEqual(JSON.parse(fs.readFileSync(first.path, 'utf8')), run.spec, 'the file holds the proposal as documented');
  assert.equal(writeProposal({ other: 1 }, 'proposal.json', { cwd }).ok, false, 'an existing file is not replaced without --force');
  assert.deepEqual(JSON.parse(fs.readFileSync(first.path, 'utf8')), run.spec);
  fs.mkdirSync(path.join(cwd, 'dir'));
  assert.equal(proposalOutputPath('dir', { cwd, force: true }).ok, false, 'a directory is never a target');
});

test('contract: nothing in the scanner or its CLI imports the synthesis module, so nothing can load a proposal', () => {
  const importers = [];
  for (const top of ['scanner/src', 'scanner/bin']) {
    for (const rel of listTree(path.join(REPO, top))) {
      if (!/\.(m?js|cjs)$/.test(rel)) continue;
      const file = path.join(REPO, top, rel);
      if (file.endsWith(path.join('discovery', 'detector-spec-synthesis.js'))) continue;
      if (/detector-spec-synthesis\.js['"]/.test(fs.readFileSync(file, 'utf8'))) importers.push(path.join(top, rel));
    }
  }
  assert.deepEqual(importers, []);
  assert.match(fs.readFileSync(SCRIPT, 'utf8'), /detector-spec-synthesis\.js'/, 'the CLI front is the one importer');
});

test('contract: the real CLI refuses with the feature off (exit 2) and on a usage problem (exit 4), writing nothing', () => {
  const cwd = mkTestTmp('agsec-dss-cli-');
  fs.writeFileSync(path.join(cwd, 'Bad.java'), 'class Bad {}\n');
  const env = Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith('AGENTIC_SECURITY_ASSURANCE') && k !== 'AGENTIC_SECURITY_LLM_ENDPOINT'));
  const cli = (...a) => spawnSync(process.execPath, [SCRIPT, ...a], { cwd, env, encoding: 'utf8', timeout: 15000 });
  const off = cli('--cwe', 'CWE-89', '--lang', 'java', '--files', 'Bad.java', '--out', 'p.json');
  assert.equal(off.status, EXIT.refused, off.stderr);
  const noEndpoint = spawnSync(process.execPath, [SCRIPT, '--cwe', 'CWE-89', '--lang', 'java', '--files', 'Bad.java', '--out', 'p.json'], { cwd, env: { ...env, ...ENV_ON }, encoding: 'utf8', timeout: 15000 });
  assert.equal(noEndpoint.status, EXIT.refused, noEndpoint.stderr);
  assert.match(noEndpoint.stderr, /missing-provider/);
  assert.equal(cli('--cwe', 'CWE-89', '--lang', 'cobol', '--files', 'Bad.java').status, EXIT.usage);
  assert.equal(cli('--lang', 'java').status, EXIT.usage);
  assert.ok(!fs.existsSync(path.join(cwd, 'p.json')), 'a refused run writes no proposal');
});

test('contract: the comparison itself fails when a field is added or dropped', () => {
  const doc = fieldsUnder(PAGE, 'Proposal');
  assert.throws(() => sameFields({ ...run.spec, extra: 1 }, doc, 'proposal'));
  const { review, ...rest } = run.spec;
  assert.ok(review);
  assert.throws(() => sameFields(rest, doc, 'proposal'));
});
