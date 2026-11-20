// Discovery localization and classification: the hunter is shown numbered, budget-shared slices; a citation must name a line
// that was shown and, when it carries a code anchor, the anchor must be on that line (or uniquely within two of it); a proposed
// CWE is kept only when the lens can raise it and, for an operation weakness, the cited lines hold that operation.
// Independently authored examples; no benchmark, advisory or answer-key input.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildHunterPromptWithMap, allotBudget, lensByKey } from '../src/discovery/lenses.js';
import { runHunter, parseCandidates } from '../src/discovery/hunter.js';
import { classifyCandidate, normalizeCwe } from '../src/discovery/classification.js';

const APP = [
  "const cp = require('child_process');",
  'function ping(req, res) {',
  '  const host = req.query.host;',
  "  cp.exec('ping -c 1 ' + host, (e, out) => res.send(out));",
  '}',
  'function show(req, res) {',
  "  res.send('<p>' + req.query.q + '</p>');",
  '}',
  'module.exports = { ping, show };',
].join('\n') + '\n';

const area = (files) => ({ id: 'area1', label: 'a', files, functions: [], size: files.length });
const invokeWith = (candidates) => async () => JSON.stringify({ candidates });

test('allotBudget shares the budget: a small file is shown whole even after a huge one', () => {
  const a = allotBudget(new Map([['huge.js', 1_000_000], ['small.js', 300]]), 10_000);
  assert.equal(a.get('small.js'), 300);
  assert.equal(a.get('huge.js'), 9_700);
});

test('the prompt numbers lines and the map records the shown range of a truncated file', () => {
  const big = Array.from({ length: 2000 }, (_, i) => `const v${i} = ${i};`).join('\n') + '\n';
  const { prompt, shown } = buildHunterPromptWithMap(area(['big.js', 'app.js']), lensByKey('injection'), { fileContents: { 'big.js': big, 'app.js': APP }, maxChars: 6000 });
  assert.match(prompt, /\n4\| {3}cp\.exec\('ping -c 1 ' \+ host/);
  assert.equal(shown['app.js'].to, 9);
  assert.equal(shown['app.js'].truncated, false);
  assert.ok(shown['big.js'].truncated && shown['big.js'].to < 2000 && shown['big.js'].to > 10);
  assert.match(prompt, /truncated: lines 1-\d+ of 2000 shown/);
});

test('a citation of a line that was not shown is discarded (line-not-shown)', async () => {
  const big = Array.from({ length: 2000 }, (_, i) => `const v${i} = ${i};`).join('\n') + '\n';
  const r = await runHunter(area(['big.js']), lensByKey('injection'), { fileContents: { 'big.js': big }, maxChars: 4000 }, { llmInvoke: invokeWith([{ title: 't', file: 'big.js', line: 1900 }]) });
  assert.equal(r.candidates.length, 0);
  assert.equal(r.citation.discardedByReason['line-not-shown'], 1);
});

test('a code anchor on the cited line is accepted; one line off is moved; a fabricated one is discarded', async () => {
  const ctx = { fileContents: { 'app.js': APP } };
  const ok = await runHunter(area(['app.js']), lensByKey('injection'), ctx, { llmInvoke: invokeWith([{ title: 'cmd', file: 'app.js', line: 4, code: "cp.exec('ping -c 1 ' + host, (e, out) => res.send(out));" }]) });
  assert.equal(ok.candidates.length, 1); assert.equal(ok.candidates[0].anchored, true); assert.equal(ok.candidates[0].line, 4);
  const moved = await runHunter(area(['app.js']), lensByKey('injection'), ctx, { llmInvoke: invokeWith([{ title: 'cmd', file: 'app.js', line: 3, code: "cp.exec('ping -c 1 ' + host" }]) });
  assert.equal(moved.candidates[0].line, 4); assert.equal(moved.candidates[0].citedLine, 3);
  const fake = await runHunter(area(['app.js']), lensByKey('injection'), ctx, { llmInvoke: invokeWith([{ title: 'cmd', file: 'app.js', line: 4, code: 'os.system(user_input)' }]) });
  assert.equal(fake.candidates.length, 0); assert.equal(fake.citation.discardedByReason['anchor-mismatch'], 1);
});

test('an anchor matching two nearby lines but not the cited one is ambiguous and discarded', async () => {
  const src = 'a();\nrun(x);\nb();\nrun(x);\nc();\n';
  const r = await runHunter(area(['d.js']), lensByKey('injection'), { fileContents: { 'd.js': src } }, { llmInvoke: invokeWith([{ title: 't', file: 'd.js', line: 3, code: 'run(x);' }]) });
  assert.equal(r.candidates.length, 0); assert.equal(r.citation.discardedByReason['anchor-ambiguous'], 1);
});

test('a candidate with no anchor is kept and marked unanchored (backward compatible)', () => {
  const c = parseCandidates(JSON.stringify({ candidates: [{ title: 't', file: 'app.js', line: 4 }] }), area(['app.js']), lensByKey('injection'), { fileContents: { 'app.js': APP } });
  assert.equal(c.length, 1); assert.equal(c[0].anchored, false); assert.equal(c[0].cwe, 'CWE-74'); assert.equal(c[0].cweBasis, 'lens');
});

test('a specific CWE is kept when the cited lines hold the operation, refused when they do not', async () => {
  const ctx = { fileContents: { 'app.js': APP } };
  const cmd = await runHunter(area(['app.js']), lensByKey('injection'), ctx, { llmInvoke: invokeWith([{ title: 'cmd', file: 'app.js', line: 4, code: "cp.exec('ping -c 1 ' + host", cwe: 'CWE-78' }]) });
  assert.equal(cmd.candidates[0].cwe, 'CWE-78'); assert.equal(cmd.candidates[0].cweBasis, 'operation-checked');
  // A command-injection claim cited on the module.exports line: no process call there, so the broad lens CWE stays.
  const wrong = await runHunter(area(['app.js']), lensByKey('injection'), ctx, { llmInvoke: invokeWith([{ title: 'cmd', file: 'app.js', line: 9, code: 'module.exports = { ping, show };', cwe: 'CWE-78' }]) });
  assert.equal(wrong.candidates[0].cwe, 'CWE-74'); assert.equal(wrong.candidates[0].proposedCwe, 'CWE-78'); assert.equal(wrong.candidates[0].cweRejected, 'no-operation-on-cited-lines');
});

test('classifyCandidate: lens bounds, logic weaknesses stay model-proposed, one CWE only', () => {
  const authz = lensByKey('authz');
  assert.deepEqual(classifyCandidate(authz, 'CWE-639', ['const doc = await Doc.findById(req.params.id);']).cwe, 'CWE-639');
  assert.equal(classifyCandidate(authz, 'CWE-639', []).cweBasis, 'model-proposed');
  assert.equal(classifyCandidate(authz, 'CWE-327', ['md5(x)']).cweRejected, 'outside-lens');
  assert.equal(classifyCandidate(authz, ['CWE-639', 'CWE-862'], []).cwe, 'CWE-285', 'a list of alternatives is not a CWE');
  assert.equal(classifyCandidate(lensByKey('wildcard'), 'cwe 22', ['fs.readFile(path.join(base, name))']).cwe, 'CWE-22');
  assert.equal(normalizeCwe('CWE-0078'), 'CWE-78'); assert.equal(normalizeCwe('not'), null);
});
