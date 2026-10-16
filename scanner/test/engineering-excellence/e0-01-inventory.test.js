// E0-01: the repository inventory and its maturity labels.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { execFileSync } from 'node:child_process';
import { makeRoot, cleanup, REPO } from './helpers.js';
import { MATURITY, absentFindings, buildInventory, checkClaims, classify, collectFacts, loadCapabilities, loadVerification, problems } from '../../../scripts/engineering-excellence/inventory.mjs';

const okRun = (over = {}) => ({ outcome: 'exited', exitCode: 0, counts: { tests: 5, pass: 5, fail: 0, skipped: 0 }, files: ['a.test.js'], log: 'x.log', commit: 'abcdef0123', version: '1.0.0', ...over });

async function fixtureRoot() {
  const { root, git } = await makeRoot();
  fs.mkdirSync(path.join(root, 'lib'), { recursive: true });
  fs.writeFileSync(path.join(root, 'lib', 'impl.js'), 'export const x = 1;\n');
  fs.writeFileSync(path.join(root, 'lib', 'impl.test.js'), "import { test } from 'node:test';\ntest('x', () => {});\n");
  git('add', '-A'); git('commit', '-q', '-m', 'impl');
  return { root, git };
}

test('maturity is computed from source, test mapping and a recorded run, never written by hand', async () => {
  const { root } = await fixtureRoot();
  try {
    const cap = { id: 'c', name: 'c', epics: [], source: ['lib/impl.js'], tests: ['lib/impl.test.js'], docs: [], partial: null };
    const v = (r) => ({ results: r ? { c: r } : {} });
    assert.equal(classify(root, { ...cap, source: ['lib/nope.js'] }, v(), '1.0.0').maturity, 'ABSENT');
    assert.equal(classify(root, { ...cap, tests: [] }, v(), '1.0.0').maturity, 'EXISTS-UNVERIFIED', 'no test mapped');
    assert.equal(classify(root, cap, v(), '1.0.0').maturity, 'EXISTS-UNVERIFIED', 'tests never run');
    assert.equal(classify(root, cap, v(okRun({ version: '0.9.0' })), '1.0.0').maturity, 'EXISTS-UNVERIFIED', 'run is for another version');
    assert.equal(classify(root, cap, v(okRun({ exitCode: 1, counts: { pass: 3, fail: 2 } })), '1.0.0').maturity, 'BLOCKED');
    assert.equal(classify(root, cap, v(okRun({ outcome: 'timeout-wall', exitCode: null })), '1.0.0').maturity, 'BLOCKED');
    assert.equal(classify(root, cap, v(okRun({ counts: { tests: 0, pass: 0, fail: 0 } })), '1.0.0').maturity, 'BLOCKED', 'a run that passed nothing proves nothing');
    assert.equal(classify(root, { ...cap, partial: 'only k=1' }, v(okRun()), '1.0.0').maturity, 'PARTIAL');
    const verified = classify(root, cap, v(okRun()), '1.0.0');
    assert.equal(verified.maturity, 'VERIFIED');
    assert.match(verified.reasons[0], /5 tests passed/);
  } finally { cleanup(root); }
});

test('the capability map must point at real files and real tests', async () => {
  const { root } = await fixtureRoot();
  try {
    fs.mkdirSync(path.join(root, 'scripts', 'engineering-excellence', 'data'), { recursive: true });
    const write = (caps) => fs.writeFileSync(path.join(root, 'scripts', 'engineering-excellence', 'data', 'capabilities.json'), JSON.stringify({ schemaVersion: 1, capabilities: caps }));
    write([{ id: 'a', name: 'a', epics: [], source: ['lib/impl.js'], tests: ['lib/impl.test.js'], docs: [] }]);
    assert.deepEqual(problems(root), []);
    write([{ id: 'a', name: 'a', epics: [], source: ['lib/missing.js'], tests: ['lib/impl.test.js'], docs: ['docs/none.md'] }, { id: 'a', name: 'b', epics: [], source: [], tests: ['lib/impl.js'], docs: [] }]);
    const p = problems(root).join('\n');
    assert.match(p, /does not exist: lib\/missing\.js/);
    assert.match(p, /does not exist: docs\/none\.md/);
    assert.match(p, /duplicate capability id a/);
    assert.match(p, /no source listed/);
    assert.match(p, /is not a test file/);
  } finally { cleanup(root); }
});

test('an item is reported ABSENT only when none of its search terms occur, and the search is reproducible', async () => {
  const { root } = await fixtureRoot();
  try {
    fs.mkdirSync(path.join(root, 'scanner', 'src'), { recursive: true });
    fs.writeFileSync(path.join(root, 'scanner', 'src', 'x.js'), '// FixVerificationRecord lives here\n');
    execFileSync('git', ['add', '-A'], { cwd: root }); execFileSync('git', ['commit', '-q', '-m', 'x'], { cwd: root });
    const out = absentFindings(root, { absent: [{ id: 'one', name: 'one', terms: ['FixVerificationRecord'], note: 'n' }, { id: 'two', name: 'two', terms: ['NoSuchSymbolAnywhere', 'AlsoNone'], note: 'n' }] });
    assert.equal(out[0].status, 'FOUND-ELSEWHERE');
    assert.equal(out[0].hits[0].files[0], 'scanner/src/x.js');
    assert.equal(out[1].status, 'ABSENT');
  } finally { cleanup(root); }
});

test('documentation claims are checked against the checkout and a mismatch is flagged, not hidden', async () => {
  const { root, git } = await makeRoot();
  try {
    fs.mkdirSync(path.join(root, 'scanner'), { recursive: true });
    fs.mkdirSync(path.join(root, '.claude-plugin'), { recursive: true });
    fs.writeFileSync(path.join(root, 'scanner', 'package.json'), JSON.stringify({ name: 'p', version: '2.0.0', scripts: {} }));
    fs.writeFileSync(path.join(root, 'CLAUDE.md'), '**Version:** 1.9.0  \n17 dispatchers\n MCP server. 17 tools (2 write)\n');
    fs.writeFileSync(path.join(root, 'README.md'), '![v](https://img.shields.io/badge/version-2.0.0-blue)');
    fs.writeFileSync(path.join(root, '.claude-plugin', 'plugin.json'), JSON.stringify({ version: '2.0.0' }));
    git('add', '-A'); git('commit', '-q', '-m', 'docs');
    const facts = collectFacts(root);
    assert.equal(facts.version, '2.0.0');
    const claims = checkClaims(root, { ...facts, mcpToolCount: 23, slashCommandFiles: 17 });
    const by = (c) => claims.find((x) => x.claim.startsWith(c));
    assert.equal(by('Version line').ok, false);
    assert.equal(by('Version line').actual, '1.9.0');
    assert.equal(claims.find((x) => x.doc === 'README.md').ok, true);
    assert.equal(by('slash command').ok, true);
    assert.equal(claims.find((x) => x.claim.startsWith('MCP tool count')).ok, false);
  } finally { cleanup(root); }
});

test('facts are measured from the real checkout', () => {
  const facts = collectFacts(REPO);
  const pkg = JSON.parse(fs.readFileSync(path.join(REPO, 'scanner', 'package.json'), 'utf8'));
  assert.equal(facts.version, pkg.version);
  assert.ok(facts.sourceFileCount > 500);
  assert.ok(facts.testFileCount > 500);
  assert.ok(facts.cliCommands.includes('scan') && facts.cliCommands.includes('context'));
  assert.equal(facts.mcpToolCount, Object.values(facts.mcpTools).flat().length);
  assert.ok(facts.mcpTools['tools.js'].includes('verify_fix'));
  assert.ok(facts.benchDirs.includes('independent') && facts.benchDirs.includes('cve-replay'));
});

test('the committed capability map is consistent with the checkout', () => {
  assert.deepEqual(problems(REPO), []);
  const doc = loadCapabilities(REPO);
  assert.ok(doc.capabilities.length >= 30);
  for (const c of doc.capabilities) {
    assert.ok(c.source.length >= 1, `${c.id} has source`);
    assert.ok(c.tests.length >= 1, `${c.id} maps at least one executable test`);
  }
  assert.ok(doc.absent.length >= 5);
});

test('the committed INVENTORY.md and inventory.json agree with the checkout and with the recorded test runs', () => {
  const dir = path.join(REPO, 'docs', 'engineering-excellence');
  const md = fs.readFileSync(path.join(dir, 'INVENTORY.md'), 'utf8');
  const committed = JSON.parse(fs.readFileSync(path.join(dir, 'inventory.json'), 'utf8'));
  const pkg = JSON.parse(fs.readFileSync(path.join(REPO, 'scanner', 'package.json'), 'utf8'));
  assert.equal(committed.facts.version, pkg.version, 'the inventory names the version at HEAD');
  assert.match(md, new RegExp(`\\*\\*${pkg.version.replace(/\./g, '\\.')}\\*\\*`));
  const verification = loadVerification(REPO);
  const doc = loadCapabilities(REPO);
  assert.deepEqual(committed.capabilities.map((c) => c.id), doc.capabilities.map((c) => c.id));
  for (const c of committed.capabilities) {
    assert.ok(MATURITY.includes(c.maturity), `${c.id}: ${c.maturity}`);
    const recomputed = classify(REPO, doc.capabilities.find((x) => x.id === c.id), verification, pkg.version);
    assert.equal(c.maturity, recomputed.maturity, `${c.id}: label does not follow from the recorded run`);
    if (c.maturity === 'VERIFIED' || c.maturity === 'PARTIAL') {
      assert.ok(verification.results[c.id]?.counts?.pass > 0, `${c.id} is ${c.maturity} without a passing recorded run`);
      assert.equal(verification.results[c.id].exitCode, 0);
    }
    assert.ok(md.includes(`\`${c.id}\``), `${c.id} appears in INVENTORY.md`);
  }
  const counts = Object.fromEntries(MATURITY.map((m) => [m, committed.capabilities.filter((c) => c.maturity === m).length]));
  assert.deepEqual(committed.maturityCounts, counts);
  void buildInventory;
});
