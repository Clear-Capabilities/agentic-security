// Dataset manifest validation, workspace materialization and the leakage gate (PRD 6 requirements 1, 3, 4 and benchmark integrity).
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { mkTestTmp } from '../helpers/tmp.js';
import { validateDatasetManifest, loadDatasetFile, datasetHash, resolveInside, normalizeCwe, HARD_NEGATIVE_CATEGORIES } from '../../src/posture/evaluation/lab/dataset.js';
import { stageNeutralized, stripComments, globToRegExp } from '../../src/posture/evaluation/lab/neutralize.js';
import { materializeEntry } from '../../src/posture/evaluation/lab/materialize.js';
import { prepareWorkspaces } from '../../src/posture/evaluation/lab/run.js';

const FX = path.join(path.dirname(fileURLToPath(import.meta.url)), '../fixtures/eval-lab');
const good = () => structuredClone(JSON.parse(fs.readFileSync(path.join(FX, 'detect/dataset.json'), 'utf8')));

test('the shipped fixture datasets are valid, and a manifest hash ignores key order but not content', () => {
  for (const d of ['detect', 'proof']) { const r = loadDatasetFile(path.join(FX, d, 'dataset.json')); assert.equal(r.ok, true, JSON.stringify(r.errors)); assert.match(r.hash, /^sha256:|^[0-9a-f]{16,}/); }
  const m = good();
  const reordered = { entries: m.entries, dataset: Object.fromEntries(Object.entries(m.dataset).reverse()) };
  assert.equal(datasetHash(m), datasetHash(reordered));
  const changed = good(); changed.entries[0].expectedSpan.startLine = 9;
  assert.notEqual(datasetHash(m), datasetHash(changed));
});

test('manifest: every way a dataset could make a score meaningless is refused', () => {
  const bad = (mutate, re) => { const m = good(); mutate(m); const v = validateDatasetManifest(m); assert.equal(v.ok, false, `expected a refusal matching ${re}`); assert.match(v.errors.join('|'), re); };
  bad((m) => { m.dataset.leakagePolicy.mode = 'off'; }, /must be "enforce"/);
  bad((m) => { delete m.dataset.leakagePolicy; }, /leakagePolicy is required/);
  bad((m) => { m.dataset.license = ''; }, /license is required/);
  bad((m) => { m.dataset.source.kind = 'git-pairs'; m.dataset.license = 'Proprietary'; }, /license that permits use/);
  bad((m) => { m.dataset.cwe = ['89']; }, /CWE ids/);
  bad((m) => { m.dataset.split = 'test'; }, /split must be/);
  bad((m) => { delete m.entries[0].expectedSpan; }, /expectedSpan/);
  bad((m) => { m.entries[0].expectedSpan.endLine = 1; }, /endLine/);
  bad((m) => { m.entries[0].expectedSpan.file = '../../etc/passwd'; }, /relative path inside the workspace/);
  bad((m) => { m.entries[5].category = 'vibes'; }, /category must be one of/);
  bad((m) => { delete m.entries[5].lookalikeSpan; }, /lookalikeSpan/);
  bad((m) => { m.entries[5].expectedSpan = { file: 'a', startLine: 1, endLine: 1 }; }, /not vulnerable/);
  bad((m) => { m.entries[1].id = m.entries[0].id; }, /duplicated/);
  bad((m) => { m.entries[0].workspace = { dir: '../outside' }; }, /inside the manifest folder/);
  bad((m) => { m.entries[0].workspace = { git: { repo: '.', rev: 'main' } }; }, /commit id/);
  bad((m) => { m.entries = m.entries.filter((e) => e.kind === 'vulnerable'); }, /negative entry/);
  bad((m) => { m.entries = m.entries.filter((e) => e.kind !== 'vulnerable'); }, /vulnerable entry/);
  bad((m) => { m.entries[0].reproducer = '/etc/passwd'; }, /reproducer must be a relative path/);
  assert.equal(validateDatasetManifest(null).ok, false);
  assert.equal(validateDatasetManifest({}).ok, false);
  assert.ok(HARD_NEGATIVE_CATEGORIES.includes('correct-crypto'));
  assert.equal(normalizeCwe('cwe-079'), 'CWE-79');
});

test('loadDatasetFile: unreadable, oversized and malformed manifests fail with a reason, never a stack trace', () => {
  const dir = mkTestTmp('lab-ds-');
  assert.equal(loadDatasetFile(path.join(dir, 'missing.json')).ok, false);
  fs.writeFileSync(path.join(dir, 'broken.json'), '{ nope');
  assert.match(loadDatasetFile(path.join(dir, 'broken.json')).errors[0], /cannot parse/);
  fs.writeFileSync(path.join(dir, 'huge.json'), ' '.repeat(6 * 1024 * 1024));
  assert.equal(loadDatasetFile(path.join(dir, 'huge.json')).ok, false);
  fs.writeFileSync(path.join(dir, 'm.yaml'), `dataset:\n  id: x\n`);
  assert.equal(loadDatasetFile(path.join(dir, 'm.yaml')).ok, false);
});

test('resolveInside: a path that leaves the manifest folder, by name or by symlink, is refused', () => {
  const dir = mkTestTmp('lab-in-'); fs.mkdirSync(path.join(dir, 'ok'));
  const out = mkTestTmp('lab-out-');
  fs.symlinkSync(out, path.join(dir, 'link'));
  assert.ok(resolveInside(dir, 'ok'));
  assert.equal(resolveInside(dir, 'link'), null);
  assert.equal(resolveInside(dir, 'missing'), null);
});

test('stripComments keeps every line number, protects strings, and leaves unknown file types alone', () => {
  const js = "const u = 'http://x.test/a'; // note\n/* multi\nline */ const t = `// not a comment`;\nconst re = \"/*\"; // tail\n";
  const out = stripComments(js, '.js');
  assert.equal(out.split('\n').length, js.split('\n').length);
  assert.match(out, /http:\/\/x\.test\/a/); assert.match(out, /`\/\/ not a comment`/); assert.match(out, /"\/\*"/);
  assert.doesNotMatch(out, /note|multi|tail/);
  assert.equal(stripComments('x = 1  # c\ny = "#keep"\n', '.py'), 'x = 1  \ny = "#keep"\n');
  assert.equal(stripComments('// kept', '.md'), '// kept');
  assert.equal(stripComments("let c = 'a'; // x\nlet life<'a> = 1;\n", '.rs').split('\n').length, 3);
});

test('neutralization: comments stripped, spans still point at the same code, and the audit runs', () => {
  const dir = mkTestTmp('lab-neu-');
  const src = path.join(dir, 'src'); fs.mkdirSync(src);
  fs.writeFileSync(path.join(src, 'a.js'), '// FLAW: this is the vulnerable line\nconst x = 1;\nexec(userInput);\n');
  const r = stageNeutralized({ srcDir: src, destDir: path.join(dir, 'dest'), policy: { stripComments: true }, terms: [] });
  assert.equal(r.ok, true, JSON.stringify(r.leaks));
  const text = fs.readFileSync(path.join(r.destDir, 'a.js'), 'utf8').split('\n');
  assert.equal(text[2], 'exec(userInput);', 'line 3 is still line 3');
  assert.doesNotMatch(text.join('\n'), /FLAW|vulnerable/);
});

test('leakage gate: each kind of answer-key signal quarantines the workspace instead of being scanned', () => {
  const cases = {
    'an answer-key file': { files: { 'expected.json': '{}', 'a.js': 'x' }, policy: { stripComments: true }, kind: 'answer-key-file' },
    'a descriptive comment kept in': { files: { 'a.js': '// this is a vulnerability\nx()\n' }, policy: { stripComments: false }, kind: 'descriptive-comment' },
    'a weakness id in the content': { files: { 'a.js': 'const tag = "CWE-89";\n' }, policy: { stripComments: true }, kind: 'weakness-id-in-content' },
    'a weakness-bearing file name': { files: { 'CWE89_Injection__case_01.java': 'class A {}' }, policy: { stripComments: true }, kind: 'weakness-in-file-name' },
    'an advisory id': { files: { 'a.js': 'x = 1; // fixed per CVE-2021-44228\n' }, policy: { stripComments: false }, kind: 'advisory-id' },
    'a protected term': { files: { 'a.js': 'const note = "secret benchmark marker zzz";\n' }, policy: { stripComments: true }, terms: ['secret benchmark marker zzz'], kind: 'protected-term' },
  };
  for (const [name, c] of Object.entries(cases)) {
    const dir = mkTestTmp('lab-leak-'); const src = path.join(dir, 's'); fs.mkdirSync(src);
    for (const [f, t] of Object.entries(c.files)) fs.writeFileSync(path.join(src, f), t);
    const r = stageNeutralized({ srcDir: src, destDir: path.join(dir, 'd'), policy: c.policy, terms: c.terms ?? [] });
    assert.equal(r.ok, false, name); assert.equal(r.quarantined, true, name);
    assert.ok(r.leaks.some((l) => l.kind === c.kind), `${name}: expected ${c.kind}, got ${r.leaks.map((l) => l.kind)}`);
    assert.equal(fs.existsSync(path.join(dir, 'd')), false, `${name}: a quarantined workspace must not remain on disk`);
  }
});

test('leakage gate: renaming weakness-bearing files follows the class name through the sources, and the map records the change', () => {
  const dir = mkTestTmp('lab-ren-'); const src = path.join(dir, 's'); fs.mkdirSync(src);
  fs.writeFileSync(path.join(src, 'CWE89_Test.java'), 'public class CWE89_Test { }\n');
  fs.writeFileSync(path.join(src, 'Main.java'), 'class Main { CWE89_Test t; }\n');
  const kept = stageNeutralized({ srcDir: src, destDir: path.join(dir, 'd0'), policy: { stripComments: true }, terms: [] });
  assert.equal(kept.ok, false, 'without the rename policy a weakness-bearing file name is a leak');
  const r = stageNeutralized({ srcDir: src, destDir: path.join(dir, 'd'), policy: { stripComments: true, renameFiles: true }, terms: [] });
  assert.equal(r.ok, true, JSON.stringify(r.leaks));
  assert.equal(r.fileMap['CWE89_Test.java'], 'case0001.java');
  assert.match(fs.readFileSync(path.join(r.destDir, 'Main.java'), 'utf8'), /case0001 t;/);
  assert.match(fs.readFileSync(path.join(r.destDir, 'case0001.java'), 'utf8'), /class case0001/);
});

test('removePaths drops change logs and docs before the audit judges them', () => {
  assert.equal(globToRegExp('docs/**').test('docs/a/b.md'), true);
  assert.equal(globToRegExp('CHANGELOG*').test('CHANGELOG.md'), true);
  assert.equal(globToRegExp('**/*.md').test('a/b.md'), true);
  const dir = mkTestTmp('lab-rm-'); const src = path.join(dir, 's'); fs.mkdirSync(src);
  fs.writeFileSync(path.join(src, 'CHANGELOG.md'), 'fixed CVE-2020-12345');
  fs.writeFileSync(path.join(src, 'a.js'), 'x();\n');
  assert.equal(stageNeutralized({ srcDir: src, destDir: path.join(dir, 'd1'), policy: { stripComments: true }, terms: [] }).ok, false);
  assert.equal(stageNeutralized({ srcDir: src, destDir: path.join(dir, 'd2'), policy: { stripComments: true, removePaths: ['CHANGELOG*'] }, terms: [] }).ok, true);
});

test('symlinks in a workspace are quarantined, never followed', () => {
  const dir = mkTestTmp('lab-sym-'); const src = path.join(dir, 's'); fs.mkdirSync(src);
  fs.writeFileSync(path.join(src, 'a.js'), 'x();\n'); fs.symlinkSync('/etc/hosts', path.join(src, 'link.js'));
  const r = stageNeutralized({ srcDir: src, destDir: path.join(dir, 'd'), policy: { stripComments: true }, terms: [] });
  assert.equal(r.ok, false); assert.ok(r.leaks.some((l) => l.kind === 'symlink'));
});

function gitRepo() {
  const dir = mkTestTmp('lab-git-');
  const git = (args) => { const r = spawnSync('git', args, { cwd: dir, encoding: 'utf8', env: { ...process.env, GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@t', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@t' } }); assert.equal(r.status, 0, r.stderr); return r.stdout.trim(); };
  git(['init', '-q', '-b', 'main']);
  fs.writeFileSync(path.join(dir, 'app.js'), "exec('ls ' + req.body.x);\n"); git(['add', '.']); git(['commit', '-q', '-m', 'vulnerable']);
  const vuln = git(['rev-parse', 'HEAD']);
  fs.writeFileSync(path.join(dir, 'app.js'), "execFile('ls', [req.body.x]);\n"); git(['commit', '-qam', 'fix']);
  return { dir, vuln, fix: git(['rev-parse', 'HEAD']) };
}

test('vulnerable commit -> fixing commit: both revisions materialize from a local repository, and a bad revision is a typed failure', () => {
  const { dir, vuln, fix } = gitRepo();
  const out = mkTestTmp('lab-mat-');
  const a = materializeEntry({ workspace: { git: { repo: dir, rev: vuln } } }, { baseDir: out, destDir: path.join(out, 'v') });
  const b = materializeEntry({ workspace: { git: { repo: dir, rev: fix } } }, { baseDir: out, destDir: path.join(out, 'f') });
  assert.equal(a.ok, true); assert.equal(b.ok, true);
  assert.match(fs.readFileSync(path.join(out, 'v', 'app.js'), 'utf8'), /exec\('ls ' \+/);
  assert.match(fs.readFileSync(path.join(out, 'f', 'app.js'), 'utf8'), /execFile/);
  const bad = materializeEntry({ workspace: { git: { repo: dir, rev: 'deadbeefdeadbeef' } } }, { baseDir: out, destDir: path.join(out, 'x') });
  assert.equal(bad.ok, false); assert.match(bad.reason, /git archive failed/);
  assert.equal(materializeEntry({ workspace: { git: { repo: path.join(out, 'nope'), rev: vuln } } }, { baseDir: out, destDir: path.join(out, 'y') }).ok, false);
  assert.equal(materializeEntry({ workspace: { dir: '../../etc' } }, { baseDir: out, destDir: path.join(out, 'z') }).ok, false);
});

test('prepareWorkspaces: a clean dataset audits clean; one tainted entry is excluded and named, the rest still run', () => {
  const dir = mkTestTmp('lab-prep-');
  fs.cpSync(path.join(FX, 'detect'), dir, { recursive: true });
  const ds = loadDatasetFile(path.join(dir, 'dataset.json'));
  const root = mkTestTmp('lab-work-');
  const clean = prepareWorkspaces({ manifest: ds.manifest, baseDir: dir, workRoot: root });
  assert.equal(clean.audit.status, 'clean'); assert.equal(clean.audit.usable, 6); assert.equal(clean.prepared.size, 6);
  fs.writeFileSync(path.join(dir, 'cases', 'sqli-vuln', 'answers.json'), '{}');
  const root2 = mkTestTmp('lab-work2-');
  const dirty = prepareWorkspaces({ manifest: ds.manifest, baseDir: dir, workRoot: root2 });
  assert.equal(dirty.audit.status, 'entries-excluded'); assert.equal(dirty.audit.usable, 5);
  assert.deepEqual(dirty.audit.quarantined.map((q) => q.entryId), ['sqli-1']);
  assert.equal(dirty.prepared.has('sqli-1'), false);
  // workspaces an arm sees carry neither the entry id nor its kind in their path
  for (const w of clean.prepared.values()) assert.doesNotMatch(w.dir, /cmdi|sqli|vuln|fixed|hn-|hard/i);
});
