// E0-04: the durable task manifest and status initialisation.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { makeRoot, cleanup, EE, REPO } from './helpers.js';
import { EPICS, assertAcyclic, buildManifest, parseTasks } from '../../../scripts/engineering-excellence/lib/prd-tasks.mjs';
import { validateStatus } from '../../../scripts/engineering-excellence/lib/model.mjs';
import { StatusCorruptError, initStatus, readStatus, restoreBackup, startTask, loadManifest } from '../../../scripts/engineering-excellence/lib/store.mjs';

const PRD = ['AGENTIC_SECURITY_ENGINEERING_EXCELLENCE_MASTER.prd', 'docs/prds/AGENTIC_SECURITY_ENGINEERING_EXCELLENCE_MASTER.prd'].map((p) => path.join(REPO, p)).find((p) => fs.existsSync(p));

test('the committed manifest defines every PRD task exactly once, with acceptance text and an acyclic dependency graph', () => {
  const m = JSON.parse(fs.readFileSync(path.join(EE, 'tasks.json'), 'utf8'));
  assert.equal(m.schemaVersion, 1);
  assert.equal(m.tasks.length, 67);
  const perEpic = Object.fromEntries(EPICS.map((e) => [e.id, m.tasks.filter((t) => t.epic === e.id).length]));
  assert.deepEqual(perEpic, { E0: 6, E1: 8, E2: 9, E3: 8, E4: 7, E5: 7, E6: 8, E7: 8, E8: 6 });
  assert.equal(new Set(m.tasks.map((t) => t.id)).size, 67);
  for (const t of m.tasks) {
    assert.match(t.id, /^E[0-8]-\d\d$/);
    assert.ok(t.acceptance.length > 10, `${t.id} has acceptance text`);
    assert.ok([1, 2, 3].includes(t.weight));
    for (const r of t.requires) assert.ok(m.tasks.some((x) => x.id === r), `${t.id} requires unknown ${r}`);
  }
  assertAcyclic(m.tasks);
});

test('the E0 exit gate holds: every non-E0 task requires the inventory, the baseline and the status observer', () => {
  const m = JSON.parse(fs.readFileSync(path.join(EE, 'tasks.json'), 'utf8'));
  for (const t of m.tasks.filter((x) => x.epic !== 'E0')) {
    const closure = new Set();
    const walk = (id) => { for (const r of m.tasks.find((x) => x.id === id).requires) if (!closure.has(r)) { closure.add(r); walk(r); } };
    walk(t.id);
    for (const g of ['E0-01', 'E0-02', 'E0-05']) assert.ok(closure.has(g), `${t.id} does not (transitively) require ${g}`);
  }
});

test('the manifest is what the PRD says: regenerating it from the PRD gives the same tasks', { skip: PRD ? false : 'the PRD is an untracked working document and is not in this checkout' }, () => {
  const text = fs.readFileSync(PRD, 'utf8');
  const regenerated = buildManifest(text);
  const committed = JSON.parse(fs.readFileSync(path.join(EE, 'tasks.json'), 'utf8'));
  assert.deepEqual(regenerated.tasks, committed.tasks);
});

test('the PRD parser refuses a duplicate task id and a task without an Accept clause', () => {
  const dup = '**E0-01 — A.** do. **Accept:** x.\n**E0-01 — B.** do. **Accept:** y.\n';
  assert.throws(() => parseTasks(dup), /twice/);
  assert.throws(() => parseTasks('**E0-01 — A.** no acceptance here\n'), /no Accept/);
});

test('a dependency cycle is rejected', () => {
  assert.throws(() => assertAcyclic([{ id: 'E0-01', requires: ['E0-02'] }, { id: 'E0-02', requires: ['E0-01'] }]), /cycle/);
});

test('initialisation is idempotent and never resets recorded state', async () => {
  const { root, store } = await makeRoot();
  try {
    startTask(root, 'E0-01');
    const before = readStatus(root);
    const again = initStatus(root);
    assert.equal(again.created, false);
    assert.equal(again.added, 0);
    const after = readStatus(root);
    assert.deepEqual(after.tasks, before.tasks);
    assert.equal(after.tasks['E0-01'].state, 'in_progress');
    assert.equal(after.tasks['E0-01'].attempts, 1);
    void store;
  } finally { cleanup(root); }
});

test('a task added to the manifest later appears as pending without touching the others', async () => {
  const { root } = await makeRoot();
  try {
    startTask(root, 'E0-01');
    const mp = path.join(root, 'scripts', 'engineering-excellence', 'tasks.json');
    const m = JSON.parse(fs.readFileSync(mp, 'utf8'));
    m.tasks.push({ ...m.tasks[0], id: 'E1-02', epic: 'E1', requires: [] });
    fs.writeFileSync(mp, JSON.stringify(m));
    const r = initStatus(root);
    assert.equal(r.added, 1);
    assert.equal(r.doc.tasks['E1-02'].state, 'pending');
    assert.equal(r.doc.tasks['E0-01'].state, 'in_progress');
  } finally { cleanup(root); }
});

test('a task in status.json that the manifest no longer defines is an error, not a silent drop of its evidence', async () => {
  const { root } = await makeRoot();
  try {
    const mp = path.join(root, 'scripts', 'engineering-excellence', 'tasks.json');
    const m = JSON.parse(fs.readFileSync(mp, 'utf8'));
    m.tasks = m.tasks.filter((t) => t.id !== 'E1-01');
    fs.writeFileSync(mp, JSON.stringify(m));
    assert.throws(() => initStatus(root), (e) => e instanceof StatusCorruptError && /E1-01/.test(e.message));
    assert.ok(readStatus(root).tasks['E1-01'], 'the record is still there');
  } finally { cleanup(root); }
});

test('malformed JSON and schema violations fail explicitly and leave the file untouched; the backup restores it', async () => {
  const { root } = await makeRoot();
  try {
    startTask(root, 'E0-01');
    const p = path.join(root, 'scripts', 'engineering-excellence', 'status.json');
    const good = fs.readFileSync(p, 'utf8');
    fs.writeFileSync(p, '{"schemaVersion":1,');
    assert.throws(() => readStatus(root), (e) => e instanceof StatusCorruptError && /not valid JSON/.test(e.message));
    assert.throws(() => initStatus(root), StatusCorruptError);
    assert.throws(() => startTask(root, 'E0-02'), StatusCorruptError);
    assert.equal(fs.readFileSync(p, 'utf8'), '{"schemaVersion":1,', 'not modified');
    const revisionBefore = JSON.parse(good).revision;
    restoreBackup(root);
    // the backup is the revision BEFORE the last successful write, so a restore loses at most that one update
    assert.equal(readStatus(root).revision, revisionBefore - 1);
    assert.equal(readStatus(root).tasks['E0-01'].state, 'pending');
    const doc = JSON.parse(fs.readFileSync(p, 'utf8'));
    doc.tasks['E0-01'].state = 'finished';
    fs.writeFileSync(p, JSON.stringify(doc));
    assert.throws(() => readStatus(root), (e) => e instanceof StatusCorruptError && e.problems.length > 0);
  } finally { cleanup(root); }
});

test('the schema rejects an unknown state, a missing field and an unexpected property', async () => {
  const { root } = await makeRoot();
  try {
    const doc = readStatus(root);
    assert.deepEqual(validateStatus(doc), []);
    const bad = structuredClone(doc);
    bad.tasks['E0-01'].state = 'complete';
    assert.ok(validateStatus(bad).some((e) => /state/.test(e)));
    const bad2 = structuredClone(doc); delete bad2.tasks['E0-01'].attempts;
    assert.ok(validateStatus(bad2).some((e) => /attempts/.test(e)));
    const bad3 = structuredClone(doc); bad3.extra = 1;
    assert.ok(validateStatus(bad3).some((e) => /extra/.test(e)));
  } finally { cleanup(root); }
});

test('the real repository status file is valid and its task ids equal the manifest', () => {
  const m = loadManifest(REPO);
  const doc = readStatus(REPO);
  assert.deepEqual(Object.keys(doc.tasks).sort(), m.tasks.map((t) => t.id).sort());
});
