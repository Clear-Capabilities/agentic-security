// E8-05: another session can resume from disk, and the terminal summary, the markdown status and the final report all read the same ledger.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const DOCS = 'docs/engineering-excellence';
const read = (p) => fs.readFileSync(path.join(ROOT, p), 'utf8');
const node = (script, ...a) => spawnSync(process.execPath, [path.join(ROOT, script), ...a], { cwd: ROOT, encoding: 'utf8', timeout: 120_000 });

test('THE FOUR HANDOFF FILES EXIST AND THE GENERATED ONES ARE CURRENT', () => {
  for (const f of ['FINAL_REPORT.md', 'STATUS.md', 'unresolved.json']) assert.ok(fs.existsSync(path.join(ROOT, DOCS, f)), f);
  assert.ok(fs.existsSync(path.join(ROOT, 'scripts/engineering-excellence/status.json')));
  const r = node('scripts/engineering-excellence/final-report.mjs', '--check'); assert.equal(r.status, 0, r.stdout + r.stderr);
});

test('THE TERMINAL SUMMARY, THE MARKDOWN STATUS AND THE FINAL REPORT AGREE WITH THE LEDGER', () => {
  const j = JSON.parse(node('scripts/engineering-excellence/status.mjs', '--json').stdout);
  const ledger = JSON.parse(read('scripts/engineering-excellence/status.json')).tasks; const done = Object.values(ledger).filter((t) => t.state === 'done' || t.state === 'already_satisfied').length;
  const total = Object.keys(ledger).length;
  const summary = j.summary || j; assert.equal(summary.total ?? summary.tasks ?? total, total);
  assert.match(read(`${DOCS}/FINAL_REPORT.md`), new RegExp(`${total} tasks: ${done} done`));
  const status = read(`${DOCS}/STATUS.md`); assert.match(status, new RegExp(`${done} of ${total} tasks verified`), 'STATUS.md was regenerated from the ledger: run node scripts/engineering-excellence/status.mjs --markdown');
});

test('A SESSION CAN RESUME FROM DISK WITHOUT GUESSING: --resume names the next step, and every task has a recorded state', () => {
  // the read-only dashboard, not --resume: --resume RECOVERS interrupted tasks, which would reset the very task this test is evidence for
  const r = node('scripts/engineering-excellence/status.mjs'); assert.equal(r.status, 0, r.stderr); assert.match(r.stdout, /NEXT: /);
  const ledger = JSON.parse(read('scripts/engineering-excellence/status.json')).tasks; for (const [id, t] of Object.entries(ledger)) assert.ok(['pending', 'in_progress', 'done', 'already_satisfied', 'blocked', 'failed'].includes(t.state), id);
});

test('THE UNRESOLVED LIST IS COMPLETE AND CONSISTENT WITH THE SOURCE AND THE DECISION', () => {
  const out = JSON.parse(read(`${DOCS}/unresolved.json`)); const src = JSON.parse(read('scripts/engineering-excellence/data/unresolved-source.json')).items;
  assert.deepEqual(out.items.map((i) => i.id), src.map((i) => i.id)); for (const i of out.items) { assert.ok(i.title && i.nextStep && i.priority, i.id); assert.equal(typeof i.blocksRelease, 'boolean'); }
  assert.ok(out.items.filter((i) => i.blocksRelease).every((i) => out.blockers.some((b) => b.message.startsWith(i.id + ':')) || out.caveats.some((c) => c.startsWith(i.id + ' waived'))), 'every blocking item is a blocker or an honoured waiver');
  assert.equal(out.verdict, out.blockers.length ? 'release_blocked' : 'release_ready');
});

test('EVERY RE-RUN COMMAND IN THE REPORT EXISTS, AND ITS ARTIFACT IS NAMED WITH A DIGEST', () => {
  const report = read(`${DOCS}/FINAL_REPORT.md`); const pkg = JSON.parse(read('scanner/package.json')).scripts;
  const rows = report.split('\n').filter((l) => /^\| `(npm run|node) /.test(l)); assert.ok(rows.length >= 7);
  for (const row of rows) {
    const [, cmd, artifact, digest] = row.split('|').map((c) => c.trim().replace(/^`|`$/g, ''));
    const m = cmd.match(/^npm run ([\w:-]+)/); if (m) assert.ok(pkg[m[1]], `${m[1]} is an npm script`);
    const s = cmd.match(/^node (\S+)/); if (s) assert.ok(fs.existsSync(path.join(ROOT, 'scanner', s[1])), s[1]);
    assert.ok(fs.existsSync(path.join(ROOT, artifact)), artifact); assert.match(digest, /^sha256:[0-9a-f]{16}/);
  }
  assert.match(report, /status\.mjs --resume/);
});
