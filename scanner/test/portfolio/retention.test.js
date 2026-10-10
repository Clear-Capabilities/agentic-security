// X-708.AC01: evidence retention by class, legal holds, logged deletions, required current receipts. SYNTHETIC records and files only.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { mkTestTmp } from '../helpers/tmp.js';
import {
  RETENTION_CLASSES, RETENTION_DEFAULTS, RETENTION_LOG_SCHEMA, resolveRetentionPolicy, normalizeHolds, planRetention, applyRetention, verifyRetentionLog, classOfBundleRole,
} from '../../src/posture/portfolio/retention.js';
import { ROLES } from '../../src/posture/portfolio/bundle.js';
import { newStore, leaseUnit, startUnit, completeUnit, cancelUnits } from '../../src/posture/portfolio/work-units.js';
import { applyResume } from '../../src/posture/portfolio/resume.js';
import { runPortfolioCommand } from '../../src/posture/portfolio/cli.js';
import { manyUnitsPlan, DEPS, sha } from './helpers.js';

const DAY = 86_400_000;
const NOW = Date.UTC(2026, 9, 9);
const ago = (days) => NOW - days * DAY;
const ON = { AGENTIC_SECURITY_ASSURANCE_PORTFOLIO_ASSURANCE: '1' };

// a root with one real file per record; returns the record list
function world(specs) {
  const root = mkTestTmp('ret-');
  const records = specs.map((s, i) => {
    const rel = s.path ?? `${s.class ?? 'x'}-${i}.dat`;
    fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
    fs.writeFileSync(path.join(root, rel), `synthetic content ${i} ${s.id}`);
    const { path: _p, ...rest } = s;
    return { createdAt: ago(s.ageDays ?? 0), ...rest, path: rel };
  });
  return { root, records, log: path.join(root, 'deletions.jsonl') };
}
const dec = (plan, id) => plan.decisions.find((d) => d.id === id);
const exists = (root, rel) => fs.existsSync(path.join(root, rel));

describe('[X-708.AC01] retention distinguishes replay evidence, metadata, model traces and secrets', () => {
  test('[X-708.AC01] the four classes have different defaults, and a record 40 days old is treated differently in each', () => {
    assert.deepEqual([...RETENTION_CLASSES], ['replay-evidence', 'metadata', 'model-trace', 'secret']);
    const days = RETENTION_CLASSES.map((c) => RETENTION_DEFAULTS[c].defaultDays);
    assert.equal(new Set(days).size, 4, 'no two classes share a default');
    const recs = RETENTION_CLASSES.map((c) => ({ id: `r-${c}`, class: c, path: `${c}.dat`, createdAt: ago(40) }));
    const plan = planRetention({ records: recs, now: NOW });
    assert.equal(plan.ok, true);
    assert.equal(dec(plan, 'r-replay-evidence').action, 'keep');
    assert.equal(dec(plan, 'r-metadata').action, 'keep');
    assert.equal(dec(plan, 'r-model-trace').action, 'delete', 'model traces age out first (30 days)');
    assert.equal(dec(plan, 'r-secret').action, 'delete');
    assert.equal(dec(plan, 'r-secret').reason, 'secret-expired');
    assert.equal(dec(plan, 'r-metadata').reason, 'within-retention');
  });

  test('[X-708.AC01] a secret does not outlive the first sweep by default, and a configured value cannot exceed the 7 day ceiling', () => {
    const fresh = planRetention({ records: [{ id: 's', class: 'secret', path: 's.dat', createdAt: NOW - 1000 }], now: NOW });
    assert.equal(dec(fresh, 's').action, 'delete', 'a secret one second old is already past a 0 day retention');
    const clamped = resolveRetentionPolicy({ version: 'v', classes: { secret: { retainDays: 365 }, 'model-trace': { retainDays: 10 } } });
    assert.equal(clamped.effective.secret.days, 7);
    assert.equal(clamped.effective.secret.clamped, true, 'the clamp is disclosed, not silent');
    assert.equal(clamped.effective['model-trace'].days, 10);
    assert.equal(clamped.effective['model-trace'].source, 'policy');
    assert.equal(clamped.effective.metadata.source, 'default');
    const p = planRetention({ records: [{ id: 's', class: 'secret', path: 's.dat', createdAt: ago(6) }], policy: { version: 'v', classes: { secret: { retainDays: 365 } } }, now: NOW });
    assert.equal(dec(p, 's').action, 'keep', 'inside the clamped 7 days');
    assert.equal(dec(planRetention({ records: [{ id: 's', class: 'secret', path: 's.dat', createdAt: ago(8) }], policy: { version: 'v', classes: { secret: { retainDays: 365 } } }, now: NOW }), 's').action, 'delete');
    assert.equal(p.effective.secret.clamped, true);
  });

  test('[X-708.AC01] an operator policy shortens retention for one class and leaves the others at their defaults', () => {
    const recs = [{ id: 'a', class: 'replay-evidence', path: 'a', createdAt: ago(100) }, { id: 'b', class: 'metadata', path: 'b', createdAt: ago(100) }];
    const plan = planRetention({ records: recs, policy: { version: 'org-2026', classes: { 'replay-evidence': { retainDays: 90 } } }, now: NOW });
    assert.equal(plan.policyVersion, 'org-2026');
    assert.equal(dec(plan, 'a').action, 'delete');
    assert.equal(dec(plan, 'b').action, 'keep');
  });

  test('[X-708.AC01] negative: an unknown class, a negative or non-numeric retention, a bad version and a bad clock are rejected, not defaulted', () => {
    assert.equal(resolveRetentionPolicy({ classes: { logs: { retainDays: 1 } } }).errors[0].code, 'UNKNOWN_CLASS');
    assert.equal(resolveRetentionPolicy({ classes: { metadata: { retainDays: -1 } } }).errors[0].code, 'BAD_DAYS');
    assert.equal(resolveRetentionPolicy({ classes: { metadata: { retainDays: 'forever' } } }).errors[0].code, 'BAD_DAYS');
    assert.equal(resolveRetentionPolicy({ version: '' }).ok, false);
    assert.equal(resolveRetentionPolicy([]).ok, false);
    assert.equal(resolveRetentionPolicy(undefined).ok, true);
    assert.equal(planRetention({ records: [], policy: { classes: { logs: {} } }, now: NOW }).ok, false);
    assert.equal(planRetention({ records: [] }).errors[0].code, 'NO_NOW');
  });

  test('[X-708.AC01] a record in an unknown class, or a malformed record, is KEPT and reported, never deleted', () => {
    const plan = planRetention({ records: [{ id: 'u', class: 'logs', path: 'u', createdAt: ago(9999) }, { id: 'm', class: 'metadata', createdAt: ago(9999) }, null, { id: 'n', class: 'metadata', path: 'n', createdAt: 'not a date' }], now: NOW });
    assert.deepEqual(plan.decisions.map((d) => [d.action, d.reason]), [['keep', 'unclassified'], ['keep', 'malformed-record'], ['keep', 'malformed-record'], ['keep', 'malformed-record']]);
    assert.equal(plan.summary.delete, 0);
  });

  test('[X-708.AC01] bundle roles map to a class; an unknown role has none', () => {
    for (const r of ROLES) assert.ok(RETENTION_CLASSES.includes(classOfBundleRole(r)), `${r} has a class`);
    assert.equal(classOfBundleRole('replay-manifest'), 'replay-evidence');
    assert.equal(classOfBundleRole('receipt'), 'replay-evidence');
    assert.equal(classOfBundleRole('findings'), 'metadata');
    assert.equal(classOfBundleRole('mystery'), null);
  });
});

describe('[X-708.AC01] retention honors declared legal holds', () => {
  const rec = (over = {}) => ({ id: 'r1', class: 'model-trace', path: 'r1', createdAt: ago(400), repository: 'shop', ...over });
  const hold = (target, over = {}) => ({ target, owner: 'legal@example.test', reason: 'matter 2026-114', ...over });

  test('[X-708.AC01] a hold on the record, its class or its repository keeps an expired record, naming the hold; without one it is deleted', () => {
    assert.equal(dec(planRetention({ records: [rec()], now: NOW }), 'r1').action, 'delete');
    for (const t of [{ id: 'r1' }, { class: 'model-trace' }, { repository: 'shop' }]) {
      const d = dec(planRetention({ records: [rec()], holds: [hold(t)], now: NOW }), 'r1');
      assert.equal(d.action, 'keep', JSON.stringify(t));
      assert.equal(d.reason, 'legal-hold');
      assert.equal(d.hold.owner, 'legal@example.test');
      assert.equal(d.hold.reason, 'matter 2026-114');
    }
  });

  test('[X-708.AC01] a hold protects only what it names', () => {
    const recs = [rec(), rec({ id: 'r2', repository: 'billing' }), rec({ id: 'r3', class: 'metadata', repository: 'billing' })];
    const plan = planRetention({ records: recs, holds: [hold({ repository: 'shop' })], now: NOW });
    assert.equal(dec(plan, 'r1').action, 'keep');
    assert.equal(dec(plan, 'r2').action, 'delete');
    assert.equal(dec(plan, 'r3').action, 'keep', 'metadata at 400 days is simply inside its own retention');
    assert.equal(plan.summary.heldByLegalHold, 1);
  });

  test('[X-708.AC01] an indefinite hold lasts; an expiring hold protects until its date and then the record is exposed to retention again', () => {
    const until = new Date(NOW + 5 * DAY).toISOString();
    assert.equal(dec(planRetention({ records: [rec()], holds: [hold({ id: 'r1' }, { expires_at: until })], now: NOW }), 'r1').action, 'keep');
    assert.equal(dec(planRetention({ records: [rec()], holds: [hold({ id: 'r1' }, { expires_at: until })], now: NOW + 6 * DAY }), 'r1').action, 'delete');
    assert.equal(dec(planRetention({ records: [rec()], holds: [hold({ id: 'r1' })], now: NOW + 9999 * DAY }), 'r1').action, 'keep');
  });

  test('[X-708.AC01] a hold is identity-bound and reasoned or it is rejected, and a malformed hold list never silently drops a hold', () => {
    for (const bad of [{ target: { id: 'r1' }, reason: 'x' }, { target: { id: 'r1' }, owner: 'o' }, { owner: 'o', reason: 'x' }, { target: {}, owner: 'o', reason: 'x' }, { target: { class: 'logs' }, owner: 'o', reason: 'x' }, { target: { id: 'r1' }, owner: 'o', reason: 'x', expires_at: 'someday' }]) {
      assert.equal(normalizeHolds([bad]).ok, false, JSON.stringify(bad));
      assert.equal(planRetention({ records: [rec()], holds: [bad], now: NOW }).ok, false, 'the plan is refused rather than run without that hold');
    }
    assert.equal(normalizeHolds([hold({ id: 'r1' })]).ok, true);
    assert.deepEqual(normalizeHolds(undefined).holds, []);
  });

  test('[X-708.AC01] a hold on a secret is honored and flagged, because a hold is a legal act', () => {
    const plan = planRetention({ records: [rec({ id: 's', class: 'secret' })], holds: [hold({ id: 's' })], now: NOW });
    assert.equal(dec(plan, 's').action, 'keep');
    assert.match(dec(plan, 's').warning, /secret is being retained under a legal hold/);
  });

  test('[X-708.AC01] applying a plan leaves held files on disk and deletes the rest', () => {
    const w = world([{ id: 'held', class: 'model-trace', ageDays: 400, repository: 'shop' }, { id: 'free', class: 'model-trace', ageDays: 400, repository: 'billing' }]);
    const r = applyRetention({ root: w.root, logFile: w.log, actor: 'ops', records: w.records, holds: [hold({ repository: 'shop' })], now: NOW });
    assert.deepEqual(r.deleted.map((d) => d.id), ['free']);
    assert.equal(exists(w.root, w.records[0].path), true);
    assert.equal(exists(w.root, w.records[1].path), false);
  });
});

describe('[X-708.AC01] retention never silently deletes a required current receipt', () => {
  const unitFixture = () => {
    const s = newStore(manyUnitsPlan({ a: 2 }));
    const [u1, u2] = Object.keys(s.units);
    const l = leaseUnit(s, { holder: 'w', now: NOW, ttlMs: 1000, unitId: u1 });
    startUnit(s, { unitId: u1, attemptId: l.attemptId, now: NOW });
    completeUnit(s, { unitId: u1, attemptId: l.attemptId, resultDigest: sha('r1'), dependencies: DEPS, now: NOW });
    return { s, u1, u2 };
  };

  test('[X-708.AC01] a receipt that a verified unit depends on is protected even when expired and unheld, and the block is reported loudly', () => {
    const { s, u1 } = unitFixture();
    const w = world([{ id: 'receipt-1', class: 'replay-evidence', ageDays: 2000, requiredBy: [u1] }, { id: 'old-trace', class: 'model-trace', ageDays: 2000 }]);
    const plan = planRetention({ records: w.records, store: s, now: NOW });
    const d = dec(plan, 'receipt-1');
    assert.equal(d.action, 'protect');
    assert.equal(d.reason, 'required-current-receipt');
    assert.equal(d.expiredButRequired, true);
    assert.match(d.detail, /deletion is blocked/);
    assert.equal(plan.summary.expiredButRequired, 1);
    const r = applyRetention({ root: w.root, logFile: w.log, actor: 'ops', records: w.records, store: s, now: NOW });
    assert.equal(exists(w.root, w.records[0].path), true, 'the required receipt is still there');
    assert.deepEqual(r.deleted.map((x) => x.id), ['old-trace']);
    assert.deepEqual(r.blocked.map((b) => b.id), ['receipt-1'], 'and the blocked deletion is reported, not skipped quietly');
  });

  test('[X-708.AC01] a receipt named in the current-receipt set is protected the same way', () => {
    const w = world([{ id: 'receipt-2', class: 'replay-evidence', ageDays: 5000 }]);
    const r = applyRetention({ root: w.root, logFile: w.log, actor: 'ops', records: w.records, currentReceiptIds: ['receipt-2'], now: NOW });
    assert.equal(exists(w.root, w.records[0].path), true);
    assert.equal(r.blocked.length, 1);
    const without = applyRetention({ root: w.root, logFile: w.log, actor: 'ops', records: w.records, currentReceiptIds: [], now: NOW });
    assert.equal(without.deleted.length, 1, 'not required, expired, unheld: deleted');
  });

  test('[X-708.AC01] required beats a hold in the record: the reason stays required-current-receipt, and a hold does not hide a block', () => {
    const { s, u1 } = unitFixture();
    const rec = { id: 'r', class: 'replay-evidence', path: 'r', createdAt: ago(5000), requiredBy: [u1] };
    const d = dec(planRetention({ records: [rec], store: s, holds: [{ target: { id: 'r' }, owner: 'o', reason: 'x' }], now: NOW }), 'r');
    assert.equal(d.action, 'protect');
    assert.equal(d.reason, 'required-current-receipt');
  });

  test('[X-708.AC01] once the unit is stale, cancelled or never verified, its receipt is no longer required and ages out normally', () => {
    const { s, u1, u2 } = unitFixture();
    const rec = (unit) => ({ id: `r-${unit}`, class: 'replay-evidence', path: 'p', createdAt: ago(5000), requiredBy: [unit] });
    assert.equal(dec(planRetention({ records: [rec(u2)], store: s, now: NOW }), `r-${u2}`).action, 'delete', 'never verified: nothing current depends on it');
    applyResume(s, { revalidate: [], invalidate: [{ unitId: u1, changed: ['code'], reason: 'code changed' }] }, NOW + 1);
    assert.equal(dec(planRetention({ records: [rec(u1)], store: s, now: NOW }), `r-${u1}`).action, 'delete', 'the unit went stale, so the receipt is superseded');
    const { s: s2, u1: v1 } = unitFixture();
    cancelUnits(s2, { reason: 'x', now: NOW });
    assert.equal(dec(planRetention({ records: [rec(v1)], store: s2, now: NOW }), `r-${v1}`).action, 'protect', 'cancelling does not touch a verified unit');
  });

  test('[X-708.AC01] a plan made earlier cannot delete a receipt that has become required since: apply re-plans against the live store', () => {
    const { s, u1 } = unitFixture();
    const w = world([{ id: 'late', class: 'replay-evidence', ageDays: 5000, requiredBy: [u1] }]);
    const stalePlan = planRetention({ records: w.records, store: newStore(manyUnitsPlan({ a: 2 })), now: NOW });
    assert.equal(dec(stalePlan, 'late').action, 'delete', 'against an empty store the record looks deletable');
    const r = applyRetention({ root: w.root, logFile: w.log, actor: 'ops', records: w.records, store: s, now: NOW });
    assert.equal(r.deleted.length, 0);
    assert.equal(exists(w.root, w.records[0].path), true);
  });
});

describe('[X-708.AC01] deletions are logged, logged first, and the log is tamper-evident', () => {
  test('[X-708.AC01] each deletion appends an intent and an outcome with the record, class, size, digest, reason, age, policy and actor, and never the content', () => {
    const w = world([{ id: 'gone', class: 'model-trace', ageDays: 60 }]);
    const content = fs.readFileSync(path.join(w.root, w.records[0].path), 'utf8');
    const r = applyRetention({ root: w.root, logFile: w.log, actor: 'ops@example.test', policy: { version: 'org-1' }, records: w.records, now: NOW });
    assert.equal(r.deleted.length, 1);
    const v = verifyRetentionLog(w.log);
    assert.equal(v.ok, true);
    assert.deepEqual(v.entries.map((e) => e.type), ['delete-intent', 'deleted']);
    assert.ok(v.entries.every((e) => e.schema === RETENTION_LOG_SCHEMA));
    const [intent, done] = v.entries;
    assert.equal(intent.recordId, 'gone');
    assert.equal(intent.class, 'model-trace');
    assert.equal(intent.bytes, Buffer.byteLength(content));
    assert.match(intent.contentDigest, /^sha256:[0-9a-f]{64}$/);
    assert.equal(intent.reason, 'expired');
    assert.equal(intent.ttlDays, 30);
    assert.equal(intent.policyVersion, 'org-1');
    assert.equal(intent.actor, 'ops@example.test');
    assert.equal(intent.at, new Date(NOW).toISOString(), 'the time comes from the supplied now, not a clock read');
    assert.equal(done.contentDigest, intent.contentDigest);
    assert.equal(fs.readFileSync(w.log, 'utf8').includes(content), false, 'the log holds no content');
    assert.equal(exists(w.root, w.records[0].path), false);
  });

  test('[X-708.AC01] the log is a hash chain: editing, removing or reordering an entry is detected', () => {
    const w = world([{ id: 'a', class: 'model-trace', ageDays: 60 }, { id: 'b', class: 'model-trace', ageDays: 60 }]);
    applyRetention({ root: w.root, logFile: w.log, actor: 'ops', records: w.records, now: NOW });
    const lines = fs.readFileSync(w.log, 'utf8').split('\n').filter(Boolean);
    assert.equal(lines.length, 4);
    const rewrite = (f) => { const p = path.join(w.root, `t${Math.random()}.jsonl`); fs.writeFileSync(p, `${f([...lines]).join('\n')}\n`); return verifyRetentionLog(p); };
    assert.equal(rewrite((l) => l).ok, true);
    assert.equal(rewrite((l) => { const e = JSON.parse(l[0]); e.actor = 'someone-else'; l[0] = JSON.stringify(e); return l; }).ok, false, 'edited');
    assert.equal(rewrite((l) => l.filter((_, i) => i !== 1)).ok, false, 'removed');
    assert.equal(rewrite((l) => [l[1], l[0], l[2], l[3]]).ok, false, 'reordered');
    assert.equal(rewrite((l) => l.slice(0, 3)).ok, true, 'a truncated tail is a shorter valid chain: the log proves what it holds, not what it lacks');
  });

  test('[X-708.AC01] fail closed: a broken log, or a log that cannot be written, deletes nothing', () => {
    const w = world([{ id: 'a', class: 'model-trace', ageDays: 60 }]);
    fs.writeFileSync(w.log, `${JSON.stringify({ schema: 'agentic-security/retention-log', seq: 1, prev: null, type: 'deleted', digest: 'sha256:00' })}\n`);
    const r = applyRetention({ root: w.root, logFile: w.log, actor: 'ops', records: w.records, now: NOW });
    assert.equal(r.deleted.length, 0);
    assert.equal(r.failed[0].code, 'LOG_BROKEN');
    assert.equal(exists(w.root, w.records[0].path), true);
    const w2 = world([{ id: 'a', class: 'model-trace', ageDays: 60 }]);
    const dirAsLog = path.join(w2.root, 'logdir'); fs.mkdirSync(dirAsLog);
    const r2 = applyRetention({ root: w2.root, logFile: dirAsLog, actor: 'ops', records: w2.records, now: NOW });
    assert.equal(r2.deleted.length, 0);
    assert.equal(exists(w2.root, w2.records[0].path), true, 'no log, no deletion');
  });

  test('[X-708.AC01] dry run deletes and logs nothing, and an apply without an actor is refused', () => {
    const w = world([{ id: 'a', class: 'model-trace', ageDays: 60 }]);
    const d = applyRetention({ root: w.root, logFile: w.log, records: w.records, now: NOW, dryRun: true });
    assert.equal(d.ok, true); assert.equal(d.dryRun, true); assert.equal(d.plan.summary.delete, 1);
    assert.equal(exists(w.root, w.records[0].path), true);
    assert.equal(fs.existsSync(w.log), false);
    const noActor = applyRetention({ root: w.root, logFile: w.log, records: w.records, now: NOW });
    assert.equal(noActor.ok, false);
    assert.equal(noActor.errors[0].code, 'NO_ACTOR');
    assert.equal(exists(w.root, w.records[0].path), true);
  });

  test('[X-708.AC01] deletion is confined to the root: traversal, absolute paths, links and directories are refused and the outside file survives', () => {
    const outsideDir = mkTestTmp('outside-'); const outside = path.join(outsideDir, 'precious.txt'); fs.writeFileSync(outside, 'keep me');
    const w = world([{ id: 'real', class: 'model-trace', ageDays: 60 }]);
    fs.symlinkSync(outside, path.join(w.root, 'link.dat'));
    fs.mkdirSync(path.join(w.root, 'adir'));
    fs.symlinkSync(outsideDir, path.join(w.root, 'dirlink'));
    const mk = (id, p) => ({ id, class: 'model-trace', path: p, createdAt: ago(60) });
    const records = [mk('trav', '../escape.dat'), mk('abs', outside), mk('lnk', 'link.dat'), mk('dir', 'adir'), mk('thru', 'dirlink/precious.txt'), mk('gone', 'no-such-file.dat'), ...w.records];
    const r = applyRetention({ root: w.root, logFile: w.log, actor: 'ops', records, now: NOW });
    const code = (id) => r.failed.find((f) => f.id === id)?.code;
    assert.equal(code('trav'), 'PATH_ESCAPES_ROOT');
    assert.equal(code('abs'), 'PATH_ESCAPES_ROOT');
    assert.equal(code('lnk'), 'SYMLINK_REFUSED');
    assert.equal(code('dir'), 'NOT_A_FILE');
    assert.equal(code('thru'), 'PATH_ESCAPES_ROOT');
    assert.equal(code('gone'), 'ALREADY_GONE');
    assert.equal(fs.readFileSync(outside, 'utf8'), 'keep me');
    assert.deepEqual(r.deleted.map((d) => d.id), ['real']);
    const logged = verifyRetentionLog(w.log).entries.map((e) => e.recordId);
    assert.ok(!logged.includes('trav') && !logged.includes('lnk'), 'a refused deletion is not logged as an intent');
  });
});

describe('[X-708.AC01] retention from the command line', () => {
  test('[X-708.AC01] plan deletes nothing, apply deletes and logs, verify-log checks the chain; each is off unless the feature is on', async () => {
    const w = world([{ id: 'a', class: 'model-trace', ageDays: 60 }, { id: 'keep', class: 'metadata', ageDays: 60 }]);
    const recFile = path.join(w.root, 'records.json'); fs.writeFileSync(recFile, JSON.stringify(w.records));
    let out = ''; let err = '';
    const io = (env) => ({ cwd: w.root, env, out: (s) => { out += s; }, err: (s) => { err += s; }, now: () => NOW });
    const flags = { records: recFile, root: w.root };
    assert.equal(await runPortfolioCommand({ _: ['portfolio', 'retention', 'plan'], flags }, io({})), 1);
    assert.match(err, /disabled/);
    assert.equal(await runPortfolioCommand({ _: ['portfolio', 'retention', 'plan'], flags }, io(ON)), 0);
    assert.match(out, /1 to delete/);
    assert.equal(exists(w.root, w.records[0].path), true, 'plan deletes nothing');
    assert.equal(await runPortfolioCommand({ _: ['portfolio', 'retention', 'apply'], flags }, io(ON)), 2, 'apply needs a log and an actor');
    assert.equal(await runPortfolioCommand({ _: ['portfolio', 'retention', 'apply'], flags: { ...flags, log: w.log, actor: 'ops' } }, io(ON)), 0);
    assert.equal(exists(w.root, w.records[0].path), false);
    assert.equal(exists(w.root, w.records[1].path), true);
    assert.equal(await runPortfolioCommand({ _: ['portfolio', 'retention', 'verify-log'], flags: { log: w.log } }, io(ON)), 0);
    fs.writeFileSync(w.log, fs.readFileSync(w.log, 'utf8').replace('"ops"', '"mallory"'));
    assert.equal(await runPortfolioCommand({ _: ['portfolio', 'retention', 'verify-log'], flags: { log: w.log } }, io(ON)), 1);
    const bad = path.join(w.root, 'holds.json'); fs.writeFileSync(bad, JSON.stringify([{ target: { id: 'a' } }]));
    assert.equal(await runPortfolioCommand({ _: ['portfolio', 'retention', 'plan'], flags: { ...flags, holds: bad } }, io(ON)), 1, 'a malformed hold file refuses the plan');
  });
});
