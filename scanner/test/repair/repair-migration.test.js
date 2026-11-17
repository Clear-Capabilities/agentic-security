// Verified remediation M4-06 (FR-16, AC-16.4): a repair that ships a schema migration. The patched revision runs on the schema its up
// file leaves; the migration-window legs check the deployment window, the rollback and the forward recovery over the rows an older
// revision writes while rolled back, and state what each rollback does to the exposure. A skip is not a pass.
import { test, describe, before } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { planRepair, runRepair } from '../../src/repair/coordinator.js';
import { queueProposer } from '../../src/repair/candidates.js';
import { validateProfile } from '../../src/repair/profile.js';
import { validateRepairRecord } from '../../src/repair/schemas.js';
import { resolveAssuranceConfig } from '../../src/posture/assurance/config.js';
import { getOracle } from '../../src/posture/oracles/registry.js';
import { detectBackend } from '../../src/sandbox/capabilities.js';
import { probeControls, unmetControls } from '../../src/sandbox/control-probes.js';
import { DEFAULT_REQUIRED_CONTROLS } from '../../src/sandbox/trust-boundary.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FIX = path.join(HERE, '..', 'fixtures', 'repair', 'order-migration');
const ON = resolveAssuranceConfig({ env: {}, overrides: { features: { 'verification-oracles': true } } });

let ready = false; let whyNot = '';
before(async () => {
  const backend = detectBackend();
  const unmet = unmetControls(await probeControls({}), [...DEFAULT_REQUIRED_CONTROLS, 'network']);
  ready = (backend === 'userspace' || backend === 'namespace') && unmet.length === 0;
  whyNot = `SKIPPED, NOT PASSED: the trust boundary cannot run on this host (backend '${backend}'); the migration execution tests are UNVERIFIED here`;
});
const needs = (fn) => async (t) => (ready ? fn(t) : t.skip(whyNot));

const setup = () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'mig-'));
  fs.cpSync(FIX, root, { recursive: true });
  const profile = JSON.parse(fs.readFileSync(path.join(root, 'profile.json'), 'utf8'));
  const p = planRepair({ root, finding: { findingId: 'wf:orders', file: 'src/app.mjs' }, family: 'workflow', profile, profileOrigin: 'repository-file' });
  assert.ok(p.plan, [...p.problems, ...p.blocked].join('; '));
  return { root, plan: p.plan, profile, original: fs.readFileSync(path.join(root, 'src', 'app.mjs'), 'utf8') };
};
const rep = (t, a, b) => { assert.ok(t.includes(a), a.slice(0, 40)); return t.replace(a, () => b); };
const UP = 'migrations/002_one_charge.up.sql';
const DOWN = 'migrations/002_one_charge.down.sql';
const INDEX = "CREATE UNIQUE INDEX one_charge_per_order ON events (order_id) WHERE kind = 'charge';\n";
const RELABEL = "UPDATE events SET kind = 'charge-duplicate' WHERE kind = 'charge' AND id NOT IN (SELECT min(id) FROM events WHERE kind = 'charge' GROUP BY order_id);\n";
const REMOVE_INDEX = ['DROP', 'INDEX one_charge_per_order;\n'].join(' ');
const PAY = '      const r = await provider.charge(order.id, order.amount);\n';
const RECORD = '      db.prepare("INSERT INTO events (order_id, kind, amount) VALUES (?, \'charge\', ?)").run(order.id, r.amount);\n';
const SHIP = '    db.prepare("INSERT INTO events (order_id, kind, amount) VALUES (?, \'ship\', 0)").run(order.id);\n';
const SHIP_CHECK = "    if (order.status !== 'paid') return send(res, 409, { error: 'not paid' });\n";

// claim the charge through the unique index BEFORE calling the provider; ship only a paid order
const claimed = (orig) => rep(rep(orig, PAY + RECORD,
  '      try { db.prepare("INSERT INTO events (order_id, kind, amount) VALUES (?, \'charge\', ?)").run(order.id, order.amount); } catch { return send(res, 409, { error: \'already paid\' }); }\n      await provider.charge(order.id, order.amount);\n'),
SHIP, SHIP_CHECK + SHIP);
// an atomic status claim needs no schema change, but the contract declares a migration
const statusClaim = (orig) => rep(rep(orig, PAY, "      const claim = db.prepare(\"UPDATE orders SET status = 'paying' WHERE id = ? AND status = 'new'\").run(order.id);\n      if (claim.changes !== 1) return send(res, 409, { error: 'already paid' });\n" + PAY), SHIP, SHIP_CHECK + SHIP);

describe('[M4-06] migration contracts (no execution)', () => {
  test('a declared migration adds a required migration-window obligation and puts the up and down files in the edit scope', () => {
    const { plan } = setup();
    const ob = plan.contract.obligations.find((o) => o.kind === 'migration-window');
    assert.ok(ob && ob.required && ob.oracleId === null);
    assert.equal(ob.inputs.deployOrder, 'migrate-then-deploy');
    assert.equal(ob.inputs.interim.length, 2);
    assert.ok(plan.contract.editScope.allowed.includes(UP) && plan.contract.editScope.allowed.includes(DOWN));
  });

  test('the profile section is closed and checked', () => {
    const { profile } = setup();
    const m = (over) => validateProfile({ ...profile, migration: { ...profile.migration, ...over } }).join(' ');
    assert.match(m({ up: 'migrations/x.txt' }), /migration\.up must be a relative \.sql path/);
    assert.match(m({ down: 'src/app.mjs' }), /must be a relative \.sql path/);
    assert.match(m({ down: profile.migration.up }), /must differ/);
    assert.match(m({ deployOrder: 'whenever' }), /deployOrder/);
    assert.match(m({ interim: [{ sql: 'DELETE FROM events', params: [] }] }), /INSERT statements/);
    assert.match(m({ extra: 1 }), /unknown field 'extra'/);
  });

  test('the application oracle (version 6) accepts migration steps and refuses ATTACH and multi-statement INSERT steps', () => {
    const o = getOracle('application-behaviour');
    assert.equal(o.version, '6');
    const base = { export: 'createApp', schemaSql: 'CREATE TABLE t (a INTEGER);', seed: [], requests: [{ id: 'c', role: 'control', method: 'GET', path: '/' }] };
    assert.equal(o.validateInputs({ ...base, migrations: [{ exec: 'ALTER TABLE t ADD COLUMN b TEXT;' }, { sql: 'INSERT INTO t (a) VALUES (?)', params: [1] }] }), null);
    assert.match(o.validateInputs({ ...base, migrations: [{ exec: "ATTACH DATABASE 'x.db' AS x;" }] }), /ATTACH/);
    assert.match(o.validateInputs({ ...base, migrations: [{ sql: 'INSERT INTO t VALUES (1); SELECT 1', params: [] }] }), /one INSERT/);
  });
});

describe('[M4-06] migration repair, executed', () => {
  test('a migration missing, one that cannot re-apply after a rollback, and a down that does not apply are rejected; a robust migration is verified and every rollback is stated as reinstating the exposure', needs(async () => {
    const s = setup();
    const code = claimed(s.original);
    const items = [
      { round: 1, strategy: 'noMigration', files: { 'src/app.mjs': statusClaim(s.original) } },
      { round: 1, strategy: 'naiveUp', files: { 'src/app.mjs': code, [UP]: INDEX, [DOWN]: REMOVE_INDEX } },
      { round: 1, strategy: 'badDown', files: { 'src/app.mjs': code, [UP]: RELABEL + INDEX, [DOWN]: REMOVE_INDEX.replace('one_charge_per_order', 'no_such_index') } },
      { round: 2, strategy: 'robust', files: { 'src/app.mjs': code, [UP]: RELABEL + INDEX, [DOWN]: REMOVE_INDEX } },
    ];
    const r = await runRepair({ root: s.root, plan: s.plan, config: ON, proposers: [queueProposer(items)], policy: { schema: 'agentic-security/repair-policy', schemaVersion: '1.0.0', budgets: { rounds: 2 } } });
    const by = Object.fromEntries(r.record.candidates.map((c) => [c.strategy, c]));
    const mig = (k) => by[k].results.find((x) => x.obligation === 'migration-window');
    const cx = (k) => r.record.counterexamples.find((x) => x.candidateId === by[k].candidateId);
    assert.equal(mig('noMigration')?.status, 'failed', JSON.stringify(by.noMigration.results.map((x) => [x.obligation, x.status, x.reason])));
    assert.equal(cx('noMigration').property, 'migration-missing');
    assert.equal(mig('naiveUp')?.status, 'failed', 'the unique index cannot be created over the duplicate rows written while rolled back');
    assert.equal(cx('naiveUp').leg, 'recovery');
    assert.match(mig('naiveUp').reason, /migration step/);
    assert.equal(mig('badDown')?.status, 'failed');
    assert.equal(cx('badDown').leg, 'rollback');
    assert.equal(by.robust.status, 'verified-for-contract', r.record.reasons.join('; ') + JSON.stringify(by.robust.results.map((x) => [x.obligation, x.status, x.reason])));
    assert.equal(r.record.disposition, 'verified-for-contract');
    const m = r.record.migration;
    assert.equal(m.deployOrder, 'migrate-then-deploy');
    assert.deepEqual(m.legs.filter((l) => l.required).map((l) => [l.leg, l.status]), [['window', 'passed'], ['rollback', 'passed'], ['recovery', 'passed'], ['recovery', 'passed']]);
    assert.equal(m.exposure.fullRollback, 'exposed', 'rolling back to the original code reinstates the double charge');
    assert.equal(m.exposure.codeRollbackSchemaKept, 'exposed', 'the original code charges before it records, so the index does not stop the provider charging twice');
    assert.equal(m.exposure.schemaRollbackCodeKept, 'exposed', 'the patched code depends on the index');
    assert.match(m.mitigations[0], /none observed/);
    assert.ok(r.record.reasons.some((x) => /reinstates the exposure/.test(x)));
    assert.ok(validateRepairRecord(r.record).ok);
  }));
});
