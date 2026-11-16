// Contract test for contract-driven repair (docs/reference/repair-contract.md): the contract, obligation and record fields the code
// produces are held to the page's tables in both directions, and so are the obligation kinds, the dispositions and the exit codes.
// Nothing here executes an application: the record comes from a run with execution disabled, which must be `blocked` and exit 3.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { mkTestTmp } from '../helpers/tmp.js';
import { REPO, readPage, fieldsUnder, sameFields } from '../helpers/contract-page.js';
import { planRepair, runRepair, EXIT } from '../../src/repair/coordinator.js';
import { OBLIGATION_KINDS, DISPOSITIONS, CONTRACT_FIELDS, RECORD_FIELDS, OBLIGATION_FIELDS } from '../../src/repair/schemas.js';
import { USAGE } from '../../src/repair/cli.js';
import { resolveAssuranceConfig } from '../../src/posture/assurance/config.js';

const PAGE = readPage('docs/reference/repair-contract.md');
const FIXTURE = path.join(REPO, 'scanner', 'test', 'fixtures', 'repair', 'sql-notes');

function plan() {
  const root = mkTestTmp('agsec-repair-contract-');
  fs.cpSync(FIXTURE, root, { recursive: true });
  const profile = JSON.parse(fs.readFileSync(path.join(root, 'profile.json'), 'utf8'));
  const p = planRepair({ root, finding: { findingId: 'contract-test', file: 'src/app.mjs' }, family: 'sql-injection', profile, profileOrigin: 'repository-file' });
  assert.ok(p.plan, p.problems.join('; '));
  return { root, plan: p.plan };
}

const tableColumn = (heading) => {
  const lines = PAGE.split('\n');
  const at = lines.findIndex((l) => l.startsWith(`**${heading}`));
  assert.ok(at >= 0, heading);
  const out = [];
  for (let i = at + 1; i < lines.length && !lines[i].startsWith('#') && !(lines[i].startsWith('**') && i > at); i++) { const m = /^\| `([^`]+)` \|/.exec(lines[i]); if (m) out.push(m[1]); }
  return out;
};

test('the contract and obligation fields match the page; the closed allowlists list exactly the documented fields', () => {
  const { plan: p } = plan();
  sameFields(p.contract, fieldsUnder(PAGE, 'Contract'), 'contract', ['expiresAt', 'approval']);
  assert.deepEqual([...CONTRACT_FIELDS].sort(), [...fieldsUnder(PAGE, 'Contract')].sort());
  sameFields(p.contract.obligations[0], fieldsUnder(PAGE, 'Obligation'), 'obligation');
  assert.deepEqual([...OBLIGATION_FIELDS].sort(), [...fieldsUnder(PAGE, 'Obligation')].sort());
});

test('the registered obligation kinds and the dispositions are the documented ones', () => {
  assert.deepEqual(Object.keys(OBLIGATION_KINDS).sort(), tableColumn('Obligation kinds').sort());
  assert.deepEqual([...DISPOSITIONS].sort(), tableColumn('Dispositions').sort());
});

test('a run without operator-enabled execution is blocked with exit 3; its record fields are the documented ones', async () => {
  const { root, plan: p } = plan();
  const r = await runRepair({ root, plan: p, config: resolveAssuranceConfig({ env: {} }), proposers: [] });
  assert.equal(r.record.disposition, 'blocked');
  assert.equal(r.exitCode, 3);
  assert.equal(r.record.artifact, 'source-only');
  assert.equal(r.record.environment, 'not-checked');
  sameFields(r.record, fieldsUnder(PAGE, 'Record'), 'record', ['patchDigest', 'exactPatch', 'legacy', 'source']);
  assert.deepEqual([...RECORD_FIELDS].sort(), [...fieldsUnder(PAGE, 'Record')].sort());
});

test('the exit codes and the subcommands are the documented ones', () => {
  assert.deepEqual(Object.values(EXIT).map(String).sort(), fieldsUnder(PAGE, 'Exit codes').sort());
  const documented = [...PAGE.matchAll(/^\| `repair (\w+)` \|/gm)].map((m) => m[1]).sort();
  const usage = [...USAGE.matchAll(/^ {2}(\w+) /gm)].map((m) => m[1]).sort();
  assert.deepEqual(usage, documented);
});
