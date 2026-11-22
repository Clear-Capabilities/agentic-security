// The operator surface of the service contract: validate, inspect and draft through the real CLI, and the loader `hunt --contract`
// uses. Drafting consults no model and grants no approval; a draft is proposed with origin `inferred`.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { loadContractForHunt, draftContract } from '../../src/contracts/cli.js';
import { validateContract } from '../../src/contracts/schema.js';
import { buildContext } from '../../src/context-intelligence/build.js';
import { persistBuild } from '../../src/context-intelligence/persist.js';
import { normalizeConfig } from '../../src/context-intelligence/config.js';
import { setStateWritesEnabled } from '../../src/posture/state-dir.js';
import { proposeContract, approveContract } from '../../src/contracts/approval.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.join(HERE, '..', '..', 'bin', 'agentic-security.js');
const FIXTURE = path.join(HERE, '..', 'fixtures', 'contract-slice');
const CONTRACT = path.join(FIXTURE, 'security', 'contracts', 'invoices-service', 'contract.json');
const run = (...args) => spawnSync(process.execPath, [BIN, ...args], { encoding: 'utf8', timeout: 60_000 });

test('contracts validate: exit 0 on the slice contract with its pack; exit 1 on a placeholder revision; exit 2 on usage', () => {
  const ok = run('contracts', 'validate', CONTRACT);
  assert.equal(ok.status, 0, ok.stderr); assert.match(ok.stdout, /^valid invoices-service@1\.0\.0#/); assert.match(ok.stdout, /pack: threat-pack\.md agrees/);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'contract-cli-'));
  try {
    const c = JSON.parse(fs.readFileSync(CONTRACT, 'utf8')); c.scope.repositories[0].revision = 'REPLACE_WITH_EXACT_COMMIT'; delete c.threatPack;
    fs.writeFileSync(path.join(dir, 'contract.json'), JSON.stringify(c));
    const bad = run('contracts', 'validate', path.join(dir, 'contract.json'));
    assert.equal(bad.status, 1); assert.match(bad.stdout, /INVALID/); assert.match(bad.stdout, /RULE_VIOLATION scope\.repositories\[0\]\.revision/);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  assert.equal(run('contracts', 'validate').status, 2);
  assert.equal(run('contracts', 'nonsense').status, 1);
});

test('contracts inspect: approval not-recorded without a ledger, bindings and gaps listed, pack agreement, --json shape', () => {
  const r = run('contracts', 'inspect', CONTRACT);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /approval: not-recorded \(not current authority\)/);
  assert.match(r.stdout, /TENANT-ISOLATION-001: static=declared scenario=declared runtime=missing preservation=missing {2}gaps: runtime, preservation/);
  assert.match(r.stdout, /pack: agrees/);
  const j = JSON.parse(run('contracts', 'inspect', CONTRACT, '--json').stdout);
  assert.equal(j.schema, 'agentic-security/contract-inspection'); assert.equal(j.bindings.length, 2); assert.equal(j.approval.state, 'not-recorded');
});

test('loadContractForHunt: a valid contract loads with a warning when no ledger is given; an approved ledger gives approval; an unreadable or invalid file is refused', async () => {
  const noLedger = await loadContractForHunt({ contractPath: CONTRACT, now: '2026-11-22' });
  assert.equal(noLedger.ok, true); assert.equal(noLedger.contractMode.approval, null); assert.match(noLedger.warnings[0], /no --ledger given/);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'contract-cli-'));
  try {
    const contract = JSON.parse(fs.readFileSync(CONTRACT, 'utf8'));
    const lax = { sign: () => 'ff', verify: () => true };
    let ledger = proposeContract(null, contract, { actor: { id: 'd', kind: 'code' }, reason: 'r', signer: lax }).ledger;
    ledger = approveContract(ledger, contract, { actor: { id: 'dana', kind: 'human' }, reason: 'ok', policy: { id: 'p', reviewers: ['dana'] }, signer: lax }).ledger;
    fs.writeFileSync(path.join(dir, 'ledger.json'), JSON.stringify(ledger));
    // the install key did not sign this lax ledger, so without the test signer the ledger does not verify: approval-unverifiable, a warning, never a pass
    const loaded = await loadContractForHunt({ contractPath: CONTRACT, ledgerPath: path.join(dir, 'ledger.json'), scanRoot: dir, now: '2026-11-22' });
    assert.equal(loaded.ok, true); assert.equal(loaded.contractMode.approval.state, 'approval-unverifiable'); assert.ok(loaded.warnings.some((w) => /approval: approval-unverifiable/.test(w)));
    assert.equal((await loadContractForHunt({ contractPath: path.join(dir, 'missing.json'), now: '2026-11-22' })).ok, false);
    fs.writeFileSync(path.join(dir, 'bad.json'), JSON.stringify({ ...contract, id: 'Bad Id' }));
    const bad = await loadContractForHunt({ contractPath: path.join(dir, 'bad.json'), now: '2026-11-22' });
    assert.equal(bad.ok, false); assert.ok(bad.errors.some((e) => /^id:/.test(e)));
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('contracts draft: a PROPOSED, inferred contract from the context build, with one invariant per observed protection dimension; refused with no build or no commit', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'contract-draft-'));
  try {
    for (const f of ['service.mjs', 'server.js']) fs.copyFileSync(path.join(FIXTURE, f), path.join(dir, f));
    fs.writeFileSync(path.join(dir, 'package.json'), '{"name":"x","private":true,"type":"module"}\n');
    assert.match((await draftContract(dir, { id: 'invoices', now: '2026-11-22' })).reason, /no context build/);
    setStateWritesEnabled(true);
    const { config } = normalizeConfig({});
    const built = await buildContext(dir, { config });
    persistBuild(dir, built, config);
    const noCommit = await draftContract(dir, { id: 'invoices', now: '2026-11-22' });
    // a temp directory is not a repository: the build records no exact commit, and a contract names an exact revision or nothing
    assert.equal(noCommit.ok, false); assert.match(noCommit.reason, /no exact commit/);
    // with a commit recorded, the draft validates, is proposed and inferred, and lists the observed authentication control
    const index = JSON.parse(fs.readFileSync(path.join(dir, '.agentic-security', 'context-intelligence', 'index.json'), 'utf8'));
    index.repository = { ...(index.repository || {}), commit: 'a'.repeat(40) };
    fs.writeFileSync(path.join(dir, '.agentic-security', 'context-intelligence', 'index.json'), JSON.stringify(index));
    const d = await draftContract(dir, { id: 'invoices', now: '2026-11-22' });
    assert.equal(d.ok, true, d.reason);
    assert.deepEqual(validateContract(d.contract), { ok: true, errors: [] });
    assert.equal(d.contract.review.state, 'proposed'); assert.equal(d.contract.review.origin, 'inferred');
    assert.ok(d.contract.invariants.some((i) => i.id === 'AUTHENTICATION-001' && i.attacker.entryPoints.includes('PUT /invoices/:id/memo')));
    assert.ok(d.contract.controls.some((c) => c.kind === 'authentication' && c.source === 'declared'));
    const cli = run('contracts', 'draft', '--root', dir, '--id', 'invoices', '--out', path.join(dir, 'draft.json'));
    assert.equal(cli.status, 0, cli.stderr); assert.match(cli.stdout, /drafted invoices@0\.1\.0#[0-9a-f]{16} .*PROPOSED/);
    assert.equal(validateContract(JSON.parse(fs.readFileSync(path.join(dir, 'draft.json'), 'utf8'))).ok, true);
  } finally { setStateWritesEnabled(false); fs.rmSync(dir, { recursive: true, force: true }); }
});
