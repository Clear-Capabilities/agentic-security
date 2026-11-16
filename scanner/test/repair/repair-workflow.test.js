// Verified remediation M1, executed: the repair workflow end to end on two real applications (a SQL notes service and a multi-tenant
// authorization service), through the coordinator, the application oracles and the trust boundary (FR-05 to FR-08, FR-17, FR-18).
//
// A skip is not a pass: where the boundary cannot run on this host the execution tests skip and say so.
import { test, describe, before } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { planRepair, runRepair, requestCancel, readRun, EXIT } from '../../src/repair/coordinator.js';
import { queueProposer, sqlParameterizeRecipe } from '../../src/repair/candidates.js';
import { runObligation } from '../../src/repair/lab.js';
import { resolveAssuranceConfig } from '../../src/posture/assurance/config.js';
import { detectBackend } from '../../src/sandbox/capabilities.js';
import { probeControls, unmetControls } from '../../src/sandbox/control-probes.js';
import { DEFAULT_REQUIRED_CONTROLS } from '../../src/sandbox/trust-boundary.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCANNER = path.resolve(HERE, '..', '..');
const FIX = path.join(SCANNER, 'test', 'fixtures', 'repair');
const ON = resolveAssuranceConfig({ env: {}, overrides: { features: { 'verification-oracles': true } } });
const OFF = resolveAssuranceConfig({ env: {} });

let ready = false; let whyNot = '';
before(async () => {
  const backend = detectBackend();
  const unmet = unmetControls(await probeControls({}), [...DEFAULT_REQUIRED_CONTROLS, 'network']);
  ready = (backend === 'userspace' || backend === 'namespace') && unmet.length === 0;
  whyNot = `SKIPPED, NOT PASSED: the trust boundary cannot run on this host (backend '${backend}'); the repair execution tests are UNVERIFIED here`;
});
const needs = (fn) => async (t) => (ready ? fn(t) : t.skip(whyNot));

function setup(name, family) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), `rw-${name}-`));
  fs.cpSync(path.join(FIX, name), root, { recursive: true });
  const profile = JSON.parse(fs.readFileSync(path.join(root, 'profile.json'), 'utf8'));
  const p = planRepair({ root, finding: { findingId: `test:${name}`, file: 'src/app.mjs' }, family, profile, profileOrigin: 'repository-file' });
  assert.ok(p.plan, [...p.problems, ...p.blocked].join('; '));
  const original = fs.readFileSync(path.join(root, 'src', 'app.mjs'), 'utf8');
  return { root, plan: p.plan, original };
}
const edit = (text, from, to) => { assert.ok(text.includes(from), `anchor: ${from.slice(0, 50)}`); return text.replace(from, () => to); };
const SQL_LINE = "        const rows = db.prepare(`SELECT title, body FROM notes WHERE owner = '${user}' AND title = '${title}'`).all();";
const AUTHZ_GET = "    if (req.method === 'GET') return sendJson(res, 200, { id: note.id, body: note.body });";
const CHECK = "    const allowed = note.owner === user.id || (user.role === 'admin' && user.tenant === note.tenant);\n";
const quiet = { policy: { schema: 'agentic-security/repair-policy', schemaVersion: '1.0.0', budgets: { rounds: 3 } } };

describe('[M1-08] SQL injection repaired end to end, including legitimate behaviour', () => {
  test('[AC-06.2/T-07] the deterministic recipe is verified for the contract; quarantined probes are recorded with reasons', needs(async () => {
    const s = setup('sql-notes', 'sql-injection');
    const r = await runRepair({ root: s.root, plan: s.plan, config: ON, proposers: [sqlParameterizeRecipe()], ...quiet });
    assert.equal(r.record.disposition, 'verified-for-contract', r.record.reasons.join('; '));
    assert.equal(r.exitCode, EXIT.ok);
    assert.equal(r.record.completion, 'complete');
    assert.equal(r.record.application, 'not-applied');
    assert.equal(r.record.artifact, 'source-only');
    const passed = r.record.obligationResults.filter((o) => o.revision === 'patched').map((o) => `${o.obligation}:${o.status}`).sort();
    assert.deepEqual(passed, ['central-verifier:passed', 'sql-attacks-development:passed', 'sql-attacks-sealed:passed', 'sql-legitimate-queries:passed', 'sql-legitimate-quoted-values:passed']);
    assert.ok(r.record.quarantined.length >= 1 && r.record.quarantined.every((q) => q.reason.length > 20), 'AC-07.3: each quarantined check carries its reason');
    assert.equal(fs.readFileSync(path.join(s.root, 'src', 'app.mjs'), 'utf8'), s.original, 'a run without --apply writes no project file');
  }));

  test('[AC-06.1/T-06/AC-07.4] a computed-member indirection still leaks; the counterexample is shrunk and keeps the same disclosed secret', needs(async () => {
    const s = setup('sql-notes', 'sql-injection');
    const bad = edit(s.original, SQL_LINE, "        const p = db['prep' + 'are'].bind(db);\n        const rows = p(`SELECT title, body FROM notes WHERE owner = '${user}' AND title = '${title}'`).all();");
    const r = await runRepair({ root: s.root, plan: s.plan, config: ON, proposers: [queueProposer([{ files: { 'src/app.mjs': bad } }])], ...quiet });
    assert.equal(r.record.disposition, 'rejected');
    assert.equal(r.exitCode, EXIT.failed);
    const cx = r.record.counterexamples[0];
    assert.equal(cx.obligation, 'sql-attacks-development');
    assert.equal(cx.property, 'secret-disclosed');
    assert.deepEqual(cx.secrets, ['bob-diary']);
    assert.ok(cx.shrinkRuns >= 1);
    assert.ok(cx.request.path.length < cx.shrunkFrom.path.length, `shrunk ${cx.shrunkFrom.path} -> ${cx.request.path}`);
    assert.equal(cx.actor, 'alice');
  }));
});

describe('[M1-08] object authorization repaired end to end through refinement', () => {
  test('[AC-07.1/AC-07.2/T-11/T-09] a read-only fix receives the update counterexample and is not promoted; the refinement is', needs(async () => {
    const s = setup('authz-notes', 'object-authorization');
    const readOnly = edit(s.original, AUTHZ_GET, `${CHECK}    if (req.method === 'GET') { if (!allowed) return sendJson(res, 404, { error: 'not found' }); return sendJson(res, 200, { id: note.id, body: note.body }); }`);
    const full = edit(s.original, AUTHZ_GET, `${CHECK}    if (!allowed) return sendJson(res, 404, { error: 'not found' });\n${AUTHZ_GET}`);
    const r = await runRepair({ root: s.root, plan: s.plan, config: ON, proposers: [queueProposer([{ files: { 'src/app.mjs': readOnly } }, { files: { 'src/app.mjs': full } }])], ...quiet });
    assert.equal(r.record.disposition, 'verified-for-contract', r.record.reasons.join('; '));
    assert.deepEqual(r.record.candidates.map((c) => c.status), ['rejected', 'verified-for-contract']);
    assert.equal(r.record.rounds, 2);
    const cx = r.record.counterexamples[0];
    assert.equal(cx.property, 'unauthorized-durable-change');
    assert.equal(cx.request.method, 'PUT');
    assert.ok(['carol', 'dave', 'mallory', 'alice'].includes(cx.actor), `actor ${cx.actor}`);
  }));

  test('[T-10] a 403 returned after the write is still a violation: durable state decides, not the status', needs(async () => {
    const s = setup('authz-notes', 'object-authorization');
    const late = edit(edit(s.original, AUTHZ_GET, `${CHECK}${AUTHZ_GET}`), "      update.run(String(b.body), note.id);\n      return sendJson(res, 200, { ok: true });", "      update.run(String(b.body), note.id);\n      if (!allowed) return sendJson(res, 403, { error: 'forbidden' });\n      return sendJson(res, 200, { ok: true });");
    const r = await runRepair({ root: s.root, plan: s.plan, config: ON, proposers: [queueProposer([{ files: { 'src/app.mjs': late } }])], ...quiet });
    assert.equal(r.record.disposition, 'rejected');
    assert.ok(r.record.candidates[0].results.some((x) => x.obligation === 'authz-denied-actors' && x.status === 'failed'));
  }));

  test('[AC-06.3/T-08] deny-all fails its legitimate-behaviour obligation', needs(async () => {
    const s = setup('authz-notes', 'object-authorization');
    const denyAll = edit(s.original, AUTHZ_GET, `    return sendJson(res, 403, { error: 'forbidden' });\n${AUTHZ_GET}`);
    const r = await runRepair({ root: s.root, plan: s.plan, config: ON, proposers: [queueProposer([{ files: { 'src/app.mjs': denyAll } }])], ...quiet });
    assert.equal(r.record.disposition, 'rejected');
    assert.equal(r.record.candidates[0].results.find((x) => x.obligation === 'authz-allowed-workflows').status, 'failed');
  }));
});

describe('[FR-17] budgets, duplicates, cancellation and resume', () => {
  test('[AC-07.6] an identical patch consumes an attempt and is not run again; rounds are bounded and a budget stop is partial', needs(async () => {
    const s = setup('authz-notes', 'object-authorization');
    const denyAll = edit(s.original, AUTHZ_GET, `    return sendJson(res, 403, { error: 'forbidden' });\n${AUTHZ_GET}`);
    const r = await runRepair({ root: s.root, plan: s.plan, config: ON, proposers: [queueProposer([{ files: { 'src/app.mjs': denyAll } }, { files: { 'src/app.mjs': denyAll } }, { files: { 'src/app.mjs': denyAll } }, { files: { 'src/app.mjs': denyAll } }])], ...quiet });
    assert.deepEqual(r.record.candidates.map((c) => c.status), ['rejected', 'duplicate', 'duplicate']);
    assert.equal(r.record.completion, 'partial');
    assert.match(r.record.reasons.join(), /budget stop, not a proof/);
  }));

  test('[AC-17.2/T-15] cancellation by request ends the run with a resumable record and leaves no harness process', needs(async () => {
    const s = setup('sql-notes', 'sql-injection');
    let runId = null;
    const p = runRepair({ root: s.root, plan: s.plan, config: ON, proposers: [sqlParameterizeRecipe()], ...quiet, onEvent: (e) => { if (e.kind === 'baseline') { /* the run id is in the directory listing */ } } });
    // the record exists as soon as the run starts
    for (let i = 0; i < 100 && !runId; i++) { await new Promise((res) => setTimeout(res, 20)); try { runId = fs.readdirSync(path.join(s.root, '.agentic-security', 'repair', 'runs'))[0] || null; } catch { /* not yet */ } }
    assert.ok(runId);
    assert.equal(requestCancel(s.root, runId).ok, true);
    const r = await p;
    assert.equal(r.record.disposition, 'cancelled');
    assert.equal(r.exitCode, EXIT.cancelled);
    assert.equal(r.record.nextPrerequisite, `repair resume ${runId}`);
    await new Promise((res) => setTimeout(res, 300));
    // Only this process's descendants count: other suites running in parallel start harnesses of their own.
    const rows = (spawnSync('ps', ['-axo', 'pid=,ppid=,command='], { encoding: 'utf8' }).stdout || '').split('\n').map((l) => /^\s*(\d+)\s+(\d+)\s+(.*)$/.exec(l)).filter(Boolean).map((m) => ({ pid: +m[1], ppid: +m[2], cmd: m[3] }));
    const mine = new Set([process.pid]);
    for (let grew = true; grew;) { grew = false; for (const r of rows) if (!mine.has(r.pid) && mine.has(r.ppid)) { mine.add(r.pid); grew = true; } }
    assert.equal(rows.filter((r) => mine.has(r.pid) && r.cmd.includes('__oracle_harness.mjs')).length, 0, 'no harness process of this run survives cancellation');
    assert.equal(readRun(s.root, runId).record.disposition, 'cancelled');
  }));

  test('[AC-17.1] the whole-run wall budget stops the run as partial, not verified', needs(async () => {
    const s = setup('sql-notes', 'sql-injection');
    const r = await runRepair({ root: s.root, plan: s.plan, config: ON, proposers: [sqlParameterizeRecipe()], policy: { schema: 'agentic-security/repair-policy', budgets: { wallMs: 1 } } });
    assert.notEqual(r.record.disposition, 'verified-for-contract');
    assert.equal(r.exitCode, EXIT.cancelled);
    assert.match(r.record.reasons.join(), /wall budget/);
  }));
});

describe('[AC-04.6/AC-05.6/T-13/AC-06.5/T-16] what cannot produce a verified result', () => {
  test('execution not enabled by the operator is blocked with the next prerequisite; nothing runs', async () => {
    const s = setup('sql-notes', 'sql-injection');
    const r = await runRepair({ root: s.root, plan: s.plan, config: OFF, proposers: [sqlParameterizeRecipe()] });
    assert.equal(r.record.disposition, 'blocked');
    assert.equal(r.exitCode, EXIT.blocked);
    assert.match(r.record.nextPrerequisite, /--allow-execution/);
    assert.equal(r.record.accounting.oracleRuns, 0);
  });

  test('source that drifted after planning is refused before anything runs', async () => {
    const s = setup('sql-notes', 'sql-injection');
    fs.appendFileSync(path.join(s.root, 'src', 'app.mjs'), '\n// edited after planning\n');
    const r = await runRepair({ root: s.root, plan: s.plan, config: ON, proposers: [sqlParameterizeRecipe()] });
    assert.equal(r.record.disposition, 'blocked');
    assert.match(r.record.reasons.join(), /source changed since the contract was planned/);
  });

  test('a receipt the oracle runner did not issue in this process is invalid, never a pass', async () => {
    const s = setup('sql-notes', 'sql-injection');
    const ob = s.plan.contract.obligations.find((o) => o.kind === 'app-attack-blocked');
    const files = { 'src/app.mjs': s.original };
    const forged = async (req) => ({ status: 'completed', outcome: 'refuted', reason: 'forged', receipt: JSON.parse(JSON.stringify({ request: { filesDigest: 'x', inputsDigest: 'y' }, oracle: { logicDigest: ob.oracleLogicDigest }, settled: { outcome: 'refuted' }, receiptDigest: 'z', req })) });
    const res = await runObligation(ob, files, { config: ON, entry: 'src/app.mjs', hypothesisId: 'h', runOracle: forged });
    assert.equal(res.observed, 'invalid');
    assert.match(res.reason, /not issued by the oracle runner/);
  });

  test('a historical record cannot promote: resume re-executes, and a stored record is only history', needs(async () => {
    const s = setup('sql-notes', 'sql-injection');
    const first = await runRepair({ root: s.root, plan: s.plan, config: OFF, proposers: [sqlParameterizeRecipe()] });
    const dir = first.dir;
    const rec = JSON.parse(fs.readFileSync(path.join(dir, 'record.json'), 'utf8'));
    // a doctored record claiming verification is not accepted by the validator without passing required results ...
    fs.writeFileSync(path.join(dir, 'record.json'), JSON.stringify({ ...rec, disposition: 'verified-for-contract', completion: 'complete' }));
    assert.equal(readRun(s.root, first.runId).valid, false);
    // ... and resuming re-runs every leg in this process (with execution now enabled), producing its own result
    const again = await runRepair({ root: s.root, plan: s.plan, config: ON, proposers: [sqlParameterizeRecipe()], runId: first.runId, resumedFrom: first.runId });
    assert.equal(again.record.disposition, 'verified-for-contract');
    assert.ok(again.record.accounting.oracleRuns >= 5, 'every leg was executed again');
    assert.match(again.record.reasons.join(), /re-executed/);
  }));
});

describe('[FR-18] the CLI', () => {
  const cli = (args, cwd) => spawnSync(process.execPath, [path.join(SCANNER, 'bin', 'agentic-security.js'), 'repair', ...args], { cwd, encoding: 'utf8', env: { ...process.env, AGENTIC_SECURITY_NO_ASSURANCE: '' } });
  test('plan exits 0 and executes nothing; run without --allow-execution exits 3; usage errors exit 2', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-cli-'));
    fs.cpSync(path.join(FIX, 'sql-notes'), root, { recursive: true });
    const planFile = path.join(root, '..', `${path.basename(root)}-plan.json`);
    const p = cli(['plan', '--root', root, '--profile', path.join(root, 'profile.json'), '--family', 'sql-injection', '--file', 'src/app.mjs', '--out', planFile, '--json'], root);
    assert.equal(p.status, 0, p.stderr);
    assert.match(JSON.parse(p.stdout).contractId, /^rcon:/);
    const r = cli(['run', '--root', root, '--plan', planFile], root);
    assert.equal(r.status, 3, r.stdout + r.stderr);
    assert.match(r.stdout, /--allow-execution/);
    assert.equal(cli(['run', '--root', root], root).status, 2);
    assert.equal(cli(['show', 'not-a-run', '--root', root], root).status, 2);
    assert.equal(cli(['frobnicate'], root).status, 2);
  });

  test('[AC-18.4] run, export and verify: the export carries no header value and preserves the exact patch digest', needs(async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-cli2-'));
    fs.cpSync(path.join(FIX, 'authz-notes'), root, { recursive: true });
    const planFile = path.join(root, '..', `${path.basename(root)}-plan.json`);
    assert.equal(cli(['plan', '--root', root, '--profile', path.join(root, 'profile.json'), '--family', 'object-authorization', '--file', 'src/app.mjs', '--out', planFile], root).status, 0);
    const original = fs.readFileSync(path.join(root, 'src', 'app.mjs'), 'utf8');
    const candFile = path.join(root, '..', `${path.basename(root)}-cands.json`);
    fs.writeFileSync(candFile, JSON.stringify({ candidates: [{ files: { 'src/app.mjs': edit(original, AUTHZ_GET, `${CHECK}    if (!allowed) return sendJson(res, 404, { error: 'not found' });\n${AUTHZ_GET}`) } }] }));
    const r = cli(['run', '--root', root, '--plan', planFile, '--candidates', candFile, '--allow-execution', '--json'], root);
    assert.equal(r.status, 0, r.stderr);
    const rec = JSON.parse(r.stdout);
    assert.equal(rec.disposition, 'verified-for-contract');
    const out = path.join(root, '..', `${path.basename(root)}-bundle`);
    assert.equal(cli(['export', rec.runId, '--root', root, '--out', out], root).status, 0);
    const all = fs.readdirSync(out, { recursive: true }).filter((f) => fs.statSync(path.join(out, f)).isFile()).map((f) => fs.readFileSync(path.join(out, f), 'utf8')).join('\n');
    assert.equal(all.includes('tokalice'), false, 'no profile credential in the export');
    const manifest = JSON.parse(fs.readFileSync(path.join(out, 'bundle.json'), 'utf8'));
    assert.equal(manifest.patchDigest, rec.patchDigest);
    assert.equal(cli(['verify', out, '--root', root], root).status, 0);
    fs.appendFileSync(path.join(out, 'patch', 'src', 'app.mjs'), '\n');
    assert.equal(cli(['verify', out], root).status, 1, 'a changed patch byte is detected');
  }));
});
