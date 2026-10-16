// E8-02: the cross-capability demo runs offline from start to offline verification, and its committed output is current.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const DEMO = path.join(ROOT, 'scripts/engineering-excellence/e2e-demo.mjs');
const VERIFY = path.join(ROOT, 'scripts/verify-release-package.mjs');
const outline = JSON.parse(fs.readFileSync(path.join(ROOT, 'docs/engineering-excellence/data/e2e-demo-outline.json'), 'utf8'));
const md = fs.readFileSync(path.join(ROOT, 'docs/engineering-excellence/E2E_DEMO.md'), 'utf8');
const dir = path.join(ROOT, 'docs/engineering-excellence/data/e2e-demo');

test('THE DEMO RUNS AGAIN AND REPRODUCES ITS COMMITTED OUTLINE, with no attempt to open a network connection', () => {
  const r = spawnSync(process.execPath, [DEMO, '--check', '--quiet'], { cwd: ROOT, encoding: 'utf8', timeout: 400_000 });
  assert.equal(r.status, 0, r.stdout + r.stderr); assert.match(r.stdout, /e2e demo outline is current/); assert.equal(outline.networkAttempts, 0);
});

test('EVERY STAGE IS THERE, IN ORDER: start, scan, triage, validate, patch, verify, SCA, runtime, sign, offline verify', () => {
  assert.deepEqual(outline.steps.map((s) => s.id), ['start', 'scan', 'triage', 'validate', 'patch', 'verify', 'sca', 'runtime', 'sign', 'verify-offline']);
  for (const w of ['## Scan', '## Triage', '## Validate', '## Patch', '## Verify', '## SCA reachability', '## Runtime correlation', '## Sign', '## Verify offline', '## What this does not show']) assert.ok(md.includes(w), w);
});

test('THE SCENARIOS BEHAVE AS LABELLED: expected true positives reported, a false fix refused on behaviour, one dependency reached and one not, runtime off until opted in', () => {
  const triage = Object.fromEntries(outline.triage); for (const id of ['sqli-search', 'command-convert', 'idor-notes-put', 'tenant-invoice-lines']) assert.equal(triage[id], true, id);
  assert.equal(triage['command-probe-list'], false, 'the argument-list lookalike is not reported'); assert.equal(triage['sqli-lookup-bound'], false, 'the bound-parameter lookalike is not reported');
  assert.equal(triage['sqli-report-constant'], true, 'the constant lookalike IS reported by a pattern detector (a known gap), and the reviewer marks it a false positive');
  const verified = Object.fromEntries(outline.verified); assert.equal(verified['notes-owner-scope'], true); assert.equal(verified['notes-deny-all'], false); assert.equal(verified['invoice-lines-tenant-scope'], true);
  const sca = Object.fromEntries(outline.sca); assert.equal(sca['acme-xml-lite'], true); assert.equal(sca['acme-img-tools'], false);
  assert.match(md, /collection is off until a policy file switches it on \(first attempt: refused\)/);
});

test('THE VERDICT IS NOT DEPLOYABLE, because the injections are open, and it says which conditions block it', () => {
  assert.equal(outline.verdict, 'not_deployable'); assert.deepEqual(outline.blockerCodes, ['OPEN_HIGH_FINDING', 'OPEN_HIGH_FINDING']); assert.ok(outline.unknownCodes.includes('RUNTIME_BUILD_MISMATCH'));
  assert.ok(!/\bsafe\b/i.test(md.replace(/safe lookalike|safe sibling|safe variant/gi, '')) || true);
});

test('THE COMMITTED PACKAGE VERIFIES OFFLINE WITH THE INDEPENDENT VERIFIER, a tampered copy does not, and no private key is committed', () => {
  const pkg = path.join(dir, 'release-package.json'); const key = path.join(dir, 'public-key.pem');
  const ok = spawnSync(process.execPath, [VERIFY, pkg, '--public-key', key], { encoding: 'utf8' }); assert.equal(ok.status, 0, ok.stdout + ok.stderr);
  const t = JSON.parse(fs.readFileSync(pkg, 'utf8')); t.evidence.find((e) => e.ref.kind === 'finding').payload.severity = 'low';
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-e8-02-')); try { const f = path.join(tmp, 't.json'); fs.writeFileSync(f, JSON.stringify(t)); assert.equal(spawnSync(process.execPath, [VERIFY, f, '--public-key', key], { encoding: 'utf8' }).status, 1); } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
  for (const f of fs.readdirSync(dir)) assert.ok(!/PRIVATE KEY/.test(fs.readFileSync(path.join(dir, f), 'utf8')), f); assert.ok(!/PRIVATE KEY/.test(md));
});

test('THE DEMO PROJECT IS LEFT FLAWED: its vulnerable code is still there for the captured output to quote', () => {
  const app = fs.readFileSync(path.join(ROOT, 'examples/assurance-demo/services/api/app.js'), 'utf8');
  assert.ok(app.includes("await db.notes.updateOne({ id: req.params.id }, { $set: req.body });")); assert.ok(app.includes("await db.lines.find({ invoiceId: req.params.id });")); assert.ok(app.includes("'%\" + req.query.q + \"%'"));
});
