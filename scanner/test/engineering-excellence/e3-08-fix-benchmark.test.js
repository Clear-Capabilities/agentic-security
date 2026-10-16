// E3-08: the fix verification benchmark and its gate.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { REPO } from './helpers.js';
import { CASES, NOT_COVERED } from '../../../bench/fix-verification/cases.mjs';
import { decide, pinned, runBench, summarize } from '../../../bench/fix-verification/runner.mjs';
import { CHECKS as RELEASE } from '../../../scripts/release-check.mjs';
import { CHECKS as PREPUSH } from '../../../scripts/pre-push-gate.mjs';

const BASE = JSON.parse(fs.readFileSync(path.join(REPO, 'bench/fix-verification/baseline.json'), 'utf8'));
const RUN = path.join(REPO, 'bench/fix-verification/runner.mjs');

test('the corpus covers the classes the PRD names, with at least one safe and one unsafe patch each, and says what it does not cover', () => {
  const classes = new Set(CASES.map((c) => c.cls));
  for (const k of ['sql-injection', 'xss', 'path-traversal', 'idor', 'authorization', 'secret-remediation', 'command-injection']) assert.ok(classes.has(k), k);
  assert.ok(NOT_COVERED.some((n) => n.cls === 'dependency-upgrade'));
  for (const c of CASES) {
    assert.ok(c.patches.some((p) => p.safe), `${c.id} has a real fix`);
    assert.ok(c.patches.some((p) => !p.safe), `${c.id} has a fake fix`);
    assert.ok(c.files['app.js'] && c.files['test.js'], `${c.id} has source and a behaviour test`);
    const ids = c.patches.map((p) => p.id); assert.equal(new Set(ids).size, ids.length);
    for (const p of c.patches) if (!p.safe) assert.ok(p.kind, `${c.id}/${p.id} names what kind of fake it is`);
  }
  const kinds = new Set(CASES.flatMap((c) => c.patches.filter((p) => !p.safe).map((p) => p.kind)));
  for (const k of ['feature-removed', 'scanner-dodge', 'cosmetic-check']) assert.ok(kinds.has(k), k);
});

test('the gate logic: a new unsafe acceptance, a new safe rejection, an unrecorded closed gap and a changed corpus each fail; the baseline passes itself', () => {
  assert.deepEqual(decide(BASE, structuredClone(BASE)), []);
  const worse = structuredClone(BASE); worse.unsafeAccepted.push('sqli-query/disable-feature');
  assert.ok(decide(BASE, worse).some((p) => /NEW unsafe fixes accepted: sqli-query\/disable-feature/.test(p)));
  assert.ok(decide(BASE, worse).some((p) => /not declared gaps/.test(p)));
  const rej = structuredClone(BASE); rej.safeRejected.push('sqli-query/parameterized');
  assert.ok(decide(BASE, rej).some((p) => /NEW safe fixes rejected/.test(p)));
  const better = structuredClone(BASE); better.unsafeAccepted = [];
  assert.ok(decide(BASE, better).some((p) => /gaps closed but not recorded/.test(p)), 'an improvement must be recorded too');
  const grown = structuredClone(BASE); grown.denominators.patches += 1;
  assert.ok(decide(BASE, grown).some((p) => /corpus size changed/.test(p)));
  const misread = structuredClone(BASE); misread.unavailableMisreadAsBlocked = 1;
  assert.ok(decide(BASE, misread).some((p) => /read as a blocked exploit/.test(p)));
});

test('the real run matches the baseline, and every unsafe patch it accepts is a declared gap', { timeout: 600000 }, async () => {
  const res = await runBench();
  const s = summarize(res);
  assert.deepEqual(res.unscored, []);
  assert.deepEqual(decide(BASE, pinned(res.rows, s)), []);
  for (const r of res.rows.filter((x) => !x.safe && x.accepted)) assert.equal(r.knownGap, true, `${r.case}/${r.patch} was accepted and is not a declared gap`);
  assert.equal(s.denominators.patches, s.denominators.safe + s.denominators.unsafe);
  assert.ok(s.denominators.unsafe >= 12 && s.denominators.safe >= 7);
  assert.equal(s.replay.unavailableMisreadAsBlocked, 0);
  // feature-removal fakes are all rejected, and by something other than luck
  for (const r of res.rows.filter((x) => x.kind === 'feature-removed')) assert.equal(r.accepted, false, `${r.case}/${r.patch}`);
});

test('--check exits 0 on the baseline and non-zero on a doctored one (both directions), and a missing baseline is a failure not a skip', { timeout: 600000 }, () => {
  const ok = spawnSync(process.execPath, [RUN, '--check'], { cwd: REPO, encoding: 'utf8' });
  assert.equal(ok.status, 0, ok.stdout + ok.stderr);
  const bad = fs.mkdtempSync(path.join(os.tmpdir(), 'fixbench-bad-'));
  const file = path.join(REPO, 'bench/fix-verification/baseline.json');
  const original = fs.readFileSync(file, 'utf8');
  try {
    const doctored = structuredClone(BASE); doctored.unsafeAccepted = []; doctored.declaredGaps = [];
    fs.writeFileSync(file, JSON.stringify(doctored));
    const r = spawnSync(process.execPath, [RUN, '--check'], { cwd: REPO, encoding: 'utf8' });
    assert.notEqual(r.status, 0); assert.match(r.stderr, /FAIL/);
    fs.rmSync(file);
    const m = spawnSync(process.execPath, [RUN, '--check'], { cwd: REPO, encoding: 'utf8' });
    assert.notEqual(m.status, 0); assert.match(m.stderr, /no baseline/);
  } finally { fs.writeFileSync(file, original); fs.rmSync(bad, { recursive: true, force: true }); }
});

test('the published doc states denominators, the declared gaps and its limitations, and matches the baseline', () => {
  const doc = fs.readFileSync(path.join(REPO, 'docs/engineering-excellence/FIX_BENCHMARK.md'), 'utf8');
  assert.match(doc, new RegExp(`${BASE.denominators.patches} patches scored`));
  for (const g of BASE.unsafeAccepted) assert.ok(doc.includes(g), `doc names the accepted fake ${g}`);
  for (const g of BASE.safeRejected) assert.ok(doc.includes(g), `doc names the refused real fix ${g}`);
  assert.match(doc, /## Limitations/); assert.match(doc, /hand-written, synthetic and tiny/); assert.match(doc, /Dependency upgrades are verified by a different route/);
  assert.match(doc, /unavailable replays misread as a blocked exploit: 0/);
});

test('an unavailable exploit replay never masquerades as a blocked exploit: a case run with a blocked sandbox has exploitProofAfter not_run', async () => {
  const { verifyPatch } = await import('../../src/fix/verify-patch.js');
  const { runScan } = await import('../../src/runScan.js');
  const { signLastScan } = await import('../../src/posture/integrity.js');
  const c = CASES.find((x) => x.id === 'cmdi-exec');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'fixbench-blocked-'));
  try {
    fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name: 'c', version: '1.0.0' }));
    for (const [rel, text] of Object.entries(c.files)) fs.writeFileSync(path.join(root, rel), text);
    const saved = process.env.AGENTIC_SECURITY_DEEP; process.env.AGENTIC_SECURITY_DEEP = '1';
    let scan; try { ({ scan } = await runScan(root)); } finally { if (saved === undefined) delete process.env.AGENTIC_SECURITY_DEEP; else process.env.AGENTIC_SECURITY_DEEP = saved; }
    const f = scan.findings.find((x) => x.cwe === 'CWE-78');
    const st = path.join(root, '.agentic-security'); fs.mkdirSync(st, { recursive: true }); const body = JSON.stringify(scan);
    fs.writeFileSync(path.join(st, 'last-scan.json'), body); fs.writeFileSync(path.join(st, 'last-scan.json.sig'), signLastScan(body));
    const blocked = async () => ({ status: 'blocked', oracle: null, reasons: ['no confined runner on this host'], degraded: [] });
    const r = await verifyPatch({ scanRoot: root, finding: { id: f.id, stableId: f.stableId }, files: c.patches.find((p) => p.safe).files, route: 't', reproducer: c.reproducer, attemptFn: blocked });
    assert.equal(r.fixVerification.exploitProofAfter.status, 'not_run');
    assert.equal(r.fixVerification.exploitProofBefore.status, 'not_run');
    assert.notEqual(r.fixVerification.confidence.level, 'proven');
    assert.equal(r.fixVerification.verifiedFull, false, 'a required replay that did not run keeps the fix from being fully verified');
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('the gate is registered in the pre-push gate and the release gate, and its npm script exists', () => {
  assert.ok(PREPUSH.find((c) => c.id === 'fix-verification-gate' && c.npmScript === 'bench:fix-verify:check'));
  assert.equal(RELEASE.find((c) => c.id === 'fix-verification-gate')?.slow, true);
  const pkg = JSON.parse(fs.readFileSync(path.join(REPO, 'scanner/package.json'), 'utf8'));
  assert.match(pkg.scripts['bench:fix-verify:check'], /fix-verification\/runner\.mjs --check/);
});
