#!/usr/bin/env node
// End-to-end assurance demo (E8-02): start -> scan -> triage -> validate -> patch -> verify -> SCA reachability -> runtime correlate -> sign -> offline verify,
// over the project in examples/assurance-demo. Nothing here needs the network, and the run counts every attempt to open one (it must be zero).
//
//   node scripts/engineering-excellence/e2e-demo.mjs            run, print the steps, write docs/engineering-excellence/E2E_DEMO.md and data/e2e-demo/
//   node scripts/engineering-excellence/e2e-demo.mjs --check    run again and fail when the outline differs from the committed one
//   node scripts/engineering-excellence/e2e-demo.mjs --quiet    do not print the steps
//
// TRIAGE here is the project's recorded reviewer decisions (examples/assurance-demo/spec/expected.json), matched to what the engine reported; the engine does
// not make those decisions. Every other step calls the real library code.
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..', '..');
const DEMO = path.join(ROOT, 'examples', 'assurance-demo');
const COMMITTED_DIR = path.join(ROOT, 'docs', 'engineering-excellence', 'data', 'e2e-demo');
// a --check run must leave the committed package and key alone, or checking would dirty the tree it is checking
const OUT_DIR = process.argv.includes('--check') ? fs.mkdtempSync(path.join(os.tmpdir(), 'ee-e2e-check-')) : COMMITTED_DIR;
const OUT_MD = path.join(ROOT, 'docs', 'engineering-excellence', 'E2E_DEMO.md');
const OUT_OUTLINE = path.join(ROOT, 'docs', 'engineering-excellence', 'data', 'e2e-demo-outline.json');
const argv = process.argv.slice(2);
const imp = (p) => import(path.join(ROOT, 'scanner', 'src', p));

// ---- the network guard: any attempt to open a connection is recorded, and refused ----------------------------------------------
const networkAttempts = [];
const refuse = (what) => (...a) => { networkAttempts.push(`${what} ${String(a[0] && (a[0].host || a[0].hostname || a[0].href || a[0])).slice(0, 80)}`); throw new Error(`network refused (${what})`); };
globalThis.fetch = refuse('fetch'); http.request = refuse('http.request'); https.request = refuse('https.request'); http.get = refuse('http.get'); https.get = refuse('https.get'); net.connect = refuse('net.connect'); net.createConnection = refuse('net.createConnection');
process.env.AGENTIC_SECURITY_OFFLINE = '1';

const read = (p) => fs.readFileSync(p, 'utf8');
function treeOf(dir) { const out = {}; (function walk(p, rel) { for (const e of fs.readdirSync(p, { withFileTypes: true })) { if (e.name === '.agentic-security' || e.name === 'node_modules') continue; const r = rel ? `${rel}/${e.name}` : e.name; if (e.isDirectory()) walk(path.join(p, e.name), r); else out[r] = read(path.join(p, e.name)); } })(dir, ''); return out; }
const sha = (o) => 'sha256:' + crypto.createHash('sha256').update(typeof o === 'string' ? o : JSON.stringify(o)).digest('hex');

export async function run() {
  const steps = []; const step = (id, title, summary, detail = {}) => { steps.push({ id, title, summary, detail }); };
  const { runFullScan } = await imp('engine.js'); const { setStateWritesEnabled } = await imp('posture/state-dir.js');
  const { buildContext } = await imp('context-intelligence/build.js'); const { normalizeConfig } = await imp('context-intelligence/config.js');
  const { findCrossRouteInconsistencies } = await imp('context-intelligence/cross-route.js'); const { evaluateInvariants } = await imp('context-intelligence/invariants.js');
  const { candidatesFromEvidence, dciFindings, verifyDciFix } = await imp('context-intelligence/findings.js'); const { runFixture } = await imp('context-intelligence/counterexample.js');
  const { buildFixVerificationRecord, leg } = await imp('fix/verification-record.js'); const { augmentReachabilityViaImports } = await imp('sca/import-reachability.js');
  const { ingestRuntimeRecords } = await imp('posture/runtime-trace-ingest.js'); const { staticEdgesFromGraph, readRuntimeEdges, reconcileGraphs } = await imp('posture/graph-reconciliation.js');
  const { buildRuntimeExplanation } = await imp('posture/runtime-explanation.js'); const { buildSnapshotRef } = await imp('posture/assurance/evidence-registry.js');
  const { buildReleasePackage, signReleasePackage } = await imp('posture/assurance/release-package.js'); const { releaseVerdict, verifyStatedVerdict } = await imp('posture/assurance/release-verdict.js');
  const { verifyReleasePackage } = await imp('posture/assurance/release-package-verify.js');

  // ---- 1 start
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-e2e-demo-')); const project = path.join(work, 'assurance-demo'); fs.cpSync(DEMO, project, { recursive: true });
  const files = treeOf(project); const expected = JSON.parse(read(path.join(DEMO, 'spec', 'expected.json')));
  setStateWritesEnabled(true);
  step('start', 'Start', `copied examples/assurance-demo (${Object.keys(files).length} files) to a scratch directory; offline mode on; every attempt to open a network connection is refused and counted`, { files: Object.keys(files).sort() });

  // ---- 2 scan
  const scan = await runFullScan({ fileContents: files, scanRoot: project, deep: true });
  const material = scan.findings.filter((f) => f.severity !== 'info' && f.severity !== 'low');
  step('scan', 'Scan', `${scan.findings.length} findings (${material.length} medium or above); scan health ${scan.scanHealth.status}`, { health: scan.scanHealth.status, findings: material.map((f) => ({ severity: f.severity, file: f.file, line: f.line, parser: f.parser, vuln: String(f.vuln).slice(0, 90) })).sort((a, b) => (a.file + String(a.line).padStart(5) + a.vuln < b.file + String(b.line).padStart(5) + b.vuln ? -1 : 1)) });

  // ---- 3 triage
  const decisions = []; const matched = new Set();
  for (const e of expected.triage) {
    const hits = material.filter((f) => f.file === e.file && f.line >= e.lines[0] && f.line <= e.lines[1] && (!e.parser || f.parser === e.parser));
    hits.forEach((f) => matched.add(f));
    decisions.push({ id: e.id, class: e.class, label: e.label, reason: e.reason, reported: hits.length > 0, reportedBy: [...new Set(hits.map((f) => f.parser))].sort() });
    for (const f of hits) f.triage = e.label === 'false_positive' ? { state: 'false_positive', by: expected.reviewer, reason: e.reason } : { state: 'confirmed', by: expected.reviewer, reason: e.reason };
  }
  const unreviewed = material.filter((f) => !matched.has(f)).map((f) => `${f.severity} ${f.file}:${f.line} ${f.parser} ${String(f.vuln).slice(0, 60)}`).sort();
  const tp = decisions.filter((d) => d.label === 'true_positive'); const fp = decisions.filter((d) => d.label === 'false_positive');
  step('triage', 'Triage', `${tp.filter((d) => d.reported).length} of ${tp.length} expected true positives were reported; ${fp.filter((d) => d.reported).length} of ${fp.length} expected false positives were reported and marked by the reviewer; ${unreviewed.length} reported finding(s) have no recorded decision`, { reviewer: expected.reviewer, note: 'decisions are the project\'s recorded reviewer decisions, not made by the engine', decisions, unreviewed });

  // ---- 4 validate (executed counterexamples for the authorization findings)
  const ctxRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-e2e-ctx-'));
  const analyse = async (tree) => { fs.rmSync(ctxRoot, { recursive: true, force: true }); fs.mkdirSync(ctxRoot, { recursive: true }); fs.writeFileSync(path.join(ctxRoot, 'package.json'), '{"name":"p","version":"1.0.0"}'); for (const [f, t] of Object.entries(tree)) { fs.mkdirSync(path.dirname(path.join(ctxRoot, f)), { recursive: true }); fs.writeFileSync(path.join(ctxRoot, f), t); } const b = await buildContext(ctxRoot, { config: normalizeConfig({}).config }); return { bundles: b.bundles, crossRoute: findCrossRouteInconsistencies(b.bundles, { now: new Date(expected.now) }) }; };
  const apiFiles = { 'services/api/app.js': files['services/api/app.js'] };
  const behavior = JSON.parse(read(path.join(DEMO, 'spec', 'behavior.json')));
  const FIXTURES = {
    'PUT /notes/:id': { files: apiFiles, entry: 'services/api/app.js', victim: { user: { id: 'A', tenantId: 'T1' }, ownsId: 'n1', collection: 'notes', marker: 'mine' }, attacker: { user: { id: 'B', tenantId: 'T2' } }, store: behavior.store, path: '/notes/n1', method: 'PUT', body: { body: 'hijacked' }, siblingPath: '/notes/n1', siblingMethod: 'GET' },
    'GET /invoices/:id/lines': { files: apiFiles, entry: 'services/api/app.js', victim: { user: { id: 'A', tenantId: 'T1' }, ownsId: 'i1', collection: 'lines', marker: 'S-1' }, attacker: { user: { id: 'B', tenantId: 'T2' } }, store: behavior.store, path: '/invoices/i1/lines', method: 'GET', siblingPath: '/invoices/i1', siblingMethod: 'GET' },
  };
  const POLICY = { schema: 'agentic-security/dci-invariants', schemaVersion: '1.0.0', invariants: [{ id: 'TENANT-1', title: 'Invoices are tenant scoped', rule: 'requires', appliesTo: { routes: ['/invoices/**'] }, requires: ['tenant-scope'], severity: 'high' }] };
  const a0 = await analyse(files); const inv0 = evaluateInvariants(POLICY, a0.bundles, { now: new Date(expected.now) });
  const candidates = candidatesFromEvidence({ crossRoute: a0.crossRoute, invariantResults: inv0.results, bundles: a0.bundles });
  const dci = await dciFindings({ candidates, bundles: a0.bundles, fixtures: FIXTURES });
  fs.rmSync(ctxRoot, { recursive: true, force: true });
  const dciList = dci.findings.map((f) => (f.contextIntelligence.deterministic.counterexample.state === 'proven' ? { ...f, triage: { state: 'confirmed', by: expected.reviewer, reason: 'executed counterexample' } } : f));
  step('validate', 'Validate', `${candidates.length} candidate(s) from cross-route consistency and the tenant invariant; ${dciList.length} became findings, ${dciList.filter((f) => f.contextIntelligence.deterministic.counterexample.state === 'proven').length} of them proven by an executed attacker request; ${dci.counterexampleRefuted.length} refuted. SQL injection and command injection stay taint findings: nothing was executed for them`, { assessments: dci.assessments, findings: dciList.map((f) => ({ route: f.contextIntelligence.deterministic.scope.route, severity: f.severity, tier: f.proofTier ?? f.confirmationTier ?? null, counterexample: f.contextIntelligence.deterministic.counterexample.state, trace: f.contextIntelligence.deterministic.counterexample.trace.map((t) => `${t.kind}: ${t.what}${t.detail ? ' - ' + t.detail : ''}`) })) });

  // ---- 5 patch
  const patchSpec = JSON.parse(read(path.join(DEMO, 'spec', 'patches.json'))).patches;
  const applyPatch = (p) => { const after = { ...files }; for (const e of p.edits) { const n = after[e.file].split(e.find).length - 1; if (n !== 1) throw new Error(`patch ${p.id}: expected one match, found ${n}`); after[e.file] = after[e.file].replace(e.find, () => e.replace); } return after; };
  const patched = Object.fromEntries(patchSpec.map((p) => [p.id, applyPatch(p)]));
  step('patch', 'Patch', `${patchSpec.length} candidate patches applied to scratch copies (${patchSpec.filter((p) => p.kind === 'correct').length} correct, ${patchSpec.filter((p) => p.kind === 'false-fix').length} false fix)`, { patches: patchSpec.map((p) => ({ id: p.id, fixes: p.fixes, kind: p.kind, files: p.edits.map((e) => e.file) })) });

  // ---- 6 verify
  const runChecks = (tree, route = null) => behavior.checks.filter((c) => !route || c.covers.includes(route)).map((c) => {
    const r = runFixture({ files: { 'services/api/app.js': tree['services/api/app.js'] }, entry: 'services/api/app.js', request: c.request, user: c.user, store: behavior.store });
    if (!r.ok) return { id: c.id, passed: false, why: `could not run: ${r.error}` };
    const changed = JSON.stringify(r.store) !== JSON.stringify(behavior.store); const text = JSON.stringify(r.body ?? '');
    const e = c.expect; const why = [];
    if (e.status !== undefined && r.status !== e.status) why.push(`status ${r.status}, expected ${e.status}`);
    if (e.storeChanged !== undefined && changed !== e.storeChanged) why.push(`store ${changed ? 'changed' : 'unchanged'}, expected ${e.storeChanged ? 'changed' : 'unchanged'}`);
    if (e.bodyIncludes && !text.includes(e.bodyIncludes)) why.push(`body lacks ${e.bodyIncludes}`);
    if (e.bodyExcludes && text.includes(e.bodyExcludes)) why.push(`body leaks ${e.bodyExcludes}`);
    return { id: c.id, passed: why.length === 0, why: why.join('; ') || null };
  });
  const baselineChecks = runChecks(files);
  const verified = []; const claimed = [];
  for (const p of patchSpec) {
    const cand = candidates.find((c) => (c._crossRoute && c._crossRoute.route === p.fixes) || (c._invariant && c._invariant.label === p.fixes)); const finding = dciList.find((f) => f.contextIntelligence.deterministic.scope.route === p.fixes);
    const r = await verifyDciFix({ finding, candidate: cand, before: files, after: patched[p.id], fixture: FIXTURES[p.fixes] && cand._crossRoute ? FIXTURES[p.fixes] : null, invariants: POLICY, now: new Date(expected.now) });
    const checks = runChecks(patched[p.id], p.fixes); const failed = checks.filter((c) => !c.passed);
    const behaviorLeg = failed.length ? leg('failed', { reason: `${failed.length} of ${checks.length} behaviour checks failed: ${failed.map((c) => `${c.id} (${c.why})`).join('; ')}` }) : leg('passed', { reason: `${checks.length} of ${checks.length} behaviour checks passed` });
    const rec = buildFixVerificationRecord({ ...r.record, behaviorPreservation: behaviorLeg, behaviorTests: behaviorLeg, failures: failed.length ? [{ leg: 'behaviorTests', reason: behaviorLeg.reason }] : [] });
    const row = { patch: p.id, kind: p.kind, fixes: p.fixes, securityAfter: rec.securityAfter.status, exploitAfter: rec.exploitProofAfter.status, behavior: rec.behaviorTests.status, verifiedFull: rec.verifiedFull, behaviorFailures: failed.map((c) => c.id), degraded: rec.degradedLegs, checksRun: checks.length };
    verified.push(row); if (rec.verifiedFull) claimed.push({ patch: p, record: rec, finding });
  }
  const falseFix = verified.find((v) => v.kind === 'false-fix');
  step('verify', 'Verify', `${verified.filter((v) => v.verifiedFull).length} of ${verified.length} patches fully verified; the false fix passed the security re-analysis and the attack replay and was refused on behaviour (${falseFix.behaviorFailures.join(', ')})`, { baselineBehaviorChecksPassing: `${baselineChecks.filter((c) => c.passed).length} of ${baselineChecks.length} (the vulnerable code passes the checks that only the legitimate user exercises and fails the ones that attack)`, patches: verified });

  // ---- 7 SCA reachability with local advisories
  const pkg = JSON.parse(read(path.join(DEMO, 'package.json'))); const adv = JSON.parse(read(path.join(DEMO, 'spec', 'advisories.json'))).advisories;
  const cmp = (a, b) => { const x = a.split('.').map(Number), y = b.split('.').map(Number); for (let i = 0; i < 3; i++) if ((x[i] || 0) !== (y[i] || 0)) return (x[i] || 0) - (y[i] || 0); return 0; };
  const supplyChain = adv.filter((a) => pkg.dependencies[a.package] && cmp(pkg.dependencies[a.package], a.introduced) >= 0 && cmp(pkg.dependencies[a.package], a.fixed) < 0).map((a) => ({ type: 'vulnerable_dep', ecosystem: a.ecosystem, name: a.package, version: pkg.dependencies[a.package], advisory: a.id, severity: a.severity, osvVulnFunctions: a.functions }));
  augmentReachabilityViaImports(supplyChain, files, {});
  const scaRows = supplyChain.map((s) => ({ package: s.name, version: s.version, advisory: s.advisory, vulnerableFunction: s.osvVulnFunctions[0], reachable: (s.vulnerableFunctionCallSites || []).length > 0, callSites: (s.vulnerableFunctionCallSites || []).map((c) => `${c.file}:${c.line}`) }));
  step('sca', 'SCA reachability', `${scaRows.length} vulnerable dependencies from the local advisory data; ${scaRows.filter((r) => r.reachable).length} reached by a call to the advisory's function, ${scaRows.filter((r) => !r.reachable).length} imported but not reached`, { advisorySource: 'spec/advisories.json (local demo data, not a feed)', rows: scaRows });

  // ---- 8 runtime correlation, opt-in
  const records = JSON.parse(read(path.join(DEMO, 'spec', 'runtime-records.json'))).records;
  const commit = 'c'.repeat(40); const snapshotIdentity = { commit, buildHash: 'build-released' };
  const withIdentity = records.map((r) => { const { build, ...rest } = r; return { ...rest, commit: build === 'released' ? commit : 'd'.repeat(40), buildHash: build === 'released' ? 'build-released' : 'build-older' }; });
  const off = ingestRuntimeRecords(project, withIdentity);
  fs.mkdirSync(path.join(project, '.agentic-security'), { recursive: true }); fs.writeFileSync(path.join(project, '.agentic-security', 'runtime-policy.json'), JSON.stringify({ collect: true, sampleRate: 1, retentionDays: 30 }));
  const on = ingestRuntimeRecords(project, withIdentity, { now: Date.parse(expected.now) });
  const edges = await readRuntimeEdges(path.join(project, '.agentic-security', 'runtime-trace.jsonl'), { snapshotIdentity, now: Date.parse(expected.now) });
  const staticEdges = staticEdgesFromGraph({}, { routes: [{ path: '/search', handler: 'app.search' }, { path: '/notes/:id', handler: 'app.updateNote' }] });
  const reconciled = reconcileGraphs(staticEdges, edges, { sampling: { state: 'complete' } });
  const sqli = scan.findings.find((f) => /SQL Injection \(db\.query\)/.test(f.vuln) && f.parser === 'IR-TAINT'); const idor = dciList.find((f) => f.contextIntelligence.deterministic.scope.route === 'PUT /notes/:id');
  const explain = (finding, key) => buildRuntimeExplanation(finding, { reconciled, pathKeys: [key], sampling: { state: 'complete' }, snapshotIdentity });
  const exSqli = explain(sqli, 'route|/search|app.search'); const exIdor = explain(idor, 'route|/notes/:id|app.updateNote');
  step('runtime', 'Runtime correlation', `collection is off until a policy file switches it on (first attempt: ${off.ok ? 'accepted' : 'refused'}); after opt-in ${on.accepted} records were ingested; /search is corroborated by the released build, the /notes/:id records came from an older build and corroborate nothing`, { offByDefault: !off.ok && /not enabled/.test(off.reason), optInAccepted: on.accepted, edges: reconciled.edges.map((e) => ({ key: e.key, state: e.state, matched: e.matchedRecords, mismatched: e.mismatchedRecords })), explanations: [{ finding: 'SQL injection /search', compare: exSqli.compare.state, missing: exSqli.runtime.missingObservations }, { finding: 'IDOR PUT /notes/:id', compare: exIdor.compare.state, missing: exIdor.runtime.missingObservations }] });

  // ---- 9 sign
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519'); const PRIV = privateKey.export({ type: 'pkcs8', format: 'pem' }); const PUB = publicKey.export({ type: 'spki', format: 'pem' });
  const snapshot = buildSnapshotRef({ commit, engineVersion: scan.engineVersion || 'demo' });
  // The proof tier is a statement about HOW the finding was established, recorded as the stage that did it: an executed counterexample is execution-proven, a path found by the
  // taint engine is taint-proven (nothing was executed), anything else is unproven.
  const proofTierOf = (f) => (f.contextIntelligence && f.contextIntelligence.deterministic.counterexample.state === 'proven' ? 'execution-proven' : f.parser === 'IR-TAINT' ? 'taint-proven' : 'unproven');
  const payloadFinding = (f, extra = {}) => ({ id: f.id, stableId: f.stableId, severity: f.severity, vuln: f.vuln, file: f.file, line: f.line, parser: f.parser, family: f.family, cwe: f.cwe, proofTier: f.proofTier ?? proofTierOf(f), ...(f.triage ? { triage: f.triage } : {}), ...(f.contextIntelligence ? { contextIntelligence: { counterexample: { state: f.contextIntelligence.deterministic.counterexample.state } } } : {}), ...extra });
  const sqliF = payloadFinding(sqli, { stableId: sqli.stableId || 'sf-demo-sqli' });
  const cmdF = scan.findings.find((f) => /Command Injection/.test(f.vuln) && f.file.endsWith('convert.py'));
  const dciPayloads = dciList.map((f) => payloadFinding(f, { id: f.id, stableId: f.stableId || `sf-${f.id}`, severity: f.severity }));
  const scanPayloads = [sqliF, payloadFinding(cmdF)];
  const fixesClaimed = claimed.map((c) => ({ ...c, stable: dciPayloads.find((p) => p.contextIntelligence && c.finding && p.id === c.finding.id) }));
  const evidence = [{ kind: 'scan-health', payload: scan.scanHealth }];
  [...scanPayloads, ...dciPayloads].forEach((f) => evidence.push({ kind: 'finding', payload: f }));
  const indexOfFinding = (id) => evidence.findIndex((e) => e.kind === 'finding' && e.payload.id === id);
  for (const c of fixesClaimed) evidence.push({ kind: 'fix-verification', payload: { ...c.record, findingStableId: c.stable.stableId, findingId: c.stable.id }, restsOn: [indexOfFinding(c.stable.id)] });
  evidence.push({ kind: 'runtime-explanation', payload: exSqli }); evidence.push({ kind: 'runtime-explanation', payload: exIdor });
  const draft = buildReleasePackage({ snapshot, evidence }); const v = releaseVerdict(draft);
  const pkgObj = signReleasePackage(buildReleasePackage({ snapshot, evidence, policyDecisions: [{ id: 'release-verdict', outcome: v.verdict, reason: v.statement, policyVersion: '1' }], assertions: [{ id: 'scan-finished', text: 'the scan finished', status: scan.scanHealth.status === 'complete' ? 'supported' : 'unknown', reason: scan.scanHealth.status === 'complete' ? undefined : 'the scan did not finish cleanly', evidence: scan.scanHealth.status === 'complete' ? [0] : [] }] }), PRIV);
  step('sign', 'Sign', `release package with ${pkgObj.evidence.length} evidence records signed with a throwaway Ed25519 key; the verdict computed from its own contents is ${v.verdict}`, { verdict: v.verdict, statement: v.statement, blockers: v.blockers.map((b) => ({ code: b.code, message: b.message })), unknowns: v.unknowns.map((u) => ({ code: u.code, message: u.message })), evidenceKinds: [...new Set(pkgObj.evidence.map((e) => e.ref.kind))].sort() });

  // ---- 10 offline verify, and a tampered copy
  fs.mkdirSync(OUT_DIR, { recursive: true });
  const pkgFile = path.join(OUT_DIR, 'release-package.json'); const keyFile = path.join(OUT_DIR, 'public-key.pem');
  fs.writeFileSync(pkgFile, JSON.stringify(pkgObj, null, 2) + '\n'); fs.writeFileSync(keyFile, PUB);
  const verifier = path.join(ROOT, 'scripts', 'verify-release-package.mjs');
  const ok = spawnSync(process.execPath, [verifier, pkgFile, '--public-key', keyFile], { encoding: 'utf8' });
  const tampered = JSON.parse(JSON.stringify(pkgObj)); const fixed = tampered.evidence.find((e) => e.ref.kind === 'finding'); fixed.payload.severity = 'low';
  const tamperFile = path.join(work, 'tampered.json'); fs.writeFileSync(tamperFile, JSON.stringify(tampered));
  const bad = spawnSync(process.execPath, [verifier, tamperFile, '--public-key', keyFile], { encoding: 'utf8' });
  const stated = verifyStatedVerdict(pkgObj);
  step('verify-offline', 'Verify offline', `the independent verifier ${ok.status === 0 ? 'accepted' : 'REJECTED'} the package (exit ${ok.status}); a copy with one finding's severity lowered was ${bad.status === 1 ? 'rejected' : 'NOT rejected'} (exit ${bad.status}); the stated verdict ${stated.ok ? 'matches' : 'does not match'} the one recomputed from the contents`, { genuine: { exit: ok.status, output: ok.stdout.trim() }, tampered: { exit: bad.status, firstError: (bad.stderr.split('\n')[0] || '').slice(0, 160) }, statedVerdictMatches: stated.ok, replay: `node scripts/verify-release-package.mjs docs/engineering-excellence/data/e2e-demo/release-package.json --public-key docs/engineering-excellence/data/e2e-demo/public-key.pem` });

  fs.rmSync(work, { recursive: true, force: true }); if (OUT_DIR !== COMMITTED_DIR) fs.rmSync(OUT_DIR, { recursive: true, force: true });
  const outline = { schema: 'agentic-security/e2e-demo-outline@1', networkAttempts: networkAttempts.length, steps: steps.map((s) => ({ id: s.id, summary: s.summary })), verdict: v.verdict, blockerCodes: v.blockers.map((b) => b.code).sort(), unknownCodes: v.unknowns.map((u) => u.code).sort(), triage: decisions.map((d) => [d.id, d.reported]), verified: verified.map((x) => [x.patch, x.verifiedFull]), sca: scaRows.map((r) => [r.package, r.reachable]) };
  return { steps, outline, networkAttempts };
}

function render(r) {
  const L = ['# End-to-end assurance demo (E8-02)', '', 'Generated by `node scripts/engineering-excellence/e2e-demo.mjs`; checked by `--check`. The project is `examples/assurance-demo`. **No network is used**: every attempt to open a connection is refused and counted, and the count for this run was ' + r.networkAttempts + '.', '',
    'Triage is the project\'s recorded reviewer decisions matched to what the engine reported; the engine makes none of them. The advisories are local demo data. The signing key is thrown away after the run; the public key is committed so the verification step can be replayed.', ''];
  for (const s of r.steps) { L.push(`## ${s.title}`, '', s.summary + '.', ''); if (s.detail && Object.keys(s.detail).length) { L.push('```json', JSON.stringify(s.detail, null, 2), '```', ''); } }
  L.push('## What this does not show', '', '- The SQL injection, the command injection and the CSRF finding are left open, so the verdict is not_deployable: that is the gate working, not a failure of the demo.', '- Only authorization findings were executed (a confined local fixture); the injection findings are taint findings that nothing executed.', '- The behaviour checks are a small set of requests written for the demo, run in the same confined runner; they are not a real project test suite.', '- The runtime records are written for the demo, not collected from a running service.', '');
  return L.join('\n');
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const r = await run();
  const md = render(r);
  if (!argv.includes('--quiet')) for (const s of r.steps) console.log(`[${s.id}] ${s.summary}`);
  if (argv.includes('--check')) {
    const prior = fs.existsSync(OUT_OUTLINE) ? read(OUT_OUTLINE) : null; const now = JSON.stringify(r.outline, null, 2) + '\n';
    if (prior !== now || r.networkAttempts.length) { console.error(r.networkAttempts.length ? 'network attempts: ' + r.networkAttempts.join(', ') : 'the e2e demo outline differs from the committed one: run node scripts/engineering-excellence/e2e-demo.mjs'); process.exit(1); }
    console.log('e2e demo outline is current'); process.exit(0);
  }
  fs.writeFileSync(OUT_MD, md); fs.writeFileSync(OUT_OUTLINE, JSON.stringify(r.outline, null, 2) + '\n');
  process.exit(r.networkAttempts.length ? 1 : 0);
}
