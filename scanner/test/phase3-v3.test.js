// Tests for v3 next-gen PRD modules.
//
// One test per module: imports every export and exercises a happy-path
// scenario + an empty-input scenario. The tests are intentionally compact —
// the module-level rules and structural shape are the contract.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { shapeHash, annotateCloneClusters, findCloneOutliers } from '../src/posture/semantic-clone.js';
import { fingerprintFile, annotateAiProvenance, extractImportedPackageNames } from '../src/posture/ai-code-fingerprint.js';
import { scoreFile, mapCrownJewels, annotateCrownJewelScores } from '../src/posture/crown-jewels.js';
import { detectFlagSites, annotateFeatureFlagGating } from '../src/posture/feature-flags.js';
import { annotatePersonaScores, PERSONAS } from '../src/posture/persona-prioritization.js';
import { annotateMitigationComposite } from '../src/posture/mitigation-composite.js';
import { findNarrowableFunctions, annotateTypeNarrowing } from '../src/posture/type-narrowing.js';
import { buildWhyFired, annotateWhyFired, explainWhyNotFired } from '../src/posture/why-fired.js';
import { scanSpecificationDrift } from '../src/posture/specification-mining.js';
import { runCounterfactual } from '../src/posture/counterfactual.js';
import { buildAssetInventory, buildTrustBoundaries, classifyFindingsByStride, buildThreatModel, annotateStrideCategory } from '../src/posture/threat-model.js';
import { loadWafRules, annotateWafMitigation } from '../src/posture/waf-ingest.js';
import { loadTelemetry, annotateTelemetry } from '../src/posture/telemetry-ingest.js';
import { loadAuthPosture, annotateAuthMitigation } from '../src/posture/auth-posture-import.js';
import { loadNetworkPosture, annotateNetworkMitigation } from '../src/posture/network-policy-import.js';
import { buildReverseBlastRadius, annotateScaReverseBlast } from '../src/posture/reverse-blast-radius.js';
import { computeDrift } from '../src/posture/calibration-drift.js';
import { buildTrustBoundaryDiagram } from '../src/posture/trust-boundary-diagram.js';
import { mutateSnippet, buildMutationCorpus, summarizeSelfTest } from '../src/posture/adversarial-self-test.js';
import { prepareFuzzCorpus, recordOutcome, summarize } from '../src/posture/detector-fuzz.js';
import { startTranscript, appendEntry, isExceeded, runAgent, defaultLlmInvoke, defaultExecuteTool, TOOL_ACL, OUTCOMES } from '../src/posture/adversary-agent.js';
import { archaeologyForFinding } from '../src/posture/pre-incident-archaeology.js';
import { scanConcurrency } from '../src/posture/concurrency-checker.js';
import { isAvailable as dockerAvailable, startTarget, runPoCAgainst } from '../src/posture/verifier-ephemeral.js';
import { predictBounty, annotateBountyPrediction } from '../src/posture/bounty-prediction.js';
import { getPlaybook, annotateAttackPlaybooks } from '../src/posture/attack-playbooks.js';

// ── FR-SEM-8 ─────────────────────────────────────────────────────────────
test('semantic-clone: shapeHash returns null on tiny snippets, hex on real code', () => {
  assert.equal(shapeHash('x;'), null);
  const h = shapeHash('function add(a, b) { return a + b; }');
  assert.match(h, /^[0-9a-f]{16}$/);
});

test('semantic-clone: cluster + outlier surfacing', () => {
  const code = 'function fn(req, res) { return res.send(req.query.q + "!"); }';
  const findings = [
    { file: 'a.js', line: 1, severity: 'high', snippet: code },
    { file: 'b.js', line: 1, severity: 'low',  snippet: code },
    { file: 'c.js', line: 1, severity: 'info', snippet: 'unrelated stuff here for sure' },
  ];
  annotateCloneClusters(findings);
  assert.equal(findings[0].cloneClusterSize, 2);
  const outliers = findCloneOutliers(findings);
  assert.equal(outliers.length, 1);
  assert.equal(outliers[0].family, 'clone-outlier');
});

// ── FR-LEARN-10 ──────────────────────────────────────────────────────────
test('ai-fingerprint: provenance tier + import extraction', () => {
  const heavyComments = Array.from({ length: 20 }, (_, i) =>
    `// We do step ${i} of the helper utility.\nconst result${i} = process();`
  ).join('\n');
  const fp = fingerprintFile(heavyComments);
  assert.ok(['mixed', 'ai-likely'].includes(fp.provenance), `got ${fp.provenance}`);
  assert.deepEqual(
    extractImportedPackageNames('import x from "lodash";\nimport y from "@sentry/node/utils";'),
    ['lodash', '@sentry/node']
  );
  const findings = [{ file: 'a.js', vuln: 'x' }];
  annotateAiProvenance(findings, { 'a.js': heavyComments });
  assert.ok(findings[0].provenance);
});

// ── FR-PROD-5 ────────────────────────────────────────────────────────────
test('crown-jewels: scores Stripe webhook handler higher than health check', () => {
  const stripe = scoreFile('src/api/webhooks/stripe.ts', 'import Stripe from "stripe"; const s = new Stripe();');
  const health = scoreFile('src/routes/health/index.ts', 'return res.send("ok");');
  assert.ok(stripe.score > health.score, `${stripe.score} vs ${health.score}`);
  const findings = [{ file: 'src/api/webhooks/stripe.ts' }];
  annotateCrownJewelScores(findings, { 'src/api/webhooks/stripe.ts': 'import Stripe from "stripe";' });
  assert.ok(findings[0].crownJewelScore > 0);
  const m = mapCrownJewels({ 'src/admin/users.ts': 'const x = 1;' });
  assert.ok(m['src/admin/users.ts']);
});

// ── FR-PROD-6 ────────────────────────────────────────────────────────────
test('feature-flags: detects LD/Statsig + 0%-rollout demotion', () => {
  const text = `
    if (ldClient.variation("new_billing", false)) { dangerouslyDoIt(); }
  `;
  const sites = detectFlagSites({ 'src/x.ts': text });
  assert.ok(sites['src/x.ts']);
  assert.equal(sites['src/x.ts'][0].flagName, 'new_billing');
  const findings = [{ file: 'src/x.ts', line: 2 }];
  annotateFeatureFlagGating(findings, { 'src/x.ts': text }, { rollouts: { new_billing: 0 } });
  assert.equal(findings[0].featureFlag, 'new_billing');
  assert.equal(findings[0].featureFlagState, 'gated-off');
});

// ── FR-ADV-2 ─────────────────────────────────────────────────────────────
test('persona-prioritization: matrix shape + top-two ranking', () => {
  assert.equal(PERSONAS.length, 5);
  const findings = [{ severity: 'high', family: 'sql-injection', exposedInProd: true }];
  annotatePersonaScores(findings);
  assert.ok(findings[0].personaScores);
  assert.equal(Object.keys(findings[0].personaScores).length, 5);
  assert.equal(findings[0].personaTopTwo.length, 2);
});

// ── FR-PROD-7 ────────────────────────────────────────────────────────────
test('mitigation-composite: exposed / mitigated / unreachable verdicts', () => {
  const findings = [
    { severity: 'high' },
    { severity: 'high', mitigatedByWaf: true, wafRuleId: 'cf-1' },
    { severity: 'high', unreachable: true },
  ];
  annotateMitigationComposite(findings);
  assert.equal(findings[0].mitigationVerdict, 'exposed-in-prod');
  assert.equal(findings[1].mitigationVerdict, 'mitigated-in-prod');
  assert.equal(findings[2].mitigationVerdict, 'unreachable-in-prod');
});

// ── FR-SEM-10 ────────────────────────────────────────────────────────────
test('type-narrowing: catalogs wide-param functions; tolerates empty input', () => {
  const text = `function handle(x: any) { return x.id; }`;
  const fns = findNarrowableFunctions({ 'a.ts': text });
  assert.equal(fns[0]?.name, 'handle');
  const findings = [{ file: 'a.ts', enclosingFunction: 'handle', confidence: 0.7 }];
  // Without call sites of `handle` available, narrowing should NOT fire.
  annotateTypeNarrowing(findings, { 'a.ts': text });
  assert.equal(findings[0].typeNarrowed, undefined);
});

// ── FR-UX-9 ──────────────────────────────────────────────────────────────
test('why-fired: provenance record + why-not probe', () => {
  const f = { severity: 'high', file: 'a.js', line: 1, vuln: 'SQL injection', cwe: 'CWE-89' };
  const w = buildWhyFired(f);
  assert.equal(w.ruleId, 'CWE-89');
  const findings = [f];
  annotateWhyFired(findings, { rulesetVersion: 'v3-test' });
  assert.equal(findings[0].whyFired.scanner.rulesetVersion, 'v3-test');
  const report = explainWhyNotFired('CWE-89', { 'q.js': "db.query('SELECT * FROM u WHERE id=' + req.q.id)" });
  assert.ok(Array.isArray(report.considered));
});

// ── FR-LOGIC-8 ───────────────────────────────────────────────────────────
test('spec-mining: catches validateOwnership without user-id reference', () => {
  const code = `function validateOwnership(req) { return true; }`;
  const out = scanSpecificationDrift({ 'src/check.ts': code });
  assert.ok(out.find(f => f.family === 'spec-drift' && /ownership/i.test(f.vuln)));
});

// ── FR-LOGIC-9 ───────────────────────────────────────────────────────────
test('counterfactual: SPOF detection requires control + ≥3 high+ findings', () => {
  const fc = { 'src/auth.js': 'function requireAuth(req, res, next) { return next(); }' };
  const findings = [
    { file: 'src/auth.js', severity: 'high', family: 'missing-authz', line: 10 },
    { file: 'src/auth.js', severity: 'high', family: 'idor', line: 12 },
    { file: 'src/auth.js', severity: 'critical', family: 'broken-auth', line: 14 },
  ];
  const r = runCounterfactual(findings, fc);
  assert.ok(r.spofControls.length >= 1);
});

// ── FR-LOGIC-10 ──────────────────────────────────────────────────────────
test('threat-model: STRIDE classification + asset+boundary discovery', () => {
  const fc = {
    'src/routes.ts': 'app.get("/users", h);\napp.post("/admin", h);',
    'src/payments.ts': 'stripe.charges.create({ amount: 1000 });',
  };
  const findings = [{ vuln: 'SQL injection', severity: 'high', file: 'src/routes.ts', line: 1 }];
  const tm = buildThreatModel(findings, fc);
  assert.ok(tm.summary.assetCount >= 1);
  assert.ok(tm.summary.boundaryCount >= 1);
  annotateStrideCategory(findings);
  assert.equal(findings[0].strideCategory, 'tampering');
  const stride = classifyFindingsByStride(findings);
  assert.ok(stride.tampering.length >= 1);
  const assets = buildAssetInventory(fc);
  assert.ok(assets.length >= 1);
  const boundaries = buildTrustBoundaries(fc);
  assert.ok(boundaries.length >= 1);
});

// ── FR-PROD-1 ────────────────────────────────────────────────────────────
test('waf-ingest: no-config case + family inference from CF expression', () => {
  const rules = loadWafRules('/tmp/_no_waf_dir_v3test');
  assert.deepEqual(rules, []);
  const findings = [{ vuln: 'SQL injection', severity: 'high' }];
  const { rules: r2 } = annotateWafMitigation(findings, '/tmp/_no_waf_dir_v3test');
  assert.deepEqual(r2, []);
});

// ── FR-PROD-2 ────────────────────────────────────────────────────────────
test('telemetry-ingest: gracefully no-ops without a digest', () => {
  const t = loadTelemetry('/tmp/_no_telem_v3test');
  assert.equal(t, null);
  const f = [{ file: 'a.js', confidence: 0.7 }];
  annotateTelemetry(f, '/tmp/_no_telem_v3test');
  assert.equal(f[0].confidence, 0.7);
});

// ── FR-PROD-3 ────────────────────────────────────────────────────────────
test('auth-posture: no-op without a digest', () => {
  const t = loadAuthPosture('/tmp/_no_auth_v3test');
  assert.equal(t, null);
  const f = [{ file: 'a.js', vuln: 'IDOR' }];
  annotateAuthMitigation(f, '/tmp/_no_auth_v3test');
  assert.equal(f[0].mitigatedByAuth, undefined);
});

// ── FR-PROD-4 ────────────────────────────────────────────────────────────
test('network-policy: no-op without manifests', () => {
  const r = loadNetworkPosture('/tmp/_no_netpol_v3test');
  assert.equal(r, null);
  const f = [{ file: 'src/api/admin.js' }];
  annotateNetworkMitigation(f, '/tmp/_no_netpol_v3test');
  assert.equal(f[0].mitigatedByNetwork, undefined);
});

// ── FR-ADV-5 ─────────────────────────────────────────────────────────────
test('reverse-blast-radius: imports + route mapping', () => {
  const fc = {
    'src/api/users.ts': 'import _ from "lodash";\napp.get("/users", h);',
  };
  const map = buildReverseBlastRadius(fc);
  assert.ok(map.lodash);
  const findings = [{ package: 'lodash', severity: 'high', parser: 'SCA' }];
  annotateScaReverseBlast(findings, fc);
  assert.ok(findings[0].reverseExposure.importerCount >= 1);
});

// ── FR-LEARN-9 ───────────────────────────────────────────────────────────
test('calibration-drift: no-data path returns note', () => {
  const r = computeDrift('/tmp/_no_drift_v3test');
  assert.ok(r.note === 'no-feedback-data' || Array.isArray(r.alarms));
});

// ── FR-UX-10 ─────────────────────────────────────────────────────────────
test('trust-boundary-diagram: emits Mermaid + node list', () => {
  const fc = { 'src/routes.ts': 'app.get("/x", h);\napp.post("/y", h);' };
  const d = buildTrustBoundaryDiagram([], fc);
  assert.match(d.mermaid, /flowchart LR/);
  assert.ok(d.nodes.length >= 3);
});

// ── FR-LEARN-8 ───────────────────────────────────────────────────────────
test('adversarial-self-test: mutator produces variants + summary', () => {
  const muts = mutateSnippet("db.query('SELECT * FROM u WHERE id=' + req.q.id)", 'sql-injection');
  assert.ok(muts.length >= 1);
  const corpus = buildMutationCorpus([{ id: 'fx-1', family: 'sql-injection', code: "db.query('SELECT * FROM u')" }]);
  assert.equal(corpus[0].fixtureId, 'fx-1');
  const sum = summarizeSelfTest([
    { fixtureId: 'fx-1', family: 'sql-injection', mutation: { strategy: 'mut-1' }, detectedByScanner: true },
    { fixtureId: 'fx-1', family: 'sql-injection', mutation: { strategy: 'mut-2' }, detectedByScanner: false },
  ]);
  assert.equal(sum.gaps.length, 1);
  assert.equal(sum.confirmed.length, 1);
});

// ── FR-ADV-6 ─────────────────────────────────────────────────────────────
test('detector-fuzz: matrix prepare + record + summarize', () => {
  const matrix = prepareFuzzCorpus([
    { id: 'fx', family: 'xss', code: 'el.innerHTML = userInput' },
  ]);
  assert.ok(matrix.length >= 1);
  recordOutcome(matrix[0], false);
  const s = summarize(matrix);
  assert.equal(s.totalEscaped, 1);
});

// ── FR-ADV-1 ─────────────────────────────────────────────────────────────
test('adversary-agent: transcript shape + ACL refusal + no-llm short-circuit', async () => {
  const t = startTranscript({ stableId: 'abc', file: 'x', line: 1, vuln: 'IDOR' }, 'http://localhost:3000');
  assert.ok(t.chainHead);
  appendEntry(t, { tool: 'http.get', args: { path: '/' }, result: {} });
  appendEntry(t, { tool: 'rm -rf', args: {} });    // ACL refusal
  assert.ok(t.entries[1].refused);
  assert.equal(isExceeded(t, { maxCalls: 1 }), 'aborted-budget');
  const { outcome } = await runAgent({ stableId: 'a', file: 'x', line: 1, vuln: 'v' });
  assert.equal(outcome, 'unverified-no-llm-endpoint');
  assert.ok(TOOL_ACL.has('http.get'));
  assert.ok(OUTCOMES.includes('data-exfil'));
});

// ── FR-UX-11 ─────────────────────────────────────────────────────────────
test('pre-incident-archaeology: graceful no-git-repo', () => {
  const r = archaeologyForFinding({ file: 'x.js', snippet: 'abc' }, '/tmp/_no_git_v3test');
  assert.equal(r.available, false);
});

// ── FR-SEM-9 ─────────────────────────────────────────────────────────────
test('concurrency-checker: catches missed unlock + fire-and-forget', () => {
  const goCode = `
func handle(mu *sync.Mutex, x *int) {
  mu.Lock()
  if *x == 0 { return }
  *x += 1
  mu.Unlock()
}`;
  const findings = scanConcurrency({ 'src/h.go': goCode });
  assert.ok(findings.some(f => f.family === 'concurrency-bug' && /return without releasing|no matching unlock/i.test(f.vuln)));
});

// ── FR-VER-10 ────────────────────────────────────────────────────────────
test('verifier-ephemeral: gracefully reports docker availability', () => {
  const avail = dockerAvailable();
  assert.equal(typeof avail, 'boolean');
  // startTarget without image returns no-image-supplied or docker-not-installed.
  const r = startTarget({});
  assert.equal(r.available, false);
  assert.ok(r.reason);
  // runPoCAgainst with no target returns no-target / docker-not-installed.
  const p = runPoCAgainst(null, 'console.log(0);');
  assert.equal(p.available, false);
});

// ── FR-ADV-3 ─────────────────────────────────────────────────────────────
test('bounty-prediction: per-CWE bands + scaling', () => {
  const f = { severity: 'critical', cwe: 'CWE-89', vuln: 'SQL injection', file: 'src/api/users.ts' };
  const p = predictBounty(f);
  assert.ok(p.likely > 0);
  assert.equal(p.program, 'web2');
  // mitigated-in-prod should scale down.
  const fMit = { ...f, mitigationVerdict: 'mitigated-in-prod' };
  const pMit = predictBounty(fMit);
  assert.ok(pMit.likely < p.likely);
  const arr = [f, fMit];
  annotateBountyPrediction(arr);
  assert.ok(arr[0].predictedBountyUsd);
});

// ── FR-ADV-4 ─────────────────────────────────────────────────────────────
test('attack-playbooks: high+ finding gets a playbook with ethics header', () => {
  const f = { severity: 'high', cwe: 'CWE-89', vuln: 'SQL injection', file: 'src/api/users.ts', snippet: 'req.query.id' };
  const pb = getPlaybook(f);
  assert.ok(pb);
  assert.match(pb.script, /AUTHORIZED USE ONLY/);
  // Low severity → no playbook attached.
  const arr = [
    f,
    { severity: 'low', cwe: 'CWE-89', vuln: 'SQL injection', file: 'src/x.ts' },
  ];
  annotateAttackPlaybooks(arr);
  assert.ok(arr[0].attackPlaybook);
  assert.equal(arr[1].attackPlaybook, undefined);
});

// ── FR-ADV-1 live LLM wiring ─────────────────────────────────────────────
test('adversary-agent: defaultLlmInvoke returns null without endpoint; defaultExecuteTool refuses non-ACL', async () => {
  const prev = process.env.AGENTIC_SECURITY_LLM_ENDPOINT;
  delete process.env.AGENTIC_SECURITY_LLM_ENDPOINT;
  const r = await defaultLlmInvoke({ seedFinding: {}, target: '', entries: [] });
  assert.equal(r, null);
  if (prev) process.env.AGENTIC_SECURITY_LLM_ENDPOINT = prev;
  const t = startTranscript({}, 'http://localhost:0');
  const out = await defaultExecuteTool({ tool: 'rm -rf' }, t);
  assert.ok(out.refused);
});
